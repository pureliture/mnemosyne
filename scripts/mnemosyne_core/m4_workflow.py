"""Thin application workflow for bounded M4 deferred curation commands."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import (
    batch_event_contract,
    ledger_runtime,
    review_state,
    split_batch_service,
)
from .canonical_json import canonical_json_bytes, sha256_bytes
from .m2_workflow import M2WorkflowError, _canonical_root, _control_root


class M4WorkflowError(M2WorkflowError):
    """An M4 curation workflow operation cannot complete safely."""


@dataclass(frozen=True)
class SplitReviewBatchReport:
    event_id: str
    batch_id: str
    state: str
    resumed: bool
    child_batch_id: str
    parent_snapshot_id: str
    child_snapshot_id: str


def _partition_snapshot_payload(
    head_payload: dict,
    *,
    batch_id: str,
    batch_version: int,
    parent_snapshot_id: str,
    parent_snapshot_sha256: str,
    request_hash: str,
    snapshot_id: str,
    unit_ids: frozenset[str],
    keep_selected: bool,
) -> bytes:
    units = head_payload.get("units")
    if type(units) is not list:
        raise M4WorkflowError("batch head snapshot units are invalid")
    if keep_selected:
        filtered = [unit for unit in units if unit.get("unit_id") in unit_ids]
    else:
        filtered = [unit for unit in units if unit.get("unit_id") not in unit_ids]
    filtered.sort(key=lambda unit: unit.get("unit_id", ""))
    body = dict(head_payload)
    body["batch_id"] = batch_id
    body["batch_version"] = batch_version
    body["parent_snapshot_id"] = parent_snapshot_id
    body["parent_snapshot_sha256"] = parent_snapshot_sha256
    body["request_hash"] = request_hash
    body["snapshot_id"] = snapshot_id
    body["units"] = filtered
    return canonical_json_bytes(body)


def _split_bundle(
    control_root: Path,
    campaign_id: str,
    head_payload: dict,
    request: split_batch_service.SplitReviewBatchRequest,
) -> split_batch_service.SplitSnapshotBundle:
    selected = frozenset(request.selected_unit_ids)
    parent_request_hash = head_payload.get("request_hash")
    if type(parent_request_hash) is not str:
        raise M4WorkflowError("split source snapshot request hash is invalid")
    parent_payload = _partition_snapshot_payload(
        head_payload,
        batch_id=request.batch_id,
        batch_version=request.expected_review_revision + 1,
        parent_snapshot_id=request.expected_snapshot_id,
        parent_snapshot_sha256=request.expected_snapshot_sha256,
        request_hash=parent_request_hash,
        snapshot_id=request.parent_next_snapshot_id,
        unit_ids=selected,
        keep_selected=False,
    )
    child_payload = _partition_snapshot_payload(
        head_payload,
        batch_id=request.child_batch_id,
        batch_version=1,
        parent_snapshot_id=request.expected_snapshot_id,
        parent_snapshot_sha256=request.expected_snapshot_sha256,
        request_hash=batch_event_contract.split_child_request_hash(
            request.batch_id,
            request.child_batch_id,
        ),
        snapshot_id=request.child_snapshot_id,
        unit_ids=selected,
        keep_selected=True,
    )
    if sha256_bytes(parent_payload) != request.parent_next_snapshot_sha256:
        raise M4WorkflowError("parent next snapshot hash does not match request")
    if sha256_bytes(child_payload) != request.child_snapshot_sha256:
        raise M4WorkflowError("child genesis snapshot hash does not match request")
    snapshot_root = batch_event_contract.campaign_snapshot_root(
        control_root,
        campaign_id,
    )
    parent_path = (
        snapshot_root
        / request.parent_next_snapshot_id
        / "snapshot.json"
    )
    child_path = (
        snapshot_root
        / request.child_snapshot_id
        / "snapshot.json"
    )
    return split_batch_service.SplitSnapshotBundle(
        parent_snapshot_final_path=parent_path,
        parent_snapshot_payload_json=parent_payload,
        child_snapshot_final_path=child_path,
        child_snapshot_payload_json=child_payload,
    )


def _split_head_payload(
    sealed: review_state.SealedReviewSnapshot,
    request: split_batch_service.SplitReviewBatchRequest,
    campaign_id: str,
) -> dict:
    payload = sealed.payload
    if (
        sealed.schema_version != 2
        or sealed.snapshot_id != request.expected_snapshot_id
        or sealed.snapshot_sha256 != request.expected_snapshot_sha256
        or type(payload) is not dict
        or payload.get("campaign_id") != campaign_id
        or payload.get("batch_id") != request.batch_id
        or payload.get("batch_version") != request.expected_review_revision
        or payload.get("snapshot_id") != request.expected_snapshot_id
        or type(payload.get("request_hash")) is not str
    ):
        raise M4WorkflowError("split source snapshot binding is invalid")
    return payload


def split_review_batch(
    root: Path,
    *,
    event_id: str,
    batch_id: str,
    expected_snapshot_id: str,
    expected_snapshot_sha256: str,
    expected_review_revision: int,
    expected_execution_generation: int,
    selected_unit_ids: tuple[str, ...],
    child_batch_id: str,
    child_snapshot_id: str,
    child_snapshot_sha256: str,
    child_submission_id: str,
    parent_next_snapshot_id: str,
    parent_next_snapshot_sha256: str,
    parent_submission_id: str,
    actor: str,
) -> SplitReviewBatchReport:
    canonical = _canonical_root(root)
    try:
        with ledger_runtime.open_reader_session(canonical) as reader:
            control_root = _control_root(reader, canonical)
            campaign_row = reader.connection.execute(
                "SELECT campaign_id FROM review_batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            if campaign_row is None:
                raise M4WorkflowError("batch campaign binding is missing")
            campaign_id = campaign_row[0]
            sealed = review_state.ReviewSnapshotLoader(
                reader.connection,
                control_root,
            ).load(expected_snapshot_id)
            policy = reader.current_policy()
            request = split_batch_service.SplitReviewBatchRequest(
                event_id=event_id,
                batch_id=batch_id,
                expected_snapshot_id=expected_snapshot_id,
                expected_snapshot_sha256=expected_snapshot_sha256,
                expected_review_revision=expected_review_revision,
                expected_execution_generation=expected_execution_generation,
                selected_unit_ids=selected_unit_ids,
                child_batch_id=child_batch_id,
                child_snapshot_id=child_snapshot_id,
                child_snapshot_sha256=child_snapshot_sha256,
                child_submission_id=child_submission_id,
                parent_next_snapshot_id=parent_next_snapshot_id,
                parent_next_snapshot_sha256=parent_next_snapshot_sha256,
                parent_submission_id=parent_submission_id,
                policy=policy,
                actor=actor,
                units=sealed.units,
            )
            head_payload = _split_head_payload(
                sealed,
                request,
                campaign_id,
            )
            bundle = _split_bundle(
                control_root,
                campaign_id,
                head_payload,
                request,
            )
            prepared_policy = policy
        with ledger_runtime.open_writer_session(canonical, observed_by=actor) as writer:
            if writer.approved_policy_ref != prepared_policy:
                raise M4WorkflowError("approved policy changed during split")
            control_root = _control_root(writer, canonical)
            campaign_row = writer.connection.execute(
                "SELECT campaign_id FROM review_batches WHERE batch_id = ?",
                (request.batch_id,),
            ).fetchone()
            if campaign_row is None or campaign_row[0] != campaign_id:
                raise M4WorkflowError("batch campaign binding changed")
            service = split_batch_service.SplitBatchService(
                writer.connection,
                batch_event_contract.campaign_event_root(
                    control_root,
                    campaign_id,
                ),
                placement_shared=writer.placement_shared,
                ledger_exclusive=writer.ledger_exclusive,
            )
            result = service.split(request, bundle)
    except split_batch_service.SplitBatchError as exc:
        raise M4WorkflowError(str(exc)) from exc
    except (
        batch_event_contract.BatchEventContractError,
        ledger_runtime.LedgerRuntimeError,
        review_state.ReviewStateError,
        M2WorkflowError,
    ) as exc:
        raise M4WorkflowError(str(exc)) from exc
    return SplitReviewBatchReport(
        event_id=result.event_id,
        batch_id=result.parent_batch_id,
        state=result.event_state,
        resumed=result.resumed,
        child_batch_id=result.child_batch_id,
        parent_snapshot_id=result.parent_snapshot_id,
        child_snapshot_id=result.child_snapshot_id,
    )


def resume_split_batch_event(
    root: Path,
    *,
    event_id: str,
    resumed_by: str,
) -> SplitReviewBatchReport:
    canonical = _canonical_root(root)
    try:
        with ledger_runtime.open_writer_session(canonical, observed_by=resumed_by) as writer:
            control_root = _control_root(writer, canonical)
            campaign_row = writer.connection.execute(
                "SELECT b.campaign_id FROM batch_events AS e "
                "JOIN review_batches AS b ON b.batch_id = e.batch_id "
                "WHERE e.batch_event_id = ?",
                (event_id,),
            ).fetchone()
            if campaign_row is None:
                raise M4WorkflowError("batch event campaign binding is missing")
            campaign_id = campaign_row[0]
            service = split_batch_service.SplitBatchService(
                writer.connection,
                batch_event_contract.campaign_event_root(
                    control_root,
                    campaign_id,
                ),
                placement_shared=writer.placement_shared,
                ledger_exclusive=writer.ledger_exclusive,
            )
            prepared = service.load_prepared(
                event_id,
                policy=writer.approved_policy_ref,
            )
            sealed = review_state.ReviewSnapshotLoader(
                writer.connection,
                control_root,
            ).load(prepared.request.expected_snapshot_id)
            head_payload = _split_head_payload(
                sealed,
                prepared.request,
                campaign_id,
            )
            bundle = _split_bundle(
                control_root,
                campaign_id,
                head_payload,
                prepared.request,
            )
            result = service.resume(
                event_id,
                bundle,
                resumed_by=resumed_by,
                policy=writer.approved_policy_ref,
            )
    except split_batch_service.SplitBatchError as exc:
        raise M4WorkflowError(str(exc)) from exc
    except (
        batch_event_contract.BatchEventContractError,
        ledger_runtime.LedgerRuntimeError,
        review_state.ReviewStateError,
        M2WorkflowError,
    ) as exc:
        raise M4WorkflowError(str(exc)) from exc
    return SplitReviewBatchReport(
        event_id=result.event_id,
        batch_id=result.parent_batch_id,
        state=result.event_state,
        resumed=result.resumed,
        child_batch_id=result.child_batch_id,
        parent_snapshot_id=result.parent_snapshot_id,
        child_snapshot_id=result.child_snapshot_id,
    )
