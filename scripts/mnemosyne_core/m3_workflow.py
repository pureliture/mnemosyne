"""Thin application workflow for M3 review decisions and submissions."""

from __future__ import annotations

import datetime
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from . import (
    admission,
    batch_event_contract,
    batch_event_service,
    decision_service,
    deferral_service,
    deferral_store,
    legacy_import,
    ledger_runtime,
    progress_query,
    review_draft,
    review_state,
    review_submission,
)
from .canonical_json import canonical_json_bytes, sha256_bytes
from .m2_workflow import M2WorkflowError, _canonical_root, _control_root
from .m4_workflow import M4WorkflowError, SplitReviewBatchReport, resume_split_batch_event


@dataclass(frozen=True)
class _SealedPaths:
    staging_path: Path
    final_path: Path


_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_DRAFT_DECISION_TO_ACTION = {
    "accept-recommendation": "keep",
    "keep": "keep",
    "link": "link",
    "defer": "defer",
    "exclude": "exclude",
    "proposal-reject": "proposal-reject",
    "correction": "correction",
}


class M3WorkflowError(M2WorkflowError):
    """An M3 curation workflow operation cannot complete safely."""


@dataclass(frozen=True)
class SubmitReviewReport:
    batch_id: str
    snapshot_id: str
    submission_id: str
    submission_state: str
    review_revision: int
    execution_generation: int
    snapshot_sha256: str
    package_sha256: str
    final_path: str
    review_directory: str
    structural_approval_ready: bool
    resumed: bool

    def __post_init__(self) -> None:
        if self.submission_state != "COMMITTED":
            raise M3WorkflowError("review submission did not reach COMMITTED")
        if self.structural_approval_ready is not False:
            raise M3WorkflowError("M3 decision submission cannot grant structural authority")


@dataclass(frozen=True)
class ReopenDecisionReport(SubmitReviewReport):
    pass


class MinimalDecisionSnapshotPublisher:
    """Seal decision-lineage v3 snapshots with immutable snapshot.json only."""

    def __init__(self, snapshot_root: Path) -> None:
        self.snapshot_root = Path(snapshot_root).resolve()

    def plan(
        self,
        publication: review_submission.SnapshotPublication,
    ) -> review_submission.SnapshotPublishPlan:
        if type(publication) is not review_submission.SnapshotPublication:
            raise TypeError("publication must be SnapshotPublication")
        package_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "package_sha256": publication.snapshot_sha256,
                    "snapshot_sha256": publication.snapshot_sha256,
                }
            )
        )
        sealed_identity_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "package_sha256": package_sha256,
                    "snapshot_sha256": publication.snapshot_sha256,
                }
            )
        )
        staging_path = publication.final_path.parent / (
            ".incomplete-%s" % publication.snapshot_id
        )
        return review_submission.SnapshotPublishPlan(
            publication=publication,
            final_path=publication.final_path,
            package_sha256=package_sha256,
            sealed_identity_sha256=sealed_identity_sha256,
            sealed_payload=_SealedPaths(
                staging_path=staging_path,
                final_path=publication.final_path,
            ),
        )

    def publish(
        self,
        plan: review_submission.SnapshotPublishPlan,
    ) -> review_submission.SnapshotPublishResult:
        if type(plan) is not review_submission.SnapshotPublishPlan:
            raise TypeError("plan must be SnapshotPublishPlan")
        plan.final_path.mkdir(mode=0o700, parents=True, exist_ok=False)
        payload_path = plan.final_path / "snapshot.json"
        descriptor = os.open(
            payload_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, plan.publication.canonical_payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return review_submission.SnapshotPublishResult(
            final_path=plan.final_path,
            snapshot_sha256=plan.publication.snapshot_sha256,
            package_sha256=plan.package_sha256,
            sealed_identity_sha256=plan.sealed_identity_sha256,
        )


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise M3WorkflowError("%s is invalid" % label)
    return value


def _utc_timestamp(value: str, label: str) -> str:
    if _TIME.fullmatch(value) is None:
        raise M3WorkflowError("%s must use UTC Z notation" % label)
    return value


def _decision_snapshot_payload(
    *,
    batch_id: str,
    next_snapshot_id: str,
    parent_snapshot_id: str,
    parent_snapshot_sha256: str,
    review_revision: int,
    decision_event_ids: Tuple[str, ...],
) -> bytes:
    return canonical_json_bytes(
        {
            "approval_ready": False,
            "batch_id": batch_id,
            "batch_version": review_revision,
            "decision_event_ids": list(decision_event_ids),
            "parent_snapshot_id": parent_snapshot_id,
            "parent_snapshot_sha256": parent_snapshot_sha256,
            "schema_version": 3,
            "snapshot_id": next_snapshot_id,
            "structural_approval_ready": False,
        }
    )


def _member_ids_for_unit(
    sealed: review_state.SealedReviewSnapshot,
    unit_id: str,
) -> Tuple[str, ...]:
    payload = json.loads(sealed.snapshot_payload.decode("utf-8"))
    for unit in payload.get("units", ()):
        if unit.get("unit_id") == unit_id:
            member_ids = unit.get("member_item_ids")
            if (
                type(member_ids) is not list
                or not member_ids
                or any(type(value) is not str for value in member_ids)
            ):
                raise M3WorkflowError("batch unit membership is invalid")
            return tuple(member_ids)
    raise M3WorkflowError("draft unit is not on the sealed snapshot")


def _draft_edit_to_input(
    edit: review_draft.DraftItemEdit,
    *,
    member_item_ids: Tuple[str, ...],
    reason: str,
) -> decision_service.ItemDecisionInput:
    if edit.decision == "pending":
        raise M3WorkflowError("draft still has pending decisions")
    action = _DRAFT_DECISION_TO_ACTION.get(edit.decision)
    if action is None:
        raise M3WorkflowError("draft decision is not submittable")
    corrections = tuple(
        (field, changed)
        for field, changed in edit.corrections
    )
    return decision_service.ItemDecisionInput(
        unit_id=edit.unit_id,
        member_item_ids=member_item_ids,
        selected_item_ids=member_item_ids,
        action=action,
        reason=reason,
        corrections=corrections,
    )


def _submit_prepared(
    root: Path,
    *,
    actor: str,
    campaign_id: str,
    prepared: review_submission.PreparedReviewSubmission
    | review_submission.PreparedReopenReviewSubmission,
    snapshot_root: Path,
    publisher: MinimalDecisionSnapshotPublisher,
) -> SubmitReviewReport:
    with ledger_runtime.open_writer_session(
        root,
        observed_by=actor,
    ) as session:
        control_root = _control_root(session, root)
        resolved_root = control_root / "campaigns" / campaign_id / "snapshots"
        if resolved_root != snapshot_root:
            raise M3WorkflowError("snapshot root changed during submission")
        service = review_submission.ReviewSubmissionPublisher(
            session.connection,
            snapshot_root,
            placement_shared=session.placement_shared,
            ledger_exclusive=session.ledger_exclusive,
            publisher=publisher,
            current_policy=session.current_policy,
        )
        if type(prepared) is review_submission.PreparedReopenReviewSubmission:
            result = service.submit_prepared_reopen(prepared)
        elif type(prepared) is review_submission.PreparedReviewSubmission:
            result = service.submit_prepared(prepared)
        else:
            raise M3WorkflowError("prepared submission type is invalid")
    final_path = result.final_path
    return SubmitReviewReport(
        batch_id=result.batch_id,
        snapshot_id=result.snapshot_id,
        submission_id=result.submission_id,
        submission_state=result.submission_state,
        review_revision=result.review_revision,
        execution_generation=result.execution_generation,
        snapshot_sha256=result.snapshot_sha256,
        package_sha256=result.package_sha256,
        final_path=str(final_path),
        review_directory=str(final_path / "review"),
        structural_approval_ready=False,
        resumed=result.resumed,
    )


def submit_review_decision(
    root: Path,
    *,
    decision_request: decision_service.DecisionRequest,
) -> SubmitReviewReport:
    """Compile and commit one exact nonmovement decision submission."""

    canonical = _canonical_root(root)
    compiled = decision_service.DecisionService().compile(decision_request)
    next_payload = _decision_snapshot_payload(
        batch_id=decision_request.batch_id,
        next_snapshot_id=decision_request.next_snapshot_id,
        parent_snapshot_id=decision_request.base_snapshot_id,
        parent_snapshot_sha256=decision_request.base_snapshot_sha256,
        review_revision=decision_request.expected_review_revision + 1,
        decision_event_ids=tuple(
            event["event_id"] for event in compiled.events
        ),
    )
    with ledger_runtime.open_reader_session(canonical) as reader:
        policy = reader.approved_policy_ref
        control_root = _control_root(reader, canonical)
        snapshot_root = (
            control_root
            / "campaigns"
            / decision_request.campaign_id
            / "snapshots"
        )
        submission_request = review_submission.ReviewSubmissionRequest(
            policy=policy,
            decision_request=decision_request,
            compiled=compiled,
            next_snapshot_payload=next_payload,
        )
        publisher = MinimalDecisionSnapshotPublisher(snapshot_root)
        prepared = review_submission.prepare_review_submission(
            snapshot_root,
            publisher,
            submission_request,
        )
    return _submit_prepared(
        canonical,
        actor=decision_request.actor,
        campaign_id=decision_request.campaign_id,
        prepared=prepared,
        snapshot_root=snapshot_root,
        publisher=publisher,
    )


def decide(
    root: Path,
    *,
    campaign_id: str,
    batch_id: str,
    base_snapshot_id: str,
    base_snapshot_sha256: str,
    expected_review_revision: int,
    expected_execution_generation: int,
    submission_id: str,
    next_snapshot_id: str,
    actor: str,
    unit_id: str,
    member_item_ids: Tuple[str, ...],
    action: str,
    reason: str,
    decided_at_utc: Optional[str] = None,
) -> SubmitReviewReport:
    """Submit one single-unit decision through the review submission publisher."""

    request = decision_service.DecisionRequest(
        campaign_id=_identifier(campaign_id, "campaign id"),
        batch_id=_identifier(batch_id, "batch id"),
        base_snapshot_id=_identifier(base_snapshot_id, "base snapshot id"),
        base_snapshot_sha256=base_snapshot_sha256,
        expected_review_revision=expected_review_revision,
        expected_execution_generation=expected_execution_generation,
        submission_id=_identifier(submission_id, "submission id"),
        next_snapshot_id=_identifier(next_snapshot_id, "next snapshot id"),
        actor=_identifier(actor, "actor"),
        decided_at_utc=_utc_timestamp(decided_at_utc or _utc_now(), "decided_at"),
        decisions=(
            decision_service.ItemDecisionInput(
                unit_id=_identifier(unit_id, "unit id"),
                member_item_ids=member_item_ids,
                selected_item_ids=member_item_ids,
                action=action,
                reason=reason,
            ),
        ),
    )
    return submit_review_decision(root, decision_request=request)


def submit_review(
    root: Path,
    *,
    draft_id: str,
    submission_id: str,
    next_snapshot_id: str,
    actor: str,
    reason: str = "submitted from review draft",
    decided_at_utc: Optional[str] = None,
) -> SubmitReviewReport:
    """Parse one checked-out draft and commit its marker decisions."""

    canonical = _canonical_root(root)
    draft_identity = _identifier(draft_id, "draft id")
    actor_identity = _identifier(actor, "actor")
    with ledger_runtime.open_reader_session(canonical) as reader:
        control_root = _control_root(reader, canonical)
        draft_path = control_root / "drafts" / draft_identity
        if not draft_path.is_dir():
            raise M3WorkflowError("review draft checkout is missing")
        manifest_path = draft_path / "draft.json"
        try:
            manifest = json.loads(manifest_path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise M3WorkflowError("review draft manifest is unreadable") from exc
        draft_request = review_draft.ReviewDraftRequest(
            draft_id=draft_identity,
            base_snapshot_id=manifest["base_snapshot_id"],
            base_snapshot_sha256=manifest["base_snapshot_sha256"],
            actor=manifest.get("owner_actor", actor_identity),
        )
        loader = review_state.ReviewSnapshotLoader(
            reader.connection,
            control_root,
        )
        sealed = loader.load(draft_request.base_snapshot_id)
        if sealed.snapshot_sha256 != draft_request.base_snapshot_sha256:
            raise M3WorkflowError("draft base snapshot hash does not match ledger")

        def load_trusted(
            expected_id: str,
            expected_hash: str,
        ) -> review_draft.TrustedReviewSnapshot:
            if expected_id != sealed.snapshot_id or expected_hash != sealed.snapshot_sha256:
                raise review_draft.ReviewDraftConflict(
                    "draft requested another sealed snapshot"
                )
            return review_draft.TrustedReviewSnapshot(
                snapshot_id=sealed.snapshot_id,
                snapshot_sha256=sealed.snapshot_sha256,
                snapshot_bytes=sealed.snapshot_payload,
                review_markdown=sealed.review_markdown,
                review_markdown_sha256=sealed.review_hashes.markdown_sha256,
            )

        try:
            draft = review_draft.checkout_review(
                draft_request,
                drafts_root=control_root / "drafts",
                snapshot_loader=load_trusted,
            )
        except review_draft.ReviewDraftConflict as exc:
            raise M3WorkflowError(str(exc)) from exc
        try:
            payload = json.loads(sealed.snapshot_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise M3WorkflowError("sealed snapshot payload is invalid") from exc
        batch_id = payload.get("batch_id")
        campaign_id = payload.get("campaign_id")
        if (
            type(batch_id) is not str
            or type(campaign_id) is not str
            or _IDENTIFIER.fullmatch(batch_id) is None
            or _IDENTIFIER.fullmatch(campaign_id) is None
        ):
            raise M3WorkflowError("sealed snapshot batch lineage is invalid")
        head = reader.connection.execute(
            "SELECT review_revision, execution_generation FROM review_batches "
            "WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if head is None:
            raise M3WorkflowError("review batch head is missing")
        review_revision, execution_generation = int(head[0]), int(head[1])
        decisions = tuple(
            _draft_edit_to_input(
                edit,
                member_item_ids=_member_ids_for_unit(sealed, edit.unit_id),
                reason=reason,
            )
            for edit in draft.edits
        )
        decision_request = decision_service.DecisionRequest(
            campaign_id=campaign_id,
            batch_id=batch_id,
            base_snapshot_id=draft_request.base_snapshot_id,
            base_snapshot_sha256=draft_request.base_snapshot_sha256,
            expected_review_revision=review_revision,
            expected_execution_generation=execution_generation,
            submission_id=_identifier(submission_id, "submission id"),
            next_snapshot_id=_identifier(next_snapshot_id, "next snapshot id"),
            actor=actor_identity,
            decided_at_utc=_utc_timestamp(
                decided_at_utc or _utc_now(),
                "decided_at",
            ),
            decisions=decisions,
        )
    return submit_review_decision(root, decision_request=decision_request)


def reopen_review_decision(
    root: Path,
    *,
    reopen_request: decision_service.ReopenDecisionRequest,
) -> ReopenDecisionReport:
    """Reopen one item decision through the partial-publish-safe publisher."""

    canonical = _canonical_root(root)
    compiled = decision_service.DecisionService().compile_reopen(reopen_request)
    next_payload = _decision_snapshot_payload(
        batch_id=reopen_request.batch_id,
        next_snapshot_id=reopen_request.next_snapshot_id,
        parent_snapshot_id=reopen_request.base_snapshot_id,
        parent_snapshot_sha256=reopen_request.base_snapshot_sha256,
        review_revision=reopen_request.expected_review_revision + 1,
        decision_event_ids=(compiled.event["event_id"],),
    )
    with ledger_runtime.open_reader_session(canonical) as reader:
        policy = reader.approved_policy_ref
        control_root = _control_root(reader, canonical)
        snapshot_root = (
            control_root
            / "campaigns"
            / reopen_request.campaign_id
            / "snapshots"
        )
        submission_request = review_submission.ReopenReviewSubmissionRequest(
            policy=policy,
            reopen_request=reopen_request,
            compiled=compiled,
            next_snapshot_payload=next_payload,
        )
        publisher = MinimalDecisionSnapshotPublisher(snapshot_root)
        prepared = review_submission.prepare_reopen_review_submission(
            snapshot_root,
            publisher,
            submission_request,
        )
    report = _submit_prepared(
        canonical,
        actor=reopen_request.actor,
        campaign_id=reopen_request.campaign_id,
        prepared=prepared,
        snapshot_root=snapshot_root,
        publisher=publisher,
    )
    return ReopenDecisionReport(**report.__dict__)


def reopen_decision(
    root: Path,
    *,
    campaign_id: str,
    batch_id: str,
    base_snapshot_id: str,
    base_snapshot_sha256: str,
    expected_review_revision: int,
    expected_execution_generation: int,
    submission_id: str,
    next_snapshot_id: str,
    item_id: str,
    current_decision_event_id: str,
    current_projection_generation: int,
    actor: str,
    reason: str,
    reopened_at_utc: Optional[str] = None,
    selected_relation_kind: Optional[str] = None,
    selected_relation_id: Optional[str] = None,
) -> ReopenDecisionReport:
    """Reopen one item for review using explicit CLI identity fields."""

    request = decision_service.ReopenDecisionRequest(
        campaign_id=_identifier(campaign_id, "campaign id"),
        batch_id=_identifier(batch_id, "batch id"),
        base_snapshot_id=_identifier(base_snapshot_id, "base snapshot id"),
        base_snapshot_sha256=base_snapshot_sha256,
        expected_review_revision=expected_review_revision,
        expected_execution_generation=expected_execution_generation,
        submission_id=_identifier(submission_id, "submission id"),
        next_snapshot_id=_identifier(next_snapshot_id, "next snapshot id"),
        item_id=_identifier(item_id, "item id"),
        current_decision_event_id=_identifier(
            current_decision_event_id,
            "current decision event id",
        ),
        current_projection_generation=current_projection_generation,
        actor=_identifier(actor, "actor"),
        reason=reason,
        reopened_at_utc=_utc_timestamp(reopened_at_utc or _utc_now(), "reopened_at"),
        selected_relation_kind=selected_relation_kind,
        selected_relation_id=selected_relation_id,
    )
    return reopen_review_decision(root, reopen_request=request)


@dataclass(frozen=True)
class LegacyPreviewReport:
    preview_id: str
    preview_sha256: str
    entry_count: int
    pending_count: int
    collision_count: int
    preview: Dict[str, Any]


@dataclass(frozen=True)
class LegacyImportReport:
    import_run_id: str
    preview_sha256: str
    state: str
    entry_count: int
    result_path: str


@dataclass(frozen=True)
class ProgressViewReport:
    view: str
    payload: Dict[str, Any]


@dataclass(frozen=True)
class EvidenceAttachReport:
    event_id: str
    deferral_id: str
    deferral_version: int
    state: str
    final_path: str
    final_sha256: str
    resumed: bool


@dataclass(frozen=True)
class DeferralEvaluateReport:
    trigger_event_id: str
    deferral_id: str
    deferral_version: int
    trigger_kind: str
    projection_generation: int
    repeated: bool


@dataclass(frozen=True)
class BatchTerminalReport:
    event_id: str
    event_state: str
    event_sha256: str
    batch_id: str
    batch_status: str
    released_memberships: int
    final_path: str
    resumed: bool


def preview_legacy_history_import(
    root: Path,
    *,
    preview_id: str,
    requested_by: str,
) -> LegacyPreviewReport:
    """Build a ledger-free legacy import preview."""

    preview = legacy_import.preview_legacy_history_import(
        _canonical_root(root),
        preview_id=preview_id,
        requested_by=requested_by,
    )
    return LegacyPreviewReport(
        preview_id=preview["preview_id"],
        preview_sha256=preview["preview_sha256"],
        entry_count=len(preview["entries"]),
        pending_count=preview["pending_count"],
        collision_count=len(preview["collisions"]),
        preview=preview,
    )


def _load_preview_document(path: Path) -> Dict[str, Any]:
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise M3WorkflowError("legacy import preview file is unreadable") from exc
    try:
        preview = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M3WorkflowError("legacy import preview file is invalid JSON") from exc
    if type(preview) is not dict:
        raise M3WorkflowError("legacy import preview file is invalid")
    digest = legacy_import.preview_sha256(preview)
    recorded = preview.get("preview_sha256")
    if type(recorded) is not str or recorded != digest:
        raise M3WorkflowError("legacy import preview hash is invalid")
    return preview


def import_legacy_history(
    root: Path,
    *,
    import_run_id: str,
    preview_file: Path,
    actor: str,
) -> LegacyImportReport:
    """Commit one exact legacy import using a sealed preview artifact."""

    canonical = _canonical_root(root)
    preview = _load_preview_document(Path(preview_file).expanduser().resolve())
    legacy_import.require_legacy_import_allowed(canonical)
    try:
        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=actor,
        ) as session:
            result = legacy_import.import_legacy_history(
                canonical,
                session.connection,
                preview=preview,
                expected_preview_sha256=preview["preview_sha256"],
                import_run_id=import_run_id,
                actor=actor,
            )
    except legacy_import.LegacyImportError as exc:
        raise M3WorkflowError(str(exc)) from exc
    return LegacyImportReport(
        import_run_id=result["import_run_id"],
        preview_sha256=result["preview_sha256"],
        state=result["state"],
        entry_count=len(result["entries"]),
        result_path=str(result["result_path"]),
    )


def _progress_query(session: ledger_runtime.ReaderSession) -> progress_query.ProgressQuery:
    policy = session.approved_policy_ref
    workstreams = session.compiled_policy.workstreams

    def lifecycle(workstream_id: str) -> str:
        for workstream in workstreams:
            if workstream.id == workstream_id:
                return workstream.lifecycle
        if session.compiled_policy.scope_rules:
            return session.compiled_policy.scope_rules[0].workstream_lifecycle[0]
        return "active"

    return progress_query.ProgressQuery(
        session.connection,
        now=lambda: datetime.datetime.now(datetime.timezone.utc),
        workstream_lifecycle=lifecycle,
        current_policy_hash=lambda: policy.full_hash,
    )


def query_progress(
    root: Path,
    *,
    workstream_id: Optional[str] = None,
    item_id: Optional[str] = None,
    deferred_state: Optional[str] = None,
    history: bool = False,
) -> ProgressViewReport:
    """Run one read-only progress projection."""

    canonical = _canonical_root(root)
    with ledger_runtime.open_reader_session(canonical) as reader:
        query = _progress_query(reader)
        try:
            if history:
                if not item_id:
                    raise M3WorkflowError("progress history requires --item-id")
                payload = query.history(item_id)
                return ProgressViewReport(view="history", payload=payload)
            if item_id:
                payload = query.item_detail(item_id)
                return ProgressViewReport(view="item", payload=payload)
            if deferred_state is not None:
                payload = query.list_deferred(
                    state=deferred_state,
                    workstream_id=workstream_id,
                )
                return ProgressViewReport(view="deferred", payload=payload)
            if not workstream_id:
                raise M3WorkflowError("progress requires --workstream-id")
            payload = query.workstream_home(workstream_id)
            return ProgressViewReport(view="workstream", payload=payload)
        except progress_query.ProgressQueryError as exc:
            raise M3WorkflowError(str(exc)) from exc


def _batch_terminal(
    root: Path,
    *,
    request: batch_event_service.BatchTerminalRequest,
    actor: str,
) -> BatchTerminalReport:
    canonical = _canonical_root(root)
    try:
        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=actor,
        ) as session:
            control_root = _control_root(session, canonical)
            campaign_row = session.connection.execute(
                "SELECT campaign_id FROM review_batches WHERE batch_id = ?",
                (request.batch_id,),
            ).fetchone()
            if campaign_row is None:
                raise M3WorkflowError("batch campaign binding is missing")
            service = batch_event_service.BatchEventService(
                session.connection,
                batch_event_contract.campaign_event_root(
                    control_root,
                    campaign_row[0],
                ),
                placement_shared=session.placement_shared,
                ledger_exclusive=session.ledger_exclusive,
            )
            if request.event_kind == "close":
                result = service.close(request)
            elif request.event_kind == "abandon":
                result = service.abandon(request)
            else:
                raise M3WorkflowError("batch terminal kind is invalid")
    except (
        batch_event_contract.BatchEventContractError,
        batch_event_service.BatchEventError,
    ) as exc:
        raise M3WorkflowError(str(exc)) from exc
    return BatchTerminalReport(
        event_id=result.event_id,
        event_state=result.event_state,
        event_sha256=result.event_sha256,
        batch_id=result.batch_id,
        batch_status=result.batch_status,
        released_memberships=result.released_memberships,
        final_path=str(result.final_path),
        resumed=result.resumed,
    )


def close_review_batch(
    root: Path,
    *,
    event_id: str,
    batch_id: str,
    expected_snapshot_id: str,
    expected_snapshot_sha256: str,
    expected_review_revision: int,
    expected_execution_generation: int,
    actor: str,
) -> BatchTerminalReport:
    request = batch_event_service.BatchTerminalRequest(
        event_id=_identifier(event_id, "batch event id"),
        batch_id=_identifier(batch_id, "batch id"),
        event_kind="close",
        expected_snapshot_id=_identifier(
            expected_snapshot_id,
            "expected snapshot id",
        ),
        expected_snapshot_sha256=expected_snapshot_sha256,
        expected_review_revision=expected_review_revision,
        expected_execution_generation=expected_execution_generation,
        actor=_identifier(actor, "actor"),
    )
    return _batch_terminal(root, request=request, actor=actor)


def abandon_review_batch(
    root: Path,
    *,
    event_id: str,
    batch_id: str,
    expected_snapshot_id: str,
    expected_snapshot_sha256: str,
    expected_review_revision: int,
    expected_execution_generation: int,
    actor: str,
) -> BatchTerminalReport:
    request = batch_event_service.BatchTerminalRequest(
        event_id=_identifier(event_id, "batch event id"),
        batch_id=_identifier(batch_id, "batch id"),
        event_kind="abandon",
        expected_snapshot_id=_identifier(
            expected_snapshot_id,
            "expected snapshot id",
        ),
        expected_snapshot_sha256=expected_snapshot_sha256,
        expected_review_revision=expected_review_revision,
        expected_execution_generation=expected_execution_generation,
        actor=_identifier(actor, "actor"),
    )
    return _batch_terminal(root, request=request, actor=actor)


def _split_batch_terminal_report(report: SplitReviewBatchReport) -> BatchTerminalReport:
    return BatchTerminalReport(
        event_id=report.event_id,
        event_state=report.state,
        event_sha256="",
        batch_id=report.batch_id,
        batch_status="OPEN",
        released_memberships=0,
        final_path="",
        resumed=report.resumed,
    )


def _batch_terminal_report(result: batch_event_service.BatchEventResult) -> BatchTerminalReport:
    return BatchTerminalReport(
        event_id=result.event_id,
        event_state=result.event_state,
        event_sha256=result.event_sha256,
        batch_id=result.batch_id,
        batch_status=result.batch_status,
        released_memberships=result.released_memberships,
        final_path=str(result.final_path),
        resumed=result.resumed,
    )


def _submission_report(result: review_submission.ReviewSubmissionResult) -> SubmitReviewReport:
    final_path = result.final_path
    return SubmitReviewReport(
        batch_id=result.batch_id,
        snapshot_id=result.snapshot_id,
        submission_id=result.submission_id,
        submission_state=result.submission_state,
        review_revision=result.review_revision,
        execution_generation=result.execution_generation,
        snapshot_sha256=result.snapshot_sha256,
        package_sha256=result.package_sha256,
        final_path=str(final_path),
        review_directory=str(final_path / "review"),
        structural_approval_ready=False,
        resumed=result.resumed,
    )


def _legacy_import_report(result: Dict[str, Any]) -> LegacyImportReport:
    return LegacyImportReport(
        import_run_id=result["import_run_id"],
        preview_sha256=result["preview_sha256"],
        state=result["state"],
        entry_count=len(result["entries"]),
        result_path=str(result["result_path"]),
    )


def _submission_campaign_id(
    connection: sqlite3.Connection,
    submission_id: str,
) -> str:
    row = connection.execute(
        "SELECT payload_json FROM review_submissions WHERE submission_id = ?",
        (_identifier(submission_id, "submission id"),),
    ).fetchone()
    if row is None:
        raise M3WorkflowError("review submission does not exist")
    try:
        envelope = json.loads(_as_bytes(row[0], "stored submission payload").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M3WorkflowError("stored review submission is invalid") from exc
    if type(envelope) is not dict:
        raise M3WorkflowError("stored review submission is invalid")
    for key in ("request", "reopen_request"):
        section = envelope.get(key)
        if type(section) is dict:
            campaign_id = section.get("campaign_id")
            if type(campaign_id) is str and _IDENTIFIER.fullmatch(campaign_id):
                return campaign_id
    raise M3WorkflowError("stored review submission campaign is missing")


def _as_bytes(value: Any, label: str) -> bytes:
    if type(value) is bytes:
        return value
    if type(value) is memoryview:
        return bytes(value)
    raise M3WorkflowError("%s is invalid" % label)


def resume_batch_event(
    root: Path,
    *,
    event_id: str,
    resumed_by: str,
) -> BatchTerminalReport:
    canonical = _canonical_root(root)
    identity = _identifier(event_id, "batch event id")
    actor = _identifier(resumed_by, "resumed_by")
    try:
        with ledger_runtime.open_reader_session(canonical) as reader:
            kind_row = reader.connection.execute(
                "SELECT event_kind FROM batch_events WHERE batch_event_id = ?",
                (identity,),
            ).fetchone()
        if kind_row is not None and kind_row[0] == "SPLIT":
            report = resume_split_batch_event(
                canonical,
                event_id=identity,
                resumed_by=actor,
            )
            return _split_batch_terminal_report(report)
        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=actor,
        ) as session:
            control_root = _control_root(session, canonical)
            campaign_row = session.connection.execute(
                "SELECT b.campaign_id FROM batch_events AS e "
                "JOIN review_batches AS b ON b.batch_id = e.batch_id "
                "WHERE e.batch_event_id = ?",
                (identity,),
            ).fetchone()
            if campaign_row is None:
                raise M3WorkflowError("batch event campaign binding is missing")
            service = batch_event_service.BatchEventService(
                session.connection,
                batch_event_contract.campaign_event_root(
                    control_root,
                    campaign_row[0],
                ),
                placement_shared=session.placement_shared,
                ledger_exclusive=session.ledger_exclusive,
            )
            result = service.resume(identity, resumed_by=actor)
    except (
        batch_event_contract.BatchEventContractError,
        batch_event_service.BatchEventError,
    ) as exc:
        raise M3WorkflowError(str(exc)) from exc
    except M4WorkflowError as exc:
        raise M3WorkflowError(str(exc)) from exc
    return _batch_terminal_report(result)


def resume_legacy_history_import(
    root: Path,
    *,
    import_run_id: str,
    resumed_by: str,
) -> LegacyImportReport:
    canonical = _canonical_root(root)
    legacy_import.require_legacy_import_allowed(canonical)
    try:
        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=resumed_by,
        ) as session:
            result = legacy_import.resume_legacy_history_import(
                canonical,
                session.connection,
                import_run_id=import_run_id,
                resumed_by=resumed_by,
            )
    except legacy_import.LegacyImportError as exc:
        raise M3WorkflowError(str(exc)) from exc
    return _legacy_import_report(result)


def resume_review_submission(
    root: Path,
    *,
    submission_id: str,
    actor: str,
) -> SubmitReviewReport:
    canonical = _canonical_root(root)
    submission_identity = _identifier(submission_id, "submission id")
    actor_identity = _identifier(actor, "actor")
    with ledger_runtime.open_reader_session(canonical) as reader:
        campaign_id = _submission_campaign_id(
            reader.connection,
            submission_identity,
        )
        control_root = _control_root(reader, canonical)
        snapshot_root = control_root / "campaigns" / campaign_id / "snapshots"
    try:
        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=actor_identity,
        ) as session:
            control_root = _control_root(session, canonical)
            resolved_root = control_root / "campaigns" / campaign_id / "snapshots"
            if resolved_root != snapshot_root:
                raise M3WorkflowError("snapshot root changed during submission resume")
            publisher = MinimalDecisionSnapshotPublisher(snapshot_root)
            service = review_submission.ReviewSubmissionPublisher(
                session.connection,
                snapshot_root,
                placement_shared=session.placement_shared,
                ledger_exclusive=session.ledger_exclusive,
                publisher=publisher,
                current_policy=session.current_policy,
            )
            result = service.resume(submission_identity)
    except review_submission.ReviewSubmissionError as exc:
        raise M3WorkflowError(str(exc)) from exc
    return _submission_report(result)


def _metadata_pairs(entries: Tuple[str, ...]) -> Tuple[Tuple[str, Any], ...]:
    pairs: list[Tuple[str, Any]] = []
    for raw in entries:
        if type(raw) is not str or "=" not in raw:
            raise M3WorkflowError("metadata entry is invalid")
        key, _, value_text = raw.partition("=")
        key = key.strip()
        if not key:
            raise M3WorkflowError("metadata entry is invalid")
        try:
            value = json.loads(value_text)
        except json.JSONDecodeError:
            value = value_text
        pairs.append((key, value))
    return tuple(pairs)


def _workstream_lifecycle(session: Any, workstream_id: str) -> str:
    identity = _identifier(workstream_id, "workstream id")
    for workstream in session.compiled_policy.workstreams:
        if workstream.id == identity:
            return workstream.lifecycle
    if session.compiled_policy.scope_rules:
        return session.compiled_policy.scope_rules[0].workstream_lifecycle[0]
    return "active"


def list_deferred(
    root: Path,
    *,
    state: str = "due",
    workstream_id: Optional[str] = None,
) -> ProgressViewReport:
    if state not in ("due", "waiting", "all"):
        raise M3WorkflowError("deferred state filter is invalid")
    return query_progress(
        root,
        workstream_id=workstream_id,
        deferred_state=state,
    )


def query_item_history(root: Path, *, item_id: str) -> ProgressViewReport:
    return query_progress(root, item_id=_identifier(item_id, "item id"), history=True)


def attach_deferral_evidence(
    root: Path,
    *,
    event_id: str,
    deferral_id: str,
    deferral_version: int,
    actor: str,
    scope_class: str,
    allowed_metadata: Tuple[str, ...] = (),
    source_ref: Optional[str] = None,
    content_sha256: Optional[str] = None,
    opaque_source_id: Optional[str] = None,
    actor_attestation: Optional[str] = None,
) -> EvidenceAttachReport:
    if type(deferral_version) is not int or deferral_version < 1:
        raise M3WorkflowError("deferral version is invalid")
    request = deferral_service.EvidenceAttachmentInput(
        event_id=_identifier(event_id, "evidence event id"),
        deferral_id=_identifier(deferral_id, "deferral id"),
        deferral_version=deferral_version,
        actor=_identifier(actor, "actor"),
        scope_class=scope_class,
        allowed_metadata=_metadata_pairs(allowed_metadata),
        source_ref=source_ref,
        content_sha256=content_sha256,
        opaque_source_id=opaque_source_id,
        actor_attestation=actor_attestation,
    )
    canonical = _canonical_root(root)
    try:
        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=request.actor,
        ) as session:
            control_root = _control_root(session, canonical)
            result = deferral_store.attach_deferral_evidence(
                control_root,
                session.connection,
                request,
            )
    except deferral_store.DeferralStoreError as exc:
        raise M3WorkflowError(str(exc)) from exc
    return EvidenceAttachReport(
        event_id=result.event_id,
        deferral_id=result.deferral_id,
        deferral_version=result.deferral_version,
        state=result.state,
        final_path=str(result.final_path),
        final_sha256=result.final_sha256,
        resumed=result.resumed,
    )


def evaluate_deferral_trigger(
    root: Path,
    *,
    deferral_id: str,
    expected_version: int,
    actor: str,
    evidence_event_id: Optional[str] = None,
    manual_reason: Optional[str] = None,
) -> DeferralEvaluateReport:
    if type(expected_version) is not int or expected_version < 1:
        raise M3WorkflowError("expected deferral version is invalid")
    identity = _identifier(deferral_id, "deferral id")
    actor_identity = _identifier(actor, "actor")
    canonical = _canonical_root(root)
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=actor_identity,
        ) as session:
            control_root = _control_root(session, canonical)
            policy = session.current_policy()
            row = session.connection.execute(
                "SELECT trigger_workstream_id FROM deferrals WHERE deferral_id = ?",
                (identity,),
            ).fetchone()
            lifecycle = None
            if row is not None and type(row[0]) is str and row[0]:
                lifecycle = _workstream_lifecycle(session, row[0])
            result = deferral_store.evaluate_deferral(
                control_root,
                session.connection,
                deferral_id=identity,
                expected_version=expected_version,
                actor=actor_identity,
                now=now,
                current_workstream_lifecycle=lifecycle,
                current_policy_hash=policy.full_hash,
                evidence_event_id=evidence_event_id,
                manual_reason=manual_reason,
            )
    except deferral_store.DeferralStoreError as exc:
        raise M3WorkflowError(str(exc)) from exc
    return DeferralEvaluateReport(
        trigger_event_id=result.trigger_event_id,
        deferral_id=result.deferral_id,
        deferral_version=result.deferral_version,
        trigger_kind=result.trigger_kind,
        projection_generation=result.projection_generation,
        repeated=result.repeated,
    )


__all__ = [
    "BatchTerminalReport",
    "DeferralEvaluateReport",
    "EvidenceAttachReport",
    "LegacyImportReport",
    "LegacyPreviewReport",
    "M3WorkflowError",
    "MinimalDecisionSnapshotPublisher",
    "ProgressViewReport",
    "ReopenDecisionReport",
    "SubmitReviewReport",
    "abandon_review_batch",
    "attach_deferral_evidence",
    "close_review_batch",
    "decide",
    "evaluate_deferral_trigger",
    "import_legacy_history",
    "list_deferred",
    "preview_legacy_history_import",
    "query_progress",
    "query_item_history",
    "reopen_decision",
    "reopen_review_decision",
    "resume_batch_event",
    "resume_legacy_history_import",
    "resume_review_submission",
    "submit_review",
    "submit_review_decision",
]
