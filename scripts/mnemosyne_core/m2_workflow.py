"""Thin application workflow for opening one sealed M2 root review."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Tuple, Union

from . import (
    batch_service,
    campaign_ledger,
    explode_service,
    inventory,
    ledger_runtime,
    m2_publishers,
    policy_authority,
    review_context,
    review_draft,
    review_snapshot,
    review_state,
    run_review,
)
from .canonical_json import canonical_json_bytes, sha256_bytes


RENDERER_ID = "mnemosyne-review-m2-v1"
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class M2WorkflowError(RuntimeError):
    """A sealed M2 application operation cannot complete safely."""


@dataclass(frozen=True)
class OpenRootRunReport:
    campaign_id: str
    binding_id: str
    integration_id: str
    snapshot_id: str
    status: str
    snapshot_path: str
    review_directory: str
    snapshot_payload_sha256: str
    resumed: bool

    def __post_init__(self) -> None:
        if self.status != "READY":
            raise M2WorkflowError("root campaign did not reach READY")
        if type(self.resumed) is not bool:
            raise TypeError("resumed must be boolean")


@dataclass(frozen=True)
class OpenBatchReport:
    campaign_id: str
    batch_id: str
    snapshot_id: str
    status: str
    snapshot_state: str
    snapshot_version: int
    review_revision: int
    snapshot_sha256: str
    package_sha256: str
    final_path: str
    review_directory: str
    structural_approval_ready: bool
    structural_blocker: str
    resumed: bool

    def __post_init__(self) -> None:
        if self.status != "OPEN" or self.snapshot_state != "COMMITTED":
            raise M2WorkflowError("batch genesis did not reach OPEN/COMMITTED")
        if self.structural_approval_ready is not False:
            raise M2WorkflowError("M2 batch cannot grant structural authority")
        if self.structural_blocker != "effect-preview-not-available-m2":
            raise M2WorkflowError("M2 structural blocker is missing")


@dataclass(frozen=True)
class ValidateReviewReport:
    snapshot_id: str
    final_path: str
    review_directory: str
    snapshot_sha256: str
    package_sha256: str
    sealed_identity_sha256: str
    review_kind: str
    source_kind: str
    source_id: str
    unit_count: int
    structural_approval_ready: bool

    def __post_init__(self) -> None:
        if type(self.unit_count) is not int or self.unit_count < 0:
            raise M2WorkflowError("validated review unit count is invalid")
        if type(self.structural_approval_ready) is not bool:
            raise TypeError("structural_approval_ready must be boolean")


@dataclass(frozen=True)
class CheckoutReviewReport:
    draft_id: str
    base_snapshot_id: str
    base_snapshot_sha256: str
    actor: str
    final_path: str
    draft_markdown_path: str
    template_markdown_sha256: str
    current_markdown_sha256: str
    authority: bool
    approval_ready: bool

    def __post_init__(self) -> None:
        if self.authority is not False or self.approval_ready is not False:
            raise M2WorkflowError("review draft cannot grant authority or approval")


@dataclass(frozen=True)
class ExplodeReviewUnitReport:
    batch_id: str
    snapshot_id: str
    status: str
    snapshot_state: str
    snapshot_version: int
    review_revision: int
    execution_generation: int
    parent_snapshot_id: str
    parent_snapshot_sha256: str
    snapshot_sha256: str
    package_sha256: str
    final_path: str
    review_directory: str
    structural_approval_ready: bool
    structural_blocker: str
    resumed: bool

    def __post_init__(self) -> None:
        if self.status != "OPEN" or self.snapshot_state != "PUBLISHED":
            raise M2WorkflowError("exploded batch did not reach OPEN/PUBLISHED")
        if self.structural_approval_ready is not False:
            raise M2WorkflowError("exploded M2 batch cannot grant structural authority")
        if self.structural_blocker != "effect-preview-not-available-m2":
            raise M2WorkflowError("exploded M2 structural blocker is missing")


def _canonical_root(root: Path) -> Path:
    value = Path(root)
    if not value.is_absolute() or any(part in (".", "..") for part in value.parts):
        raise M2WorkflowError("raw root must be a canonical absolute path")
    return value


def _control_root(
    session: Union[ledger_runtime.ReaderSession, ledger_runtime.WriterSession],
    root: Path,
) -> Path:
    control_root = Path(session.compiled_policy.foundation.state_root)
    if control_root != root / "_registry" / "curation":
        raise M2WorkflowError("policy control root is not canonical")
    return control_root


def _uuid4(value: str) -> uuid.UUID:
    if not isinstance(value, str):
        raise M2WorkflowError("identity supplier must return text")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise M2WorkflowError("identity supplier returned an invalid UUID") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise M2WorkflowError("identity supplier must return canonical UUID4")
    return parsed


def _new_id(prefix: str, supplier: Callable[[], str]) -> str:
    return "%s-%s" % (prefix, _uuid4(supplier()).hex)


def _default_id_supplier() -> str:
    return str(uuid.uuid4())


def _relative_to_root(root: Path, path: str) -> str:
    candidate = Path(path)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise M2WorkflowError("sealed inventory path escapes raw root") from exc
    if not relative.parts or any(part in (".", "..") for part in relative.parts):
        raise M2WorkflowError("sealed inventory path is invalid")
    return relative.as_posix()


def _campaign_paths(
    campaign_id: str,
    binding_id: str,
    snapshot_id: str,
) -> tuple[str, str, str]:
    prefix = "campaigns/%s" % campaign_id
    return (
        "%s/campaign.json" % prefix,
        "%s/run-bindings/%s/binding.json" % (prefix, binding_id),
        "%s/snapshots/%s" % (prefix, snapshot_id),
    )


def _root_publishers(
    control_root: Path,
    request: campaign_ledger.RootRunRequest,
) -> Tuple[object, object]:
    snapshot_root = control_root / "campaigns" / request.campaign_id / "snapshots"
    review_publisher = review_snapshot.ReviewSnapshotPublisher(
        snapshot_root,
        renderer_id=RENDERER_ID,
    )
    return (
        m2_publishers.CampaignArtifactPublisher(control_root),
        m2_publishers.CampaignReviewPublisherAdapter(
            control_root,
            review_publisher=review_publisher,
            review_document_factory=(
                run_review.review_document_from_campaign_snapshot
            ),
        ),
    )


def _binder(
    session: object,
    *,
    campaign_publisher: object,
    integration_publisher: object,
) -> campaign_ledger.CampaignRunBinder:
    return campaign_ledger.CampaignRunBinder(
        connection=session.connection,
        placement_shared=session.placement_shared,
        ledger_exclusive=session.ledger_exclusive,
        current_policy=session.current_policy,
        campaign_publisher=campaign_publisher,
        integration_publisher=integration_publisher,
    )


def _report(
    control_root: Path,
    request: campaign_ledger.RootRunRequest,
    result: campaign_ledger.CampaignOpenResult,
) -> OpenRootRunReport:
    if not isinstance(result, campaign_ledger.CampaignOpenResult):
        raise M2WorkflowError("campaign binder returned an invalid result")
    if (
        result.campaign_id,
        result.binding_id,
        result.integration_id,
        result.snapshot_id,
        result.snapshot_payload_json,
    ) != (
        request.campaign_id,
        request.binding_id,
        request.integration_id,
        request.snapshot_id,
        request.snapshot_payload_json,
    ):
        raise M2WorkflowError("campaign binder result changed root identity")
    final_path = control_root.joinpath(*Path(request.snapshot_path).parts)
    return OpenRootRunReport(
        campaign_id=result.campaign_id,
        binding_id=result.binding_id,
        integration_id=result.integration_id,
        snapshot_id=result.snapshot_id,
        status=result.status,
        snapshot_path=str(final_path),
        review_directory=str(final_path / "review"),
        snapshot_payload_sha256=sha256_bytes(result.snapshot_payload_json),
        resumed=result.resumed,
    )


def _stored_root_request(
    connection: sqlite3.Connection,
    run_id: str,
) -> Optional[campaign_ledger.RootRunRequest]:
    row = connection.execute(
        "SELECT request_json FROM campaign_run_bindings WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if row is None:
        return None
    request = campaign_ledger.RootRunRequest.from_canonical_bytes(bytes(row[0]))
    if request.run_id != run_id:
        raise M2WorkflowError("stored root request run identity changed")
    return request


def _require_requested_campaign(
    request: campaign_ledger.RootRunRequest,
    campaign_id: Optional[str],
) -> None:
    if campaign_id is not None and campaign_id != request.campaign_id:
        raise M2WorkflowError("run is already bound to a different campaign")


def _prepare_root_publication(
    control_root: Path,
    request: campaign_ledger.RootRunRequest,
) -> Tuple[
    object,
    object,
    campaign_ledger.PreparedRootPublication,
]:
    campaign_publisher, integration_publisher = _root_publishers(
        control_root,
        request,
    )
    prepared = campaign_ledger.prepare_root_publication(
        request,
        campaign_publisher=campaign_publisher,
        integration_publisher=integration_publisher,
    )
    return campaign_publisher, integration_publisher, prepared


def _resume_prepared_root_request(
    canonical: Path,
    *,
    opened_by: str,
    requested_campaign_id: Optional[str],
    expected_control_root: Path,
    request: campaign_ledger.RootRunRequest,
    campaign_publisher: object,
    integration_publisher: object,
    prepared: campaign_ledger.PreparedRootPublication,
) -> OpenRootRunReport:
    with ledger_runtime.open_writer_session(
        canonical,
        observed_by=opened_by,
    ) as session:
        control_root = _control_root(session, canonical)
        if control_root != expected_control_root:
            raise M2WorkflowError("policy control root changed during preparation")
        existing_request = _stored_root_request(
            session.connection,
            request.run_id,
        )
        if existing_request is None:
            raise M2WorkflowError("stored root binding disappeared during resume")
        _require_requested_campaign(existing_request, requested_campaign_id)
        if existing_request.canonical_bytes() != request.canonical_bytes():
            raise M2WorkflowError("stored root request changed during resume")
        if session.approved_policy_ref != request.policy:
            raise M2WorkflowError("approved policy changed during root preparation")
        if session.current_policy() != request.policy:
            raise M2WorkflowError("approved policy changed during root preparation")
        result = _binder(
            session,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        ).resume_prepared_root_run(request.run_id, prepared)
        return _report(control_root, request, result)


def _latched_reader_policy_observation(session: object) -> Optional[object]:
    verifier = getattr(session, "_policy_verifier", None)
    filesystem_guard = getattr(verifier, "filesystem_guard", None)
    observation = getattr(filesystem_guard, "observation", None)
    return observation


def _require_new_root_snapshot_v2(snapshot_payload_json: bytes) -> None:
    try:
        payload = json.loads(snapshot_payload_json.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M2WorkflowError("new root review snapshot is invalid") from exc
    if type(payload) is not dict or payload.get("schema_version") != 2:
        raise M2WorkflowError(
            "new root review snapshot must use schema version 2"
        )


def _campaign_head_identity(
    connection: sqlite3.Connection,
    campaign_id: str,
) -> Tuple[Any, ...]:
    row = connection.execute(
        "SELECT status, current_snapshot_id, current_snapshot_sha256, "
        "review_revision FROM campaigns WHERE campaign_id = ?",
        (campaign_id,),
    ).fetchone()
    if row is None:
        raise M2WorkflowError("campaign head disappeared during preparation")
    return tuple(row)


def _batch_head_identity(
    connection: sqlite3.Connection,
    batch_id: str,
) -> Tuple[Any, ...]:
    row = connection.execute(
        "SELECT campaign_id, status, current_snapshot_id, "
        "current_snapshot_sha256, review_revision, execution_generation "
        "FROM review_batches WHERE batch_id = ?",
        (batch_id,),
    ).fetchone()
    if row is None:
        raise M2WorkflowError("batch head disappeared during preparation")
    return tuple(row)


def _snapshot_package_identity(
    connection: sqlite3.Connection,
    snapshot_id: str,
) -> Tuple[Any, ...]:
    row = connection.execute(
        "SELECT lineage_kind, campaign_id, batch_id, version, payload_sha256, "
        "final_path, final_sha256, state, structural_approval_ready "
        "FROM review_snapshots WHERE snapshot_id = ?",
        (snapshot_id,),
    ).fetchone()
    if row is None:
        raise M2WorkflowError("sealed snapshot package binding disappeared")
    return tuple(row)


_SEALED_PACKAGE_MEMBERS = (
    ("", "directory"),
    ("manifest.json", "file"),
    ("review", "directory"),
    ("review/review.html", "file"),
    ("review/review.md", "file"),
    ("review/review.meta.json", "file"),
    ("snapshot.json", "file"),
)


def _sealed_member_identity(
    final_path: Path,
    relative_path: str,
    kind: str,
) -> Tuple[Any, ...]:
    path = final_path if not relative_path else final_path / relative_path
    try:
        info = path.lstat()
    except OSError as exc:
        raise M2WorkflowError("sealed package member is unreadable") from exc
    expected_mode = 0o700 if kind == "directory" else 0o600
    expected_kind = stat.S_ISDIR if kind == "directory" else stat.S_ISREG
    if (
        not expected_kind(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != expected_mode
        or (kind == "file" and info.st_nlink != 1)
    ):
        raise M2WorkflowError("sealed package member identity is invalid")
    return (
        relative_path,
        info.st_dev,
        info.st_ino,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _sealed_package_filesystem_identity(
    final_path: Path,
) -> Tuple[Tuple[Any, ...], ...]:
    first = tuple(
        _sealed_member_identity(final_path, relative_path, kind)
        for relative_path, kind in _SEALED_PACKAGE_MEMBERS
    )
    second = tuple(
        _sealed_member_identity(final_path, relative_path, kind)
        for relative_path, kind in _SEALED_PACKAGE_MEMBERS
    )
    if first != second:
        raise M2WorkflowError("sealed package identity changed during observation")
    return second


def _sealed_package_witness(
    snapshot: review_state.SealedReviewSnapshot,
) -> Tuple[Tuple[Any, ...], ...]:
    before = _sealed_package_filesystem_identity(snapshot.final_path)
    reloaded = review_state.read_sealed_review_snapshot(
        snapshot.final_path,
        expected_snapshot_id=snapshot.snapshot_id,
        expected_snapshot_sha256=snapshot.snapshot_sha256,
        expected_package_sha256=snapshot.package_sha256,
    )
    after = _sealed_package_filesystem_identity(snapshot.final_path)
    if before != after or reloaded != snapshot:
        raise M2WorkflowError(
            "sealed package changed during exact reader readback"
        )
    return after


def _require_live_package_witness(
    snapshot: review_state.SealedReviewSnapshot,
    expected: Tuple[Tuple[Any, ...], ...],
) -> None:
    if _sealed_package_filesystem_identity(snapshot.final_path) != expected:
        raise M2WorkflowError(
            "sealed package filesystem identity changed during preparation"
        )


def _require_campaign_head_capture(
    head: review_state.CampaignReviewHead,
    head_identity: Tuple[Any, ...],
    package_identity: Tuple[Any, ...],
    *,
    control_root: Path,
) -> None:
    expected_head = (
        "READY",
        head.current_snapshot_id,
        head.current_snapshot_sha256,
        head.review_revision,
    )
    if head_identity != expected_head:
        raise M2WorkflowError("verified campaign head changed during reader capture")
    raw_final_path = package_identity[5]
    candidate = Path(raw_final_path)
    captured_final_path = candidate if candidate.is_absolute() else control_root / candidate
    if captured_final_path != head.snapshot.final_path:
        raise M2WorkflowError("sealed campaign package path is inconsistent")
    expected_package = (
        "CAMPAIGN",
        head.campaign_id,
        None,
        head.review_revision,
        head.current_snapshot_sha256,
        raw_final_path,
        head.snapshot.package_sha256,
        "PUBLISHED",
        int(bool(head.snapshot.payload["structural_approval_ready"])),
    )
    if package_identity != expected_package:
        raise M2WorkflowError("sealed campaign package binding is inconsistent")


def _require_batch_head_capture(
    head: review_state.BatchReviewHead,
    head_identity: Tuple[Any, ...],
    package_identity: Tuple[Any, ...],
    *,
    control_root: Path,
) -> None:
    expected_head = (
        head.campaign_id,
        "OPEN",
        head.current_snapshot_id,
        head.current_snapshot_sha256,
        head.review_revision,
        head.execution_generation,
    )
    if head_identity != expected_head:
        raise M2WorkflowError("verified batch head changed during reader capture")
    _require_batch_package_capture(
        head.snapshot,
        package_identity,
        campaign_id=head.campaign_id,
        batch_id=head.batch_id,
        review_revision=head.review_revision,
        snapshot_id=head.current_snapshot_id,
        snapshot_sha256=head.current_snapshot_sha256,
        control_root=control_root,
    )


def _require_batch_package_capture(
    snapshot: review_state.SealedReviewSnapshot,
    package_identity: Tuple[Any, ...],
    *,
    campaign_id: str,
    batch_id: str,
    review_revision: int,
    snapshot_id: str,
    snapshot_sha256: str,
    control_root: Path,
) -> None:
    if (
        snapshot.snapshot_id != snapshot_id
        or snapshot.snapshot_sha256 != snapshot_sha256
    ):
        raise M2WorkflowError("sealed batch package changed requested identity")
    raw_final_path = package_identity[5]
    candidate = Path(raw_final_path)
    captured_final_path = candidate if candidate.is_absolute() else control_root / candidate
    if captured_final_path != snapshot.final_path:
        raise M2WorkflowError("sealed batch package path is inconsistent")
    expected_package = (
        "BATCH",
        campaign_id,
        batch_id,
        review_revision,
        snapshot_sha256,
        raw_final_path,
        snapshot.package_sha256,
        "PUBLISHED",
        int(bool(snapshot.payload["structural_approval_ready"])),
    )
    if package_identity != expected_package:
        raise M2WorkflowError("sealed batch package binding is inconsistent")


def open_root_run(
    root: Path,
    *,
    run_id: str,
    opened_by: str,
    rendered_at: str,
    campaign_id: Optional[str] = None,
    id_supplier: Callable[[], str] = _default_id_supplier,
) -> OpenRootRunReport:
    """Open or exactly resume the one root campaign bound to a sealed run."""

    canonical = _canonical_root(root)
    if not isinstance(run_id, str) or not run_id:
        raise M2WorkflowError("run_id is required")
    if (
        not isinstance(opened_by, str)
        or not opened_by.strip()
        or opened_by != opened_by.strip()
    ):
        raise M2WorkflowError("opened_by is invalid")
    if not isinstance(rendered_at, str) or _TIME.fullmatch(rendered_at) is None:
        raise M2WorkflowError("rendered_at must be canonical UTC seconds")
    if not callable(id_supplier):
        raise TypeError("id_supplier must be callable")
    try:
        prepared_package = None
        prepared_compiled_policy = None
        prepared_policy = None
        prepared_request = None
        reader_request = None
        reader_control_root = None
        reader_policy_observation = None
        reader_policy_error = None
        with ledger_runtime.open_reader_session(canonical) as reader:
            reader_control_root = _control_root(reader, canonical)
            reader_request = _stored_root_request(reader.connection, run_id)
            if reader_request is not None:
                _require_requested_campaign(reader_request, campaign_id)
            else:
                prepared_package = inventory.InventoryRunStore(
                    Path(reader.compiled_policy.foundation.runs_root)
                ).read_complete_package(run_id)
                prepared_compiled_policy = reader.compiled_policy
                prepared_policy = reader.approved_policy_ref
                try:
                    reader.current_policy()
                except ledger_runtime.LedgerRuntimeError as exc:
                    reader_policy_observation = _latched_reader_policy_observation(
                        reader
                    )
                    if reader_policy_observation is None:
                        raise
                    reader_policy_error = exc

        if reader_policy_observation is not None:
            try:
                recorded = (
                    policy_authority.observe_policy_drift_from_stable_observation(
                        canonical,
                        observed_by=opened_by,
                        observed_raw=reader_policy_observation.observed_raw,
                        observed_identity=reader_policy_observation.observed_identity,
                        expected_head_generation=(
                            reader_policy_observation.expected_head_generation
                        ),
                        expected_head_full_hash=(
                            reader_policy_observation.expected_head_full_hash
                        ),
                        expected_guard_epoch=(
                            reader_policy_observation.expected_guard_epoch
                        ),
                    )
                )
            except Exception as exc:
                error = M2WorkflowError(
                    "policy drift was detected but its guard record failed"
                )
                if reader_policy_error is not None:
                    error.__context__ = reader_policy_error
                raise error from exc
            error = M2WorkflowError(
                "policy drift recorded: episode %s event %s"
                % (recorded["episode_id"], recorded["event_id"])
            )
            if reader_policy_error is not None:
                raise error from reader_policy_error
            raise error

        if reader_request is None:
            if (
                prepared_package is None
                or prepared_compiled_policy is None
                or prepared_policy is None
            ):
                raise M2WorkflowError("root review preparation state is incomplete")
            selected_campaign_id = campaign_id or _new_id(
                "campaign",
                id_supplier,
            )
            binding_id = _new_id("binding", id_supplier)
            integration_id = _new_id("integration", id_supplier)
            submission_id = _new_id("submission", id_supplier)
            snapshot_id = _new_id("snapshot", id_supplier)
            paths = run_review.root_review_item_paths(prepared_package)
            item_ids_by_path = {
                path: str(_uuid4(id_supplier())) for path in paths
            }
            prepared = run_review.prepare_root_review(
                prepared_package,
                prepared_compiled_policy,
                prepared_policy,
                campaign_id=selected_campaign_id,
                snapshot_id=snapshot_id,
                rendered_at=rendered_at,
                item_ids_by_path=item_ids_by_path,
            )
            _require_new_root_snapshot_v2(prepared.snapshot_payload_json)
            campaign_path, binding_path, snapshot_path = _campaign_paths(
                selected_campaign_id,
                binding_id,
                snapshot_id,
            )
            prepared_request = campaign_ledger.RootRunRequest(
                run_id=run_id,
                run_sha256=prepared_package.terminal.package_sha256,
                run_package_path=_relative_to_root(
                    canonical,
                    prepared_package.terminal.path,
                ),
                manifest_sha256=prepared_package.terminal.package_sha256,
                policy=prepared_policy,
                campaign_id=selected_campaign_id,
                binding_id=binding_id,
                integration_id=integration_id,
                submission_id=submission_id,
                snapshot_id=snapshot_id,
                campaign_path=campaign_path,
                binding_path=binding_path,
                snapshot_path=snapshot_path,
                import_plan=prepared.import_plan,
                opened_by=opened_by,
                snapshot_payload_json=prepared.snapshot_payload_json,
            )

        plan_request = reader_request or prepared_request
        if plan_request is None or reader_control_root is None:
            raise M2WorkflowError("root publication preparation is incomplete")
        (
            campaign_publisher,
            integration_publisher,
            prepared_publication,
        ) = _prepare_root_publication(reader_control_root, plan_request)

        if reader_request is not None:
            return _resume_prepared_root_request(
                canonical,
                opened_by=opened_by,
                requested_campaign_id=campaign_id,
                expected_control_root=reader_control_root,
                request=reader_request,
                campaign_publisher=campaign_publisher,
                integration_publisher=integration_publisher,
                prepared=prepared_publication,
            )

        concurrent_request = None
        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=opened_by,
        ) as session:
            control_root = _control_root(session, canonical)
            if control_root != reader_control_root:
                raise M2WorkflowError("policy control root changed during preparation")

            existing_request = _stored_root_request(session.connection, run_id)
            if existing_request is not None:
                _require_requested_campaign(existing_request, campaign_id)
                concurrent_request = existing_request
            else:
                if prepared_request is None or prepared_package is None:
                    raise M2WorkflowError(
                        "stored root binding disappeared during resume"
                    )
                if session.approved_policy_ref != prepared_request.policy:
                    raise M2WorkflowError(
                        "approved policy changed during root preparation"
                    )
                if session.current_policy() != prepared_request.policy:
                    raise M2WorkflowError(
                        "approved policy changed during root preparation"
                    )
                current_package = inventory.InventoryRunStore(
                    Path(session.compiled_policy.foundation.runs_root)
                ).read_complete_package(run_id)
                if current_package != prepared_package:
                    raise M2WorkflowError(
                        "sealed inventory package changed during root preparation"
                    )
                result = _binder(
                    session,
                    campaign_publisher=campaign_publisher,
                    integration_publisher=integration_publisher,
                ).open_prepared_root_run(
                    prepared_request,
                    prepared_publication,
                )
                return _report(control_root, prepared_request, result)

        if concurrent_request is None:
            raise M2WorkflowError("concurrent root binding state is incomplete")
        (
            concurrent_campaign_publisher,
            concurrent_integration_publisher,
            concurrent_publication,
        ) = _prepare_root_publication(reader_control_root, concurrent_request)
        return _resume_prepared_root_request(
            canonical,
            opened_by=opened_by,
            requested_campaign_id=campaign_id,
            expected_control_root=reader_control_root,
            request=concurrent_request,
            campaign_publisher=concurrent_campaign_publisher,
            integration_publisher=concurrent_integration_publisher,
            prepared=concurrent_publication,
        )
    except M2WorkflowError:
        raise
    except (
        campaign_ledger.CampaignLedgerError,
        inventory.InventoryError,
        ledger_runtime.LedgerRuntimeError,
        run_review.RunReviewError,
        sqlite3.Error,
        TypeError,
        ValueError,
    ) as exc:
        raise M2WorkflowError(str(exc)) from exc


def open_batch(
    root: Path,
    *,
    campaign_id: str,
    unit_ids: tuple[str, ...],
    batch_id: str,
    snapshot_id: str,
    submission_id: str,
    actor: str,
    max_items: int,
    max_files: int,
    max_bytes: int,
    max_effects: int,
) -> OpenBatchReport:
    """Open or exactly retry one bounded batch from a verified campaign head."""

    canonical = _canonical_root(root)
    try:
        with ledger_runtime.open_reader_session(canonical) as reader:
            reader_control_root = _control_root(reader, canonical)
            head = review_state.CampaignHeadLoader(
                reader.connection,
                reader_control_root,
            ).load(campaign_id, unit_ids)
            if head.snapshot.schema_version != 2:
                raise M2WorkflowError(
                    "COW-normalization-required: campaign head uses snapshot v1"
                )
            analysis_contexts = (
                review_context.AnalysisContextBundle.from_canonical_bytes(
                    head.snapshot.analysis_contexts_json
                ).select_for_units(head.units)
            )
            try:
                context_value = head.snapshot.payload["review_context"]
            except (AttributeError, KeyError) as exc:
                raise M2WorkflowError(
                    "campaign head has no restart-safe review context"
                ) from exc
            campaign_context = review_context.ReviewContext.from_canonical_bytes(
                canonical_json_bytes(context_value)
            )
            selected_context = review_context.ReviewContext(
                rendered_at=campaign_context.rendered_at,
                policy_binding=campaign_context.policy_binding,
                coverage=campaign_context.coverage,
                workstreams=(
                    review_context.workstream_summaries_for_unit_payloads(
                        tuple(unit.to_dict() for unit in head.units),
                        campaign_context,
                    )
                ),
                warning_codes=campaign_context.warning_codes,
            )
            context_json = selected_context.canonical_bytes()
            prepared_policy = reader.approved_policy_ref
            if reader.current_policy() != prepared_policy:
                raise M2WorkflowError(
                    "approved policy changed during batch reader capture"
                )
            prepared_head_identity = _campaign_head_identity(
                reader.connection,
                head.campaign_id,
            )
            prepared_package_identity = _snapshot_package_identity(
                reader.connection,
                head.current_snapshot_id,
            )
            _require_campaign_head_capture(
                head,
                prepared_head_identity,
                prepared_package_identity,
                control_root=reader_control_root,
            )
            prepared_filesystem_witness = _sealed_package_witness(
                head.snapshot
            )
            snapshot_root = (
                reader_control_root
                / "campaigns"
                / head.campaign_id
                / "snapshots"
            )

        request = batch_service.OpenBatchRequest(
            campaign_id=head.campaign_id,
            expected_campaign_head_sha256=head.current_snapshot_sha256,
            expected_campaign_review_revision=head.review_revision,
            policy=prepared_policy,
            batch_id=batch_id,
            snapshot_id=snapshot_id,
            submission_id=submission_id,
            actor=actor,
            review_context_json=context_json,
            analysis_contexts_json=analysis_contexts.canonical_bytes,
            units=head.units,
            max_items=max_items,
            max_files=max_files,
            max_bytes=max_bytes,
            max_effects=max_effects,
        )
        review_publisher = review_snapshot.ReviewSnapshotPublisher(
            snapshot_root,
            renderer_id=RENDERER_ID,
        )
        publisher = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=review_publisher,
            review_document_factory=(
                review_context.batch_review_document_from_snapshot
            ),
        )
        prepared_publication = batch_service.prepare_batch_publication(
            snapshot_root,
            publisher,
            request,
        )

        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=actor,
        ) as session:
            control_root = _control_root(session, canonical)
            if control_root != reader_control_root:
                raise M2WorkflowError(
                    "policy control root changed during batch preparation"
                )
            if session.approved_policy_ref != prepared_policy:
                raise M2WorkflowError(
                    "approved policy changed during batch preparation"
                )
            if session.current_policy() != prepared_policy:
                raise M2WorkflowError(
                    "approved policy changed during batch preparation"
                )
            if (
                _campaign_head_identity(session.connection, head.campaign_id)
                != prepared_head_identity
            ):
                raise M2WorkflowError(
                    "campaign head changed during batch preparation"
                )
            if (
                _snapshot_package_identity(
                    session.connection,
                    head.current_snapshot_id,
                )
                != prepared_package_identity
            ):
                raise M2WorkflowError(
                    "sealed campaign package changed during batch preparation"
                )
            _require_live_package_witness(
                head.snapshot,
                prepared_filesystem_witness,
            )
            service = batch_service.BatchService(
                session.connection,
                snapshot_root,
                placement_shared=session.placement_shared,
                ledger_exclusive=session.ledger_exclusive,
                publisher=publisher,
                current_policy=session.current_policy,
                canonical_root=canonical,
            )
            result = service.open_prepared_batch(
                request,
                prepared_publication,
            )
            if not isinstance(result, batch_service.OpenBatchResult):
                raise M2WorkflowError("batch service returned an invalid result")
            if (
                result.batch_id != request.batch_id
                or result.snapshot_id != request.snapshot_id
                or result.final_path != snapshot_root / request.snapshot_id
            ):
                raise M2WorkflowError("batch result changed requested identity")
            return OpenBatchReport(
                campaign_id=head.campaign_id,
                batch_id=result.batch_id,
                snapshot_id=result.snapshot_id,
                status=result.status,
                snapshot_state=result.snapshot_state,
                snapshot_version=result.snapshot_version,
                review_revision=result.review_revision,
                snapshot_sha256=result.snapshot_sha256,
                package_sha256=result.package_sha256,
                final_path=str(result.final_path),
                review_directory=str(result.final_path / "review"),
                structural_approval_ready=(
                    result.structural_approval_ready
                ),
                structural_blocker=result.structural_blocker,
                resumed=result.resumed,
            )
    except M2WorkflowError:
        raise
    except (
        batch_service.BatchServiceError,
        ledger_runtime.LedgerRuntimeError,
        review_context.ReviewContextError,
        review_snapshot.ReviewSnapshotError,
        review_state.ReviewStateError,
        sqlite3.Error,
        TypeError,
        ValueError,
    ) as exc:
        raise M2WorkflowError(str(exc)) from exc


def validate_review(
    root: Path,
    *,
    snapshot_id: str,
) -> ValidateReviewReport:
    """Validate one ledger-published review by identifier without any write."""

    canonical = _canonical_root(root)
    try:
        with ledger_runtime.open_reader_session(canonical) as session:
            control_root = _control_root(session, canonical)
            sealed = review_state.ReviewSnapshotLoader(
                session.connection,
                control_root,
            ).load(snapshot_id)
            try:
                structural = sealed.payload["structural_approval_ready"]
            except (AttributeError, KeyError) as exc:
                raise M2WorkflowError(
                    "sealed review has no structural authority marker"
                ) from exc
            return ValidateReviewReport(
                snapshot_id=sealed.snapshot_id,
                final_path=str(sealed.final_path),
                review_directory=str(sealed.final_path / "review"),
                snapshot_sha256=sealed.snapshot_sha256,
                package_sha256=sealed.package_sha256,
                sealed_identity_sha256=sealed.sealed_identity_sha256,
                review_kind=sealed.review_kind,
                source_kind=sealed.source_kind,
                source_id=sealed.source_id,
                unit_count=len(sealed.units),
                structural_approval_ready=structural,
            )
    except M2WorkflowError:
        raise
    except (
        ledger_runtime.LedgerRuntimeError,
        review_state.ReviewStateError,
        sqlite3.Error,
        TypeError,
        ValueError,
    ) as exc:
        raise M2WorkflowError(str(exc)) from exc


def _stored_explode_envelope(
    connection: sqlite3.Connection,
    submission_id: str,
) -> Optional[Tuple[str, bytes]]:
    row = connection.execute(
        "SELECT campaign_id, payload_json, payload_sha256, state "
        "FROM review_submissions "
        "WHERE submission_id = ?",
        (submission_id,),
    ).fetchone()
    if row is None:
        return None
    campaign_id, payload, payload_sha256, state = tuple(row)
    raw = bytes(payload)
    if (
        type(campaign_id) is not str
        or _IDENTIFIER.fullmatch(campaign_id) is None
        or sha256_bytes(raw) != payload_sha256
        or state not in ("PREPARED", "COMMITTED")
    ):
        raise M2WorkflowError("stored explode submission is not exactly resumable")
    return campaign_id, raw


def explode_review_unit(
    root: Path,
    *,
    batch_id: str,
    snapshot_id: str,
    snapshot_sha256: str,
    folder_unit_id: str,
    next_snapshot_id: str,
    submission_id: str,
    actor: str,
) -> ExplodeReviewUnitReport:
    """Expand one current folder unit into a copy-on-write sealed snapshot."""

    canonical = _canonical_root(root)
    try:
        expected_identity = explode_service.ExplodeInvocationIdentity(
            batch_id=batch_id,
            expected_snapshot_id=snapshot_id,
            expected_snapshot_sha256=snapshot_sha256,
            folder_unit_id=folder_unit_id,
            next_snapshot_id=next_snapshot_id,
            submission_id=submission_id,
            actor=actor,
        )
        with ledger_runtime.open_reader_session(canonical) as reader:
            reader_control_root = _control_root(reader, canonical)
            prepared_policy = reader.approved_policy_ref
            stored = _stored_explode_envelope(
                reader.connection,
                submission_id,
            )
            if stored is None:
                head = review_state.BatchHeadLoader(
                    reader.connection,
                    reader_control_root,
                ).load(batch_id, (folder_unit_id,))
                if (
                    head.current_snapshot_id != snapshot_id
                    or head.current_snapshot_sha256 != snapshot_sha256
                ):
                    raise M2WorkflowError("requested batch snapshot is not current")
                if head.snapshot.schema_version != 2:
                    raise M2WorkflowError(
                        "COW-normalization-required: batch head uses snapshot v1"
                    )
                analysis_contexts = (
                    review_context.AnalysisContextBundle.from_canonical_bytes(
                        head.snapshot.analysis_contexts_json
                    )
                )
                request = explode_service.ExplodeReviewUnitRequest(
                    batch_id=head.batch_id,
                    expected_snapshot_id=head.current_snapshot_id,
                    expected_snapshot_sha256=head.current_snapshot_sha256,
                    expected_review_revision=head.review_revision,
                    expected_execution_generation=head.execution_generation,
                    policy=prepared_policy,
                    folder_unit_id=folder_unit_id,
                    next_snapshot_id=next_snapshot_id,
                    submission_id=submission_id,
                    actor=actor,
                    analysis_contexts_json=analysis_contexts.canonical_bytes,
                )
                campaign_id = head.campaign_id
                base_snapshot = head.snapshot
            else:
                campaign_id, _stored_envelope = stored

            snapshot_root = (
                reader_control_root
                / "campaigns"
                / campaign_id
                / "snapshots"
            )
            publisher = m2_publishers.BatchReviewPublisherAdapter(
                review_publisher=review_snapshot.ReviewSnapshotPublisher(
                    snapshot_root,
                    renderer_id=RENDERER_ID,
                ),
                review_document_factory=(
                    explode_service.exploded_batch_review_document_from_snapshot
                ),
            )
            transition_preparer = explode_service.ExplodeTransitionPreparer(
                reader.connection,
                reader_control_root,
                publisher,
            )
            if stored is None:
                transition = transition_preparer.prepare(request, head)
            else:
                transition = transition_preparer.from_stored(
                    _stored_envelope,
                    policy=prepared_policy,
                    expected_identity=expected_identity,
                )
                request = transition.request
                base_snapshot = review_state.ReviewSnapshotLoader(
                    reader.connection,
                    reader_control_root,
                ).load(request.expected_snapshot_id)
                if base_snapshot.schema_version != 2:
                    raise M2WorkflowError(
                        "COW-normalization-required: batch head uses snapshot v1"
                    )
                try:
                    campaign_id = base_snapshot.payload["campaign_id"]
                    base_batch_id = base_snapshot.payload["batch_id"]
                    base_version = base_snapshot.payload["batch_version"]
                except (AttributeError, KeyError) as exc:
                    raise M2WorkflowError(
                        "stored explode base snapshot is invalid"
                    ) from exc
                if (
                    base_batch_id != request.batch_id
                    or base_version != request.expected_review_revision
                ):
                    raise M2WorkflowError(
                        "stored explode base snapshot changed lineage"
                    )

            if (
                transition.request != request
                or transition.campaign_id != campaign_id
            ):
                raise M2WorkflowError("prepared explode transition changed identity")

            prepared_head_identity = _batch_head_identity(
                reader.connection,
                request.batch_id,
            )
            prepared_package_identity = _snapshot_package_identity(
                reader.connection,
                request.expected_snapshot_id,
            )
            if stored is None:
                _require_batch_head_capture(
                    head,
                    prepared_head_identity,
                    prepared_package_identity,
                    control_root=reader_control_root,
                )
            else:
                _require_batch_package_capture(
                    base_snapshot,
                    prepared_package_identity,
                    campaign_id=campaign_id,
                    batch_id=request.batch_id,
                    review_revision=request.expected_review_revision,
                    snapshot_id=request.expected_snapshot_id,
                    snapshot_sha256=request.expected_snapshot_sha256,
                    control_root=reader_control_root,
                )
            prepared_filesystem_witness = _sealed_package_witness(
                base_snapshot
            )
            if reader.current_policy() != prepared_policy:
                raise M2WorkflowError(
                    "approved policy changed during explode reader preparation"
                )

        with ledger_runtime.open_writer_session(
            canonical,
            observed_by=actor,
        ) as session:
            control_root = _control_root(session, canonical)
            if control_root != reader_control_root:
                raise M2WorkflowError(
                    "policy control root changed during explode preparation"
                )
            if session.approved_policy_ref != prepared_policy:
                raise M2WorkflowError(
                    "approved policy changed during explode preparation"
                )
            if session.current_policy() != prepared_policy:
                raise M2WorkflowError(
                    "approved policy changed during explode preparation"
                )
            if (
                _snapshot_package_identity(
                    session.connection,
                    request.expected_snapshot_id,
                )
                != prepared_package_identity
            ):
                raise M2WorkflowError(
                    "sealed batch package changed during explode preparation"
                )
            observed_head_identity = _batch_head_identity(
                session.connection,
                request.batch_id,
            )
            expected_base_identity = (
                campaign_id,
                "OPEN",
                request.expected_snapshot_id,
                request.expected_snapshot_sha256,
                request.expected_review_revision,
                request.expected_execution_generation,
            )
            expected_winner_identity = (
                campaign_id,
                "OPEN",
                request.next_snapshot_id,
                transition.publication.snapshot_sha256,
                request.expected_review_revision + 1,
                request.expected_execution_generation,
            )
            if observed_head_identity not in (
                expected_base_identity,
                expected_winner_identity,
            ):
                raise M2WorkflowError(
                    "batch head changed during explode preparation"
                )
            _require_live_package_witness(
                base_snapshot,
                prepared_filesystem_witness,
            )
            service = explode_service.ExplodeReviewUnitService(
                session.connection,
                control_root,
                publisher=publisher,
                placement_shared=session.placement_shared,
                ledger_exclusive=session.ledger_exclusive,
                current_policy=session.current_policy,
            )
            result = service.explode_prepared(transition)
            if not isinstance(result, explode_service.ExplodeReviewUnitResult):
                raise M2WorkflowError("explode service returned an invalid result")
            expected_path = snapshot_root / request.next_snapshot_id
            if (
                result.batch_id != request.batch_id
                or result.snapshot_id != request.next_snapshot_id
                or result.parent_snapshot_id != request.expected_snapshot_id
                or result.parent_snapshot_sha256
                != request.expected_snapshot_sha256
                or result.final_path != expected_path
            ):
                raise M2WorkflowError("explode result changed requested identity")
            return ExplodeReviewUnitReport(
                batch_id=result.batch_id,
                snapshot_id=result.snapshot_id,
                status=result.status,
                snapshot_state=result.snapshot_state,
                snapshot_version=result.snapshot_version,
                review_revision=result.review_revision,
                execution_generation=result.execution_generation,
                parent_snapshot_id=result.parent_snapshot_id,
                parent_snapshot_sha256=result.parent_snapshot_sha256,
                snapshot_sha256=result.snapshot_sha256,
                package_sha256=result.package_sha256,
                final_path=str(result.final_path),
                review_directory=str(result.final_path / "review"),
                structural_approval_ready=result.structural_approval_ready,
                structural_blocker=result.structural_blocker,
                resumed=result.resumed,
            )
    except M2WorkflowError:
        raise
    except (
        explode_service.ExplodeReviewUnitError,
        ledger_runtime.LedgerRuntimeError,
        review_context.ReviewContextError,
        review_snapshot.ReviewSnapshotError,
        review_state.ReviewStateError,
        sqlite3.Error,
        TypeError,
        ValueError,
    ) as exc:
        raise M2WorkflowError(str(exc)) from exc


def checkout_review(
    root: Path,
    *,
    snapshot_id: str,
    snapshot_sha256: str,
    draft_id: str,
    actor: str,
) -> CheckoutReviewReport:
    """Create or exactly replay one non-authoritative draft from a sealed review."""

    canonical = _canonical_root(root)
    try:
        request = review_draft.ReviewDraftRequest(
            draft_id=draft_id,
            base_snapshot_id=snapshot_id,
            base_snapshot_sha256=snapshot_sha256,
            actor=actor,
        )
        with ledger_runtime.open_reader_session(canonical) as session:
            control_root = _control_root(session, canonical)
            sealed = review_state.ReviewSnapshotLoader(
                session.connection,
                control_root,
            ).load(request.base_snapshot_id)
            if sealed.snapshot_sha256 != request.base_snapshot_sha256:
                raise M2WorkflowError("base snapshot hash does not match the ledger")
            trusted = review_draft.TrustedReviewSnapshot(
                snapshot_id=sealed.snapshot_id,
                snapshot_sha256=sealed.snapshot_sha256,
                snapshot_bytes=sealed.snapshot_payload,
                review_markdown=sealed.review_markdown,
                review_markdown_sha256=sealed.review_hashes.markdown_sha256,
            )

            def load_trusted(
                expected_id: str,
                expected_hash: str,
            ) -> review_draft.TrustedReviewSnapshot:
                if (
                    expected_id != trusted.snapshot_id
                    or expected_hash != trusted.snapshot_sha256
                ):
                    raise review_draft.ReviewDraftConflict(
                        "draft requested another sealed snapshot"
                    )
                return trusted

            drafts_root = control_root / "drafts"
            draft = review_draft.checkout_review(
                request,
                drafts_root=drafts_root,
                snapshot_loader=load_trusted,
            )
            expected_path = drafts_root / request.draft_id
            if draft.path != expected_path:
                raise M2WorkflowError("draft checkout changed the requested path")
            return CheckoutReviewReport(
                draft_id=draft.draft_id,
                base_snapshot_id=draft.base_snapshot_id,
                base_snapshot_sha256=draft.base_snapshot_sha256,
                actor=draft.actor,
                final_path=str(draft.path),
                draft_markdown_path=str(draft.path / "review.draft.md"),
                template_markdown_sha256=draft.template_markdown_sha256,
                current_markdown_sha256=draft.current_markdown_sha256,
                authority=draft.authority,
                approval_ready=draft.approval_ready,
            )
    except M2WorkflowError:
        raise
    except (
        ledger_runtime.LedgerRuntimeError,
        review_draft.ReviewDraftError,
        review_state.ReviewStateError,
        sqlite3.Error,
        TypeError,
        ValueError,
    ) as exc:
        raise M2WorkflowError(str(exc)) from exc


__all__ = [
    "CheckoutReviewReport",
    "ExplodeReviewUnitReport",
    "M2WorkflowError",
    "OpenBatchReport",
    "OpenRootRunReport",
    "ValidateReviewReport",
    "checkout_review",
    "explode_review_unit",
    "open_batch",
    "open_root_run",
    "validate_review",
]
