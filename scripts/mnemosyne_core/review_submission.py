"""Partial-publish-safe persistence for nonmovement curation decisions.

PREPARED stores only immutable publication bindings; decision history,
relations, deferrals, and item projections materialize together with the
final batch-head compare-and-swap.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from . import admission, decision_service, m3_schema
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENVELOPE_KIND = "review-submission"
_DECISION_ACTION_DB = {
    "keep": "KEEP",
    "link": "LINK",
    "defer": "DEFER",
    "exclude": "EXCLUDE",
    "correction": "CORRECTION",
    "proposal-reject": "PROPOSAL_REJECT",
    "reopen": "REOPEN",
}
_PRIMARY_STATE_DB = {
    "keep": "KEEP",
    "linked": "LINKED",
    "deferred": "DEFERRED",
    "excluded": "EXCLUDED",
    "review-ready": "REVIEW_READY",
}
_WORKSTREAM_KIND_DB = {
    "primary": "PRIMARY",
    "related": "RELATED",
    "shared": "SHARED",
}
_DOCUMENT_KIND_DB = {
    "reference": "REFERENCE",
    "derived": "DERIVED",
    "evidence": "EVIDENCE",
}
_DIRECTION_DB = {
    "canonical-to-related": "FORWARD",
    "related-to-canonical": "REVERSE",
}
_TRIGGER_DB = {
    "date": "DATE",
    "workstream-resume": "WORKSTREAM_RESUME",
    "evidence": "EVIDENCE",
    "manual-reopen": "MANUAL_REOPEN",
}


def _relation_provenance(evidence: str, provenance: str) -> Tuple[bytes, str]:
    payload = canonical_json_bytes({"evidence": evidence, "provenance": provenance})
    return payload, sha256_bytes(payload)


def _document_relation_action(decision_action: str) -> str:
    if decision_action == "link":
        return "CONFIRM"
    if decision_action == "correction":
        return "CORRECT"
    raise ReviewSubmissionValidationError(
        "document relations require link or correction action"
    )


def _deferral_id_for_event(
    compiled: decision_service.CompiledDecisionSet,
    event_id: str,
) -> Optional[str]:
    for row in compiled.deferrals:
        if row["source_decision_event_id"] == event_id:
            return row["deferral_id"]
    return None


def _committed_projection_tuple(
    event: Dict[str, Any],
    projection: Dict[str, Any],
    *,
    item_run_id: str,
    deferral_id: Optional[str],
) -> Tuple[Any, ...]:
    primary = projection["primary_state"]
    if primary not in _PRIMARY_STATE_DB:
        raise ReviewSubmissionValidationError(
            "compiled projection state is unsupported"
        )
    generation = int(projection["projection_generation_delta"])
    return (
        _PRIMARY_STATE_DB[primary],
        event["event_id"],
        deferral_id,
        item_run_id,
        "FRESH",
        event["event_id"],
        None,
        generation,
        0,
        0,
        int(projection["unassigned"]),
        0,
        int(projection["correction_required"]),
    )


class ReviewSubmissionError(RuntimeError):
    """A review decision could not be durably submitted."""


class ReviewSubmissionValidationError(ReviewSubmissionError):
    """The supplied decision/snapshot contract is not the supported slice."""


class ReviewSubmissionConflict(ReviewSubmissionError):
    """Current ledger state does not match the submitted exact base."""


class ReviewSubmissionPublicationError(ReviewSubmissionError):
    """A planned immutable snapshot did not publish or read back exactly."""


class _StalePreparedSubmission(ReviewSubmissionConflict):
    """A PREPARED submission lost its final-CAS base."""


def _tuple_row(value: object) -> Optional[tuple]:
    return None if value is None else tuple(value)  # type: ignore[arg-type]


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ReviewSubmissionValidationError("%s is invalid" % label)
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ReviewSubmissionValidationError("%s is invalid" % label)
    return value


def _as_bytes(value: Any, label: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise ReviewSubmissionValidationError("%s is not bytes" % label)


def _canonical_object(raw: bytes, label: str) -> Dict[str, Any]:
    if type(raw) is not bytes:
        raise ReviewSubmissionValidationError("%s must be bytes" % label)
    try:
        value = json.loads(raw.decode("utf-8"))
        encoded = canonical_json_bytes(value)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ReviewSubmissionValidationError(
            "%s is not canonical JSON" % label
        ) from exc
    if type(value) is not dict or encoded != raw:
        raise ReviewSubmissionValidationError(
            "%s is not a canonical JSON object" % label
        )
    return value


def _policy_payload(policy: admission.ApprovedPolicyRef) -> Dict[str, Any]:
    return {
        "foundation_hash": policy.foundation_hash,
        "full_hash": policy.full_hash,
        "generation": policy.generation,
        "guard_epoch": policy.guard_epoch,
        "raw_hash": policy.raw_hash,
        "source_kind": policy.source_kind,
        "source_run_id": policy.source_run_id,
        "writer_control_hash": policy.writer_control_hash,
    }


def _policy_from_payload(value: Any) -> admission.ApprovedPolicyRef:
    expected = {
        "foundation_hash",
        "full_hash",
        "generation",
        "guard_epoch",
        "raw_hash",
        "source_kind",
        "source_run_id",
        "writer_control_hash",
    }
    if type(value) is not dict or set(value) != expected:
        raise ReviewSubmissionValidationError("stored policy binding is invalid")
    try:
        return admission.ApprovedPolicyRef(
            raw_hash=value["raw_hash"],
            full_hash=value["full_hash"],
            writer_control_hash=value["writer_control_hash"],
            foundation_hash=value["foundation_hash"],
            generation=value["generation"],
            source_kind=value["source_kind"],
            source_run_id=value["source_run_id"],
            guard_epoch=value["guard_epoch"],
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise ReviewSubmissionValidationError(
            "stored policy binding is invalid"
        ) from exc


def _decision_request_payload(
    request: decision_service.DecisionRequest,
) -> Dict[str, Any]:
    return {
        "actor": request.actor,
        "base_snapshot_id": request.base_snapshot_id,
        "base_snapshot_sha256": request.base_snapshot_sha256,
        "batch_id": request.batch_id,
        "campaign_id": request.campaign_id,
        "decided_at_utc": request.decided_at_utc,
        "decisions": [
            {
                "action": value.action,
                "member_item_ids": list(value.member_item_ids),
                "reason": value.reason,
                "selected_item_ids": list(value.selected_item_ids),
                "unit_id": value.unit_id,
            }
            for value in request.decisions
        ],
        "expected_execution_generation": request.expected_execution_generation,
        "expected_review_revision": request.expected_review_revision,
        "next_snapshot_id": request.next_snapshot_id,
        "submission_id": request.submission_id,
    }


def _decision_request_from_payload(value: Any) -> decision_service.DecisionRequest:
    expected = {
        "actor",
        "base_snapshot_id",
        "base_snapshot_sha256",
        "batch_id",
        "campaign_id",
        "decided_at_utc",
        "decisions",
        "expected_execution_generation",
        "expected_review_revision",
        "next_snapshot_id",
        "submission_id",
    }
    if type(value) is not dict or set(value) != expected:
        raise ReviewSubmissionValidationError(
            "stored decision request is invalid"
        )
    values = value.get("decisions")
    if type(values) is not list or not values:
        raise ReviewSubmissionValidationError(
            "stored decision request is invalid"
        )
    decisions = []
    decision_keys = {
        "action",
        "member_item_ids",
        "reason",
        "selected_item_ids",
        "unit_id",
    }
    try:
        for entry in values:
            if type(entry) is not dict or set(entry) != decision_keys:
                raise ReviewSubmissionValidationError(
                    "stored item decision is invalid"
                )
            if type(entry["member_item_ids"]) is not list or type(
                entry["selected_item_ids"]
            ) is not list:
                raise ReviewSubmissionValidationError(
                    "stored item decision is invalid"
                )
            decisions.append(
                decision_service.ItemDecisionInput(
                    unit_id=entry["unit_id"],
                    member_item_ids=tuple(entry["member_item_ids"]),
                    selected_item_ids=tuple(entry["selected_item_ids"]),
                    action=entry["action"],
                    reason=entry["reason"],
                )
            )
        request = decision_service.DecisionRequest(
            campaign_id=value["campaign_id"],
            batch_id=value["batch_id"],
            base_snapshot_id=value["base_snapshot_id"],
            base_snapshot_sha256=value["base_snapshot_sha256"],
            expected_review_revision=value["expected_review_revision"],
            expected_execution_generation=value[
                "expected_execution_generation"
            ],
            submission_id=value["submission_id"],
            next_snapshot_id=value["next_snapshot_id"],
            actor=value["actor"],
            decided_at_utc=value["decided_at_utc"],
            decisions=tuple(decisions),
        )
        decision_service.DecisionService().compile(request)
    except (KeyError, TypeError, ValueError, decision_service.DecisionValidationError) as exc:
        raise ReviewSubmissionValidationError(
            "stored decision request is invalid"
        ) from exc
    if _decision_request_payload(request) != value:
        raise ReviewSubmissionValidationError(
            "stored decision request changed identity"
        )
    return request


def _compiled_payload(
    compiled: decision_service.CompiledDecisionSet,
) -> Dict[str, Any]:
    return {
        "deferrals": [dict(value) for value in compiled.deferrals],
        "document_relation_events": [
            dict(value) for value in compiled.document_relation_events
        ],
        "events": [dict(value) for value in compiled.events],
        "projections": [dict(value) for value in compiled.projections],
        "unassigned_exceptions": [
            dict(value) for value in compiled.unassigned_exceptions
        ],
        "workstream_relations": [
            dict(value) for value in compiled.workstream_relations
        ],
    }


@dataclass(frozen=True)
class ReviewSubmissionRequest:
    policy: admission.ApprovedPolicyRef
    decision_request: decision_service.DecisionRequest
    compiled: decision_service.CompiledDecisionSet
    next_snapshot_payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.policy, admission.ApprovedPolicyRef):
            raise TypeError("policy must be ApprovedPolicyRef")
        if type(self.decision_request) is not decision_service.DecisionRequest:
            raise TypeError("decision_request must be DecisionRequest")
        if type(self.compiled) is not decision_service.CompiledDecisionSet:
            raise TypeError("compiled must be CompiledDecisionSet")
        try:
            expected = decision_service.DecisionService().compile(
                self.decision_request
            )
        except decision_service.DecisionValidationError as exc:
            raise ReviewSubmissionValidationError(str(exc)) from exc
        if self.compiled != expected:
            raise ReviewSubmissionValidationError(
                "compiled decisions do not match the exact request"
            )
        for value in self.decision_request.decisions:
            if value.action not in _DECISION_ACTION_DB:
                raise ReviewSubmissionValidationError(
                    "decision action is outside the supported nonmovement slice"
                )
        snapshot = _canonical_object(
            self.next_snapshot_payload,
            "next snapshot payload",
        )
        request = self.decision_request
        event_ids = [value["event_id"] for value in self.compiled.events]
        expected_snapshot = {
            "approval_ready": False,
            "batch_id": request.batch_id,
            "batch_version": request.expected_review_revision + 1,
            "decision_event_ids": event_ids,
            "parent_snapshot_id": request.base_snapshot_id,
            "parent_snapshot_sha256": request.base_snapshot_sha256,
            "schema_version": m3_schema.M3_SCHEMA_VERSION,
            "snapshot_id": request.next_snapshot_id,
            "structural_approval_ready": False,
        }
        if snapshot != expected_snapshot:
            raise ReviewSubmissionValidationError(
                "next snapshot does not match the exact decision set"
            )

    def identity_payload(self) -> Dict[str, Any]:
        return {
            "compiled": _compiled_payload(self.compiled),
            "kind": _ENVELOPE_KIND,
            "policy": _policy_payload(self.policy),
            "request": _decision_request_payload(self.decision_request),
            "schema_version": m3_schema.M3_SCHEMA_VERSION,
            "snapshot": _canonical_object(
                self.next_snapshot_payload,
                "next snapshot payload",
            ),
        }

    @property
    def request_hash(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.identity_payload()))


_ENVELOPE_KIND_REOPEN = "reopen-review-submission"


def _reopen_request_payload(
    request: decision_service.ReopenDecisionRequest,
) -> Dict[str, Any]:
    return {
        "actor": request.actor,
        "batch_id": request.batch_id,
        "base_snapshot_id": request.base_snapshot_id,
        "base_snapshot_sha256": request.base_snapshot_sha256,
        "campaign_id": request.campaign_id,
        "current_decision_event_id": request.current_decision_event_id,
        "current_projection_generation": request.current_projection_generation,
        "expected_execution_generation": request.expected_execution_generation,
        "expected_review_revision": request.expected_review_revision,
        "item_id": request.item_id,
        "next_snapshot_id": request.next_snapshot_id,
        "reason": request.reason,
        "reopened_at_utc": request.reopened_at_utc,
        "selected_relation_id": request.selected_relation_id,
        "selected_relation_kind": request.selected_relation_kind,
        "submission_id": request.submission_id,
    }


def _reopen_compiled_payload(
    compiled: decision_service.CompiledReopen,
) -> Dict[str, Any]:
    return {
        "event": dict(compiled.event),
        "projection": dict(compiled.projection),
        "supersessions": [dict(value) for value in compiled.supersessions],
    }


@dataclass(frozen=True)
class ReopenReviewSubmissionRequest:
    policy: admission.ApprovedPolicyRef
    reopen_request: decision_service.ReopenDecisionRequest
    compiled: decision_service.CompiledReopen
    next_snapshot_payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.policy, admission.ApprovedPolicyRef):
            raise TypeError("policy must be ApprovedPolicyRef")
        if type(self.reopen_request) is not decision_service.ReopenDecisionRequest:
            raise TypeError("reopen_request must be ReopenDecisionRequest")
        if type(self.compiled) is not decision_service.CompiledReopen:
            raise TypeError("compiled must be CompiledReopen")
        try:
            expected = decision_service.DecisionService().compile_reopen(
                self.reopen_request
            )
        except decision_service.DecisionValidationError as exc:
            raise ReviewSubmissionValidationError(str(exc)) from exc
        if self.compiled != expected:
            raise ReviewSubmissionValidationError(
                "compiled reopen does not match the exact request"
            )
        snapshot = _canonical_object(
            self.next_snapshot_payload,
            "next snapshot payload",
        )
        request = self.reopen_request
        expected_snapshot = {
            "approval_ready": False,
            "batch_id": request.batch_id,
            "batch_version": request.expected_review_revision + 1,
            "decision_event_ids": [self.compiled.event["event_id"]],
            "parent_snapshot_id": request.base_snapshot_id,
            "parent_snapshot_sha256": request.base_snapshot_sha256,
            "schema_version": m3_schema.M3_SCHEMA_VERSION,
            "snapshot_id": request.next_snapshot_id,
            "structural_approval_ready": False,
        }
        if snapshot != expected_snapshot:
            raise ReviewSubmissionValidationError(
                "next snapshot does not match the exact reopen"
            )

    def identity_payload(self) -> Dict[str, Any]:
        return {
            "compiled": _reopen_compiled_payload(self.compiled),
            "kind": _ENVELOPE_KIND_REOPEN,
            "policy": _policy_payload(self.policy),
            "request": _reopen_request_payload(self.reopen_request),
            "schema_version": m3_schema.M3_SCHEMA_VERSION,
            "snapshot": _canonical_object(
                self.next_snapshot_payload,
                "next snapshot payload",
            ),
        }

    @property
    def request_hash(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.identity_payload()))


@dataclass(frozen=True)
class SnapshotPublication:
    snapshot_id: str
    batch_id: str
    version: int
    canonical_payload: bytes
    snapshot_sha256: str
    final_path: Path
    structural_approval_ready: bool


@dataclass(frozen=True)
class SnapshotPublishPlan:
    publication: SnapshotPublication
    final_path: Path
    package_sha256: str
    sealed_identity_sha256: str
    sealed_payload: object


@dataclass(frozen=True)
class SnapshotPublishResult:
    final_path: Path
    snapshot_sha256: str
    package_sha256: str
    sealed_identity_sha256: str


@dataclass(frozen=True)
class PreparedReviewSubmission:
    request: ReviewSubmissionRequest
    publication: SnapshotPublication
    plan: SnapshotPublishPlan
    envelope: bytes

    def __post_init__(self) -> None:
        if type(self.request) is not ReviewSubmissionRequest:
            raise TypeError("request must be ReviewSubmissionRequest")
        if type(self.publication) is not SnapshotPublication:
            raise TypeError("publication must be SnapshotPublication")
        if type(self.plan) is not SnapshotPublishPlan:
            raise TypeError("plan must be SnapshotPublishPlan")
        if type(self.envelope) is not bytes:
            raise TypeError("envelope must be bytes")


@dataclass(frozen=True)
class PreparedReopenReviewSubmission:
    request: ReopenReviewSubmissionRequest
    publication: SnapshotPublication
    plan: SnapshotPublishPlan
    envelope: bytes

    def __post_init__(self) -> None:
        if type(self.request) is not ReopenReviewSubmissionRequest:
            raise TypeError("request must be ReopenReviewSubmissionRequest")
        if type(self.publication) is not SnapshotPublication:
            raise TypeError("publication must be SnapshotPublication")
        if type(self.plan) is not SnapshotPublishPlan:
            raise TypeError("plan must be SnapshotPublishPlan")
        if type(self.envelope) is not bytes:
            raise TypeError("envelope must be bytes")


@dataclass(frozen=True)
class ReviewSubmissionResult:
    submission_id: str
    submission_state: str
    batch_id: str
    snapshot_id: str
    snapshot_state: str
    snapshot_version: int
    review_revision: int
    execution_generation: int
    parent_snapshot_id: str
    parent_snapshot_sha256: str
    snapshot_sha256: str
    package_sha256: str
    final_path: Path
    resumed: bool


def _require_owner_only_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReviewSubmissionPublicationError(
            "%s directory is unreadable" % label
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ReviewSubmissionPublicationError(
            "%s directory identity is invalid" % label
        )


def _publication(
    snapshot_root: Path,
    request: ReviewSubmissionRequest,
) -> SnapshotPublication:
    decision = request.decision_request
    return SnapshotPublication(
        snapshot_id=decision.next_snapshot_id,
        batch_id=decision.batch_id,
        version=decision.expected_review_revision + 1,
        canonical_payload=request.next_snapshot_payload,
        snapshot_sha256=sha256_bytes(request.next_snapshot_payload),
        final_path=snapshot_root / decision.next_snapshot_id,
        structural_approval_ready=False,
    )


def _publication_reopen(
    snapshot_root: Path,
    request: ReopenReviewSubmissionRequest,
) -> SnapshotPublication:
    reopen = request.reopen_request
    return SnapshotPublication(
        snapshot_id=reopen.next_snapshot_id,
        batch_id=reopen.batch_id,
        version=reopen.expected_review_revision + 1,
        canonical_payload=request.next_snapshot_payload,
        snapshot_sha256=sha256_bytes(request.next_snapshot_payload),
        final_path=snapshot_root / reopen.next_snapshot_id,
        structural_approval_ready=False,
    )


def _sealed_paths(
    snapshot_root: Path,
    plan: SnapshotPublishPlan,
) -> Tuple[Path, Path]:
    staging_path = getattr(plan.sealed_payload, "staging_path", None)
    final_path = getattr(plan.sealed_payload, "final_path", None)
    if not isinstance(staging_path, Path) or not isinstance(final_path, Path):
        raise ReviewSubmissionPublicationError(
            "publisher must seal snapshot staging and final paths"
        )
    expected_staging = snapshot_root / (
        ".incomplete-%s" % plan.publication.snapshot_id
    )
    if staging_path != expected_staging or final_path != plan.final_path:
        raise ReviewSubmissionPublicationError("publisher sealed paths are invalid")
    return staging_path, final_path


def _validate_plan(
    snapshot_root: Path,
    publication: SnapshotPublication,
    plan: SnapshotPublishPlan,
) -> None:
    if type(plan) is not SnapshotPublishPlan:
        raise ReviewSubmissionPublicationError("publisher plan type is invalid")
    if plan.publication != publication:
        raise ReviewSubmissionPublicationError(
            "publisher plan changed snapshot publication"
        )
    if (
        plan.final_path != publication.final_path
        or not plan.final_path.is_absolute()
        or plan.final_path.parent != snapshot_root
    ):
        raise ReviewSubmissionPublicationError(
            "publisher plan final path is invalid"
        )
    try:
        _sha256(plan.package_sha256, "publisher package hash")
        _sha256(plan.sealed_identity_sha256, "publisher sealed identity hash")
    except ReviewSubmissionValidationError as exc:
        raise ReviewSubmissionPublicationError(str(exc)) from exc
    _sealed_paths(snapshot_root, plan)


def _submission_envelope(
    request: ReviewSubmissionRequest,
    publication: SnapshotPublication,
    plan: SnapshotPublishPlan,
) -> bytes:
    value = request.identity_payload()
    value.update(
        {
            "publish_plan": {
                "final_path": str(plan.final_path),
                "package_sha256": plan.package_sha256,
                "sealed_identity_sha256": plan.sealed_identity_sha256,
            },
            "request_hash": request.request_hash,
            "snapshot_sha256": publication.snapshot_sha256,
        }
    )
    return canonical_json_bytes(value)


def prepare_review_submission(
    snapshot_root: Path,
    publisher: object,
    request: ReviewSubmissionRequest,
) -> PreparedReviewSubmission:
    """Plan immutable snapshot publication without any writer guard held."""

    if type(request) is not ReviewSubmissionRequest:
        raise TypeError("request must be ReviewSubmissionRequest")
    if not callable(getattr(publisher, "plan", None)) or not callable(
        getattr(publisher, "publish", None)
    ):
        raise TypeError("publisher must provide plan() and publish()")
    root = Path(snapshot_root).resolve()
    _require_owner_only_directory(root, "snapshot root")
    publication = _publication(root, request)
    plan = publisher.plan(publication)
    _validate_plan(root, publication, plan)
    return PreparedReviewSubmission(
        request=request,
        publication=publication,
        plan=plan,
        envelope=_submission_envelope(request, publication, plan),
    )


def _reopen_submission_envelope(
    request: ReopenReviewSubmissionRequest,
    publication: SnapshotPublication,
    plan: SnapshotPublishPlan,
) -> bytes:
    value = request.identity_payload()
    value.update(
        {
            "publish_plan": {
                "final_path": str(plan.final_path),
                "package_sha256": plan.package_sha256,
                "sealed_identity_sha256": plan.sealed_identity_sha256,
            },
            "request_hash": request.request_hash,
            "snapshot_sha256": publication.snapshot_sha256,
        }
    )
    return canonical_json_bytes(value)


def prepare_reopen_review_submission(
    snapshot_root: Path,
    publisher: object,
    request: ReopenReviewSubmissionRequest,
) -> PreparedReopenReviewSubmission:
    """Plan immutable reopen snapshot publication without writer guards held."""

    if type(request) is not ReopenReviewSubmissionRequest:
        raise TypeError("request must be ReopenReviewSubmissionRequest")
    if not callable(getattr(publisher, "plan", None)) or not callable(
        getattr(publisher, "publish", None)
    ):
        raise TypeError("publisher must provide plan() and publish()")
    root = Path(snapshot_root).resolve()
    _require_owner_only_directory(root, "snapshot root")
    publication = _publication_reopen(root, request)
    plan = publisher.plan(publication)
    _validate_plan(root, publication, plan)
    return PreparedReopenReviewSubmission(
        request=request,
        publication=publication,
        plan=plan,
        envelope=_reopen_submission_envelope(request, publication, plan),
    )


def _request_from_envelope(envelope: bytes) -> ReviewSubmissionRequest:
    value = _canonical_object(envelope, "stored review submission")
    expected = {
        "compiled",
        "kind",
        "policy",
        "publish_plan",
        "request",
        "request_hash",
        "schema_version",
        "snapshot",
        "snapshot_sha256",
    }
    plan_keys = {
        "final_path",
        "package_sha256",
        "sealed_identity_sha256",
    }
    if (
        set(value) != expected
        or value.get("kind") != _ENVELOPE_KIND
        or value.get("schema_version") != m3_schema.M3_SCHEMA_VERSION
        or type(value.get("publish_plan")) is not dict
        or set(value["publish_plan"]) != plan_keys
        or type(value.get("compiled")) is not dict
    ):
        raise ReviewSubmissionValidationError(
            "stored review submission contract is invalid"
        )
    policy = _policy_from_payload(value["policy"])
    decision = _decision_request_from_payload(value["request"])
    compiled = decision_service.DecisionService().compile(decision)
    if _compiled_payload(compiled) != value["compiled"]:
        raise ReviewSubmissionValidationError(
            "stored compiled decisions changed identity"
        )
    try:
        snapshot_payload = canonical_json_bytes(value["snapshot"])
    except (TypeError, ValueError) as exc:
        raise ReviewSubmissionValidationError(
            "stored next snapshot is invalid"
        ) from exc
    request = ReviewSubmissionRequest(
        policy=policy,
        decision_request=decision,
        compiled=compiled,
        next_snapshot_payload=snapshot_payload,
    )
    if (
        request.request_hash != value["request_hash"]
        or sha256_bytes(snapshot_payload) != value["snapshot_sha256"]
    ):
        raise ReviewSubmissionValidationError(
            "stored review submission hash binding is invalid"
        )
    return request


class ReviewSubmissionPublisher:
    """Publish and atomically project one exact non-genesis keep decision."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        snapshot_root: Path,
        *,
        placement_shared: Callable[[], object],
        ledger_exclusive: Callable[[], object],
        publisher: object,
        current_policy: Callable[[], admission.ApprovedPolicyRef],
        checkpoint: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if connection.in_transaction:
            raise ReviewSubmissionConflict(
                "review submission requires transaction ownership"
            )
        self.connection = connection
        self.snapshot_root = Path(snapshot_root).resolve()
        if not callable(placement_shared) or not callable(ledger_exclusive):
            raise TypeError("placement_shared and ledger_exclusive are required")
        self.placement_shared = placement_shared
        self.ledger_exclusive = ledger_exclusive
        if not callable(getattr(publisher, "plan", None)) or not callable(
            getattr(publisher, "publish", None)
        ):
            raise TypeError("publisher must provide plan() and publish()")
        self.publisher = publisher
        if not callable(current_policy):
            raise TypeError("current_policy is required")
        self.current_policy = current_policy
        self.checkpoint = checkpoint or (lambda _point: None)

    def _verify_schema(self) -> None:
        try:
            m3_schema.verify_v3_schema(self.connection)
        except m3_schema.M3SchemaError as exc:
            raise ReviewSubmissionConflict(
                "exact ledger schema v3 is required"
            ) from exc

    def _require_current_policy(
        self,
        request: ReviewSubmissionRequest | ReopenReviewSubmissionRequest,
    ) -> None:
        try:
            observed = self.current_policy()
        except Exception as exc:
            raise ReviewSubmissionConflict(
                "current policy authority drifted"
            ) from exc
        if observed != request.policy:
            raise ReviewSubmissionConflict("current policy authority drifted")

    def _require_lineage_policy(self, request: ReviewSubmissionRequest) -> None:
        decision = request.decision_request
        row = _tuple_row(
            self.connection.execute(
                "SELECT b.campaign_id, r.policy_raw_hash, r.policy_full_hash, "
                "r.policy_writer_control_hash, r.policy_foundation_hash, "
                "r.policy_generation, r.policy_source_kind, "
                "r.policy_source_run_id, r.policy_guard_epoch "
                "FROM review_batches AS b "
                "JOIN campaigns AS c ON c.campaign_id = b.campaign_id "
                "JOIN inventory_runs AS r ON r.run_id = c.root_run_id "
                "WHERE b.batch_id = ?",
                (decision.batch_id,),
            ).fetchone()
        )
        expected = (
            decision.campaign_id,
            request.policy.raw_hash,
            request.policy.full_hash,
            request.policy.writer_control_hash,
            request.policy.foundation_hash,
            request.policy.generation,
            request.policy.source_kind,
            request.policy.source_run_id,
            request.policy.guard_epoch,
        )
        if row != expected:
            raise ReviewSubmissionConflict("batch policy authority is stale")

    def _require_base_head(self, request: ReviewSubmissionRequest) -> None:
        decision = request.decision_request
        row = _tuple_row(
            self.connection.execute(
                "SELECT b.campaign_id, c.status, b.status, "
                "b.current_snapshot_id, b.current_snapshot_sha256, "
                "b.review_revision, b.execution_generation "
                "FROM review_batches AS b "
                "JOIN campaigns AS c ON c.campaign_id = b.campaign_id "
                "WHERE b.batch_id = ?",
                (decision.batch_id,),
            ).fetchone()
        )
        expected = (
            decision.campaign_id,
            "READY",
            "OPEN",
            decision.base_snapshot_id,
            decision.base_snapshot_sha256,
            decision.expected_review_revision,
            decision.expected_execution_generation,
        )
        if row != expected:
            raise ReviewSubmissionConflict("OPEN batch head is stale")

    def _require_next_head(
        self,
        request: ReviewSubmissionRequest,
        publication: SnapshotPublication,
    ) -> None:
        decision = request.decision_request
        row = _tuple_row(
            self.connection.execute(
                "SELECT status, current_snapshot_id, current_snapshot_sha256, "
                "review_revision, execution_generation FROM review_batches "
                "WHERE batch_id = ? AND campaign_id = ?",
                (decision.batch_id, decision.campaign_id),
            ).fetchone()
        )
        if row != (
            "OPEN",
            decision.next_snapshot_id,
            publication.snapshot_sha256,
            decision.expected_review_revision + 1,
            decision.expected_execution_generation,
        ):
            raise ReviewSubmissionConflict(
                "committed review submission head is stale"
            )

    def _require_base_snapshot(self, request: ReviewSubmissionRequest) -> None:
        decision = request.decision_request
        row = _tuple_row(
            self.connection.execute(
                "SELECT lineage_kind, campaign_id, batch_id, version, "
                "payload_sha256, state FROM review_snapshots "
                "WHERE snapshot_id = ?",
                (decision.base_snapshot_id,),
            ).fetchone()
        )
        if row != (
            "BATCH",
            decision.campaign_id,
            decision.batch_id,
            decision.expected_review_revision,
            decision.base_snapshot_sha256,
            "PUBLISHED",
        ):
            raise ReviewSubmissionConflict("base review snapshot is stale")

    def _require_no_batch_event(self, request: ReviewSubmissionRequest) -> None:
        row = self.connection.execute(
            "SELECT batch_event_id FROM batch_events "
            "WHERE batch_id = ? AND state = 'PREPARED'",
            (request.decision_request.batch_id,),
        ).fetchone()
        if row is not None:
            raise ReviewSubmissionConflict(
                "an unresolved batch event blocks review submission"
            )

    def _require_memberships(self, request: ReviewSubmissionRequest) -> None:
        decision = request.decision_request
        for value in decision.decisions:
            rows = [
                tuple(row)
                for row in self.connection.execute(
                    "SELECT item_id, status FROM batch_memberships "
                    "WHERE batch_id = ? AND unit_id = ? ORDER BY item_id",
                    (decision.batch_id, value.unit_id),
                ).fetchall()
            ]
            expected = [(item_id, "OPEN") for item_id in value.member_item_ids]
            if rows != expected:
                raise ReviewSubmissionConflict("review unit membership is stale")
            for item_id in value.member_item_ids:
                item = _tuple_row(
                    self.connection.execute(
                        "SELECT state FROM items WHERE item_id = ?",
                        (item_id,),
                    ).fetchone()
                )
                if item != ("REVIEW_READY",):
                    raise ReviewSubmissionConflict(
                        "decided item is not review-ready"
                    )

    def _require_unmaterialized(self, request: ReviewSubmissionRequest) -> None:
        for event in request.compiled.events:
            if self.connection.execute(
                "SELECT 1 FROM decision_events WHERE decision_event_id = ?",
                (event["event_id"],),
            ).fetchone() is not None:
                raise ReviewSubmissionConflict(
                    "decision event identity is already materialized"
                )
            if self.connection.execute(
                "SELECT 1 FROM item_curation_projection WHERE item_id = ?",
                (event["item_id"],),
            ).fetchone() is not None:
                raise ReviewSubmissionConflict(
                    "review item already has a curation projection"
                )

    def _require_prepared_binding(
        self,
        prepared: PreparedReviewSubmission,
        *,
        expected_state: str,
    ) -> None:
        request = prepared.request
        decision = request.decision_request
        row = self.connection.execute(
            "SELECT lineage_kind, campaign_id, batch_id, request_hash, "
            "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
            "payload_sha256, final_path, final_sha256, expected_lineage_status, "
            "expected_review_revision, expected_execution_generation, state "
            "FROM review_submissions WHERE submission_id = ?",
            (decision.submission_id,),
        ).fetchone()
        if row is None:
            raise _StalePreparedSubmission(
                "prepared review submission disappeared"
            )
        values = list(tuple(row))
        values[7] = _as_bytes(values[7], "stored submission payload")
        expected = (
            "BATCH",
            decision.campaign_id,
            decision.batch_id,
            request.request_hash,
            decision.next_snapshot_id,
            decision.base_snapshot_id,
            decision.base_snapshot_sha256,
            prepared.envelope,
            sha256_bytes(prepared.envelope),
            str(prepared.plan.final_path),
            prepared.plan.package_sha256,
            "OPEN",
            decision.expected_review_revision,
            decision.expected_execution_generation,
            expected_state,
        )
        if tuple(values) != expected:
            raise _StalePreparedSubmission(
                "prepared review submission binding changed"
            )
        snapshot = _tuple_row(
            self.connection.execute(
                "SELECT lineage_kind, campaign_id, batch_id, version, "
                "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
                "final_path, final_sha256, state, structural_approval_ready "
                "FROM review_snapshots WHERE snapshot_id = ?",
                (decision.next_snapshot_id,),
            ).fetchone()
        )
        snapshot_state = "PREPARED" if expected_state == "PREPARED" else "PUBLISHED"
        if snapshot != (
            "BATCH",
            decision.campaign_id,
            decision.batch_id,
            prepared.publication.version,
            decision.base_snapshot_id,
            decision.base_snapshot_sha256,
            prepared.publication.snapshot_sha256,
            str(prepared.plan.final_path),
            prepared.plan.package_sha256,
            snapshot_state,
            0,
        ):
            raise _StalePreparedSubmission(
                "prepared review snapshot binding changed"
            )

    def _require_committed_materialization(
        self,
        prepared: PreparedReviewSubmission,
    ) -> None:
        request = prepared.request
        decision = request.decision_request
        compiled = request.compiled
        revision = decision.expected_review_revision + 1
        for event, projection in zip(compiled.events, compiled.projections):
            action = event["action"]
            if action not in _DECISION_ACTION_DB:
                raise ReviewSubmissionValidationError(
                    "compiled decision action is unsupported"
                )
            generation = int(projection["projection_generation_delta"])
            payload = canonical_json_bytes(event)
            row = _tuple_row(
                self.connection.execute(
                    "SELECT campaign_id, batch_id, item_id, snapshot_id, "
                    "snapshot_sha256, review_revision, projection_generation, "
                    "actor, action, current_decision_id, reason, payload_json, "
                    "payload_sha256, occurred_at FROM decision_events "
                    "WHERE decision_event_id = ?",
                    (event["event_id"],),
                ).fetchone()
            )
            if row is None:
                raise ReviewSubmissionConflict(
                    "committed decision event is missing"
                )
            event_values = list(row)
            event_values[11] = _as_bytes(
                event_values[11],
                "stored decision payload",
            )
            if tuple(event_values) != (
                decision.campaign_id,
                decision.batch_id,
                event["item_id"],
                decision.next_snapshot_id,
                prepared.publication.snapshot_sha256,
                revision,
                generation,
                event["actor"],
                _DECISION_ACTION_DB[action],
                None,
                event.get("reason"),
                payload,
                sha256_bytes(payload),
                event["decided_at_utc"],
            ):
                raise ReviewSubmissionConflict(
                    "committed decision event binding changed"
                )
            item = _tuple_row(
                self.connection.execute(
                    "SELECT first_seen_run_id FROM items WHERE item_id = ?",
                    (event["item_id"],),
                ).fetchone()
            )
            if item is None:
                raise ReviewSubmissionConflict("committed item disappeared")
            deferral_id = _deferral_id_for_event(compiled, event["event_id"])
            current = _tuple_row(
                self.connection.execute(
                    "SELECT primary_state, current_decision_id, "
                    "current_deferral_id, source_run_id, source_freshness, "
                    "source_event_id, source_execution_id, projection_generation, "
                    "identity_ambiguous, lifecycle_frozen, unassigned, "
                    "reversal_available, correction_required "
                    "FROM item_curation_projection WHERE item_id = ?",
                    (event["item_id"],),
                ).fetchone()
            )
            expected = _committed_projection_tuple(
                event,
                projection,
                item_run_id=item[0],
                deferral_id=deferral_id,
            )
            if current != expected:
                raise ReviewSubmissionConflict(
                    "committed item projection binding changed"
                )

    def _prepare_ledger(
        self,
        prepared: PreparedReviewSubmission,
    ) -> Tuple[str, bool]:
        request = prepared.request
        decision = request.decision_request
        staging_path, final_path = _sealed_paths(self.snapshot_root, prepared.plan)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            existing = self.connection.execute(
                "SELECT state FROM review_submissions WHERE submission_id = ?",
                (decision.submission_id,),
            ).fetchone()
            if existing is not None:
                state = existing[0]
                if state not in ("PREPARED", "COMMITTED"):
                    raise ReviewSubmissionConflict(
                        "submission id is not exactly resumable"
                    )
                self._require_prepared_binding(
                    prepared,
                    expected_state=state,
                )
                if state == "COMMITTED":
                    self._require_next_head(request, prepared.publication)
                    self._require_committed_materialization(prepared)
                    self._require_current_policy(request)
                    self._require_lineage_policy(request)
                    self.connection.execute("COMMIT")
                    return state, True
                try:
                    self._require_base_head(request)
                    self._require_base_snapshot(request)
                    self._require_no_batch_event(request)
                    self._require_memberships(request)
                    self._require_unmaterialized(request)
                except ReviewSubmissionConflict as exc:
                    raise _StalePreparedSubmission(str(exc)) from exc
                if os.path.lexists(staging_path):
                    raise ReviewSubmissionPublicationError(
                        "conflicting snapshot staging exists"
                    )
                self._require_current_policy(request)
                self._require_lineage_policy(request)
                self.connection.execute("COMMIT")
                return state, True

            self._require_base_head(request)
            self._require_base_snapshot(request)
            self._require_no_batch_event(request)
            unresolved = self.connection.execute(
                "SELECT submission_id FROM review_submissions "
                "WHERE batch_id = ? AND state = 'PREPARED'",
                (decision.batch_id,),
            ).fetchone()
            if unresolved is not None:
                raise ReviewSubmissionConflict(
                    "another unresolved batch submission exists"
                )
            self._require_memberships(request)
            self._require_unmaterialized(request)
            if self.connection.execute(
                "SELECT 1 FROM review_snapshots WHERE snapshot_id = ?",
                (decision.next_snapshot_id,),
            ).fetchone() is not None:
                raise ReviewSubmissionConflict(
                    "next snapshot id is already globally bound"
                )
            if os.path.lexists(final_path) or os.path.lexists(staging_path):
                raise ReviewSubmissionConflict(
                    "next snapshot filesystem identity is already bound"
                )
            self.connection.execute(
                "INSERT INTO review_submissions ("
                "submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
                "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
                "payload_sha256, final_path, final_sha256, state, "
                "expected_lineage_status, expected_review_revision, "
                "expected_execution_generation"
                ") VALUES (?, 'BATCH', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', "
                "'OPEN', ?, ?)",
                (
                    decision.submission_id,
                    decision.campaign_id,
                    decision.batch_id,
                    request.request_hash,
                    decision.next_snapshot_id,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    prepared.envelope,
                    sha256_bytes(prepared.envelope),
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                    decision.expected_review_revision,
                    decision.expected_execution_generation,
                ),
            )
            self.connection.execute(
                "INSERT INTO review_snapshots ("
                "snapshot_id, lineage_kind, campaign_id, batch_id, version, "
                "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
                "final_path, final_sha256, state, structural_approval_ready"
                ") VALUES (?, 'BATCH', ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', 0)",
                (
                    decision.next_snapshot_id,
                    decision.campaign_id,
                    decision.batch_id,
                    prepared.publication.version,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    prepared.publication.snapshot_sha256,
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                ),
            )
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            self.connection.execute("COMMIT")
            return "PREPARED", False
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise ReviewSubmissionConflict(
                "review submission identity or lineage constraint failed"
            ) from exc
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _readback_snapshot(
        self,
        prepared: PreparedReviewSubmission | PreparedReopenReviewSubmission,
    ) -> None:
        staging_path, final_path = _sealed_paths(self.snapshot_root, prepared.plan)
        if os.path.lexists(staging_path):
            raise ReviewSubmissionPublicationError(
                "conflicting snapshot staging exists beside final package"
            )
        _require_owner_only_directory(self.snapshot_root, "snapshot root")
        _require_owner_only_directory(final_path, "snapshot package")
        payload_path = final_path / "snapshot.json"
        try:
            before = payload_path.lstat()
        except OSError as exc:
            raise ReviewSubmissionPublicationError(
                "published snapshot payload is unreadable"
            ) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise ReviewSubmissionPublicationError(
                "published snapshot payload identity is invalid"
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = None
        try:
            descriptor = os.open(payload_path, flags)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ReviewSubmissionPublicationError(
                    "published snapshot payload changed during readback"
                )
            expected = prepared.publication.canonical_payload
            raw = os.read(descriptor, len(expected) + 1)
            after = os.fstat(descriptor)
        except OSError as exc:
            raise ReviewSubmissionPublicationError(
                "published snapshot payload is unreadable"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if (
            raw != prepared.publication.canonical_payload
            or sha256_bytes(raw) != prepared.publication.snapshot_sha256
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise ReviewSubmissionPublicationError(
                "published snapshot readback changed prepared bytes"
            )

    def _publish_or_readback(
        self,
        prepared: PreparedReviewSubmission | PreparedReopenReviewSubmission,
    ) -> None:
        staging_path, final_path = _sealed_paths(self.snapshot_root, prepared.plan)
        if os.path.lexists(staging_path):
            raise ReviewSubmissionPublicationError(
                "conflicting snapshot staging exists"
            )
        if not os.path.lexists(final_path):
            try:
                result = self.publisher.publish(prepared.plan)
            except Exception as exc:
                raise ReviewSubmissionPublicationError(
                    "snapshot publication failed"
                ) from exc
            if type(result) is not SnapshotPublishResult or (
                result.final_path != prepared.plan.final_path
                or result.snapshot_sha256
                != prepared.publication.snapshot_sha256
                or result.package_sha256 != prepared.plan.package_sha256
                or result.sealed_identity_sha256
                != prepared.plan.sealed_identity_sha256
            ):
                raise ReviewSubmissionPublicationError(
                    "publisher readback does not match prepared plan"
                )
        self._readback_snapshot(prepared)

    def _block_stale(self, prepared: PreparedReviewSubmission) -> None:
        request = prepared.request
        decision = request.decision_request
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            self._require_prepared_binding(
                prepared,
                expected_state="PREPARED",
            )
            blocked_submission = self.connection.execute(
                "UPDATE review_submissions SET state = 'BLOCKED' "
                "WHERE submission_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND request_hash = ? AND payload_sha256 = ? "
                "AND expected_lineage_status = 'OPEN' "
                "AND expected_review_revision = ? "
                "AND expected_execution_generation = ?",
                (
                    decision.submission_id,
                    decision.batch_id,
                    request.request_hash,
                    sha256_bytes(prepared.envelope),
                    decision.expected_review_revision,
                    decision.expected_execution_generation,
                ),
            ).rowcount
            blocked_snapshot = self.connection.execute(
                "UPDATE review_snapshots SET state = 'BLOCKED' "
                "WHERE snapshot_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND parent_snapshot_id = ? AND parent_snapshot_sha256 = ? "
                "AND payload_sha256 = ? AND final_path = ? AND final_sha256 = ?",
                (
                    decision.next_snapshot_id,
                    decision.batch_id,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    prepared.publication.snapshot_sha256,
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                ),
            ).rowcount
            if (blocked_submission, blocked_snapshot) != (1, 1):
                raise ReviewSubmissionConflict(
                    "stale review submission could not be blocked exactly once"
                )
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _insert_decisions(self, prepared: PreparedReviewSubmission) -> None:
        request = prepared.request
        decision = request.decision_request
        compiled = request.compiled
        revision = decision.expected_review_revision + 1
        deferrals_by_event = {
            row["source_decision_event_id"]: row for row in compiled.deferrals
        }
        for event, projection in zip(compiled.events, compiled.projections):
            event_id = event["event_id"]
            item_id = event["item_id"]
            action = event["action"]
            if action not in _DECISION_ACTION_DB:
                raise ReviewSubmissionValidationError(
                    "compiled decision action is unsupported"
                )
            item = _tuple_row(
                self.connection.execute(
                    "SELECT first_seen_run_id FROM items WHERE item_id = ?",
                    (item_id,),
                ).fetchone()
            )
            if item is None:
                raise _StalePreparedSubmission("decided item disappeared")
            payload = canonical_json_bytes(event)
            generation = int(projection["projection_generation_delta"])
            self.connection.execute(
                "INSERT INTO decision_events ("
                "decision_event_id, campaign_id, batch_id, item_id, snapshot_id, "
                "snapshot_sha256, review_revision, projection_generation, actor, "
                "action, current_decision_id, reason, payload_json, payload_sha256, "
                "occurred_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                (
                    event_id,
                    decision.campaign_id,
                    decision.batch_id,
                    item_id,
                    decision.next_snapshot_id,
                    prepared.publication.snapshot_sha256,
                    revision,
                    generation,
                    event["actor"],
                    _DECISION_ACTION_DB[action],
                    event.get("reason"),
                    payload,
                    sha256_bytes(payload),
                    event["decided_at_utc"],
                ),
            )
            deferral_id = None
            deferral_row = deferrals_by_event.get(event_id)
            if deferral_row is not None:
                trigger = deferral_row["trigger_kind"]
                if trigger not in _TRIGGER_DB:
                    raise ReviewSubmissionValidationError(
                        "compiled deferral trigger is unsupported"
                    )
                required = canonical_json_bytes(deferral_row["required_evidence"])
                deferral_id = deferral_row["deferral_id"]
                self.connection.execute(
                    "INSERT INTO deferrals ("
                    "deferral_id, item_id, source_decision_event_id, version, reason, "
                    "required_evidence_json, required_evidence_sha256, trigger_kind, "
                    "revisit_date, timezone, trigger_workstream_id, captured_lifecycle, "
                    "captured_policy_sha256, owner_actor, state"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CURRENT')",
                    (
                        deferral_id,
                        item_id,
                        event_id,
                        int(deferral_row["version"]),
                        deferral_row["reason"],
                        required,
                        sha256_bytes(required),
                        _TRIGGER_DB[trigger],
                        deferral_row.get("review_date"),
                        deferral_row.get("timezone"),
                        deferral_row.get("workstream_id"),
                        deferral_row.get("captured_lifecycle"),
                        deferral_row.get("captured_policy_hash"),
                        deferral_row.get("owner"),
                    ),
                )
            primary = projection["primary_state"]
            if primary not in _PRIMARY_STATE_DB:
                raise ReviewSubmissionValidationError(
                    "compiled projection state is unsupported"
                )
            self.connection.execute(
                "INSERT INTO item_curation_projection ("
                "item_id, primary_state, current_decision_id, current_deferral_id, "
                "source_run_id, source_freshness, source_event_id, "
                "source_execution_id, projection_generation, identity_ambiguous, "
                "lifecycle_frozen, unassigned, reversal_available, "
                "correction_required"
                ") VALUES (?, ?, ?, ?, ?, 'FRESH', ?, NULL, ?, 0, 0, ?, 0, ?)",
                (
                    item_id,
                    _PRIMARY_STATE_DB[primary],
                    event_id,
                    deferral_id,
                    item[0],
                    event_id,
                    generation,
                    int(projection["unassigned"]),
                    int(projection["correction_required"]),
                ),
            )
            for relation in compiled.workstream_relations:
                if relation["source_decision_event_id"] != event_id:
                    continue
                kind = relation["relation_kind"]
                if kind not in _WORKSTREAM_KIND_DB:
                    raise ReviewSubmissionValidationError(
                        "compiled workstream relation kind is unsupported"
                    )
                provenance_json, provenance_sha256 = _relation_provenance(
                    relation["evidence"],
                    relation["provenance"],
                )
                self.connection.execute(
                    "INSERT INTO workstream_relations ("
                    "workstream_relation_id, item_id, workstream_id, relation_kind, "
                    "source_decision_event_id, relation_generation, provenance_json, "
                    "provenance_sha256, state"
                    ") VALUES (?, ?, ?, ?, ?, 1, ?, ?, 'CURRENT')",
                    (
                        relation["relation_id"],
                        relation["item_id"],
                        relation["workstream_id"],
                        _WORKSTREAM_KIND_DB[kind],
                        event_id,
                        provenance_json,
                        provenance_sha256,
                    ),
                )
            relation_action = None
            if compiled.document_relation_events:
                relation_action = _document_relation_action(action)
            for relation_event in compiled.document_relation_events:
                if relation_event["source_decision_event_id"] != event_id:
                    continue
                kind = relation_event["relation_kind"]
                direction = relation_event["direction"]
                if kind not in _DOCUMENT_KIND_DB or direction not in _DIRECTION_DB:
                    raise ReviewSubmissionValidationError(
                        "compiled document relation is unsupported"
                    )
                provenance_json, provenance_sha256 = _relation_provenance(
                    relation_event["evidence"],
                    relation_event["provenance"],
                )
                self.connection.execute(
                    "INSERT INTO document_relation_events ("
                    "relation_event_id, relation_id, canonical_item_id, related_item_id, "
                    "relation_kind, direction, action, source_decision_event_id, "
                    "supersedes_event_id, provenance_json, provenance_sha256, occurred_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                    (
                        relation_event["event_id"],
                        relation_event["relation_id"],
                        relation_event["canonical_item_id"],
                        relation_event["related_item_id"],
                        _DOCUMENT_KIND_DB[kind],
                        _DIRECTION_DB[direction],
                        relation_action,
                        event_id,
                        provenance_json,
                        provenance_sha256,
                        event["decided_at_utc"],
                    ),
                )
                self.connection.execute(
                    "INSERT INTO document_relations ("
                    "relation_id, canonical_item_id, related_item_id, relation_kind, "
                    "direction, source_relation_event_id, relation_generation, state"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, 'CURRENT')",
                    (
                        relation_event["relation_id"],
                        relation_event["canonical_item_id"],
                        relation_event["related_item_id"],
                        _DOCUMENT_KIND_DB[kind],
                        _DIRECTION_DB[direction],
                        relation_event["event_id"],
                    ),
                )
            for exception in compiled.unassigned_exceptions:
                if exception["source_decision_event_id"] != event_id:
                    continue
                condition = canonical_json_bytes(
                    {
                        "assignment_condition": exception["assignment_condition"],
                        "reason": exception["reason"],
                    }
                )
                self.connection.execute(
                    "INSERT INTO unassigned_exceptions ("
                    "unassigned_exception_id, item_id, reason, "
                    "assignment_condition_json, assignment_condition_sha256, "
                    "source_decision_event_id, exception_generation, state"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, 'CURRENT')",
                    (
                        exception["exception_id"],
                        exception["item_id"],
                        exception["reason"],
                        condition,
                        sha256_bytes(condition),
                        event_id,
                    ),
                )

    def _require_lineage_policy_reopen(
        self,
        request: ReopenReviewSubmissionRequest,
    ) -> None:
        decision = request.reopen_request
        row = _tuple_row(
            self.connection.execute(
                "SELECT b.campaign_id, r.policy_raw_hash, r.policy_full_hash, "
                "r.policy_writer_control_hash, r.policy_foundation_hash, "
                "r.policy_generation, r.policy_source_kind, "
                "r.policy_source_run_id, r.policy_guard_epoch "
                "FROM review_batches AS b "
                "JOIN campaigns AS c ON c.campaign_id = b.campaign_id "
                "JOIN inventory_runs AS r ON r.run_id = c.root_run_id "
                "WHERE b.batch_id = ?",
                (decision.batch_id,),
            ).fetchone()
        )
        expected = (
            decision.campaign_id,
            request.policy.raw_hash,
            request.policy.full_hash,
            request.policy.writer_control_hash,
            request.policy.foundation_hash,
            request.policy.generation,
            request.policy.source_kind,
            request.policy.source_run_id,
            request.policy.guard_epoch,
        )
        if row != expected:
            raise ReviewSubmissionConflict("batch policy authority is stale")

    def _require_base_head_reopen(
        self,
        request: ReopenReviewSubmissionRequest,
    ) -> None:
        decision = request.reopen_request
        row = _tuple_row(
            self.connection.execute(
                "SELECT b.campaign_id, c.status, b.status, "
                "b.current_snapshot_id, b.current_snapshot_sha256, "
                "b.review_revision, b.execution_generation "
                "FROM review_batches AS b "
                "JOIN campaigns AS c ON c.campaign_id = b.campaign_id "
                "WHERE b.batch_id = ?",
                (decision.batch_id,),
            ).fetchone()
        )
        expected = (
            decision.campaign_id,
            "READY",
            "OPEN",
            decision.base_snapshot_id,
            decision.base_snapshot_sha256,
            decision.expected_review_revision,
            decision.expected_execution_generation,
        )
        if row != expected:
            raise ReviewSubmissionConflict("OPEN batch head is stale")

    def _require_base_snapshot_reopen(
        self,
        request: ReopenReviewSubmissionRequest,
    ) -> None:
        decision = request.reopen_request
        row = _tuple_row(
            self.connection.execute(
                "SELECT lineage_kind, campaign_id, batch_id, version, "
                "payload_sha256, state FROM review_snapshots "
                "WHERE snapshot_id = ?",
                (decision.base_snapshot_id,),
            ).fetchone()
        )
        if row != (
            "BATCH",
            decision.campaign_id,
            decision.batch_id,
            decision.expected_review_revision,
            decision.base_snapshot_sha256,
            "PUBLISHED",
        ):
            raise ReviewSubmissionConflict("base review snapshot is stale")

    def _require_no_batch_event_reopen(
        self,
        request: ReopenReviewSubmissionRequest,
    ) -> None:
        row = self.connection.execute(
            "SELECT batch_event_id FROM batch_events "
            "WHERE batch_id = ? AND state = 'PREPARED'",
            (request.reopen_request.batch_id,),
        ).fetchone()
        if row is not None:
            raise ReviewSubmissionConflict(
                "an unresolved batch event blocks review submission"
            )

    def _require_reopen_projection(
        self,
        request: ReopenReviewSubmissionRequest,
    ) -> None:
        reopen = request.reopen_request
        event_id = request.compiled.event["event_id"]
        if self.connection.execute(
            "SELECT 1 FROM decision_events WHERE decision_event_id = ?",
            (event_id,),
        ).fetchone() is not None:
            raise ReviewSubmissionConflict(
                "reopen event identity is already materialized"
            )
        row = _tuple_row(
            self.connection.execute(
                "SELECT current_decision_id, projection_generation "
                "FROM item_curation_projection WHERE item_id = ?",
                (reopen.item_id,),
            ).fetchone()
        )
        if row is None:
            raise ReviewSubmissionConflict("reopen requires an existing projection")
        if row != (
            reopen.current_decision_event_id,
            reopen.current_projection_generation,
        ):
            raise ReviewSubmissionConflict("reopen projection head is stale")

    def _insert_reopen(self, prepared: PreparedReopenReviewSubmission) -> None:
        request = prepared.request
        reopen = request.reopen_request
        compiled = request.compiled
        event = compiled.event
        projection = compiled.projection
        revision = reopen.expected_review_revision + 1
        event_id = event["event_id"]
        payload = canonical_json_bytes(event)
        new_generation = int(projection["projection_generation"])
        prior = _tuple_row(
            self.connection.execute(
                "SELECT current_deferral_id FROM item_curation_projection "
                "WHERE item_id = ?",
                (reopen.item_id,),
            ).fetchone()
        )
        prior_deferral_id = prior[0] if prior is not None else None

        self.connection.execute(
            "INSERT INTO decision_events ("
            "decision_event_id, campaign_id, batch_id, item_id, snapshot_id, "
            "snapshot_sha256, review_revision, projection_generation, actor, "
            "action, current_decision_id, reason, payload_json, payload_sha256, "
            "occurred_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'REOPEN', NULL, ?, ?, ?, ?)",
            (
                event_id,
                reopen.campaign_id,
                reopen.batch_id,
                reopen.item_id,
                reopen.next_snapshot_id,
                prepared.publication.snapshot_sha256,
                revision,
                new_generation,
                event["actor"],
                event["reason"],
                payload,
                sha256_bytes(payload),
                event["reopened_at_utc"],
            ),
        )

        for supersession in compiled.supersessions:
            kind = supersession["kind"]
            subject_id = supersession["subject_id"]
            if kind == "decision-projection":
                if subject_id != reopen.current_decision_event_id:
                    raise ReviewSubmissionValidationError(
                        "reopen decision supersession target mismatch"
                    )
                continue
            if kind == "workstream-relation":
                updated = self.connection.execute(
                    "UPDATE workstream_relations SET state = 'SUPERSEDED' "
                    "WHERE workstream_relation_id = ? AND state = 'CURRENT'",
                    (subject_id,),
                ).rowcount
                if updated != 1:
                    raise ReviewSubmissionConflict(
                        "reopen workstream supersession failed"
                    )
                continue
            if kind == "document-relation":
                updated = self.connection.execute(
                    "UPDATE document_relations SET state = 'SUPERSEDED' "
                    "WHERE relation_id = ? AND state = 'CURRENT'",
                    (subject_id,),
                ).rowcount
                if updated != 1:
                    raise ReviewSubmissionConflict(
                        "reopen document supersession failed"
                    )
                continue
            raise ReviewSubmissionValidationError(
                "unsupported reopen supersession kind"
            )

        if prior_deferral_id is not None:
            self.connection.execute(
                "UPDATE deferrals SET state = 'SUPERSEDED' "
                "WHERE deferral_id = ? AND state = 'CURRENT'",
                (prior_deferral_id,),
            )

        updated = self.connection.execute(
            "UPDATE item_curation_projection SET "
            "primary_state = 'REVIEW_READY', current_decision_id = ?, "
            "current_deferral_id = NULL, source_event_id = ?, "
            "projection_generation = ?, correction_required = 0, "
            "unassigned = 0, reversal_available = 0 "
            "WHERE item_id = ? AND current_decision_id = ? "
            "AND projection_generation = ?",
            (
                event_id,
                event_id,
                new_generation,
                reopen.item_id,
                reopen.current_decision_event_id,
                reopen.current_projection_generation,
            ),
        ).rowcount
        if updated != 1:
            raise ReviewSubmissionConflict("reopen projection CAS failed")

    def _require_prepared_reopen(self, prepared: PreparedReopenReviewSubmission) -> None:
        if type(prepared) is not PreparedReopenReviewSubmission:
            raise TypeError("prepared must be PreparedReopenReviewSubmission")
        expected_publication = _publication_reopen(
            self.snapshot_root,
            prepared.request,
        )
        if prepared.publication != expected_publication:
            raise ReviewSubmissionPublicationError(
                "prepared reopen submission changed snapshot identity"
            )
        _validate_plan(
            self.snapshot_root,
            prepared.publication,
            prepared.plan,
        )
        if prepared.envelope != _reopen_submission_envelope(
            prepared.request,
            prepared.publication,
            prepared.plan,
        ):
            raise ReviewSubmissionPublicationError(
                "prepared reopen submission changed sealed envelope"
            )

    def _prepare_reopen_ledger(
        self,
        prepared: PreparedReopenReviewSubmission,
    ) -> Tuple[str, bool]:
        request = prepared.request
        decision = request.reopen_request
        staging_path, final_path = _sealed_paths(self.snapshot_root, prepared.plan)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._require_lineage_policy_reopen(request)
            self._require_base_head_reopen(request)
            self._require_base_snapshot_reopen(request)
            self._require_no_batch_event_reopen(request)
            unresolved = self.connection.execute(
                "SELECT submission_id FROM review_submissions "
                "WHERE batch_id = ? AND state = 'PREPARED'",
                (decision.batch_id,),
            ).fetchone()
            if unresolved is not None:
                raise ReviewSubmissionConflict(
                    "another unresolved batch submission exists"
                )
            self._require_reopen_projection(request)
            if self.connection.execute(
                "SELECT 1 FROM review_snapshots WHERE snapshot_id = ?",
                (decision.next_snapshot_id,),
            ).fetchone() is not None:
                raise ReviewSubmissionConflict(
                    "next snapshot id is already globally bound"
                )
            if os.path.lexists(final_path) or os.path.lexists(staging_path):
                raise ReviewSubmissionConflict(
                    "next snapshot filesystem identity is already bound"
                )
            self.connection.execute(
                "INSERT INTO review_submissions ("
                "submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
                "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
                "payload_sha256, final_path, final_sha256, state, "
                "expected_lineage_status, expected_review_revision, "
                "expected_execution_generation"
                ") VALUES (?, 'BATCH', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', "
                "'OPEN', ?, ?)",
                (
                    decision.submission_id,
                    decision.campaign_id,
                    decision.batch_id,
                    request.request_hash,
                    decision.next_snapshot_id,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    prepared.envelope,
                    sha256_bytes(prepared.envelope),
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                    decision.expected_review_revision,
                    decision.expected_execution_generation,
                ),
            )
            self.connection.execute(
                "INSERT INTO review_snapshots ("
                "snapshot_id, lineage_kind, campaign_id, batch_id, version, "
                "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
                "final_path, final_sha256, state, structural_approval_ready"
                ") VALUES (?, 'BATCH', ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', 0)",
                (
                    decision.next_snapshot_id,
                    decision.campaign_id,
                    decision.batch_id,
                    prepared.publication.version,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    prepared.publication.snapshot_sha256,
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                ),
            )
            self._require_current_policy(request)
            self._require_lineage_policy_reopen(request)
            self.connection.execute("COMMIT")
            return "PREPARED", False
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise ReviewSubmissionConflict(
                "reopen submission identity or lineage constraint failed"
            ) from exc
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _commit_reopen(self, prepared: PreparedReopenReviewSubmission) -> None:
        request = prepared.request
        decision = request.reopen_request
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._require_lineage_policy_reopen(request)
            try:
                self._require_base_head_reopen(request)
                self._require_base_snapshot_reopen(request)
                self._require_no_batch_event_reopen(request)
                self._require_reopen_projection(request)
            except ReviewSubmissionConflict as exc:
                raise _StalePreparedSubmission(str(exc)) from exc
            updated_batch = self.connection.execute(
                "UPDATE review_batches SET current_snapshot_id = ?, "
                "current_snapshot_sha256 = ?, review_revision = ? "
                "WHERE batch_id = ? AND campaign_id = ? AND status = 'OPEN' "
                "AND current_snapshot_id = ? AND current_snapshot_sha256 = ? "
                "AND review_revision = ? AND execution_generation = ?",
                (
                    decision.next_snapshot_id,
                    prepared.publication.snapshot_sha256,
                    decision.expected_review_revision + 1,
                    decision.batch_id,
                    decision.campaign_id,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    decision.expected_review_revision,
                    decision.expected_execution_generation,
                ),
            ).rowcount
            if updated_batch != 1:
                raise _StalePreparedSubmission(
                    "reopen submission final head CAS is stale"
                )
            self._insert_reopen(prepared)
            updated_snapshot = self.connection.execute(
                "UPDATE review_snapshots SET state = 'PUBLISHED' "
                "WHERE snapshot_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND version = ? AND parent_snapshot_id = ? "
                "AND parent_snapshot_sha256 = ? AND payload_sha256 = ? "
                "AND final_path = ? AND final_sha256 = ? "
                "AND structural_approval_ready = 0",
                (
                    decision.next_snapshot_id,
                    decision.batch_id,
                    prepared.publication.version,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    prepared.publication.snapshot_sha256,
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                ),
            ).rowcount
            updated_submission = self.connection.execute(
                "UPDATE review_submissions SET state = 'COMMITTED' "
                "WHERE submission_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND request_hash = ? AND snapshot_id = ? "
                "AND base_snapshot_id = ? AND base_snapshot_sha256 = ? "
                "AND payload_sha256 = ? AND final_path = ? AND final_sha256 = ? "
                "AND expected_lineage_status = 'OPEN' "
                "AND expected_review_revision = ? "
                "AND expected_execution_generation = ?",
                (
                    decision.submission_id,
                    decision.batch_id,
                    request.request_hash,
                    decision.next_snapshot_id,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    sha256_bytes(prepared.envelope),
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                    decision.expected_review_revision,
                    decision.expected_execution_generation,
                ),
            ).rowcount
            if (updated_snapshot, updated_submission) != (1, 1):
                raise _StalePreparedSubmission(
                    "reopen submission final CAS is stale"
                )
            self._require_current_policy(request)
            self._require_lineage_policy_reopen(request)
            self.connection.execute("COMMIT")
        except _StalePreparedSubmission as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise ReviewSubmissionConflict(
                "reopen submission final CAS is stale"
            ) from exc
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise ReviewSubmissionConflict(
                "reopen submission final CAS constraint is stale"
            ) from exc
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _result_reopen(
        self,
        prepared: PreparedReopenReviewSubmission,
        *,
        resumed: bool,
    ) -> ReviewSubmissionResult:
        decision = prepared.request.reopen_request
        return ReviewSubmissionResult(
            submission_id=decision.submission_id,
            submission_state="COMMITTED",
            batch_id=decision.batch_id,
            snapshot_id=decision.next_snapshot_id,
            snapshot_state="PUBLISHED",
            snapshot_version=prepared.publication.version,
            review_revision=decision.expected_review_revision + 1,
            execution_generation=decision.expected_execution_generation,
            parent_snapshot_id=decision.base_snapshot_id,
            parent_snapshot_sha256=decision.base_snapshot_sha256,
            snapshot_sha256=prepared.publication.snapshot_sha256,
            package_sha256=prepared.plan.package_sha256,
            final_path=prepared.plan.final_path,
            resumed=resumed,
        )

    def _submit_locked_reopen(
        self,
        prepared: PreparedReopenReviewSubmission,
    ) -> ReviewSubmissionResult:
        if self.connection.in_transaction:
            raise ReviewSubmissionConflict(
                "review submission requires transaction ownership"
            )
        self._verify_schema()
        self._require_prepared_reopen(prepared)
        self._require_current_policy(prepared.request)
        self._require_lineage_policy_reopen(prepared.request)
        try:
            _state, resumed = self._prepare_reopen_ledger(prepared)
        except ReviewSubmissionConflict as exc:
            raise ReviewSubmissionConflict(
                "prepared reopen submission is stale"
            ) from exc
        self.checkpoint("prepared")
        self._publish_or_readback(prepared)
        self.checkpoint("published")
        self._commit_reopen(prepared)
        self.checkpoint("committed")
        return self._result_reopen(prepared, resumed=resumed)

    def submit_prepared_reopen(
        self,
        prepared: PreparedReopenReviewSubmission,
    ) -> ReviewSubmissionResult:
        if type(prepared) is not PreparedReopenReviewSubmission:
            raise TypeError("prepared must be PreparedReopenReviewSubmission")
        placement_context = self.placement_shared()
        with placement_context:
            ledger_context = self.ledger_exclusive()
            with ledger_context:
                return self._submit_locked_reopen(prepared)

    def submit_reopen(
        self,
        request: ReopenReviewSubmissionRequest,
    ) -> ReviewSubmissionResult:
        if type(request) is not ReopenReviewSubmissionRequest:
            raise TypeError("request must be ReopenReviewSubmissionRequest")
        self._verify_schema()
        self._require_current_policy(request)
        self._require_lineage_policy_reopen(request)
        prepared = prepare_reopen_review_submission(
            self.snapshot_root,
            self.publisher,
            request,
        )
        return self.submit_prepared_reopen(prepared)

    def _commit(self, prepared: PreparedReviewSubmission) -> None:
        request = prepared.request
        decision = request.decision_request
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            self._require_prepared_binding(
                prepared,
                expected_state="PREPARED",
            )
            try:
                self._require_base_head(request)
                self._require_base_snapshot(request)
                self._require_no_batch_event(request)
                self._require_memberships(request)
                self._require_unmaterialized(request)
            except ReviewSubmissionConflict as exc:
                raise _StalePreparedSubmission(str(exc)) from exc
            updated_batch = self.connection.execute(
                "UPDATE review_batches SET current_snapshot_id = ?, "
                "current_snapshot_sha256 = ?, review_revision = ? "
                "WHERE batch_id = ? AND campaign_id = ? AND status = 'OPEN' "
                "AND current_snapshot_id = ? AND current_snapshot_sha256 = ? "
                "AND review_revision = ? AND execution_generation = ?",
                (
                    decision.next_snapshot_id,
                    prepared.publication.snapshot_sha256,
                    decision.expected_review_revision + 1,
                    decision.batch_id,
                    decision.campaign_id,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    decision.expected_review_revision,
                    decision.expected_execution_generation,
                ),
            ).rowcount
            if updated_batch != 1:
                raise _StalePreparedSubmission(
                    "review submission final head CAS is stale"
                )
            self._insert_decisions(prepared)
            updated_snapshot = self.connection.execute(
                "UPDATE review_snapshots SET state = 'PUBLISHED' "
                "WHERE snapshot_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND version = ? AND parent_snapshot_id = ? "
                "AND parent_snapshot_sha256 = ? AND payload_sha256 = ? "
                "AND final_path = ? AND final_sha256 = ? "
                "AND structural_approval_ready = 0",
                (
                    decision.next_snapshot_id,
                    decision.batch_id,
                    prepared.publication.version,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    prepared.publication.snapshot_sha256,
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                ),
            ).rowcount
            updated_submission = self.connection.execute(
                "UPDATE review_submissions SET state = 'COMMITTED' "
                "WHERE submission_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND request_hash = ? AND snapshot_id = ? "
                "AND base_snapshot_id = ? AND base_snapshot_sha256 = ? "
                "AND payload_sha256 = ? AND final_path = ? AND final_sha256 = ? "
                "AND expected_lineage_status = 'OPEN' "
                "AND expected_review_revision = ? "
                "AND expected_execution_generation = ?",
                (
                    decision.submission_id,
                    decision.batch_id,
                    request.request_hash,
                    decision.next_snapshot_id,
                    decision.base_snapshot_id,
                    decision.base_snapshot_sha256,
                    sha256_bytes(prepared.envelope),
                    str(prepared.plan.final_path),
                    prepared.plan.package_sha256,
                    decision.expected_review_revision,
                    decision.expected_execution_generation,
                ),
            ).rowcount
            if (updated_snapshot, updated_submission) != (1, 1):
                raise _StalePreparedSubmission(
                    "review submission final CAS is stale"
                )
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            self.connection.execute("COMMIT")
        except _StalePreparedSubmission as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            self._block_stale(prepared)
            raise ReviewSubmissionConflict(
                "review submission final CAS is stale"
            ) from exc
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            self._block_stale(prepared)
            raise ReviewSubmissionConflict(
                "review submission final CAS constraint is stale"
            ) from exc
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _result(
        self,
        prepared: PreparedReviewSubmission,
        *,
        resumed: bool,
    ) -> ReviewSubmissionResult:
        decision = prepared.request.decision_request
        return ReviewSubmissionResult(
            submission_id=decision.submission_id,
            submission_state="COMMITTED",
            batch_id=decision.batch_id,
            snapshot_id=decision.next_snapshot_id,
            snapshot_state="PUBLISHED",
            snapshot_version=prepared.publication.version,
            review_revision=decision.expected_review_revision + 1,
            execution_generation=decision.expected_execution_generation,
            parent_snapshot_id=decision.base_snapshot_id,
            parent_snapshot_sha256=decision.base_snapshot_sha256,
            snapshot_sha256=prepared.publication.snapshot_sha256,
            package_sha256=prepared.plan.package_sha256,
            final_path=prepared.plan.final_path,
            resumed=resumed,
        )

    def _require_prepared(self, prepared: PreparedReviewSubmission) -> None:
        if type(prepared) is not PreparedReviewSubmission:
            raise TypeError("prepared must be PreparedReviewSubmission")
        expected_publication = _publication(
            self.snapshot_root,
            prepared.request,
        )
        if prepared.publication != expected_publication:
            raise ReviewSubmissionPublicationError(
                "prepared review submission changed snapshot identity"
            )
        _validate_plan(
            self.snapshot_root,
            prepared.publication,
            prepared.plan,
        )
        if prepared.envelope != _submission_envelope(
            prepared.request,
            prepared.publication,
            prepared.plan,
        ):
            raise ReviewSubmissionPublicationError(
                "prepared review submission changed sealed envelope"
            )

    def _submit_locked(
        self,
        prepared: PreparedReviewSubmission,
    ) -> ReviewSubmissionResult:
        if self.connection.in_transaction:
            raise ReviewSubmissionConflict(
                "review submission requires transaction ownership"
            )
        self._verify_schema()
        self._require_prepared(prepared)
        self._require_current_policy(prepared.request)
        self._require_lineage_policy(prepared.request)
        try:
            state, resumed = self._prepare_ledger(prepared)
        except _StalePreparedSubmission as exc:
            self._block_stale(prepared)
            raise ReviewSubmissionConflict(
                "prepared review submission is stale"
            ) from exc
        if state == "COMMITTED":
            self._readback_snapshot(prepared)
            return self._result(prepared, resumed=True)
        self.checkpoint("prepared")
        self._publish_or_readback(prepared)
        self.checkpoint("published")
        self._commit(prepared)
        self.checkpoint("committed")
        return self._result(prepared, resumed=resumed)

    def submit(self, request: ReviewSubmissionRequest) -> ReviewSubmissionResult:
        """Plan outside writer guards, then submit or exactly resume."""

        if type(request) is not ReviewSubmissionRequest:
            raise TypeError("request must be ReviewSubmissionRequest")
        self._verify_schema()
        self._require_current_policy(request)
        self._require_lineage_policy(request)
        prepared = prepare_review_submission(
            self.snapshot_root,
            self.publisher,
            request,
        )
        return self.submit_prepared(prepared)

    def resume(self, submission_id: str) -> ReviewSubmissionResult:
        """Replan only the exact stored envelope, then resume under guards."""

        submission_id = _identifier(submission_id, "submission id")
        if self.connection.in_transaction:
            raise ReviewSubmissionConflict(
                "review submission requires transaction ownership"
            )
        self._verify_schema()
        row = self.connection.execute(
            "SELECT payload_json, state FROM review_submissions "
            "WHERE submission_id = ?",
            (submission_id,),
        ).fetchone()
        if row is None:
            raise ReviewSubmissionConflict("review submission does not exist")
        if row[1] not in ("PREPARED", "COMMITTED"):
            raise ReviewSubmissionConflict(
                "review submission is not exactly resumable"
            )
        envelope = _as_bytes(row[0], "stored submission payload")
        request = _request_from_envelope(envelope)
        if request.decision_request.submission_id != submission_id:
            raise ReviewSubmissionConflict(
                "stored review submission identity changed"
            )
        self._require_current_policy(request)
        self._require_lineage_policy(request)
        prepared = prepare_review_submission(
            self.snapshot_root,
            self.publisher,
            request,
        )
        if prepared.envelope != envelope:
            raise ReviewSubmissionConflict(
                "stored review submission cannot be replanned exactly"
            )
        return self.submit_prepared(prepared)

    def submit_prepared(
        self,
        prepared: PreparedReviewSubmission,
    ) -> ReviewSubmissionResult:
        """Apply one exact reader-prepared submission under writer guards."""

        if type(prepared) is not PreparedReviewSubmission:
            raise TypeError("prepared must be PreparedReviewSubmission")
        placement_context = self.placement_shared()
        if not hasattr(placement_context, "__enter__") or not hasattr(
            placement_context,
            "__exit__",
        ):
            raise TypeError("placement_shared must return a context manager")
        with placement_context:
            ledger_context = self.ledger_exclusive()
            if not hasattr(ledger_context, "__enter__") or not hasattr(
                ledger_context,
                "__exit__",
            ):
                raise TypeError("ledger_exclusive must return a context manager")
            with ledger_context:
                return self._submit_locked(prepared)


__all__ = [
    "PreparedReopenReviewSubmission",
    "PreparedReviewSubmission",
    "ReopenReviewSubmissionRequest",
    "ReviewSubmissionConflict",
    "ReviewSubmissionError",
    "ReviewSubmissionPublicationError",
    "ReviewSubmissionPublisher",
    "ReviewSubmissionRequest",
    "ReviewSubmissionResult",
    "ReviewSubmissionValidationError",
    "SnapshotPublication",
    "SnapshotPublishPlan",
    "SnapshotPublishResult",
    "prepare_reopen_review_submission",
    "prepare_review_submission",
]
