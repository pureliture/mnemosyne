"""Bounded review-batch genesis and immutable snapshot publication.

This module deliberately owns no schema DDL and imports no renderer.  The
``ledger_schema`` migration must already be applied.  A two-phase publisher
plans exact package identity before the PREPARED transaction and must return
that same identity after immutable publish/readback.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

from . import admission, ledger_schema, review_context
from . import legacy_import
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_RISK_BANDS = frozenset(("low", "medium", "high", "blocked"))
_ACTIONS = frozenset(("keep", "link", "move", "archive", "defer", "exclude"))
_FRESHNESS = frozenset(("fresh", "stale", "unknown"))
_WARNING_CODES = frozenset(
    (
        "m2-no-structural-authority",
        "private-metadata-only",
        "opaque-content-unopened",
        "reference-incomplete",
        "lifecycle-frozen",
        "competing-candidate",
        "inventory-error",
    )
)
_EFFECT_CODES = frozenset(("none", "plan-unavailable-m2"))
_STRUCTURAL_BLOCKER = "effect-preview-not-available-m2"
_INDIVIDUAL_SCOPE_CLASSES = frozenset(
    (
        "private-reviewable",
        "opaque-private-evidence",
        "opaque",
    )
)


class BatchServiceError(Exception):
    """Base error for batch genesis and snapshot publication."""


class BatchValidationError(BatchServiceError, ValueError):
    """The requested batch is malformed, unbounded, or heterogeneous."""


class BatchConflictError(BatchServiceError):
    """Current campaign, batch lineage, or membership conflicts."""


class BatchPublicationError(BatchServiceError):
    """The immutable package plan or publish readback is invalid."""


def _tuple_row(value: object) -> Optional[tuple]:
    return None if value is None else tuple(value)


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise BatchValidationError("%s is invalid" % label)
    return value


def _sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise BatchValidationError("%s is invalid" % label)
    return value


def _canonical_path(value: str, label: str = "path") -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise BatchValidationError("%s must be raw-relative" % label)
    if (
        posixpath.normpath(value) != value
        or value in (".", "..")
        or value.startswith("../")
        or value.endswith("/")
    ):
        raise BatchValidationError("%s must be canonical" % label)
    if any(ord(character) < 0x20 for character in value):
        raise BatchValidationError("%s contains control characters" % label)
    return value


def _paths_overlap(left: str, right: str) -> bool:
    return (
        left == right
        or left.startswith(right + "/")
        or right.startswith(left + "/")
    )


def _ordered_unique_strings(
    values: Tuple[str, ...],
    *,
    label: str,
    identifier: bool = True,
) -> Tuple[str, ...]:
    if type(values) is not tuple or not values:
        raise BatchValidationError("%s must be a non-empty tuple" % label)
    if len(set(values)) != len(values):
        raise BatchValidationError("%s must be unique" % label)
    for value in values:
        if identifier:
            _identifier(value, label)
        else:
            _canonical_path(value, label)
    return values


def _sorted_codes(values: Tuple[str, ...], label: str) -> Tuple[str, ...]:
    if type(values) is not tuple or tuple(sorted(set(values))) != values:
        raise BatchValidationError("%s must be unique and sorted" % label)
    for value in values:
        _identifier(value, label)
    return values


@dataclass(frozen=True)
class BatchUnit:
    unit_id: str
    unit_kind: str
    path: str
    display_path: str
    member_item_ids: Tuple[str, ...]
    member_paths: Tuple[str, ...]
    scope_class: str
    sensitivity: str
    access_domain: str
    primary_workstream: str
    related_workstreams: Tuple[str, ...]
    shared: bool
    document_role: str
    authority: str
    document_lifecycle: str
    lifecycle_class: str
    override_class: str
    scope_rule_id: str
    recommended_action: str
    target_path: Optional[str]
    reference_complete: bool
    risk_band: str
    context_freshness: str
    evidence_providers: Tuple[str, ...]
    warning_codes: Tuple[str, ...]
    effect_codes: Tuple[str, ...]
    canonical_conflict: bool
    relation_conflict: bool
    target_proven: bool
    analysis_provenance_json: bytes
    file_count: int
    total_bytes: int
    effect_count: int

    def __post_init__(self) -> None:
        _identifier(self.unit_id, "unit id")
        if self.unit_kind not in ("folder", "file"):
            raise BatchValidationError("unit kind is invalid")
        object.__setattr__(self, "path", _canonical_path(self.path, "unit path"))
        if not isinstance(self.display_path, str) or not self.display_path:
            raise BatchValidationError("display path is required")
        _ordered_unique_strings(
            self.member_item_ids,
            label="member item ids",
        )
        if any(_UUID4.fullmatch(item_id) is None for item_id in self.member_item_ids):
            raise BatchValidationError("member item ids must be canonical UUID4")
        _ordered_unique_strings(
            self.member_paths,
            label="member paths",
            identifier=False,
        )
        if len(self.member_item_ids) != len(self.member_paths):
            raise BatchValidationError("member ids and paths must have equal length")
        for member_path in self.member_paths:
            if not (
                member_path == self.path
                or member_path.startswith(self.path + "/")
            ):
                raise BatchValidationError("member path is outside unit path")
        for label, value in (
            ("sensitivity", self.sensitivity),
            ("scope class", self.scope_class),
            ("access domain", self.access_domain),
            ("primary workstream", self.primary_workstream),
            ("document role", self.document_role),
            ("authority", self.authority),
            ("document lifecycle", self.document_lifecycle),
            ("lifecycle class", self.lifecycle_class),
            ("override class", self.override_class),
            ("scope rule id", self.scope_rule_id),
        ):
            _identifier(value, label)
        if type(self.related_workstreams) is not tuple or tuple(
            sorted(set(self.related_workstreams))
        ) != self.related_workstreams:
            raise BatchValidationError(
                "related workstreams must be unique and sorted"
            )
        for workstream in self.related_workstreams:
            _identifier(workstream, "related workstream")
        if type(self.shared) is not bool:
            raise BatchValidationError("shared must be boolean")
        if type(self.reference_complete) is not bool:
            raise BatchValidationError("reference_complete must be boolean")
        if type(self.target_proven) is not bool:
            raise BatchValidationError("target_proven must be boolean")
        if type(self.canonical_conflict) is not bool:
            raise BatchValidationError("canonical_conflict must be boolean")
        if type(self.relation_conflict) is not bool:
            raise BatchValidationError("relation_conflict must be boolean")
        if self.recommended_action not in _ACTIONS:
            raise BatchValidationError("recommended action is invalid")
        if self.target_path is not None:
            object.__setattr__(
                self,
                "target_path",
                _canonical_path(self.target_path, "target path"),
            )
        if self.recommended_action in ("move", "archive"):
            if self.target_path is None:
                raise BatchValidationError("movement action requires a target path")
        elif self.target_path is not None:
            raise BatchValidationError("nonmovement action cannot carry a target path")
        if self.target_proven != (self.target_path is not None):
            raise BatchValidationError("target proof and target path disagree")
        if self.risk_band not in _RISK_BANDS:
            raise BatchValidationError("risk band is invalid")
        if self.context_freshness not in _FRESHNESS:
            raise BatchValidationError("context freshness is invalid")
        _sorted_codes(self.evidence_providers, "evidence providers")
        _sorted_codes(self.warning_codes, "warning codes")
        _sorted_codes(self.effect_codes, "effect codes")
        if set(self.warning_codes) - _WARNING_CODES:
            raise BatchValidationError("warning codes contain unsupported values")
        if set(self.effect_codes) - _EFFECT_CODES:
            raise BatchValidationError("effect codes contain unsupported values")
        if "m2-no-structural-authority" not in self.warning_codes:
            raise BatchValidationError(
                "M2 review unit requires no-structural-authority warning"
            )
        if "plan-unavailable-m2" not in self.effect_codes:
            raise BatchValidationError(
                "M2 review unit requires plan-unavailable effect"
            )
        private_boundary = (
            self.sensitivity == "private"
            or self.scope_class == "private-reviewable"
        )
        opaque_boundary = self.scope_class in (
            "opaque-private-evidence",
            "opaque",
        )
        if private_boundary and "private-metadata-only" not in self.warning_codes:
            raise BatchValidationError(
                "private review unit requires metadata-only warning"
            )
        if opaque_boundary and "opaque-content-unopened" not in self.warning_codes:
            raise BatchValidationError(
                "opaque review unit requires unopened-content warning"
            )
        if (
            not self.reference_complete
            and "reference-incomplete" not in self.warning_codes
        ):
            raise BatchValidationError(
                "incomplete reference unit requires reference warning"
            )
        if (
            self.override_class != "none"
            and "lifecycle-frozen" not in self.warning_codes
        ):
            raise BatchValidationError(
                "override unit requires lifecycle warning"
            )
        if (
            self.canonical_conflict or self.relation_conflict
        ) and "competing-candidate" not in self.warning_codes:
            raise BatchValidationError(
                "conflicted review unit requires competing-candidate warning"
            )
        if (private_boundary or opaque_boundary) and (
            self.recommended_action in ("move", "archive")
            or self.target_path is not None
        ):
            raise BatchValidationError(
                "private or opaque review unit cannot be movement-ready"
            )
        for label, value in (
            ("file count", self.file_count),
            ("total bytes", self.total_bytes),
            ("effect count", self.effect_count),
        ):
            if type(value) is not int or value < 0:
                raise BatchValidationError("%s must be non-negative" % label)
        if self.file_count != len(self.member_item_ids):
            raise BatchValidationError("file count must equal member count")
        try:
            provenance = json.loads(self.analysis_provenance_json.decode("utf-8"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BatchValidationError("analysis provenance is invalid") from exc
        if canonical_json_bytes(provenance) != self.analysis_provenance_json:
            raise BatchValidationError("analysis provenance is not canonical")
        if (
            type(provenance) is not dict
            or set(provenance) != {"items", "schema_version"}
            or provenance["schema_version"] != 1
            or type(provenance["items"]) is not list
            or any(
                type(row) is not dict
                or set(row) != {"item_id", "reference", "risk", "target"}
                or type(row["reference"]) is not dict
                or type(row["risk"]) is not dict
                or type(row["target"]) is not dict
                for row in provenance["items"]
            )
        ):
            raise BatchValidationError("analysis provenance fields are invalid")
        if [row["item_id"] for row in provenance["items"]] != sorted(
            self.member_item_ids
        ):
            raise BatchValidationError("analysis provenance membership is invalid")
        if any(
            row["reference"].get("complete") is not self.reference_complete
            or row["target"].get("status")
            != ("resolved" if self.target_proven else "blocked")
            or row["risk"].get("band") != self.risk_band
            or _SHA256.fullmatch(row["reference"].get("input_manifest_sha256", ""))
            is None
            or _SHA256.fullmatch(row["target"].get("input_sha256", "")) is None
            or _SHA256.fullmatch(row["risk"].get("input_sha256", "")) is None
            for row in provenance["items"]
        ):
            raise BatchValidationError("analysis provenance binding is invalid")

    def homogeneity_key(self) -> Tuple[object, ...]:
        return (
            self.scope_class,
            self.sensitivity,
            self.access_domain,
            self.primary_workstream,
            self.related_workstreams,
            self.shared,
            self.document_role,
            self.authority,
            self.document_lifecycle,
            self.lifecycle_class,
            self.override_class,
            self.scope_rule_id,
            self.recommended_action,
            self.reference_complete,
            self.target_proven,
            self.risk_band,
            self.canonical_conflict,
            self.relation_conflict,
        )

    def to_dict(self) -> dict:
        return {
            "access_domain": self.access_domain,
            "analysis_provenance": json.loads(
                self.analysis_provenance_json.decode("utf-8")
            ),
            "authority": self.authority,
            "canonical_conflict": self.canonical_conflict,
            "canonical_path": self.path,
            "context_freshness": self.context_freshness,
            "display_path": self.display_path,
            "document_lifecycle": self.document_lifecycle,
            "document_role": self.document_role,
            "effect_count": self.effect_count,
            "effect_codes": list(self.effect_codes),
            "evidence_providers": list(self.evidence_providers),
            "file_count": self.file_count,
            "lifecycle_class": self.lifecycle_class,
            "member_item_ids": list(self.member_item_ids),
            "member_paths": list(self.member_paths),
            "override_class": self.override_class,
            "primary_workstream": self.primary_workstream,
            "recommended_action": self.recommended_action,
            "reference_complete": self.reference_complete,
            "relation_conflict": self.relation_conflict,
            "related_workstreams": list(self.related_workstreams),
            "risk_band": self.risk_band,
            "scope_rule_id": self.scope_rule_id,
            "scope_class": self.scope_class,
            "sensitivity": self.sensitivity,
            "shared": self.shared,
            "target_path": self.target_path,
            "target_proven": self.target_proven,
            "total_bytes": self.total_bytes,
            "unit_id": self.unit_id,
            "unit_kind": self.unit_kind,
            "underlying_file_count": self.file_count,
            "warning_codes": list(self.warning_codes),
        }


@dataclass(frozen=True)
class OpenBatchRequest:
    campaign_id: str
    expected_campaign_head_sha256: str
    expected_campaign_review_revision: int
    policy: admission.ApprovedPolicyRef
    batch_id: str
    snapshot_id: str
    submission_id: str
    actor: str
    review_context_json: bytes
    analysis_contexts_json: bytes
    units: Tuple[BatchUnit, ...]
    max_items: int
    max_files: int
    max_bytes: int
    max_effects: int

    def __post_init__(self) -> None:
        for label, value in (
            ("campaign id", self.campaign_id),
            ("batch id", self.batch_id),
            ("snapshot id", self.snapshot_id),
            ("submission id", self.submission_id),
        ):
            _identifier(value, label)
        _sha256(self.expected_campaign_head_sha256, "campaign head hash")
        if (
            type(self.expected_campaign_review_revision) is not int
            or self.expected_campaign_review_revision < 1
        ):
            raise BatchValidationError(
                "campaign review revision must be positive"
            )
        if not isinstance(self.policy, admission.ApprovedPolicyRef):
            raise BatchValidationError("policy must be ApprovedPolicyRef")
        if (
            not isinstance(self.actor, str)
            or not self.actor.strip()
            or self.actor != self.actor.strip()
            or any(ord(character) < 0x20 for character in self.actor)
        ):
            raise BatchValidationError("actor is invalid")
        try:
            review_context.ReviewContext.from_canonical_bytes(
                self.review_context_json
            )
        except (TypeError, review_context.ReviewContextError) as exc:
            raise BatchValidationError("review context is invalid") from exc
        if type(self.units) is not tuple or not self.units:
            raise BatchValidationError("units must be a non-empty tuple")
        if any(type(unit) is not BatchUnit for unit in self.units):
            raise BatchValidationError("units must contain BatchUnit values")
        try:
            analysis_contexts = (
                review_context.AnalysisContextBundle.from_canonical_bytes(
                    self.analysis_contexts_json
                )
            )
            analysis_contexts.require_exact_unit_bindings(self.units)
        except (TypeError, review_context.ReviewContextError) as exc:
            raise BatchValidationError("analysis contexts are invalid") from exc
        if len({unit.unit_id for unit in self.units}) != len(self.units):
            raise BatchValidationError("unit ids must be unique")
        item_ids = [item_id for unit in self.units for item_id in unit.member_item_ids]
        member_paths = [path for unit in self.units for path in unit.member_paths]
        if len(item_ids) != len(set(item_ids)):
            raise BatchValidationError("member item ids overlap")
        if len(member_paths) != len(set(member_paths)):
            raise BatchValidationError("member paths overlap")
        for index, left in enumerate(self.units):
            for right in self.units[index + 1 :]:
                if _paths_overlap(left.path, right.path):
                    raise BatchValidationError("unit resource paths overlap")
        if len({unit.homogeneity_key() for unit in self.units}) != 1:
            raise BatchValidationError("batch units must be homogeneous")
        if len(self.units) > 1:
            unit = self.units[0]
            individual_reasons = (
                unit.sensitivity == "private",
                unit.scope_class in _INDIVIDUAL_SCOPE_CLASSES,
                not unit.reference_complete,
                unit.override_class != "none",
                unit.risk_band in ("high", "blocked"),
                unit.canonical_conflict,
                unit.relation_conflict,
            )
            if any(individual_reasons):
                raise BatchValidationError(
                    "private, opaque, incomplete, override, conflict, or high-risk "
                    "review units require an individual batch"
                )
        for label, value in (
            ("items bound", self.max_items),
            ("files bound", self.max_files),
            ("bytes bound", self.max_bytes),
            ("effects bound", self.max_effects),
        ):
            if type(value) is not int or value < 1:
                raise BatchValidationError("%s must be positive" % label)
        totals = (
            ("items bound", len(item_ids), self.max_items),
            ("files bound", sum(unit.file_count for unit in self.units), self.max_files),
            ("bytes bound", sum(unit.total_bytes for unit in self.units), self.max_bytes),
            ("effects bound", sum(unit.effect_count for unit in self.units), self.max_effects),
        )
        for label, observed, bound in totals:
            if observed > bound:
                raise BatchValidationError("%s exceeded" % label)

    def request_payload(self) -> dict:
        return {
            "analysis_contexts": json.loads(
                self.analysis_contexts_json.decode("utf-8")
            ),
            "actor": self.actor,
            "batch_id": self.batch_id,
            "bounds": {
                "bytes": self.max_bytes,
                "effects": self.max_effects,
                "files": self.max_files,
                "items": self.max_items,
            },
            "campaign": {
                "expected_head_sha256": self.expected_campaign_head_sha256,
                "expected_review_revision": self.expected_campaign_review_revision,
                "id": self.campaign_id,
            },
            "policy": {
                "foundation_hash": self.policy.foundation_hash,
                "full_hash": self.policy.full_hash,
                "generation": self.policy.generation,
                "guard_epoch": self.policy.guard_epoch,
                "raw_hash": self.policy.raw_hash,
                "source_kind": self.policy.source_kind,
                "source_run_id": self.policy.source_run_id,
                "writer_control_hash": self.policy.writer_control_hash,
            },
            "review_context": json.loads(
                self.review_context_json.decode("utf-8")
            ),
            "schema_version": 2,
            "snapshot_id": self.snapshot_id,
            "submission_id": self.submission_id,
            "units": [
                unit.to_dict()
                for unit in sorted(self.units, key=lambda value: value.unit_id)
            ],
        }

    @property
    def request_hash(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.request_payload()))


@dataclass(frozen=True)
class SnapshotPublication:
    snapshot_id: str
    batch_id: str
    version: int
    canonical_payload: bytes
    snapshot_sha256: str
    final_path: Path
    structural_approval_ready: bool
    structural_blocker: str


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
class PreparedBatchPublication:
    """Exact immutable publication inputs prepared outside the writer lock."""

    publication: SnapshotPublication
    plan: SnapshotPublishPlan
    envelope: bytes

    def __post_init__(self) -> None:
        if type(self.publication) is not SnapshotPublication:
            raise TypeError("publication must be SnapshotPublication")
        if type(self.plan) is not SnapshotPublishPlan:
            raise TypeError("plan must be SnapshotPublishPlan")
        if type(self.envelope) is not bytes:
            raise TypeError("envelope must be bytes")


@dataclass(frozen=True)
class OpenBatchResult:
    batch_id: str
    status: str
    snapshot_id: str
    snapshot_state: str
    snapshot_version: int
    review_revision: int
    snapshot_sha256: str
    package_sha256: str
    final_path: Path
    structural_approval_ready: bool
    structural_blocker: str
    resumed: bool


def _require_owner_only_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BatchPublicationError("%s directory is unreadable" % label) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise BatchPublicationError("%s directory identity is invalid" % label)


def _batch_snapshot_payload(request: OpenBatchRequest) -> dict:
    return {
        "analysis_contexts": json.loads(
            request.analysis_contexts_json.decode("utf-8")
        ),
        "actor": request.actor,
        "approval_ready": False,
        "batch_id": request.batch_id,
        "batch_version": 1,
        "bounds": request.request_payload()["bounds"],
        "campaign_id": request.campaign_id,
        "campaign_snapshot_sha256": request.expected_campaign_head_sha256,
        "campaign_review_revision": request.expected_campaign_review_revision,
        "parent_snapshot_id": None,
        "parent_snapshot_sha256": None,
        "request_hash": request.request_hash,
        "review_context": json.loads(
            request.review_context_json.decode("utf-8")
        ),
        "schema_version": 2,
        "snapshot_id": request.snapshot_id,
        "structural_approval_ready": False,
        "structural_blocker": _STRUCTURAL_BLOCKER,
        "units": [
            unit.to_dict()
            for unit in sorted(request.units, key=lambda value: value.unit_id)
        ],
    }


def _batch_publication(
    snapshot_root: Path,
    request: OpenBatchRequest,
) -> SnapshotPublication:
    payload = canonical_json_bytes(_batch_snapshot_payload(request))
    return SnapshotPublication(
        snapshot_id=request.snapshot_id,
        batch_id=request.batch_id,
        version=1,
        canonical_payload=payload,
        snapshot_sha256=sha256_bytes(payload),
        final_path=snapshot_root / request.snapshot_id,
        structural_approval_ready=False,
        structural_blocker=_STRUCTURAL_BLOCKER,
    )


def _batch_sealed_paths(
    snapshot_root: Path,
    plan: SnapshotPublishPlan,
) -> Tuple[Path, Path]:
    staging_path = getattr(plan.sealed_payload, "staging_path", None)
    final_path = getattr(plan.sealed_payload, "final_path", None)
    if not isinstance(staging_path, Path) or not isinstance(final_path, Path):
        raise BatchPublicationError(
            "publisher must seal full snapshot staging and final paths"
        )
    expected_staging = snapshot_root / (
        ".incomplete-%s" % plan.publication.snapshot_id
    )
    if staging_path != expected_staging or final_path != plan.final_path:
        raise BatchPublicationError("publisher sealed paths are invalid")
    return staging_path, final_path


def _validate_batch_plan(
    snapshot_root: Path,
    publication: SnapshotPublication,
    plan: SnapshotPublishPlan,
) -> None:
    if type(plan) is not SnapshotPublishPlan:
        raise BatchPublicationError("publisher plan type is invalid")
    if plan.publication != publication:
        raise BatchPublicationError("publisher plan changed snapshot publication")
    if plan.final_path != publication.final_path or not plan.final_path.is_absolute():
        raise BatchPublicationError("publisher plan final path is invalid")
    try:
        _sha256(plan.package_sha256, "publisher package hash")
        _sha256(plan.sealed_identity_sha256, "publisher sealed identity hash")
    except BatchValidationError as exc:
        raise BatchPublicationError(str(exc)) from exc
    _batch_sealed_paths(snapshot_root, plan)


def _batch_submission_envelope(
    request: OpenBatchRequest,
    publication: SnapshotPublication,
    plan: SnapshotPublishPlan,
) -> bytes:
    return canonical_json_bytes(
        {
            "publish_plan": {
                "final_path": str(plan.final_path),
                "package_sha256": plan.package_sha256,
                "sealed_identity_sha256": plan.sealed_identity_sha256,
            },
            "request": request.request_payload(),
            "request_hash": request.request_hash,
            "schema_version": 2,
            "snapshot": json.loads(publication.canonical_payload.decode("utf-8")),
            "snapshot_sha256": publication.snapshot_sha256,
        }
    )


def prepare_batch_publication(
    snapshot_root: Path,
    publisher: object,
    request: OpenBatchRequest,
) -> PreparedBatchPublication:
    """Prepare and seal one genesis renderer plan without a ledger writer."""

    if type(request) is not OpenBatchRequest:
        raise TypeError("request must be OpenBatchRequest")
    root = Path(snapshot_root).resolve()
    if not callable(getattr(publisher, "plan", None)) or not callable(
        getattr(publisher, "publish", None)
    ):
        raise TypeError("publisher must provide plan() and publish()")
    publication = _batch_publication(root, request)
    plan = publisher.plan(publication)
    _validate_batch_plan(root, publication, plan)
    return PreparedBatchPublication(
        publication=publication,
        plan=plan,
        envelope=_batch_submission_envelope(request, publication, plan),
    )


class BatchService:
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
        canonical_root: Optional[Path] = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if connection.in_transaction:
            raise BatchConflictError("batch service requires transaction ownership")
        self.connection = connection
        self.snapshot_root = Path(snapshot_root).resolve()
        if not callable(placement_shared) or not callable(ledger_exclusive):
            raise TypeError("placement_shared and ledger_exclusive guards are required")
        self.placement_shared = placement_shared
        self.ledger_exclusive = ledger_exclusive
        if publisher is None:
            raise TypeError("publisher is required")
        self.publisher = publisher
        if not callable(getattr(self.publisher, "plan", None)) or not callable(
            getattr(self.publisher, "publish", None)
        ):
            raise TypeError("publisher must provide plan() and publish()")
        if not callable(current_policy):
            raise TypeError("current_policy is required")
        self.current_policy = current_policy
        self.checkpoint = checkpoint or (lambda _point: None)
        if canonical_root is None:
            self.canonical_root = None
        else:
            resolved = Path(canonical_root).resolve()
            if not resolved.is_absolute():
                raise BatchValidationError("canonical root must be absolute")
            self.canonical_root = resolved

    def _validate_no_legacy_pending_collision(self, request: OpenBatchRequest) -> None:
        if self.canonical_root is None:
            return
        paths = tuple(unit.path for unit in request.units)
        blockers = legacy_import.legacy_pending_blockers_for_membership_paths(
            self.canonical_root,
            paths,
        )
        if blockers:
            raise BatchConflictError(
                "legacy pending collision blocks curation batch approval-ready"
            )

    def _require_current_policy(self, request: OpenBatchRequest) -> None:
        try:
            observed = self.current_policy()
        except Exception as exc:
            raise BatchConflictError("current policy authority drifted") from exc
        if observed != request.policy:
            raise BatchConflictError("current policy authority drifted")

    def _campaign_row(self, request: OpenBatchRequest) -> Tuple[str, str, int]:
        row = _tuple_row(self.connection.execute(
            "SELECT c.status, c.current_snapshot_sha256, c.review_revision, "
            "r.policy_raw_hash, r.policy_full_hash, "
            "r.policy_writer_control_hash, r.policy_foundation_hash, "
            "r.policy_generation, r.policy_source_kind, "
            "r.policy_source_run_id, r.policy_guard_epoch "
            "FROM campaigns AS c "
            "JOIN inventory_runs AS r ON r.run_id = c.root_run_id "
            "WHERE c.campaign_id = ?",
            (request.campaign_id,),
        ).fetchone())
        if row is None:
            raise BatchConflictError("campaign does not exist")
        status, head_sha256, review_revision = row[:3]
        if status != "READY":
            raise BatchConflictError("campaign is not READY")
        if head_sha256 != request.expected_campaign_head_sha256:
            raise BatchConflictError("campaign head is stale")
        if review_revision != request.expected_campaign_review_revision:
            raise BatchConflictError("campaign review revision is stale")
        if row[3:] != (
            request.policy.raw_hash,
            request.policy.full_hash,
            request.policy.writer_control_hash,
            request.policy.foundation_hash,
            request.policy.generation,
            request.policy.source_kind,
            request.policy.source_run_id,
            request.policy.guard_epoch,
        ):
            raise BatchConflictError("campaign policy authority is stale")
        return status, head_sha256, review_revision

    def _validate_no_active_overlap(self, request: OpenBatchRequest) -> None:
        rows = self.connection.execute(
            "SELECT item_id, path FROM batch_memberships "
            "WHERE status IN ('OPEN', 'CLAIMED')"
        ).fetchall()
        requested = [
            (item_id, unit.path)
            for unit in request.units
            for item_id in unit.member_item_ids
        ]
        for item_id, path in requested:
            for existing_item_id, existing_path in rows:
                if item_id == existing_item_id or _paths_overlap(path, existing_path):
                    raise BatchConflictError("active batch membership overlap")

    def _membership_rows(
        self,
        request: OpenBatchRequest,
    ) -> Tuple[Tuple[str, str, str, str, str, str], ...]:
        rows = []
        for unit in sorted(request.units, key=lambda value: value.unit_id):
            for item_id in unit.member_item_ids:
                digest = sha256_bytes(
                    canonical_json_bytes(
                        {
                            "batch_id": request.batch_id,
                            "item_id": item_id,
                            "path": unit.path,
                            "unit_id": unit.unit_id,
                        }
                    )
                )
                rows.append(
                    (
                        "membership-%s" % digest[:24],
                        request.batch_id,
                        unit.unit_id,
                        item_id,
                        unit.path,
                        "OPEN",
                    )
                )
        return tuple(rows)

    def _existing_state(
        self,
        request: OpenBatchRequest,
        envelope: bytes,
        publication: SnapshotPublication,
        plan: SnapshotPublishPlan,
    ) -> Optional[OpenBatchResult]:
        batch = _tuple_row(self.connection.execute(
            "SELECT request_hash, status, current_snapshot_id, "
            "current_snapshot_sha256, review_revision, execution_generation "
            "FROM review_batches WHERE batch_id = ?",
            (request.batch_id,),
        ).fetchone())
        if batch is None:
            return None
        if batch[0] != request.request_hash:
            raise BatchConflictError("batch id is bound to another request")
        submission = _tuple_row(self.connection.execute(
            "SELECT submission_id, snapshot_id, payload_json, payload_sha256, "
            "final_path, final_sha256, state FROM review_submissions "
            "WHERE batch_id = ?",
            (request.batch_id,),
        ).fetchone())
        snapshot = _tuple_row(self.connection.execute(
            "SELECT snapshot_id, version, payload_sha256, final_path, "
            "final_sha256, state, structural_approval_ready "
            "FROM review_snapshots WHERE batch_id = ?",
            (request.batch_id,),
        ).fetchone())
        if submission is None or snapshot is None:
            raise BatchConflictError("batch genesis is incomplete")
        expected_submission = (
            request.submission_id,
            request.snapshot_id,
            envelope,
            sha256_bytes(envelope),
            str(plan.final_path),
            plan.package_sha256,
        )
        if tuple(submission[:6]) != expected_submission:
            raise BatchConflictError("batch request does not match prepared submission")
        expected_snapshot = (
            request.snapshot_id,
            1,
            publication.snapshot_sha256,
            str(plan.final_path),
            plan.package_sha256,
        )
        if tuple(snapshot[:5]) != expected_snapshot:
            raise BatchConflictError("snapshot id is bound to another batch")
        if (
            batch[1] == "OPEN"
            and batch[2] == request.snapshot_id
            and batch[3] == publication.snapshot_sha256
            and batch[4] == 1
            and submission[6] == "COMMITTED"
            and snapshot[5] == "PUBLISHED"
            and snapshot[6] == 0
        ):
            return self._result(
                request,
                publication,
                plan,
                resumed=True,
            )
        if not (
            batch[1] == "OPEN"
            and batch[2] is None
            and batch[3] is None
            and batch[4] == 0
            and batch[5] == 0
            and submission[6] == "PREPARED"
            and snapshot[5] == "PREPARED"
            and snapshot[6] == 0
        ):
            raise BatchConflictError("batch genesis state cannot be resumed")
        return None

    def _prepare(
        self,
        request: OpenBatchRequest,
        publication: SnapshotPublication,
        plan: SnapshotPublishPlan,
        envelope: bytes,
    ) -> Tuple[Optional[OpenBatchResult], bool]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._campaign_row(request)
            existing_batch = self.connection.execute(
                "SELECT 1 FROM review_batches WHERE batch_id = ?",
                (request.batch_id,),
            ).fetchone()
            existing = self._existing_state(
                request,
                envelope,
                publication,
                plan,
            )
            if existing is not None:
                self._require_current_policy(request)
                self.connection.execute("COMMIT")
                return existing, True
            if existing_batch is not None:
                self._require_current_policy(request)
                self.connection.execute("COMMIT")
                return None, True
            if self.connection.execute(
                "SELECT 1 FROM review_snapshots WHERE snapshot_id = ?",
                (request.snapshot_id,),
            ).fetchone() is not None:
                raise BatchConflictError("snapshot id is already globally bound")
            if self.connection.execute(
                "SELECT 1 FROM review_submissions WHERE submission_id = ?",
                (request.submission_id,),
            ).fetchone() is not None:
                raise BatchConflictError("submission id is already globally bound")
            self._validate_no_active_overlap(request)
            self._validate_no_legacy_pending_collision(request)
            self.connection.execute(
                "INSERT INTO review_batches "
                "(batch_id, campaign_id, request_hash, status, current_snapshot_id, "
                "current_snapshot_sha256, review_revision, execution_generation) "
                "VALUES (?, ?, ?, 'OPEN', NULL, NULL, 0, 0)",
                (request.batch_id, request.campaign_id, request.request_hash),
            )
            self.connection.executemany(
                "INSERT INTO batch_memberships "
                "(membership_id, batch_id, unit_id, item_id, path, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                self._membership_rows(request),
            )
            envelope_sha256 = sha256_bytes(envelope)
            self.connection.execute(
                "INSERT INTO review_submissions "
                "(submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
                "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
                "payload_sha256, final_path, final_sha256, state) "
                "VALUES (?, 'BATCH', ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, 'PREPARED')",
                (
                    request.submission_id,
                    request.campaign_id,
                    request.batch_id,
                    request.request_hash,
                    request.snapshot_id,
                    envelope,
                    envelope_sha256,
                    str(plan.final_path),
                    plan.package_sha256,
                ),
            )
            self.connection.execute(
                "INSERT INTO review_snapshots "
                "(snapshot_id, lineage_kind, campaign_id, batch_id, version, "
                "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
                "final_path, final_sha256, state, structural_approval_ready) "
                "VALUES (?, 'BATCH', ?, ?, 1, NULL, NULL, ?, ?, ?, 'PREPARED', 0)",
                (
                    request.snapshot_id,
                    request.campaign_id,
                    request.batch_id,
                    publication.snapshot_sha256,
                    str(plan.final_path),
                    plan.package_sha256,
                ),
            )
            self._require_current_policy(request)
            self.connection.execute("COMMIT")
            return None, False
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            message = str(exc).lower()
            if "overlap" in message or "batch_memberships.item_id" in message:
                raise BatchConflictError("active batch membership overlap") from exc
            if "snapshot" in message:
                raise BatchConflictError("snapshot id is already globally bound") from exc
            raise BatchConflictError("batch genesis constraint failed") from exc
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _validate_publish_result(
        self,
        publication: SnapshotPublication,
        plan: SnapshotPublishPlan,
        result: SnapshotPublishResult,
    ) -> None:
        if type(result) is not SnapshotPublishResult:
            raise BatchPublicationError("publisher result type is invalid")
        if (
            result.final_path != plan.final_path
            or result.snapshot_sha256 != publication.snapshot_sha256
            or result.package_sha256 != plan.package_sha256
            or result.sealed_identity_sha256 != plan.sealed_identity_sha256
        ):
            raise BatchPublicationError("publisher readback does not match prepared plan")
        staging_path, final_path = _batch_sealed_paths(self.snapshot_root, plan)
        if os.path.lexists(staging_path):
            raise BatchPublicationError(
                "conflicting snapshot staging exists beside final package"
            )
        _require_owner_only_directory(final_path, "snapshot package")

    def _commit(
        self,
        request: OpenBatchRequest,
        publication: SnapshotPublication,
        plan: SnapshotPublishPlan,
    ) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._campaign_row(request)
            batch = _tuple_row(self.connection.execute(
                "SELECT status, current_snapshot_id, current_snapshot_sha256, "
                "review_revision, execution_generation, request_hash "
                "FROM review_batches WHERE batch_id = ?",
                (request.batch_id,),
            ).fetchone())
            if batch is None or batch[5] != request.request_hash:
                raise BatchConflictError("batch request changed before snapshot commit")
            submission = _tuple_row(self.connection.execute(
                "SELECT state, snapshot_id, final_path, final_sha256 "
                "FROM review_submissions WHERE submission_id = ? AND batch_id = ?",
                (request.submission_id, request.batch_id),
            ).fetchone())
            snapshot = _tuple_row(self.connection.execute(
                "SELECT state, payload_sha256, final_path, final_sha256, "
                "structural_approval_ready FROM review_snapshots "
                "WHERE snapshot_id = ? AND batch_id = ?",
                (request.snapshot_id, request.batch_id),
            ).fetchone())
            if submission is None or snapshot is None:
                raise BatchConflictError("prepared genesis disappeared")
            if (
                batch[0] == "OPEN"
                and batch[1] == request.snapshot_id
                and batch[2] == publication.snapshot_sha256
                and batch[3] == 1
                and submission[0] == "COMMITTED"
                and snapshot[0] == "PUBLISHED"
            ):
                self._require_current_policy(request)
                self.connection.execute("COMMIT")
                return
            if not (
                batch[:5] == ("OPEN", None, None, 0, 0)
                and submission
                == (
                    "PREPARED",
                    request.snapshot_id,
                    str(plan.final_path),
                    plan.package_sha256,
                )
                and snapshot
                == (
                    "PREPARED",
                    publication.snapshot_sha256,
                    str(plan.final_path),
                    plan.package_sha256,
                    0,
                )
            ):
                raise BatchConflictError("prepared genesis CAS is stale")
            updated_snapshot = self.connection.execute(
                "UPDATE review_snapshots SET state = 'PUBLISHED' "
                "WHERE snapshot_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND payload_sha256 = ? AND final_path = ? AND final_sha256 = ? "
                "AND structural_approval_ready = 0",
                (
                    request.snapshot_id,
                    request.batch_id,
                    publication.snapshot_sha256,
                    str(plan.final_path),
                    plan.package_sha256,
                ),
            ).rowcount
            updated_submission = self.connection.execute(
                "UPDATE review_submissions SET state = 'COMMITTED' "
                "WHERE submission_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND snapshot_id = ? AND final_path = ? AND final_sha256 = ?",
                (
                    request.submission_id,
                    request.batch_id,
                    request.snapshot_id,
                    str(plan.final_path),
                    plan.package_sha256,
                ),
            ).rowcount
            updated_batch = self.connection.execute(
                "UPDATE review_batches SET current_snapshot_id = ?, "
                "current_snapshot_sha256 = ?, review_revision = 1 "
                "WHERE batch_id = ? AND request_hash = ? AND status = 'OPEN' "
                "AND current_snapshot_id IS NULL AND current_snapshot_sha256 IS NULL "
                "AND review_revision = 0 AND execution_generation = 0",
                (
                    request.snapshot_id,
                    publication.snapshot_sha256,
                    request.batch_id,
                    request.request_hash,
                ),
            ).rowcount
            if (updated_snapshot, updated_submission, updated_batch) != (1, 1, 1):
                raise BatchConflictError("prepared genesis CAS did not commit exactly once")
            self._require_current_policy(request)
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _result(
        self,
        request: OpenBatchRequest,
        publication: SnapshotPublication,
        plan: SnapshotPublishPlan,
        *,
        resumed: bool,
    ) -> OpenBatchResult:
        return OpenBatchResult(
            batch_id=request.batch_id,
            status="OPEN",
            snapshot_id=request.snapshot_id,
            snapshot_state="COMMITTED",
            snapshot_version=1,
            review_revision=1,
            snapshot_sha256=publication.snapshot_sha256,
            package_sha256=plan.package_sha256,
            final_path=plan.final_path,
            structural_approval_ready=False,
            structural_blocker=_STRUCTURAL_BLOCKER,
            resumed=resumed,
        )

    def _require_prepared_publication(
        self,
        request: OpenBatchRequest,
        prepared: PreparedBatchPublication,
    ) -> None:
        if type(prepared) is not PreparedBatchPublication:
            raise TypeError("prepared must be PreparedBatchPublication")
        expected_publication = _batch_publication(self.snapshot_root, request)
        if prepared.publication != expected_publication:
            raise BatchPublicationError(
                "prepared batch publication changed snapshot identity"
            )
        _validate_batch_plan(
            self.snapshot_root,
            prepared.publication,
            prepared.plan,
        )
        if prepared.envelope != _batch_submission_envelope(
            request,
            prepared.publication,
            prepared.plan,
        ):
            raise BatchPublicationError(
                "prepared batch publication changed sealed envelope"
            )

    def _open_batch_locked(
        self,
        request: OpenBatchRequest,
        prepared: PreparedBatchPublication,
    ) -> OpenBatchResult:
        if type(request) is not OpenBatchRequest:
            raise TypeError("request must be OpenBatchRequest")
        if self.connection.in_transaction:
            raise BatchConflictError("batch service requires transaction ownership")
        try:
            ledger_schema.verify_v2_schema(self.connection)
        except ledger_schema.LedgerSchemaError as exc:
            raise BatchConflictError("exact ledger schema v2 is required") from exc
        self._require_current_policy(request)
        self._require_prepared_publication(request, prepared)
        publication = prepared.publication
        plan = prepared.plan
        envelope = prepared.envelope
        existing, resumed = self._prepare(
            request,
            publication,
            plan,
            envelope,
        )
        if existing is not None:
            return existing
        self.checkpoint("prepared")
        publish_result = self.publisher.publish(plan)
        self._validate_publish_result(publication, plan, publish_result)
        self.checkpoint("published")
        self._require_current_policy(request)
        self._commit(request, publication, plan)
        self.checkpoint("committed")
        return self._result(
            request,
            publication,
            plan,
            resumed=resumed,
        )

    def open_batch(self, request: OpenBatchRequest) -> OpenBatchResult:
        """Prepare outside writer guards, then open or resume one genesis."""

        prepared = prepare_batch_publication(
            self.snapshot_root,
            self.publisher,
            request,
        )
        return self.open_prepared_batch(request, prepared)

    def open_prepared_batch(
        self,
        request: OpenBatchRequest,
        prepared: PreparedBatchPublication,
    ) -> OpenBatchResult:
        """Apply one exact lock-free publication plan under writer guards."""

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
                return self._open_batch_locked(request, prepared)


__all__ = [
    "BatchConflictError",
    "BatchPublicationError",
    "BatchService",
    "BatchServiceError",
    "BatchUnit",
    "BatchValidationError",
    "OpenBatchRequest",
    "OpenBatchResult",
    "PreparedBatchPublication",
    "SnapshotPublication",
    "SnapshotPublishPlan",
    "SnapshotPublishResult",
    "prepare_batch_publication",
]
