"""Persistent copy-on-write expansion of one folder review unit.

The service consumes only a verified sealed batch head plus the version-2
ledger.  Descendant paths and sizes come from durable observation/link rows;
the source corpus is never reopened.  Publication follows the same
PREPARED -> immutable full-package publish/readback -> final CAS protocol as
batch genesis.
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
from typing import Any, Callable, Dict, Optional, Tuple

from . import (
    admission,
    batch_service,
    ledger_schema,
    m2_publishers,
    review_compiler,
    review_context,
    review_state,
    safety,
)
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STRUCTURAL_BLOCKER = "effect-preview-not-available-m2"
_BUILDER_VERSION = "adaptive-folder-m2-v1"


class ExplodeReviewUnitError(RuntimeError):
    """The requested copy-on-write expansion cannot complete safely."""


class _StalePreparedOperation(ExplodeReviewUnitError):
    """A PREPARED operation lost its exact final-CAS base."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ExplodeReviewUnitError("%s is invalid" % label)
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ExplodeReviewUnitError("%s is invalid" % label)
    return value


def _relative_path(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.startswith("/"):
        raise ExplodeReviewUnitError("%s must be raw-relative" % label)
    if (
        posixpath.normpath(value) != value
        or value in (".", "..")
        or value.startswith("../")
        or value.endswith("/")
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ExplodeReviewUnitError("%s is not canonical" % label)
    return value


def _canonical_object(raw: bytes, label: str) -> Dict[str, Any]:
    if type(raw) is not bytes:
        raise ExplodeReviewUnitError("%s must be bytes" % label)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExplodeReviewUnitError("%s is not canonical JSON" % label) from exc
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise ExplodeReviewUnitError("%s is not canonical JSON" % label) from exc
    if type(value) is not dict or encoded != raw:
        raise ExplodeReviewUnitError("%s is not a canonical JSON object" % label)
    return value


def _as_bytes(value: Any, label: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise ExplodeReviewUnitError("%s is not bytes" % label)


def exploded_batch_review_document_from_snapshot(
    snapshot_payload: bytes,
) -> review_compiler.ReviewDocument:
    """Rebuild an exploded v2+ batch preview from exact snapshot bytes only.

    ``review_context.batch_review_document_from_snapshot`` intentionally binds
    genesis v2 (null parent).  This stricter companion accepts only non-genesis
    copy-on-write snapshots and therefore cannot accidentally render genesis.
    """

    try:
        parsed = review_context.parse_batch_review_snapshot(
            snapshot_payload,
            lineage_policy=review_context.DESCENDANT_BATCH_LINEAGE,
        )
        return review_context.review_document_from_parsed_batch_snapshot(
            parsed
        )
    except ExplodeReviewUnitError:
        raise
    except review_context.ReviewContextError as exc:
        if "COW-normalization-required" in str(exc):
            raise ExplodeReviewUnitError(
                "base batch snapshot v1 requires COW-normalization-required"
            ) from exc
        raise ExplodeReviewUnitError(
            "exploded batch review document is invalid"
        ) from exc
    except (
        TypeError,
        ValueError,
        review_compiler.ReviewCompileError,
    ) as exc:
        raise ExplodeReviewUnitError(
            "exploded batch review document is invalid"
        ) from exc


@dataclass(frozen=True)
class ExplodeReviewUnitRequest:
    batch_id: str
    expected_snapshot_id: str
    expected_snapshot_sha256: str
    expected_review_revision: int
    expected_execution_generation: int
    policy: admission.ApprovedPolicyRef
    folder_unit_id: str
    next_snapshot_id: str
    submission_id: str
    actor: str
    analysis_contexts_json: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("batch id", self.batch_id),
            ("expected snapshot id", self.expected_snapshot_id),
            ("folder unit id", self.folder_unit_id),
            ("next snapshot id", self.next_snapshot_id),
            ("submission id", self.submission_id),
        ):
            _identifier(value, label)
        _sha256(self.expected_snapshot_sha256, "expected snapshot hash")
        if self.next_snapshot_id == self.expected_snapshot_id:
            raise ExplodeReviewUnitError(
                "next snapshot id must be globally new"
            )
        if (
            type(self.expected_review_revision) is not int
            or self.expected_review_revision < 1
        ):
            raise ExplodeReviewUnitError(
                "expected review revision must be positive"
            )
        if (
            type(self.expected_execution_generation) is not int
            or self.expected_execution_generation < 0
        ):
            raise ExplodeReviewUnitError(
                "expected execution generation must be non-negative"
            )
        if not isinstance(self.policy, admission.ApprovedPolicyRef):
            raise ExplodeReviewUnitError("policy must be ApprovedPolicyRef")
        if (
            not isinstance(self.actor, str)
            or not self.actor.strip()
            or self.actor != self.actor.strip()
            or any(ord(character) < 0x20 for character in self.actor)
        ):
            raise ExplodeReviewUnitError("actor is invalid")
        try:
            review_context.AnalysisContextBundle.from_canonical_bytes(
                self.analysis_contexts_json
            )
        except (TypeError, review_context.ReviewContextError) as exc:
            raise ExplodeReviewUnitError(
                "analysis contexts are invalid"
            ) from exc

    def request_payload(self) -> dict:
        return {
            "analysis_contexts": json.loads(
                self.analysis_contexts_json.decode("utf-8")
            ),
            "actor": self.actor,
            "batch_id": self.batch_id,
            "expected_execution_generation": self.expected_execution_generation,
            "expected_review_revision": self.expected_review_revision,
            "expected_snapshot_id": self.expected_snapshot_id,
            "expected_snapshot_sha256": self.expected_snapshot_sha256,
            "folder_unit_id": self.folder_unit_id,
            "kind": "explode-review-unit",
            "next_snapshot_id": self.next_snapshot_id,
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
            "schema_version": 2,
            "submission_id": self.submission_id,
        }

    @property
    def request_hash(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.request_payload()))


@dataclass(frozen=True)
class ExplodeInvocationIdentity:
    """Caller-visible identity fields used to bind stored resume envelopes."""

    batch_id: str
    expected_snapshot_id: str
    expected_snapshot_sha256: str
    folder_unit_id: str
    next_snapshot_id: str
    submission_id: str
    actor: str

    def __post_init__(self) -> None:
        for label, value in (
            ("batch id", self.batch_id),
            ("expected snapshot id", self.expected_snapshot_id),
            ("folder unit id", self.folder_unit_id),
            ("next snapshot id", self.next_snapshot_id),
            ("submission id", self.submission_id),
        ):
            _identifier(value, label)
        _sha256(self.expected_snapshot_sha256, "expected snapshot hash")
        if (
            type(self.actor) is not str
            or not self.actor.strip()
            or self.actor != self.actor.strip()
            or any(ord(character) < 0x20 for character in self.actor)
        ):
            raise ExplodeReviewUnitError("actor is invalid")

    def require(self, request: ExplodeReviewUnitRequest) -> None:
        observed = (
            request.batch_id,
            request.expected_snapshot_id,
            request.expected_snapshot_sha256,
            request.folder_unit_id,
            request.next_snapshot_id,
            request.submission_id,
            request.actor,
        )
        expected = (
            self.batch_id,
            self.expected_snapshot_id,
            self.expected_snapshot_sha256,
            self.folder_unit_id,
            self.next_snapshot_id,
            self.submission_id,
            self.actor,
        )
        if observed != expected:
            raise ExplodeReviewUnitError(
                "submission id is bound to another explode request"
            )


@dataclass(frozen=True)
class ExplodeReviewUnitResult:
    batch_id: str
    status: str
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
    structural_approval_ready: bool
    structural_blocker: str
    resumed: bool


@dataclass(frozen=True)
class ExplodeMembership:
    unit_id: str
    item_id: str
    path: str

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "path": self.path,
            "unit_id": self.unit_id,
        }


@dataclass(frozen=True)
class PreparedExplodeTransition:
    """Exact read-prepared transition applied later by the writer service."""

    request: ExplodeReviewUnitRequest
    campaign_id: str
    publication: batch_service.SnapshotPublication
    plan: batch_service.SnapshotPublishPlan
    envelope: bytes
    base_memberships: Tuple[ExplodeMembership, ...]
    next_memberships: Tuple[ExplodeMembership, ...]

    def __post_init__(self) -> None:
        if type(self.request) is not ExplodeReviewUnitRequest:
            raise TypeError("request must be ExplodeReviewUnitRequest")
        _identifier(self.campaign_id, "campaign id")
        if type(self.publication) is not batch_service.SnapshotPublication:
            raise TypeError("publication must be SnapshotPublication")
        if type(self.plan) is not batch_service.SnapshotPublishPlan:
            raise TypeError("plan must be SnapshotPublishPlan")
        if type(self.envelope) is not bytes:
            raise TypeError("envelope must be bytes")
        for label, rows in (
            ("base memberships", self.base_memberships),
            ("next memberships", self.next_memberships),
        ):
            if type(rows) is not tuple or any(
                type(row) is not ExplodeMembership for row in rows
            ):
                raise TypeError("%s must contain ExplodeMembership values" % label)
        if tuple(sorted(self.base_memberships, key=lambda row: (row.item_id, row.unit_id, row.path))) != self.base_memberships:
            raise ExplodeReviewUnitError("base memberships are not sorted")
        if tuple(sorted(self.next_memberships, key=lambda row: (row.item_id, row.unit_id, row.path))) != self.next_memberships:
            raise ExplodeReviewUnitError("next memberships are not sorted")
        if tuple(row.item_id for row in self.base_memberships) != tuple(
            row.item_id for row in self.next_memberships
        ):
            raise ExplodeReviewUnitError(
                "explode transition does not conserve exact membership"
            )


@dataclass(frozen=True)
class _PreparedOperation:
    publication: batch_service.SnapshotPublication
    plan: batch_service.SnapshotPublishPlan
    envelope: bytes
    old_memberships: Tuple[ExplodeMembership, ...]
    next_memberships: Tuple[ExplodeMembership, ...]
    state: str
    resumed: bool


def _memberships(
    units: Tuple[batch_service.BatchUnit, ...],
) -> Tuple[ExplodeMembership, ...]:
    rows = tuple(
        sorted(
            (
                ExplodeMembership(unit.unit_id, item_id, unit.path)
                for unit in units
                for item_id in unit.member_item_ids
            ),
            key=lambda row: (row.item_id, row.unit_id, row.path),
        )
    )
    item_ids = tuple(row.item_id for row in rows)
    if len(item_ids) != len(set(item_ids)):
        raise ExplodeReviewUnitError("batch membership overlaps")
    return rows


def _membership_values(value: Any, label: str) -> Tuple[ExplodeMembership, ...]:
    if type(value) is not list:
        raise ExplodeReviewUnitError("%s must be a list" % label)
    rows = []
    for item in value:
        if type(item) is not dict or set(item) != {"item_id", "path", "unit_id"}:
            raise ExplodeReviewUnitError("%s row is invalid" % label)
        rows.append(
            ExplodeMembership(
                _identifier(item["unit_id"], "%s unit id" % label),
                _identifier(item["item_id"], "%s item id" % label),
                _relative_path(item["path"], "%s path" % label),
            )
        )
    result = tuple(rows)
    if result != tuple(
        sorted(result, key=lambda row: (row.item_id, row.unit_id, row.path))
    ):
        raise ExplodeReviewUnitError("%s is not sorted" % label)
    return result


def _validated_transition_roots(
    connection: sqlite3.Connection,
    raw_root: Path,
    publisher: m2_publishers.BatchReviewPublisherAdapter,
) -> Tuple[Path, Path]:
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be sqlite3.Connection")
    root = Path(raw_root)
    if not root.is_absolute() or any(part in (".", "..") for part in root.parts):
        raise ExplodeReviewUnitError("raw root must be a canonical absolute path")
    descriptor = safety.open_verified_directory(
        root,
        require_owner_only=True,
        error_type=ExplodeReviewUnitError,
    )
    try:
        opened_root = os.fstat(descriptor)
        if (
            opened_root.st_uid != os.getuid()
            or stat.S_IMODE(opened_root.st_mode) & 0o022
        ):
            raise ExplodeReviewUnitError("raw root is not owner-controlled")
    finally:
        os.close(descriptor)
    if type(publisher) is not m2_publishers.BatchReviewPublisherAdapter:
        raise TypeError("publisher must be the full BatchReviewPublisherAdapter")
    snapshot_root = publisher.review_publisher.snapshot_root
    try:
        relative = snapshot_root.relative_to(root)
    except ValueError as exc:
        raise ExplodeReviewUnitError(
            "snapshot publisher root escapes raw root"
        ) from exc
    if not relative.parts:
        raise ExplodeReviewUnitError("snapshot publisher root cannot equal raw root")
    return root, snapshot_root


def _descendant_from_ledger(
    connection: sqlite3.Connection,
    campaign_id: str,
    *,
    item_id: str,
    expected_path: str,
) -> Tuple[str, int]:
    rows = connection.execute(
        "SELECT o.run_id, o.observation_id, o.path, o.kind, o.payload_json, "
        "o.payload_sha256, l.link_id, l.link_generation, l.provenance_json, "
        "l.provenance_sha256 "
        "FROM campaigns AS c "
        "JOIN observations AS o ON o.run_id = c.root_run_id "
        "JOIN observation_item_links AS l "
        "ON l.run_id = o.run_id AND l.observation_id = o.observation_id "
        "WHERE c.campaign_id = ? AND l.item_id = ? AND l.is_current = 1",
        (campaign_id, item_id),
    ).fetchall()
    if len(rows) != 1:
        raise ExplodeReviewUnitError(
            "folder descendant observation/link is incomplete or ambiguous"
        )
    (
        run_id,
        _observation_id,
        row_path,
        row_kind,
        payload_value,
        payload_sha256,
        link_id,
        link_generation,
        provenance_value,
        provenance_sha256,
    ) = tuple(rows[0])
    payload = _as_bytes(payload_value, "observation payload")
    provenance = _as_bytes(provenance_value, "observation link provenance")
    if (
        row_path != expected_path
        or row_kind != "file"
        or sha256_bytes(payload) != payload_sha256
        or sha256_bytes(provenance) != provenance_sha256
        or type(link_generation) is not int
        or link_generation < 1
    ):
        raise ExplodeReviewUnitError(
            "folder descendant durable binding does not match membership"
        )
    _identifier(link_id, "observation link id")
    _canonical_object(provenance, "observation link provenance")
    observation = _canonical_object(payload, "observation payload")
    stat_value = observation.get("stat")
    schema_version = observation.get("schema_version")
    projection_shape_valid = (
        schema_version == 1 and "reference_projection" not in observation
    ) or (
        schema_version == 2
        and "reference_projection" in observation
        and (
            observation["reference_projection"] is None
            or type(observation["reference_projection"]) is dict
        )
    )
    if (
        not projection_shape_valid
        or observation.get("run_id") != run_id
        or observation.get("path") != expected_path
        or observation.get("kind") != "file"
        or observation.get("physical_kind") != "file"
        or not isinstance(observation.get("display_path"), str)
        or not observation["display_path"]
        or type(stat_value) is not dict
        or set(stat_value) != {"device", "inode", "mode", "mtime_ns", "size"}
        or any(type(value) is not int or value < 0 for value in stat_value.values())
        or not stat.S_ISREG(stat_value["mode"])
    ):
        raise ExplodeReviewUnitError(
            "folder descendant observation is not an exact file projection"
        )
    return observation["display_path"], stat_value["size"]


def _exploded_file_unit_id(item_id: str, path: str) -> str:
    return "unit-%s" % sha256_bytes(
        canonical_json_bytes(
            {
                "builder_version": _BUILDER_VERSION,
                "kind": "file",
                "member_item_ids": [item_id],
                "path": path,
            }
        )
    )[:24]


def _exploded_target_path(
    folder: batch_service.BatchUnit,
    member_path: str,
) -> Optional[str]:
    if folder.target_path is None:
        return None
    prefix = folder.path + "/"
    if not member_path.startswith(prefix):
        raise ExplodeReviewUnitError(
            "folder descendant path is outside folder unit"
        )
    return posixpath.join(folder.target_path, member_path[len(prefix) :])


def _explode_units_from_ledger(
    connection: sqlite3.Connection,
    campaign_id: str,
    base_units: Tuple[batch_service.BatchUnit, ...],
    folder_unit_id: str,
) -> Tuple[batch_service.BatchUnit, ...]:
    targets = tuple(unit for unit in base_units if unit.unit_id == folder_unit_id)
    if len(targets) != 1 or targets[0].unit_kind != "folder":
        raise ExplodeReviewUnitError("folder review unit was not found")
    target = targets[0]
    if target.effect_count not in (0, target.file_count):
        raise ExplodeReviewUnitError(
            "folder effect count cannot be losslessly expanded"
        )
    if len(target.member_item_ids) != len(target.member_paths):
        raise ExplodeReviewUnitError("folder descendant membership is incomplete")
    replacements = []
    for item_id, member_path in zip(
        target.member_item_ids,
        target.member_paths,
    ):
        if not member_path.startswith(target.path + "/"):
            raise ExplodeReviewUnitError(
                "folder descendant membership escapes folder"
            )
        display_path, size = _descendant_from_ledger(
            connection,
            campaign_id,
            item_id=item_id,
            expected_path=member_path,
        )
        provenance = json.loads(target.analysis_provenance_json)["items"]
        replacements.append(
            batch_service.BatchUnit(
                unit_id=_exploded_file_unit_id(item_id, member_path),
                unit_kind="file",
                path=member_path,
                display_path=display_path,
                member_item_ids=(item_id,),
                member_paths=(member_path,),
                scope_class=target.scope_class,
                sensitivity=target.sensitivity,
                access_domain=target.access_domain,
                primary_workstream=target.primary_workstream,
                related_workstreams=target.related_workstreams,
                shared=target.shared,
                document_role=target.document_role,
                authority=target.authority,
                document_lifecycle=target.document_lifecycle,
                lifecycle_class=target.lifecycle_class,
                override_class=target.override_class,
                scope_rule_id=target.scope_rule_id,
                recommended_action=target.recommended_action,
                target_path=_exploded_target_path(target, member_path),
                reference_complete=target.reference_complete,
                risk_band=target.risk_band,
                context_freshness=target.context_freshness,
                evidence_providers=target.evidence_providers,
                warning_codes=target.warning_codes,
                effect_codes=target.effect_codes,
                canonical_conflict=target.canonical_conflict,
                relation_conflict=target.relation_conflict,
                target_proven=target.target_proven,
                analysis_provenance_json=canonical_json_bytes(
                    {
                        "items": [
                            row for row in provenance if row["item_id"] == item_id
                        ],
                        "schema_version": 1,
                    }
                ),
                file_count=1,
                total_bytes=size,
                effect_count=1 if target.effect_count else 0,
            )
        )
    if sum(unit.total_bytes for unit in replacements) != target.total_bytes:
        raise ExplodeReviewUnitError(
            "folder descendant durable sizes changed from sealed membership"
        )
    units = tuple(
        sorted(
            tuple(unit for unit in base_units if unit.unit_id != target.unit_id)
            + tuple(replacements),
            key=lambda unit: unit.unit_id,
        )
    )
    before = sorted(item_id for unit in base_units for item_id in unit.member_item_ids)
    after = sorted(item_id for unit in units for item_id in unit.member_item_ids)
    if before != after or len(after) != len(set(after)):
        raise ExplodeReviewUnitError(
            "explode did not conserve exact batch membership"
        )
    for index, left in enumerate(units):
        for right in units[index + 1 :]:
            if (
                left.path == right.path
                or left.path.startswith(right.path + "/")
                or right.path.startswith(left.path + "/")
            ):
                raise ExplodeReviewUnitError(
                    "exploded review unit resource paths overlap"
                )
    return units


def _next_explode_payload(
    connection: sqlite3.Connection,
    request: ExplodeReviewUnitRequest,
    head: review_state.BatchReviewHead,
) -> Tuple[
    bytes,
    Tuple[ExplodeMembership, ...],
    Tuple[ExplodeMembership, ...],
]:
    try:
        parsed = review_context.parse_batch_review_snapshot(
            head.snapshot.snapshot_payload,
            lineage_policy=review_context.CURRENT_BATCH_LINEAGE,
        )
    except review_context.ReviewContextError as exc:
        if "COW-normalization-required" in str(exc):
            raise ExplodeReviewUnitError(
                "base batch snapshot v1 requires COW-normalization-required"
            ) from exc
        raise ExplodeReviewUnitError(
            "base batch snapshot contract is invalid"
        ) from exc
    base = parsed.payload
    if (
        base["batch_id"] != request.batch_id
        or base["campaign_id"] != head.campaign_id
        or base["snapshot_id"] != request.expected_snapshot_id
        or base["batch_version"] != request.expected_review_revision
    ):
        raise ExplodeReviewUnitError("base batch snapshot contract is invalid")
    units = _explode_units_from_ledger(
        connection,
        head.campaign_id,
        head.snapshot.units,
        request.folder_unit_id,
    )
    try:
        next_contexts = parsed.analysis_contexts.select_for_units(units)
    except review_context.ReviewContextError as exc:
        raise ExplodeReviewUnitError(
            "exploded analysis contexts are invalid"
        ) from exc
    if next_contexts.canonical_bytes != request.analysis_contexts_json:
        raise ExplodeReviewUnitError(
            "explode analysis contexts do not match exact descendants"
        )
    bounds = parsed.bounds
    if (
        len(units) > bounds["items"]
        or sum(unit.file_count for unit in units) > bounds["files"]
        or sum(unit.total_bytes for unit in units) > bounds["bytes"]
        or sum(unit.effect_count for unit in units) > bounds["effects"]
    ):
        raise ExplodeReviewUnitError("exploded units exceed the base batch bounds")
    unit_payloads = tuple(unit.to_dict() for unit in units)
    try:
        next_context = review_context.ReviewContext(
            rendered_at=parsed.context.rendered_at,
            policy_binding=parsed.context.policy_binding,
            coverage=parsed.context.coverage,
            workstreams=review_context.workstream_summaries_for_unit_payloads(
                unit_payloads,
                parsed.context,
            ),
            warning_codes=parsed.context.warning_codes,
        )
    except review_context.ReviewContextError as exc:
        raise ExplodeReviewUnitError(
            "base review context cannot be advanced"
        ) from exc
    payload = dict(base)
    payload.update(
        {
            "analysis_contexts": next_contexts.to_json_value(),
            "actor": request.actor,
            "approval_ready": False,
            "batch_version": request.expected_review_revision + 1,
            "parent_snapshot_id": request.expected_snapshot_id,
            "parent_snapshot_sha256": request.expected_snapshot_sha256,
            "request_hash": request.request_hash,
            "review_context": next_context.to_dict(),
            "snapshot_id": request.next_snapshot_id,
            "structural_approval_ready": False,
            "structural_blocker": _STRUCTURAL_BLOCKER,
            "units": list(unit_payloads),
        }
    )
    encoded = canonical_json_bytes(payload)
    exploded_batch_review_document_from_snapshot(encoded)
    return encoded, _memberships(head.snapshot.units), _memberships(units)


def _explode_publication(
    snapshot_root: Path,
    request: ExplodeReviewUnitRequest,
    payload: bytes,
) -> batch_service.SnapshotPublication:
    return batch_service.SnapshotPublication(
        snapshot_id=request.next_snapshot_id,
        batch_id=request.batch_id,
        version=request.expected_review_revision + 1,
        canonical_payload=payload,
        snapshot_sha256=sha256_bytes(payload),
        final_path=snapshot_root / request.next_snapshot_id,
        structural_approval_ready=False,
        structural_blocker=_STRUCTURAL_BLOCKER,
    )


def _validate_explode_plan(
    snapshot_root: Path,
    publication: batch_service.SnapshotPublication,
    plan: batch_service.SnapshotPublishPlan,
) -> None:
    if (
        type(plan) is not batch_service.SnapshotPublishPlan
        or plan.publication != publication
        or plan.final_path != publication.final_path
        or plan.final_path != snapshot_root / publication.snapshot_id
    ):
        raise ExplodeReviewUnitError(
            "review package plan changed snapshot identity"
        )
    _sha256(plan.package_sha256, "review package hash")
    _sha256(plan.sealed_identity_sha256, "sealed review identity hash")


def _explode_plan(
    snapshot_root: Path,
    publisher: m2_publishers.BatchReviewPublisherAdapter,
    publication: batch_service.SnapshotPublication,
) -> batch_service.SnapshotPublishPlan:
    try:
        plan = publisher.plan(publication)
    except batch_service.BatchServiceError as exc:
        raise ExplodeReviewUnitError(
            "full review package planning failed"
        ) from exc
    _validate_explode_plan(snapshot_root, publication, plan)
    return plan


def _explode_envelope(
    request: ExplodeReviewUnitRequest,
    publication: batch_service.SnapshotPublication,
    plan: batch_service.SnapshotPublishPlan,
    old_memberships: Tuple[ExplodeMembership, ...],
    next_memberships: Tuple[ExplodeMembership, ...],
) -> bytes:
    return canonical_json_bytes(
        {
            "kind": "explode-review-unit-submission",
            "membership_transition": {
                "base": [row.to_dict() for row in old_memberships],
                "next": [row.to_dict() for row in next_memberships],
            },
            "publish_plan": {
                "final_path": str(plan.final_path),
                "package_sha256": plan.package_sha256,
                "sealed_identity_sha256": plan.sealed_identity_sha256,
            },
            "request": request.request_payload(),
            "schema_version": 2,
            "snapshot": json.loads(publication.canonical_payload.decode("utf-8")),
            "snapshot_sha256": publication.snapshot_sha256,
        }
    )


class ExplodeTransitionPreparer:
    """Build exact explode transitions with a reader, never a ledger writer."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        raw_root: Path,
        publisher: m2_publishers.BatchReviewPublisherAdapter,
    ) -> None:
        root, snapshot_root = _validated_transition_roots(
            connection,
            raw_root,
            publisher,
        )
        self.connection = connection
        self.raw_root = root
        self.snapshot_root = snapshot_root
        self.publisher = publisher

    def _require_campaign_snapshot_root(self, campaign_id: str) -> None:
        expected = self.raw_root / "campaigns" / campaign_id / "snapshots"
        if self.snapshot_root != expected:
            raise ExplodeReviewUnitError(
                "snapshot publisher root does not match explode campaign"
            )

    def _transition(
        self,
        request: ExplodeReviewUnitRequest,
        campaign_id: str,
        payload: bytes,
        base_memberships: Tuple[ExplodeMembership, ...],
        next_memberships: Tuple[ExplodeMembership, ...],
    ) -> PreparedExplodeTransition:
        self._require_campaign_snapshot_root(campaign_id)
        publication = _explode_publication(
            self.snapshot_root,
            request,
            payload,
        )
        plan = _explode_plan(self.snapshot_root, self.publisher, publication)
        envelope = _explode_envelope(
            request,
            publication,
            plan,
            base_memberships,
            next_memberships,
        )
        return PreparedExplodeTransition(
            request=request,
            campaign_id=campaign_id,
            publication=publication,
            plan=plan,
            envelope=envelope,
            base_memberships=base_memberships,
            next_memberships=next_memberships,
        )

    def prepare(
        self,
        request: ExplodeReviewUnitRequest,
        head: review_state.BatchReviewHead,
    ) -> PreparedExplodeTransition:
        """Prepare a new transition from one fully verified reader head."""

        if type(request) is not ExplodeReviewUnitRequest:
            raise TypeError("request must be ExplodeReviewUnitRequest")
        if type(head) is not review_state.BatchReviewHead:
            raise TypeError("head must be BatchReviewHead")
        if (
            head.batch_id != request.batch_id
            or head.current_snapshot_id != request.expected_snapshot_id
            or head.current_snapshot_sha256 != request.expected_snapshot_sha256
            or head.review_revision != request.expected_review_revision
            or head.execution_generation != request.expected_execution_generation
        ):
            raise ExplodeReviewUnitError("batch head is stale")
        payload, base_memberships, next_memberships = _next_explode_payload(
            self.connection,
            request,
            head,
        )
        return self._transition(
            request,
            head.campaign_id,
            payload,
            base_memberships,
            next_memberships,
        )

    def from_stored(
        self,
        envelope: bytes,
        *,
        policy: admission.ApprovedPolicyRef,
        expected_identity: ExplodeInvocationIdentity,
    ) -> PreparedExplodeTransition:
        """Strictly parse and replan one stored PREPARED/COMMITTED envelope."""

        if not isinstance(policy, admission.ApprovedPolicyRef):
            raise TypeError("policy must be ApprovedPolicyRef")
        if type(expected_identity) is not ExplodeInvocationIdentity:
            raise TypeError(
                "expected_identity must be ExplodeInvocationIdentity"
            )
        value = _canonical_object(envelope, "stored explode submission")
        if (
            set(value)
            != {
                "kind",
                "membership_transition",
                "publish_plan",
                "request",
                "schema_version",
                "snapshot",
                "snapshot_sha256",
            }
            or value.get("kind") != "explode-review-unit-submission"
            or value.get("schema_version") != 2
            or type(value.get("request")) is not dict
            or type(value.get("membership_transition")) is not dict
            or set(value["membership_transition"]) != {"base", "next"}
            or type(value.get("publish_plan")) is not dict
            or set(value["publish_plan"])
            != {"final_path", "package_sha256", "sealed_identity_sha256"}
        ):
            raise ExplodeReviewUnitError(
                "stored explode submission contract is invalid"
            )
        request_value = value["request"]
        try:
            request = ExplodeReviewUnitRequest(
                batch_id=request_value["batch_id"],
                expected_snapshot_id=request_value["expected_snapshot_id"],
                expected_snapshot_sha256=request_value[
                    "expected_snapshot_sha256"
                ],
                expected_review_revision=request_value[
                    "expected_review_revision"
                ],
                expected_execution_generation=request_value[
                    "expected_execution_generation"
                ],
                policy=policy,
                folder_unit_id=request_value["folder_unit_id"],
                next_snapshot_id=request_value["next_snapshot_id"],
                submission_id=request_value["submission_id"],
                actor=request_value["actor"],
                analysis_contexts_json=canonical_json_bytes(
                    request_value["analysis_contexts"]
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExplodeReviewUnitError(
                "stored explode submission request is invalid"
            ) from exc
        if request.request_payload() != request_value:
            raise ExplodeReviewUnitError(
                "stored explode submission request changed identity"
            )
        expected_identity.require(request)
        payload = canonical_json_bytes(value["snapshot"])
        if sha256_bytes(payload) != value.get("snapshot_sha256"):
            raise ExplodeReviewUnitError("stored explode snapshot hash is invalid")
        try:
            parsed = review_context.parse_batch_review_snapshot(
                payload,
                lineage_policy=review_context.DESCENDANT_BATCH_LINEAGE,
            )
        except review_context.ReviewContextError as exc:
            raise ExplodeReviewUnitError(
                "stored explode snapshot contract is invalid"
            ) from exc
        snapshot = parsed.payload
        if (
            snapshot["batch_id"] != request.batch_id
            or snapshot["snapshot_id"] != request.next_snapshot_id
            or snapshot["batch_version"]
            != request.expected_review_revision + 1
            or snapshot["parent_snapshot_id"] != request.expected_snapshot_id
            or snapshot["parent_snapshot_sha256"]
            != request.expected_snapshot_sha256
            or snapshot["request_hash"] != request.request_hash
            or canonical_json_bytes(snapshot["analysis_contexts"])
            != request.analysis_contexts_json
        ):
            raise ExplodeReviewUnitError(
                "stored explode snapshot changed request identity"
            )
        campaign_id = _identifier(snapshot["campaign_id"], "campaign id")
        base_memberships = _membership_values(
            value["membership_transition"]["base"],
            "base membership",
        )
        next_memberships = _membership_values(
            value["membership_transition"]["next"],
            "next membership",
        )
        transition = self._transition(
            request,
            campaign_id,
            payload,
            base_memberships,
            next_memberships,
        )
        if transition.envelope != envelope:
            raise ExplodeReviewUnitError(
                "stored explode package plan does not match exact bytes"
            )
        return transition


class ExplodeReviewUnitService:
    """Expand one current folder unit through a durable submission saga."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        raw_root: Path,
        *,
        placement_shared: Callable[[], object],
        ledger_exclusive: Callable[[], object],
        publisher: m2_publishers.BatchReviewPublisherAdapter,
        current_policy: Callable[[], admission.ApprovedPolicyRef],
        checkpoint: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if connection.in_transaction:
            raise ExplodeReviewUnitError(
                "explode service requires transaction ownership"
            )
        if not callable(placement_shared) or not callable(ledger_exclusive):
            raise TypeError("writer guards are required")
        root, snapshot_root = _validated_transition_roots(
            connection,
            raw_root,
            publisher,
        )
        self.connection = connection
        self.raw_root = root
        self.snapshot_root = snapshot_root
        self.placement_shared = placement_shared
        self.ledger_exclusive = ledger_exclusive
        self.publisher = publisher
        if not callable(current_policy):
            raise TypeError("current_policy is required")
        self.current_policy = current_policy
        self.checkpoint = checkpoint or (lambda _point: None)

    def _require_current_policy(
        self,
        request: ExplodeReviewUnitRequest,
    ) -> None:
        try:
            observed = self.current_policy()
        except Exception as exc:
            raise ExplodeReviewUnitError(
                "current policy authority drifted"
            ) from exc
        if observed != request.policy:
            raise ExplodeReviewUnitError("current policy authority drifted")

    def _require_lineage_policy(
        self,
        request: ExplodeReviewUnitRequest,
    ) -> None:
        row = self.connection.execute(
            "SELECT r.policy_raw_hash, r.policy_full_hash, "
            "r.policy_writer_control_hash, r.policy_foundation_hash, "
            "r.policy_generation, r.policy_source_kind, "
            "r.policy_source_run_id, r.policy_guard_epoch "
            "FROM review_batches AS b "
            "JOIN campaigns AS c ON c.campaign_id = b.campaign_id "
            "JOIN inventory_runs AS r ON r.run_id = c.root_run_id "
            "WHERE b.batch_id = ?",
            (request.batch_id,),
        ).fetchone()
        expected = (
            request.policy.raw_hash,
            request.policy.full_hash,
            request.policy.writer_control_hash,
            request.policy.foundation_hash,
            request.policy.generation,
            request.policy.source_kind,
            request.policy.source_run_id,
            request.policy.guard_epoch,
        )
        if row is None or tuple(row) != expected:
            raise ExplodeReviewUnitError(
                "lineage policy authority is stale"
            )

    def _verify_schema(self) -> None:
        if self.connection.in_transaction:
            raise ExplodeReviewUnitError(
                "explode service requires transaction ownership"
            )
        try:
            ledger_schema.verify_v2_schema(self.connection)
        except ledger_schema.LedgerSchemaError as exc:
            raise ExplodeReviewUnitError(
                "exact ledger schema v2 is required"
            ) from exc

    def _batch_row(
        self,
        request: ExplodeReviewUnitRequest,
    ) -> Tuple[Any, ...]:
        row = self.connection.execute(
            "SELECT campaign_id, status, current_snapshot_id, "
            "current_snapshot_sha256, review_revision, execution_generation "
            "FROM review_batches WHERE batch_id = ?",
            (request.batch_id,),
        ).fetchone()
        if row is None:
            raise ExplodeReviewUnitError("batch does not exist")
        return tuple(row)

    def _require_base_head(
        self,
        request: ExplodeReviewUnitRequest,
    ) -> str:
        row = self._batch_row(request)
        if row[1] != "OPEN":
            raise ExplodeReviewUnitError("batch is not OPEN")
        if (
            row[2] != request.expected_snapshot_id
            or row[3] != request.expected_snapshot_sha256
            or row[4] != request.expected_review_revision
            or row[5] != request.expected_execution_generation
        ):
            raise ExplodeReviewUnitError("batch head is stale")
        return _identifier(row[0], "campaign id")

    def _require_next_head(
        self,
        request: ExplodeReviewUnitRequest,
        publication: batch_service.SnapshotPublication,
    ) -> None:
        row = self._batch_row(request)
        if (
            row[1] != "OPEN"
            or row[2] != request.next_snapshot_id
            or row[3] != publication.snapshot_sha256
            or row[4] != request.expected_review_revision + 1
            or row[5] != request.expected_execution_generation
        ):
            raise ExplodeReviewUnitError(
                "committed explode head does not match exact request"
            )

    def _require_base_snapshot(
        self,
        request: ExplodeReviewUnitRequest,
    ) -> None:
        row = self.connection.execute(
            "SELECT version, payload_sha256, state, structural_approval_ready "
            "FROM review_snapshots WHERE snapshot_id = ? AND batch_id = ?",
            (request.expected_snapshot_id, request.batch_id),
        ).fetchone()
        if row is None or tuple(row) != (
            request.expected_review_revision,
            request.expected_snapshot_sha256,
            "PUBLISHED",
            0,
        ):
            raise ExplodeReviewUnitError(
                "base snapshot is not the exact published batch head"
            )

    def _observed_memberships(
        self,
        batch_id: str,
    ) -> Tuple[Tuple[str, str, str, str], ...]:
        return tuple(
            tuple(row)
            for row in self.connection.execute(
                "SELECT unit_id, item_id, path, status FROM batch_memberships "
                "WHERE batch_id = ? ORDER BY item_id, unit_id, path",
                (batch_id,),
            ).fetchall()
        )

    def _require_memberships(
        self,
        batch_id: str,
        expected: Tuple[ExplodeMembership, ...],
        *,
        label: str,
    ) -> None:
        rows = tuple(
            (row.unit_id, row.item_id, row.path, "OPEN") for row in expected
        )
        if self._observed_memberships(batch_id) != rows:
            raise ExplodeReviewUnitError(
                "%s batch membership is incomplete or changed" % label
            )

    def _prepared_from_stored(
        self,
        request: ExplodeReviewUnitRequest,
        row: Tuple[Any, ...],
        prepared: PreparedExplodeTransition,
    ) -> _PreparedOperation:
        self._require_prepared_transition(prepared)
        if prepared.request != request:
            raise ExplodeReviewUnitError(
                "prepared explode transition changed request identity"
            )
        (
            lineage_kind,
            campaign_id,
            batch_id,
            request_hash,
            snapshot_id,
            base_snapshot_id,
            base_snapshot_sha256,
            envelope_value,
            envelope_sha256,
            final_path,
            final_sha256,
            state,
        ) = row
        envelope = _as_bytes(envelope_value, "stored submission payload")
        if (
            lineage_kind != "BATCH"
            or campaign_id != prepared.campaign_id
            or batch_id != request.batch_id
            or request_hash != request.request_hash
            or snapshot_id != request.next_snapshot_id
            or base_snapshot_id != request.expected_snapshot_id
            or base_snapshot_sha256 != request.expected_snapshot_sha256
            or envelope != prepared.envelope
            or sha256_bytes(envelope) != envelope_sha256
            or final_path != str(prepared.plan.final_path)
            or final_sha256 != prepared.plan.package_sha256
            or state not in ("PREPARED", "COMMITTED")
        ):
            raise ExplodeReviewUnitError(
                "submission id is bound to another or nonresumable request"
            )
        snapshot_row = self.connection.execute(
            "SELECT lineage_kind, campaign_id, batch_id, version, "
            "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
            "final_path, final_sha256, state, structural_approval_ready "
            "FROM review_snapshots WHERE snapshot_id = ?",
            (request.next_snapshot_id,),
        ).fetchone()
        expected_snapshot = (
            "BATCH",
            prepared.campaign_id,
            request.batch_id,
            prepared.publication.version,
            request.expected_snapshot_id,
            request.expected_snapshot_sha256,
            prepared.publication.snapshot_sha256,
            str(prepared.plan.final_path),
            prepared.plan.package_sha256,
            "PREPARED" if state == "PREPARED" else "PUBLISHED",
            0,
        )
        if snapshot_row is None or tuple(snapshot_row) != expected_snapshot:
            raise ExplodeReviewUnitError(
                "stored explode snapshot ledger binding is invalid"
            )
        return _PreparedOperation(
            prepared.publication,
            prepared.plan,
            prepared.envelope,
            prepared.base_memberships,
            prepared.next_memberships,
            state,
            True,
        )

    def _stored_transition(
        self,
        request: ExplodeReviewUnitRequest,
    ) -> Optional[PreparedExplodeTransition]:
        row = self.connection.execute(
            "SELECT lineage_kind, batch_id, request_hash, snapshot_id, "
            "base_snapshot_id, base_snapshot_sha256, payload_json, state "
            "FROM review_submissions "
            "WHERE submission_id = ?",
            (request.submission_id,),
        ).fetchone()
        if row is None:
            return None
        if tuple(row[:6]) != (
            "BATCH",
            request.batch_id,
            request.request_hash,
            request.next_snapshot_id,
            request.expected_snapshot_id,
            request.expected_snapshot_sha256,
        ) or row[7] not in ("PREPARED", "COMMITTED"):
            raise ExplodeReviewUnitError(
                "submission id is bound to another or nonresumable request"
            )
        return ExplodeTransitionPreparer(
            self.connection,
            self.raw_root,
            self.publisher,
        ).from_stored(
            _as_bytes(row[6], "stored submission payload"),
            policy=request.policy,
            expected_identity=ExplodeInvocationIdentity(
                batch_id=request.batch_id,
                expected_snapshot_id=request.expected_snapshot_id,
                expected_snapshot_sha256=request.expected_snapshot_sha256,
                folder_unit_id=request.folder_unit_id,
                next_snapshot_id=request.next_snapshot_id,
                submission_id=request.submission_id,
                actor=request.actor,
            ),
        )

    def _existing(
        self,
        request: ExplodeReviewUnitRequest,
        prepared: PreparedExplodeTransition,
    ) -> Optional[_PreparedOperation]:
        row = self.connection.execute(
            "SELECT lineage_kind, campaign_id, batch_id, request_hash, snapshot_id, "
            "base_snapshot_id, base_snapshot_sha256, payload_json, payload_sha256, "
            "final_path, final_sha256, state FROM review_submissions "
            "WHERE submission_id = ?",
            (request.submission_id,),
        ).fetchone()
        if row is None:
            return None
        return self._prepared_from_stored(request, tuple(row), prepared)

    def _require_prepared_transition(
        self,
        prepared: PreparedExplodeTransition,
    ) -> None:
        if type(prepared) is not PreparedExplodeTransition:
            raise TypeError("prepared must be PreparedExplodeTransition")
        request = prepared.request
        expected_root = (
            self.raw_root
            / "campaigns"
            / prepared.campaign_id
            / "snapshots"
        )
        if self.snapshot_root != expected_root:
            raise ExplodeReviewUnitError(
                "prepared explode campaign changed publisher root"
            )
        expected_publication = _explode_publication(
            self.snapshot_root,
            request,
            prepared.publication.canonical_payload,
        )
        if prepared.publication != expected_publication:
            raise ExplodeReviewUnitError(
                "prepared explode transition changed snapshot identity"
            )
        _validate_explode_plan(
            self.snapshot_root,
            prepared.publication,
            prepared.plan,
        )
        if prepared.envelope != _explode_envelope(
            request,
            prepared.publication,
            prepared.plan,
            prepared.base_memberships,
            prepared.next_memberships,
        ):
            raise ExplodeReviewUnitError(
                "prepared explode transition changed sealed envelope"
            )

    def _prepare_transition(
        self,
        prepared: PreparedExplodeTransition,
    ) -> _PreparedOperation:
        self._require_prepared_transition(prepared)
        request = prepared.request
        publication = prepared.publication
        plan = prepared.plan
        envelope = prepared.envelope
        old_memberships = prepared.base_memberships
        next_memberships = prepared.next_memberships
        review_plan = plan.sealed_payload
        staging_path = getattr(review_plan, "staging_path", None)
        if os.path.lexists(plan.final_path) or (
            isinstance(staging_path, Path) and os.path.lexists(staging_path)
        ):
            raise ExplodeReviewUnitError(
                "next snapshot filesystem identity is already bound"
            )
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            campaign_id = self._require_base_head(request)
            if campaign_id != prepared.campaign_id:
                raise ExplodeReviewUnitError("batch campaign changed")
            unresolved = self.connection.execute(
                "SELECT submission_id FROM review_submissions "
                "WHERE batch_id = ? AND state = 'PREPARED'",
                (request.batch_id,),
            ).fetchone()
            if unresolved is not None:
                raise ExplodeReviewUnitError(
                    "another unresolved batch submission exists"
                )
            if self.connection.execute(
                "SELECT 1 FROM review_submissions WHERE submission_id = ?",
                (request.submission_id,),
            ).fetchone() is not None:
                raise ExplodeReviewUnitError(
                    "submission id is already globally bound"
                )
            if self.connection.execute(
                "SELECT 1 FROM review_snapshots WHERE snapshot_id = ?",
                (request.next_snapshot_id,),
            ).fetchone() is not None:
                raise ExplodeReviewUnitError(
                    "next snapshot id is already globally bound"
                )
            self._require_base_snapshot(request)
            self._require_memberships(
                request.batch_id,
                old_memberships,
                label="base",
            )
            self.connection.execute(
                "INSERT INTO review_submissions "
                "(submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
                "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
                "payload_sha256, final_path, final_sha256, state) "
                "VALUES (?, 'BATCH', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                (
                    request.submission_id,
                    prepared.campaign_id,
                    request.batch_id,
                    request.request_hash,
                    request.next_snapshot_id,
                    request.expected_snapshot_id,
                    request.expected_snapshot_sha256,
                    envelope,
                    sha256_bytes(envelope),
                    str(plan.final_path),
                    plan.package_sha256,
                ),
            )
            self.connection.execute(
                "INSERT INTO review_snapshots "
                "(snapshot_id, lineage_kind, campaign_id, batch_id, version, "
                "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
                "final_path, final_sha256, state, structural_approval_ready) "
                "VALUES (?, 'BATCH', ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', 0)",
                (
                    request.next_snapshot_id,
                    prepared.campaign_id,
                    request.batch_id,
                    publication.version,
                    request.expected_snapshot_id,
                    request.expected_snapshot_sha256,
                    publication.snapshot_sha256,
                    str(plan.final_path),
                    plan.package_sha256,
                ),
            )
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            self.connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise ExplodeReviewUnitError(
                "explode submission identity or lineage constraint failed"
            ) from exc
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        return _PreparedOperation(
            publication,
            plan,
            envelope,
            old_memberships,
            next_memberships,
            "PREPARED",
            False,
        )

    def _publish_and_readback(
        self,
        operation: _PreparedOperation,
    ) -> None:
        try:
            result = self.publisher.publish(operation.plan)
        except batch_service.BatchServiceError as exc:
            raise ExplodeReviewUnitError(
                "full review package publication failed"
            ) from exc
        if (
            type(result) is not batch_service.SnapshotPublishResult
            or result.final_path != operation.plan.final_path
            or result.snapshot_sha256 != operation.publication.snapshot_sha256
            or result.package_sha256 != operation.plan.package_sha256
            or result.sealed_identity_sha256
            != operation.plan.sealed_identity_sha256
        ):
            raise ExplodeReviewUnitError(
                "published review package changed prepared identity"
            )
        try:
            sealed = review_state.read_sealed_review_snapshot(
                operation.plan.final_path,
                expected_snapshot_id=operation.publication.snapshot_id,
                expected_snapshot_sha256=operation.publication.snapshot_sha256,
                expected_package_sha256=operation.plan.package_sha256,
            )
        except review_state.ReviewStateError as exc:
            raise ExplodeReviewUnitError(
                "published review package readback failed"
            ) from exc
        if (
            sealed.snapshot_payload != operation.publication.canonical_payload
            or sealed.snapshot_id != operation.publication.snapshot_id
            or sealed.review_kind != "batch-preview"
            or sealed.source_kind != "batch-snapshot"
            or sealed.source_id != operation.publication.snapshot_id
        ):
            raise ExplodeReviewUnitError(
                "published review package readback changed snapshot"
            )

    def _block_stale(
        self,
        request: ExplodeReviewUnitRequest,
        operation: _PreparedOperation,
    ) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            submission = self.connection.execute(
                "SELECT request_hash, payload_sha256, final_path, final_sha256, state "
                "FROM review_submissions WHERE submission_id = ? AND batch_id = ?",
                (request.submission_id, request.batch_id),
            ).fetchone()
            snapshot = self.connection.execute(
                "SELECT parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
                "final_path, final_sha256, state FROM review_snapshots "
                "WHERE snapshot_id = ? AND batch_id = ?",
                (request.next_snapshot_id, request.batch_id),
            ).fetchone()
            if submission is None or snapshot is None or tuple(submission) != (
                request.request_hash,
                sha256_bytes(operation.envelope),
                str(operation.plan.final_path),
                operation.plan.package_sha256,
                "PREPARED",
            ) or tuple(snapshot) != (
                request.expected_snapshot_id,
                request.expected_snapshot_sha256,
                operation.publication.snapshot_sha256,
                str(operation.plan.final_path),
                operation.plan.package_sha256,
                "PREPARED",
            ):
                self.connection.execute("ROLLBACK")
                return
            blocked_submission = self.connection.execute(
                "UPDATE review_submissions SET state = 'BLOCKED' "
                "WHERE submission_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND request_hash = ? AND payload_sha256 = ?",
                (
                    request.submission_id,
                    request.batch_id,
                    request.request_hash,
                    sha256_bytes(operation.envelope),
                ),
            ).rowcount
            blocked_snapshot = self.connection.execute(
                "UPDATE review_snapshots SET state = 'BLOCKED' "
                "WHERE snapshot_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND parent_snapshot_id = ? AND parent_snapshot_sha256 = ? "
                "AND payload_sha256 = ?",
                (
                    request.next_snapshot_id,
                    request.batch_id,
                    request.expected_snapshot_id,
                    request.expected_snapshot_sha256,
                    operation.publication.snapshot_sha256,
                ),
            ).rowcount
            if (blocked_submission, blocked_snapshot) != (1, 1):
                raise ExplodeReviewUnitError(
                    "stale explode rows could not be blocked exactly once"
                )
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _commit(
        self,
        request: ExplodeReviewUnitRequest,
        operation: _PreparedOperation,
    ) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            submission = self.connection.execute(
                "SELECT payload_json, payload_sha256, final_path, final_sha256, "
                "state FROM review_submissions WHERE submission_id = ? "
                "AND batch_id = ?",
                (request.submission_id, request.batch_id),
            ).fetchone()
            snapshot = self.connection.execute(
                "SELECT version, parent_snapshot_id, parent_snapshot_sha256, "
                "payload_sha256, final_path, final_sha256, state, "
                "structural_approval_ready FROM review_snapshots "
                "WHERE snapshot_id = ? AND batch_id = ?",
                (request.next_snapshot_id, request.batch_id),
            ).fetchone()
            if submission is None or snapshot is None:
                raise _StalePreparedOperation(
                    "prepared explode ledger rows disappeared"
                )
            expected_submission = (
                operation.envelope,
                sha256_bytes(operation.envelope),
                str(operation.plan.final_path),
                operation.plan.package_sha256,
            )
            if tuple(submission[:4]) != expected_submission:
                raise _StalePreparedOperation(
                    "prepared explode submission changed"
                )
            expected_snapshot = (
                operation.publication.version,
                request.expected_snapshot_id,
                request.expected_snapshot_sha256,
                operation.publication.snapshot_sha256,
                str(operation.plan.final_path),
                operation.plan.package_sha256,
            )
            if tuple(snapshot[:6]) != expected_snapshot or snapshot[7] != 0:
                raise _StalePreparedOperation(
                    "prepared explode snapshot changed"
                )
            if submission[4] == "COMMITTED" and snapshot[6] == "PUBLISHED":
                self._require_next_head(request, operation.publication)
                self._require_memberships(
                    request.batch_id,
                    operation.next_memberships,
                    label="committed",
                )
                self._require_current_policy(request)
                self._require_lineage_policy(request)
                self.connection.execute("COMMIT")
                return
            if submission[4] != "PREPARED" or snapshot[6] != "PREPARED":
                raise _StalePreparedOperation(
                    "explode submission is not exactly resumable"
                )
            try:
                self._require_base_head(request)
                self._require_base_snapshot(request)
                self._require_memberships(
                    request.batch_id,
                    operation.old_memberships,
                    label="base",
                )
            except ExplodeReviewUnitError as exc:
                raise _StalePreparedOperation(str(exc)) from exc
            old_by_item = {
                row.item_id: row for row in operation.old_memberships
            }
            for next_row in operation.next_memberships:
                old_row = old_by_item[next_row.item_id]
                if old_row == next_row:
                    continue
                updated = self.connection.execute(
                    "UPDATE batch_memberships SET unit_id = ?, path = ? "
                    "WHERE batch_id = ? AND item_id = ? AND unit_id = ? "
                    "AND path = ? AND status = 'OPEN'",
                    (
                        next_row.unit_id,
                        next_row.path,
                        request.batch_id,
                        next_row.item_id,
                        old_row.unit_id,
                        old_row.path,
                    ),
                ).rowcount
                if updated != 1:
                    raise _StalePreparedOperation(
                        "explode membership CAS did not update exactly once"
                    )
            try:
                self._require_memberships(
                    request.batch_id,
                    operation.next_memberships,
                    label="next",
                )
            except ExplodeReviewUnitError as exc:
                raise _StalePreparedOperation(str(exc)) from exc
            updated_snapshot = self.connection.execute(
                "UPDATE review_snapshots SET state = 'PUBLISHED' "
                "WHERE snapshot_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND version = ? AND parent_snapshot_id = ? "
                "AND parent_snapshot_sha256 = ? AND payload_sha256 = ? "
                "AND final_path = ? AND final_sha256 = ? "
                "AND structural_approval_ready = 0",
                (
                    request.next_snapshot_id,
                    request.batch_id,
                    operation.publication.version,
                    request.expected_snapshot_id,
                    request.expected_snapshot_sha256,
                    operation.publication.snapshot_sha256,
                    str(operation.plan.final_path),
                    operation.plan.package_sha256,
                ),
            ).rowcount
            updated_submission = self.connection.execute(
                "UPDATE review_submissions SET state = 'COMMITTED' "
                "WHERE submission_id = ? AND batch_id = ? AND state = 'PREPARED' "
                "AND request_hash = ? AND snapshot_id = ? "
                "AND base_snapshot_id = ? AND base_snapshot_sha256 = ? "
                "AND payload_sha256 = ? AND final_path = ? AND final_sha256 = ?",
                (
                    request.submission_id,
                    request.batch_id,
                    request.request_hash,
                    request.next_snapshot_id,
                    request.expected_snapshot_id,
                    request.expected_snapshot_sha256,
                    sha256_bytes(operation.envelope),
                    str(operation.plan.final_path),
                    operation.plan.package_sha256,
                ),
            ).rowcount
            updated_batch = self.connection.execute(
                "UPDATE review_batches SET current_snapshot_id = ?, "
                "current_snapshot_sha256 = ?, review_revision = ? "
                "WHERE batch_id = ? AND status = 'OPEN' "
                "AND current_snapshot_id = ? AND current_snapshot_sha256 = ? "
                "AND review_revision = ? AND execution_generation = ?",
                (
                    request.next_snapshot_id,
                    operation.publication.snapshot_sha256,
                    request.expected_review_revision + 1,
                    request.batch_id,
                    request.expected_snapshot_id,
                    request.expected_snapshot_sha256,
                    request.expected_review_revision,
                    request.expected_execution_generation,
                ),
            ).rowcount
            if (updated_snapshot, updated_submission, updated_batch) != (1, 1, 1):
                raise _StalePreparedOperation(
                    "explode final CAS did not commit exactly once"
                )
            self._require_current_policy(request)
            self._require_lineage_policy(request)
            self.connection.execute("COMMIT")
        except _StalePreparedOperation:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            self._block_stale(request, operation)
            raise
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            self._block_stale(request, operation)
            raise _StalePreparedOperation(
                "explode membership or final CAS constraint became stale"
            ) from exc
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _result(
        self,
        request: ExplodeReviewUnitRequest,
        operation: _PreparedOperation,
    ) -> ExplodeReviewUnitResult:
        return ExplodeReviewUnitResult(
            batch_id=request.batch_id,
            status="OPEN",
            snapshot_id=request.next_snapshot_id,
            snapshot_state="PUBLISHED",
            snapshot_version=request.expected_review_revision + 1,
            review_revision=request.expected_review_revision + 1,
            execution_generation=request.expected_execution_generation,
            parent_snapshot_id=request.expected_snapshot_id,
            parent_snapshot_sha256=request.expected_snapshot_sha256,
            snapshot_sha256=operation.publication.snapshot_sha256,
            package_sha256=operation.plan.package_sha256,
            final_path=operation.plan.final_path,
            structural_approval_ready=False,
            structural_blocker=_STRUCTURAL_BLOCKER,
            resumed=operation.resumed,
        )

    def _prepare_compatibility_transition(
        self,
        request: ExplodeReviewUnitRequest,
    ) -> PreparedExplodeTransition:
        """Prepare a direct public invocation without any writer guard held."""

        if type(request) is not ExplodeReviewUnitRequest:
            raise TypeError("request must be ExplodeReviewUnitRequest")
        self._verify_schema()
        self._require_current_policy(request)
        self._require_lineage_policy(request)
        prepared = self._stored_transition(request)
        if prepared is not None:
            return prepared
        unresolved = self.connection.execute(
            "SELECT submission_id FROM review_submissions "
            "WHERE batch_id = ? AND state = 'PREPARED'",
            (request.batch_id,),
        ).fetchone()
        if unresolved is not None:
            raise ExplodeReviewUnitError(
                "another unresolved batch submission exists"
            )
        try:
            head = review_state.BatchHeadLoader(
                self.connection,
                self.raw_root,
            ).load(request.batch_id, (request.folder_unit_id,))
        except review_state.ReviewStateError as exc:
            raise ExplodeReviewUnitError(
                "exact OPEN batch head could not be loaded"
            ) from exc
        return ExplodeTransitionPreparer(
            self.connection,
            self.raw_root,
            self.publisher,
        ).prepare(request, head)

    def _explode_locked(
        self,
        prepared: PreparedExplodeTransition,
    ) -> ExplodeReviewUnitResult:
        if type(prepared) is not PreparedExplodeTransition:
            raise TypeError("prepared must be PreparedExplodeTransition")
        request = prepared.request
        self._verify_schema()
        self._require_current_policy(request)
        self._require_lineage_policy(request)
        self._require_prepared_transition(prepared)
        operation = self._existing(request, prepared)
        if operation is None:
            unresolved = self.connection.execute(
                "SELECT submission_id FROM review_submissions "
                "WHERE batch_id = ? AND state = 'PREPARED'",
                (request.batch_id,),
            ).fetchone()
            if unresolved is not None:
                raise ExplodeReviewUnitError(
                    "another unresolved batch submission exists"
                )
            operation = self._prepare_transition(prepared)
        self.checkpoint("prepared")
        self._publish_and_readback(operation)
        self.checkpoint("published")
        self._require_current_policy(request)
        self._require_lineage_policy(request)
        self._commit(request, operation)
        self.checkpoint("committed")
        return self._result(request, operation)

    def explode(
        self,
        request: ExplodeReviewUnitRequest,
    ) -> ExplodeReviewUnitResult:
        """Prepare outside writer guards, then expand or exactly resume."""

        prepared = self._prepare_compatibility_transition(request)
        return self.explode_prepared(prepared)

    def explode_prepared(
        self,
        prepared: PreparedExplodeTransition,
    ) -> ExplodeReviewUnitResult:
        """Apply one exact reader-prepared transition under writer guards."""

        if type(prepared) is not PreparedExplodeTransition:
            raise TypeError("prepared must be PreparedExplodeTransition")
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
                return self._explode_locked(prepared)


__all__ = [
    "ExplodeInvocationIdentity",
    "ExplodeMembership",
    "ExplodeReviewUnitError",
    "ExplodeReviewUnitRequest",
    "ExplodeReviewUnitResult",
    "ExplodeReviewUnitService",
    "ExplodeTransitionPreparer",
    "PreparedExplodeTransition",
    "exploded_batch_review_document_from_snapshot",
]
