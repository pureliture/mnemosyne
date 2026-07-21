"""Split one OPEN review batch into parent remainder + child genesis batches."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import (
    admission,
    batch_event_contract,
    batch_service,
    m3_schema,
    safety,
)
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_MAX_EVENT_BLOB_BYTES = 64 * 1024 * 1024


class SplitBatchError(RuntimeError):
    """Base error for split-review-batch."""


class SplitBatchValidationError(SplitBatchError):
    """The requested unit selection is not a legal split."""


class SplitBatchConflict(SplitBatchError):
    """Batch lineage, membership, or publication state blocks the split."""


class SplitBatchPublicationError(SplitBatchError):
    """Sealed split artifacts could not be published or read back."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise SplitBatchValidationError("%s is invalid" % label)
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise SplitBatchValidationError("%s is invalid" % label)
    return value


def _actor(value: Any, label: str) -> str:
    try:
        return batch_event_contract.validate_actor(value)
    except batch_event_contract.BatchEventContractError as exc:
        raise SplitBatchValidationError("%s is invalid" % label) from exc


def _canonical_event_root(path: Path) -> Path:
    value = Path(path)
    if (
        not value.is_absolute()
        or any(part in (".", "..") for part in value.parts)
        or value.name != "batch-events"
        or value.parent.parent.name != "campaigns"
        or _ID.fullmatch(value.parent.name) is None
    ):
        raise SplitBatchValidationError(
            "split batch event root must be a canonical campaign namespace"
        )
    return value


def _ordered_unique(values: Sequence[str], *, label: str) -> Tuple[str, ...]:
    ordered = tuple(sorted(set(values)))
    if tuple(values) != ordered:
        raise SplitBatchValidationError("%s must be unique and sorted" % label)
    return ordered


@dataclass(frozen=True)
class SplitSelection:
    selected_unit_ids: Tuple[str, ...]
    remainder_unit_ids: Tuple[str, ...]
    selected_units: Tuple[batch_service.BatchUnit, ...]
    remainder_units: Tuple[batch_service.BatchUnit, ...]


def validate_split_selection(
    units: Sequence[batch_service.BatchUnit],
    selected_unit_ids: Sequence[str],
) -> SplitSelection:
    if not units:
        raise SplitBatchValidationError("batch units are empty")
    if not selected_unit_ids:
        raise SplitBatchValidationError("selected unit ids are empty")
    selected = _ordered_unique(selected_unit_ids, label="selected unit ids")
    by_id = {unit.unit_id: unit for unit in units}
    unknown = tuple(unit_id for unit_id in selected if unit_id not in by_id)
    if unknown:
        raise SplitBatchValidationError("unknown selected unit id")
    if len(selected) == len(units):
        raise SplitBatchValidationError("cannot select every unit in the batch")

    selected_set = frozenset(selected)
    seen_items: set[str] = set()
    selected_units = [by_id[unit_id] for unit_id in selected]
    for index, left in enumerate(selected_units):
        for right in selected_units[index + 1 :]:
            if (
                left.path == right.path
                or left.path.startswith(right.path + "/")
                or right.path.startswith(left.path + "/")
            ):
                raise SplitBatchValidationError(
                    "selected units are not resource-disjoint"
                )
    for unit_id in selected:
        unit = by_id[unit_id]
        for item_id in unit.member_item_ids:
            if item_id in seen_items:
                raise SplitBatchValidationError(
                    "selected units overlap on member items"
                )
            seen_items.add(item_id)
        if unit.unit_kind == "file":
            for other in units:
                if other.unit_kind != "folder" or other.unit_id in selected_set:
                    continue
                for member_path in unit.member_paths:
                    if member_path.startswith(other.path + "/"):
                        raise SplitBatchValidationError(
                            "folder descendant selection requires explode first"
                        )

    item_to_units: Dict[str, Tuple[str, ...]] = {}
    for unit in units:
        for item_id in unit.member_item_ids:
            prior = item_to_units.get(item_id, ())
            item_to_units[item_id] = tuple(sorted(set(prior + (unit.unit_id,))))
    for linked in item_to_units.values():
        if len(linked) < 2:
            continue
        chosen = frozenset(linked) & selected_set
        if chosen and chosen != frozenset(linked):
            raise SplitBatchValidationError(
                "shared resource component must move entirely into one partition"
            )

    selected_units = tuple(by_id[unit_id] for unit_id in selected)
    remainder_units = tuple(
        unit for unit in units if unit.unit_id not in selected_set
    )
    remainder_ids = tuple(unit.unit_id for unit in remainder_units)
    if len({unit.homogeneity_key() for unit in selected_units}) != 1:
        raise SplitBatchValidationError("selected units must be homogeneous")
    return SplitSelection(
        selected_unit_ids=selected,
        remainder_unit_ids=remainder_ids,
        selected_units=selected_units,
        remainder_units=remainder_units,
    )


@dataclass(frozen=True)
class SplitReviewBatchRequest:
    event_id: str
    batch_id: str
    expected_snapshot_id: str
    expected_snapshot_sha256: str
    expected_review_revision: int
    expected_execution_generation: int
    selected_unit_ids: Tuple[str, ...]
    child_batch_id: str
    child_snapshot_id: str
    child_snapshot_sha256: str
    child_submission_id: str
    parent_next_snapshot_id: str
    parent_next_snapshot_sha256: str
    parent_submission_id: str
    policy: admission.ApprovedPolicyRef
    actor: str
    units: Tuple[batch_service.BatchUnit, ...]

    def __post_init__(self) -> None:
        _identifier(self.event_id, "event id")
        _identifier(self.batch_id, "batch id")
        _identifier(self.expected_snapshot_id, "expected snapshot id")
        _hash(self.expected_snapshot_sha256, "expected snapshot hash")
        if (
            type(self.expected_review_revision) is not int
            or self.expected_review_revision < 1
        ):
            raise SplitBatchValidationError("expected review revision is invalid")
        if (
            type(self.expected_execution_generation) is not int
            or self.expected_execution_generation < 0
        ):
            raise SplitBatchValidationError(
                "expected execution generation is invalid"
            )
        object.__setattr__(
            self,
            "selected_unit_ids",
            _ordered_unique(self.selected_unit_ids, label="selected unit ids"),
        )
        for label, value in (
            ("child batch id", self.child_batch_id),
            ("child snapshot id", self.child_snapshot_id),
            ("child snapshot hash", self.child_snapshot_sha256),
            ("child submission id", self.child_submission_id),
            ("parent next snapshot id", self.parent_next_snapshot_id),
            ("parent next snapshot hash", self.parent_next_snapshot_sha256),
            ("parent submission id", self.parent_submission_id),
        ):
            if label.endswith("hash"):
                _hash(value, label)
            else:
                _identifier(value, label)
        if self.child_batch_id == self.batch_id:
            raise SplitBatchValidationError("child batch must differ from parent batch")
        if len(
            {
                self.expected_snapshot_id,
                self.child_snapshot_id,
                self.parent_next_snapshot_id,
            }
        ) != 3:
            raise SplitBatchValidationError("split snapshot ids must be distinct")
        if self.child_submission_id == self.parent_submission_id:
            raise SplitBatchValidationError("split submission ids must be distinct")
        _actor(self.actor, "actor")
        if type(self.units) is not tuple:
            raise SplitBatchValidationError("batch units are required")


@dataclass(frozen=True)
class PreparedSplitBatchEvent:
    request: SplitReviewBatchRequest
    membership_release_json: bytes
    membership_release_sha256: str
    payload_json: bytes
    payload_sha256: str
    final_path: Path

    @property
    def payload(self) -> Dict[str, Any]:
        return json.loads(self.payload_json.decode("utf-8"))


def _request_identity(request: SplitReviewBatchRequest) -> tuple:
    return (
        request.event_id,
        request.batch_id,
        request.expected_snapshot_id,
        request.expected_snapshot_sha256,
        request.expected_review_revision,
        request.expected_execution_generation,
        request.selected_unit_ids,
        request.child_batch_id,
        request.child_snapshot_id,
        request.child_snapshot_sha256,
        request.child_submission_id,
        request.parent_next_snapshot_id,
        request.parent_next_snapshot_sha256,
        request.parent_submission_id,
        request.actor,
    )


class SplitBatchService:
    """Prepare SPLIT batch events and (eventually) dual-snapshot publication."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        event_root: Path,
        *,
        placement_shared: Callable[[], object],
        ledger_exclusive: Callable[[], object],
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        self.connection = connection
        self.event_root = _canonical_event_root(event_root)
        self.campaign_id = self.event_root.parent.name
        self.snapshot_root = self.event_root.parent / "snapshots"
        self.placement_shared = placement_shared
        self.ledger_exclusive = ledger_exclusive

    def _verify_schema(self) -> None:
        try:
            m3_schema.verify_v3_schema(self.connection)
        except (m3_schema.M3SchemaError, sqlite3.Error) as exc:
            raise SplitBatchConflict("exact curation ledger v3 is required") from exc

    def _memberships(self, batch_id: str) -> Tuple[Dict[str, str], ...]:
        rows = self.connection.execute(
            "SELECT membership_id, unit_id, item_id, path, status "
            "FROM batch_memberships WHERE batch_id = ? ORDER BY membership_id",
            (batch_id,),
        ).fetchall()
        if not rows:
            raise SplitBatchConflict("batch membership is empty")
        return tuple(
            {
                "item_id": row[2],
                "membership_id": row[0],
                "path": row[3],
                "status": row[4],
                "unit_id": row[1],
            }
            for row in rows
        )

    @staticmethod
    def _require_request_membership_binding(
        request: SplitReviewBatchRequest,
        memberships: Tuple[Dict[str, str], ...],
    ) -> None:
        expected = tuple(
            sorted(
                (
                    unit.unit_id,
                    item_id,
                    unit.path,
                    "OPEN",
                )
                for unit in request.units
                for item_id in unit.member_item_ids
            )
        )
        observed = tuple(
            sorted(
                (
                    row["unit_id"],
                    row["item_id"],
                    row["path"],
                    row["status"],
                )
                for row in memberships
            )
        )
        if observed != expected:
            raise SplitBatchConflict(
                "request units do not match current batch membership"
            )

    def prepare(self, request: SplitReviewBatchRequest) -> PreparedSplitBatchEvent:
        if type(request) is not SplitReviewBatchRequest:
            raise TypeError("request must be SplitReviewBatchRequest")
        if not request.units:
            raise SplitBatchValidationError("batch units are required for prepare")
        self._verify_schema()
        selection = validate_split_selection(
            request.units,
            request.selected_unit_ids,
        )
        memberships = self._memberships(request.batch_id)
        self._require_request_membership_binding(request, memberships)
        selected_set = frozenset(selection.selected_unit_ids)
        selected_memberships = [
            row
            for row in memberships
            if row["unit_id"] in selected_set and row["status"] == "OPEN"
        ]
        remainder_memberships = [
            row
            for row in memberships
            if row["unit_id"] not in selected_set and row["status"] == "OPEN"
        ]
        release = [
            {
                "item_id": row["item_id"],
                "membership_id": row["membership_id"],
                "path": row["path"],
                "unit_id": row["unit_id"],
            }
            for row in memberships
            if row["status"] == "OPEN"
        ]
        release_json = canonical_json_bytes(release)
        payload = {
            "actor": request.actor,
            "batch_id": request.batch_id,
            "child_batch_id": request.child_batch_id,
            "child_snapshot_id": request.child_snapshot_id,
            "child_snapshot_sha256": request.child_snapshot_sha256,
            "child_submission_id": request.child_submission_id,
            "event_id": request.event_id,
            "event_kind": "SPLIT",
            "expected_execution_generation": request.expected_execution_generation,
            "expected_review_revision": request.expected_review_revision,
            "expected_snapshot_id": request.expected_snapshot_id,
            "expected_snapshot_sha256": request.expected_snapshot_sha256,
            "parent_next_snapshot_id": request.parent_next_snapshot_id,
            "parent_next_snapshot_sha256": request.parent_next_snapshot_sha256,
            "parent_submission_id": request.parent_submission_id,
            "remainder_memberships": remainder_memberships,
            "remainder_unit_ids": list(selection.remainder_unit_ids),
            "schema_version": 1,
            "selected_memberships": selected_memberships,
            "selected_unit_ids": list(selection.selected_unit_ids),
        }
        encoded = canonical_json_bytes(payload)
        final_path = self.event_root / request.event_id / "event.json"
        prepared = PreparedSplitBatchEvent(
            request=request,
            membership_release_json=release_json,
            membership_release_sha256=sha256_bytes(release_json),
            payload_json=encoded,
            payload_sha256=sha256_bytes(encoded),
            final_path=final_path,
        )
        try:
            batch_event_contract.validate_batch_event(
                {
                    "batch_event_id": request.event_id,
                    "batch_id": request.batch_id,
                    "event_kind": "SPLIT",
                    "expected_batch_status": "OPEN",
                    "expected_snapshot_id": request.expected_snapshot_id,
                    "expected_snapshot_sha256": request.expected_snapshot_sha256,
                    "expected_review_revision": request.expected_review_revision,
                    "expected_execution_generation": (
                        request.expected_execution_generation
                    ),
                    "terminal_batch_status": None,
                    "membership_release_json": prepared.membership_release_json,
                    "membership_release_sha256": (
                        prepared.membership_release_sha256
                    ),
                    "payload_json": prepared.payload_json,
                    "payload_sha256": prepared.payload_sha256,
                    "final_path": str(prepared.final_path),
                    "final_sha256": prepared.payload_sha256,
                    "state": "PREPARED",
                    "child_batch_id": request.child_batch_id,
                    "child_snapshot_id": request.child_snapshot_id,
                    "child_snapshot_sha256": request.child_snapshot_sha256,
                    "source_execution_id": None,
                    "source_approval_id": None,
                    "result_path": None,
                    "result_sha256": None,
                },
                max_blob_bytes=_MAX_EVENT_BLOB_BYTES,
            )
        except batch_event_contract.BatchEventContractError as exc:
            raise SplitBatchValidationError(
                "prepared split event contract is invalid"
            ) from exc
        return prepared

    def _batch_lineage(self, request: SplitReviewBatchRequest) -> None:
        row = self.connection.execute(
            "SELECT campaign_id, status, current_snapshot_id, current_snapshot_sha256, "
            "review_revision, execution_generation FROM review_batches "
            "WHERE batch_id = ?",
            (request.batch_id,),
        ).fetchone()
        if row is None:
            raise SplitBatchConflict("batch does not exist")
        if tuple(row) != (
            self.campaign_id,
            "OPEN",
            request.expected_snapshot_id,
            request.expected_snapshot_sha256,
            request.expected_review_revision,
            request.expected_execution_generation,
        ):
            raise SplitBatchConflict("batch lineage is stale")

    def _child_binding_error(
        self,
        request: SplitReviewBatchRequest,
        *,
        require_genesis: bool,
    ) -> Optional[str]:
        row = self.connection.execute(
            "SELECT campaign_id, request_hash, status, current_snapshot_id, "
            "current_snapshot_sha256, review_revision, execution_generation "
            "FROM review_batches WHERE batch_id = ?",
            (request.child_batch_id,),
        ).fetchone()
        if row is None:
            return "split child genesis is missing"
        try:
            request_hash = batch_event_contract.split_child_request_hash(
                request.batch_id,
                request.child_batch_id,
            )
        except batch_event_contract.BatchEventContractError:
            return "split child genesis identity is invalid"
        observed = tuple(row)
        if observed[:2] != (self.campaign_id, request_hash):
            return "split child genesis binding is stale"
        if require_genesis and observed[2:] != ("OPEN", None, None, 0, 0):
            return "split child genesis state is stale"
        return None

    def prepare_locked(self, prepared: PreparedSplitBatchEvent) -> bool:
        if type(prepared) is not PreparedSplitBatchEvent:
            raise TypeError("prepared must be PreparedSplitBatchEvent")
        request = prepared.request
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._stored_event_row(request.event_id)
            if existing is not None:
                self._require_stored_match(prepared, existing)
                if existing[14] == "PUBLISHED":
                    child_error = self._child_binding_error(
                        request,
                        require_genesis=False,
                    )
                    if child_error is not None:
                        raise SplitBatchConflict(child_error)
                    self.connection.execute("COMMIT")
                    return True
                if existing[14] != "PREPARED":
                    raise SplitBatchConflict("split event is not resumable")
                self._batch_lineage(request)
                child_error = self._child_binding_error(
                    request,
                    require_genesis=True,
                )
                if child_error is not None:
                    raise SplitBatchConflict(child_error)
                self.connection.execute("COMMIT")
                return True
            self._batch_lineage(request)
            if os.path.lexists(prepared.final_path):
                raise SplitBatchPublicationError(
                    "rowless split event artifact is orphan evidence"
                )
            other = self.connection.execute(
                "SELECT batch_event_id FROM batch_events "
                "WHERE batch_id = ? AND state = 'PREPARED'",
                (request.batch_id,),
            ).fetchone()
            if other is not None:
                raise SplitBatchConflict("another unresolved batch event blocks split")
            child_row = self.connection.execute(
                "SELECT batch_id FROM review_batches WHERE batch_id = ?",
                (request.child_batch_id,),
            ).fetchone()
            if child_row is not None:
                raise SplitBatchConflict("split child batch already exists")
            self.connection.execute(
                "INSERT INTO review_batches ("
                "batch_id, campaign_id, request_hash, status, current_snapshot_id, "
                "current_snapshot_sha256, review_revision, execution_generation"
                ") VALUES (?, ?, ?, 'OPEN', NULL, NULL, 0, 0)",
                (
                    request.child_batch_id,
                    self.campaign_id,
                    batch_event_contract.split_child_request_hash(
                        request.batch_id,
                        request.child_batch_id,
                    ),
                ),
            )
            self.connection.execute(
                "INSERT INTO batch_events ("
                "batch_event_id, batch_id, event_kind, expected_batch_status, "
                "expected_snapshot_id, expected_snapshot_sha256, "
                "expected_review_revision, expected_execution_generation, "
                "terminal_batch_status, child_batch_id, child_snapshot_id, "
                "child_snapshot_sha256, source_execution_id, source_approval_id, "
                "result_path, result_sha256, membership_release_json, "
                "membership_release_sha256, payload_json, payload_sha256, "
                "final_path, final_sha256, state"
                ") VALUES (?, ?, 'SPLIT', 'OPEN', ?, ?, ?, ?, NULL, ?, ?, ?, "
                "NULL, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                (
                    request.event_id,
                    request.batch_id,
                    request.expected_snapshot_id,
                    request.expected_snapshot_sha256,
                    request.expected_review_revision,
                    request.expected_execution_generation,
                    request.child_batch_id,
                    request.child_snapshot_id,
                    request.child_snapshot_sha256,
                    prepared.membership_release_json,
                    prepared.membership_release_sha256,
                    prepared.payload_json,
                    prepared.payload_sha256,
                    str(prepared.final_path),
                    prepared.payload_sha256,
                ),
            )
            self.connection.execute("COMMIT")
            return False
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise


    def _stored_event_row(self, event_id: str) -> Optional[tuple]:
        row = self.connection.execute(
            "SELECT batch_id, event_kind, expected_batch_status, "
            "expected_snapshot_id, expected_snapshot_sha256, "
            "expected_review_revision, expected_execution_generation, "
            "terminal_batch_status, CASE WHEN "
            "typeof(membership_release_json) = 'blob' AND "
            "octet_length(membership_release_json) <= ? "
            "THEN membership_release_json ELSE X'' END, "
            "membership_release_sha256, CASE WHEN "
            "typeof(payload_json) = 'blob' AND octet_length(payload_json) <= ? "
            "THEN payload_json ELSE X'' END, payload_sha256, "
            "final_path, final_sha256, state, child_batch_id, "
            "child_snapshot_id, child_snapshot_sha256, source_execution_id, "
            "source_approval_id, result_path, result_sha256, "
            "typeof(membership_release_json), CASE WHEN "
            "typeof(membership_release_json) = 'blob' "
            "THEN octet_length(membership_release_json) ELSE -1 END, "
            "typeof(payload_json), CASE WHEN typeof(payload_json) = 'blob' "
            "THEN octet_length(payload_json) ELSE -1 END "
            "FROM batch_events WHERE batch_event_id = ?",
            (
                _MAX_EVENT_BLOB_BYTES,
                _MAX_EVENT_BLOB_BYTES,
                event_id,
            ),
        ).fetchone()
        if row is None:
            return None
        values = tuple(row)
        release_size = values[23]
        payload_size = values[25]
        if (
            values[22] != "blob"
            or type(release_size) is not int
            or not 0 <= release_size <= _MAX_EVENT_BLOB_BYTES
            or values[24] != "blob"
            or type(payload_size) is not int
            or not 0 <= payload_size <= _MAX_EVENT_BLOB_BYTES
        ):
            raise SplitBatchConflict(
                "stored split event contract is invalid: bounded blob preflight"
            )
        return values[:22]

    def _require_stored_match(
        self,
        prepared: PreparedSplitBatchEvent,
        row: tuple,
    ) -> None:
        request = prepared.request
        record = {
            "batch_event_id": request.event_id,
            "batch_id": row[0],
            "event_kind": row[1],
            "expected_batch_status": row[2],
            "expected_snapshot_id": row[3],
            "expected_snapshot_sha256": row[4],
            "expected_review_revision": row[5],
            "expected_execution_generation": row[6],
            "terminal_batch_status": row[7],
            "membership_release_json": row[8],
            "membership_release_sha256": row[9],
            "payload_json": row[10],
            "payload_sha256": row[11],
            "final_path": row[12],
            "final_sha256": row[13],
            "state": row[14],
            "child_batch_id": row[15],
            "child_snapshot_id": row[16],
            "child_snapshot_sha256": row[17],
            "source_execution_id": row[18],
            "source_approval_id": row[19],
            "result_path": row[20],
            "result_sha256": row[21],
        }
        try:
            batch_event_contract.validate_batch_event(
                record,
                max_blob_bytes=_MAX_EVENT_BLOB_BYTES,
            )
        except batch_event_contract.BatchEventContractError as exc:
            raise SplitBatchConflict(
                "stored split event contract is invalid"
            ) from exc
        expected = (
            request.batch_id,
            "SPLIT",
            "OPEN",
            request.expected_snapshot_id,
            request.expected_snapshot_sha256,
            request.expected_review_revision,
            request.expected_execution_generation,
            None,
            prepared.membership_release_json,
            prepared.membership_release_sha256,
            prepared.payload_json,
            prepared.payload_sha256,
            str(prepared.final_path),
            prepared.payload_sha256,
        )
        if row[:14] != expected or row[15:22] != (
            request.child_batch_id,
            request.child_snapshot_id,
            request.child_snapshot_sha256,
            None,
            None,
            None,
            None,
        ):
            raise SplitBatchConflict("split event identity is rebound")

    def _read_exact_event(self, prepared: PreparedSplitBatchEvent) -> None:
        final_path = prepared.final_path
        try:
            directory_fd = safety.open_verified_directory(
                final_path.parent,
                require_owner_only=True,
                error_type=SplitBatchPublicationError,
            )
            try:
                info, raw = safety.read_regular_file_at(
                    directory_fd,
                    final_path.name,
                    final_path,
                    label="split batch event artifact",
                    expected_mode=0o600,
                    max_bytes=len(prepared.payload_json),
                    error_type=SplitBatchPublicationError,
                )
                if info.st_nlink != 1:
                    raise SplitBatchPublicationError(
                        "split batch event artifact identity is invalid: %s"
                        % final_path
                    )
                if raw != prepared.payload_json:
                    raise SplitBatchPublicationError(
                        "split batch event artifact readback mismatch"
                    )
                safety.require_same_directory_identity(
                    final_path.parent,
                    directory_fd,
                    "split batch event artifact",
                    error_type=SplitBatchPublicationError,
                )
            finally:
                os.close(directory_fd)
        except SplitBatchPublicationError:
            raise
        except OSError as exc:
            raise SplitBatchPublicationError(
                "split batch event artifact is unreadable"
            ) from exc

    def _publish_event(self, prepared: PreparedSplitBatchEvent) -> None:
        if os.path.lexists(prepared.final_path):
            self._read_exact_event(prepared)
            return
        safety.publish_bytes_atomic_no_replace(
            prepared.final_path,
            prepared.payload_json,
            label="split batch event artifact",
            mode=0o600,
            create_parent=True,
            collision_error="split batch event artifact already exists",
            final_identity_error="split batch event artifact identity is invalid",
            parent_error="split batch event artifact parent is invalid",
            error_type=SplitBatchPublicationError,
            after_fd_readback=lambda _path, _fd, _directory_fd: None,
        )
        self._read_exact_event(prepared)

    @staticmethod
    def _caused_by_missing(error: BaseException) -> bool:
        current: Optional[BaseException] = error
        while current is not None:
            if isinstance(current, FileNotFoundError):
                return True
            current = current.__cause__
        return False

    def _read_exact_snapshot_if_present(
        self,
        final_path: Path,
        payload: bytes,
    ) -> bool:
        try:
            directory_fd = safety.open_verified_directory(
                final_path.parent,
                require_owner_only=True,
                error_type=SplitBatchPublicationError,
            )
        except SplitBatchPublicationError as exc:
            if self._caused_by_missing(exc):
                return False
            raise
        try:
            try:
                info, raw = safety.read_regular_file_at(
                    directory_fd,
                    final_path.name,
                    final_path,
                    label="split snapshot artifact",
                    expected_mode=0o600,
                    max_bytes=len(payload),
                    error_type=SplitBatchPublicationError,
                )
            except SplitBatchPublicationError as exc:
                if self._caused_by_missing(exc):
                    return False
                raise
            if info.st_nlink != 1:
                raise SplitBatchPublicationError(
                    "split snapshot artifact identity is invalid: %s" % final_path
                )
            if raw != payload:
                raise SplitBatchPublicationError(
                    "split snapshot readback mismatch"
                )
            safety.require_same_directory_identity(
                final_path.parent,
                directory_fd,
                "split snapshot artifact",
                error_type=SplitBatchPublicationError,
            )
            return True
        finally:
            os.close(directory_fd)

    def _parent_request_hash(self, batch_id: str) -> str:
        row = self.connection.execute(
            "SELECT request_hash FROM review_batches WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if row is None:
            raise SplitBatchConflict("batch does not exist")
        value = row[0]
        if type(value) is not str or _HASH.fullmatch(value) is None:
            raise SplitBatchConflict("parent batch request hash is invalid")
        return value

    @staticmethod
    def _snapshot_unit_projection(values: Any) -> tuple:
        if type(values) is not list:
            raise SplitBatchValidationError(
                "split snapshot payload binding is invalid"
            )
        projection = []
        seen = set()
        for value in values:
            if type(value) is not dict:
                raise SplitBatchValidationError(
                    "split snapshot payload binding is invalid"
                )
            unit_id = value.get("unit_id")
            path = value.get("canonical_path")
            member_item_ids = value.get("member_item_ids")
            if (
                type(unit_id) is not str
                or unit_id in seen
                or type(path) is not str
                or type(member_item_ids) is not list
                or any(type(item_id) is not str for item_id in member_item_ids)
                or tuple(sorted(set(member_item_ids)))
                != tuple(member_item_ids)
            ):
                raise SplitBatchValidationError(
                    "split snapshot payload binding is invalid"
                )
            seen.add(unit_id)
            projection.append((unit_id, path, tuple(member_item_ids)))
        return tuple(sorted(projection))

    @staticmethod
    def _membership_unit_projection(values: Any) -> tuple:
        if type(values) is not list:
            raise SplitBatchValidationError(
                "split snapshot payload binding is invalid"
            )
        grouped: Dict[str, tuple[str, list[str]]] = {}
        for value in values:
            if type(value) is not dict:
                raise SplitBatchValidationError(
                    "split snapshot payload binding is invalid"
                )
            unit_id = value.get("unit_id")
            path = value.get("path")
            item_id = value.get("item_id")
            if not all(type(item) is str for item in (unit_id, path, item_id)):
                raise SplitBatchValidationError(
                    "split snapshot payload binding is invalid"
                )
            prior = grouped.get(unit_id)
            if prior is None:
                grouped[unit_id] = (path, [item_id])
            elif prior[0] != path or item_id in prior[1]:
                raise SplitBatchValidationError(
                    "split snapshot payload binding is invalid"
                )
            else:
                prior[1].append(item_id)
        return tuple(
            sorted(
                (unit_id, path, tuple(sorted(item_ids)))
                for unit_id, (path, item_ids) in grouped.items()
            )
        )

    def _validate_snapshot_envelope(
        self,
        encoded: bytes,
        *,
        expected_identity: dict,
        expected_units: Optional[list] = None,
        expected_memberships: Optional[list] = None,
    ) -> None:
        try:
            payload = json.loads(encoded.decode("utf-8"))
            canonical = canonical_json_bytes(payload)
        except (
            TypeError,
            ValueError,
            UnicodeError,
            RecursionError,
            OverflowError,
        ) as exc:
            raise SplitBatchValidationError(
                "split snapshot payload binding is invalid"
            ) from exc
        if (
            type(payload) is not dict
            or canonical != encoded
            or any(payload.get(key) != value for key, value in expected_identity.items())
            or type(payload.get("schema_version")) is not int
            or type(payload.get("batch_version")) is not int
        ):
            raise SplitBatchValidationError(
                "split snapshot payload binding is invalid"
            )
        units = payload.get("units")
        if expected_units is not None:
            if units != expected_units:
                raise SplitBatchValidationError(
                    "split snapshot payload binding is invalid"
                )
        elif expected_memberships is not None:
            if self._snapshot_unit_projection(units) != (
                self._membership_unit_projection(expected_memberships)
            ):
                raise SplitBatchValidationError(
                    "split snapshot payload binding is invalid"
                )
        else:
            raise SplitBatchValidationError(
                "split snapshot payload binding is invalid"
            )

    def _validate_bundle(
        self,
        bundle: "SplitSnapshotBundle",
        request: SplitReviewBatchRequest,
        *,
        allow_existing: bool,
        require_existing: bool = False,
        event_payload: Optional[dict] = None,
    ) -> None:
        if type(bundle) is not SplitSnapshotBundle:
            raise TypeError("bundle must be SplitSnapshotBundle")
        expected_parent = (
            self.snapshot_root
            / request.parent_next_snapshot_id
            / "snapshot.json"
        )
        expected_child = (
            self.snapshot_root / request.child_snapshot_id / "snapshot.json"
        )
        if (
            bundle.parent_snapshot_final_path != expected_parent
            or bundle.child_snapshot_final_path != expected_child
        ):
            raise SplitBatchValidationError(
                "split snapshot path is outside campaign namespace"
            )
        if (
            type(bundle.parent_snapshot_payload_json) is not bytes
            or type(bundle.child_snapshot_payload_json) is not bytes
            or sha256_bytes(bundle.parent_snapshot_payload_json)
            != request.parent_next_snapshot_sha256
            or sha256_bytes(bundle.child_snapshot_payload_json)
            != request.child_snapshot_sha256
        ):
            raise SplitBatchValidationError("split snapshot payload binding is invalid")
        parent_request_hash = self._parent_request_hash(request.batch_id)
        selected_ids = frozenset(request.selected_unit_ids)
        if request.units:
            parent_units = [
                unit.to_dict()
                for unit in sorted(request.units, key=lambda value: value.unit_id)
                if unit.unit_id not in selected_ids
            ]
            child_units = [
                unit.to_dict()
                for unit in sorted(request.units, key=lambda value: value.unit_id)
                if unit.unit_id in selected_ids
            ]
            parent_memberships = None
            child_memberships = None
        elif type(event_payload) is dict:
            parent_units = None
            child_units = None
            parent_memberships = event_payload.get("remainder_memberships")
            child_memberships = event_payload.get("selected_memberships")
        else:
            raise SplitBatchValidationError(
                "split snapshot payload binding is invalid"
            )
        common_identity = {
            "campaign_id": self.campaign_id,
            "parent_snapshot_id": request.expected_snapshot_id,
            "parent_snapshot_sha256": request.expected_snapshot_sha256,
            "schema_version": 2,
        }
        self._validate_snapshot_envelope(
            bundle.parent_snapshot_payload_json,
            expected_identity={
                **common_identity,
                "batch_id": request.batch_id,
                "batch_version": request.expected_review_revision + 1,
                "request_hash": parent_request_hash,
                "snapshot_id": request.parent_next_snapshot_id,
            },
            expected_units=parent_units,
            expected_memberships=parent_memberships,
        )
        self._validate_snapshot_envelope(
            bundle.child_snapshot_payload_json,
            expected_identity={
                **common_identity,
                "batch_id": request.child_batch_id,
                "batch_version": 1,
                "request_hash": batch_event_contract.split_child_request_hash(
                    request.batch_id,
                    request.child_batch_id,
                ),
                "snapshot_id": request.child_snapshot_id,
            },
            expected_units=child_units,
            expected_memberships=child_memberships,
        )
        for final_path, payload in (
            (
                bundle.parent_snapshot_final_path,
                bundle.parent_snapshot_payload_json,
            ),
            (
                bundle.child_snapshot_final_path,
                bundle.child_snapshot_payload_json,
            ),
        ):
            present = self._read_exact_snapshot_if_present(final_path, payload)
            if require_existing and not present:
                raise SplitBatchPublicationError(
                    "split snapshot artifact is missing"
                )
            if present and not allow_existing:
                raise SplitBatchPublicationError(
                    "rowless split snapshot artifact is orphan evidence"
                )

    def _publish_snapshots(
        self,
        bundle: "SplitSnapshotBundle",
        prepared: PreparedSplitBatchEvent,
        *,
        allow_existing: bool,
    ) -> None:
        request = prepared.request
        self._validate_bundle(
            bundle,
            request,
            allow_existing=allow_existing,
            event_payload=prepared.payload,
        )
        for final_path, payload in (
            (bundle.parent_snapshot_final_path, bundle.parent_snapshot_payload_json),
            (bundle.child_snapshot_final_path, bundle.child_snapshot_payload_json),
        ):
            present = self._read_exact_snapshot_if_present(final_path, payload)
            if present and not allow_existing:
                raise SplitBatchPublicationError(
                    "rowless split snapshot artifact is orphan evidence"
                )
            if present:
                continue
            safety.publish_bytes_atomic_no_replace(
                final_path,
                payload,
                label="split snapshot payload",
                mode=0o600,
                create_parent=True,
                collision_error="split snapshot artifact already exists",
                final_identity_error="split snapshot artifact identity is invalid",
                parent_error="split snapshot artifact parent is invalid",
                error_type=SplitBatchPublicationError,
                after_fd_readback=lambda _path, _fd, _directory_fd: None,
            )
            if not self._read_exact_snapshot_if_present(final_path, payload):
                raise SplitBatchPublicationError("split snapshot readback mismatch")

    def _lineage_error(
        self,
        prepared: PreparedSplitBatchEvent,
        *,
        allow_event_id: Optional[str],
    ) -> Optional[str]:
        request = prepared.request
        row = self.connection.execute(
            "SELECT campaign_id, status, current_snapshot_id, current_snapshot_sha256, "
            "review_revision, execution_generation FROM review_batches "
            "WHERE batch_id = ?",
            (request.batch_id,),
        ).fetchone()
        if row is None:
            return "batch does not exist"
        if tuple(row) != (
            self.campaign_id,
            "OPEN",
            request.expected_snapshot_id,
            request.expected_snapshot_sha256,
            request.expected_review_revision,
            request.expected_execution_generation,
        ):
            return "batch lineage is stale"
        submissions = self.connection.execute(
            "SELECT submission_id FROM review_submissions "
            "WHERE batch_id = ? AND state = 'PREPARED' ORDER BY submission_id",
            (request.batch_id,),
        ).fetchall()
        if submissions:
            return "unresolved review submission blocks split event"
        events = self.connection.execute(
            "SELECT batch_event_id FROM batch_events "
            "WHERE batch_id = ? AND state = 'PREPARED' ORDER BY batch_event_id",
            (request.batch_id,),
        ).fetchall()
        if any(event_row[0] != allow_event_id for event_row in events):
            return "another unresolved batch event blocks split event"
        child_error = self._child_binding_error(
            request,
            require_genesis=True,
        )
        if child_error is not None:
            return child_error
        observed = self._memberships(request.batch_id)
        expected = tuple(
            {
                "item_id": row["item_id"],
                "membership_id": row["membership_id"],
                "path": row["path"],
                "status": "OPEN",
                "unit_id": row["unit_id"],
            }
            for row in json.loads(prepared.membership_release_json.decode("utf-8"))
        )
        if observed != expected:
            return "batch membership is stale or claimed"
        return None

    def _commit_locked(
        self,
        prepared: PreparedSplitBatchEvent,
        bundle: "SplitSnapshotBundle",
    ) -> None:
        request = prepared.request
        payload = prepared.payload
        selected_ids = tuple(payload["selected_unit_ids"])
        placeholders = ",".join("?" for _value in selected_ids)
        self.connection.execute("BEGIN IMMEDIATE")
        stale_error: Optional[str] = None
        try:
            row = self._stored_event_row(request.event_id)
            if row is None:
                raise SplitBatchConflict("prepared split event disappeared")
            self._require_stored_match(prepared, row)
            if row[14] == "PUBLISHED":
                self.connection.execute("COMMIT")
                return
            if row[14] != "PREPARED":
                raise SplitBatchConflict("split event is not resumable")
            error = self._lineage_error(prepared, allow_event_id=request.event_id)
            if error is not None:
                self.connection.execute(
                    "UPDATE batch_events SET state = 'BLOCKED' "
                    "WHERE batch_event_id = ? AND state = 'PREPARED'",
                    (request.event_id,),
                )
                self.connection.execute("COMMIT")
                stale_error = error
            else:
                moved = self.connection.execute(
                    "UPDATE batch_memberships SET batch_id = ? "
                    "WHERE batch_id = ? AND status = 'OPEN' AND unit_id IN (%s)"
                    % placeholders,
                    (request.child_batch_id, request.batch_id, *selected_ids),
                ).rowcount
                expected_moves = len(payload["selected_memberships"])
                parent_next_revision = request.expected_review_revision + 1
                updated_parent = self.connection.execute(
                    "UPDATE review_batches SET current_snapshot_id = ?, "
                    "current_snapshot_sha256 = ?, review_revision = ? "
                    "WHERE batch_id = ? AND status = 'OPEN' AND current_snapshot_id = ? "
                    "AND current_snapshot_sha256 = ? AND review_revision = ? "
                    "AND execution_generation = ?",
                    (
                        request.parent_next_snapshot_id,
                        request.parent_next_snapshot_sha256,
                        parent_next_revision,
                        request.batch_id,
                        request.expected_snapshot_id,
                        request.expected_snapshot_sha256,
                        request.expected_review_revision,
                        request.expected_execution_generation,
                    ),
                ).rowcount
                updated_child = self.connection.execute(
                    "UPDATE review_batches SET current_snapshot_id = ?, "
                    "current_snapshot_sha256 = ?, review_revision = 1 "
                    "WHERE batch_id = ? AND campaign_id = ? AND request_hash = ? "
                    "AND status = 'OPEN' AND current_snapshot_id IS NULL "
                    "AND current_snapshot_sha256 IS NULL AND review_revision = 0 "
                    "AND execution_generation = 0",
                    (
                        request.child_snapshot_id,
                        request.child_snapshot_sha256,
                        request.child_batch_id,
                        self.campaign_id,
                        batch_event_contract.split_child_request_hash(
                            request.batch_id,
                            request.child_batch_id,
                        ),
                    ),
                ).rowcount
                updated_event = self.connection.execute(
                    "UPDATE batch_events SET state = 'PUBLISHED' "
                    "WHERE batch_event_id = ? AND state = 'PREPARED'",
                    (request.event_id,),
                ).rowcount
                if (moved, updated_parent, updated_child, updated_event) != (
                    expected_moves,
                    1,
                    1,
                    1,
                ):
                    raise SplitBatchConflict(
                        "split final CAS did not commit exactly once"
                    )
                self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        if stale_error is not None:
            raise SplitBatchConflict("split event final CAS is stale: %s" % stale_error)

    def _run_locked(
        self,
        prepared: PreparedSplitBatchEvent,
        bundle: "SplitSnapshotBundle",
        *,
        resumed: bool,
        checkpoint: Optional[Callable[[str], None]] = None,
    ) -> "SplitBatchResult":
        stored = self._stored_event_row(prepared.request.event_id)
        published = stored is not None and stored[14] == "PUBLISHED"
        self._validate_bundle(
            bundle,
            prepared.request,
            allow_existing=stored is not None,
            require_existing=published,
            event_payload=prepared.payload,
        )
        mark = checkpoint or (lambda _point: None)
        already = self.prepare_locked(prepared)
        if already:
            row = self._stored_event_row(prepared.request.event_id)
            if row is not None and row[14] == "PUBLISHED":
                self._validate_bundle(
                    bundle,
                    prepared.request,
                    allow_existing=True,
                    require_existing=True,
                    event_payload=prepared.payload,
                )
                self._read_exact_event(prepared)
                return self._result(prepared, bundle, resumed=True)
        mark("prepared")
        try:
            self._publish_event(prepared)
        except SplitBatchPublicationError:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute(
                    "UPDATE batch_events SET state = 'BLOCKED' "
                    "WHERE batch_event_id = ? AND state = 'PREPARED'",
                    (prepared.request.event_id,),
                )
                self.connection.execute("COMMIT")
            except BaseException:
                if self.connection.in_transaction:
                    self.connection.execute("ROLLBACK")
                raise
            raise
        mark("published")
        self._publish_snapshots(
            bundle,
            prepared,
            allow_existing=already,
        )
        self._commit_locked(prepared, bundle)
        mark("committed")
        return self._result(prepared, bundle, resumed=resumed or already)

    def _result(
        self,
        prepared: PreparedSplitBatchEvent,
        bundle: "SplitSnapshotBundle",
        *,
        resumed: bool,
    ) -> "SplitBatchResult":
        payload = prepared.payload
        return SplitBatchResult(
            event_id=prepared.request.event_id,
            event_state="PUBLISHED",
            parent_batch_id=prepared.request.batch_id,
            child_batch_id=prepared.request.child_batch_id,
            parent_snapshot_id=prepared.request.parent_next_snapshot_id,
            child_snapshot_id=prepared.request.child_snapshot_id,
            transferred_memberships=len(payload["selected_memberships"]),
            final_path=prepared.final_path,
            resumed=resumed,
        )

    def _under_guards(
        self,
        prepared: PreparedSplitBatchEvent,
        bundle: "SplitSnapshotBundle",
        *,
        resumed: bool,
        checkpoint: Optional[Callable[[str], None]] = None,
    ) -> "SplitBatchResult":
        placement = self.placement_shared()
        if not hasattr(placement, "__enter__") or not hasattr(placement, "__exit__"):
            raise TypeError("placement_shared must return a context manager")
        with placement:
            ledger = self.ledger_exclusive()
            if not hasattr(ledger, "__enter__") or not hasattr(ledger, "__exit__"):
                raise TypeError("ledger_exclusive must return a context manager")
            with ledger:
                self._verify_schema()
                return self._run_locked(
                    prepared,
                    bundle,
                    resumed=resumed,
                    checkpoint=checkpoint,
                )

    def split(
        self,
        request: SplitReviewBatchRequest,
        bundle: "SplitSnapshotBundle",
        *,
        checkpoint: Optional[Callable[[str], None]] = None,
    ) -> "SplitBatchResult":
        if type(request) is not SplitReviewBatchRequest:
            raise TypeError("request must be SplitReviewBatchRequest")
        self._verify_schema()
        existing = self._stored_event_row(request.event_id)
        self._validate_bundle(
            bundle,
            request,
            allow_existing=existing is not None,
            require_existing=(
                existing is not None and existing[14] == "PUBLISHED"
            ),
        )
        if existing is None:
            prepared = self.prepare(request)
        else:
            prepared = self.load_prepared(
                request.event_id,
                policy=request.policy,
            )
            if _request_identity(prepared.request) != _request_identity(request):
                raise SplitBatchConflict("split event identity is rebound")
        return self._under_guards(
            prepared,
            bundle,
            resumed=False,
            checkpoint=checkpoint,
        )

    def load_prepared(self, event_id: str, *, policy: admission.ApprovedPolicyRef) -> PreparedSplitBatchEvent:
        _identifier(event_id, "event id")
        row = self._stored_event_row(event_id)
        if row is None:
            raise SplitBatchConflict("split event does not exist")
        if row[1] != "SPLIT":
            raise SplitBatchConflict("stored batch event kind is not SPLIT")
        expected_path = self.event_root / event_id / "event.json"
        if row[12] != str(expected_path):
            raise SplitBatchConflict("stored split event path is rebound")
        try:
            batch_event_contract.validate_batch_event(
                {
                    "batch_event_id": event_id,
                    "batch_id": row[0],
                    "event_kind": row[1],
                    "expected_batch_status": row[2],
                    "expected_snapshot_id": row[3],
                    "expected_snapshot_sha256": row[4],
                    "expected_review_revision": row[5],
                    "expected_execution_generation": row[6],
                    "terminal_batch_status": row[7],
                    "membership_release_json": row[8],
                    "membership_release_sha256": row[9],
                    "payload_json": row[10],
                    "payload_sha256": row[11],
                    "final_path": row[12],
                    "final_sha256": row[13],
                    "state": row[14],
                    "child_batch_id": row[15],
                    "child_snapshot_id": row[16],
                    "child_snapshot_sha256": row[17],
                    "source_execution_id": row[18],
                    "source_approval_id": row[19],
                    "result_path": row[20],
                    "result_sha256": row[21],
                },
                max_blob_bytes=_MAX_EVENT_BLOB_BYTES,
            )
        except batch_event_contract.BatchEventContractError as exc:
            raise SplitBatchConflict("stored split event contract is invalid") from exc
        payload_json = row[10]
        payload = json.loads(payload_json.decode("utf-8"))
        request = SplitReviewBatchRequest(
            event_id=event_id,
            batch_id=row[0],
            expected_snapshot_id=row[3],
            expected_snapshot_sha256=row[4],
            expected_review_revision=row[5],
            expected_execution_generation=row[6],
            selected_unit_ids=tuple(payload["selected_unit_ids"]),
            child_batch_id=payload["child_batch_id"],
            child_snapshot_id=payload["child_snapshot_id"],
            child_snapshot_sha256=payload["child_snapshot_sha256"],
            child_submission_id=payload["child_submission_id"],
            parent_next_snapshot_id=payload["parent_next_snapshot_id"],
            parent_next_snapshot_sha256=payload["parent_next_snapshot_sha256"],
            parent_submission_id=payload["parent_submission_id"],
            policy=policy,
            actor=payload["actor"],
            units=(),
        )
        return PreparedSplitBatchEvent(
            request=request,
            membership_release_json=row[8],
            membership_release_sha256=row[9],
            payload_json=payload_json,
            payload_sha256=row[11],
            final_path=expected_path,
        )

    def resume(
        self,
        event_id: str,
        bundle: "SplitSnapshotBundle",
        *,
        resumed_by: str,
        policy: admission.ApprovedPolicyRef,
        checkpoint: Optional[Callable[[str], None]] = None,
    ) -> "SplitBatchResult":
        _actor(resumed_by, "resumed_by")
        prepared = self.load_prepared(event_id, policy=policy)
        existing = self._stored_event_row(event_id)
        self._validate_bundle(
            bundle,
            prepared.request,
            allow_existing=True,
            require_existing=(
                existing is not None and existing[14] == "PUBLISHED"
            ),
            event_payload=prepared.payload,
        )
        return self._under_guards(
            prepared,
            bundle,
            resumed=True,
            checkpoint=checkpoint,
        )


@dataclass(frozen=True)
class SplitSnapshotBundle:
    parent_snapshot_final_path: Path
    parent_snapshot_payload_json: bytes
    child_snapshot_final_path: Path
    child_snapshot_payload_json: bytes


@dataclass(frozen=True)
class SplitBatchResult:
    event_id: str
    event_state: str
    parent_batch_id: str
    child_batch_id: str
    parent_snapshot_id: str
    child_snapshot_id: str
    transferred_memberships: int
    final_path: Path
    resumed: bool


__all__ = [
    "PreparedSplitBatchEvent",
    "SplitBatchConflict",
    "SplitBatchError",
    "SplitBatchPublicationError",
    "SplitBatchResult",
    "SplitBatchService",
    "SplitBatchValidationError",
    "SplitReviewBatchRequest",
    "SplitSelection",
    "SplitSnapshotBundle",
    "validate_split_selection",
]
