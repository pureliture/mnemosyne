"""Partial-publish-safe nonstructural batch close and abandon events."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from . import batch_event_contract, m3_schema, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_KINDS = {"close": ("CLOSE_REVIEW", "CLOSED_REVIEW"), "abandon": ("ABANDON", "ABANDONED")}
_CLOSE_TERMINAL_STATES = frozenset(("KEEP", "LINKED", "DEFERRED", "EXCLUDED"))
_MAX_EVENT_BLOB_BYTES = 64 * 1024 * 1024


class BatchEventError(RuntimeError):
    """Base error for a batch terminal event."""


class BatchEventConflict(BatchEventError):
    """The batch lineage, membership, or projection is not exact."""


class BatchEventPublicationError(BatchEventError):
    """The sealed event artifact could not be published or read back."""


@dataclass(frozen=True)
class BatchTerminalRequest:
    event_id: str
    batch_id: str
    event_kind: str
    expected_snapshot_id: str
    expected_snapshot_sha256: str
    expected_review_revision: int
    expected_execution_generation: int
    actor: str

    def __post_init__(self) -> None:
        _identifier(self.event_id, "batch event id")
        _identifier(self.batch_id, "batch id")
        if self.event_kind not in _KINDS:
            raise BatchEventConflict("batch event kind is invalid")
        _identifier(self.expected_snapshot_id, "expected snapshot id")
        _hash(self.expected_snapshot_sha256, "expected snapshot hash")
        if (
            type(self.expected_review_revision) is not int
            or self.expected_review_revision < 1
        ):
            raise BatchEventConflict("expected review revision is invalid")
        if (
            type(self.expected_execution_generation) is not int
            or self.expected_execution_generation < 0
        ):
            raise BatchEventConflict("expected execution generation is invalid")
        _actor(self.actor, "actor")


@dataclass(frozen=True)
class PreparedBatchEvent:
    request: BatchTerminalRequest
    membership_release_json: bytes
    membership_release_sha256: str
    payload_json: bytes
    payload_sha256: str
    final_path: Path


@dataclass(frozen=True)
class BatchEventResult:
    event_id: str
    event_state: str
    event_sha256: str
    batch_id: str
    batch_status: str
    released_memberships: int
    final_path: Path
    resumed: bool


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise BatchEventConflict("%s is invalid" % label)
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise BatchEventConflict("%s is invalid" % label)
    return value


def _actor(value: Any, label: str) -> str:
    try:
        return batch_event_contract.validate_actor(value)
    except batch_event_contract.BatchEventContractError as exc:
        raise BatchEventConflict("%s is invalid" % label) from exc


def _canonical_root(path: Path) -> Path:
    value = Path(path)
    if (
        not value.is_absolute()
        or any(part in (".", "..") for part in value.parts)
        or value.name != "batch-events"
        or value.parent.parent.name != "campaigns"
        or _ID.fullmatch(value.parent.name) is None
    ):
        raise BatchEventConflict(
            "batch event root must be a canonical campaign namespace"
        )
    return value


def _tuple_row(value: Any) -> Optional[tuple]:
    return None if value is None else tuple(value)


def _canonical_object(encoded: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BatchEventConflict("%s is invalid" % label) from exc
    if type(value) is not dict or canonical_json_bytes(value) != encoded:
        raise BatchEventConflict("%s is not canonical JSON" % label)
    return value


class BatchEventService:
    """Publish one exact close/abandon event and finalize it by batch CAS."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        event_root: Path,
        *,
        placement_shared: Callable[[], object],
        ledger_exclusive: Callable[[], object],
        checkpoint: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if connection.in_transaction:
            raise BatchEventConflict("batch event service requires transaction ownership")
        if not callable(placement_shared) or not callable(ledger_exclusive):
            raise TypeError("placement_shared and ledger_exclusive are required")
        if checkpoint is not None and not callable(checkpoint):
            raise TypeError("checkpoint must be callable")
        self.connection = connection
        self.event_root = _canonical_root(event_root)
        self.campaign_id = self.event_root.parent.name
        self.placement_shared = placement_shared
        self.ledger_exclusive = ledger_exclusive
        self.checkpoint = checkpoint or (lambda _point: None)

    def _verify_schema(self) -> None:
        try:
            m3_schema.verify_v3_schema(self.connection)
        except (m3_schema.M3SchemaError, sqlite3.Error) as exc:
            raise BatchEventConflict("exact curation ledger v3 is required") from exc

    def _memberships(self, batch_id: str) -> Tuple[Dict[str, str], ...]:
        rows = self.connection.execute(
            "SELECT membership_id, unit_id, item_id, path, status "
            "FROM batch_memberships WHERE batch_id = ? ORDER BY membership_id",
            (batch_id,),
        ).fetchall()
        if not rows:
            raise BatchEventConflict("batch membership is empty")
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

    def prepare(self, request: BatchTerminalRequest) -> PreparedBatchEvent:
        if type(request) is not BatchTerminalRequest:
            raise TypeError("request must be BatchTerminalRequest")
        self._verify_schema()
        memberships = self._memberships(request.batch_id)
        release = [
            {
                "item_id": row["item_id"],
                "membership_id": row["membership_id"],
                "path": row["path"],
                "unit_id": row["unit_id"],
            }
            for row in memberships
        ]
        release_json = canonical_json_bytes(release)
        event_kind, terminal_status = _KINDS[request.event_kind]
        final_path = self.event_root / request.event_id / "event.json"
        payload = {
            "actor": request.actor,
            "batch_id": request.batch_id,
            "event_id": request.event_id,
            "event_kind": event_kind,
            "expected_execution_generation": request.expected_execution_generation,
            "expected_review_revision": request.expected_review_revision,
            "expected_snapshot_id": request.expected_snapshot_id,
            "expected_snapshot_sha256": request.expected_snapshot_sha256,
            "membership_release": release,
            "membership_release_sha256": sha256_bytes(release_json),
            "schema_version": 1,
            "terminal_batch_status": terminal_status,
        }
        encoded = canonical_json_bytes(payload)
        prepared = PreparedBatchEvent(
            request=request,
            membership_release_json=release_json,
            membership_release_sha256=sha256_bytes(release_json),
            payload_json=encoded,
            payload_sha256=sha256_bytes(encoded),
            final_path=final_path,
        )
        event_kind, terminal_status = _KINDS[request.event_kind]
        try:
            batch_event_contract.validate_batch_event(
                {
                    "batch_event_id": request.event_id,
                    "batch_id": request.batch_id,
                    "event_kind": event_kind,
                    "expected_batch_status": "OPEN",
                    "expected_snapshot_id": request.expected_snapshot_id,
                    "expected_snapshot_sha256": request.expected_snapshot_sha256,
                    "expected_review_revision": request.expected_review_revision,
                    "expected_execution_generation": (
                        request.expected_execution_generation
                    ),
                    "terminal_batch_status": terminal_status,
                    "membership_release_json": prepared.membership_release_json,
                    "membership_release_sha256": (
                        prepared.membership_release_sha256
                    ),
                    "payload_json": prepared.payload_json,
                    "payload_sha256": prepared.payload_sha256,
                    "final_path": str(prepared.final_path),
                    "final_sha256": prepared.payload_sha256,
                    "state": "PREPARED",
                    "child_batch_id": None,
                    "child_snapshot_id": None,
                    "child_snapshot_sha256": None,
                    "source_execution_id": None,
                    "source_approval_id": None,
                    "result_path": None,
                    "result_sha256": None,
                },
                max_blob_bytes=_MAX_EVENT_BLOB_BYTES,
            )
        except batch_event_contract.BatchEventContractError as exc:
            raise BatchEventConflict(
                "prepared batch event contract is invalid"
            ) from exc
        return prepared

    def _batch_row(self, request: BatchTerminalRequest) -> Optional[tuple]:
        return _tuple_row(
            self.connection.execute(
                "SELECT campaign_id, status, current_snapshot_id, current_snapshot_sha256, "
                "review_revision, execution_generation FROM review_batches "
                "WHERE batch_id = ?",
                (request.batch_id,),
            ).fetchone()
        )

    def _lineage_error(
        self,
        prepared: PreparedBatchEvent,
        *,
        allow_event_id: Optional[str],
    ) -> Optional[str]:
        request = prepared.request
        batch = self._batch_row(request)
        if batch is None:
            return "batch does not exist"
        if batch != (
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
            return "unresolved review submission blocks batch event"
        events = self.connection.execute(
            "SELECT batch_event_id FROM batch_events "
            "WHERE batch_id = ? AND state = 'PREPARED' ORDER BY batch_event_id",
            (request.batch_id,),
        ).fetchall()
        if any(row[0] != allow_event_id for row in events):
            return "another unresolved batch event blocks batch event"
        observed_memberships = self._memberships(request.batch_id)
        expected_memberships = tuple(
            {
                "item_id": row["item_id"],
                "membership_id": row["membership_id"],
                "path": row["path"],
                "status": "OPEN",
                "unit_id": row["unit_id"],
            }
            for row in json.loads(prepared.membership_release_json.decode("utf-8"))
        )
        if observed_memberships != expected_memberships:
            return "batch membership is stale or claimed"
        if request.event_kind == "close":
            item_ids = tuple(row["item_id"] for row in observed_memberships)
            placeholders = ",".join("?" for _value in item_ids)
            rows = self.connection.execute(
                "SELECT p.item_id, p.primary_state, p.source_freshness, "
                "d.batch_id FROM item_curation_projection AS p "
                "JOIN decision_events AS d "
                "ON d.decision_event_id = p.current_decision_id "
                "WHERE p.item_id IN (%s) ORDER BY p.item_id" % placeholders,
                item_ids,
            ).fetchall()
            if len(rows) != len(item_ids) or any(
                row[1] not in _CLOSE_TERMINAL_STATES for row in rows
            ):
                return "every batch membership item must have a terminal decision"
            if any(row[2] != "FRESH" for row in rows):
                return "every terminal decision must use fresh source evidence"
            if any(row[3] != request.batch_id for row in rows):
                return "terminal decision belongs to another batch lineage"
        return None

    def _stored_event(self, event_id: str) -> Optional[tuple]:
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
            "final_path, final_sha256, state, "
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
        release_size = values[16]
        payload_size = values[18]
        if (
            values[15] != "blob"
            or type(release_size) is not int
            or not 0 <= release_size <= _MAX_EVENT_BLOB_BYTES
            or values[17] != "blob"
            or type(payload_size) is not int
            or not 0 <= payload_size <= _MAX_EVENT_BLOB_BYTES
        ):
            raise BatchEventConflict(
                "stored batch event contract is invalid: bounded blob preflight"
            )
        return values[:15]

    def _require_published_poststate(
        self,
        prepared: PreparedBatchEvent,
    ) -> None:
        request = prepared.request
        terminal_status = _KINDS[request.event_kind][1]
        if self._batch_row(request) != (
            self.campaign_id,
            terminal_status,
            request.expected_snapshot_id,
            request.expected_snapshot_sha256,
            request.expected_review_revision,
            request.expected_execution_generation,
        ):
            raise BatchEventConflict(
                "published batch terminal state is stale: batch lineage"
            )
        expected_memberships = tuple(
            {
                "item_id": row["item_id"],
                "membership_id": row["membership_id"],
                "path": row["path"],
                "status": "RELEASED",
                "unit_id": row["unit_id"],
            }
            for row in json.loads(
                prepared.membership_release_json.decode("utf-8")
            )
        )
        if self._memberships(request.batch_id) != expected_memberships:
            raise BatchEventConflict(
                "published batch terminal state is stale: membership release"
            )
        if self.connection.execute(
            "SELECT 1 FROM review_submissions "
            "WHERE batch_id = ? AND state = 'PREPARED' LIMIT 1",
            (request.batch_id,),
        ).fetchone() is not None:
            raise BatchEventConflict(
                "published batch terminal state is stale: unresolved submission"
            )

    def _require_stored_match(
        self,
        prepared: PreparedBatchEvent,
        row: tuple,
    ) -> None:
        request = prepared.request
        event_kind, terminal_status = _KINDS[request.event_kind]
        try:
            batch_event_contract.validate_batch_event(
                {
                    "batch_event_id": request.event_id,
                    "batch_id": row[0],
                    "event_kind": row[1],
                    "expected_batch_status": row[2],
                    "expected_snapshot_id": row[3],
                    "expected_snapshot_sha256": row[4],
                    "expected_review_revision": row[5],
                    "expected_execution_generation": row[6],
                    "terminal_batch_status": row[7],
                    "child_batch_id": None,
                    "child_snapshot_id": None,
                    "child_snapshot_sha256": None,
                    "source_execution_id": None,
                    "source_approval_id": None,
                    "result_path": None,
                    "result_sha256": None,
                    "membership_release_json": row[8],
                    "membership_release_sha256": row[9],
                    "payload_json": row[10],
                    "payload_sha256": row[11],
                    "final_path": row[12],
                    "final_sha256": row[13],
                    "state": row[14],
                },
                max_blob_bytes=_MAX_EVENT_BLOB_BYTES,
            )
        except batch_event_contract.BatchEventContractError as exc:
            raise BatchEventConflict(
                "stored batch event contract is invalid"
            ) from exc
        expected = (
            request.batch_id,
            event_kind,
            "OPEN",
            request.expected_snapshot_id,
            request.expected_snapshot_sha256,
            request.expected_review_revision,
            request.expected_execution_generation,
            terminal_status,
            prepared.membership_release_json,
            prepared.membership_release_sha256,
            prepared.payload_json,
            prepared.payload_sha256,
            str(prepared.final_path),
            prepared.payload_sha256,
        )
        observed = tuple(
            bytes(value) if index in (8, 10) else value
            for index, value in enumerate(row[:14])
        )
        if observed != expected:
            raise BatchEventConflict("batch event identity is rebound")

    def _prepare_locked(self, prepared: PreparedBatchEvent) -> bool:
        request = prepared.request
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._stored_event(request.event_id)
            if existing is not None:
                self._require_stored_match(prepared, existing)
                if existing[14] == "PUBLISHED":
                    self._require_published_poststate(prepared)
                    self.connection.execute("COMMIT")
                    return True
                if existing[14] != "PREPARED":
                    raise BatchEventConflict("batch event is not resumable")
                error = self._lineage_error(
                    prepared, allow_event_id=request.event_id
                )
                if error is not None:
                    raise BatchEventConflict(error)
                self.connection.execute("COMMIT")
                return True
            if os.path.lexists(prepared.final_path):
                raise BatchEventPublicationError(
                    "rowless batch event artifact is orphan evidence"
                )
            error = self._lineage_error(prepared, allow_event_id=None)
            if error is not None:
                raise BatchEventConflict(error)
            event_kind, terminal_status = _KINDS[request.event_kind]
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
                ") VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, NULL, NULL, NULL, "
                "NULL, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                (
                    request.event_id,
                    request.batch_id,
                    event_kind,
                    request.expected_snapshot_id,
                    request.expected_snapshot_sha256,
                    request.expected_review_revision,
                    request.expected_execution_generation,
                    terminal_status,
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

    def _read_exact(self, prepared: PreparedBatchEvent) -> None:
        try:
            directory_fd = safety.open_verified_directory(
                prepared.final_path.parent,
                require_owner_only=True,
                error_type=BatchEventPublicationError,
            )
            try:
                info, raw = safety.read_regular_file_at(
                    directory_fd,
                    prepared.final_path.name,
                    prepared.final_path,
                    label="batch event artifact",
                    expected_mode=0o600,
                    max_bytes=len(prepared.payload_json),
                    error_type=BatchEventPublicationError,
                )
                if info.st_nlink != 1 or raw != prepared.payload_json:
                    raise BatchEventPublicationError(
                        "batch event artifact readback mismatch"
                    )
                safety.require_same_directory_identity(
                    prepared.final_path.parent,
                    directory_fd,
                    "batch event artifact",
                    error_type=BatchEventPublicationError,
                )
            finally:
                os.close(directory_fd)
        except BatchEventPublicationError:
            raise
        except OSError as exc:
            raise BatchEventPublicationError(
                "batch event artifact is unreadable"
            ) from exc

    def _publish(self, prepared: PreparedBatchEvent) -> None:
        if os.path.lexists(prepared.final_path):
            self._read_exact(prepared)
            return
        safety.publish_bytes_atomic_no_replace(
            prepared.final_path,
            prepared.payload_json,
            label="batch event artifact",
            mode=0o600,
            create_parent=True,
            collision_error="batch event artifact already exists",
            final_identity_error="batch event artifact identity is invalid",
            parent_error="batch event artifact parent is invalid",
            error_type=BatchEventPublicationError,
            after_fd_readback=lambda _path, _fd, _directory_fd: None,
        )
        self._read_exact(prepared)

    def _block(self, event_id: str) -> None:
        if self.connection.in_transaction:
            self.connection.execute("ROLLBACK")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                "UPDATE batch_events SET state = 'BLOCKED' "
                "WHERE batch_event_id = ? AND state = 'PREPARED'",
                (event_id,),
            )
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _commit(self, prepared: PreparedBatchEvent) -> None:
        request = prepared.request
        terminal_status = _KINDS[request.event_kind][1]
        self.connection.execute("BEGIN IMMEDIATE")
        stale_error: Optional[str] = None
        try:
            row = self._stored_event(request.event_id)
            if row is None:
                raise BatchEventConflict("prepared batch event disappeared")
            self._require_stored_match(prepared, row)
            if row[14] == "PUBLISHED":
                self._require_published_poststate(prepared)
                self.connection.execute("COMMIT")
                return
            if row[14] != "PREPARED":
                raise BatchEventConflict("batch event is not resumable")
            error = self._lineage_error(
                prepared, allow_event_id=request.event_id
            )
            if error is not None:
                self.connection.execute(
                    "UPDATE batch_events SET state = 'BLOCKED' "
                    "WHERE batch_event_id = ? AND state = 'PREPARED'",
                    (request.event_id,),
                )
                self.connection.execute("COMMIT")
                stale_error = error
            else:
                released = self.connection.execute(
                    "UPDATE batch_memberships SET status = 'RELEASED' "
                    "WHERE batch_id = ? AND status = 'OPEN'",
                    (request.batch_id,),
                ).rowcount
                expected_count = len(
                    json.loads(prepared.membership_release_json.decode("utf-8"))
                )
                updated_batch = self.connection.execute(
                    "UPDATE review_batches SET status = ? WHERE batch_id = ? "
                    "AND status = 'OPEN' AND current_snapshot_id = ? "
                    "AND current_snapshot_sha256 = ? AND review_revision = ? "
                    "AND execution_generation = ?",
                    (
                        terminal_status,
                        request.batch_id,
                        request.expected_snapshot_id,
                        request.expected_snapshot_sha256,
                        request.expected_review_revision,
                        request.expected_execution_generation,
                    ),
                ).rowcount
                updated_event = self.connection.execute(
                    "UPDATE batch_events SET state = 'PUBLISHED' "
                    "WHERE batch_event_id = ? AND state = 'PREPARED'",
                    (request.event_id,),
                ).rowcount
                if (released, updated_batch, updated_event) != (
                    expected_count,
                    1,
                    1,
                ):
                    raise BatchEventConflict(
                        "batch terminal CAS did not commit exactly once"
                    )
                self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        if stale_error is not None:
            raise BatchEventConflict("batch event final CAS is stale: %s" % stale_error)

    def _result(
        self,
        prepared: PreparedBatchEvent,
        *,
        resumed: bool,
    ) -> BatchEventResult:
        terminal_status = _KINDS[prepared.request.event_kind][1]
        return BatchEventResult(
            event_id=prepared.request.event_id,
            event_state="PUBLISHED",
            event_sha256=prepared.payload_sha256,
            batch_id=prepared.request.batch_id,
            batch_status=terminal_status,
            released_memberships=len(
                json.loads(prepared.membership_release_json.decode("utf-8"))
            ),
            final_path=prepared.final_path,
            resumed=resumed,
        )

    def _run_locked(
        self,
        prepared: PreparedBatchEvent,
        *,
        resumed: bool,
    ) -> BatchEventResult:
        already = self._prepare_locked(prepared)
        if already:
            row = self._stored_event(prepared.request.event_id)
            if row is not None and row[14] == "PUBLISHED":
                self._read_exact(prepared)
                return self._result(prepared, resumed=True)
        self.checkpoint("prepared")
        try:
            self._publish(prepared)
        except BatchEventPublicationError:
            self._block(prepared.request.event_id)
            raise
        self.checkpoint("published")
        self._commit(prepared)
        self.checkpoint("committed")
        return self._result(prepared, resumed=resumed or already)

    def _under_guards(
        self,
        prepared: PreparedBatchEvent,
        *,
        resumed: bool,
    ) -> BatchEventResult:
        placement = self.placement_shared()
        if not hasattr(placement, "__enter__") or not hasattr(placement, "__exit__"):
            raise TypeError("placement_shared must return a context manager")
        with placement:
            ledger = self.ledger_exclusive()
            if not hasattr(ledger, "__enter__") or not hasattr(ledger, "__exit__"):
                raise TypeError("ledger_exclusive must return a context manager")
            with ledger:
                self._verify_schema()
                return self._run_locked(prepared, resumed=resumed)

    def close(self, request: BatchTerminalRequest) -> BatchEventResult:
        if request.event_kind != "close":
            raise BatchEventConflict("close requires event_kind close")
        return self._under_guards(self.prepare(request), resumed=False)

    def abandon(self, request: BatchTerminalRequest) -> BatchEventResult:
        if request.event_kind != "abandon":
            raise BatchEventConflict("abandon requires event_kind abandon")
        return self._under_guards(self.prepare(request), resumed=False)

    def _load_prepared(self, event_id: str) -> PreparedBatchEvent:
        identity = _identifier(event_id, "batch event id")
        row = self._stored_event(identity)
        if row is None:
            raise BatchEventConflict("batch event does not exist")
        expected_path = self.event_root / identity / "event.json"
        if row[12] != str(expected_path):
            raise BatchEventConflict("stored batch event path is rebound")
        if type(row[10]) is not bytes:
            raise BatchEventConflict("stored batch event payload type is invalid")
        payload_json = row[10]
        payload = _canonical_object(payload_json, "stored batch event payload")
        kind = {"CLOSE_REVIEW": "close", "ABANDON": "abandon"}.get(row[1])
        if kind is None:
            raise BatchEventConflict("stored batch event kind is not resumable")
        request = BatchTerminalRequest(
            event_id=identity,
            batch_id=row[0],
            event_kind=kind,
            expected_snapshot_id=row[3],
            expected_snapshot_sha256=row[4],
            expected_review_revision=row[5],
            expected_execution_generation=row[6],
            actor=payload.get("actor"),
        )
        prepared = PreparedBatchEvent(
            request=request,
            membership_release_json=row[8],
            membership_release_sha256=row[9],
            payload_json=payload_json,
            payload_sha256=row[11],
            final_path=expected_path,
        )
        self._require_stored_match(prepared, row)
        return prepared

    def resume(
        self,
        event_id: str,
        *,
        resumed_by: str,
    ) -> BatchEventResult:
        _actor(resumed_by, "resumed_by")
        self._verify_schema()
        prepared = self._load_prepared(event_id)
        return self._under_guards(prepared, resumed=True)


__all__ = [
    "BatchEventConflict",
    "BatchEventError",
    "BatchEventPublicationError",
    "BatchEventResult",
    "BatchEventService",
    "BatchTerminalRequest",
    "PreparedBatchEvent",
]
