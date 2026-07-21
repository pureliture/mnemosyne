"""Exact v3 persistence for safe deferral evidence and trigger intents.

The pure compilers in :mod:`deferral_service` remain the only authority for
evidence payloads and trigger evaluation.  This module adds the two-phase
SQLite/artifact bridge and the single-transaction trigger projection update.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Optional, Tuple

from . import deferral_service, m3_schema, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TRIGGER_NAMES = {
    "DATE": "date",
    "WORKSTREAM_RESUME": "workstream-resume",
    "EVIDENCE": "evidence",
    "MANUAL_REOPEN": "manual-reopen",
}


class DeferralStoreError(Exception):
    """The exact v3 deferral persistence contract cannot be completed."""


@dataclass(frozen=True)
class EvidencePublication:
    event_id: str
    deferral_id: str
    deferral_version: int
    idempotency_key: str
    payload_bytes: bytes
    final_path: Path
    final_sha256: str
    state: str
    resumed: bool


@dataclass(frozen=True)
class DeferralEvaluationResult:
    trigger_event_id: str
    deferral_id: str
    deferral_version: int
    trigger_kind: str
    trigger_evidence_sha256: str
    payload_bytes: bytes
    projection_generation: int
    source_evidence_event_id: Optional[str]
    repeated: bool


def _schema(connection: sqlite3.Connection) -> None:
    try:
        m3_schema.verify_v3_schema(connection)
    except (m3_schema.M3SchemaError, sqlite3.Error) as exc:
        raise DeferralStoreError("exact version-3 schema is required") from exc


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise DeferralStoreError("%s is invalid" % label)
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise DeferralStoreError("%s is invalid" % label)
    return value


def _text(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 16 * 1024
        or any(ord(character) < 0x20 for character in value)
    ):
        raise DeferralStoreError("%s is invalid" % label)
    return value


def _control_root(value: Path) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise DeferralStoreError("control root must be an absolute Path")
    try:
        root = value.resolve(strict=True)
    except OSError as exc:
        raise DeferralStoreError("control root is unavailable") from exc
    if root != value:
        raise DeferralStoreError("control root must be canonical")
    directory_fd = safety.open_verified_directory(
        root,
        require_owner_only=True,
        error_type=DeferralStoreError,
    )
    os.close(directory_fd)
    return root


def _relative_path(value: Any, label: str) -> PurePosixPath:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 0x20 for character in value)
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise DeferralStoreError("%s is not a canonical relative path" % label)
    path = PurePosixPath(value)
    if str(path) != value:
        raise DeferralStoreError("%s is not a canonical relative path" % label)
    return path


def _campaign_binding(
    connection: sqlite3.Connection,
    deferral_id: str,
) -> Optional[Tuple[Any, ...]]:
    return connection.execute(
        "SELECT d.item_id, d.version, d.state, d.trigger_kind, "
        "d.revisit_date, d.timezone, d.trigger_workstream_id, "
        "d.captured_lifecycle, d.captured_policy_sha256, "
        "e.campaign_id, c.campaign_path "
        "FROM deferrals d "
        "JOIN decision_events e ON e.decision_event_id = d.source_decision_event_id "
        "JOIN campaigns c ON c.campaign_id = e.campaign_id "
        "WHERE d.deferral_id = ?",
        (deferral_id,),
    ).fetchone()


def _expected_evidence_path(
    binding: Tuple[Any, ...],
    event_id: str,
) -> PurePosixPath:
    campaign_id = _identifier(binding[9], "campaign id")
    campaign_path = _relative_path(binding[10], "campaign path")
    if campaign_path.name != "campaign.json" or campaign_path.parent.name != campaign_id:
        raise DeferralStoreError("campaign path does not bind campaign identity")
    return (
        campaign_path.parent
        / "deferral-evidence"
        / _identifier(event_id, "evidence event id")
        / "evidence.json"
    )


def _stored_payload(raw: Any, expected_hash: str) -> Dict[str, Any]:
    if not isinstance(raw, bytes) or sha256_bytes(raw) != _hash(
        expected_hash, "payload hash"
    ):
        raise DeferralStoreError("stored evidence payload hash is invalid")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeferralStoreError("stored evidence payload is invalid") from exc
    if type(payload) is not dict or canonical_json_bytes(payload) != raw:
        raise DeferralStoreError("stored evidence payload is not canonical")
    return payload


def _compile_payload(
    request: deferral_service.EvidenceAttachmentInput,
) -> Tuple[deferral_service.CompiledEvidenceAttachment, bytes]:
    try:
        compiled = deferral_service.DeferralEvidenceCompiler().compile(request)
    except (TypeError, deferral_service.DeferralValidationError) as exc:
        raise DeferralStoreError("deferral evidence request is invalid") from exc
    encoded = canonical_json_bytes(compiled.payload)
    return compiled, encoded


def _validate_stored_evidence(row: Tuple[Any, ...]) -> Dict[str, Any]:
    payload = _stored_payload(row[9], row[10])
    metadata = payload.get("allowed_metadata")
    if type(metadata) is not dict:
        raise DeferralStoreError("stored evidence metadata is invalid")
    request = deferral_service.EvidenceAttachmentInput(
        event_id=payload.get("event_id"),
        deferral_id=payload.get("deferral_id"),
        deferral_version=payload.get("deferral_version"),
        actor=payload.get("actor"),
        scope_class=payload.get("scope_class"),
        allowed_metadata=tuple(sorted(metadata.items())),
        source_ref=payload.get("source_ref"),
        content_sha256=payload.get("content_sha256"),
        opaque_source_id=payload.get("opaque_source_id"),
        actor_attestation=payload.get("actor_attestation"),
    )
    compiled, encoded = _compile_payload(request)
    if (
        encoded != row[9]
        or compiled.idempotency_key != row[8]
        or payload.get("event_id") != row[0]
        or payload.get("deferral_id") != row[1]
        or payload.get("deferral_version") != row[2]
        or payload.get("actor") != row[3]
        or payload.get("source_ref") != row[4]
        or payload.get("content_sha256") != row[5]
        or payload.get("opaque_source_id") != row[6]
        or payload.get("actor_attestation") != row[7]
        or row[12] != sha256_bytes(encoded)
    ):
        raise DeferralStoreError("stored evidence row does not bind its payload")
    return payload


_EVIDENCE_SELECT = (
    "SELECT evidence_event_id, deferral_id, deferral_version, actor, "
    "source_reference, supplied_content_sha256, opaque_source_id, "
    "actor_attestation, idempotency_key, payload_json, payload_sha256, "
    "final_path, final_sha256, state FROM deferral_evidence_events "
)


def _evidence_row(
    connection: sqlite3.Connection,
    event_id: str,
) -> Optional[Tuple[Any, ...]]:
    return connection.execute(
        _EVIDENCE_SELECT + "WHERE evidence_event_id = ?",
        (event_id,),
    ).fetchone()


def _read_exact_artifact(path: Path, expected: bytes) -> None:
    try:
        directory_fd = safety.open_verified_directory(
            path.parent,
            require_owner_only=True,
            error_type=DeferralStoreError,
        )
    except DeferralStoreError:
        raise
    try:
        info, observed = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label="deferral evidence artifact",
            expected_mode=0o600,
            error_type=DeferralStoreError,
        )
        if info.st_nlink != 1 or observed != expected:
            raise DeferralStoreError("deferral evidence artifact readback mismatch")
    finally:
        os.close(directory_fd)


def _artifact_present(path: Path) -> bool:
    try:
        os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise DeferralStoreError("deferral evidence artifact is unreadable") from exc
    return True


def _publish_or_readback(path: Path, encoded: bytes) -> None:
    if _artifact_present(path):
        _read_exact_artifact(path, encoded)
        return

    def after_readback(
        final_path: Path,
        _opened_fd: int,
        directory_fd: int,
    ) -> None:
        info, observed = safety.read_regular_file_at(
            directory_fd,
            final_path.name,
            final_path,
            label="deferral evidence artifact",
            expected_mode=0o600,
            error_type=DeferralStoreError,
        )
        if info.st_nlink != 1 or observed != encoded:
            raise DeferralStoreError("deferral evidence artifact readback mismatch")

    safety.publish_bytes_atomic_no_replace(
        path,
        encoded,
        label="deferral evidence artifact",
        mode=0o600,
        create_parent=True,
        collision_error="deferral evidence artifact already exists",
        final_identity_error="deferral evidence artifact identity changed",
        parent_error="deferral evidence artifact parent is unsafe",
        error_type=DeferralStoreError,
        after_fd_readback=after_readback,
    )
    _read_exact_artifact(path, encoded)


def _block_evidence(
    connection: sqlite3.Connection,
    event_id: str,
    states: Tuple[str, ...],
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        placeholders = ",".join("?" for _ in states)
        connection.execute(
            "UPDATE deferral_evidence_events SET state = 'BLOCKED' "
            "WHERE evidence_event_id = ? AND state IN (%s)" % placeholders,
            (event_id,) + states,
        )
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _publication(
    root: Path,
    row: Tuple[Any, ...],
    *,
    resumed: bool,
) -> EvidencePublication:
    relative = _relative_path(row[11], "evidence final path")
    encoded = row[9]
    return EvidencePublication(
        event_id=row[0],
        deferral_id=row[1],
        deferral_version=row[2],
        idempotency_key=row[8],
        payload_bytes=encoded,
        final_path=root.joinpath(*relative.parts),
        final_sha256=row[12],
        state=row[13],
        resumed=resumed,
    )


def _finish_evidence_publication(
    root: Path,
    connection: sqlite3.Connection,
    event_id: str,
    *,
    resumed: bool,
    checkpoint: Optional[Callable[[str], None]],
) -> EvidencePublication:
    _schema(connection)
    row = _evidence_row(connection, event_id)
    if row is None:
        raise DeferralStoreError("prepared deferral evidence row is missing")
    _validate_stored_evidence(row)
    relative = _relative_path(row[11], "evidence final path")
    path = root.joinpath(*relative.parts)
    binding = _campaign_binding(connection, row[1])
    if binding is None or _expected_evidence_path(binding, row[0]) != relative:
        if row[13] in ("PREPARED", "PUBLISHED"):
            _block_evidence(connection, row[0], (row[13],))
        raise DeferralStoreError("evidence final path binding is stale")
    if row[13] in ("PUBLISHED", "CONSUMED"):
        try:
            _read_exact_artifact(path, row[9])
        except DeferralStoreError:
            if row[13] == "PUBLISHED":
                _block_evidence(connection, row[0], ("PUBLISHED",))
            raise
        return _publication(root, row, resumed=resumed)
    if row[13] != "PREPARED":
        raise DeferralStoreError("deferral evidence event is not resumable")
    try:
        _publish_or_readback(path, row[9])
    except DeferralStoreError:
        _block_evidence(connection, row[0], ("PREPARED",))
        raise
    if checkpoint is not None:
        checkpoint("artifact-published")
    try:
        _read_exact_artifact(path, row[9])
    except DeferralStoreError:
        _block_evidence(connection, row[0], ("PREPARED",))
        raise

    connection.execute("BEGIN IMMEDIATE")
    stale = False
    try:
        _schema(connection)
        current = _evidence_row(connection, event_id)
        if current is None:
            raise DeferralStoreError("prepared deferral evidence row is missing")
        if current != row:
            raise DeferralStoreError("prepared deferral evidence row changed")
        binding = _campaign_binding(connection, row[1])
        if (
            binding is None
            or binding[1] != row[2]
            or binding[2] != "CURRENT"
            or binding[3] != "EVIDENCE"
            or _expected_evidence_path(binding, row[0]) != relative
        ):
            connection.execute(
                "UPDATE deferral_evidence_events SET state = 'BLOCKED' "
                "WHERE evidence_event_id = ? AND state = 'PREPARED'",
                (event_id,),
            )
            connection.execute("COMMIT")
            stale = True
        else:
            _read_exact_artifact(path, row[9])
            changed = connection.execute(
                "UPDATE deferral_evidence_events SET state = 'PUBLISHED' "
                "WHERE evidence_event_id = ? AND state = 'PREPARED'",
                (event_id,),
            ).rowcount
            if changed != 1:
                raise DeferralStoreError("deferral evidence publish CAS failed")
            connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    if stale:
        raise DeferralStoreError("deferral evidence identity is stale")
    if checkpoint is not None:
        checkpoint("published")
    published = _evidence_row(connection, event_id)
    if published is None:
        raise DeferralStoreError("published deferral evidence row is missing")
    return _publication(root, published, resumed=resumed)


def attach_deferral_evidence(
    control_root: Path,
    connection: sqlite3.Connection,
    request: deferral_service.EvidenceAttachmentInput,
    *,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> EvidencePublication:
    """Prepare, no-replace publish, read back, and CAS one evidence event."""
    root = _control_root(control_root)
    _schema(connection)
    compiled, encoded = _compile_payload(request)
    event_id = _identifier(compiled.payload.get("event_id"), "evidence event id")
    deferral_id = _identifier(compiled.payload.get("deferral_id"), "deferral id")
    version = compiled.payload.get("deferral_version")
    if type(version) is not int or version < 1:
        raise DeferralStoreError("deferral version is invalid")
    binding = _campaign_binding(connection, deferral_id)
    if (
        binding is None
        or binding[1] != version
        or binding[2] != "CURRENT"
        or binding[3] != "EVIDENCE"
    ):
        raise DeferralStoreError("deferral evidence identity is stale")
    relative = _expected_evidence_path(binding, event_id)
    payload_hash = sha256_bytes(encoded)
    existing = connection.execute(
        _EVIDENCE_SELECT
        + "WHERE evidence_event_id = ? OR "
        "(deferral_id = ? AND deferral_version = ? AND idempotency_key = ?) "
        "ORDER BY CASE WHEN evidence_event_id = ? THEN 0 ELSE 1 END LIMIT 1",
        (event_id, deferral_id, version, compiled.idempotency_key, event_id),
    ).fetchone()
    if existing is not None:
        _validate_stored_evidence(existing)
        same_event_id = existing[0] == event_id
        if (
            existing[1] != deferral_id
            or existing[2] != version
            or existing[8] != compiled.idempotency_key
            or (
                same_event_id
                and (existing[9] != encoded or existing[11] != str(relative))
            )
        ):
            raise DeferralStoreError("evidence idempotency identity conflicts")
        if existing[13] == "PREPARED":
            raise DeferralStoreError("explicit evidence resume is required")
        return _finish_evidence_publication(
            root,
            connection,
            existing[0],
            resumed=True,
            checkpoint=None,
        )

    connection.execute("BEGIN IMMEDIATE")
    try:
        _schema(connection)
        binding = _campaign_binding(connection, deferral_id)
        if (
            binding is None
            or binding[1] != version
            or binding[2] != "CURRENT"
            or binding[3] != "EVIDENCE"
            or _expected_evidence_path(binding, event_id) != relative
        ):
            raise DeferralStoreError("deferral evidence identity is stale")
        payload = compiled.payload
        connection.execute(
            "INSERT INTO deferral_evidence_events "
            "(evidence_event_id, deferral_id, deferral_version, actor, "
            "source_reference, supplied_content_sha256, opaque_source_id, "
            "actor_attestation, idempotency_key, payload_json, payload_sha256, "
            "final_path, final_sha256, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
            (
                event_id,
                deferral_id,
                version,
                payload["actor"],
                payload.get("source_ref"),
                payload.get("content_sha256"),
                payload.get("opaque_source_id"),
                payload.get("actor_attestation"),
                compiled.idempotency_key,
                encoded,
                payload_hash,
                str(relative),
                payload_hash,
            ),
        )
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise DeferralStoreError("cannot prepare deferral evidence") from exc
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    if checkpoint is not None:
        checkpoint("prepared")
    return _finish_evidence_publication(
        root,
        connection,
        event_id,
        resumed=False,
        checkpoint=checkpoint,
    )


def resume_deferral_evidence(
    control_root: Path,
    connection: sqlite3.Connection,
    event_id: str,
    *,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> EvidencePublication:
    """Resume solely from the canonical bytes stored in the PREPARED row."""
    root = _control_root(control_root)
    _schema(connection)
    _identifier(event_id, "evidence event id")
    return _finish_evidence_publication(
        root,
        connection,
        event_id,
        resumed=True,
        checkpoint=checkpoint,
    )


def _record(binding: Tuple[Any, ...], deferral_id: str) -> deferral_service.DeferralRecord:
    try:
        trigger_kind = _TRIGGER_NAMES[binding[3]]
    except KeyError as exc:
        raise DeferralStoreError("stored deferral trigger kind is invalid") from exc
    return deferral_service.DeferralRecord(
        deferral_id=deferral_id,
        item_id=binding[0],
        version=binding[1],
        state="waiting",
        trigger_kind=trigger_kind,
        review_date=binding[4],
        timezone=binding[5],
        workstream_id=binding[6],
        captured_lifecycle=binding[7],
        captured_policy_hash=binding[8],
    )


def _utc_timestamp(value: datetime.datetime) -> str:
    if not isinstance(value, datetime.datetime) or value.tzinfo is None:
        raise DeferralStoreError("evaluation clock must be timezone-aware")
    if value.utcoffset() is None:
        raise DeferralStoreError("evaluation clock must be timezone-aware")
    return value.astimezone(datetime.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _trigger_row(
    connection: sqlite3.Connection,
    deferral_id: str,
    trigger_kind: str,
    evidence_hash: str,
) -> Optional[Tuple[Any, ...]]:
    return connection.execute(
        "SELECT trigger_event_id, deferral_id, trigger_kind, "
        "trigger_evidence_sha256, source_evidence_event_id, actor, "
        "policy_sha256, payload_json, payload_sha256, occurred_at "
        "FROM deferral_trigger_events WHERE deferral_id = ? "
        "AND trigger_kind = ? AND trigger_evidence_sha256 = ?",
        (deferral_id, trigger_kind, evidence_hash),
    ).fetchone()


def _verify_existing_trigger(
    connection: sqlite3.Connection,
    row: Tuple[Any, ...],
    payload: bytes,
    source_evidence_event_id: Optional[str],
) -> int:
    if (
        row[4] != source_evidence_event_id
        or row[7] != payload
        or row[8] != sha256_bytes(payload)
    ):
        raise DeferralStoreError("stored trigger event conflicts with pure intent")
    projection = connection.execute(
        "SELECT primary_state, current_deferral_id, source_event_id, "
        "projection_generation FROM item_curation_projection p "
        "JOIN deferrals d ON d.item_id = p.item_id WHERE d.deferral_id = ?",
        (row[1],),
    ).fetchone()
    state = connection.execute(
        "SELECT state FROM deferrals WHERE deferral_id = ?",
        (row[1],),
    ).fetchone()
    if (
        state != ("TRIGGERED",)
        or projection is None
        or projection[0:3] != ("REVIEW_READY", None, row[0])
    ):
        raise DeferralStoreError("stored trigger projection is incomplete")
    if source_evidence_event_id is not None:
        evidence_state = connection.execute(
            "SELECT state FROM deferral_evidence_events WHERE evidence_event_id = ?",
            (source_evidence_event_id,),
        ).fetchone()
        if evidence_state != ("CONSUMED",):
            raise DeferralStoreError("stored trigger evidence was not consumed")
    return projection[3]


def evaluate_deferral(
    control_root: Path,
    connection: sqlite3.Connection,
    *,
    deferral_id: str,
    expected_version: int,
    actor: str,
    now: datetime.datetime,
    current_workstream_lifecycle: Optional[str] = None,
    current_policy_hash: Optional[str] = None,
    evidence_event_id: Optional[str] = None,
    manual_reason: Optional[str] = None,
) -> DeferralEvaluationResult:
    """Persist one pure due intent and atomically return its item to review."""
    root = _control_root(control_root)
    _schema(connection)
    deferral_id = _identifier(deferral_id, "deferral id")
    if type(expected_version) is not int or expected_version < 1:
        raise DeferralStoreError("expected deferral version is invalid")
    actor = _text(actor, "evaluation actor")
    occurred_at = _utc_timestamp(now)
    binding = _campaign_binding(connection, deferral_id)
    if binding is None or binding[1] != expected_version:
        if evidence_event_id is not None:
            _block_evidence(connection, evidence_event_id, ("PUBLISHED",))
        raise DeferralStoreError("deferral evaluation identity is stale")
    record = _record(binding, deferral_id)
    published = None
    manual = None
    source_evidence_event_id = None
    evidence_row = None
    if record.trigger_kind == "evidence":
        if evidence_event_id is None:
            raise DeferralStoreError("published evidence event is required")
        evidence_event_id = _identifier(evidence_event_id, "evidence event id")
        evidence_row = _evidence_row(connection, evidence_event_id)
        if (
            evidence_row is None
            or evidence_row[1] != deferral_id
            or evidence_row[2] != expected_version
            or evidence_row[13] not in ("PUBLISHED", "CONSUMED")
        ):
            if evidence_row is not None and evidence_row[13] == "PUBLISHED":
                _block_evidence(connection, evidence_event_id, ("PUBLISHED",))
            raise DeferralStoreError("published evidence identity is stale")
        _validate_stored_evidence(evidence_row)
        relative = _relative_path(evidence_row[11], "evidence final path")
        try:
            _read_exact_artifact(root.joinpath(*relative.parts), evidence_row[9])
        except DeferralStoreError:
            if evidence_row[13] == "PUBLISHED":
                _block_evidence(connection, evidence_event_id, ("PUBLISHED",))
            raise
        published = deferral_service.PublishedEvidence(
            event_id=evidence_event_id,
            event_sha256=evidence_row[12],
            deferral_id=deferral_id,
            deferral_version=expected_version,
            state="PUBLISHED",
        )
        source_evidence_event_id = evidence_event_id
    elif evidence_event_id is not None:
        raise DeferralStoreError("non-evidence trigger received evidence event")
    if record.trigger_kind == "manual-reopen":
        if manual_reason is None:
            raise DeferralStoreError("manual reopen reason is required")
        manual = deferral_service.ManualReopenEvidence(
            deferral_id=deferral_id,
            deferral_version=expected_version,
            actor=actor,
            reason=manual_reason,
        )
    elif manual_reason is not None:
        raise DeferralStoreError("non-manual trigger received manual reason")
    try:
        evaluator = deferral_service.DeferralTriggerEvaluator()
        preview = evaluator.preview(
            record,
            now=now,
            current_workstream_lifecycle=current_workstream_lifecycle,
            current_policy_hash=current_policy_hash,
            published_evidence=published,
            manual_reopen=manual,
        )
        intent = evaluator.evaluate(record, preview, actor=actor)
    except (TypeError, deferral_service.DeferralValidationError) as exc:
        raise DeferralStoreError("deferral trigger is not due or is invalid") from exc
    payload = canonical_json_bytes(intent.event)
    trigger_kind = binding[3]
    evidence_hash = preview.trigger_evidence_hash
    policy_hash = current_policy_hash if trigger_kind == "WORKSTREAM_RESUME" else None

    connection.execute("BEGIN IMMEDIATE")
    try:
        _schema(connection)
        existing = _trigger_row(connection, deferral_id, trigger_kind, evidence_hash)
        if existing is not None:
            generation = _verify_existing_trigger(
                connection,
                existing,
                payload,
                source_evidence_event_id,
            )
            connection.execute("COMMIT")
            return DeferralEvaluationResult(
                trigger_event_id=existing[0],
                deferral_id=deferral_id,
                deferral_version=expected_version,
                trigger_kind=record.trigger_kind,
                trigger_evidence_sha256=evidence_hash,
                payload_bytes=existing[7],
                projection_generation=generation,
                source_evidence_event_id=source_evidence_event_id,
                repeated=True,
            )
        current = _campaign_binding(connection, deferral_id)
        if (
            current is None
            or current[1] != expected_version
            or current[2] != "CURRENT"
            or current[3] != trigger_kind
        ):
            raise DeferralStoreError("deferral evaluation identity is stale")
        projection = connection.execute(
            "SELECT primary_state, current_deferral_id, projection_generation "
            "FROM item_curation_projection WHERE item_id = ?",
            (current[0],),
        ).fetchone()
        if (
            projection is None
            or projection[0] != "DEFERRED"
            or projection[1] != deferral_id
        ):
            raise DeferralStoreError("deferral projection is stale")
        if source_evidence_event_id is not None:
            current_evidence = _evidence_row(connection, source_evidence_event_id)
            if current_evidence is None or current_evidence[13] != "PUBLISHED":
                raise DeferralStoreError("published evidence was already consumed")
        connection.execute(
            "INSERT INTO deferral_trigger_events "
            "(trigger_event_id, deferral_id, trigger_kind, "
            "trigger_evidence_sha256, source_evidence_event_id, actor, "
            "policy_sha256, payload_json, payload_sha256, occurred_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                intent.event["event_id"],
                deferral_id,
                trigger_kind,
                evidence_hash,
                source_evidence_event_id,
                actor,
                policy_hash,
                payload,
                sha256_bytes(payload),
                occurred_at,
            ),
        )
        changed = connection.execute(
            "UPDATE deferrals SET state = 'TRIGGERED' "
            "WHERE deferral_id = ? AND version = ? AND state = 'CURRENT'",
            (deferral_id, expected_version),
        ).rowcount
        if changed != 1:
            raise DeferralStoreError("deferral trigger CAS failed")
        changed = connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'REVIEW_READY', "
            "current_deferral_id = NULL, source_event_id = ?, "
            "projection_generation = projection_generation + 1 "
            "WHERE item_id = ? AND primary_state = 'DEFERRED' "
            "AND current_deferral_id = ? AND projection_generation = ?",
            (intent.event["event_id"], current[0], deferral_id, projection[2]),
        ).rowcount
        if changed != 1:
            raise DeferralStoreError("deferral projection CAS failed")
        if source_evidence_event_id is not None:
            changed = connection.execute(
                "UPDATE deferral_evidence_events SET state = 'CONSUMED' "
                "WHERE evidence_event_id = ? AND state = 'PUBLISHED'",
                (source_evidence_event_id,),
            ).rowcount
            if changed != 1:
                raise DeferralStoreError("deferral evidence consume CAS failed")
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    return DeferralEvaluationResult(
        trigger_event_id=intent.event["event_id"],
        deferral_id=deferral_id,
        deferral_version=expected_version,
        trigger_kind=record.trigger_kind,
        trigger_evidence_sha256=evidence_hash,
        payload_bytes=payload,
        projection_generation=projection[2] + 1,
        source_evidence_event_id=source_evidence_event_id,
        repeated=False,
    )


__all__ = [
    "DeferralEvaluationResult",
    "DeferralStoreError",
    "EvidencePublication",
    "attach_deferral_evidence",
    "evaluate_deferral",
    "resume_deferral_evidence",
]
