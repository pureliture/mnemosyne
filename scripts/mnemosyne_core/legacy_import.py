"""Idempotent import bridge for the preserved legacy placement decision log.

The legacy YAML files remain evidence and are never rewritten.  This module
binds every imported row to the registry-relative legacy file path and its raw
byte hash; parsed placement paths are evidence and collision inputs, not the
import identity and never become a current curation decision by themselves.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import m3_schema, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


PREVIEW_KIND = "MNEMOSYNE_LEGACY_HISTORY_IMPORT_PREVIEW"
RESULT_KIND = "MNEMOSYNE_LEGACY_HISTORY_IMPORT_RESULT"
PLAN_KIND = "MNEMOSYNE_LEGACY_HISTORY_IMPORT_PLAN"
SCHEMA_VERSION = 1

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CURRENT_KEYS = (
    "id",
    "proposal_id",
    "decision",
    "decided_at",
    "actor",
    "source",
    "target",
    "category",
    "reason",
    "proposal_created_at",
)


class LegacyImportError(RuntimeError):
    """The legacy import evidence or durable transition is unsafe."""


def _canonical_root(root: Path) -> Path:
    value = Path(root)
    if not value.is_absolute() or any(part in (".", "..") for part in value.parts):
        raise LegacyImportError("raw root must be a canonical absolute path")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise LegacyImportError("%s is invalid" % label)
    return value


def _actor(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise LegacyImportError("%s is invalid" % label)
    return value


def _file_witness(info: os.stat_result) -> Tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_stable_legacy_file(
    directory: Path,
    directory_fd: int,
    name: str,
) -> Tuple[bytes, Dict[str, int]]:
    path = directory / name
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lexical_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise LegacyImportError("legacy decision is unreadable: %s" % path) from exc
    try:
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_uid != os.getuid()
            or opened_before.st_nlink != 1
            or bool(stat.S_IMODE(opened_before.st_mode) & 0o022)
            or _file_witness(opened_before) != _file_witness(lexical_before)
        ):
            raise LegacyImportError("legacy decision identity is invalid: %s" % path)
        first = safety.read_open_file_bytes(descriptor)
        opened_after_first = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = safety.read_open_file_bytes(descriptor)
        opened_after_second = os.fstat(descriptor)
        lexical_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            first != second
            or _file_witness(opened_before) != _file_witness(opened_after_first)
            or _file_witness(opened_before) != _file_witness(opened_after_second)
            or _file_witness(opened_before) != _file_witness(lexical_after)
        ):
            raise LegacyImportError("legacy decision changed during read: %s" % path)
        return first, {
            "bytes": len(first),
            "mode": stat.S_IMODE(opened_before.st_mode),
            "mtime_ns": opened_before.st_mtime_ns,
            "ctime_ns": opened_before.st_ctime_ns,
        }
    finally:
        os.close(descriptor)


def _decode_scalar(raw: str) -> str:
    value = raw.strip()
    if not value or value[0:1] not in ('"', "'"):
        raise ValueError("value-not-quoted")
    if value[0] == "\"":
        parsed = json.loads(value)
    else:
        if len(value) < 2 or value[-1] != "'":
            raise ValueError("value-not-quoted")
        parsed = value[1:-1]
    if type(parsed) is not str:
        raise ValueError("value-not-text")
    return parsed


def _relative_record_path(value: str, root: Path) -> str:
    path = Path(value)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ValueError("path-not-canonical")
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("path-outside-root") from exc
    if not relative.parts:
        raise ValueError("path-is-root")
    return relative.as_posix()


def _parse_current_decision(raw: bytes, root: Path) -> Dict[str, Any]:
    errors: List[str] = []
    record: Dict[str, str] = {}
    keys: List[str] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"errors": ["invalid-utf8"], "status": "UNPARSED"}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line != line.strip() or ":" not in line:
            errors.append("invalid-line")
            continue
        key, encoded = line.split(":", 1)
        if key in record:
            errors.append("duplicate-key")
            continue
        keys.append(key)
        try:
            record[key] = _decode_scalar(encoded)
        except (ValueError, json.JSONDecodeError):
            errors.append("invalid-value")
    if tuple(keys) != _CURRENT_KEYS:
        errors.append("invalid-key-set-or-order")
    if not errors:
        if _ID.fullmatch(record["id"]) is None:
            errors.append("invalid-id")
        if _ID.fullmatch(record["proposal_id"]) is None:
            errors.append("invalid-proposal-id")
        if record["decision"] not in ("approved", "rejected"):
            errors.append("invalid-decision")
        if _UTC_TIMESTAMP.fullmatch(record["decided_at"]) is None:
            errors.append("invalid-decided-at")
        if _UTC_TIMESTAMP.fullmatch(record["proposal_created_at"]) is None:
            errors.append("invalid-proposal-created-at")
        if not record["actor"].strip() or record["actor"] != record["actor"].strip():
            errors.append("invalid-actor")
        try:
            source = _relative_record_path(record["source"], root)
            target = _relative_record_path(record["target"], root)
            if source == target:
                errors.append("source-equals-target")
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        return {"errors": sorted(set(errors)), "status": "UNPARSED"}
    return {
        "legacy_historical": True,
        "normalized_source": source,
        "normalized_target": target,
        "record": record,
        "reversal_available": False,
        "schema": "legacy-placement-decision-v1",
        "status": "PARSED",
    }


def _preview_body(preview: Dict[str, Any]) -> Dict[str, Any]:
    body = dict(preview)
    body.pop("preview_sha256", None)
    return body


def _is_ancestor(left: str, right: str) -> bool:
    return left != right and right.startswith(left.rstrip("/") + "/")


def _collision_kinds(left: Dict[str, Any], right: Dict[str, Any]) -> List[str]:
    left_result = left["parse_result"]
    right_result = right["parse_result"]
    if left_result["status"] != "PARSED" or right_result["status"] != "PARSED":
        return []
    left_source = left_result["normalized_source"]
    left_target = left_result["normalized_target"]
    right_source = right_result["normalized_source"]
    right_target = right_result["normalized_target"]
    kinds: List[str] = []
    if left_source == right_source:
        kinds.append("same-source")
    if left_target == right_target:
        kinds.append("same-target")
    if left_source == right_target or left_target == right_source:
        kinds.append("source-target-equality")
    paths = (left_source, left_target, right_source, right_target)
    if any(
        _is_ancestor(paths[left_index], paths[right_index])
        or _is_ancestor(paths[right_index], paths[left_index])
        for left_index in (0, 1)
        for right_index in (2, 3)
    ):
        kinds.append("ancestor-descendant")
    left_parent = posixpath.dirname(left_target)
    right_parent = posixpath.dirname(right_target)
    if left_parent in (right_source, right_target) or right_parent in (
        left_source,
        left_target,
    ):
        kinds.append("target-parent")
    return kinds


def _collision_set(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    collisions: List[Dict[str, Any]] = []
    for left_index, left in enumerate(entries):
        for right in entries[left_index + 1 :]:
            kinds = _collision_kinds(left, right)
            if kinds:
                collisions.append(
                    {
                        "kinds": kinds,
                        "left": left["legacy_path"],
                        "right": right["legacy_path"],
                    }
                )
    return collisions


def preview_bytes(preview: Dict[str, Any]) -> bytes:
    return canonical_json_bytes(_preview_body(preview))


def preview_sha256(preview: Dict[str, Any]) -> str:
    return sha256_bytes(preview_bytes(preview))


def preview_legacy_history_import(
    root: Path,
    *,
    preview_id: str,
    requested_by: str,
) -> Dict[str, Any]:
    """Build a write-free, hash-sealed view of the current legacy decisions."""

    canonical = _canonical_root(root)
    identity = _identifier(preview_id, "preview id")
    requester = _actor(requested_by, "requested_by")
    decisions = canonical / "_registry" / "decisions"
    try:
        directory_fd = safety.open_verified_directory(
            decisions,
            require_owner_only=True,
            error_type=LegacyImportError,
        )
    except LegacyImportError as exc:
        raise LegacyImportError("legacy decisions directory is invalid") from exc
    entries: List[Dict[str, Any]] = []
    try:
        names = sorted(os.listdir(directory_fd))
        if any(not name.endswith(".yml") for name in names):
            raise LegacyImportError("legacy decisions directory has unexpected members")
        for name in names:
            raw, witness = _read_stable_legacy_file(decisions, directory_fd, name)
            digest = sha256_bytes(raw)
            legacy_path = "decisions/%s" % name
            entries.append(
                {
                    "content_sha256": digest,
                    "idempotency_key": [legacy_path, digest],
                    "legacy_path": legacy_path,
                    "parse_result": _parse_current_decision(raw, canonical),
                    "source_filename": name,
                    "witness": witness,
                }
            )
        safety.require_same_directory_identity(
            decisions,
            directory_fd,
            "legacy decisions",
            error_type=LegacyImportError,
        )
    finally:
        os.close(directory_fd)

    pending = canonical / "_registry" / "pending"
    pending_names = _pending_yaml_filenames(canonical)
    manifest = {
        "entries": entries,
        "legacy_directory": "decisions",
        "pending_filenames": pending_names,
    }
    preview: Dict[str, Any] = {
        "collisions": _collision_set(entries),
        "curation_source_blockers": curation_source_blockers(
            canonical,
            entries,
        ),
        "entries": entries,
        "kind": PREVIEW_KIND,
        "manifest_sha256": sha256_bytes(canonical_json_bytes(manifest)),
        "pending_count": len(pending_names),
        "preview_id": identity,
        "requested_by": requester,
        "schema_version": SCHEMA_VERSION,
    }
    preview["preview_sha256"] = preview_sha256(preview)
    return preview


def _pending_yaml_filenames(canonical: Path) -> Tuple[str, ...]:
    pending = canonical / "_registry" / "pending"
    if not pending.exists():
        return ()
    try:
        pending_fd = safety.open_verified_directory(
            pending,
            require_owner_only=True,
            error_type=LegacyImportError,
        )
    except LegacyImportError as exc:
        raise LegacyImportError("legacy pending directory is invalid") from exc
    try:
        names = tuple(
            sorted(name for name in os.listdir(pending_fd) if name.endswith(".yml"))
        )
        safety.require_same_directory_identity(
            pending,
            pending_fd,
            "legacy pending",
            error_type=LegacyImportError,
        )
        return names
    finally:
        os.close(pending_fd)


def require_legacy_import_allowed(canonical: Path) -> None:
    """Fail closed while legacy placement proposals remain in pending."""

    if _pending_yaml_filenames(_canonical_root(canonical)):
        raise LegacyImportError(
            "legacy import is blocked while pending proposals exist"
        )


def _flat_yaml_lookup(raw: bytes, *keys: str) -> Dict[str, str]:
    wanted = frozenset(keys)
    found: Dict[str, str] = {}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return found
    for line in text.splitlines():
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, encoded = line.split(":", 1)
        if key not in wanted or key in found:
            continue
        try:
            found[key] = _decode_scalar(encoded)
        except (ValueError, json.JSONDecodeError):
            continue
    return found


def _pending_placement_sources(
    canonical: Path,
) -> Tuple[Tuple[str, str], ...]:
    root = _canonical_root(canonical)
    pending = root / "_registry" / "pending"
    sources: List[Tuple[str, str]] = []
    for name in _pending_yaml_filenames(root):
        try:
            directory_fd = safety.open_verified_directory(
                pending,
                require_owner_only=True,
                error_type=LegacyImportError,
            )
        except LegacyImportError:
            continue
        try:
            _info, raw = safety.read_regular_file_at(
                directory_fd,
                name,
                pending / name,
                label="legacy pending proposal",
                expected_mode=0o600,
                error_type=LegacyImportError,
            )
            safety.require_same_directory_identity(
                pending,
                directory_fd,
                "legacy pending",
                error_type=LegacyImportError,
            )
        except LegacyImportError:
            continue
        finally:
            os.close(directory_fd)
        fields = _flat_yaml_lookup(raw, "id", "status", "source")
        if fields.get("status") != "pending":
            continue
        proposal_id = fields.get("id", name)
        source_text = fields.get("source")
        if type(source_text) is not str or not source_text.strip():
            continue
        try:
            normalized = _relative_record_path(source_text, root)
        except ValueError:
            continue
        sources.append((proposal_id, normalized))
    return tuple(sorted(sources, key=lambda row: (row[1], row[0])))


def _open_curation_batch_paths(
    connection: sqlite3.Connection,
) -> frozenset[str]:
    rows = connection.execute(
        "SELECT DISTINCT m.path FROM batch_memberships AS m "
        "JOIN review_batches AS b ON b.batch_id = m.batch_id "
        "WHERE b.status = 'OPEN' AND m.status = 'OPEN' "
        "ORDER BY m.path",
    ).fetchall()
    return frozenset(str(row[0]) for row in rows)


def _path_conflicts_with_curation_source(
    normalized_source: str,
    other_path: str,
) -> bool:
    if normalized_source == other_path:
        return True
    return _is_ancestor(normalized_source, other_path) or _is_ancestor(
        other_path,
        normalized_source,
    )


def curation_source_blockers(
    canonical: Path,
    entries: Sequence[Dict[str, Any]],
    *,
    connection: Optional[sqlite3.Connection] = None,
) -> Tuple[Dict[str, Any], ...]:
    root = _canonical_root(canonical)
    pending_sources = _pending_placement_sources(root)
    batch_paths = (
        _open_curation_batch_paths(connection)
        if connection is not None
        else frozenset()
    )
    blockers: List[Dict[str, Any]] = []
    for entry in entries:
        parse_result = entry.get("parse_result")
        if type(parse_result) is not dict or parse_result.get("status") != "PARSED":
            continue
        normalized = parse_result.get("normalized_source")
        if type(normalized) is not str:
            continue
        legacy_path = entry.get("legacy_path", "")
        for proposal_id, pending_source in pending_sources:
            if _path_conflicts_with_curation_source(normalized, pending_source):
                blockers.append(
                    {
                        "kind": "pending-proposal-source",
                        "legacy_path": legacy_path,
                        "normalized_source": normalized,
                        "proposal_id": proposal_id,
                    }
                )
                break
        else:
            for batch_path in sorted(batch_paths):
                if _path_conflicts_with_curation_source(normalized, batch_path):
                    blockers.append(
                        {
                            "kind": "open-curation-batch-path",
                            "batch_path": batch_path,
                            "legacy_path": legacy_path,
                            "normalized_source": normalized,
                        }
                    )
                    break
    return tuple(blockers)


def legacy_pending_blockers_for_membership_paths(
    canonical: Path,
    membership_paths: Sequence[str],
) -> Tuple[Dict[str, Any], ...]:
    """Block curation batch paths that conflict with legacy pending proposal sources."""

    root = _canonical_root(canonical)
    pending_sources = _pending_placement_sources(root)
    blockers: List[Dict[str, Any]] = []
    for path in membership_paths:
        if type(path) is not str or not path:
            continue
        for proposal_id, pending_source in pending_sources:
            if _path_conflicts_with_curation_source(path, pending_source):
                blockers.append(
                    {
                        "kind": "legacy-pending-source",
                        "membership_path": path,
                        "normalized_source": pending_source,
                        "proposal_id": proposal_id,
                    }
                )
                break
    return tuple(blockers)


def _require_no_curation_source_conflicts(
    canonical: Path,
    connection: sqlite3.Connection,
    entries: Sequence[Dict[str, Any]],
) -> None:
    blockers = curation_source_blockers(
        canonical,
        entries,
        connection=connection,
    )
    if blockers:
        raise LegacyImportError(
            "legacy import is blocked by matching curation source conflicts"
        )


def _result_body(result: Dict[str, Any]) -> Dict[str, Any]:
    body = dict(result)
    body.pop("result_sha256", None)
    return body


def result_bytes(result: Dict[str, Any]) -> bytes:
    return canonical_json_bytes(_result_body(result))


def _result_sha256(result: Dict[str, Any]) -> str:
    return sha256_bytes(result_bytes(result))


def _canonical_object(encoded: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyImportError("%s is invalid" % label) from exc
    if type(value) is not dict or canonical_json_bytes(value) != encoded:
        raise LegacyImportError("%s is not canonical" % label)
    return value


def _require_no_transaction(connection: sqlite3.Connection) -> None:
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be sqlite3.Connection")
    if connection.in_transaction:
        raise LegacyImportError("legacy import requires transaction ownership")


def _verify_schema(connection: sqlite3.Connection) -> None:
    try:
        m3_schema.verify_v3_schema(connection)
    except (m3_schema.M3SchemaError, sqlite3.Error) as exc:
        raise LegacyImportError("curation ledger v3 schema is invalid") from exc


def _head_generation(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT generation FROM legacy_import_head WHERE id = 1"
    ).fetchone()
    return 0 if row is None else int(row[0])


def _source_manifest(preview: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "collisions": preview["collisions"],
        "entries": [
            {
                "content_sha256": entry["content_sha256"],
                "legacy_path": entry["legacy_path"],
                "parse_status": entry["parse_result"]["status"],
                "source_filename": entry["source_filename"],
            }
            for entry in preview["entries"]
        ],
        "pending_filenames": [
            name
            for name in preview.get("pending_filenames", [])
        ],
    }


def _require_preview(
    root: Path,
    preview: Dict[str, Any],
    expected_sha256: str,
) -> Dict[str, Any]:
    if type(preview) is not dict:
        raise TypeError("preview must be a dictionary")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise LegacyImportError("expected preview hash is invalid")
    if (
        preview.get("kind") != PREVIEW_KIND
        or preview.get("schema_version") != SCHEMA_VERSION
        or preview.get("preview_sha256") != expected_sha256
        or preview_sha256(preview) != expected_sha256
    ):
        raise LegacyImportError("legacy import preview binding is invalid")
    current = preview_legacy_history_import(
        root,
        preview_id=preview.get("preview_id"),
        requested_by=preview.get("requested_by"),
    )
    if preview_sha256(current) != preview_sha256(preview):
        raise LegacyImportError("legacy history changed after preview")
    return current


def _collision_paths(preview: Dict[str, Any]) -> set[str]:
    return {
        path
        for collision in preview["collisions"]
        for path in (collision["left"], collision["right"])
    }


def _entry_payload(entry: Dict[str, Any], collision_paths: set[str]) -> Dict[str, Any]:
    status = entry["parse_result"]["status"]
    if entry["legacy_path"] in collision_paths and status == "PARSED":
        status = "COLLISION"
    return {
        "content_sha256": entry["content_sha256"],
        "legacy_historical": True,
        "legacy_path": entry["legacy_path"],
        "parse_result": entry["parse_result"],
        "parse_status": status,
        "reversal_available": False,
        "source_filename": entry["source_filename"],
    }


def _legacy_import_id(path: str, digest: str) -> str:
    identity = sha256_bytes((path + "\0" + digest).encode("utf-8"))
    return "legacy-" + identity[:40]


def _result_payload(
    *,
    actor: str,
    expected_head_generation: int,
    import_run_id: str,
    preview: Dict[str, Any],
    result_id: str,
    result_path: Path,
) -> Dict[str, Any]:
    collision_paths = _collision_paths(preview)
    entries = [
        _entry_payload(entry, collision_paths) for entry in preview["entries"]
    ]
    return {
        "actor": actor,
        "entries": entries,
        "expected_head_generation": expected_head_generation,
        "generation": expected_head_generation + 1,
        "import_run_id": import_run_id,
        "kind": RESULT_KIND,
        "manifest_sha256": preview["manifest_sha256"],
        "pending_count": preview["pending_count"],
        "preview_id": preview["preview_id"],
        "preview_sha256": preview["preview_sha256"],
        "result_id": result_id,
        "result_path": str(result_path),
        "schema_version": SCHEMA_VERSION,
        "state": "COMPLETE",
    }


def _plan_payload(
    *,
    actor: str,
    expected_head_generation: int,
    import_run_id: str,
    preview: Dict[str, Any],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "actor": actor,
        "expected_head_generation": expected_head_generation,
        "import_run_id": import_run_id,
        "kind": PLAN_KIND,
        "preview": preview,
        "result": result,
        "schema_version": SCHEMA_VERSION,
    }


def _read_exact_result(path: Path, expected: bytes) -> None:
    try:
        directory_fd = safety.open_verified_directory(
            path.parent,
            require_owner_only=True,
            error_type=LegacyImportError,
        )
    except LegacyImportError as exc:
        raise LegacyImportError("legacy import result parent is invalid") from exc
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label="legacy import result",
            expected_mode=0o600,
            error_type=LegacyImportError,
        )
        if info.st_nlink != 1 or raw != expected:
            raise LegacyImportError("legacy import result readback mismatch")
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            "legacy import result",
            error_type=LegacyImportError,
        )
    finally:
        os.close(directory_fd)


def _publish_or_verify_result(path: Path, encoded: bytes) -> None:
    if os.path.lexists(path):
        _read_exact_result(path, encoded)
        return
    safety.publish_bytes_atomic_no_replace(
        path,
        encoded,
        label="legacy import result",
        mode=0o600,
        create_parent=True,
        collision_error="legacy import result already exists",
        final_identity_error="legacy import result identity mismatch",
        parent_error="legacy import result parent is invalid",
        error_type=LegacyImportError,
        after_fd_readback=lambda _path, _fd, _directory_fd: None,
    )
    _read_exact_result(path, encoded)


def _stored_run(
    connection: sqlite3.Connection,
    import_run_id: str,
) -> Optional[Tuple[Any, ...]]:
    return connection.execute(
        "SELECT request_hash, expected_head_generation, source_manifest_json, "
        "source_manifest_sha256, actor, payload_json, payload_sha256, result_id, "
        "result_path, result_sha256, state FROM legacy_import_runs "
        "WHERE import_run_id = ?",
        (import_run_id,),
    ).fetchone()


def _load_stored_plan(row: Tuple[Any, ...]) -> Dict[str, Any]:
    encoded = bytes(row[5])
    if sha256_bytes(encoded) != row[6]:
        raise LegacyImportError("stored legacy import plan hash is invalid")
    plan = _canonical_object(encoded, "stored legacy import plan")
    result = plan.get("result")
    if type(result) is not dict:
        raise LegacyImportError("stored legacy import result is invalid")
    if (
        result.get("result_id") != row[7]
        or result.get("result_path") != row[8]
        or _result_sha256(result) != row[9]
    ):
        raise LegacyImportError("stored legacy import result binding is invalid")
    return plan


def _insert_or_verify_import(
    connection: sqlite3.Connection,
    *,
    import_run_id: str,
    result_id: str,
    entry: Dict[str, Any],
) -> bool:
    path = entry["legacy_path"]
    digest = entry["content_sha256"]
    payload = canonical_json_bytes(entry)
    payload_hash = sha256_bytes(payload)
    existing = connection.execute(
        "SELECT source_filename, parse_status, payload_json, payload_sha256 "
        "FROM legacy_imports WHERE normalized_source_path = ? AND content_sha256 = ?",
        (path, digest),
    ).fetchone()
    if existing is not None:
        if (
            existing[0] != entry["source_filename"]
            or existing[1] != entry["parse_status"]
            or bytes(existing[2]) != payload
            or existing[3] != payload_hash
        ):
            raise LegacyImportError("existing legacy import identity is rebound")
        return False
    connection.execute(
        "INSERT INTO legacy_imports (legacy_import_id, import_run_id, result_id, "
        "normalized_source_path, source_filename, content_sha256, parse_status, "
        "payload_json, payload_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            _legacy_import_id(path, digest),
            import_run_id,
            result_id,
            path,
            entry["source_filename"],
            digest,
            entry["parse_status"],
            payload,
            payload_hash,
        ),
    )
    return True


def _block_run(connection: sqlite3.Connection, import_run_id: str) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "UPDATE legacy_import_runs SET state = 'BLOCKED' "
            "WHERE import_run_id = ? AND state = 'PREPARED'",
            (import_run_id,),
        )
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _finish_prepared(
    root: Path,
    connection: sqlite3.Connection,
    *,
    import_run_id: str,
    plan: Dict[str, Any],
    checkpoint: Optional[Callable[[str], None]],
) -> Dict[str, Any]:
    _verify_schema(connection)
    require_legacy_import_allowed(root)
    result = plan["result"]
    preview = plan["preview"]
    _require_no_curation_source_conflicts(
        root,
        connection,
        preview["entries"],
    )
    try:
        current = _require_preview(root, preview, preview["preview_sha256"])
    except LegacyImportError:
        _block_run(connection, import_run_id)
        raise
    if preview_sha256(current) != preview_sha256(preview):
        _block_run(connection, import_run_id)
        raise LegacyImportError("legacy history changed before result publication")
    encoded = result_bytes(result)
    try:
        _publish_or_verify_result(Path(result["result_path"]), encoded)
    except LegacyImportError:
        _block_run(connection, import_run_id)
        raise
    if checkpoint is not None:
        checkpoint("result-published")

    connection.execute("BEGIN IMMEDIATE")
    try:
        _verify_schema(connection)
        row = _stored_run(connection, import_run_id)
        if row is None:
            raise LegacyImportError("prepared legacy import run is missing")
        if row[10] == "COMPLETE":
            connection.execute("ROLLBACK")
            _read_exact_result(Path(result["result_path"]), encoded)
            completed = dict(result)
            completed["result_sha256"] = sha256_bytes(encoded)
            return completed
        if row[10] != "PREPARED":
            raise LegacyImportError("legacy import run is not resumable")
        expected_generation = int(row[1])
        if _head_generation(connection) != expected_generation:
            raise LegacyImportError("legacy import head changed before commit")
        inserted = 0
        for entry in result["entries"]:
            inserted += int(
                _insert_or_verify_import(
                    connection,
                    import_run_id=import_run_id,
                    result_id=result["result_id"],
                    entry=entry,
                )
            )
        if expected_generation == 0:
            connection.execute(
                "INSERT INTO legacy_import_head (id, generation, manifest_sha256, "
                "import_run_id, result_id, result_sha256) VALUES (1, ?, ?, ?, ?, ?)",
                (
                    result["generation"],
                    result["manifest_sha256"],
                    import_run_id,
                    result["result_id"],
                    sha256_bytes(encoded),
                ),
            )
        else:
            cursor = connection.execute(
                "UPDATE legacy_import_head SET generation = ?, manifest_sha256 = ?, "
                "import_run_id = ?, result_id = ?, result_sha256 = ? "
                "WHERE id = 1 AND generation = ?",
                (
                    result["generation"],
                    result["manifest_sha256"],
                    import_run_id,
                    result["result_id"],
                    sha256_bytes(encoded),
                    expected_generation,
                ),
            )
            if cursor.rowcount != 1:
                raise LegacyImportError("legacy import head CAS failed")
        cursor = connection.execute(
            "UPDATE legacy_import_runs SET state = 'COMPLETE' "
            "WHERE import_run_id = ? AND state = 'PREPARED'",
            (import_run_id,),
        )
        if cursor.rowcount != 1:
            raise LegacyImportError("legacy import run completion CAS failed")
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    if checkpoint is not None:
        checkpoint("complete")
    completed = dict(result)
    completed["result_sha256"] = sha256_bytes(encoded)
    return completed


def import_legacy_history(
    root: Path,
    connection: sqlite3.Connection,
    *,
    preview: Dict[str, Any],
    expected_preview_sha256: str,
    import_run_id: str,
    actor: str,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Prepare, publish, and atomically commit one exact legacy manifest."""

    canonical = _canonical_root(root)
    _require_no_transaction(connection)
    _verify_schema(connection)
    identity = _identifier(import_run_id, "import run id")
    importer = _actor(actor, "actor")
    if checkpoint is not None and not callable(checkpoint):
        raise TypeError("checkpoint must be callable")
    bound = _require_preview(canonical, preview, expected_preview_sha256)
    existing = _stored_run(connection, identity)
    if existing is not None:
        plan = _load_stored_plan(existing)
        if (
            preview_sha256(plan["preview"]) != preview_sha256(bound)
            or plan["actor"] != importer
            or plan["import_run_id"] != identity
        ):
            raise LegacyImportError("legacy import run identity is rebound")
        return _finish_prepared(
            canonical,
            connection,
            import_run_id=identity,
            plan=plan,
            checkpoint=checkpoint,
        )

    require_legacy_import_allowed(canonical)
    _require_no_curation_source_conflicts(
        canonical,
        connection,
        bound["entries"],
    )
    generation = _head_generation(connection)
    result_id = "legacy-result:%s" % identity
    result_path = (
        canonical
        / "_registry"
        / "curation"
        / "legacy-imports"
        / "runs"
        / identity
        / "result.json"
    )
    result = _result_payload(
        actor=importer,
        expected_head_generation=generation,
        import_run_id=identity,
        preview=bound,
        result_id=result_id,
        result_path=result_path,
    )
    plan = _plan_payload(
        actor=importer,
        expected_head_generation=generation,
        import_run_id=identity,
        preview=bound,
        result=result,
    )
    plan_encoded = canonical_json_bytes(plan)
    source_manifest = _source_manifest(bound)
    source_manifest_encoded = canonical_json_bytes(source_manifest)
    request_hash = sha256_bytes(
        canonical_json_bytes(
            {
                "actor": importer,
                "import_run_id": identity,
                "preview_sha256": expected_preview_sha256,
            }
        )
    )
    connection.execute("BEGIN IMMEDIATE")
    try:
        if _head_generation(connection) != generation:
            raise LegacyImportError("legacy import head changed before prepare")
        connection.execute(
            "INSERT INTO legacy_import_runs (import_run_id, request_hash, "
            "expected_head_generation, source_manifest_json, source_manifest_sha256, "
            "actor, payload_json, payload_sha256, result_id, result_path, "
            "result_sha256, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
            (
                identity,
                request_hash,
                generation,
                source_manifest_encoded,
                sha256_bytes(source_manifest_encoded),
                importer,
                plan_encoded,
                sha256_bytes(plan_encoded),
                result_id,
                str(result_path),
                _result_sha256(result),
            ),
        )
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    if checkpoint is not None:
        checkpoint("prepared")
    try:
        return _finish_prepared(
            canonical,
            connection,
            import_run_id=identity,
            plan=plan,
            checkpoint=checkpoint,
        )
    except LegacyImportError:
        raise
    except sqlite3.Error as exc:
        raise LegacyImportError(str(exc)) from exc


def resume_legacy_history_import(
    root: Path,
    connection: sqlite3.Connection,
    *,
    import_run_id: str,
    resumed_by: str,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Resume only the exact stored PREPARED bytes for one import run."""

    canonical = _canonical_root(root)
    _require_no_transaction(connection)
    _verify_schema(connection)
    identity = _identifier(import_run_id, "import run id")
    _actor(resumed_by, "resumed_by")
    if checkpoint is not None and not callable(checkpoint):
        raise TypeError("checkpoint must be callable")
    row = _stored_run(connection, identity)
    if row is None:
        raise LegacyImportError("legacy import run not found")
    plan = _load_stored_plan(row)
    try:
        return _finish_prepared(
            canonical,
            connection,
            import_run_id=identity,
            plan=plan,
            checkpoint=checkpoint,
        )
    except LegacyImportError:
        raise
    except sqlite3.Error as exc:
        raise LegacyImportError(str(exc)) from exc


__all__ = [
    "LegacyImportError",
    "PLAN_KIND",
    "PREVIEW_KIND",
    "RESULT_KIND",
    "SCHEMA_VERSION",
    "curation_source_blockers",
    "import_legacy_history",
    "legacy_pending_blockers_for_membership_paths",
    "preview_bytes",
    "preview_legacy_history_import",
    "preview_sha256",
    "require_legacy_import_allowed",
    "result_bytes",
    "resume_legacy_history_import",
]
