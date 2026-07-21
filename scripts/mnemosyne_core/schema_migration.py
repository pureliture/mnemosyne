"""Explicit preview, approval, and apply boundary for the M2 ledger schema.

The preview is observational.  Approval seals the exact preview identity, and
apply is the only component allowed to create a SQLite backup and invoke the
version-1 to version-2 schema delta.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from . import control, ledger_runtime, ledger_schema, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


PLAN_KIND = "MNEMOSYNE_M2_SCHEMA_MIGRATION_PLAN"
APPROVAL_KIND = "MNEMOSYNE_M2_SCHEMA_MIGRATION_APPROVAL"
RESULT_KIND = "MNEMOSYNE_M2_SCHEMA_MIGRATION_RESULT"
SCHEMA_VERSION = 1
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


class SchemaMigrationError(RuntimeError):
    """The explicit M2 schema migration boundary failed closed."""


def _canonical_root(root: Path) -> Path:
    path = Path(root)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise SchemaMigrationError("raw root must be a canonical absolute path")
    return path


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise SchemaMigrationError("%s is invalid" % label)
    return value


def _actor(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise SchemaMigrationError("%s is invalid" % label)
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise SchemaMigrationError("%s is invalid" % label)
    return value


def _plan_body(plan: Dict[str, Any]) -> Dict[str, Any]:
    if type(plan) is not dict:
        raise TypeError("plan must be a dictionary")
    body = dict(plan)
    body.pop("plan_sha256", None)
    return body


def plan_bytes(plan: Dict[str, Any]) -> bytes:
    """Return the canonical, non-self-referential plan bytes."""

    return canonical_json_bytes(_plan_body(plan))


def plan_sha256(plan: Dict[str, Any]) -> str:
    return sha256_bytes(plan_bytes(plan))


def _stable_regular(path: Path, label: str, *, expected_mode: Optional[int]) -> Dict[str, Any]:
    directory_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=SchemaMigrationError,
    )
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label=label,
            expected_mode=expected_mode,
            error_type=SchemaMigrationError,
        )
        if info.st_uid != os.getuid() or info.st_nlink != 1:
            raise SchemaMigrationError("%s ownership or link count is invalid" % label)
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=SchemaMigrationError,
        )
    finally:
        os.close(directory_fd)
    return {
        "bytes": len(raw),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": "%04o" % stat.S_IMODE(info.st_mode),
        "mtime_ns": info.st_mtime_ns,
        "nlink": info.st_nlink,
        "path": str(path),
        "sha256": sha256_bytes(raw),
        "uid": info.st_uid,
    }


def _connect_immutable_preview(
    path: Path,
    identity: Tuple[int, int],
) -> sqlite3.Connection:
    """Open the checkpointed ledger image without creating or touching WAL state."""

    wal_path = Path(str(path) + "-wal")
    if os.path.lexists(wal_path):
        wal = _stable_regular(
            wal_path,
            "curation ledger WAL",
            expected_mode=0o600,
        )
        if wal["bytes"]:
            raise SchemaMigrationError(
                "nonempty WAL blocks the write-free preview; checkpoint it first"
            )
    try:
        connection = sqlite3.connect(
            path.as_uri() + "?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        raise SchemaMigrationError("cannot open immutable v1 ledger preview") from exc
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = %d" % control.BUSY_TIMEOUT_MS)
        ledger_runtime._require_database_identity(
            path,
            identity,
            phase="while opening immutable preview",
        )
        return connection
    except BaseException:
        connection.close()
        raise


def _schema_identity(connection: Any) -> Dict[str, Any]:
    rows = [
        [row[0], row[1], row[2]]
        for row in connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
    ]
    migrations = [
        list(row)
        for row in connection.execute(
            "SELECT version, schema_sha256, applied_by_bootstrap_id "
            "FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]
    return {
        "objects_sha256": sha256_bytes(canonical_json_bytes(rows)),
        "schema_migrations": migrations,
    }


def _logical_cell(value: Any) -> Dict[str, Any]:
    if value is None:
        return {"type": "null", "value": None}
    if type(value) is int:
        return {"type": "integer", "value": value}
    if type(value) is float:
        return {"type": "real", "value": repr(value)}
    if type(value) is str:
        return {"type": "text", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {
            "type": "blob",
            "value": base64.b64encode(bytes(value)).decode("ascii"),
        }
    raise SchemaMigrationError("ledger contains an unsupported SQLite value")


def _logical_identity(connection: sqlite3.Connection) -> Dict[str, Any]:
    names = [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    ]
    tables = []
    for name in names:
        quoted = '"%s"' % name.replace('"', '""')
        columns = [
            row[1]
            for row in connection.execute("PRAGMA table_info(%s)" % quoted).fetchall()
        ]
        row_hashes = sorted(
            sha256_bytes(
                canonical_json_bytes([_logical_cell(value) for value in row])
            )
            for row in connection.execute("SELECT * FROM %s" % quoted).fetchall()
        )
        tables.append(
            {
                "columns": columns,
                "name": name,
                "row_count": len(row_hashes),
                "rows_sha256": sha256_bytes(canonical_json_bytes(row_hashes)),
            }
        )
    return {
        "sha256": sha256_bytes(canonical_json_bytes(tables)),
        "tables": tables,
    }


def _policy_identity(approved: Any) -> Dict[str, Any]:
    return {
        "foundation_hash": approved.foundation_hash,
        "full_hash": approved.full_hash,
        "generation": approved.generation,
        "guard_epoch": approved.guard_epoch,
        "raw_hash": approved.raw_hash,
        "source_kind": approved.source_kind,
        "source_run_id": approved.source_run_id,
        "writer_control_hash": approved.writer_control_hash,
    }


def _paths(root: Path, plan_id: str) -> Dict[str, str]:
    namespace = root / "_registry" / "curation" / "schema-migrations"
    return {
        "approval": str(namespace / "approvals" / plan_id / "approval.json"),
        "backup": str(
            namespace / "backups" / plan_id / "ledger-v1.sqlite3"
        ),
        "backup_manifest": str(
            namespace / "backups" / plan_id / "backup.json"
        ),
        "backup_attempts": str(namespace / "backups" / plan_id / "attempts"),
        "result": str(namespace / "runs" / plan_id / "result.json"),
    }


def _read_exact_artifact(path: Path, label: str) -> bytes:
    directory_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=SchemaMigrationError,
    )
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label=label,
            expected_mode=0o600,
            error_type=SchemaMigrationError,
        )
        if info.st_uid != os.getuid() or info.st_nlink != 1:
            raise SchemaMigrationError("%s ownership or link count is invalid" % label)
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=SchemaMigrationError,
        )
        return raw
    finally:
        os.close(directory_fd)


def _publish_or_verify(path: Path, encoded: bytes, label: str) -> None:
    if os.path.lexists(path):
        if _read_exact_artifact(path, label) != encoded:
            raise SchemaMigrationError("%s collision differs from sealed bytes" % label)
        return
    def verify_open_file(
        _path: Path,
        descriptor: int,
        _directory_fd: int,
    ) -> None:
        if safety.read_open_file_bytes(descriptor) != encoded:
            raise SchemaMigrationError("%s readback changed" % label)

    safety.publish_bytes_atomic_no_replace(
        path,
        encoded,
        label=label,
        mode=0o600,
        create_parent=True,
        collision_error="refusing to overwrite %s" % label,
        final_identity_error="%s final identity is invalid" % label,
        parent_error="%s parent is unsafe" % label,
        error_type=SchemaMigrationError,
        after_fd_readback=verify_open_file,
    )
    if _read_exact_artifact(path, label) != encoded:
        raise SchemaMigrationError("%s final readback changed" % label)


def _build_v1_plan(
    resources: Any,
    *,
    plan_id: str,
    requested_by: str,
) -> Dict[str, Any]:
    schema_state = ledger_runtime._require_exact_schema_preflight(
        resources.connection
    )
    if schema_state != "v1":
        raise SchemaMigrationError("preview requires the exact version-1 ledger")
    bootstrap_id = ledger_runtime._single_complete_bootstrap(
        resources.connection,
        resources.root,
        resources.placement_fd,
        resources.ledger_fd,
        resources.ledger_identity,
    )
    ledger_runtime._require_bootstrap_schema_binding(
        resources.connection,
        bootstrap_id,
        "v1",
    )
    approved, compiled, verify_policy = ledger_runtime._session_policy(
        resources,
        bootstrap_id,
    )
    if verify_policy() != approved:
        raise SchemaMigrationError("current policy binding changed")
    registry_info, registry_raw = ledger_runtime._read_registry(resources.root)
    if sha256_bytes(registry_raw) != approved.raw_hash:
        raise SchemaMigrationError("registry bytes do not match approved policy")
    source = {
        "bootstrap_id": bootstrap_id,
        "control_schema_sha256": control.CONTROL_SCHEMA_SHA256,
        "ledger": _stable_regular(
            resources.ledger_path,
            "curation ledger",
            expected_mode=0o600,
        ),
        "logical": _logical_identity(resources.connection),
        "policy": _policy_identity(approved),
        "registry": {
            "bytes": len(registry_raw),
            "device": registry_info.st_dev,
            "inode": registry_info.st_ino,
            "mode": "%04o" % stat.S_IMODE(registry_info.st_mode),
            "nlink": registry_info.st_nlink,
            "path": str(resources.root / "_registry" / "placement-map.yml"),
            "sha256": sha256_bytes(registry_raw),
            "uid": registry_info.st_uid,
        },
        "schema": _schema_identity(resources.connection),
        "schema_state": "v1",
    }
    body = {
        "approval_ready": False,
        "authority": "NONE_UNTIL_EXACT_APPROVAL_AND_APPLY",
        "kind": PLAN_KIND,
        "paths": _paths(resources.root, plan_id),
        "plan_id": plan_id,
        "raw_root": str(resources.root),
        "requested_by": requested_by,
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "target": {
            "migration_id": ledger_runtime.M2_MIGRATION_ID,
            "schema_sha256": ledger_schema.LEDGER_SCHEMA_SHA256,
            "schema_version": ledger_schema.LEDGER_SCHEMA_VERSION,
        },
    }
    body["plan_sha256"] = plan_sha256(body)
    return body


def preview_m2_migration(
    root: Path,
    *,
    plan_id: str,
    requested_by: str,
) -> Dict[str, Any]:
    """Compute an exact v1 migration plan without filesystem or DB writes."""

    canonical = _canonical_root(root)
    identity = _identifier(plan_id, "plan id")
    actor = _actor(requested_by, "requested_by")
    try:
        with ledger_runtime._open_runtime_resources(
            canonical,
            ledger_operation=fcntl.LOCK_SH,
            connector=_connect_immutable_preview,
            reader=True,
        ) as resources:
            return _build_v1_plan(
                resources,
                plan_id=identity,
                requested_by=actor,
            )
    except SchemaMigrationError:
        raise
    except ledger_runtime.LedgerRuntimeError as exc:
        raise SchemaMigrationError(str(exc)) from exc


def _approval_payload(plan: Dict[str, Any], approved_by: str) -> Dict[str, Any]:
    digest = plan_sha256(plan)
    approval_seed = canonical_json_bytes(
        {
            "approved_by": approved_by,
            "plan_id": plan["plan_id"],
            "plan_sha256": digest,
        }
    )
    approval_id = "m2mig-approval-" + sha256_bytes(approval_seed)[:24]
    return {
        "approval_id": approval_id,
        "approval_path": plan["paths"]["approval"],
        "approved_by": approved_by,
        "authority": "APPROVED_FOR_EXACT_M2_SCHEMA_MIGRATION",
        "kind": APPROVAL_KIND,
        "plan": plan,
        "plan_id": plan["plan_id"],
        "plan_sha256": digest,
        "schema_version": SCHEMA_VERSION,
    }


def approve_m2_migration(
    root: Path,
    *,
    plan_id: str,
    expected_plan_sha256: str,
    requested_by: str,
    approved_by: str,
) -> Dict[str, Any]:
    """Seal approval for the exact recomputed write-free preview."""

    canonical = _canonical_root(root)
    identity = _identifier(plan_id, "plan id")
    expected_hash = _hash(expected_plan_sha256, "expected plan hash")
    requester = _actor(requested_by, "requested_by")
    approver = _actor(approved_by, "approved_by")
    try:
        with ledger_runtime._open_runtime_resources(
            canonical,
            ledger_operation=fcntl.LOCK_EX,
            connector=ledger_runtime._connect,
            reader=False,
        ) as resources:
            plan = _build_v1_plan(
                resources,
                plan_id=identity,
                requested_by=requester,
            )
            if plan["plan_sha256"] != expected_hash:
                raise SchemaMigrationError("migration preview binding changed")
            payload = _approval_payload(plan, approver)
            encoded = canonical_json_bytes(payload)
            approval_path = Path(plan["paths"]["approval"])
            _publish_or_verify(
                approval_path,
                encoded,
                "M2 schema migration approval",
            )
            if _build_v1_plan(
                resources,
                plan_id=identity,
                requested_by=requester,
            ) != plan:
                raise SchemaMigrationError(
                    "migration source changed during approval publication"
                )
            return {
                "approval_id": payload["approval_id"],
                "approval_path": str(approval_path),
                "approval_sha256": sha256_bytes(encoded),
                "approved_by": approver,
                "kind": APPROVAL_KIND,
                "plan_id": identity,
                "plan_sha256": expected_hash,
                "schema_version": SCHEMA_VERSION,
            }
    except SchemaMigrationError:
        raise
    except ledger_runtime.LedgerRuntimeError as exc:
        raise SchemaMigrationError(str(exc)) from exc


def _canonical_object(encoded: bytes, label: str) -> Dict[str, Any]:
    if len(encoded) > 8 * 1024 * 1024:
        raise SchemaMigrationError("%s exceeds its byte bound" % label)
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SchemaMigrationError("%s is not canonical JSON" % label) from exc
    if type(value) is not dict or canonical_json_bytes(value) != encoded:
        raise SchemaMigrationError("%s is not canonical JSON" % label)
    return value


def _validate_sealed_plan(
    root: Path,
    plan: Dict[str, Any],
    *,
    plan_id: str,
    expected_plan_sha256: str,
    requested_by: str,
) -> None:
    expected_keys = {
        "approval_ready",
        "authority",
        "kind",
        "paths",
        "plan_id",
        "plan_sha256",
        "raw_root",
        "requested_by",
        "schema_version",
        "source",
        "target",
    }
    if (
        set(plan) != expected_keys
        or plan.get("schema_version") != SCHEMA_VERSION
        or plan.get("kind") != PLAN_KIND
        or plan.get("plan_id") != plan_id
        or plan.get("requested_by") != requested_by
        or plan.get("raw_root") != str(root)
        or plan.get("approval_ready") is not False
        or plan.get("authority") != "NONE_UNTIL_EXACT_APPROVAL_AND_APPLY"
        or plan.get("paths") != _paths(root, plan_id)
        or plan.get("target")
        != {
            "migration_id": ledger_runtime.M2_MIGRATION_ID,
            "schema_sha256": ledger_schema.LEDGER_SCHEMA_SHA256,
            "schema_version": ledger_schema.LEDGER_SCHEMA_VERSION,
        }
        or plan.get("plan_sha256") != expected_plan_sha256
        or plan_sha256(plan) != expected_plan_sha256
    ):
        raise SchemaMigrationError("sealed migration plan binding is invalid")
    source = plan.get("source")
    if (
        type(source) is not dict
        or source.get("schema_state") != "v1"
        or source.get("control_schema_sha256") != control.CONTROL_SCHEMA_SHA256
        or type(source.get("bootstrap_id")) is not str
        or type(source.get("ledger")) is not dict
        or type(source.get("logical")) is not dict
        or type(source.get("policy")) is not dict
        or type(source.get("registry")) is not dict
        or type(source.get("schema")) is not dict
    ):
        raise SchemaMigrationError("sealed migration source binding is invalid")


def _load_approval(
    root: Path,
    *,
    plan_id: str,
    expected_plan_sha256: str,
    requested_by: str,
    approval_id: str,
    approval_sha256: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    path = Path(_paths(root, plan_id)["approval"])
    encoded = _read_exact_artifact(path, "M2 schema migration approval")
    if sha256_bytes(encoded) != approval_sha256:
        raise SchemaMigrationError("migration approval hash changed")
    payload = _canonical_object(encoded, "M2 schema migration approval")
    if set(payload) != {
        "approval_id",
        "approval_path",
        "approved_by",
        "authority",
        "kind",
        "plan",
        "plan_id",
        "plan_sha256",
        "schema_version",
    }:
        raise SchemaMigrationError("migration approval fields are invalid")
    plan = payload.get("plan")
    if type(plan) is not dict:
        raise SchemaMigrationError("migration approval plan is missing")
    _validate_sealed_plan(
        root,
        plan,
        plan_id=plan_id,
        expected_plan_sha256=expected_plan_sha256,
        requested_by=requested_by,
    )
    if (
        payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("kind") != APPROVAL_KIND
        or payload.get("approval_id") != approval_id
        or payload.get("approval_path") != str(path)
        or payload.get("plan_id") != plan_id
        or payload.get("plan_sha256") != expected_plan_sha256
        or payload.get("authority")
        != "APPROVED_FOR_EXACT_M2_SCHEMA_MIGRATION"
        or type(payload.get("approved_by")) is not str
    ):
        raise SchemaMigrationError("migration approval binding is invalid")
    return payload, plan


def _require_no_sqlite_sidecars(path: Path, label: str) -> None:
    for suffix in ("-journal", "-shm", "-wal"):
        if os.path.lexists(Path(str(path) + suffix)):
            raise SchemaMigrationError(
                "%s has an unexpected SQLite sidecar: %s" % (label, suffix)
            )


def _validate_v1_backup(
    path: Path,
    plan: Dict[str, Any],
    *,
    allow_stale_sidecars: bool = False,
) -> Dict[str, Any]:
    if not allow_stale_sidecars:
        _require_no_sqlite_sidecars(path, "M2 schema migration backup")
    record = _stable_regular(
        path,
        "M2 schema migration backup",
        expected_mode=0o600,
    )
    try:
        connection = sqlite3.connect(
            path.as_uri() + "?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        raise SchemaMigrationError("cannot open M2 schema migration backup") from exc
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).upper() != "DELETE":
            raise SchemaMigrationError("migration backup is not standalone DELETE mode")
        state = ledger_runtime._require_exact_schema_preflight(connection)
        if state != "v1":
            raise SchemaMigrationError("migration backup is not exact version 1")
        ledger_runtime._require_bootstrap_schema_binding(
            connection,
            plan["source"]["bootstrap_id"],
            "v1",
        )
        if _logical_identity(connection) != plan["source"]["logical"]:
            raise SchemaMigrationError("migration backup source binding changed")
    except (ledger_runtime.LedgerRuntimeError, sqlite3.Error) as exc:
        raise SchemaMigrationError("migration backup validation failed") from exc
    finally:
        connection.close()
    return record


def _new_backup_attempt(attempts_root: Path) -> Tuple[Path, int, int]:
    directory_fd = safety.open_or_create_verified_directory(
        attempts_root,
        mode=0o700,
        error_type=SchemaMigrationError,
    )
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for attempt in range(1, 1001):
        name = ".incomplete-ledger-v1-%04d.sqlite3" % attempt
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            continue
        info = os.fstat(descriptor)
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            os.close(descriptor)
            os.close(directory_fd)
            raise SchemaMigrationError("backup attempt identity is invalid")
        return attempts_root / name, descriptor, directory_fd
    os.close(directory_fd)
    raise SchemaMigrationError("backup attempt bound is exhausted")


def _backup_database(
    source: sqlite3.Connection,
    destination: sqlite3.Connection,
) -> None:
    source.backup(destination)


def _backup_manifest_payload(
    plan: Dict[str, Any],
    backup: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "backup": backup,
        "kind": "MNEMOSYNE_M2_SCHEMA_MIGRATION_BACKUP",
        "plan_id": plan["plan_id"],
        "plan_sha256": plan["plan_sha256"],
        "schema_version": SCHEMA_VERSION,
        "source_logical_sha256": plan["source"]["logical"]["sha256"],
        "source_schema_sha256": control.CONTROL_SCHEMA_SHA256,
        "source_schema_version": control.CONTROL_SCHEMA_VERSION,
        "status": "COMPLETE",
    }


def _seal_or_validate_backup(
    plan: Dict[str, Any],
) -> Dict[str, Any]:
    backup_path = Path(plan["paths"]["backup"])
    backup = _validate_v1_backup(backup_path, plan)
    manifest_path = Path(plan["paths"]["backup_manifest"])
    encoded = canonical_json_bytes(_backup_manifest_payload(plan, backup))
    _publish_or_verify(
        manifest_path,
        encoded,
        "M2 schema migration backup manifest",
    )
    if _read_exact_artifact(
        manifest_path,
        "M2 schema migration backup manifest",
    ) != encoded:
        raise SchemaMigrationError("migration backup manifest readback changed")
    return backup


def _materialize_backup(
    source: sqlite3.Connection,
    plan: Dict[str, Any],
    *,
    checkpoint: Optional[Callable[[str], None]],
) -> Dict[str, Any]:
    backup_path = Path(plan["paths"]["backup"])
    if os.path.lexists(backup_path):
        return _seal_or_validate_backup(plan)
    attempt_path, descriptor, attempts_fd = _new_backup_attempt(
        Path(plan["paths"]["backup_attempts"])
    )
    destination: Optional[sqlite3.Connection] = None
    try:
        before = os.fstat(descriptor)
        destination = sqlite3.connect(
            attempt_path.as_uri() + "?mode=rw",
            uri=True,
            isolation_level=None,
        )
        current = attempt_path.lstat()
        if (
            (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_uid != os.getuid()
            or current.st_nlink != 1
        ):
            raise SchemaMigrationError("backup attempt changed before SQLite backup")
        destination.execute("PRAGMA synchronous = FULL")
        _backup_database(source, destination)
        destination.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        journal_mode = destination.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
        if str(journal_mode).upper() != "DELETE":
            raise SchemaMigrationError("backup journal mode could not be normalized")
        destination.close()
        destination = None
        after = os.fstat(descriptor)
        lexical = attempt_path.lstat()
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or (lexical.st_dev, lexical.st_ino) != (before.st_dev, before.st_ino)
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_uid != os.getuid()
            or after.st_nlink != 1
        ):
            raise SchemaMigrationError("backup attempt identity changed")
        os.fsync(descriptor)
        os.fsync(attempts_fd)
    except SchemaMigrationError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise SchemaMigrationError("SQLite backup API failed") from exc
    finally:
        if destination is not None:
            destination.close()
        os.close(descriptor)
        os.close(attempts_fd)
    _validate_v1_backup(attempt_path, plan, allow_stale_sidecars=True)
    if checkpoint is not None:
        checkpoint("backup-attempt-ready")
    safety.rename_path_no_replace(
        attempt_path,
        backup_path,
        collision_error="M2 schema migration backup already exists",
        require_directory=False,
        error_type=SchemaMigrationError,
    )
    return _seal_or_validate_backup(plan)


def _require_current_policy_for_plan(
    resources: Any,
    plan: Dict[str, Any],
    schema_state: str,
) -> None:
    bootstrap_id = ledger_runtime._single_complete_bootstrap(
        resources.connection,
        resources.root,
        resources.placement_fd,
        resources.ledger_fd,
        resources.ledger_identity,
    )
    if bootstrap_id != plan["source"]["bootstrap_id"]:
        raise SchemaMigrationError("migration bootstrap binding changed")
    ledger_runtime._require_bootstrap_schema_binding(
        resources.connection,
        bootstrap_id,
        schema_state,
    )
    approved, _compiled, verify_policy = ledger_runtime._session_policy(
        resources,
        bootstrap_id,
    )
    if (
        _policy_identity(approved) != plan["source"]["policy"]
        or _policy_identity(verify_policy()) != plan["source"]["policy"]
    ):
        raise SchemaMigrationError("migration policy binding changed")


def _result_payload(
    plan: Dict[str, Any],
    approval: Dict[str, Any],
    *,
    approval_sha256: str,
    backup: Dict[str, Any],
    executed_by: str,
) -> Dict[str, Any]:
    return {
        "approval_id": approval["approval_id"],
        "approval_sha256": approval_sha256,
        "backup": backup,
        "executed_by": executed_by,
        "kind": RESULT_KIND,
        "migration_id": ledger_runtime.M2_MIGRATION_ID,
        "plan_id": plan["plan_id"],
        "plan_sha256": plan["plan_sha256"],
        "result_path": plan["paths"]["result"],
        "schema_version": SCHEMA_VERSION,
        "source_logical_sha256": plan["source"]["logical"]["sha256"],
        "status": "COMPLETE",
        "target_schema_sha256": ledger_schema.LEDGER_SCHEMA_SHA256,
        "target_schema_version": ledger_schema.LEDGER_SCHEMA_VERSION,
    }


def apply_m2_migration(
    root: Path,
    *,
    plan_id: str,
    expected_plan_sha256: str,
    requested_by: str,
    approval_id: str,
    approval_sha256: str,
    executed_by: str,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Backup exact v1, migrate once, and seal an exact resumable result."""

    canonical = _canonical_root(root)
    identity = _identifier(plan_id, "plan id")
    expected_hash = _hash(expected_plan_sha256, "expected plan hash")
    requester = _actor(requested_by, "requested_by")
    approval_identity = _identifier(approval_id, "approval id")
    approval_hash = _hash(approval_sha256, "approval hash")
    executor = _actor(executed_by, "executed_by")
    if checkpoint is not None and not callable(checkpoint):
        raise TypeError("checkpoint must be callable")
    try:
        with ledger_runtime._open_runtime_resources(
            canonical,
            ledger_operation=fcntl.LOCK_EX,
            connector=ledger_runtime._connect,
            reader=False,
        ) as resources:
            approval, plan = _load_approval(
                canonical,
                plan_id=identity,
                expected_plan_sha256=expected_hash,
                requested_by=requester,
                approval_id=approval_identity,
                approval_sha256=approval_hash,
            )
            resources.verify_locks()
            ledger_runtime._install_commit_lock_guard(
                resources.connection,
                resources.verify_locks,
            )
            schema_state = ledger_runtime._require_exact_schema_preflight(
                resources.connection
            )
            if schema_state == "v1":
                recomputed = _build_v1_plan(
                    resources,
                    plan_id=identity,
                    requested_by=requester,
                )
                if recomputed != plan:
                    raise SchemaMigrationError("migration source bytes changed")
            elif schema_state == "v2":
                _require_current_policy_for_plan(resources, plan, "v2")
            else:
                raise SchemaMigrationError("migration source schema is unsupported")

            backup = _materialize_backup(
                resources.connection,
                plan,
                checkpoint=checkpoint,
            )
            if checkpoint is not None:
                checkpoint("backup-published")

            if schema_state == "v1":
                if _build_v1_plan(
                    resources,
                    plan_id=identity,
                    requested_by=requester,
                ) != plan:
                    raise SchemaMigrationError(
                        "migration source changed after backup readback"
                    )
                resources.verify_locks()
                ledger_schema.ensure_v2_schema(
                    resources.connection,
                    migration_id=ledger_runtime.M2_MIGRATION_ID,
                )
                schema_state = "v2"
                if checkpoint is not None:
                    checkpoint("migration-committed")

            resources.verify_locks()
            ledger_schema.verify_v2_schema(resources.connection)
            _require_current_policy_for_plan(resources, plan, "v2")
            if _validate_v1_backup(Path(plan["paths"]["backup"]), plan) != backup:
                raise SchemaMigrationError("migration backup changed after schema delta")
            payload = _result_payload(
                plan,
                approval,
                approval_sha256=approval_hash,
                backup=backup,
                executed_by=executor,
            )
            encoded = canonical_json_bytes(payload)
            result_path = Path(plan["paths"]["result"])
            _publish_or_verify(
                result_path,
                encoded,
                "M2 schema migration result",
            )
            if checkpoint is not None:
                checkpoint("result-published")
            ledger_schema.verify_v2_schema(resources.connection)
            return {
                "approval_id": approval_identity,
                "backup_path": plan["paths"]["backup"],
                "kind": RESULT_KIND,
                "plan_id": identity,
                "result_path": str(result_path),
                "result_sha256": sha256_bytes(encoded),
                "schema_version": SCHEMA_VERSION,
                "status": "COMPLETE",
            }
    except SchemaMigrationError:
        raise
    except (
        ledger_runtime.LedgerRuntimeError,
        ledger_schema.LedgerSchemaError,
        sqlite3.Error,
    ) as exc:
        raise SchemaMigrationError(str(exc)) from exc


__all__ = [
    "APPROVAL_KIND",
    "PLAN_KIND",
    "RESULT_KIND",
    "SCHEMA_VERSION",
    "SchemaMigrationError",
    "approve_m2_migration",
    "apply_m2_migration",
    "plan_bytes",
    "plan_sha256",
    "preview_m2_migration",
]
