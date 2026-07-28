"""Verified lifetime writer session for the Mnemosyne curation ledger."""

from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from . import (
    activation_contract,
    activation_foundation,
    activation_markers,
    admission,
    control,
    ledger_schema,
    m3_schema,
    policy,
    policy_authority,
    safety,
)
from .canonical_json import sha256_bytes
from .canonical_json import canonical_json_bytes
from .operation_contract import codec as operation_codec


M2_MIGRATION_ID = "document-curation-m2-v2"
DEFAULT_WRITER_OBSERVER = "mnemosyne-writer-session"


class LedgerRuntimeError(RuntimeError):
    """The live curation ledger cannot grant an exact writer session."""


class PolicyAdmissionError(LedgerRuntimeError):
    """The live placement policy cannot admit a policy-bound session."""


class FoundationKind(str, Enum):
    """Closed, verified foundation identity exposed to runtime consumers."""

    LEGACY_BOOTSTRAP = "LEGACY_BOOTSTRAP"
    SAFE_LIBRARIAN_ACTIVATION_V1 = "SAFE_LIBRARIAN_ACTIVATION_V1"
    LOCAL_SQLITE = "LOCAL_SQLITE"


@dataclass(frozen=True)
class _LegacyBootstrapFoundation:
    bootstrap_id: str
    schema_state: str


@dataclass(frozen=True)
class _SafeLibrarianActivationV1Foundation:
    plan: activation_foundation.ActivationFoundationPlan
    policy_source: policy_authority.ActivationInitialPolicySource


@dataclass(frozen=True)
class _LocalSQLiteFoundation:
    schema_state: str


_FoundationEvidence = (
    _LegacyBootstrapFoundation
    | _SafeLibrarianActivationV1Foundation
    | _LocalSQLiteFoundation
)


LOCAL_RUNTIME_MODE = "local-sqlite-v1"
LOCAL_RUNTIME_MODE_PATH = "_registry/curation/runtime-mode"


def _require_observed_by(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError("observed_by is invalid")
    return value


class WriterSession:
    """Active writer capability backed by already-held lifetime locks."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        approved_policy_ref: admission.ApprovedPolicyRef,
        compiled_policy: policy.CompiledPolicy,
        foundation_kind: FoundationKind,
        policy_verifier: Callable[[], admission.ApprovedPolicyRef],
        lock_verifier: Callable[[], None],
    ) -> None:
        self.connection = connection
        self.approved_policy_ref = approved_policy_ref
        self.compiled_policy = compiled_policy
        self.foundation_kind = foundation_kind
        self._policy_verifier = policy_verifier
        self._lock_verifier = lock_verifier
        self._active = True
        self._thread_id = threading.get_ident()
        self._placement_depth = 0
        self._ledger_depth = 0

    def _require_active_thread(self) -> None:
        if not self._active:
            raise LedgerRuntimeError("writer session is not active")
        if threading.get_ident() != self._thread_id:
            raise LedgerRuntimeError("writer session cannot cross threads")
        self._lock_verifier()

    def current_policy(self) -> admission.ApprovedPolicyRef:
        self._require_active_thread()
        observed = self._policy_verifier()
        if observed != self.approved_policy_ref:
            raise PolicyAdmissionError("current approved policy binding changed")
        return observed

    @contextmanager
    def placement_shared(self) -> Iterator[None]:
        self._require_active_thread()
        self._placement_depth += 1
        try:
            yield
        finally:
            try:
                if self._active:
                    self._lock_verifier()
            finally:
                self._placement_depth -= 1

    @contextmanager
    def ledger_exclusive(self) -> Iterator[None]:
        self._require_active_thread()
        if self._placement_depth < 1:
            raise LedgerRuntimeError(
                "ledger_exclusive requires an active placement_shared guard"
            )
        self._ledger_depth += 1
        try:
            yield
        finally:
            try:
                if self._active:
                    self._lock_verifier()
            finally:
                self._ledger_depth -= 1

    def _deactivate(self) -> None:
        guard_leaked = bool(self._placement_depth or self._ledger_depth)
        self._active = False
        self.connection.set_authorizer(None)
        if guard_leaked:
            raise LedgerRuntimeError("writer guard is still active at session close")


class ReaderSession:
    """Active read-only capability backed by both shared lifetime locks."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        approved_policy_ref: admission.ApprovedPolicyRef,
        compiled_policy: policy.CompiledPolicy,
        foundation_kind: FoundationKind,
        policy_verifier: Callable[[], admission.ApprovedPolicyRef],
        lock_verifier: Callable[[], None],
    ) -> None:
        self.connection = connection
        self.approved_policy_ref = approved_policy_ref
        self.compiled_policy = compiled_policy
        self.foundation_kind = foundation_kind
        self._policy_verifier = policy_verifier
        self._lock_verifier = lock_verifier
        self._active = True
        self._thread_id = threading.get_ident()

    def _require_active_thread(self) -> None:
        if not self._active:
            raise LedgerRuntimeError("reader session is not active")
        if threading.get_ident() != self._thread_id:
            raise LedgerRuntimeError("reader session cannot cross threads")
        self._lock_verifier()

    def current_policy(self) -> admission.ApprovedPolicyRef:
        self._require_active_thread()
        observed = self._policy_verifier()
        if observed != self.approved_policy_ref:
            raise PolicyAdmissionError("current approved policy binding changed")
        return observed

    def _deactivate(self) -> None:
        self._active = False


def _canonical_root(root: Path) -> Path:
    candidate = Path(root)
    if not candidate.is_absolute() or any(
        part in (".", "..") for part in candidate.parts
    ):
        raise LedgerRuntimeError("raw root is not a canonical absolute path")
    descriptor = safety.open_verified_directory(
        candidate,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    os.close(descriptor)
    return candidate


def _open_lock(path: Path, label: str, operation: int) -> int:
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    descriptor: Optional[int] = None
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lexical = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (lexical.st_dev, lexical.st_ino)
        ):
            raise LedgerRuntimeError("%s identity is invalid" % label)
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LedgerRuntimeError("%s is busy" % label) from exc
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            label,
            error_type=LedgerRuntimeError,
        )
        return descriptor
    except LedgerRuntimeError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise LedgerRuntimeError("%s identity is invalid" % label) from exc
    finally:
        os.close(parent_fd)


def _require_lock_identity(path: Path, descriptor: int, label: str) -> None:
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    try:
        try:
            lexical = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise LedgerRuntimeError("%s identity changed" % label) from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (lexical.st_dev, lexical.st_ino)
        ):
            raise LedgerRuntimeError("%s identity changed" % label)
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            label,
            error_type=LedgerRuntimeError,
        )
    finally:
        os.close(parent_fd)


def _require_curation_directory(root: Path) -> None:
    path = root / "_registry" / "curation"
    descriptor = safety.open_verified_directory(
        path,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise LedgerRuntimeError("curation control root mode is invalid")
        safety.require_same_directory_identity(
            path,
            descriptor,
            "curation control root",
            error_type=LedgerRuntimeError,
        )
    finally:
        os.close(descriptor)


def _verify_file_identity_record(record: object, label: str) -> bytes:
    if not isinstance(record, dict) or set(record) != {
        "path",
        "sha256",
        "device",
        "inode",
        "mode",
        "uid",
        "nlink",
    }:
        raise LedgerRuntimeError("%s identity binding is invalid" % label)
    path_value = record.get("path")
    mode_value = record.get("mode")
    if (
        not isinstance(path_value, str)
        or not Path(path_value).is_absolute()
        or not isinstance(mode_value, str)
        or len(mode_value) != 4
        or any(character not in "01234567" for character in mode_value)
    ):
        raise LedgerRuntimeError("%s identity binding is invalid" % label)
    path = Path(path_value)
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    try:
        info, raw = safety.read_regular_file_at(
            parent_fd,
            path.name,
            path,
            label=label,
            expected_mode=int(mode_value, 8),
            error_type=LedgerRuntimeError,
        )
        if (
            sha256_bytes(raw) != record.get("sha256")
            or info.st_dev != record.get("device")
            or info.st_ino != record.get("inode")
            or info.st_uid != record.get("uid")
            or info.st_nlink != record.get("nlink")
        ):
            raise LedgerRuntimeError("%s identity changed" % label)
        return raw
    finally:
        os.close(parent_fd)


def _database_identity(
    path: Path,
    *,
    activation_foundation: Optional[bool] = False,
) -> Tuple[int, int]:
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    descriptor: Optional[int] = None
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lexical = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise LedgerRuntimeError("curation ledger identity is invalid")
        header = os.read(descriptor, 100)
        expected_header_modes = (
            {b"\x01\x01", b"\x02\x02"}
            if activation_foundation is None
            else {b"\x01\x01" if activation_foundation else b"\x02\x02"}
        )
        if (
            len(header) != 100
            or header[:16] != b"SQLite format 3\x00"
            or header[18:20] not in expected_header_modes
        ):
            raise LedgerRuntimeError("curation ledger header is invalid")
        final = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (info.st_dev, info.st_ino):
            raise LedgerRuntimeError("curation ledger identity changed during open")
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            "curation ledger",
            error_type=LedgerRuntimeError,
        )
        return info.st_dev, info.st_ino
    except LedgerRuntimeError:
        raise
    except OSError as exc:
        raise LedgerRuntimeError("curation ledger identity is invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _require_database_identity(
    path: Path,
    identity: Tuple[int, int],
    *,
    phase: str,
) -> None:
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise LedgerRuntimeError(
            "curation ledger identity changed %s" % phase
        ) from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.getuid()
        or stat.S_IMODE(current.st_mode) != 0o600
        or current.st_nlink != 1
        or (current.st_dev, current.st_ino) != identity
    ):
        raise LedgerRuntimeError("curation ledger identity changed %s" % phase)


def _connect(path: Path, identity: Tuple[int, int]) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(
            path.as_uri() + "?mode=rw",
            uri=True,
            isolation_level=None,
            # The dynamic COMMIT authorizer must run for every transaction;
            # reusing a previously authorized cached COMMIT would bypass it.
            cached_statements=0,
        )
    except sqlite3.Error as exc:
        raise LedgerRuntimeError("cannot open curation ledger for writing") from exc
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = %d" % control.BUSY_TIMEOUT_MS)
        _require_database_identity(
            path,
            identity,
            phase="while opening writer",
        )
        return connection
    except Exception:
        connection.close()
        raise


def _connect_readonly(
    path: Path,
    identity: Tuple[int, int],
) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(
            path.as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        raise LedgerRuntimeError("cannot open curation ledger read-only") from exc
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = %d" % control.BUSY_TIMEOUT_MS)
        _require_database_identity(
            path,
            identity,
            phase="while opening reader",
        )
        return connection
    except Exception:
        connection.close()
        raise


def _connect_immutable_readonly(
    path: Path,
    identity: Tuple[int, int],
) -> sqlite3.Connection:
    """Open a stable reader without creating SQLite WAL sidecar files."""

    wal_path = Path(str(path) + "-wal")
    try:
        if os.path.lexists(wal_path) and os.stat(
            wal_path,
            follow_symlinks=False,
        ).st_size:
            raise LedgerRuntimeError(
                "immutable reader requires a checkpointed curation ledger"
            )
        connection = sqlite3.connect(
            path.as_uri() + "?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
    except LedgerRuntimeError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise LedgerRuntimeError(
            "cannot open immutable curation ledger reader"
        ) from exc
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = %d" % control.BUSY_TIMEOUT_MS)
        _require_database_identity(
            path,
            identity,
            phase="while opening immutable reader",
        )
        return connection
    except Exception:
        connection.close()
        raise


def _single_complete_bootstrap(
    connection: sqlite3.Connection,
    root: Path,
    placement_fd: int,
    ledger_fd: int,
    ledger_identity: Tuple[int, int],
) -> str:
    rows = connection.execute(
        "SELECT * FROM control_bootstraps ORDER BY bootstrap_id"
    ).fetchall()
    if len(rows) != 1 or rows[0]["state"] != "COMPLETE":
        raise LedgerRuntimeError("exactly one COMPLETE control bootstrap is required")
    row = rows[0]
    bootstrap_id = row["bootstrap_id"]
    final = root / "_registry" / "curation"
    ledger_path = final / "ledger.sqlite3"
    ledger_lock_path = final / "ledger.lock"
    placement_path = root / "_registry" / "placement-map.lock"
    placement_info = os.fstat(placement_fd)
    ledger_lock_info = os.fstat(ledger_fd)
    placement_raw = safety.read_open_file_bytes(placement_fd)
    ledger_lock_raw = safety.read_open_file_bytes(ledger_fd)
    if (
        row["schema_sha256"] != control.CONTROL_SCHEMA_SHA256
        or row["final_path"] != str(final)
        or row["ledger_path"] != str(ledger_path)
        or row["ledger_lock_path"] != str(ledger_lock_path)
        or row["placement_lock_path"] != str(placement_path)
        or row["terminal_journal_mode"] != "WAL"
        or row["wal_checkpoint_status"] != "FULL"
        or row["logical_readback_sha256"] is None
        or (row["placement_lock_device"], row["placement_lock_inode"])
        != (placement_info.st_dev, placement_info.st_ino)
        or (row["ledger_lock_device"], row["ledger_lock_inode"])
        != (ledger_lock_info.st_dev, ledger_lock_info.st_ino)
        or (row["ledger_device"], row["ledger_inode"]) != ledger_identity
        or os.path.lexists(row["staging_path"])
    ):
        raise LedgerRuntimeError("COMPLETE control bootstrap binding is invalid")
    if ledger_lock_raw != b"":
        raise LedgerRuntimeError("control ledger lock content is invalid")
    if sha256_bytes(placement_raw) != row["placement_lock_sha256"]:
        raise LedgerRuntimeError("placement lock evidence changed")
    try:
        manifest = control._verify_manifest_for_row(row, bootstrap_id)
        logical_sha256 = control._logical_readback_sha256(connection, bootstrap_id)
    except (control.ControlBootstrapError, sqlite3.Error) as exc:
        raise LedgerRuntimeError("COMPLETE control bootstrap evidence changed") from exc
    if (
        manifest.get("raw_root") != str(root)
        or manifest.get("settings")
        != {
            "foreign_keys": True,
            "synchronous": "FULL",
            "busy_timeout_ms": control.BUSY_TIMEOUT_MS,
            "staging_journal_mode": "DELETE",
            "terminal_journal_mode": "WAL",
        }
        or manifest.get("modes")
        != {
            "directory": "0700",
            "ledger": "0600",
            "ledger_lock": "0600",
            "manifest": "0600",
        }
    ):
        raise LedgerRuntimeError("COMPLETE control bootstrap manifest changed")
    placement_record = manifest.get("placement_lock")
    completed = manifest.get("completed_lock_migration")
    completed_record = completed.get("result") if isinstance(completed, dict) else None
    if (
        not isinstance(placement_record, dict)
        or placement_record.get("path") != row["placement_lock_path"]
        or placement_record.get("sha256") != row["placement_lock_sha256"]
        or not isinstance(completed, dict)
        or completed.get("id") != row["completed_migration_id"]
        or not isinstance(completed_record, dict)
        or completed_record.get("path") != row["completed_result_path"]
        or completed_record.get("sha256") != row["completed_result_sha256"]
    ):
        raise LedgerRuntimeError("COMPLETE control bootstrap provenance changed")
    if _verify_file_identity_record(
        placement_record,
        "placement lock evidence",
    ) != placement_raw:
        raise LedgerRuntimeError("placement lock evidence changed")
    _verify_file_identity_record(
        completed_record,
        "completed lock migration result",
    )
    if logical_sha256 != row["logical_readback_sha256"]:
        raise LedgerRuntimeError("COMPLETE control bootstrap readback changed")
    return bootstrap_id


def _schema_rows(connection: sqlite3.Connection) -> list[Tuple[object, ...]]:
    try:
        return [
            tuple(row)
            for row in connection.execute(
                "SELECT version, schema_sha256, applied_by_bootstrap_id "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
    except sqlite3.Error as exc:
        raise LedgerRuntimeError("curation ledger schema binding is unknown") from exc


def _require_exact_schema_preflight(connection: sqlite3.Connection) -> str:
    rows = _schema_rows(connection)
    if len(rows) == 1 and rows[0][:2] == (
        control.CONTROL_SCHEMA_VERSION,
        control.CONTROL_SCHEMA_SHA256,
    ):
        try:
            control._verify_schema(connection)
        except control.ControlBootstrapError as exc:
            raise LedgerRuntimeError("curation ledger v1 schema is not exact") from exc
        schema_state = "v1"
    elif (
        len(rows) == 2
        and rows[0][:2]
        == (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256)
        and rows[1]
        == (
            ledger_schema.LEDGER_SCHEMA_VERSION,
            ledger_schema.LEDGER_SCHEMA_SHA256,
            M2_MIGRATION_ID,
        )
    ):
        try:
            ledger_schema.verify_v2_schema(connection)
        except ledger_schema.LedgerSchemaError as exc:
            raise LedgerRuntimeError("curation ledger v2 schema is not exact") from exc
        schema_state = "v2"
    elif (
        len(rows) == 3
        and rows[0][:2]
        == (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256)
        and rows[1]
        == (
            ledger_schema.LEDGER_SCHEMA_VERSION,
            ledger_schema.LEDGER_SCHEMA_SHA256,
            M2_MIGRATION_ID,
        )
        and rows[2]
        == (
            m3_schema.M3_SCHEMA_VERSION,
            m3_schema.M3_SCHEMA_SHA256,
            m3_schema.M3_MIGRATION_ID,
        )
    ):
        try:
            m3_schema.verify_v3_schema(connection)
        except m3_schema.M3SchemaError as exc:
            raise LedgerRuntimeError("curation ledger v3 schema is not exact") from exc
        schema_state = "v3"
    else:
        raise LedgerRuntimeError("curation ledger schema binding is unknown")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise LedgerRuntimeError("SQLite foreign keys are disabled")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise LedgerRuntimeError("SQLite foreign key check failed")
    if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [
        ("ok",)
    ]:
        raise LedgerRuntimeError("SQLite integrity check failed")
    return schema_state


def _require_bootstrap_schema_binding(
    connection: sqlite3.Connection,
    bootstrap_id: str,
    schema_state: str,
) -> None:
    expected_v1 = [
        (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256, bootstrap_id)
    ]
    if schema_state == "v1":
        expected = expected_v1
    elif schema_state in ("v2", "v3"):
        expected = expected_v1 + [
            (
                ledger_schema.LEDGER_SCHEMA_VERSION,
                ledger_schema.LEDGER_SCHEMA_SHA256,
                M2_MIGRATION_ID,
            )
        ]
        if schema_state == "v3":
            expected += [
                (
                    m3_schema.M3_SCHEMA_VERSION,
                    m3_schema.M3_SCHEMA_SHA256,
                    m3_schema.M3_MIGRATION_ID,
                )
            ]
    else:
        raise LedgerRuntimeError("curation ledger schema binding is unknown")
    if _schema_rows(connection) != expected:
        raise LedgerRuntimeError("curation ledger schema bootstrap binding is invalid")


def _install_commit_lock_guard(
    connection: sqlite3.Connection,
    commit_verifier: Callable[[], object],
) -> None:
    def authorize(
        action: int,
        argument1: Optional[str],
        _argument2: Optional[str],
        _database: Optional[str],
        _trigger: Optional[str],
    ) -> int:
        if (
            action == sqlite3.SQLITE_TRANSACTION
            and isinstance(argument1, str)
            and argument1.upper() == "COMMIT"
        ):
            try:
                commit_verifier()
            except BaseException:
                return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    connection.set_authorizer(authorize)


def _ensure_exact_v2(
    connection: sqlite3.Connection,
    *,
    bootstrap_id: str,
) -> None:
    v1 = [
        (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256, bootstrap_id)
    ]
    v2 = v1 + [
        (
            ledger_schema.LEDGER_SCHEMA_VERSION,
            ledger_schema.LEDGER_SCHEMA_SHA256,
            M2_MIGRATION_ID,
        )
    ]
    v3 = v2 + [
        (
            m3_schema.M3_SCHEMA_VERSION,
            m3_schema.M3_SCHEMA_SHA256,
            m3_schema.M3_MIGRATION_ID,
        )
    ]
    rows = _schema_rows(connection)
    if rows == v1:
        raise LedgerRuntimeError(
            "v1 ledger requires the explicit schema migration workflow"
        )
    if rows == v3:
        try:
            m3_schema.verify_v3_schema(connection)
        except m3_schema.M3SchemaError as exc:
            raise LedgerRuntimeError("curation ledger v3 schema is not exact") from exc
        return
    if rows != v2:
        raise LedgerRuntimeError("curation ledger schema binding is unknown")
    try:
        ledger_schema.verify_v2_schema(connection)
    except ledger_schema.LedgerSchemaError as exc:
        raise LedgerRuntimeError("curation ledger v2 schema is not exact") from exc


def _require_exact_v2_reader(
    connection: sqlite3.Connection,
    *,
    bootstrap_id: str,
) -> None:
    expected = [
        (
            control.CONTROL_SCHEMA_VERSION,
            control.CONTROL_SCHEMA_SHA256,
            bootstrap_id,
        ),
        (
            ledger_schema.LEDGER_SCHEMA_VERSION,
            ledger_schema.LEDGER_SCHEMA_SHA256,
            M2_MIGRATION_ID,
        ),
    ]
    expected_v3 = expected + [
        (
            m3_schema.M3_SCHEMA_VERSION,
            m3_schema.M3_SCHEMA_SHA256,
            m3_schema.M3_MIGRATION_ID,
        )
    ]
    rows = _schema_rows(connection)
    if rows == expected_v3:
        try:
            m3_schema.verify_v3_schema(connection)
        except m3_schema.M3SchemaError as exc:
            raise LedgerRuntimeError("reader requires exact v3 ledger") from exc
        return
    if rows != expected:
        raise LedgerRuntimeError(
            "reader requires exact v2 ledger; migration is forbidden"
        )
    try:
        ledger_schema.verify_v2_schema(connection)
    except ledger_schema.LedgerSchemaError as exc:
        raise LedgerRuntimeError("reader requires exact v2 ledger") from exc


def _read_registry(root: Path) -> Tuple[os.stat_result, bytes]:
    path = root / "_registry" / "placement-map.yml"
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    try:
        info, raw = safety.read_regular_file_at(
            parent_fd,
            path.name,
            path,
            label="placement registry",
            expected_mode=None,
            error_type=LedgerRuntimeError,
        )
        if info.st_uid != os.getuid() or info.st_nlink != 1:
            raise LedgerRuntimeError("placement registry ownership is invalid")
        return info, raw
    finally:
        os.close(parent_fd)


def _local_runtime_enabled(root: Path) -> bool:
    path = root / LOCAL_RUNTIME_MODE_PATH
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise LedgerRuntimeError("local curation runtime mode is unavailable") from exc
    if raw != (LOCAL_RUNTIME_MODE + "\n").encode("ascii"):
        raise LedgerRuntimeError("local curation runtime mode is invalid")
    return True


def _compile_local_policy(registry_raw: bytes, root: Path) -> policy.CompiledPolicy:
    try:
        return policy.compile_policy(registry_raw, str(root))
    except policy.PolicyError as original_error:
        try:
            postimage = policy.build_additive_curation_postimage(
                registry_raw,
                str(root),
            )
            return policy.compile_policy(postimage, str(root))
        except (TypeError, ValueError, policy.PolicyError) as exc:
            raise PolicyAdmissionError("local placement registry is invalid") from original_error


def _require_local_schema(connection: sqlite3.Connection) -> str:
    rows = _schema_rows(connection)
    if not rows or rows[0][:2] != (
        control.CONTROL_SCHEMA_VERSION,
        control.CONTROL_SCHEMA_SHA256,
    ):
        raise LedgerRuntimeError("local curation ledger schema is unknown")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise LedgerRuntimeError("local curation SQLite foreign keys are disabled")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise LedgerRuntimeError("local curation SQLite foreign key check failed")
    if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [
        ("ok",)
    ]:
        raise LedgerRuntimeError("local curation SQLite integrity check failed")
    if len(rows) == 1:
        return "v1"
    if rows[1][:2] != (
        ledger_schema.LEDGER_SCHEMA_VERSION,
        ledger_schema.LEDGER_SCHEMA_SHA256,
    ):
        raise LedgerRuntimeError("local curation ledger schema is unknown")
    try:
        ledger_schema.verify_v2_schema(connection)
    except ledger_schema.LedgerSchemaError as exc:
        raise LedgerRuntimeError("local curation ledger v2 schema is invalid") from exc
    if len(rows) == 2:
        return "v2"
    if len(rows) == 3 and rows[2][:2] == (
        m3_schema.M3_SCHEMA_VERSION,
        m3_schema.M3_SCHEMA_SHA256,
    ):
        try:
            m3_schema.verify_v3_schema(connection)
        except m3_schema.M3SchemaError as exc:
            raise LedgerRuntimeError("local curation ledger v3 schema is invalid") from exc
        return "v3"
    raise LedgerRuntimeError("local curation ledger schema is unknown")


def _entry_present(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise LedgerRuntimeError("foundation marker is unavailable") from exc
    return True


def _activation_marker_evidence(
    root: Path,
) -> activation_markers.ActivationMarkerEvidence:
    """Return the one shared, closed activation marker classification."""

    registry_path = root / "_registry"
    registry_fd = safety.open_verified_directory(
        registry_path,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    try:
        try:
            return activation_markers.classify_activation_markers(
                registry_fd,
                root,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise LedgerRuntimeError(
                "activation foundation marker classification failed"
            ) from exc
    finally:
        os.close(registry_fd)


def _activation_selection(root: Path) -> bool:
    evidence = _activation_marker_evidence(root)
    if evidence.state is activation_markers.ActivationMarkerState.ACTIVE:
        return True
    if evidence.state is activation_markers.ActivationMarkerState.LEGACY:
        return False
    if evidence.state is activation_markers.ActivationMarkerState.FRESH:
        raise LedgerRuntimeError("activation foundation is not active")
    raise LedgerRuntimeError("activation foundation is incomplete")


def _require_exact_directory_inventory(
    descriptor: int,
    expected: set[str],
    label: str,
) -> None:
    try:
        observed = set(os.listdir(descriptor))
    except OSError as exc:
        raise LedgerRuntimeError("%s inventory is unavailable" % label) from exc
    if observed != expected:
        raise LedgerRuntimeError("%s inventory is invalid" % label)


def _read_activation_protocol(root: Path) -> Tuple[bytes, bytes]:
    activation_path = root / "_registry" / "curation" / "activation"
    version_path = activation_path / "v1"
    staging_path = version_path / "staging"
    activation_fd = safety.open_verified_directory(
        activation_path,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    version_fd: Optional[int] = None
    staging_fd: Optional[int] = None
    try:
        version_fd = safety.open_verified_directory(
            version_path,
            require_owner_only=True,
            error_type=LedgerRuntimeError,
        )
        staging_fd = safety.open_verified_directory(
            staging_path,
            require_owner_only=True,
            error_type=LedgerRuntimeError,
        )
        for descriptor, path, label in (
            (activation_fd, activation_path, "activation protocol"),
            (version_fd, version_path, "activation protocol version"),
            (staging_fd, staging_path, "activation staging"),
        ):
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise LedgerRuntimeError("%s identity is invalid" % label)
            safety.require_same_directory_identity(
                path,
                descriptor,
                label,
                error_type=LedgerRuntimeError,
            )
        _require_exact_directory_inventory(
            activation_fd,
            {"v1"},
            "activation protocol",
        )
        _require_exact_directory_inventory(
            version_fd,
            {"request.json", "receipt.json", "staging"},
            "activation protocol version",
        )
        _require_exact_directory_inventory(staging_fd, set(), "activation staging")
        _request_info, request_raw = safety.read_regular_file_at(
            version_fd,
            "request.json",
            version_path / "request.json",
            label="activation request",
            expected_mode=0o600,
            max_bytes=1024 * 1024,
            error_type=LedgerRuntimeError,
        )
        _receipt_info, receipt_raw = safety.read_regular_file_at(
            version_fd,
            "receipt.json",
            version_path / "receipt.json",
            label="activation receipt",
            expected_mode=0o600,
            max_bytes=1024 * 1024,
            error_type=LedgerRuntimeError,
        )
        return request_raw, receipt_raw
    finally:
        if staging_fd is not None:
            os.close(staging_fd)
        if version_fd is not None:
            os.close(version_fd)
        os.close(activation_fd)


def _root_identity_sha256(root: Path) -> str:
    descriptor = safety.open_verified_directory(
        root,
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    try:
        info = os.fstat(descriptor)
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "canonical_path": str(root),
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                }
            )
        )
    finally:
        os.close(descriptor)


def _require_activation_has_no_legacy_sentinels(root: Path) -> None:
    registry_fd = safety.open_verified_directory(
        root / "_registry",
        require_owner_only=True,
        error_type=LedgerRuntimeError,
    )
    try:
        for name in ("placement-map.lock", "lock-migrations", "curation-runs"):
            if _entry_present(registry_fd, name):
                raise LedgerRuntimeError(
                    "activation and legacy foundation evidence co-present"
                )
    finally:
        os.close(registry_fd)


def _require_lane_and_guard_clear(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        "SELECT generation, state, owner_kind, owner_proposal_id, "
        "owner_approval_id, owner_run_id, owner_process_id "
        "FROM policy_mutation_lane ORDER BY id"
    ).fetchall()
    if len(rows) != 1 or rows[0]["state"] != "IDLE" or any(
        rows[0][field] is not None
        for field in (
            "owner_kind",
            "owner_proposal_id",
            "owner_approval_id",
            "owner_run_id",
            "owner_process_id",
        )
    ):
        raise LedgerRuntimeError("policy mutation lane is not IDLE")
    if connection.execute(
        "SELECT COUNT(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
    ).fetchone()[0]:
        raise PolicyAdmissionError(
            "open policy guard episode blocks writer session"
        )
    if connection.execute(
        "SELECT COUNT(*) FROM policy_guard_events WHERE state != 'COMPLETE'"
    ).fetchone()[0]:
        raise PolicyAdmissionError(
            "nonterminal policy guard event blocks writer session"
        )


def _current_policy_binding(
    connection: sqlite3.Connection,
    root: Path,
    foundation: _FoundationEvidence,
    registry_raw: bytes,
) -> Tuple[admission.ApprovedPolicyRef, policy.CompiledPolicy]:
    if isinstance(foundation, _LocalSQLiteFoundation):
        compiled = _compile_local_policy(registry_raw, root)
        generation = 1
        try:
            row = connection.execute(
                "SELECT generation FROM policy_head ORDER BY id LIMIT 1"
            ).fetchone()
            if row is not None and isinstance(row["generation"], int):
                generation = max(1, row["generation"])
        except sqlite3.Error:
            pass
        try:
            approved = admission.ApprovedPolicyRef(
                raw_hash=sha256_bytes(registry_raw),
                full_hash=compiled.full_hash,
                writer_control_hash=compiled.writer_hash,
                foundation_hash=compiled.foundation_hash,
                generation=generation,
                source_kind="INITIAL",
                source_run_id="local-sqlite",
                guard_epoch=0,
            )
        except ValueError as exc:
            raise PolicyAdmissionError("local policy fields are invalid") from exc
        return approved, compiled
    if isinstance(foundation, _LegacyBootstrapFoundation):
        try:
            compiled = policy.compile_policy(registry_raw, str(root))
        except policy.PolicyError as exc:
            raise PolicyAdmissionError("current placement registry is invalid") from exc
        expected_initial_bootstrap_id = foundation.bootstrap_id
        activation_initial_source = None
    elif isinstance(foundation, _SafeLibrarianActivationV1Foundation):
        if registry_raw != foundation.plan.registry_bytes:
            raise PolicyAdmissionError("activation registry input changed")
        compiled = foundation.plan.compiled_policy
        expected_initial_bootstrap_id = None
        activation_initial_source = foundation.policy_source
    else:
        raise LedgerRuntimeError("foundation evidence is invalid")
    heads = connection.execute(
        "SELECT * FROM policy_head ORDER BY id"
    ).fetchall()
    if len(heads) != 1:
        raise PolicyAdmissionError("exactly one current policy head is required")
    head = heads[0]
    try:
        policy_authority.verify_current_policy_binding_locked(
            connection,
            root,
            registry_raw,
            compiled,
            head,
            expected_initial_bootstrap_id=expected_initial_bootstrap_id,
            activation_initial_source=activation_initial_source,
        )
    except policy_authority.PolicyAuthorityError as exc:
        raise PolicyAdmissionError("current policy binding is not exact") from exc
    try:
        approved = admission.ApprovedPolicyRef(
            raw_hash=compiled.raw_hash,
            full_hash=compiled.full_hash,
            writer_control_hash=compiled.writer_hash,
            foundation_hash=compiled.foundation_hash,
            generation=head["generation"],
            source_kind=head["source_kind"],
            source_run_id=head["source_run_id"],
            guard_epoch=head["guard_epoch"],
        )
    except ValueError as exc:
        raise PolicyAdmissionError("current policy head fields are invalid") from exc
    return approved, compiled


@dataclass(frozen=True)
class _RuntimeResources:
    root: Path
    placement_path: Path
    policy_lock_label: str
    activation_selected: bool
    local_mode: bool
    ledger_lock_path: Path
    ledger_path: Path
    placement_fd: int
    ledger_fd: int
    connection: sqlite3.Connection
    ledger_identity: Tuple[int, int]

    def verify_locks(self) -> None:
        _require_curation_directory(self.root)
        _require_lock_identity(
            self.placement_path,
            self.placement_fd,
            self.policy_lock_label,
        )
        _require_lock_identity(
            self.ledger_lock_path,
            self.ledger_fd,
            "curation ledger lock",
        )


@dataclass(frozen=True)
class _StablePolicyObservation:
    observed_raw: bytes
    observed_identity: Dict[str, Any]
    expected_head_generation: int
    expected_head_full_hash: str
    expected_guard_epoch: int


class _PolicyFilesystemGuard:
    """Filesystem-only registry verifier safe for SQLite authorizer callbacks."""

    def __init__(
        self,
        resources: _RuntimeResources,
        expected_raw: bytes,
        expected_policy_ref: admission.ApprovedPolicyRef,
        *,
        expected_registry_sha256: Optional[str] = None,
    ) -> None:
        expected_hash = (
            expected_policy_ref.raw_hash
            if expected_registry_sha256 is None
            else expected_registry_sha256
        )
        if sha256_bytes(expected_raw) != expected_hash:
            raise PolicyAdmissionError(
                "session registry bytes do not match policy authority"
            )
        self._resources = resources
        self._expected_raw = expected_raw
        self._expected_policy_ref = expected_policy_ref
        self._observation: Optional[_StablePolicyObservation] = None

    @property
    def observation(self) -> Optional[_StablePolicyObservation]:
        return self._observation

    def _latch(self, info: os.stat_result, raw: bytes) -> None:
        if self._observation is not None:
            return
        try:
            normalized_full_hash: Optional[str] = policy.compile_policy(
                raw,
                str(self._resources.root),
            ).full_hash
            compile_status = "VALID"
        except policy.PolicyError:
            normalized_full_hash = None
            compile_status = "INVALID"
        path = self._resources.root / "_registry" / "placement-map.yml"
        self._observation = _StablePolicyObservation(
            observed_raw=raw,
            observed_identity={
                "path": str(path),
                "raw_sha256": sha256_bytes(raw),
                "normalized_full_hash": normalized_full_hash,
                "compile_status": compile_status,
                "bytes": len(raw),
                "device": info.st_dev,
                "inode": info.st_ino,
                "mode": "%04o" % stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "nlink": info.st_nlink,
            },
            expected_head_generation=self._expected_policy_ref.generation,
            expected_head_full_hash=self._expected_policy_ref.full_hash,
            expected_guard_epoch=self._expected_policy_ref.guard_epoch,
        )

    def verify_registry(self) -> bytes:
        self._resources.verify_locks()
        if self._observation is not None:
            raise PolicyAdmissionError(
                "placement registry drift was already observed during writer session"
            )
        info, raw = _read_registry(self._resources.root)
        if raw != self._expected_raw:
            self._latch(info, raw)
            raise PolicyAdmissionError(
                "placement registry drifted during writer session"
            )
        return raw


class _SessionPolicyVerifier:
    def __init__(
        self,
        resources: _RuntimeResources,
        foundation: _FoundationEvidence,
        compiled_policy: policy.CompiledPolicy,
        filesystem_guard: _PolicyFilesystemGuard,
    ) -> None:
        self._resources = resources
        self._foundation = foundation
        self._compiled_policy = compiled_policy
        self.filesystem_guard = filesystem_guard

    def __call__(self) -> admission.ApprovedPolicyRef:
        current_raw = self.filesystem_guard.verify_registry()
        _require_lane_and_guard_clear(self._resources.connection)
        observed_ref, observed_compiled = _current_policy_binding(
            self._resources.connection,
            self._resources.root,
            self._foundation,
            current_raw,
        )
        if observed_compiled != self._compiled_policy:
            raise PolicyAdmissionError("current approved policy binding changed")
        return observed_ref


def _cleanup_runtime_resources(
    *,
    root: Path,
    placement_path: Path,
    policy_lock_label: str,
    ledger_lock_path: Path,
    ledger_path: Optional[Path],
    placement_fd: int,
    ledger_fd: Optional[int],
    connection: Optional[sqlite3.Connection],
    ledger_identity: Optional[Tuple[int, int]],
    reader: bool,
) -> None:
    close_error: Optional[BaseException] = None
    try:
        _require_curation_directory(root)
        _require_lock_identity(
            placement_path,
            placement_fd,
            policy_lock_label,
        )
        if ledger_fd is not None:
            _require_lock_identity(
                ledger_lock_path,
                ledger_fd,
                "curation ledger lock",
            )
    except BaseException as exc:
        close_error = exc

    close_label = "reader close" if reader else "close"
    if connection is not None:
        if ledger_path is not None and ledger_identity is not None:
            try:
                _require_database_identity(
                    ledger_path,
                    ledger_identity,
                    phase="before %s" % close_label,
                )
            except BaseException as exc:
                if close_error is None:
                    close_error = exc
        try:
            connection.close()
        except sqlite3.Error as exc:
            if close_error is None:
                message = (
                    "cannot close curation reader cleanly"
                    if reader
                    else "cannot close curation ledger cleanly"
                )
                close_error = LedgerRuntimeError(message)
                close_error.__cause__ = exc
        if ledger_path is not None and ledger_identity is not None:
            try:
                _require_database_identity(
                    ledger_path,
                    ledger_identity,
                    phase="after %s" % close_label,
                )
            except BaseException as exc:
                if close_error is None:
                    close_error = exc

    if ledger_fd is not None:
        os.close(ledger_fd)
    os.close(placement_fd)
    if close_error is not None:
        raise close_error


@contextmanager
def _open_runtime_resources(
    root: Path,
    *,
    ledger_operation: int,
    connector: Callable[[Path, Tuple[int, int]], sqlite3.Connection],
    reader: bool,
) -> Iterator[_RuntimeResources]:
    canonical = _canonical_root(root)
    local_mode = _local_runtime_enabled(canonical)
    activation_selected = False if local_mode else _activation_selection(canonical)
    if local_mode or activation_selected:
        placement_path = canonical / "_registry" / "curation" / "policy.lock"
        policy_lock_label = (
            "local curation policy lock"
            if local_mode
            else "activation policy lock"
        )
    else:
        placement_path = canonical / "_registry" / "placement-map.lock"
        policy_lock_label = "placement policy lock"
    ledger_lock_path = canonical / "_registry" / "curation" / "ledger.lock"
    placement_fd = _open_lock(
        placement_path,
        policy_lock_label,
        fcntl.LOCK_SH,
    )
    ledger_fd: Optional[int] = None
    connection: Optional[sqlite3.Connection] = None
    ledger_path: Optional[Path] = None
    ledger_identity: Optional[Tuple[int, int]] = None
    try:
        _require_curation_directory(canonical)
        ledger_fd = _open_lock(
            ledger_lock_path,
            "curation ledger lock",
            ledger_operation,
        )
        ledger_path = canonical / "_registry" / "curation" / "ledger.sqlite3"
        ledger_identity = _database_identity(
            ledger_path,
            activation_foundation=(None if local_mode else activation_selected),
        )
        connection = connector(ledger_path, ledger_identity)
        yield _RuntimeResources(
            root=canonical,
            placement_path=placement_path,
            policy_lock_label=policy_lock_label,
            activation_selected=activation_selected,
            local_mode=local_mode,
            ledger_lock_path=ledger_lock_path,
            ledger_path=ledger_path,
            placement_fd=placement_fd,
            ledger_fd=ledger_fd,
            connection=connection,
            ledger_identity=ledger_identity,
        )
    finally:
        _cleanup_runtime_resources(
            root=canonical,
            placement_path=placement_path,
            policy_lock_label=policy_lock_label,
            ledger_lock_path=ledger_lock_path,
            ledger_path=ledger_path,
            placement_fd=placement_fd,
            ledger_fd=ledger_fd,
            connection=connection,
            ledger_identity=ledger_identity,
            reader=reader,
        )


def _resolve_foundation(resources: _RuntimeResources) -> _FoundationEvidence:
    if resources.local_mode:
        return _LocalSQLiteFoundation(
            schema_state=_require_local_schema(resources.connection),
        )
    observed_activation = _activation_selection(resources.root)
    if observed_activation != resources.activation_selected:
        raise LedgerRuntimeError("foundation selection changed during open")
    if not observed_activation:
        schema_state = _require_exact_schema_preflight(resources.connection)
        bootstrap_id = _single_complete_bootstrap(
            resources.connection,
            resources.root,
            resources.placement_fd,
            resources.ledger_fd,
            resources.ledger_identity,
        )
        _require_bootstrap_schema_binding(
            resources.connection,
            bootstrap_id,
            schema_state,
        )
        return _LegacyBootstrapFoundation(
            bootstrap_id=bootstrap_id,
            schema_state=schema_state,
        )

    _require_activation_has_no_legacy_sentinels(resources.root)
    try:
        request_raw, receipt_raw = _read_activation_protocol(resources.root)
        request = operation_codec.decode_operation_request(request_raw)
        activation_contract.validate_activation_request(request)
        if (
            request.root != str(resources.root)
            or request.payload["root_identity_sha256"]
            != _root_identity_sha256(resources.root)
        ):
            raise LedgerRuntimeError("activation request root identity changed")
        _registry_info, registry_raw = _read_registry(resources.root)
        plan = activation_foundation.build_activation_foundation(
            registry_raw,
            str(resources.root),
            request.scope["activation_id"],
        )
        if dict(request.payload["initial_policy"]) != plan.initial_policy.as_dict():
            raise LedgerRuntimeError("activation request policy identity changed")
        receipt = activation_contract.require_activation_receipt_bytes(
            receipt_raw,
            request=request,
            expected_uid=os.getuid(),
        )
        readback = activation_foundation.verify_activation_ledger(
            resources.ledger_path,
            plan,
        )
        if (
            receipt["logical_readback_sha256"] != readback.sha256
            or receipt["initial_snapshot_identity"]["snapshot_id"]
            != plan.snapshot_id
        ):
            raise LedgerRuntimeError("activation receipt foundation binding changed")
    except LedgerRuntimeError:
        raise
    except (TypeError, ValueError) as exc:
        raise LedgerRuntimeError("activation foundation is invalid") from exc
    receipt_path = (
        resources.root
        / "_registry"
        / "curation"
        / "activation"
        / "v1"
        / "receipt.json"
    )
    return _SafeLibrarianActivationV1Foundation(
        plan=plan,
        policy_source=policy_authority.ActivationInitialPolicySource(
            plan=plan,
            receipt_path=receipt_path,
            receipt_sha256=sha256_bytes(receipt_raw),
        ),
    )


def _session_policy(
    resources: _RuntimeResources,
    foundation: _FoundationEvidence | str,
) -> Tuple[
    admission.ApprovedPolicyRef,
    policy.CompiledPolicy,
    Callable[[], admission.ApprovedPolicyRef],
]:
    if isinstance(foundation, str):
        # Preserve the established explicit schema-migration call seam.  Those
        # callers already verified the legacy bootstrap and pass its exact id.
        foundation = _LegacyBootstrapFoundation(
            bootstrap_id=foundation,
            schema_state="externally-verified",
        )
    resources.verify_locks()
    _require_lane_and_guard_clear(resources.connection)
    _registry_info, registry_raw = _read_registry(resources.root)
    approved_policy_ref, compiled_policy = _current_policy_binding(
        resources.connection,
        resources.root,
        foundation,
        registry_raw,
    )
    filesystem_guard = _PolicyFilesystemGuard(
        resources,
        registry_raw,
        approved_policy_ref,
        expected_registry_sha256=(
            foundation.plan.initial_policy.registry_input_sha256
            if isinstance(foundation, _SafeLibrarianActivationV1Foundation)
            else sha256_bytes(registry_raw)
            if isinstance(foundation, _LocalSQLiteFoundation)
            else None
        ),
    )

    verify_policy = _SessionPolicyVerifier(
        resources,
        foundation,
        compiled_policy,
        filesystem_guard,
    )
    return approved_policy_ref, compiled_policy, verify_policy


@contextmanager
def open_writer_session(
    root: Path,
    *,
    observed_by: str = DEFAULT_WRITER_OBSERVER,
    allow_m2_migration: bool = False,
) -> Iterator[WriterSession]:
    """Open the exact curation writer boundary; v1 never upgrades implicitly."""

    _require_observed_by(observed_by)
    if not isinstance(allow_m2_migration, bool):
        raise TypeError("allow_m2_migration must be a boolean")
    if allow_m2_migration:
        raise LedgerRuntimeError(
            "allow_m2_migration is disabled; use the explicit schema migration workflow"
        )
    observation: Optional[_StablePolicyObservation] = None
    legacy_foundation = False
    pending_error: Optional[BaseException] = None
    try:
        with _open_runtime_resources(
            root,
            ledger_operation=fcntl.LOCK_EX,
            connector=_connect,
            reader=False,
        ) as resources:
            foundation = _resolve_foundation(resources)
            legacy_foundation = isinstance(
                foundation,
                _LegacyBootstrapFoundation,
            )
            approved_policy_ref, compiled_policy, verify_policy = _session_policy(
                resources,
                foundation,
            )
            if not isinstance(verify_policy, _SessionPolicyVerifier):
                raise LedgerRuntimeError("session policy verifier is invalid")
            filesystem_guard = verify_policy.filesystem_guard
            resources.verify_locks()
            _install_commit_lock_guard(
                resources.connection,
                filesystem_guard.verify_registry,
            )
            if isinstance(foundation, _LegacyBootstrapFoundation):
                _ensure_exact_v2(
                    resources.connection,
                    bootstrap_id=foundation.bootstrap_id,
                )
            resources.verify_locks()
            session = WriterSession(
                resources.connection,
                approved_policy_ref,
                compiled_policy,
                (
                    FoundationKind.LEGACY_BOOTSTRAP
                    if isinstance(foundation, _LegacyBootstrapFoundation)
                    else (
                        FoundationKind.LOCAL_SQLITE
                        if isinstance(foundation, _LocalSQLiteFoundation)
                        else FoundationKind.SAFE_LIBRARIAN_ACTIVATION_V1
                    )
                ),
                verify_policy,
                resources.verify_locks,
            )
            resources.verify_locks()
            try:
                yield session
            except BaseException as exc:
                pending_error = exc
            finally:
                try:
                    filesystem_guard.verify_registry()
                except BaseException as exc:
                    if pending_error is None:
                        pending_error = exc
                if resources.connection.in_transaction:
                    try:
                        resources.connection.execute("ROLLBACK")
                    except BaseException as exc:
                        if pending_error is None:
                            pending_error = exc
                try:
                    session._deactivate()
                except BaseException as exc:
                    if pending_error is None:
                        pending_error = exc
                observation = filesystem_guard.observation
    except BaseException as exc:
        if pending_error is None:
            pending_error = exc

    if observation is not None and legacy_foundation:
        try:
            recorded = policy_authority.observe_policy_drift_from_stable_observation(
                Path(root),
                observed_by=observed_by,
                observed_raw=observation.observed_raw,
                observed_identity=observation.observed_identity,
                expected_head_generation=observation.expected_head_generation,
                expected_head_full_hash=observation.expected_head_full_hash,
                expected_guard_epoch=observation.expected_guard_epoch,
            )
        except Exception as exc:
            error = LedgerRuntimeError(
                "policy drift was detected but its guard record failed"
            )
            if pending_error is not None:
                error.__context__ = pending_error
            raise error from exc
        error = LedgerRuntimeError(
            "policy drift recorded: episode %s event %s"
            % (recorded["episode_id"], recorded["event_id"])
        )
        if pending_error is not None:
            raise error from pending_error
        raise error
    if observation is not None and pending_error is None:
        pending_error = PolicyAdmissionError(
            "placement registry drifted during activation writer session"
        )
    if pending_error is not None:
        raise pending_error


@contextmanager
def open_reader_session(
    root: Path,
    *,
    immutable: bool = False,
) -> Iterator[ReaderSession]:
    """Open an exact v2/v3 policy-bound session that cannot migrate or write."""

    if type(immutable) is not bool:
        raise TypeError("immutable must be a boolean")

    with _open_runtime_resources(
        root,
        ledger_operation=fcntl.LOCK_SH,
        connector=(
            _connect_immutable_readonly if immutable else _connect_readonly
        ),
        reader=True,
    ) as resources:
        foundation = _resolve_foundation(resources)
        if isinstance(foundation, _LegacyBootstrapFoundation):
            _require_exact_v2_reader(
                resources.connection,
                bootstrap_id=foundation.bootstrap_id,
            )
        approved_policy_ref, compiled_policy, verify_policy = _session_policy(
            resources,
            foundation,
        )
        session = ReaderSession(
            resources.connection,
            approved_policy_ref,
            compiled_policy,
            (
                FoundationKind.LEGACY_BOOTSTRAP
                if isinstance(foundation, _LegacyBootstrapFoundation)
                else (
                    FoundationKind.LOCAL_SQLITE
                    if isinstance(foundation, _LocalSQLiteFoundation)
                    else FoundationKind.SAFE_LIBRARIAN_ACTIVATION_V1
                )
            ),
            verify_policy,
            resources.verify_locks,
        )
        try:
            yield session
        finally:
            session._deactivate()


__all__ = [
    "FoundationKind",
    "LedgerRuntimeError",
    "PolicyAdmissionError",
    "M2_MIGRATION_ID",
    "ReaderSession",
    "WriterSession",
    "open_reader_session",
    "open_writer_session",
]
