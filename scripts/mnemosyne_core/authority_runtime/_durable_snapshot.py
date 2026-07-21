"""Private anchored primitives and snapshot storage for Authority Runtime."""

from __future__ import annotations

import errno
import fcntl
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Callable, Iterator, Optional

from .. import safety
from ..canonical_json import canonical_json_bytes, sha256_bytes
from . import AuthorityRuntimeError


_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_RUNTIME_PARTS = ("_registry", "curation", "authority-runtime")
_MUTATION_LOCK_NAME = "durable-mutation.lock"
_SNAPSHOT_PARTS = _RUNTIME_PARTS + ("snapshot-v1",)
_SNAPSHOT_OBJECTS_PARTS = _SNAPSHOT_PARTS + ("objects",)
_SNAPSHOT_RECEIPTS_PARTS = _SNAPSHOT_PARTS + ("head-receipts",)
_SNAPSHOT_HEADS_PARTS = _SNAPSHOT_PARTS + ("heads",)
_SNAPSHOT_LOCKS_PARTS = _SNAPSHOT_PARTS + ("locks",)
_SNAPSHOT_STAGING_PARTS = _SNAPSHOT_PARTS + ("staging",)
_SNAPSHOT_ROOT_STOPS_PARTS = _SNAPSHOT_PARTS + ("root-stops",)
_SNAPSHOT_NAMESPACE_PARTS = (
    ("_registry",),
    ("_registry", "curation"),
    _RUNTIME_PARTS,
    _SNAPSHOT_PARTS,
    _SNAPSHOT_OBJECTS_PARTS,
    _SNAPSHOT_RECEIPTS_PARTS,
    _SNAPSHOT_HEADS_PARTS,
    _SNAPSHOT_LOCKS_PARTS,
    _SNAPSHOT_STAGING_PARTS,
    _SNAPSHOT_ROOT_STOPS_PARTS,
)
_SNAPSHOT_HISTORY_MARKER_PARTS = (
    _SNAPSHOT_PARTS,
    _SNAPSHOT_OBJECTS_PARTS,
    _SNAPSHOT_RECEIPTS_PARTS,
    _SNAPSHOT_HEADS_PARTS,
    _SNAPSHOT_LOCKS_PARTS,
)
_SNAPSHOT_WRITER_LOCK_NAME = "snapshot-writer.lock"
_LEGACY_V1_DATABASE_NAME = "authority-runtime.sqlite3"
_LEGACY_V1_ALLOWED_RUNTIME_NAMES = frozenset(
    {
        _LEGACY_V1_DATABASE_NAME,
        _MUTATION_LOCK_NAME,
        _SNAPSHOT_PARTS[-1],
    }
)
_LEGACY_V1_EFFECT_COLUMN_SIGNATURE = (
    ("effect_id", "TEXT", 1, None, 1),
    ("target_relative_path", "TEXT", 1, None, 0),
    ("artifact_ref", "BLOB", 1, None, 0),
    ("artifact_bytes", "BLOB", 1, None, 0),
    ("request_sha256", "TEXT", 1, None, 0),
    ("scope_sha256", "TEXT", 1, None, 0),
    ("spec_identity", "TEXT", 1, None, 0),
    ("spec_sha256", "TEXT", 1, None, 0),
    ("policy_identity_sha256", "TEXT", 1, None, 0),
    ("state", "TEXT", 1, None, 0),
)
_LEGACY_V1_EFFECT_INDEX_SIGNATURE = frozenset(
    {
        ("pk", 1, 0, ("effect_id",)),
        ("u", 1, 0, ("target_relative_path",)),
    }
)
_LEGACY_V1_DURABLE_EFFECTS_SQL = (
    "CREATE TABLE durable_effects ("
    "effect_id TEXT NOT NULL PRIMARY KEY, "
    "target_relative_path TEXT NOT NULL UNIQUE, "
    "artifact_ref BLOB NOT NULL, "
    "artifact_bytes BLOB NOT NULL, "
    "request_sha256 TEXT NOT NULL, "
    "scope_sha256 TEXT NOT NULL, "
    "spec_identity TEXT NOT NULL, "
    "spec_sha256 TEXT NOT NULL, "
    "policy_identity_sha256 TEXT NOT NULL, "
    "state TEXT NOT NULL"
    ")"
)
_TRANSIENT_SNAPSHOT_READ_ERRNOS = frozenset(
    error_number
    for error_number in (
        errno.EIO,
        getattr(errno, "ESTALE", None),
        getattr(errno, "ENODEV", None),
        getattr(errno, "ENXIO", None),
    )
    if error_number is not None
)
_HEAD_NAME = re.compile(r"h-([0-9a-f]{64})\.json")
_OBJECT_NAME = re.compile(r"o-([0-9a-f]{64})")
_ROOT_STOP_NAME = re.compile(r"f-([0-9a-f]{64})\.json")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_EFFECT_ID = re.compile(r"[a-z][a-z0-9-]{2,63}")
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
_RECOVERY_REASON = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
_RECOVERY_PROTOCOL_VERSION = 1
_RECOVERY_OWNER = "authority-runtime"
_RECOVERY_BINDING_KIND = "DURABLE_EFFECT_BINDING"
_MAX_SNAPSHOT_GENERATION = (1 << 64) - 1
_MAX_SNAPSHOT_PROTOCOL_ENTRIES = 16_384
_SNAPSHOT_TRANSITIONS = frozenset(
    {
        "EMPTY_GENESIS",
        "CLAIMED",
        "PREPARED",
        "PUBLISHED",
        "FINALIZED",
        "BLOCKED_RECOVERY",
    }
)


def _run_snapshot_checkpoint(point: str) -> None:
    """Private test seam for snapshot-publication crash regression coverage."""


# A flock survives raw fork because the child inherits the open file
# description. Track every durable lock so the child cannot inherit a valid
# writer-liveness proof.
_FORK_TRACKED_LOCK_FDS: set[int] = set()
_FORK_LOCK_STATE_POISONED = False
_FORK_CHILD_LOCK_STATE_POISONED = False
_FORK_LOCK_REGISTRATION_GATE = threading.RLock()


def _track_fork_lock(fd: int) -> None:
    _FORK_TRACKED_LOCK_FDS.add(fd)


def _release_tracked_lock(fd: int, *, label: str) -> None:
    global _FORK_LOCK_STATE_POISONED
    with _FORK_LOCK_REGISTRATION_GATE:
        try:
            os.close(fd)
        except OSError as exc:
            _FORK_LOCK_STATE_POISONED = True
            raise AuthorityRuntimeError(f"{label} is unavailable") from exc
        _FORK_TRACKED_LOCK_FDS.discard(fd)


def _close_descriptor(fd: int, *, label: str) -> None:
    try:
        os.close(fd)
    except OSError as exc:
        raise AuthorityRuntimeError(f"{label} is unavailable") from exc


def _acquire_fork_safe_lock(
    *,
    directory_fd: int,
    name: str,
    flags: int,
    label: str,
    wait: bool,
    verify: Callable[[int], None],
) -> int | None:
    """Acquire and register one flock without leaking an untracked OFD."""

    while True:
        fd: int | None = None
        retry = False
        with _FORK_LOCK_REGISTRATION_GATE:
            try:
                fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
                verify(fd)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    _close_descriptor(fd, label=label)
                    fd = None
                    if not wait:
                        return None
                    retry = True
                else:
                    _track_fork_lock(fd)
                    return fd
            except BaseException:
                if fd is not None:
                    _close_descriptor(fd, label=label)
                raise
        if retry:
            time.sleep(0.001)


def _close_inherited_fork_locks() -> None:
    """Fail closed in a fork child instead of inheriting durable liveness."""

    global _FORK_CHILD_LOCK_STATE_POISONED, _FORK_LOCK_STATE_POISONED
    inherited = tuple(_FORK_TRACKED_LOCK_FDS)
    if inherited:
        _FORK_LOCK_STATE_POISONED = True
        _FORK_CHILD_LOCK_STATE_POISONED = True
    for fd in inherited:
        try:
            os.close(fd)
        except OSError:
            _FORK_LOCK_STATE_POISONED = True
    _FORK_TRACKED_LOCK_FDS.clear()


def _before_fork_lock_tracking() -> None:
    _FORK_LOCK_REGISTRATION_GATE.acquire()


def _after_fork_parent_lock_tracking() -> None:
    _FORK_LOCK_REGISTRATION_GATE.release()


def _after_fork_child_lock_tracking() -> None:
    try:
        _close_inherited_fork_locks()
    finally:
        _FORK_LOCK_REGISTRATION_GATE.release()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_before_fork_lock_tracking,
        after_in_parent=_after_fork_parent_lock_tracking,
        after_in_child=_after_fork_child_lock_tracking,
    )


def _fork_lock_state_poisoned() -> bool:
    return _FORK_LOCK_STATE_POISONED


def _fork_child_lock_state_poisoned() -> bool:
    return _FORK_CHILD_LOCK_STATE_POISONED


def _anchored_parts(value: object) -> tuple[str, ...]:
    """Return safe root-relative components for a private anchored path."""

    if isinstance(value, Path):
        raw = value.as_posix()
    elif isinstance(value, str):
        raw = value
    else:
        raise TypeError("anchored path component is invalid")
    if raw.startswith("/"):
        raise ValueError("anchored path component is invalid")
    parts = tuple(raw.split("/"))
    if not parts or any(
        not part or part in {".", ".."} or "/" in part for part in parts
    ):
        raise ValueError("anchored path component is invalid")
    return parts


@dataclass(frozen=True)
class _AnchoredPath:
    """Private root-relative locator backed by an open root directory FD."""

    anchor: "_RootAnchor"
    parts: tuple[str, ...]

    def __truediv__(self, value: object) -> "_AnchoredPath":
        return _AnchoredPath(self.anchor, self.parts + _anchored_parts(value))

    def joinpath(self, *values: object) -> "_AnchoredPath":
        result = self
        for value in values:
            result = result / value
        return result

    @property
    def name(self) -> str:
        return self.parts[-1]

    @property
    def parent(self) -> "_AnchoredPath":
        if not self.parts:
            raise ValueError("anchored root has no parent")
        return _AnchoredPath(self.anchor, self.parts[:-1])

    @property
    def display_path(self) -> Path:
        return self.anchor.display_path(self.parts)

    def __str__(self) -> str:
        return str(self.display_path)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _AnchoredPath):
            return self.anchor is other.anchor and self.parts == other.parts
        if isinstance(other, Path):
            return self.display_path == other
        return False


class _RootAnchor:
    """Own a root descriptor for all durable filesystem targets."""

    __slots__ = ("__display_root", "__root_fd", "__identity", "__closed")

    def __init__(
        self,
        display_root: Path,
        root_fd: int,
        identity: tuple[int, int],
    ) -> None:
        self.__display_root = display_root
        self.__root_fd = root_fd
        self.__identity = identity
        self.__closed = False

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        expected_identity: tuple[int, int],
    ) -> "_RootAnchor":
        if (
            type(expected_identity) is not tuple
            or len(expected_identity) != 2
            or any(type(value) is not int for value in expected_identity)
        ):
            raise AuthorityRuntimeError("authority root identity is invalid")
        root_fd = safety.open_verified_directory(
            root,
            require_owner_only=True,
            error_type=AuthorityRuntimeError,
        )
        try:
            info = os.fstat(root_fd)
            identity = (info.st_dev, info.st_ino)
            if identity != expected_identity:
                raise AuthorityRuntimeError("authority root identity changed")
            return cls(root, root_fd, identity)
        except BaseException:
            os.close(root_fd)
            raise

    def __truediv__(self, value: object) -> _AnchoredPath:
        return _AnchoredPath(self, _anchored_parts(value))

    def joinpath(self, *values: object) -> _AnchoredPath:
        if not values:
            raise ValueError("anchored root join requires a component")
        result = self / values[0]
        for value in values[1:]:
            result = result / value
        return result

    def display_path(self, parts: tuple[str, ...]) -> Path:
        return self.__display_root.joinpath(*parts)

    @property
    def identity(self) -> tuple[int, int]:
        self._require_open()
        return self.__identity

    @staticmethod
    def _directory_flags() -> int:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return flags

    def _require_open(self) -> None:
        if self.__closed:
            raise AuthorityRuntimeError("durable root anchor is not active")
        try:
            info = os.fstat(self.__root_fd)
        except OSError as exc:
            raise AuthorityRuntimeError("durable root anchor is unavailable") from exc
        if (info.st_dev, info.st_ino) != self.__identity:
            raise AuthorityRuntimeError("durable root anchor identity is invalid")

    def _open_directory(
        self,
        parts: tuple[str, ...],
        *,
        create: bool,
    ) -> int:
        self._require_open()
        try:
            current_fd = os.dup(self.__root_fd)
        except OSError as exc:
            raise AuthorityRuntimeError(
                "durable root directory is unavailable"
            ) from exc
        try:
            for part in parts:
                try:
                    next_fd = os.open(
                        part,
                        self._directory_flags(),
                        dir_fd=current_fd,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(part, 0o700, dir_fd=current_fd)
                        os.fsync(current_fd)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise AuthorityRuntimeError(
                            "durable root directory is unavailable"
                        ) from exc
                    try:
                        next_fd = os.open(
                            part,
                            self._directory_flags(),
                            dir_fd=current_fd,
                        )
                    except OSError as exc:
                        raise AuthorityRuntimeError(
                            "durable root directory is unavailable"
                        ) from exc
                try:
                    info = os.fstat(next_fd)
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) & 0o022
                    ):
                        raise AuthorityRuntimeError(
                            "durable root directory identity is invalid"
                        )
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except FileNotFoundError:
            os.close(current_fd)
            raise
        except OSError as exc:
            os.close(current_fd)
            raise AuthorityRuntimeError(
                "durable root directory is unavailable"
            ) from exc
        except BaseException:
            os.close(current_fd)
            raise

    def directory_identity(
        self,
        parts: tuple[str, ...],
    ) -> tuple[int, int, int, int, int]:
        """Return the verified identity of one anchored protocol directory."""

        directory_fd = self._open_directory(parts, create=False)
        try:
            info = os.fstat(directory_fd)
            return (
                info.st_dev,
                info.st_ino,
                info.st_nlink,
                info.st_uid,
                stat.S_IMODE(info.st_mode),
            )
        except OSError as exc:
            raise AuthorityRuntimeError(
                "durable root directory is unavailable"
            ) from exc
        finally:
            os.close(directory_fd)

    def directory_change_marker(
        self,
        parts: tuple[str, ...],
    ) -> tuple[int, int, int]:
        """Return a directory-entry mutation marker without using a lexical path."""

        directory_fd = self._open_directory(parts, create=False)
        try:
            info = os.fstat(directory_fd)
            return info.st_dev, info.st_ino, info.st_ctime_ns
        except OSError as exc:
            raise AuthorityRuntimeError(
                "durable root directory is unavailable"
            ) from exc
        finally:
            os.close(directory_fd)

    def read_bytes(self, path: _AnchoredPath) -> Optional[bytes]:
        if path.anchor is not self:
            raise AuthorityRuntimeError("durable root anchor is invalid")
        try:
            parent_fd = self._open_directory(path.parts[:-1], create=False)
        except FileNotFoundError:
            return None
        try:
            try:
                os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise AuthorityRuntimeError(
                    "durable artifact metadata is unavailable"
                ) from exc
            _info, raw = safety.read_regular_file_at(
                parent_fd,
                path.name,
                path.display_path,
                label="durable artifact",
                expected_mode=0o600,
                max_bytes=_MAX_ARTIFACT_BYTES,
                error_type=AuthorityRuntimeError,
            )
            return raw
        finally:
            os.close(parent_fd)

    def list_directory(self, path: _AnchoredPath) -> tuple[str, ...]:
        if path.anchor is not self:
            raise AuthorityRuntimeError("durable root anchor is invalid")
        try:
            directory_fd = self._open_directory(path.parts, create=False)
        except FileNotFoundError:
            return ()
        try:
            try:
                return tuple(sorted(os.listdir(directory_fd)))
            except OSError as exc:
                raise AuthorityRuntimeError(
                    "durable root directory is unavailable"
                ) from exc
        finally:
            os.close(directory_fd)

    def list_directory_bounded(
        self,
        path: _AnchoredPath,
        *,
        maximum_entries: int,
    ) -> tuple[str, ...]:
        """Enumerate an anchored directory without accepting an unbounded set."""

        if path.anchor is not self:
            raise AuthorityRuntimeError("durable root anchor is invalid")
        if type(maximum_entries) is not int or maximum_entries < 1:
            raise ValueError("durable directory entry limit is invalid")
        try:
            directory_fd = self._open_directory(path.parts, create=False)
        except FileNotFoundError:
            return ()
        entries: list[str] = []
        scanner = None
        try:
            scanner = os.scandir(directory_fd)
            directory_fd = -1
            for entry in scanner:
                if len(entries) >= maximum_entries:
                    raise AuthorityRuntimeError("durable directory entry limit exceeded")
                if type(entry.name) is not str:
                    raise AuthorityRuntimeError("durable directory entry is invalid")
                entries.append(entry.name)
            return tuple(sorted(entries, key=os.fsencode))
        except OSError as exc:
            raise AuthorityRuntimeError("durable root directory is unavailable") from exc
        finally:
            if scanner is not None:
                scanner.close()
            elif directory_fd >= 0:
                os.close(directory_fd)

    def publish_bytes(
        self,
        path: _AnchoredPath,
        raw: bytes,
        *,
        label: str,
        after_file_fsync: Callable[[], None] | None = None,
        after_file_readback: Callable[[], None] | None = None,
        after_directory_fsync: Callable[[], None] | None = None,
    ) -> None:
        if path.anchor is not self:
            raise AuthorityRuntimeError("durable root anchor is invalid")
        parent_fd = self._open_directory(path.parts[:-1], create=True)
        try:
            def verify_readback(
                _path: Path,
                fd: int,
                _directory_fd: int,
            ) -> None:
                if safety.read_open_file_bytes(fd) != raw:
                    raise AuthorityRuntimeError(f"{label} readback is invalid")

            safety.publish_bytes_atomic_no_replace_at(
                parent_fd,
                path.name,
                path.display_path,
                raw,
                label=label,
                mode=0o600,
                collision_error=f"{label} already exists",
                final_identity_error=f"{label} final identity is invalid",
                error_type=AuthorityRuntimeError,
                after_fd_readback=verify_readback,
                after_file_fsync=after_file_fsync,
                after_file_readback=after_file_readback,
                after_directory_fsync=after_directory_fsync,
            )
        finally:
            os.close(parent_fd)

    def remove_exact_bytes(
        self,
        path: _AnchoredPath,
        expected: bytes,
        *,
        label: str,
    ) -> None:
        if path.anchor is not self:
            raise AuthorityRuntimeError("durable root anchor is invalid")
        parent_fd = self._open_directory(path.parts[:-1], create=False)
        try:
            info, raw = safety.read_regular_file_at(
                parent_fd,
                path.name,
                path.display_path,
                label=label,
                expected_mode=0o600,
                max_bytes=_MAX_ARTIFACT_BYTES,
                error_type=AuthorityRuntimeError,
            )
            if info.st_nlink != 1 or raw != expected:
                raise AuthorityRuntimeError(f"{label} identity is invalid")
            try:
                os.unlink(path.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError as exc:
                raise AuthorityRuntimeError(f"{label} cannot be removed") from exc
        finally:
            os.close(parent_fd)

    @contextmanager
    def mutation_gate(self) -> Iterator[None]:
        runtime_fd = self._open_directory(_RUNTIME_PARTS, create=True)
        lock_fd: int | None = None
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            def verify_lock(fd: int) -> None:
                info = os.fstat(fd)
                lexical = os.stat(
                    _MUTATION_LOCK_NAME,
                    dir_fd=runtime_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                    or (info.st_dev, info.st_ino)
                    != (lexical.st_dev, lexical.st_ino)
                ):
                    raise AuthorityRuntimeError("durable mutation lock is invalid")

            lock_fd = _acquire_fork_safe_lock(
                directory_fd=runtime_fd,
                name=_MUTATION_LOCK_NAME,
                flags=flags,
                label="durable mutation lock",
                wait=True,
                verify=verify_lock,
            )
            if lock_fd is None:
                raise AuthorityRuntimeError("durable mutation lock is unavailable")
            yield
        except OSError as exc:
            raise AuthorityRuntimeError("durable mutation lock is unavailable") from exc
        finally:
            close_error: AuthorityRuntimeError | None = None
            if lock_fd is not None:
                try:
                    _release_tracked_lock(lock_fd, label="durable mutation lock")
                except AuthorityRuntimeError as exc:
                    close_error = exc
            try:
                os.close(runtime_fd)
            except OSError as exc:
                if close_error is None:
                    close_error = AuthorityRuntimeError(
                        "durable root directory is unavailable"
                    )
                    close_error.__cause__ = exc
            if close_error is not None:
                raise close_error

    def open_runtime_directory(self) -> int:
        return self._open_directory(_RUNTIME_PARTS, create=True)

    def close(self) -> None:
        if not self.__closed:
            self.__closed = True
            try:
                os.close(self.__root_fd)
            except OSError as exc:
                raise AuthorityRuntimeError(
                    "durable root directory is unavailable"
                ) from exc


@dataclass(frozen=True)
class _SnapshotFileIdentity:
    """The immutable filesystem identity of one canonical protocol member."""

    device: int
    inode: int
    link_count: int
    owner: int
    mode: int
    byte_length: int

    @classmethod
    def from_stat(cls, info: os.stat_result) -> "_SnapshotFileIdentity":
        return cls(
            device=info.st_dev,
            inode=info.st_ino,
            link_count=info.st_nlink,
            owner=info.st_uid,
            mode=stat.S_IMODE(info.st_mode),
            byte_length=info.st_size,
        )


@dataclass(frozen=True)
class _LegacyV1InputFile:
    """One anchored legacy input that can later be proven retired unchanged."""

    relative_parts: tuple[str, ...]
    raw: bytes
    raw_sha256: str
    identity: _SnapshotFileIdentity


@dataclass(frozen=True)
class _LegacyV1Inventory:
    """The immutable V1 evidence observed before a V2 lineage may begin."""

    members: tuple[_LegacyV1InputFile, ...]
    legacy_runtime_names: tuple[str, ...]
    input_digest_sha256: str


@dataclass(frozen=True)
class _LegacyV1Classification:
    """The one exact empty V1 input that may become a V2 genesis."""

    inventory: _LegacyV1Inventory
    legacy_provenance_raw: bytes
    legacy_provenance_sha256: str
    retired_witness_sha256: str


@dataclass(frozen=True)
class _SnapshotHistoryMember:
    """The expected anchored identities of one immutable canonical head pack."""

    head_sha256: str
    head_identity: _SnapshotFileIdentity
    receipt_identity: _SnapshotFileIdentity
    manifest_identity: _SnapshotFileIdentity
    snapshot_identity: _SnapshotFileIdentity


@dataclass(frozen=True)
class _SnapshotHistoryProfile:
    """The canonical history an active writer is permitted to extend."""

    namespace_identities: tuple[
        tuple[tuple[str, ...], tuple[int, int, int, int]], ...
    ]
    directory_change_markers: tuple[
        tuple[tuple[str, ...], tuple[int, int, int]], ...
    ]
    members: tuple[_SnapshotHistoryMember, ...]


class _SnapshotProtocolReadError(AuthorityRuntimeError):
    """A safety helper rejected one protocol-file read before classification."""


class _SnapshotHistoryChanged(AuthorityRuntimeError):
    """An active writer can no longer prove that its expected history remains."""


class _SnapshotHistoryUnavailable(AuthorityRuntimeError):
    """An active writer could not read history, without evidence of drift."""


class _SnapshotLegacyFenceRequired(AuthorityRuntimeError):
    """Private V1 classifier result translated only at the public boundary."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        observed_evidence_sha256: str,
        publish_root_stop: bool,
    ) -> None:
        if (
            type(reason_code) is not str
            or _RECOVERY_REASON.fullmatch(reason_code) is None
            or type(observed_evidence_sha256) is not str
            or _SHA256.fullmatch(observed_evidence_sha256) is None
            or type(publish_root_stop) is not bool
        ):
            raise ValueError("durable legacy fence is invalid")
        super().__init__(message)
        self.reason_code = reason_code
        self.observed_evidence_sha256 = observed_evidence_sha256
        self.publish_root_stop = publish_root_stop


class _SnapshotRootStopRequired(AuthorityRuntimeError):
    """A V2 root-stop is present or was just published for an untrusted root."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        observed_evidence_sha256: str,
    ) -> None:
        if (
            type(reason_code) is not str
            or _RECOVERY_REASON.fullmatch(reason_code) is None
            or type(observed_evidence_sha256) is not str
            or _SHA256.fullmatch(observed_evidence_sha256) is None
        ):
            raise ValueError("durable root stop is invalid")
        super().__init__(message)
        self.reason_code = reason_code
        self.observed_evidence_sha256 = observed_evidence_sha256


class _LegacyV1InventoryError(AuthorityRuntimeError):
    """An anchored legacy artifact cannot be treated as a supported input."""


class _SnapshotWriterBusy(AuthorityRuntimeError):
    """A healthy owner already holds the one snapshot writer lease."""


class _SnapshotWriterUnavailable(AuthorityRuntimeError):
    """A fork child must not turn its inherited lock state into root damage."""


def _is_transient_snapshot_read_error(exc: OSError) -> bool:
    """Keep only explicit transport faults out of immutable-drift fencing."""

    return exc.errno in _TRANSIENT_SNAPSHOT_READ_ERRNOS


def _has_transient_snapshot_read_error(exc: BaseException) -> bool:
    """Find an explicit transient I/O cause without parsing error messages."""

    observed: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in observed:
        observed.add(id(current))
        if isinstance(current, OSError) and _is_transient_snapshot_read_error(
            current
        ):
            return True
        current = current.__cause__
    return False


class _SnapshotWriterLease:
    """One session-lifetime writer lease; it is never history authority."""

    __slots__ = ("__directory_fd", "__lock_fd", "__owner_pid", "__closed")

    def __init__(self, directory_fd: int, lock_fd: int) -> None:
        self.__directory_fd = directory_fd
        self.__lock_fd = lock_fd
        self.__owner_pid = os.getpid()
        self.__closed = False

    @classmethod
    def acquire(cls, root: _RootAnchor) -> "_SnapshotWriterLease":
        if _fork_lock_state_poisoned() or _fork_child_lock_state_poisoned():
            raise _SnapshotWriterUnavailable("durable snapshot writer is unavailable")
        directory_fd = root._open_directory(_SNAPSHOT_LOCKS_PARTS, create=True)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            def verify_lock(fd: int) -> None:
                info = os.fstat(fd)
                lexical = os.stat(
                    _SNAPSHOT_WRITER_LOCK_NAME,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                    or (info.st_dev, info.st_ino)
                    != (lexical.st_dev, lexical.st_ino)
                ):
                    raise AuthorityRuntimeError("durable snapshot writer is invalid")

            lock_fd = _acquire_fork_safe_lock(
                directory_fd=directory_fd,
                name=_SNAPSHOT_WRITER_LOCK_NAME,
                flags=flags,
                label="durable snapshot writer",
                wait=False,
                verify=verify_lock,
            )
            if lock_fd is None:
                raise _SnapshotWriterBusy("durable snapshot writer is active")
            return cls(directory_fd, lock_fd)
        except BaseException:
            os.close(directory_fd)
            raise

    def _require_active(self) -> None:
        if self.__closed or os.getpid() != self.__owner_pid:
            raise AuthorityRuntimeError("durable snapshot writer is unavailable")

    def close(self) -> None:
        if self.__closed:
            return
        self._require_active()
        self.__closed = True
        close_error: AuthorityRuntimeError | None = None
        try:
            _release_tracked_lock(
                self.__lock_fd,
                label="durable snapshot writer",
            )
        except AuthorityRuntimeError as exc:
            close_error = exc
        try:
            os.close(self.__directory_fd)
        except OSError as exc:
            if close_error is None:
                close_error = AuthorityRuntimeError("durable snapshot writer is unavailable")
                close_error.__cause__ = exc
        if close_error is not None:
            raise close_error


class _SnapshotClaimDenied(AuthorityRuntimeError):
    """The one active pre-effect claim belongs to different sealed input."""


class _SnapshotClaimBusy(AuthorityRuntimeError):
    """A sealed unfinished or blocked history cannot admit a new claim."""

    def __init__(self, message: str, *, reason_code: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class _SnapshotBindingValue:
    """Private immutable binding value crossing the coordinator/store boundary."""

    effect_id: str
    target_relative_path: str
    artifact_ref_sha256: str
    request_sha256: str
    scope_sha256: str
    bounds_sha256: str
    spec_identity: str
    spec_sha256: str
    policy_identity_sha256: str
    token_request_sha256: str
    token_continuation_identity: str
    token_authentication_tag: str
    binding_sha256: str

    def __post_init__(self) -> None:
        if any(type(value) is not str for value in self.__dict__.values()):
            raise TypeError("durable snapshot binding is invalid")


@dataclass(frozen=True)
class _SnapshotTargetClaimValue:
    """Private immutable target claim crossing the coordinator/store boundary."""

    target_relative_path: str
    effect_id: str
    binding_sha256: str

    def __post_init__(self) -> None:
        if any(type(value) is not str for value in self.__dict__.values()):
            raise TypeError("durable snapshot target claim is invalid")


@dataclass(frozen=True)
class _SnapshotPublishedAttestationValue:
    """Private immutable readback proof sealed with a PUBLISHED transition."""

    effect_id: str
    target_relative_path: str
    binding_sha256: str
    artifact_bytes_sha256: str
    byte_length: int
    target_device: int
    target_inode: int
    target_nlink: int
    attestation_sha256: str

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str
                for value in (
                    self.effect_id,
                    self.target_relative_path,
                    self.binding_sha256,
                    self.artifact_bytes_sha256,
                    self.attestation_sha256,
                )
            )
            or any(
                type(value) is not int
                for value in (
                    self.byte_length,
                    self.target_device,
                    self.target_inode,
                    self.target_nlink,
                )
            )
        ):
            raise TypeError("durable published attestation is invalid")


@dataclass(frozen=True)
class _SnapshotFinalCasResultValue:
    """Private immutable successful final-CAS result."""

    effect_id: str
    binding_sha256: str
    published_attestation_sha256: str
    expected_state: str
    resulting_state: str
    result_sha256: str

    def __post_init__(self) -> None:
        if any(type(value) is not str for value in self.__dict__.values()):
            raise TypeError("durable final CAS result is invalid")


@dataclass(frozen=True)
class _SnapshotRecoveryBlockerValue:
    """Private immutable blocker evidence sealed with BLOCKED_RECOVERY."""

    effect_id: str
    binding_sha256: str
    reason_code: str
    observed_evidence_sha256: str
    token_request_sha256: str
    token_continuation_identity: str
    blocker_sha256: str

    def __post_init__(self) -> None:
        if any(type(value) is not str for value in self.__dict__.values()):
            raise TypeError("durable recovery blocker is invalid")


class _SnapshotBindingConflict(AuthorityRuntimeError):
    """A binding key is already sealed to different immutable evidence."""


class _SnapshotTargetClaimConflict(AuthorityRuntimeError):
    """A final target is already sealed to a different durable effect."""


class _DurableSnapshotStore:
    """Private :memory: SQLite store sealed by immutable snapshot heads."""

    __slots__ = (
        "__root",
        "__lease",
        "__connection",
        "__head_sha256",
        "__generation",
        "__history_profile",
        "__legacy_witness",
        "__owner_pid",
        "__closed",
    )

    def __init__(
        self,
        root: _RootAnchor,
        lease: _SnapshotWriterLease,
        connection: sqlite3.Connection,
        *,
        head_sha256: str | None,
        generation: int,
        history_profile: _SnapshotHistoryProfile,
        legacy_witness: _LegacyV1Inventory | None,
    ) -> None:
        if legacy_witness is not None and type(legacy_witness) is not _LegacyV1Inventory:
            raise TypeError("durable legacy witness is invalid")
        self.__root = root
        self.__lease = lease
        self.__connection = connection
        self.__head_sha256 = head_sha256
        self.__generation = generation
        self.__history_profile = history_profile
        self.__legacy_witness = legacy_witness
        self.__owner_pid = os.getpid()
        self.__closed = False

    @property
    def root(self) -> _RootAnchor:
        self._require_active()
        return self.__root

    @staticmethod
    def _legacy_inventory_evidence_sha256(*, detail: str) -> str:
        if type(detail) is not str or not detail:
            raise ValueError("durable legacy inventory detail is invalid")
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "kind": "LEGACY_D1A_V1_FENCE",
                    "detail": detail,
                }
            )
        )

    @classmethod
    def _legacy_fence(
        cls,
        *,
        detail: str,
        publish_root_stop: bool = False,
    ) -> _SnapshotLegacyFenceRequired:
        return _SnapshotLegacyFenceRequired(
            "durable legacy V1 input is fenced",
            reason_code="RECOVERY_LEGACY_V1_FENCE",
            observed_evidence_sha256=cls._legacy_inventory_evidence_sha256(
                detail=detail
            ),
            publish_root_stop=publish_root_stop,
        )

    @classmethod
    def _legacy_inventory_fence(
        cls,
        inventory: _LegacyV1Inventory,
        *,
        detail: str,
        publish_root_stop: bool = False,
    ) -> _SnapshotLegacyFenceRequired:
        if type(inventory) is not _LegacyV1Inventory:
            raise TypeError("durable legacy inventory is invalid")
        return _SnapshotLegacyFenceRequired(
            "durable legacy V1 input is fenced",
            reason_code="RECOVERY_LEGACY_V1_FENCE",
            observed_evidence_sha256=sha256_bytes(
                canonical_json_bytes(
                    {
                        "schema_version": 1,
                        "kind": "LEGACY_D1A_V1_FENCE",
                        "detail": detail,
                        "legacy_input_digest_sha256": inventory.input_digest_sha256,
                    }
                )
            ),
            publish_root_stop=publish_root_stop,
        )

    @staticmethod
    def _root_stop_evidence(detail: str) -> str:
        if type(detail) is not str or not detail:
            raise ValueError("durable root-stop detail is invalid")
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "kind": "DURABLE_ROOT_STOP_EVIDENCE",
                    "detail": detail,
                }
            )
        )

    @classmethod
    def _root_stop_invalid(cls, *, detail: str) -> _SnapshotRootStopRequired:
        return _SnapshotRootStopRequired(
            "durable snapshot root stop is invalid",
            reason_code="RECOVERY_ROOT_STOP_INVALID",
            observed_evidence_sha256=cls._root_stop_evidence(detail),
        )

    @classmethod
    def _observed_protocol_directory_members(
        cls,
        root: _RootAnchor,
        parts: tuple[str, ...],
        *,
        maximum_entries: int,
    ) -> tuple[dict[str, object], ...]:
        """Return a bounded, anchored forensic projection of one V2 directory."""

        directory = root.joinpath(*parts)
        before_marker = root.directory_change_marker(parts)
        names = root.list_directory_bounded(
            directory,
            maximum_entries=maximum_entries,
        )
        members: list[dict[str, object]] = []
        for name in names:
            directory_fd: int | None = None
            try:
                directory_fd = root._open_directory(parts, create=False)
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise AuthorityRuntimeError(
                    "durable root-stop observation is unavailable"
                ) from exc
            finally:
                if directory_fd is not None:
                    os.close(directory_fd)
            identity = _SnapshotFileIdentity.from_stat(info)
            raw_sha256: str | None = None
            if stat.S_ISREG(info.st_mode) and info.st_size <= _MAX_ARTIFACT_BYTES:
                try:
                    observed_info, raw = cls._read_protocol_file(
                        root,
                        directory / name,
                        label="durable root-stop observation member",
                    )
                except AuthorityRuntimeError:
                    pass
                else:
                    if _SnapshotFileIdentity.from_stat(observed_info) == identity:
                        raw_sha256 = sha256_bytes(raw)
            members.append(
                {
                    "name_hex": os.fsencode(name).hex(),
                    "file_type": stat.S_IFMT(info.st_mode),
                    "identity": {
                        "device": identity.device,
                        "inode": identity.inode,
                        "link_count": identity.link_count,
                        "owner": identity.owner,
                        "mode": identity.mode,
                        "byte_length": identity.byte_length,
                    },
                    "raw_sha256": raw_sha256,
                }
            )
        if root.directory_change_marker(parts) != before_marker:
            raise AuthorityRuntimeError("durable root-stop observation changed")
        return tuple(members)

    @classmethod
    def _root_stop_observation(
        cls,
        root: _RootAnchor,
    ) -> tuple[str, str]:
        remaining = _MAX_SNAPSHOT_PROTOCOL_ENTRIES
        observations: dict[str, tuple[dict[str, object], ...]] = {}
        for name, parts in (
            ("heads", _SNAPSHOT_HEADS_PARTS),
            ("objects", _SNAPSHOT_OBJECTS_PARTS),
            ("head-receipts", _SNAPSHOT_RECEIPTS_PARTS),
        ):
            if remaining < 1:
                raise AuthorityRuntimeError("durable root-stop observation overflow")
            members = cls._observed_protocol_directory_members(
                root,
                parts,
                maximum_entries=remaining,
            )
            observations[name] = members
            remaining -= len(members)
        head_set_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "kind": "DURABLE_ROOT_STOP_HEAD_SET",
                    "members": observations["heads"],
                }
            )
        )
        namespace_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "kind": "DURABLE_ROOT_STOP_NAMESPACE",
                    "heads": observations["heads"],
                    "objects": observations["objects"],
                    "head_receipts": observations["head-receipts"],
                }
            )
        )
        return head_set_sha256, namespace_sha256

    @classmethod
    def _require_no_root_stop(cls, root: _RootAnchor) -> None:
        directory = root.joinpath(*_SNAPSHOT_ROOT_STOPS_PARTS)
        try:
            names = root.list_directory_bounded(
                directory,
                maximum_entries=_MAX_SNAPSHOT_PROTOCOL_ENTRIES,
            )
        except AuthorityRuntimeError as exc:
            raise cls._root_stop_invalid(detail="root-stops-unavailable") from exc
        if not names:
            return
        if len(names) != 1:
            raise cls._root_stop_invalid(detail="root-stops-duplicate")
        match = _ROOT_STOP_NAME.fullmatch(names[0])
        if match is None:
            raise cls._root_stop_invalid(detail="root-stops-unknown-name")
        try:
            info, raw = cls._read_protocol_file(
                root,
                directory / names[0],
                label="durable snapshot root stop",
            )
            payload = cls._parse_canonical_json(
                raw,
                label="durable snapshot root stop",
            )
        except AuthorityRuntimeError as exc:
            raise cls._root_stop_invalid(detail="root-stops-unreadable") from exc
        if (
            info.st_nlink != 1
            or sha256_bytes(raw) != match.group(1)
            or set(payload)
            != {
                "protocol_version",
                "kind",
                "anchor_identity_sha256",
                "observed_head_set_sha256",
                "observed_namespace_sha256",
                "reason_code",
                "observed_evidence_sha256",
            }
            or payload.get("protocol_version") != 1
            or payload.get("kind") != "DURABLE_ROOT_STOP"
            or type(payload.get("reason_code")) is not str
            or _RECOVERY_REASON.fullmatch(payload["reason_code"]) is None
            or any(
                type(payload.get(field)) is not str
                or _SHA256.fullmatch(payload[field]) is None
                for field in (
                    "anchor_identity_sha256",
                    "observed_head_set_sha256",
                    "observed_namespace_sha256",
                    "observed_evidence_sha256",
                )
            )
        ):
            raise cls._root_stop_invalid(detail="root-stops-malformed")
        try:
            observed_head_set_sha256, observed_namespace_sha256 = (
                cls._root_stop_observation(root)
            )
        except AuthorityRuntimeError as exc:
            raise cls._root_stop_invalid(detail="root-stops-observation-unavailable") from exc
        if (
            payload["anchor_identity_sha256"]
            != sha256_bytes(canonical_json_bytes(root.identity))
            or payload["observed_head_set_sha256"] != observed_head_set_sha256
            or payload["observed_namespace_sha256"] != observed_namespace_sha256
        ):
            raise cls._root_stop_invalid(detail="root-stops-observation-mismatch")
        raise _SnapshotRootStopRequired(
            "durable snapshot root is stopped",
            reason_code=payload["reason_code"],
            observed_evidence_sha256=payload["observed_evidence_sha256"],
        )

    @classmethod
    def _publish_root_stop_if_possible(
        cls,
        root: _RootAnchor,
        *,
        reason_code: str,
        observed_evidence_sha256: str,
    ) -> None:
        if (
            type(reason_code) is not str
            or _RECOVERY_REASON.fullmatch(reason_code) is None
            or type(observed_evidence_sha256) is not str
            or _SHA256.fullmatch(observed_evidence_sha256) is None
        ):
            raise ValueError("durable root-stop input is invalid")
        try:
            observed_head_set_sha256, observed_namespace_sha256 = (
                cls._root_stop_observation(root)
            )
            payload = {
                "protocol_version": 1,
                "kind": "DURABLE_ROOT_STOP",
                "anchor_identity_sha256": sha256_bytes(
                    canonical_json_bytes(root.identity)
                ),
                "observed_head_set_sha256": observed_head_set_sha256,
                "observed_namespace_sha256": observed_namespace_sha256,
                "reason_code": reason_code,
                "observed_evidence_sha256": observed_evidence_sha256,
            }
            raw = canonical_json_bytes(payload)
            root.publish_bytes(
                root.joinpath(
                    *_SNAPSHOT_ROOT_STOPS_PARTS,
                    f"f-{sha256_bytes(raw)}.json",
                ),
                raw,
                label="durable snapshot root stop",
            )
        except (AuthorityRuntimeError, OSError):
            # A root stop is best-effort only when the root is already
            # untrusted.  The caller still returns its typed fence.
            return

    @classmethod
    def _inventory_legacy_v1(
        cls,
        root: _RootAnchor,
        *,
        allow_snapshot_staging: bool = False,
    ) -> _LegacyV1Inventory | None:
        """Collect V1 candidates through the anchored runtime directory FD."""

        if type(allow_snapshot_staging) is not bool:
            raise TypeError("durable legacy staging allowance is invalid")

        runtime_fd: int | None = None
        try:
            try:
                runtime_fd = root._open_directory(_RUNTIME_PARTS, create=False)
            except FileNotFoundError:
                return None
            try:
                before_directory = os.fstat(runtime_fd)
                names = tuple(sorted(os.listdir(runtime_fd)))
            except OSError as exc:
                raise cls._legacy_fence(detail="runtime-directory-unavailable") from exc
            if _LEGACY_V1_DATABASE_NAME not in names:
                if any(name not in _LEGACY_V1_ALLOWED_RUNTIME_NAMES for name in names):
                    raise cls._legacy_fence(
                        detail="legacy-artifact-without-database"
                    )
                return None
            if not allow_snapshot_staging:
                try:
                    before_staging_marker = root.directory_change_marker(
                        _SNAPSHOT_STAGING_PARTS
                    )
                    stage_names = root.list_directory_bounded(
                        root.joinpath(*_SNAPSHOT_STAGING_PARTS),
                        maximum_entries=_MAX_SNAPSHOT_PROTOCOL_ENTRIES,
                    )
                    after_staging_marker = root.directory_change_marker(
                        _SNAPSHOT_STAGING_PARTS
                    )
                except FileNotFoundError:
                    # Before fresh V2 namespace creation, an absent V2 staging
                    # directory is the expected no-stage proof for an L1
                    # preflight.  It is not legacy stage evidence.
                    before_staging_marker = None
                    stage_names = ()
                    after_staging_marker = None
                except AuthorityRuntimeError as exc:
                    raise cls._legacy_fence(
                        detail="legacy-stage-unavailable"
                    ) from exc
                if before_staging_marker != after_staging_marker or stage_names:
                    raise cls._legacy_fence(detail="legacy-stage-present")
            legacy_runtime_names = tuple(
                name
                for name in names
                if name not in _LEGACY_V1_ALLOWED_RUNTIME_NAMES
            )
            legacy_runtime_names = tuple(
                sorted(legacy_runtime_names + (_LEGACY_V1_DATABASE_NAME,))
            )
            members: list[_LegacyV1InputFile] = []
            if _LEGACY_V1_DATABASE_NAME in legacy_runtime_names:
                database_path = root.joinpath(
                    *_RUNTIME_PARTS,
                    _LEGACY_V1_DATABASE_NAME,
                )
                try:
                    info, raw = safety.read_regular_file_at(
                        runtime_fd,
                        _LEGACY_V1_DATABASE_NAME,
                        database_path.display_path,
                        label="durable legacy V1 database",
                        expected_mode=0o600,
                        max_bytes=_MAX_ARTIFACT_BYTES,
                        error_type=_LegacyV1InventoryError,
                    )
                    lexical = os.stat(
                        _LEGACY_V1_DATABASE_NAME,
                        dir_fd=runtime_fd,
                        follow_symlinks=False,
                    )
                except (OSError, _LegacyV1InventoryError) as exc:
                    raise cls._legacy_fence(detail="database-unreadable") from exc
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or (info.st_dev, info.st_ino)
                    != (lexical.st_dev, lexical.st_ino)
                ):
                    raise cls._legacy_fence(detail="database-identity-changed")
                members.append(
                    _LegacyV1InputFile(
                        relative_parts=_RUNTIME_PARTS
                        + (_LEGACY_V1_DATABASE_NAME,),
                        raw=raw,
                        raw_sha256=sha256_bytes(raw),
                        identity=_SnapshotFileIdentity.from_stat(info),
                    )
                )
            try:
                after_directory = os.fstat(runtime_fd)
            except OSError as exc:
                raise cls._legacy_fence(detail="runtime-directory-unavailable") from exc
            if (
                (before_directory.st_dev, before_directory.st_ino)
                != (after_directory.st_dev, after_directory.st_ino)
                or before_directory.st_ctime_ns != after_directory.st_ctime_ns
            ):
                raise cls._legacy_fence(detail="runtime-directory-changed")
            input_digest_sha256 = sha256_bytes(
                canonical_json_bytes(
                    {
                        "schema_version": 1,
                        "kind": "LEGACY_D1A_V1_INPUT",
                        "legacy_runtime_names": list(legacy_runtime_names),
                        "members": [
                            {
                                "relative_parts": list(member.relative_parts),
                                "raw_sha256": member.raw_sha256,
                                "identity": {
                                    "device": member.identity.device,
                                    "inode": member.identity.inode,
                                    "link_count": member.identity.link_count,
                                    "owner": member.identity.owner,
                                    "mode": member.identity.mode,
                                    "byte_length": member.identity.byte_length,
                                },
                            }
                            for member in members
                        ],
                    }
                )
            )
            return _LegacyV1Inventory(
                members=tuple(members),
                legacy_runtime_names=legacy_runtime_names,
                input_digest_sha256=input_digest_sha256,
            )
        except _SnapshotLegacyFenceRequired:
            raise
        except (AuthorityRuntimeError, OSError) as exc:
            raise cls._legacy_fence(detail="inventory-unavailable") from exc
        finally:
            if runtime_fd is not None:
                try:
                    os.close(runtime_fd)
                except OSError as exc:
                    raise cls._legacy_fence(detail="runtime-directory-unavailable") from exc

    @classmethod
    def _classify_legacy_v1(
        cls,
        inventory: _LegacyV1Inventory,
    ) -> _LegacyV1Classification:
        """Admit only the exact legacy rows covered by the current matrix."""

        if (
            inventory.legacy_runtime_names != (_LEGACY_V1_DATABASE_NAME,)
            or len(inventory.members) != 1
            or inventory.members[0].relative_parts
            != _RUNTIME_PARTS + (_LEGACY_V1_DATABASE_NAME,)
        ):
            raise cls._legacy_inventory_fence(inventory, detail="legacy-topology")
        member = inventory.members[0]
        connection: sqlite3.Connection | None = None
        try:
            connection = cls._new_connection()
            connection.set_authorizer(None)
            connection.deserialize(member.raw)
            cls._configure_connection(connection)
            table_rows = tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT type, name, tbl_name FROM sqlite_master "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
                )
            )
            column_signature = tuple(
                (
                    row["name"],
                    row["type"],
                    row["notnull"],
                    row["dflt_value"],
                    row["pk"],
                )
                for row in connection.execute("PRAGMA table_info(durable_effects)")
            )
            index_signature = frozenset(
                (
                    row["origin"],
                    row["unique"],
                    row["partial"],
                    tuple(
                        index_member["name"]
                        for index_member in connection.execute(
                            "SELECT name FROM pragma_index_info(?) ORDER BY seqno",
                            (row["name"],),
                        )
                    ),
                )
                for row in connection.execute("PRAGMA index_list(durable_effects)")
            )
            integrity_rows = tuple(
                tuple(row) for row in connection.execute("PRAGMA integrity_check")
            )
            foreign_key_rows = tuple(
                tuple(row)
                for row in connection.execute("PRAGMA foreign_key_list(durable_effects)")
            )
            schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            legacy_effect_count_row = connection.execute(
                "SELECT COUNT(*) FROM durable_effects"
            ).fetchone()
            schema_fingerprint = cls._schema_fingerprint_for(connection)
        except (AuthorityRuntimeError, sqlite3.Error, TypeError, ValueError) as exc:
            raise cls._legacy_inventory_fence(
                inventory,
                detail="legacy-database-unreadable",
            ) from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
        if (
            table_rows != (("table", "durable_effects", "durable_effects"),)
            or column_signature != _LEGACY_V1_EFFECT_COLUMN_SIGNATURE
            or index_signature != _LEGACY_V1_EFFECT_INDEX_SIGNATURE
            or integrity_rows != (("ok",),)
            or foreign_key_rows != ()
            or schema_version != 1
            or user_version != 0
            or application_id != 0
            or schema_fingerprint != cls._expected_legacy_v1_schema_fingerprint()
        ):
            raise cls._legacy_inventory_fence(inventory, detail="legacy-schema")
        if (
            legacy_effect_count_row is None
            or type(legacy_effect_count_row[0]) is not int
        ):
            raise cls._legacy_inventory_fence(inventory, detail="legacy-row-count")
        if legacy_effect_count_row[0] != 0:
            raise cls._legacy_inventory_fence(
                inventory,
                detail="legacy-nonempty",
                publish_root_stop=False,
            )
        legacy_provenance_raw = canonical_json_bytes(
            {
                "schema_version": 1,
                "kind": "LEGACY_D1A_V1_PROVENANCE",
                "classification": "L1",
                "legacy_input_digest_sha256": inventory.input_digest_sha256,
                "legacy_runtime_names": list(inventory.legacy_runtime_names),
                "members": [
                    {
                        "relative_parts": list(member.relative_parts),
                        "raw_sha256": member.raw_sha256,
                        "identity": {
                            "device": member.identity.device,
                            "inode": member.identity.inode,
                            "link_count": member.identity.link_count,
                            "owner": member.identity.owner,
                            "mode": member.identity.mode,
                            "byte_length": member.identity.byte_length,
                        },
                    }
                    for member in inventory.members
                ],
                "legacy_database_schema_fingerprint_sha256": schema_fingerprint,
                "sidecar_absence_proof": True,
                "bridge_absence_proof": True,
                "stage_absence_proof": True,
            }
        )
        return _LegacyV1Classification(
            inventory=inventory,
            legacy_provenance_raw=legacy_provenance_raw,
            legacy_provenance_sha256=sha256_bytes(legacy_provenance_raw),
            retired_witness_sha256=inventory.input_digest_sha256,
        )

    @classmethod
    def _verify_legacy_v1_inventory(
        cls,
        root: _RootAnchor,
        expected: _LegacyV1Inventory,
        *,
        allow_snapshot_staging: bool = False,
    ) -> None:
        try:
            observed = cls._inventory_legacy_v1(
                root,
                allow_snapshot_staging=allow_snapshot_staging,
            )
        except _SnapshotLegacyFenceRequired as exc:
            raise cls._legacy_witness_fence(exc) from exc
        if observed != expected:
            raise cls._legacy_inventory_fence(
                expected,
                detail="legacy-witness-changed",
                publish_root_stop=True,
            )

    @staticmethod
    def _legacy_witness_fence(
        exc: _SnapshotLegacyFenceRequired,
    ) -> _SnapshotLegacyFenceRequired:
        """Upgrade an observed retired-witness mismatch to a V2 root-stop fence."""

        if type(exc) is not _SnapshotLegacyFenceRequired:
            raise TypeError("durable legacy witness fence is invalid")
        return _SnapshotLegacyFenceRequired(
            str(exc),
            reason_code=exc.reason_code,
            observed_evidence_sha256=exc.observed_evidence_sha256,
            publish_root_stop=True,
        )

    @staticmethod
    def _snapshot_namespace_exists(root: _RootAnchor) -> bool:
        """Probe V2 namespace presence without creating any authority state."""

        directory_fd: int | None = None
        try:
            directory_fd = root._open_directory(_SNAPSHOT_PARTS, create=False)
        except FileNotFoundError:
            return False
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
        return True

    @classmethod
    def open(cls, root: _RootAnchor) -> "_DurableSnapshotStore":
        # A fresh root must classify legacy input before taking the V2 writer
        # lease, because creating that lease also creates V2 directories.  An
        # existing V2 namespace stays on the normal V2 discovery path below so
        # a retired L1 witness can still be root-stopped on drift.
        preflight_legacy_inventory: _LegacyV1Inventory | None = None
        if not cls._snapshot_namespace_exists(root):
            preflight_legacy_inventory = cls._inventory_legacy_v1(
                root,
                allow_snapshot_staging=False,
            )
            if preflight_legacy_inventory is not None:
                cls._classify_legacy_v1(preflight_legacy_inventory)
        lease = _SnapshotWriterLease.acquire(root)
        connection: sqlite3.Connection | None = None
        try:
            cls._ensure_namespace(root)
            cls._require_no_root_stop(root)
            if preflight_legacy_inventory is not None:
                # A caller that presented exact L1 before the lease must not
                # become a fresh V2 root if that retired input disappears or
                # changes while waiting for the writer.  Recheck after the
                # namespace exists so a feasible witness fence can seal a
                # root stop, but before any history discovery or genesis.
                cls._verify_legacy_v1_inventory(
                    root,
                    preflight_legacy_inventory,
                    allow_snapshot_staging=False,
                )
            try:
                namespace_identities = cls._snapshot_namespace_identities(root)
                discovered = cls._discover_tip(root, namespace_identities)
                cls._verify_snapshot_namespace_identities(root, namespace_identities)
            except _SnapshotHistoryUnavailable:
                raise
            except AuthorityRuntimeError as exc:
                reason_code = "RECOVERY_SNAPSHOT_HISTORY_CHANGED"
                observed_evidence_sha256 = cls._root_stop_evidence(
                    "snapshot-open-history-untrusted"
                )
                cls._publish_root_stop_if_possible(
                    root,
                    reason_code=reason_code,
                    observed_evidence_sha256=observed_evidence_sha256,
                )
                raise _SnapshotRootStopRequired(
                    "durable snapshot history changed",
                    reason_code=reason_code,
                    observed_evidence_sha256=observed_evidence_sha256,
                ) from exc
            connection = cls._new_connection()
            if discovered is None:
                legacy_inventory = cls._inventory_legacy_v1(
                    root,
                    allow_snapshot_staging=False,
                )
                legacy_classification = (
                    cls._classify_legacy_v1(legacy_inventory)
                    if legacy_inventory is not None
                    else None
                )
                if legacy_inventory is not None:
                    cls._verify_legacy_v1_inventory(root, legacy_inventory)
                cls._create_schema(connection)
                store = cls(
                    root,
                    lease,
                    connection,
                    head_sha256=None,
                    generation=-1,
                    history_profile=_SnapshotHistoryProfile(
                        cls._history_namespace_identities(namespace_identities),
                        cls._history_directory_change_markers(root),
                        (),
                    ),
                    legacy_witness=(
                        legacy_classification.inventory
                        if legacy_classification is not None
                        else None
                    ),
                )
                store._create_recovery_token_key()
                store.checkpoint(
                    "EMPTY_GENESIS",
                    _initial_legacy=legacy_classification,
                )
                return store
            head_sha256, head, snapshot_raw, history_profile = discovered
            connection.set_authorizer(None)
            connection.deserialize(snapshot_raw)
            cls._configure_connection(connection)
            cls._verify_schema(connection)
            meta = connection.execute(
                "SELECT transition_kind, generation, parent_head_sha256 "
                "FROM snapshot_meta WHERE singleton = 1"
            ).fetchone()
            if (
                meta is None
                or meta[1] != head["generation"]
                or meta[2] != head["parent_head_sha256"]
            ):
                raise AuthorityRuntimeError("durable snapshot metadata is invalid")
            migration_rows = tuple(
                connection.execute(
                    "SELECT legacy_provenance_sha256, retired_witness_sha256, "
                    "legacy_provenance_canonical_json "
                    "FROM durable_migration_provenance ORDER BY singleton"
                )
            )
            legacy_witness: _LegacyV1Inventory | None = None
            if migration_rows:
                try:
                    legacy_inventory = cls._inventory_legacy_v1(
                        root,
                        allow_snapshot_staging=True,
                    )
                except _SnapshotLegacyFenceRequired as exc:
                    raise cls._legacy_witness_fence(exc) from exc
                if legacy_inventory is None:
                    raise cls._legacy_fence(
                        detail="retired-witness-missing",
                        publish_root_stop=True,
                    )
                try:
                    legacy_classification = cls._classify_legacy_v1(legacy_inventory)
                except _SnapshotLegacyFenceRequired as exc:
                    raise cls._legacy_witness_fence(exc) from exc
                if (
                    len(migration_rows) != 1
                    or tuple(migration_rows[0])
                    != (
                        legacy_classification.legacy_provenance_sha256,
                        legacy_classification.retired_witness_sha256,
                        legacy_classification.legacy_provenance_raw,
                    )
                ):
                    raise cls._legacy_inventory_fence(
                        legacy_inventory,
                        detail="retired-witness-mismatch",
                        publish_root_stop=True,
                )
                legacy_witness = legacy_classification.inventory
            else:
                legacy_inventory = cls._inventory_legacy_v1(
                    root,
                    allow_snapshot_staging=True,
                )
                if legacy_inventory is not None:
                    raise cls._legacy_inventory_fence(
                        legacy_inventory,
                        detail="legacy-input-with-nonlegacy-lineage",
                    )
            store = cls(
                root,
                lease,
                connection,
                head_sha256=head_sha256,
                generation=head["generation"],
                history_profile=history_profile,
                legacy_witness=legacy_witness,
            )
            store.recovery_token_key()
            return store
        except BaseException as exc:
            if (
                isinstance(exc, _SnapshotLegacyFenceRequired)
                and exc.publish_root_stop
            ):
                cls._publish_root_stop_if_possible(
                    root,
                    reason_code=exc.reason_code,
                    observed_evidence_sha256=exc.observed_evidence_sha256,
                )
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            try:
                lease.close()
            except AuthorityRuntimeError:
                pass
            raise

    @staticmethod
    def _ensure_namespace(root: _RootAnchor) -> None:
        for parts in (
            _SNAPSHOT_OBJECTS_PARTS,
            _SNAPSHOT_RECEIPTS_PARTS,
            _SNAPSHOT_HEADS_PARTS,
            _SNAPSHOT_LOCKS_PARTS,
            _SNAPSHOT_STAGING_PARTS,
            _SNAPSHOT_ROOT_STOPS_PARTS,
        ):
            directory_fd = root._open_directory(parts, create=True)
            os.close(directory_fd)

    @staticmethod
    def _snapshot_namespace_identities(
        root: _RootAnchor,
    ) -> tuple[tuple[tuple[str, ...], tuple[int, int, int, int, int]], ...]:
        return tuple(
            (parts, root.directory_identity(parts))
            for parts in _SNAPSHOT_NAMESPACE_PARTS
        )

    @staticmethod
    def _history_namespace_identities(
        namespace_identities: tuple[
            tuple[tuple[str, ...], tuple[int, int, int, int, int]], ...
        ],
    ) -> tuple[tuple[tuple[str, ...], tuple[int, int, int, int]], ...]:
        """Exclude mutable sibling counts from an active history identity."""

        return tuple(
            (parts, (identity[0], identity[1], identity[3], identity[4]))
            for parts, identity in namespace_identities
        )

    @staticmethod
    def _history_directory_change_markers(
        root: _RootAnchor,
    ) -> tuple[tuple[tuple[str, ...], tuple[int, int, int]], ...]:
        return tuple(
            (parts, root.directory_change_marker(parts))
            for parts in _SNAPSHOT_HISTORY_MARKER_PARTS
        )

    @staticmethod
    def _verify_snapshot_namespace_identities(
        root: _RootAnchor,
        expected: tuple[tuple[tuple[str, ...], tuple[int, int, int, int, int]], ...],
    ) -> None:
        if type(expected) is not tuple or not expected:
            raise AuthorityRuntimeError("durable snapshot namespace is invalid")
        try:
            observed = _DurableSnapshotStore._snapshot_namespace_identities(root)
        except (AuthorityRuntimeError, TypeError, ValueError) as exc:
            raise AuthorityRuntimeError("durable snapshot namespace is invalid") from exc
        if observed != expected:
            raise AuthorityRuntimeError("durable snapshot namespace changed")

    @staticmethod
    def _authorizer(
        action_code: int,
        _arg1: str | None,
        _arg2: str | None,
        _database: str | None,
        _trigger: str | None,
    ) -> int:
        if action_code in {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH} or (
            action_code == sqlite3.SQLITE_FUNCTION
            and type(_arg2) is str
            and _arg2.lower() == "load_extension"
        ):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    @classmethod
    def _new_connection(cls) -> sqlite3.Connection:
        if not hasattr(sqlite3.Connection, "serialize") or not hasattr(
            sqlite3.Connection, "deserialize"
        ):
            raise AuthorityRuntimeError("durable snapshot runtime is unavailable")
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            cls._configure_connection(connection)
            return connection
        except BaseException:
            connection.close()
            raise

    @classmethod
    def _configure_connection(cls, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("PRAGMA journal_mode=MEMORY")
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            connection.execute("PRAGMA temp_store=MEMORY")
            temp_store = connection.execute("PRAGMA temp_store").fetchone()[0]
            connection.execute("PRAGMA foreign_keys=ON")
            foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
            connection.execute("PRAGMA trusted_schema=OFF")
            trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()[0]
            connection.set_authorizer(cls._authorizer)
            try:
                connection.execute(
                    "ATTACH DATABASE ':memory:' AS snapshot_forbidden_probe"
                )
            except sqlite3.DatabaseError:
                pass
            else:
                try:
                    connection.execute("DETACH DATABASE snapshot_forbidden_probe")
                except sqlite3.DatabaseError:
                    pass
                raise AuthorityRuntimeError(
                    "durable snapshot attachment gate is unavailable"
                )
            database_rows = tuple(
                tuple(row) for row in connection.execute("PRAGMA database_list")
            )
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable snapshot runtime is unavailable") from exc
        if (
            str(journal_mode).lower() != "memory"
            or int(temp_store) not in {1, 2}
            or int(foreign_keys) != 1
            or int(trusted_schema) != 0
            or database_rows != ((0, "main", ""),)
        ):
            raise AuthorityRuntimeError("durable snapshot memory gate is unavailable")

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE durable_effects ("
            "effect_id TEXT NOT NULL PRIMARY KEY, "
            "target_relative_path TEXT NOT NULL UNIQUE, "
            "artifact_ref BLOB NOT NULL, "
            "artifact_bytes BLOB NOT NULL, "
            "request_sha256 TEXT NOT NULL, "
            "scope_sha256 TEXT NOT NULL, "
            "spec_identity TEXT NOT NULL, "
            "spec_sha256 TEXT NOT NULL, "
            "policy_identity_sha256 TEXT NOT NULL, "
            "state TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE TABLE snapshot_meta ("
            "singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1), "
            "transition_kind TEXT NOT NULL, "
            "generation INTEGER NOT NULL, "
            "parent_head_sha256 TEXT, "
            "publication_nonce TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "INSERT INTO snapshot_meta "
            "(singleton, transition_kind, generation, parent_head_sha256, publication_nonce) "
            "VALUES (1, ?, ?, ?, ?)",
            ("EMPTY_GENESIS", -1, None, "bootstrap"),
        )
        connection.execute(
            "CREATE TABLE durable_claims ("
            "claim_key_sha256 TEXT NOT NULL PRIMARY KEY, "
            "effect_id TEXT NOT NULL UNIQUE, "
            "target_relative_path TEXT NOT NULL UNIQUE, "
            "artifact_ref_sha256 TEXT NOT NULL, "
            "artifact_bytes_sha256 TEXT NOT NULL, "
            "request_sha256 TEXT NOT NULL, "
            "scope_sha256 TEXT NOT NULL, "
            "bounds_sha256 TEXT NOT NULL, "
            "spec_identity TEXT NOT NULL, "
            "spec_sha256 TEXT NOT NULL, "
            "policy_identity_sha256 TEXT NOT NULL, "
            "expected_predecessor_head_sha256 TEXT, "
            "claim_generation INTEGER NOT NULL, "
            "active INTEGER NOT NULL CHECK(active IN (0, 1))"
            ")"
        )
        connection.execute(
            "CREATE TABLE recovery_token_keys ("
            "singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1), "
            "token_key BLOB NOT NULL, "
            "key_sha256 TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE TABLE durable_effect_bindings ("
            "effect_id TEXT NOT NULL PRIMARY KEY, "
            "target_relative_path TEXT NOT NULL UNIQUE, "
            "artifact_ref_sha256 TEXT NOT NULL, "
            "request_sha256 TEXT NOT NULL, "
            "scope_sha256 TEXT NOT NULL, "
            "bounds_sha256 TEXT NOT NULL, "
            "spec_identity TEXT NOT NULL, "
            "spec_sha256 TEXT NOT NULL, "
            "policy_identity_sha256 TEXT NOT NULL, "
            "token_request_sha256 TEXT NOT NULL, "
            "token_continuation_identity TEXT NOT NULL, "
            "token_authentication_tag TEXT NOT NULL, "
            "binding_sha256 TEXT NOT NULL UNIQUE"
            ")"
        )
        connection.execute(
            "CREATE TABLE durable_target_claims ("
            "target_relative_path TEXT NOT NULL PRIMARY KEY, "
            "effect_id TEXT NOT NULL UNIQUE, "
            "binding_sha256 TEXT NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE TABLE durable_published_attestations ("
            "effect_id TEXT NOT NULL PRIMARY KEY, "
            "target_relative_path TEXT NOT NULL UNIQUE, "
            "binding_sha256 TEXT NOT NULL, "
            "artifact_bytes_sha256 TEXT NOT NULL, "
            "byte_length INTEGER NOT NULL, "
            "target_device INTEGER NOT NULL, "
            "target_inode INTEGER NOT NULL, "
            "target_nlink INTEGER NOT NULL, "
            "attestation_sha256 TEXT NOT NULL UNIQUE"
            ")"
        )
        connection.execute(
            "CREATE TABLE durable_final_cas_results ("
            "effect_id TEXT NOT NULL PRIMARY KEY, "
            "binding_sha256 TEXT NOT NULL, "
            "published_attestation_sha256 TEXT NOT NULL, "
            "expected_state TEXT NOT NULL CHECK(expected_state = 'PUBLISHED'), "
            "resulting_state TEXT NOT NULL CHECK(resulting_state = 'FINALIZED'), "
            "result_sha256 TEXT NOT NULL UNIQUE"
            ")"
        )
        connection.execute(
            "CREATE TABLE durable_recovery_blockers ("
            "effect_id TEXT NOT NULL PRIMARY KEY, "
            "binding_sha256 TEXT NOT NULL, "
            "reason_code TEXT NOT NULL, "
            "observed_evidence_sha256 TEXT NOT NULL, "
            "token_request_sha256 TEXT NOT NULL, "
            "token_continuation_identity TEXT NOT NULL, "
            "blocker_sha256 TEXT NOT NULL UNIQUE"
            ")"
        )
        connection.execute(
            "CREATE TABLE durable_migration_provenance ("
            "singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1), "
            "legacy_provenance_sha256 TEXT NOT NULL, "
            "retired_witness_sha256 TEXT NOT NULL, "
            "legacy_provenance_canonical_json BLOB NOT NULL"
            ")"
        )

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        try:
            durable_columns = tuple(
                row["name"]
                for row in connection.execute("PRAGMA table_info(durable_effects)")
            )
            meta_columns = tuple(
                row["name"]
                for row in connection.execute("PRAGMA table_info(snapshot_meta)")
            )
            claim_columns = tuple(
                row["name"]
                for row in connection.execute("PRAGMA table_info(durable_claims)")
            )
            binding_columns = tuple(
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(durable_effect_bindings)"
                )
            )
            target_claim_columns = tuple(
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(durable_target_claims)"
                )
            )
            published_attestation_columns = tuple(
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(durable_published_attestations)"
                )
            )
            final_cas_columns = tuple(
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(durable_final_cas_results)"
                )
            )
            blocker_columns = tuple(
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(durable_recovery_blockers)"
                )
            )
            migration_columns = tuple(
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(durable_migration_provenance)"
                )
            )
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable snapshot schema is invalid") from exc
        if durable_columns != (
            "effect_id",
            "target_relative_path",
            "artifact_ref",
            "artifact_bytes",
            "request_sha256",
            "scope_sha256",
            "spec_identity",
            "spec_sha256",
            "policy_identity_sha256",
            "state",
        ) or meta_columns != (
            "singleton",
            "transition_kind",
            "generation",
            "parent_head_sha256",
            "publication_nonce",
        ) or claim_columns != (
            "claim_key_sha256",
            "effect_id",
            "target_relative_path",
            "artifact_ref_sha256",
            "artifact_bytes_sha256",
            "request_sha256",
            "scope_sha256",
            "bounds_sha256",
            "spec_identity",
            "spec_sha256",
            "policy_identity_sha256",
            "expected_predecessor_head_sha256",
            "claim_generation",
            "active",
        ) or tuple(
            row["name"]
            for row in connection.execute("PRAGMA table_info(recovery_token_keys)")
        ) != (
            "singleton",
            "token_key",
            "key_sha256",
        ) or binding_columns != (
            "effect_id",
            "target_relative_path",
            "artifact_ref_sha256",
            "request_sha256",
            "scope_sha256",
            "bounds_sha256",
            "spec_identity",
            "spec_sha256",
            "policy_identity_sha256",
            "token_request_sha256",
            "token_continuation_identity",
            "token_authentication_tag",
            "binding_sha256",
        ) or target_claim_columns != (
            "target_relative_path",
            "effect_id",
            "binding_sha256",
        ) or published_attestation_columns != (
            "effect_id",
            "target_relative_path",
            "binding_sha256",
            "artifact_bytes_sha256",
            "byte_length",
            "target_device",
            "target_inode",
            "target_nlink",
            "attestation_sha256",
        ) or final_cas_columns != (
            "effect_id",
            "binding_sha256",
            "published_attestation_sha256",
            "expected_state",
            "resulting_state",
            "result_sha256",
        ) or blocker_columns != (
            "effect_id",
            "binding_sha256",
            "reason_code",
            "observed_evidence_sha256",
            "token_request_sha256",
            "token_continuation_identity",
            "blocker_sha256",
        ) or migration_columns != (
            "singleton",
            "legacy_provenance_sha256",
            "retired_witness_sha256",
            "legacy_provenance_canonical_json",
        ):
            raise AuthorityRuntimeError("durable snapshot schema is invalid")
        if _DurableSnapshotStore._schema_fingerprint_for(connection) != (
            _DurableSnapshotStore._expected_schema_fingerprint()
        ):
            raise AuthorityRuntimeError("durable snapshot schema is invalid")

    @classmethod
    def _expected_schema_fingerprint(cls) -> str:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(":memory:", isolation_level=None)
            connection.row_factory = sqlite3.Row
            cls._create_schema(connection)
            return cls._schema_fingerprint_for(connection)
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable snapshot schema is unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    @classmethod
    def _expected_legacy_v1_schema_fingerprint(cls) -> str:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(":memory:", isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute(_LEGACY_V1_DURABLE_EFFECTS_SQL)
            return cls._schema_fingerprint_for(connection)
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError(
                "durable legacy schema is unavailable"
            ) from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_sha256(value: object, *, label: str) -> str:
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise AuthorityRuntimeError(f"{label} is invalid")
        return value

    @staticmethod
    def _require_effect_id(value: object, *, label: str) -> str:
        if type(value) is not str or _EFFECT_ID.fullmatch(value) is None:
            raise AuthorityRuntimeError(f"{label} is invalid")
        return value

    @staticmethod
    def _require_target_path(value: object, *, label: str) -> str:
        if (
            type(value) is not str
            or not value
            or value.startswith("/")
            or any(_PATH_COMPONENT.fullmatch(part) is None for part in value.split("/"))
        ):
            raise AuthorityRuntimeError(f"{label} is invalid")
        return value

    @classmethod
    def _binding_canonical_bytes(cls, value: _SnapshotBindingValue) -> bytes:
        if type(value) is not _SnapshotBindingValue:
            raise AuthorityRuntimeError("durable snapshot binding is invalid")
        return canonical_json_bytes(
            {
                "schema_version": _RECOVERY_PROTOCOL_VERSION,
                "kind": _RECOVERY_BINDING_KIND,
                "recovery_owner": _RECOVERY_OWNER,
                "effect_id": value.effect_id,
                "target_relative_path": value.target_relative_path,
                "artifact_ref_sha256": value.artifact_ref_sha256,
                "request_sha256": value.request_sha256,
                "scope_sha256": value.scope_sha256,
                "bounds_sha256": value.bounds_sha256,
                "spec_identity": value.spec_identity,
                "spec_sha256": value.spec_sha256,
                "policy_identity_sha256": value.policy_identity_sha256,
                "recovery_token": {
                    "schema_version": _RECOVERY_PROTOCOL_VERSION,
                    "effect_id": value.effect_id,
                    "request_sha256": value.token_request_sha256,
                    "continuation_identity": value.token_continuation_identity,
                    "authentication_tag": value.token_authentication_tag,
                },
            }
        )

    @classmethod
    def _binding_continuation_identity(cls, value: _SnapshotBindingValue) -> str:
        if type(value) is not _SnapshotBindingValue:
            raise AuthorityRuntimeError("durable snapshot binding is invalid")
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "schema_version": _RECOVERY_PROTOCOL_VERSION,
                    "effect_id": value.effect_id,
                    "target_relative_path": value.target_relative_path,
                    "artifact_ref_sha256": value.artifact_ref_sha256,
                    "request_sha256": value.request_sha256,
                    "scope_sha256": value.scope_sha256,
                    "bounds_sha256": value.bounds_sha256,
                    "spec_identity": value.spec_identity,
                    "spec_sha256": value.spec_sha256,
                    "policy_identity_sha256": value.policy_identity_sha256,
                }
            )
        )

    @classmethod
    def _validate_binding_value(
        cls,
        value: _SnapshotBindingValue,
        *,
        token_key: bytes,
    ) -> None:
        if type(value) is not _SnapshotBindingValue or type(token_key) is not bytes:
            raise AuthorityRuntimeError("durable snapshot binding is invalid")
        cls._require_effect_id(value.effect_id, label="durable snapshot binding")
        cls._require_target_path(value.target_relative_path, label="durable snapshot binding")
        if type(value.spec_identity) is not str or not value.spec_identity:
            raise AuthorityRuntimeError("durable snapshot binding is invalid")
        for field in (
            value.artifact_ref_sha256,
            value.request_sha256,
            value.scope_sha256,
            value.bounds_sha256,
            value.spec_sha256,
            value.policy_identity_sha256,
            value.token_request_sha256,
            value.token_continuation_identity,
            value.token_authentication_tag,
            value.binding_sha256,
        ):
            cls._require_sha256(field, label="durable snapshot binding")
        if (
            value.token_request_sha256 != value.request_sha256
            or value.token_continuation_identity
            != cls._binding_continuation_identity(value)
            or value.binding_sha256 != sha256_bytes(cls._binding_canonical_bytes(value))
        ):
            raise AuthorityRuntimeError("durable snapshot binding is invalid")
        expected_tag = hmac.new(
            token_key,
            canonical_json_bytes(
                {
                    "schema_version": _RECOVERY_PROTOCOL_VERSION,
                    "effect_id": value.effect_id,
                    "request_sha256": value.token_request_sha256,
                    "continuation_identity": value.token_continuation_identity,
                }
            ),
            sha256,
        ).hexdigest()
        if not hmac.compare_digest(value.token_authentication_tag, expected_tag):
            raise AuthorityRuntimeError("durable snapshot binding is invalid")

    @classmethod
    def _published_attestation_canonical_bytes(
        cls,
        value: _SnapshotPublishedAttestationValue,
    ) -> bytes:
        if type(value) is not _SnapshotPublishedAttestationValue:
            raise AuthorityRuntimeError("durable published attestation is invalid")
        return canonical_json_bytes(
            {
                "schema_version": _RECOVERY_PROTOCOL_VERSION,
                "kind": "DURABLE_PUBLISHED_READBACK",
                "effect_id": value.effect_id,
                "target_relative_path": value.target_relative_path,
                "binding_sha256": value.binding_sha256,
                "artifact_bytes_sha256": value.artifact_bytes_sha256,
                "byte_length": value.byte_length,
                "target_device": value.target_device,
                "target_inode": value.target_inode,
                "target_nlink": value.target_nlink,
            }
        )

    @classmethod
    def published_attestation_sha256(
        cls,
        value: _SnapshotPublishedAttestationValue,
    ) -> str:
        return sha256_bytes(cls._published_attestation_canonical_bytes(value))

    @classmethod
    def _validate_published_attestation_value(
        cls,
        value: _SnapshotPublishedAttestationValue,
    ) -> None:
        if type(value) is not _SnapshotPublishedAttestationValue:
            raise AuthorityRuntimeError("durable published attestation is invalid")
        cls._require_effect_id(value.effect_id, label="durable published attestation")
        cls._require_target_path(
            value.target_relative_path,
            label="durable published attestation",
        )
        for field in (
            value.binding_sha256,
            value.artifact_bytes_sha256,
            value.attestation_sha256,
        ):
            cls._require_sha256(field, label="durable published attestation")
        if (
            value.byte_length < 0
            or value.byte_length > _MAX_ARTIFACT_BYTES
            or value.target_device < 0
            or value.target_inode < 0
            or value.target_nlink < 1
            or value.attestation_sha256 != cls.published_attestation_sha256(value)
        ):
            raise AuthorityRuntimeError("durable published attestation is invalid")

    @classmethod
    def _final_cas_canonical_bytes(
        cls,
        value: _SnapshotFinalCasResultValue,
    ) -> bytes:
        if type(value) is not _SnapshotFinalCasResultValue:
            raise AuthorityRuntimeError("durable final CAS result is invalid")
        return canonical_json_bytes(
            {
                "schema_version": _RECOVERY_PROTOCOL_VERSION,
                "kind": "DURABLE_FINAL_CAS_RESULT",
                "effect_id": value.effect_id,
                "binding_sha256": value.binding_sha256,
                "published_attestation_sha256": value.published_attestation_sha256,
                "expected_state": value.expected_state,
                "resulting_state": value.resulting_state,
            }
        )

    @classmethod
    def final_cas_result_sha256(
        cls,
        value: _SnapshotFinalCasResultValue,
    ) -> str:
        return sha256_bytes(cls._final_cas_canonical_bytes(value))

    @classmethod
    def _validate_final_cas_result_value(
        cls,
        value: _SnapshotFinalCasResultValue,
    ) -> None:
        if type(value) is not _SnapshotFinalCasResultValue:
            raise AuthorityRuntimeError("durable final CAS result is invalid")
        cls._require_effect_id(value.effect_id, label="durable final CAS result")
        for field in (
            value.binding_sha256,
            value.published_attestation_sha256,
            value.result_sha256,
        ):
            cls._require_sha256(field, label="durable final CAS result")
        if (
            value.expected_state != "PUBLISHED"
            or value.resulting_state != "FINALIZED"
            or value.result_sha256 != cls.final_cas_result_sha256(value)
        ):
            raise AuthorityRuntimeError("durable final CAS result is invalid")

    @classmethod
    def _blocker_canonical_bytes(
        cls,
        value: _SnapshotRecoveryBlockerValue,
    ) -> bytes:
        if type(value) is not _SnapshotRecoveryBlockerValue:
            raise AuthorityRuntimeError("durable recovery blocker is invalid")
        return canonical_json_bytes(
            {
                "schema_version": _RECOVERY_PROTOCOL_VERSION,
                "kind": "DURABLE_RECOVERY_BLOCKER",
                "effect_id": value.effect_id,
                "binding_sha256": value.binding_sha256,
                "reason_code": value.reason_code,
                "observed_evidence_sha256": value.observed_evidence_sha256,
                "token_request_sha256": value.token_request_sha256,
                "token_continuation_identity": value.token_continuation_identity,
            }
        )

    @classmethod
    def recovery_blocker_sha256(
        cls,
        value: _SnapshotRecoveryBlockerValue,
    ) -> str:
        return sha256_bytes(cls._blocker_canonical_bytes(value))

    @classmethod
    def _validate_recovery_blocker_value(
        cls,
        value: _SnapshotRecoveryBlockerValue,
    ) -> None:
        if type(value) is not _SnapshotRecoveryBlockerValue:
            raise AuthorityRuntimeError("durable recovery blocker is invalid")
        cls._require_effect_id(value.effect_id, label="durable recovery blocker")
        if type(value.reason_code) is not str or _RECOVERY_REASON.fullmatch(value.reason_code) is None:
            raise AuthorityRuntimeError("durable recovery blocker is invalid")
        for field in (
            value.binding_sha256,
            value.observed_evidence_sha256,
            value.token_request_sha256,
            value.token_continuation_identity,
            value.blocker_sha256,
        ):
            cls._require_sha256(field, label="durable recovery blocker")
        if value.blocker_sha256 != cls.recovery_blocker_sha256(value):
            raise AuthorityRuntimeError("durable recovery blocker is invalid")

    @classmethod
    def _validate_snapshot_rows(cls, connection: sqlite3.Connection) -> None:
        try:
            key_rows = tuple(
                connection.execute(
                    "SELECT singleton, token_key, key_sha256 FROM recovery_token_keys "
                    "ORDER BY singleton"
                )
            )
            effect_rows = tuple(
                connection.execute(
                    "SELECT effect_id, target_relative_path, artifact_ref, artifact_bytes, "
                    "request_sha256, scope_sha256, spec_identity, spec_sha256, "
                    "policy_identity_sha256, state FROM durable_effects ORDER BY effect_id"
                )
            )
            claim_rows = tuple(
                connection.execute(
                    "SELECT claim_key_sha256, effect_id, target_relative_path, "
                    "artifact_ref_sha256, artifact_bytes_sha256, request_sha256, "
                    "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                    "policy_identity_sha256, expected_predecessor_head_sha256, "
                    "claim_generation, active FROM durable_claims ORDER BY claim_key_sha256"
                )
            )
            binding_rows = tuple(
                connection.execute(
                    "SELECT effect_id, target_relative_path, artifact_ref_sha256, "
                    "request_sha256, scope_sha256, bounds_sha256, spec_identity, "
                    "spec_sha256, policy_identity_sha256, token_request_sha256, "
                    "token_continuation_identity, token_authentication_tag, binding_sha256 "
                    "FROM durable_effect_bindings ORDER BY effect_id"
                )
            )
            target_rows = tuple(
                connection.execute(
                    "SELECT target_relative_path, effect_id, binding_sha256 "
                    "FROM durable_target_claims ORDER BY target_relative_path"
                )
            )
            published_rows = tuple(
                connection.execute(
                    "SELECT effect_id, target_relative_path, binding_sha256, "
                    "artifact_bytes_sha256, byte_length, target_device, target_inode, "
                    "target_nlink, attestation_sha256 "
                    "FROM durable_published_attestations ORDER BY effect_id"
                )
            )
            final_rows = tuple(
                connection.execute(
                    "SELECT effect_id, binding_sha256, published_attestation_sha256, "
                    "expected_state, resulting_state, result_sha256 "
                    "FROM durable_final_cas_results ORDER BY effect_id"
                )
            )
            blocker_rows = tuple(
                connection.execute(
                    "SELECT effect_id, binding_sha256, reason_code, "
                    "observed_evidence_sha256, token_request_sha256, "
                    "token_continuation_identity, blocker_sha256 "
                    "FROM durable_recovery_blockers ORDER BY effect_id"
                )
            )
            migration_rows = tuple(
                connection.execute(
                    "SELECT singleton, legacy_provenance_sha256, retired_witness_sha256, "
                    "legacy_provenance_canonical_json "
                    "FROM durable_migration_provenance ORDER BY singleton"
                )
            )
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable snapshot state is invalid") from exc
        if len(key_rows) != 1:
            raise AuthorityRuntimeError("durable snapshot recovery key is invalid")
        key_row = key_rows[0]
        token_key = key_row["token_key"]
        if (
            type(key_row["singleton"]) is not int
            or key_row["singleton"] != 1
            or type(token_key) is not bytes
            or len(token_key) != 32
            or type(key_row["key_sha256"]) is not str
            or key_row["key_sha256"] != sha256_bytes(token_key)
        ):
            raise AuthorityRuntimeError("durable snapshot recovery key is invalid")
        effects: dict[str, sqlite3.Row] = {}
        for row in effect_rows:
            effect_id = cls._require_effect_id(
                row["effect_id"],
                label="durable snapshot effect",
            )
            cls._require_target_path(
                row["target_relative_path"],
                label="durable snapshot effect",
            )
            if (
                effect_id in effects
                or type(row["artifact_ref"]) is not bytes
                or type(row["artifact_bytes"]) is not bytes
                or len(row["artifact_ref"]) > _MAX_ARTIFACT_BYTES
                or len(row["artifact_bytes"]) > _MAX_ARTIFACT_BYTES
                or type(row["spec_identity"]) is not str
                or not row["spec_identity"]
                or row["state"]
                not in {
                    "PREPARED",
                    "PUBLISHED",
                    "FINALIZED",
                    "ABORTED",
                    "BLOCKED_RECOVERY",
                }
            ):
                raise AuthorityRuntimeError("durable snapshot effect is invalid")
            for field in (
                row["request_sha256"],
                row["scope_sha256"],
                row["spec_sha256"],
                row["policy_identity_sha256"],
            ):
                cls._require_sha256(field, label="durable snapshot effect")
            effects[effect_id] = row
        for row in claim_rows:
            if (
                type(row["claim_generation"]) is not int
                or row["claim_generation"] < 0
                or row["claim_generation"] > _MAX_SNAPSHOT_GENERATION
                or type(row["active"]) is not int
                or row["active"] not in {0, 1}
                or type(row["spec_identity"]) is not str
                or not row["spec_identity"]
            ):
                raise AuthorityRuntimeError("durable snapshot claim is invalid")
            cls._require_sha256(row["claim_key_sha256"], label="durable snapshot claim")
            cls._require_effect_id(row["effect_id"], label="durable snapshot claim")
            cls._require_target_path(
                row["target_relative_path"],
                label="durable snapshot claim",
            )
            for field in (
                row["artifact_ref_sha256"],
                row["artifact_bytes_sha256"],
                row["request_sha256"],
                row["scope_sha256"],
                row["bounds_sha256"],
                row["spec_sha256"],
                row["policy_identity_sha256"],
            ):
                cls._require_sha256(field, label="durable snapshot claim")
            parent = row["expected_predecessor_head_sha256"]
            if parent is not None:
                cls._require_sha256(parent, label="durable snapshot claim")
        bindings: dict[str, _SnapshotBindingValue] = {}
        for row in binding_rows:
            try:
                value = _SnapshotBindingValue(*tuple(row))
            except (TypeError, ValueError) as exc:
                raise AuthorityRuntimeError("durable snapshot binding is invalid") from exc
            if value.effect_id in bindings:
                raise AuthorityRuntimeError("durable snapshot binding is invalid")
            cls._validate_binding_value(value, token_key=token_key)
            bindings[value.effect_id] = value
        targets: dict[str, tuple[object, ...]] = {}
        for row in target_rows:
            target = tuple(row)
            if len(target) != 3 or target[0] in targets:
                raise AuthorityRuntimeError("durable snapshot target claim is invalid")
            target_path = cls._require_target_path(
                target[0],
                label="durable snapshot target claim",
            )
            effect_id = cls._require_effect_id(
                target[1],
                label="durable snapshot target claim",
            )
            binding_sha256 = cls._require_sha256(
                target[2],
                label="durable snapshot target claim",
            )
            targets[target_path] = (target_path, effect_id, binding_sha256)
        bound_effects = {
            effect_id
            for effect_id, effect in effects.items()
            if effect["state"] != "ABORTED"
        }
        if bound_effects != set(bindings):
            raise AuthorityRuntimeError("durable snapshot binding is invalid")
        if set(targets) != {value.target_relative_path for value in bindings.values()}:
            raise AuthorityRuntimeError("durable snapshot target claim is invalid")
        for effect_id, effect in effects.items():
            if effect["state"] == "ABORTED":
                continue
            binding = bindings[effect_id]
            if (
                effect["target_relative_path"] != binding.target_relative_path
                or sha256_bytes(effect["artifact_ref"])
                != binding.artifact_ref_sha256
                or effect["request_sha256"] != binding.request_sha256
                or effect["scope_sha256"] != binding.scope_sha256
                or effect["spec_identity"] != binding.spec_identity
                or effect["spec_sha256"] != binding.spec_sha256
                or effect["policy_identity_sha256"]
                != binding.policy_identity_sha256
                or targets[binding.target_relative_path]
                != (
                    binding.target_relative_path,
                    binding.effect_id,
                    binding.binding_sha256,
                )
            ):
                raise AuthorityRuntimeError("durable snapshot binding is invalid")
        published: dict[str, _SnapshotPublishedAttestationValue] = {}
        for row in published_rows:
            try:
                value = _SnapshotPublishedAttestationValue(*tuple(row))
            except (TypeError, ValueError) as exc:
                raise AuthorityRuntimeError(
                    "durable published attestation is invalid"
                ) from exc
            if value.effect_id in published:
                raise AuthorityRuntimeError("durable published attestation is invalid")
            cls._validate_published_attestation_value(value)
            effect = effects.get(value.effect_id)
            binding = bindings.get(value.effect_id)
            if (
                effect is None
                or binding is None
                or effect["target_relative_path"] != value.target_relative_path
                or binding.binding_sha256 != value.binding_sha256
                or sha256_bytes(effect["artifact_bytes"])
                != value.artifact_bytes_sha256
                or len(effect["artifact_bytes"]) != value.byte_length
            ):
                raise AuthorityRuntimeError("durable published attestation is invalid")
            published[value.effect_id] = value
        final_results: dict[str, _SnapshotFinalCasResultValue] = {}
        for row in final_rows:
            try:
                value = _SnapshotFinalCasResultValue(*tuple(row))
            except (TypeError, ValueError) as exc:
                raise AuthorityRuntimeError("durable final CAS result is invalid") from exc
            if value.effect_id in final_results:
                raise AuthorityRuntimeError("durable final CAS result is invalid")
            cls._validate_final_cas_result_value(value)
            binding = bindings.get(value.effect_id)
            attestation = published.get(value.effect_id)
            if (
                binding is None
                or attestation is None
                or binding.binding_sha256 != value.binding_sha256
                or attestation.attestation_sha256
                != value.published_attestation_sha256
            ):
                raise AuthorityRuntimeError("durable final CAS result is invalid")
            final_results[value.effect_id] = value
        for row in blocker_rows:
            try:
                value = _SnapshotRecoveryBlockerValue(*tuple(row))
            except (TypeError, ValueError) as exc:
                raise AuthorityRuntimeError("durable recovery blocker is invalid") from exc
            cls._validate_recovery_blocker_value(value)
            binding = bindings.get(value.effect_id)
            effect = effects.get(value.effect_id)
            if (
                binding is None
                or effect is None
                or effect["state"] != "BLOCKED_RECOVERY"
                or binding.binding_sha256 != value.binding_sha256
                or binding.token_request_sha256 != value.token_request_sha256
                or binding.token_continuation_identity
                != value.token_continuation_identity
            ):
                raise AuthorityRuntimeError("durable recovery blocker is invalid")
        if len(migration_rows) > 1:
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        for row in migration_rows:
            if (
                type(row["singleton"]) is not int
                or row["singleton"] != 1
                or type(row["legacy_provenance_sha256"]) is not str
                or type(row["retired_witness_sha256"]) is not str
                or type(row["legacy_provenance_canonical_json"]) is not bytes
            ):
                raise AuthorityRuntimeError("durable migration provenance is invalid")
            cls._require_sha256(
                row["legacy_provenance_sha256"],
                label="durable migration provenance",
            )
            cls._require_sha256(
                row["retired_witness_sha256"],
                label="durable migration provenance",
            )
            cls._validate_legacy_provenance_payload(
                row["legacy_provenance_canonical_json"],
                legacy_provenance_sha256=row["legacy_provenance_sha256"],
                retired_witness_sha256=row["retired_witness_sha256"],
            )

    @classmethod
    def _parse_canonical_json(cls, raw: bytes, *, label: str) -> dict[str, object]:
        def reject_duplicate_keys(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            value: dict[str, object] = {}
            for key, item in pairs:
                if type(key) is not str or key in value:
                    raise ValueError("duplicate JSON key")
                value[key] = item
            return value

        def reject_nonfinite(_value: str) -> object:
            raise ValueError("non-finite JSON value")

        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise AuthorityRuntimeError(f"{label} is invalid") from exc
        if type(value) is not dict or canonical_json_bytes(value) != raw:
            raise AuthorityRuntimeError(f"{label} is invalid")
        return value

    @classmethod
    def _validate_legacy_provenance_payload(
        cls,
        raw: bytes,
        *,
        legacy_provenance_sha256: str,
        retired_witness_sha256: str,
    ) -> None:
        """Validate the sealed supported V1 witness without a live V1 path."""

        if (
            type(raw) is not bytes
            or len(raw) == 0
            or len(raw) > _MAX_ARTIFACT_BYTES
            or sha256_bytes(raw) != legacy_provenance_sha256
        ):
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        payload = cls._parse_canonical_json(
            raw,
            label="durable migration provenance",
        )
        if set(payload) != {
            "schema_version",
            "kind",
            "classification",
            "legacy_input_digest_sha256",
            "legacy_runtime_names",
            "members",
            "legacy_database_schema_fingerprint_sha256",
            "sidecar_absence_proof",
            "bridge_absence_proof",
            "stage_absence_proof",
        }:
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        if (
            payload["schema_version"] != 1
            or payload["kind"] != "LEGACY_D1A_V1_PROVENANCE"
            or payload["classification"] != "L1"
            or payload["legacy_runtime_names"] != [_LEGACY_V1_DATABASE_NAME]
            or payload["sidecar_absence_proof"] is not True
            or payload["bridge_absence_proof"] is not True
            or payload["stage_absence_proof"] is not True
        ):
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        legacy_input_digest = payload["legacy_input_digest_sha256"]
        schema_fingerprint = payload["legacy_database_schema_fingerprint_sha256"]
        if (
            type(legacy_input_digest) is not str
            or type(schema_fingerprint) is not str
            or legacy_input_digest != retired_witness_sha256
        ):
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        cls._require_sha256(
            legacy_input_digest,
            label="durable migration provenance",
        )
        cls._require_sha256(
            schema_fingerprint,
            label="durable migration provenance",
        )
        members = payload["members"]
        if type(members) is not list or len(members) != 1:
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        member = members[0]
        if type(member) is not dict or set(member) != {
            "relative_parts",
            "raw_sha256",
            "identity",
        }:
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        if member["relative_parts"] != list(
            _RUNTIME_PARTS + (_LEGACY_V1_DATABASE_NAME,)
        ):
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        raw_sha256 = member["raw_sha256"]
        if type(raw_sha256) is not str:
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        cls._require_sha256(raw_sha256, label="durable migration provenance")
        identity = member["identity"]
        identity_keys = (
            "device",
            "inode",
            "link_count",
            "owner",
            "mode",
            "byte_length",
        )
        if type(identity) is not dict or set(identity) != set(identity_keys):
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        if any(type(identity[key]) is not int for key in identity_keys) or (
            identity["device"] < 0
            or identity["inode"] < 1
            or identity["link_count"] != 1
            or identity["owner"] < 0
            or identity["mode"] != 0o600
            or identity["byte_length"] < 0
            or identity["byte_length"] > _MAX_ARTIFACT_BYTES
        ):
            raise AuthorityRuntimeError("durable migration provenance is invalid")
        expected_digest = sha256_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "kind": "LEGACY_D1A_V1_INPUT",
                    "legacy_runtime_names": payload["legacy_runtime_names"],
                    "members": members,
                }
            )
        )
        if expected_digest != legacy_input_digest:
            raise AuthorityRuntimeError("durable migration provenance is invalid")

    @classmethod
    def _read_protocol_file(
        cls,
        root: _RootAnchor,
        path: _AnchoredPath,
        *,
        label: str,
    ) -> tuple[os.stat_result, bytes]:
        parent_fd: int | None = None
        try:
            try:
                parent_fd = root._open_directory(path.parts[:-1], create=False)
            except (AuthorityRuntimeError, OSError) as exc:
                if _has_transient_snapshot_read_error(exc):
                    raise _SnapshotHistoryUnavailable(
                        "durable snapshot history is unavailable"
                    ) from exc
                raise _SnapshotHistoryChanged(
                    "durable snapshot history changed"
                ) from exc
            try:
                info, raw = safety.read_regular_file_at(
                    parent_fd,
                    path.name,
                    path.display_path,
                    label=label,
                    expected_mode=0o600,
                    max_bytes=_MAX_ARTIFACT_BYTES,
                    error_type=_SnapshotProtocolReadError,
                )
            except _SnapshotProtocolReadError as exc:
                if _has_transient_snapshot_read_error(exc):
                    raise _SnapshotHistoryUnavailable(
                        "durable snapshot history is unavailable"
                    ) from exc
                raise _SnapshotHistoryChanged(
                    "durable snapshot history changed"
                ) from exc
            except OSError as exc:
                if _has_transient_snapshot_read_error(exc):
                    raise _SnapshotHistoryUnavailable(
                        "durable snapshot history is unavailable"
                    ) from exc
                raise _SnapshotHistoryChanged(
                    "durable snapshot history changed"
                ) from exc
            try:
                lexical = os.stat(
                    path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                if _has_transient_snapshot_read_error(exc):
                    raise _SnapshotHistoryUnavailable(
                        "durable snapshot history is unavailable"
                    ) from exc
                raise _SnapshotHistoryChanged(
                    "durable snapshot history changed"
                ) from exc
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or (info.st_dev, info.st_ino) != (lexical.st_dev, lexical.st_ino)
            ):
                raise AuthorityRuntimeError(f"{label} is invalid")
            return info, raw
        finally:
            if parent_fd is not None:
                os.close(parent_fd)

    @classmethod
    def _read_object(
        cls,
        root: _RootAnchor,
        object_sha256: str,
    ) -> tuple[_SnapshotFileIdentity, bytes]:
        if (
            type(object_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", object_sha256) is None
        ):
            raise AuthorityRuntimeError("durable snapshot object is invalid")
        info, raw = cls._read_protocol_file(
            root,
            root.joinpath(*_SNAPSHOT_OBJECTS_PARTS, f"o-{object_sha256}"),
            label="durable snapshot object",
        )
        if info.st_nlink != 1 or sha256_bytes(raw) != object_sha256:
            raise AuthorityRuntimeError("durable snapshot object is invalid")
        return _SnapshotFileIdentity.from_stat(info), raw

    @classmethod
    def _discover_tip(
        cls,
        root: _RootAnchor,
        namespace_identities: tuple[
            tuple[tuple[str, ...], tuple[int, int, int, int, int]], ...
        ],
        *,
        validate_tip_target_readback: bool = True,
    ) -> tuple[str, dict[str, object], bytes, _SnapshotHistoryProfile] | None:
        head_directory = root.joinpath(*_SNAPSHOT_HEADS_PARTS)
        names = root.list_directory(head_directory)
        if not names:
            return None
        anchor_identity_sha256 = sha256_bytes(canonical_json_bytes(root.identity))
        records: list[
            tuple[
                str,
                dict[str, object],
                bytes,
                _SnapshotFileIdentity,
                _SnapshotFileIdentity,
            ]
        ] = []
        for name in names:
            match = _HEAD_NAME.fullmatch(name)
            if match is None:
                raise AuthorityRuntimeError("durable snapshot head is invalid")
            head_sha256 = match.group(1)
            head_info, raw = cls._read_protocol_file(
                root,
                head_directory / name,
                label="durable snapshot head",
            )
            if head_info.st_nlink != 2 or sha256_bytes(raw) != head_sha256:
                raise AuthorityRuntimeError("durable snapshot head is invalid")
            head = cls._parse_canonical_json(raw, label="durable snapshot head")
            if set(head) != {
                "protocol_version",
                "kind",
                "receipt_token",
                "generation",
                "parent_head_sha256",
                "manifest_object_sha256",
                "snapshot_object_sha256",
                "recovery_projection_sha256",
                "sqlite_schema_fingerprint_sha256",
                "origin",
                "anchor_identity_sha256",
            } or (
                head.get("protocol_version") != 1
                or head.get("kind") != "DURABLE_SNAPSHOT_HEAD"
                or type(head.get("generation")) is not int
                or head["generation"] < 0
                or head["generation"] > _MAX_SNAPSHOT_GENERATION
                or head.get("origin")
                not in {"EMPTY_GENESIS", "LEGACY_D1A_V1", "NORMAL"}
                or type(head.get("receipt_token")) is not str
                or re.fullmatch(r"[0-9a-f]{32}", head["receipt_token"]) is None
                or head.get("anchor_identity_sha256") != anchor_identity_sha256
            ):
                raise AuthorityRuntimeError("durable snapshot head is invalid")
            for key in (
                "manifest_object_sha256",
                "snapshot_object_sha256",
                "recovery_projection_sha256",
                "sqlite_schema_fingerprint_sha256",
                "anchor_identity_sha256",
            ):
                if (
                    type(head[key]) is not str
                    or _SHA256.fullmatch(head[key]) is None
                ):
                    raise AuthorityRuntimeError("durable snapshot head is invalid")
            parent = head["parent_head_sha256"]
            if parent is not None and (
                type(parent) is not str or _SHA256.fullmatch(parent) is None
            ):
                raise AuthorityRuntimeError("durable snapshot head is invalid")
            receipt_info, receipt_raw = cls._read_protocol_file(
                root,
                root.joinpath(
                    *_SNAPSHOT_RECEIPTS_PARTS,
                    f"r-{head_sha256}-{head['receipt_token']}",
                ),
                label="durable snapshot head receipt",
            )
            if (
                receipt_info.st_nlink != 2
                or (receipt_info.st_dev, receipt_info.st_ino)
                != (head_info.st_dev, head_info.st_ino)
                or receipt_raw != raw
            ):
                raise AuthorityRuntimeError("durable snapshot head receipt is invalid")
            records.append(
                (
                    head_sha256,
                    head,
                    raw,
                    _SnapshotFileIdentity.from_stat(head_info),
                    _SnapshotFileIdentity.from_stat(receipt_info),
                )
            )
        records.sort(key=lambda record: record[1]["generation"])
        validated_records: list[
            tuple[str, dict[str, object], dict[str, object], bytes]
        ] = []
        members: list[_SnapshotHistoryMember] = []
        referenced_objects: set[str] = set()
        for position, (
            head_sha256,
            head,
            _raw,
            head_identity,
            receipt_identity,
        ) in enumerate(records):
            if head["generation"] != position:
                raise AuthorityRuntimeError("durable snapshot history is invalid")
            expected_parent = None if position == 0 else records[position - 1][0]
            if head["parent_head_sha256"] != expected_parent:
                raise AuthorityRuntimeError("durable snapshot history is invalid")
            if position == 0 and head["origin"] not in {
                "EMPTY_GENESIS",
                "LEGACY_D1A_V1",
            }:
                raise AuthorityRuntimeError("durable snapshot history is invalid")
            if position and head["origin"] != "NORMAL":
                raise AuthorityRuntimeError("durable snapshot history is invalid")
            for object_sha256 in (
                head["manifest_object_sha256"],
                head["snapshot_object_sha256"],
            ):
                if object_sha256 in referenced_objects:
                    raise AuthorityRuntimeError(
                        "durable snapshot object is referenced more than once"
                    )
                referenced_objects.add(object_sha256)
            manifest_identity, manifest_raw = cls._read_object(
                root,
                head["manifest_object_sha256"],
            )
            manifest = cls._parse_canonical_json(
                manifest_raw,
                label="durable snapshot manifest",
            )
            snapshot_identity, snapshot_raw = cls._read_object(
                root,
                head["snapshot_object_sha256"],
            )
            if set(manifest) != {
                "protocol_version",
                "kind",
                "publication_nonce",
                "snapshot_object_sha256",
                "snapshot_byte_length",
                "sqlite_schema_fingerprint_sha256",
                "recovery_projection_sha256",
                "origin",
                "legacy_provenance_sha256",
                "anchor_identity_sha256",
            } or (
                manifest.get("protocol_version") != 1
                or manifest.get("kind") != "DURABLE_SNAPSHOT_MANIFEST"
                or type(manifest.get("publication_nonce")) is not str
                or re.fullmatch(r"[0-9a-f]{32}", manifest["publication_nonce"])
                is None
                or manifest.get("snapshot_object_sha256")
                != head["snapshot_object_sha256"]
                or type(manifest.get("snapshot_byte_length")) is not int
                or manifest["snapshot_byte_length"] < 0
                or manifest["snapshot_byte_length"] > _MAX_ARTIFACT_BYTES
                or manifest.get("snapshot_byte_length") != len(snapshot_raw)
                or manifest.get("sqlite_schema_fingerprint_sha256")
                != head["sqlite_schema_fingerprint_sha256"]
                or manifest.get("recovery_projection_sha256")
                != head["recovery_projection_sha256"]
                or manifest.get("origin") != head["origin"]
                or (
                    head["origin"] == "LEGACY_D1A_V1"
                    and (
                        type(manifest.get("legacy_provenance_sha256")) is not str
                        or _SHA256.fullmatch(
                            manifest["legacy_provenance_sha256"]
                        )
                        is None
                    )
                )
                or (
                    head["origin"] != "LEGACY_D1A_V1"
                    and manifest.get("legacy_provenance_sha256") is not None
                )
                or manifest.get("anchor_identity_sha256") != anchor_identity_sha256
            ):
                raise AuthorityRuntimeError("durable snapshot manifest is invalid")
            for key in (
                "snapshot_object_sha256",
                "sqlite_schema_fingerprint_sha256",
                "recovery_projection_sha256",
                "anchor_identity_sha256",
            ):
                if (
                    type(manifest[key]) is not str
                    or _SHA256.fullmatch(manifest[key]) is None
                ):
                    raise AuthorityRuntimeError("durable snapshot manifest is invalid")
            validated_records.append((head_sha256, head, manifest, snapshot_raw))
            members.append(
                _SnapshotHistoryMember(
                    head_sha256=head_sha256,
                    head_identity=head_identity,
                    receipt_identity=receipt_identity,
                    manifest_identity=manifest_identity,
                    snapshot_identity=snapshot_identity,
                )
            )
        cls._verify_snapshot_namespace_identities(root, namespace_identities)
        hydrated_records = tuple(
            (
                head_sha256,
                head,
                cls._validate_hydrated_snapshot(
                    root,
                    snapshot_raw,
                    head,
                    manifest,
                    validate_published_target_readbacks=False,
                ),
            )
            for head_sha256, head, manifest, snapshot_raw in validated_records
        )
        cls._validate_parent_child_deltas(hydrated_records)
        head_sha256, head, _manifest, snapshot_raw = validated_records[-1]
        if validate_tip_target_readback:
            # A historical PUBLISHED snapshot proves what was sealed at that
            # generation. Only a fresh open requires a current target
            # readback: a later BLOCKED_RECOVERY head deliberately records
            # that this evidence is no longer available.
            cls._validate_hydrated_snapshot(
                root,
                snapshot_raw,
                head,
                validated_records[-1][2],
            )
        return (
            head_sha256,
            head,
            snapshot_raw,
            _SnapshotHistoryProfile(
                namespace_identities=cls._history_namespace_identities(
                    namespace_identities
                ),
                directory_change_markers=cls._history_directory_change_markers(
                    root
                ),
                members=tuple(members),
            ),
        )

    def _require_active(self) -> None:
        if self.__closed or os.getpid() != self.__owner_pid:
            raise AuthorityRuntimeError("durable snapshot store is unavailable")
        self.__root.identity
        self._require_no_root_stop(self.__root)
        try:
            if self.__legacy_witness is None:
                observed_legacy = self._inventory_legacy_v1(
                    self.__root,
                    allow_snapshot_staging=self.__head_sha256 is not None,
                )
                if observed_legacy is not None:
                    raise self._legacy_inventory_fence(
                        observed_legacy,
                        detail="legacy-input-with-nonlegacy-lineage",
                    )
            else:
                self._verify_legacy_v1_inventory(
                    self.__root,
                    self.__legacy_witness,
                    allow_snapshot_staging=True,
                )
        except _SnapshotLegacyFenceRequired as exc:
            if exc.publish_root_stop:
                self._publish_root_stop_if_possible(
                    self.__root,
                    reason_code=exc.reason_code,
                    observed_evidence_sha256=exc.observed_evidence_sha256,
                )
            raise

    def _current_history_profile(
        self,
    ) -> tuple[str | None, int, _SnapshotHistoryProfile]:
        """Rediscover the only history an active writer may safely extend."""

        try:
            namespace_identities = self._snapshot_namespace_identities(self.__root)
            discovered = self._discover_tip(
                self.__root,
                namespace_identities,
                validate_tip_target_readback=False,
            )
        except _SnapshotHistoryUnavailable:
            raise
        except _SnapshotHistoryChanged:
            raise
        except (AuthorityRuntimeError, OSError) as exc:
            if _has_transient_snapshot_read_error(exc):
                raise _SnapshotHistoryUnavailable(
                    "durable snapshot history is unavailable"
                ) from exc
            raise _SnapshotHistoryChanged(
                "durable snapshot history changed"
            ) from exc
        if discovered is None:
            return (
                None,
                -1,
                _SnapshotHistoryProfile(
                    self._history_namespace_identities(namespace_identities),
                    self._history_directory_change_markers(self.__root),
                    (),
                ),
            )
        head_sha256, head, _snapshot_raw, history_profile = discovered
        return head_sha256, head["generation"], history_profile

    def _verify_expected_history(self) -> None:
        self._require_active()
        head_sha256, generation, history_profile = self._current_history_profile()
        if (
            head_sha256 != self.__head_sha256
            or generation != self.__generation
            or history_profile != self.__history_profile
        ):
            raise _SnapshotHistoryChanged("durable snapshot history changed")

    def _adopt_published_history(
        self,
        *,
        head_sha256: str,
        generation: int,
    ) -> None:
        observed_head, observed_generation, history_profile = (
            self._current_history_profile()
        )
        if observed_head != head_sha256 or observed_generation != generation:
            raise _SnapshotHistoryChanged("durable snapshot history changed")
        self.__head_sha256 = observed_head
        self.__generation = observed_generation
        self.__history_profile = history_profile

    def verify_canonical_database_identity(self) -> None:
        try:
            self._verify_expected_history()
        except _SnapshotHistoryChanged as exc:
            reason_code = "RECOVERY_SNAPSHOT_HISTORY_CHANGED"
            observed_evidence_sha256 = self._root_stop_evidence(
                "snapshot-history-changed"
            )
            self._publish_root_stop_if_possible(
                self.__root,
                reason_code=reason_code,
                observed_evidence_sha256=observed_evidence_sha256,
            )
            raise _SnapshotRootStopRequired(
                "durable snapshot history changed",
                reason_code=reason_code,
                observed_evidence_sha256=observed_evidence_sha256,
            ) from exc

    def record_root_stop(
        self,
        *,
        reason_code: str,
        observed_evidence_sha256: str,
    ) -> None:
        """Best-effort immutable V2 stop for a root-wide trust failure."""

        if self.__closed or os.getpid() != self.__owner_pid:
            raise AuthorityRuntimeError("durable snapshot store is unavailable")
        self.__root.identity
        self._publish_root_stop_if_possible(
            self.__root,
            reason_code=reason_code,
            observed_evidence_sha256=observed_evidence_sha256,
        )

    @staticmethod
    def _schema_fingerprint_for(connection: sqlite3.Connection) -> str:
        rows = tuple(
            (row["type"], row["name"], row["tbl_name"], row["sql"])
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        )
        return sha256_bytes(canonical_json_bytes(rows))

    @staticmethod
    def _recovery_projection_value(
        connection: sqlite3.Connection,
    ) -> dict[str, object]:
        return {
            "snapshot_meta": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT transition_kind, generation, parent_head_sha256, publication_nonce "
                    "FROM snapshot_meta ORDER BY singleton"
                )
            ),
            "durable_effects": tuple(
                (
                    row["effect_id"],
                    row["target_relative_path"],
                    sha256_bytes(bytes(row["artifact_ref"])),
                    sha256_bytes(bytes(row["artifact_bytes"])),
                    row["request_sha256"],
                    row["scope_sha256"],
                    row["spec_identity"],
                    row["spec_sha256"],
                    row["policy_identity_sha256"],
                    row["state"],
                )
                for row in connection.execute(
                    "SELECT effect_id, target_relative_path, artifact_ref, artifact_bytes, "
                    "request_sha256, scope_sha256, spec_identity, spec_sha256, "
                    "policy_identity_sha256, state FROM durable_effects ORDER BY effect_id"
                )
            ),
            "durable_claims": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT claim_key_sha256, effect_id, target_relative_path, "
                    "artifact_ref_sha256, artifact_bytes_sha256, request_sha256, "
                    "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                    "policy_identity_sha256, expected_predecessor_head_sha256, "
                    "claim_generation, active FROM durable_claims ORDER BY claim_key_sha256"
                )
            ),
            "recovery_token_keys": tuple(
                (
                    row["singleton"],
                    sha256_bytes(bytes(row["token_key"])),
                    row["key_sha256"],
                )
                for row in connection.execute(
                    "SELECT singleton, token_key, key_sha256 "
                    "FROM recovery_token_keys ORDER BY singleton"
                )
            ),
            "durable_effect_bindings": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT effect_id, target_relative_path, artifact_ref_sha256, "
                    "request_sha256, scope_sha256, bounds_sha256, spec_identity, "
                    "spec_sha256, policy_identity_sha256, token_request_sha256, "
                    "token_continuation_identity, token_authentication_tag, binding_sha256 "
                    "FROM durable_effect_bindings ORDER BY effect_id"
                )
            ),
            "durable_target_claims": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT target_relative_path, effect_id, binding_sha256 "
                    "FROM durable_target_claims ORDER BY target_relative_path"
                )
            ),
            "durable_published_attestations": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT effect_id, target_relative_path, binding_sha256, "
                    "artifact_bytes_sha256, byte_length, target_device, target_inode, "
                    "target_nlink, attestation_sha256 "
                    "FROM durable_published_attestations ORDER BY effect_id"
                )
            ),
            "durable_final_cas_results": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT effect_id, binding_sha256, published_attestation_sha256, "
                    "expected_state, resulting_state, result_sha256 "
                    "FROM durable_final_cas_results ORDER BY effect_id"
                )
            ),
            "durable_recovery_blockers": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT effect_id, binding_sha256, reason_code, "
                    "observed_evidence_sha256, token_request_sha256, "
                    "token_continuation_identity, blocker_sha256 "
                    "FROM durable_recovery_blockers ORDER BY effect_id"
                )
            ),
            "durable_migration_provenance": tuple(
                (
                    row["singleton"],
                    row["legacy_provenance_sha256"],
                    row["retired_witness_sha256"],
                    sha256_bytes(bytes(row["legacy_provenance_canonical_json"])),
                )
                for row in connection.execute(
                    "SELECT singleton, legacy_provenance_sha256, retired_witness_sha256, "
                    "legacy_provenance_canonical_json "
                    "FROM durable_migration_provenance ORDER BY singleton"
                )
            ),
        }

    @classmethod
    def _recovery_projection_for(cls, connection: sqlite3.Connection) -> str:
        projection = cls._recovery_projection_value(connection)
        return sha256_bytes(canonical_json_bytes(projection))

    def _schema_fingerprint(self) -> str:
        return self._schema_fingerprint_for(self.__connection)

    def _recovery_projection(self) -> str:
        return self._recovery_projection_for(self.__connection)

    @classmethod
    def _validate_hydrated_snapshot(
        cls,
        root: _RootAnchor,
        snapshot_raw: bytes,
        head: dict[str, object],
        manifest: dict[str, object],
        *,
        validate_published_target_readbacks: bool = True,
    ) -> dict[str, object]:
        connection: sqlite3.Connection | None = None
        try:
            connection = cls._new_connection()
            connection.set_authorizer(None)
            connection.deserialize(snapshot_raw)
            cls._configure_connection(connection)
            cls._verify_schema(connection)
            integrity_rows = tuple(
                tuple(row) for row in connection.execute("PRAGMA integrity_check")
            )
            if integrity_rows != (("ok",),):
                raise AuthorityRuntimeError("durable snapshot integrity is invalid")
            metadata = connection.execute(
                "SELECT transition_kind, generation, parent_head_sha256, publication_nonce "
                "FROM snapshot_meta WHERE singleton = 1"
            ).fetchone()
            if (
                metadata is None
                or metadata["generation"] != head["generation"]
                or metadata["parent_head_sha256"] != head["parent_head_sha256"]
                or metadata["publication_nonce"] != manifest["publication_nonce"]
                or metadata["transition_kind"] not in _SNAPSHOT_TRANSITIONS
                or cls._schema_fingerprint_for(connection)
                != head["sqlite_schema_fingerprint_sha256"]
                or cls._recovery_projection_for(connection)
                != head["recovery_projection_sha256"]
            ):
                raise AuthorityRuntimeError("durable snapshot metadata is invalid")
            cls._validate_snapshot_rows(connection)
            projection = cls._recovery_projection_value(connection)
            migration_rows = projection["durable_migration_provenance"]
            if head["origin"] == "LEGACY_D1A_V1":
                if (
                    type(migration_rows) is not tuple
                    or len(migration_rows) != 1
                    or type(migration_rows[0]) is not tuple
                    or len(migration_rows[0]) != 4
                    or manifest["legacy_provenance_sha256"] != migration_rows[0][1]
                    or migration_rows[0][1] != migration_rows[0][3]
                ):
                    raise AuthorityRuntimeError(
                        "durable legacy migration provenance is invalid"
                    )
            elif head["origin"] == "NORMAL":
                if manifest["legacy_provenance_sha256"] is not None:
                    raise AuthorityRuntimeError(
                        "durable legacy migration provenance is invalid"
                    )
            elif (
                migration_rows != ()
                or manifest["legacy_provenance_sha256"] is not None
            ):
                raise AuthorityRuntimeError(
                    "durable legacy migration provenance is invalid"
                )
            if validate_published_target_readbacks:
                cls._validate_published_target_readbacks(root, connection)
            return projection
        except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
            raise AuthorityRuntimeError("durable snapshot state is invalid") from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass

    @classmethod
    def _validate_published_target_readbacks(
        cls,
        root: _RootAnchor,
        connection: sqlite3.Connection,
    ) -> None:
        """Bind each sealed PUBLISHED readback to its anchored target file."""

        try:
            rows = tuple(
                connection.execute(
                    "SELECT e.state, e.target_relative_path, e.artifact_bytes, "
                    "p.artifact_bytes_sha256, p.byte_length, p.target_device, "
                    "p.target_inode, p.target_nlink "
                    "FROM durable_published_attestations AS p "
                    "JOIN durable_effects AS e ON e.effect_id = p.effect_id "
                    "ORDER BY p.effect_id"
                )
            )
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError(
                "durable published readback is invalid"
            ) from exc
        for row in rows:
            if row["state"] == "BLOCKED_RECOVERY":
                # A sealed blocker records that the target's current evidence
                # could not prove exact recovery. Reopening that valid terminal
                # state must surface its directive, not turn the known target
                # absence into a root-wide history fence.
                continue
            parent_fd: int | None = None
            try:
                target = root / row["target_relative_path"]
                parent_fd = root._open_directory(target.parts[:-1], create=False)
                info, raw = safety.read_regular_file_at(
                    parent_fd,
                    target.name,
                    target.display_path,
                    label="durable published artifact",
                    expected_mode=0o600,
                    max_bytes=_MAX_ARTIFACT_BYTES,
                    error_type=AuthorityRuntimeError,
                )
                if (
                    raw != row["artifact_bytes"]
                    or sha256_bytes(raw) != row["artifact_bytes_sha256"]
                    or len(raw) != row["byte_length"]
                    or info.st_dev != row["target_device"]
                    or info.st_ino != row["target_inode"]
                    or info.st_nlink != row["target_nlink"]
                ):
                    raise AuthorityRuntimeError("durable published readback is invalid")
            except (AuthorityRuntimeError, OSError, TypeError, ValueError) as exc:
                raise AuthorityRuntimeError(
                    "durable published readback is invalid"
                ) from exc
            finally:
                if parent_fd is not None:
                    os.close(parent_fd)

    @staticmethod
    def _projection_row_map(
        projection: dict[str, object],
        key: str,
    ) -> dict[str, tuple[object, ...]]:
        rows = projection.get(key)
        if type(rows) is not tuple:
            raise AuthorityRuntimeError("durable snapshot projection is invalid")
        result: dict[str, tuple[object, ...]] = {}
        for row in rows:
            if (
                type(row) is not tuple
                or not row
                or type(row[0]) is not str
                or row[0] in result
            ):
                raise AuthorityRuntimeError("durable snapshot projection is invalid")
            result[row[0]] = row
        return result

    @classmethod
    def _validate_parent_child_deltas(
        cls,
        records: tuple[tuple[str, dict[str, object], dict[str, object]], ...],
    ) -> None:
        allowed_transitions = {
            "EMPTY_GENESIS": frozenset({"CLAIMED"}),
            "CLAIMED": frozenset({"PREPARED"}),
            "PREPARED": frozenset({"PUBLISHED", "BLOCKED_RECOVERY"}),
            "PUBLISHED": frozenset({"FINALIZED", "BLOCKED_RECOVERY"}),
            "FINALIZED": frozenset({"CLAIMED"}),
            "BLOCKED_RECOVERY": frozenset(),
        }
        if not records:
            raise AuthorityRuntimeError("durable snapshot history is invalid")
        genesis_sha256, genesis_head, genesis = records[0]
        genesis_meta = genesis.get("snapshot_meta")
        if not (
            type(genesis_meta) is tuple
            and len(genesis_meta) == 1
            and type(genesis_meta[0]) is tuple
            and len(genesis_meta[0]) == 4
        ):
            raise AuthorityRuntimeError("durable snapshot genesis is invalid")
        genesis_transition, genesis_generation, genesis_parent, genesis_nonce = (
            genesis_meta[0]
        )
        genesis_migration = genesis.get("durable_migration_provenance")
        genesis_effects = cls._projection_row_map(genesis, "durable_effects")
        genesis_non_effect_rows = any(
            cls._projection_row_map(genesis, key)
            for key in (
                "durable_claims",
                "durable_effect_bindings",
                "durable_target_claims",
                "durable_published_attestations",
                "durable_final_cas_results",
                "durable_recovery_blockers",
            )
        )
        if (
            genesis_transition != "EMPTY_GENESIS"
            or genesis_generation != 0
            or genesis_parent is not None
            or genesis_head.get("generation") != 0
            or genesis_head.get("origin")
            not in {"EMPTY_GENESIS", "LEGACY_D1A_V1"}
            or type(genesis_nonce) is not str
            or re.fullmatch(r"[0-9a-f]{32}", genesis_nonce) is None
            or genesis_non_effect_rows
            or (
                genesis_head.get("origin") == "EMPTY_GENESIS"
                and genesis_effects
            )
            or (
                genesis_head.get("origin") == "LEGACY_D1A_V1"
                and genesis_effects
            )
            or (
                genesis_head.get("origin") == "EMPTY_GENESIS"
                and genesis_migration != ()
            )
            or (
                genesis_head.get("origin") == "LEGACY_D1A_V1"
                and not (
                    type(genesis_migration) is tuple
                    and len(genesis_migration) == 1
                    and type(genesis_migration[0]) is tuple
                    and len(genesis_migration[0]) == 4
                    and genesis_migration[0][0] == 1
                    and type(genesis_migration[0][1]) is str
                    and _SHA256.fullmatch(genesis_migration[0][1]) is not None
                    and type(genesis_migration[0][2]) is str
                    and _SHA256.fullmatch(genesis_migration[0][2]) is not None
                    and genesis_migration[0][1] == genesis_migration[0][3]
                )
            )
        ):
            raise AuthorityRuntimeError("durable snapshot genesis is invalid")
        for index in range(1, len(records)):
            parent_sha256, parent_head, parent = records[index - 1]
            _child_sha256, child_head, child = records[index]
            parent_meta = parent.get("snapshot_meta")
            child_meta = child.get("snapshot_meta")
            if (
                type(parent_meta) is not tuple
                or type(child_meta) is not tuple
                or len(parent_meta) != 1
                or len(child_meta) != 1
                or type(parent_meta[0]) is not tuple
                or type(child_meta[0]) is not tuple
                or len(parent_meta[0]) != 4
                or len(child_meta[0]) != 4
                or child_meta[0][0]
                not in allowed_transitions.get(parent_meta[0][0], frozenset())
                or parent.get("recovery_token_keys")
                != child.get("recovery_token_keys")
            ):
                raise AuthorityRuntimeError("durable snapshot history is invalid")
            parent_transition = parent_meta[0][0]
            child_transition = child_meta[0][0]
            parent_effects = cls._projection_row_map(parent, "durable_effects")
            child_effects = cls._projection_row_map(child, "durable_effects")
            parent_claims = cls._projection_row_map(parent, "durable_claims")
            child_claims = cls._projection_row_map(child, "durable_claims")
            parent_bindings = cls._projection_row_map(
                parent,
                "durable_effect_bindings",
            )
            child_bindings = cls._projection_row_map(
                child,
                "durable_effect_bindings",
            )
            parent_targets = cls._projection_row_map(
                parent,
                "durable_target_claims",
            )
            child_targets = cls._projection_row_map(
                child,
                "durable_target_claims",
            )
            parent_published = cls._projection_row_map(
                parent,
                "durable_published_attestations",
            )
            child_published = cls._projection_row_map(
                child,
                "durable_published_attestations",
            )
            parent_final = cls._projection_row_map(
                parent,
                "durable_final_cas_results",
            )
            child_final = cls._projection_row_map(
                child,
                "durable_final_cas_results",
            )
            parent_blockers = cls._projection_row_map(
                parent,
                "durable_recovery_blockers",
            )
            child_blockers = cls._projection_row_map(
                child,
                "durable_recovery_blockers",
            )
            if (
                type(parent.get("durable_migration_provenance")) is not tuple
                or parent.get("durable_migration_provenance")
                != child.get("durable_migration_provenance")
            ):
                raise AuthorityRuntimeError("durable snapshot history is invalid")
            for effect_id, parent_row in parent_effects.items():
                child_row = child_effects.get(effect_id)
                if (
                    child_row is None
                    or child_row[:-1] != parent_row[:-1]
                ):
                    raise AuthorityRuntimeError("durable snapshot history is invalid")
            effect_state_changes = tuple(
                (effect_id, parent_effects[effect_id][-1], child_effects[effect_id][-1])
                for effect_id in parent_effects
                if parent_effects[effect_id][-1] != child_effects[effect_id][-1]
            )
            for claim_key, parent_row in parent_claims.items():
                child_row = child_claims.get(claim_key)
                if (
                    child_row is None
                    or child_row[:-1] != parent_row[:-1]
                ):
                    raise AuthorityRuntimeError("durable snapshot history is invalid")
            claim_state_changes = tuple(
                (claim_key, parent_claims[claim_key][-1], child_claims[claim_key][-1])
                for claim_key in parent_claims
                if parent_claims[claim_key][-1] != child_claims[claim_key][-1]
            )
            for parent_rows, child_rows in (
                (parent_bindings, child_bindings),
                (parent_targets, child_targets),
                (parent_published, child_published),
                (parent_final, child_final),
                (parent_blockers, child_blockers),
            ):
                if any(child_rows.get(row_key) != row for row_key, row in parent_rows.items()):
                    raise AuthorityRuntimeError("durable snapshot history is invalid")
            added_effects = set(child_effects).difference(parent_effects)
            added_claims = set(child_claims).difference(parent_claims)
            added_bindings = set(child_bindings).difference(parent_bindings)
            added_targets = set(child_targets).difference(parent_targets)
            added_published = set(child_published).difference(parent_published)
            added_final = set(child_final).difference(parent_final)
            added_blockers = set(child_blockers).difference(parent_blockers)
            if child_transition == "CLAIMED":
                if (
                    added_effects
                    or added_bindings
                    or added_targets
                    or added_published
                    or added_final
                    or added_blockers
                    or len(added_claims) != 1
                    or effect_state_changes
                    or claim_state_changes
                    or any(row[-1] == 1 for row in parent_claims.values())
                    or any(
                        row[-1] not in {"FINALIZED", "ABORTED", "BLOCKED_RECOVERY"}
                        for row in parent_effects.values()
                    )
                ):
                    raise AuthorityRuntimeError("durable snapshot history is invalid")
                claim = child_claims[next(iter(added_claims))]
                if (
                    claim[-1] != 1
                    or claim[11] != parent_sha256
                    or claim[12] != child_head["generation"]
                    or claim[0]
                    != cls._claim_key(
                        effect_id=claim[1],
                        target_relative_path=claim[2],
                        artifact_ref_sha256=claim[3],
                        artifact_bytes_sha256=claim[4],
                        request_sha256=claim[5],
                        scope_sha256=claim[6],
                        bounds_sha256=claim[7],
                        spec_identity=claim[8],
                        spec_sha256=claim[9],
                        policy_identity_sha256=claim[10],
                        anchor_identity_sha256=child_head["anchor_identity_sha256"],
                        expected_predecessor_head_sha256=parent_sha256,
                    )
                ):
                    raise AuthorityRuntimeError("durable snapshot history is invalid")
            elif parent_transition == "CLAIMED" and child_transition == "PREPARED":
                active_claims = [
                    row for row in parent_claims.values() if row[-1] == 1
                ]
                if (
                    len(active_claims) != 1
                    or added_claims
                    or len(added_effects) != 1
                    or len(added_bindings) != 1
                    or len(added_targets) != 1
                    or added_published
                    or added_final
                    or added_blockers
                    or len(effect_state_changes) != 0
                    or len(claim_state_changes) != 1
                ):
                    raise AuthorityRuntimeError("durable snapshot history is invalid")
                claim = active_claims[0]
                effect = child_effects[next(iter(added_effects))]
                binding = child_bindings[next(iter(added_bindings))]
                target = child_targets[next(iter(added_targets))]
                if (
                    child_claims.get(claim[0]) is None
                    or child_claims[claim[0]][-1] != 0
                    or effect[0] != claim[1]
                    or effect[1] != claim[2]
                    or effect[2] != claim[3]
                    or effect[3] != claim[4]
                    or effect[4] != claim[5]
                    or effect[5] != claim[6]
                    or effect[6] != claim[8]
                    or effect[7] != claim[9]
                    or effect[8] != claim[10]
                    or effect[9] != "PREPARED"
                    or binding[0] != claim[1]
                    or binding[1] != claim[2]
                    or binding[2] != claim[3]
                    or binding[3] != claim[5]
                    or binding[4] != claim[6]
                    or binding[5] != claim[7]
                    or binding[6] != claim[8]
                    or binding[7] != claim[9]
                    or binding[8] != claim[10]
                    or binding[9] != binding[3]
                    or target != (claim[2], claim[1], binding[12])
                    or claim_state_changes != ((claim[0], 1, 0),)
                ):
                    raise AuthorityRuntimeError("durable snapshot history is invalid")
            else:
                if (
                    added_effects
                    or added_claims
                    or added_bindings
                    or added_targets
                    or claim_state_changes
                ):
                    raise AuthorityRuntimeError("durable snapshot history is invalid")
                if child_transition == "PUBLISHED":
                    if (
                        len(effect_state_changes) != 1
                        or effect_state_changes[0][1:] != ("PREPARED", "PUBLISHED")
                        or len(added_published) != 1
                        or added_published != {effect_state_changes[0][0]}
                        or added_final
                        or added_blockers
                    ):
                        raise AuthorityRuntimeError("durable snapshot history is invalid")
                elif child_transition == "FINALIZED":
                    if (
                        len(effect_state_changes) != 1
                        or effect_state_changes[0][1:] != ("PUBLISHED", "FINALIZED")
                        or added_published
                        or len(added_final) != 1
                        or added_final != {effect_state_changes[0][0]}
                        or added_blockers
                    ):
                        raise AuthorityRuntimeError("durable snapshot history is invalid")
                elif child_transition == "BLOCKED_RECOVERY":
                    if (
                        len(effect_state_changes) != 1
                        or effect_state_changes[0][1:] not in {
                            ("PREPARED", "BLOCKED_RECOVERY"),
                            ("PUBLISHED", "BLOCKED_RECOVERY"),
                        }
                        or added_published
                        or added_final
                        or len(added_blockers) != 1
                        or added_blockers != {effect_state_changes[0][0]}
                    ):
                        raise AuthorityRuntimeError("durable snapshot history is invalid")
                else:
                    raise AuthorityRuntimeError("durable snapshot history is invalid")

    def _publish_object(self, raw: bytes, *, seal_kind: str) -> str:
        object_sha256 = sha256_bytes(raw)
        self.__root.publish_bytes(
            self.__root.joinpath(*_SNAPSHOT_OBJECTS_PARTS, f"o-{object_sha256}"),
            raw,
            label="durable snapshot object",
            after_file_fsync=lambda: _run_snapshot_checkpoint(
                f"after-{seal_kind}-file-fsync"
            ),
            after_file_readback=lambda: _run_snapshot_checkpoint(
                f"after-{seal_kind}-readback"
            ),
            after_directory_fsync=lambda: _run_snapshot_checkpoint(
                f"after-{seal_kind}-directory-fsync"
            ),
        )
        return object_sha256

    def _publish_head(
        self,
        head_raw: bytes,
        head_sha256: str,
        receipt_token: str,
        *,
        _initial_legacy_witness: _LegacyV1Inventory | None = None,
    ) -> None:
        receipt_name = f"r-{head_sha256}-{receipt_token}"
        head_name = f"h-{head_sha256}.json"
        self.__root.publish_bytes(
            self.__root.joinpath(*_SNAPSHOT_RECEIPTS_PARTS, receipt_name),
            head_raw,
            label="durable snapshot head receipt",
            after_file_fsync=lambda: _run_snapshot_checkpoint(
                "after-receipt-file-fsync"
            ),
            after_file_readback=lambda: _run_snapshot_checkpoint(
                "after-receipt-readback"
            ),
            after_directory_fsync=lambda: _run_snapshot_checkpoint(
                "after-receipt-directory-fsync"
            ),
        )
        receipt_directory_fd: int | None = None
        heads_directory_fd: int | None = None
        source_fd: int | None = None
        destination_fd: int | None = None
        try:
            receipt_directory_fd = self.__root._open_directory(
                _SNAPSHOT_RECEIPTS_PARTS,
                create=False,
            )
            heads_directory_fd = self.__root._open_directory(
                _SNAPSHOT_HEADS_PARTS,
                create=False,
            )
            os.link(
                receipt_name,
                head_name,
                src_dir_fd=receipt_directory_fd,
                dst_dir_fd=heads_directory_fd,
                follow_symlinks=False,
            )
            _run_snapshot_checkpoint("after-receipt-link")
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            source_fd = os.open(receipt_name, flags, dir_fd=receipt_directory_fd)
            destination_fd = os.open(head_name, flags, dir_fd=heads_directory_fd)
            source_info = os.fstat(source_fd)
            destination_info = os.fstat(destination_fd)
            if (
                not stat.S_ISREG(source_info.st_mode)
                or source_info.st_uid != os.getuid()
                or stat.S_IMODE(source_info.st_mode) != 0o600
                or source_info.st_nlink != 2
                or (source_info.st_dev, source_info.st_ino)
                != (destination_info.st_dev, destination_info.st_ino)
                or safety.read_open_file_bytes(destination_fd) != head_raw
            ):
                raise AuthorityRuntimeError("durable snapshot head is invalid")
            _run_snapshot_checkpoint("after-canonical-head-readback")
            os.fsync(source_fd)
            os.fsync(destination_fd)
            _run_snapshot_checkpoint("after-head-file-fsync")
            os.fsync(heads_directory_fd)
            _run_snapshot_checkpoint("after-heads-directory-fsync")
            if _initial_legacy_witness is not None:
                try:
                    self._verify_legacy_v1_inventory(
                        self.__root,
                        _initial_legacy_witness,
                    )
                except _SnapshotLegacyFenceRequired as exc:
                    self._publish_root_stop_if_possible(
                        self.__root,
                        reason_code=exc.reason_code,
                        observed_evidence_sha256=exc.observed_evidence_sha256,
                    )
                    raise
        except FileExistsError as exc:
            raise AuthorityRuntimeError("durable snapshot head already exists") from exc
        except OSError as exc:
            raise AuthorityRuntimeError("durable snapshot head is unavailable") from exc
        finally:
            for fd in (destination_fd, source_fd, heads_directory_fd, receipt_directory_fd):
                if fd is not None:
                    os.close(fd)

    @staticmethod
    def _claim_key(
        *,
        effect_id: str,
        target_relative_path: str,
        artifact_ref_sha256: str,
        artifact_bytes_sha256: str,
        request_sha256: str,
        scope_sha256: str,
        bounds_sha256: str,
        spec_identity: str,
        spec_sha256: str,
        policy_identity_sha256: str,
        anchor_identity_sha256: str,
        expected_predecessor_head_sha256: str | None,
    ) -> str:
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "effect_id": effect_id,
                    "target_relative_path": target_relative_path,
                    "artifact_ref_sha256": artifact_ref_sha256,
                    "artifact_bytes_sha256": artifact_bytes_sha256,
                    "request_sha256": request_sha256,
                    "scope_sha256": scope_sha256,
                    "bounds_sha256": bounds_sha256,
                    "spec_identity": spec_identity,
                    "spec_sha256": spec_sha256,
                    "policy_identity_sha256": policy_identity_sha256,
                    "anchor_identity_sha256": anchor_identity_sha256,
                    "expected_predecessor_head_sha256": expected_predecessor_head_sha256,
                }
            )
        )

    def claim_or_replay(
        self,
        *,
        effect_id: str,
        target_relative_path: str,
        artifact_ref_sha256: str,
        artifact_bytes_sha256: str,
        request_sha256: str,
        scope_sha256: str,
        bounds_sha256: str,
        spec_identity: str,
        spec_sha256: str,
        policy_identity_sha256: str,
    ) -> str | None:
        """Persist or validate the one pre-effect claim for this snapshot tip."""

        self._require_active()
        anchor_identity_sha256 = sha256_bytes(
            canonical_json_bytes(self.__root.identity)
        )
        try:
            if self.__connection.execute(
                "SELECT 1 FROM durable_effects WHERE effect_id = ?",
                (effect_id,),
            ).fetchone() is not None:
                return None
            active_claims = tuple(
                self.__connection.execute(
                    "SELECT claim_key_sha256, effect_id, target_relative_path, "
                    "artifact_ref_sha256, artifact_bytes_sha256, request_sha256, "
                    "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                    "policy_identity_sha256, expected_predecessor_head_sha256, "
                    "claim_generation FROM durable_claims WHERE active = 1 "
                    "ORDER BY claim_key_sha256"
                )
            )
            metadata = self.__connection.execute(
                "SELECT transition_kind, generation, parent_head_sha256 "
                "FROM snapshot_meta WHERE singleton = 1"
            ).fetchone()
            unfinished_effect = self.__connection.execute(
                "SELECT effect_id FROM durable_effects "
                "WHERE state NOT IN ('FINALIZED', 'ABORTED', 'BLOCKED_RECOVERY') "
                "ORDER BY effect_id LIMIT 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable snapshot claim is unavailable") from exc
        if len(active_claims) > 1:
            raise AuthorityRuntimeError("durable snapshot claim is ambiguous")
        if active_claims:
            claim = active_claims[0]
            if (
                metadata is None
                or metadata["transition_kind"] != "CLAIMED"
                or metadata["generation"] != self.__generation
                or metadata["parent_head_sha256"]
                != claim["expected_predecessor_head_sha256"]
                or claim["claim_generation"] != self.__generation
            ):
                raise _SnapshotClaimDenied(
                    "durable snapshot claim predecessor is invalid"
                )
            expected_key = self._claim_key(
                effect_id=effect_id,
                target_relative_path=target_relative_path,
                artifact_ref_sha256=artifact_ref_sha256,
                artifact_bytes_sha256=artifact_bytes_sha256,
                request_sha256=request_sha256,
                scope_sha256=scope_sha256,
                bounds_sha256=bounds_sha256,
                spec_identity=spec_identity,
                spec_sha256=spec_sha256,
                policy_identity_sha256=policy_identity_sha256,
                anchor_identity_sha256=anchor_identity_sha256,
                expected_predecessor_head_sha256=claim[
                    "expected_predecessor_head_sha256"
                ],
            )
            if (
                claim["claim_key_sha256"] != expected_key
                or claim["effect_id"] != effect_id
                or claim["target_relative_path"] != target_relative_path
                or claim["artifact_ref_sha256"] != artifact_ref_sha256
                or claim["artifact_bytes_sha256"] != artifact_bytes_sha256
                or claim["request_sha256"] != request_sha256
                or claim["scope_sha256"] != scope_sha256
                or claim["bounds_sha256"] != bounds_sha256
                or claim["spec_identity"] != spec_identity
                or claim["spec_sha256"] != spec_sha256
                or claim["policy_identity_sha256"] != policy_identity_sha256
            ):
                raise _SnapshotClaimDenied(
                    "durable snapshot claim belongs to another admission"
                )
            return str(claim["claim_key_sha256"])
        if metadata is None:
            raise _SnapshotClaimDenied(
                "durable snapshot does not permit another claim"
            )
        if metadata["transition_kind"] == "BLOCKED_RECOVERY":
            raise _SnapshotClaimBusy(
                "durable snapshot history is blocked",
                reason_code="RECOVERY_BLOCKED_HISTORY",
            )
        if unfinished_effect is not None:
            raise _SnapshotClaimBusy(
                "durable snapshot has an outstanding effect",
                reason_code="RECOVERY_OUTSTANDING_EFFECT",
            )
        expected_predecessor = self.__head_sha256
        claim_key_sha256 = self._claim_key(
            effect_id=effect_id,
            target_relative_path=target_relative_path,
            artifact_ref_sha256=artifact_ref_sha256,
            artifact_bytes_sha256=artifact_bytes_sha256,
            request_sha256=request_sha256,
            scope_sha256=scope_sha256,
            bounds_sha256=bounds_sha256,
            spec_identity=spec_identity,
            spec_sha256=spec_sha256,
            policy_identity_sha256=policy_identity_sha256,
            anchor_identity_sha256=anchor_identity_sha256,
            expected_predecessor_head_sha256=expected_predecessor,
        )
        try:
            self.__connection.execute(
                "INSERT INTO durable_claims "
                "(claim_key_sha256, effect_id, target_relative_path, "
                "artifact_ref_sha256, artifact_bytes_sha256, request_sha256, "
                "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                "policy_identity_sha256, expected_predecessor_head_sha256, "
                "claim_generation, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    claim_key_sha256,
                    effect_id,
                    target_relative_path,
                    artifact_ref_sha256,
                    artifact_bytes_sha256,
                    request_sha256,
                    scope_sha256,
                    bounds_sha256,
                    spec_identity,
                    spec_sha256,
                    policy_identity_sha256,
                    expected_predecessor,
                    self.__generation + 1,
                ),
            )
        except sqlite3.IntegrityError as exc:
            target_claim = self.__connection.execute(
                "SELECT 1 FROM durable_effects WHERE target_relative_path = ? "
                "UNION ALL "
                "SELECT 1 FROM durable_target_claims WHERE target_relative_path = ? "
                "LIMIT 1",
                (target_relative_path, target_relative_path),
            ).fetchone()
            if target_claim is not None:
                raise _SnapshotTargetClaimConflict(
                    "durable effect target is already claimed"
                ) from exc
            raise AuthorityRuntimeError("durable snapshot claim is unavailable") from exc
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable snapshot claim is unavailable") from exc
        self.checkpoint("CLAIMED")
        return claim_key_sha256

    def consume_claim(self, claim_key_sha256: str) -> None:
        self._require_active()
        try:
            updated = self.__connection.execute(
                "UPDATE durable_claims SET active = 0 "
                "WHERE claim_key_sha256 = ? AND active = 1",
                (claim_key_sha256,),
            ).rowcount
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable snapshot claim is unavailable") from exc
        if updated != 1:
            raise AuthorityRuntimeError("durable snapshot claim is unavailable")
        self.checkpoint("PREPARED")

    def _create_recovery_token_key(self) -> bytes:
        token_key = secrets.token_bytes(32)
        self.__connection.execute(
            "INSERT INTO recovery_token_keys (singleton, token_key, key_sha256) "
            "VALUES (1, ?, ?)",
            (token_key, sha256_bytes(token_key)),
        )
        return token_key

    def recovery_token_key(self) -> bytes:
        self._require_active()
        try:
            row = self.__connection.execute(
                "SELECT token_key, key_sha256 FROM recovery_token_keys "
                "WHERE singleton = 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable recovery authority is unavailable") from exc
        if row is None:
            raise AuthorityRuntimeError("durable recovery authority is unavailable")
        token_key = bytes(row["token_key"])
        if len(token_key) != 32 or row["key_sha256"] != sha256_bytes(token_key):
            raise AuthorityRuntimeError("durable recovery authority is unavailable")
        return token_key

    @staticmethod
    def _binding_record(
        row: sqlite3.Row | None,
    ) -> _SnapshotBindingValue | None:
        if row is None:
            return None
        return _SnapshotBindingValue(
            effect_id=str(row["effect_id"]),
            target_relative_path=str(row["target_relative_path"]),
            artifact_ref_sha256=str(row["artifact_ref_sha256"]),
            request_sha256=str(row["request_sha256"]),
            scope_sha256=str(row["scope_sha256"]),
            bounds_sha256=str(row["bounds_sha256"]),
            spec_identity=str(row["spec_identity"]),
            spec_sha256=str(row["spec_sha256"]),
            policy_identity_sha256=str(row["policy_identity_sha256"]),
            token_request_sha256=str(row["token_request_sha256"]),
            token_continuation_identity=str(row["token_continuation_identity"]),
            token_authentication_tag=str(row["token_authentication_tag"]),
            binding_sha256=str(row["binding_sha256"]),
        )

    def binding(self, effect_id: str) -> _SnapshotBindingValue | None:
        self._require_active()
        return self._binding_record(
            self.__connection.execute(
                "SELECT effect_id, target_relative_path, artifact_ref_sha256, "
                "request_sha256, scope_sha256, bounds_sha256, spec_identity, "
                "spec_sha256, policy_identity_sha256, token_request_sha256, "
                "token_continuation_identity, token_authentication_tag, binding_sha256 "
                "FROM durable_effect_bindings WHERE effect_id = ?",
                (effect_id,),
            ).fetchone()
        )

    def binding_for_continuation(
        self,
        continuation_identity: str,
    ) -> _SnapshotBindingValue | None:
        self._require_active()
        if (
            type(continuation_identity) is not str
            or _SHA256.fullmatch(continuation_identity) is None
        ):
            raise ValueError("durable continuation identity is invalid")
        rows = self.__connection.execute(
            "SELECT effect_id, target_relative_path, artifact_ref_sha256, "
            "request_sha256, scope_sha256, bounds_sha256, spec_identity, "
            "spec_sha256, policy_identity_sha256, token_request_sha256, "
            "token_continuation_identity, token_authentication_tag, binding_sha256 "
            "FROM durable_effect_bindings WHERE token_continuation_identity = ? "
            "LIMIT 2",
            (continuation_identity,),
        ).fetchall()
        if len(rows) > 1:
            raise AuthorityRuntimeError(
                "durable continuation identity is not unique"
            )
        return self._binding_record(rows[0] if rows else None)

    def record_binding(
        self,
        value: _SnapshotBindingValue,
    ) -> _SnapshotBindingValue:
        self._require_active()
        if type(value) is not _SnapshotBindingValue:
            raise AuthorityRuntimeError("durable snapshot binding is invalid")
        existing = self.binding(value.effect_id)
        if existing is not None:
            if existing != value:
                raise _SnapshotBindingConflict("durable snapshot binding is invalid")
            return existing
        try:
            self.__connection.execute(
                "INSERT INTO durable_effect_bindings "
                "(effect_id, target_relative_path, artifact_ref_sha256, request_sha256, "
                "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                "policy_identity_sha256, token_request_sha256, "
                "token_continuation_identity, token_authentication_tag, binding_sha256) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    value.effect_id,
                    value.target_relative_path,
                    value.artifact_ref_sha256,
                    value.request_sha256,
                    value.scope_sha256,
                    value.bounds_sha256,
                    value.spec_identity,
                    value.spec_sha256,
                    value.policy_identity_sha256,
                    value.token_request_sha256,
                    value.token_continuation_identity,
                    value.token_authentication_tag,
                    value.binding_sha256,
                ),
            )
        except sqlite3.IntegrityError as exc:
            existing = self.binding(value.effect_id)
            if existing == value:
                return value
            raise _SnapshotBindingConflict("durable snapshot binding is invalid") from exc
        return value

    def target_claim(
        self,
        target_relative_path: str,
    ) -> _SnapshotTargetClaimValue | None:
        self._require_active()
        row = self.__connection.execute(
            "SELECT effect_id, binding_sha256 FROM durable_target_claims "
            "WHERE target_relative_path = ?",
            (target_relative_path,),
        ).fetchone()
        if row is None:
            return None
        return _SnapshotTargetClaimValue(
            target_relative_path=target_relative_path,
            effect_id=str(row["effect_id"]),
            binding_sha256=str(row["binding_sha256"]),
        )

    def record_target_claim(
        self,
        value: _SnapshotTargetClaimValue,
    ) -> _SnapshotTargetClaimValue:
        self._require_active()
        if type(value) is not _SnapshotTargetClaimValue:
            raise AuthorityRuntimeError("durable snapshot target claim is invalid")
        existing = self.target_claim(value.target_relative_path)
        if existing is not None:
            if existing != value:
                raise _SnapshotTargetClaimConflict(
                    "durable snapshot target claim is invalid"
                )
            return existing
        try:
            self.__connection.execute(
                "INSERT INTO durable_target_claims "
                "(target_relative_path, effect_id, binding_sha256) VALUES (?, ?, ?)",
                (
                    value.target_relative_path,
                    value.effect_id,
                    value.binding_sha256,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if self.target_claim(value.target_relative_path) == value:
                return value
            raise _SnapshotTargetClaimConflict(
                "durable snapshot target claim is invalid"
            ) from exc
        return value

    @staticmethod
    def _published_attestation_record(
        row: sqlite3.Row | None,
    ) -> _SnapshotPublishedAttestationValue | None:
        if row is None:
            return None
        return _SnapshotPublishedAttestationValue(*tuple(row))

    def published_attestation(
        self,
        effect_id: str,
    ) -> _SnapshotPublishedAttestationValue | None:
        self._require_active()
        try:
            return self._published_attestation_record(
                self.__connection.execute(
                    "SELECT effect_id, target_relative_path, binding_sha256, "
                    "artifact_bytes_sha256, byte_length, target_device, target_inode, "
                    "target_nlink, attestation_sha256 "
                    "FROM durable_published_attestations WHERE effect_id = ?",
                    (effect_id,),
                ).fetchone()
            )
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise AuthorityRuntimeError("durable published attestation is invalid") from exc

    def record_published_attestation(
        self,
        value: _SnapshotPublishedAttestationValue,
    ) -> _SnapshotPublishedAttestationValue:
        self._require_active()
        self._validate_published_attestation_value(value)
        existing = self.published_attestation(value.effect_id)
        if existing is not None:
            if existing != value:
                raise AuthorityRuntimeError("durable published attestation is invalid")
            return existing
        try:
            self.__connection.execute(
                "INSERT INTO durable_published_attestations "
                "(effect_id, target_relative_path, binding_sha256, "
                "artifact_bytes_sha256, byte_length, target_device, target_inode, "
                "target_nlink, attestation_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    value.effect_id,
                    value.target_relative_path,
                    value.binding_sha256,
                    value.artifact_bytes_sha256,
                    value.byte_length,
                    value.target_device,
                    value.target_inode,
                    value.target_nlink,
                    value.attestation_sha256,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if self.published_attestation(value.effect_id) == value:
                return value
            raise AuthorityRuntimeError("durable published attestation is invalid") from exc
        return value

    @staticmethod
    def _final_cas_result_record(
        row: sqlite3.Row | None,
    ) -> _SnapshotFinalCasResultValue | None:
        if row is None:
            return None
        return _SnapshotFinalCasResultValue(*tuple(row))

    def final_cas_result(
        self,
        effect_id: str,
    ) -> _SnapshotFinalCasResultValue | None:
        self._require_active()
        try:
            return self._final_cas_result_record(
                self.__connection.execute(
                    "SELECT effect_id, binding_sha256, published_attestation_sha256, "
                    "expected_state, resulting_state, result_sha256 "
                    "FROM durable_final_cas_results WHERE effect_id = ?",
                    (effect_id,),
                ).fetchone()
            )
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise AuthorityRuntimeError("durable final CAS result is invalid") from exc

    def record_final_cas_result(
        self,
        value: _SnapshotFinalCasResultValue,
    ) -> _SnapshotFinalCasResultValue:
        self._require_active()
        self._validate_final_cas_result_value(value)
        existing = self.final_cas_result(value.effect_id)
        if existing is not None:
            if existing != value:
                raise AuthorityRuntimeError("durable final CAS result is invalid")
            return existing
        try:
            self.__connection.execute(
                "INSERT INTO durable_final_cas_results "
                "(effect_id, binding_sha256, published_attestation_sha256, "
                "expected_state, resulting_state, result_sha256) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    value.effect_id,
                    value.binding_sha256,
                    value.published_attestation_sha256,
                    value.expected_state,
                    value.resulting_state,
                    value.result_sha256,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if self.final_cas_result(value.effect_id) == value:
                return value
            raise AuthorityRuntimeError("durable final CAS result is invalid") from exc
        return value

    @staticmethod
    def _recovery_blocker_record(
        row: sqlite3.Row | None,
    ) -> _SnapshotRecoveryBlockerValue | None:
        if row is None:
            return None
        return _SnapshotRecoveryBlockerValue(*tuple(row))

    def recovery_blocker(
        self,
        effect_id: str,
    ) -> _SnapshotRecoveryBlockerValue | None:
        self._require_active()
        try:
            return self._recovery_blocker_record(
                self.__connection.execute(
                    "SELECT effect_id, binding_sha256, reason_code, "
                    "observed_evidence_sha256, token_request_sha256, "
                    "token_continuation_identity, blocker_sha256 "
                    "FROM durable_recovery_blockers WHERE effect_id = ?",
                    (effect_id,),
                ).fetchone()
            )
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise AuthorityRuntimeError("durable recovery blocker is invalid") from exc

    def record_recovery_blocker(
        self,
        value: _SnapshotRecoveryBlockerValue,
    ) -> _SnapshotRecoveryBlockerValue:
        self._require_active()
        self._validate_recovery_blocker_value(value)
        existing = self.recovery_blocker(value.effect_id)
        if existing is not None:
            if existing != value:
                raise AuthorityRuntimeError("durable recovery blocker is invalid")
            return existing
        try:
            self.__connection.execute(
                "INSERT INTO durable_recovery_blockers "
                "(effect_id, binding_sha256, reason_code, observed_evidence_sha256, "
                "token_request_sha256, token_continuation_identity, blocker_sha256) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    value.effect_id,
                    value.binding_sha256,
                    value.reason_code,
                    value.observed_evidence_sha256,
                    value.token_request_sha256,
                    value.token_continuation_identity,
                    value.blocker_sha256,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if self.recovery_blocker(value.effect_id) == value:
                return value
            raise AuthorityRuntimeError("durable recovery blocker is invalid") from exc
        return value

    @staticmethod
    def _effect_record(row: sqlite3.Row | None) -> dict[str, object] | None:
        if row is None:
            return None
        return {
            "effect_id": row["effect_id"],
            "target_relative_path": row["target_relative_path"],
            "artifact_ref": bytes(row["artifact_ref"]),
            "artifact_bytes": bytes(row["artifact_bytes"]),
            "request_sha256": row["request_sha256"],
            "scope_sha256": row["scope_sha256"],
            "spec_identity": row["spec_identity"],
            "spec_sha256": row["spec_sha256"],
            "policy_identity_sha256": row["policy_identity_sha256"],
            "state": row["state"],
        }

    def effect(self, effect_id: str) -> dict[str, object] | None:
        self._require_active()
        return self._effect_record(
            self.__connection.execute(
                "SELECT effect_id, target_relative_path, artifact_ref, artifact_bytes, "
                "request_sha256, scope_sha256, spec_identity, spec_sha256, "
                "policy_identity_sha256, state FROM durable_effects WHERE effect_id = ?",
                (effect_id,),
            ).fetchone()
        )

    def insert_effect(
        self,
        *,
        effect_id: str,
        target_relative_path: str,
        artifact_ref: bytes,
        artifact_bytes: bytes,
        request_sha256: str,
        scope_sha256: str,
        spec_identity: str,
        spec_sha256: str,
        policy_identity_sha256: str,
        state: str,
    ) -> None:
        self._require_active()
        self.__connection.execute(
            "INSERT INTO durable_effects "
            "(effect_id, target_relative_path, artifact_ref, artifact_bytes, request_sha256, "
            "scope_sha256, spec_identity, spec_sha256, policy_identity_sha256, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                effect_id,
                target_relative_path,
                artifact_ref,
                artifact_bytes,
                request_sha256,
                scope_sha256,
                spec_identity,
                spec_sha256,
                policy_identity_sha256,
                state,
            ),
        )

    def transition_effect(
        self,
        row: dict[str, object],
        *,
        expected_state: str,
        target_state: str,
    ) -> int:
        self._require_active()
        return self.__connection.execute(
            "UPDATE durable_effects SET state = ? "
            "WHERE effect_id = ? AND state = ? "
            "AND target_relative_path = ? AND artifact_ref = ? AND artifact_bytes = ? "
            "AND request_sha256 = ? AND scope_sha256 = ? "
            "AND spec_identity = ? AND spec_sha256 = ? "
            "AND policy_identity_sha256 = ?",
            (
                target_state,
                row["effect_id"],
                expected_state,
                row["target_relative_path"],
                row["artifact_ref"],
                row["artifact_bytes"],
                row["request_sha256"],
                row["scope_sha256"],
                row["spec_identity"],
                row["spec_sha256"],
                row["policy_identity_sha256"],
            ),
        ).rowcount

    def block_effect(
        self,
        *,
        effect_id: str,
        expected_state: str,
    ) -> int:
        self._require_active()
        return self.__connection.execute(
            "UPDATE durable_effects SET state = ? "
            "WHERE effect_id = ? AND state = ?",
            ("BLOCKED_RECOVERY", effect_id, expected_state),
        ).rowcount

    def checkpoint(
        self,
        transition_kind: str,
        *,
        _initial_legacy: _LegacyV1Classification | None = None,
    ) -> None:
        self._verify_expected_history()
        if transition_kind not in _SNAPSHOT_TRANSITIONS:
            raise AuthorityRuntimeError("durable snapshot transition is invalid")
        if self.__head_sha256 is None:
            if transition_kind != "EMPTY_GENESIS":
                raise AuthorityRuntimeError("durable snapshot genesis is unavailable")
            generation = 0
            parent = None
            if _initial_legacy is None:
                origin = "EMPTY_GENESIS"
                legacy_provenance_sha256: str | None = None
            else:
                if type(_initial_legacy) is not _LegacyV1Classification:
                    raise TypeError("durable legacy classification is invalid")
                origin = "LEGACY_D1A_V1"
                legacy_provenance_sha256 = (
                    _initial_legacy.legacy_provenance_sha256
                )
        else:
            if transition_kind == "EMPTY_GENESIS" or _initial_legacy is not None:
                raise AuthorityRuntimeError("durable snapshot transition is invalid")
            generation = self.__generation + 1
            parent = self.__head_sha256
            origin = "NORMAL"
            legacy_provenance_sha256 = None
        nonce = secrets.token_hex(16)
        try:
            if _initial_legacy is not None:
                existing_migration = tuple(
                    self.__connection.execute(
                        "SELECT singleton FROM durable_migration_provenance"
                    )
                )
                if existing_migration:
                    raise AuthorityRuntimeError(
                        "durable legacy migration provenance is invalid"
                    )
                self.__connection.execute(
                    "INSERT INTO durable_migration_provenance "
                    "(singleton, legacy_provenance_sha256, retired_witness_sha256, "
                    "legacy_provenance_canonical_json) VALUES (1, ?, ?, ?)",
                    (
                        _initial_legacy.legacy_provenance_sha256,
                        _initial_legacy.retired_witness_sha256,
                        _initial_legacy.legacy_provenance_raw,
                    ),
                )
            self.__connection.execute(
                "UPDATE snapshot_meta SET transition_kind = ?, generation = ?, "
                "parent_head_sha256 = ?, publication_nonce = ? WHERE singleton = 1",
                (transition_kind, generation, parent, nonce),
            )
            self.__connection.commit()
            _run_snapshot_checkpoint("after-snapshot-commit")
            self._configure_connection(self.__connection)
            if self.__connection.in_transaction:
                raise AuthorityRuntimeError("durable snapshot transaction is active")
            snapshot_raw = self.__connection.serialize()
            _run_snapshot_checkpoint("after-snapshot-serialize")
            if _initial_legacy is not None:
                try:
                    self._verify_legacy_v1_inventory(
                        self.__root,
                        _initial_legacy.inventory,
                    )
                except _SnapshotLegacyFenceRequired as exc:
                    self._publish_root_stop_if_possible(
                        self.__root,
                        reason_code=exc.reason_code,
                        observed_evidence_sha256=exc.observed_evidence_sha256,
                    )
                    raise
        except sqlite3.Error as exc:
            raise AuthorityRuntimeError("durable snapshot state is unavailable") from exc
        snapshot_object_sha256 = self._publish_object(
            snapshot_raw,
            seal_kind="snapshot-object",
        )
        _run_snapshot_checkpoint("after-snapshot-object-seal")
        schema_fingerprint = self._schema_fingerprint()
        recovery_projection = self._recovery_projection()
        anchor_identity_sha256 = sha256_bytes(
            canonical_json_bytes(self.__root.identity)
        )
        manifest_raw = canonical_json_bytes(
            {
                "protocol_version": 1,
                "kind": "DURABLE_SNAPSHOT_MANIFEST",
                "publication_nonce": nonce,
                "snapshot_object_sha256": snapshot_object_sha256,
                "snapshot_byte_length": len(snapshot_raw),
                "sqlite_schema_fingerprint_sha256": schema_fingerprint,
                "recovery_projection_sha256": recovery_projection,
                "origin": origin,
                "legacy_provenance_sha256": legacy_provenance_sha256,
                "anchor_identity_sha256": anchor_identity_sha256,
            }
        )
        manifest_object_sha256 = self._publish_object(
            manifest_raw,
            seal_kind="manifest-object",
        )
        _run_snapshot_checkpoint("after-manifest-object-seal")
        receipt_token = secrets.token_hex(16)
        head_raw = canonical_json_bytes(
            {
                "protocol_version": 1,
                "kind": "DURABLE_SNAPSHOT_HEAD",
                "receipt_token": receipt_token,
                "generation": generation,
                "parent_head_sha256": parent,
                "manifest_object_sha256": manifest_object_sha256,
                "snapshot_object_sha256": snapshot_object_sha256,
                "recovery_projection_sha256": recovery_projection,
                "sqlite_schema_fingerprint_sha256": schema_fingerprint,
                "origin": origin,
                "anchor_identity_sha256": anchor_identity_sha256,
            }
        )
        head_sha256 = sha256_bytes(head_raw)
        self._publish_head(
            head_raw,
            head_sha256,
            receipt_token,
            _initial_legacy_witness=(
                _initial_legacy.inventory if _initial_legacy is not None else None
            ),
        )
        self._adopt_published_history(
            head_sha256=head_sha256,
            generation=generation,
        )

    def close(self) -> None:
        if self.__closed:
            return
        if os.getpid() != self.__owner_pid:
            raise AuthorityRuntimeError("durable snapshot store is unavailable")
        self.__closed = True
        close_error: BaseException | None = None
        try:
            self.__connection.close()
        except BaseException as exc:
            close_error = exc
        try:
            self.__lease.close()
        except BaseException as exc:
            if close_error is None:
                close_error = exc
        try:
            self.__root.close()
        except BaseException as exc:
            if close_error is None:
                close_error = exc
        if close_error is not None:
            raise close_error

    def abandon(self) -> None:
        self.close()
