"""Private durable coordinator used only through an Authority Runtime WriteSession."""

from __future__ import annotations

import os
import re
import sqlite3
import stat
import hmac
import json
import secrets
import tempfile
from contextlib import contextmanager
from hashlib import sha256
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, Mapping, Optional

from .. import artifact_contract, operation_contract, safety
from ..canonical_json import canonical_json_bytes, sha256_bytes
from . import AuthorityRuntimeError, _durable_snapshot


_EFFECT_ID = re.compile(r"[a-z][a-z0-9-]{2,63}")
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RECOVERY_REASON = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
_DATABASE_NAME = "authority-runtime.sqlite3"
_DATABASE_BRIDGE_LEASE_DIRECTORY = "database-bridge-leases"
_RECOVERY_TOKEN_KEY_NAME = "recovery-token.key"
_RECOVERY_TOKEN_KEY_ATTESTATION_NAME = "recovery-token-key-attestation.json"
_RECOVERY_TOKEN_KEY_BYTES = 32
_RECOVERY_BINDING_DIRECTORY = "recovery-bindings"
_RECOVERY_TARGET_CLAIM_DIRECTORY = "recovery-target-claims"
_RECOVERY_BLOCKER_DIRECTORY = "recovery-blockers"
_RECOVERY_BINDING_KIND = "DURABLE_EFFECT_BINDING"
_RECOVERY_TARGET_CLAIM_KIND = "DURABLE_TARGET_CLAIM"
_RECOVERY_BLOCKER_KIND = "DURABLE_RECOVERY_BLOCKER"
_RECOVERY_TOKEN_KEY_ATTESTATION_KIND = "DURABLE_RECOVERY_TOKEN_KEY_ATTESTATION"
_RECOVERY_FENCE_DIRECTORY = "recovery-fences"
_RECOVERY_FENCE_NAME = "root-recovery-fence.json"
_RECOVERY_FENCE_KIND = "DURABLE_ROOT_RECOVERY_FENCE"
_DATABASE_BRIDGE_LEASE_KIND = "DURABLE_DATABASE_BRIDGE_LEASE"
_DATABASE_BRIDGE_LIFETIME_LOCK_NAME = "database-bridge-lifetime.lock"
_RECOVERY_OWNER = "authority-runtime"
_RECOVERY_PROTOCOL_VERSION = 1
_DATABASE_BRIDGE_LEASE_ID = re.compile(r"[0-9a-f]{32}")
_DURABLE_EFFECT_COLUMN_SIGNATURE = (
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
_DURABLE_EFFECT_INDEX_SIGNATURE = frozenset(
    {
        ("pk", 1, 0, ("effect_id",)),
        ("u", 1, 0, ("target_relative_path",)),
    }
)
_SnapshotEffectRow = Mapping[str, object]
_MAX_ARTIFACT_BYTES = _durable_snapshot._MAX_ARTIFACT_BYTES
_RUNTIME_PARTS = _durable_snapshot._RUNTIME_PARTS
_MUTATION_LOCK_NAME = _durable_snapshot._MUTATION_LOCK_NAME
_anchored_parts = _durable_snapshot._anchored_parts
_AnchoredPath = _durable_snapshot._AnchoredPath
_RootAnchor = _durable_snapshot._RootAnchor
_acquire_fork_safe_lock = _durable_snapshot._acquire_fork_safe_lock
_release_tracked_lock = _durable_snapshot._release_tracked_lock
_close_descriptor = _durable_snapshot._close_descriptor


class DurableCapabilityDenied(AuthorityRuntimeError):
    """An admitted session attempted an action outside its capability."""


_ACTIVE_DATABASE_BRIDGE_ROOTS: set[tuple[int, int]] = set()


def _clear_inherited_database_bridge_roots() -> None:
    _ACTIVE_DATABASE_BRIDGE_ROOTS.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_inherited_database_bridge_roots)


@dataclass(frozen=True)
class RecoveryToken:
    """Opaque selector bound to one durable effect's immutable continuation."""

    effect_id: str
    request_sha256: str
    continuation_identity: str
    authentication_tag: str

    def __post_init__(self) -> None:
        if type(self.effect_id) is not str or _EFFECT_ID.fullmatch(self.effect_id) is None:
            raise ValueError("durable recovery token effect is invalid")
        if (
            type(self.request_sha256) is not str
            or _SHA256.fullmatch(self.request_sha256) is None
            or type(self.continuation_identity) is not str
            or _SHA256.fullmatch(self.continuation_identity) is None
            or type(self.authentication_tag) is not str
            or _SHA256.fullmatch(self.authentication_tag) is None
        ):
            raise ValueError("durable recovery token identity is invalid")

    @property
    def unsigned_canonical_value(self) -> dict[str, object]:
        return {
            "schema_version": _RECOVERY_PROTOCOL_VERSION,
            "effect_id": self.effect_id,
            "request_sha256": self.request_sha256,
            "continuation_identity": self.continuation_identity,
        }

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            **self.unsigned_canonical_value,
            "authentication_tag": self.authentication_tag,
        }


@dataclass(frozen=True)
class DurableRecoveryDirective:
    """Typed private recovery result that D1b will translate into an outcome."""

    request_sha256: str
    recovery_owner: str
    continuation_identity: str
    disposition: str
    reason_code: str
    observed_evidence_sha256: str
    allowed_recovery_action: str | None
    token: RecoveryToken

    def __post_init__(self) -> None:
        if (
            type(self.request_sha256) is not str
            or _SHA256.fullmatch(self.request_sha256) is None
            or self.recovery_owner != _RECOVERY_OWNER
            or type(self.continuation_identity) is not str
            or _SHA256.fullmatch(self.continuation_identity) is None
            or self.disposition not in {"recoverable", "blocked_recovery"}
            or type(self.reason_code) is not str
            or _RECOVERY_REASON.fullmatch(self.reason_code) is None
            or type(self.observed_evidence_sha256) is not str
            or _SHA256.fullmatch(self.observed_evidence_sha256) is None
            or type(self.token) is not RecoveryToken
            or self.token.request_sha256 != self.request_sha256
            or self.token.continuation_identity != self.continuation_identity
        ):
            raise ValueError("durable recovery directive is invalid")
        if self.disposition == "recoverable":
            if self.allowed_recovery_action != "recover":
                raise ValueError("durable recovery directive action is invalid")
        elif self.allowed_recovery_action is not None:
            raise ValueError("blocked recovery directive action is invalid")

    @property
    def canonical_value(self) -> dict[str, object]:
        value: dict[str, object] = {
            "request_sha256": self.request_sha256,
            "recovery_owner": self.recovery_owner,
            "continuation_identity": self.continuation_identity,
            "disposition": self.disposition,
            "reason_code": self.reason_code,
            "observed_evidence_sha256": self.observed_evidence_sha256,
            "recovery_token": self.token.canonical_value,
        }
        if self.allowed_recovery_action is not None:
            value["allowed_recovery_action"] = self.allowed_recovery_action
        return value


class DurableRecoveryRequired(AuthorityRuntimeError):
    """A possible effect needs typed recovery or durable blocking."""

    def __init__(
        self,
        message: str,
        *,
        directive: DurableRecoveryDirective | None = None,
    ) -> None:
        super().__init__(message)
        if directive is not None and type(directive) is not DurableRecoveryDirective:
            raise TypeError("durable recovery directive is invalid")
        self.directive = directive


class DurableRecoveryDenied(AuthorityRuntimeError):
    """Reject an unauthenticated recovery selector without disclosing row evidence."""

    def __init__(self, message: str, *, reason_code: str) -> None:
        if type(reason_code) is not str or _RECOVERY_REASON.fullmatch(reason_code) is None:
            raise ValueError("durable recovery denial reason is invalid")
        super().__init__(message)
        self.reason_code = reason_code


class DurableRecoveryFenceRequired(AuthorityRuntimeError):
    """A root-local durable fence prevents every further automatic effect."""

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
            raise ValueError("durable recovery fence is invalid")
        super().__init__(message)
        self.reason_code = reason_code
        self.observed_evidence_sha256 = observed_evidence_sha256


@dataclass(frozen=True)
class _RootRecoveryFence:
    reason_code: str
    observed_evidence_sha256: str
    initiating_token: RecoveryToken | None


class _RecoveryTokenKeyUnavailable(Exception):
    """Private signal used to publish a typed root-wide recovery fence."""


class _TargetClaimConflict(AuthorityRuntimeError):
    """A different durable effect already owns the requested final target."""


class DurableEffectState(str, Enum):
    PREPARED = "PREPARED"
    PUBLISHED = "PUBLISHED"
    FINALIZED = "FINALIZED"
    ABORTED = "ABORTED"
    BLOCKED_RECOVERY = "BLOCKED_RECOVERY"


@dataclass(frozen=True)
class StagedEffect:
    """A sealed byte payload that a WriteSession may publish exactly once."""

    effect_id: str
    target_relative_path: str
    artifact_ref: artifact_contract.SealedArtifactRef
    artifact_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.effect_id) is not str or _EFFECT_ID.fullmatch(self.effect_id) is None:
            raise ValueError("durable effect identifier is invalid")
        if (
            type(self.target_relative_path) is not str
            or not self.target_relative_path
            or self.target_relative_path.startswith("/")
        ):
            raise ValueError("durable effect target is invalid")
        components = tuple(self.target_relative_path.split("/"))
        if not components or any(
            _PATH_COMPONENT.fullmatch(component) is None for component in components
        ):
            raise ValueError("durable effect target is invalid")
        if type(self.artifact_ref) is not artifact_contract.SealedArtifactRef:
            raise TypeError("durable effect reference is invalid")
        if self.target_relative_path != self.artifact_ref.canonical_path:
            raise ValueError("durable effect target does not match sealed artifact path")
        if type(self.artifact_bytes) is not bytes:
            raise TypeError("durable effect bytes are invalid")
        if len(self.artifact_bytes) > _MAX_ARTIFACT_BYTES:
            raise ValueError("durable effect bytes exceed maximum size")
        self.artifact_ref.verify_bytes(self.artifact_bytes)


@dataclass(frozen=True)
class _DurableBinding:
    """Immutable predecessor identity persisted before a durable row exists."""

    effect_id: str
    target_relative_path: str
    artifact_ref_sha256: str
    request_sha256: str
    scope_sha256: str
    bounds_sha256: str
    spec_identity: str
    spec_sha256: str
    policy_identity_sha256: str
    token: RecoveryToken
    binding_sha256: str


@dataclass(frozen=True)
class _TargetClaim:
    """Immutable target-to-effect claim published before the durable row."""

    effect_id: str
    target_relative_path: str
    binding_sha256: str


class _DurableDatabaseBridgeBusy(AuthorityRuntimeError):
    """A healthy bridge owns this root; this is availability, not recovery."""


class _DurableDatabaseBridgeForkUnavailable(AuthorityRuntimeError):
    """A fork child cannot safely use an inherited durable bridge."""


class _DatabaseBridgeLifetimeLock:
    """One root-local liveness lock for exactly one external SQLite alias."""

    __slots__ = ("__fd", "__root_identity", "__owner_pid", "__closed")

    def __init__(self, fd: int, root_identity: tuple[int, int]) -> None:
        self.__fd = fd
        self.__root_identity = root_identity
        self.__owner_pid = os.getpid()
        self.__closed = False

    @classmethod
    def acquire(
        cls,
        directory: _AnchoredPath,
    ) -> "_DatabaseBridgeLifetimeLock | None":
        if _durable_snapshot._fork_lock_state_poisoned():
            if _durable_snapshot._fork_child_lock_state_poisoned():
                raise _DurableDatabaseBridgeForkUnavailable(
                    "durable database bridge is unavailable after fork"
                )
            raise AuthorityRuntimeError("durable fork lock state is unavailable")
        root_identity = directory.anchor.identity
        if root_identity in _ACTIVE_DATABASE_BRIDGE_ROOTS:
            return None
        parent_fd = directory.anchor._open_directory(directory.parts, create=True)
        fd: int | None = None
        acquired = False
        try:
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            def verify_lock(candidate_fd: int) -> None:
                info = os.fstat(candidate_fd)
                lexical = os.stat(
                    _DATABASE_BRIDGE_LIFETIME_LOCK_NAME,
                    dir_fd=parent_fd,
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
                    raise AuthorityRuntimeError(
                        "durable database bridge lock is invalid"
                    )
                os.fsync(parent_fd)

            fd = _acquire_fork_safe_lock(
                directory_fd=parent_fd,
                name=_DATABASE_BRIDGE_LIFETIME_LOCK_NAME,
                flags=flags,
                label="durable database bridge lock",
                wait=False,
                verify=verify_lock,
            )
            if fd is None:
                return None
            acquired = True
            _ACTIVE_DATABASE_BRIDGE_ROOTS.add(root_identity)
            return cls(fd, root_identity)
        except AuthorityRuntimeError:
            raise
        except OSError as exc:
            raise AuthorityRuntimeError(
                "durable database bridge lock is unavailable"
            ) from exc
        finally:
            if fd is not None and not acquired:
                _close_descriptor(fd, label="durable database bridge lock")
            _close_descriptor(parent_fd, label="durable root directory")

    def close(self) -> None:
        if self.__closed:
            return
        if os.getpid() != self.__owner_pid:
            raise AuthorityRuntimeError("durable database bridge inherited across fork")
        _release_tracked_lock(
            self.__fd,
            label="durable database bridge lock",
        )
        self.__closed = True
        _ACTIVE_DATABASE_BRIDGE_ROOTS.discard(self.__root_identity)


class _DurableDatabaseBridge:
    """Temporary SQLite alias guarded by a root-anchored crash lease."""

    __slots__ = (
        "__directory",
        "__path",
        "__parent_fd",
        "__bridge_fd",
        "__runtime_directory",
        "__lease",
        "__lifetime_lock",
        "__owner_pid",
        "__closed",
    )

    def __init__(
        self,
        directory: Path,
        path: Path,
        parent_fd: int,
        bridge_fd: int,
        runtime_directory: _AnchoredPath,
        lease: "_DatabaseBridgeLease",
        lifetime_lock: _DatabaseBridgeLifetimeLock,
    ) -> None:
        self.__directory = directory
        self.__path = path
        self.__parent_fd: int | None = parent_fd
        self.__bridge_fd: int | None = bridge_fd
        self.__runtime_directory = runtime_directory
        self.__lease = lease
        self.__lifetime_lock = lifetime_lock
        self.__owner_pid = os.getpid()
        self.__closed = False

    @property
    def path(self) -> Path:
        return self.__path

    def verify_sqlite_path(self) -> None:
        """Prove the lexical SQLite path still names the retained alias."""

        self._require_owner()
        parent_fd, bridge_fd = self.__parent_fd, self.__bridge_fd
        if parent_fd is None or bridge_fd is None:
            raise AuthorityRuntimeError("durable database bridge is unavailable")
        bridge_info = os.fstat(bridge_fd)
        bridge_entry = os.stat(
            self.__directory.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        database_entry = os.stat(
            _DATABASE_NAME,
            dir_fd=bridge_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(bridge_info.st_mode)
            or bridge_info.st_uid != os.getuid()
            or stat.S_IMODE(bridge_info.st_mode) != 0o700
            or (bridge_info.st_dev, bridge_info.st_ino)
            != (self.__lease.bridge_device, self.__lease.bridge_inode)
            or (bridge_entry.st_dev, bridge_entry.st_ino)
            != (bridge_info.st_dev, bridge_info.st_ino)
            or not stat.S_ISREG(database_entry.st_mode)
            or database_entry.st_uid != os.getuid()
            or stat.S_IMODE(database_entry.st_mode) != 0o600
            or (database_entry.st_dev, database_entry.st_ino)
            != (self.__lease.database_device, self.__lease.database_inode)
        ):
            raise AuthorityRuntimeError("durable database bridge identity is invalid")

    def verify_canonical_database_identity(self) -> None:
        """Prove the anchored runtime entry still names this bridge's database.

        The external alias is only a connection bridge.  Removing its crash
        lease is safe only while the canonical authority-runtime entry still
        points at the inode captured in that lease.  A replacement must leave
        the lease behind so the next opener fences instead of accepting a
        disconnected database history.
        """

        self._require_owner()
        directory_fd: int | None = None
        database_fd: int | None = None
        try:
            directory_fd = self.__runtime_directory.anchor._open_directory(
                self.__runtime_directory.parts,
                create=False,
            )
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            database_fd = os.open(
                _DATABASE_NAME,
                flags,
                dir_fd=directory_fd,
            )
            database_info = os.fstat(database_fd)
            database_entry = os.stat(
                _DATABASE_NAME,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(database_info.st_mode)
                or database_info.st_uid != os.getuid()
                or stat.S_IMODE(database_info.st_mode) != 0o600
                or (database_info.st_dev, database_info.st_ino)
                != (self.__lease.database_device, self.__lease.database_inode)
                or (database_entry.st_dev, database_entry.st_ino)
                != (database_info.st_dev, database_info.st_ino)
            ):
                raise AuthorityRuntimeError("durable database identity is invalid")
        except FileNotFoundError as exc:
            raise AuthorityRuntimeError("durable database identity is invalid") from exc
        except OSError as exc:
            raise AuthorityRuntimeError("durable database identity is invalid") from exc
        finally:
            if database_fd is not None:
                _close_descriptor(database_fd, label="durable database")
            if directory_fd is not None:
                _close_descriptor(directory_fd, label="durable root directory")

    def _require_owner(self) -> None:
        if os.getpid() != self.__owner_pid:
            raise AuthorityRuntimeError("durable database bridge inherited across fork")

    def abandon(self) -> None:
        """Leave the anchored lease behind while making it detectable as stale."""

        if self.__closed:
            return
        self.__closed = True
        if os.getpid() != self.__owner_pid:
            # The at-fork hook has already closed inherited liveness locks.  A
            # fork child must never delete the parent bridge lease or alias.
            return
        cleanup_error: BaseException | None = None
        try:
            self._close_external_descriptors()
        except BaseException as exc:
            cleanup_error = exc
        try:
            self.__lifetime_lock.close()
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None:
            if isinstance(cleanup_error, AuthorityRuntimeError):
                raise cleanup_error
            raise AuthorityRuntimeError(
                "durable database bridge cleanup failed"
            ) from cleanup_error

    def _close_external_descriptors(self) -> None:
        parent_fd, bridge_fd = self.__parent_fd, self.__bridge_fd
        self.__parent_fd = None
        self.__bridge_fd = None
        _close_external_database_bridge_descriptors(
            parent_fd,
            bridge_fd,
        )

    def close(self, *, mutation_gate_held: bool = False) -> None:
        if self.__closed:
            return
        self.__closed = True
        cleanup_error: BaseException | None = None
        try:
            self._require_owner()
            parent_fd, bridge_fd = self.__parent_fd, self.__bridge_fd
            if parent_fd is None or bridge_fd is None:
                raise AuthorityRuntimeError("durable database bridge is unavailable")

            def cleanup_and_release() -> None:
                release_error: BaseException | None = None
                try:
                    self.verify_canonical_database_identity()
                    _cleanup_external_database_bridge(
                        parent_fd=parent_fd,
                        bridge_fd=bridge_fd,
                        directory_name=self.__directory.name,
                        database_identity=(
                            self.__lease.database_device,
                            self.__lease.database_inode,
                        ),
                        bridge_identity=(
                            self.__lease.bridge_device,
                            self.__lease.bridge_inode,
                        ),
                    )
                    _remove_database_bridge_lease(
                        self.__runtime_directory,
                        self.__lease,
                    )
                except BaseException as exc:
                    release_error = exc
                try:
                    self.__lifetime_lock.close()
                except BaseException as exc:
                    if release_error is None:
                        release_error = exc
                if release_error is not None:
                    raise release_error

            if mutation_gate_held:
                cleanup_and_release()
            else:
                with self.__runtime_directory.anchor.mutation_gate():
                    cleanup_and_release()
        except BaseException as exc:
            cleanup_error = exc
        try:
            self._close_external_descriptors()
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None:
            if isinstance(cleanup_error, AuthorityRuntimeError):
                raise cleanup_error
            raise AuthorityRuntimeError(
                "durable database bridge cleanup failed"
            ) from cleanup_error


def _discard_durable_database(
    connection: sqlite3.Connection | None,
    bridge: _DurableDatabaseBridge | None,
    *,
    mutation_gate_held: bool = False,
) -> None:
    """Best-effort failed-open cleanup that never clears an unproven crash lease."""

    connection_closed = connection is None
    if connection is not None:
        try:
            connection.close()
            connection_closed = True
        except BaseException:
            # The lease must survive a failed SQLite close: its journal state is
            # no longer proven safe to reopen.
            connection_closed = False
    if bridge is not None:
        if connection_closed:
            try:
                bridge.close(mutation_gate_held=mutation_gate_held)
            except AuthorityRuntimeError:
                pass
        else:
            bridge.abandon()


@dataclass(frozen=True)
class _BlockerReceipt:
    """First-writer-wins durable manual-blocker result for one binding."""

    effect_id: str
    binding_sha256: str
    directive: DurableRecoveryDirective


@dataclass(frozen=True)
class _DatabaseBridgeLease:
    """Root-local proof that a temporary SQLite alias was not cleanly closed."""

    lease_id: str
    raw: bytes
    database_device: int
    database_inode: int
    bridge_device: int
    bridge_inode: int


def _external_directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _close_external_database_bridge_descriptors(
    parent_fd: int | None,
    bridge_fd: int | None,
) -> None:
    close_error: AuthorityRuntimeError | None = None
    for descriptor, label in (
        (bridge_fd, "durable database bridge"),
        (parent_fd, "durable database bridge parent"),
    ):
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            if close_error is None:
                close_error = AuthorityRuntimeError(f"{label} is unavailable")
                close_error.__cause__ = exc
    if close_error is not None:
        raise close_error


def _cleanup_external_database_bridge(
    *,
    parent_fd: int,
    bridge_fd: int,
    directory_name: str,
    database_identity: tuple[int, int] | None,
    bridge_identity: tuple[int, int],
) -> None:
    """Delete exactly the verified external alias, never a replacement path."""

    database_fd: int | None = None
    cleanup_error: BaseException | None = None
    try:
        bridge_info = os.fstat(bridge_fd)
        bridge_entry = os.stat(
            directory_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(bridge_info.st_mode)
            or bridge_info.st_uid != os.getuid()
            or stat.S_IMODE(bridge_info.st_mode) != 0o700
            or (bridge_info.st_dev, bridge_info.st_ino) != bridge_identity
            or (bridge_entry.st_dev, bridge_entry.st_ino)
            != (bridge_info.st_dev, bridge_info.st_ino)
        ):
            raise AuthorityRuntimeError("durable database bridge identity is invalid")
        if database_identity is not None:
            database_flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                database_flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                database_flags |= os.O_NOFOLLOW
            database_fd = os.open(
                _DATABASE_NAME,
                database_flags,
                dir_fd=bridge_fd,
            )
            database_info = os.fstat(database_fd)
            database_entry = os.stat(
                _DATABASE_NAME,
                dir_fd=bridge_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(database_info.st_mode)
                or database_info.st_uid != os.getuid()
                or stat.S_IMODE(database_info.st_mode) != 0o600
                or (database_info.st_dev, database_info.st_ino) != database_identity
                or (database_entry.st_dev, database_entry.st_ino)
                != (database_info.st_dev, database_info.st_ino)
            ):
                raise AuthorityRuntimeError(
                    "durable database bridge target identity is invalid"
                )
            os.unlink(_DATABASE_NAME, dir_fd=bridge_fd)
            os.fsync(bridge_fd)
        # Re-check the parent entry immediately before rmdir.  A rename/swap
        # must leave the root lease behind rather than deleting a replacement.
        bridge_entry = os.stat(
            directory_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        current_bridge = os.fstat(bridge_fd)
        if (
            (current_bridge.st_dev, current_bridge.st_ino) != bridge_identity
            or (bridge_entry.st_dev, bridge_entry.st_ino)
            != (current_bridge.st_dev, current_bridge.st_ino)
        ):
            raise AuthorityRuntimeError("durable database bridge identity is invalid")
        os.rmdir(directory_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except BaseException as exc:
        cleanup_error = exc
    for descriptor, label in (
        (database_fd, "durable database bridge target"),
    ):
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            if cleanup_error is None:
                cleanup_error = AuthorityRuntimeError(f"{label} is unavailable")
                cleanup_error.__cause__ = exc
    if cleanup_error is not None:
        if isinstance(cleanup_error, AuthorityRuntimeError):
            raise cleanup_error
        raise AuthorityRuntimeError("durable database bridge cleanup failed") from cleanup_error


def _runtime_directory(root: Path) -> Path:
    return root / "_registry" / "curation" / "authority-runtime"


def _binding_path(root: Path, effect_id: str) -> Path:
    return _runtime_directory(root) / _RECOVERY_BINDING_DIRECTORY / f"{effect_id}.json"


def _target_claim_path(root: Path, target_relative_path: str) -> Path:
    target_sha256 = sha256_bytes(target_relative_path.encode("utf-8"))
    return (
        _runtime_directory(root)
        / _RECOVERY_TARGET_CLAIM_DIRECTORY
        / f"{target_sha256}.json"
    )


def _blocker_path(root: Path, effect_id: str) -> Path:
    return _runtime_directory(root) / _RECOVERY_BLOCKER_DIRECTORY / f"{effect_id}.json"


def _key_attestation_path(root: Path) -> Path:
    return _runtime_directory(root) / _RECOVERY_TOKEN_KEY_ATTESTATION_NAME


def _database_bridge_lease_directory(directory: _AnchoredPath) -> _AnchoredPath:
    return directory / _DATABASE_BRIDGE_LEASE_DIRECTORY


def _database_bridge_lease_path(
    directory: _AnchoredPath,
    lease_id: str,
) -> _AnchoredPath:
    if _DATABASE_BRIDGE_LEASE_ID.fullmatch(lease_id) is None:
        raise ValueError("durable database bridge lease identifier is invalid")
    return _database_bridge_lease_directory(directory) / f"{lease_id}.json"


def _canonical_mapping(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise ValueError(f"{label} is invalid")
    return value


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _database_bridge_lease_from_raw(
    raw: bytes,
    *,
    expected_lease_id: str | None = None,
) -> _DatabaseBridgeLease:
    payload = _canonical_mapping(raw, label="durable database bridge lease")
    fields = {
        "schema_version",
        "kind",
        "recovery_owner",
        "lease_id",
        "database_device",
        "database_inode",
        "bridge_device",
        "bridge_inode",
    }
    if set(payload) != fields:
        raise ValueError("durable database bridge lease fields are invalid")
    identities = (
        payload["database_device"],
        payload["database_inode"],
        payload["bridge_device"],
        payload["bridge_inode"],
    )
    if (
        payload["schema_version"] != _RECOVERY_PROTOCOL_VERSION
        or payload["kind"] != _DATABASE_BRIDGE_LEASE_KIND
        or payload["recovery_owner"] != _RECOVERY_OWNER
        or type(payload["lease_id"]) is not str
        or _DATABASE_BRIDGE_LEASE_ID.fullmatch(payload["lease_id"]) is None
        or expected_lease_id is not None
        and payload["lease_id"] != expected_lease_id
        or any(type(value) is not int or value < 0 for value in identities)
    ):
        raise ValueError("durable database bridge lease identity is invalid")
    return _DatabaseBridgeLease(
        lease_id=payload["lease_id"],
        raw=raw,
        database_device=payload["database_device"],
        database_inode=payload["database_inode"],
        bridge_device=payload["bridge_device"],
        bridge_inode=payload["bridge_inode"],
    )


def _read_database_bridge_leases(
    directory: _AnchoredPath,
) -> tuple[_DatabaseBridgeLease, ...]:
    leases: list[_DatabaseBridgeLease] = []
    for name in directory.anchor.list_directory(
        _database_bridge_lease_directory(directory)
    ):
        if not name.endswith(".json"):
            raise ValueError("durable database bridge lease entry is invalid")
        lease_id = name.removesuffix(".json")
        if _DATABASE_BRIDGE_LEASE_ID.fullmatch(lease_id) is None:
            raise ValueError("durable database bridge lease entry is invalid")
        raw = _try_read_verified_bytes(
            _database_bridge_lease_path(directory, lease_id)
        )
        if raw is None:
            raise AuthorityRuntimeError("durable database bridge lease is unavailable")
        leases.append(
            _database_bridge_lease_from_raw(
                raw,
                expected_lease_id=lease_id,
            )
        )
    return tuple(leases)


def _abandoned_database_bridge_lease(
    directory: _AnchoredPath,
) -> _DatabaseBridgeLease | None:
    # The caller owns the root-local lifetime lock.  Any lease observed while
    # that lock is held has no live owner and is therefore crash evidence.
    leases = _read_database_bridge_leases(directory)
    return leases[0] if leases else None


def _record_database_bridge_lease(
    directory: _AnchoredPath,
    database_info: os.stat_result,
    bridge_info: os.stat_result,
) -> _DatabaseBridgeLease:
    lease_id = secrets.token_hex(16)
    payload = {
        "schema_version": _RECOVERY_PROTOCOL_VERSION,
        "kind": _DATABASE_BRIDGE_LEASE_KIND,
        "recovery_owner": _RECOVERY_OWNER,
        "lease_id": lease_id,
        "database_device": database_info.st_dev,
        "database_inode": database_info.st_ino,
        "bridge_device": bridge_info.st_dev,
        "bridge_inode": bridge_info.st_ino,
    }
    raw = canonical_json_bytes(payload)
    lease = _database_bridge_lease_from_raw(raw, expected_lease_id=lease_id)
    _publish_exact_bytes(
        _database_bridge_lease_path(directory, lease_id),
        raw,
        label="durable database bridge lease",
    )
    return lease


def _remove_database_bridge_lease(
    directory: _AnchoredPath,
    lease: _DatabaseBridgeLease,
) -> None:
    directory.anchor.remove_exact_bytes(
        _database_bridge_lease_path(directory, lease.lease_id),
        lease.raw,
        label="durable database bridge lease",
    )


def _database_bridge_lease_evidence(lease: _DatabaseBridgeLease) -> str:
    return sha256_bytes(lease.raw)


def _continuation_identity(
    *,
    effect_id: str,
    target_relative_path: str,
    artifact_ref_sha256: str,
    request_sha256: str,
    scope_sha256: str,
    bounds_sha256: str,
    spec_identity: str,
    spec_sha256: str,
    policy_identity_sha256: str,
) -> str:
    """Bind a recovery token to every immutable predecessor identity field."""

    return sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": _RECOVERY_PROTOCOL_VERSION,
                "effect_id": effect_id,
                "target_relative_path": target_relative_path,
                "artifact_ref_sha256": artifact_ref_sha256,
                "request_sha256": request_sha256,
                "scope_sha256": scope_sha256,
                "bounds_sha256": bounds_sha256,
                "spec_identity": spec_identity,
                "spec_sha256": spec_sha256,
                "policy_identity_sha256": policy_identity_sha256,
            }
        )
    )


def _binding_payload(binding: _DurableBinding) -> dict[str, object]:
    return {
        "schema_version": _RECOVERY_PROTOCOL_VERSION,
        "kind": _RECOVERY_BINDING_KIND,
        "recovery_owner": _RECOVERY_OWNER,
        "effect_id": binding.effect_id,
        "target_relative_path": binding.target_relative_path,
        "artifact_ref_sha256": binding.artifact_ref_sha256,
        "request_sha256": binding.request_sha256,
        "scope_sha256": binding.scope_sha256,
        "bounds_sha256": binding.bounds_sha256,
        "spec_identity": binding.spec_identity,
        "spec_sha256": binding.spec_sha256,
        "policy_identity_sha256": binding.policy_identity_sha256,
        "recovery_token": binding.token.canonical_value,
    }


def _binding_from_raw(
    raw: bytes,
    *,
    expected_effect_id: str | None = None,
) -> _DurableBinding:
    payload = _canonical_mapping(raw, label="durable effect binding")
    required_fields = {
        "schema_version",
        "kind",
        "recovery_owner",
        "effect_id",
        "target_relative_path",
        "artifact_ref_sha256",
        "request_sha256",
        "scope_sha256",
        "bounds_sha256",
        "spec_identity",
        "spec_sha256",
        "policy_identity_sha256",
        "recovery_token",
    }
    if set(payload) != required_fields:
        raise ValueError("durable effect binding fields are invalid")
    try:
        token_value = payload["recovery_token"]
        if type(token_value) is not dict:
            raise ValueError("durable effect binding token is invalid")
        token = RecoveryToken(
            effect_id=token_value["effect_id"],
            request_sha256=token_value["request_sha256"],
            continuation_identity=token_value["continuation_identity"],
            authentication_tag=token_value["authentication_tag"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("durable effect binding token is invalid") from exc
    if (
        token.canonical_value != token_value
        or payload["schema_version"] != _RECOVERY_PROTOCOL_VERSION
        or payload["kind"] != _RECOVERY_BINDING_KIND
        or payload["recovery_owner"] != _RECOVERY_OWNER
        or type(payload["effect_id"]) is not str
        or _EFFECT_ID.fullmatch(payload["effect_id"]) is None
        or expected_effect_id is not None
        and payload["effect_id"] != expected_effect_id
        or type(payload["target_relative_path"]) is not str
        or not payload["target_relative_path"]
        or type(payload["spec_identity"]) is not str
        or not payload["spec_identity"]
        or not all(
            _valid_sha256(payload[field])
            for field in (
                "artifact_ref_sha256",
                "request_sha256",
                "scope_sha256",
                "bounds_sha256",
                "spec_sha256",
                "policy_identity_sha256",
            )
        )
        or token.effect_id != payload["effect_id"]
        or token.request_sha256 != payload["request_sha256"]
    ):
        raise ValueError("durable effect binding identity is invalid")
    if token.continuation_identity != _continuation_identity(
        effect_id=payload["effect_id"],
        target_relative_path=payload["target_relative_path"],
        artifact_ref_sha256=payload["artifact_ref_sha256"],
        request_sha256=payload["request_sha256"],
        scope_sha256=payload["scope_sha256"],
        bounds_sha256=payload["bounds_sha256"],
        spec_identity=payload["spec_identity"],
        spec_sha256=payload["spec_sha256"],
        policy_identity_sha256=payload["policy_identity_sha256"],
    ):
        raise ValueError("durable effect binding continuation is invalid")
    return _DurableBinding(
        effect_id=payload["effect_id"],
        target_relative_path=payload["target_relative_path"],
        artifact_ref_sha256=payload["artifact_ref_sha256"],
        request_sha256=payload["request_sha256"],
        scope_sha256=payload["scope_sha256"],
        bounds_sha256=payload["bounds_sha256"],
        spec_identity=payload["spec_identity"],
        spec_sha256=payload["spec_sha256"],
        policy_identity_sha256=payload["policy_identity_sha256"],
        token=token,
        binding_sha256=sha256_bytes(raw),
    )


def _read_binding(root: Path, effect_id: str) -> _DurableBinding | None:
    raw = _try_read_verified_bytes(_binding_path(root, effect_id))
    if raw is None:
        return None
    return _binding_from_raw(raw, expected_effect_id=effect_id)


def _record_binding(root: Path, binding: _DurableBinding) -> _DurableBinding:
    existing = _read_binding(root, binding.effect_id)
    if existing is not None:
        return existing
    raw = canonical_json_bytes(_binding_payload(binding))
    if sha256_bytes(raw) != binding.binding_sha256:
        raise ValueError("durable effect binding identity is invalid")
    try:
        _publish_exact_bytes(
            _binding_path(root, binding.effect_id),
            raw,
            label="durable effect binding",
        )
    except AuthorityRuntimeError:
        existing = _read_binding(root, binding.effect_id)
        if existing is None:
            raise
        return existing
    return binding


def _target_claim_from_raw(raw: bytes) -> _TargetClaim:
    payload = _canonical_mapping(raw, label="durable target claim")
    if set(payload) != {
        "schema_version",
        "kind",
        "recovery_owner",
        "effect_id",
        "target_relative_path",
        "binding_sha256",
    }:
        raise ValueError("durable target claim fields are invalid")
    if (
        payload["schema_version"] != _RECOVERY_PROTOCOL_VERSION
        or payload["kind"] != _RECOVERY_TARGET_CLAIM_KIND
        or payload["recovery_owner"] != _RECOVERY_OWNER
        or type(payload["effect_id"]) is not str
        or _EFFECT_ID.fullmatch(payload["effect_id"]) is None
        or type(payload["target_relative_path"]) is not str
        or not payload["target_relative_path"]
        or not _valid_sha256(payload["binding_sha256"])
    ):
        raise ValueError("durable target claim identity is invalid")
    return _TargetClaim(
        effect_id=payload["effect_id"],
        target_relative_path=payload["target_relative_path"],
        binding_sha256=payload["binding_sha256"],
    )


def _read_target_claim(root: Path, target_relative_path: str) -> _TargetClaim | None:
    raw = _try_read_verified_bytes(_target_claim_path(root, target_relative_path))
    if raw is None:
        return None
    return _target_claim_from_raw(raw)


def _record_target_claim(root: Path, binding: _DurableBinding) -> _TargetClaim:
    existing = _read_target_claim(root, binding.target_relative_path)
    expected = _TargetClaim(
        effect_id=binding.effect_id,
        target_relative_path=binding.target_relative_path,
        binding_sha256=binding.binding_sha256,
    )
    if existing is not None:
        if existing != expected:
            raise _TargetClaimConflict("durable effect target is already claimed")
        return existing
    raw = canonical_json_bytes(
        {
            "schema_version": _RECOVERY_PROTOCOL_VERSION,
            "kind": _RECOVERY_TARGET_CLAIM_KIND,
            "recovery_owner": _RECOVERY_OWNER,
            "effect_id": expected.effect_id,
            "target_relative_path": expected.target_relative_path,
            "binding_sha256": expected.binding_sha256,
        }
    )
    try:
        _publish_exact_bytes(
            _target_claim_path(root, binding.target_relative_path),
            raw,
            label="durable target claim",
        )
    except AuthorityRuntimeError:
        existing = _read_target_claim(root, binding.target_relative_path)
        if existing is None:
            raise
        if existing != expected:
            raise _TargetClaimConflict("durable effect target is already claimed")
        return existing
    return expected


def _directive_from_canonical_value(value: object) -> DurableRecoveryDirective:
    if type(value) is not dict:
        raise ValueError("durable blocker directive is invalid")
    try:
        token_value = value["recovery_token"]
        if type(token_value) is not dict:
            raise ValueError("durable blocker token is invalid")
        token = RecoveryToken(
            effect_id=token_value["effect_id"],
            request_sha256=token_value["request_sha256"],
            continuation_identity=token_value["continuation_identity"],
            authentication_tag=token_value["authentication_tag"],
        )
        directive = DurableRecoveryDirective(
            request_sha256=value["request_sha256"],
            recovery_owner=value["recovery_owner"],
            continuation_identity=value["continuation_identity"],
            disposition=value["disposition"],
            reason_code=value["reason_code"],
            observed_evidence_sha256=value["observed_evidence_sha256"],
            allowed_recovery_action=value.get("allowed_recovery_action"),
            token=token,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("durable blocker directive is invalid") from exc
    if directive.canonical_value != value:
        raise ValueError("durable blocker directive is invalid")
    return directive


def _read_blocker(root: Path, effect_id: str) -> _BlockerReceipt | None:
    raw = _try_read_verified_bytes(_blocker_path(root, effect_id))
    if raw is None:
        return None
    payload = _canonical_mapping(raw, label="durable recovery blocker")
    if set(payload) != {
        "schema_version",
        "kind",
        "recovery_owner",
        "effect_id",
        "binding_sha256",
        "directive",
    }:
        raise ValueError("durable recovery blocker fields are invalid")
    directive = _directive_from_canonical_value(payload["directive"])
    if (
        payload["schema_version"] != _RECOVERY_PROTOCOL_VERSION
        or payload["kind"] != _RECOVERY_BLOCKER_KIND
        or payload["recovery_owner"] != _RECOVERY_OWNER
        or payload["effect_id"] != effect_id
        or not _valid_sha256(payload["binding_sha256"])
        or directive.disposition != "blocked_recovery"
        or directive.token.effect_id != effect_id
    ):
        raise ValueError("durable recovery blocker identity is invalid")
    return _BlockerReceipt(
        effect_id=effect_id,
        binding_sha256=payload["binding_sha256"],
        directive=directive,
    )


def _record_blocker(
    root: Path,
    binding: _DurableBinding,
    directive: DurableRecoveryDirective,
) -> DurableRecoveryDirective:
    existing = _read_blocker(root, binding.effect_id)
    if existing is not None:
        if existing.binding_sha256 != binding.binding_sha256:
            raise AuthorityRuntimeError("durable recovery blocker identity is invalid")
        return existing.directive
    raw = canonical_json_bytes(
        {
            "schema_version": _RECOVERY_PROTOCOL_VERSION,
            "kind": _RECOVERY_BLOCKER_KIND,
            "recovery_owner": _RECOVERY_OWNER,
            "effect_id": binding.effect_id,
            "binding_sha256": binding.binding_sha256,
            "directive": directive.canonical_value,
        }
    )
    try:
        _publish_exact_bytes(
            _blocker_path(root, binding.effect_id),
            raw,
            label="durable recovery blocker",
        )
    except AuthorityRuntimeError:
        existing = _read_blocker(root, binding.effect_id)
        if existing is None:
            raise
        if existing.binding_sha256 != binding.binding_sha256:
            raise AuthorityRuntimeError("durable recovery blocker identity is invalid")
        return existing.directive
    return directive


def _read_key_attestation(directory: Path) -> str | None:
    raw = _try_read_verified_bytes(
        directory / _RECOVERY_TOKEN_KEY_ATTESTATION_NAME
    )
    if raw is None:
        return None
    payload = _canonical_mapping(raw, label="durable recovery token key attestation")
    if set(payload) != {
        "schema_version",
        "kind",
        "recovery_owner",
        "key_sha256",
    }:
        raise ValueError("durable recovery token key attestation fields are invalid")
    if (
        payload["schema_version"] != _RECOVERY_PROTOCOL_VERSION
        or payload["kind"] != _RECOVERY_TOKEN_KEY_ATTESTATION_KIND
        or payload["recovery_owner"] != _RECOVERY_OWNER
        or not _valid_sha256(payload["key_sha256"])
    ):
        raise ValueError("durable recovery token key attestation is invalid")
    return payload["key_sha256"]


def _record_key_attestation(directory: Path, key: bytes) -> str:
    key_sha256 = sha256_bytes(key)
    existing = _read_key_attestation(directory)
    if existing is not None:
        return existing
    raw = canonical_json_bytes(
        {
            "schema_version": _RECOVERY_PROTOCOL_VERSION,
            "kind": _RECOVERY_TOKEN_KEY_ATTESTATION_KIND,
            "recovery_owner": _RECOVERY_OWNER,
            "key_sha256": key_sha256,
        }
    )
    try:
        _publish_exact_bytes(
            directory / _RECOVERY_TOKEN_KEY_ATTESTATION_NAME,
            raw,
            label="durable recovery token key attestation",
        )
    except AuthorityRuntimeError:
        existing = _read_key_attestation(directory)
        if existing is None:
            raise
        return existing
    return key_sha256


def _recovery_fence_path(root: Path) -> Path:
    return (
        root
        / "_registry"
        / "curation"
        / "authority-runtime"
        / _RECOVERY_FENCE_DIRECTORY
        / _RECOVERY_FENCE_NAME
    )


def _fence_observed_evidence(reason_code: str) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "schema_version": _RECOVERY_PROTOCOL_VERSION,
                "kind": _RECOVERY_FENCE_KIND,
                "reason_code": reason_code,
            }
        )
    )


def _fence_required(
    fence: _RootRecoveryFence,
    *,
    message: str = "durable recovery is fenced",
) -> DurableRecoveryFenceRequired:
    return DurableRecoveryFenceRequired(
        message,
        reason_code=fence.reason_code,
        observed_evidence_sha256=fence.observed_evidence_sha256,
    )


def _fence_unavailable_error(
    message: str = "durable recovery fence is unavailable",
) -> DurableRecoveryFenceRequired:
    reason_code = "RECOVERY_FENCE_UNAVAILABLE"
    return DurableRecoveryFenceRequired(
        message,
        reason_code=reason_code,
        observed_evidence_sha256=_fence_observed_evidence(reason_code),
    )


def _read_root_recovery_fence(root: Path) -> _RootRecoveryFence | None:
    try:
        raw = _try_read_verified_bytes(_recovery_fence_path(root))
    except AuthorityRuntimeError as exc:
        raise _fence_unavailable_error() from exc
    if raw is None:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
        if type(payload) is not dict or canonical_json_bytes(payload) != raw:
            raise ValueError("root recovery fence bytes are invalid")
        if set(payload) != {
            "schema_version",
            "kind",
            "recovery_owner",
            "reason_code",
            "observed_evidence_sha256",
            "initiating_token",
            "nonterminal_snapshot_sha256",
        }:
            raise ValueError("root recovery fence fields are invalid")
        if (
            payload["schema_version"] != _RECOVERY_PROTOCOL_VERSION
            or payload["kind"] != _RECOVERY_FENCE_KIND
            or payload["recovery_owner"] != _RECOVERY_OWNER
            or type(payload["reason_code"]) is not str
            or _RECOVERY_REASON.fullmatch(payload["reason_code"]) is None
            or type(payload["observed_evidence_sha256"]) is not str
            or _SHA256.fullmatch(payload["observed_evidence_sha256"]) is None
            or payload["nonterminal_snapshot_sha256"] is not None
            and (
                type(payload["nonterminal_snapshot_sha256"]) is not str
                or _SHA256.fullmatch(payload["nonterminal_snapshot_sha256"])
                is None
            )
        ):
            raise ValueError("root recovery fence identity is invalid")
        token_value = payload["initiating_token"]
        if token_value is None:
            token = None
        elif type(token_value) is dict:
            token = RecoveryToken(
                effect_id=token_value["effect_id"],
                request_sha256=token_value["request_sha256"],
                continuation_identity=token_value["continuation_identity"],
                authentication_tag=token_value["authentication_tag"],
            )
            if token.canonical_value != token_value:
                raise ValueError("root recovery fence token is invalid")
        else:
            raise ValueError("root recovery fence token is invalid")
        return _RootRecoveryFence(
            reason_code=payload["reason_code"],
            observed_evidence_sha256=payload["observed_evidence_sha256"],
            initiating_token=token,
        )
    except (KeyError, TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise _fence_unavailable_error("durable recovery fence is invalid") from exc


def _record_root_recovery_fence(
    root: Path,
    *,
    reason_code: str,
    observed_evidence_sha256: str,
    initiating_token: RecoveryToken | None,
    nonterminal_snapshot_sha256: str | None = None,
) -> _RootRecoveryFence:
    if (
        type(reason_code) is not str
        or _RECOVERY_REASON.fullmatch(reason_code) is None
        or type(observed_evidence_sha256) is not str
        or _SHA256.fullmatch(observed_evidence_sha256) is None
        or nonterminal_snapshot_sha256 is not None
        and (
            type(nonterminal_snapshot_sha256) is not str
            or _SHA256.fullmatch(nonterminal_snapshot_sha256) is None
        )
    ):
        raise ValueError("root recovery fence input is invalid")
    existing = _read_root_recovery_fence(root)
    if existing is not None:
        return existing
    payload = {
        "schema_version": _RECOVERY_PROTOCOL_VERSION,
        "kind": _RECOVERY_FENCE_KIND,
        "recovery_owner": _RECOVERY_OWNER,
        "reason_code": reason_code,
        "observed_evidence_sha256": observed_evidence_sha256,
        "initiating_token": (
            initiating_token.canonical_value if initiating_token is not None else None
        ),
        "nonterminal_snapshot_sha256": nonterminal_snapshot_sha256,
    }
    raw = canonical_json_bytes(payload)
    try:
        _publish_exact_bytes(
            _recovery_fence_path(root),
            raw,
            label="durable recovery fence",
        )
    except AuthorityRuntimeError as exc:
        existing = _read_root_recovery_fence(root)
        if existing is None:
            raise _fence_unavailable_error() from exc
        return existing
    return _RootRecoveryFence(
        reason_code=reason_code,
        observed_evidence_sha256=observed_evidence_sha256,
        initiating_token=initiating_token,
    )


def _nonterminal_snapshot_sha256(connection: sqlite3.Connection) -> str:
    try:
        rows = tuple(
            connection.execute(
                "SELECT effect_id, target_relative_path, artifact_ref, artifact_bytes, request_sha256, "
                "scope_sha256, spec_identity, spec_sha256, policy_identity_sha256, state "
                "FROM durable_effects WHERE state NOT IN (?, ?) ORDER BY effect_id",
                (
                    DurableEffectState.FINALIZED.value,
                    DurableEffectState.ABORTED.value,
                ),
            )
        )
        value = {
            "schema_version": _RECOVERY_PROTOCOL_VERSION,
            "kind": _RECOVERY_FENCE_KIND,
            "effects": [
                {
                    "effect_id_sha256": sha256_bytes(
                        str(row["effect_id"]).encode("utf-8")
                    ),
                    "immutable_identity_sha256": sha256_bytes(
                        canonical_json_bytes(
                            {
                                "target_relative_path_sha256": sha256_bytes(
                                    str(row["target_relative_path"]).encode("utf-8")
                                ),
                                "artifact_ref_sha256": sha256_bytes(
                                    bytes(row["artifact_ref"])
                                ),
                                "artifact_bytes_sha256": sha256_bytes(
                                    bytes(row["artifact_bytes"])
                                ),
                                "request_sha256": row["request_sha256"],
                                "scope_sha256": row["scope_sha256"],
                                "spec_identity": row["spec_identity"],
                                "spec_sha256": row["spec_sha256"],
                                "policy_identity_sha256": row[
                                    "policy_identity_sha256"
                                ],
                                "state": row["state"],
                            }
                        )
                    ),
                }
                for row in rows
            ],
        }
    except (sqlite3.Error, KeyError, TypeError, ValueError):
        value = {
            "schema_version": _RECOVERY_PROTOCOL_VERSION,
            "kind": _RECOVERY_FENCE_KIND,
            "effects": "unavailable",
        }
    return sha256_bytes(canonical_json_bytes(value))


class DurableCoordinator:
    """Owns PREPARED -> PUBLISHED -> FINALIZED transitions and restart recovery."""

    __slots__ = (
        "__snapshot_store",
        "__request_sha256",
        "__scope_sha256",
        "__bounds_sha256",
        "__spec_identity",
        "__spec_sha256",
        "__policy_identity_sha256",
        "__recovery_token_key",
        "__transition_guard",
        "__on_invalidate",
        "__action",
        "__mutation_depth",
        "__active",
        "__owner_pid",
    )

    def __init__(
        self,
        snapshot_store: _durable_snapshot._DurableSnapshotStore,
        request_sha256: str,
        scope_sha256: str,
        bounds_sha256: str,
        spec_identity: str,
        spec_sha256: str,
        policy_identity_sha256: str,
        recovery_token_key: bytes | None,
        action: operation_contract.LifecycleAction,
        transition_guard: Callable[[], None],
        on_invalidate: Callable[[AuthorityRuntimeError], None],
    ) -> None:
        self.__snapshot_store = snapshot_store
        self.__request_sha256 = request_sha256
        self.__scope_sha256 = scope_sha256
        self.__bounds_sha256 = bounds_sha256
        self.__spec_identity = spec_identity
        self.__spec_sha256 = spec_sha256
        self.__policy_identity_sha256 = policy_identity_sha256
        self.__recovery_token_key = recovery_token_key
        self.__action = action
        self.__transition_guard = transition_guard
        self.__on_invalidate = on_invalidate
        self.__active = True
        self.__mutation_depth = 0
        self.__owner_pid = os.getpid()

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        root_identity: tuple[int, int],
        request_sha256: str,
        scope_sha256: str,
        bounds_sha256: str,
        spec_identity: str,
        spec_sha256: str,
        policy_identity: object,
        action: operation_contract.LifecycleAction,
        transition_guard: Callable[[], None],
        on_invalidate: Callable[[AuthorityRuntimeError], None],
    ) -> "DurableCoordinator":
        if type(request_sha256) is not str or len(request_sha256) != 64:
            raise AuthorityRuntimeError("durable request identity is invalid")
        if type(scope_sha256) is not str or _SHA256.fullmatch(scope_sha256) is None:
            raise AuthorityRuntimeError("durable scope identity is invalid")
        if type(bounds_sha256) is not str or _SHA256.fullmatch(bounds_sha256) is None:
            raise AuthorityRuntimeError("durable bounds identity is invalid")
        if type(spec_identity) is not str or not spec_identity:
            raise AuthorityRuntimeError("durable operation spec identity is invalid")
        if type(spec_sha256) is not str or len(spec_sha256) != 64:
            raise AuthorityRuntimeError("durable operation spec hash is invalid")
        if action not in (
            operation_contract.LifecycleAction.APPLY,
            operation_contract.LifecycleAction.RECOVER,
        ):
            raise AuthorityRuntimeError("durable lifecycle action is invalid")
        try:
            anchored_root = _RootAnchor.open(
                root,
                expected_identity=root_identity,
            )
        except AuthorityRuntimeError as exc:
            on_invalidate(exc)
            raise
        snapshot_store: _durable_snapshot._DurableSnapshotStore | None = None
        try:
            with anchored_root.mutation_gate():
                try:
                    snapshot_store = _durable_snapshot._DurableSnapshotStore.open(
                        anchored_root
                    )
                except _durable_snapshot._SnapshotLegacyFenceRequired as exc:
                    raise DurableRecoveryFenceRequired(
                        "durable legacy state is fenced",
                        reason_code=exc.reason_code,
                        observed_evidence_sha256=exc.observed_evidence_sha256,
                    ) from exc
                except _durable_snapshot._SnapshotRootStopRequired as exc:
                    raise DurableRecoveryFenceRequired(
                        str(exc),
                        reason_code=exc.reason_code,
                        observed_evidence_sha256=exc.observed_evidence_sha256,
                    ) from exc
                except (
                    _durable_snapshot._SnapshotWriterBusy,
                    _durable_snapshot._SnapshotWriterUnavailable,
                ):
                    raise
                except AuthorityRuntimeError as exc:
                    on_invalidate(exc)
                    raise
                try:
                    recovery_token_key = snapshot_store.recovery_token_key()
                except AuthorityRuntimeError as exc:
                    raise AuthorityRuntimeError(
                        "durable recovery authority is unavailable"
                    ) from exc
        except BaseException:
            if snapshot_store is not None:
                try:
                    snapshot_store.close()
                except AuthorityRuntimeError:
                    pass
            else:
                try:
                    anchored_root.close()
                except AuthorityRuntimeError:
                    pass
            raise
        return cls(
            snapshot_store,
            request_sha256,
            scope_sha256,
            bounds_sha256,
            spec_identity,
            spec_sha256,
            _policy_identity_digest(policy_identity),
            recovery_token_key,
            action,
            transition_guard,
            on_invalidate,
        )

    def _require_active(self) -> None:
        if not self.__active:
            raise AuthorityRuntimeError("durable coordinator is not active")
        if os.getpid() != self.__owner_pid:
            error = AuthorityRuntimeError("durable coordinator inherited across fork")
            self.__on_invalidate(error)
            raise error
        try:
            self.__snapshot_store.verify_canonical_database_identity()
        except _durable_snapshot._SnapshotLegacyFenceRequired as exc:
            self.__on_invalidate(exc)
            raise DurableRecoveryFenceRequired(
                "durable legacy state is fenced",
                reason_code=exc.reason_code,
                observed_evidence_sha256=exc.observed_evidence_sha256,
            ) from exc
        except _durable_snapshot._SnapshotRootStopRequired as exc:
            self.__on_invalidate(exc)
            raise DurableRecoveryFenceRequired(
                str(exc),
                reason_code=exc.reason_code,
                observed_evidence_sha256=exc.observed_evidence_sha256,
            ) from exc
        except _durable_snapshot._SnapshotHistoryChanged as exc:
            self.__on_invalidate(exc)
            raise DurableRecoveryFenceRequired(
                "durable snapshot history changed",
                reason_code="RECOVERY_SNAPSHOT_HISTORY_CHANGED",
                observed_evidence_sha256=_fence_observed_evidence(
                    "RECOVERY_SNAPSHOT_HISTORY_CHANGED"
                ),
            ) from exc

    def _run_bound_operation(
        self,
        token: RecoveryToken,
        operation: Callable[[], object],
    ) -> object:
        """Normalize a valid token's storage fault at the private/public boundary.

        A caller that already owns an exact recovery token must never need to
        distinguish a temporarily unavailable snapshot store from a malformed
        immutable history.  The former revokes this coordinator and becomes a
        token-scoped recovery result; the latter remains a typed root fence.
        """

        if type(token) is not RecoveryToken:
            raise TypeError("durable recovery token is invalid")
        try:
            self._require_active()
            return operation()
        except (
            DurableRecoveryRequired,
            DurableRecoveryDenied,
            DurableRecoveryFenceRequired,
        ):
            raise
        except sqlite3.Error as exc:
            error = AuthorityRuntimeError("durable snapshot state is unavailable")
            self.__on_invalidate(error)
            raise self._unavailable_error(
                "durable snapshot state is unavailable",
                token=token,
            ) from exc
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise self._unavailable_error(
                "durable snapshot state is unavailable",
                token=token,
            ) from exc

    @contextmanager
    def _mutation_gate(self) -> Iterator[None]:
        """Serialize every durable state/fence/effect mutation for this root."""

        if self.__mutation_depth:
            self.__mutation_depth += 1
            try:
                yield
            finally:
                self.__mutation_depth -= 1
            return
        self._require_active()
        with self.__snapshot_store.root.mutation_gate():
            self.__mutation_depth = 1
            try:
                yield
            finally:
                self.__mutation_depth = 0

    def _require_apply(self) -> None:
        if self.__action is not operation_contract.LifecycleAction.APPLY:
            raise DurableCapabilityDenied("durable apply capability is not admitted")

    def _require_recovery(self) -> None:
        if self.__action is not operation_contract.LifecycleAction.RECOVER:
            raise DurableCapabilityDenied("durable recovery capability is not admitted")

    def _root_fence(
        self,
        message: str,
        *,
        reason_code: str,
    ) -> DurableRecoveryFenceRequired:
        observed_evidence_sha256 = _fence_observed_evidence(reason_code)
        self.__snapshot_store.record_root_stop(
            reason_code=reason_code,
            observed_evidence_sha256=observed_evidence_sha256,
        )
        return DurableRecoveryFenceRequired(
            message,
            reason_code=reason_code,
            observed_evidence_sha256=observed_evidence_sha256,
        )

    def _binding_fence(self, message: str) -> DurableRecoveryFenceRequired:
        return self._root_fence(
            message,
            reason_code="RECOVERY_EVIDENCE_UNSAFE",
        )

    def fence_root_for_owner(
        self,
        *,
        reason_code: str,
    ) -> None:
        """Publish one typed root stop for a narrow profile-gated owner."""

        with self._mutation_gate():
            self._require_active()
            error = self._root_fence(
                "durable owner evidence requires manual recovery",
                reason_code=reason_code,
            )
            self.__on_invalidate(error)
            raise error

    def _raise_pre_prepared_unavailable(
        self,
        message: str,
        *,
        cause: BaseException,
    ) -> None:
        """Revoke a CLAIMED-only writer without turning availability into a root stop."""

        error = AuthorityRuntimeError(message)
        self.__on_invalidate(error)
        raise error from cause

    @staticmethod
    def _snapshot_binding_value(
        binding: _DurableBinding,
    ) -> _durable_snapshot._SnapshotBindingValue:
        token_value = binding.token.canonical_value
        return _durable_snapshot._SnapshotBindingValue(
            effect_id=binding.effect_id,
            target_relative_path=binding.target_relative_path,
            artifact_ref_sha256=binding.artifact_ref_sha256,
            request_sha256=binding.request_sha256,
            scope_sha256=binding.scope_sha256,
            bounds_sha256=binding.bounds_sha256,
            spec_identity=binding.spec_identity,
            spec_sha256=binding.spec_sha256,
            policy_identity_sha256=binding.policy_identity_sha256,
            token_request_sha256=token_value["request_sha256"],
            token_continuation_identity=token_value["continuation_identity"],
            token_authentication_tag=token_value["authentication_tag"],
            binding_sha256=binding.binding_sha256,
        )

    @staticmethod
    def _binding_from_snapshot_value(
        value: _durable_snapshot._SnapshotBindingValue,
        *,
        expected_effect_id: str | None = None,
    ) -> _DurableBinding:
        if type(value) is not _durable_snapshot._SnapshotBindingValue:
            raise ValueError("durable snapshot binding is invalid")
        raw = canonical_json_bytes(
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
        if sha256_bytes(raw) != value.binding_sha256:
            raise ValueError("durable snapshot binding is invalid")
        return _binding_from_raw(raw, expected_effect_id=expected_effect_id)

    def _snapshot_binding_for_effect_id(
        self,
        effect_id: str,
    ) -> _DurableBinding | None:
        value = self.__snapshot_store.binding(effect_id)
        if value is None:
            return None
        return self._binding_from_snapshot_value(
            value,
            expected_effect_id=effect_id,
        )

    def _binding_for_effect_id(self, effect_id: str) -> _DurableBinding:
        try:
            binding = self._snapshot_binding_for_effect_id(effect_id)
        except (AuthorityRuntimeError, sqlite3.Error):
            raise
        except ValueError as exc:
            raise self._binding_fence("durable effect binding is unavailable") from exc
        if binding is None:
            raise self._binding_fence("durable effect binding is unavailable")
        expected_claim = _durable_snapshot._SnapshotTargetClaimValue(
            target_relative_path=binding.target_relative_path,
            effect_id=binding.effect_id,
            binding_sha256=binding.binding_sha256,
        )
        try:
            target_claim = self.__snapshot_store.target_claim(
                binding.target_relative_path
            )
        except (AuthorityRuntimeError, sqlite3.Error):
            raise
        except ValueError as exc:
            raise self._binding_fence(
                "durable effect target claim is unavailable"
            ) from exc
        if target_claim != expected_claim:
            raise self._binding_fence("durable effect target claim is unavailable")
        return binding

    def _binding_for_effect(
        self,
        effect: StagedEffect,
        token: RecoveryToken,
    ) -> _DurableBinding:
        return _DurableBinding(
            effect_id=effect.effect_id,
            target_relative_path=effect.target_relative_path,
            artifact_ref_sha256=sha256_bytes(effect.artifact_ref.canonical_bytes),
            request_sha256=self.__request_sha256,
            scope_sha256=self.__scope_sha256,
            bounds_sha256=self.__bounds_sha256,
            spec_identity=self.__spec_identity,
            spec_sha256=self.__spec_sha256,
            policy_identity_sha256=self.__policy_identity_sha256,
            token=token,
            binding_sha256=sha256_bytes(
                canonical_json_bytes(
                    {
                        "schema_version": _RECOVERY_PROTOCOL_VERSION,
                        "kind": _RECOVERY_BINDING_KIND,
                        "recovery_owner": _RECOVERY_OWNER,
                        "effect_id": effect.effect_id,
                        "target_relative_path": effect.target_relative_path,
                        "artifact_ref_sha256": sha256_bytes(
                            effect.artifact_ref.canonical_bytes
                        ),
                        "request_sha256": self.__request_sha256,
                        "scope_sha256": self.__scope_sha256,
                        "bounds_sha256": self.__bounds_sha256,
                        "spec_identity": self.__spec_identity,
                        "spec_sha256": self.__spec_sha256,
                        "policy_identity_sha256": self.__policy_identity_sha256,
                        "recovery_token": token.canonical_value,
                    }
                )
            ),
        )

    def _row_matches_binding(
        self,
        row: _SnapshotEffectRow,
        binding: _DurableBinding,
    ) -> bool:
        try:
            return (
                row["effect_id"] == binding.effect_id
                and row["target_relative_path"] == binding.target_relative_path
                and sha256_bytes(bytes(row["artifact_ref"]))
                == binding.artifact_ref_sha256
                and row["request_sha256"] == binding.request_sha256
                and row["scope_sha256"] == binding.scope_sha256
                and row["spec_identity"] == binding.spec_identity
                and row["spec_sha256"] == binding.spec_sha256
                and row["policy_identity_sha256"] == binding.policy_identity_sha256
            )
        except (KeyError, TypeError, ValueError):
            return False

    def _validate_binding_admission(self, binding: _DurableBinding) -> None:
        if (
            binding.spec_identity != self.__spec_identity
            or binding.spec_sha256 != self.__spec_sha256
            or binding.scope_sha256 != self.__scope_sha256
            or binding.bounds_sha256 != self.__bounds_sha256
            or self.__action is operation_contract.LifecycleAction.APPLY
            and (
                binding.request_sha256 != self.__request_sha256
                or binding.policy_identity_sha256 != self.__policy_identity_sha256
            )
        ):
            raise DurableRecoveryDenied(
                "durable recovery token does not belong to this admission",
                reason_code="RECOVERY_ADMISSION_MISMATCH",
            )

    def _binding_for_token(self, token: RecoveryToken) -> _DurableBinding:
        if type(token) is not RecoveryToken:
            raise TypeError("durable recovery token is invalid")
        if self.__recovery_token_key is not None:
            self._validate_token_authentication(token)
        binding = self._binding_for_effect_id(token.effect_id)
        if token != binding.token:
            raise DurableRecoveryDenied(
                "durable recovery token does not match its effect",
                reason_code="RECOVERY_TOKEN_MISMATCH",
            )
        return binding

    def _token_for_row(self, row: _SnapshotEffectRow) -> RecoveryToken:
        try:
            effect_id = row["effect_id"]
        except (KeyError, TypeError) as exc:
            raise self._binding_fence("durable effect binding is unavailable") from exc
        return self._binding_for_effect_id(effect_id).token

    def _signed_token(
        self,
        *,
        effect_id: str,
        request_sha256: str,
        continuation_identity: str,
    ) -> RecoveryToken:
        if self.__recovery_token_key is None:
            raise AuthorityRuntimeError("durable recovery authority is unavailable")
        unsigned_value = {
            "schema_version": _RECOVERY_PROTOCOL_VERSION,
            "effect_id": effect_id,
            "request_sha256": request_sha256,
            "continuation_identity": continuation_identity,
        }
        return RecoveryToken(
            effect_id=effect_id,
            request_sha256=request_sha256,
            continuation_identity=continuation_identity,
            authentication_tag=hmac.new(
                self.__recovery_token_key,
                canonical_json_bytes(unsigned_value),
                sha256,
            ).hexdigest(),
        )

    def _validate_token_authentication(self, token: RecoveryToken) -> None:
        if self.__recovery_token_key is None:
            raise AuthorityRuntimeError("durable recovery authority is unavailable")
        expected_tag = hmac.new(
            self.__recovery_token_key,
            canonical_json_bytes(token.unsigned_canonical_value),
            sha256,
        ).hexdigest()
        if not hmac.compare_digest(token.authentication_tag, expected_tag):
            raise DurableRecoveryDenied(
                "durable recovery token does not match its effect",
                reason_code="RECOVERY_TOKEN_MISMATCH",
            )

    def _token_for_effect(self, effect: StagedEffect) -> RecoveryToken:
        """Derive the exact retry selector before its PREPARED row is re-read."""

        continuation_identity = _continuation_identity(
            effect_id=effect.effect_id,
            target_relative_path=effect.target_relative_path,
            artifact_ref_sha256=sha256_bytes(effect.artifact_ref.canonical_bytes),
            request_sha256=self.__request_sha256,
            scope_sha256=self.__scope_sha256,
            bounds_sha256=self.__bounds_sha256,
            spec_identity=self.__spec_identity,
            spec_sha256=self.__spec_sha256,
            policy_identity_sha256=self.__policy_identity_sha256,
        )
        return self._signed_token(
            effect_id=effect.effect_id,
            request_sha256=self.__request_sha256,
            continuation_identity=continuation_identity,
        )

    def _directive_from_token(
        self,
        token: RecoveryToken,
        *,
        disposition: str,
        reason_code: str,
    ) -> DurableRecoveryDirective:
        observed_evidence_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "schema_version": _RECOVERY_PROTOCOL_VERSION,
                    "continuation_identity": token.continuation_identity,
                    "reason_code": reason_code,
                }
            )
        )
        return DurableRecoveryDirective(
            request_sha256=token.request_sha256,
            recovery_owner=_RECOVERY_OWNER,
            continuation_identity=token.continuation_identity,
            disposition=disposition,
            reason_code=reason_code,
            observed_evidence_sha256=observed_evidence_sha256,
            allowed_recovery_action=("recover" if disposition == "recoverable" else None),
            token=token,
        )

    def _directive_for_row(
        self,
        row: _SnapshotEffectRow,
        *,
        disposition: str,
        reason_code: str,
    ) -> DurableRecoveryDirective:
        return self._directive_from_token(
            self._token_for_row(row),
            disposition=disposition,
            reason_code=reason_code,
        )

    def _unavailable_error(
        self,
        message: str,
        *,
        token: RecoveryToken,
        reason_code: str = "RECOVERY_STATE_UNAVAILABLE",
    ) -> DurableRecoveryRequired:
        return DurableRecoveryRequired(
            message,
            directive=self._directive_from_token(
                token,
                disposition="recoverable",
                reason_code=reason_code,
            ),
        )

    def _recovery_required_for_token(
        self,
        token: RecoveryToken,
        *,
        message: str,
        reason_code: str,
    ) -> DurableRecoveryRequired:
        """Preserve an exact issued token when a session is revoked mid-effect."""

        if type(token) is not RecoveryToken:
            raise TypeError("durable recovery token is invalid")
        return self._unavailable_error(
            message,
            token=token,
            reason_code=reason_code,
        )

    def _snapshot_blocker_directive(
        self,
        binding: _DurableBinding,
    ) -> DurableRecoveryDirective | None:
        """Read a BLOCKED_RECOVERY directive sealed in the canonical snapshot."""

        try:
            value = self.__snapshot_store.recovery_blocker(binding.effect_id)
            if value is None:
                return None
            directive = self._directive_from_token(
                binding.token,
                disposition="blocked_recovery",
                reason_code=value.reason_code,
            )
            if self._snapshot_blocker_value(binding, directive) != value:
                raise ValueError("durable recovery blocker is invalid")
        except (AuthorityRuntimeError, sqlite3.Error):
            raise
        except (TypeError, ValueError) as exc:
            raise self._binding_fence("durable recovery blocker is invalid") from exc
        return directive

    def _existing_blocker(self, binding: _DurableBinding) -> DurableRecoveryDirective | None:
        """Use only immutable V2 snapshot evidence for a valid blocker."""

        return self._snapshot_blocker_directive(binding)

    @staticmethod
    def _snapshot_blocker_value(
        binding: _DurableBinding,
        directive: DurableRecoveryDirective,
    ) -> _durable_snapshot._SnapshotRecoveryBlockerValue:
        provisional = _durable_snapshot._SnapshotRecoveryBlockerValue(
            effect_id=binding.effect_id,
            binding_sha256=binding.binding_sha256,
            reason_code=directive.reason_code,
            observed_evidence_sha256=directive.observed_evidence_sha256,
            token_request_sha256=binding.token.request_sha256,
            token_continuation_identity=binding.token.continuation_identity,
            blocker_sha256="",
        )
        return _durable_snapshot._SnapshotRecoveryBlockerValue(
            effect_id=provisional.effect_id,
            binding_sha256=provisional.binding_sha256,
            reason_code=provisional.reason_code,
            observed_evidence_sha256=provisional.observed_evidence_sha256,
            token_request_sha256=provisional.token_request_sha256,
            token_continuation_identity=provisional.token_continuation_identity,
            blocker_sha256=(
                _durable_snapshot._DurableSnapshotStore.recovery_blocker_sha256(
                    provisional
                )
            ),
        )

    def _block_from_binding(
        self,
        binding: _DurableBinding,
        row: _SnapshotEffectRow | None,
        *,
        reason_code: str,
    ) -> DurableRecoveryDirective:
        directive = self._directive_from_token(
            binding.token,
            disposition="blocked_recovery",
            reason_code=reason_code,
        )
        if row is not None:
            state = self._state(row)
            if state is not DurableEffectState.BLOCKED_RECOVERY:
                if state not in (
                    DurableEffectState.PREPARED,
                    DurableEffectState.PUBLISHED,
                ):
                    raise DurableRecoveryRequired(
                        "durable effect is terminal before recovery can be blocked",
                        directive=self._directive_for_row(
                            row,
                            disposition="recoverable",
                            reason_code="RECOVERY_STATE_CHANGED",
                        ),
                    )
                try:
                    self.__snapshot_store.record_recovery_blocker(
                        self._snapshot_blocker_value(binding, directive)
                    )
                except AuthorityRuntimeError as exc:
                    self.__on_invalidate(exc)
                    return directive
                try:
                    updated = self.__snapshot_store.block_effect(
                        effect_id=binding.effect_id,
                        expected_state=state.value,
                    )
                except sqlite3.Error as exc:
                    self.__on_invalidate(
                        AuthorityRuntimeError(
                            "durable recovery block state is unavailable"
                        )
                    )
                    return directive
                if updated != 1:
                    self.__on_invalidate(
                        AuthorityRuntimeError(
                            "durable recovery block state changed unexpectedly"
                        )
                    )
                    return directive
                try:
                    self.__snapshot_store.checkpoint(
                        DurableEffectState.BLOCKED_RECOVERY.value
                    )
                except AuthorityRuntimeError as exc:
                    self.__on_invalidate(exc)
                    return directive
        existing = self._existing_blocker(binding)
        if existing is not None:
            return existing
        return directive

    def _record_unproven_blocker(
        self,
        token: RecoveryToken,
        *,
        reason_code: str,
    ) -> DurableRecoveryDirective:
        """Stop the V2 root when an effect owner cannot be proven safely."""

        directive = self._directive_from_token(
            token,
            disposition="blocked_recovery",
            reason_code=reason_code,
        )
        self.__snapshot_store.record_root_stop(
            reason_code=directive.reason_code,
            observed_evidence_sha256=directive.observed_evidence_sha256,
        )
        raise DurableRecoveryFenceRequired(
            "durable recovery evidence is unsafe",
            reason_code=directive.reason_code,
            observed_evidence_sha256=directive.observed_evidence_sha256,
        )

    def _block_authenticated_token_mismatch(
        self,
        row: _SnapshotEffectRow,
        token: RecoveryToken,
        *,
        message: str,
    ) -> DurableRecoveryRequired:
        """Block a signed original token without returning a row-derived selector."""

        try:
            self._block(row)
        except DurableRecoveryRequired:
            directive = self._record_unproven_blocker(
                token,
                reason_code="RECOVERY_EVIDENCE_UNSAFE",
            )
        else:
            directive = self._directive_from_token(
                token,
                disposition="blocked_recovery",
                reason_code="RECOVERY_EVIDENCE_UNSAFE",
            )
        return DurableRecoveryRequired(message, directive=directive)

    def _block_for_token(
        self,
        token: RecoveryToken,
        *,
        message: str,
        reason_code: str,
    ) -> DurableRecoveryRequired:
        """Block an authenticated in-flight effect without reusing admission evidence."""

        with self._mutation_gate():
            return self._run_bound_operation(
                token,
                lambda: self._block_for_token_locked(
                    token,
                    message=message,
                    reason_code=reason_code,
                ),
            )

    def _block_for_token_locked(
        self,
        token: RecoveryToken,
        *,
        message: str,
        reason_code: str,
    ) -> DurableRecoveryRequired:

        if type(token) is not RecoveryToken:
            raise TypeError("durable recovery token is invalid")
        binding = self._binding_for_token(token)
        self._validate_binding_admission(binding)
        existing_blocker = self._existing_blocker(binding)
        if existing_blocker is not None:
            return DurableRecoveryRequired(message, directive=existing_blocker)
        try:
            row = self._row(token.effect_id)
        except sqlite3.Error:
            directive = self._block_from_binding(
                binding,
                None,
                reason_code="RECOVERY_STATE_UNAVAILABLE",
            )
            return DurableRecoveryRequired(message, directive=directive)
        if row is None:
            directive = self._block_from_binding(
                binding,
                None,
                reason_code="RECOVERY_ROW_MISSING",
            )
            return DurableRecoveryRequired(message, directive=directive)
        if not self._row_matches_binding(row, binding):
            directive = self._block_from_binding(
                binding,
                row,
                reason_code="RECOVERY_EVIDENCE_UNSAFE",
            )
            return DurableRecoveryRequired(message, directive=directive)
        return DurableRecoveryRequired(
            message,
            directive=self._block_from_binding(
                binding,
                row,
                reason_code=reason_code,
            ),
        )

    def _block_unavailable_recovery_authority(
        self,
        token: RecoveryToken,
    ) -> DurableRecoveryRequired:
        """Fail closed for exactly one proven token when its signing key is gone."""

        binding = self._binding_for_token(token)
        self._validate_binding_admission(binding)
        existing_blocker = self._existing_blocker(binding)
        if existing_blocker is not None:
            return DurableRecoveryRequired(
                "durable effect is blocked for recovery",
                directive=existing_blocker,
            )
        try:
            row = self._row(token.effect_id)
        except sqlite3.Error:
            row = None
        try:
            directive = self._block_from_binding(
                binding,
                row,
                reason_code="RECOVERY_AUTHORITY_UNAVAILABLE",
            )
        except DurableRecoveryRequired as exc:
            if exc.directive is None:
                raise
            directive = exc.directive
        return DurableRecoveryRequired(
            "durable recovery authority is unavailable",
            directive=directive,
        )

    def _row(self, effect_id: str) -> Optional[_SnapshotEffectRow]:
        return self.__snapshot_store.effect(effect_id)

    def _row_for_token(
        self,
        token: RecoveryToken,
        *,
        require_current_request: bool,
    ) -> _SnapshotEffectRow:
        if type(token) is not RecoveryToken:
            raise TypeError("durable recovery token is invalid")
        binding = self._binding_for_token(token)
        if (
            binding.spec_identity != self.__spec_identity
            or binding.spec_sha256 != self.__spec_sha256
            or binding.scope_sha256 != self.__scope_sha256
        ):
            raise DurableRecoveryRequired(
                "durable effect belongs to a different operation spec",
                directive=self._directive_from_token(
                    binding.token,
                    disposition="recoverable",
                    reason_code="RECOVERY_SPEC_MISMATCH",
                ),
            )
        if binding.bounds_sha256 != self.__bounds_sha256:
            raise DurableRecoveryDenied(
                "durable recovery token belongs to different admitted bounds",
                reason_code="RECOVERY_ADMISSION_MISMATCH",
            )
        if self.__action is operation_contract.LifecycleAction.APPLY and (
            binding.request_sha256 != self.__request_sha256
            or binding.policy_identity_sha256 != self.__policy_identity_sha256
        ):
            raise DurableRecoveryRequired(
                "durable effect belongs to different admission evidence",
                directive=self._directive_from_token(
                    binding.token,
                    disposition="recoverable",
                    reason_code="RECOVERY_REQUEST_MISMATCH",
                ),
            )
        existing_blocker = self._existing_blocker(binding)
        if existing_blocker is not None:
            raise DurableRecoveryRequired(
                "durable effect is blocked for recovery",
                directive=existing_blocker,
            )
        try:
            row = self._row(token.effect_id)
        except sqlite3.Error as exc:
            self.__on_invalidate(
                AuthorityRuntimeError("durable effect lookup is unavailable")
            )
            raise self._unavailable_error(
                "durable effect lookup is unavailable",
                token=token,
            ) from exc
        if row is None:
            raise DurableRecoveryRequired(
                "durable effect does not exist",
                directive=self._block_from_binding(
                    binding,
                    None,
                    reason_code="RECOVERY_ROW_MISSING",
                ),
            )
        self._validate_row_context(
            row,
            token=token,
            binding=binding,
            require_current_request=require_current_request,
        )
        return row

    def _validate_row_context(
        self,
        row: _SnapshotEffectRow,
        *,
        token: RecoveryToken,
        binding: _DurableBinding,
        require_current_request: bool,
    ) -> None:
        if not self._row_matches_binding(row, binding):
            raise DurableRecoveryRequired(
                "durable effect identity does not match its recovery token",
                directive=self._block_from_binding(
                    binding,
                    row,
                    reason_code="RECOVERY_EVIDENCE_UNSAFE",
                ),
            )
        if row["policy_identity_sha256"] != self.__policy_identity_sha256:
            raise DurableRecoveryRequired(
                "durable effect belongs to different admission evidence",
                directive=self._block_from_binding(
                    binding,
                    row,
                    reason_code="RECOVERY_POLICY_MISMATCH",
                ),
            )
        self._effect_payload(row)
        if require_current_request and row["request_sha256"] != self.__request_sha256:
            raise DurableRecoveryRequired(
                "durable effect belongs to different admission evidence",
                directive=self._directive_for_row(
                    row,
                    disposition="recoverable",
                    reason_code="RECOVERY_REQUEST_MISMATCH",
                ),
            )

    def _blocked_error(
        self,
        row: _SnapshotEffectRow,
        message: str,
        *,
        token: RecoveryToken | None = None,
    ) -> DurableRecoveryRequired:
        binding = self._binding_for_effect_id(row["effect_id"])
        persisted = self._existing_blocker(binding)
        return DurableRecoveryRequired(
            message,
            directive=(
                persisted
                if persisted is not None
                else
                self._directive_from_token(
                    token,
                    disposition="blocked_recovery",
                    reason_code="RECOVERY_EVIDENCE_UNSAFE",
                )
                if token is not None
                else self._directive_for_row(
                    row,
                    disposition="blocked_recovery",
                    reason_code="RECOVERY_EVIDENCE_UNSAFE",
                )
            ),
        )

    def _state(self, row: _SnapshotEffectRow) -> DurableEffectState:
        try:
            return _state_from_row(row)
        except DurableRecoveryRequired as exc:
            raise DurableRecoveryRequired(
                "durable effect state is invalid",
                directive=self._directive_for_row(
                    row,
                    disposition="blocked_recovery",
                    reason_code="RECOVERY_EVIDENCE_UNSAFE",
                ),
            ) from exc

    def _effect_ref(self, row: _SnapshotEffectRow) -> artifact_contract.SealedArtifactRef:
        try:
            raw = bytes(row["artifact_ref"])
            reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(raw)
        except (TypeError, ValueError) as exc:
            self._block(row)
            raise self._blocked_error(row, "durable effect reference is invalid") from exc
        if row["target_relative_path"] != reference.canonical_path:
            self._block(row)
            raise self._blocked_error(
                row,
                "durable effect target does not match sealed artifact path",
            )
        return reference

    def _effect_payload(self, row: _SnapshotEffectRow) -> bytes:
        """Return the exact PREPARED payload only when its sealed ref verifies it."""

        reference = self._effect_ref(row)
        try:
            payload = bytes(row["artifact_bytes"])
            reference.verify_bytes(payload)
        except (KeyError, TypeError, ValueError) as exc:
            self._block(row)
            raise self._blocked_error(
                row,
                "durable prepared payload is invalid",
            ) from exc
        return payload

    def _target_path(self, row: _SnapshotEffectRow) -> _AnchoredPath:
        components = tuple(str(row["target_relative_path"]).split("/"))
        if not components or any(
            _PATH_COMPONENT.fullmatch(component) is None for component in components
        ):
            self._block(row)
            raise self._blocked_error(row, "durable effect target is invalid")
        return self.__snapshot_store.root.joinpath(*components)

    def _stage_path(self, effect_id: str) -> _AnchoredPath:
        return (
            self.__snapshot_store.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "staging"
            / f"{effect_id}.artifact"
        )

    def _guard_before_unbound_write(self) -> None:
        """Revalidate before the first durable write has a recoverable token."""

        try:
            self._require_active()
            self.__transition_guard()
        except DurableRecoveryFenceRequired:
            raise
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise

    def _guard_before_bound_effect(
        self,
        token: RecoveryToken,
        *,
        message: str,
    ) -> None:
        """Revalidate immediately before a write once its exact token exists."""

        try:
            self._require_active()
            self.__transition_guard()
        except DurableRecoveryFenceRequired:
            raise
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise self._block_for_token(
                token,
                message=message,
                reason_code="RECOVERY_ADMISSION_DRIFT",
            ) from exc

    def _guard_before_possible_effect(
        self,
        row: _SnapshotEffectRow,
        *,
        message: str,
    ) -> None:
        """Revalidate immediately before an external durable filesystem effect."""

        try:
            self._require_active()
            self.__transition_guard()
        except DurableRecoveryFenceRequired:
            raise
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            try:
                directive = self._block(
                    row,
                    reason_code="RECOVERY_ADMISSION_DRIFT",
                )
            except DurableRecoveryRequired as block_error:
                raise block_error from exc
            raise DurableRecoveryRequired(message, directive=directive) from exc

    def _transition(
        self,
        row: _SnapshotEffectRow,
        expected: DurableEffectState,
        target: DurableEffectState,
    ) -> None:
        effect_id = row["effect_id"]
        token = self._token_for_row(row)
        try:
            self.__transition_guard()
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            try:
                directive = self._block(
                    row,
                    reason_code="RECOVERY_ADMISSION_DRIFT",
                )
            except DurableRecoveryRequired as block_error:
                raise block_error from exc
            raise DurableRecoveryRequired(
                "durable admission evidence changed before state transition",
                directive=directive,
            ) from exc
        binding = self._binding_for_effect_id(effect_id)
        if not self._row_matches_binding(row, binding):
            raise DurableRecoveryRequired(
                "durable effect identity changed before state transition",
                directive=self._block_from_binding(
                    binding,
                    row,
                    reason_code="RECOVERY_EVIDENCE_UNSAFE",
                ),
            )
        try:
            updated = self.__snapshot_store.transition_effect(
                row,
                expected_state=expected.value,
                target_state=target.value,
            )
        except sqlite3.Error as exc:
            self.__on_invalidate(
                AuthorityRuntimeError("durable state transition is unavailable")
            )
            raise self._unavailable_error(
                "durable state transition is unavailable",
                token=token,
            ) from exc
        if updated != 1:
            self.__on_invalidate(
                AuthorityRuntimeError("durable effect state changed unexpectedly")
            )
            try:
                row = self._row(effect_id)
            except sqlite3.Error as exc:
                raise self._unavailable_error(
                    "durable effect state is unavailable",
                    token=token,
                ) from exc
            if row is not None and not self._row_matches_binding(row, binding):
                raise DurableRecoveryRequired(
                    "durable effect identity changed before state transition",
                    directive=self._block_from_binding(
                        binding,
                        row,
                        reason_code="RECOVERY_EVIDENCE_UNSAFE",
                    ),
                )
            if row is not None and self._state(row) is DurableEffectState.BLOCKED_RECOVERY:
                raise self._blocked_error(row, "durable effect is blocked for recovery")
            current_token = (
                self._token_for_row(row)
                if row is not None
                else token
            )
            raise self._unavailable_error(
                "durable effect state changed unexpectedly",
                token=current_token,
                reason_code="RECOVERY_STATE_CHANGED",
            )
        try:
            self.__snapshot_store.checkpoint(target.value)
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise self._unavailable_error(
                "durable state transition is unavailable",
                token=token,
            ) from exc

    def _block(
        self,
        row: _SnapshotEffectRow,
        *,
        reason_code: str = "RECOVERY_EVIDENCE_UNSAFE",
    ) -> DurableRecoveryDirective:
        binding = self._binding_for_effect_id(row["effect_id"])
        persisted = self._existing_blocker(binding)
        if persisted is not None:
            return persisted
        try:
            current = self._row(binding.effect_id)
        except sqlite3.Error:
            self.__on_invalidate(
                AuthorityRuntimeError("durable recovery state is unavailable")
            )
            current = None
        return self._block_from_binding(
            binding,
            current,
            reason_code=reason_code,
        )

    def _verify_target_or_block(self, row: _SnapshotEffectRow) -> Optional[bytes]:
        reference = self._effect_ref(row)
        target = self._target_path(row)
        try:
            raw = _try_read_verified_bytes(target)
        except AuthorityRuntimeError as exc:
            self._block(row)
            raise self._blocked_error(
                row,
                "durable effect target readback is unavailable",
            ) from exc
        if raw is None:
            return None
        try:
            reference.verify_bytes(raw)
        except ValueError as exc:
            self._block(row)
            raise self._blocked_error(row, "durable effect target is not sealed") from exc
        return raw

    def _verify_stage_or_block(self, row: _SnapshotEffectRow) -> Optional[bytes]:
        reference = self._effect_ref(row)
        try:
            raw = _try_read_verified_bytes(self._stage_path(row["effect_id"]))
        except AuthorityRuntimeError as exc:
            self._block(row)
            raise self._blocked_error(
                row,
                "durable staging artifact readback is unavailable",
            ) from exc
        if raw is None:
            return None
        try:
            reference.verify_bytes(raw)
        except ValueError as exc:
            self._block(row)
            raise self._blocked_error(row, "durable staging artifact is not sealed") from exc
        return raw

    def _restore_stage_or_block(self, row: _SnapshotEffectRow) -> None:
        """Recreate a missing staging file from the canonical PREPARED payload."""

        self._guard_before_possible_effect(
            row,
            message="durable admission evidence changed before staging publication",
        )
        payload = self._effect_payload(row)
        try:
            _publish_exact_bytes(
                self._stage_path(row["effect_id"]),
                payload,
                label="durable staging artifact",
            )
        except AuthorityRuntimeError as exc:
            self._block(row)
            raise self._blocked_error(
                row,
                "durable staging artifact is unavailable",
            ) from exc

    def _attest_target_durability(
        self,
        row: _SnapshotEffectRow,
    ) -> _durable_snapshot._SnapshotPublishedAttestationValue:
        """Prove the exact existing target and its containing directory are durable."""

        reference = self._effect_ref(row)
        target = self._target_path(row)
        parent_fd: int | None = None
        target_fd: int | None = None
        opened: os.stat_result | None = None
        verified_raw: bytes | None = None
        try:
            parent_fd = target.anchor._open_directory(
                target.parts[:-1],
                create=False,
            )
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            lexical_before = os.stat(
                target.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            target_fd = os.open(target.name, flags, dir_fd=parent_fd)
            opened = os.fstat(target_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (opened.st_dev, opened.st_ino)
                != (lexical_before.st_dev, lexical_before.st_ino)
            ):
                raise AuthorityRuntimeError("durable target identity is invalid")
            reference.verify_bytes(safety.read_open_file_bytes(target_fd))
            os.fsync(target_fd)
            os.fsync(parent_fd)
            lexical_after = os.stat(
                target.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if (
                (lexical_after.st_dev, lexical_after.st_ino)
                != (opened.st_dev, opened.st_ino)
                or lexical_after.st_nlink != opened.st_nlink
                or lexical_after.st_size != opened.st_size
            ):
                raise AuthorityRuntimeError("durable target identity changed")
            verified_raw = safety.read_open_file_bytes(target_fd)
            reference.verify_bytes(verified_raw)
        except (AuthorityRuntimeError, OSError, ValueError) as exc:
            raise self._unavailable_error(
                "durable target durability proof is unavailable",
                token=self._token_for_row(row),
                reason_code="RECOVERY_DURABILITY_UNPROVEN",
            ) from exc
        finally:
            if target_fd is not None:
                os.close(target_fd)
            if parent_fd is not None:
                os.close(parent_fd)
        if opened is None or verified_raw is None:
            raise AuthorityRuntimeError("durable target durability proof is unavailable")
        binding = self._binding_for_effect_id(row["effect_id"])
        provisional = _durable_snapshot._SnapshotPublishedAttestationValue(
            effect_id=row["effect_id"],
            target_relative_path=row["target_relative_path"],
            binding_sha256=binding.binding_sha256,
            artifact_bytes_sha256=sha256_bytes(verified_raw),
            byte_length=len(verified_raw),
            target_device=opened.st_dev,
            target_inode=opened.st_ino,
            target_nlink=opened.st_nlink,
            attestation_sha256="",
        )
        return _durable_snapshot._SnapshotPublishedAttestationValue(
            effect_id=provisional.effect_id,
            target_relative_path=provisional.target_relative_path,
            binding_sha256=provisional.binding_sha256,
            artifact_bytes_sha256=provisional.artifact_bytes_sha256,
            byte_length=provisional.byte_length,
            target_device=provisional.target_device,
            target_inode=provisional.target_inode,
            target_nlink=provisional.target_nlink,
            attestation_sha256=(
                _durable_snapshot._DurableSnapshotStore.published_attestation_sha256(
                    provisional
                )
            ),
        )

    def _retry_prepared_effect(
        self,
        row: _SnapshotEffectRow,
        effect: StagedEffect,
        token: RecoveryToken,
    ) -> RecoveryToken:
        """Reissue only the identical PREPARED effect after a prepare-side crash."""

        try:
            row_token = self._token_for_row(row)
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise self._unavailable_error(
                "durable effect identity is unavailable",
                token=token,
            ) from exc
        except DurableRecoveryRequired as exc:
            raise DurableRecoveryRequired(
                "durable effect identity is unavailable",
                directive=self._record_unproven_blocker(
                    token,
                    reason_code="RECOVERY_EVIDENCE_UNSAFE",
                ),
            ) from exc
        if (
            row["target_relative_path"] != effect.target_relative_path
            or bytes(row["artifact_ref"]) != effect.artifact_ref.canonical_bytes
            or row["request_sha256"] != self.__request_sha256
            or row["scope_sha256"] != self.__scope_sha256
            or row["spec_identity"] != self.__spec_identity
            or row["spec_sha256"] != self.__spec_sha256
            or row["policy_identity_sha256"] != self.__policy_identity_sha256
            or row_token != token
        ):
            raise AuthorityRuntimeError(
                "durable effect identifier is bound to different immutable evidence"
            )
        state = self._state(row)
        if state is DurableEffectState.BLOCKED_RECOVERY:
            raise self._blocked_error(row, "durable effect is blocked for recovery")
        if state is not DurableEffectState.PREPARED:
            raise self._unavailable_error(
                "durable effect already requires exact recovery",
                token=token,
                reason_code="RECOVERY_STATE_CHANGED",
            )
        if self._verify_stage_or_block(row) is None:
            self._guard_before_possible_effect(
                row,
                message="durable admission evidence changed before staging publication",
            )
            payload = self._effect_payload(row)
            try:
                _publish_exact_bytes(
                    self._stage_path(effect.effect_id),
                    payload,
                    label="durable staging artifact",
                )
            except AuthorityRuntimeError as exc:
                self._block(row)
                raise self._blocked_error(
                    row,
                    "durable staging artifact is unavailable",
                ) from exc
        return token

    def replay_finalized(
        self,
        effect_id: str,
        target_relative_path: str,
    ) -> tuple[artifact_contract.SealedArtifactRef, bytes] | None:
        """Return one exact finalized effect for an identical APPLY retry."""

        with self._mutation_gate():
            self._require_active()
            self._require_apply()
            if (
                type(effect_id) is not str
                or _EFFECT_ID.fullmatch(effect_id) is None
                or type(target_relative_path) is not str
                or not target_relative_path
            ):
                raise ValueError("durable replay selector is invalid")
            try:
                row = self._row(effect_id)
            except sqlite3.Error as exc:
                self.__on_invalidate(
                    AuthorityRuntimeError("durable replay state is unavailable")
                )
                raise AuthorityRuntimeError(
                    "durable replay state is unavailable"
                ) from exc
            if row is None:
                return None
            token = self._token_for_row(row)
            binding = self._binding_for_token(token)
            self._validate_binding_admission(binding)
            self._validate_row_context(
                row,
                token=token,
                binding=binding,
                require_current_request=True,
            )
            if row["target_relative_path"] != target_relative_path:
                raise DurableRecoveryDenied(
                    "durable retry target does not match its effect",
                    reason_code="RECOVERY_ADMISSION_MISMATCH",
                )
            if self._state(row) is not DurableEffectState.FINALIZED:
                raise self._unavailable_error(
                    "durable effect requires exact recovery",
                    token=token,
                    reason_code="RECOVERY_STATE_CHANGED",
                )
            payload = self._effect_payload(row)
            readback = self._verify_target_or_block(row)
            if readback is None or readback != payload:
                self._block(row)
                raise self._blocked_error(
                    row,
                    "durable finalized effect readback is unavailable",
                )
            return self._effect_ref(row), payload

    def read_finalized_artifact(
        self,
        effect_id: str,
        target_relative_path: str,
    ) -> tuple[artifact_contract.SealedArtifactRef, bytes] | None:
        """Read one finalized predecessor without weakening exact retry rules."""

        with self._mutation_gate():
            self._require_active()
            if (
                type(effect_id) is not str
                or _EFFECT_ID.fullmatch(effect_id) is None
                or type(target_relative_path) is not str
                or not target_relative_path
            ):
                raise ValueError("durable artifact selector is invalid")
            try:
                row = self._row(effect_id)
                binding = self._snapshot_binding_for_effect_id(effect_id)
            except sqlite3.Error as exc:
                self.__on_invalidate(
                    AuthorityRuntimeError("durable predecessor state is unavailable")
                )
                raise AuthorityRuntimeError(
                    "durable predecessor state is unavailable"
                ) from exc
            except ValueError as exc:
                raise self._binding_fence(
                    "durable predecessor binding is unavailable"
                ) from exc
            if row is None and binding is None:
                return None
            if row is None or binding is None:
                raise self._binding_fence(
                    "durable predecessor evidence is incomplete"
                )
            binding = self._binding_for_effect_id(effect_id)
            if not self._row_matches_binding(row, binding):
                raise self._binding_fence(
                    "durable predecessor evidence does not match"
                )
            if row["target_relative_path"] != target_relative_path:
                raise self._binding_fence(
                    "durable predecessor target does not match"
                )
            token = self._token_for_row(row)
            if self._state(row) is not DurableEffectState.FINALIZED:
                raise self._unavailable_error(
                    "durable predecessor requires exact recovery",
                    token=token,
                    reason_code="RECOVERY_STATE_CHANGED",
                )
            payload = self._effect_payload(row)
            readback = self._verify_target_or_block(row)
            if readback is None or readback != payload:
                self._block(row)
                raise self._blocked_error(
                    row,
                    "durable predecessor readback is unavailable",
                )
            return self._effect_ref(row), payload

    def resolve_public_continuation(
        self,
        continuation_identity: str,
        producer_request_sha256: str,
    ) -> RecoveryToken:
        """Resolve a public selector to its authenticated token inside D1a."""

        with self._mutation_gate():
            self._require_active()
            self._require_recovery()
            if (
                type(continuation_identity) is not str
                or _SHA256.fullmatch(continuation_identity) is None
                or type(producer_request_sha256) is not str
                or _SHA256.fullmatch(producer_request_sha256) is None
            ):
                raise DurableRecoveryDenied(
                    "durable public continuation is invalid",
                    reason_code="RECOVERY_ADMISSION_MISMATCH",
                )
            try:
                value = self.__snapshot_store.binding_for_continuation(
                    continuation_identity
                )
            except (AuthorityRuntimeError, sqlite3.Error, ValueError) as exc:
                raise DurableRecoveryDenied(
                    "durable public continuation is unavailable",
                    reason_code="RECOVERY_ADMISSION_MISMATCH",
                ) from exc
            if value is None:
                raise DurableRecoveryDenied(
                    "durable public continuation is unavailable",
                    reason_code="RECOVERY_ADMISSION_MISMATCH",
                )
            try:
                binding = self._binding_from_snapshot_value(value)
                binding = self._binding_for_effect_id(binding.effect_id)
                self._validate_binding_admission(binding)
                if (
                    binding.request_sha256 != producer_request_sha256
                    or binding.token.request_sha256 != producer_request_sha256
                    or binding.token.continuation_identity
                    != continuation_identity
                ):
                    raise DurableRecoveryDenied(
                        "durable public continuation does not match APPLY",
                        reason_code="RECOVERY_ADMISSION_MISMATCH",
                    )
                self._validate_token_authentication(binding.token)
            except DurableRecoveryDenied:
                raise
            except (AuthorityRuntimeError, ValueError) as exc:
                raise DurableRecoveryDenied(
                    "durable public continuation is unavailable",
                    reason_code="RECOVERY_ADMISSION_MISMATCH",
                ) from exc
            return binding.token

    def prepare(self, effect: StagedEffect) -> RecoveryToken:
        with self._mutation_gate():
            return self._prepare_locked(effect)

    def _prepare_locked(self, effect: StagedEffect) -> RecoveryToken:
        self._require_active()
        self._require_apply()
        if type(effect) is not StagedEffect:
            raise TypeError("durable effect is invalid")
        token = self._token_for_effect(effect)
        binding = self._binding_for_effect(effect, token)
        # Token derivation is pure. Recheck immediately before the first
        # durable claim so admission drift cannot create a new predecessor.
        self._guard_before_unbound_write()
        try:
            claim_key_sha256 = self.__snapshot_store.claim_or_replay(
                effect_id=effect.effect_id,
                target_relative_path=effect.target_relative_path,
                artifact_ref_sha256=sha256_bytes(effect.artifact_ref.canonical_bytes),
                artifact_bytes_sha256=sha256_bytes(effect.artifact_bytes),
                request_sha256=self.__request_sha256,
                scope_sha256=self.__scope_sha256,
                bounds_sha256=self.__bounds_sha256,
                spec_identity=self.__spec_identity,
                spec_sha256=self.__spec_sha256,
                policy_identity_sha256=self.__policy_identity_sha256,
            )
        except _durable_snapshot._SnapshotClaimBusy as exc:
            raise DurableRecoveryDenied(
                str(exc),
                reason_code=exc.reason_code,
            ) from exc
        except _durable_snapshot._SnapshotClaimDenied as exc:
            raise DurableRecoveryDenied(
                "durable claim belongs to different admitted input",
                reason_code="RECOVERY_ADMISSION_MISMATCH",
            ) from exc
        except _durable_snapshot._SnapshotTargetClaimConflict as exc:
            raise AuthorityRuntimeError("durable effect target is already claimed") from exc
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise
        if claim_key_sha256 is not None:
            _run_checkpoint("after-claimed-head")
        try:
            existing_binding = self._snapshot_binding_for_effect_id(effect.effect_id)
        except (AuthorityRuntimeError, sqlite3.Error) as exc:
            self._raise_pre_prepared_unavailable(
                "durable effect binding is unavailable",
                cause=exc,
            )
        except ValueError as exc:
            raise self._binding_fence("durable effect binding is unavailable") from exc
        try:
            existing = self._row(effect.effect_id)
        except (AuthorityRuntimeError, sqlite3.Error) as exc:
            self._raise_pre_prepared_unavailable(
                "durable prepare state is unavailable",
                cause=exc,
            )
        if existing is not None:
            if existing_binding is None:
                if not self._row_matches_binding(existing, binding):
                    raise DurableRecoveryDenied(
                        "durable effect predecessor binding belongs to another admission",
                        reason_code="RECOVERY_ADMISSION_MISMATCH",
                    )
                raise DurableRecoveryRequired(
                    "durable effect predecessor binding is unavailable",
                    directive=self._record_unproven_blocker(
                        token,
                        reason_code="RECOVERY_EVIDENCE_UNSAFE",
                    ),
                )
            if existing_binding != binding:
                raise DurableRecoveryDenied(
                    "durable effect predecessor binding belongs to another admission",
                    reason_code="RECOVERY_ADMISSION_MISMATCH",
                )
            return self._retry_prepared_effect(existing, effect, token)
        if existing_binding is not None and existing_binding != binding:
            raise DurableRecoveryDenied(
                "durable effect predecessor binding belongs to another admission",
                reason_code="RECOVERY_ADMISSION_MISMATCH",
            )
        if existing_binding is None:
            try:
                self._guard_before_unbound_write()
                self.__snapshot_store.record_target_claim(
                    _durable_snapshot._SnapshotTargetClaimValue(
                        target_relative_path=binding.target_relative_path,
                        effect_id=binding.effect_id,
                        binding_sha256=binding.binding_sha256,
                    )
                )
            except _durable_snapshot._SnapshotTargetClaimConflict as exc:
                raise AuthorityRuntimeError(str(exc)) from exc
            except (AuthorityRuntimeError, sqlite3.Error) as exc:
                self._raise_pre_prepared_unavailable(
                    "durable effect binding is unavailable",
                    cause=exc,
                )
            except ValueError as exc:
                raise self._binding_fence(
                    "durable effect binding is unavailable"
                ) from exc
            try:
                self._guard_before_unbound_write()
                persisted_binding = self._binding_from_snapshot_value(
                    self.__snapshot_store.record_binding(
                        self._snapshot_binding_value(binding)
                    ),
                    expected_effect_id=binding.effect_id,
                )
            except (AuthorityRuntimeError, sqlite3.Error) as exc:
                self._raise_pre_prepared_unavailable(
                    "durable effect binding is unavailable",
                    cause=exc,
                )
            except ValueError as exc:
                raise self._binding_fence(
                    "durable effect binding is unavailable"
                ) from exc
        else:
            persisted_binding = existing_binding
            try:
                self._guard_before_bound_effect(
                    token,
                    message="durable admission evidence changed before target claim",
                )
                self.__snapshot_store.record_target_claim(
                    _durable_snapshot._SnapshotTargetClaimValue(
                        target_relative_path=persisted_binding.target_relative_path,
                        effect_id=persisted_binding.effect_id,
                        binding_sha256=persisted_binding.binding_sha256,
                    )
                )
            except DurableRecoveryRequired:
                raise
            except _durable_snapshot._SnapshotTargetClaimConflict as exc:
                raise self._binding_fence(
                    "durable effect target claim is inconsistent"
                ) from exc
            except (AuthorityRuntimeError, sqlite3.Error) as exc:
                self._raise_pre_prepared_unavailable(
                    "durable effect target claim is unavailable",
                    cause=exc,
                )
            except ValueError as exc:
                raise self._binding_fence(
                    "durable effect target claim is inconsistent"
                ) from exc
        if persisted_binding != binding:
            if existing_binding is None:
                raise self._binding_fence(
                    "durable effect target claim is inconsistent"
                )
            raise DurableRecoveryDenied(
                "durable effect predecessor binding belongs to another admission",
                reason_code="RECOVERY_ADMISSION_MISMATCH",
            )
        self._guard_before_bound_effect(
            token,
            message="durable admission evidence changed before PREPARED state",
        )
        try:
            existing = self._row(effect.effect_id)
        except sqlite3.Error as exc:
            raise self._unavailable_error(
                "durable prepare state is unavailable",
                token=token,
            ) from exc
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise
        if existing is not None:
            return self._retry_prepared_effect(existing, effect, token)
        try:
            self.__snapshot_store.insert_effect(
                effect_id=effect.effect_id,
                target_relative_path=effect.target_relative_path,
                artifact_ref=effect.artifact_ref.canonical_bytes,
                artifact_bytes=effect.artifact_bytes,
                request_sha256=self.__request_sha256,
                scope_sha256=self.__scope_sha256,
                spec_identity=self.__spec_identity,
                spec_sha256=self.__spec_sha256,
                policy_identity_sha256=self.__policy_identity_sha256,
                state=DurableEffectState.PREPARED.value,
            )
        except sqlite3.IntegrityError as exc:
            try:
                existing = self._row(effect.effect_id)
            except sqlite3.Error as lookup_exc:
                raise self._unavailable_error(
                    "durable prepare state is unavailable",
                    token=token,
                ) from lookup_exc
            if existing is not None:
                return self._retry_prepared_effect(existing, effect, token)
            raise AuthorityRuntimeError("durable effect target is already claimed") from exc
        except sqlite3.Error as exc:
            raise self._unavailable_error(
                "durable prepare state is unavailable",
                token=token,
            ) from exc
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise
        if claim_key_sha256 is not None:
            try:
                self.__snapshot_store.consume_claim(claim_key_sha256)
            except AuthorityRuntimeError as exc:
                self.__on_invalidate(exc)
                raise self._unavailable_error(
                    "durable prepare state is unavailable",
                    token=token,
                ) from exc
        _run_checkpoint("after-prepared-row")
        try:
            row = self._row(effect.effect_id)
        except sqlite3.Error as exc:
            self.__on_invalidate(
                AuthorityRuntimeError("durable prepare state is unavailable")
            )
            raise self._unavailable_error(
                "durable prepare state is unavailable",
                token=token,
            ) from exc
        if row is None:
            self.__on_invalidate(
                AuthorityRuntimeError("durable prepared effect is unavailable")
            )
            raise self._unavailable_error(
                "durable prepared effect is unavailable",
                token=token,
            )
        try:
            row_token = self._token_for_row(row)
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise self._unavailable_error(
                "durable prepared effect identity is unavailable",
                token=token,
            ) from exc
        except DurableRecoveryRequired as exc:
            raise DurableRecoveryRequired(
                "durable prepared effect identity is unavailable",
                directive=self._record_unproven_blocker(
                    token,
                    reason_code="RECOVERY_EVIDENCE_UNSAFE",
                ),
            ) from exc
        if row_token != token:
            self.__on_invalidate(
                AuthorityRuntimeError("durable prepared effect identity is unavailable")
            )
            raise self._unavailable_error(
                "durable prepared effect identity is unavailable",
                token=token,
                reason_code="RECOVERY_TOKEN_MISMATCH",
            )
        self._guard_before_possible_effect(
            row,
            message="durable admission evidence changed before staging publication",
        )
        try:
            _publish_exact_bytes(
                self._stage_path(effect.effect_id),
                effect.artifact_bytes,
                label="durable staging artifact",
            )
        except AuthorityRuntimeError as exc:
            self._block(row)
            raise self._blocked_error(
                row,
                "durable staging artifact is unavailable",
            ) from exc
        _run_checkpoint("after-prepare")
        return token

    def _record_published_attestation(self, row: _SnapshotEffectRow) -> None:
        """Seal the verified target readback before a PUBLISHED transition."""

        try:
            attestation = self._attest_target_durability(row)
            self.__snapshot_store.record_published_attestation(attestation)
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise self._unavailable_error(
                "durable published readback is unavailable",
                token=self._token_for_row(row),
                reason_code="RECOVERY_DURABILITY_UNPROVEN",
            ) from exc

    def _publish_prepared(
        self,
        row: _SnapshotEffectRow,
    ) -> artifact_contract.SealedArtifactRef:
        state = self._state(row)
        if state is DurableEffectState.BLOCKED_RECOVERY:
            raise self._blocked_error(row, "durable effect is blocked for recovery")
        if state is not DurableEffectState.PREPARED:
            raise DurableRecoveryRequired(
                "durable effect is not prepared for publish",
                directive=self._directive_for_row(
                    row,
                    disposition="recoverable",
                    reason_code="RECOVERY_STATE_CHANGED",
                ),
            )
        reference = self._effect_ref(row)
        target_raw = self._verify_target_or_block(row)
        if target_raw is None:
            stage_raw = self._verify_stage_or_block(row)
            if stage_raw is None:
                self._block(row)
                raise self._blocked_error(row, "durable staging artifact is unavailable")
            target = self._target_path(row)
            self._guard_before_possible_effect(
                row,
                message="durable admission evidence changed before publication",
            )
            try:
                _publish_exact_bytes(target, stage_raw, label="durable published artifact")
            except AuthorityRuntimeError as exc:
                try:
                    target_raw = self._verify_target_or_block(row)
                except DurableRecoveryRequired:
                    raise
                if target_raw is None:
                    self._block(row)
                    raise self._blocked_error(
                        row,
                        "durable publish outcome is unavailable",
                    ) from exc
                raise self._unavailable_error(
                    "durable publish durability proof is unavailable",
                    token=self._token_for_row(row),
                    reason_code="RECOVERY_DURABILITY_UNPROVEN",
                ) from exc
        self._record_published_attestation(row)
        _run_checkpoint("after-publish")
        try:
            self._transition(
                row,
                DurableEffectState.PREPARED,
                DurableEffectState.PUBLISHED,
            )
        except sqlite3.Error as exc:
            raise DurableRecoveryRequired(
                "durable publish state transition is unavailable",
                directive=self._directive_for_row(
                    row,
                    disposition="recoverable",
                    reason_code="RECOVERY_STATE_UNAVAILABLE",
                ),
            ) from exc
        return reference

    def publish(self, token: RecoveryToken) -> artifact_contract.SealedArtifactRef:
        with self._mutation_gate():
            return self._publish_locked(token)

    def _publish_locked(
        self,
        token: RecoveryToken,
    ) -> artifact_contract.SealedArtifactRef:
        self._require_apply()
        return self._run_bound_operation(
            token,
            lambda: self._publish_prepared(
                self._row_for_token(token, require_current_request=True),
            ),
        )

    def _finalize_published(self, row: _SnapshotEffectRow) -> artifact_contract.SealedArtifactRef:
        state = self._state(row)
        if state is DurableEffectState.BLOCKED_RECOVERY:
            raise self._blocked_error(row, "durable effect is blocked for recovery")
        if state is DurableEffectState.FINALIZED:
            return self._effect_ref(row)
        if state is not DurableEffectState.PUBLISHED:
            raise DurableRecoveryRequired(
                "durable effect is not published for finalization",
                directive=self._directive_for_row(
                    row,
                    disposition="recoverable",
                    reason_code="RECOVERY_STATE_CHANGED",
                ),
            )
        if self._verify_target_or_block(row) is None:
            self._block(row)
            raise self._blocked_error(row, "published durable effect is absent")
        try:
            binding = self._binding_for_effect_id(row["effect_id"])
            published_attestation = self.__snapshot_store.published_attestation(
                row["effect_id"]
            )
            if published_attestation is None:
                raise AuthorityRuntimeError(
                    "durable published readback is unavailable"
                )
            provisional = _durable_snapshot._SnapshotFinalCasResultValue(
                effect_id=row["effect_id"],
                binding_sha256=binding.binding_sha256,
                published_attestation_sha256=(
                    published_attestation.attestation_sha256
                ),
                expected_state=DurableEffectState.PUBLISHED.value,
                resulting_state=DurableEffectState.FINALIZED.value,
                result_sha256="",
            )
            final_result = _durable_snapshot._SnapshotFinalCasResultValue(
                effect_id=provisional.effect_id,
                binding_sha256=provisional.binding_sha256,
                published_attestation_sha256=(
                    provisional.published_attestation_sha256
                ),
                expected_state=provisional.expected_state,
                resulting_state=provisional.resulting_state,
                result_sha256=(
                    _durable_snapshot._DurableSnapshotStore.final_cas_result_sha256(
                        provisional
                    )
                ),
            )
            self.__snapshot_store.record_final_cas_result(final_result)
        except AuthorityRuntimeError as exc:
            self.__on_invalidate(exc)
            raise self._unavailable_error(
                "durable final CAS evidence is unavailable",
                token=self._token_for_row(row),
                reason_code="RECOVERY_DURABILITY_UNPROVEN",
            ) from exc
        try:
            self._transition(
                row,
                DurableEffectState.PUBLISHED,
                DurableEffectState.FINALIZED,
            )
        except sqlite3.Error as exc:
            raise DurableRecoveryRequired(
                "durable finalization state transition is unavailable",
                directive=self._directive_for_row(
                    row,
                    disposition="recoverable",
                    reason_code="RECOVERY_STATE_UNAVAILABLE",
                ),
            ) from exc
        return self._effect_ref(row)

    def finalize(self, token: RecoveryToken) -> artifact_contract.SealedArtifactRef:
        with self._mutation_gate():
            return self._finalize_locked(token)

    def _finalize_locked(
        self,
        token: RecoveryToken,
    ) -> artifact_contract.SealedArtifactRef:
        self._require_apply()
        return self._run_bound_operation(
            token,
            lambda: self._finalize_published(
                self._row_for_token(token, require_current_request=True)
            ),
        )

    def recover(self, token: RecoveryToken) -> artifact_contract.SealedArtifactRef | None:
        with self._mutation_gate():
            return self._recover_locked(token)

    def _recover_locked(
        self,
        token: RecoveryToken,
    ) -> artifact_contract.SealedArtifactRef | None:
        self._require_recovery()
        return self._run_bound_operation(
            token,
            lambda: self._recover_bound_token(token),
        )

    def _recover_bound_token(
        self,
        token: RecoveryToken,
    ) -> artifact_contract.SealedArtifactRef | None:
        if self.__recovery_token_key is None:
            raise self._block_unavailable_recovery_authority(token)
        row = self._row_for_token(token, require_current_request=False)
        state = self._state(row)
        if state is DurableEffectState.BLOCKED_RECOVERY:
            raise self._blocked_error(row, "durable effect is blocked for recovery")
        if state is DurableEffectState.FINALIZED:
            return self._effect_ref(row)
        if state is DurableEffectState.ABORTED:
            return None
        if state is DurableEffectState.PREPARED:
            if self._verify_target_or_block(row) is None:
                if self._verify_stage_or_block(row) is None:
                    self._restore_stage_or_block(row)
                self._publish_prepared(row)
            else:
                self._record_published_attestation(row)
                try:
                    self._transition(
                        row,
                        DurableEffectState.PREPARED,
                        DurableEffectState.PUBLISHED,
                    )
                except sqlite3.Error as exc:
                    raise DurableRecoveryRequired(
                        "durable recovery state transition is unavailable",
                        directive=self._directive_for_row(
                            row,
                            disposition="recoverable",
                            reason_code="RECOVERY_STATE_UNAVAILABLE",
                        ),
                    ) from exc
        return self._finalize_published(
            self._row_for_token(token, require_current_request=False)
        )

    def close(self) -> None:
        if self.__active:
            if os.getpid() != self.__owner_pid:
                raise AuthorityRuntimeError("durable coordinator inherited across fork")
            self.__active = False
            try:
                self.__snapshot_store.close()
            except BaseException as exc:
                raise exc


def _open_durable_database(
    directory: _AnchoredPath,
    lifetime_lock: _DatabaseBridgeLifetimeLock,
) -> tuple[sqlite3.Connection, _DurableDatabaseBridge]:
    if directory.parts != _RUNTIME_PARTS:
        raise AuthorityRuntimeError("durable database root is invalid")
    directory_fd = directory.anchor.open_runtime_directory()
    database_fd: Optional[int] = None
    bridge_directory: Path | None = None
    bridge_parent_fd: int | None = None
    bridge_fd: int | None = None
    database_identity: tuple[int, int] | None = None
    bridge_identity: tuple[int, int] | None = None
    bridge_linked = False
    database_bridge: _DurableDatabaseBridge | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        database_fd = os.open(_DATABASE_NAME, flags, 0o600, dir_fd=directory_fd)
        info = os.fstat(database_fd)
        lexical = os.stat(_DATABASE_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise AuthorityRuntimeError("durable database identity is invalid")
        database_identity = (info.st_dev, info.st_ino)
        os.fsync(database_fd)
        bridge_directory = Path(tempfile.mkdtemp(prefix="mnemosyne-durable-"))
        created_bridge_info = os.stat(bridge_directory, follow_symlinks=False)
        if (
            not stat.S_ISDIR(created_bridge_info.st_mode)
            or created_bridge_info.st_uid != os.getuid()
            or stat.S_IMODE(created_bridge_info.st_mode) != 0o700
        ):
            raise AuthorityRuntimeError("durable database bridge is invalid")
        bridge_parent_fd = os.open(
            str(bridge_directory.parent),
            _external_directory_flags(),
        )
        bridge_fd = os.open(
            bridge_directory.name,
            _external_directory_flags(),
            dir_fd=bridge_parent_fd,
        )
        bridge_info = os.fstat(bridge_fd)
        bridge_entry = os.stat(
            bridge_directory.name,
            dir_fd=bridge_parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(bridge_info.st_mode)
            or bridge_info.st_uid != os.getuid()
            or stat.S_IMODE(bridge_info.st_mode) != 0o700
            or (bridge_info.st_dev, bridge_info.st_ino)
            != (created_bridge_info.st_dev, created_bridge_info.st_ino)
            or (bridge_entry.st_dev, bridge_entry.st_ino)
            != (bridge_info.st_dev, bridge_info.st_ino)
        ):
            raise AuthorityRuntimeError("durable database bridge is invalid")
        bridge_identity = (bridge_info.st_dev, bridge_info.st_ino)
        os.link(
            _DATABASE_NAME,
            _DATABASE_NAME,
            src_dir_fd=directory_fd,
            dst_dir_fd=bridge_fd,
            follow_symlinks=False,
        )
        bridge_linked = True
        bridge_stat = os.stat(
            _DATABASE_NAME,
            dir_fd=bridge_fd,
            follow_symlinks=False,
        )
        if (bridge_stat.st_dev, bridge_stat.st_ino) != (info.st_dev, info.st_ino):
            raise AuthorityRuntimeError("durable database bridge is invalid")
        lease = _record_database_bridge_lease(
            directory,
            info,
            bridge_info,
        )
        database_bridge = _DurableDatabaseBridge(
            bridge_directory,
            bridge_directory / _DATABASE_NAME,
            bridge_parent_fd,
            bridge_fd,
            directory,
            lease,
            lifetime_lock,
        )
        bridge_parent_fd = None
        bridge_fd = None
    except OSError as exc:
        if database_bridge is not None:
            try:
                database_bridge.close(mutation_gate_held=True)
            except AuthorityRuntimeError:
                pass
        elif bridge_parent_fd is not None and bridge_fd is not None:
            if bridge_identity is not None:
                try:
                    _cleanup_external_database_bridge(
                        parent_fd=bridge_parent_fd,
                        bridge_fd=bridge_fd,
                        directory_name=bridge_directory.name,
                        database_identity=(
                            database_identity if bridge_linked else None
                        ),
                        bridge_identity=bridge_identity,
                    )
                except AuthorityRuntimeError:
                    pass
            try:
                _close_external_database_bridge_descriptors(
                    bridge_parent_fd,
                    bridge_fd,
                )
            except AuthorityRuntimeError:
                pass
            bridge_parent_fd = None
            bridge_fd = None
        raise AuthorityRuntimeError("durable database is unavailable") from exc
    except BaseException:
        if database_bridge is not None:
            try:
                database_bridge.close(mutation_gate_held=True)
            except AuthorityRuntimeError:
                pass
        elif bridge_parent_fd is not None and bridge_fd is not None:
            if bridge_identity is not None:
                try:
                    _cleanup_external_database_bridge(
                        parent_fd=bridge_parent_fd,
                        bridge_fd=bridge_fd,
                        directory_name=bridge_directory.name,
                        database_identity=(
                            database_identity if bridge_linked else None
                        ),
                        bridge_identity=bridge_identity,
                    )
                except AuthorityRuntimeError:
                    pass
            try:
                _close_external_database_bridge_descriptors(
                    bridge_parent_fd,
                    bridge_fd,
                )
            except AuthorityRuntimeError:
                pass
            bridge_parent_fd = None
            bridge_fd = None
        raise
    finally:
        if database_fd is not None:
            _close_descriptor(database_fd, label="durable database")
        _close_descriptor(directory_fd, label="durable root directory")
    connection: Optional[sqlite3.Connection] = None
    try:
        database_bridge.verify_sqlite_path()
        connection = sqlite3.connect(
            f"{database_bridge.path.as_uri()}?mode=rw",
            isolation_level=None,
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS durable_effects ("
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
        column_rows = tuple(
            connection.execute("PRAGMA table_info(durable_effects)")
        )
        column_names = tuple(row["name"] for row in column_rows)
        if not {"spec_identity", "spec_sha256"}.issubset(column_names):
            raise DurableRecoveryRequired(
                "durable predecessor identity is unavailable"
            )
        column_signature = tuple(
            (
                row["name"],
                row["type"],
                row["notnull"],
                row["dflt_value"],
                row["pk"],
            )
            for row in column_rows
        )
        index_signature = frozenset(
            (
                row["origin"],
                row["unique"],
                row["partial"],
                tuple(
                    member["name"]
                    for member in connection.execute(
                        "SELECT name FROM pragma_index_info(?) ORDER BY seqno",
                        (row["name"],),
                    )
                ),
            )
            for row in connection.execute("PRAGMA index_list(durable_effects)")
        )
        if (
            column_signature != _DURABLE_EFFECT_COLUMN_SIGNATURE
            or index_signature != _DURABLE_EFFECT_INDEX_SIGNATURE
        ):
            raise DurableRecoveryRequired("durable schema identity is invalid")
        return connection, database_bridge
    except DurableRecoveryRequired:
        _discard_durable_database(
            connection,
            database_bridge,
            mutation_gate_held=True,
        )
        raise
    except OSError as exc:
        _discard_durable_database(
            connection,
            database_bridge,
            mutation_gate_held=True,
        )
        raise AuthorityRuntimeError("durable database cannot open") from exc
    except sqlite3.Error as exc:
        _discard_durable_database(
            connection,
            database_bridge,
            mutation_gate_held=True,
        )
        raise AuthorityRuntimeError("durable database cannot open") from exc


def _load_or_create_recovery_token_key(
    directory: Path,
    connection: sqlite3.Connection,
) -> bytes:
    """Keep recovery tokens unforgeable even if a durable row is later corrupted."""

    def has_nonterminal_effect() -> bool:
        try:
            return bool(
                connection.execute(
                    "SELECT 1 FROM durable_effects WHERE state NOT IN (?, ?) LIMIT 1",
                    (
                        DurableEffectState.FINALIZED.value,
                        DurableEffectState.ABORTED.value,
                    ),
                ).fetchone()
            )
        except sqlite3.Error:
            return True

    key_path = directory / _RECOVERY_TOKEN_KEY_NAME
    try:
        raw = _try_read_verified_bytes(key_path)
    except AuthorityRuntimeError as exc:
        if has_nonterminal_effect():
            raise _RecoveryTokenKeyUnavailable() from exc
        raise AuthorityRuntimeError("durable recovery token key is unavailable") from exc
    if raw is None:
        if has_nonterminal_effect():
            raise _RecoveryTokenKeyUnavailable()
        candidate = secrets.token_bytes(_RECOVERY_TOKEN_KEY_BYTES)
        try:
            _publish_exact_bytes(
                key_path,
                candidate,
                label="durable recovery token key",
            )
            raw = candidate
        except AuthorityRuntimeError as exc:
            try:
                raw = _try_read_verified_bytes(key_path)
            except AuthorityRuntimeError as read_exc:
                if has_nonterminal_effect():
                    raise _RecoveryTokenKeyUnavailable() from read_exc
                raise AuthorityRuntimeError(
                    "durable recovery token key is unavailable"
                ) from read_exc
            if raw != candidate:
                if has_nonterminal_effect():
                    raise _RecoveryTokenKeyUnavailable() from exc
                raise AuthorityRuntimeError(
                    "durable recovery token key is unavailable"
                ) from exc
    if type(raw) is not bytes or len(raw) != _RECOVERY_TOKEN_KEY_BYTES:
        if has_nonterminal_effect():
            raise _RecoveryTokenKeyUnavailable()
        raise AuthorityRuntimeError("durable recovery token key is invalid")
    try:
        attested_key_sha256 = _read_key_attestation(directory)
    except (AuthorityRuntimeError, ValueError) as exc:
        if has_nonterminal_effect():
            raise _RecoveryTokenKeyUnavailable() from exc
        raise AuthorityRuntimeError(
            "durable recovery token key attestation is unavailable"
        ) from exc
    if attested_key_sha256 is None:
        if has_nonterminal_effect():
            raise _RecoveryTokenKeyUnavailable()
        try:
            attested_key_sha256 = _record_key_attestation(directory, raw)
        except (AuthorityRuntimeError, ValueError) as exc:
            raise AuthorityRuntimeError(
                "durable recovery token key attestation is unavailable"
            ) from exc
    if attested_key_sha256 != sha256_bytes(raw):
        if has_nonterminal_effect():
            raise _RecoveryTokenKeyUnavailable()
        raise AuthorityRuntimeError("durable recovery token key identity is invalid")
    return raw


def _policy_identity_digest(identity: object) -> str:
    fields = (
        "raw_hash",
        "full_hash",
        "writer_control_hash",
        "foundation_hash",
        "generation",
        "source_kind",
        "source_run_id",
        "guard_epoch",
    )
    try:
        value = {field: getattr(identity, field) for field in fields}
    except AttributeError as exc:
        raise AuthorityRuntimeError("durable policy identity is invalid") from exc
    return sha256_bytes(canonical_json_bytes(value))


def _state_from_row(row: _SnapshotEffectRow) -> DurableEffectState:
    try:
        return DurableEffectState(row["state"])
    except ValueError as exc:
        raise DurableRecoveryRequired("durable effect state is invalid") from exc


def _try_read_verified_bytes(path: Path | _AnchoredPath) -> Optional[bytes]:
    if isinstance(path, _AnchoredPath):
        return path.anchor.read_bytes(path)
    try:
        os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuthorityRuntimeError("durable artifact metadata is unavailable") from exc
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=AuthorityRuntimeError,
    )
    try:
        _info, raw = safety.read_regular_file_at(
            parent_fd,
            path.name,
            path,
            label="durable artifact",
            expected_mode=0o600,
            max_bytes=_MAX_ARTIFACT_BYTES,
            error_type=AuthorityRuntimeError,
        )
        return raw
    finally:
        os.close(parent_fd)


def _read_finalized_artifacts(
    root: Path,
    *,
    root_identity: tuple[int, int],
    effect_prefixes: tuple[str, ...],
    offset: int,
    max_items: int,
) -> tuple[tuple[str, artifact_contract.SealedArtifactRef, bytes], ...]:
    """Read a bounded immutable projection without taking the writer lease."""

    if (
        type(effect_prefixes) is not tuple
        or not effect_prefixes
        or any(
            type(prefix) is not str
            or not prefix
            or _EFFECT_ID.fullmatch(prefix + "x") is None
            for prefix in effect_prefixes
        )
        or type(offset) is not int
        or offset < 0
        or type(max_items) is not int
        or not 1 <= max_items <= 16385
    ):
        raise ValueError("durable artifact projection bounds are invalid")
    anchor = _RootAnchor.open(root, expected_identity=root_identity)
    connection: sqlite3.Connection | None = None
    try:
        _durable_snapshot._DurableSnapshotStore._require_no_root_stop(anchor)
        identities = (
            _durable_snapshot._DurableSnapshotStore._snapshot_namespace_identities(
                anchor
            )
        )
        discovered = _durable_snapshot._DurableSnapshotStore._discover_tip(
            anchor,
            identities,
        )
        if discovered is None:
            return ()
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.deserialize(discovered[2])
        clauses = " OR ".join("effect_id LIKE ?" for _prefix in effect_prefixes)
        rows = connection.execute(
            "SELECT effect_id, target_relative_path, artifact_ref, artifact_bytes "
            "FROM durable_effects WHERE state = 'FINALIZED' AND ("
            + clauses
            + ") ORDER BY effect_id LIMIT ? OFFSET ?",
            tuple(prefix + "%" for prefix in effect_prefixes)
            + (max_items, offset),
        ).fetchall()
        result = []
        for row in rows:
            reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
                bytes(row["artifact_ref"])
            )
            artifact_bytes = bytes(row["artifact_bytes"])
            reference.verify_bytes(artifact_bytes)
            if reference.canonical_path != row["target_relative_path"]:
                raise AuthorityRuntimeError(
                    "durable artifact projection target is invalid"
                )
            result.append((str(row["effect_id"]), reference, artifact_bytes))
        return tuple(result)
    except (sqlite3.Error, ValueError) as exc:
        raise AuthorityRuntimeError(
            "durable artifact projection is unavailable"
        ) from exc
    finally:
        if connection is not None:
            connection.close()
        anchor.close()


def _publish_exact_bytes(
    path: Path | _AnchoredPath,
    raw: bytes,
    *,
    label: str,
) -> None:
    if isinstance(path, _AnchoredPath):
        path.anchor.publish_bytes(path, raw, label=label)
        return

    def verify_readback(_path: Path, fd: int, _directory_fd: int) -> None:
        if safety.read_open_file_bytes(fd) != raw:
            raise AuthorityRuntimeError(f"{label} readback is invalid")

    safety.publish_bytes_atomic_no_replace(
        path,
        raw,
        label=label,
        mode=0o600,
        create_parent=True,
        collision_error=f"{label} already exists",
        final_identity_error=f"{label} final identity is invalid",
        parent_error=f"{label} parent is unavailable",
        error_type=AuthorityRuntimeError,
        after_fd_readback=verify_readback,
    )


def _run_checkpoint(point: str) -> None:
    """Private test seam for process-boundary crash regression coverage."""
