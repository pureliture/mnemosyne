"""Anchored read-only evidence for Safe Librarian first activation."""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from .. import (
    activation_contract,
    activation_foundation,
    activation_markers,
    artifact_contract,
    control,
    ledger_schema,
    operation_contract,
    safety,
)
from ..canonical_json import canonical_json_bytes, sha256_bytes
from ..operation_contract import codec as operation_codec
from . import ActivationOperationFence, AuthorityRuntimeError


MAX_REGISTRY_BYTES = 4 * 1024 * 1024
_SENTINELS = (
    "curation",
    "placement-map.lock",
    "lock-migrations",
    "curation-runs",
)

_RECOVERY_MARKER_STATES = frozenset(
    {
        activation_markers.ActivationMarkerState.REQUEST_TEMP,
        activation_markers.ActivationMarkerState.REQUEST_SEALED,
        activation_markers.ActivationMarkerState.LEDGER_LOCK_ONLY,
        activation_markers.ActivationMarkerState.LOCKS_READY,
        activation_markers.ActivationMarkerState.EMPTY_STAGING_LEDGER,
        activation_markers.ActivationMarkerState.STAGING_LEDGER_READY,
        activation_markers.ActivationMarkerState.FINAL_LEDGER_READY,
        activation_markers.ActivationMarkerState.RECEIPT_TEMP,
    }
)

_FENCE_ACTIONS = {
    "ALREADY_ACTIVE_DIFFERENT_REQUEST": "review-original-request",
    "EXPLICIT_CURATION_REQUIRES_REVIEW": "manual-review",
    "FOUNDATION_READBACK_FAILED": "manual-review",
    "LEGACY_AUTHORITY_PRESENT": "manual-review",
    "POLICY_IDENTITY_CHANGED": "repeat-audit",
    "PRESEAL_ORPHAN": "manual-review",
    "PUBLICATION_COLLISION": "manual-review",
    "REQUEST_MISMATCH": "review-original-request",
    "ROOT_IDENTITY_CHANGED": "verify-root",
    "UNKNOWN_AUTHORITY_MEMBER": "manual-review",
    "UNSAFE_BOUNDARY": "manual-review",
    "WRITER_BUSY": "inspect-current-activation",
}


def _activation_fence(reason_code: str, message: str) -> ActivationOperationFence:
    try:
        next_safe_action = _FENCE_ACTIONS[reason_code]
    except KeyError as exc:
        raise AuthorityRuntimeError("activation marker reason is unsupported") from exc
    return ActivationOperationFence(
        message,
        reason_code=reason_code,
        next_safe_action=next_safe_action,
    )


@dataclass(frozen=True)
class ActivationAuditEvidence:
    """Immutable admission evidence for one bounded activation audit."""

    exact_root: str
    root_identity_sha256: str
    registry_identity_sha256: str
    placement_identity_sha256: str
    sentinel_observations: tuple[tuple[object, ...], ...]
    activation_state: str
    activation_eligible: bool
    reason_code: str
    next_safe_action: str
    initial_policy: activation_foundation.InitialPolicyIdentity | None

    def public_fields(self) -> dict[str, object]:
        return {
            "exact_root": self.exact_root,
            "activation_state": self.activation_state,
            "activation_eligible": self.activation_eligible,
            "reason_code": self.reason_code,
            "next_safe_action": self.next_safe_action,
            "allowed_namespace": "_registry/curation",
            "corpus_effect": "none",
            "root_identity_sha256": self.root_identity_sha256,
            "initial_policy": (
                None if self.initial_policy is None else self.initial_policy.as_dict()
            ),
        }


@dataclass(frozen=True)
class ActivationAdmissionEvidence:
    """Immutable marker and boundary evidence sealed during write admission."""

    audit: ActivationAuditEvidence
    request_sha256: str
    markers: activation_markers.ActivationMarkerEvidence
    receipt_sha256: str | None


def _directory_identity_sha256(path: Path, info: os.stat_result) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "canonical_path": str(path),
                "device": info.st_dev,
                "inode": info.st_ino,
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
            }
        )
    )


def _file_identity_sha256(path: Path, info: os.stat_result) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "canonical_path": str(path),
                "device": info.st_dev,
                "inode": info.st_ino,
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "nlink": info.st_nlink,
                "size": info.st_size,
                "mtime_ns": info.st_mtime_ns,
                "ctime_ns": info.st_ctime_ns,
            }
        )
    )


def _sentinel_observations(
    directory_fd: int,
) -> tuple[tuple[object, ...], ...]:
    observed = []
    for name in _SENTINELS:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuthorityRuntimeError(
                "activation audit sentinel is unavailable"
            ) from exc
        observed.append(
            (
                name,
                stat.S_IFMT(info.st_mode),
                info.st_dev,
                info.st_ino,
                stat.S_IMODE(info.st_mode),
                info.st_nlink,
            )
        )
    return tuple(observed)


def _read_registry(
    registry_fd: int,
    registry_path: Path,
) -> tuple[os.stat_result, bytes]:
    info, raw = safety.read_regular_file_at(
        registry_fd,
        "placement-map.yml",
        registry_path,
        label="activation policy input",
        expected_mode=None,
        max_bytes=MAX_REGISTRY_BYTES,
        error_type=AuthorityRuntimeError,
    )
    if info.st_nlink != 1:
        raise AuthorityRuntimeError("activation policy input identity is unsafe")
    return info, raw


def _classify_markers(
    root: Path,
    *,
    incoming_request: operation_contract.OperationRequest | None = None,
) -> activation_markers.ActivationMarkerEvidence:
    registry_fd = safety.open_verified_directory(
        root / "_registry",
        require_owner_only=True,
        error_type=AuthorityRuntimeError,
    )
    try:
        return activation_markers.classify_activation_markers(
            registry_fd,
            root,
            incoming_request=incoming_request,
        )
    finally:
        os.close(registry_fd)


def _marker_reason(marker: activation_markers.ActivationMarkerEvidence) -> str:
    return marker.reason_code.value


def _raise_marker_fence(
    marker: activation_markers.ActivationMarkerEvidence,
) -> None:
    reason_code = _marker_reason(marker)
    raise _activation_fence(reason_code, "activation marker requires manual review")


def _blocked_boundary_evidence(
    canonical_root: Path,
    root_info: os.stat_result,
    *,
    registry_identity_sha256: str = "",
    placement_identity_sha256: str = "",
    sentinel_observations: tuple[tuple[object, ...], ...] = (),
    reason_code: str = "UNSAFE_BOUNDARY",
    next_safe_action: str = "Review the unsafe authority boundary manually.",
) -> ActivationAuditEvidence:
    return ActivationAuditEvidence(
        exact_root=str(canonical_root),
        root_identity_sha256=_directory_identity_sha256(canonical_root, root_info),
        registry_identity_sha256=registry_identity_sha256,
        placement_identity_sha256=placement_identity_sha256,
        sentinel_observations=sentinel_observations,
        activation_state="BLOCKED",
        activation_eligible=False,
        reason_code=reason_code,
        next_safe_action=next_safe_action,
        initial_policy=None,
    )


def capture_audit_evidence(
    root: Path,
    *,
    runtime_state: str | None = None,
) -> ActivationAuditEvidence:
    """Capture and recapture one bounded, no-follow activation observation."""

    canonical_root = Path(root)
    if not canonical_root.is_absolute():
        raise AuthorityRuntimeError("activation audit root is not absolute")
    root_fd = safety.open_verified_directory(
        canonical_root,
        require_owner_only=True,
        error_type=AuthorityRuntimeError,
    )
    try:
        root_info = os.fstat(root_fd)
        registry_path = canonical_root / "_registry"
        try:
            registry_fd = safety.open_verified_directory(
                registry_path,
                require_owner_only=True,
                error_type=AuthorityRuntimeError,
            )
        except AuthorityRuntimeError:
            safety.require_same_directory_identity(
                canonical_root,
                root_fd,
                "activation root",
                error_type=AuthorityRuntimeError,
            )
            return _blocked_boundary_evidence(canonical_root, root_info)
        try:
            registry_info = os.fstat(registry_fd)
            registry_identity = _directory_identity_sha256(
                registry_path,
                registry_info,
            )
            registry_file = registry_path / "placement-map.yml"
            try:
                placement_info, registry_raw = _read_registry(
                    registry_fd,
                    registry_file,
                )
            except AuthorityRuntimeError:
                safety.require_same_directory_identity(
                    canonical_root,
                    root_fd,
                    "activation root",
                    error_type=AuthorityRuntimeError,
                )
                safety.require_same_directory_identity(
                    registry_path,
                    registry_fd,
                    "activation registry",
                    error_type=AuthorityRuntimeError,
                )
                return _blocked_boundary_evidence(
                    canonical_root,
                    root_info,
                    registry_identity_sha256=registry_identity,
                )
            placement_identity = _file_identity_sha256(
                registry_file,
                placement_info,
            )
            observations = _sentinel_observations(registry_fd)
            present_names = {value[0] for value in observations}
            unsafe_sentinel = any(
                value[1] == stat.S_IFLNK for value in observations
            )
            legacy_present = bool(present_names - {"curation"})
            if unsafe_sentinel:
                state = "BLOCKED"
                eligible = False
                reason_code = "UNSAFE_BOUNDARY"
                initial_policy = None
            elif legacy_present:
                state = "BLOCKED"
                eligible = False
                reason_code = "LEGACY_AUTHORITY_PRESENT"
                initial_policy = None
            elif "curation" in present_names:
                markers = activation_markers.classify_activation_markers(
                    registry_fd,
                    canonical_root,
                )
                if markers.state is activation_markers.ActivationMarkerState.ACTIVE:
                    if runtime_state not in {None, "ACTIVE"}:
                        raise AuthorityRuntimeError(
                            "activation audit control state changed"
                        )
                    state = "ACTIVE"
                    eligible = False
                    reason_code = "ALREADY_ACTIVE"
                    initial_policy = None
                elif markers.state in _RECOVERY_MARKER_STATES:
                    state = "RECOVERY_REQUIRED"
                    eligible = False
                    reason_code = "RECOVERY_SAME_REQUEST_ONLY"
                    initial_policy = None
                elif (
                    markers.state
                    is activation_markers.ActivationMarkerState.PRESEAL_ORPHAN
                ):
                    state = "RECOVERY_REQUIRED"
                    eligible = False
                    reason_code = "PRESEAL_ORPHAN"
                    initial_policy = None
                elif markers.state in {
                    activation_markers.ActivationMarkerState.LEGACY,
                    activation_markers.ActivationMarkerState.MANUAL_FENCE,
                }:
                    state = "BLOCKED"
                    eligible = False
                    reason_code = _marker_reason(markers)
                    initial_policy = None
                else:
                    raise AuthorityRuntimeError(
                        "activation audit marker state is invalid"
                    )
            elif runtime_state is not None:
                raise AuthorityRuntimeError("activation audit control state changed")
            else:
                try:
                    initial_policy = activation_foundation.compile_initial_policy(
                        registry_raw,
                        str(canonical_root),
                    )
                except activation_foundation.ExplicitCurationPolicyError:
                    state = "BLOCKED"
                    eligible = False
                    reason_code = "EXPLICIT_CURATION_REQUIRES_REVIEW"
                    initial_policy = None
                except (TypeError, ValueError):
                    state = "BLOCKED"
                    eligible = False
                    reason_code = "UNSAFE_BOUNDARY"
                    initial_policy = None
                else:
                    state = "NOT_ACTIVATED"
                    eligible = True
                    reason_code = "FRESH_CURATION_STATE"

            next_action = activation_contract.audit_next_safe_action(
                state,
                reason_code,
            )

            final_info, final_raw = _read_registry(registry_fd, registry_file)
            final_observations = _sentinel_observations(registry_fd)
            safety.require_same_directory_identity(
                canonical_root,
                root_fd,
                "activation root",
                error_type=AuthorityRuntimeError,
            )
            safety.require_same_directory_identity(
                registry_path,
                registry_fd,
                "activation registry",
                error_type=AuthorityRuntimeError,
            )
            if (
                _file_identity_sha256(registry_file, final_info)
                != placement_identity
                or final_raw != registry_raw
                or final_observations != observations
            ):
                raise AuthorityRuntimeError(
                    "activation audit evidence changed during read"
                )
            return ActivationAuditEvidence(
                exact_root=str(canonical_root),
                root_identity_sha256=_directory_identity_sha256(
                    canonical_root,
                    root_info,
                ),
                registry_identity_sha256=registry_identity,
                placement_identity_sha256=placement_identity,
                sentinel_observations=observations,
                activation_state=state,
                activation_eligible=eligible,
                reason_code=reason_code,
                next_safe_action=next_action,
                initial_policy=initial_policy,
            )
        finally:
            os.close(registry_fd)
    finally:
        os.close(root_fd)


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _regular_open_flags(*, exclusive: bool = False) -> int:
    flags = os.O_RDWR
    if exclusive:
        flags |= os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _read_open_file(fd: int, *, maximum: int = 64 * 1024 * 1024) -> bytes:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise AuthorityRuntimeError("activation artifact exceeds byte budget")
    except OSError as exc:
        raise AuthorityRuntimeError("activation artifact readback failed") from exc


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    try:
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise AuthorityRuntimeError("activation artifact write made no progress")
            offset += written
    except OSError as exc:
        raise AuthorityRuntimeError("activation artifact write failed") from exc


def _require_directory_entry(
    parent_fd: int,
    name: str,
    path: Path,
) -> int:
    try:
        lexical = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        child_fd = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
        opened = os.fstat(child_fd)
    except OSError as exc:
        raise AuthorityRuntimeError(f"activation directory is unavailable: {path}") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
    ):
        os.close(child_fd)
        raise AuthorityRuntimeError(f"activation directory identity is invalid: {path}")
    return child_fd


def _create_directory_at(
    parent_fd: int,
    name: str,
    path: Path,
) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError as exc:
        raise _activation_fence(
            "PUBLICATION_COLLISION",
            "activation directory publication collided",
        ) from exc
    except OSError as exc:
        raise AuthorityRuntimeError(
            f"activation directory creation failed: {path}"
        ) from exc
    child_fd = _require_directory_entry(parent_fd, name, path)
    try:
        os.fchmod(child_fd, 0o700)
        os.fsync(child_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        os.close(child_fd)
        raise AuthorityRuntimeError(f"activation directory durability failed: {path}") from exc
    return child_fd


def _require_regular_identity(
    directory_fd: int,
    name: str,
    path: Path,
    *,
    expected_mode: int = 0o600,
) -> os.stat_result:
    try:
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        fd = os.open(name, _regular_open_flags(), dir_fd=directory_fd)
        try:
            opened = os.fstat(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise AuthorityRuntimeError(f"activation file is unavailable: {path}") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
    ):
        raise AuthorityRuntimeError(f"activation file identity is invalid: {path}")
    return opened


def _read_regular_bytes(
    directory_fd: int,
    name: str,
    path: Path,
    *,
    maximum: int = 64 * 1024 * 1024,
) -> bytes:
    _info, raw = safety.read_regular_file_at(
        directory_fd,
        name,
        path,
        label="activation artifact",
        expected_mode=0o600,
        max_bytes=maximum,
        error_type=AuthorityRuntimeError,
    )
    return raw


def _publish_exact_bytes(
    directory_fd: int,
    directory_path: Path,
    *,
    temporary_name: str,
    final_name: str,
    raw: bytes,
    temporary_checkpoint: str,
    before_final_publish: Callable[[], object],
) -> None:
    temporary_path = directory_path / temporary_name
    final_path = directory_path / final_name
    try:
        fd = os.open(
            temporary_name,
            _regular_open_flags(exclusive=True),
            0o600,
            dir_fd=directory_fd,
        )
    except FileExistsError as exc:
        raise _activation_fence(
            "PUBLICATION_COLLISION",
            "activation staging file already exists",
        ) from exc
    except OSError as exc:
        raise AuthorityRuntimeError(
            f"activation staging file is unavailable: {temporary_path}"
        ) from exc
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, raw)
        os.fsync(fd)
        opened = os.fstat(fd)
        lexical = os.stat(
            temporary_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
            or _read_open_file(fd) != raw
        ):
            raise AuthorityRuntimeError(
                f"activation staging file readback failed: {temporary_path}"
            )
        _checkpoint(temporary_checkpoint)
        before_final_publish()
        collision_message = f"activation final file collision: {final_path}"
        try:
            safety.rename_entry_no_replace_at(
                directory_fd,
                temporary_name,
                directory_fd,
                final_name,
                collision_error=collision_message,
                error_type=AuthorityRuntimeError,
            )
        except AuthorityRuntimeError as exc:
            if str(exc) != collision_message:
                raise
            raise _activation_fence(
                "PUBLICATION_COLLISION",
                "activation final file publication collided",
            ) from exc
        os.fsync(directory_fd)
        final = os.stat(final_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or _read_open_file(fd) != raw
        ):
            raise AuthorityRuntimeError(
                f"activation final file readback failed: {final_path}"
            )
    except AuthorityRuntimeError:
        raise
    except OSError as exc:
        raise AuthorityRuntimeError(
            f"activation artifact publication failed: {final_path}"
        ) from exc
    finally:
        os.close(fd)


def _publish_existing_exact_bytes(
    directory_fd: int,
    directory_path: Path,
    *,
    temporary_name: str,
    final_name: str,
    raw: bytes,
) -> None:
    temporary_path = directory_path / temporary_name
    final_path = directory_path / final_name
    _require_regular_identity(directory_fd, temporary_name, temporary_path)
    if _read_regular_bytes(
        directory_fd,
        temporary_name,
        temporary_path,
        maximum=max(1024 * 1024, len(raw)),
    ) != raw:
        raise AuthorityRuntimeError(
            f"activation staging file readback failed: {temporary_path}"
        )
    collision_message = f"activation final file collision: {final_path}"
    try:
        safety.rename_entry_no_replace_at(
            directory_fd,
            temporary_name,
            directory_fd,
            final_name,
            collision_error=collision_message,
            error_type=AuthorityRuntimeError,
        )
    except AuthorityRuntimeError as exc:
        if str(exc) != collision_message:
            raise
        raise _activation_fence(
            "PUBLICATION_COLLISION",
            "activation final file publication collided",
        ) from exc
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise AuthorityRuntimeError(
            f"activation final file durability failed: {final_path}"
        ) from exc
    _require_regular_identity(directory_fd, final_name, final_path)
    if _read_regular_bytes(
        directory_fd,
        final_name,
        final_path,
        maximum=max(1024 * 1024, len(raw)),
    ) != raw:
        raise AuthorityRuntimeError(
            f"activation final file readback failed: {final_path}"
        )


def _create_empty_file(
    directory_fd: int,
    name: str,
    path: Path,
) -> None:
    try:
        fd = os.open(
            name,
            _regular_open_flags(exclusive=True),
            0o600,
            dir_fd=directory_fd,
        )
    except FileExistsError as exc:
        raise _activation_fence(
            "PUBLICATION_COLLISION",
            "activation file publication collided",
        ) from exc
    except OSError as exc:
        raise AuthorityRuntimeError(f"activation file creation failed: {path}") from exc
    try:
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        opened = os.fstat(fd)
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
            or _read_open_file(fd) != b""
        ):
            raise AuthorityRuntimeError(f"activation file readback failed: {path}")
        os.fsync(directory_fd)
    except AuthorityRuntimeError:
        raise
    except OSError as exc:
        raise AuthorityRuntimeError(f"activation file durability failed: {path}") from exc
    finally:
        os.close(fd)


def _checkpoint(_boundary: str) -> None:
    """Private crash-injection seam; production does nothing."""


def _request_policy_matches(
    request: operation_contract.OperationRequest,
    audit: ActivationAuditEvidence,
) -> bool:
    return (
        request.root == audit.exact_root
        and request.payload["root_identity_sha256"] == audit.root_identity_sha256
        and audit.initial_policy is not None
        and dict(request.payload["initial_policy"]) == audit.initial_policy.as_dict()
        and request.payload["allowed_namespace"] == "_registry/curation"
        and request.payload["corpus_effect"] == "none"
    )


def _require_exact_names(fd: int, expected: set[str], label: str) -> None:
    try:
        observed = set(os.listdir(fd))
    except OSError as exc:
        raise AuthorityRuntimeError(f"{label} inventory is unavailable") from exc
    if observed != expected:
        raise AuthorityRuntimeError(f"{label} inventory is invalid")


def _open_activation_protocol_tree(
    root: Path,
) -> tuple[int, int, int, int, int]:
    registry_path = root / "_registry"
    curation_path = registry_path / "curation"
    activation_path = curation_path / "activation"
    version_path = activation_path / "v1"
    staging_path = version_path / "staging"
    registry_fd = safety.open_verified_directory(
        registry_path,
        require_owner_only=True,
        error_type=AuthorityRuntimeError,
    )
    opened: list[int] = [registry_fd]
    try:
        curation_fd = _require_directory_entry(registry_fd, "curation", curation_path)
        opened.append(curation_fd)
        activation_fd = _require_directory_entry(
            curation_fd,
            "activation",
            activation_path,
        )
        opened.append(activation_fd)
        version_fd = _require_directory_entry(activation_fd, "v1", version_path)
        opened.append(version_fd)
        staging_fd = _require_directory_entry(version_fd, "staging", staging_path)
        opened.append(staging_fd)
        return tuple(opened)  # type: ignore[return-value]
    except BaseException:
        for fd in reversed(opened):
            os.close(fd)
        raise


def _close_fds(fds: tuple[int, ...]) -> None:
    for fd in reversed(fds):
        os.close(fd)


def _verify_completed_activation(
    root: Path,
    request: operation_contract.OperationRequest,
) -> tuple[artifact_contract.SealedArtifactRef, str]:
    fds = _open_activation_protocol_tree(root)
    registry_fd, curation_fd, activation_fd, version_fd, staging_fd = fds
    try:
        markers = activation_markers.classify_activation_markers(
            registry_fd,
            root,
            incoming_request=request,
        )
        if markers.state is activation_markers.ActivationMarkerState.MANUAL_FENCE:
            _raise_marker_fence(markers)
        if markers.state is not activation_markers.ActivationMarkerState.ACTIVE:
            raise AuthorityRuntimeError("activation foundation is not active")
        _require_exact_names(activation_fd, {"v1"}, "activation protocol")
        _require_exact_names(
            version_fd,
            {"request.json", "receipt.json", "staging"},
            "activation protocol version",
        )
        _require_exact_names(staging_fd, set(), "activation staging")
        for name in ("ledger.lock", "ledger.sqlite3", "policy.lock"):
            _require_regular_identity(
                curation_fd,
                name,
                root / "_registry" / "curation" / name,
            )
        request_path = root / "_registry" / "curation" / "activation" / "v1" / "request.json"
        receipt_path = root / activation_contract.RECEIPT_PATH
        request_raw = _read_regular_bytes(
            version_fd,
            "request.json",
            request_path,
            maximum=1024 * 1024,
        )
        stored_request = operation_codec.decode_operation_request(request_raw)
        activation_contract.validate_activation_request(stored_request)
        if stored_request.canonical_bytes != request.canonical_bytes:
            raise AuthorityRuntimeError("activation request does not match completed state")
        placement_info, registry_raw = _read_registry(
            registry_fd,
            root / "_registry" / "placement-map.yml",
        )
        plan = activation_foundation.build_activation_foundation(
            registry_raw,
            str(root),
            request.scope["activation_id"],
        )
        if dict(request.payload["initial_policy"]) != plan.initial_policy.as_dict():
            raise AuthorityRuntimeError("activation policy identity changed")
        readback = activation_foundation.verify_activation_ledger(
            root / "_registry" / "curation" / "ledger.sqlite3",
            plan,
        )
        receipt_raw = _read_regular_bytes(
            version_fd,
            "receipt.json",
            receipt_path,
            maximum=1024 * 1024,
        )
        receipt = activation_contract.require_activation_receipt_bytes(
            receipt_raw,
            request=request,
            expected_uid=os.getuid(),
        )
        if (
            receipt["logical_readback_sha256"] != readback.sha256
            or receipt["initial_snapshot_identity"]["snapshot_id"]
            != plan.snapshot_id
        ):
            raise AuthorityRuntimeError("activation receipt readback is invalid")
        final_info, final_raw = _read_registry(
            registry_fd,
            root / "_registry" / "placement-map.yml",
        )
        if (
            _file_identity_sha256(
                root / "_registry" / "placement-map.yml",
                final_info,
            )
            != _file_identity_sha256(
                root / "_registry" / "placement-map.yml",
                placement_info,
            )
            or final_raw != registry_raw
        ):
            raise AuthorityRuntimeError("activation policy input changed during readback")
        reference = activation_contract.activation_receipt_reference(
            receipt_raw,
            request_sha256=request.sha256,
        )
        return reference, sha256_bytes(receipt_raw)
    except (TypeError, ValueError) as exc:
        raise AuthorityRuntimeError("activation foundation readback failed") from exc
    finally:
        _close_fds(fds)


def capture_admission_evidence(
    root: Path,
    request: operation_contract.OperationRequest,
) -> ActivationAdmissionEvidence:
    """Capture exact fresh, recoverable, or completed activation evidence."""

    activation_contract.validate_activation_request(request)
    canonical_root = Path(root)
    if request.root != str(canonical_root):
        raise AuthorityRuntimeError("activation request root is not exact")
    markers = _classify_markers(
        canonical_root,
        incoming_request=request,
    )
    if markers.state is activation_markers.ActivationMarkerState.FRESH:
        audit = capture_audit_evidence(canonical_root)
        if audit.activation_state != "NOT_ACTIVATED" or not _request_policy_matches(
            request,
            audit,
        ):
            raise _activation_fence(
                "POLICY_IDENTITY_CHANGED",
                "activation policy identity changed",
            )
        return ActivationAdmissionEvidence(
            audit=audit,
            request_sha256=request.sha256,
            markers=markers,
            receipt_sha256=None,
        )
    if markers.state is activation_markers.ActivationMarkerState.ACTIVE:
        _reference, receipt_sha256 = _verify_completed_activation(
            canonical_root,
            request,
        )
        audit = capture_audit_evidence(canonical_root, runtime_state="ACTIVE")
        if audit.activation_state != "ACTIVE":
            raise AuthorityRuntimeError(
                "activation foundation is not exclusively active"
            )
        if markers.receipt_sha256 != receipt_sha256:
            raise AuthorityRuntimeError("activation receipt identity changed")
        return ActivationAdmissionEvidence(
            audit=audit,
            request_sha256=request.sha256,
            markers=markers,
            receipt_sha256=receipt_sha256,
        )
    if markers.state in _RECOVERY_MARKER_STATES:
        audit = capture_audit_evidence(
            canonical_root,
            runtime_state="RECOVERY_REQUIRED",
        )
        if (
            audit.activation_state != "RECOVERY_REQUIRED"
            or audit.reason_code != "RECOVERY_SAME_REQUEST_ONLY"
            or markers.stored_request_bytes != request.canonical_bytes
            or markers.stored_request_sha256 != request.sha256
        ):
            raise AuthorityRuntimeError("activation recovery evidence is invalid")
        return ActivationAdmissionEvidence(
            audit=audit,
            request_sha256=request.sha256,
            markers=markers,
            receipt_sha256=None,
        )
    _raise_marker_fence(markers)


def _receipt_value(
    request: operation_contract.OperationRequest,
    readback: object,
    snapshot_id: str,
) -> dict[str, object]:
    initial_policy = activation_contract.require_initial_policy(
        request.payload["initial_policy"]
    )
    activation_id = request.scope["activation_id"]
    return {
        "schema": activation_contract.RECEIPT_SCHEMA.canonical_value,
        "kind": activation_contract.RECEIPT_SCHEMA.kind,
        "status": "ACTIVE",
        "activation_id": activation_id,
        "request_sha256": request.sha256,
        "actor": request.actor,
        "exact_root": request.root,
        "root_identity_sha256": request.payload["root_identity_sha256"],
        "allowed_namespace": "_registry/curation",
        "corpus_effect": "none",
        "initial_policy": initial_policy,
        "schema_identity": {
            "control": {
                "applied_by": activation_id,
                "schema_sha256": control.CONTROL_SCHEMA_SHA256,
                "version": control.CONTROL_SCHEMA_VERSION,
            },
            "ledger": {
                "applied_by": activation_contract.ACTIVATION_V2_SOURCE_ID,
                "schema_sha256": ledger_schema.LEDGER_SCHEMA_SHA256,
                "version": ledger_schema.LEDGER_SCHEMA_VERSION,
            },
        },
        "initial_snapshot_identity": {
            "foundation_hash": initial_policy["foundation_hash"],
            "full_hash": initial_policy["full_hash"],
            "generation": 1,
            "guard_epoch": 0,
            "snapshot_id": snapshot_id,
            "source_kind": "INITIAL",
            "source_run_id": activation_id,
            "state": "TERMINAL",
            "writer_control_hash": initial_policy["writer_control_hash"],
        },
        "write_set": activation_contract.activation_write_set(os.getuid()),
        "control_bootstrap_rows": 0,
        "legacy_evidence": False,
        "logical_readback_sha256": getattr(readback, "sha256"),
    }


class ActivationSession:
    """One-shot, exact-prefix activation capability exposed to one handler."""

    __slots__ = (
        "__root",
        "__root_fd",
        "__registry_fd",
        "__request",
        "__evidence",
        "__active",
        "__used",
    )

    def __init__(
        self,
        root: Path,
        root_fd: int,
        registry_fd: int,
        request: operation_contract.OperationRequest,
        evidence: ActivationAdmissionEvidence,
    ) -> None:
        self.__root = root
        self.__root_fd = root_fd
        self.__registry_fd = registry_fd
        self.__request = request
        self.__evidence = evidence
        self.__active = True
        self.__used = False

    def _require_active(self) -> None:
        if not self.__active or self.__used:
            raise AuthorityRuntimeError("activation session is not active")

    def _revalidate_boundary(self) -> bytes:
        try:
            safety.require_same_directory_identity(
                self.__root,
                self.__root_fd,
                "activation root",
                error_type=AuthorityRuntimeError,
            )
            root_identity = _directory_identity_sha256(
                self.__root,
                os.fstat(self.__root_fd),
            )
        except (OSError, AuthorityRuntimeError) as exc:
            raise _activation_fence(
                "ROOT_IDENTITY_CHANGED",
                "activation root identity changed",
            ) from exc
        if (
            root_identity != self.__evidence.audit.root_identity_sha256
            or root_identity
            != self.__request.payload["root_identity_sha256"]
        ):
            raise _activation_fence(
                "ROOT_IDENTITY_CHANGED",
                "activation root identity changed",
            )
        try:
            safety.require_same_directory_identity(
                self.__root / "_registry",
                self.__registry_fd,
                "activation registry",
                error_type=AuthorityRuntimeError,
            )
            registry_identity = _directory_identity_sha256(
                self.__root / "_registry",
                os.fstat(self.__registry_fd),
            )
        except (OSError, AuthorityRuntimeError) as exc:
            raise _activation_fence(
                "ROOT_IDENTITY_CHANGED",
                "activation registry identity changed",
            ) from exc
        if registry_identity != self.__evidence.audit.registry_identity_sha256:
            raise _activation_fence(
                "ROOT_IDENTITY_CHANGED",
                "activation registry identity changed",
            )
        registry_path = self.__root / "_registry" / "placement-map.yml"
        try:
            placement_info, registry_raw = _read_registry(
                self.__registry_fd,
                registry_path,
            )
            current_policy = activation_foundation.compile_initial_policy(
                registry_raw,
                str(self.__root),
            )
        except (AuthorityRuntimeError, TypeError, ValueError) as exc:
            raise _activation_fence(
                "POLICY_IDENTITY_CHANGED",
                "activation policy identity changed",
            ) from exc
        if (
            _file_identity_sha256(registry_path, placement_info)
            != self.__evidence.audit.placement_identity_sha256
            or current_policy.as_dict()
            != dict(self.__request.payload["initial_policy"])
        ):
            raise _activation_fence(
                "POLICY_IDENTITY_CHANGED",
                "activation policy identity changed",
            )
        return registry_raw

    def _require_marker_state(
        self,
        expected: activation_markers.ActivationMarkerState,
    ) -> activation_markers.ActivationMarkerEvidence:
        marker = activation_markers.classify_activation_markers(
            self.__registry_fd,
            self.__root,
            incoming_request=self.__request,
        )
        if marker.state is expected:
            return marker
        if marker.state is activation_markers.ActivationMarkerState.MANUAL_FENCE:
            _raise_marker_fence(marker)
        if (
            marker.state
            is activation_markers.ActivationMarkerState.PRESEAL_ORPHAN
        ):
            raise _activation_fence(
                "PRESEAL_ORPHAN",
                "activation request is not durably sealed",
            )
        raise _activation_fence(
            "PUBLICATION_COLLISION",
            "activation marker advanced unexpectedly",
        )

    def _activate_prefix(self) -> artifact_contract.SealedArtifactRef:
        root = self.__root
        registry_path = root / "_registry"
        curation_path = registry_path / "curation"
        activation_path = curation_path / "activation"
        version_path = activation_path / "v1"
        staging_path = version_path / "staging"
        request = self.__request
        state = self.__evidence.markers.state
        registry_raw = self._revalidate_boundary()
        plan = activation_foundation.build_activation_foundation(
            registry_raw,
            str(root),
            request.scope["activation_id"],
        )
        if dict(request.payload["initial_policy"]) != plan.initial_policy.as_dict():
            raise _activation_fence(
                "POLICY_IDENTITY_CHANGED",
                "activation policy identity changed",
            )
        if state is activation_markers.ActivationMarkerState.FRESH:
            curation_fd = _create_directory_at(
                self.__registry_fd,
                "curation",
                curation_path,
            )
            self._revalidate_boundary()
            activation_fd = version_fd = staging_fd = None
        else:
            fds = _open_activation_protocol_tree(root)
            _registry_fd, curation_fd, activation_fd, version_fd, staging_fd = fds
            os.close(_registry_fd)
        try:
            if state is activation_markers.ActivationMarkerState.FRESH:
                activation_fd = _create_directory_at(
                    curation_fd,
                    "activation",
                    activation_path,
                )
                self._revalidate_boundary()
                version_fd = _create_directory_at(
                    activation_fd,
                    "v1",
                    version_path,
                )
                self._revalidate_boundary()
                staging_fd = _create_directory_at(
                    version_fd,
                    "staging",
                    staging_path,
                )
                self._revalidate_boundary()
                _checkpoint("A2")
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.PRESEAL_ORPHAN
                )
                _publish_exact_bytes(
                    version_fd,
                    version_path,
                    temporary_name=f".request-{request.sha256}.tmp",
                    final_name="request.json",
                    raw=request.canonical_bytes,
                    temporary_checkpoint="A3_TEMP",
                    before_final_publish=self._revalidate_boundary,
                )
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.REQUEST_SEALED
                )
                _checkpoint("A3")
                state = activation_markers.ActivationMarkerState.REQUEST_SEALED
            elif state is activation_markers.ActivationMarkerState.REQUEST_TEMP:
                self._revalidate_boundary()
                _publish_existing_exact_bytes(
                    version_fd,
                    version_path,
                    temporary_name=f".request-{request.sha256}.tmp",
                    final_name="request.json",
                    raw=request.canonical_bytes,
                )
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.REQUEST_SEALED
                )
                _checkpoint("A3")
                state = activation_markers.ActivationMarkerState.REQUEST_SEALED

            if state is activation_markers.ActivationMarkerState.REQUEST_SEALED:
                self._revalidate_boundary()
                _create_empty_file(
                    curation_fd,
                    "ledger.lock",
                    curation_path / "ledger.lock",
                )
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.LEDGER_LOCK_ONLY
                )
                _checkpoint("A4_LEDGER_LOCK")
                state = activation_markers.ActivationMarkerState.LEDGER_LOCK_ONLY
            if state is activation_markers.ActivationMarkerState.LEDGER_LOCK_ONLY:
                self._revalidate_boundary()
                _create_empty_file(
                    curation_fd,
                    "policy.lock",
                    curation_path / "policy.lock",
                )
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.LOCKS_READY
                )
                _checkpoint("A4")
                state = activation_markers.ActivationMarkerState.LOCKS_READY

            staging_ledger = staging_path / "ledger.sqlite3"
            if state is activation_markers.ActivationMarkerState.LOCKS_READY:
                self._revalidate_boundary()
                _create_empty_file(staging_fd, "ledger.sqlite3", staging_ledger)
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.EMPTY_STAGING_LEDGER
                )
                _checkpoint("A5_EMPTY")
                state = activation_markers.ActivationMarkerState.EMPTY_STAGING_LEDGER
            if (
                state
                is activation_markers.ActivationMarkerState.EMPTY_STAGING_LEDGER
            ):
                self._revalidate_boundary()
                try:
                    activation_foundation.initialize_activation_ledger(
                        staging_ledger,
                        plan,
                    )
                except (OSError, TypeError, ValueError) as exc:
                    raise AuthorityRuntimeError(
                        "activation ledger genesis failed"
                    ) from exc
                _require_regular_identity(staging_fd, "ledger.sqlite3", staging_ledger)
                _require_exact_names(
                    staging_fd,
                    {"ledger.sqlite3"},
                    "activation staging",
                )
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.STAGING_LEDGER_READY
                )
                _checkpoint("A5")
                state = activation_markers.ActivationMarkerState.STAGING_LEDGER_READY
            if (
                state
                is activation_markers.ActivationMarkerState.STAGING_LEDGER_READY
            ):
                self._revalidate_boundary()
                activation_foundation.verify_activation_ledger(
                    staging_ledger,
                    plan,
                )
                collision_message = "activation ledger already exists"
                try:
                    safety.rename_entry_no_replace_at(
                        staging_fd,
                        "ledger.sqlite3",
                        curation_fd,
                        "ledger.sqlite3",
                        collision_error=collision_message,
                        error_type=AuthorityRuntimeError,
                    )
                except AuthorityRuntimeError as exc:
                    if str(exc) != collision_message:
                        raise
                    raise _activation_fence(
                        "PUBLICATION_COLLISION",
                        "activation ledger publication collided",
                    ) from exc
                os.fsync(staging_fd)
                os.fsync(curation_fd)
                _require_exact_names(staging_fd, set(), "activation staging")
                _require_regular_identity(
                    curation_fd,
                    "ledger.sqlite3",
                    curation_path / "ledger.sqlite3",
                )
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.FINAL_LEDGER_READY
                )
                _checkpoint("A6")
                state = activation_markers.ActivationMarkerState.FINAL_LEDGER_READY

            verified = activation_foundation.verify_activation_ledger(
                curation_path / "ledger.sqlite3",
                plan,
            )
            self._revalidate_boundary()
            _checkpoint("A7")
            receipt = _receipt_value(request, verified, plan.snapshot_id)
            activation_contract.require_activation_receipt(
                receipt,
                request=request,
                expected_uid=os.getuid(),
            )
            receipt_raw = canonical_json_bytes(receipt)
            receipt_temporary_name = (
                f".receipt-{sha256_bytes(receipt_raw)}.tmp"
            )
            if (
                state
                is activation_markers.ActivationMarkerState.FINAL_LEDGER_READY
            ):
                self._revalidate_boundary()
                _publish_exact_bytes(
                    version_fd,
                    version_path,
                    temporary_name=receipt_temporary_name,
                    final_name="receipt.json",
                    raw=receipt_raw,
                    temporary_checkpoint="A8_TEMP",
                    before_final_publish=self._revalidate_boundary,
                )
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.ACTIVE
                )
                _checkpoint("A8")
            elif state is activation_markers.ActivationMarkerState.RECEIPT_TEMP:
                self._revalidate_boundary()
                _publish_existing_exact_bytes(
                    version_fd,
                    version_path,
                    temporary_name=receipt_temporary_name,
                    final_name="receipt.json",
                    raw=receipt_raw,
                )
                self._revalidate_boundary()
                self._require_marker_state(
                    activation_markers.ActivationMarkerState.ACTIVE
                )
                _checkpoint("A8")
        finally:
            for fd in (staging_fd, version_fd, activation_fd):
                if fd is not None:
                    os.close(fd)
            os.close(curation_fd)
        reference, _receipt_sha256 = _verify_completed_activation(root, request)
        _checkpoint("A9")
        return reference

    def activate(self) -> artifact_contract.SealedArtifactRef:
        self._require_active()
        try:
            if (
                self.__evidence.markers.state
                is activation_markers.ActivationMarkerState.ACTIVE
            ):
                self._revalidate_boundary()
                reference, receipt_sha256 = _verify_completed_activation(
                    self.__root,
                    self.__request,
                )
                if receipt_sha256 != self.__evidence.receipt_sha256:
                    raise AuthorityRuntimeError("activation receipt identity changed")
                _checkpoint("A9")
                return reference
            if (
                self.__evidence.markers.state
                not in _RECOVERY_MARKER_STATES
                | {activation_markers.ActivationMarkerState.FRESH}
            ):
                raise AuthorityRuntimeError("activation admission state is invalid")
            return self._activate_prefix()
        finally:
            self.__used = True

    def _close(self) -> None:
        self.__active = False


@contextmanager
def open_activation_session(
    root: Path,
    *,
    request_bytes: bytes,
    admitted_evidence: object,
) -> Iterator[ActivationSession]:
    """Open one registry-locked activation session without legacy writer access."""

    if type(admitted_evidence) is not ActivationAdmissionEvidence:
        raise TypeError("activation admission evidence is invalid")
    try:
        request = operation_codec.decode_operation_request(request_bytes)
        activation_contract.validate_activation_request(request)
    except (TypeError, ValueError) as exc:
        raise AuthorityRuntimeError("activation request evidence is invalid") from exc
    canonical_root = Path(root)
    root_fd = safety.open_verified_directory(
        canonical_root,
        require_owner_only=True,
        error_type=AuthorityRuntimeError,
    )
    registry_path = canonical_root / "_registry"
    try:
        registry_fd = safety.open_verified_directory(
            registry_path,
            require_owner_only=True,
            error_type=AuthorityRuntimeError,
        )
    except BaseException:
        os.close(root_fd)
        raise
    session = None
    try:
        try:
            fcntl.flock(registry_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise _activation_fence(
                "WRITER_BUSY",
                "activation writer is already active",
            ) from exc
        observed = capture_admission_evidence(canonical_root, request)
        if observed != admitted_evidence:
            if (
                observed.audit.root_identity_sha256
                != admitted_evidence.audit.root_identity_sha256
                or observed.audit.registry_identity_sha256
                != admitted_evidence.audit.registry_identity_sha256
            ):
                raise _activation_fence(
                    "ROOT_IDENTITY_CHANGED",
                    "activation root identity changed after admission",
                )
            if (
                observed.audit.placement_identity_sha256
                != admitted_evidence.audit.placement_identity_sha256
            ):
                raise _activation_fence(
                    "POLICY_IDENTITY_CHANGED",
                    "activation policy identity changed after admission",
                )
            raise AuthorityRuntimeError("activation admission evidence changed")
        _checkpoint("A1_LOCKED")
        session = ActivationSession(
            canonical_root,
            root_fd,
            registry_fd,
            request,
            observed,
        )
        try:
            yield session
        finally:
            session._close()
    finally:
        try:
            fcntl.flock(registry_fd, fcntl.LOCK_UN)
        finally:
            os.close(registry_fd)
            os.close(root_fd)


__all__ = [
    "ActivationAdmissionEvidence",
    "ActivationAuditEvidence",
    "ActivationSession",
    "capture_admission_evidence",
    "capture_audit_evidence",
    "open_activation_session",
]
