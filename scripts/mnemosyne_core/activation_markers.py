"""Closed, read-only classification of Safe Librarian activation markers."""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from . import (
    activation_contract,
    activation_foundation,
    operation_contract,
    safety,
)
from .canonical_json import canonical_json_bytes, sha256_bytes
from .operation_contract import codec as operation_codec


_MAX_REGISTRY_BYTES = 4 * 1024 * 1024
_MAX_PROTOCOL_BYTES = 1024 * 1024
_MAX_LEDGER_BYTES = 64 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 16
_REQUEST_TEMP = re.compile(r"\.request-([0-9a-f]{64})\.tmp")
_RECEIPT_TEMP = re.compile(r"\.receipt-([0-9a-f]{64})\.tmp")
_LEGACY_SENTINELS = frozenset(
    {
        "placement-map.lock",
        "lock-migrations",
        "curation-runs",
    }
)
_POST_ACTIVE_CURATION_DIRECTORIES = frozenset(
    {
        "authority-runtime",
        "canonical-curation-v1",
        "canonical-curation-v2",
        "safe-librarian",
    }
)
_PROTOCOL_CURATION_NAMES = frozenset(
    {
        "activation",
        "ledger.lock",
        "policy.lock",
        "ledger.sqlite3",
    }
)


class ActivationMarkerState(str, Enum):
    """Every marker topology that callers may distinguish."""

    FRESH = "FRESH"
    LEGACY = "LEGACY"
    PRESEAL_ORPHAN = "PRESEAL_ORPHAN"
    REQUEST_TEMP = "REQUEST_TEMP"
    REQUEST_SEALED = "REQUEST_SEALED"
    LEDGER_LOCK_ONLY = "LEDGER_LOCK_ONLY"
    LOCKS_READY = "LOCKS_READY"
    EMPTY_STAGING_LEDGER = "EMPTY_STAGING_LEDGER"
    STAGING_LEDGER_READY = "STAGING_LEDGER_READY"
    FINAL_LEDGER_READY = "FINAL_LEDGER_READY"
    RECEIPT_TEMP = "RECEIPT_TEMP"
    ACTIVE = "ACTIVE"
    MANUAL_FENCE = "MANUAL_FENCE"


class ActivationReasonCode(str, Enum):
    """Typed public-safe reason carried by one marker observation."""

    FRESH_CURATION_STATE = "FRESH_CURATION_STATE"
    LEGACY_AUTHORITY_PRESENT = "LEGACY_AUTHORITY_PRESENT"
    PRESEAL_ORPHAN = "PRESEAL_ORPHAN"
    RECOVERY_SAME_REQUEST_ONLY = "RECOVERY_SAME_REQUEST_ONLY"
    ALREADY_ACTIVE = "ALREADY_ACTIVE"
    REQUEST_MISMATCH = "REQUEST_MISMATCH"
    ALREADY_ACTIVE_DIFFERENT_REQUEST = "ALREADY_ACTIVE_DIFFERENT_REQUEST"
    UNKNOWN_AUTHORITY_MEMBER = "UNKNOWN_AUTHORITY_MEMBER"
    UNSAFE_BOUNDARY = "UNSAFE_BOUNDARY"
    FOUNDATION_READBACK_FAILED = "FOUNDATION_READBACK_FAILED"


@dataclass(frozen=True)
class ActivationMarkerEvidence:
    """Immutable classification with no live file or database handle."""

    state: ActivationMarkerState
    reason_code: ActivationReasonCode
    stored_request: operation_contract.OperationRequest | None
    stored_request_bytes: bytes | None
    stored_request_sha256: str | None
    receipt_sha256: str | None


class _UnsafeBoundary(ValueError):
    pass


class _UnknownMember(ValueError):
    pass


class _FoundationReadbackFailed(ValueError):
    pass


def _evidence(
    state: ActivationMarkerState,
    reason_code: ActivationReasonCode,
    *,
    request: operation_contract.OperationRequest | None = None,
    request_bytes: bytes | None = None,
    receipt_sha256: str | None = None,
) -> ActivationMarkerEvidence:
    if request is None:
        request_bytes = None
        request_sha256 = None
    else:
        if request_bytes != request.canonical_bytes:
            raise AssertionError("stored request evidence is not canonical")
        request_sha256 = request.sha256
    return ActivationMarkerEvidence(
        state=state,
        reason_code=reason_code,
        stored_request=request,
        stored_request_bytes=request_bytes,
        stored_request_sha256=request_sha256,
        receipt_sha256=receipt_sha256,
    )


def _manual(
    reason_code: ActivationReasonCode,
    *,
    request: operation_contract.OperationRequest | None = None,
    request_bytes: bytes | None = None,
    receipt_sha256: str | None = None,
) -> ActivationMarkerEvidence:
    return _evidence(
        ActivationMarkerState.MANUAL_FENCE,
        reason_code,
        request=request,
        request_bytes=request_bytes,
        receipt_sha256=receipt_sha256,
    )


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _regular_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _bounded_names(directory_fd: int) -> frozenset[str]:
    names: list[str] = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > _MAX_DIRECTORY_ENTRIES:
                    raise _UnknownMember("activation inventory exceeds its bound")
    except _UnknownMember:
        raise
    except OSError as exc:
        raise _UnsafeBoundary("activation inventory is unavailable") from exc
    return frozenset(names)


def _entry_info(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _UnsafeBoundary("activation member is unavailable") from exc


def _open_directory_at(
    parent_fd: int,
    name: str,
    *,
    expected_mode: int | None = 0o700,
) -> int:
    lexical = _entry_info(parent_fd, name)
    if lexical is None or not stat.S_ISDIR(lexical.st_mode):
        raise _UnsafeBoundary("activation directory type is unsafe")
    try:
        child_fd = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
        opened = os.fstat(child_fd)
    except OSError as exc:
        raise _UnsafeBoundary("activation directory cannot be opened") from exc
    mode = stat.S_IMODE(opened.st_mode)
    mode_is_unsafe = (
        mode != expected_mode
        if expected_mode is not None
        else bool(mode & 0o022)
    )
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.getuid()
        or mode_is_unsafe
        or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
    ):
        os.close(child_fd)
        raise _UnsafeBoundary("activation directory identity is unsafe")
    return child_fd


def _read_regular_at(
    directory_fd: int,
    name: str,
    path: Path,
    *,
    maximum: int,
    expected_mode: int | None = 0o600,
) -> tuple[os.stat_result, bytes]:
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            name,
            path,
            label="activation marker",
            expected_mode=expected_mode,
            max_bytes=maximum,
            error_type=_UnsafeBoundary,
        )
    except _UnsafeBoundary:
        raise
    except OSError as exc:
        raise _UnsafeBoundary("activation marker is unreadable") from exc
    if info.st_nlink != 1:
        raise _UnsafeBoundary("activation marker link identity is unsafe")
    return info, raw


def _require_empty_lock(directory_fd: int, name: str, path: Path) -> None:
    _info, raw = _read_regular_at(
        directory_fd,
        name,
        path,
        maximum=1,
    )
    if raw:
        raise _FoundationReadbackFailed("activation lock is not empty")


def _root_identity_sha256(exact_root: Path) -> str:
    root_fd = safety.open_verified_directory(
        exact_root,
        require_owner_only=True,
        error_type=_UnsafeBoundary,
    )
    try:
        info = os.fstat(root_fd)
        return sha256_bytes(
            canonical_json_bytes(
                {
                    "canonical_path": str(exact_root),
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                }
            )
        )
    finally:
        os.close(root_fd)


def _read_registry(registry_fd: int, exact_root: Path) -> bytes:
    _info, raw = _read_regular_at(
        registry_fd,
        "placement-map.yml",
        exact_root / "_registry" / "placement-map.yml",
        maximum=_MAX_REGISTRY_BYTES,
        expected_mode=None,
    )
    return raw


def _legacy_sentinel_present(registry_fd: int) -> bool:
    for name in _LEGACY_SENTINELS:
        info = _entry_info(registry_fd, name)
        if info is not None:
            # Presence is enough to make activation ineligible.  The legacy
            # runtime keeps ownership of its exact type/mode/link validation
            # when no activation protocol marker exists.
            return True
    return False


def _decode_stored_request(
    raw: bytes,
    *,
    name: str,
    registry_raw: bytes,
    exact_root: Path,
    root_identity_sha256: str,
) -> tuple[operation_contract.OperationRequest, activation_foundation.ActivationFoundationPlan]:
    try:
        request = operation_codec.decode_operation_request(raw)
        activation_contract.validate_activation_request(request)
    except (TypeError, ValueError) as exc:
        raise _FoundationReadbackFailed(
            "stored activation request is invalid"
        ) from exc
    match = _REQUEST_TEMP.fullmatch(name)
    if match is not None and match.group(1) != request.sha256:
        raise _FoundationReadbackFailed("request temporary identity is invalid")
    if (
        request.root != str(exact_root)
        or request.payload["root_identity_sha256"] != root_identity_sha256
    ):
        raise _FoundationReadbackFailed("stored activation root is invalid")
    try:
        plan = activation_foundation.build_activation_foundation(
            registry_raw,
            str(exact_root),
            request.scope["activation_id"],
        )
    except (TypeError, ValueError) as exc:
        raise _FoundationReadbackFailed(
            "activation base overlay cannot be rebuilt"
        ) from exc
    if dict(request.payload["initial_policy"]) != plan.initial_policy.as_dict():
        raise _FoundationReadbackFailed("activation base overlay changed")
    return request, plan


def _read_open_file(fd: int, *, maximum: int) -> bytes:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise _UnsafeBoundary("activation ledger is unreadable") from exc
    if len(raw) > maximum:
        raise _UnsafeBoundary("activation ledger exceeds its byte bound")
    return raw


def _verify_ledger_at(
    directory_fd: int,
    name: str,
    raw: bytes,
    plan: activation_foundation.ActivationFoundationPlan,
) -> activation_foundation.ActivationFoundationReadback:
    if not raw:
        raise _FoundationReadbackFailed("activation ledger is empty")
    lexical = _entry_info(directory_fd, name)
    try:
        fd = os.open(name, _regular_open_flags(), dir_fd=directory_fd)
        opened = os.fstat(fd)
    except OSError as exc:
        raise _UnsafeBoundary("activation ledger cannot be opened") from exc
    if (
        lexical is None
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
        or opened.st_size != len(raw)
        or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        or _read_open_file(fd, maximum=_MAX_LEDGER_BYTES) != raw
    ):
        os.close(fd)
        raise _UnsafeBoundary("activation ledger identity is unsafe")
    connection = None
    try:
        try:
            connection = sqlite3.connect(
                "file:/dev/fd/%d?mode=ro&immutable=1" % fd,
                uri=True,
                isolation_level=None,
            )
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA query_only = ON")
            readback = activation_foundation.verify_activation_ledger(connection, plan)
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise _FoundationReadbackFailed(
                "activation ledger readback failed"
            ) from exc
        final = _entry_info(directory_fd, name)
        if (
            final is None
            or (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or final.st_nlink != opened.st_nlink
            or final.st_size != opened.st_size
            or _read_open_file(fd, maximum=_MAX_LEDGER_BYTES) != raw
        ):
            raise _UnsafeBoundary("activation ledger changed during readback")
        return readback
    finally:
        if connection is not None:
            connection.close()
        os.close(fd)


def _validate_incoming_request(
    incoming_request: operation_contract.OperationRequest | None,
) -> None:
    if incoming_request is None:
        return
    try:
        activation_contract.validate_activation_request(incoming_request)
    except (TypeError, ValueError) as exc:
        raise ValueError("incoming activation request is invalid") from exc


def _request_mismatch(
    incoming_request: operation_contract.OperationRequest | None,
    stored_request: operation_contract.OperationRequest,
    *,
    active: bool,
) -> ActivationReasonCode | None:
    if (
        incoming_request is None
        or incoming_request.canonical_bytes == stored_request.canonical_bytes
    ):
        return None
    if active:
        return ActivationReasonCode.ALREADY_ACTIVE_DIFFERENT_REQUEST
    return ActivationReasonCode.REQUEST_MISMATCH


def _classify_request_bound_tree(
    *,
    exact_root: Path,
    registry_raw: bytes,
    root_identity_sha256: str,
    curation_fd: int,
    curation_names: frozenset[str],
    version_fd: int,
    version_names: frozenset[str],
    staging_fd: int,
    staging_names: frozenset[str],
    incoming_request: operation_contract.OperationRequest | None,
) -> ActivationMarkerEvidence:
    request_temps = tuple(sorted(name for name in version_names if _REQUEST_TEMP.fullmatch(name)))
    receipt_temps = tuple(sorted(name for name in version_names if _RECEIPT_TEMP.fullmatch(name)))
    if len(request_temps) > 1 or len(receipt_temps) > 1:
        raise _FoundationReadbackFailed("multiple activation temporaries exist")
    request_final = "request.json" in version_names
    receipt_final = "receipt.json" in version_names
    if request_final and request_temps:
        raise _FoundationReadbackFailed("request temporary and final co-exist")
    if receipt_final and receipt_temps:
        raise _FoundationReadbackFailed("receipt temporary and final co-exist")
    if not request_final and not request_temps:
        if (
            version_names == {"staging"}
            and not staging_names
            and curation_names == {"activation"}
        ):
            return _evidence(
                ActivationMarkerState.PRESEAL_ORPHAN,
                ActivationReasonCode.PRESEAL_ORPHAN,
            )
        raise _FoundationReadbackFailed("activation members precede the request")

    request_name = "request.json" if request_final else request_temps[0]
    _request_info, request_raw = _read_regular_at(
        version_fd,
        request_name,
        exact_root / "_registry" / "curation" / "activation" / "v1" / request_name,
        maximum=_MAX_PROTOCOL_BYTES,
    )
    request, plan = _decode_stored_request(
        request_raw,
        name=request_name,
        registry_raw=registry_raw,
        exact_root=exact_root,
        root_identity_sha256=root_identity_sha256,
    )
    if request_temps:
        if (
            version_names != {"staging", request_name}
            or staging_names
            or curation_names != {"activation"}
        ):
            raise _FoundationReadbackFailed("request temporary order is invalid")
        mismatch = _request_mismatch(incoming_request, request, active=False)
        if mismatch is not None:
            return _manual(mismatch, request=request, request_bytes=request_raw)
        return _evidence(
            ActivationMarkerState.REQUEST_TEMP,
            ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            request=request,
            request_bytes=request_raw,
        )

    for name in ("ledger.lock", "policy.lock"):
        if name in curation_names:
            _require_empty_lock(
                curation_fd,
                name,
                exact_root / "_registry" / "curation" / name,
            )

    ledger_lock = "ledger.lock" in curation_names
    policy_lock = "policy.lock" in curation_names
    final_ledger = "ledger.sqlite3" in curation_names
    staging_ledger = "ledger.sqlite3" in staging_names
    if policy_lock and not ledger_lock:
        raise _FoundationReadbackFailed("policy lock precedes ledger lock")
    if staging_ledger and not (ledger_lock and policy_lock):
        raise _FoundationReadbackFailed("staging ledger precedes locks")
    if final_ledger and (not (ledger_lock and policy_lock) or staging_ledger):
        raise _FoundationReadbackFailed("final ledger order is invalid")

    readback = None
    if staging_ledger:
        staging_info, staging_raw = _read_regular_at(
            staging_fd,
            "ledger.sqlite3",
            exact_root / "_registry" / "curation" / "activation" / "v1" / "staging" / "ledger.sqlite3",
            maximum=_MAX_LEDGER_BYTES,
        )
        if staging_info.st_size:
            readback = _verify_ledger_at(
                staging_fd,
                "ledger.sqlite3",
                staging_raw,
                plan,
            )
    elif final_ledger:
        _final_info, final_raw = _read_regular_at(
            curation_fd,
            "ledger.sqlite3",
            exact_root / "_registry" / "curation" / "ledger.sqlite3",
            maximum=_MAX_LEDGER_BYTES,
        )
        readback = _verify_ledger_at(
            curation_fd,
            "ledger.sqlite3",
            final_raw,
            plan,
        )

    receipt_name = "receipt.json" if receipt_final else (receipt_temps[0] if receipt_temps else None)
    receipt_sha256 = None
    if receipt_name is not None:
        if not final_ledger or readback is None or staging_ledger:
            raise _FoundationReadbackFailed("receipt precedes final ledger")
        _receipt_info, receipt_raw = _read_regular_at(
            version_fd,
            receipt_name,
            exact_root / "_registry" / "curation" / "activation" / "v1" / receipt_name,
            maximum=_MAX_PROTOCOL_BYTES,
        )
        try:
            receipt = activation_contract.require_activation_receipt_bytes(
                receipt_raw,
                request=request,
                expected_uid=os.getuid(),
            )
        except (TypeError, ValueError) as exc:
            raise _FoundationReadbackFailed(
                "activation receipt is invalid"
            ) from exc
        receipt_sha256 = sha256_bytes(receipt_raw)
        match = _RECEIPT_TEMP.fullmatch(receipt_name)
        if (
            (match is not None and match.group(1) != receipt_sha256)
            or receipt["logical_readback_sha256"] != readback.sha256
        ):
            raise _FoundationReadbackFailed("activation receipt readback changed")

    base_version_names = {"staging", "request.json"}
    if receipt_name is not None:
        base_version_names.add(receipt_name)
    if version_names != base_version_names:
        raise _FoundationReadbackFailed("activation protocol order is invalid")

    if receipt_final:
        state = ActivationMarkerState.ACTIVE
        reason = ActivationReasonCode.ALREADY_ACTIVE
    elif receipt_temps:
        state = ActivationMarkerState.RECEIPT_TEMP
        reason = ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY
    elif final_ledger:
        state = ActivationMarkerState.FINAL_LEDGER_READY
        reason = ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY
    elif staging_ledger and readback is not None:
        state = ActivationMarkerState.STAGING_LEDGER_READY
        reason = ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY
    elif staging_ledger:
        state = ActivationMarkerState.EMPTY_STAGING_LEDGER
        reason = ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY
    elif ledger_lock and policy_lock:
        state = ActivationMarkerState.LOCKS_READY
        reason = ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY
    elif ledger_lock:
        state = ActivationMarkerState.LEDGER_LOCK_ONLY
        reason = ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY
    elif curation_names == {"activation"} and not staging_names:
        state = ActivationMarkerState.REQUEST_SEALED
        reason = ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY
    else:
        raise _FoundationReadbackFailed("activation member order is invalid")

    mismatch = _request_mismatch(
        incoming_request,
        request,
        active=state is ActivationMarkerState.ACTIVE,
    )
    if mismatch is not None:
        return _manual(
            mismatch,
            request=request,
            request_bytes=request_raw,
            receipt_sha256=receipt_sha256,
        )
    return _evidence(
        state,
        reason,
        request=request,
        request_bytes=request_raw,
        receipt_sha256=receipt_sha256,
    )


def classify_activation_markers(
    registry_fd: int,
    exact_root: Path,
    *,
    incoming_request: operation_contract.OperationRequest | None = None,
) -> ActivationMarkerEvidence:
    """Classify one fixed-depth activation topology without mutation or fallback."""

    if type(registry_fd) is not int or registry_fd < 0:
        raise TypeError("registry_fd must be an open integer descriptor")
    if not isinstance(exact_root, Path):
        raise TypeError("exact_root must be a Path")
    if (
        not exact_root.is_absolute()
        or str(exact_root).startswith("//")
        or Path(os.path.normpath(str(exact_root))) != exact_root
    ):
        raise ValueError("exact_root must be canonical and absolute")
    _validate_incoming_request(incoming_request)

    try:
        registry_info = os.fstat(registry_fd)
        if (
            not stat.S_ISDIR(registry_info.st_mode)
            or registry_info.st_uid != os.getuid()
            or stat.S_IMODE(registry_info.st_mode) & 0o022
        ):
            raise _UnsafeBoundary("activation registry identity is unsafe")
        safety.require_same_directory_identity(
            exact_root / "_registry",
            registry_fd,
            "activation registry",
            error_type=_UnsafeBoundary,
        )
        root_identity = _root_identity_sha256(exact_root)
        registry_raw = _read_registry(registry_fd, exact_root)
        legacy_present = _legacy_sentinel_present(registry_fd)
        curation_info = _entry_info(registry_fd, "curation")
        if curation_info is None:
            if legacy_present:
                return _evidence(
                    ActivationMarkerState.LEGACY,
                    ActivationReasonCode.LEGACY_AUTHORITY_PRESENT,
                )
            return _evidence(
                ActivationMarkerState.FRESH,
                ActivationReasonCode.FRESH_CURATION_STATE,
            )

        curation_fd = _open_directory_at(
            registry_fd,
            "curation",
            expected_mode=None if legacy_present else 0o700,
        )
        try:
            curation_names = _bounded_names(curation_fd)
            allowed_curation = (
                _PROTOCOL_CURATION_NAMES | _POST_ACTIVE_CURATION_DIRECTORIES
            )
            # Legacy policy bootstrap also owns ``policy.lock``.  The protocol
            # directory is the first marker that unambiguously claims the new
            # activation namespace.
            activation_specific = "activation" in curation_names
            if legacy_present and not activation_specific:
                return _evidence(
                    ActivationMarkerState.LEGACY,
                    ActivationReasonCode.LEGACY_AUTHORITY_PRESENT,
                )
            if legacy_present:
                return _manual(ActivationReasonCode.LEGACY_AUTHORITY_PRESENT)
            if curation_names - allowed_curation:
                raise _UnknownMember("unknown activation foundation member")
            post_active_names = curation_names & _POST_ACTIVE_CURATION_DIRECTORIES
            protocol_curation_names = curation_names - post_active_names
            for post_active_name in sorted(post_active_names):
                post_active_fd = _open_directory_at(curation_fd, post_active_name)
                os.close(post_active_fd)
            if not curation_names:
                return _evidence(
                    ActivationMarkerState.PRESEAL_ORPHAN,
                    ActivationReasonCode.PRESEAL_ORPHAN,
                )
            if "activation" not in curation_names:
                raise _FoundationReadbackFailed(
                    "activation foundation precedes protocol directory"
                )

            activation_fd = _open_directory_at(curation_fd, "activation")
            try:
                activation_names = _bounded_names(activation_fd)
                if not activation_names and curation_names == {"activation"}:
                    return _evidence(
                        ActivationMarkerState.PRESEAL_ORPHAN,
                        ActivationReasonCode.PRESEAL_ORPHAN,
                    )
                if activation_names != {"v1"}:
                    if activation_names - {"v1"}:
                        raise _UnknownMember("unknown activation protocol member")
                    raise _FoundationReadbackFailed(
                        "activation protocol directory is incomplete"
                    )
                version_fd = _open_directory_at(activation_fd, "v1")
                try:
                    version_names = _bounded_names(version_fd)
                    if not version_names and curation_names == {"activation"}:
                        return _evidence(
                            ActivationMarkerState.PRESEAL_ORPHAN,
                            ActivationReasonCode.PRESEAL_ORPHAN,
                        )
                    allowed_version = {"staging", "request.json", "receipt.json"}
                    allowed_version.update(
                        name
                        for name in version_names
                        if _REQUEST_TEMP.fullmatch(name)
                        or _RECEIPT_TEMP.fullmatch(name)
                    )
                    if version_names - allowed_version:
                        raise _UnknownMember("unknown activation version member")
                    if "staging" not in version_names:
                        raise _FoundationReadbackFailed(
                            "activation staging directory is missing"
                        )
                    staging_fd = _open_directory_at(version_fd, "staging")
                    try:
                        staging_names = _bounded_names(staging_fd)
                        if staging_names - {"ledger.sqlite3"}:
                            raise _UnknownMember("unknown activation staging member")
                        result = _classify_request_bound_tree(
                            exact_root=exact_root,
                            registry_raw=registry_raw,
                            root_identity_sha256=root_identity,
                            curation_fd=curation_fd,
                            curation_names=protocol_curation_names,
                            version_fd=version_fd,
                            version_names=version_names,
                            staging_fd=staging_fd,
                            staging_names=staging_names,
                            incoming_request=incoming_request,
                        )
                    finally:
                        os.close(staging_fd)
                finally:
                        os.close(version_fd)
            finally:
                os.close(activation_fd)
            if (
                post_active_names
                and result.state is not ActivationMarkerState.ACTIVE
            ):
                raise _FoundationReadbackFailed(
                    "activation-owned namespace precedes active foundation"
                )
        finally:
            os.close(curation_fd)
        safety.require_same_directory_identity(
            exact_root / "_registry",
            registry_fd,
            "activation registry",
            error_type=_UnsafeBoundary,
        )
        return result
    except _UnknownMember:
        return _manual(ActivationReasonCode.UNKNOWN_AUTHORITY_MEMBER)
    except _UnsafeBoundary:
        return _manual(ActivationReasonCode.UNSAFE_BOUNDARY)
    except _FoundationReadbackFailed:
        return _manual(ActivationReasonCode.FOUNDATION_READBACK_FAILED)


__all__ = [
    "ActivationMarkerEvidence",
    "ActivationMarkerState",
    "ActivationReasonCode",
    "classify_activation_markers",
]
