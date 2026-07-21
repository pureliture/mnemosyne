"""Low-level filesystem safety primitives for Mnemosyne.

This module deliberately does not import the compatibility CLI.  It owns every
filesystem safety operation; callers may inject only their domain error class
and observational fault seams that run before mandatory core verification.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable

from .canonical_json import sha256_bytes

ErrorType = type[Exception]
DirectoryObservationCallback = Callable[[Path, int, str], None]
ArtifactReadbackCallback = Callable[[Path, int, int], None]
PublicationCheckpointCallback = Callable[[], None]


class ManualRecoveryRequired(Exception):
    """Core-owned structured signal for an unverified rename effect."""

    def __init__(
        self,
        message: str,
        *,
        source: Path,
        target: Path,
        reason: str,
        expected_source_identity: tuple[int, int, int],
        observed_target_identity: tuple[int, int, int] | None,
    ) -> None:
        super().__init__(message)
        self.source = source
        self.target = target
        self.reason = reason
        self.expected_source_identity = expected_source_identity
        self.observed_target_identity = observed_target_identity

__all__ = [
    "ManualRecoveryRequired",
    "create_verified_directory_no_replace",
    "move_regular_file_no_replace",
    "open_or_create_verified_directory",
    "open_verified_directory",
    "publish_bytes_atomic_no_replace",
    "read_open_file_bytes",
    "read_regular_file_at",
    "relative_posix",
    "require_movable_path",
    "require_no_symlink_components",
    "require_same_directory_identity",
    "require_safe_path",
    "require_safe_tree",
    "resolve_under_root",
    "rename_entry_no_replace_at",
    "rename_path_no_replace",
    "safe_tree_identity_manifest",
    "source_identity",
    "verified_directory_present",
    "violates_never_touch",
]


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _require_same_directory_identity(
    path: Path,
    opened_fd: int,
    label: str,
    *,
    error_type: ErrorType,
    before_directory_identity_check: DirectoryObservationCallback | None,
) -> None:
    if before_directory_identity_check is not None:
        before_directory_identity_check(path, opened_fd, label)
    try:
        current_fd = open_verified_directory(
            path,
            require_owner_only=True,
            error_type=error_type,
        )
    except (error_type, OSError) as exc:
        raise error_type(f"{label} directory identity changed: {path}") from exc
    try:
        current = os.fstat(current_fd)
        opened = os.fstat(opened_fd)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise error_type(f"{label} directory identity changed: {path}")
    except OSError as exc:
        raise error_type(f"{label} directory identity changed: {path}") from exc
    finally:
        os.close(current_fd)


def require_same_directory_identity(
    path: Path,
    opened_fd: int,
    label: str,
    *,
    error_type: ErrorType,
    before_directory_identity_check: DirectoryObservationCallback | None = None,
) -> None:
    """Verify that a lexical path still names an already-open directory."""
    _require_same_directory_identity(
        path,
        opened_fd,
        label,
        error_type=error_type,
        before_directory_identity_check=before_directory_identity_check,
    )


def open_or_create_verified_directory(
    path: Path,
    *,
    mode: int = 0o700,
    error_type: ErrorType,
) -> int:
    """Open an absolute directory no-follow, creating missing components."""
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise error_type(f"verified directory path is not canonical: {path}")
    flags = _directory_open_flags()
    current_fd: int | None = None
    try:
        current_fd = os.open(os.sep, flags)
        for part in path.parts[1:]:
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode, dir_fd=current_fd)
                    os.fsync(current_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        info = os.fstat(current_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise error_type(f"verified directory is not owner-controlled: {path}")
        return current_fd
    except error_type:
        if current_fd is not None:
            os.close(current_fd)
        raise
    except OSError as exc:
        if current_fd is not None:
            os.close(current_fd)
        raise error_type(f"cannot open verified directory: {path}") from exc


def create_verified_directory_no_replace(
    path: Path,
    *,
    label: str,
    collision_error: str,
    mode: int = 0o700,
    error_type: ErrorType,
    before_directory_identity_check: DirectoryObservationCallback | None = None,
) -> None:
    """Create and fsync an owner-only directory without replacing an entry."""
    try:
        parent_fd = open_or_create_verified_directory(
            path.parent,
            error_type=error_type,
        )
    except error_type as exc:
        raise error_type(f"cannot open verified {label} parent: {path.parent}") from exc
    flags = _directory_open_flags()
    child_fd: int | None = None
    try:
        _require_same_directory_identity(
            path.parent,
            parent_fd,
            label,
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        try:
            os.mkdir(path.name, mode, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise error_type(collision_error) from exc
        child_fd = os.open(path.name, flags, dir_fd=parent_fd)
        child_info = os.fstat(child_fd)
        lexical_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(child_info.st_mode)
            or child_info.st_uid != os.getuid()
            or stat.S_IMODE(child_info.st_mode) & 0o077
            or (child_info.st_dev, child_info.st_ino)
            != (lexical_info.st_dev, lexical_info.st_ino)
        ):
            raise error_type(f"verified {label} directory identity is invalid: {path}")
        os.fsync(child_fd)
        os.fsync(parent_fd)
        _require_same_directory_identity(
            path.parent,
            parent_fd,
            label,
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
    except error_type:
        raise
    except OSError as exc:
        raise error_type(f"cannot create verified {label} directory: {path}") from exc
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(parent_fd)


def rename_entry_no_replace_at(
    source_directory_fd: int,
    source_name: str,
    target_directory_fd: int,
    target_name: str,
    *,
    collision_error: str,
    error_type: ErrorType,
) -> None:
    """Atomically rename one directory entry without replacing its target."""
    libc = ctypes.CDLL(None, use_errno=True)
    old_name = os.fsencode(source_name)
    new_name = os.fsencode(target_name)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        rename_no_replace = libc.renameatx_np
        rename_no_replace.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            source_directory_fd,
            old_name,
            target_directory_fd,
            new_name,
            0x00000004,
        )
    elif hasattr(libc, "renameat2"):
        rename_no_replace = libc.renameat2
        rename_no_replace.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            source_directory_fd,
            old_name,
            target_directory_fd,
            new_name,
            0x00000001,
        )
    else:
        raise error_type("atomic no-replace rename is unavailable")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise error_type(collision_error)
        raise error_type(
            f"atomic no-replace rename failed: {os.strerror(error_number)}"
        )


def publish_bytes_atomic_no_replace(
    path: Path,
    encoded: bytes,
    *,
    label: str,
    mode: int,
    create_parent: bool,
    collision_error: str,
    final_identity_error: str,
    parent_error: str,
    error_type: ErrorType,
    after_fd_readback: ArtifactReadbackCallback,
    before_directory_identity_check: DirectoryObservationCallback | None = None,
) -> os.stat_result:
    """Crash-safely publish bytes through a same-directory staging file."""
    try:
        if create_parent:
            directory_fd = open_or_create_verified_directory(
                path.parent,
                error_type=error_type,
            )
        else:
            directory_fd = open_verified_directory(
                path.parent,
                require_owner_only=True,
                error_type=error_type,
            )
    except error_type as exc:
        raise error_type(parent_error) from exc
    digest = sha256_bytes(encoded)
    staging_prefix = f".{path.name}.incomplete-"
    staging_name = f"{staging_prefix}{digest[:24]}"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        try:
            os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise error_type(collision_error)
        other_staging = sorted(
            name
            for name in os.listdir(directory_fd)
            if name.startswith(staging_prefix) and name != staging_name
        )
        if other_staging:
            raise error_type(f"{label} staging content mismatch: {path}")
        fd = os.open(staging_name, flags, mode, dir_fd=directory_fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        opened = os.fstat(fd)
        lexical = os.stat(staging_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise error_type(f"{label} staging identity is invalid: {path}")
        existing = read_open_file_bytes(fd)
        if len(existing) > len(encoded) or encoded[: len(existing)] != existing:
            raise error_type(f"{label} staging content mismatch: {path}")
        offset = len(existing)
        os.lseek(fd, offset, os.SEEK_SET)
        while offset < len(encoded):
            written = os.write(fd, encoded[offset:])
            if written <= 0:
                raise error_type(f"{label} write made no progress: {path}")
            offset += written
        os.fsync(fd)
        opened = os.fstat(fd)
        lexical = os.stat(staging_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
            or read_open_file_bytes(fd) != encoded
        ):
            raise error_type(f"{label} identity or readback mismatch: {path}")
        _require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        rename_entry_no_replace_at(
            directory_fd,
            staging_name,
            directory_fd,
            path.name,
            collision_error=collision_error,
            error_type=error_type,
        )
        os.fsync(directory_fd)
        after_fd_readback(path, fd, directory_fd)
        _require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        final = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
            raise error_type(final_identity_error)
        if read_open_file_bytes(fd) != encoded:
            raise error_type(f"{label} final readback mismatch: {path}")
        return opened
    except error_type:
        raise
    except OSError as exc:
        raise error_type(f"cannot publish {label}: {path}") from exc
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory_fd)


def publish_bytes_atomic_no_replace_at(
    directory_fd: int,
    name: str,
    path: Path,
    encoded: bytes,
    *,
    label: str,
    mode: int,
    collision_error: str,
    final_identity_error: str,
    error_type: ErrorType,
    after_fd_readback: ArtifactReadbackCallback,
    after_file_fsync: PublicationCheckpointCallback | None = None,
    after_file_readback: PublicationCheckpointCallback | None = None,
    after_directory_fsync: PublicationCheckpointCallback | None = None,
) -> os.stat_result:
    """Publish under an already-open, caller-anchored directory descriptor.

    Unlike :func:`publish_bytes_atomic_no_replace`, this helper never resolves a
    lexical parent path.  The caller owns the directory capability and keeps it
    anchored for the entire effect.
    """

    if type(name) is not str or not name or name in {".", ".."} or "/" in name:
        raise error_type(f"{label} name is invalid: {path}")
    try:
        owned_directory_fd = os.dup(directory_fd)
    except OSError as exc:
        raise error_type(f"{label} parent is unavailable: {path}") from exc
    digest = sha256_bytes(encoded)
    staging_prefix = f".{name}.incomplete-"
    staging_name = f"{staging_prefix}{digest[:24]}"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        directory_info = os.fstat(owned_directory_fd)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.getuid()
            or stat.S_IMODE(directory_info.st_mode) & 0o022
        ):
            raise error_type(f"{label} parent identity is invalid: {path}")
        try:
            os.stat(name, dir_fd=owned_directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise error_type(collision_error)
        other_staging = sorted(
            candidate
            for candidate in os.listdir(owned_directory_fd)
            if candidate.startswith(staging_prefix) and candidate != staging_name
        )
        if other_staging:
            raise error_type(f"{label} staging content mismatch: {path}")
        fd = os.open(staging_name, flags, mode, dir_fd=owned_directory_fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        opened = os.fstat(fd)
        lexical = os.stat(
            staging_name,
            dir_fd=owned_directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise error_type(f"{label} staging identity is invalid: {path}")
        existing = read_open_file_bytes(fd)
        if len(existing) > len(encoded) or encoded[: len(existing)] != existing:
            raise error_type(f"{label} staging content mismatch: {path}")
        offset = len(existing)
        os.lseek(fd, offset, os.SEEK_SET)
        while offset < len(encoded):
            written = os.write(fd, encoded[offset:])
            if written <= 0:
                raise error_type(f"{label} write made no progress: {path}")
            offset += written
        os.fsync(fd)
        if after_file_fsync is not None:
            after_file_fsync()
        opened = os.fstat(fd)
        lexical = os.stat(
            staging_name,
            dir_fd=owned_directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
            or read_open_file_bytes(fd) != encoded
        ):
            raise error_type(f"{label} identity or readback mismatch: {path}")
        if after_file_readback is not None:
            after_file_readback()
        rename_entry_no_replace_at(
            owned_directory_fd,
            staging_name,
            owned_directory_fd,
            name,
            collision_error=collision_error,
            error_type=error_type,
        )
        os.fsync(owned_directory_fd)
        if after_directory_fsync is not None:
            after_directory_fsync()
        after_fd_readback(path, fd, owned_directory_fd)
        final = os.stat(name, dir_fd=owned_directory_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
            raise error_type(final_identity_error)
        if read_open_file_bytes(fd) != encoded:
            raise error_type(f"{label} final readback mismatch: {path}")
        return opened
    except error_type:
        raise
    except OSError as exc:
        raise error_type(f"cannot publish {label}: {path}") from exc
    finally:
        if fd is not None:
            os.close(fd)
        os.close(owned_directory_fd)


def open_verified_directory(
    path: Path,
    *,
    require_owner_only: bool = False,
    error_type: ErrorType,
) -> int:
    """Open an absolute directory one no-follow component at a time."""
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise error_type(f"verified directory path is not canonical: {path}")
    flags = _directory_open_flags()
    current_fd: int | None = None
    try:
        current_fd = os.open(os.sep, flags)
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        info = os.fstat(current_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise error_type(f"verified directory is not a directory: {path}")
        if require_owner_only and (
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise error_type(f"verified directory is not owner-only: {path}")
        return current_fd
    except error_type:
        if current_fd is not None:
            os.close(current_fd)
        raise
    except OSError as exc:
        if current_fd is not None:
            os.close(current_fd)
        raise error_type(f"cannot open verified directory: {path}") from exc


def verified_directory_present(
    path: Path,
    *,
    label: str,
    error_type: ErrorType,
    before_directory_identity_check: DirectoryObservationCallback | None = None,
) -> bool:
    """Return whether *path* exists as the same verified owner-only directory."""
    if not os.path.lexists(path):
        return False
    try:
        directory_fd = open_verified_directory(
            path,
            require_owner_only=True,
            error_type=error_type,
        )
    except error_type as exc:
        raise error_type(f"{label} directory is not verified: {path}") from exc
    try:
        _require_same_directory_identity(
            path,
            directory_fd,
            label,
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
    finally:
        os.close(directory_fd)
    return True


def read_open_file_bytes(fd: int) -> bytes:
    """Read all bytes from an open descriptor, starting at offset zero."""
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 64 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def source_identity(info: os.stat_result) -> tuple[int, int, int]:
    """Return device, inode, and file type for rename identity binding."""
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _manual_recovery_required(
    source: Path,
    target: Path,
    source_info: os.stat_result,
    *,
    reason: str,
    observed_target_info: os.stat_result | None,
) -> ManualRecoveryRequired:
    return ManualRecoveryRequired(
        f"rename effect requires manual recovery: {source} -> {target}",
        source=source,
        target=target,
        reason=reason,
        expected_source_identity=source_identity(source_info),
        observed_target_identity=(
            source_identity(observed_target_info)
            if observed_target_info is not None
            else None
        ),
    )


def _compensate_rename_effect(
    source_parent_fd: int,
    source_name: str,
    target_parent_fd: int,
    target_name: str,
    source_info: os.stat_result,
    *,
    source: Path,
    target: Path,
    error_type: ErrorType,
) -> None:
    try:
        current_target = os.stat(
            target_name,
            dir_fd=target_parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise _manual_recovery_required(
            source,
            target,
            source_info,
            reason="compensation-target-unreadable",
            observed_target_info=None,
        ) from exc
    if source_identity(current_target) != source_identity(source_info):
        raise _manual_recovery_required(
            source,
            target,
            source_info,
            reason="compensation-target-identity-mismatch",
            observed_target_info=current_target,
        )
    rename_entry_no_replace_at(
        target_parent_fd,
        target_name,
        source_parent_fd,
        source_name,
        collision_error=f"rename compensation source was recreated: {source}",
        error_type=error_type,
    )
    os.fsync(target_parent_fd)
    if (os.fstat(source_parent_fd).st_dev, os.fstat(source_parent_fd).st_ino) != (
        os.fstat(target_parent_fd).st_dev,
        os.fstat(target_parent_fd).st_ino,
    ):
        os.fsync(source_parent_fd)
    restored = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
    if (restored.st_dev, restored.st_ino) != (source_info.st_dev, source_info.st_ino):
        try:
            rename_entry_no_replace_at(
                source_parent_fd,
                source_name,
                target_parent_fd,
                target_name,
                collision_error=f"rename compensation undo target was recreated: {target}",
                error_type=error_type,
            )
            os.fsync(source_parent_fd)
            os.fsync(target_parent_fd)
            returned = os.stat(
                target_name,
                dir_fd=target_parent_fd,
                follow_symlinks=False,
            )
            if source_identity(returned) != source_identity(restored):
                raise error_type(f"rename compensation undo identity mismatch: {target}")
            try:
                os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise error_type(f"rename compensation undo source still exists: {source}")
        except (error_type, OSError) as exc:
            raise _manual_recovery_required(
                source,
                target,
                source_info,
                reason="compensation-undo-failed",
                observed_target_info=restored,
            ) from exc
        raise _manual_recovery_required(
            source,
            target,
            source_info,
            reason="compensation-target-changed-during-rename",
            observed_target_info=restored,
        )
    try:
        os.stat(target_name, dir_fd=target_parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise error_type(f"rename compensation target still exists: {target}")


def rename_path_no_replace(
    source: Path,
    target: Path,
    *,
    collision_error: str,
    require_directory: bool | None = None,
    expected_source_identity: tuple[int, int, int] | None = None,
    create_target_parent: bool = True,
    error_type: ErrorType,
    before_directory_identity_check: DirectoryObservationCallback | None = None,
) -> None:
    """Move a regular file or directory with identity and no-replace checks.

    Existing callers retain parent creation by default.  Authority-bounded
    callers can require an already-existing target parent without widening the
    rename into a directory-creation capability.
    """
    if (
        not source.is_absolute()
        or not target.is_absolute()
        or source.name in {"", ".", ".."}
        or target.name in {"", ".", ".."}
    ):
        raise error_type("atomic no-replace rename requires canonical absolute paths")
    try:
        source_parent_fd = open_verified_directory(
            source.parent,
            require_owner_only=True,
            error_type=error_type,
        )
    except error_type as exc:
        raise error_type(f"cannot open verified source parent: {source.parent}") from exc
    try:
        before_target_info = os.stat(
            source.name,
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        os.close(source_parent_fd)
        raise error_type(f"rename source is missing: {source}") from exc
    if (
        expected_source_identity is not None
        and source_identity(before_target_info) != expected_source_identity
    ):
        os.close(source_parent_fd)
        raise error_type(f"rename source identity changed: {source}")
    try:
        target_parent_fd = (
            open_or_create_verified_directory(
                target.parent,
                error_type=error_type,
            )
            if create_target_parent
            else open_verified_directory(
                target.parent,
                require_owner_only=True,
                error_type=error_type,
            )
        )
    except error_type as exc:
        os.close(source_parent_fd)
        raise error_type(f"cannot open verified target parent: {target.parent}") from exc
    try:
        _require_same_directory_identity(
            source.parent,
            source_parent_fd,
            "source",
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        _require_same_directory_identity(
            target.parent,
            target_parent_fd,
            "target",
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        try:
            source_info = os.stat(
                source.name,
                dir_fd=source_parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise error_type(f"rename source is missing: {source}") from exc
        if (
            expected_source_identity is not None
            and source_identity(source_info) != expected_source_identity
        ):
            raise error_type(f"rename source identity changed: {source}")
        if require_directory is True and not stat.S_ISDIR(source_info.st_mode):
            raise error_type(f"rename source is not a directory: {source}")
        if require_directory is False and not stat.S_ISREG(source_info.st_mode):
            raise error_type(f"rename source is not a regular file: {source}")
        if require_directory is None and not (
            stat.S_ISDIR(source_info.st_mode) or stat.S_ISREG(source_info.st_mode)
        ):
            raise error_type(f"rename source type is not supported: {source}")

        renamed = False
        try:
            rename_entry_no_replace_at(
                source_parent_fd,
                source.name,
                target_parent_fd,
                target.name,
                collision_error=collision_error,
                error_type=error_type,
            )
            renamed = True
            _require_same_directory_identity(
                source.parent,
                source_parent_fd,
                "source",
                error_type=error_type,
                before_directory_identity_check=before_directory_identity_check,
            )
            _require_same_directory_identity(
                target.parent,
                target_parent_fd,
                "target",
                error_type=error_type,
                before_directory_identity_check=before_directory_identity_check,
            )
            os.fsync(source_parent_fd)
            if (os.fstat(source_parent_fd).st_dev, os.fstat(source_parent_fd).st_ino) != (
                os.fstat(target_parent_fd).st_dev,
                os.fstat(target_parent_fd).st_ino,
            ):
                os.fsync(target_parent_fd)
            target_info = os.stat(
                target.name,
                dir_fd=target_parent_fd,
                follow_symlinks=False,
            )
            if (
                (target_info.st_dev, target_info.st_ino)
                != (source_info.st_dev, source_info.st_ino)
                or (
                    expected_source_identity is not None
                    and source_identity(target_info) != expected_source_identity
                )
            ):
                raise error_type(f"no-replace rename target identity mismatch: {target}")
            try:
                os.stat(source.name, dir_fd=source_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise error_type(f"rename source still exists after publish: {source}")
        except (error_type, OSError) as exc:
            if renamed:
                try:
                    _compensate_rename_effect(
                        source_parent_fd,
                        source.name,
                        target_parent_fd,
                        target.name,
                        source_info,
                        source=source,
                        target=target,
                        error_type=error_type,
                    )
                    _require_same_directory_identity(
                        source.parent,
                        source_parent_fd,
                        "source",
                        error_type=error_type,
                        before_directory_identity_check=before_directory_identity_check,
                    )
                except ManualRecoveryRequired:
                    raise
                except (error_type, OSError) as compensation_exc:
                    raise _manual_recovery_required(
                        source,
                        target,
                        source_info,
                        reason="compensation-failed",
                        observed_target_info=None,
                    ) from compensation_exc
            if isinstance(exc, error_type):
                raise
            raise error_type(
                f"cannot verify no-replace rename effect: {source} -> {target}"
            ) from exc
    finally:
        os.close(target_parent_fd)
        os.close(source_parent_fd)


def read_regular_file_at(
    directory_fd: int,
    name: str,
    path: Path,
    *,
    label: str,
    expected_mode: int | None = 0o600,
    max_bytes: int | None = None,
    error_type: ErrorType,
) -> tuple[os.stat_result, bytes]:
    """Read a regular file by dirfd while binding its lexical/open identity."""
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
        raise TypeError("max_bytes must be a nonnegative integer or None")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lexical_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise error_type(f"{label} is unreadable: {path}") from exc
    try:
        opened_info = os.fstat(fd)
        if (
            not stat.S_ISREG(opened_info.st_mode)
            or opened_info.st_uid != os.getuid()
            or (
                stat.S_IMODE(opened_info.st_mode) != expected_mode
                if expected_mode is not None
                else bool(stat.S_IMODE(opened_info.st_mode) & 0o022)
            )
            or (opened_info.st_dev, opened_info.st_ino)
            != (lexical_info.st_dev, lexical_info.st_ino)
            or (max_bytes is not None and opened_info.st_size > max_bytes)
        ):
            raise error_type(f"{label} identity is invalid: {path}")
        if max_bytes is None:
            raw = read_open_file_bytes(fd)
        else:
            remaining = max_bytes + 1
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > max_bytes:
                raise error_type(f"{label} exceeds byte bound: {path}")
        final_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (final_info.st_dev, final_info.st_ino) != (
            opened_info.st_dev,
            opened_info.st_ino,
        ) or (
            final_info.st_nlink != opened_info.st_nlink
        ) or (
            max_bytes is not None and final_info.st_size != opened_info.st_size
        ):
            raise error_type(f"{label} identity changed during read: {path}")
        return opened_info, raw
    finally:
        os.close(fd)


def move_regular_file_no_replace(
    source: Path,
    target: Path,
    expected_sha256: str,
    *,
    expected_device: int,
    expected_inode: int,
    error_type: ErrorType,
    before_directory_identity_check: DirectoryObservationCallback | None = None,
) -> None:
    """Hard-link then unlink a verified regular file without overwriting."""
    try:
        source_directory_fd = open_verified_directory(
            source.parent,
            require_owner_only=True,
            error_type=error_type,
        )
    except error_type as exc:
        raise error_type("cannot open verified legacy lease directory") from exc
    try:
        target_directory_fd = open_or_create_verified_directory(
            target.parent,
            error_type=error_type,
        )
    except error_type as exc:
        os.close(source_directory_fd)
        raise error_type("cannot open verified quarantine parent") from exc
    try:
        _require_same_directory_identity(
            source.parent,
            source_directory_fd,
            "legacy lease",
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        _require_same_directory_identity(
            target.parent,
            target_directory_fd,
            "quarantine",
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        source_info, raw = read_regular_file_at(
            source_directory_fd,
            source.name,
            source,
            label="approved stale lease",
            error_type=error_type,
        )
        if (
            sha256_bytes(raw) != expected_sha256
            or (source_info.st_dev, source_info.st_ino)
            != (expected_device, expected_inode)
        ):
            raise error_type(f"approved stale lease changed: {source}")
        _require_same_directory_identity(
            source.parent,
            source_directory_fd,
            "legacy lease",
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        _require_same_directory_identity(
            target.parent,
            target_directory_fd,
            "quarantine",
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        try:
            os.link(
                source.name,
                target.name,
                src_dir_fd=source_directory_fd,
                dst_dir_fd=target_directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise error_type(f"refusing to overwrite quarantine target: {target}") from exc
        except OSError as exc:
            raise error_type(f"cannot quarantine stale lease: {source}") from exc
        os.fsync(target_directory_fd)
        target_info, target_raw = read_regular_file_at(
            target_directory_fd,
            target.name,
            target,
            label="quarantined lease",
            error_type=error_type,
        )
        if (
            target_raw != raw
            or (target_info.st_dev, target_info.st_ino)
            != (source_info.st_dev, source_info.st_ino)
        ):
            raise error_type(f"quarantined lease readback mismatch: {target}")
        _require_same_directory_identity(
            source.parent,
            source_directory_fd,
            "legacy lease",
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        _require_same_directory_identity(
            target.parent,
            target_directory_fd,
            "quarantine",
            error_type=error_type,
            before_directory_identity_check=before_directory_identity_check,
        )
        current_source = os.stat(
            source.name,
            dir_fd=source_directory_fd,
            follow_symlinks=False,
        )
        if (current_source.st_dev, current_source.st_ino) != (
            source_info.st_dev,
            source_info.st_ino,
        ):
            raise error_type(f"approved stale lease changed before removal: {source}")
        os.unlink(source.name, dir_fd=source_directory_fd)
        os.fsync(source_directory_fd)
    finally:
        os.close(target_directory_fd)
        os.close(source_directory_fd)


def resolve_under_root(
    value: str | Path,
    root: Path,
    *,
    must_exist: bool = False,
    error_type: ErrorType,
) -> Path:
    """Resolve a path and reject any result outside *root*."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    resolved_root = root.resolve()
    resolved_path = path.resolve(strict=must_exist)
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise error_type(f"path outside raw root: {resolved_path}")
    return resolved_path


def require_no_symlink_components(
    value: str | Path,
    root: Path,
    label: str,
    *,
    error_type: ErrorType,
) -> Path:
    """Return the absolute lexical path after rejecting symlink components."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    lexical_path = Path(os.path.abspath(path))
    resolved_root = root.resolve()
    resolved_path = lexical_path.resolve(strict=False)
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise error_type(f"{label} is outside raw root")

    anchor: Path | None = None
    for candidate in [lexical_path, *lexical_path.parents]:
        if candidate.resolve(strict=False) == resolved_root:
            anchor = candidate
    if anchor is None:
        raise error_type(f"{label} is outside raw root")
    if anchor.is_symlink():
        raise error_type(f"{label} has a symlink component")

    relative = lexical_path.relative_to(anchor)
    current = anchor
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise error_type(f"{label} has a symlink component")
        if not current.exists():
            break
    return lexical_path


def relative_posix(path: Path, root: Path) -> str:
    """Return *path* relative to *root* using POSIX separators."""
    return path.resolve(strict=False).relative_to(root.resolve()).as_posix()


def violates_never_touch(path: Path, root: Path, rules: list[str]) -> str | None:
    """Return the matching never-touch rule, or ``outside-root``/``None``."""
    try:
        rel = relative_posix(path, root)
    except ValueError:
        return "outside-root"
    parts = set(Path(rel).parts)
    for raw_rule in rules:
        rule = str(raw_rule).strip().strip("/")
        if not rule:
            continue
        if rel == rule or rel.startswith(rule + "/") or rule in parts:
            return str(raw_rule)
    return None


def require_safe_path(
    path: Path,
    root: Path,
    registry: dict[str, Any],
    label: str,
    *,
    error_type: ErrorType,
) -> None:
    """Reject a path covered by the registry's never-touch policy."""
    rule = violates_never_touch(path, root, list(registry.get("never_touch", [])))
    if rule:
        raise error_type(f"{label} is inside never-touch path ({rule}): {path}")


def require_movable_path(
    path: Path,
    root: Path,
    label: str,
    *,
    error_type: ErrorType,
) -> None:
    """Reject raw-root and registry/memory control paths as move sources."""
    resolved = path.resolve(strict=False)
    resolved_root = root.resolve()
    if resolved == resolved_root:
        raise error_type(f"{label} cannot be the raw root")
    registry_root = (root / "_registry").resolve(strict=False)
    if resolved == registry_root or registry_root in resolved.parents:
        raise error_type(f"{label} cannot be inside registry control paths")
    workspaces = (root / "memory" / "workspaces.yml").resolve(strict=False)
    if resolved == workspaces:
        raise error_type(f"{label} cannot be memory/workspaces.yml")


def require_safe_tree(
    path: Path,
    root: Path,
    registry: dict[str, Any],
    label: str,
    *,
    error_type: ErrorType,
) -> None:
    """Reject unsafe control paths and every symlink in a movable tree."""
    require_safe_path(path, root, registry, label, error_type=error_type)
    require_movable_path(path, root, label, error_type=error_type)
    if path.is_symlink():
        raise error_type(f"{label} is a symlink")
    if not path.is_dir():
        return
    for current, dirs, filenames in os.walk(path, followlinks=False):
        current_path = Path(current)
        for name in [*dirs, *filenames]:
            child = current_path / name
            if child.is_symlink():
                raise error_type(f"{label} has a symlink descendant")
            require_safe_path(
                child,
                root,
                registry,
                f"{label} descendant",
                error_type=error_type,
            )
            require_movable_path(
                child,
                root,
                f"{label} descendant",
                error_type=error_type,
            )


def safe_tree_identity_manifest(
    path: Path,
    label: str,
    *,
    error_type: ErrorType,
) -> tuple[tuple[str, int, int, int], ...]:
    """Capture a deterministic no-symlink device/inode/type tree manifest."""
    try:
        top = os.lstat(path)
    except OSError as exc:
        raise error_type(f"{label} identity is unreadable") from exc
    if stat.S_ISLNK(top.st_mode):
        raise error_type(f"{label} is a symlink")
    entries = [(".", top.st_dev, top.st_ino, stat.S_IFMT(top.st_mode))]
    if not stat.S_ISDIR(top.st_mode):
        return tuple(entries)
    for current, dirs, filenames in os.walk(path, followlinks=False):
        current_path = Path(current)
        for name in sorted([*dirs, *filenames]):
            child = current_path / name
            try:
                info = os.lstat(child)
            except OSError as exc:
                raise error_type(f"{label} descendant identity is unreadable") from exc
            if stat.S_ISLNK(info.st_mode):
                raise error_type(f"{label} has a symlink descendant")
            entries.append(
                (
                    child.relative_to(path).as_posix(),
                    info.st_dev,
                    info.st_ino,
                    stat.S_IFMT(info.st_mode),
                )
            )
    return tuple(sorted(entries))
