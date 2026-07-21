"""Anchored, read-only observations used by Safe Librarian proposals."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path

from .. import librarian_contract
from ..canonical_json import canonical_json_bytes, sha256_bytes


_MAX_ENTRIES = 4096
_MAX_DEPTH = 16
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_PROPOSAL_ID = re.compile(r"p-[0-9a-f]{32}")
_HARD_PROTECTED_PREFIXES = (
    ("_registry",),
    ("memory",),
    ("worktrees",),
    ("graphify-out",),
    (".agents",),
    (".codex",),
    (".claude",),
    (".gemini",),
    (".harnesskit",),
    ("agents", "mnemosyne"),
    ("mirrors",),
    ("private",),
)
_HARD_PROTECTED_NAMES = frozenset(
    (".agents", ".codex", ".claude", ".gemini", ".harnesskit", "graphify-out")
)


class LibrarianSnapshotError(librarian_contract.LibrarianOperationError):
    """A proposal observation cannot be completed without guessing."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        next_safe_action: str,
    ) -> None:
        super().__init__(
            message,
            reason_code=reason_code,
            next_safe_action=next_safe_action,
        )


def _fail(message: str, reason_code: str, next_safe_action: str) -> None:
    raise LibrarianSnapshotError(
        message,
        reason_code=reason_code,
        next_safe_action=next_safe_action,
    )


def _components(value: object) -> tuple[str, ...]:
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or any(ord(character) < 32 for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        _fail("relative path is invalid", "SCOPE_UNSAFE", "choose-scope")
    parts = tuple(value.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        _fail("relative path is invalid", "SCOPE_UNSAFE", "choose-scope")
    return parts


def _has_prefix(parts: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(parts) >= len(prefix) and parts[: len(prefix)] == prefix


def _has_folded_prefix(parts: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return _has_prefix(
        tuple(part.casefold() for part in parts),
        tuple(part.casefold() for part in prefix),
    )


def _relative_policy_parts(root: Path, value: object) -> tuple[str, ...] | None:
    if type(value) is not str:
        return None
    candidate = Path(value)
    try:
        parts = candidate.relative_to(root).parts
    except ValueError:
        return None
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    return tuple(parts)


def _policy_paths(
    root: Path,
    compiled_policy: object,
) -> tuple[
    tuple[tuple[str, ...], ...],
    tuple[tuple[tuple[str, ...], str, str], ...],
    tuple[tuple[tuple[str, ...], str], ...],
]:
    protected = list(_HARD_PROTECTED_PREFIXES)
    for value in getattr(compiled_policy, "never_touch", ()):
        components = getattr(value, "components", None)
        if type(components) is tuple and components:
            protected.append(tuple(components))
    for value in getattr(compiled_policy, "archive_roots", ()):
        components = _relative_policy_parts(root, getattr(value, "root", None))
        if components:
            protected.append(components)

    workstreams = []
    for value in getattr(compiled_policy, "workstreams", ()):
        components = _relative_policy_parts(
            root,
            getattr(value, "project_home", None),
        )
        identifier = getattr(value, "id", None)
        lifecycle = getattr(value, "lifecycle", None)
        if (
            components
            and type(identifier) is str
            and identifier
            and type(lifecycle) is str
            and lifecycle
        ):
            workstreams.append((components, identifier, lifecycle))

    categories = []
    for value in getattr(compiled_policy, "categories", ()):
        components = _relative_policy_parts(root, getattr(value, "target", None))
        identifier = getattr(value, "id", None)
        if components and type(identifier) is str and identifier:
            categories.append((components, identifier))
    return tuple(protected), tuple(workstreams), tuple(categories)


def _is_hard_protected(parts: tuple[str, ...]) -> bool:
    folded = tuple(part.casefold() for part in parts)
    return (
        any(part in _HARD_PROTECTED_NAMES for part in folded)
        or bool(folded and folded[0].endswith("-cleanup-audit"))
        or any(_has_prefix(folded, prefix) for prefix in _HARD_PROTECTED_PREFIXES)
    )


def _destination_owners(
    target_parts: tuple[str, ...],
    workstreams: tuple[tuple[tuple[str, ...], str, str], ...],
    categories: tuple[tuple[tuple[str, ...], str], ...],
) -> tuple[tuple[str, str], ...]:
    workstream_owners = tuple(
        ("workstream", identifier)
        for prefix, identifier, lifecycle in workstreams
        if lifecycle.casefold() == "active"
        and len(target_parts) > len(prefix)
        and _has_folded_prefix(target_parts, prefix)
    )
    category_owners = tuple(
        ("manual_category", identifier)
        for prefix, identifier in categories
        if len(target_parts) > len(prefix)
        and _has_folded_prefix(target_parts, prefix)
    )
    return category_owners or workstream_owners


def _inactive_workstream_prefixes(
    workstreams: tuple[tuple[tuple[str, ...], str, str], ...],
) -> tuple[tuple[str, ...], ...]:
    return tuple(
        prefix
        for prefix, _identifier, lifecycle in workstreams
        if lifecycle.casefold() != "active"
    )


def _belongs_to_inactive_workstream(
    parts: tuple[str, ...],
    workstreams: tuple[tuple[tuple[str, ...], str, str], ...],
) -> bool:
    return any(
        _has_folded_prefix(parts, prefix)
        for prefix in _inactive_workstream_prefixes(workstreams)
    )


def resolve_destination_owner(
    root: Path,
    compiled_policy: object,
    target_relative_path: object,
) -> tuple[str, str]:
    """Resolve one category-first owner; proposal validation still rechecks safety."""

    root_path = Path(root)
    target_parts = _components(target_relative_path)
    _protected, workstreams, categories = _policy_paths(root_path, compiled_policy)
    owners = _destination_owners(target_parts, workstreams, categories)
    if len(owners) != 1:
        _fail(
            "target does not have one exact destination",
            "DESTINATION_INVALID",
            "correct-request",
        )
    return owners[0]


def _validate_policy_scope(
    *,
    root: Path,
    compiled_policy: object,
    source_parts: tuple[str, ...],
    target_parts: tuple[str, ...],
    destination_kind: object,
    destination_id: object,
) -> None:
    protected, workstreams, categories = _policy_paths(root, compiled_policy)
    for parts in (source_parts, target_parts):
        if _is_hard_protected(parts) or any(
            _has_folded_prefix(parts, prefix) for prefix in protected
        ):
            _fail("path is protected", "SCOPE_UNSAFE", "choose-scope")

    if any(
        _belongs_to_inactive_workstream(parts, workstreams)
        for parts in (source_parts, target_parts)
    ):
        _fail(
            "path belongs to an inactive workstream",
            "WORKSTREAM_INACTIVE",
            "inspect",
        )

    if type(destination_kind) is not str or type(destination_id) is not str:
        _fail("destination is invalid", "DESTINATION_INVALID", "correct-request")
    declared = (destination_kind, destination_id)
    owners = _destination_owners(target_parts, workstreams, categories)

    if destination_kind == "workstream":
        matching = [item for item in workstreams if item[1] == destination_id]
        if matching and all(item[2].casefold() != "active" for item in matching):
            _fail(
                "destination workstream is inactive",
                "WORKSTREAM_INACTIVE",
                "inspect",
            )
    elif destination_kind != "manual_category":
        _fail("destination is invalid", "DESTINATION_INVALID", "correct-request")

    if owners != (declared,):
        _fail(
            "target does not have one exact declared destination",
            "DESTINATION_INVALID",
            "correct-request",
        )


def _validate_request_parts(
    scope: object,
    bounds: object,
    payload: object,
) -> tuple[tuple[str, ...], tuple[str, ...], int, int, int]:
    if not isinstance(scope, Mapping) or set(scope) != {
        "proposal_id",
        "source_relative_path",
        "target_relative_path",
    }:
        _fail("proposal scope is invalid", "SCOPE_UNSAFE", "correct-request")
    if (
        type(scope["proposal_id"]) is not str
        or _PROPOSAL_ID.fullmatch(scope["proposal_id"]) is None
    ):
        _fail("proposal id is invalid", "SCOPE_UNSAFE", "correct-request")
    source_parts = _components(scope["source_relative_path"])
    target_parts = _components(scope["target_relative_path"])

    if not isinstance(bounds, Mapping) or set(bounds) != {
        "max_entries",
        "max_depth",
        "max_total_bytes",
    }:
        _fail("proposal bounds are invalid", "SCOPE_LIMIT_EXCEEDED", "narrow-scope")
    max_entries = bounds["max_entries"]
    max_depth = bounds["max_depth"]
    max_total_bytes = bounds["max_total_bytes"]
    if (
        type(max_entries) is not int
        or not 1 <= max_entries <= _MAX_ENTRIES
        or type(max_depth) is not int
        or not 0 <= max_depth <= _MAX_DEPTH
        or type(max_total_bytes) is not int
        or not 0 <= max_total_bytes <= _MAX_TOTAL_BYTES
    ):
        _fail("proposal bounds are invalid", "SCOPE_LIMIT_EXCEEDED", "narrow-scope")

    if not isinstance(payload, Mapping) or set(payload) != {
        "destination_kind",
        "destination_id",
        "reason",
    }:
        _fail("proposal destination is invalid", "DESTINATION_INVALID", "correct-request")
    if (
        type(payload["reason"]) is not str
        or not payload["reason"]
        or payload["reason"] != payload["reason"].strip()
    ):
        _fail("proposal reason is invalid", "DESTINATION_INVALID", "correct-request")
    return source_parts, target_parts, max_entries, max_depth, max_total_bytes


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _open_root(root: Path) -> tuple[int, os.stat_result]:
    try:
        lexical = os.stat(root, follow_symlinks=False)
        descriptor = os.open(root, _directory_flags())
    except OSError as exc:
        _fail("root cannot be opened safely", "SCOPE_UNSAFE", "choose-scope")
        raise AssertionError("unreachable") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(lexical.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or (lexical.st_dev, lexical.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        os.close(descriptor)
        _fail("root identity changed", "SCOPE_UNSAFE", "choose-scope")
    return descriptor, opened


def _open_parent(
    root_fd: int,
    parts: tuple[str, ...],
    *,
    root_device: int,
    missing_reason: str,
) -> int:
    current = os.dup(root_fd)
    try:
        for component in parts:
            try:
                lexical = os.stat(
                    component,
                    dir_fd=current,
                    follow_symlinks=False,
                )
                child = os.open(component, _directory_flags(), dir_fd=current)
            except OSError:
                _fail(
                    "parent cannot be opened safely",
                    missing_reason,
                    "correct-request" if missing_reason == "DESTINATION_INVALID" else "inspect",
                )
            opened = os.fstat(child)
            if (
                not stat.S_ISDIR(lexical.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or (lexical.st_dev, lexical.st_ino)
                != (opened.st_dev, opened.st_ino)
                or opened.st_dev != root_device
            ):
                os.close(child)
                _fail("parent is unsafe", "SCOPE_UNSAFE", "choose-scope")
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _stable_file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _stable_directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _snapshot_regular_file(
    parent_fd: int,
    leaf: str,
    relative_path: str,
    *,
    root_device: int,
    max_total_bytes: int,
) -> dict[str, object]:
    parent_before = os.fstat(parent_fd)
    try:
        lexical = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        _fail("source cannot be observed", "SOURCE_CHANGED", "create-proposal")
    if not stat.S_ISREG(lexical.st_mode):
        _fail("source type is unsupported", "SOURCE_UNSUPPORTED", "inspect")
    try:
        descriptor = os.open(leaf, _file_flags(), dir_fd=parent_fd)
    except OSError:
        _fail("source cannot be opened safely", "SOURCE_CHANGED", "create-proposal")
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stable_file_identity(opened) != _stable_file_identity(lexical)
        ):
            _fail("source identity changed", "SOURCE_CHANGED", "create-proposal")
        if opened.st_dev != root_device:
            _fail("source crosses a filesystem boundary", "SCOPE_UNSAFE", "choose-scope")
        if opened.st_uid != os.getuid() or opened.st_nlink != 1:
            _fail("source identity is unsupported", "SOURCE_UNSUPPORTED", "inspect")
        if opened.st_size > max_total_bytes:
            _fail("source exceeds the admitted bound", "SCOPE_LIMIT_EXCEEDED", "narrow-scope")

        digest = hashlib.sha256()
        consumed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > max_total_bytes:
                _fail(
                    "source exceeds the admitted bound",
                    "SCOPE_LIMIT_EXCEEDED",
                    "narrow-scope",
                )
            digest.update(chunk)
        final = os.fstat(descriptor)
        if (
            _stable_file_identity(final) != _stable_file_identity(opened)
            or consumed != opened.st_size
        ):
            _fail("source changed during observation", "SOURCE_CHANGED", "create-proposal")
    finally:
        os.close(descriptor)

    try:
        rebound = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        _fail("source path changed during observation", "SOURCE_CHANGED", "create-proposal")
    if _stable_file_identity(rebound) != _stable_file_identity(opened):
        _fail("source path changed during observation", "SOURCE_CHANGED", "create-proposal")

    parent_after = os.fstat(parent_fd)
    if (parent_before.st_dev, parent_before.st_ino) != (
        parent_after.st_dev,
        parent_after.st_ino,
    ):
        _fail("source parent identity changed", "SOURCE_CHANGED", "create-proposal")
    snapshot = {
        "kind": "regular_file",
        "relative_path": relative_path,
        "device": opened.st_dev,
        "inode": opened.st_ino,
        "owner": opened.st_uid,
        "mode": stat.S_IMODE(opened.st_mode),
        "link_count": opened.st_nlink,
        "size": opened.st_size,
        "modified_time_ns": opened.st_mtime_ns,
        "parent": {
            "device": parent_before.st_dev,
            "inode": parent_before.st_ino,
        },
        "content_sha256": digest.hexdigest(),
    }
    snapshot["snapshot_sha256"] = sha256_bytes(canonical_json_bytes(snapshot))
    return snapshot


def _validate_directory_member(
    *,
    root: Path,
    compiled_policy: object,
    absolute_parts: tuple[str, ...],
) -> None:
    protected, workstreams, _categories = _policy_paths(root, compiled_policy)
    if _is_hard_protected(absolute_parts) or any(
        _has_folded_prefix(absolute_parts, prefix) for prefix in protected
    ):
        _fail("directory contains a protected path", "SCOPE_UNSAFE", "choose-scope")
    if _belongs_to_inactive_workstream(absolute_parts, workstreams):
        _fail(
            "directory contains an inactive workstream",
            "WORKSTREAM_INACTIVE",
            "inspect",
        )


def _manifest_file_entry(
    parent_fd: int,
    leaf: str,
    relative_path: str,
    lexical: os.stat_result,
    *,
    root_device: int,
    remaining_bytes: int,
) -> tuple[dict[str, object], int]:
    try:
        descriptor = os.open(leaf, _file_flags(), dir_fd=parent_fd)
    except OSError:
        _fail("directory file cannot be opened safely", "SOURCE_CHANGED", "create-proposal")
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stable_file_identity(opened) != _stable_file_identity(lexical)
        ):
            _fail("directory file identity changed", "SOURCE_CHANGED", "create-proposal")
        if opened.st_dev != root_device:
            _fail("directory crosses a filesystem boundary", "SCOPE_UNSAFE", "choose-scope")
        if opened.st_uid != os.getuid() or opened.st_nlink != 1:
            _fail("directory file is unsupported", "SOURCE_UNSUPPORTED", "inspect")
        if opened.st_size > remaining_bytes:
            _fail("directory exceeds the admitted byte bound", "SCOPE_LIMIT_EXCEEDED", "narrow-scope")

        digest = hashlib.sha256()
        consumed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > remaining_bytes:
                _fail(
                    "directory exceeds the admitted byte bound",
                    "SCOPE_LIMIT_EXCEEDED",
                    "narrow-scope",
                )
            digest.update(chunk)
        final = os.fstat(descriptor)
        if (
            _stable_file_identity(final) != _stable_file_identity(opened)
            or consumed != opened.st_size
        ):
            _fail("directory file changed", "SOURCE_CHANGED", "create-proposal")
    finally:
        os.close(descriptor)

    try:
        rebound = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        _fail("directory file path changed", "SOURCE_CHANGED", "create-proposal")
    if _stable_file_identity(rebound) != _stable_file_identity(opened):
        _fail("directory file path changed", "SOURCE_CHANGED", "create-proposal")
    return (
        {
            "relative_path": relative_path,
            "entry_type": "file",
            "device": opened.st_dev,
            "inode": opened.st_ino,
            "owner": opened.st_uid,
            "mode": stat.S_IMODE(opened.st_mode),
            "size": opened.st_size,
            "modified_time_ns": opened.st_mtime_ns,
            "content_sha256": digest.hexdigest(),
        },
        consumed,
    )


def _snapshot_directory(
    parent_fd: int,
    leaf: str,
    relative_path: str,
    *,
    root: Path,
    compiled_policy: object,
    source_parts: tuple[str, ...],
    root_device: int,
    max_entries: int,
    max_depth: int,
    max_total_bytes: int,
) -> dict[str, object]:
    parent_before = os.fstat(parent_fd)
    try:
        lexical = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        _fail("source directory cannot be observed", "SOURCE_CHANGED", "create-proposal")
    if not stat.S_ISDIR(lexical.st_mode):
        _fail("source type is unsupported", "SOURCE_UNSUPPORTED", "inspect")
    try:
        descriptor = os.open(leaf, _directory_flags(), dir_fd=parent_fd)
    except OSError:
        _fail("source directory cannot be opened safely", "SOURCE_CHANGED", "create-proposal")

    manifest: list[dict[str, object]] = []
    file_count = 0
    total_bytes = 0

    def walk(
        directory_fd: int,
        base_relative: tuple[str, ...],
        base_absolute: tuple[str, ...],
        directory_depth: int,
    ) -> None:
        nonlocal file_count, total_bytes
        directory_before = os.fstat(directory_fd)
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError:
            _fail("source directory cannot be listed", "SOURCE_CHANGED", "create-proposal")
        for name in names:
            if (
                not name
                or name in {".", ".."}
                or "/" in name
                or "\\" in name
                or any(ord(character) < 32 for character in name)
                or any(0xD800 <= ord(character) <= 0xDFFF for character in name)
            ):
                _fail("directory entry name is unsafe", "SCOPE_UNSAFE", "choose-scope")
            entry_depth = directory_depth + 1
            if entry_depth > max_depth or len(manifest) >= max_entries:
                _fail("directory exceeds admitted bounds", "SCOPE_LIMIT_EXCEEDED", "narrow-scope")
            member_relative_parts = base_relative + (name,)
            member_absolute_parts = base_absolute + (name,)
            member_relative = "/".join(member_relative_parts)
            _validate_directory_member(
                root=root,
                compiled_policy=compiled_policy,
                absolute_parts=member_absolute_parts,
            )
            try:
                member_lexical = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError:
                _fail("directory member changed", "SOURCE_CHANGED", "create-proposal")
            if member_lexical.st_dev != root_device:
                _fail("directory crosses a filesystem boundary", "SCOPE_UNSAFE", "choose-scope")
            if member_lexical.st_uid != os.getuid():
                _fail("directory member is unsupported", "SOURCE_UNSUPPORTED", "inspect")
            if stat.S_ISREG(member_lexical.st_mode):
                if member_lexical.st_nlink != 1:
                    _fail("directory file has multiple links", "SOURCE_UNSUPPORTED", "inspect")
                entry, consumed = _manifest_file_entry(
                    directory_fd,
                    name,
                    member_relative,
                    member_lexical,
                    root_device=root_device,
                    remaining_bytes=max_total_bytes - total_bytes,
                )
                manifest.append(entry)
                file_count += 1
                total_bytes += consumed
                continue
            if not stat.S_ISDIR(member_lexical.st_mode):
                _fail("directory member type is unsupported", "SOURCE_UNSUPPORTED", "inspect")
            try:
                child_fd = os.open(name, _directory_flags(), dir_fd=directory_fd)
            except OSError:
                _fail("directory member cannot be opened safely", "SOURCE_CHANGED", "create-proposal")
            try:
                child_opened = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(child_opened.st_mode)
                    or _stable_directory_identity(child_opened)
                    != _stable_directory_identity(member_lexical)
                    or child_opened.st_dev != root_device
                    or child_opened.st_uid != os.getuid()
                ):
                    _fail("directory member identity changed", "SOURCE_CHANGED", "create-proposal")
                manifest.append(
                    {
                        "relative_path": member_relative,
                        "entry_type": "directory",
                        "device": child_opened.st_dev,
                        "inode": child_opened.st_ino,
                        "owner": child_opened.st_uid,
                        "mode": stat.S_IMODE(child_opened.st_mode),
                        "size": 0,
                        "modified_time_ns": child_opened.st_mtime_ns,
                    }
                )
                walk(
                    child_fd,
                    member_relative_parts,
                    member_absolute_parts,
                    entry_depth,
                )
                child_final = os.fstat(child_fd)
                if _stable_directory_identity(child_final) != _stable_directory_identity(
                    child_opened
                ):
                    _fail("directory member changed", "SOURCE_CHANGED", "create-proposal")
            finally:
                os.close(child_fd)
            try:
                child_rebound = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError:
                _fail("directory member path changed", "SOURCE_CHANGED", "create-proposal")
            if _stable_directory_identity(child_rebound) != _stable_directory_identity(
                child_opened
            ):
                _fail("directory member path changed", "SOURCE_CHANGED", "create-proposal")

        directory_after = os.fstat(directory_fd)
        if _stable_directory_identity(directory_after) != _stable_directory_identity(
            directory_before
        ):
            _fail("source directory changed", "SOURCE_CHANGED", "create-proposal")

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _stable_directory_identity(opened) != _stable_directory_identity(lexical)
        ):
            _fail("source directory identity changed", "SOURCE_CHANGED", "create-proposal")
        if opened.st_dev != root_device:
            _fail("source crosses a filesystem boundary", "SCOPE_UNSAFE", "choose-scope")
        if opened.st_uid != os.getuid():
            _fail("source directory is unsupported", "SOURCE_UNSUPPORTED", "inspect")
        walk(descriptor, (), source_parts, 0)
        final = os.fstat(descriptor)
        if _stable_directory_identity(final) != _stable_directory_identity(opened):
            _fail("source directory changed", "SOURCE_CHANGED", "create-proposal")
    finally:
        os.close(descriptor)

    try:
        rebound = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        _fail("source directory path changed", "SOURCE_CHANGED", "create-proposal")
    if _stable_directory_identity(rebound) != _stable_directory_identity(opened):
        _fail("source directory path changed", "SOURCE_CHANGED", "create-proposal")
    parent_after = os.fstat(parent_fd)
    if (parent_before.st_dev, parent_before.st_ino) != (
        parent_after.st_dev,
        parent_after.st_ino,
    ):
        _fail("source parent identity changed", "SOURCE_CHANGED", "create-proposal")

    manifest.sort(key=lambda entry: entry["relative_path"])
    snapshot = {
        "kind": "directory",
        "relative_path": relative_path,
        "device": opened.st_dev,
        "inode": opened.st_ino,
        "owner": opened.st_uid,
        "mode": stat.S_IMODE(opened.st_mode),
        "modified_time_ns": opened.st_mtime_ns,
        "parent": {
            "device": parent_before.st_dev,
            "inode": parent_before.st_ino,
        },
        "entry_count": len(manifest),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "manifest_sha256": sha256_bytes(canonical_json_bytes(manifest)),
    }
    snapshot["snapshot_sha256"] = sha256_bytes(canonical_json_bytes(snapshot))
    return snapshot


def _require_target_absent(
    parent_fd: int,
    leaf: str,
    relative_path: str,
) -> dict[str, object]:
    parent = os.fstat(parent_fd)
    try:
        os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return {
            "observed_absent": True,
            "relative_path": relative_path,
            "parent": {"device": parent.st_dev, "inode": parent.st_ino},
        }
    except OSError:
        _fail("target absence cannot be proven", "SCOPE_UNSAFE", "choose-scope")
    _fail("target already exists", "TARGET_COLLISION", "create-proposal")


def observe_proposal(
    root: Path,
    compiled_policy: object,
    scope: Mapping[str, object],
    bounds: Mapping[str, object],
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Observe one exact proposal source and absent target without writing."""

    source_parts, target_parts, max_entries, max_depth, max_total_bytes = (
        _validate_request_parts(
            scope,
            bounds,
            payload,
        )
    )
    root_path = Path(root)
    _validate_policy_scope(
        root=root_path,
        compiled_policy=compiled_policy,
        source_parts=source_parts,
        target_parts=target_parts,
        destination_kind=payload["destination_kind"],
        destination_id=payload["destination_id"],
    )

    root_fd, root_info = _open_root(root_path)
    source_parent_fd = -1
    target_parent_fd = -1
    try:
        source_parent_fd = _open_parent(
            root_fd,
            source_parts[:-1],
            root_device=root_info.st_dev,
            missing_reason="SOURCE_CHANGED",
        )
        target_parent_fd = _open_parent(
            root_fd,
            target_parts[:-1],
            root_device=root_info.st_dev,
            missing_reason="DESTINATION_INVALID",
        )
        target_absent = _require_target_absent(
            target_parent_fd,
            target_parts[-1],
            "/".join(target_parts),
        )
        try:
            source_type = os.stat(
                source_parts[-1],
                dir_fd=source_parent_fd,
                follow_symlinks=False,
            ).st_mode
        except OSError:
            _fail("source cannot be observed", "SOURCE_CHANGED", "create-proposal")
        if stat.S_ISREG(source_type):
            source_snapshot = _snapshot_regular_file(
                source_parent_fd,
                source_parts[-1],
                "/".join(source_parts),
                root_device=root_info.st_dev,
                max_total_bytes=max_total_bytes,
            )
        elif stat.S_ISDIR(source_type):
            source_snapshot = _snapshot_directory(
                source_parent_fd,
                source_parts[-1],
                "/".join(source_parts),
                root=root_path,
                compiled_policy=compiled_policy,
                source_parts=source_parts,
                root_device=root_info.st_dev,
                max_entries=max_entries,
                max_depth=max_depth,
                max_total_bytes=max_total_bytes,
            )
        else:
            _fail("source type is unsupported", "SOURCE_UNSUPPORTED", "inspect")
        if source_snapshot["device"] != target_absent["parent"]["device"]:
            _fail("source and target cross filesystems", "SCOPE_UNSAFE", "choose-scope")
        if _require_target_absent(
            target_parent_fd,
            target_parts[-1],
            "/".join(target_parts),
        ) != target_absent:
            _fail("target parent identity changed", "SOURCE_CHANGED", "create-proposal")
        return {
            "source_snapshot": source_snapshot,
            "target_absent": target_absent,
        }
    finally:
        if target_parent_fd >= 0:
            os.close(target_parent_fd)
        if source_parent_fd >= 0:
            os.close(source_parent_fd)
        os.close(root_fd)


def observe_regular_file(
    root: Path,
    compiled_policy: object,
    relative_path: str,
    *,
    max_total_bytes: int,
) -> dict[str, object]:
    """Capture one exact active/unassigned regular file without inventing a target."""

    parts = _components(relative_path)
    if (
        type(max_total_bytes) is not int
        or not 0 <= max_total_bytes <= _MAX_TOTAL_BYTES
    ):
        _fail(
            "source observation bound is invalid",
            "SCOPE_LIMIT_EXCEEDED",
            "narrow-scope",
        )
    protected, workstreams, _categories = _policy_paths(Path(root), compiled_policy)
    if _is_hard_protected(parts) or any(
        _has_folded_prefix(parts, prefix) for prefix in protected
    ):
        _fail("source path is protected", "SCOPE_UNSAFE", "choose-scope")
    if any(
        lifecycle.casefold() != "active" and _has_folded_prefix(parts, prefix)
        for prefix, _identifier, lifecycle in workstreams
    ):
        _fail(
            "source belongs to an inactive Workstream",
            "WORKSTREAM_INACTIVE",
            "inspect",
        )
    root_path = Path(root)
    root_fd, root_info = _open_root(root_path)
    parent_fd = -1
    try:
        parent_fd = _open_parent(
            root_fd,
            parts[:-1],
            root_device=root_info.st_dev,
            missing_reason="SOURCE_CHANGED",
        )
        return _snapshot_regular_file(
            parent_fd,
            parts[-1],
            relative_path,
            root_device=root_info.st_dev,
            max_total_bytes=max_total_bytes,
        )
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


def verify_placement_pre_move(
    *,
    root: Path,
    compiled_policy: object,
    scope: Mapping[str, object],
    bounds: Mapping[str, object],
    payload: Mapping[str, object],
    expected_observation: Mapping[str, object],
) -> dict[str, object]:
    """Require the exact proposal observation immediately before placement."""

    observed = observe_proposal(root, compiled_policy, scope, bounds, payload)
    _require_expected_observation(
        expected_observation,
        source_relative_path=observed["source_snapshot"]["relative_path"],
        target_relative_path=observed["target_absent"]["relative_path"],
    )
    if observed != dict(expected_observation):
        _fail(
            "placement source or target evidence changed",
            "SOURCE_CHANGED",
            "create-proposal",
        )
    return observed


def _require_expected_observation(
    value: object,
    *,
    source_relative_path: str,
    target_relative_path: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"source_snapshot", "target_absent"}
        or type(value["source_snapshot"]) is not dict
        or type(value["target_absent"]) is not dict
    ):
        _fail(
            "placement proposal observation is invalid",
            "PROPOSAL_MISMATCH",
            "inspect-pending",
        )
    source_snapshot = value["source_snapshot"]
    target_absent = value["target_absent"]
    if (
        source_snapshot.get("kind") not in {"regular_file", "directory"}
        or source_snapshot.get("relative_path") != source_relative_path
        or type(source_snapshot.get("snapshot_sha256")) is not str
        or set(target_absent) != {"observed_absent", "relative_path", "parent"}
        or target_absent["observed_absent"] is not True
        or target_absent["relative_path"] != target_relative_path
        or type(source_snapshot.get("parent")) is not dict
        or type(target_absent["parent"]) is not dict
    ):
        _fail(
            "placement proposal observation is invalid",
            "PROPOSAL_MISMATCH",
            "inspect-pending",
        )
    unsigned_snapshot = dict(source_snapshot)
    snapshot_sha256 = unsigned_snapshot.pop("snapshot_sha256")
    if sha256_bytes(canonical_json_bytes(unsigned_snapshot)) != snapshot_sha256:
        _fail(
            "placement proposal snapshot identity is invalid",
            "PROPOSAL_MISMATCH",
            "inspect-pending",
        )
    for parent in (source_snapshot["parent"], target_absent["parent"]):
        if (
            set(parent) != {"device", "inode"}
            or type(parent["device"]) is not int
            or parent["device"] < 0
            or type(parent["inode"]) is not int
            or parent["inode"] <= 0
        ):
            _fail(
                "placement proposal parent identity is invalid",
                "PROPOSAL_MISMATCH",
                "inspect-pending",
            )
    return source_snapshot, target_absent


def _placement_recovery_required(message: str) -> None:
    _fail(
        message,
        "PLACEMENT_RECOVERY_REQUIRED",
        "inspect-recovery",
    )


def _require_exact_parent(
    parent_fd: int,
    expected: Mapping[str, object],
    label: str,
) -> None:
    observed = os.fstat(parent_fd)
    if (observed.st_dev, observed.st_ino) != (
        expected["device"],
        expected["inode"],
    ):
        _placement_recovery_required(f"{label} parent identity changed")


def _require_source_absent(
    parent_fd: int,
    leaf: str,
    relative_path: str,
) -> dict[str, object]:
    parent = os.fstat(parent_fd)
    try:
        os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return {
            "observed_absent": True,
            "relative_path": relative_path,
            "parent": {"device": parent.st_dev, "inode": parent.st_ino},
        }
    except OSError:
        _placement_recovery_required("placement source absence cannot be proven")
    _placement_recovery_required("placement source still exists")
    raise AssertionError("unreachable")


def _snapshot_matches_relocated_source(
    expected: Mapping[str, object],
    observed: Mapping[str, object],
) -> bool:
    relocation_fields = {"relative_path", "parent", "snapshot_sha256"}
    return set(expected) == set(observed) and all(
        expected[key] == observed[key]
        for key in expected
        if key not in relocation_fields
    )


def verify_placement_post_move(
    *,
    root: Path,
    compiled_policy: object,
    scope: Mapping[str, object],
    bounds: Mapping[str, object],
    payload: Mapping[str, object],
    expected_observation: Mapping[str, object],
) -> dict[str, object]:
    """Prove exact source absence and target snapshot after one placement."""

    source_parts, target_parts, max_entries, max_depth, max_total_bytes = (
        _validate_request_parts(scope, bounds, payload)
    )
    source_relative_path = "/".join(source_parts)
    target_relative_path = "/".join(target_parts)
    expected_source, expected_target_absent = _require_expected_observation(
        expected_observation,
        source_relative_path=source_relative_path,
        target_relative_path=target_relative_path,
    )
    root_path = Path(root)
    root_fd = -1
    source_parent_fd = -1
    target_parent_fd = -1
    try:
        _validate_policy_scope(
            root=root_path,
            compiled_policy=compiled_policy,
            source_parts=source_parts,
            target_parts=target_parts,
            destination_kind=payload["destination_kind"],
            destination_id=payload["destination_id"],
        )
        root_fd, root_info = _open_root(root_path)
        source_parent_fd = _open_parent(
            root_fd,
            source_parts[:-1],
            root_device=root_info.st_dev,
            missing_reason="SOURCE_CHANGED",
        )
        target_parent_fd = _open_parent(
            root_fd,
            target_parts[:-1],
            root_device=root_info.st_dev,
            missing_reason="DESTINATION_INVALID",
        )
        _require_exact_parent(
            source_parent_fd,
            expected_source["parent"],
            "placement source",
        )
        _require_exact_parent(
            target_parent_fd,
            expected_target_absent["parent"],
            "placement target",
        )
        source_absent = _require_source_absent(
            source_parent_fd,
            source_parts[-1],
            source_relative_path,
        )
        try:
            target_type = os.stat(
                target_parts[-1],
                dir_fd=target_parent_fd,
                follow_symlinks=False,
            ).st_mode
        except OSError:
            _placement_recovery_required("placement target cannot be observed")
        if expected_source["kind"] == "regular_file" and stat.S_ISREG(target_type):
            target_snapshot = _snapshot_regular_file(
                target_parent_fd,
                target_parts[-1],
                target_relative_path,
                root_device=root_info.st_dev,
                max_total_bytes=max_total_bytes,
            )
        elif expected_source["kind"] == "directory" and stat.S_ISDIR(target_type):
            target_snapshot = _snapshot_directory(
                target_parent_fd,
                target_parts[-1],
                target_relative_path,
                root=root_path,
                compiled_policy=compiled_policy,
                source_parts=target_parts,
                root_device=root_info.st_dev,
                max_entries=max_entries,
                max_depth=max_depth,
                max_total_bytes=max_total_bytes,
            )
        else:
            _placement_recovery_required("placement target type changed")
        if not _snapshot_matches_relocated_source(
            expected_source,
            target_snapshot,
        ):
            _placement_recovery_required("placement target snapshot changed")
        if (
            _require_source_absent(
                source_parent_fd,
                source_parts[-1],
                source_relative_path,
            )
            != source_absent
        ):
            _placement_recovery_required("placement source parent identity changed")
        _require_exact_parent(
            target_parent_fd,
            expected_target_absent["parent"],
            "placement target",
        )
        return {
            "source_absent": source_absent,
            "target_snapshot": target_snapshot,
        }
    except LibrarianSnapshotError as exc:
        if exc.reason_code == "PLACEMENT_RECOVERY_REQUIRED":
            raise
        raise LibrarianSnapshotError(
            "placement post-move evidence cannot be proven",
            reason_code="PLACEMENT_RECOVERY_REQUIRED",
            next_safe_action="inspect-recovery",
        ) from exc
    except OSError as exc:
        raise LibrarianSnapshotError(
            "placement post-move evidence cannot be proven",
            reason_code="PLACEMENT_RECOVERY_REQUIRED",
            next_safe_action="inspect-recovery",
        ) from exc
    finally:
        if target_parent_fd >= 0:
            os.close(target_parent_fd)
        if source_parent_fd >= 0:
            os.close(source_parent_fd)
        if root_fd >= 0:
            os.close(root_fd)


def classify_placement_state(
    *,
    root: Path,
    compiled_policy: object,
    scope: Mapping[str, object],
    bounds: Mapping[str, object],
    payload: Mapping[str, object],
    expected_observation: Mapping[str, object],
) -> dict[str, object]:
    """Classify one finalized-intent state without guessing a rename outcome."""

    source_parts, target_parts, max_entries, max_depth, max_total_bytes = (
        _validate_request_parts(scope, bounds, payload)
    )
    source_relative_path = "/".join(source_parts)
    target_relative_path = "/".join(target_parts)
    expected_source, expected_target_absent = _require_expected_observation(
        expected_observation,
        source_relative_path=source_relative_path,
        target_relative_path=target_relative_path,
    )
    root_path = Path(root)
    _validate_policy_scope(
        root=root_path,
        compiled_policy=compiled_policy,
        source_parts=source_parts,
        target_parts=target_parts,
        destination_kind=payload["destination_kind"],
        destination_id=payload["destination_id"],
    )
    root_fd, root_info = _open_root(root_path)
    source_parent_fd = -1
    target_parent_fd = -1
    try:
        source_parent_fd = _open_parent(
            root_fd,
            source_parts[:-1],
            root_device=root_info.st_dev,
            missing_reason="SOURCE_CHANGED",
        )
        target_parent_fd = _open_parent(
            root_fd,
            target_parts[:-1],
            root_device=root_info.st_dev,
            missing_reason="DESTINATION_INVALID",
        )
        source_parent = os.fstat(source_parent_fd)
        target_parent = os.fstat(target_parent_fd)
        if (source_parent.st_dev, source_parent.st_ino) != (
            expected_source["parent"]["device"],
            expected_source["parent"]["inode"],
        ) or (target_parent.st_dev, target_parent.st_ino) != (
            expected_target_absent["parent"]["device"],
            expected_target_absent["parent"]["inode"],
        ):
            _fail(
                "placement parent identity changed before move",
                "SOURCE_CHANGED",
                "create-proposal",
            )

        def present(parent_fd: int, leaf: str) -> bool:
            try:
                os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            except OSError:
                _placement_recovery_required(
                    "placement path identity cannot be classified"
                )
            return True

        source_present = present(source_parent_fd, source_parts[-1])
        target_present = present(target_parent_fd, target_parts[-1])
        if source_present and not target_present:
            evidence = verify_placement_pre_move(
                root=root_path,
                compiled_policy=compiled_policy,
                scope=scope,
                bounds=bounds,
                payload=payload,
                expected_observation=expected_observation,
            )
            return {"state": "PRE_MOVE", "evidence": evidence}
        if not source_present and target_present:
            evidence = verify_placement_post_move(
                root=root_path,
                compiled_policy=compiled_policy,
                scope=scope,
                bounds=bounds,
                payload=payload,
                expected_observation=expected_observation,
            )
            return {"state": "POST_MOVE", "evidence": evidence}
        if not source_present:
            _placement_recovery_required(
                "placement source and target are both absent"
            )

        source_mode = os.stat(
            source_parts[-1],
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        ).st_mode
        if stat.S_ISREG(source_mode):
            current_source = _snapshot_regular_file(
                source_parent_fd,
                source_parts[-1],
                source_relative_path,
                root_device=root_info.st_dev,
                max_total_bytes=max_total_bytes,
            )
        elif stat.S_ISDIR(source_mode):
            current_source = _snapshot_directory(
                source_parent_fd,
                source_parts[-1],
                source_relative_path,
                root=root_path,
                compiled_policy=compiled_policy,
                source_parts=source_parts,
                root_device=root_info.st_dev,
                max_entries=max_entries,
                max_depth=max_depth,
                max_total_bytes=max_total_bytes,
            )
        else:
            _fail(
                "placement source type changed",
                "SOURCE_CHANGED",
                "create-proposal",
            )
        if current_source != expected_source:
            _fail(
                "placement source changed before a target collision",
                "SOURCE_CHANGED",
                "create-proposal",
            )
        _fail(
            "placement target appeared before move",
            "TARGET_COLLISION",
            "create-proposal",
        )
        raise AssertionError("unreachable")
    finally:
        if target_parent_fd >= 0:
            os.close(target_parent_fd)
        if source_parent_fd >= 0:
            os.close(source_parent_fd)
        os.close(root_fd)


__all__ = [
    "LibrarianSnapshotError",
    "classify_placement_state",
    "observe_regular_file",
    "observe_proposal",
    "resolve_destination_owner",
    "verify_placement_post_move",
    "verify_placement_pre_move",
]
