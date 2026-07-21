"""Private anchored filesystem capabilities for the Safe Librarian profile."""

from __future__ import annotations

import os
import stat
from pathlib import Path


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
_TEXT_SUFFIXES = frozenset(
    (".md", ".markdown", ".txt", ".rst", ".json", ".yaml", ".yml", ".toml", ".csv", ".tsv")
)
_SECRET_MARKERS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "api-key",
    "token",
    "private key",
)


class LibrarianScopeError(ValueError):
    """The admitted scope cannot be inspected without widening authority."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "SCOPE_UNSAFE",
        next_safe_action: str = "inspect",
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.next_safe_action = next_safe_action


def _components(relative_path: str) -> tuple[str, ...]:
    if (
        type(relative_path) is not str
        or not relative_path
        or "\\" in relative_path
        or any(ord(character) < 32 for character in relative_path)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in relative_path)
    ):
        raise LibrarianScopeError("scope relative path is invalid")
    parts = tuple(relative_path.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise LibrarianScopeError("scope relative path is invalid")
    return parts


def _relative_parts(root: Path, value: object) -> tuple[str, ...] | None:
    if type(value) is not str:
        return None
    try:
        return Path(value).relative_to(root).parts
    except ValueError:
        return None


def _has_prefix(parts: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(parts) >= len(prefix) and parts[: len(prefix)] == prefix


def _is_hard_protected(parts: tuple[str, ...]) -> bool:
    folded = tuple(part.casefold() for part in parts)
    return (
        any(part in _HARD_PROTECTED_NAMES for part in folded)
        or bool(folded and folded[0].endswith("-cleanup-audit"))
        or any(_has_prefix(folded, prefix) for prefix in _HARD_PROTECTED_PREFIXES)
    )


def _returned_count(
    organized: list[dict[str, object]],
    candidates: list[dict[str, object]],
    excluded: list[dict[str, object]],
    uncertain: list[dict[str, object]],
) -> int:
    return sum(len(items) for items in (organized, candidates, excluded, uncertain))


def _policy_prefixes(root: Path, compiled_policy: object):
    protected = list(_HARD_PROTECTED_PREFIXES)
    for value in getattr(compiled_policy, "never_touch", ()):
        components = getattr(value, "components", None)
        if type(components) is tuple and components:
            protected.append(components)
    for value in getattr(compiled_policy, "archive_roots", ()):
        components = _relative_parts(root, getattr(value, "root", None))
        if components:
            protected.append(components)
    inactive = []
    active = []
    for workstream in getattr(compiled_policy, "workstreams", ()):
        components = _relative_parts(root, getattr(workstream, "project_home", None))
        if not components:
            continue
        item = (
            components,
            getattr(workstream, "id", ""),
            getattr(workstream, "lifecycle", ""),
        )
        if item[2] == "active":
            active.append(item)
        else:
            inactive.append(item)
    categories = []
    for category in getattr(compiled_policy, "categories", ()):
        components = _relative_parts(root, getattr(category, "target", None))
        if components:
            categories.append((components, getattr(category, "id", "")))
    return tuple(protected), tuple(inactive), tuple(active), tuple(categories)


def _open_directory_at(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor: int | None = None
    try:
        lexical = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (lexical.st_dev, lexical.st_ino)
        ):
            raise LibrarianScopeError("scope directory identity changed")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _open_scope(root: Path, parts: tuple[str, ...]) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        current = os.open(root, flags)
    except OSError as exc:
        raise LibrarianScopeError("scope root cannot be opened") from exc
    try:
        for part in parts:
            next_descriptor = _open_directory_at(current, part)
            os.close(current)
            current = next_descriptor
        return current
    except OSError as exc:
        os.close(current)
        raise LibrarianScopeError("scope cannot be opened safely") from exc
    except BaseException:
        os.close(current)
        raise


def _safe_heading(parent_fd: int, name: str, maximum: int) -> tuple[str | None, int]:
    if maximum <= 0:
        return None, 0
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    lexical = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise LibrarianScopeError("scope file identity changed")
        raw = os.read(descriptor, min(maximum, 8192))
        final = os.fstat(descriptor)
        if (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise LibrarianScopeError("scope file changed during inspection")
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, len(raw)
    for line in text.splitlines()[:32]:
        candidate = line.strip()
        if candidate.startswith("#"):
            candidate = candidate.lstrip("#").strip()
        elif ":" in candidate and candidate.split(":", 1)[0] in {"title", "name"}:
            candidate = candidate.split(":", 1)[1].strip()
        else:
            continue
        lowered = candidate.lower()
        if candidate and not any(marker in lowered for marker in _SECRET_MARKERS):
            return candidate[:200], len(raw)
    return None, len(raw)


def inspect_scope(
    *,
    root: Path,
    compiled_policy: object,
    relative_path: str,
    max_items: int,
    max_depth: int,
    max_hint_bytes: int,
) -> dict[str, object]:
    """Inspect one exact admitted directory tree without persisting an index."""

    parts = _components(relative_path)
    protected, inactive, active, categories = _policy_prefixes(root, compiled_policy)
    if _is_hard_protected(parts) or any(
        _has_prefix(parts, prefix) for prefix in protected
    ):
        raise LibrarianScopeError("scope is protected")
    if any(
        _has_prefix(parts, prefix) for prefix, _identifier, _lifecycle in inactive
    ):
        raise LibrarianScopeError(
            "scope belongs to an inactive workstream",
            reason_code="WORKSTREAM_INACTIVE",
            next_safe_action="inspect",
        )
    scope_fd = _open_scope(root, parts)
    try:
        root_device = os.stat(root, follow_symlinks=False).st_dev
        scope_device = os.fstat(scope_fd).st_dev
    except OSError as exc:
        try:
            os.close(scope_fd)
        except OSError:
            pass
        raise LibrarianScopeError("scope identity cannot be verified") from exc
    if scope_device != root_device:
        os.close(scope_fd)
        raise LibrarianScopeError("scope crosses a filesystem boundary")
    organized: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    excluded: list[dict[str, object]] = []
    uncertain: list[dict[str, object]] = []
    hint_bytes = 0
    truncated = False

    def visit(directory_fd: int, base: tuple[str, ...], depth: int) -> None:
        nonlocal hint_bytes, truncated
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise LibrarianScopeError("scope directory cannot be listed") from exc
        for name in names:
            if _returned_count(organized, candidates, excluded, uncertain) >= max_items:
                truncated = True
                return
            relative_parts = base + (name,)
            if any(ord(character) < 32 for character in name) or any(
                0xD800 <= ord(character) <= 0xDFFF for character in name
            ):
                raise LibrarianScopeError("scope contains an unsafe entry name")
            relative = "/".join(relative_parts)
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                uncertain.append(
                    {"relative_path": relative, "reason_code": "SOURCE_CHANGED"}
                )
                continue
            protected_match = _is_hard_protected(relative_parts) or any(
                _has_prefix(relative_parts, prefix) for prefix in protected
            )
            inactive_match = next(
                (
                    item
                    for item in inactive
                    if _has_prefix(relative_parts, item[0])
                ),
                None,
            )
            if protected_match or inactive_match is not None:
                excluded.append(
                    {
                        "relative_path": relative,
                        "reason_code": (
                            "WORKSTREAM_INACTIVE"
                            if inactive_match is not None
                            else "SCOPE_UNSAFE"
                        ),
                    }
                )
                continue
            if stat.S_ISLNK(info.st_mode):
                excluded.append(
                    {"relative_path": relative, "reason_code": "SOURCE_UNSUPPORTED"}
                )
                continue
            if info.st_dev != root_device:
                excluded.append(
                    {"relative_path": relative, "reason_code": "SCOPE_UNSAFE"}
                )
                continue
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                uncertain.append(
                    {"relative_path": relative, "reason_code": "SOURCE_UNSUPPORTED"}
                )
                continue
            if info.st_uid != os.getuid() or (
                stat.S_ISREG(info.st_mode) and info.st_nlink != 1
            ):
                uncertain.append(
                    {"relative_path": relative, "reason_code": "SOURCE_UNSUPPORTED"}
                )
                continue
            entry_type = "directory" if stat.S_ISDIR(info.st_mode) else "file"
            if entry_type == "file" and Path(name).suffix.casefold() not in _TEXT_SUFFIXES:
                uncertain.append(
                    {"relative_path": relative, "reason_code": "CONTENT_OPAQUE"}
                )
                continue
            hint = None
            if entry_type == "file":
                try:
                    hint, consumed = _safe_heading(
                        directory_fd,
                        name,
                        max_hint_bytes - hint_bytes,
                    )
                except (LibrarianScopeError, OSError):
                    uncertain.append(
                        {
                            "relative_path": relative,
                            "reason_code": "SOURCE_CHANGED",
                        }
                    )
                    continue
                hint_bytes += consumed
            item = {
                "relative_path": relative,
                "entry_type": entry_type,
                "size": info.st_size if entry_type == "file" else 0,
                "hint": hint,
            }
            active_match = next(
                (item for item in active if _has_prefix(relative_parts, item[0])),
                None,
            )
            category_match = next(
                (item for item in categories if _has_prefix(relative_parts, item[0])),
                None,
            )
            if category_match is not None:
                item.update(
                    {
                        "destination_kind": "manual_category",
                        "destination_id": category_match[1],
                    }
                )
                destination = organized
            elif active_match is not None:
                item.update(
                    {
                        "destination_kind": "workstream",
                        "destination_id": active_match[1],
                    }
                )
                destination = organized
            else:
                destination = candidates
            destination.append(item)
            if entry_type == "directory":
                if depth >= max_depth:
                    truncated = True
                    continue
                try:
                    child_fd = _open_directory_at(directory_fd, name)
                except (LibrarianScopeError, OSError):
                    destination.pop()
                    uncertain.append(
                        {
                            "relative_path": relative,
                            "reason_code": "SOURCE_CHANGED",
                        }
                    )
                    continue
                try:
                    visit(child_fd, relative_parts, depth + 1)
                finally:
                    os.close(child_fd)
                if truncated and _returned_count(
                    organized,
                    candidates,
                    excluded,
                    uncertain,
                ) >= max_items:
                    return

    try:
        visit(scope_fd, parts, 1)
    finally:
        os.close(scope_fd)
    workstreams = []
    for workstream in sorted(
        getattr(compiled_policy, "workstreams", ()),
        key=lambda item: getattr(item, "id", ""),
    ):
        project_parts = _relative_parts(root, getattr(workstream, "project_home", None))
        if project_parts:
            workstreams.append(
                {
                    "id": getattr(workstream, "id", ""),
                    "lifecycle": getattr(workstream, "lifecycle", ""),
                    "project_home": "/".join(project_parts),
                }
            )
    returned = _returned_count(organized, candidates, excluded, uncertain)
    return {
        "schema_version": 1,
        "view": "scope",
        "scope": {"relative_path": relative_path},
        "bounds": {
            "max_items": max_items,
            "max_depth": max_depth,
            "max_hint_bytes": max_hint_bytes,
        },
        "workstreams": workstreams,
        "organized": organized,
        "candidates": candidates,
        "excluded": excluded,
        "uncertain": uncertain,
        "returned": returned,
        "truncated": truncated,
    }


__all__ = ["LibrarianScopeError", "inspect_scope"]
