"""Read-only, bounded queries over Mnemosyne workspace-sync memory.

This module deliberately owns no CLI formatting and never inspects a project
tree.  It safely reads the raw-memory projection and returns small typed
results for a history collector or a project-context skill to render.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import safety


_MAX_REGISTRY_BYTES = 128 * 1024
_MAX_FRONTMATTER_BYTES = 64 * 1024
_MAX_HISTORY_BYTES = 128 * 1024
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_HISTORY_ENTRIES = 512
_MAX_RECEIPTS = 512
_TOKEN_RE = re.compile(r"[\w-]{2,}", re.UNICODE)
_WORKSPACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_RECORDED_TIMESTAMP_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})T(?P<hour>\d{2})[-:]"
    r"(?P<minute>\d{2})[-:](?P<second>\d{2})(?P<fraction>\.\d+)?"
    r"(?P<zone>Z|[+-]\d{2}:?\d{2})\Z"
)


class RawMemoryQueryError(ValueError):
    """Raised for invalid caller input before any raw-memory read."""


@dataclass(frozen=True)
class QueryIssue:
    kind: str
    path: str
    detail: str


class _BoundedIssues(list[QueryIssue]):
    """Keep malformed legacy input from making a query response unbounded."""

    _limit = 32

    def __init__(self) -> None:
        super().__init__()
        self._omitted = False

    def append(self, value: QueryIssue) -> None:
        if len(self) < self._limit:
            super().append(value)
        elif not self._omitted:
            super().append(
                QueryIssue("truncated", "query", "additional issues omitted")
            )
            self._omitted = True


@dataclass(frozen=True)
class SyncHistoryItem:
    """One reader-facing synced work item, expanded from one history record."""

    item: str
    recorded_at: str
    source_refs: tuple[str, ...]
    history_path: str
    workspace: str
    workstream: str
    receipt_linked: bool = False


@dataclass(frozen=True)
class SyncHistoryResult:
    status: str
    items: tuple[SyncHistoryItem, ...]
    issues: tuple[QueryIssue, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ContextHistoryEntry:
    history_path: str
    recorded_at: str | None
    source_refs: tuple[str, ...]
    excerpt: str
    relevance: int


@dataclass(frozen=True)
class ProjectContextResult:
    status: str
    workspace: str | None
    candidates: tuple[str, ...]
    snapshot_path: str | None
    snapshot_excerpt: str | None
    history: tuple[ContextHistoryEntry, ...]
    issues: tuple[QueryIssue, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def collect_sync_history(
    raw_root: Path | str,
    *,
    start_date: str,
    end_date: str,
) -> SyncHistoryResult:
    """Return expanded synced work items in an inclusive calendar-date range."""
    start = _parse_calendar_date(start_date, "start_date")
    end = _parse_calendar_date(end_date, "end_date")
    if start > end:
        raise RawMemoryQueryError("start_date must not be after end_date")

    root = _canonical_root(raw_root)
    issues: list[QueryIssue] = _BoundedIssues()
    registry = _read_registry(root, issues)
    if registry is None:
        return SyncHistoryResult("unavailable", (), tuple(issues))

    items: list[SyncHistoryItem] = []
    receipt_index = _read_receipt_index(root, issues)
    history_truncated = False
    for workspace in sorted(registry):
        records, workspace_history_truncated = _read_workspace_history(
            root, workspace, issues, start_date=start, end_date=end
        )
        history_truncated = history_truncated or workspace_history_truncated
        for record in records:
            recorded_date = _recorded_date(record.recorded_at)
            if recorded_date is None:
                issues.append(
                    QueryIssue("malformed", record.history_path, "created_at is invalid")
                )
                continue
            if not start <= recorded_date <= end:
                continue
            for text in _expand_work_items(record.body, record.frontmatter):
                items.append(
                    SyncHistoryItem(
                        item=text,
                        recorded_at=record.recorded_at,
                        source_refs=record.source_refs,
                        history_path=record.history_path,
                        workspace=workspace,
                        workstream=record.workstream,
                        receipt_linked=record.history_path in receipt_index,
                    )
                )

    # The path is intentionally part of the key: it is reader-facing provenance,
    # so records from separate sync artifacts are not silently conflated.
    deduped = {
        (
            item.item,
            item.recorded_at,
            item.source_refs,
            item.history_path,
            item.workspace,
            item.workstream,
            item.receipt_linked,
        ): item
        for item in items
    }
    return SyncHistoryResult(
        "found" if deduped else "unavailable" if history_truncated else "not_found",
        tuple(
            sorted(
                deduped.values(),
                key=lambda item: (item.recorded_at, item.history_path),
            )
        ),
        tuple(issues),
    )


def lookup_project_context(
    raw_root: Path | str,
    *,
    project_root: Path | str,
    question: str = "",
    task_context: str = "",
    snapshot_char_limit: int = 12_000,
    history_limit: int = 8,
    history_excerpt_char_limit: int = 2_000,
) -> ProjectContextResult:
    """Find bounded raw context for one normalized exact project-root match."""
    if snapshot_char_limit < 0 or history_limit < 0 or history_excerpt_char_limit < 0:
        raise RawMemoryQueryError("query bounds must be nonnegative")
    root = _canonical_root(raw_root)
    normalized_project = _normalize_project_root(project_root)
    issues: list[QueryIssue] = _BoundedIssues()
    registry = _read_registry(root, issues)
    if registry is None:
        return ProjectContextResult("unavailable", None, (), None, None, (), tuple(issues))

    candidates = tuple(
        workspace
        for workspace, workspace_root in sorted(registry.items())
        if _normalize_project_root(workspace_root) == normalized_project
    )
    if not candidates:
        return ProjectContextResult("not_found", None, (), None, None, (), tuple(issues))
    if len(candidates) > 1:
        return ProjectContextResult("ambiguous", None, candidates, None, None, (), tuple(issues))

    workspace = candidates[0]
    snapshot_path, snapshot_excerpt = _read_snapshot(
        root, workspace, snapshot_char_limit, issues
    )
    records, _history_truncated = _read_workspace_history(root, workspace, issues)
    tokens = _query_tokens(question, task_context)
    selected = sorted(
        records,
        key=lambda record: (
            _history_relevance(record, tokens),
            record.recorded_at or "",
            record.history_path,
        ),
        reverse=True,
    )[:history_limit]
    history = tuple(
        ContextHistoryEntry(
            history_path=record.history_path,
            recorded_at=record.recorded_at,
            source_refs=record.source_refs,
            excerpt=_truncate(record.body.strip(), history_excerpt_char_limit),
            relevance=_history_relevance(record, tokens),
        )
        for record in selected
    )
    return ProjectContextResult(
        "unavailable" if snapshot_path is None and not records else "found",
        workspace,
        candidates,
        snapshot_path,
        snapshot_excerpt,
        history,
        tuple(issues),
    )


@dataclass(frozen=True)
class _HistoryRecord:
    history_path: str
    recorded_at: str | None
    source_refs: tuple[str, ...]
    workstream: str
    frontmatter: Mapping[str, Any]
    body: str


def _canonical_root(value: Path | str) -> Path:
    try:
        return Path(os.path.abspath(Path(value).expanduser())).resolve(strict=False)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RawMemoryQueryError("raw_root is invalid") from exc


def _normalize_project_root(value: Path | str) -> str:
    try:
        return str(Path(os.path.abspath(Path(value).expanduser())).resolve(strict=False))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RawMemoryQueryError("project root is invalid") from exc


def _parse_calendar_date(value: str, label: str) -> date:
    if type(value) is not str:
        raise RawMemoryQueryError(f"{label} must be YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise RawMemoryQueryError(f"{label} must be YYYY-MM-DD") from exc


def _read_registry(root: Path, issues: list[QueryIssue]) -> dict[str, str] | None:
    memory = root / "memory"
    registry_path = memory / "workspaces.yml"
    try:
        memory_fd = safety.open_verified_directory(
            memory, require_owner_only=False, error_type=RawMemoryQueryError
        )
    except RawMemoryQueryError as exc:
        issues.append(QueryIssue("unavailable", "memory", str(exc)))
        return None
    try:
        _info, raw = safety.read_regular_file_at(
            memory_fd,
            "workspaces.yml",
            registry_path,
            label="workspace registry",
            expected_mode=None,
            max_bytes=_MAX_REGISTRY_BYTES,
            error_type=RawMemoryQueryError,
        )
    except RawMemoryQueryError as exc:
        issues.append(QueryIssue("unavailable", "memory/workspaces.yml", str(exc)))
        return None
    finally:
        os.close(memory_fd)
    try:
        workspace_roots = _parse_workspace_roots(raw)
        for workspace_root in workspace_roots.values():
            _normalize_project_root(workspace_root)
        return workspace_roots
    except (UnicodeDecodeError, RawMemoryQueryError, ValueError) as exc:
        issues.append(QueryIssue("malformed", "memory/workspaces.yml", str(exc)))
        return None


def _parse_workspace_roots(raw: bytes) -> dict[str, str]:
    """Read only workspace roots from the bounded legacy registry grammar.

    Workspace registries gained human confirmation metadata over time.  The
    query contract needs only ``workspaces.<name>.root`` and must not turn an
    unrelated timestamp or confirmation mapping into a parser failure.
    """
    text = raw.decode("utf-8")
    in_workspaces = False
    current_workspace: str | None = None
    roots: dict[str, str | None] = {}
    for raw_line in text.splitlines():
        line_without_comment = raw_line.split("#", 1)[0].rstrip()
        if not line_without_comment.strip():
            continue
        if "\t" in line_without_comment[: len(line_without_comment) - len(line_without_comment.lstrip())]:
            raise ValueError("workspace registry indentation is malformed")
        indent = len(line_without_comment) - len(line_without_comment.lstrip(" "))
        line = line_without_comment.strip()
        if indent == 0:
            in_workspaces = line == "workspaces:"
            current_workspace = None
            continue
        if not in_workspaces:
            continue
        if indent == 2 and line.endswith(":"):
            workspace = line[:-1].strip()
            if _WORKSPACE_RE.fullmatch(workspace) is None or workspace in roots:
                raise ValueError("workspace registry has an invalid workspace")
            roots[workspace] = None
            current_workspace = workspace
            continue
        if indent == 2:
            raise ValueError("workspace registry entry is malformed")
        if indent == 4 and current_workspace is not None and ":" in line:
            key, value = line.split(":", 1)
            if key.strip() == "root":
                root = value.strip().strip("\"'")
                if not root:
                    raise ValueError("workspace root is missing")
                if roots[current_workspace] is not None:
                    raise ValueError("workspace root is duplicated")
                roots[current_workspace] = root
    if not roots:
        raise ValueError("workspace registry has no workspaces")
    if any(root is None for root in roots.values()):
        raise ValueError("workspace root is missing")
    return {workspace: root for workspace, root in roots.items() if root is not None}


def _read_workspace_history(
    root: Path,
    workspace: str,
    issues: list[QueryIssue],
    *,
    start_date: date | None = None,
    end_date: date | None = None,
) -> tuple[tuple[_HistoryRecord, ...], bool]:
    workspace_path = root / "memory" / workspace
    history_path = workspace_path / "history"
    relative_directory = f"memory/{workspace}/history"
    try:
        workspace_fd = safety.open_verified_directory(
            workspace_path, require_owner_only=True, error_type=RawMemoryQueryError
        )
    except RawMemoryQueryError as exc:
        issues.append(QueryIssue("unavailable", f"memory/{workspace}", str(exc)))
        return (), False
    try:
        try:
            history_fd = safety.open_verified_directory(
                history_path, require_owner_only=True, error_type=RawMemoryQueryError
            )
        except RawMemoryQueryError as exc:
            issues.append(QueryIssue("unavailable", relative_directory, str(exc)))
            return (), False
    finally:
        os.close(workspace_fd)
    try:
        names = sorted(name for name in os.listdir(history_fd) if name.endswith(".md"))
        history_truncated = len(names) > _MAX_HISTORY_ENTRIES
        if history_truncated:
            issues.append(
                QueryIssue(
                    "truncated",
                    relative_directory,
                    "history entry limit exceeded; matching records may be unread",
                )
            )
            names = _prioritize_history_names(names, start_date, end_date)
        records: list[_HistoryRecord] = []
        for name in names:
            relative_path = f"{relative_directory}/{name}"
            filename_date = _date_from_filename(name)
            try:
                _info, raw = safety.read_regular_file_at(
                    history_fd,
                    name,
                    history_path / name,
                    label="workspace history",
                    expected_mode=None,
                    max_bytes=_MAX_HISTORY_BYTES,
                    error_type=RawMemoryQueryError,
                )
                frontmatter, body = _parse_history_document(raw, name)
                source_refs = _source_refs(frontmatter)
                recorded_at = _recorded_at(frontmatter)
                if recorded_at is None:
                    recorded_at = _timestamp_from_filename(name)
                workstream = _workstream(frontmatter, workspace)
                records.append(
                    _HistoryRecord(
                        relative_path,
                        recorded_at,
                        source_refs,
                        workstream,
                        frontmatter,
                        body,
                    )
                )
            except (RawMemoryQueryError, ValueError) as exc:
                if (
                    filename_date is not None
                    and start_date is not None
                    and end_date is not None
                    and not start_date <= filename_date <= end_date
                ):
                    continue
                issues.append(QueryIssue("malformed", relative_path, str(exc)))
        return tuple(records), history_truncated
    finally:
        os.close(history_fd)


def _prioritize_history_names(
    names: Sequence[str], start_date: date | None, end_date: date | None
) -> tuple[str, ...]:
    """Choose bounded history reads without burying requested or recent records."""
    if start_date is not None and end_date is not None:
        in_range = [
            name
            for name in names
            if (filename_date := _date_from_filename(name)) is not None
            and start_date <= filename_date <= end_date
        ]
        in_range_set = set(in_range)
        remaining = [name for name in names if name not in in_range_set]
        return tuple((*in_range, *remaining)[:_MAX_HISTORY_ENTRIES])
    return tuple(reversed(names[-_MAX_HISTORY_ENTRIES:]))


def _read_snapshot(
    root: Path, workspace: str, limit: int, issues: list[QueryIssue]
) -> tuple[str | None, str | None]:
    workspace_path = root / "memory" / workspace
    relative_path = f"memory/{workspace}/snapshot.md"
    try:
        workspace_fd = safety.open_verified_directory(
            workspace_path, require_owner_only=True, error_type=RawMemoryQueryError
        )
        try:
            _info, raw = safety.read_regular_file_at(
                workspace_fd,
                "snapshot.md",
                workspace_path / "snapshot.md",
                label="workspace snapshot",
                expected_mode=None,
                max_bytes=_MAX_SNAPSHOT_BYTES,
                error_type=RawMemoryQueryError,
            )
        finally:
            os.close(workspace_fd)
        _frontmatter, body = _parse_frontmatter(raw)
        return relative_path, _truncate(body.strip(), limit)
    except (RawMemoryQueryError, ValueError) as exc:
        issues.append(QueryIssue("unavailable", relative_path, str(exc)))
        return None, None


def _read_receipt_index(root: Path, issues: list[QueryIssue]) -> set[str]:
    directory = root / "memory" / "_receipts" / "workspace-sync"
    try:
        directory_fd = safety.open_verified_directory(
            directory, require_owner_only=True, error_type=RawMemoryQueryError
        )
    except RawMemoryQueryError:
        return set()
    try:
        counts: dict[str, int] = {}
        names = sorted(os.listdir(directory_fd))[:_MAX_RECEIPTS]
        for name in names:
            path = directory / name
            try:
                _info, raw = safety.read_regular_file_at(
                    directory_fd,
                    name,
                    path,
                    label="workspace sync receipt",
                    expected_mode=None,
                    max_bytes=_MAX_RECEIPT_BYTES,
                    error_type=RawMemoryQueryError,
                )
                value = json.loads(raw.decode("utf-8"))
                plan_sha = value.get("plan_sha256")
                effects = value.get("effects")
                if (
                    type(plan_sha) is not str
                    or not isinstance(effects, list)
                    or not all(isinstance(effect, Mapping) for effect in effects)
                ):
                    raise ValueError("receipt is malformed")
                for effect in effects:
                    effect_path = effect.get("path")
                    if isinstance(effect_path, str) and "/history/" in effect_path:
                        counts[effect_path] = counts.get(effect_path, 0) + 1
            except (RawMemoryQueryError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                issues.append(QueryIssue("malformed", str(path.relative_to(root)), str(exc)))
        return {path for path, count in counts.items() if count == 1}
    finally:
        os.close(directory_fd)


def _parse_history_document(raw: bytes, filename: str) -> tuple[Mapping[str, Any], str]:
    """Read modern frontmatter or the small legacy heading-metadata form."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("document is not UTF-8") from exc
    if text.startswith("---"):
        return _parse_frontmatter(raw)
    return _parse_legacy_history(text, filename)


def _parse_legacy_history(text: str, filename: str) -> tuple[Mapping[str, Any], str]:
    metadata: dict[str, Any] = {}
    source_refs: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^\s*-\s*(Workspace|Workstream|Updated at|Source refs)\s*:\s*(.*?)\s*$", line, re.IGNORECASE)
        if match is None:
            continue
        key = match.group(1).casefold()
        value = match.group(2)
        if key == "workspace":
            metadata["workspace"] = value
        elif key == "workstream":
            metadata["workstream"] = value
        elif key == "updated at":
            metadata["updated_at"] = value
        elif key == "source refs":
            source_refs.extend(part.strip() for part in value.split(",") if part.strip())
    if source_refs:
        metadata["source_refs"] = source_refs
    timestamp = _recorded_at(metadata)
    if timestamp is None:
        inferred = _timestamp_from_filename(filename)
        if inferred is not None:
            metadata["recorded_at"] = inferred
    return metadata, text


def _parse_frontmatter(raw: bytes) -> tuple[Mapping[str, Any], str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("document is not UTF-8") from exc
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        raise ValueError("frontmatter is missing")
    closing = next((index for index, line in enumerate(lines[1:], 1) if line.strip() == "---"), None)
    if closing is None:
        raise ValueError("frontmatter is not closed")
    frontmatter_text = "".join(lines[1:closing])
    if len(frontmatter_text.encode("utf-8")) > _MAX_FRONTMATTER_BYTES:
        raise ValueError("frontmatter exceeds byte bound")
    return _read_frontmatter_fields(frontmatter_text), "".join(lines[closing + 1 :])


def _read_frontmatter_fields(text: str) -> dict[str, Any]:
    """Extract query fields from legacy YAML-like frontmatter without coercion.

    Raw history predates one schema and has both flat and normally-indented
    ``source_refs``.  Querying does not validate its semantics, so this reader
    intentionally extracts only the few fields it can safely recognize.
    """
    result: dict[str, Any] = {}
    source_refs: list[object] = []
    active: str | None = None
    pending_source_mapping: dict[str, str] | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        content = raw_line.strip()
        if indent == 0 and not content.startswith("-") and ":" in content:
            key, value = content.split(":", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            active = key if not value else None
            if key == "source_refs":
                if value:
                    source_refs.append(value)
                continue
            if key in {"workstream", "workstream_id", "created_at", "event_time", "recorded_at", "updated_at", "summary"}:
                result[key] = value if value else {}
            continue
        if active == "workstream" and indent >= 2 and ":" in content:
            key, value = content.split(":", 1)
            if isinstance(result.get("workstream"), dict):
                result["workstream"][key.strip()] = value.strip().strip("\"'")
            continue
        if active != "source_refs":
            continue
        if content.startswith("- "):
            if pending_source_mapping is not None:
                source_refs.append(pending_source_mapping)
                pending_source_mapping = None
            entry = content[2:].strip()
            if ":" in entry:
                key, value = entry.split(":", 1)
                pending_source_mapping = {key.strip(): value.strip().strip("\"'")}
            elif entry:
                source_refs.append(entry.strip("\"'"))
            continue
        if ":" in content:
            key, value = content.split(":", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if pending_source_mapping is not None and indent >= 4:
                pending_source_mapping[key] = value
            else:
                if pending_source_mapping is not None:
                    source_refs.append(pending_source_mapping)
                    pending_source_mapping = None
                source_refs.append({key: value})
    if pending_source_mapping is not None:
        source_refs.append(pending_source_mapping)
    if source_refs:
        result["source_refs"] = source_refs
    return result


def _source_refs(frontmatter: Mapping[str, Any]) -> tuple[str, ...]:
    values = frontmatter.get("source_refs", ())
    if values is None:
        return ()
    if isinstance(values, (str, Mapping)):
        values = (values,)
    if not isinstance(values, list) and not isinstance(values, tuple):
        return ()
    rendered = tuple(
        value
        for raw_value in values
        if (value := _render_source_ref(raw_value)) is not None
    )
    return rendered


def _render_source_ref(value: object) -> str | None:
    if type(value) is str:
        return value.strip() or None
    if not isinstance(value, Mapping):
        return None
    ref = value.get("ref")
    kind = value.get("type")
    if type(ref) is str and ref.strip():
        return f"{kind}: {ref}" if type(kind) is str and kind.strip() else ref
    parts = [
        f"{key}: {item}"
        for key, item in sorted(value.items())
        if type(key) is str and type(item) is str and item.strip()
    ]
    return "; ".join(parts) or None


def _recorded_at(frontmatter: Mapping[str, Any]) -> str | None:
    for field in ("created_at", "event_time", "recorded_at", "updated_at"):
        value = frontmatter.get(field)
        if type(value) is str and value.strip():
            normalized = _normalize_recorded_timestamp(value)
            if normalized is None:
                raise ValueError("recorded timestamp is invalid")
            return normalized
    return None


def _workstream(frontmatter: Mapping[str, Any], workspace: str) -> str:
    value = frontmatter.get("workstream")
    if type(value) is str and value.strip():
        return value.strip()
    if isinstance(value, Mapping):
        identifier = value.get("id")
        if type(identifier) is str and identifier.strip():
            return identifier.strip()
    identifier = frontmatter.get("workstream_id")
    if type(identifier) is str and identifier.strip():
        return identifier.strip()
    return workspace


def _recorded_date(value: str | None) -> date | None:
    if value is None:
        return None
    normalized = _normalize_recorded_timestamp(value)
    if normalized is None:
        return None
    try:
        return date.fromisoformat(normalized[:10])
    except ValueError:
        return None


def _normalize_recorded_timestamp(value: str) -> str | None:
    match = _RECORDED_TIMESTAMP_RE.fullmatch(value.strip())
    if match is None:
        return None
    zone = match.group("zone")
    if zone != "Z" and ":" not in zone:
        zone = f"{zone[:3]}:{zone[3:]}"
    normalized = (
        f"{match.group('date')}T{match.group('hour')}:"
        f"{match.group('minute')}:{match.group('second')}"
        f"{match.group('fraction') or ''}{zone}"
    )
    try:
        datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return None
    return normalized


def _date_from_filename(name: str) -> date | None:
    timestamp = _timestamp_from_filename(name)
    if timestamp is None:
        return None
    try:
        return date.fromisoformat(timestamp[:10])
    except ValueError:
        return None


def _timestamp_from_filename(name: str) -> str | None:
    dashed = re.search(
        r"(?P<date>\d{4}-\d{2}-\d{2})T(?P<hour>\d{2})[-:]"
        r"(?P<minute>\d{2})[-:](?P<second>\d{2})"
        r"(?P<zone>Z|[+-]\d{2}:?\d{2})",
        name,
    )
    if dashed is not None:
        encoded_date = dashed.group("date")
        hour = dashed.group("hour")
        minute = dashed.group("minute")
        second = dashed.group("second")
        zone = dashed.group("zone")
    else:
        compact = re.search(
            r"(?P<date>\d{8})T(?P<time>\d{6})(?P<zone>Z|[+-]\d{2}:?\d{2})",
            name,
        )
        if compact is None:
            return None
        raw_date = compact.group("date")
        raw_time = compact.group("time")
        encoded_date = f"{raw_date[:4]}-{raw_date[4:6]}-{raw_date[6:]}"
        hour, minute, second = raw_time[:2], raw_time[2:4], raw_time[4:]
        zone = compact.group("zone")
    if zone != "Z" and ":" not in zone:
        zone = f"{zone[:3]}:{zone[3:]}"
    value = f"{encoded_date}T{hour}:{minute}:{second}{zone}"
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value


def _expand_work_items(body: str, frontmatter: Mapping[str, Any]) -> tuple[str, ...]:
    lines = body.splitlines()
    selected_lines: list[str] = []
    selected = False
    for line in lines:
        if line in {"## 최신 상태에 반영한 내용", "## 기록으로 남긴 내용"}:
            selected = True
            continue
        if line.startswith("## "):
            selected = False
        if selected:
            selected_lines.append(line)
    bullets = tuple(
        match.group(1).strip()
        for line in selected_lines
        if (match := re.match(r"^\s*[-*]\s+(.+?)\s*$", line)) is not None
        and match.group(1).strip()
    )
    if bullets:
        return bullets
    summary = _summary_paragraph(body)
    if summary is not None:
        return (summary,)
    summary = frontmatter.get("summary")
    if isinstance(summary, str) and summary.strip():
        return (summary.strip(),)
    paragraphs = [
        " ".join(line.strip() for line in paragraph.splitlines() if line.strip())
        for paragraph in re.split(r"\n\s*\n", body)
    ]
    paragraphs = [paragraph for paragraph in paragraphs if paragraph and not paragraph.startswith("#")]
    return (paragraphs[0],) if paragraphs else ()


def _summary_paragraph(body: str) -> str | None:
    lines = body.splitlines()
    try:
        start = next(index for index, line in enumerate(lines) if line.strip() == "## Summary") + 1
    except StopIteration:
        return None
    selected: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        selected.append(line)
    paragraphs = [
        " ".join(part.strip() for part in paragraph.splitlines() if part.strip())
        for paragraph in re.split(r"\n\s*\n", "\n".join(selected))
    ]
    return next((paragraph for paragraph in paragraphs if paragraph), None)


def _query_tokens(question: str, task_context: str) -> tuple[str, ...]:
    return tuple(sorted(set(token.casefold() for token in _TOKEN_RE.findall(question + " " + task_context))))


def _relevance(text: str, tokens: Sequence[str]) -> int:
    normalized = text.casefold()
    return sum(normalized.count(token) for token in tokens)


def _history_relevance(record: _HistoryRecord, tokens: Sequence[str]) -> int:
    return _relevance(
        "\n".join(
            (
                record.history_path,
                record.workstream,
                *record.source_refs,
                record.body,
            )
        ),
        tokens,
    )


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    marker = "\n[... truncated ...]"
    if limit <= len(marker):
        return value[:limit]
    return value[: limit - len(marker)] + marker


__all__ = [
    "ContextHistoryEntry",
    "ProjectContextResult",
    "QueryIssue",
    "RawMemoryQueryError",
    "SyncHistoryItem",
    "SyncHistoryResult",
    "collect_sync_history",
    "lookup_project_context",
]
