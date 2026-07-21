"""Pure Context Assembly contracts for Workstream curation."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Mapping, Optional, Tuple
from urllib.parse import urlsplit

from . import policy, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


COMPLETE = "COMPLETE"
INCOMPLETE = "INCOMPLETE"
BLOCKED_UNSAFE = "BLOCKED_UNSAFE"
STALE = "STALE"
CONTEXT_ASSEMBLY_SCHEMA = "mnemosyne-workstream-context-assembly-v1"
APPROVED_REQUIREMENTS_SHA256 = (
    "6f4407aadab564962bf796856994fa226dd38912b8abd6d9f1231406e54d06a9"
)
_EMPTY_MEMORY_FRESHNESS_VALUE = {
    "history_directory_identity": None,
    "history_entries": [],
    "snapshot": None,
    "workspace_identity": None,
}
NOT_CONFIGURED_MEMORY_FRESHNESS_SHA256 = sha256_bytes(
    canonical_json_bytes(_EMPTY_MEMORY_FRESHNESS_VALUE)
)

_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_EXTERNAL_SOURCE_ID_RE = re.compile(
    r"external:(jira|confluence|foundry|url|unknown):([0-9a-f]{64})\Z"
)
_MEMORY_WORKSPACE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)


def _is_canonical_rfc3339(value: object) -> bool:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        return False
    parsed_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(parsed_value)
    except ValueError:
        return False
    return True


_SOURCE_GROUPS = frozenset(
    {
        "PROJECT_ROOT",
        "MEETING",
        "REFERENCE_LIBRARY",
        "OTHER_NESTED",
        "ALLOWLISTED_EXTERNAL_LOCAL",
        "MEMORY_SNAPSHOT",
        "MEMORY_HISTORY",
        "EXTERNAL_REFERENCE",
    }
)
_LOCAL_GROUPS = frozenset(
    {
        "PROJECT_ROOT",
        "MEETING",
        "REFERENCE_LIBRARY",
        "OTHER_NESTED",
        "ALLOWLISTED_EXTERNAL_LOCAL",
    }
)
_MEMORY_GROUPS = frozenset({"MEMORY_SNAPSHOT", "MEMORY_HISTORY"})
_EXTERNAL_REFERENCE_FAMILIES = frozenset(
    {"jira", "confluence", "foundry", "url", "unknown"}
)
_CLAIM_MODES = frozenset(
    {
        "CURRENT_LOCAL",
        "CURRENT_EXTERNAL",
        "HISTORICAL_HINT",
        "UNVERIFIED_EXTERNAL",
        "CONFLICT",
        "MISSING",
    }
)
_COVERAGE_COUNT_FIELDS = (
    "local_inspected",
    "local_excluded",
    "local_unreadable",
    "local_truncated",
    "memory_history_inspected",
    "memory_history_included",
    "memory_history_excluded",
    "memory_history_malformed",
    "memory_history_truncated",
    "memory_snapshot_bytes_read",
    "memory_snapshot_hint_count",
    "memory_history_bytes_read",
    "memory_hint_tokens_extracted",
    "external_verified",
    "external_unverified",
)
_SECRET_KEYS = "token|secret|password|api_key|credential"
_PERSONAL_ID_KEYS = "user_id|account_id|customer_id|employee_id"
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?P<key>"
    + _SECRET_KEYS
    + "|"
    + _PERSONAL_ID_KEYS
    + r")[ \t]*[:=][ \t]*)(?P<value>.*)$",
    re.ASCII | re.IGNORECASE,
)
_SENSITIVE_KEY_PREFIX_RE = re.compile(
    r"^[ \t]*(?:" + _SECRET_KEYS + "|" + _PERSONAL_ID_KEYS + r")(?=$|[ \t:=])",
    re.ASCII | re.IGNORECASE,
)
_AUTHORIZATION_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?:proxy-)?authorization[ \t]*:[ \t]*)(?P<value>.*)$",
    re.ASCII | re.IGNORECASE,
)
_BEARER_RE = re.compile(r"\bBearer[ \t]+\S+", re.ASCII | re.IGNORECASE)
_PEM_BEGIN_RE = re.compile(r"-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY)-----")
_KNOWN_TOKEN_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{8,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{8,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[A-Za-z0-9_-]{20,}"),
)
_BASE64_LIKE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])"
)
_URL_RE = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_MARKDOWN_TARGET_RE = re.compile(r"\[[^\]\n]*\]\([ \t]*<?([^\s)>]+)>?")
_POSIX_PATH_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_.@+-])"
    r"(?:/[A-Za-z0-9_.@+~-]+(?:/[A-Za-z0-9_.@+~-]+)+"
    r"|[A-Za-z0-9_.@+~-]+(?:/[A-Za-z0-9_.@+~-]+)+)"
)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"
)
_EXTERNAL_MARKER_RE = re.compile(
    r"\[EXTERNAL:(jira|confluence|foundry|url|unknown):([0-9a-f]{64})\]"
)


def _increment_count(counts: dict[str, int], name: str, amount: int = 1) -> None:
    counts[name] = counts.get(name, 0) + amount


class ContextAssemblyError(ValueError):
    """A Context Assembly value violates its sealed domain contract."""

    def __init__(self, message: str, *, reason_code: str = "CONTEXT_INVALID") -> None:
        super().__init__(message)
        self.reason_code = reason_code


class _MemoryUnsafeError(ContextAssemblyError):
    def __init__(self, message: str) -> None:
        super().__init__(message, reason_code="CONTEXT_BLOCKED_UNSAFE")


def _require_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise ContextAssemblyError("%s is invalid" % label)
    return value


def _require_hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise ContextAssemblyError("%s is invalid" % label)
    return value


def _require_relative_path(value: object, label: str) -> str:
    path = _require_text(value, label)
    parts = path.split("/")
    if (
        path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ContextAssemblyError("%s is invalid" % label)
    return path


def _require_identity(value: object, label: str, *, size: int) -> Tuple[int, ...]:
    if (
        type(value) is not tuple
        or len(value) != size
        or any(type(item) is not int or item < 0 for item in value)
    ):
        raise ContextAssemblyError("%s is invalid" % label)
    return value


def _require_count_pairs(
    value: object, label: str
) -> Tuple[Tuple[str, int], ...]:
    if type(value) is not tuple:
        raise ContextAssemblyError("%s is invalid" % label)
    keys = []
    for item in value:
        if (
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or not item[0]
            or type(item[1]) is not int
            or item[1] < 0
        ):
            raise ContextAssemblyError("%s is invalid" % label)
        keys.append(item[0])
    if len(keys) != len(set(keys)):
        raise ContextAssemblyError("%s has duplicate keys" % label)
    return value


def _require_unique_text_tuple(
    value: object, error_message: str
) -> Tuple[str, ...]:
    if (
        type(value) is not tuple
        or any(type(item) is not str or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ContextAssemblyError(error_message)
    return value


def _require_absent(values: Tuple[object, ...], error_message: str) -> None:
    if any(value is not None for value in values):
        raise ContextAssemblyError(error_message)


def _observation_value(observation: object, name: str, expected_type: type) -> object:
    value = getattr(observation, name, None)
    if type(value) is not expected_type:
        raise ContextAssemblyError("current local observation is invalid")
    return value


def _line_parts(value: str) -> Tuple[str, str]:
    content = value.rstrip("\r\n")
    return content, value[len(content) :]


def _line_indentation(value: str) -> str:
    content, _ = _line_parts(value)
    return content[: len(content) - len(content.lstrip(" \t"))]


def _is_deeper_indented(value: str, indentation: str) -> bool:
    return (
        value.startswith(indentation)
        and len(value) > len(indentation)
        and value[len(indentation)] in " \t"
    )


def _has_closed_quote(value: str) -> bool:
    if not value or value[0] not in "\"'":
        return True
    quote = value[0]
    escaped = False
    for character in value[1:]:
        if character == quote and not escaped:
            return True
        escaped = character == "\\" and not escaped
        if character != "\\":
            escaped = False
    return False


def _external_reference_family(url: str) -> str:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if "confluence" in host or ("atlassian" in host and path.startswith("/wiki")):
        return "confluence"
    if "jira" in host or ("atlassian" in host and "/browse/" in path):
        return "jira"
    if "foundry" in host:
        return "foundry"
    if "." in host:
        return "url"
    return "unknown"


def _redact_inline_text(value: str, counts: dict[str, int]) -> str:
    def replace_secret(match: re.Match[str]) -> str:
        _increment_count(counts, "secret")
        return "[REDACTED_SECRET]"

    def replace_url(match: re.Match[str]) -> str:
        raw_target = match.group(0)
        target = raw_target.rstrip(".,;:!?")
        suffix = raw_target[len(target) :]
        if not target:
            return raw_target
        _increment_count(counts, "external")
        return "[EXTERNAL:%s:%s]%s" % (
            _external_reference_family(target),
            sha256_bytes(target.encode("utf-8")),
            suffix,
        )

    def replace_email(match: re.Match[str]) -> str:
        _increment_count(counts, "email")
        return "[REDACTED_EMAIL]"

    for pattern in _KNOWN_TOKEN_PATTERNS:
        value = pattern.sub(replace_secret, value)
    value = _BASE64_LIKE_RE.sub(replace_secret, value)
    value = _URL_RE.sub(replace_url, value)
    return _EMAIL_RE.sub(replace_email, value)


def _redact_local_text(value: str) -> Tuple[str, Tuple[Tuple[str, int], ...]]:
    counts: dict[str, int] = {}
    redacted_lines = []
    lines = value.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        content, ending = _line_parts(lines[index])
        pem_begin = _PEM_BEGIN_RE.search(content)
        if pem_begin is not None:
            end_marker = "-----END %s-----" % pem_begin.group("label")
            end_index = index
            while end_index < len(lines):
                end_content, _ = _line_parts(lines[end_index])
                if end_marker in end_content:
                    break
                end_index += 1
            if end_index == len(lines):
                end_index -= 1
            _, final_ending = _line_parts(lines[end_index])
            redacted_lines.append("[REDACTED_SECRET]" + final_ending)
            _increment_count(counts, "secret")
            index = end_index + 1
            continue

        authorization = _AUTHORIZATION_RE.fullmatch(content)
        if authorization is not None and authorization.group("value").strip():
            redacted_lines.append(
                authorization.group("prefix") + "[REDACTED_SECRET]" + ending
            )
            _increment_count(counts, "secret")
            index += 1
            continue

        assignment = _SENSITIVE_ASSIGNMENT_RE.fullmatch(content)
        if assignment is not None:
            key = assignment.group("key").lower()
            category = "secret" if key in _SECRET_KEYS.split("|") else "personal_id"
            marker = "[REDACTED_%s]" % category.upper()
            value_part = assignment.group("value").lstrip(" \t")
            if not _has_closed_quote(value_part):
                redacted_lines.append("[REDACTED_AMBIGUOUS]" + ending)
                _increment_count(counts, "ambiguous")
                index += 1
                continue
            redacted_lines.append(assignment.group("prefix") + marker + ending)
            _increment_count(counts, category)
            indentation = _line_indentation(lines[index])
            block_value = value_part in {"|", ">"}
            next_is_continuation = (
                index + 1 < len(lines)
                and _is_deeper_indented(lines[index + 1], indentation)
            )
            if block_value or next_is_continuation:
                index += 1
                while index < len(lines) and _is_deeper_indented(
                    lines[index], indentation
                ):
                    continuation_indentation = _line_indentation(lines[index])
                    _, continuation_ending = _line_parts(lines[index])
                    redacted_lines.append(
                        continuation_indentation + marker + continuation_ending
                    )
                    index += 1
                continue
            index += 1
            continue

        if _SENSITIVE_KEY_PREFIX_RE.match(content) is not None:
            redacted_lines.append("[REDACTED_AMBIGUOUS]" + ending)
            _increment_count(counts, "ambiguous")
            index += 1
            continue

        bearer_value, bearer_count = _BEARER_RE.subn(
            "Bearer [REDACTED_SECRET]", content
        )
        if bearer_count:
            _increment_count(counts, "secret", bearer_count)
        redacted_lines.append(_redact_inline_text(bearer_value, counts) + ending)
        index += 1
    return "".join(redacted_lines), tuple(sorted(counts.items()))


def _utf8_prefix(value: str, maximum_bytes: int) -> str:
    if maximum_bytes <= 0:
        return ""
    return value.encode("utf-8")[:maximum_bytes].decode("utf-8", errors="ignore")


def _bounded_excerpt(value: str, maximum_bytes: int) -> Tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return value, False
    marker = b"\n[... CONTENT OMITTED ...]\n"
    if maximum_bytes <= len(marker):
        return marker[:maximum_bytes].decode("ascii"), True
    available = maximum_bytes - len(marker)
    front_budget = available * 3 // 4
    back_budget = available - front_budget
    front = encoded[:front_budget].decode("utf-8", errors="ignore")
    back = encoded[len(encoded) - back_budget :].decode(
        "utf-8", errors="ignore"
    )
    return front + marker.decode("ascii") + back, True


def _projection_byte_count(projection: "ContextContentProjection") -> int:
    return (
        len(projection.title.encode("utf-8"))
        + sum(len(heading.encode("utf-8")) for heading in projection.headings)
        + len(projection.excerpt.encode("utf-8"))
    )


def _project_local_text(
    value: str,
    *,
    bounds: "ContextAssemblyBounds",
    content_sha256: str,
    content_byte_count: int,
) -> Tuple["ContextContentProjection", Tuple[str, ...], bool]:
    redacted_value, redaction_counts = _redact_local_text(value)
    all_reference_source_ids = tuple(
        sorted(
            {
                "external:%s:%s" % match.groups()
                for match in _EXTERNAL_MARKER_RE.finditer(redacted_value)
            }
        )
    )
    reference_source_ids = all_reference_source_ids[
        : bounds.local_reference_per_source
    ]
    lines = redacted_value.splitlines()
    title = next(
        (
            match.group(1).strip()
            for line in lines
            if (match := re.fullmatch(r"#[ \t]+(.+)", line)) is not None
        ),
        next((line.strip() for line in lines if line.strip()), "Untitled"),
    )
    all_headings = tuple(
        match.group(1).strip()
        for line in lines
        if (match := re.fullmatch(r"#{2,6}[ \t]+(.+)", line)) is not None
    )
    headings = all_headings[: bounds.local_heading_count]
    excerpt, excerpt_truncated = _bounded_excerpt(
        redacted_value,
        bounds.local_excerpt_bytes,
    )
    return (
        ContextContentProjection(
            title=title,
            headings=headings,
            headings_truncated=len(all_headings) > len(headings),
            excerpt=excerpt,
            excerpt_truncated=excerpt_truncated,
            redaction_counts=redaction_counts,
            full_content_sha256=content_sha256,
            full_content_byte_count=content_byte_count,
        ),
        reference_source_ids,
        len(reference_source_ids) != len(all_reference_source_ids),
    )


def _cap_local_projection(
    source: "ContextSource",
    *,
    excerpt_bytes: int,
    heading_count: int,
    projection_bytes: int,
) -> "ContextSource":
    projection = source.content_projection
    if projection is None:
        return source
    excerpt, excerpt_truncated = _bounded_excerpt(
        projection.excerpt,
        excerpt_bytes,
    )
    headings = projection.headings[:heading_count]
    capped = replace(
        projection,
        headings=headings,
        headings_truncated=(
            projection.headings_truncated or len(headings) != len(projection.headings)
        ),
        excerpt=excerpt,
        excerpt_truncated=projection.excerpt_truncated or excerpt_truncated,
    )
    if _projection_byte_count(capped) > projection_bytes:
        fixed_bytes = (
            len(capped.title.encode("utf-8"))
            + sum(len(heading.encode("utf-8")) for heading in capped.headings)
        )
        excerpt, excerpt_truncated = _bounded_excerpt(
            capped.excerpt,
            max(projection_bytes - fixed_bytes, 0),
        )
        capped = replace(
            capped,
            excerpt=excerpt,
            excerpt_truncated=capped.excerpt_truncated or excerpt_truncated,
        )
    while capped.headings and _projection_byte_count(capped) > projection_bytes:
        capped = replace(
            capped,
            headings=capped.headings[:-1],
            headings_truncated=True,
        )
    if _projection_byte_count(capped) > projection_bytes:
        remaining_title_bytes = max(
            projection_bytes - len(capped.excerpt.encode("utf-8")),
            1,
        )
        capped = replace(
            capped,
            title=_utf8_prefix(capped.title, remaining_title_bytes) or "?",
        )
    return replace(source, content_projection=capped)


def _count_source_groups(sources: Tuple["ContextSource", ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for source in sources:
        counts[source.group] = counts.get(source.group, 0) + 1
    return counts


def _count_sources_with_mode(
    sources: Tuple["ContextSource", ...], mode: str
) -> int:
    return sum(source.mode == mode for source in sources)


def _count_sources_in_group(
    sources: Tuple["ContextSource", ...], group: str
) -> int:
    return sum(source.group == group for source in sources)


@dataclass(frozen=True)
class ContextAssemblyBounds:
    snapshot_bytes: int = 2 * 1024 * 1024
    memory_frontmatter_bytes: int = 64 * 1024
    history_entry_count: int = 512
    history_file_bytes: int = 1024 * 1024
    history_total_bytes: int = 32 * 1024 * 1024
    hint_token_count: int = 4096
    local_source_bytes: int = 64 * 1024 * 1024
    local_total_bytes: int = 256 * 1024 * 1024
    local_excerpt_bytes: int = 8 * 1024
    local_excerpt_total_bytes: int = 1024 * 1024
    local_heading_count: int = 128
    local_heading_total_count: int = 4096
    local_reference_per_source: int = 256
    local_reference_total: int = 4096
    local_projection_total_bytes: int = 2 * 1024 * 1024

    def __post_init__(self) -> None:
        if any(type(value) is not int or value <= 0 for value in self.__dict__.values()):
            raise ContextAssemblyError("Context Assembly bounds are invalid")

    @property
    def canonical_value(self) -> dict[str, int]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class ContextWorkstream:
    id: str
    lifecycle: str
    project_home: str
    aliases: Tuple[str, ...]
    memory_workspace: Optional[str]

    def __post_init__(self) -> None:
        _require_text(self.id, "Workstream id", maximum=128)
        if self.lifecycle not in {"active", "paused", "completed"}:
            raise ContextAssemblyError("Workstream lifecycle is invalid")
        _require_relative_path(self.project_home, "Workstream project home")
        _require_unique_text_tuple(self.aliases, "Workstream aliases are invalid")
        if self.memory_workspace is not None and (
            type(self.memory_workspace) is not str
            or _MEMORY_WORKSPACE_RE.fullmatch(self.memory_workspace) is None
        ):
            raise ContextAssemblyError("Workstream memory workspace is invalid")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "aliases": sorted(self.aliases),
            "id": self.id,
            "lifecycle": self.lifecycle,
            "memory_workspace": self.memory_workspace,
            "project_home": self.project_home,
        }


@dataclass(frozen=True)
class ContextContentProjection:
    title: str
    headings: Tuple[str, ...]
    headings_truncated: bool
    excerpt: str
    excerpt_truncated: bool
    redaction_counts: Tuple[Tuple[str, int], ...]
    full_content_sha256: str
    full_content_byte_count: int
    encoding: str = "utf-8"

    def __post_init__(self) -> None:
        _require_text(self.title, "content projection title")
        if (
            type(self.headings) is not tuple
            or any(type(value) is not str or not value for value in self.headings)
            or type(self.headings_truncated) is not bool
            or type(self.excerpt) is not str
            or type(self.excerpt_truncated) is not bool
            or self.encoding != "utf-8"
            or type(self.full_content_byte_count) is not int
            or self.full_content_byte_count < 0
        ):
            raise ContextAssemblyError("content projection is invalid")
        _require_count_pairs(self.redaction_counts, "content redaction counts")
        _require_hash(self.full_content_sha256, "full content hash")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "encoding": self.encoding,
            "excerpt": self.excerpt,
            "excerpt_truncated": self.excerpt_truncated,
            "full_content_byte_count": self.full_content_byte_count,
            "full_content_sha256": self.full_content_sha256,
            "headings": list(self.headings),
            "headings_truncated": self.headings_truncated,
            "redaction_counts": dict(self.redaction_counts),
            "title": self.title,
        }


@dataclass(frozen=True)
class ContextSource:
    source_id: str
    group: str
    mode: str
    relative_path: Optional[str] = None
    observation_id: Optional[str] = None
    identity: Optional[Tuple[int, ...]] = None
    content_sha256: Optional[str] = None
    snapshot_sha256: Optional[str] = None
    content_projection: Optional[ContextContentProjection] = None
    evidence_sha256: Optional[str] = None
    recorded_at: Optional[str] = None
    reference_family: Optional[str] = None
    reference_sha256: Optional[str] = None
    reference_source_ids: Tuple[str, ...] = ()
    references_truncated: bool = False

    def __post_init__(self) -> None:
        _require_text(self.source_id, "context source id", maximum=256)
        if self.group not in _SOURCE_GROUPS:
            raise ContextAssemblyError("context source group is invalid")
        if self.mode == "CURRENT_LOCAL":
            self._validate_current_local()
        elif self.mode == "HISTORICAL_HINT":
            self._validate_historical()
        elif self.mode == "UNVERIFIED_EXTERNAL":
            self._validate_unverified_external()
        else:
            raise ContextAssemblyError("context source mode is invalid")

    def _validate_current_local(self) -> None:
        if self.group not in _LOCAL_GROUPS:
            raise ContextAssemblyError("current local source group is invalid")
        _require_relative_path(self.relative_path, "current local source path")
        _require_text(self.observation_id, "current local observation id")
        identity = _require_identity(self.identity, "current local identity", size=7)
        if identity[4] != 1:
            raise ContextAssemblyError("current local link count is unsupported")
        _require_hash(self.content_sha256, "current local content hash")
        _require_hash(self.snapshot_sha256, "current local snapshot hash")
        _require_absent(
            (
                self.evidence_sha256,
                self.recorded_at,
                self.reference_family,
                self.reference_sha256,
            ),
            "current local source binding is invalid",
        )
        if (
            not isinstance(self.content_projection, ContextContentProjection)
            or self.content_projection.full_content_sha256 != self.content_sha256
            or self.content_projection.full_content_byte_count != identity[5]
        ):
            raise ContextAssemblyError("current local source binding is invalid")
        _require_unique_text_tuple(
            self.reference_source_ids,
            "current local reference ids are invalid",
        )
        if (
            any(
                _EXTERNAL_SOURCE_ID_RE.fullmatch(source_id) is None
                for source_id in self.reference_source_ids
            )
            or type(self.references_truncated) is not bool
        ):
            raise ContextAssemblyError("current local reference binding is invalid")

    def _validate_historical(self) -> None:
        if self.group not in _MEMORY_GROUPS:
            raise ContextAssemblyError("historical source group is invalid")
        _require_relative_path(self.relative_path, "historical source path")
        identity = _require_identity(self.identity, "historical source identity", size=7)
        if identity[4] != 1:
            raise ContextAssemblyError("historical source link count is unsupported")
        _require_hash(self.content_sha256, "historical content hash")
        _require_hash(self.evidence_sha256, "historical evidence hash")
        _require_text(self.recorded_at, "historical recorded at")
        _require_absent(
            (
                self.observation_id,
                self.snapshot_sha256,
                self.content_projection,
                self.reference_family,
                self.reference_sha256,
            ),
            "historical source binding is invalid",
        )
        if self.reference_source_ids or self.references_truncated:
            raise ContextAssemblyError("historical source reference binding is invalid")

    def _validate_unverified_external(self) -> None:
        if self.group != "EXTERNAL_REFERENCE":
            raise ContextAssemblyError("external source group is invalid")
        if self.reference_family not in _EXTERNAL_REFERENCE_FAMILIES:
            raise ContextAssemblyError("external reference family is invalid")
        _require_hash(self.reference_sha256, "external reference hash")
        expected_source_id = "external:%s:%s" % (
            self.reference_family,
            self.reference_sha256,
        )
        if self.source_id != expected_source_id:
            raise ContextAssemblyError("external source id is invalid")
        _require_absent(
            (
                self.relative_path,
                self.observation_id,
                self.identity,
                self.content_sha256,
                self.snapshot_sha256,
                self.content_projection,
                self.evidence_sha256,
                self.recorded_at,
            ),
            "external source binding is invalid",
        )
        if self.reference_source_ids or self.references_truncated:
            raise ContextAssemblyError("external source reference binding is invalid")

    @property
    def canonical_value(self) -> dict[str, object]:
        value: dict[str, object] = {
            "group": self.group,
            "mode": self.mode,
            "source_id": self.source_id,
        }
        for key, item in (
            ("relative_path", self.relative_path),
            ("observation_id", self.observation_id),
            ("content_sha256", self.content_sha256),
            ("snapshot_sha256", self.snapshot_sha256),
            ("evidence_sha256", self.evidence_sha256),
            ("recorded_at", self.recorded_at),
            ("reference_family", self.reference_family),
            ("reference_sha256", self.reference_sha256),
        ):
            if item is not None:
                value[key] = item
        if self.identity is not None:
            value["identity"] = list(self.identity)
        if self.content_projection is not None:
            value["content_projection"] = self.content_projection.canonical_value
        if self.reference_source_ids:
            value["reference_source_ids"] = sorted(self.reference_source_ids)
        if self.references_truncated:
            value["references_truncated"] = True
        return value


def read_current_local_source(
    root: Path,
    observation: object,
    *,
    group: str,
    bounds: ContextAssemblyBounds,
) -> ContextSource:
    """Re-read one observed local source and return a bounded safe projection."""
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or Path(os.path.abspath(root)) != root
        or group not in _LOCAL_GROUPS
        or not isinstance(bounds, ContextAssemblyBounds)
    ):
        raise ContextAssemblyError("current local reader input is invalid")
    relative_path = _observation_value(observation, "relative_path", str)
    _require_relative_path(relative_path, "current local source path")
    observation_id = _observation_value(observation, "observation_id", str)
    expected_identity = tuple(
        _observation_value(observation, name, int)
        for name in (
            "device",
            "inode",
            "owner",
            "mode",
            "link_count",
            "size",
            "modified_time_ns",
        )
    )
    if expected_identity[4] != 1:
        raise ContextAssemblyError("current local observation is invalid")
    expected_content_sha256 = _require_hash(
        _observation_value(observation, "content_sha256", str),
        "current local observation content hash",
    )
    snapshot_sha256 = _require_hash(
        _observation_value(observation, "snapshot_sha256", str),
        "current local observation snapshot hash",
    )

    lexical_path = safety.require_no_symlink_components(
        relative_path,
        root,
        "current local source",
        error_type=ContextAssemblyError,
    )
    parent_fd = safety.open_verified_directory(
        lexical_path.parent,
        require_owner_only=True,
        error_type=ContextAssemblyError,
    )
    try:
        info, raw = safety.read_regular_file_at(
            parent_fd,
            lexical_path.name,
            lexical_path,
            label="current local source",
            expected_mode=None,
            max_bytes=bounds.local_source_bytes,
            error_type=ContextAssemblyError,
        )
        safety.require_same_directory_identity(
            lexical_path.parent,
            parent_fd,
            "current local source parent",
            error_type=ContextAssemblyError,
        )
    finally:
        os.close(parent_fd)

    actual_identity = (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
    )
    content_sha256 = sha256_bytes(raw)
    if actual_identity != expected_identity or content_sha256 != expected_content_sha256:
        raise ContextAssemblyError(
            "current local source changed after observation",
            reason_code="CONTEXT_STALE",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContextAssemblyError(
            "current local source is not valid UTF-8",
            reason_code="LOCAL_SOURCE_INVALID_UTF8",
        ) from exc
    projection, reference_source_ids, references_truncated = _project_local_text(
        text,
        bounds=bounds,
        content_sha256=content_sha256,
        content_byte_count=len(raw),
    )
    return ContextSource(
        source_id=observation_id,
        group=group,
        mode="CURRENT_LOCAL",
        relative_path=relative_path,
        observation_id=observation_id,
        identity=actual_identity,
        content_sha256=content_sha256,
        snapshot_sha256=snapshot_sha256,
        content_projection=projection,
        reference_source_ids=reference_source_ids,
        references_truncated=references_truncated,
    )


@dataclass(frozen=True)
class ContextClaim:
    claim_id: str
    mode: str
    subject: str
    supporting_source_ids: Tuple[str, ...]
    historical_source_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.claim_id, "context claim id", maximum=256)
        _require_text(self.subject, "context claim subject")
        if self.mode not in _CLAIM_MODES or self.mode == "CURRENT_EXTERNAL":
            raise ContextAssemblyError("context claim mode is invalid")
        for label, values in (
            ("supporting source ids", self.supporting_source_ids),
            ("historical source ids", self.historical_source_ids),
        ):
            _require_unique_text_tuple(
                values, "context claim %s are invalid" % label
            )
        if not self.supporting_source_ids:
            raise ContextAssemblyError("context claim has no supporting source")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "historical_source_ids": sorted(self.historical_source_ids),
            "mode": self.mode,
            "subject": self.subject,
            "supporting_source_ids": sorted(self.supporting_source_ids),
        }


@dataclass(frozen=True)
class ContextGap:
    gap_id: str
    kind: str
    group: str
    reason_code: str
    relative_path: Optional[str] = None

    def __post_init__(self) -> None:
        _require_text(self.gap_id, "context gap id", maximum=256)
        if self.kind not in {"MISSING", "CONFLICT", "UNREADABLE", "TRUNCATED"}:
            raise ContextAssemblyError("context gap kind is invalid")
        if self.group not in _SOURCE_GROUPS:
            raise ContextAssemblyError("context gap group is invalid")
        _require_text(self.reason_code, "context gap reason", maximum=128)
        if self.relative_path is not None:
            _require_relative_path(self.relative_path, "context gap path")

    @property
    def canonical_value(self) -> dict[str, object]:
        value: dict[str, object] = {
            "gap_id": self.gap_id,
            "group": self.group,
            "kind": self.kind,
            "reason_code": self.reason_code,
        }
        if self.relative_path is not None:
            value["relative_path"] = self.relative_path
        return value


@dataclass(frozen=True)
class ContextLocalObservation:
    observation: object
    group: str

    def __post_init__(self) -> None:
        if self.group not in _LOCAL_GROUPS:
            raise ContextAssemblyError("local Context source group is invalid")
        _observation_value(self.observation, "observation_id", str)
        _observation_value(self.observation, "relative_path", str)
        _observation_value(self.observation, "content_sha256", str)
        _observation_value(self.observation, "snapshot_sha256", str)


@dataclass(frozen=True)
class MemoryHint:
    hint_id: str
    kind: str
    historical_source_ids: Tuple[str, ...]
    relative_path: Optional[str] = None
    reference_family: Optional[str] = None
    reference_sha256: Optional[str] = None

    def __post_init__(self) -> None:
        _require_text(self.hint_id, "memory hint id", maximum=256)
        _require_unique_text_tuple(
            self.historical_source_ids,
            "memory hint source ids are invalid",
        )
        if not self.historical_source_ids:
            raise ContextAssemblyError("memory hint has no historical source")
        if self.kind == "LOCAL_PATH":
            relative_path = _require_relative_path(
                self.relative_path, "memory local hint path"
            )
            expected_id = "memory-hint:local:%s" % sha256_bytes(
                relative_path.encode("utf-8")
            )
            if (
                self.hint_id != expected_id
                or self.reference_family is not None
                or self.reference_sha256 is not None
            ):
                raise ContextAssemblyError("memory local hint is invalid")
        elif self.kind == "EXTERNAL_REFERENCE":
            if self.reference_family not in _EXTERNAL_REFERENCE_FAMILIES:
                raise ContextAssemblyError("memory external hint family is invalid")
            reference_sha256 = _require_hash(
                self.reference_sha256, "memory external hint hash"
            )
            expected_id = "memory-hint:external:%s:%s" % (
                self.reference_family,
                reference_sha256,
            )
            if self.hint_id != expected_id or self.relative_path is not None:
                raise ContextAssemblyError("memory external hint is invalid")
        else:
            raise ContextAssemblyError("memory hint kind is invalid")

    @property
    def canonical_value(self) -> dict[str, object]:
        value: dict[str, object] = {
            "historical_source_ids": sorted(self.historical_source_ids),
            "hint_id": self.hint_id,
            "kind": self.kind,
        }
        if self.relative_path is not None:
            value["relative_path"] = self.relative_path
        if self.reference_family is not None:
            value["reference_family"] = self.reference_family
        if self.reference_sha256 is not None:
            value["reference_sha256"] = self.reference_sha256
        return value


@dataclass(frozen=True)
class MemoryCaptureCounts:
    snapshot_bytes_read: int
    snapshot_hint_count: int
    history_inspected: int
    history_included: int
    history_excluded: int
    history_malformed: int
    history_truncated: int
    history_bytes_read: int
    hint_tokens_extracted: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0 for value in self.__dict__.values()
        ):
            raise ContextAssemblyError("memory capture counts are invalid")

    @property
    def canonical_value(self) -> dict[str, int]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class MemoryContextCapture:
    status: str
    workspace_identity: Optional[Tuple[int, int, int, int]]
    history_directory_identity: Optional[Tuple[int, int, int, int]]
    snapshot: Optional[ContextSource]
    history: Tuple[ContextSource, ...]
    hints: Tuple[MemoryHint, ...]
    gaps: Tuple[ContextGap, ...]
    excluded_paths: Tuple[str, ...]
    freshness_sha256: str
    counts: MemoryCaptureCounts

    def __post_init__(self) -> None:
        if self.status not in {"NOT_CONFIGURED", "CONFIGURED"}:
            raise ContextAssemblyError("memory capture status is invalid")
        if not isinstance(self.counts, MemoryCaptureCounts):
            raise ContextAssemblyError("memory capture counts are invalid")
        _require_hash(self.freshness_sha256, "memory freshness hash")
        for value, label in (
            (self.workspace_identity, "memory workspace identity"),
            (self.history_directory_identity, "memory history identity"),
        ):
            if value is not None:
                _require_identity(value, label, size=4)
        if self.snapshot is not None and (
            not isinstance(self.snapshot, ContextSource)
            or self.snapshot.group != "MEMORY_SNAPSHOT"
            or self.snapshot.mode != "HISTORICAL_HINT"
        ):
            raise ContextAssemblyError("memory snapshot capture is invalid")
        if (
            type(self.history) is not tuple
            or any(
                not isinstance(source, ContextSource)
                or source.group != "MEMORY_HISTORY"
                or source.mode != "HISTORICAL_HINT"
                for source in self.history
            )
            or type(self.hints) is not tuple
            or any(not isinstance(hint, MemoryHint) for hint in self.hints)
            or type(self.gaps) is not tuple
            or any(not isinstance(gap, ContextGap) for gap in self.gaps)
        ):
            raise ContextAssemblyError("memory capture semantic is invalid")
        _require_unique_text_tuple(
            self.excluded_paths, "memory excluded paths are invalid"
        )
        if self.status == "NOT_CONFIGURED" and any(
            value
            for value in (
                self.workspace_identity,
                self.history_directory_identity,
                self.snapshot,
                self.history,
                self.hints,
                self.gaps,
                self.excluded_paths,
            )
        ):
            raise ContextAssemblyError("unconfigured memory capture is not empty")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "counts": self.counts.canonical_value,
            "excluded_paths": sorted(self.excluded_paths),
            "freshness_sha256": self.freshness_sha256,
            "gaps": [
                gap.canonical_value
                for gap in sorted(self.gaps, key=lambda value: value.gap_id)
            ],
            "hints": [
                hint.canonical_value
                for hint in sorted(self.hints, key=lambda value: value.hint_id)
            ],
            "history": [
                source.canonical_value
                for source in sorted(self.history, key=lambda value: value.source_id)
            ],
            "history_directory_identity": (
                None
                if self.history_directory_identity is None
                else list(self.history_directory_identity)
            ),
            "snapshot": (
                None if self.snapshot is None else self.snapshot.canonical_value
            ),
            "status": self.status,
            "workspace_identity": (
                None
                if self.workspace_identity is None
                else list(self.workspace_identity)
            ),
        }


def _empty_memory_counts() -> MemoryCaptureCounts:
    return MemoryCaptureCounts(
        snapshot_bytes_read=0,
        snapshot_hint_count=0,
        history_inspected=0,
        history_included=0,
        history_excluded=0,
        history_malformed=0,
        history_truncated=0,
        history_bytes_read=0,
        hint_tokens_extracted=0,
    )


def _filesystem_identity(info: os.stat_result) -> Tuple[int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
    )


def _source_identity(info: os.stat_result) -> Tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
    )


def _parse_memory_frontmatter(
    raw: bytes,
    *,
    maximum_bytes: int,
) -> Tuple[object, str, bytes]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContextAssemblyError("memory document is not valid UTF-8") from exc
    lines = text.splitlines(keepends=True)
    if not lines or _line_parts(lines[0])[0] != "---":
        raise ContextAssemblyError("memory frontmatter is missing")
    closing_index = next(
        (
            index
            for index, line in enumerate(lines[1:], 1)
            if _line_parts(line)[0] == "---"
        ),
        None,
    )
    if closing_index is None:
        raise ContextAssemblyError("memory frontmatter is malformed")
    frontmatter = "".join(lines[1:closing_index]).encode("utf-8")
    if len(frontmatter) > maximum_bytes:
        raise ContextAssemblyError("memory frontmatter exceeds byte bound")
    parser_input_lines = []
    for line in "".join(lines[1:closing_index]).splitlines(keepends=True):
        content, ending = _line_parts(line)
        normalized = content
        for field in ("created_at", "event_time", "updated_at"):
            prefix = field + ":"
            if content.startswith(prefix):
                value = content[len(prefix) :].strip()
                if _is_canonical_rfc3339(value):
                    normalized = f'{prefix} "{value}"'
                break
        parser_input_lines.append(normalized + ending)
    try:
        parsed = policy.parse_strict_yaml("".join(parser_input_lines).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ContextAssemblyError("memory frontmatter is malformed") from exc
    return parsed, "".join(lines[closing_index + 1 :]), frontmatter


def _select_snapshot_block(
    body: str,
    workstream: ContextWorkstream,
) -> str:
    lines = body.splitlines()
    section_indexes = [
        index for index, line in enumerate(lines) if line == "## Workstreams"
    ]
    if len(section_indexes) != 1:
        raise ContextAssemblyError(
            "snapshot Workstreams section is ambiguous",
            reason_code="SNAPSHOT_WORKSTREAM_SECTION_INVALID",
        )
    section_start = section_indexes[0] + 1
    section_end = next(
        (
            index
            for index in range(section_start, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    block_starts = [
        index
        for index in range(section_start, section_end)
        if re.fullmatch(r"- id:[ \t]+.+", lines[index]) is not None
    ]
    names = {workstream.id, *workstream.aliases}
    matches = []
    for offset, block_start in enumerate(block_starts):
        block_end = (
            block_starts[offset + 1]
            if offset + 1 < len(block_starts)
            else section_end
        )
        identifier = lines[block_start].split(":", 1)[1].strip()
        if identifier in names:
            matches.append("\n".join(lines[block_start:block_end]) + "\n")
    if not matches:
        raise ContextAssemblyError(
            "snapshot Workstream block is missing",
            reason_code="SNAPSHOT_WORKSTREAM_UNMATCHED",
        )
    if len(matches) != 1:
        raise ContextAssemblyError(
            "snapshot Workstream block is ambiguous",
            reason_code="SNAPSHOT_WORKSTREAM_AMBIGUOUS",
        )
    return matches[0]


def _normalize_memory_local_path(
    value: str,
    root: Path,
    project_home: str,
) -> Optional[str]:
    candidate = value.strip().strip("<>`'\"")
    candidate = candidate.split("#", 1)[0].split("?", 1)[0]
    root_prefix = root.as_posix().rstrip("/") + "/"
    if candidate.startswith(root_prefix):
        candidate = candidate[len(root_prefix) :]
    elif candidate.startswith("/"):
        return None
    elif candidate.startswith("~/"):
        return None
    elif not (
        candidate == project_home
        or candidate.startswith(project_home + "/")
        or candidate.startswith("projects/")
        or candidate.startswith("artifacts/")
    ):
        candidate = project_home + "/" + candidate
    try:
        return _require_relative_path(candidate, "memory local hint path")
    except ContextAssemblyError:
        return None


def _is_explicit_free_path_token(value: str) -> bool:
    if value.startswith(("/", "projects/", "artifacts/")):
        return True
    final_component = value.rsplit("/", 1)[-1]
    return "." in final_component and not final_component.startswith(".")


def _memory_hints_from_text(
    value: str,
    *,
    source_id: str,
    root: Path,
    project_home: str,
    maximum_tokens: int,
) -> Tuple[Tuple[MemoryHint, ...], int, bool]:
    hints: dict[str, MemoryHint] = {}
    extracted_count = 0
    truncated = False
    for line in value.splitlines():
        line_hints = []
        for url_match in _URL_RE.finditer(line):
            raw_target = url_match.group(0)
            target = raw_target.rstrip(".,;:!?")
            family = _external_reference_family(target)
            reference_sha256 = sha256_bytes(target.encode("utf-8"))
            line_hints.append(
                MemoryHint(
                    hint_id="memory-hint:external:%s:%s"
                    % (family, reference_sha256),
                    kind="EXTERNAL_REFERENCE",
                    historical_source_ids=(source_id,),
                    reference_family=family,
                    reference_sha256=reference_sha256,
                )
            )
        assignment_match = re.fullmatch(
            r"[ \t]*(?:path|source|ref)[ \t]*:[ \t]*(\S+)[ \t]*",
            line,
            re.IGNORECASE,
        )
        path_candidates = []
        if assignment_match is not None:
            path_candidates.append(assignment_match.group(1))
        path_candidates.extend(
            match.group(1) for match in _MARKDOWN_TARGET_RE.finditer(line)
        )
        path_candidates.extend(
            match.group(0)
            for match in _POSIX_PATH_TOKEN_RE.finditer(line)
            if _is_explicit_free_path_token(match.group(0))
        )
        line_relative_paths = set()
        for candidate in path_candidates:
            if candidate.startswith(("http://", "https://")):
                continue
            relative_path = _normalize_memory_local_path(
                candidate,
                root,
                project_home,
            )
            if relative_path is None or relative_path in line_relative_paths:
                continue
            line_relative_paths.add(relative_path)
            line_hints.append(
                MemoryHint(
                    hint_id="memory-hint:local:%s"
                    % sha256_bytes(relative_path.encode("utf-8")),
                    kind="LOCAL_PATH",
                    historical_source_ids=(source_id,),
                    relative_path=relative_path,
                )
            )
        for hint in line_hints:
            if extracted_count >= maximum_tokens:
                truncated = True
                break
            extracted_count += 1
            hints[hint.hint_id] = hint
        if truncated:
            break
    return (
        tuple(sorted(hints.values(), key=lambda value: value.hint_id)),
        extracted_count,
        truncated,
    )


def _merge_memory_hints(
    current: Tuple[MemoryHint, ...],
    added: Tuple[MemoryHint, ...],
) -> Tuple[MemoryHint, ...]:
    merged = {hint.hint_id: hint for hint in current}
    for hint in added:
        existing = merged.get(hint.hint_id)
        if existing is None:
            merged[hint.hint_id] = hint
            continue
        source_ids = tuple(
            sorted(
                {
                    *existing.historical_source_ids,
                    *hint.historical_source_ids,
                }
            )
        )
        merged[hint.hint_id] = MemoryHint(
            hint_id=existing.hint_id,
            kind=existing.kind,
            historical_source_ids=source_ids,
            relative_path=existing.relative_path,
            reference_family=existing.reference_family,
            reference_sha256=existing.reference_sha256,
        )
    return tuple(sorted(merged.values(), key=lambda value: value.hint_id))


def _historical_source(
    *,
    source_id: str,
    group: str,
    relative_path: str,
    info: os.stat_result,
    raw: bytes,
    evidence_sha256: str,
    recorded_at: object,
) -> ContextSource:
    return ContextSource(
        source_id=source_id,
        group=group,
        mode="HISTORICAL_HINT",
        relative_path=relative_path,
        identity=_source_identity(info),
        content_sha256=sha256_bytes(raw),
        evidence_sha256=evidence_sha256,
        recorded_at=_require_text(recorded_at, "memory recorded at", maximum=128),
    )


def _revalidate_memory_file(
    *,
    parent_fd: int,
    entry_name: str,
    lexical_path: Path,
    expected_identity: Tuple[int, ...],
    expected_content_sha256: str,
    maximum_bytes: int,
) -> None:
    info, raw = safety.read_regular_file_at(
        parent_fd,
        entry_name,
        lexical_path,
        label="memory source revalidation",
        expected_mode=None,
        max_bytes=maximum_bytes,
        error_type=_MemoryUnsafeError,
    )
    if (
        _source_identity(info) != expected_identity
        or sha256_bytes(raw) != expected_content_sha256
    ):
        raise ContextAssemblyError(
            "memory source changed during capture",
            reason_code="CONTEXT_STALE",
        )


def _memory_gap(
    *,
    kind: str,
    group: str,
    reason_code: str,
    relative_path: str,
) -> ContextGap:
    return ContextGap(
        gap_id="memory-gap:%s"
        % sha256_bytes((reason_code + "\0" + relative_path).encode("utf-8")),
        kind=kind,
        group=group,
        reason_code=reason_code,
        relative_path=relative_path,
    )


def _memory_freshness_sha256(
    *,
    workspace_identity: Optional[Tuple[int, int, int, int]],
    history_directory_identity: Optional[Tuple[int, int, int, int]],
    snapshot_binding: Optional[Tuple[Tuple[int, ...], str]],
    history_bindings: Tuple[Tuple[str, Path, Tuple[int, ...], str], ...],
) -> str:
    """Hash the bounded memory membership without persisting bodies or raw paths."""

    value = {
        "history_directory_identity": (
            None
            if history_directory_identity is None
            else list(history_directory_identity)
        ),
        "history_entries": [
            {
                "content_sha256": content_sha256,
                "identity": list(identity),
                "name": entry_name,
            }
            for entry_name, _entry_path, identity, content_sha256 in sorted(
                history_bindings,
                key=lambda item: item[0],
            )
        ],
        "snapshot": (
            None
            if snapshot_binding is None
            else {
                "content_sha256": snapshot_binding[1],
                "identity": list(snapshot_binding[0]),
            }
        ),
        "workspace_identity": (
            None if workspace_identity is None else list(workspace_identity)
        ),
    }
    return sha256_bytes(canonical_json_bytes(value))


def _configured_memory_capture(
    *,
    workspace_identity: Optional[Tuple[int, int, int, int]],
    history_directory_identity: Optional[Tuple[int, int, int, int]],
    snapshot: Optional[ContextSource],
    history: Tuple[ContextSource, ...],
    hints: Tuple[MemoryHint, ...],
    gaps: Tuple[ContextGap, ...],
    excluded_paths: Tuple[str, ...],
    freshness_sha256: str,
    counts: MemoryCaptureCounts,
) -> MemoryContextCapture:
    return MemoryContextCapture(
        status="CONFIGURED",
        workspace_identity=workspace_identity,
        history_directory_identity=history_directory_identity,
        snapshot=snapshot,
        history=history,
        hints=hints,
        gaps=gaps,
        excluded_paths=excluded_paths,
        freshness_sha256=freshness_sha256,
        counts=counts,
    )


def read_memory_context(
    root: Path,
    workstream: ContextWorkstream,
    *,
    bounds: ContextAssemblyBounds,
) -> MemoryContextCapture:
    """Read exact protected-memory routes without promoting hints to current truth."""
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or Path(os.path.abspath(root)) != root
        or not isinstance(workstream, ContextWorkstream)
        or not isinstance(bounds, ContextAssemblyBounds)
    ):
        raise ContextAssemblyError("memory reader input is invalid")
    if workstream.memory_workspace is None:
        return MemoryContextCapture(
            status="NOT_CONFIGURED",
            workspace_identity=None,
            history_directory_identity=None,
            snapshot=None,
            history=(),
            hints=(),
            gaps=(),
            excluded_paths=(),
            freshness_sha256=NOT_CONFIGURED_MEMORY_FRESHNESS_SHA256,
            counts=_empty_memory_counts(),
        )

    workspace_relative = "memory/%s" % workstream.memory_workspace
    workspace_path = safety.require_no_symlink_components(
        workspace_relative,
        root,
        "memory workspace",
        error_type=_MemoryUnsafeError,
    )
    snapshot_relative = "%s/snapshot.md" % workspace_relative
    history_relative = "%s/history" % workspace_relative
    if not os.path.lexists(workspace_path):
        return _configured_memory_capture(
            workspace_identity=None,
            history_directory_identity=None,
            snapshot=None,
            history=(),
            hints=(),
            gaps=(
                _memory_gap(
                    kind="MISSING",
                    group="MEMORY_SNAPSHOT",
                    reason_code="SNAPSHOT_MISSING",
                    relative_path=snapshot_relative,
                ),
                _memory_gap(
                    kind="MISSING",
                    group="MEMORY_HISTORY",
                    reason_code="HISTORY_DIRECTORY_MISSING",
                    relative_path=history_relative,
                ),
            ),
            excluded_paths=(),
            freshness_sha256=NOT_CONFIGURED_MEMORY_FRESHNESS_SHA256,
            counts=_empty_memory_counts(),
        )
    workspace_fd = safety.open_verified_directory(
        workspace_path,
        require_owner_only=True,
        error_type=_MemoryUnsafeError,
    )
    history_fd = None
    try:
        workspace_info = os.fstat(workspace_fd)
        gaps = []
        snapshot_source = None
        snapshot_raw = b""
        snapshot_binding = None
        hints: Tuple[MemoryHint, ...] = ()
        hint_tokens_extracted = 0
        hint_limit_reached = False
        snapshot_path = workspace_path / "snapshot.md"
        try:
            snapshot_lexical = os.stat(
                "snapshot.md",
                dir_fd=workspace_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            snapshot_lexical = None
        if snapshot_lexical is None:
            gaps.append(
                _memory_gap(
                    kind="MISSING",
                    group="MEMORY_SNAPSHOT",
                    reason_code="SNAPSHOT_MISSING",
                    relative_path=snapshot_relative,
                )
            )
        else:
            if (
                not stat.S_ISREG(snapshot_lexical.st_mode)
                or snapshot_lexical.st_uid != os.getuid()
                or stat.S_IMODE(snapshot_lexical.st_mode) & 0o022
                or snapshot_lexical.st_nlink != 1
            ):
                raise _MemoryUnsafeError("memory snapshot is unsafe")
            if snapshot_lexical.st_size > bounds.snapshot_bytes:
                gaps.append(
                    _memory_gap(
                        kind="TRUNCATED",
                        group="MEMORY_SNAPSHOT",
                        reason_code="SNAPSHOT_BYTE_LIMIT",
                        relative_path=snapshot_relative,
                    )
                )
            else:
                snapshot_info, snapshot_raw = safety.read_regular_file_at(
                    workspace_fd,
                    "snapshot.md",
                    snapshot_path,
                    label="memory snapshot",
                    expected_mode=None,
                    max_bytes=bounds.snapshot_bytes,
                    error_type=_MemoryUnsafeError,
                )
                snapshot_binding = (
                    _source_identity(snapshot_info),
                    sha256_bytes(snapshot_raw),
                )
                try:
                    snapshot_frontmatter, snapshot_body, _ = _parse_memory_frontmatter(
                        snapshot_raw,
                        maximum_bytes=bounds.memory_frontmatter_bytes,
                    )
                    updated_at = snapshot_frontmatter.get("updated_at")
                    if not _is_canonical_rfc3339(updated_at):
                        raise ContextAssemblyError(
                            "snapshot updated_at is invalid",
                            reason_code="SNAPSHOT_UPDATED_AT_INVALID",
                        )
                    selected_block = _select_snapshot_block(snapshot_body, workstream)
                    snapshot_source = _historical_source(
                        source_id="memory:snapshot:%s" % workstream.memory_workspace,
                        group="MEMORY_SNAPSHOT",
                        relative_path=snapshot_relative,
                        info=snapshot_info,
                        raw=snapshot_raw,
                        evidence_sha256=sha256_bytes(selected_block.encode("utf-8")),
                        recorded_at=updated_at,
                    )
                    (
                        hints,
                        hint_tokens_extracted,
                        hint_limit_reached,
                    ) = _memory_hints_from_text(
                        selected_block,
                        source_id=snapshot_source.source_id,
                        root=root,
                        project_home=workstream.project_home,
                        maximum_tokens=bounds.hint_token_count,
                    )
                except ContextAssemblyError as exc:
                    reason_code = (
                        exc.reason_code
                        if exc.reason_code.startswith("SNAPSHOT_")
                        else "SNAPSHOT_MALFORMED"
                    )
                    gap_kind = (
                        "MISSING"
                        if reason_code == "SNAPSHOT_WORKSTREAM_UNMATCHED"
                        else "CONFLICT"
                        if reason_code == "SNAPSHOT_WORKSTREAM_AMBIGUOUS"
                        else "UNREADABLE"
                    )
                    gaps.append(
                        _memory_gap(
                            kind=gap_kind,
                            group="MEMORY_SNAPSHOT",
                            reason_code=reason_code,
                            relative_path=snapshot_relative,
                        )
                    )
        if hint_limit_reached:
            gaps.append(
                _memory_gap(
                    kind="TRUNCATED",
                    group="MEMORY_SNAPSHOT",
                    reason_code="MEMORY_HINT_TOKEN_LIMIT",
                    relative_path=snapshot_relative,
                )
            )
        snapshot_hint_count = len(hints)

        history_path = workspace_path / "history"
        try:
            history_lexical = os.stat(
                "history",
                dir_fd=workspace_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            history_lexical = None
        if history_lexical is None:
            gaps.append(
                _memory_gap(
                    kind="MISSING",
                    group="MEMORY_HISTORY",
                    reason_code="HISTORY_DIRECTORY_MISSING",
                    relative_path=history_relative,
                )
            )
            if snapshot_binding is not None:
                _revalidate_memory_file(
                    parent_fd=workspace_fd,
                    entry_name="snapshot.md",
                    lexical_path=snapshot_path,
                    expected_identity=snapshot_binding[0],
                    expected_content_sha256=snapshot_binding[1],
                    maximum_bytes=bounds.snapshot_bytes,
                )
            safety.require_same_directory_identity(
                workspace_path,
                workspace_fd,
                "memory workspace",
                error_type=_MemoryUnsafeError,
            )
            return _configured_memory_capture(
                workspace_identity=_filesystem_identity(workspace_info),
                history_directory_identity=None,
                snapshot=snapshot_source,
                history=(),
                hints=hints,
                gaps=tuple(gaps),
                excluded_paths=(),
                freshness_sha256=_memory_freshness_sha256(
                    workspace_identity=_filesystem_identity(workspace_info),
                    history_directory_identity=None,
                    snapshot_binding=snapshot_binding,
                    history_bindings=(),
                ),
                counts=MemoryCaptureCounts(
                    snapshot_bytes_read=len(snapshot_raw),
                    snapshot_hint_count=snapshot_hint_count,
                    history_inspected=0,
                    history_included=0,
                    history_excluded=0,
                    history_malformed=0,
                    history_truncated=0,
                    history_bytes_read=0,
                    hint_tokens_extracted=hint_tokens_extracted,
                ),
            )
        if not stat.S_ISDIR(history_lexical.st_mode):
            raise _MemoryUnsafeError("memory history route is unsafe")
        history_fd = safety.open_verified_directory(
            history_path,
            require_owner_only=True,
            error_type=_MemoryUnsafeError,
        )
        history_info = os.fstat(history_fd)
        all_entry_names = sorted(os.listdir(history_fd))
        history_truncated = max(
            len(all_entry_names) - bounds.history_entry_count,
            0,
        )
        entry_names = all_entry_names[: bounds.history_entry_count]
        if history_truncated:
            gaps.append(
                _memory_gap(
                    kind="TRUNCATED",
                    group="MEMORY_HISTORY",
                    reason_code="HISTORY_ENTRY_LIMIT",
                    relative_path=history_relative,
                )
            )
        history_sources = []
        history_bindings = []
        excluded_paths = []
        history_bytes = 0
        history_malformed = 0
        for entry_name in entry_names:
            entry_path = history_path / entry_name
            lexical_info = os.stat(
                entry_name,
                dir_fd=history_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(lexical_info.st_mode)
                or lexical_info.st_uid != os.getuid()
                or stat.S_IMODE(lexical_info.st_mode) & 0o022
                or lexical_info.st_nlink != 1
            ):
                raise _MemoryUnsafeError("memory history entry is unsafe")
            relative_path = "%s/history/%s" % (workspace_relative, entry_name)
            if lexical_info.st_size > bounds.history_file_bytes:
                history_truncated += 1
                gaps.append(
                    _memory_gap(
                        kind="TRUNCATED",
                        group="MEMORY_HISTORY",
                        reason_code="HISTORY_FILE_LIMIT",
                        relative_path=relative_path,
                    )
                )
                continue
            if history_bytes + lexical_info.st_size > bounds.history_total_bytes:
                history_truncated += 1
                gaps.append(
                    _memory_gap(
                        kind="TRUNCATED",
                        group="MEMORY_HISTORY",
                        reason_code="HISTORY_TOTAL_LIMIT",
                        relative_path=relative_path,
                    )
                )
                continue
            info, raw = safety.read_regular_file_at(
                history_fd,
                entry_name,
                entry_path,
                label="memory history entry",
                expected_mode=None,
                max_bytes=bounds.history_file_bytes,
                error_type=_MemoryUnsafeError,
            )
            history_bindings.append(
                (
                    entry_name,
                    entry_path,
                    _source_identity(info),
                    sha256_bytes(raw),
                )
            )
            history_bytes += len(raw)
            try:
                frontmatter, history_body, _frontmatter_raw = _parse_memory_frontmatter(
                    raw,
                    maximum_bytes=bounds.memory_frontmatter_bytes,
                )
                workstream_id = frontmatter.get("workstream_id")
                frontmatter_workstream = frontmatter.get("workstream")
                created_at = frontmatter.get("created_at")
                event_time = frontmatter.get("event_time")
                legacy_event = (
                    isinstance(frontmatter_workstream, Mapping)
                    or event_time is not None
                )
                if legacy_event:
                    schema_version = frontmatter.get("schema_version")
                    if (
                        type(schema_version) is not int
                        or schema_version != 1
                        or workstream_id is not None
                        or created_at is not None
                        or not isinstance(frontmatter_workstream, Mapping)
                        or set(frontmatter_workstream) != {"id", "status"}
                        or type(frontmatter_workstream.get("id")) is not str
                        or frontmatter_workstream.get("status")
                        not in {"active", "paused", "completed"}
                        or not _is_canonical_rfc3339(event_time)
                    ):
                        raise ContextAssemblyError(
                            "memory history legacy event membership is malformed"
                        )
                    observed_workstream = frontmatter_workstream["id"]
                    recorded_at = event_time
                    evidence = {
                        "event_time": event_time,
                        "workstream": observed_workstream,
                    }
                else:
                    if (
                        workstream_id is not None
                        and frontmatter_workstream is not None
                        and workstream_id != frontmatter_workstream
                    ):
                        raise ContextAssemblyError(
                            "memory history membership is contradictory"
                        )
                    observed_workstream = (
                        workstream_id
                        if workstream_id is not None
                        else frontmatter_workstream
                    )
                    if (
                        type(observed_workstream) is not str
                        or not _is_canonical_rfc3339(created_at)
                    ):
                        raise ContextAssemblyError(
                            "memory history membership is malformed"
                        )
                    recorded_at = created_at
                    evidence = {
                        "created_at": created_at,
                        "workstream": observed_workstream,
                    }
            except ContextAssemblyError:
                history_malformed += 1
                gaps.append(
                    _memory_gap(
                        kind="UNREADABLE",
                        group="MEMORY_HISTORY",
                        reason_code="HISTORY_MEMBER_MALFORMED",
                        relative_path=relative_path,
                    )
                )
                continue
            if observed_workstream not in {workstream.id, *workstream.aliases}:
                excluded_paths.append(relative_path)
                continue
            history_source = _historical_source(
                source_id="memory:history:%s:%s"
                % (
                    workstream.memory_workspace,
                    sha256_bytes(relative_path.encode("utf-8")),
                ),
                group="MEMORY_HISTORY",
                relative_path=relative_path,
                info=info,
                raw=raw,
                evidence_sha256=sha256_bytes(canonical_json_bytes(evidence)),
                recorded_at=recorded_at,
            )
            history_sources.append(history_source)
            if not hint_limit_reached:
                (
                    history_hints,
                    history_hint_tokens,
                    history_hints_truncated,
                ) = _memory_hints_from_text(
                    history_body,
                    source_id=history_source.source_id,
                    root=root,
                    project_home=workstream.project_home,
                    maximum_tokens=(
                        bounds.hint_token_count - hint_tokens_extracted
                    ),
                )
                hint_tokens_extracted += history_hint_tokens
                hints = _merge_memory_hints(hints, history_hints)
                if history_hints_truncated:
                    hint_limit_reached = True
                    gaps.append(
                        _memory_gap(
                            kind="TRUNCATED",
                            group="MEMORY_HISTORY",
                            reason_code="MEMORY_HINT_TOKEN_LIMIT",
                            relative_path=history_relative,
                        )
                    )
        if sorted(os.listdir(history_fd)) != all_entry_names:
            raise ContextAssemblyError(
                "memory history membership changed during capture",
                reason_code="CONTEXT_STALE",
            )
        if snapshot_binding is not None:
            _revalidate_memory_file(
                parent_fd=workspace_fd,
                entry_name="snapshot.md",
                lexical_path=snapshot_path,
                expected_identity=snapshot_binding[0],
                expected_content_sha256=snapshot_binding[1],
                maximum_bytes=bounds.snapshot_bytes,
            )
        for (
            entry_name,
            entry_path,
            expected_identity,
            expected_content_sha256,
        ) in history_bindings:
            _revalidate_memory_file(
                parent_fd=history_fd,
                entry_name=entry_name,
                lexical_path=entry_path,
                expected_identity=expected_identity,
                expected_content_sha256=expected_content_sha256,
                maximum_bytes=bounds.history_file_bytes,
            )
        safety.require_same_directory_identity(
            history_path,
            history_fd,
            "memory history",
            error_type=_MemoryUnsafeError,
        )
        safety.require_same_directory_identity(
            workspace_path,
            workspace_fd,
            "memory workspace",
            error_type=_MemoryUnsafeError,
        )
        return _configured_memory_capture(
            workspace_identity=_filesystem_identity(workspace_info),
            history_directory_identity=_filesystem_identity(history_info),
            snapshot=snapshot_source,
            history=tuple(history_sources),
            hints=hints,
            gaps=tuple(gaps),
            excluded_paths=tuple(excluded_paths),
            freshness_sha256=_memory_freshness_sha256(
                workspace_identity=_filesystem_identity(workspace_info),
                history_directory_identity=_filesystem_identity(history_info),
                snapshot_binding=snapshot_binding,
                history_bindings=tuple(history_bindings),
            ),
            counts=MemoryCaptureCounts(
                snapshot_bytes_read=len(snapshot_raw),
                snapshot_hint_count=snapshot_hint_count,
                history_inspected=len(entry_names),
                history_included=len(history_sources),
                history_excluded=len(excluded_paths),
                history_malformed=history_malformed,
                history_truncated=history_truncated,
                history_bytes_read=history_bytes,
                hint_tokens_extracted=hint_tokens_extracted,
            ),
        )
    finally:
        if history_fd is not None:
            os.close(history_fd)
        os.close(workspace_fd)


@dataclass(frozen=True)
class ContextCoverage:
    local_inspected: int
    local_excluded: int
    local_unreadable: int
    local_truncated: int
    source_group_counts: Tuple[Tuple[str, int], ...]
    memory_status: str
    memory_history_inspected: int
    memory_history_included: int
    memory_history_excluded: int
    memory_history_malformed: int
    memory_history_truncated: int
    external_verified: int
    external_unverified: int
    excluded_paths: Tuple[str, ...]
    gap_paths: Tuple[str, ...]
    redaction_counts: Tuple[Tuple[str, int], ...]
    memory_snapshot_bytes_read: int = 0
    memory_snapshot_hint_count: int = 0
    memory_history_bytes_read: int = 0
    memory_hint_tokens_extracted: int = 0
    memory_freshness_sha256: str = NOT_CONFIGURED_MEMORY_FRESHNESS_SHA256

    def __post_init__(self) -> None:
        for name in _COVERAGE_COUNT_FIELDS:
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ContextAssemblyError("context coverage count is invalid")
        if self.memory_status not in {"NOT_CONFIGURED", "CONFIGURED"}:
            raise ContextAssemblyError("context memory status is invalid")
        _require_hash(self.memory_freshness_sha256, "memory freshness hash")
        _require_count_pairs(self.source_group_counts, "source group counts")
        _require_count_pairs(self.redaction_counts, "coverage redaction counts")
        for label, paths in (
            ("excluded paths", self.excluded_paths),
            ("gap paths", self.gap_paths),
        ):
            if type(paths) is not tuple or len(paths) != len(set(paths)):
                raise ContextAssemblyError("context coverage %s are invalid" % label)
            for path in paths:
                _require_relative_path(path, "context coverage path")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "excluded_paths": sorted(self.excluded_paths),
            "external_unverified": self.external_unverified,
            "external_verified": self.external_verified,
            "gap_paths": sorted(self.gap_paths),
            "local_excluded": self.local_excluded,
            "local_inspected": self.local_inspected,
            "local_truncated": self.local_truncated,
            "local_unreadable": self.local_unreadable,
            "memory_history_excluded": self.memory_history_excluded,
            "memory_history_included": self.memory_history_included,
            "memory_history_inspected": self.memory_history_inspected,
            "memory_history_malformed": self.memory_history_malformed,
            "memory_history_truncated": self.memory_history_truncated,
            "memory_history_bytes_read": self.memory_history_bytes_read,
            "memory_freshness_sha256": self.memory_freshness_sha256,
            "memory_hint_tokens_extracted": self.memory_hint_tokens_extracted,
            "memory_snapshot_bytes_read": self.memory_snapshot_bytes_read,
            "memory_snapshot_hint_count": self.memory_snapshot_hint_count,
            "memory_status": self.memory_status,
            "redaction_counts": dict(self.redaction_counts),
            "source_group_counts": dict(self.source_group_counts),
        }


@dataclass(frozen=True)
class ContextAssembly:
    workstream: ContextWorkstream
    root_identity: Tuple[int, int, int, int]
    project_identity: Tuple[int, int, int, int]
    policy_sha256: str
    outcome: str
    bounds: ContextAssemblyBounds
    sources: Tuple[ContextSource, ...]
    claims: Tuple[ContextClaim, ...]
    gaps: Tuple[ContextGap, ...]
    coverage: ContextCoverage
    schema: str = CONTEXT_ASSEMBLY_SCHEMA
    spec_sha256: str = APPROVED_REQUIREMENTS_SHA256

    def __post_init__(self) -> None:
        if not isinstance(self.workstream, ContextWorkstream):
            raise ContextAssemblyError("Context Assembly Workstream is invalid")
        _require_identity(self.root_identity, "root identity", size=4)
        _require_identity(self.project_identity, "project identity", size=4)
        _require_hash(self.policy_sha256, "policy hash")
        if (
            self.outcome not in {COMPLETE, INCOMPLETE}
            or not isinstance(self.bounds, ContextAssemblyBounds)
            or type(self.sources) is not tuple
            or type(self.claims) is not tuple
            or type(self.gaps) is not tuple
            or not isinstance(self.coverage, ContextCoverage)
            or self.schema != CONTEXT_ASSEMBLY_SCHEMA
            or self.spec_sha256 != APPROVED_REQUIREMENTS_SHA256
        ):
            raise ContextAssemblyError("Context Assembly seal is invalid")
        if self.outcome == COMPLETE and self.gaps:
            raise ContextAssemblyError("complete Context Assembly has gaps")
        if self.outcome == INCOMPLETE and not self.gaps:
            raise ContextAssemblyError("incomplete Context Assembly has no gaps")
        source_ids = [source.source_id for source in self.sources]
        claim_ids = [claim.claim_id for claim in self.claims]
        gap_ids = [gap.gap_id for gap in self.gaps]
        if (
            len(source_ids) != len(set(source_ids))
            or len(claim_ids) != len(set(claim_ids))
            or len(gap_ids) != len(set(gap_ids))
        ):
            raise ContextAssemblyError("Context Assembly ids are not unique")
        self._validate_claim_bindings()
        self._validate_coverage_bindings()

    def _validate_claim_bindings(self) -> None:
        sources_by_id = {source.source_id: source for source in self.sources}
        for source in self.sources:
            if any(
                reference_id not in sources_by_id
                or sources_by_id[reference_id].mode != "UNVERIFIED_EXTERNAL"
                for reference_id in source.reference_source_ids
            ):
                raise ContextAssemblyError("context source reference binding is invalid")
        expected_support_mode = {
            "CURRENT_LOCAL": "CURRENT_LOCAL",
            "HISTORICAL_HINT": "HISTORICAL_HINT",
            "UNVERIFIED_EXTERNAL": "UNVERIFIED_EXTERNAL",
        }
        for claim in self.claims:
            referenced_source_ids = (
                *claim.supporting_source_ids,
                *claim.historical_source_ids,
            )
            if any(source_id not in sources_by_id for source_id in referenced_source_ids):
                raise ContextAssemblyError("context claim source binding is invalid")
            if self.outcome == COMPLETE and claim.mode in {"MISSING", "CONFLICT"}:
                raise ContextAssemblyError("complete Context Assembly has blocker claims")

            required_mode = expected_support_mode.get(claim.mode)
            if required_mode is not None and any(
                sources_by_id[source_id].mode != required_mode
                for source_id in claim.supporting_source_ids
            ):
                raise ContextAssemblyError("context claim authority is invalid")
            if any(
                sources_by_id[source_id].mode != "HISTORICAL_HINT"
                for source_id in claim.historical_source_ids
            ):
                raise ContextAssemblyError("context historical claim binding is invalid")

    def _validate_coverage_bindings(self) -> None:
        expected_group_counts = _count_source_groups(self.sources)
        if dict(self.coverage.source_group_counts) != expected_group_counts:
            raise ContextAssemblyError("context source coverage is inconsistent")

        expected_gap_paths = {
            gap.relative_path for gap in self.gaps if gap.relative_path is not None
        }
        if set(self.coverage.gap_paths) != expected_gap_paths:
            raise ContextAssemblyError("context gap coverage is inconsistent")

        expected_external_unverified = _count_sources_with_mode(
            self.sources, "UNVERIFIED_EXTERNAL"
        )
        expected_external_verified = _count_sources_with_mode(
            self.sources, "CURRENT_EXTERNAL"
        )
        if (
            self.coverage.external_unverified != expected_external_unverified
            or self.coverage.external_verified != expected_external_verified
        ):
            raise ContextAssemblyError("context external coverage is inconsistent")

        expected_history_included = _count_sources_in_group(
            self.sources, "MEMORY_HISTORY"
        )
        if self.coverage.memory_history_included != expected_history_included:
            raise ContextAssemblyError("context memory coverage is inconsistent")

        expected_memory_status = (
            "CONFIGURED"
            if self.workstream.memory_workspace is not None
            else "NOT_CONFIGURED"
        )
        if self.coverage.memory_status != expected_memory_status:
            raise ContextAssemblyError("context memory status is inconsistent")

    @property
    def coverage_sha256(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.coverage.canonical_value))

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "bounds": self.bounds.canonical_value,
            "claims": [
                claim.canonical_value
                for claim in sorted(self.claims, key=lambda value: value.claim_id)
            ],
            "coverage": self.coverage.canonical_value,
            "coverage_sha256": self.coverage_sha256,
            "gaps": [
                gap.canonical_value
                for gap in sorted(self.gaps, key=lambda value: value.gap_id)
            ],
            "outcome": self.outcome,
            "policy_sha256": self.policy_sha256,
            "project_identity": list(self.project_identity),
            "root_identity": list(self.root_identity),
            "schema": self.schema,
            "sources": [
                source.canonical_value
                for source in sorted(self.sources, key=lambda value: value.source_id)
            ],
            "spec_sha256": self.spec_sha256,
            "workstream": self.workstream.canonical_value,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_value)

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes)

    def require_complete(
        self,
        *,
        expected_workstream: ContextWorkstream,
        expected_policy_sha256: str,
        expected_root_identity: Tuple[int, int, int, int],
        expected_project_identity: Tuple[int, int, int, int],
        expected_assembly_sha256: str,
        expected_coverage_sha256: str,
    ) -> "CompleteContextAssembly":
        return CompleteContextAssembly(
            assembly=self,
            assembly_sha256=expected_assembly_sha256,
            coverage_sha256=expected_coverage_sha256,
            workstream=expected_workstream,
            policy_sha256=expected_policy_sha256,
            root_identity=expected_root_identity,
            project_identity=expected_project_identity,
        )


def _decode_object(
    value: object,
    label: str,
    expected_keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected_keys:
        raise ContextAssemblyError("%s has an invalid field set" % label)
    if any(type(key) is not str for key in value):
        raise ContextAssemblyError("%s has an invalid field set" % label)
    return value


def _decode_list(value: object, label: str) -> list[object]:
    if type(value) is not list:
        raise ContextAssemblyError("%s is invalid" % label)
    return value


def _decode_identity_list(
    value: object,
    label: str,
    *,
    size: int,
) -> Tuple[int, ...]:
    values = _decode_list(value, label)
    decoded = tuple(values)
    return _require_identity(decoded, label, size=size)


def _decode_text_list(value: object, label: str) -> Tuple[str, ...]:
    values = _decode_list(value, label)
    if any(type(item) is not str for item in values):
        raise ContextAssemblyError("%s is invalid" % label)
    return tuple(values)


def _decode_count_map(value: object, label: str) -> Tuple[Tuple[str, int], ...]:
    if type(value) is not dict or any(
        type(key) is not str or type(count) is not int or count < 0
        for key, count in value.items()
    ):
        raise ContextAssemblyError("%s is invalid" % label)
    return tuple(sorted(value.items()))


def _decode_bounds(value: object) -> ContextAssemblyBounds:
    expected_keys = frozenset(ContextAssemblyBounds.__dataclass_fields__)
    payload = _decode_object(value, "Context Assembly bounds", expected_keys)
    if any(type(item) is not int for item in payload.values()):
        raise ContextAssemblyError("Context Assembly bounds are invalid")
    return ContextAssemblyBounds(**payload)


def _decode_workstream(value: object) -> ContextWorkstream:
    payload = _decode_object(
        value,
        "Context Assembly Workstream",
        frozenset({"aliases", "id", "lifecycle", "memory_workspace", "project_home"}),
    )
    memory_workspace = payload["memory_workspace"]
    if memory_workspace is not None and type(memory_workspace) is not str:
        raise ContextAssemblyError("Workstream memory workspace is invalid")
    return ContextWorkstream(
        id=_require_text(payload["id"], "Workstream id", maximum=128),
        lifecycle=_require_text(payload["lifecycle"], "Workstream lifecycle"),
        project_home=_require_relative_path(
            payload["project_home"], "Workstream project home"
        ),
        aliases=_decode_text_list(payload["aliases"], "Workstream aliases"),
        memory_workspace=memory_workspace,
    )


def _decode_content_projection(value: object) -> ContextContentProjection:
    payload = _decode_object(
        value,
        "content projection",
        frozenset(
            {
                "encoding",
                "excerpt",
                "excerpt_truncated",
                "full_content_byte_count",
                "full_content_sha256",
                "headings",
                "headings_truncated",
                "redaction_counts",
                "title",
            }
        ),
    )
    if (
        type(payload["headings_truncated"]) is not bool
        or type(payload["excerpt_truncated"]) is not bool
        or type(payload["full_content_byte_count"]) is not int
    ):
        raise ContextAssemblyError("content projection is invalid")
    return ContextContentProjection(
        title=_require_text(payload["title"], "content projection title"),
        headings=_decode_text_list(payload["headings"], "content projection headings"),
        headings_truncated=payload["headings_truncated"],
        excerpt=(
            payload["excerpt"]
            if type(payload["excerpt"]) is str
            else _raise_context_invalid("content projection excerpt")
        ),
        excerpt_truncated=payload["excerpt_truncated"],
        redaction_counts=_decode_count_map(
            payload["redaction_counts"], "content redaction counts"
        ),
        full_content_sha256=_require_hash(
            payload["full_content_sha256"], "full content hash"
        ),
        full_content_byte_count=payload["full_content_byte_count"],
        encoding=(
            payload["encoding"]
            if type(payload["encoding"]) is str
            else _raise_context_invalid("content projection encoding")
        ),
    )


def _raise_context_invalid(label: str) -> None:
    raise ContextAssemblyError("%s is invalid" % label)


def _decode_source(value: object) -> ContextSource:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ContextAssemblyError("context source has an invalid field set")
    mode = value.get("mode")
    if type(mode) is not str:
        raise ContextAssemblyError("context source mode is invalid")
    base_keys = {"group", "mode", "source_id"}
    if mode == "CURRENT_LOCAL":
        expected_keys = {
            *base_keys,
            "relative_path",
            "observation_id",
            "identity",
            "content_sha256",
            "snapshot_sha256",
            "content_projection",
        }
        optional_keys = {"reference_source_ids", "references_truncated"}
    elif mode == "HISTORICAL_HINT":
        expected_keys = {
            *base_keys,
            "relative_path",
            "identity",
            "content_sha256",
            "evidence_sha256",
            "recorded_at",
        }
        optional_keys = set()
    elif mode == "UNVERIFIED_EXTERNAL":
        expected_keys = {*base_keys, "reference_family", "reference_sha256"}
        optional_keys = set()
    else:
        raise ContextAssemblyError("context source mode is invalid")
    actual_keys = set(value)
    if not expected_keys <= actual_keys or actual_keys - expected_keys - optional_keys:
        raise ContextAssemblyError("context source has an invalid field set")
    group = _require_text(value["group"], "context source group")
    source_id = _require_text(value["source_id"], "context source id", maximum=256)
    if mode == "CURRENT_LOCAL":
        reference_source_ids = ()
        if "reference_source_ids" in value:
            reference_source_ids = _decode_text_list(
                value["reference_source_ids"], "current local reference ids"
            )
            if not reference_source_ids:
                raise ContextAssemblyError("current local reference ids are invalid")
        references_truncated = value.get("references_truncated", False)
        if type(references_truncated) is not bool or not references_truncated and (
            "references_truncated" in value
        ):
            raise ContextAssemblyError("current local reference binding is invalid")
        return ContextSource(
            source_id=source_id,
            group=group,
            mode=mode,
            relative_path=_require_relative_path(
                value["relative_path"], "current local source path"
            ),
            observation_id=_require_text(
                value["observation_id"], "current local observation id"
            ),
            identity=_decode_identity_list(
                value["identity"], "current local identity", size=7
            ),
            content_sha256=_require_hash(
                value["content_sha256"], "current local content hash"
            ),
            snapshot_sha256=_require_hash(
                value["snapshot_sha256"], "current local snapshot hash"
            ),
            content_projection=_decode_content_projection(value["content_projection"]),
            reference_source_ids=reference_source_ids,
            references_truncated=references_truncated,
        )
    if mode == "HISTORICAL_HINT":
        return ContextSource(
            source_id=source_id,
            group=group,
            mode=mode,
            relative_path=_require_relative_path(
                value["relative_path"], "historical source path"
            ),
            identity=_decode_identity_list(
                value["identity"], "historical source identity", size=7
            ),
            content_sha256=_require_hash(
                value["content_sha256"], "historical content hash"
            ),
            evidence_sha256=_require_hash(
                value["evidence_sha256"], "historical evidence hash"
            ),
            recorded_at=_require_text(value["recorded_at"], "historical recorded at"),
        )
    return ContextSource(
        source_id=source_id,
        group=group,
        mode=mode,
        reference_family=_require_text(
            value["reference_family"], "external reference family"
        ),
        reference_sha256=_require_hash(
            value["reference_sha256"], "external reference hash"
        ),
    )


def _decode_claim(value: object) -> ContextClaim:
    payload = _decode_object(
        value,
        "context claim",
        frozenset(
            {
                "claim_id",
                "historical_source_ids",
                "mode",
                "subject",
                "supporting_source_ids",
            }
        ),
    )
    return ContextClaim(
        claim_id=_require_text(payload["claim_id"], "context claim id", maximum=256),
        mode=_require_text(payload["mode"], "context claim mode"),
        subject=_require_text(payload["subject"], "context claim subject"),
        supporting_source_ids=_decode_text_list(
            payload["supporting_source_ids"], "context claim supporting source ids"
        ),
        historical_source_ids=_decode_text_list(
            payload["historical_source_ids"], "context claim historical source ids"
        ),
    )


def _decode_gap(value: object) -> ContextGap:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ContextAssemblyError("context gap has an invalid field set")
    expected_keys = {"gap_id", "group", "kind", "reason_code"}
    if "relative_path" in value:
        expected_keys.add("relative_path")
    if set(value) != expected_keys:
        raise ContextAssemblyError("context gap has an invalid field set")
    return ContextGap(
        gap_id=_require_text(value["gap_id"], "context gap id", maximum=256),
        kind=_require_text(value["kind"], "context gap kind"),
        group=_require_text(value["group"], "context gap group"),
        reason_code=_require_text(value["reason_code"], "context gap reason", maximum=128),
        relative_path=(
            _require_relative_path(value["relative_path"], "context gap path")
            if "relative_path" in value
            else None
        ),
    )


def _decode_coverage(value: object) -> ContextCoverage:
    expected_keys = frozenset(
        {
            *_COVERAGE_COUNT_FIELDS,
            "memory_status",
            "memory_freshness_sha256",
            "source_group_counts",
            "excluded_paths",
            "gap_paths",
            "redaction_counts",
        }
    )
    payload = _decode_object(value, "context coverage", expected_keys)
    if any(type(payload[name]) is not int for name in _COVERAGE_COUNT_FIELDS):
        raise ContextAssemblyError("context coverage count is invalid")
    return ContextCoverage(
        local_inspected=payload["local_inspected"],
        local_excluded=payload["local_excluded"],
        local_unreadable=payload["local_unreadable"],
        local_truncated=payload["local_truncated"],
        source_group_counts=_decode_count_map(
            payload["source_group_counts"], "source group counts"
        ),
        memory_status=_require_text(payload["memory_status"], "context memory status"),
        memory_history_inspected=payload["memory_history_inspected"],
        memory_history_included=payload["memory_history_included"],
        memory_history_excluded=payload["memory_history_excluded"],
        memory_history_malformed=payload["memory_history_malformed"],
        memory_history_truncated=payload["memory_history_truncated"],
        external_verified=payload["external_verified"],
        external_unverified=payload["external_unverified"],
        excluded_paths=_decode_text_list(
            payload["excluded_paths"], "context coverage excluded paths"
        ),
        gap_paths=_decode_text_list(payload["gap_paths"], "context coverage gap paths"),
        redaction_counts=_decode_count_map(
            payload["redaction_counts"], "coverage redaction counts"
        ),
        memory_snapshot_bytes_read=payload["memory_snapshot_bytes_read"],
        memory_snapshot_hint_count=payload["memory_snapshot_hint_count"],
        memory_history_bytes_read=payload["memory_history_bytes_read"],
        memory_freshness_sha256=_require_hash(
            payload["memory_freshness_sha256"],
            "memory freshness hash",
        ),
        memory_hint_tokens_extracted=payload["memory_hint_tokens_extracted"],
    )


def decode_context_assembly(value: object) -> ContextAssembly:
    """Decode one sealed canonical Context Assembly; reject all envelopes."""
    payload = _decode_object(
        value,
        "Context Assembly",
        frozenset(
            {
                "bounds",
                "claims",
                "coverage",
                "coverage_sha256",
                "gaps",
                "outcome",
                "policy_sha256",
                "project_identity",
                "root_identity",
                "schema",
                "sources",
                "spec_sha256",
                "workstream",
            }
        ),
    )
    if payload["schema"] != CONTEXT_ASSEMBLY_SCHEMA:
        raise ContextAssemblyError("Context Assembly schema is invalid")
    if payload["spec_sha256"] != APPROVED_REQUIREMENTS_SHA256:
        raise ContextAssemblyError("Context Assembly specification is invalid")
    assembly = ContextAssembly(
        workstream=_decode_workstream(payload["workstream"]),
        root_identity=_decode_identity_list(
            payload["root_identity"], "root identity", size=4
        ),
        project_identity=_decode_identity_list(
            payload["project_identity"], "project identity", size=4
        ),
        policy_sha256=_require_hash(payload["policy_sha256"], "policy hash"),
        outcome=_require_text(payload["outcome"], "Context Assembly outcome"),
        bounds=_decode_bounds(payload["bounds"]),
        sources=tuple(
            _decode_source(source)
            for source in _decode_list(payload["sources"], "Context Assembly sources")
        ),
        claims=tuple(
            _decode_claim(claim)
            for claim in _decode_list(payload["claims"], "Context Assembly claims")
        ),
        gaps=tuple(
            _decode_gap(gap)
            for gap in _decode_list(payload["gaps"], "Context Assembly gaps")
        ),
        coverage=_decode_coverage(payload["coverage"]),
        schema=payload["schema"],
        spec_sha256=payload["spec_sha256"],
    )
    coverage_sha256 = _require_hash(
        payload["coverage_sha256"], "Context Assembly coverage hash"
    )
    if assembly.coverage_sha256 != coverage_sha256:
        raise ContextAssemblyError("Context Assembly coverage hash is inconsistent")
    if assembly.canonical_value != value:
        raise ContextAssemblyError("Context Assembly canonical value is invalid")
    return assembly


@dataclass(frozen=True)
class CompleteContextAssembly:
    assembly: ContextAssembly
    assembly_sha256: str
    coverage_sha256: str
    workstream: ContextWorkstream
    policy_sha256: str
    root_identity: Tuple[int, int, int, int]
    project_identity: Tuple[int, int, int, int]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.assembly, ContextAssembly)
            or self.assembly.outcome != COMPLETE
            or self.assembly.gaps
        ):
            raise ContextAssemblyError(
                "complete Context Assembly capability is unavailable",
                reason_code="CONTEXT_INCOMPLETE",
            )
        _require_hash(self.assembly_sha256, "complete Context Assembly hash")
        _require_hash(self.coverage_sha256, "complete Context coverage hash")
        _require_hash(self.policy_sha256, "complete Context policy hash")
        _require_identity(self.root_identity, "complete root identity", size=4)
        _require_identity(self.project_identity, "complete project identity", size=4)
        if (
            not isinstance(self.workstream, ContextWorkstream)
            or self.assembly.sha256 != self.assembly_sha256
            or self.assembly.coverage_sha256 != self.coverage_sha256
            or self.assembly.workstream != self.workstream
            or self.assembly.policy_sha256 != self.policy_sha256
            or self.assembly.root_identity != self.root_identity
            or self.assembly.project_identity != self.project_identity
        ):
            raise ContextAssemblyError(
                "complete Context Assembly authority is inconsistent",
                reason_code="CONTEXT_STALE",
            )


def _semantic_identifier(prefix: str, value: str) -> str:
    return "%s:%s" % (prefix, sha256_bytes(value.encode("utf-8")))


def _redaction_coverage(
    sources: Tuple[ContextSource, ...],
) -> Tuple[Tuple[str, int], ...]:
    counts: dict[str, int] = {}
    for source in sources:
        projection = source.content_projection
        if projection is None:
            continue
        for name, count in projection.redaction_counts:
            counts[name] = counts.get(name, 0) + count
    return tuple(sorted(counts.items()))


def _build_context_coverage(
    *,
    local_observation_count: int,
    local_excluded_count: int,
    sources: Tuple[ContextSource, ...],
    gaps: Tuple[ContextGap, ...],
    excluded_paths: Tuple[str, ...],
    memory: MemoryContextCapture,
) -> ContextCoverage:
    return ContextCoverage(
        local_inspected=local_observation_count,
        local_excluded=local_excluded_count,
        local_unreadable=sum(
            gap.kind == "UNREADABLE" and gap.group in _LOCAL_GROUPS
            for gap in gaps
        ),
        local_truncated=sum(
            gap.kind == "TRUNCATED" and gap.group in _LOCAL_GROUPS
            for gap in gaps
        ),
        source_group_counts=tuple(sorted(_count_source_groups(sources).items())),
        memory_status=memory.status,
        memory_history_inspected=memory.counts.history_inspected,
        memory_history_included=memory.counts.history_included,
        memory_history_excluded=memory.counts.history_excluded,
        memory_history_malformed=memory.counts.history_malformed,
        memory_history_truncated=memory.counts.history_truncated,
        external_verified=_count_sources_with_mode(sources, "CURRENT_EXTERNAL"),
        external_unverified=_count_sources_with_mode(
            sources, "UNVERIFIED_EXTERNAL"
        ),
        excluded_paths=excluded_paths,
        gap_paths=tuple(
            sorted(
                {
                    gap.relative_path
                    for gap in gaps
                    if gap.relative_path is not None
                }
            )
        ),
        redaction_counts=_redaction_coverage(sources),
        memory_snapshot_bytes_read=memory.counts.snapshot_bytes_read,
        memory_snapshot_hint_count=memory.counts.snapshot_hint_count,
        memory_history_bytes_read=memory.counts.history_bytes_read,
        memory_freshness_sha256=memory.freshness_sha256,
        memory_hint_tokens_extracted=memory.counts.hint_tokens_extracted,
    )


def build_context_assembly(
    *,
    root: Path,
    compiled_workstream: object,
    policy_sha256: str,
    root_identity: Tuple[int, int, int, int],
    project_identity: Tuple[int, int, int, int],
    local_observations: Tuple[ContextLocalObservation, ...],
    local_gaps: Tuple[ContextGap, ...],
    excluded_paths: Tuple[str, ...],
    bounds: ContextAssemblyBounds,
) -> ContextAssembly:
    """Build one sealed semantic assembly from existing observations and hints."""
    if (
        not isinstance(compiled_workstream, policy.CompiledWorkstream)
        or compiled_workstream.lifecycle != "active"
        or type(local_observations) is not tuple
        or any(
            not isinstance(item, ContextLocalObservation)
            for item in local_observations
        )
        or type(local_gaps) is not tuple
        or any(not isinstance(gap, ContextGap) for gap in local_gaps)
        or type(excluded_paths) is not tuple
        or not isinstance(bounds, ContextAssemblyBounds)
    ):
        raise ContextAssemblyError("Context Assembly builder input is invalid")
    _require_hash(policy_sha256, "Context Assembly policy hash")
    _require_identity(root_identity, "Context Assembly root identity", size=4)
    _require_identity(project_identity, "Context Assembly project identity", size=4)
    for path in excluded_paths:
        _require_relative_path(path, "Context Assembly excluded path")

    workstream = ContextWorkstream(
        id=compiled_workstream.id,
        lifecycle=compiled_workstream.lifecycle,
        project_home=compiled_workstream.project_home,
        aliases=compiled_workstream.aliases,
        memory_workspace=compiled_workstream.memory_workspace,
    )
    project_path = safety.require_no_symlink_components(
        workstream.project_home,
        root,
        "Context Assembly project home",
        error_type=ContextAssemblyError,
    )
    if (
        _filesystem_identity(root.stat()) != root_identity
        or _filesystem_identity(project_path.stat()) != project_identity
    ):
        raise ContextAssemblyError(
            "Context Assembly authority changed before build",
            reason_code="CONTEXT_STALE",
        )

    memory = read_memory_context(root, workstream, bounds=bounds)
    builder_gaps = []
    local_source_values = []
    local_source_observations = []
    local_bytes_read = 0
    ordered_local_observations = sorted(
        local_observations,
        key=lambda item: (
            getattr(item.observation, "relative_path", ""),
            getattr(item.observation, "observation_id", ""),
        ),
    )
    for item in ordered_local_observations:
        relative_path = _observation_value(item.observation, "relative_path", str)
        source_size = _observation_value(item.observation, "size", int)
        if source_size > bounds.local_source_bytes:
            builder_gaps.append(
                ContextGap(
                    gap_id=_semantic_identifier(
                        "gap-local-source-limit", relative_path
                    ),
                    kind="TRUNCATED",
                    group=item.group,
                    reason_code="LOCAL_SOURCE_LIMIT",
                    relative_path=relative_path,
                )
            )
            continue
        if local_bytes_read + source_size > bounds.local_total_bytes:
            builder_gaps.append(
                ContextGap(
                    gap_id=_semantic_identifier("gap-local-total-limit", relative_path),
                    kind="TRUNCATED",
                    group=item.group,
                    reason_code="LOCAL_TOTAL_LIMIT",
                    relative_path=relative_path,
                )
            )
            continue
        try:
            local_source = read_current_local_source(
                root,
                item.observation,
                group=item.group,
                bounds=bounds,
            )
        except ContextAssemblyError as exc:
            if exc.reason_code != "LOCAL_SOURCE_INVALID_UTF8":
                raise
            builder_gaps.append(
                ContextGap(
                    gap_id=_semantic_identifier(
                        "gap-local-invalid-utf8", relative_path
                    ),
                    kind="UNREADABLE",
                    group=item.group,
                    reason_code=exc.reason_code,
                    relative_path=relative_path,
                )
            )
            local_bytes_read += source_size
            continue
        local_source_values.append(local_source)
        local_source_observations.append(item)
        local_bytes_read += source_size

    representable_source_count = min(
        len(local_source_values),
        bounds.local_projection_total_bytes,
    )
    projection_bounded_sources = []
    remaining_excerpt_bytes = bounds.local_excerpt_total_bytes
    remaining_heading_count = bounds.local_heading_total_count
    remaining_projection_bytes = bounds.local_projection_total_bytes
    for index, source in enumerate(local_source_values):
        if index >= representable_source_count:
            builder_gaps.append(
                ContextGap(
                    gap_id=_semantic_identifier(
                        "gap-local-projection-total", source.source_id
                    ),
                    kind="TRUNCATED",
                    group=source.group,
                    reason_code="LOCAL_PROJECTION_TOTAL_LIMIT",
                    relative_path=source.relative_path,
                )
            )
            continue
        sources_after_this = representable_source_count - index - 1
        source_projection_budget = max(
            remaining_projection_bytes - sources_after_this,
            1,
        )
        source = _cap_local_projection(
            source,
            excerpt_bytes=remaining_excerpt_bytes,
            heading_count=remaining_heading_count,
            projection_bytes=source_projection_budget,
        )
        projection = source.content_projection
        if projection is None:
            raise ContextAssemblyError("current local projection is missing")
        projection_bytes = _projection_byte_count(projection)
        if projection_bytes > source_projection_budget:
            raise ContextAssemblyError("local projection bound was not enforced")
        projection_bounded_sources.append(source)
        remaining_excerpt_bytes -= len(projection.excerpt.encode("utf-8"))
        remaining_heading_count -= len(projection.headings)
        remaining_projection_bytes -= projection_bytes

    total_reference_truncated_source_ids = set()
    bounded_local_sources = []
    reference_count = 0
    for source in projection_bounded_sources:
        remaining_references = max(bounds.local_reference_total - reference_count, 0)
        kept_references = source.reference_source_ids[:remaining_references]
        if len(kept_references) != len(source.reference_source_ids):
            total_reference_truncated_source_ids.add(source.source_id)
            builder_gaps.append(
                ContextGap(
                    gap_id=_semantic_identifier(
                        "gap-local-reference-total", source.source_id
                    ),
                    kind="TRUNCATED",
                    group=source.group,
                    reason_code="LOCAL_REFERENCE_TOTAL_LIMIT",
                    relative_path=source.relative_path,
                )
            )
            source = replace(
                source,
                reference_source_ids=kept_references,
                references_truncated=True,
            )
        bounded_local_sources.append(source)
        reference_count += len(kept_references)
    local_sources = tuple(bounded_local_sources)
    memory_sources = tuple(
        source
        for source in (
            memory.snapshot,
            *memory.history,
        )
        if source is not None
    )
    external_sources: dict[str, ContextSource] = {}
    for local_source in local_sources:
        for source_id in local_source.reference_source_ids:
            match = _EXTERNAL_SOURCE_ID_RE.fullmatch(source_id)
            if match is None:
                raise ContextAssemblyError("local external reference is invalid")
            external_sources[source_id] = ContextSource(
                source_id=source_id,
                group="EXTERNAL_REFERENCE",
                mode="UNVERIFIED_EXTERNAL",
                reference_family=match.group(1),
                reference_sha256=match.group(2),
            )
    for hint in memory.hints:
        if hint.kind != "EXTERNAL_REFERENCE":
            continue
        source_id = "external:%s:%s" % (
            hint.reference_family,
            hint.reference_sha256,
        )
        external_sources[source_id] = ContextSource(
            source_id=source_id,
            group="EXTERNAL_REFERENCE",
            mode="UNVERIFIED_EXTERNAL",
            reference_family=hint.reference_family,
            reference_sha256=hint.reference_sha256,
        )
    sources = tuple(
        sorted(
            (*local_sources, *memory_sources, *external_sources.values()),
            key=lambda value: value.source_id,
        )
    )

    historical_by_local_path: dict[str, set[str]] = {}
    claims = []
    gaps = [*local_gaps, *memory.gaps, *builder_gaps]
    for source in local_sources:
        if (
            source.references_truncated
            and source.source_id not in total_reference_truncated_source_ids
        ):
            gaps.append(
                ContextGap(
                    gap_id=_semantic_identifier(
                        "gap-local-reference-limit", source.source_id
                    ),
                    kind="TRUNCATED",
                    group=source.group,
                    reason_code="LOCAL_REFERENCE_LIMIT",
                    relative_path=source.relative_path,
                )
            )
    local_paths = {source.relative_path for source in local_sources}
    excluded_local_paths = set(excluded_paths)
    for hint in memory.hints:
        claims.append(
            ContextClaim(
                claim_id=_semantic_identifier("claim-historical", hint.hint_id),
                mode="HISTORICAL_HINT",
                subject=_semantic_identifier("historical-hint", hint.hint_id),
                supporting_source_ids=hint.historical_source_ids,
            )
        )
        if hint.kind == "LOCAL_PATH":
            if hint.relative_path in local_paths:
                historical_by_local_path.setdefault(hint.relative_path, set()).update(
                    hint.historical_source_ids
                )
            elif (
                hint.relative_path in excluded_local_paths
                or not Path(hint.relative_path).suffix
            ):
                continue
            else:
                gaps.append(
                    _memory_gap(
                        kind="MISSING",
                        group="OTHER_NESTED",
                        reason_code="LOCAL_HINT_UNRESOLVED",
                        relative_path=hint.relative_path,
                    )
                )
                claims.append(
                    ContextClaim(
                        claim_id=_semantic_identifier("claim-missing", hint.hint_id),
                        mode="MISSING",
                        subject=_semantic_identifier("missing-local", hint.hint_id),
                        supporting_source_ids=hint.historical_source_ids,
                    )
                )
        else:
            external_source_id = "external:%s:%s" % (
                hint.reference_family,
                hint.reference_sha256,
            )
            claims.append(
                ContextClaim(
                    claim_id=_semantic_identifier("claim-external", hint.hint_id),
                    mode="UNVERIFIED_EXTERNAL",
                    subject=_semantic_identifier("unverified-external", hint.hint_id),
                    supporting_source_ids=(external_source_id,),
                    historical_source_ids=hint.historical_source_ids,
                )
            )
    for source in local_sources:
        claims.append(
            ContextClaim(
                claim_id=_semantic_identifier("claim-current", source.source_id),
                mode="CURRENT_LOCAL",
                subject=_semantic_identifier("current-local", source.relative_path),
                supporting_source_ids=(source.source_id,),
                historical_source_ids=tuple(
                    sorted(historical_by_local_path.get(source.relative_path, ()))
                ),
            )
        )
        for external_source_id in source.reference_source_ids:
            claims.append(
                ContextClaim(
                    claim_id=_semantic_identifier(
                        "claim-local-external",
                        source.source_id + "\0" + external_source_id,
                    ),
                    mode="UNVERIFIED_EXTERNAL",
                    subject=_semantic_identifier(
                        "unverified-local-external",
                        source.source_id + "\0" + external_source_id,
                    ),
                    supporting_source_ids=(external_source_id,),
                )
            )

    if (
        _filesystem_identity(root.stat()) != root_identity
        or _filesystem_identity(project_path.stat()) != project_identity
    ):
        raise ContextAssemblyError(
            "Context Assembly authority changed during build",
            reason_code="CONTEXT_STALE",
        )
    for item, expected_source in zip(
        local_source_observations,
        local_source_values,
    ):
        revalidated_source = read_current_local_source(
            root,
            item.observation,
            group=item.group,
            bounds=bounds,
        )
        if revalidated_source.canonical_value != expected_source.canonical_value:
            raise ContextAssemblyError(
                "current local source changed during build",
                reason_code="CONTEXT_STALE",
            )
    revalidated_memory = read_memory_context(root, workstream, bounds=bounds)
    if revalidated_memory.canonical_value != memory.canonical_value:
        raise ContextAssemblyError(
            "protected memory changed during build",
            reason_code="CONTEXT_STALE",
        )
    if (
        _filesystem_identity(root.stat()) != root_identity
        or _filesystem_identity(project_path.stat()) != project_identity
    ):
        raise ContextAssemblyError(
            "Context Assembly authority changed during revalidation",
            reason_code="CONTEXT_STALE",
        )

    gaps_tuple = tuple(sorted(gaps, key=lambda value: value.gap_id))
    combined_excluded_paths = tuple(
        sorted({*excluded_paths, *memory.excluded_paths})
    )
    coverage = _build_context_coverage(
        local_observation_count=len(local_observations),
        local_excluded_count=len(excluded_paths),
        sources=sources,
        gaps=gaps_tuple,
        excluded_paths=combined_excluded_paths,
        memory=memory,
    )
    return ContextAssembly(
        workstream=workstream,
        root_identity=root_identity,
        project_identity=project_identity,
        policy_sha256=policy_sha256,
        outcome=INCOMPLETE if gaps_tuple else COMPLETE,
        bounds=bounds,
        sources=sources,
        claims=tuple(sorted(claims, key=lambda value: value.claim_id)),
        gaps=gaps_tuple,
        coverage=coverage,
    )


@dataclass(frozen=True)
class ContextAssemblyEnvelope:
    request_id: str
    observed_at: str
    outcome: str
    assembly_id: Optional[str]
    diagnostic_reason_codes: Tuple[str, ...]
    candidate_count: int = 0

    def __post_init__(self) -> None:
        _require_text(self.request_id, "Context Assembly request id", maximum=256)
        _require_text(self.observed_at, "Context Assembly observed at", maximum=128)
        if (
            self.outcome not in {COMPLETE, INCOMPLETE, BLOCKED_UNSAFE, STALE}
            or type(self.candidate_count) is not int
            or self.candidate_count < 0
        ):
            raise ContextAssemblyError("Context Assembly envelope is invalid")
        _require_unique_text_tuple(
            self.diagnostic_reason_codes, "Context Assembly envelope is invalid"
        )
        if self.outcome in {COMPLETE, INCOMPLETE}:
            _require_hash(self.assembly_id, "Context Assembly id")
        elif self.assembly_id is not None:
            raise ContextAssemblyError(
                "unsafe or stale envelope must not carry an assembly id"
            )

    @property
    def public_value(self) -> dict[str, object]:
        return {
            "assembly_id": self.assembly_id,
            "candidate_count": self.candidate_count,
            "diagnostic_reason_codes": sorted(self.diagnostic_reason_codes),
            "observed_at": self.observed_at,
            "outcome": self.outcome,
            "request_id": self.request_id,
        }


def blocked_workstream_resolution(
    *,
    reason_code: str,
    request_id: str,
    observed_at: str,
    candidate_count: int,
) -> ContextAssemblyEnvelope:
    if reason_code not in {"WORKSTREAM_NOT_FOUND", "WORKSTREAM_AMBIGUOUS"}:
        raise ContextAssemblyError("Workstream resolution reason is invalid")
    return ContextAssemblyEnvelope(
        request_id=request_id,
        observed_at=observed_at,
        outcome=BLOCKED_UNSAFE,
        assembly_id=None,
        diagnostic_reason_codes=(reason_code,),
        candidate_count=candidate_count,
    )


def decide_outcome(
    *,
    unsafe_reason_codes: Tuple[str, ...],
    stale_reason_codes: Tuple[str, ...],
    gaps: Tuple[object, ...],
) -> str:
    """Apply the approved fail-closed Context Assembly outcome priority."""
    if unsafe_reason_codes:
        return BLOCKED_UNSAFE
    if stale_reason_codes:
        return STALE
    if gaps:
        return INCOMPLETE
    return COMPLETE
