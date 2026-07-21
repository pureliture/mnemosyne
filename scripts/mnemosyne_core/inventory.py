"""No-follow inventory and sealed run storage foundations.

This module deliberately has no SQLite or policy-compilation dependency.  It
consumes immutable policy/admission decisions, observes a corpus without
writing it, and writes only explicitly supplied inventory-run roots.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import heapq
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from . import safety as _safety_core


PACKAGE_VERSION = "inventory-foundation-v1"
RAW_PATH_ENCODING = "raw-b64-v1:"
ManualRecoveryRequired = _safety_core.ManualRecoveryRequired

_CONTENT_MODES = frozenset(("none", "bounded-text"))
_TRAVERSAL_MODES = frozenset(
    ("full", "metadata-only", "directory-count-only", "not-entered")
)
_MANDATORY_NEVER_TOUCH = (
    (b"worktrees",),
    (b"graphify-out",),
    (b".git",),
    (b".acli",),
    (b".tmp",),
    (b".agents",),
    (b".claude",),
    (b".codex",),
    (b".gemini",),
    (b".harnesskit",),
)
_MANDATORY_NEVER_TOUCH_NAMES = frozenset(
    prefix[0].lower() for prefix in _MANDATORY_NEVER_TOUCH
)
_ROOT_CONTROL_FILES = frozenset((b"AGENTS.md", b"CLAUDE.md", b"_projects.md"))
_ROOT_CONTROL_FILES_CASEFOLD = frozenset(name.lower() for name in _ROOT_CONTROL_FILES)
_LINK_TEXT_STATUSES = frozenset(
    (
        "safe-relative",
        "absolute",
        "out-of-root",
        "secret-like",
        "invalid",
        "oversize",
        "unavailable",
    )
)
_CONTENT_POLICY_OUTCOMES = frozenset(
    (
        "inspected",
        "metadata-only",
        "not-eligible",
        "budget-exhausted",
        "rejected-type",
        "rejected-size",
        "rejected-content",
        "structural-error",
    )
)
_CONTENT_POLICY_ERROR_CODES = frozenset(
    (
        "content-type-not-allowed",
        "content-too-large",
        "content-has-nul",
        "content-invalid-utf8",
        "content-run-byte-bound",
    )
)
_MAX_LINK_TEXT_BYTES = 4096
_LINK_SECRET_RE = re.compile(
    rb"(?:^|[/_.-])(?:api[-_]?key|auth|bearer|credential|password|passwd|private[-_]?key|secret|token)(?:$|[/_.-])",
    re.IGNORECASE,
)
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SEQUENCE_RE = re.compile(r"^[0-9]{8}\.json$")
_RESERVED_ARTIFACTS = frozenset(
    (
        "run.lock",
        "request.json",
        "run.json",
        "manifest.jsonl",
        "failure.json",
        "chunks",
        "checkpoints",
    )
)
_MAX_CONTROL_FILE_BYTES = 64 * 1024 * 1024
_LEGACY_REFERENCE_PROJECTION_VERSION = "internal-reference-v1"
_REFERENCE_PROJECTION_VERSION = "internal-reference-v2"
_MARKDOWN_INLINE_REFERENCE = re.compile(
    r"!?\[[^\]\n]*\]\(([^)\s]+)(?:\s+[^)]*)?\)"
)
_MARKDOWN_REFERENCE_DEFINITION = re.compile(
    r"^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*(?:<([^>\n]+)>|([^\s]+))",
    re.MULTILINE,
)
_MARKDOWN_AUTOLINK = re.compile(r"<([^<>\s]+)>")
_HTML_REFERENCE_ATTRIBUTE = re.compile(
    r"\b(?:href|src)\s*=\s*([\"'])(.*?)\1",
    re.IGNORECASE,
)
_SAFE_PATH_LITERAL = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"((?:\.\.?/|_registry/|projects/|docs/|memory/|mirrors/|inbox/)"
    r"[A-Za-z0-9._~%+/@-]+(?:/[A-Za-z0-9._~%+@-]+)*"
    r"\.(?:md|markdown|html?|txt|json|ya?ml|toml|py|js|jsx|ts|tsx|java|kt|sh))"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_REFERENCE_KINDS = frozenset(
    (
        "autolink",
        "html-attribute",
        "markdown-inline",
        "markdown-reference",
        "registry-path",
        "safe-path-literal",
    )
)
_LEGACY_REFERENCE_PARSER_TYPES = (
    "html-attribute",
    "markdown-autolink",
    "markdown-inline",
    "markdown-reference",
)
_REFERENCE_PARSER_TYPES = (
    "generated-navigation-source",
    "html-attribute",
    "markdown-autolink",
    "markdown-inline",
    "markdown-reference",
    "registry-path",
    "safe-path-literal",
)
_CLASSIFICATION_PROJECTION_VERSION = "safe-classification-v1"
_CLASSIFICATION_FRONTMATTER_AXES = frozenset(
    ("authority", "lifecycle", "role", "workstream")
)
_SAFE_CLASSIFICATION_VALUE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
)
_MARKDOWN_HEADING = re.compile(r"^[ \t]{0,3}#{1,6}[ \t]+(.+?)\s*#*\s*$", re.MULTILINE)
_REFERENCE_RESTRICTED_SCOPES = frozenset(
    (
        "private-reviewable",
        "opaque-private-evidence",
        "evidence",
        "memory",
        "mirror",
        "protected",
        "never-touch",
        "control",
    )
)


class InventoryError(RuntimeError):
    """Base class for inventory foundation failures."""


class ScopeInputError(InventoryError):
    """A compiled scope decision attempted to mint broader authority."""


class InventorySafetyError(InventoryError):
    """A mandatory filesystem safety check failed."""


class ContentReadError(InventoryError):
    """A bounded content projection was rejected."""

    def __init__(self, code: str, bytes_read: int = 0):
        super().__init__(code)
        self.code = code
        self.bytes_read = bytes_read


class RunStateError(InventoryError):
    """The requested run transition is not valid."""


class RunBusyError(RunStateError):
    """Another process owns the run lifetime lock."""


class RunCollisionError(RunStateError):
    """A no-replace run destination is already occupied."""


class RunRequestMismatchError(RunStateError):
    """Resume input does not match the sealed request bytes."""


class RunIntegrityError(RunStateError):
    """A staging or terminal package failed readback verification."""


class RunProvenanceError(RunIntegrityError):
    """Resumability evidence is noncanonical, discontinuous, or hash-invalid."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            _json_compatible(value),
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _json_compatible(value: Any) -> Any:
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            result[key] = _json_compatible(item)
        return result
    if isinstance(value, (tuple, list)):
        return [_json_compatible(item) for item in value]
    return value


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (tuple, list)):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_deep_freeze(item) for item in value)
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _encode_component(component: bytes) -> str:
    if not isinstance(component, bytes) or not component:
        raise ValueError("raw path components must be non-empty bytes")
    if b"/" in component or b"\x00" in component or component in (b".", b".."):
        raise ValueError("unsafe raw path component")
    return base64.urlsafe_b64encode(component).rstrip(b"=").decode("ascii")


def _decode_component(encoded: str) -> bytes:
    if not encoded or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise ValueError("invalid canonical raw path component")
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    try:
        value = base64.b64decode(
            (encoded + padding).encode("ascii"), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid canonical raw path component") from exc
    if _encode_component(value) != encoded:
        raise ValueError("non-canonical raw path component")
    return value


def canonical_raw_path(components: Sequence[bytes]) -> str:
    """Encode raw filename bytes without relying on locale decoding."""
    return RAW_PATH_ENCODING + "/".join(_encode_component(part) for part in components)


def decode_canonical_raw_path(value: str) -> Tuple[bytes, ...]:
    if not isinstance(value, str) or not value.startswith(RAW_PATH_ENCODING):
        raise ValueError("unsupported canonical raw path encoding")
    suffix = value[len(RAW_PATH_ENCODING) :]
    if not suffix:
        return ()
    return tuple(_decode_component(part) for part in suffix.split("/"))


def _display_component(component: bytes) -> str:
    try:
        text = component.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "".join(
            chr(value) if 0x20 <= value <= 0x7E and value not in (0x2F, 0x5C)
            else "\\x%02x" % value
            for value in component
        )
    result = []
    for character in text:
        codepoint = ord(character)
        if (
            character in ("/", "\\")
            or not character.isprintable()
            or unicodedata.category(character).startswith("C")
        ):
            if codepoint <= 0xFFFF:
                result.append("\\u%04x" % codepoint)
            else:
                result.append("\\U%08x" % codepoint)
        else:
            result.append(character)
    return "".join(result)


def display_raw_path(components: Sequence[bytes]) -> str:
    return "/".join(_display_component(part) for part in components) or "."


def _validate_components(components: Sequence[bytes]) -> Tuple[bytes, ...]:
    result = tuple(components)
    for component in result:
        _encode_component(component)
    return result


def _has_prefix(path: Tuple[bytes, ...], prefix: Tuple[bytes, ...]) -> bool:
    return len(path) >= len(prefix) and path[: len(prefix)] == prefix


def _casefold_components(components: Sequence[bytes]) -> Tuple[bytes, ...]:
    return tuple(component.lower() for component in components)


_CANONICAL_SCOPE_DECISIONS = frozenset(
    (
        (
            "active-workstream-content",
            "eligible",
            "full",
            "active",
            "bounded-text",
            None,
        ),
        (
            "paused-completed",
            "coverage-only",
            "directory-count-only",
            "paused",
            "none",
            None,
        ),
        (
            "paused-completed",
            "coverage-only",
            "directory-count-only",
            "completed",
            "none",
            None,
        ),
        (
            "opaque-evidence",
            "opaque-private-evidence",
            "metadata-only",
            "any",
            "none",
            None,
        ),
        (
            "opaque-evidence",
            "mirror",
            "metadata-only",
            "any",
            "none",
            None,
        ),
        (
            "opaque-evidence",
            "memory",
            "metadata-only",
            "any",
            "none",
            None,
        ),
        (
            "private-reviewable",
            "private-reviewable",
            "metadata-only",
            "any",
            "none",
            None,
        ),
        (
            "private-reviewable",
            "private-reviewable",
            "metadata-only",
            "active",
            "none",
            None,
        ),
        (
            "fallback-unassigned",
            "unassigned-intake",
            "metadata-only",
            "unassigned",
            "none",
            None,
        ),
        (
            "control",
            "control",
            "not-entered",
            "protected",
            "none",
            "control",
        ),
        (
            "never-touch",
            "never-touch",
            "not-entered",
            "protected",
            "none",
            "never-touch",
        ),
    )
)


def _physical_scope_decision(
    components: Tuple[bytes, ...]
) -> Optional["ScopeDecision"]:
    folded = _casefold_components(components)
    if len(folded) >= 2 and folded[:2] == (b"memory", b"workspaces.yml"):
        return ScopeDecision(
            "control", "control", "not-entered", "protected", "none", "control"
        )
    if len(folded) >= 2 and folded[:2] == (b"_index", b"memory"):
        return ScopeDecision(
            "paused-completed",
            "coverage-only",
            "directory-count-only",
            "completed",
            "none",
        )
    if folded and folded[0] == b"memory":
        return ScopeDecision(
            "opaque-evidence", "memory", "metadata-only", "any", "none"
        )
    if folded and folded[0] == b"mirrors":
        return ScopeDecision(
            "opaque-evidence", "mirror", "metadata-only", "any", "none"
        )
    if folded and folded[0] == b"private":
        return ScopeDecision(
            "private-reviewable",
            "private-reviewable",
            "metadata-only",
            "any",
            "none",
        )
    if folded and folded[0].endswith(b"-cleanup-audit"):
        return ScopeDecision(
            "opaque-evidence",
            "opaque-private-evidence",
            "metadata-only",
            "any",
            "none",
        )
    return None


def _scope_restriction_rank(decision: "ScopeDecision") -> int:
    if decision.scope_class in ("never-touch", "control"):
        return 100
    if decision.scope_class in ("opaque-private-evidence", "memory", "mirror"):
        return 90
    if decision.scope_class == "coverage-only":
        return 80
    if decision.scope_class == "private-reviewable":
        return 70
    if decision.scope_class == "unassigned-intake":
        return 60
    if decision.scope_class == "eligible":
        return 10
    raise ScopeInputError("scope decision has no restriction rank")


@dataclass(frozen=True)
class ScopeDecision:
    """Immutable, already-compiled restriction input.

    This type intentionally cannot represent lifecycle or private expansion.
    Such authority belongs to the admission layer and a later derived-run
    protocol, not to the inventory traversal input.
    """

    rule_id: str
    scope_class: str
    traversal: str
    lifecycle: str
    content_inspection: str = "none"
    excluded_reason: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise ScopeInputError("scope rule id is required")
        for label, value in (
            ("scope class", self.scope_class),
            ("traversal", self.traversal),
            ("lifecycle", self.lifecycle),
            ("content inspection", self.content_inspection),
        ):
            if not isinstance(value, str) or not value:
                raise ScopeInputError("%s is required" % label)
        if self.excluded_reason is not None and not isinstance(
            self.excluded_reason, str
        ):
            raise ScopeInputError("excluded reason must be text")
        if self.traversal not in _TRAVERSAL_MODES:
            raise ScopeInputError("unknown traversal mode")
        if self.content_inspection not in _CONTENT_MODES:
            raise ScopeInputError("unknown content inspection mode")
        if self.traversal == "not-entered" and not self.excluded_reason:
            raise ScopeInputError("not-entered scope requires an exclusion reason")
        canonical_tuple = (
            self.rule_id,
            self.scope_class,
            self.traversal,
            self.lifecycle,
            self.content_inspection,
            self.excluded_reason,
        )
        if canonical_tuple not in _CANONICAL_SCOPE_DECISIONS:
            raise ScopeInputError("scope decision tuple is not canonical")


@dataclass(frozen=True)
class ScopeMap:
    default: ScopeDecision
    bindings: Tuple[Tuple[Tuple[bytes, ...], ScopeDecision], ...]
    never_touch: Tuple[Tuple[bytes, ...], ...]

    def __post_init__(self) -> None:
        if type(self.default) is not ScopeDecision:
            raise ScopeInputError("scope default must be a canonical ScopeDecision")
        if type(self.bindings) is not tuple:
            raise ScopeInputError("scope bindings must be an immutable tuple")
        seen = set()
        normalized_bindings = []
        for binding in self.bindings:
            if type(binding) is not tuple or len(binding) != 2:
                raise ScopeInputError("scope binding must be an immutable pair")
            prefix, decision = binding
            if type(prefix) is not tuple or not prefix:
                raise ScopeInputError("scope binding prefix must be a non-empty tuple")
            try:
                normalized = _validate_components(prefix)
            except (TypeError, ValueError) as exc:
                raise ScopeInputError("scope binding prefix is invalid") from exc
            if normalized != prefix or normalized in seen:
                raise ScopeInputError("scope binding prefix is duplicate or noncanonical")
            if type(decision) is not ScopeDecision:
                raise ScopeInputError("scope binding decision must be canonical")
            seen.add(normalized)
            normalized_bindings.append((normalized, decision))
        expected_bindings = sorted(
            normalized_bindings,
            key=lambda pair: (-len(pair[0]), canonical_raw_path(pair[0])),
        )
        if list(self.bindings) != expected_bindings:
            raise ScopeInputError("scope bindings are not in canonical order")

        if type(self.never_touch) is not tuple:
            raise ScopeInputError("never-touch rules must be an immutable tuple")
        normalized_never = []
        for prefix in self.never_touch:
            if type(prefix) is not tuple or not prefix:
                raise ScopeInputError("never-touch prefix must be a non-empty tuple")
            try:
                normalized = _casefold_components(_validate_components(prefix))
            except (TypeError, ValueError) as exc:
                raise ScopeInputError("never-touch prefix is invalid") from exc
            if normalized != prefix:
                raise ScopeInputError("never-touch prefix must be casefold canonical")
            normalized_never.append(normalized)
        if len(normalized_never) != len(set(normalized_never)):
            raise ScopeInputError("duplicate never-touch prefix")
        if not set(_MANDATORY_NEVER_TOUCH) <= set(normalized_never):
            raise ScopeInputError("mandatory never-touch prefixes are missing")
        expected_never = sorted(
            normalized_never,
            key=lambda prefix: (-len(prefix), canonical_raw_path(prefix)),
        )
        if list(self.never_touch) != expected_never:
            raise ScopeInputError("never-touch prefixes are not in canonical order")

    @classmethod
    def create(
        cls,
        default: ScopeDecision,
        bindings: Iterable[Tuple[Sequence[bytes], ScopeDecision]] = (),
        never_touch: Iterable[Sequence[bytes]] = (),
    ) -> "ScopeMap":
        normalized_bindings = []
        seen = set()
        for prefix, decision in bindings:
            normalized = _validate_components(prefix)
            if not normalized:
                raise ScopeInputError("scope binding prefix must not be root")
            if normalized in seen:
                raise ScopeInputError("duplicate scope binding")
            seen.add(normalized)
            normalized_bindings.append((normalized, decision))
        normalized_bindings.sort(
            key=lambda pair: (-len(pair[0]), canonical_raw_path(pair[0]))
        )
        custom_never_touch = tuple(
            _casefold_components(_validate_components(prefix)) for prefix in never_touch
        )
        if any(not prefix for prefix in custom_never_touch):
            raise ScopeInputError("never-touch prefix must not be root")
        combined = set(_MANDATORY_NEVER_TOUCH)
        combined.update(custom_never_touch)
        ordered_never_touch = tuple(
            sorted(combined, key=lambda prefix: (-len(prefix), canonical_raw_path(prefix)))
        )
        return cls(default, tuple(normalized_bindings), ordered_never_touch)

    def exclusion_for(self, components: Sequence[bytes]) -> Optional[str]:
        path = tuple(components)
        folded = _casefold_components(path)
        if path and (
            folded[0] == b"_registry"
            or (len(path) == 1 and folded[0] in _ROOT_CONTROL_FILES_CASEFOLD)
        ):
            return "control"
        if any(component in _MANDATORY_NEVER_TOUCH_NAMES for component in folded):
            return "never-touch"
        custom_prefixes = tuple(
            prefix for prefix in self.never_touch if prefix not in _MANDATORY_NEVER_TOUCH
        )
        if any(_has_prefix(folded, prefix) for prefix in custom_prefixes):
            return "never-touch"
        return None

    def decision_for(self, components: Sequence[bytes]) -> ScopeDecision:
        path = tuple(components)
        exclusion = self.exclusion_for(path)
        if exclusion:
            return ScopeDecision(
                rule_id=exclusion,
                scope_class="control" if exclusion == "control" else "never-touch",
                traversal="not-entered",
                lifecycle="protected",
                content_inspection="none",
                excluded_reason=exclusion,
            )
        physical = _physical_scope_decision(path)
        matching_bindings = []
        hard_restrictions = []
        if physical is not None:
            hard_restrictions.append(
                (_scope_restriction_rank(physical), len(path) + 1, physical)
            )
        for prefix, decision in self.bindings:
            if _has_prefix(path, prefix):
                candidate = (_scope_restriction_rank(decision), len(prefix), decision)
                matching_bindings.append(candidate)
                if decision.scope_class not in ("eligible", "unassigned-intake"):
                    hard_restrictions.append(candidate)
        if hard_restrictions:
            return max(hard_restrictions, key=lambda item: (item[0], item[1]))[2]
        if matching_bindings:
            return max(matching_bindings, key=lambda item: item[1])[2]
        return self.default


@dataclass(frozen=True)
class TraversalBounds:
    max_entries: int = 1000000
    max_direct_entries: int = 100000
    max_depth: int = 128
    max_file_bytes: int = 1024 * 1024
    max_content_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_entries",
            "max_direct_entries",
            "max_depth",
            "max_file_bytes",
            "max_content_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError("%s must be a non-negative integer" % name)
        if self.max_entries < 1:
            raise ValueError("max_entries must allow the root observation")


@dataclass(frozen=True)
class TextPolicy:
    allowed_extensions: Tuple[bytes, ...] = (
        b".md",
        b".markdown",
        b".txt",
        b".rst",
        b".yaml",
        b".yml",
        b".json",
        b".toml",
        b".ini",
        b".cfg",
        b".csv",
        b".tsv",
        b".py",
        b".js",
        b".ts",
        b".tsx",
        b".jsx",
        b".java",
        b".kt",
        b".kts",
        b".go",
        b".rs",
        b".sh",
    )
    max_json_bytes: int = 256 * 1024

    def __post_init__(self) -> None:
        normalized = tuple(sorted(set(extension.lower() for extension in self.allowed_extensions)))
        if any(
            not isinstance(extension, bytes)
            or not extension.startswith(b".")
            or b"/" in extension
            for extension in normalized
        ):
            raise ValueError("content extensions must be safe byte suffixes")
        if normalized != self.allowed_extensions:
            object.__setattr__(self, "allowed_extensions", normalized)
        if (
            type(self.max_json_bytes) is not int
            or self.max_json_bytes < 0
        ):
            raise ValueError("max_json_bytes must be non-negative")


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        return cls(
            int(value.st_dev),
            int(value.st_ino),
            int(value.st_mode),
            int(value.st_size),
            int(getattr(value, "st_mtime_ns", int(value.st_mtime * 1000000000))),
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
        }


@dataclass(frozen=True)
class TextProjection:
    text: str
    content_sha256: str
    bytes_read: int


@dataclass(frozen=True)
class InternalReference:
    kind: str
    target: str

    def __post_init__(self) -> None:
        if self.kind not in _REFERENCE_KINDS:
            raise ValueError("unknown internal reference kind")
        try:
            components = decode_canonical_raw_path(self.target)
        except (TypeError, ValueError) as exc:
            raise ValueError("internal reference target is not canonical") from exc
        if not components or canonical_raw_path(components) != self.target:
            raise ValueError("internal reference target is not canonical")

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind, "target": self.target}


@dataclass(frozen=True)
class ReferenceProjection:
    source_path: str
    projection_version: str
    projection_sha256: str
    references: Tuple[InternalReference, ...]
    parser_types: Tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            components = decode_canonical_raw_path(self.source_path)
        except (TypeError, ValueError) as exc:
            raise ValueError("reference projection source is not canonical") from exc
        if not components or canonical_raw_path(components) != self.source_path:
            raise ValueError("reference projection source is not canonical")
        if self.projection_version not in (
            _LEGACY_REFERENCE_PROJECTION_VERSION,
            _REFERENCE_PROJECTION_VERSION,
        ):
            raise ValueError("unknown reference projection version")
        expected_parser_types = (
            _LEGACY_REFERENCE_PARSER_TYPES
            if self.projection_version == _LEGACY_REFERENCE_PROJECTION_VERSION
            else _REFERENCE_PARSER_TYPES
        )
        if self.parser_types != expected_parser_types:
            raise ValueError("reference projection parser coverage is invalid")
        if (
            type(self.references) is not tuple
            or any(type(row) is not InternalReference for row in self.references)
            or tuple(sorted(set(self.references), key=lambda row: (row.kind, row.target)))
            != self.references
        ):
            raise ValueError("reference projection rows must be unique and sorted")
        payload = {
            "projection_version": self.projection_version,
            "references": [row.to_dict() for row in self.references],
            "source_path": self.source_path,
        }
        if self.projection_version == _REFERENCE_PROJECTION_VERSION:
            payload["parser_types"] = list(self.parser_types)
        if self.projection_sha256 != hashlib.sha256(
            _canonical_json_bytes(payload)
        ).hexdigest():
            raise ValueError("reference projection hash does not match payload")

    def to_dict(self) -> Dict[str, Any]:
        value = {
            "projection_version": self.projection_version,
            "projection_sha256": self.projection_sha256,
            "references": [row.to_dict() for row in self.references],
        }
        if self.projection_version == _REFERENCE_PROJECTION_VERSION:
            value["parser_types"] = list(self.parser_types)
        return value


@dataclass(frozen=True)
class ClassificationProjection:
    projection_version: str
    projection_sha256: str
    title: Optional[str]
    headings: Tuple[str, ...]
    frontmatter: Tuple[Tuple[str, str], ...]
    tokens: Tuple[str, ...]

    def __post_init__(self) -> None:
        if self.projection_version != _CLASSIFICATION_PROJECTION_VERSION:
            raise ValueError("unknown classification projection version")
        for label, values in (
            ("classification headings", self.headings),
            ("classification tokens", self.tokens),
        ):
            if type(values) is not tuple or tuple(sorted(set(values))) != values:
                raise ValueError("%s must be unique and sorted" % label)
        if self.title is not None:
            _safe_classification_text(self.title, "classification title")
        for heading in self.headings:
            _safe_classification_text(heading, "classification heading")
        if (
            type(self.frontmatter) is not tuple
            or tuple(sorted(set(self.frontmatter))) != self.frontmatter
        ):
            raise ValueError("classification frontmatter must be unique and sorted")
        for axis, value in self.frontmatter:
            if axis not in _CLASSIFICATION_FRONTMATTER_AXES:
                raise ValueError("classification frontmatter axis is invalid")
            if _SAFE_CLASSIFICATION_VALUE.fullmatch(value) is None:
                raise ValueError("classification frontmatter value is invalid")
        for token in self.tokens:
            if re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,63}", token) is None:
                raise ValueError("classification token is invalid")
        payload = self._payload()
        if self.projection_sha256 != hashlib.sha256(
            _canonical_json_bytes(payload)
        ).hexdigest():
            raise ValueError("classification projection hash does not match payload")

    def _payload(self) -> Dict[str, Any]:
        return {
            "frontmatter": [
                {"axis": axis, "value": value}
                for axis, value in self.frontmatter
            ],
            "headings": list(self.headings),
            "projection_version": self.projection_version,
            "title": self.title,
            "tokens": list(self.tokens),
        }

    def to_dict(self) -> Dict[str, Any]:
        value = self._payload()
        value["projection_sha256"] = self.projection_sha256
        return value


def _safe_classification_text(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 512
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError("%s is invalid" % label)
    return value


def _classification_projection(text: str) -> ClassificationProjection:
    if not isinstance(text, str):
        raise TypeError("classification projection input must be text")
    frontmatter_values: Dict[str, str] = {}
    title = None
    if text.startswith("---\n"):
        closing = text.find("\n---\n", 4)
        if closing >= 0:
            for line in text[4:closing].splitlines():
                if ":" not in line:
                    continue
                key, raw_value = line.split(":", 1)
                key = key.strip().casefold()
                value = raw_value.strip()
                if key == "title":
                    try:
                        title = _safe_classification_text(
                            value, "classification title"
                        )
                    except ValueError:
                        title = None
                elif (
                    key in _CLASSIFICATION_FRONTMATTER_AXES
                    and _SAFE_CLASSIFICATION_VALUE.fullmatch(value) is not None
                ):
                    frontmatter_values[key] = value
    headings = []
    for match in _MARKDOWN_HEADING.finditer(text):
        value = " ".join(match.group(1).split())
        try:
            _safe_classification_text(value, "classification heading")
        except ValueError:
            continue
        if title is None:
            title = value
            continue
        if value != title:
            headings.append(value)
    heading_values = tuple(sorted(set(headings)))[:64]
    token_sources = (
        (() if title is None else (title,))
        + heading_values
        + tuple(frontmatter_values.values())
    )
    tokens = tuple(
        sorted(
            {
                token
                for source in token_sources
                for token in re.findall(r"[a-z0-9][a-z0-9._:-]{0,63}", source.casefold())
            }
        )
    )[:64]
    payload = {
        "frontmatter": [
            {"axis": axis, "value": value}
            for axis, value in sorted(frontmatter_values.items())
        ],
        "headings": list(heading_values),
        "projection_version": _CLASSIFICATION_PROJECTION_VERSION,
        "title": title,
        "tokens": list(tokens),
    }
    return ClassificationProjection(
        projection_version=_CLASSIFICATION_PROJECTION_VERSION,
        projection_sha256=hashlib.sha256(_canonical_json_bytes(payload)).hexdigest(),
        title=title,
        headings=heading_values,
        frontmatter=tuple(sorted(frontmatter_values.items())),
        tokens=tokens,
    )


def _internal_reference_target(
    source_components: Tuple[bytes, ...],
    raw_target: str,
) -> Optional[str]:
    value = raw_target.strip().split("#", 1)[0].split("?", 1)[0]
    if (
        not value
        or value.startswith(("/", "#"))
        or "\\" in value
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value)
    ):
        return None
    root_relative = value.startswith(
        ("_registry/", "projects/", "docs/", "memory/", "mirrors/", "inbox/")
    )
    components = [] if root_relative else list(source_components[:-1])
    for segment in value.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not components:
                return None
            components.pop()
            continue
        try:
            component = segment.encode("utf-8", "strict")
            _encode_component(component)
        except (UnicodeError, ValueError):
            return None
        components.append(component)
    if not components:
        return None
    return canonical_raw_path(tuple(components))


def _reference_projection(
    source_components: Tuple[bytes, ...],
    text: str,
) -> ReferenceProjection:
    source_path = canonical_raw_path(source_components)
    raw_references = []
    raw_references.extend(
        ("markdown-inline", match.group(1))
        for match in _MARKDOWN_INLINE_REFERENCE.finditer(text)
    )
    raw_references.extend(
        ("markdown-reference", match.group(1) or match.group(2))
        for match in _MARKDOWN_REFERENCE_DEFINITION.finditer(text)
    )
    raw_references.extend(
        ("autolink", match.group(1))
        for match in _MARKDOWN_AUTOLINK.finditer(text)
    )
    raw_references.extend(
        ("html-attribute", match.group(2))
        for match in _HTML_REFERENCE_ATTRIBUTE.finditer(text)
    )
    explicit_targets = {
        resolved
        for _kind, raw_target in raw_references
        for resolved in (_internal_reference_target(source_components, raw_target),)
        if resolved is not None
    }
    raw_references.extend(
        (
            "registry-path" if match.group(1).startswith("_registry/") else "safe-path-literal",
            match.group(1),
        )
        for match in _SAFE_PATH_LITERAL.finditer(text)
        if _internal_reference_target(source_components, match.group(1))
        not in explicit_targets
    )
    references = tuple(
        InternalReference(kind, target)
        for kind, target in sorted(
            {
                (kind, resolved)
                for kind, raw_target in raw_references
                for resolved in (
                    _internal_reference_target(source_components, raw_target),
                )
                if resolved is not None
            }
        )
    )
    projection_payload = {
        "parser_types": list(_REFERENCE_PARSER_TYPES),
        "projection_version": _REFERENCE_PROJECTION_VERSION,
        "references": [row.to_dict() for row in references],
        "source_path": source_path,
    }
    return ReferenceProjection(
        source_path=source_path,
        projection_version=_REFERENCE_PROJECTION_VERSION,
        projection_sha256=hashlib.sha256(
            _canonical_json_bytes(projection_payload)
        ).hexdigest(),
        references=references,
        parser_types=_REFERENCE_PARSER_TYPES,
    )


@dataclass(frozen=True)
class Observation:
    run_id: str
    path: str
    display_path: str
    kind: str
    physical_kind: str
    scope_class: str
    scope_rule_id: str
    traversal: str
    content_inspected: bool
    excluded_reason: Optional[str]
    identity: Optional[FileIdentity]
    fingerprint_kind: str
    fingerprint_value: Optional[str]
    errors: Tuple[str, ...] = ()
    descendant_unknown: int = 0
    link_text_status: Optional[str] = None
    safe_link_text: Optional[str] = None
    direct_file_count: int = 0
    direct_other_count: int = 0
    content_policy_outcome: Optional[str] = None
    reference_projection: Optional[ReferenceProjection] = None
    classification_projection: Optional[ClassificationProjection] = None
    schema_version: int = 2

    def __post_init__(self) -> None:
        if self.schema_version not in (1, 2):
            raise ValueError("unknown observation schema version")
        if self.reference_projection is not None and type(
            self.reference_projection
        ) is not ReferenceProjection:
            raise TypeError("reference_projection must be ReferenceProjection")
        if self.classification_projection is not None and type(
            self.classification_projection
        ) is not ClassificationProjection:
            raise TypeError(
                "classification_projection must be ClassificationProjection"
            )
        if self.schema_version == 1 and (
            self.reference_projection is not None
            or self.classification_projection is not None
        ):
            raise ValueError("observation v1 cannot carry content projection")
        if self.reference_projection is not None and (
            self.reference_projection.source_path != self.path
            or not self.content_inspected
            or self.scope_class in _REFERENCE_RESTRICTED_SCOPES
        ):
            raise ValueError("reference projection is not allowed for observation")
        if self.classification_projection is not None and (
            not self.content_inspected or self.scope_class != "eligible"
        ):
            raise ValueError(
                "classification projection is not allowed for observation"
            )
        if self.scope_class in _REFERENCE_RESTRICTED_SCOPES and (
            self.content_inspected
            or self.fingerprint_kind == "sha256"
            or (
                self.physical_kind == "file"
                and self.fingerprint_value is not None
            )
        ):
            raise ValueError("restricted observation cannot carry content evidence")
        if (
            self.physical_kind == "file"
            and not self.content_inspected
            and self.fingerprint_value is not None
        ):
            raise ValueError("uninspected observation cannot carry fingerprint value")
        if (
            self.schema_version == 2
            and self.content_inspected
            and (
                self.reference_projection is None
                or self.classification_projection is None
            )
        ):
            raise ValueError("inspected observation v2 requires safe projections")
        if self.link_text_status is not None and self.link_text_status not in _LINK_TEXT_STATUSES:
            raise ValueError("unknown link text status")
        if self.link_text_status == "safe-relative":
            if not isinstance(self.safe_link_text, str) or not self.safe_link_text:
                raise ValueError("safe-relative link text is required")
        elif self.safe_link_text is not None:
            raise ValueError("safe link text is allowed only for safe-relative links")
        for label, value in (
            ("direct file count", self.direct_file_count),
            ("direct other count", self.direct_other_count),
        ):
            if type(value) is not int or value < 0:
                raise ValueError("%s must be a non-negative integer" % label)
        if (
            self.content_policy_outcome is not None
            and self.content_policy_outcome not in _CONTENT_POLICY_OUTCOMES
        ):
            raise ValueError("unknown content policy outcome")

    def to_dict(self) -> Dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "path": self.path,
            "display_path": self.display_path,
            "kind": self.kind,
            "physical_kind": self.physical_kind,
            "scope_class": self.scope_class,
            "scope_rule_id": self.scope_rule_id,
            "traversal": self.traversal,
            "content_inspected": self.content_inspected,
            "excluded_reason": self.excluded_reason,
            "stat": None if self.identity is None else self.identity.to_dict(),
            "fingerprint": {
                "kind": self.fingerprint_kind,
                "value": self.fingerprint_value,
            },
            "errors": list(self.errors),
            "descendant_unknown": self.descendant_unknown,
            "link_text_status": self.link_text_status,
            "safe_link_text": self.safe_link_text,
            "direct_file_count": self.direct_file_count,
            "direct_other_count": self.direct_other_count,
            "content_policy_outcome": self.content_policy_outcome,
        }
        if self.schema_version == 2:
            value["reference_projection"] = (
                None
                if self.reference_projection is None
                else self.reference_projection.to_dict()
            )
            value["classification_projection"] = (
                None
                if self.classification_projection is None
                else self.classification_projection.to_dict()
            )
        return value


@dataclass(frozen=True)
class InventoryResult:
    run_id: str
    observations: Tuple[Observation, ...]
    coverage: Mapping[str, Any]
    package_version: str = PACKAGE_VERSION
    openable: bool = False
    approval_ready: bool = False
    _coverage_bytes: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "observations", tuple(self.observations))
        frozen_coverage = _deep_freeze(self.coverage)
        object.__setattr__(self, "coverage", frozen_coverage)
        object.__setattr__(
            self,
            "_coverage_bytes",
            _canonical_json_bytes(frozen_coverage),
        )

    def observations_jsonl(self) -> bytes:
        return b"".join(_canonical_json_bytes(row.to_dict()) for row in self.observations)

    def coverage_json(self) -> bytes:
        return self._coverage_bytes


@dataclass(frozen=True)
class _SnapshotEntry:
    raw_name: bytes
    identity: Optional[FileIdentity]
    stat_result: Optional[os.stat_result]
    error_code: Optional[str]

    def digest_value(self) -> Dict[str, Any]:
        return {
            "name": _encode_component(self.raw_name),
            "identity": None if self.identity is None else self.identity.to_dict(),
            "error": self.error_code,
        }


@dataclass(frozen=True)
class _DirectorySnapshot:
    entries: Tuple[_SnapshotEntry, ...]
    total_entries: int
    overflow_count: int
    bound_reason: Optional[str]


@dataclass(frozen=True)
class _ReverseName:
    raw_name: bytes

    def __lt__(self, other: "_ReverseName") -> bool:
        return self.raw_name > other.raw_name


def _required_open_flags(directory: bool, nonblock: bool = False) -> int:
    required_names = ("O_NOFOLLOW", "O_CLOEXEC")
    missing = [name for name in required_names if not hasattr(os, name)]
    if missing:
        raise InventorySafetyError("required no-follow capability unavailable: %s" % ",".join(missing))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if directory:
        if not hasattr(os, "O_DIRECTORY"):
            raise InventorySafetyError("required directory-open capability unavailable")
        flags |= os.O_DIRECTORY
    if nonblock:
        if not hasattr(os, "O_NONBLOCK"):
            raise InventorySafetyError("required nonblocking-open capability unavailable")
        flags |= os.O_NONBLOCK
    return flags


def _open_relative(
    name: Union[str, bytes],
    flags: int,
    parent_fd: int,
    mode: Optional[int] = None,
) -> int:
    """Use Darwin's stronger flag when it is accepted for this filesystem."""
    nofollow_any = getattr(os, "O_NOFOLLOW_ANY", 0)
    attempts = (flags | nofollow_any, flags) if nofollow_any else (flags,)
    last_error = None
    for index, candidate in enumerate(attempts):
        try:
            if mode is None:
                return os.open(name, candidate, dir_fd=parent_fd)
            return os.open(name, candidate, mode, dir_fd=parent_fd)
        except OSError as exc:
            last_error = exc
            if index + 1 == len(attempts) or exc.errno not in (errno.EINVAL, errno.ENOTSUP):
                raise
    assert last_error is not None
    raise last_error


def _open_directory_path_nofollow(path: Union[str, bytes, os.PathLike]) -> int:
    """Open every absolute path component without following a symlink."""
    raw_path = os.fsencode(os.fspath(path))
    if not raw_path.startswith(b"/"):
        raise InventorySafetyError("inventory roots must be absolute paths")
    components = tuple(component for component in raw_path.split(b"/") if component)
    for component in components:
        _encode_component(component)
    flags = _required_open_flags(directory=True)
    current_fd = os.open(b"/", flags)
    try:
        for component in components:
            next_fd = _open_relative(component, flags, current_fd)
            opened = os.fstat(next_fd)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(next_fd)
                raise InventorySafetyError("inventory root component is not a directory")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError as exc:
        os.close(current_fd)
        raise InventorySafetyError("cannot open inventory root component safely") from exc
    except Exception:
        os.close(current_fd)
        raise


def _bounded_readlinkat(
    parent_fd: int, raw_name: bytes, maximum_bytes: int
) -> Tuple[Optional[bytes], bool]:
    """Return link bytes through readlinkat without allocating beyond the bound."""
    _encode_component(raw_name)
    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 1
    ):
        raise ValueError("readlink bound must be a positive integer")
    libc = ctypes.CDLL(None, use_errno=True)
    readlinkat = getattr(libc, "readlinkat", None)
    if readlinkat is None:
        raise OSError(errno.ENOSYS, "readlinkat unavailable")
    readlinkat.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    )
    readlinkat.restype = ctypes.c_ssize_t
    buffer_size = maximum_bytes + 1
    buffer = ctypes.create_string_buffer(buffer_size)
    ctypes.set_errno(0)
    result = readlinkat(
        parent_fd,
        ctypes.c_char_p(raw_name),
        ctypes.cast(buffer, ctypes.c_void_p),
        buffer_size,
    )
    if result < 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))
    if result > maximum_bytes:
        return None, True
    return bytes(buffer.raw[:result]), False


def _classify_link_text(
    raw_target: bytes,
    containing_components: Tuple[bytes, ...],
) -> Tuple[str, Optional[str]]:
    if not raw_target or b"\x00" in raw_target:
        return "invalid", None
    try:
        text = raw_target.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "invalid", None
    if any(
        not character.isprintable()
        or unicodedata.category(character).startswith("C")
        for character in text
    ):
        return "invalid", None
    if raw_target.startswith(b"/"):
        return "absolute", None
    depth = len(containing_components)
    for component in raw_target.split(b"/"):
        if component in (b"", b"."):
            continue
        if component == b"..":
            if depth == 0:
                return "out-of-root", None
            depth -= 1
        else:
            depth += 1
    if _LINK_SECRET_RE.search(raw_target):
        return "secret-like", None
    return "safe-relative", text


def _observe_symlink_text(
    parent_fd: int,
    raw_name: bytes,
    containing_components: Tuple[bytes, ...],
    expected: FileIdentity,
) -> Tuple[str, Optional[str], Tuple[str, ...]]:
    try:
        before = FileIdentity.from_stat(
            os.stat(raw_name, dir_fd=parent_fd, follow_symlinks=False)
        )
        if before != expected or not stat.S_ISLNK(before.mode):
            return "unavailable", None, ("symlink-race",)
        raw_target, oversized = _bounded_readlinkat(
            parent_fd,
            raw_name,
            _MAX_LINK_TEXT_BYTES,
        )
        after = FileIdentity.from_stat(
            os.stat(raw_name, dir_fd=parent_fd, follow_symlinks=False)
        )
        if after != before:
            return "unavailable", None, ("symlink-race",)
    except OSError:
        return "unavailable", None, ("readlink-unavailable",)
    if oversized:
        return "oversize", None, ()
    if raw_target is None:
        return "unavailable", None, ("readlink-unavailable",)
    status, safe_text = _classify_link_text(raw_target, containing_components)
    return status, safe_text, ()


def _physical_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "special"


def _same_identity(first: FileIdentity, second: FileIdentity) -> bool:
    return first == second


def _same_object(first: FileIdentity, second: FileIdentity) -> bool:
    return (
        first.device,
        first.inode,
        stat.S_IFMT(first.mode),
    ) == (
        second.device,
        second.inode,
        stat.S_IFMT(second.mode),
    )


class BoundedTextReader:
    """No-follow reader bound to the directory descriptor traversal opened."""

    def __init__(self, policy: Optional[TextPolicy] = None) -> None:
        self.policy = policy or TextPolicy()

    def read(
        self,
        parent_fd: int,
        parent_identity: FileIdentity,
        root_device: int,
        components: Tuple[bytes, ...],
        expected: FileIdentity,
        maximum_bytes: int,
        fault_checkpoint: Optional[Callable[[str, str], None]] = None,
    ) -> TextProjection:
        total = 0
        if not components:
            raise ContentReadError("content-path-is-root")
        filename = components[-1].lower()
        extension = b"." + filename.rsplit(b".", 1)[-1] if b"." in filename else b""
        if extension not in self.policy.allowed_extensions:
            raise ContentReadError("content-type-not-allowed")
        limit = maximum_bytes
        if extension == b".json":
            limit = min(limit, self.policy.max_json_bytes)
        if expected.size > limit:
            raise ContentReadError("content-too-large")

        opened_file_fd = None
        try:
            current_parent = FileIdentity.from_stat(os.fstat(parent_fd))
            if not _same_object(current_parent, parent_identity):
                raise ContentReadError("content-parent-race")
            try:
                lexical_before = FileIdentity.from_stat(
                    os.stat(components[-1], dir_fd=parent_fd, follow_symlinks=False)
                )
            except OSError as exc:
                raise ContentReadError("content-race") from exc
            if not _same_identity(lexical_before, expected):
                raise ContentReadError("content-race")
            try:
                opened_file_fd = _open_relative(
                    components[-1],
                    _required_open_flags(directory=False, nonblock=True),
                    parent_fd,
                )
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ContentReadError("content-no-follow") from exc
                raise ContentReadError("content-open-failed") from exc
            opened = os.fstat(opened_file_fd)
            opened_identity = FileIdentity.from_stat(opened)
            if not stat.S_ISREG(opened.st_mode):
                raise ContentReadError("content-not-regular")
            if opened.st_dev != root_device:
                raise ContentReadError("content-mount-boundary")
            if not _same_identity(opened_identity, expected):
                raise ContentReadError("content-race")
            if opened_identity.size > limit:
                raise ContentReadError("content-too-large")

            canonical_path = canonical_raw_path(components)
            if fault_checkpoint is not None:
                fault_checkpoint("content-opened", canonical_path)
            chunks = []
            while total < opened_identity.size:
                chunk = os.read(
                    opened_file_fd,
                    min(65536, opened_identity.size - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise ContentReadError("content-too-large", total)
            body = b"".join(chunks)
            if fault_checkpoint is not None:
                fault_checkpoint("content-read", canonical_path)
            after_identity = FileIdentity.from_stat(os.fstat(opened_file_fd))
            if not _same_identity(after_identity, opened_identity):
                raise ContentReadError("content-race", total)
            if total != opened_identity.size:
                raise ContentReadError("content-race", total)
            try:
                lexical_after = FileIdentity.from_stat(
                    os.stat(components[-1], dir_fd=parent_fd, follow_symlinks=False)
                )
            except OSError as exc:
                raise ContentReadError("content-race", total) from exc
            if not _same_identity(lexical_after, opened_identity):
                raise ContentReadError("content-race", total)
            if not _same_object(
                FileIdentity.from_stat(os.fstat(parent_fd)), parent_identity
            ):
                raise ContentReadError("content-parent-race", total)
            if b"\x00" in body:
                raise ContentReadError("content-has-nul", total)
            try:
                text = body.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise ContentReadError("content-invalid-utf8", total) from exc
            return TextProjection(text, _sha256(body), len(body))
        except OSError as exc:
            raise ContentReadError("content-open-failed", total) from exc
        finally:
            if opened_file_fd is not None:
                os.close(opened_file_fd)


class InventoryEngine:
    """Deterministic descriptor-relative traversal with no corpus writes."""

    def __init__(
        self,
        raw_root: Union[str, bytes, os.PathLike],
        scope_map: ScopeMap,
        bounds: TraversalBounds,
        text_policy: Optional[TextPolicy] = None,
        observation_hook: Optional[Callable[[Observation], None]] = None,
        fault_checkpoint: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.raw_root = os.fspath(raw_root)
        self.scope_map = scope_map
        self.bounds = bounds
        self.reader = BoundedTextReader(text_policy)
        self.observation_hook = observation_hook
        self.fault_checkpoint = fault_checkpoint

    def _snapshot(
        self, directory_fd: int, observation_budget: int
    ) -> _DirectorySnapshot:
        frontier: List[_ReverseName] = []
        total_entries = 0
        frontier_limit = min(self.bounds.max_direct_entries, max(0, observation_budget))
        try:
            with os.scandir(directory_fd) as iterator:
                for directory_entry in iterator:
                    raw_name = os.fsencode(directory_entry.name)
                    total_entries += 1
                    candidate = _ReverseName(raw_name)
                    if len(frontier) < frontier_limit:
                        heapq.heappush(frontier, candidate)
                    elif frontier and raw_name < frontier[0].raw_name:
                        heapq.heapreplace(frontier, candidate)
        except OSError as exc:
            raise InventorySafetyError("directory-list-failed:%s" % exc.errno) from exc
        names = sorted(candidate.raw_name for candidate in frontier)
        result = []
        for raw_name in names:
            try:
                value = os.stat(
                    raw_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                result.append(_SnapshotEntry(raw_name, None, None, "lstat-failed:%s" % exc.errno))
            else:
                result.append(
                    _SnapshotEntry(raw_name, FileIdentity.from_stat(value), value, None)
                )
        return _DirectorySnapshot(
            tuple(result),
            total_entries,
            max(0, total_entries - len(result)),
            (
                "max-entries"
                if total_entries > len(result)
                and observation_budget < self.bounds.max_direct_entries
                else (
                    "max-direct-entries" if total_entries > len(result) else None
                )
            ),
        )

    @staticmethod
    def _snapshot_hash(snapshot: _DirectorySnapshot) -> str:
        return _sha256(
            _canonical_json_bytes(
                {
                    "entries": [entry.digest_value() for entry in snapshot.entries],
                    "total_entries": snapshot.total_entries,
                    "overflow_count": snapshot.overflow_count,
                    "bound_reason": snapshot.bound_reason,
                }
            )
        )

    def scan(self, run_id: str) -> InventoryResult:
        _validate_run_id(run_id)
        root_fd = _open_directory_path_nofollow(self.raw_root)
        observations: List[Observation] = []
        state = {"entries": 0, "content_bytes": 0}
        try:
            _safety_core.require_same_directory_identity(
                Path(os.fsdecode(self.raw_root)),
                root_fd,
                "inventory raw root",
                error_type=InventorySafetyError,
            )
            root_stat = os.fstat(root_fd)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise InventorySafetyError("raw root is not a directory")
            root_device = int(root_stat.st_dev)
            root_identity = FileIdentity.from_stat(root_stat)
            root_decision = self.scope_map.decision_for(())
            root_observation = Observation(
                run_id=run_id,
                path=canonical_raw_path(()),
                display_path=".",
                kind="directory",
                physical_kind="directory",
                scope_class=root_decision.scope_class,
                scope_rule_id=root_decision.rule_id,
                traversal="full",
                content_inspected=False,
                excluded_reason=None,
                identity=root_identity,
                fingerprint_kind="direct-entry-manifest",
                fingerprint_value=None,
            )
            observations.append(root_observation)
            self._visit_directory(
                root_fd,
                root_device,
                (),
                0,
                0,
                observations,
                state,
                run_id,
            )
            if self.fault_checkpoint is not None:
                self.fault_checkpoint(
                    "scan-before-root-identity-recheck",
                    canonical_raw_path(()),
                )
            _safety_core.require_same_directory_identity(
                Path(os.fsdecode(self.raw_root)),
                root_fd,
                "inventory raw root",
                error_type=InventorySafetyError,
            )
        finally:
            os.close(root_fd)

        coverage = _build_coverage(
            observations,
            content_bytes_attempted=state["content_bytes"],
        )
        final_observations = tuple(observations)
        if self.observation_hook is not None:
            for observation in final_observations:
                self.observation_hook(observation)
        return InventoryResult(run_id, final_observations, coverage)

    def _visit_directory(
        self,
        directory_fd: int,
        root_device: int,
        components: Tuple[bytes, ...],
        depth: int,
        observation_index: int,
        observations: List[Observation],
        state: Dict[str, int],
        run_id: str,
    ) -> None:
        try:
            observation_budget = self.bounds.max_entries - len(observations)
            before = self._snapshot(directory_fd, observation_budget)
        except InventorySafetyError as exc:
            current = observations[observation_index]
            observations[observation_index] = replace(
                current, errors=current.errors + (str(exc).split(":", 1)[0],)
            )
            return
        before_hash = self._snapshot_hash(before)
        current_directory = observations[observation_index]
        directory_errors = current_directory.errors
        if before.overflow_count and before.bound_reason:
            directory_errors = tuple(
                sorted(set(directory_errors + (before.bound_reason,)))
            )
        observations[observation_index] = replace(
            current_directory,
            fingerprint_value=before_hash,
            errors=directory_errors,
            descendant_unknown=(
                current_directory.descendant_unknown + before.overflow_count
            ),
        )
        if self.fault_checkpoint is not None:
            self.fault_checkpoint("directory-listed", canonical_raw_path(components))

        for entry_index, entry in enumerate(before.entries):
            if state.get("observation_limit_reached") or len(observations) >= self.bounds.max_entries:
                state["observation_limit_reached"] = 1
                current = observations[observation_index]
                remaining = len(before.entries) - entry_index
                observations[observation_index] = replace(
                    current,
                    errors=tuple(sorted(set(current.errors + ("max-entries",)))),
                    descendant_unknown=current.descendant_unknown + remaining,
                )
                break
            child_components = components + (entry.raw_name,)
            count_only = (
                observations[observation_index].traversal
                == "directory-count-only"
            )
            if entry.stat_result is None or entry.identity is None:
                if count_only:
                    current = observations[observation_index]
                    observations[observation_index] = replace(
                        current,
                        direct_other_count=current.direct_other_count + 1,
                        descendant_unknown=current.descendant_unknown + 1,
                        errors=tuple(
                            sorted(
                                set(
                                    current.errors
                                    + ("directory-count-entry-error",)
                                )
                            )
                        ),
                    )
                    continue
                observations.append(
                    Observation(
                        run_id,
                        canonical_raw_path(child_components),
                        display_raw_path(child_components),
                        "error",
                        "error",
                        self.scope_map.decision_for(child_components).scope_class,
                        self.scope_map.decision_for(child_components).rule_id,
                        "not-entered",
                        False,
                        "lstat-error",
                        None,
                        "none",
                        None,
                        (entry.error_code or "lstat-failed",),
                    )
                )
                continue

            physical_kind = _physical_kind(entry.stat_result.st_mode)
            decision = self.scope_map.decision_for(child_components)
            exclusion = self.scope_map.exclusion_for(child_components)
            if count_only and physical_kind != "directory":
                current = observations[observation_index]
                observations[observation_index] = replace(
                    current,
                    direct_file_count=(
                        current.direct_file_count
                        + int(physical_kind == "file")
                    ),
                    direct_other_count=(
                        current.direct_other_count
                        + int(physical_kind != "file")
                    ),
                    errors=(
                        tuple(
                            sorted(
                                set(current.errors + ("mount-boundary",))
                            )
                        )
                        if entry.stat_result.st_dev != root_device
                        else current.errors
                    ),
                )
                continue
            if entry.stat_result.st_dev != root_device:
                observations.append(
                    Observation(
                        run_id,
                        canonical_raw_path(child_components),
                        display_raw_path(child_components),
                        "boundary",
                        physical_kind,
                        decision.scope_class,
                        decision.rule_id,
                        "not-entered",
                        False,
                        "mount-boundary",
                        entry.identity,
                        "metadata",
                        None,
                        ("mount-boundary",),
                        content_policy_outcome=(
                            "structural-error"
                            if physical_kind == "file"
                            else None
                        ),
                    )
                )
                continue

            if physical_kind == "symlink":
                link_status, safe_link_text, link_errors = _observe_symlink_text(
                    directory_fd,
                    entry.raw_name,
                    components,
                    entry.identity,
                )
                observations.append(
                    Observation(
                        run_id,
                        canonical_raw_path(child_components),
                        display_raw_path(child_components),
                        "symlink",
                        "symlink",
                        decision.scope_class,
                        decision.rule_id,
                        "not-entered",
                        False,
                        exclusion or "symlink",
                        entry.identity,
                        "metadata",
                        None,
                        link_errors,
                        0,
                        link_status,
                        safe_link_text,
                    )
                )
                continue
            if physical_kind == "special":
                observations.append(
                    Observation(
                        run_id,
                        canonical_raw_path(child_components),
                        display_raw_path(child_components),
                        "special",
                        "special",
                        decision.scope_class,
                        decision.rule_id,
                        "not-entered",
                        False,
                        exclusion or "special-file",
                        entry.identity,
                        "metadata",
                        None,
                    )
                )
                continue
            if physical_kind == "file":
                observations.append(
                    self._observe_file(
                        directory_fd,
                        FileIdentity.from_stat(os.fstat(directory_fd)),
                        root_device,
                        child_components,
                        entry,
                        decision,
                        exclusion,
                        state,
                        run_id,
                    )
                )
                continue

            traversal = decision.traversal
            excluded_reason = exclusion or decision.excluded_reason
            if depth + 1 > self.bounds.max_depth:
                if state.get("strict_depth_budget"):
                    current = observations[observation_index]
                    observations[observation_index] = replace(
                        current,
                        errors=tuple(sorted(set(current.errors + ("max-depth",)))),
                        descendant_unknown=current.descendant_unknown + 1,
                    )
                    continue
                traversal = "not-entered"
                excluded_reason = "max-depth"
            directory_observation = Observation(
                run_id,
                canonical_raw_path(child_components),
                display_raw_path(child_components),
                "directory",
                "directory",
                decision.scope_class,
                decision.rule_id,
                traversal,
                False,
                excluded_reason,
                entry.identity,
                "direct-entry-manifest" if traversal != "not-entered" else "metadata",
                None,
            )
            child_index = len(observations)
            observations.append(directory_observation)
            if traversal == "not-entered":
                continue
            try:
                child_fd = _open_relative(
                    entry.raw_name,
                    _required_open_flags(directory=True),
                    directory_fd,
                )
            except OSError:
                observations[child_index] = replace(
                    observations[child_index],
                    traversal="not-entered",
                    excluded_reason="directory-open-failed",
                    errors=("directory-open-failed",),
                )
                continue
            try:
                opened_identity = FileIdentity.from_stat(os.fstat(child_fd))
                if not _same_identity(opened_identity, entry.identity):
                    observations[child_index] = replace(
                        observations[child_index],
                        traversal="not-entered",
                        excluded_reason="directory-race",
                        errors=("directory-race",),
                    )
                    continue
                if opened_identity.device != root_device:
                    observations[child_index] = replace(
                        observations[child_index],
                        kind="boundary",
                        traversal="not-entered",
                        excluded_reason="mount-boundary",
                        errors=("mount-boundary",),
                    )
                    continue
                self._visit_directory(
                    child_fd,
                    root_device,
                    child_components,
                    depth + 1,
                    child_index,
                    observations,
                    state,
                    run_id,
                )
            finally:
                os.close(child_fd)

        if before.bound_reason == "max-entries":
            state["observation_limit_reached"] = 1
        if state.get("observation_limit_reached"):
            return
        try:
            after = self._snapshot(directory_fd, observation_budget)
        except InventorySafetyError:
            after = _DirectorySnapshot((), 0, 0, None)
        # Raw os.stat_result equality includes atime, which can change merely
        # because the scan reads an entry.  Race detection must use the same
        # stable identity projection as provenance (dev/inode/mode/size/mtime)
        # plus the canonical listing bounds/errors, never access time.
        if before_hash != self._snapshot_hash(after):
            current = observations[observation_index]
            observations[observation_index] = replace(
                current,
                errors=tuple(sorted(set(current.errors + ("directory-race",)))),
            )

    def _observe_file(
        self,
        containing_fd: int,
        containing_identity: FileIdentity,
        root_device: int,
        components: Tuple[bytes, ...],
        entry: _SnapshotEntry,
        decision: ScopeDecision,
        exclusion: Optional[str],
        state: Dict[str, int],
        run_id: str,
    ) -> Observation:
        traversal = decision.traversal
        excluded_reason = exclusion or decision.excluded_reason
        if traversal == "not-entered" or exclusion:
            return Observation(
                run_id,
                canonical_raw_path(components),
                display_raw_path(components),
                "file",
                "file",
                decision.scope_class,
                decision.rule_id,
                "not-entered",
                False,
                excluded_reason,
                entry.identity,
                "metadata",
                None,
                content_policy_outcome="not-eligible",
            )
        if decision.content_inspection != "bounded-text":
            return Observation(
                run_id,
                canonical_raw_path(components),
                display_raw_path(components),
                "file",
                "file",
                decision.scope_class,
                decision.rule_id,
                traversal,
                False,
                None,
                entry.identity,
                "metadata",
                None,
                content_policy_outcome="metadata-only",
            )
        remaining = self.bounds.max_content_bytes - state["content_bytes"]
        maximum = min(self.bounds.max_file_bytes, max(remaining, 0))
        if maximum <= 0:
            return Observation(
                run_id,
                canonical_raw_path(components),
                display_raw_path(components),
                "file",
                "file",
                decision.scope_class,
                decision.rule_id,
                traversal,
                False,
                "content-run-byte-bound",
                entry.identity,
                "metadata",
                None,
                ("content-run-byte-bound",),
                content_policy_outcome="budget-exhausted",
            )

        if self.fault_checkpoint is not None:
            self.fault_checkpoint("content-before-open", canonical_raw_path(components))
        try:
            projection = self.reader.read(
                containing_fd,
                containing_identity,
                root_device,
                components,
                entry.identity,
                maximum,
                self.fault_checkpoint,
            )
        except ContentReadError as exc:
            state["content_bytes"] += exc.bytes_read
            policy_outcome = {
                "content-type-not-allowed": "rejected-type",
                "content-too-large": "rejected-size",
                "content-has-nul": "rejected-content",
                "content-invalid-utf8": "rejected-content",
            }.get(exc.code, "structural-error")
            return Observation(
                run_id,
                canonical_raw_path(components),
                display_raw_path(components),
                "file",
                "file",
                decision.scope_class,
                decision.rule_id,
                traversal,
                False,
                None,
                entry.identity,
                "metadata",
                None,
                (exc.code,),
                content_policy_outcome=policy_outcome,
            )
        state["content_bytes"] += projection.bytes_read
        return Observation(
            run_id,
            canonical_raw_path(components),
            display_raw_path(components),
            "file",
            "file",
            decision.scope_class,
            decision.rule_id,
            traversal,
            True,
            None,
            entry.identity,
            "sha256",
            projection.content_sha256,
            content_policy_outcome="inspected",
            reference_projection=_reference_projection(
                components,
                projection.text,
            ),
            classification_projection=_classification_projection(
                projection.text,
            ),
        )


class _FrozenCountScopeMap:
    """Apply one admitted frozen decision to the exact descriptor root."""

    def __init__(self, decision: ScopeDecision) -> None:
        self._decision = decision

    def decision_for(self, _components: Sequence[bytes]) -> ScopeDecision:
        return self._decision

    @staticmethod
    def exclusion_for(_components: Sequence[bytes]) -> Optional[str]:
        return None


def scan_directory_count_only(
    run_id: str,
    directory_fd: int,
    frozen_scope_decision: ScopeDecision,
    bounds: TraversalBounds,
) -> InventoryResult:
    """Count an admitted exact directory tree without opening regular files.

    The caller retains ownership of ``directory_fd``.  This entrypoint is
    intentionally in-memory only: it has no hooks, checkpoints, workflow, or
    persistence capability.
    """

    _validate_run_id(run_id)
    if type(directory_fd) is not int:
        raise TypeError("directory descriptor must be an integer")
    if type(frozen_scope_decision) is not ScopeDecision or (
        frozen_scope_decision.rule_id,
        frozen_scope_decision.scope_class,
        frozen_scope_decision.traversal,
        frozen_scope_decision.lifecycle,
        frozen_scope_decision.content_inspection,
        frozen_scope_decision.excluded_reason,
    ) not in {
        (
            "paused-completed",
            "coverage-only",
            "directory-count-only",
            "paused",
            "none",
            None,
        ),
        (
            "paused-completed",
            "coverage-only",
            "directory-count-only",
            "completed",
            "none",
            None,
        ),
    }:
        raise ScopeInputError("frozen scope decision is not canonical")
    if type(bounds) is not TraversalBounds:
        raise TypeError("frozen traversal bounds are invalid")

    frozen_bounds = TraversalBounds(
        max_entries=bounds.max_entries,
        max_direct_entries=bounds.max_entries,
        max_depth=bounds.max_depth,
        max_file_bytes=0,
        max_content_bytes=0,
    )
    engine = InventoryEngine(
        raw_root=b".",
        scope_map=_FrozenCountScopeMap(frozen_scope_decision),
        bounds=frozen_bounds,
    )
    try:
        scan_fd = os.dup(directory_fd)
    except OSError as exc:
        raise InventorySafetyError("directory-duplicate-failed") from exc
    observations: List[Observation] = []
    state = {
        "entries": 0,
        "content_bytes": 0,
        "strict_depth_budget": 1,
    }
    try:
        try:
            root_stat = os.fstat(scan_fd)
        except OSError as exc:
            raise InventorySafetyError("directory-stat-failed") from exc
        if not stat.S_ISDIR(root_stat.st_mode):
            raise InventorySafetyError("frozen root is not a directory")
        root_identity = FileIdentity.from_stat(root_stat)
        observations.append(
            Observation(
                run_id=run_id,
                path=canonical_raw_path(()),
                display_path=".",
                kind="directory",
                physical_kind="directory",
                scope_class=frozen_scope_decision.scope_class,
                scope_rule_id=frozen_scope_decision.rule_id,
                traversal="directory-count-only",
                content_inspected=False,
                excluded_reason=None,
                identity=root_identity,
                fingerprint_kind="direct-entry-manifest",
                fingerprint_value=None,
            )
        )
        engine._visit_directory(
            scan_fd,
            int(root_stat.st_dev),
            (),
            0,
            0,
            observations,
            state,
            run_id,
        )
        try:
            root_after = FileIdentity.from_stat(os.fstat(scan_fd))
        except OSError as exc:
            raise InventorySafetyError("directory-recheck-failed") from exc
        if not _same_identity(root_identity, root_after):
            raise InventorySafetyError("directory-race")
    finally:
        os.close(scan_fd)

    observations = [replace(row, fingerprint_value=None) for row in observations]
    coverage = _build_coverage(
        observations,
        content_bytes_attempted=state["content_bytes"],
    )
    return InventoryResult(run_id, tuple(observations), coverage)


def _build_coverage(
    observations: Sequence[Observation], content_bytes_attempted: int = 0
) -> Dict[str, Any]:
    folders = [row for row in observations if row.physical_kind == "directory"]
    files = [row for row in observations if row.physical_kind == "file"]
    other = [row for row in observations if row.physical_kind not in ("directory", "file")]
    aggregated_files = sum(row.direct_file_count for row in folders)
    aggregated_other = sum(row.direct_other_count for row in folders)

    def structural_errors(row: Observation) -> Tuple[str, ...]:
        return tuple(
            error for error in row.errors if error not in _CONTENT_POLICY_ERROR_CODES
        )

    def folder_outcome(row: Observation) -> str:
        if structural_errors(row):
            return "error"
        if row.traversal == "not-entered":
            return "not_entered"
        if row.descendant_unknown:
            return "traversed_partial"
        return "traversed_complete"

    def file_outcome(row: Observation) -> str:
        if structural_errors(row):
            return "error"
        if row.traversal == "not-entered":
            return "not_entered"
        if row.content_inspected:
            return "content_inspected"
        return "metadata_only"

    folder_outcomes = {
        name: sum(folder_outcome(row) == name for row in folders)
        for name in ("traversed_complete", "traversed_partial", "not_entered", "error")
    }
    file_outcomes = {
        name: sum(file_outcome(row) == name for row in files)
        for name in ("content_inspected", "metadata_only", "not_entered", "error")
    }
    file_outcomes["metadata_only"] += aggregated_files
    reasons: Dict[str, int] = {}
    for row in observations:
        if row.excluded_reason:
            reasons[row.excluded_reason] = reasons.get(row.excluded_reason, 0) + 1
        for error in structural_errors(row):
            key = "error:%s" % error
            reasons[key] = reasons.get(key, 0) + 1
    descendant_unknown = sum(row.descendant_unknown for row in observations)
    state = "explained-partial" if reasons or descendant_unknown else "complete"
    by_scope: Dict[str, Dict[str, int]] = {}
    for row in observations:
        partition = by_scope.setdefault(
            row.scope_class,
            {
                "folders": 0,
                "files": 0,
                "other_items": 0,
                "content_inspected": 0,
                "not_entered": 0,
                "errors": 0,
                "descendant_unknown": 0,
            },
        )
        if row.physical_kind == "directory":
            partition["folders"] += 1
        elif row.physical_kind == "file":
            partition["files"] += 1
        else:
            partition["other_items"] += 1
        partition["content_inspected"] += int(row.content_inspected)
        partition["not_entered"] += int(row.traversal == "not-entered")
        partition["errors"] += int(bool(structural_errors(row)))
        partition["descendant_unknown"] += row.descendant_unknown
        if row.physical_kind == "directory":
            partition["files"] += row.direct_file_count
            partition["other_items"] += row.direct_other_count
    content_policy_outcomes = {
        outcome: sum(row.content_policy_outcome == outcome for row in files)
        for outcome in sorted(_CONTENT_POLICY_OUTCOMES)
    }
    content_policy_outcomes["not-eligible"] += aggregated_files
    return {
        "schema_version": 1,
        "package_version": PACKAGE_VERSION,
        "state": state,
        "folders": {
            "denominator": len(folders),
            "outcomes": folder_outcomes,
            "entered": len(folders) - folder_outcomes["not_entered"],
            "not_entered": folder_outcomes["not_entered"],
        },
        "files": {
            "denominator": len(files) + aggregated_files,
            "outcomes": file_outcomes,
            "content_inspected": file_outcomes["content_inspected"],
            "metadata_only": file_outcomes["metadata_only"],
        },
        "other_items": {
            "denominator": len(other) + aggregated_other,
            "symlink": sum(row.physical_kind == "symlink" for row in other),
            "special": sum(row.physical_kind == "special" for row in other),
            "error": sum(row.physical_kind == "error" for row in other),
            "aggregated": aggregated_other,
        },
        "descendant_unknown": descendant_unknown,
        "content_bytes_attempted": content_bytes_attempted,
        "content_policy_outcomes": content_policy_outcomes,
        "by_scope": dict(sorted(by_scope.items())),
        "partial_reasons": dict(sorted(reasons.items())),
        "prework_eligible": False,
        "openable": False,
        "approval_ready": False,
    }


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError("invalid inventory run id")
    folded = run_id.casefold()
    if folded.startswith(".incomplete-") or folded in ("failed", ".", ".."):
        raise ValueError("reserved inventory run id")
    return run_id


def _validate_artifact_name(name: str) -> str:
    if not isinstance(name, str) or not _ARTIFACT_RE.fullmatch(name):
        raise ValueError("invalid inventory artifact name")
    if name.casefold() in _RESERVED_ARTIFACTS:
        raise ValueError("reserved inventory artifact name")
    return name


def _validate_request_bounds(bounds: Any) -> Dict[str, int]:
    if not isinstance(bounds, Mapping) or not bounds:
        raise ValueError("inventory bounds must be a non-empty mapping")
    result = {}
    for name, value in bounds.items():
        if (
            not isinstance(name, str)
            or not name.startswith("max_")
            or type(value) is not int
            or value < 0
        ):
            raise ValueError("inventory request bounds must be non-negative integers")
        result[name] = value
    if "max_entries" in result and result["max_entries"] < 1:
        raise ValueError("inventory request max_entries must allow the root")
    return result


def _validate_expected_artifacts(values: Any) -> Tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise ValueError("expected inventory artifacts must be a sequence")
    artifacts = tuple(sorted(_validate_artifact_name(name) for name in values))
    folded = [name.casefold() for name in artifacts]
    if len(folded) != len(set(folded)):
        raise ValueError("duplicate expected inventory artifact after casefold")
    return artifacts


@dataclass(frozen=True)
class InventoryRunRequest:
    run_id: str
    canonical_bytes: bytes
    sha256: str
    expected_artifacts: Tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_run_id(self.run_id)
        if type(self.canonical_bytes) is not bytes:
            raise ValueError("inventory request bytes must be immutable bytes")
        if not isinstance(self.sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.sha256
        ):
            raise ValueError("inventory request hash is invalid")
        if self.sha256 != _sha256(self.canonical_bytes):
            raise ValueError("inventory request hash does not match bytes")
        if type(self.expected_artifacts) is not tuple:
            raise ValueError("expected inventory artifacts must be immutable")
        normalized_artifacts = _validate_expected_artifacts(self.expected_artifacts)
        if normalized_artifacts != self.expected_artifacts:
            raise ValueError("expected inventory artifacts are noncanonical")

        def reject_constant(_value: str) -> None:
            raise ValueError("non-finite request JSON")

        try:
            payload = json.loads(
                self.canonical_bytes.decode("utf-8"),
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("inventory request JSON is invalid") from exc
        expected_fields = {
            "schema_version",
            "package_version",
            "run_id",
            "policy_authority",
            "scope",
            "bounds",
            "expected_artifacts",
            "openable",
            "approval_ready",
        }
        if not isinstance(payload, dict) or set(payload) != expected_fields:
            raise ValueError("inventory request contract is invalid")
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["package_version"] != PACKAGE_VERSION
            or payload["run_id"] != self.run_id
            or type(payload["policy_authority"]) is not dict
            or type(payload["scope"]) is not dict
            or payload["openable"] is not False
            or payload["approval_ready"] is not False
            or payload["expected_artifacts"] != list(self.expected_artifacts)
        ):
            raise ValueError("inventory request contract is invalid")
        _validate_request_bounds(payload["bounds"])
        if self.canonical_bytes != _canonical_json_bytes(payload):
            raise ValueError("inventory request JSON is noncanonical")

    @classmethod
    def create(
        cls,
        run_id: str,
        policy_authority: Mapping[str, Any],
        scope: Mapping[str, Any],
        bounds: Mapping[str, Any],
        expected_artifacts: Iterable[str],
    ) -> "InventoryRunRequest":
        _validate_run_id(run_id)
        if not isinstance(policy_authority, Mapping) or not isinstance(scope, Mapping):
            raise ValueError("policy authority and scope must be mappings")
        normalized_bounds = _validate_request_bounds(bounds)
        artifacts = _validate_expected_artifacts(tuple(expected_artifacts))
        payload = {
            "schema_version": 1,
            "package_version": PACKAGE_VERSION,
            "run_id": run_id,
            "policy_authority": policy_authority,
            "scope": scope,
            "bounds": normalized_bounds,
            "expected_artifacts": list(artifacts),
            "openable": False,
            "approval_ready": False,
        }
        canonical = _canonical_json_bytes(payload)
        return cls(run_id, canonical, _sha256(canonical), artifacts)


@dataclass(frozen=True)
class InventoryTerminal:
    run_id: str
    state: str
    path: str
    package_sha256: str
    openable: bool = False
    approval_ready: bool = False


@dataclass(frozen=True)
class InventoryPackageReadback:
    terminal: InventoryTerminal
    request: InventoryRunRequest
    artifacts: Tuple[Tuple[str, bytes], ...]

    def __post_init__(self) -> None:
        if type(self.terminal) is not InventoryTerminal:
            raise TypeError("terminal must be InventoryTerminal")
        if type(self.request) is not InventoryRunRequest:
            raise TypeError("request must be InventoryRunRequest")
        if (
            type(self.artifacts) is not tuple
            or tuple(sorted(self.artifacts)) != self.artifacts
            or tuple(name for name, _encoded in self.artifacts)
            != self.request.expected_artifacts
            or any(type(encoded) is not bytes for _name, encoded in self.artifacts)
        ):
            raise ValueError("inventory package artifacts are invalid")


def _verify_owner_directory(value: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise RunIntegrityError("%s is not a directory" % label)
    if value.st_uid != os.getuid():
        raise RunIntegrityError("%s owner mismatch" % label)
    if stat.S_IMODE(value.st_mode) != 0o700:
        raise RunIntegrityError("%s mode must be 0700" % label)


def _verify_owner_file(value: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise RunIntegrityError("%s is not a regular file" % label)
    if value.st_uid != os.getuid():
        raise RunIntegrityError("%s owner mismatch" % label)
    if stat.S_IMODE(value.st_mode) != 0o600:
        raise RunIntegrityError("%s mode must be 0600" % label)
    if value.st_nlink != 1:
        raise RunIntegrityError("%s link count mismatch" % label)


def _lstat_at(parent_fd: int, name: str) -> Optional[os.stat_result]:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _require_open_file_lexical_identity(
    parent_fd: int,
    name: str,
    file_fd: int,
    label: str,
) -> None:
    opened_stat = os.fstat(file_fd)
    _verify_owner_file(opened_stat, label)
    try:
        lexical_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise RunIntegrityError("%s lexical identity unavailable" % label) from exc
    _verify_owner_file(lexical_stat, label)
    if FileIdentity.from_stat(opened_stat) != FileIdentity.from_stat(lexical_stat):
        raise RunIntegrityError("%s lexical identity mismatch" % label)


def _open_directory_at(parent_fd: int, name: str, label: str) -> int:
    try:
        value = _open_relative(name, _required_open_flags(directory=True), parent_fd)
    except OSError as exc:
        raise RunIntegrityError("cannot open %s safely" % label) from exc
    try:
        _verify_owner_directory(os.fstat(value), label)
    except Exception:
        os.close(value)
        raise
    return value


def _create_owner_directory_at(parent_fd: int, name: str, label: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError as exc:
        raise RunCollisionError("%s already exists" % label) from exc
    value = None
    try:
        value = _open_relative(name, _required_open_flags(directory=True), parent_fd)
        os.fchmod(value, 0o700)
        _verify_owner_directory(os.fstat(value), label)
        os.fsync(parent_fd)
        return value
    except Exception:
        if value is not None:
            os.close(value)
        raise


def _read_all_file_at(parent_fd: int, name: str, label: str) -> bytes:
    try:
        fd = _open_relative(name, _required_open_flags(directory=False), parent_fd)
    except OSError as exc:
        raise RunIntegrityError("cannot open %s safely" % label) from exc
    try:
        before_stat = os.fstat(fd)
        _verify_owner_file(before_stat, label)
        before = FileIdentity.from_stat(before_stat)
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_CONTROL_FILE_BYTES:
                raise RunIntegrityError("%s exceeds control-file bound" % label)
            chunks.append(chunk)
        payload = b"".join(chunks)
        after_stat = os.fstat(fd)
        _verify_owner_file(after_stat, label)
        if not _same_identity(before, FileIdentity.from_stat(after_stat)):
            raise RunIntegrityError("%s changed during readback" % label)
        return payload
    finally:
        os.close(fd)


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        offset += written


def _write_once(parent_fd: int, name: str, payload: bytes, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = _open_relative(name, flags, parent_fd, 0o600)
    except FileExistsError:
        existing = _read_all_file_at(parent_fd, name, label)
        if existing != payload:
            raise RunIntegrityError("%s existing bytes mismatch" % label)
        return
    try:
        os.fchmod(fd, 0o600)
        _verify_owner_file(os.fstat(fd), label)
        _write_all(fd, payload)
        os.fsync(fd)
        if os.fstat(fd).st_size != len(payload):
            raise RunIntegrityError("%s size readback mismatch" % label)
    finally:
        os.close(fd)
    readback = _read_all_file_at(parent_fd, name, label)
    if readback != payload:
        raise RunIntegrityError("%s byte readback mismatch" % label)


def _write_resumable_request(
    parent_fd: int,
    payload: bytes,
    checkpoint: Callable[[str, Mapping[str, Any]], None],
    run_id: str,
) -> None:
    created = False
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = _open_relative(
            "request.json",
            flags | os.O_CREAT | os.O_EXCL,
            parent_fd,
            0o600,
        )
        created = True
    except FileExistsError:
        try:
            fd = _open_relative("request.json", flags, parent_fd)
        except OSError as exc:
            raise RunIntegrityError("cannot open inventory request safely") from exc
    try:
        os.fchmod(fd, 0o600)
        _verify_owner_file(os.fstat(fd), "inventory request")
        if created:
            os.fsync(parent_fd)
            checkpoint(
                "request-after-create",
                {"run_id": run_id, "bytes_written": 0, "total_bytes": len(payload)},
            )
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > len(payload):
                raise RunRequestMismatchError("inventory request is not an exact prefix")
            chunks.append(chunk)
        existing = b"".join(chunks)
        if not payload.startswith(existing):
            raise RunRequestMismatchError("inventory request is not an exact prefix")
        offset = len(existing)
        os.lseek(fd, offset, os.SEEK_SET)
        while offset < len(payload):
            remaining = len(payload) - offset
            write_size = max(1, (remaining + 1) // 2)
            written = os.write(fd, payload[offset : offset + write_size])
            if written <= 0:
                raise OSError(errno.EIO, "short request write")
            offset += written
            if offset < len(payload):
                checkpoint(
                    "request-after-partial-write",
                    {
                        "run_id": run_id,
                        "bytes_written": offset,
                        "total_bytes": len(payload),
                    },
                )
        checkpoint(
            "request-before-fsync",
            {
                "run_id": run_id,
                "bytes_written": offset,
                "total_bytes": len(payload),
            },
        )
        os.fsync(fd)
    finally:
        os.close(fd)
    check_fd = _open_relative(
        "request.json",
        _required_open_flags(directory=False),
        parent_fd,
    )
    try:
        _require_open_file_lexical_identity(
            parent_fd,
            "request.json",
            check_fd,
            "inventory request",
        )
    finally:
        os.close(check_fd)
    readback = _read_all_file_at(parent_fd, "request.json", "inventory request")
    if readback != payload:
        raise RunRequestMismatchError("inventory request bytes changed")


_CHUNK_FIELDS = frozenset(
    (
        "schema_version",
        "package_version",
        "run_id",
        "request_sha256",
        "sequence",
        "previous_chunk_sha256",
        "cursor_before",
        "cursor_after",
        "source_identities",
        "source_identities_sha256",
        "payload",
    )
)
_CHECKPOINT_FIELDS = frozenset(
    (
        "schema_version",
        "package_version",
        "run_id",
        "request_sha256",
        "sequence",
        "previous_checkpoint_sha256",
        "chunk_sha256",
        "chunk_manifest_sha256",
        "completed_prefix_sha256",
        "source_identity_prefix_sha256",
        "next_cursor",
        "counters",
    )
)
_COUNTER_FIELDS = frozenset(("observations", "content_bytes"))


@dataclass(frozen=True)
class _ResumabilityState:
    chunks: Tuple[bytes, ...]
    chunk_objects: Tuple[Mapping[str, Any], ...]
    checkpoints: Tuple[bytes, ...]
    checkpoint_objects: Tuple[Mapping[str, Any], ...]


def _load_canonical_json_object(raw: bytes, code: str) -> Mapping[str, Any]:
    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RunProvenanceError(code) from exc
    if not isinstance(value, dict):
        raise RunProvenanceError(code)
    try:
        canonical = _canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise RunProvenanceError(code) from exc
    if canonical != raw:
        raise RunProvenanceError(code)
    return value


def _validate_cursor(value: Any, allow_terminal: bool = True) -> Optional[Tuple[bytes, ...]]:
    if value is None:
        if allow_terminal:
            return None
        raise RunProvenanceError("cursor-terminal-not-allowed")
    if not isinstance(value, str):
        raise RunProvenanceError("cursor-invalid")
    try:
        return decode_canonical_raw_path(value)
    except ValueError as exc:
        raise RunProvenanceError("cursor-invalid") from exc


def _validate_counters(value: Any) -> Dict[str, int]:
    if not isinstance(value, dict) or set(value) != _COUNTER_FIELDS:
        raise RunProvenanceError("checkpoint-counters-invalid")
    result = {}
    for key in sorted(_COUNTER_FIELDS):
        counter = value[key]
        if type(counter) is not int or counter < 0:
            raise RunProvenanceError("checkpoint-counters-invalid")
        result[key] = counter
    return result


def _validate_source_identities(value: Any) -> Tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise RunProvenanceError("chunk-source-identities-invalid")
    result = []
    previous_path = None
    identity_fields = frozenset(("device", "inode", "mode", "size", "mtime_ns"))
    for row in value:
        if not isinstance(row, dict) or set(row) != {"path", "identity"}:
            raise RunProvenanceError("chunk-source-identities-invalid")
        path = row["path"]
        components = _validate_cursor(path, allow_terminal=False)
        assert components is not None
        if previous_path is not None and components <= previous_path:
            raise RunProvenanceError("chunk-source-identities-order-invalid")
        previous_path = components
        identity = row["identity"]
        if not isinstance(identity, dict) or set(identity) != identity_fields:
            raise RunProvenanceError("chunk-source-identities-invalid")
        for field in identity_fields:
            item = identity[field]
            if type(item) is not int or item < 0:
                raise RunProvenanceError("chunk-source-identities-invalid")
        result.append(row)
    return tuple(result)


def _sequence_payloads(
    staging_fd: int,
    directory: str,
) -> Tuple[bytes, ...]:
    child_fd = _open_directory_at(staging_fd, directory, directory)
    try:
        names = sorted(os.listdir(child_fd))
        for name in names:
            if not _SEQUENCE_RE.fullmatch(name):
                raise RunProvenanceError("%s-name-invalid" % directory)
        expected = ["%08d.json" % index for index in range(len(names))]
        if names != expected:
            raise RunProvenanceError("%s-sequence-gap" % directory)
        return tuple(
            _read_all_file_at(child_fd, name, "%s/%s" % (directory, name))
            for name in names
        )
    finally:
        os.close(child_fd)


def _load_resumability_state(
    staging_fd: int,
    request: InventoryRunRequest,
    allow_uncheckpointed_chunk: bool,
) -> _ResumabilityState:
    chunks = _sequence_payloads(staging_fd, "chunks")
    checkpoints = _sequence_payloads(staging_fd, "checkpoints")
    if len(checkpoints) > len(chunks):
        raise RunProvenanceError("checkpoint-without-chunk")
    if len(chunks) > len(checkpoints) + int(allow_uncheckpointed_chunk):
        raise RunProvenanceError("unreferenced-chunk")
    if not allow_uncheckpointed_chunk and len(chunks) != len(checkpoints):
        raise RunProvenanceError("unreferenced-chunk")

    chunk_objects = []
    checkpoint_objects = []
    chunk_hashes = []
    checkpoint_hashes = []
    source_hashes = []
    previous_cursor: Optional[str] = canonical_raw_path(())
    previous_source_path: Optional[Tuple[bytes, ...]] = None
    previous_counters = {"observations": 0, "content_bytes": 0}
    previous_completed_prefix = None

    for sequence, raw in enumerate(chunks):
        value = _load_canonical_json_object(raw, "chunk-json-noncanonical")
        if set(value) != _CHUNK_FIELDS:
            raise RunProvenanceError("chunk-contract-invalid")
        expected_previous = None if sequence == 0 else chunk_hashes[-1]
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["package_version"] != PACKAGE_VERSION
            or value["run_id"] != request.run_id
            or value["request_sha256"] != request.sha256
            or type(value["sequence"]) is not int
            or value["sequence"] != sequence
            or value["previous_chunk_sha256"] != expected_previous
        ):
            raise RunProvenanceError("chunk-chain-invalid")
        before_components = _validate_cursor(value["cursor_before"], allow_terminal=False)
        after_components = _validate_cursor(value["cursor_after"], allow_terminal=True)
        if value["cursor_before"] != previous_cursor:
            raise RunProvenanceError("chunk-cursor-prefix-invalid")
        assert before_components is not None
        if after_components is not None and after_components <= before_components:
            raise RunProvenanceError("chunk-cursor-order-invalid")
        if sequence + 1 < len(chunks) and after_components is None:
            raise RunProvenanceError("chunk-cursor-terminal-early")
        source_identities = _validate_source_identities(value["source_identities"])
        for source_row in source_identities:
            source_path = _validate_cursor(
                source_row["path"], allow_terminal=False
            )
            assert source_path is not None
            root_binding = (
                sequence == 0
                and source_path == ()
                and before_components == ()
            )
            if source_path < before_components or (
                source_path == before_components and not root_binding
            ):
                raise RunProvenanceError("chunk-source-before-cursor")
            if after_components is not None and source_path > after_components:
                raise RunProvenanceError("chunk-source-after-cursor")
            if previous_source_path is not None and source_path <= previous_source_path:
                raise RunProvenanceError("chunk-source-global-order-invalid")
            previous_source_path = source_path
        expected_source_hash = _sha256(_canonical_json_bytes(source_identities))
        if value["source_identities_sha256"] != expected_source_hash:
            raise RunProvenanceError("chunk-source-identity-hash-invalid")
        if not isinstance(value["payload"], dict):
            raise RunProvenanceError("chunk-payload-invalid")
        chunk_objects.append(value)
        chunk_hashes.append(_sha256(raw))
        source_hashes.append(expected_source_hash)

        if sequence < len(checkpoints):
            checkpoint_raw = checkpoints[sequence]
            checkpoint = _load_canonical_json_object(
                checkpoint_raw, "checkpoint-json-noncanonical"
            )
            if set(checkpoint) != _CHECKPOINT_FIELDS:
                raise RunProvenanceError("checkpoint-contract-invalid")
            counters = _validate_counters(checkpoint["counters"])
            if any(counters[key] < previous_counters[key] for key in _COUNTER_FIELDS):
                raise RunProvenanceError("checkpoint-counters-regressed")
            expected_previous_checkpoint = (
                None if sequence == 0 else checkpoint_hashes[-1]
            )
            chunk_manifest_hash = _sha256(_canonical_json_bytes(chunk_hashes))
            source_prefix_hash = _sha256(_canonical_json_bytes(source_hashes))
            prefix_payload = {
                "previous_completed_prefix_sha256": previous_completed_prefix,
                "chunk_manifest_sha256": chunk_manifest_hash,
                "source_identity_prefix_sha256": source_prefix_hash,
                "next_cursor": value["cursor_after"],
                "counters": counters,
            }
            completed_prefix_hash = _sha256(_canonical_json_bytes(prefix_payload))
            if (
                type(checkpoint["schema_version"]) is not int
                or checkpoint["schema_version"] != 1
                or checkpoint["package_version"] != PACKAGE_VERSION
                or checkpoint["run_id"] != request.run_id
                or checkpoint["request_sha256"] != request.sha256
                or type(checkpoint["sequence"]) is not int
                or checkpoint["sequence"] != sequence
                or checkpoint["previous_checkpoint_sha256"]
                != expected_previous_checkpoint
                or checkpoint["chunk_sha256"] != chunk_hashes[-1]
                or checkpoint["chunk_manifest_sha256"] != chunk_manifest_hash
                or checkpoint["source_identity_prefix_sha256"]
                != source_prefix_hash
                or checkpoint["completed_prefix_sha256"] != completed_prefix_hash
                or checkpoint["next_cursor"] != value["cursor_after"]
            ):
                raise RunProvenanceError("checkpoint-chain-invalid")
            checkpoint_objects.append(checkpoint)
            checkpoint_hashes.append(_sha256(checkpoint_raw))
            previous_counters = counters
            previous_completed_prefix = completed_prefix_hash
            previous_cursor = checkpoint["next_cursor"]

    return _ResumabilityState(
        chunks,
        tuple(chunk_objects),
        checkpoints,
        tuple(checkpoint_objects),
    )


def _require_complete_resumability(state: _ResumabilityState) -> None:
    if not state.chunks or len(state.chunks) != len(state.checkpoints):
        raise RunStateError("complete inventory requires checkpointed observations")
    terminal = state.checkpoint_objects[-1]
    if terminal["next_cursor"] is not None:
        raise RunStateError("complete inventory requires a terminal cursor")
    counters = terminal["counters"]
    if counters["observations"] < 1:
        raise RunStateError("complete inventory counters must include the root")


class InventoryRunStore:
    """Exclusive staging and immutable terminal publication under one runs root."""

    def __init__(
        self,
        runs_root: Union[str, bytes, os.PathLike],
        fault_checkpoint: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
    ) -> None:
        self.runs_root = os.fspath(runs_root)
        runs_path = Path(os.fsdecode(self.runs_root))
        if (
            not runs_path.is_absolute()
            or runs_path.name != "curation-runs"
            or runs_path.parent.name != "_registry"
        ):
            raise ValueError("inventory runs root must be raw/_registry/curation-runs")
        self.source_root = runs_path.parent.parent
        self.fault_checkpoint = fault_checkpoint

    def _checkpoint(self, event: str, details: Mapping[str, Any]) -> None:
        if self.fault_checkpoint is not None:
            self.fault_checkpoint(event, details)

    def _require_root_lexical_identity(self, root_fd: int) -> None:
        _safety_core.require_same_directory_identity(
            Path(os.fsdecode(self.runs_root)),
            root_fd,
            "inventory runs root",
            error_type=RunIntegrityError,
        )

    def _require_staging_lexical_identity(
        self, root_fd: int, staging_fd: int, staging_name: str
    ) -> None:
        self._require_root_lexical_identity(root_fd)
        _safety_core.require_same_directory_identity(
            Path(os.fsdecode(self.runs_root)) / staging_name,
            staging_fd,
            "inventory staging",
            error_type=RunIntegrityError,
        )

    def _open_root(self) -> int:
        try:
            fd = _open_directory_path_nofollow(self.runs_root)
        except OSError as exc:
            raise RunIntegrityError("cannot open inventory runs root safely") from exc
        try:
            _verify_owner_directory(os.fstat(fd), "inventory runs root")
        except Exception:
            os.close(fd)
            raise
        return fd

    def _verify_live_source_identities(
        self,
        staging_fd: int,
        request: InventoryRunRequest,
    ) -> None:
        state = _load_resumability_state(
            staging_fd,
            request,
            allow_uncheckpointed_chunk=False,
        )
        root_fd = _open_directory_path_nofollow(self.source_root)
        try:
            _safety_core.require_same_directory_identity(
                self.source_root,
                root_fd,
                "inventory source root",
                error_type=RunProvenanceError,
            )
            root_device = os.fstat(root_fd).st_dev
            for chunk in state.chunk_objects:
                for source_row in chunk["source_identities"]:
                    components = decode_canonical_raw_path(source_row["path"])
                    if not components:
                        observed_stat = os.fstat(root_fd)
                    else:
                        current_fd = os.dup(root_fd)
                        try:
                            for component in components[:-1]:
                                next_fd = _open_relative(
                                    component,
                                    _required_open_flags(directory=True),
                                    current_fd,
                                )
                                os.close(current_fd)
                                current_fd = next_fd
                            observed_stat = os.stat(
                                components[-1],
                                dir_fd=current_fd,
                                follow_symlinks=False,
                            )
                        except (OSError, InventorySafetyError) as exc:
                            raise RunProvenanceError(
                                "source-identity-unavailable"
                            ) from exc
                        finally:
                            os.close(current_fd)
                    observed = FileIdentity.from_stat(observed_stat)
                    expected_mapping = source_row["identity"]
                    expected = FileIdentity(
                        expected_mapping["device"],
                        expected_mapping["inode"],
                        expected_mapping["mode"],
                        expected_mapping["size"],
                        expected_mapping["mtime_ns"],
                    )
                    if observed.device != root_device or observed != expected:
                        raise RunProvenanceError("source-identity-stale")
            _safety_core.require_same_directory_identity(
                self.source_root,
                root_fd,
                "inventory source root",
                error_type=RunProvenanceError,
            )
        finally:
            os.close(root_fd)

    @staticmethod
    def _sealed_request_from_bytes(raw: bytes) -> Optional[InventoryRunRequest]:
        try:
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                return None
            run_id = payload.get("run_id")
            artifacts = payload.get("expected_artifacts")
            if not isinstance(run_id, str) or not isinstance(artifacts, list):
                return None
            return InventoryRunRequest(
                run_id=run_id,
                canonical_bytes=raw,
                sha256=_sha256(raw),
                expected_artifacts=tuple(artifacts),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return None

    def _quarantine_staging_entries(
        self,
        staging_fd: int,
        names: Sequence[str],
        reason: str,
    ) -> None:
        unique_names = tuple(sorted(set(names)))
        if not unique_names:
            return
        corrupt_stat = _lstat_at(staging_fd, "corrupt")
        if corrupt_stat is None:
            corrupt_fd = _create_owner_directory_at(
                staging_fd,
                "corrupt",
                "inventory corrupt evidence",
            )
        else:
            corrupt_fd = _open_directory_at(
                staging_fd,
                "corrupt",
                "inventory corrupt evidence",
            )
        rows = []
        try:
            existing_count = len(os.listdir(corrupt_fd))
            for offset, name in enumerate(unique_names):
                value = _lstat_at(staging_fd, name)
                if value is None:
                    continue
                raw_name = os.fsencode(name)
                destination = "%08d-%s" % (
                    existing_count + offset,
                    _sha256(raw_name)[:16],
                )
                if _lstat_at(corrupt_fd, destination) is not None:
                    raise RunIntegrityError("corrupt evidence destination collision")
                os.rename(
                    name,
                    destination,
                    src_dir_fd=staging_fd,
                    dst_dir_fd=corrupt_fd,
                )
                rows.append(
                    {
                        "original_name": _encode_component(raw_name),
                        "quarantined_name": destination,
                        "physical_kind": _physical_kind(value.st_mode),
                        "identity": FileIdentity.from_stat(value).to_dict(),
                    }
                )
            os.fsync(corrupt_fd)
            os.fsync(staging_fd)
        finally:
            os.close(corrupt_fd)
        index_payload = {
            "schema_version": 1,
            "package_version": PACKAGE_VERSION,
            "reason": reason,
            "entries": rows,
        }
        _write_once(
            staging_fd,
            "corrupt-index.json",
            _canonical_json_bytes(index_payload),
            "inventory corrupt index",
        )
        os.fsync(staging_fd)

    def _failed_fd(self, root_fd: int, create: bool) -> Optional[int]:
        current = _lstat_at(root_fd, "failed")
        if current is None and not create:
            return None
        if current is None:
            try:
                created_fd = _create_owner_directory_at(
                    root_fd, "failed", "failed run directory"
                )
            except FileExistsError:
                pass
            except RunCollisionError:
                pass
            else:
                os.close(created_fd)
        return _open_directory_at(root_fd, "failed", "failed run directory")

    def _existing_terminal(
        self, root_fd: int, request: InventoryRunRequest
    ) -> Optional[InventoryTerminal]:
        self._require_root_lexical_identity(root_fd)
        final_stat = _lstat_at(root_fd, request.run_id)
        failed_fd = self._failed_fd(root_fd, create=False)
        try:
            failed_stat = None if failed_fd is None else _lstat_at(failed_fd, request.run_id)
            if final_stat is not None and failed_stat is not None:
                raise RunIntegrityError("both complete and failed terminal paths exist")
            if final_stat is not None:
                self._checkpoint(
                    "terminal-discovered-before-open",
                    {"run_id": request.run_id, "state": "complete"},
                )
                result = self._read_terminal(
                    root_fd,
                    request.run_id,
                    request,
                    "complete",
                    _safety_core.source_identity(final_stat),
                )
                self._require_root_lexical_identity(root_fd)
                return result
            if failed_stat is not None and failed_fd is not None:
                _safety_core.require_same_directory_identity(
                    Path(os.fsdecode(self.runs_root)) / "failed",
                    failed_fd,
                    "failed inventory runs root",
                    error_type=RunIntegrityError,
                )
                self._checkpoint(
                    "terminal-discovered-before-open",
                    {"run_id": request.run_id, "state": "failed"},
                )
                result = self._read_terminal(
                    failed_fd,
                    request.run_id,
                    request,
                    "failed",
                    _safety_core.source_identity(failed_stat),
                )
                _safety_core.require_same_directory_identity(
                    Path(os.fsdecode(self.runs_root)) / "failed",
                    failed_fd,
                    "failed inventory runs root",
                    error_type=RunIntegrityError,
                )
                self._require_root_lexical_identity(root_fd)
                return result
            return None
        finally:
            if failed_fd is not None:
                os.close(failed_fd)

    def start(self, request: InventoryRunRequest) -> "InventoryRunSession":
        root_fd = self._open_root()
        staging_name = ".incomplete-%s" % request.run_id
        try:
            if self._existing_terminal(root_fd, request) is not None:
                raise RunCollisionError("inventory run is already terminal")
            if _lstat_at(root_fd, staging_name) is not None:
                raise RunCollisionError("inventory staging path already exists")
            staging_fd = _create_owner_directory_at(
                root_fd, staging_name, "inventory staging"
            )
            lock_fd = None
            try:
                self._checkpoint(
                    "start-after-staging-mkdir",
                    {"run_id": request.run_id},
                )
                lock_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
                lock_fd = _open_relative("run.lock", lock_flags, staging_fd, 0o600)
                os.fchmod(lock_fd, 0o600)
                _verify_owner_file(os.fstat(lock_fd), "inventory run lock")
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.fsync(lock_fd)
                os.fsync(staging_fd)
                self._checkpoint(
                    "start-after-run-lock",
                    {"run_id": request.run_id},
                )
                _write_resumable_request(
                    staging_fd,
                    request.canonical_bytes,
                    self._checkpoint,
                    request.run_id,
                )
                os.fsync(staging_fd)
                self._checkpoint(
                    "start-after-request",
                    {"run_id": request.run_id},
                )
                for directory in ("chunks", "checkpoints"):
                    child_fd = _create_owner_directory_at(
                        staging_fd, directory, directory
                    )
                    os.close(child_fd)
                    os.fsync(staging_fd)
                    self._checkpoint(
                        "start-after-child-directory",
                        {"run_id": request.run_id, "directory": directory},
                    )
                os.fsync(staging_fd)
                _require_open_file_lexical_identity(
                    staging_fd,
                    "run.lock",
                    lock_fd,
                    "inventory run lock",
                )
                self._require_staging_lexical_identity(
                    root_fd,
                    staging_fd,
                    staging_name,
                )
            except Exception:
                if lock_fd is not None:
                    os.close(lock_fd)
                os.close(staging_fd)
                raise
            return InventoryRunSession(
                self,
                request,
                root_fd,
                staging_fd,
                lock_fd,
                staging_name,
            )
        except Exception:
            os.close(root_fd)
            raise

    def resume(
        self, request: InventoryRunRequest
    ) -> Union["InventoryRunSession", InventoryTerminal]:
        root_fd = self._open_root()
        staging_name = ".incomplete-%s" % request.run_id
        try:
            terminal = self._existing_terminal(root_fd, request)
            if terminal is not None:
                os.close(root_fd)
                return terminal
            staging_fd = _open_directory_at(root_fd, staging_name, "inventory staging")
            lock_fd = None
            try:
                lock_stat = _lstat_at(staging_fd, "run.lock")
                if lock_stat is None:
                    try:
                        lock_fd = _open_relative(
                            "run.lock",
                            os.O_RDWR
                            | os.O_CREAT
                            | os.O_EXCL
                            | os.O_NOFOLLOW
                            | os.O_CLOEXEC,
                            staging_fd,
                            0o600,
                        )
                        os.fchmod(lock_fd, 0o600)
                        os.fsync(lock_fd)
                        os.fsync(staging_fd)
                    except FileExistsError:
                        lock_fd = None
                if lock_fd is None:
                    try:
                        lock_fd = _open_relative(
                            "run.lock",
                            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                            staging_fd,
                        )
                    except OSError as exc:
                        raise RunIntegrityError("cannot open inventory run lock") from exc
                _verify_owner_file(os.fstat(lock_fd), "inventory run lock")
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    os.close(lock_fd)
                    lock_fd = None
                    raise RunBusyError("inventory run is active") from exc
                corrupt_names = []
                request_stat = _lstat_at(staging_fd, "request.json")
                if request_stat is not None:
                    try:
                        _verify_owner_file(request_stat, "inventory request")
                    except RunIntegrityError:
                        corrupt_names.append("request.json")
                if "request.json" not in corrupt_names:
                    try:
                        _write_resumable_request(
                            staging_fd,
                            request.canonical_bytes,
                            self._checkpoint,
                            request.run_id,
                        )
                    except RunRequestMismatchError:
                        stored = _read_all_file_at(
                            staging_fd,
                            "request.json",
                            "inventory request",
                        )
                        sealed = self._sealed_request_from_bytes(stored)
                        if sealed is not None:
                            os.close(lock_fd)
                            lock_fd = None
                            raise RunRequestMismatchError(
                                "inventory request bytes changed"
                            )
                        corrupt_names.append("request.json")
                for directory in ("chunks", "checkpoints"):
                    child_stat = _lstat_at(staging_fd, directory)
                    if child_stat is not None:
                        try:
                            _verify_owner_directory(child_stat, directory)
                        except RunIntegrityError:
                            corrupt_names.append(directory)
                allowed_preterminal = {
                    "run.lock",
                    "request.json",
                    "chunks",
                    "checkpoints",
                    "run.json",
                    "manifest.jsonl",
                    "failure.json",
                } | set(request.expected_artifacts)
                unexpected = set(os.listdir(staging_fd)) - allowed_preterminal
                corrupt_names.extend(unexpected)
                if corrupt_names:
                    self._quarantine_staging_entries(
                        staging_fd,
                        corrupt_names,
                        "staging-integrity-invalid",
                    )
                if _lstat_at(staging_fd, "request.json") is None:
                    _write_resumable_request(
                        staging_fd,
                        request.canonical_bytes,
                        self._checkpoint,
                        request.run_id,
                    )
                for directory in ("chunks", "checkpoints"):
                    child_stat = _lstat_at(staging_fd, directory)
                    if child_stat is None:
                        child_fd = _create_owner_directory_at(
                            staging_fd,
                            directory,
                            directory,
                        )
                        os.close(child_fd)
                os.fsync(staging_fd)
                if corrupt_names:
                    session = InventoryRunSession(
                        self,
                        request,
                        root_fd,
                        staging_fd,
                        lock_fd,
                        staging_name,
                    )
                    root_fd = -1
                    staging_fd = -1
                    lock_fd = None
                    with session:
                        return session.fail(
                            "staging-integrity-invalid",
                            {"quarantined_entry_count": len(set(corrupt_names))},
                        )
                try:
                    self._validate_staging_layout(
                        staging_fd,
                        request,
                        validate_provenance=True,
                        allow_uncheckpointed_chunk=False,
                    )
                    self._verify_live_source_identities(staging_fd, request)
                except RunProvenanceError as exc:
                    session = InventoryRunSession(
                        self,
                        request,
                        root_fd,
                        staging_fd,
                        lock_fd,
                        staging_name,
                    )
                    root_fd = -1
                    staging_fd = -1
                    lock_fd = None
                    with session:
                        return session.fail(
                            "resume-provenance-invalid",
                            {"code": exc.code},
                        )
                except RunIntegrityError as exc:
                    preserve = {"run.lock", "request.json"}
                    quarantine = [
                        name
                        for name in os.listdir(staging_fd)
                        if name not in preserve
                    ]
                    self._quarantine_staging_entries(
                        staging_fd,
                        quarantine,
                        "staging-structure-invalid",
                    )
                    for directory in ("chunks", "checkpoints"):
                        child_fd = _create_owner_directory_at(
                            staging_fd,
                            directory,
                            directory,
                        )
                        os.close(child_fd)
                    session = InventoryRunSession(
                        self,
                        request,
                        root_fd,
                        staging_fd,
                        lock_fd,
                        staging_name,
                    )
                    root_fd = -1
                    staging_fd = -1
                    lock_fd = None
                    with session:
                        return session.fail(
                            "staging-structure-invalid",
                            {"error_type": type(exc).__name__},
                        )
                _require_open_file_lexical_identity(
                    staging_fd,
                    "run.lock",
                    lock_fd,
                    "inventory run lock",
                )
                self._require_staging_lexical_identity(
                    root_fd,
                    staging_fd,
                    staging_name,
                )
            except Exception:
                if lock_fd is not None:
                    os.close(lock_fd)
                if staging_fd >= 0:
                    os.close(staging_fd)
                raise
            return InventoryRunSession(
                self,
                request,
                root_fd,
                staging_fd,
                lock_fd,
                staging_name,
            )
        except Exception:
            if root_fd >= 0:
                os.close(root_fd)
            raise

    def _terminal_request(
        self,
        parent_fd: int,
        name: str,
        expected_terminal_identity: Tuple[int, int, int],
    ) -> InventoryRunRequest:
        terminal_fd = _open_directory_at(parent_fd, name, "inventory terminal")
        try:
            opened_identity = _safety_core.source_identity(os.fstat(terminal_fd))
            if opened_identity != expected_terminal_identity:
                raise RunIntegrityError("terminal identity changed before request read")
            raw = _read_all_file_at(
                terminal_fd,
                "request.json",
                "inventory request",
            )
            request = self._sealed_request_from_bytes(raw)
            if request is None or request.run_id != name:
                raise RunIntegrityError("terminal inventory request is invalid")
            try:
                lexical = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                raise RunIntegrityError(
                    "terminal lexical identity disappeared"
                ) from exc
            if _safety_core.source_identity(lexical) != opened_identity:
                raise RunIntegrityError(
                    "terminal identity changed during request read"
                )
            return request
        finally:
            os.close(terminal_fd)

    def open_terminal(
        self,
        run_id: str,
        *,
        require_complete: bool = True,
    ) -> InventoryTerminal:
        """Read and fully verify a sealed run without caller-supplied request bytes."""

        if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
            raise ValueError("inventory run id is invalid")
        if type(require_complete) is not bool:
            raise TypeError("require_complete must be boolean")
        root_fd = self._open_root()
        failed_fd = None
        try:
            self._require_root_lexical_identity(root_fd)
            final_stat = _lstat_at(root_fd, run_id)
            failed_fd = self._failed_fd(root_fd, create=False)
            failed_stat = None if failed_fd is None else _lstat_at(failed_fd, run_id)
            if final_stat is not None and failed_stat is not None:
                raise RunIntegrityError(
                    "both complete and failed terminal paths exist"
                )
            if final_stat is not None:
                parent_fd = root_fd
                expected_state = "complete"
                terminal_stat = final_stat
            elif failed_stat is not None and failed_fd is not None:
                parent_fd = failed_fd
                expected_state = "failed"
                terminal_stat = failed_stat
            else:
                raise RunStateError("inventory run is not terminal")
            identity = _safety_core.source_identity(terminal_stat)
            request = self._terminal_request(parent_fd, run_id, identity)
            terminal = self._read_terminal(
                parent_fd,
                run_id,
                request,
                expected_state,
                identity,
            )
            if require_complete and terminal.state != "complete":
                raise RunStateError("inventory terminal is not complete")
            self._require_root_lexical_identity(root_fd)
            return terminal
        finally:
            if failed_fd is not None:
                os.close(failed_fd)
            os.close(root_fd)

    def read_complete_package(self, run_id: str) -> InventoryPackageReadback:
        """Verify and read the bounded M1 artifacts from one complete sealed run."""

        self.open_terminal(run_id, require_complete=True)
        root_fd = self._open_root()
        terminal_fd = None
        try:
            self._require_root_lexical_identity(root_fd)
            terminal_stat = _lstat_at(root_fd, run_id)
            if terminal_stat is None:
                raise RunStateError("complete inventory terminal disappeared")
            identity = _safety_core.source_identity(terminal_stat)
            request = self._terminal_request(root_fd, run_id, identity)
            before = self._read_terminal(
                root_fd,
                run_id,
                request,
                "complete",
                identity,
            )
            terminal_fd = _open_directory_at(
                root_fd,
                run_id,
                "inventory terminal",
            )
            if _safety_core.source_identity(os.fstat(terminal_fd)) != identity:
                raise RunIntegrityError(
                    "terminal identity changed before artifact read"
                )
            artifacts = tuple(
                (
                    name,
                    _read_all_file_at(
                        terminal_fd,
                        name,
                        "inventory artifact",
                    ),
                )
                for name in request.expected_artifacts
            )
            try:
                lexical = os.stat(run_id, dir_fd=root_fd, follow_symlinks=False)
            except OSError as exc:
                raise RunIntegrityError(
                    "terminal lexical identity disappeared"
                ) from exc
            if _safety_core.source_identity(lexical) != identity:
                raise RunIntegrityError(
                    "terminal identity changed during artifact read"
                )
            after = self._read_terminal(
                root_fd,
                run_id,
                request,
                "complete",
                identity,
            )
            if after != before:
                raise RunIntegrityError("terminal readback changed")
            self._require_root_lexical_identity(root_fd)
            return InventoryPackageReadback(after, request, artifacts)
        finally:
            if terminal_fd is not None:
                os.close(terminal_fd)
            os.close(root_fd)

    def _validate_staging_layout(
        self,
        staging_fd: int,
        request: InventoryRunRequest,
        validate_provenance: bool = True,
        allow_uncheckpointed_chunk: bool = False,
    ) -> None:
        allowed = set(
            (
                "run.lock",
                "request.json",
                "chunks",
                "checkpoints",
                "run.json",
                "manifest.jsonl",
                "failure.json",
                "corrupt",
                "corrupt-index.json",
            )
        )
        allowed.update(request.expected_artifacts)
        actual = set(os.listdir(staging_fd))
        unexpected = actual - allowed
        if unexpected:
            raise RunIntegrityError("unexpected inventory staging entries")
        for directory in ("chunks", "checkpoints"):
            child_fd = _open_directory_at(staging_fd, directory, directory)
            try:
                for name in os.listdir(child_fd):
                    if not _SEQUENCE_RE.fullmatch(name):
                        raise RunIntegrityError("unexpected resumability artifact")
                    _read_all_file_at(child_fd, name, "%s/%s" % (directory, name))
            finally:
                os.close(child_fd)
        if validate_provenance:
            _load_resumability_state(
                staging_fd,
                request,
                allow_uncheckpointed_chunk=allow_uncheckpointed_chunk,
            )
        _collect_package_files(staging_fd)

    def _read_terminal(
        self,
        parent_fd: int,
        name: str,
        request: InventoryRunRequest,
        expected_state: str,
        expected_terminal_identity: Tuple[int, int, int],
    ) -> InventoryTerminal:
        terminal_fd = _open_directory_at(parent_fd, name, "inventory terminal")
        try:
            opened_terminal_identity = _safety_core.source_identity(os.fstat(terminal_fd))
            if opened_terminal_identity != expected_terminal_identity:
                raise RunIntegrityError("terminal identity changed before open")
            actual_entries = set(os.listdir(terminal_fd))
            base_entries = {
                "run.lock",
                "request.json",
                "chunks",
                "checkpoints",
                "run.json",
                "manifest.jsonl",
            }
            if expected_state == "complete":
                expected_entries = base_entries | set(request.expected_artifacts)
                if actual_entries != expected_entries:
                    raise RunIntegrityError("complete terminal membership mismatch")
            else:
                required_entries = base_entries | {"failure.json"}
                allowed_entries = required_entries | set(request.expected_artifacts) | {
                    "corrupt",
                    "corrupt-index.json",
                }
                if not required_entries <= actual_entries or not actual_entries <= allowed_entries:
                    raise RunIntegrityError("failed terminal membership mismatch")
            stored_request = _read_all_file_at(terminal_fd, "request.json", "inventory request")
            if stored_request != request.canonical_bytes:
                raise RunRequestMismatchError("terminal inventory request mismatch")
            run_raw = _read_all_file_at(terminal_fd, "run.json", "inventory run result")
            expected_run_payload = {
                "schema_version": 1,
                "package_version": PACKAGE_VERSION,
                "run_id": request.run_id,
                "state": expected_state,
                "request_sha256": request.sha256,
                "openable": False,
                "approval_ready": False,
            }
            try:
                run_payload = json.loads(run_raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RunIntegrityError("terminal run JSON is invalid") from exc
            if run_payload != expected_run_payload or run_raw != _canonical_json_bytes(expected_run_payload):
                raise RunIntegrityError("terminal run contract mismatch")
            manifest = _read_all_file_at(terminal_fd, "manifest.jsonl", "inventory manifest")
            self._verify_manifest(terminal_fd, manifest)
            if expected_state == "complete":
                terminal_state = _load_resumability_state(
                    terminal_fd,
                    request,
                    allow_uncheckpointed_chunk=False,
                )
                _require_complete_resumability(terminal_state)
            self._checkpoint(
                "terminal-readback-before-lexical-recheck",
                {"run_id": request.run_id, "state": expected_state},
            )
            try:
                lexical = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                raise RunIntegrityError("terminal lexical identity disappeared") from exc
            if _safety_core.source_identity(lexical) != opened_terminal_identity:
                raise RunIntegrityError("terminal lexical identity changed during readback")
            return InventoryTerminal(
                request.run_id,
                expected_state,
                str(Path(os.fsdecode(self.runs_root)) / ("failed" if expected_state == "failed" else "") / request.run_id),
                _sha256(manifest),
            )
        finally:
            os.close(terminal_fd)

    def _verify_manifest(self, terminal_fd: int, manifest: bytes) -> None:
        actual = _collect_package_files(terminal_fd)
        expected_manifest = b"".join(
            _canonical_json_bytes({"path": path, "sha256": _sha256(payload)})
            for path, payload in sorted(actual.items())
        )
        if manifest != expected_manifest:
            raise RunIntegrityError("inventory manifest is noncanonical or mismatched")


class InventoryRunSession:
    def __init__(
        self,
        store: InventoryRunStore,
        request: InventoryRunRequest,
        root_fd: int,
        staging_fd: int,
        lock_fd: int,
        staging_name: str,
    ) -> None:
        self.store = store
        self.request = request
        self.root_fd = root_fd
        self.staging_fd = staging_fd
        self.lock_fd = lock_fd
        self.staging_name = staging_name
        self._closed = False
        self._terminalized = False

    def __enter__(self) -> "InventoryRunSession":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        os.close(self.lock_fd)
        os.close(self.staging_fd)
        os.close(self.root_fd)

    def _require_active(self) -> None:
        if self._closed:
            raise RunStateError("inventory session is closed")
        if self._terminalized:
            raise RunStateError("inventory run is already terminal")
        self.store._require_staging_lexical_identity(
            self.root_fd,
            self.staging_fd,
            self.staging_name,
        )
        _require_open_file_lexical_identity(
            self.staging_fd,
            "run.lock",
            self.lock_fd,
            "inventory run lock",
        )

    def _write_sequence_bytes(
        self, directory: str, sequence: int, payload: bytes
    ) -> None:
        self._require_active()
        if type(sequence) is not int or not 0 <= sequence <= 99999999:
            raise ValueError("inventory sequence must be between 0 and 99999999")
        child_fd = _open_directory_at(self.staging_fd, directory, directory)
        try:
            _write_once(
                child_fd,
                "%08d.json" % sequence,
                payload,
                "%s sequence" % directory,
            )
            os.fsync(child_fd)
        finally:
            os.close(child_fd)

    def write_chunk(self, sequence: int, payload: Mapping[str, Any]) -> None:
        self._require_active()
        if not isinstance(payload, Mapping):
            raise TypeError("inventory chunk payload must be a mapping")
        state = _load_resumability_state(
            self.staging_fd,
            self.request,
            allow_uncheckpointed_chunk=True,
        )
        if len(state.chunks) != len(state.checkpoints):
            raise RunStateError("prior inventory chunk has no checkpoint")
        if sequence != len(state.chunks):
            raise RunStateError("inventory chunk sequence is not contiguous")
        normalized = _json_compatible(payload)
        required = {"cursor_before", "cursor_after", "source_identities"}
        if not isinstance(normalized, dict) or not required <= set(normalized):
            raise RunStateError("inventory chunk cursor/source fields are required")
        expected_cursor = (
            canonical_raw_path(())
            if not state.checkpoint_objects
            else state.checkpoint_objects[-1]["next_cursor"]
        )
        if normalized["cursor_before"] != expected_cursor:
            raise RunStateError("inventory chunk cursor prefix mismatch")
        before_components = _validate_cursor(
            normalized["cursor_before"], allow_terminal=False
        )
        after_components = _validate_cursor(
            normalized["cursor_after"], allow_terminal=True
        )
        assert before_components is not None
        if after_components is not None and after_components <= before_components:
            raise RunStateError("inventory chunk cursor must advance")
        source_identities = list(
            _validate_source_identities(normalized["source_identities"])
        )
        chunk_payload = {
            key: normalized[key]
            for key in sorted(normalized)
            if key not in required
        }
        envelope = {
            "schema_version": 1,
            "package_version": PACKAGE_VERSION,
            "run_id": self.request.run_id,
            "request_sha256": self.request.sha256,
            "sequence": sequence,
            "previous_chunk_sha256": (
                None if not state.chunks else _sha256(state.chunks[-1])
            ),
            "cursor_before": normalized["cursor_before"],
            "cursor_after": normalized["cursor_after"],
            "source_identities": source_identities,
            "source_identities_sha256": _sha256(
                _canonical_json_bytes(source_identities)
            ),
            "payload": chunk_payload,
        }
        self._write_sequence_bytes(
            "chunks",
            sequence,
            _canonical_json_bytes(envelope),
        )
        _load_resumability_state(
            self.staging_fd,
            self.request,
            allow_uncheckpointed_chunk=True,
        )

    def write_checkpoint(self, sequence: int, payload: Mapping[str, Any]) -> None:
        self._require_active()
        if not isinstance(payload, Mapping):
            raise TypeError("inventory checkpoint payload must be a mapping")
        state = _load_resumability_state(
            self.staging_fd,
            self.request,
            allow_uncheckpointed_chunk=True,
        )
        if len(state.chunks) != len(state.checkpoints) + 1:
            raise RunStateError("inventory checkpoint requires exactly one new chunk")
        if sequence != len(state.checkpoints):
            raise RunStateError("inventory checkpoint sequence is not contiguous")
        normalized = _json_compatible(payload)
        if not isinstance(normalized, dict) or set(normalized) != {
            "next_cursor",
            "counters",
        }:
            raise RunStateError("inventory checkpoint contract is invalid")
        chunk = state.chunk_objects[-1]
        if normalized["next_cursor"] != chunk["cursor_after"]:
            raise RunStateError("inventory checkpoint cursor mismatch")
        _validate_cursor(normalized["next_cursor"], allow_terminal=True)
        counters = _validate_counters(normalized["counters"])
        if state.checkpoint_objects:
            previous_counters = state.checkpoint_objects[-1]["counters"]
            if any(counters[key] < previous_counters[key] for key in _COUNTER_FIELDS):
                raise RunStateError("inventory checkpoint counters regressed")
        chunk_hashes = [_sha256(raw) for raw in state.chunks]
        source_hashes = [
            item["source_identities_sha256"] for item in state.chunk_objects
        ]
        chunk_manifest_hash = _sha256(_canonical_json_bytes(chunk_hashes))
        source_prefix_hash = _sha256(_canonical_json_bytes(source_hashes))
        previous_completed_prefix = (
            None
            if not state.checkpoint_objects
            else state.checkpoint_objects[-1]["completed_prefix_sha256"]
        )
        prefix_payload = {
            "previous_completed_prefix_sha256": previous_completed_prefix,
            "chunk_manifest_sha256": chunk_manifest_hash,
            "source_identity_prefix_sha256": source_prefix_hash,
            "next_cursor": normalized["next_cursor"],
            "counters": counters,
        }
        envelope = {
            "schema_version": 1,
            "package_version": PACKAGE_VERSION,
            "run_id": self.request.run_id,
            "request_sha256": self.request.sha256,
            "sequence": sequence,
            "previous_checkpoint_sha256": (
                None if not state.checkpoints else _sha256(state.checkpoints[-1])
            ),
            "chunk_sha256": chunk_hashes[-1],
            "chunk_manifest_sha256": chunk_manifest_hash,
            "completed_prefix_sha256": _sha256(
                _canonical_json_bytes(prefix_payload)
            ),
            "source_identity_prefix_sha256": source_prefix_hash,
            "next_cursor": normalized["next_cursor"],
            "counters": counters,
        }
        self._write_sequence_bytes(
            "checkpoints",
            sequence,
            _canonical_json_bytes(envelope),
        )
        _load_resumability_state(
            self.staging_fd,
            self.request,
            allow_uncheckpointed_chunk=False,
        )

    def publish_result(self, result: InventoryResult) -> InventoryTerminal:
        """Seal one deterministic terminal provenance pair and publish a scan result."""
        self._require_active()
        if type(result) is not InventoryResult or result.run_id != self.request.run_id:
            raise RunRequestMismatchError("inventory result does not match run request")
        expected_artifacts = {"coverage.json", "observations.jsonl"}
        if set(self.request.expected_artifacts) != expected_artifacts:
            raise RunStateError("inventory result publisher requires canonical artifacts")

        source_rows = []
        seen_paths = set()
        for observation in result.observations:
            if observation.identity is None:
                continue
            components = decode_canonical_raw_path(observation.path)
            if components in seen_paths:
                raise RunIntegrityError("duplicate observation source identity")
            seen_paths.add(components)
            source_rows.append(
                (
                    components,
                    {
                        "path": observation.path,
                        "identity": observation.identity.to_dict(),
                    },
                )
            )
        source_rows.sort(key=lambda item: item[0])
        source_identities = [row for _, row in source_rows]
        if not source_identities:
            raise RunStateError("inventory result has no source identities")
        observations_bytes = result.observations_jsonl()
        coverage_bytes = result.coverage_json()
        result_payload = {
            "observations_sha256": _sha256(observations_bytes),
            "coverage_sha256": _sha256(coverage_bytes),
        }
        counters = {
            "observations": len(result.observations),
            "content_bytes": result.coverage["content_bytes_attempted"],
        }
        state = _load_resumability_state(
            self.staging_fd,
            self.request,
            allow_uncheckpointed_chunk=False,
        )
        if not state.chunks:
            self.write_chunk(
                0,
                {
                    "cursor_before": canonical_raw_path(()),
                    "cursor_after": None,
                    "source_identities": source_identities,
                    "result": result_payload,
                },
            )
            self.write_checkpoint(
                0,
                {"next_cursor": None, "counters": counters},
            )
        else:
            _require_complete_resumability(state)
            if (
                len(state.chunk_objects) != 1
                or state.chunk_objects[0]["cursor_before"]
                != canonical_raw_path(())
                or state.chunk_objects[0]["cursor_after"] is not None
                or state.chunk_objects[0]["source_identities"]
                != source_identities
                or state.chunk_objects[0]["payload"]
                != {"result": result_payload}
                or state.checkpoint_objects[0]["counters"] != counters
            ):
                raise RunRequestMismatchError(
                    "existing inventory result provenance does not match"
                )
        return self.publish(
            {
                "coverage.json": coverage_bytes,
                "observations.jsonl": observations_bytes,
            }
        )

    def publish(self, artifacts: Mapping[str, bytes]) -> InventoryTerminal:
        self._require_active()
        state = _load_resumability_state(
            self.staging_fd,
            self.request,
            allow_uncheckpointed_chunk=False,
        )
        _require_complete_resumability(state)
        try:
            self.store._verify_live_source_identities(
                self.staging_fd,
                self.request,
            )
        except RunProvenanceError as exc:
            return self.fail(
                "source-identity-invalid",
                {"code": exc.code},
            )
        if set(artifacts) != set(self.request.expected_artifacts):
            raise RunStateError("complete inventory artifacts do not match sealed request")
        for name in sorted(artifacts):
            payload = artifacts[name]
            if not isinstance(payload, bytes):
                raise TypeError("inventory artifacts must be bytes")
            _write_once(self.staging_fd, name, payload, "inventory artifact %s" % name)
        run_payload = {
            "schema_version": 1,
            "package_version": PACKAGE_VERSION,
            "run_id": self.request.run_id,
            "state": "complete",
            "request_sha256": self.request.sha256,
            "openable": False,
            "approval_ready": False,
        }
        _write_once(
            self.staging_fd,
            "run.json",
            _canonical_json_bytes(run_payload),
            "inventory run result",
        )
        return self._terminalize("complete")

    def fail(self, reason: str, details: Mapping[str, Any]) -> InventoryTerminal:
        self._require_active()
        if not isinstance(reason, str) or not reason:
            raise ValueError("inventory failure reason is required")
        failure_payload = {
            "schema_version": 1,
            "package_version": PACKAGE_VERSION,
            "run_id": self.request.run_id,
            "state": "failed",
            "reason": reason,
            "details": details,
            "openable": False,
            "approval_ready": False,
        }
        _write_once(
            self.staging_fd,
            "failure.json",
            _canonical_json_bytes(failure_payload),
            "inventory failure",
        )
        run_payload = {
            "schema_version": 1,
            "package_version": PACKAGE_VERSION,
            "run_id": self.request.run_id,
            "state": "failed",
            "request_sha256": self.request.sha256,
            "openable": False,
            "approval_ready": False,
        }
        _write_once(
            self.staging_fd,
            "run.json",
            _canonical_json_bytes(run_payload),
            "inventory run result",
        )
        return self._terminalize("failed")

    def _terminalize(self, state: str) -> InventoryTerminal:
        package_files = _collect_package_files(self.staging_fd)
        manifest = b"".join(
            _canonical_json_bytes({"path": path, "sha256": _sha256(payload)})
            for path, payload in sorted(package_files.items())
        )
        _write_once(
            self.staging_fd,
            "manifest.jsonl",
            manifest,
            "inventory manifest",
        )
        self.store._validate_staging_layout(
            self.staging_fd,
            self.request,
            validate_provenance=state == "complete",
            allow_uncheckpointed_chunk=False,
        )
        self.store._verify_manifest(self.staging_fd, manifest)
        os.fsync(self.staging_fd)
        before = os.fstat(self.staging_fd)
        expected_source_identity = _safety_core.source_identity(before)
        target_parent_fd = self.root_fd
        failed_fd = None
        if state == "failed":
            failed_fd = self.store._failed_fd(self.root_fd, create=True)
            if failed_fd is None:
                raise RunIntegrityError("failed run directory unavailable")
            target_parent_fd = failed_fd
        try:
            root_path = Path(os.fsdecode(self.store.runs_root))
            source_path = root_path / self.staging_name
            target_path = (
                root_path
                / ("failed" if state == "failed" else "")
                / self.request.run_id
            )
            self.store._require_root_lexical_identity(self.root_fd)
            if failed_fd is not None:
                _safety_core.require_same_directory_identity(
                    root_path / "failed",
                    failed_fd,
                    "failed inventory runs root",
                    error_type=RunIntegrityError,
                )
            self.store._checkpoint(
                "terminal-before-rename",
                {
                    "run_id": self.request.run_id,
                    "state": state,
                    "source": str(source_path),
                    "target": str(target_path),
                },
            )
            sequence = {"value": 0}

            def observe_directory(path: Path, _fd: int, label: str) -> None:
                sequence["value"] += 1
                self.store._checkpoint(
                    "terminal-rename-directory-check",
                    {
                        "run_id": self.request.run_id,
                        "state": state,
                        "sequence": sequence["value"],
                        "label": label,
                        "path": str(path),
                    },
                )

            try:
                _safety_core.rename_path_no_replace(
                    source_path,
                    target_path,
                    collision_error="inventory terminal destination exists",
                    require_directory=True,
                    expected_source_identity=expected_source_identity,
                    error_type=RunIntegrityError,
                    before_directory_identity_check=observe_directory,
                )
            except RunIntegrityError as exc:
                if str(exc) == "inventory terminal destination exists":
                    raise RunCollisionError(str(exc)) from exc
                raise
            self.store._require_root_lexical_identity(self.root_fd)
            terminal = self.store._read_terminal(
                target_parent_fd,
                self.request.run_id,
                self.request,
                state,
                expected_source_identity,
            )
            self.store._require_root_lexical_identity(self.root_fd)
            if failed_fd is not None:
                _safety_core.require_same_directory_identity(
                    root_path / "failed",
                    failed_fd,
                    "failed inventory runs root",
                    error_type=RunIntegrityError,
                )
            if terminal.package_sha256 != _sha256(manifest):
                raise RunIntegrityError("terminal package hash mismatch")
            self._terminalized = True
            return terminal
        finally:
            if failed_fd is not None:
                os.close(failed_fd)


def _collect_package_files(directory_fd: int) -> Dict[str, bytes]:
    result: Dict[str, bytes] = {}
    for name in sorted(os.listdir(directory_fd)):
        if name == "manifest.jsonl":
            _read_all_file_at(directory_fd, name, name)
            continue
        value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISREG(value.st_mode):
            result[name] = _read_all_file_at(directory_fd, name, name)
            continue
        if stat.S_ISDIR(value.st_mode) and name in ("chunks", "checkpoints"):
            child_fd = _open_directory_at(directory_fd, name, name)
            try:
                for child_name in sorted(os.listdir(child_fd)):
                    if not _SEQUENCE_RE.fullmatch(child_name):
                        raise RunIntegrityError("unexpected resumability artifact")
                    result["%s/%s" % (name, child_name)] = _read_all_file_at(
                        child_fd, child_name, "%s/%s" % (name, child_name)
                    )
            finally:
                os.close(child_fd)
            continue
        if stat.S_ISDIR(value.st_mode) and name == "corrupt":
            child_fd = _open_directory_at(
                directory_fd,
                name,
                "inventory corrupt evidence",
            )
            try:
                for child_name in sorted(os.listdir(child_fd)):
                    child_stat = os.stat(
                        child_name,
                        dir_fd=child_fd,
                        follow_symlinks=False,
                    )
                    metadata = {
                        "schema_version": 1,
                        "name": _encode_component(os.fsencode(child_name)),
                        "physical_kind": _physical_kind(child_stat.st_mode),
                        "identity": FileIdentity.from_stat(child_stat).to_dict(),
                    }
                    result["corrupt/%s" % child_name] = _canonical_json_bytes(
                        metadata
                    )
            finally:
                os.close(child_fd)
            continue
        raise RunIntegrityError("unexpected inventory package entry")
    return result


__all__ = [
    "PACKAGE_VERSION",
    "RAW_PATH_ENCODING",
    "InventoryError",
    "ScopeInputError",
    "InventorySafetyError",
    "ContentReadError",
    "RunStateError",
    "RunBusyError",
    "RunCollisionError",
    "RunRequestMismatchError",
    "RunIntegrityError",
    "RunProvenanceError",
    "ManualRecoveryRequired",
    "ScopeDecision",
    "ScopeMap",
    "TraversalBounds",
    "TextPolicy",
    "FileIdentity",
    "TextProjection",
    "InternalReference",
    "ReferenceProjection",
    "ClassificationProjection",
    "Observation",
    "InventoryResult",
    "BoundedTextReader",
    "InventoryEngine",
    "scan_directory_count_only",
    "InventoryRunRequest",
    "InventoryTerminal",
    "InventoryPackageReadback",
    "InventoryRunStore",
    "InventoryRunSession",
    "canonical_raw_path",
    "decode_canonical_raw_path",
    "display_raw_path",
]
