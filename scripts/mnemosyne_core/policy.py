"""Pure strict-policy compiler for Mnemosyne document curation.

This module intentionally performs no filesystem I/O.  It accepts registry bytes
and a caller-supplied raw-root path, then returns typed, deterministic policy
projections.  Mutation and filesystem identity checks belong to higher layers.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from typing import (
    Any,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)


class PolicyError(ValueError):
    """The registry is parseable but not an admissible curation policy."""


class StrictYAMLError(PolicyError):
    """The registry is outside Mnemosyne's deliberately small YAML subset."""


class StrictYAMLDuplicateKeyError(StrictYAMLError):
    """The strict YAML document repeats one mapping key."""


@dataclass(frozen=True)
class CompiledScopeRule:
    id: str
    path_selectors: Tuple[str, ...]
    workstream_lifecycle: Tuple[str, ...]
    sensitivity: str
    access_domain: str
    traversal: str
    inventory: str
    content_inspection: str
    write: str
    catch_all: bool


@dataclass(frozen=True)
class CompiledWorkstream:
    id: str
    lifecycle: str
    project_home: str
    aliases: Tuple[str, ...]
    memory_workspace: Optional[str] = None


@dataclass(frozen=True)
class CompiledArchiveRoot:
    workstream_id: str
    sensitivity: str
    access_domain: str
    root: str


@dataclass(frozen=True)
class CompiledWriterControl:
    movement_writer: str
    structural_apply: str
    writer_epoch: str


@dataclass(frozen=True)
class CompiledFoundation:
    profile_version: int
    state_root: str
    runs_root: str


@dataclass(frozen=True)
class CompiledRegistryAnchors:
    registry_root: str
    inbox: str
    memory_workspaces: str


@dataclass(frozen=True)
class CompiledPathPrefix:
    components: Tuple[str, ...]


@dataclass(frozen=True)
class CompiledCategory:
    id: str
    target: str
    patterns: Tuple[str, ...]


@dataclass(frozen=True)
class CompiledPolicy:
    raw_hash: str
    full_json: bytes
    full_hash: str
    writer_control: CompiledWriterControl
    writer_json: bytes
    writer_hash: str
    foundation: CompiledFoundation
    foundation_json: bytes
    foundation_hash: str
    workstreams: Tuple[CompiledWorkstream, ...]
    archive_roots: Tuple[CompiledArchiveRoot, ...]
    scope_rules: Tuple[CompiledScopeRule, ...]
    registry_anchors: CompiledRegistryAnchors
    never_touch: Tuple[CompiledPathPrefix, ...]
    categories: Tuple[CompiledCategory, ...]


@dataclass(frozen=True)
class _SourceLine:
    number: int
    indent: int
    content: str


_CANONICAL_SCOPE_RULES = (
    OrderedDict(
        (
            ("id", "active-workstream-content"),
            ("path_selectors", ("workstream-project-home", "attributed-artifact")),
            ("workstream_lifecycle", ("active",)),
            ("sensitivity", "standard"),
            ("access_domain", "local"),
            ("traversal", "recursive-no-follow"),
            ("inventory", "content-aware"),
            ("content_inspection", "allowed"),
            ("write", "approved-only"),
        )
    ),
    OrderedDict(
        (
            ("id", "paused-completed"),
            ("path_selectors", ("workstream-project-home", "attributed-artifact")),
            ("workstream_lifecycle", ("paused", "completed")),
            ("sensitivity", "standard"),
            ("access_domain", "local"),
            ("traversal", "directory-count-only"),
            ("inventory", "coverage-only"),
            ("content_inspection", "forbidden"),
            ("write", "frozen"),
        )
    ),
    OrderedDict(
        (
            ("id", "opaque-evidence"),
            (
                "path_selectors",
                (
                    "opaque-evidence",
                    "mirror-provenance",
                    "memory-policy",
                    "protected-control",
                    "never-touch",
                ),
            ),
            ("workstream_lifecycle", ("any",)),
            ("sensitivity", "opaque"),
            ("access_domain", "local-restricted"),
            ("traversal", "metadata-no-follow"),
            ("inventory", "metadata-only"),
            ("content_inspection", "forbidden"),
            ("write", "forbidden"),
        )
    ),
    OrderedDict(
        (
            ("id", "private-reviewable"),
            ("path_selectors", ("private-reviewable",)),
            ("workstream_lifecycle", ("any",)),
            ("sensitivity", "private"),
            ("access_domain", "local-restricted"),
            ("traversal", "metadata-no-follow"),
            ("inventory", "metadata-only"),
            ("content_inspection", "scoped-approved"),
            ("write", "forbidden"),
        )
    ),
    OrderedDict(
        (
            ("id", "fallback-unassigned"),
            ("path_selectors", ("catch-all",)),
            ("workstream_lifecycle", ("unassigned",)),
            ("sensitivity", "unknown"),
            ("access_domain", "local"),
            ("traversal", "metadata-no-follow"),
            ("inventory", "metadata-only"),
            ("content_inspection", "scoped-approved"),
            (
                "write",
                "normal-structural-approval-after-confirmed-routing",
            ),
        )
    ),
)

_REQUIRED_RULE_FIELDS = tuple(_CANONICAL_SCOPE_RULES[0].keys())
_CANONICAL_RULE_BY_ID = OrderedDict(
    (rule["id"], rule) for rule in _CANONICAL_SCOPE_RULES
)
_CURATION_PROFILE_V1_FIELDS = (
    "profile_version",
    "state_root",
    "runs_root",
    "structural_apply",
    "movement_writer",
    "writer_epoch",
    "scope_rules",
    "archive_roots",
)
_ARCHIVE_ROOT_FIELDS = (
    "workstream_id",
    "sensitivity",
    "access_domain",
    "root",
)
_APPROVED_ARCHIVE_DOMAIN_PAIRS = frozenset(
    (rule["sensitivity"], rule["access_domain"])
    for rule in _CANONICAL_SCOPE_RULES
    if rule["id"] != "fallback-unassigned"
)
_APPROVED_ARCHIVE_SENSITIVITIES = frozenset(
    sensitivity for sensitivity, _ in _APPROVED_ARCHIVE_DOMAIN_PAIRS
)
_RESERVED_PLAIN_VALUES = {
    "y",
    "yes",
    "n",
    "no",
    "on",
    "off",
    "null",
    "true",
    "false",
}
_CANONICAL_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_NUMBER_LIKE = re.compile(
    r"[+-]?(?:(?:[0-9][0-9_]*)(?:\.[0-9_]*)?|\.[0-9_]+)(?:[eE][+-]?[0-9_]+)?\Z"
)
_BASE_NUMBER_LIKE = re.compile(r"[+-]?0[xXoObB][0-9A-Fa-f_]+\Z")
_DATE_LIKE = re.compile(
    r"(?:[0-9]{4}-[0-9]{1,2}-[0-9]{1,2})(?:[Tt ][0-9:.+-]+(?:[Zz])?)?\Z"
)
_TIME_LIKE = re.compile(r"[0-9]{1,2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?\Z")
_YAML_EXTENSION_TOKEN = re.compile(r"(?:^|\s)[&*!](?=\S)")
_MEMORY_WORKSPACE_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _quote_starts_scalar(text: str, index: int) -> bool:
    return index == 0 or text[index - 1].isspace()


def _strip_comment(text: str, line_number: int) -> str:
    quote: Optional[str] = None
    escaped = False
    index = 0
    while index < len(text):
        character = text[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = None
        elif quote == "'":
            if character == "'":
                if index + 1 < len(text) and text[index + 1] == "'":
                    index += 1
                else:
                    quote = None
        elif character in ("'", '"') and _quote_starts_scalar(text, index):
            quote = character
        elif character == "#" and (index == 0 or text[index - 1].isspace()):
            return text[:index].rstrip()
        index += 1
    if quote is not None:
        raise StrictYAMLError("line %d: unterminated quoted scalar" % line_number)
    return text.rstrip()


def _source_lines(source: Union[bytes, str]) -> List[_SourceLine]:
    if isinstance(source, bytes):
        try:
            text = source.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise StrictYAMLError("registry is not valid UTF-8") from error
    elif isinstance(source, str):
        text = source
    else:
        raise TypeError("strict YAML source must be bytes or str")
    if text.startswith("\ufeff"):
        raise StrictYAMLError("UTF-8 BOM is not allowed")
    if "\x00" in text:
        raise StrictYAMLError("NUL is not allowed")
    if "\t" in text:
        raise StrictYAMLError("tabs are not allowed")

    result: List[_SourceLine] = []
    for number, raw_line in enumerate(text.splitlines(), 1):
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent % 2:
            raise StrictYAMLError(
                "line %d: indentation must use two-space steps" % number
            )
        content = _strip_comment(raw_line[indent:], number)
        if not content:
            continue
        if content in ("---", "...") or content.startswith("%"):
            raise StrictYAMLError("line %d: YAML directives are not allowed" % number)
        result.append(_SourceLine(number, indent, content))
    return result


def _is_sequence_line(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _split_mapping_entry(
    text: str, line_number: int
) -> Optional[Tuple[str, str]]:
    quote: Optional[str] = None
    escaped = False
    index = 0
    while index < len(text):
        character = text[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = None
        elif quote == "'":
            if character == "'":
                if index + 1 < len(text) and text[index + 1] == "'":
                    index += 1
                else:
                    quote = None
        elif character in ("'", '"') and _quote_starts_scalar(text, index):
            quote = character
        elif character == ":" and (
            index + 1 == len(text) or text[index + 1].isspace()
        ):
            return text[:index].strip(), text[index + 1 :].strip()
        index += 1
    if quote is not None:
        raise StrictYAMLError("line %d: unterminated quoted scalar" % line_number)
    return None


def _parse_quoted_scalar(text: str, line_number: int) -> str:
    if text.startswith('"'):
        try:
            value = json.loads(text)
        except (json.JSONDecodeError, TypeError) as error:
            raise StrictYAMLError(
                "line %d: invalid double-quoted scalar" % line_number
            ) from error
        if not isinstance(value, str):
            raise StrictYAMLError("line %d: quoted scalar must be a string" % line_number)
        return value

    output: List[str] = []
    index = 1
    while index < len(text):
        character = text[index]
        if character == "'":
            if index + 1 < len(text) and text[index + 1] == "'":
                output.append("'")
                index += 2
                continue
            if index != len(text) - 1:
                raise StrictYAMLError(
                    "line %d: trailing data after quoted scalar" % line_number
                )
            return "".join(output)
        output.append(character)
        index += 1
    raise StrictYAMLError("line %d: unterminated quoted scalar" % line_number)


def _looks_ambiguously_typed(text: str) -> bool:
    lowered = text.casefold()
    if lowered in _RESERVED_PLAIN_VALUES:
        return text not in ("null", "true", "false")
    if text == "~" or lowered in (".inf", "+.inf", "-.inf", ".nan"):
        return True
    if _CANONICAL_INTEGER.fullmatch(text):
        return False
    if _NUMBER_LIKE.fullmatch(text) or _BASE_NUMBER_LIKE.fullmatch(text):
        return True
    if _DATE_LIKE.fullmatch(text) or _TIME_LIKE.fullmatch(text):
        return True
    return False


def _parse_scalar(text: str, line_number: int) -> Any:
    if not text:
        raise StrictYAMLError("line %d: empty scalar" % line_number)
    if text[0] in ("'", '"'):
        return _parse_quoted_scalar(text, line_number)
    if text[0] in ("|", ">"):
        raise StrictYAMLError("line %d: multiline scalars are not allowed" % line_number)
    if _YAML_EXTENSION_TOKEN.search(text):
        raise StrictYAMLError(
            "line %d: YAML anchors, aliases, and tags are not allowed" % line_number
        )
    if text == "[]":
        return []
    if text.startswith("[") or text.startswith("{"):
        raise StrictYAMLError(
            "line %d: flow collections other than [] are not allowed" % line_number
        )
    if text == "true":
        return True
    if text == "false":
        return False
    if text == "null":
        return None
    if _CANONICAL_INTEGER.fullmatch(text):
        return int(text)
    if _looks_ambiguously_typed(text):
        raise StrictYAMLError(
            "line %d: ambiguous typed scalar must be quoted: %s"
            % (line_number, text)
        )
    return text


def _parse_key(text: str, line_number: int) -> str:
    if not text:
        raise StrictYAMLError("line %d: empty mapping key" % line_number)
    value = _parse_scalar(text, line_number)
    if not isinstance(value, str):
        raise StrictYAMLError("line %d: mapping key must be a string" % line_number)
    if value == "<<":
        raise StrictYAMLError("line %d: merge keys are not allowed" % line_number)
    return value


class _StrictParser:
    def __init__(self, lines: Sequence[_SourceLine]) -> None:
        self._lines = lines

    def parse(self) -> Any:
        if not self._lines:
            raise StrictYAMLError("empty YAML document")
        if self._lines[0].indent != 0:
            raise StrictYAMLError(
                "line %d: document must start at indentation zero"
                % self._lines[0].number
            )
        value, index = self._parse_block(0, 0)
        if index != len(self._lines):
            line = self._lines[index]
            raise StrictYAMLError("line %d: unexpected indentation" % line.number)
        return value

    def _parse_block(self, index: int, indent: int) -> Tuple[Any, int]:
        if index >= len(self._lines) or self._lines[index].indent != indent:
            line_number = self._lines[index].number if index < len(self._lines) else 0
            raise StrictYAMLError(
                "line %d: expected indentation %d" % (line_number, indent)
            )
        if _is_sequence_line(self._lines[index].content):
            return self._parse_sequence(index, indent)
        return self._parse_mapping(index, indent)

    def _parse_child(
        self, index: int, expected_indent: int, owner_line: int
    ) -> Tuple[Any, int]:
        if index >= len(self._lines):
            raise StrictYAMLError("line %d: missing nested value" % owner_line)
        line = self._lines[index]
        if line.indent != expected_indent:
            raise StrictYAMLError(
                "line %d: expected indentation %d" % (line.number, expected_indent)
            )
        return self._parse_block(index, expected_indent)

    def _assign_entry(
        self,
        target: MutableMapping[str, Any],
        key_text: str,
        value_text: str,
        line_number: int,
        next_index: int,
        child_indent: int,
    ) -> int:
        key = _parse_key(key_text, line_number)
        if key in target:
            raise StrictYAMLDuplicateKeyError(
                "line %d: duplicate mapping key: %s" % (line_number, key)
            )
        if value_text:
            target[key] = _parse_scalar(value_text, line_number)
            return next_index
        value, next_index = self._parse_child(next_index, child_indent, line_number)
        target[key] = value
        return next_index

    def _parse_mapping(self, index: int, indent: int) -> Tuple[OrderedDict, int]:
        result: OrderedDict = OrderedDict()
        while index < len(self._lines):
            line = self._lines[index]
            if line.indent < indent:
                break
            if line.indent > indent:
                raise StrictYAMLError("line %d: unexpected indentation" % line.number)
            if _is_sequence_line(line.content):
                raise StrictYAMLError(
                    "line %d: cannot mix mapping and sequence entries" % line.number
                )
            entry = _split_mapping_entry(line.content, line.number)
            if entry is None:
                raise StrictYAMLError("line %d: expected mapping entry" % line.number)
            index = self._assign_entry(
                result,
                entry[0],
                entry[1],
                line.number,
                index + 1,
                indent + 2,
            )
        return result, index

    def _parse_sequence(self, index: int, indent: int) -> Tuple[List[Any], int]:
        result: List[Any] = []
        while index < len(self._lines):
            line = self._lines[index]
            if line.indent < indent:
                break
            if line.indent > indent:
                raise StrictYAMLError("line %d: unexpected indentation" % line.number)
            if not _is_sequence_line(line.content):
                raise StrictYAMLError(
                    "line %d: cannot mix sequence and mapping entries" % line.number
                )
            item_text = line.content[1:].strip()
            index += 1
            if not item_text:
                value, index = self._parse_child(index, indent + 2, line.number)
                result.append(value)
                continue

            entry = _split_mapping_entry(item_text, line.number)
            if entry is None:
                result.append(_parse_scalar(item_text, line.number))
                continue

            mapping: OrderedDict = OrderedDict()
            index = self._assign_entry(
                mapping,
                entry[0],
                entry[1],
                line.number,
                index,
                indent + 4,
            )
            while index < len(self._lines):
                continuation = self._lines[index]
                if continuation.indent != indent + 2:
                    break
                if _is_sequence_line(continuation.content):
                    raise StrictYAMLError(
                        "line %d: expected mapping continuation"
                        % continuation.number
                    )
                continuation_entry = _split_mapping_entry(
                    continuation.content, continuation.number
                )
                if continuation_entry is None:
                    raise StrictYAMLError(
                        "line %d: expected mapping entry" % continuation.number
                    )
                index = self._assign_entry(
                    mapping,
                    continuation_entry[0],
                    continuation_entry[1],
                    continuation.number,
                    index + 1,
                    indent + 4,
                )
            result.append(mapping)
        return result, index


def parse_strict_yaml(source: Union[bytes, str]) -> OrderedDict:
    """Parse the supported YAML subset without importing a YAML runtime."""

    value = _StrictParser(_source_lines(source)).parse()
    if not isinstance(value, OrderedDict):
        raise StrictYAMLError("registry document root must be a mapping")
    return value


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError("%s must be a mapping" % label)
    return value


def _require_list(value: Any, label: str) -> List[Any]:
    if not isinstance(value, list):
        raise PolicyError("%s must be a list" % label)
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError("%s must be a non-empty string" % label)
    return value


def _contains_control_character(value: str) -> bool:
    return any(
        unicodedata.category(character) in ("Cc", "Cf", "Cs")
        for character in value
    )


def _validate_exact_keys(
    value: Mapping[str, Any], allowed: Sequence[str], label: str
) -> None:
    unknown = [field for field in value if field not in allowed]
    if unknown:
        raise PolicyError("%s has unknown fields: %s" % (label, ", ".join(unknown)))
    missing = [field for field in allowed if field not in value]
    if missing:
        raise PolicyError(
            "%s is missing required fields: %s" % (label, ", ".join(missing))
        )


def _canonical_absolute_path(value: Any, label: str) -> str:
    path = _require_string(value, label)
    if _contains_control_character(path):
        raise PolicyError("%s contains a control character" % label)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or posixpath.normpath(path) != path
    ):
        raise PolicyError("%s must be a canonical absolute path" % label)
    return path


def _canonical_route_token(value: Any, label: str) -> str:
    token = _require_string(value, label)
    segments = token.split("/")
    if (
        _contains_control_character(token)
        or token.strip() != token
        or token.startswith("/")
        or token.endswith("/")
        or "\\" in token
        or any(segment in ("", ".", "..") for segment in segments)
        or posixpath.normpath(token) != token
    ):
        raise PolicyError("invalid Workstream route token: %s" % label)
    return token


def _canonical_memory_workspace(value: Any, label: str) -> Optional[str]:
    if value is None:
        return None
    token = _require_string(value, label)
    if _MEMORY_WORKSPACE_TOKEN.fullmatch(token) is None:
        raise PolicyError("invalid memory_workspace token: %s" % label)
    return token


def _path_is_within(path: str, root: str) -> bool:
    return root == "/" or path == root or path.startswith(root + "/")


def _path_routes_overlap(first: str, second: str) -> bool:
    first_key = first.casefold()
    second_key = second.casefold()
    return (
        first_key == second_key
        or first_key.startswith(second_key + "/")
        or second_key.startswith(first_key + "/")
    )


def _compile_registry_anchors(
    registry: Mapping[str, Any], raw_root: str
) -> CompiledRegistryAnchors:
    observed = CompiledRegistryAnchors(
        registry_root=_canonical_absolute_path(
            registry.get("registry_root"), "registry_root"
        ),
        inbox=_canonical_absolute_path(registry.get("inbox"), "inbox"),
        memory_workspaces=_canonical_absolute_path(
            registry.get("memory_workspaces"), "memory_workspaces"
        ),
    )
    expected = CompiledRegistryAnchors(
        registry_root=raw_root + "/_registry",
        inbox=raw_root + "/inbox",
        memory_workspaces=raw_root + "/memory/workspaces.yml",
    )
    if observed != expected:
        raise PolicyError("registry physical anchors are not canonical")
    return observed


def _compile_never_touch(
    registry: Mapping[str, Any],
) -> Tuple[CompiledPathPrefix, ...]:
    values = _require_list(registry.get("never_touch"), "never_touch")
    compiled: List[CompiledPathPrefix] = []
    seen = set()
    for index, raw_value in enumerate(values):
        label = "never_touch[%d]" % index
        value = _require_string(raw_value, label)
        stripped = value[:-1] if value.endswith("/") else value
        components = tuple(stripped.split("/"))
        if (
            _contains_control_character(value)
            or value.startswith("/")
            or "\\" in value
            or not stripped
            or any(component in ("", ".", "..") for component in components)
            or posixpath.normpath(stripped) != stripped
        ):
            raise PolicyError("%s must be a safe relative path prefix" % label)
        key = tuple(component.casefold() for component in components)
        if key in seen:
            raise PolicyError("duplicate never_touch path prefix")
        seen.add(key)
        compiled.append(CompiledPathPrefix(components=components))
    return tuple(compiled)


def _compile_categories(
    registry: Mapping[str, Any], raw_root: str
) -> Tuple[CompiledCategory, ...]:
    values = _require_list(registry.get("categories"), "categories")
    compiled: List[CompiledCategory] = []
    ids = set()
    targets = set()
    for index, raw_value in enumerate(values):
        label = "categories[%d]" % index
        value = _require_mapping(raw_value, label)
        category_id = _canonical_route_token(value.get("id"), label + ".id")
        id_key = category_id.casefold()
        if id_key in ids:
            raise PolicyError("duplicate category id: %s" % category_id)
        ids.add(id_key)
        target = _canonical_absolute_path(value.get("target"), label + ".target")
        if target == raw_root or not _path_is_within(target, raw_root):
            raise PolicyError("category target must stay below raw root")
        target_key = target.casefold()
        if target_key in targets:
            raise PolicyError("duplicate category target: %s" % target)
        targets.add(target_key)
        patterns = tuple(
            _require_string(pattern, label + ".patterns")
            for pattern in _require_list(value.get("patterns"), label + ".patterns")
        )
        if any(_contains_control_character(pattern) for pattern in patterns):
            raise PolicyError("category pattern contains a control character")
        description = value.get("description")
        if description is not None:
            _require_string(description, label + ".description")
        compiled.append(
            CompiledCategory(
                id=category_id,
                target=target,
                patterns=patterns,
            )
        )
    return tuple(compiled)


def _validate_workstreams(
    registry: Mapping[str, Any], raw_root: str
) -> Tuple[CompiledWorkstream, ...]:
    workstreams = _require_list(registry.get("workstreams"), "workstreams")
    ids: OrderedDict = OrderedDict()
    route_tokens: OrderedDict = OrderedDict()
    project_routes: List[Tuple[str, str]] = []
    compiled: List[CompiledWorkstream] = []
    for index, raw_workstream in enumerate(workstreams):
        label = "workstreams[%d]" % index
        workstream = _require_mapping(raw_workstream, label)
        workstream_id = _canonical_route_token(workstream.get("id"), label + ".id")
        id_key = workstream_id.casefold()
        if id_key in ids:
            raise PolicyError("duplicate Workstream id: %s" % workstream_id)
        ids[id_key] = workstream_id

        lifecycle = _require_string(
            workstream.get("lifecycle"), label + ".lifecycle"
        )
        if lifecycle not in ("active", "paused", "completed"):
            raise PolicyError("unsupported Workstream lifecycle: %s" % lifecycle)
        project_home = _canonical_absolute_path(
            workstream.get("project_home"), label + ".project_home"
        )
        if not _path_is_within(project_home, raw_root):
            raise PolicyError("Workstream project_home must stay inside raw root")
        for existing_id, existing_path in project_routes:
            if _path_routes_overlap(project_home, existing_path):
                raise PolicyError(
                    "ambiguous Workstream project routes: %s and %s"
                    % (existing_id, workstream_id)
                )
        project_routes.append((workstream_id, project_home))

        aliases = _require_list(workstream.get("aliases", []), label + ".aliases")
        memory_workspace = _canonical_memory_workspace(
            workstream.get("memory_workspace"), label + ".memory_workspace"
        )
        tokens = [workstream_id]
        compiled_aliases: List[str] = []
        for alias_index, alias_value in enumerate(aliases):
            alias = _canonical_route_token(
                alias_value, "%s.aliases[%d]" % (label, alias_index)
            )
            tokens.append(alias)
            compiled_aliases.append(alias)
        for token in tokens:
            token_key = token.casefold()
            for existing_key, existing_owner in route_tokens.items():
                exact_match = token_key == existing_key
                cross_owner_prefix = existing_owner != workstream_id and (
                    token_key.startswith(existing_key)
                    or existing_key.startswith(token_key)
                )
                if exact_match or cross_owner_prefix:
                    raise PolicyError(
                        "ambiguous Workstream alias or id route: %s (%s, %s)"
                        % (token, existing_owner, workstream_id)
                    )
            route_tokens[token_key] = workstream_id
        compiled.append(
            CompiledWorkstream(
                id=workstream_id,
                lifecycle=lifecycle,
                project_home=project_home,
                aliases=tuple(compiled_aliases),
                memory_workspace=memory_workspace,
            )
        )
    return tuple(compiled)


def _compile_scope_rules(curation: Mapping[str, Any]) -> Tuple[CompiledScopeRule, ...]:
    raw_rules = _require_list(curation.get("scope_rules"), "curation.scope_rules")
    if not raw_rules:
        raise PolicyError("curation.scope_rules must not be empty")
    compiled: List[CompiledScopeRule] = []
    seen: OrderedDict = OrderedDict()
    for index, raw_rule in enumerate(raw_rules):
        label = "curation.scope_rules[%d]" % index
        rule = _require_mapping(raw_rule, label)
        rule_id = _require_string(rule.get("id"), label + ".id")
        if rule_id in seen:
            raise PolicyError("duplicate scope rule id: %s" % rule_id)
        seen[rule_id] = index
        _validate_exact_keys(rule, _REQUIRED_RULE_FIELDS, label)
        if rule_id not in _CANONICAL_RULE_BY_ID:
            raise PolicyError("unsupported scope rule id: %s" % rule_id)
        selectors = tuple(
            _require_string(value, label + ".path_selectors")
            for value in _require_list(
                rule["path_selectors"], label + ".path_selectors"
            )
        )
        lifecycles = tuple(
            _require_string(value, label + ".workstream_lifecycle")
            for value in _require_list(
                rule["workstream_lifecycle"], label + ".workstream_lifecycle"
            )
        )
        if not selectors or not lifecycles:
            raise PolicyError(
                "%s selectors and lifecycle conditions must not be empty" % label
            )

        compiled_rule = CompiledScopeRule(
            id=rule_id,
            path_selectors=selectors,
            workstream_lifecycle=lifecycles,
            sensitivity=_require_string(rule["sensitivity"], label + ".sensitivity"),
            access_domain=_require_string(
                rule["access_domain"], label + ".access_domain"
            ),
            traversal=_require_string(rule["traversal"], label + ".traversal"),
            inventory=_require_string(rule["inventory"], label + ".inventory"),
            content_inspection=_require_string(
                rule["content_inspection"], label + ".content_inspection"
            ),
            write=_require_string(rule["write"], label + ".write"),
            catch_all=rule_id == "fallback-unassigned" and selectors == ("catch-all",),
        )
        expected = _CANONICAL_RULE_BY_ID[rule_id]
        observed = OrderedDict(
            (
                ("id", compiled_rule.id),
                ("path_selectors", compiled_rule.path_selectors),
                ("workstream_lifecycle", compiled_rule.workstream_lifecycle),
                ("sensitivity", compiled_rule.sensitivity),
                ("access_domain", compiled_rule.access_domain),
                ("traversal", compiled_rule.traversal),
                ("inventory", compiled_rule.inventory),
                ("content_inspection", compiled_rule.content_inspection),
                ("write", compiled_rule.write),
            )
        )
        if observed != expected:
            raise PolicyError("noncanonical required scope rule: %s" % rule_id)
        compiled.append(compiled_rule)

    missing_rules = [
        rule_id for rule_id in _CANONICAL_RULE_BY_ID if rule_id not in seen
    ]
    if missing_rules:
        raise PolicyError("missing required scope rule: %s" % ", ".join(missing_rules))
    expected_positions = [seen[rule_id] for rule_id in _CANONICAL_RULE_BY_ID]
    if expected_positions != sorted(expected_positions):
        raise PolicyError("required scope rules are not in canonical order")
    fallback_index = seen["fallback-unassigned"]
    if fallback_index != len(raw_rules) - 1 or not compiled[fallback_index].catch_all:
        raise PolicyError("fallback-unassigned must be the final catch-all scope rule")
    return tuple(compiled)


def _validate_archive_roots(
    curation: Mapping[str, Any],
    workstreams: Sequence[CompiledWorkstream],
    raw_root: str,
) -> Tuple[CompiledArchiveRoot, ...]:
    entries = _require_list(curation.get("archive_roots"), "curation.archive_roots")
    known_ids = {value.id.casefold(): value.id for value in workstreams}
    observed: List[Tuple[str, str]] = []
    compiled: List[CompiledArchiveRoot] = []
    for index, raw_entry in enumerate(entries):
        label = "curation.archive_roots[%d]" % index
        entry = _require_mapping(raw_entry, label)
        _validate_exact_keys(entry, _ARCHIVE_ROOT_FIELDS, label)
        workstream_id = _canonical_route_token(
            entry.get("workstream_id"), label + ".workstream_id"
        )
        canonical_workstream_id = known_ids.get(workstream_id.casefold())
        if canonical_workstream_id is None:
            raise PolicyError("unknown archive Workstream id: %s" % workstream_id)
        if workstream_id != canonical_workstream_id:
            raise PolicyError(
                "archive workstream_id must use the exact canonical Workstream id"
            )
        sensitivity = _require_string(
            entry.get("sensitivity"), label + ".sensitivity"
        )
        access_domain = _require_string(
            entry.get("access_domain"), label + ".access_domain"
        )
        if sensitivity not in _APPROVED_ARCHIVE_SENSITIVITIES:
            raise PolicyError(
                "archive root sensitivity is not an approved sensitivity"
            )
        if (sensitivity, access_domain) not in _APPROVED_ARCHIVE_DOMAIN_PAIRS:
            raise PolicyError(
                "archive root does not use an approved sensitivity/access domain pair"
            )
        root = _canonical_absolute_path(entry.get("root"), label + ".root")
        if not _path_is_within(root, raw_root):
            raise PolicyError("archive root must remain inside raw root")
        for existing_id, existing_root in observed:
            if _path_routes_overlap(root, existing_root):
                raise PolicyError(
                    "ambiguous archive roots: %s and %s"
                    % (existing_id, workstream_id)
                )
        observed.append((workstream_id, root))
        compiled.append(
            CompiledArchiveRoot(
                workstream_id=workstream_id,
                sensitivity=sensitivity,
                access_domain=access_domain,
                root=root,
            )
        )
    return tuple(compiled)


def compile_policy(registry_bytes: bytes, raw_root: str) -> CompiledPolicy:
    """Compile registry bytes into deterministic curation policy projections."""

    if not isinstance(registry_bytes, bytes):
        raise TypeError("registry_bytes must be bytes")
    canonical_root = _canonical_absolute_path(raw_root, "raw_root")
    registry = parse_strict_yaml(registry_bytes)
    schema_version = registry.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1:
        raise PolicyError("unsupported registry schema_version")
    registry_root = _canonical_absolute_path(registry.get("root"), "root")
    if registry_root != canonical_root:
        raise PolicyError("registry root does not match supplied raw root")
    registry_anchors = _compile_registry_anchors(registry, canonical_root)
    never_touch = _compile_never_touch(registry)
    categories = _compile_categories(registry, canonical_root)
    workstreams = _validate_workstreams(registry, canonical_root)
    curation = _require_mapping(registry.get("curation"), "curation")
    _validate_exact_keys(curation, _CURATION_PROFILE_V1_FIELDS, "curation")

    foundation_projection = OrderedDict(
        (
            ("profile_version", curation.get("profile_version")),
            ("state_root", curation.get("state_root")),
            ("runs_root", curation.get("runs_root")),
        )
    )
    expected_foundation = OrderedDict(
        (
            ("profile_version", 1),
            ("state_root", canonical_root + "/_registry/curation"),
            ("runs_root", canonical_root + "/_registry/curation-runs"),
        )
    )
    if (
        isinstance(foundation_projection["profile_version"], bool)
        or foundation_projection != expected_foundation
    ):
        raise PolicyError("curation must use the canonical curation foundation")
    foundation = CompiledFoundation(
        profile_version=foundation_projection["profile_version"],
        state_root=foundation_projection["state_root"],
        runs_root=foundation_projection["runs_root"],
    )

    writer_projection = OrderedDict(
        (
            ("movement_writer", curation.get("movement_writer")),
            ("structural_apply", curation.get("structural_apply")),
            ("writer_epoch", curation.get("writer_epoch")),
        )
    )
    legacy_writer = writer_projection == OrderedDict(
        (
            ("movement_writer", "legacy"),
            ("structural_apply", "disabled"),
            ("writer_epoch", "legacy-v1"),
        )
    )
    cutover_writer = (
        writer_projection["movement_writer"] == "curation"
        and writer_projection["structural_apply"] == "curation-gated"
        and isinstance(writer_projection["writer_epoch"], str)
        and bool(writer_projection["writer_epoch"])
        and writer_projection["writer_epoch"] != "legacy-v1"
    )
    if not legacy_writer and not cutover_writer:
        raise PolicyError("invalid writer-control combination")

    writer_control = CompiledWriterControl(
        movement_writer=writer_projection["movement_writer"],
        structural_apply=writer_projection["structural_apply"],
        writer_epoch=writer_projection["writer_epoch"],
    )
    scope_rules = _compile_scope_rules(curation)
    archive_roots = _validate_archive_roots(curation, workstreams, canonical_root)

    full_json = _canonical_json(registry)
    writer_json = _canonical_json(writer_projection)
    foundation_json = _canonical_json(foundation_projection)
    return CompiledPolicy(
        raw_hash=_sha256(registry_bytes),
        full_json=full_json,
        full_hash=_sha256(full_json),
        writer_control=writer_control,
        writer_json=writer_json,
        writer_hash=_sha256(writer_json),
        foundation=foundation,
        foundation_json=foundation_json,
        foundation_hash=_sha256(foundation_json),
        workstreams=workstreams,
        archive_roots=archive_roots,
        scope_rules=scope_rules,
        registry_anchors=registry_anchors,
        never_touch=never_touch,
        categories=categories,
    )


def _yaml_double_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _append_yaml_list(lines: List[str], indent: str, values: Sequence[str]) -> None:
    for value in values:
        lines.append(indent + "- " + _yaml_double_quote(value))


def build_initial_curation_block(raw_root: str) -> bytes:
    """Return the canonical, writer-disabled initial curation YAML block."""

    canonical_root = _canonical_absolute_path(raw_root, "raw_root")
    lines = [
        "curation:",
        "  profile_version: 1",
        "  state_root: " + _yaml_double_quote(canonical_root + "/_registry/curation"),
        "  runs_root: "
        + _yaml_double_quote(canonical_root + "/_registry/curation-runs"),
        "  structural_apply: disabled",
        "  movement_writer: legacy",
        "  writer_epoch: legacy-v1",
        "  scope_rules:",
    ]
    for rule in _CANONICAL_SCOPE_RULES:
        lines.append("    - id: " + rule["id"])
        lines.append("      path_selectors:")
        _append_yaml_list(lines, "        ", rule["path_selectors"])
        lines.append("      workstream_lifecycle:")
        _append_yaml_list(lines, "        ", rule["workstream_lifecycle"])
        for field in (
            "sensitivity",
            "access_domain",
            "traversal",
            "inventory",
            "content_inspection",
            "write",
        ):
            lines.append("      %s: %s" % (field, rule[field]))
    lines.append("  archive_roots: []")
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_additive_curation_postimage(registry_bytes: bytes, raw_root: str) -> bytes:
    """Append initial curation bytes without changing any existing registry byte."""

    if not isinstance(registry_bytes, bytes):
        raise TypeError("registry_bytes must be bytes")
    registry = parse_strict_yaml(registry_bytes)
    if "curation" in registry:
        raise PolicyError("registry already has curation section")
    canonical_root = _canonical_absolute_path(raw_root, "raw_root")
    registry_root = _canonical_absolute_path(registry.get("root"), "root")
    if registry_root != canonical_root:
        raise PolicyError("registry root does not match supplied raw root")
    _validate_workstreams(registry, canonical_root)
    separator = b"" if registry_bytes.endswith(b"\n") else b"\n"
    postimage = registry_bytes + separator + build_initial_curation_block(canonical_root)
    # The builder is its own postcondition: no caller can receive an invalid image.
    compile_policy(postimage, canonical_root)
    return postimage


__all__ = [
    "CompiledArchiveRoot",
    "CompiledCategory",
    "CompiledFoundation",
    "CompiledPathPrefix",
    "CompiledPolicy",
    "CompiledRegistryAnchors",
    "CompiledScopeRule",
    "CompiledWorkstream",
    "CompiledWriterControl",
    "PolicyError",
    "StrictYAMLDuplicateKeyError",
    "StrictYAMLError",
    "build_additive_curation_postimage",
    "build_initial_curation_block",
    "compile_policy",
    "parse_strict_yaml",
]
