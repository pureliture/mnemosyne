"""Deterministic reference-safety envelopes for Mnemosyne M2."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, Mapping, Optional, Sequence, Tuple

from . import inventory
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_MARKDOWN_INLINE = re.compile(r"!?\[[^\]\n]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")
_MARKDOWN_REFERENCE = re.compile(
    r"^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*(?:<([^>\n]+)>|([^\s]+))",
    re.MULTILINE,
)
_AUTOLINK = re.compile(r"<([^<>\s]+)>")
_HTML_ATTRIBUTE = re.compile(
    r"\b(?:href|src)\s*=\s*([\"'])(.*?)\1", re.IGNORECASE
)
_CONTEXT_FIELDS = frozenset(
    (
        "analyzer_version",
        "content_sha256",
        "context_id",
        "context_sha256",
        "coverage_issues",
        "documents",
        "edges",
        "frontier_complete",
        "navigation_sources",
        "parser_types",
        "registry_source",
        "scanned_roots",
        "schema_version",
    )
)
_DOCUMENT_FIELDS = frozenset(
    (
        "document_type",
        "error",
        "exclusion_reason",
        "fingerprint",
        "inspected",
        "path",
        "projection",
        "scope_class",
    )
)
_EDGE_FIELDS = frozenset(("reference_kind", "source_path", "target_path"))
_COVERAGE_FIELDS = frozenset(("kind", "path", "reason"))
_NAVIGATION_FIELDS = frozenset(("path", "sha256"))
_REGISTRY_FIELDS = frozenset(("kind", "sha256", "source_id"))
_REFERENCE_FIELDS = frozenset(("kind", "target"))
_PROJECTION_V1_FIELDS = frozenset(
    ("projection_sha256", "projection_version", "references")
)
_PROJECTION_V2_FIELDS = frozenset(
    ("parser_types", "projection_sha256", "projection_version", "references")
)


class ReferenceAnalysisError(ValueError):
    """Reference inputs cannot be represented safely or deterministically."""


def _exact_dict(value: Any, fields: FrozenSet[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise ReferenceAnalysisError("%s fields are invalid" % label)
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ReferenceAnalysisError("%s is invalid" % label)
    return value


def _optional_identifier(value: Any, label: str) -> Optional[str]:
    if value is None:
        return None
    if type(value) is not str:
        raise ReferenceAnalysisError("%s is invalid" % label)
    return _identifier(value, label)


def _strictly_increasing(values: Sequence[Any]) -> bool:
    return all(
        values[index - 1] < values[index]
        for index in range(1, len(values))
    )


def _freeze_json(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    if type(value) in (list, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ReferenceAnalysisError("%s must be raw-relative" % label)
    if (
        posixpath.normpath(value) != value
        or value in (".", "..")
        or value.startswith("../")
    ):
        raise ReferenceAnalysisError("%s must be canonical" % label)
    if any(ord(character) < 0x20 for character in value):
        raise ReferenceAnalysisError("%s contains control characters" % label)
    return value


def _covered_by_roots(path: str, roots: FrozenSet[str]) -> bool:
    current = path
    while True:
        if current in roots:
            return True
        parent, separator, _name = current.rpartition("/")
        if not separator:
            return False
        current = parent


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ReferenceAnalysisError("%s is invalid" % label)
    return value


@dataclass(frozen=True)
class ReferenceDocument:
    path: str
    document_type: str
    fingerprint: str
    scope_class: str
    text: Optional[str]
    inspected: bool
    exclusion_reason: Optional[str] = None
    error: Optional[str] = None
    projection: Optional[inventory.ReferenceProjection] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _path(self.path, "document path"))
        _identifier(self.document_type, "document type")
        if _HASH.fullmatch(self.fingerprint) is None:
            raise ReferenceAnalysisError("document fingerprint is invalid")
        _identifier(self.scope_class, "scope class")
        if type(self.inspected) is not bool:
            raise ReferenceAnalysisError("inspected must be boolean")
        if self.inspected:
            if (self.text is None) == (self.projection is None):
                raise ReferenceAnalysisError(
                    "inspected document requires exactly one safe input"
                )
            if self.text is not None and not isinstance(self.text, str):
                raise ReferenceAnalysisError("inspected document text is invalid")
            if self.projection is not None and (
                type(self.projection) is not inventory.ReferenceProjection
                or self.projection.source_path != self.path
            ):
                raise ReferenceAnalysisError(
                    "document projection source does not match path"
                )
            if self.exclusion_reason is not None or self.error is not None:
                raise ReferenceAnalysisError("inspected document cannot be excluded")
        elif self.text is not None or self.projection is not None:
            raise ReferenceAnalysisError(
                "uninspected document cannot carry safe input"
            )
        if (
            not self.inspected
            and self.exclusion_reason is None
            and self.error is None
        ):
            raise ReferenceAnalysisError(
                "uninspected document requires an exclusion reason or error"
            )
        for label, value in (
            ("exclusion reason", self.exclusion_reason),
            ("reference error", self.error),
        ):
            if value is not None:
                _identifier(value, label)

    def manifest_row(self) -> dict:
        return {
            "document_type": self.document_type,
            "error": self.error,
            "exclusion_reason": self.exclusion_reason,
            "fingerprint": self.fingerprint,
            "inspected": self.inspected,
            "path": self.path,
            "projection": (
                None if self.projection is None else self.projection.to_dict()
            ),
            "scope_class": self.scope_class,
        }


@dataclass(frozen=True)
class ReferenceMatch:
    direction: str
    source_path: str
    target_path: str
    reference_kind: str

    def __post_init__(self) -> None:
        if self.direction not in ("inbound", "outbound"):
            raise ReferenceAnalysisError("reference direction is invalid")
        _path(self.source_path, "reference source path")
        _path(self.target_path, "reference target path")
        if self.source_path == self.target_path:
            raise ReferenceAnalysisError("self reference match is invalid")
        if self.reference_kind not in inventory._REFERENCE_KINDS:
            raise ReferenceAnalysisError("reference kind is invalid")

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "reference_kind": self.reference_kind,
            "source_path": self.source_path,
            "target_path": self.target_path,
        }


@dataclass
class ReferenceTraversalCounter:
    """Deterministic operation counter for reference complexity gates."""

    document_visits: int = 0
    source_reference_visits: int = 0
    serialized_edge_visits: int = 0
    indexed_edge_visits: int = 0
    returned_match_visits: int = 0

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (
                self.document_visits,
                self.source_reference_visits,
                self.serialized_edge_visits,
                self.indexed_edge_visits,
                self.returned_match_visits,
            )
        ):
            raise ReferenceAnalysisError("reference traversal counters are invalid")


@dataclass(frozen=True)
class ReferenceCoverageIssue:
    kind: str
    path: str
    reason: str

    def __post_init__(self) -> None:
        if self.kind not in ("error", "exclusion"):
            raise ReferenceAnalysisError("coverage issue kind is invalid")
        _path(self.path, "coverage issue path")
        _identifier(self.reason, "coverage issue reason")

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "path": self.path,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ReferenceEnvelope:
    analyzer_version: str
    candidate_path: str
    complete: bool
    matches: Tuple[ReferenceMatch, ...]
    exclusions: Tuple[Tuple[str, str], ...]
    errors: Tuple[Tuple[str, str], ...]
    input_manifest: bytes
    input_manifest_sha256: str
    context_id: str
    context_sha256: str


@dataclass(frozen=True)
class ReferenceEdge:
    source_path: str
    target_path: str
    reference_kind: str

    def __post_init__(self) -> None:
        _path(self.source_path, "reference edge source path")
        _path(self.target_path, "reference edge target path")
        if self.source_path == self.target_path:
            raise ReferenceAnalysisError("self reference edge is invalid")
        if self.reference_kind not in inventory._REFERENCE_KINDS:
            raise ReferenceAnalysisError("reference edge kind is invalid")

    def to_dict(self) -> dict:
        return {
            "reference_kind": self.reference_kind,
            "source_path": self.source_path,
            "target_path": self.target_path,
        }


@dataclass(frozen=True)
class _ReferenceContextIndex:
    matches_by_path: Mapping[str, Tuple[ReferenceMatch, ...]]
    exclusions: Tuple[Tuple[str, str], ...]
    errors: Tuple[Tuple[str, str], ...]
    scanned_roots: FrozenSet[str]
    document_paths: FrozenSet[str]

    def matches_for(
        self,
        candidate_path: str,
        *,
        traversal_counter: Optional[ReferenceTraversalCounter] = None,
    ) -> Tuple[ReferenceMatch, ...]:
        matches = self.matches_by_path.get(candidate_path, ())
        if traversal_counter is not None:
            if type(traversal_counter) is not ReferenceTraversalCounter:
                raise TypeError(
                    "traversal_counter must be ReferenceTraversalCounter"
                )
            traversal_counter.returned_match_visits += len(matches)
        return matches

    def covers_manifest_document(self, candidate_path: str) -> bool:
        return (
            candidate_path in self.document_paths
            and _covered_by_roots(candidate_path, self.scanned_roots)
        )


def _reference_context_index(
    *,
    edges: Sequence[ReferenceEdge],
    coverage_issues: Sequence[ReferenceCoverageIssue],
    scanned_roots: Sequence[str],
    document_paths: Sequence[str],
    traversal_counter: Optional[ReferenceTraversalCounter] = None,
) -> _ReferenceContextIndex:
    if traversal_counter is not None and type(
        traversal_counter
    ) is not ReferenceTraversalCounter:
        raise TypeError("traversal_counter must be ReferenceTraversalCounter")
    outbound: Dict[str, list] = {}
    inbound: Dict[str, list] = {}
    for edge in edges:
        if traversal_counter is not None:
            traversal_counter.indexed_edge_visits += 1
        outbound.setdefault(edge.source_path, []).append(
            ReferenceMatch(
                "outbound",
                edge.source_path,
                edge.target_path,
                edge.reference_kind,
            )
        )
        inbound.setdefault(edge.target_path, []).append(
            ReferenceMatch(
                "inbound",
                edge.source_path,
                edge.target_path,
                edge.reference_kind,
            )
        )
    matches = {path: tuple(rows) for path, rows in outbound.items()}
    for path, rows in inbound.items():
        matches[path] = matches.get(path, ()) + tuple(rows)
    frozen_matches = MappingProxyType(matches)
    return _ReferenceContextIndex(
        matches_by_path=frozen_matches,
        exclusions=tuple(
            (issue.path, issue.reason)
            for issue in coverage_issues
            if issue.kind == "exclusion"
        ),
        errors=tuple(
            (issue.path, issue.reason)
            for issue in coverage_issues
            if issue.kind == "error"
        ),
        scanned_roots=frozenset(scanned_roots),
        document_paths=frozenset(document_paths),
    )


@dataclass(frozen=True)
class ReferenceContext:
    analyzer_version: str
    context_id: str
    context_sha256: str
    content_sha256: str
    parser_types: Tuple[str, ...]
    scanned_roots: Tuple[str, ...]
    registry_source: Mapping[str, str]
    navigation_sources: Tuple[Mapping[str, str], ...]
    documents: Tuple[Mapping[str, Any], ...]
    coverage_issues: Tuple[ReferenceCoverageIssue, ...]
    edges: Tuple[ReferenceEdge, ...]
    frontier_complete: bool
    canonical_bytes: bytes = field(repr=False, compare=False)
    canonical_sha256: str = field(repr=False, compare=False)
    _index: _ReferenceContextIndex = field(repr=False, compare=False)

    def _content_payload(self) -> dict:
        return {
            "analyzer_version": self.analyzer_version,
            "coverage_issues": [row.to_dict() for row in self.coverage_issues],
            "documents": [_thaw_json(row) for row in self.documents],
            "edges": [row.to_dict() for row in self.edges],
            "frontier_complete": self.frontier_complete,
            "navigation_sources": [
                _thaw_json(row) for row in self.navigation_sources
            ],
            "parser_types": list(self.parser_types),
            "registry_source": _thaw_json(self.registry_source),
            "scanned_roots": list(self.scanned_roots),
        }

    def _context_payload(self) -> dict:
        value = self._content_payload()
        value.update(
            {
                "content_sha256": self.content_sha256,
                "context_id": self.context_id,
                "schema_version": 1,
            }
        )
        return value

    def to_dict(self) -> dict:
        value = self._context_payload()
        value["context_sha256"] = self.context_sha256
        return value

    def matches_for(
        self,
        candidate_path: str,
        *,
        traversal_counter: Optional[ReferenceTraversalCounter] = None,
    ) -> Tuple[ReferenceMatch, ...]:
        candidate = _path(candidate_path, "candidate path")
        return self._index.matches_for(
            candidate,
            traversal_counter=traversal_counter,
        )

    def is_complete_for(self, candidate_path: str) -> bool:
        candidate = _path(candidate_path, "candidate path")
        return (
            self.frontier_complete
            and self._index.covers_manifest_document(candidate)
        )

    @property
    def exclusions(self) -> Tuple[Tuple[str, str], ...]:
        return self._index.exclusions

    @property
    def errors(self) -> Tuple[Tuple[str, str], ...]:
        return self._index.errors


def _reference_targets(
    document: ReferenceDocument,
) -> Tuple[Tuple[str, str, bool], ...]:
    if document.projection is not None:
        return tuple(
            (row.kind, row.target, True)
            for row in document.projection.references
        )
    assert document.text is not None
    rows = []
    rows.extend(
        ("markdown-inline", match.group(1))
        for match in _MARKDOWN_INLINE.finditer(document.text)
    )
    rows.extend(
        ("markdown-reference", match.group(1) or match.group(2))
        for match in _MARKDOWN_REFERENCE.finditer(document.text)
    )
    rows.extend(
        ("autolink", match.group(1))
        for match in _AUTOLINK.finditer(document.text)
    )
    rows.extend(
        ("html-attribute", match.group(2))
        for match in _HTML_ATTRIBUTE.finditer(document.text)
    )
    return tuple((kind, target, False) for kind, target in rows)


def _resolve_reference(source_path: str, raw_value: str) -> Optional[str]:
    value = raw_value.strip().split("#", 1)[0].split("?", 1)[0]
    if not value or value.startswith(("/", "#")):
        return None
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value):
        return None
    root_relative = value.startswith(
        ("_registry/", "projects/", "docs/", "memory/", "mirrors/", "inbox/")
    )
    normalized = posixpath.normpath(
        value
        if root_relative
        else posixpath.join(posixpath.dirname(source_path), value)
    )
    if normalized in (".", "..") or normalized.startswith("../"):
        return None
    try:
        return _path(normalized, "reference target")
    except ReferenceAnalysisError:
        return None


def _projection_from_dict(
    value: Any,
    *,
    source_path: str,
    traversal_counter: Optional[ReferenceTraversalCounter] = None,
) -> Optional[inventory.ReferenceProjection]:
    if value is None:
        return None
    if type(value) is not dict:
        raise ReferenceAnalysisError("document projection is invalid")
    version = value.get("projection_version")
    if version == inventory._LEGACY_REFERENCE_PROJECTION_VERSION:
        _exact_dict(value, _PROJECTION_V1_FIELDS, "document projection")
        parser_types = inventory._LEGACY_REFERENCE_PARSER_TYPES
    elif version == inventory._REFERENCE_PROJECTION_VERSION:
        _exact_dict(value, _PROJECTION_V2_FIELDS, "document projection")
        if (
            type(value["parser_types"]) is not list
            or value["parser_types"] != list(inventory._REFERENCE_PARSER_TYPES)
        ):
            raise ReferenceAnalysisError(
                "document projection parser coverage is invalid"
            )
        parser_types = inventory._REFERENCE_PARSER_TYPES
    else:
        raise ReferenceAnalysisError("document projection version is invalid")
    _hash(value["projection_sha256"], "document projection hash")
    serialized_references = value["references"]
    if type(serialized_references) is not list:
        raise ReferenceAnalysisError("document projection references are invalid")
    parsed_references = []
    for serialized in serialized_references:
        if traversal_counter is not None:
            traversal_counter.source_reference_visits += 1
        row = _exact_dict(
            serialized,
            _REFERENCE_FIELDS,
            "document projection reference",
        )
        if type(row["kind"]) is not str or type(row["target"]) is not str:
            raise ReferenceAnalysisError(
                "document projection reference is invalid"
            )
        try:
            parsed_references.append(
                inventory.InternalReference(row["kind"], row["target"])
            )
        except (TypeError, ValueError) as exc:
            raise ReferenceAnalysisError(
                "document projection reference is invalid"
            ) from exc
    references_tuple = tuple(parsed_references)
    reference_keys = tuple(
        (row.kind, row.target) for row in references_tuple
    )
    if not _strictly_increasing(reference_keys):
        raise ReferenceAnalysisError(
            "document projection references must be unique and sorted"
        )
    try:
        return inventory.ReferenceProjection(
            source_path=source_path,
            projection_version=version,
            projection_sha256=value["projection_sha256"],
            references=references_tuple,
            parser_types=parser_types,
        )
    except (TypeError, ValueError) as exc:
        raise ReferenceAnalysisError("document projection is invalid") from exc


def _document_manifest_from_dict(
    value: Any,
    *,
    traversal_counter: Optional[ReferenceTraversalCounter] = None,
) -> Tuple[dict, Optional[inventory.ReferenceProjection]]:
    row = _exact_dict(value, _DOCUMENT_FIELDS, "reference document")
    for field_name, label in (
        ("document_type", "document type"),
        ("scope_class", "scope class"),
    ):
        if type(row[field_name]) is not str:
            raise ReferenceAnalysisError("%s is invalid" % label)
        _identifier(row[field_name], label)
    if type(row["path"]) is not str:
        raise ReferenceAnalysisError("document path is invalid")
    path = _path(row["path"], "document path")
    fingerprint = _hash(row["fingerprint"], "document fingerprint")
    inspected = row["inspected"]
    if type(inspected) is not bool:
        raise ReferenceAnalysisError("inspected must be boolean")
    exclusion_reason = _optional_identifier(
        row["exclusion_reason"], "exclusion reason"
    )
    error = _optional_identifier(row["error"], "reference error")
    projection = _projection_from_dict(
        row["projection"],
        source_path=path,
        traversal_counter=traversal_counter,
    )
    if inspected:
        if exclusion_reason is not None or error is not None:
            raise ReferenceAnalysisError("inspected document cannot be excluded")
    else:
        if projection is not None:
            raise ReferenceAnalysisError(
                "uninspected document cannot carry safe projection"
            )
        if exclusion_reason is None and error is None:
            raise ReferenceAnalysisError(
                "uninspected document requires an exclusion reason or error"
            )
    return (
        {
            "document_type": row["document_type"],
            "error": error,
            "exclusion_reason": exclusion_reason,
            "fingerprint": fingerprint,
            "inspected": inspected,
            "path": path,
            "projection": None if projection is None else projection.to_dict(),
            "scope_class": row["scope_class"],
        },
        projection,
    )


def reference_context_from_dict(
    value: Any,
    *,
    traversal_counter: Optional[ReferenceTraversalCounter] = None,
) -> ReferenceContext:
    """Strictly validate and index one serialized reference context.

    The returned object owns a single canonical byte/hash representation and a
    runtime-only immutable adjacency index. No index data enters the sealed
    serialized payload.
    """

    if traversal_counter is not None and type(
        traversal_counter
    ) is not ReferenceTraversalCounter:
        raise TypeError("traversal_counter must be ReferenceTraversalCounter")
    context = _exact_dict(value, _CONTEXT_FIELDS, "reference context")
    if type(context["schema_version"]) is not int or context["schema_version"] != 1:
        raise ReferenceAnalysisError("reference context schema version is invalid")
    if type(context["analyzer_version"]) is not str:
        raise ReferenceAnalysisError("analyzer version is invalid")
    analyzer_version = _identifier(
        context["analyzer_version"], "analyzer version"
    )
    if (
        type(context["parser_types"]) is not list
        or context["parser_types"] != list(inventory._REFERENCE_PARSER_TYPES)
    ):
        raise ReferenceAnalysisError("reference parser types are invalid")
    if type(context["frontier_complete"]) is not bool:
        raise ReferenceAnalysisError("reference frontier completeness is invalid")

    serialized_roots = context["scanned_roots"]
    if type(serialized_roots) is not list or any(
        type(root) is not str for root in serialized_roots
    ):
        raise ReferenceAnalysisError("reference scanned roots are invalid")
    roots = tuple(_path(root, "scanned root") for root in serialized_roots)
    if not _strictly_increasing(roots):
        raise ReferenceAnalysisError(
            "reference scanned roots must be unique and sorted"
        )

    registry = _exact_dict(
        context["registry_source"],
        _REGISTRY_FIELDS,
        "reference registry source",
    )
    if (
        registry["kind"] != "compiled-registry"
        or registry["source_id"] != "placement-registry"
    ):
        raise ReferenceAnalysisError("reference registry source is invalid")
    registry_source = {
        "kind": "compiled-registry",
        "sha256": _hash(registry["sha256"], "registry source hash"),
        "source_id": "placement-registry",
    }

    serialized_navigation = context["navigation_sources"]
    if type(serialized_navigation) is not list:
        raise ReferenceAnalysisError("reference navigation sources are invalid")
    navigation_sources = []
    for serialized in serialized_navigation:
        row = _exact_dict(
            serialized,
            _NAVIGATION_FIELDS,
            "reference navigation source",
        )
        if type(row["path"]) is not str:
            raise ReferenceAnalysisError("reference navigation path is invalid")
        navigation_sources.append(
            {
                "path": _path(row["path"], "reference navigation path"),
                "sha256": _hash(
                    row["sha256"], "reference navigation source hash"
                ),
            }
        )
    navigation_paths = tuple(row["path"] for row in navigation_sources)
    if not _strictly_increasing(navigation_paths):
        raise ReferenceAnalysisError(
            "reference navigation sources must be unique and sorted"
        )

    serialized_documents = context["documents"]
    if type(serialized_documents) is not list:
        raise ReferenceAnalysisError("reference documents are invalid")
    documents = []
    projections: Dict[str, inventory.ReferenceProjection] = {}
    for serialized in serialized_documents:
        if traversal_counter is not None:
            traversal_counter.document_visits += 1
        manifest, projection = _document_manifest_from_dict(
            serialized,
            traversal_counter=traversal_counter,
        )
        documents.append(manifest)
        if projection is not None:
            projections[manifest["path"]] = projection
    document_paths = tuple(row["path"] for row in documents)
    if not _strictly_increasing(document_paths):
        raise ReferenceAnalysisError(
            "reference documents must be unique and sorted"
        )

    serialized_issues = context["coverage_issues"]
    if type(serialized_issues) is not list:
        raise ReferenceAnalysisError("reference coverage issues are invalid")
    coverage_issues = []
    for serialized in serialized_issues:
        row = _exact_dict(
            serialized,
            _COVERAGE_FIELDS,
            "reference coverage issue",
        )
        if any(type(row[name]) is not str for name in _COVERAGE_FIELDS):
            raise ReferenceAnalysisError("reference coverage issue is invalid")
        coverage_issues.append(
            ReferenceCoverageIssue(row["kind"], row["path"], row["reason"])
        )
    issues_tuple = tuple(coverage_issues)
    issue_keys = tuple(
        (row.kind, row.path, row.reason) for row in issues_tuple
    )
    if not _strictly_increasing(issue_keys):
        raise ReferenceAnalysisError(
            "reference coverage issues must be unique and sorted"
        )

    serialized_edges = context["edges"]
    if type(serialized_edges) is not list:
        raise ReferenceAnalysisError("reference edges are invalid")
    edges = []
    for serialized in serialized_edges:
        if traversal_counter is not None:
            traversal_counter.serialized_edge_visits += 1
        row = _exact_dict(serialized, _EDGE_FIELDS, "reference edge")
        if any(type(row[name]) is not str for name in _EDGE_FIELDS):
            raise ReferenceAnalysisError("reference edge is invalid")
        edges.append(
            ReferenceEdge(
                row["source_path"],
                row["target_path"],
                row["reference_kind"],
            )
        )
    edges_tuple = tuple(edges)
    edge_keys = tuple(
        (row.source_path, row.target_path, row.reference_kind)
        for row in edges_tuple
    )
    if not _strictly_increasing(edge_keys):
        raise ReferenceAnalysisError("reference edges must be unique and sorted")

    expected_navigation = tuple(
        {
            "path": row["path"],
            "sha256": row["fingerprint"],
        }
        for row in documents
        if row["document_type"] == "generated-navigation"
        or row["path"].endswith("/_projects.md")
    )
    if tuple(navigation_sources) != expected_navigation:
        raise ReferenceAnalysisError(
            "reference navigation sources do not match documents"
        )

    if documents:
        inspected_paths = {
            row["path"] for row in documents if row["inspected"]
        }
        if any(edge.source_path not in inspected_paths for edge in edges_tuple):
            raise ReferenceAnalysisError(
                "reference edge source is not an inspected document"
            )
        expected_projected_edges = {
            ReferenceEdge(source_path, reference.target, reference.kind)
            for source_path, projection in projections.items()
            for reference in projection.references
            if reference.target != source_path
        }
        actual_projected_edges = {
            edge for edge in edges_tuple if edge.source_path in projections
        }
        if actual_projected_edges != expected_projected_edges:
            raise ReferenceAnalysisError(
                "reference projection does not match context edges"
            )
        issue_set = set(issues_tuple)
        required_issues = {
            ReferenceCoverageIssue("exclusion", row["path"], row["exclusion_reason"])
            for row in documents
            if row["exclusion_reason"] is not None
        }
        required_issues.update(
            ReferenceCoverageIssue("error", row["path"], row["error"])
            for row in documents
            if row["error"] is not None
        )
        required_issues.update(
            ReferenceCoverageIssue(
                "exclusion", path, "parser-coverage-incomplete"
            )
            for path, projection in projections.items()
            if projection.parser_types != inventory._REFERENCE_PARSER_TYPES
        )
        if not required_issues.issubset(issue_set):
            raise ReferenceAnalysisError(
                "reference document coverage issues are incomplete"
            )

    root_set = frozenset(roots)

    def covered(path: str) -> bool:
        return _covered_by_roots(path, root_set)

    expected_frontier_complete = (
        bool(roots)
        and all(covered(row["path"]) for row in documents)
        and all(row["inspected"] for row in documents)
        and not issues_tuple
    )
    if context["frontier_complete"] is not expected_frontier_complete:
        raise ReferenceAnalysisError(
            "reference frontier completeness does not match coverage"
        )

    content_payload = {
        "analyzer_version": analyzer_version,
        "coverage_issues": [row.to_dict() for row in issues_tuple],
        "documents": documents,
        "edges": [row.to_dict() for row in edges_tuple],
        "frontier_complete": context["frontier_complete"],
        "navigation_sources": navigation_sources,
        "parser_types": list(inventory._REFERENCE_PARSER_TYPES),
        "registry_source": registry_source,
        "scanned_roots": list(roots),
    }
    content_sha256 = sha256_bytes(canonical_json_bytes(content_payload))
    if (
        _hash(context["content_sha256"], "reference context content hash")
        != content_sha256
    ):
        raise ReferenceAnalysisError("reference context content hash mismatch")
    context_id = "reference-context-%s" % content_sha256[:24]
    if type(context["context_id"]) is not str or context["context_id"] != context_id:
        raise ReferenceAnalysisError("reference context id mismatch")
    context_payload = dict(content_payload)
    context_payload.update(
        {
            "content_sha256": content_sha256,
            "context_id": context_id,
            "schema_version": 1,
        }
    )
    context_sha256 = sha256_bytes(canonical_json_bytes(context_payload))
    if _hash(context["context_sha256"], "reference context hash") != context_sha256:
        raise ReferenceAnalysisError("reference context hash mismatch")
    sealed_payload = dict(context_payload)
    sealed_payload["context_sha256"] = context_sha256
    canonical_bytes = canonical_json_bytes(sealed_payload)
    index = _reference_context_index(
        edges=edges_tuple,
        coverage_issues=issues_tuple,
        scanned_roots=roots,
        document_paths=document_paths,
        traversal_counter=traversal_counter,
    )
    return ReferenceContext(
        analyzer_version=analyzer_version,
        context_id=context_id,
        context_sha256=context_sha256,
        content_sha256=content_sha256,
        parser_types=inventory._REFERENCE_PARSER_TYPES,
        scanned_roots=roots,
        registry_source=_freeze_json(registry_source),
        navigation_sources=tuple(
            _freeze_json(row) for row in navigation_sources
        ),
        documents=tuple(_freeze_json(row) for row in documents),
        coverage_issues=issues_tuple,
        edges=edges_tuple,
        frontier_complete=context["frontier_complete"],
        canonical_bytes=canonical_bytes,
        canonical_sha256=sha256_bytes(canonical_bytes),
        _index=index,
    )


validate_reference_context = reference_context_from_dict


class ReferenceAnalyzer:
    def __init__(self, analyzer_version: str) -> None:
        self.analyzer_version = _identifier(analyzer_version, "analyzer version")

    def build_context(
        self,
        *,
        documents: Sequence[ReferenceDocument],
        scanned_roots: Sequence[str],
        registry_source_sha256: str,
        coverage_issues: Sequence[ReferenceCoverageIssue] = (),
        traversal_counter: Optional[ReferenceTraversalCounter] = None,
    ) -> ReferenceContext:
        if traversal_counter is not None and type(
            traversal_counter
        ) is not ReferenceTraversalCounter:
            raise TypeError("traversal_counter must be ReferenceTraversalCounter")
        if _HASH.fullmatch(registry_source_sha256) is None:
            raise ReferenceAnalysisError("registry source hash is invalid")
        if not isinstance(documents, (tuple, list)):
            raise TypeError("documents must be a sequence")
        ordered_documents = tuple(sorted(documents, key=lambda value: value.path))
        if len({document.path for document in ordered_documents}) != len(
            ordered_documents
        ):
            raise ReferenceAnalysisError("reference document paths must be unique")
        if not isinstance(coverage_issues, (tuple, list)) or any(
            type(issue) is not ReferenceCoverageIssue for issue in coverage_issues
        ):
            raise TypeError(
                "coverage_issues must contain ReferenceCoverageIssue values"
            )
        ordered_issues = tuple(
            sorted(
                set(coverage_issues),
                key=lambda issue: (issue.kind, issue.path, issue.reason),
            )
        )
        roots = tuple(
            sorted(set(_path(root, "scanned root") for root in scanned_roots))
        )
        issues = set(ordered_issues)
        edges = set()
        for document in ordered_documents:
            if traversal_counter is not None:
                traversal_counter.document_visits += 1
            if not document.inspected:
                if document.exclusion_reason is not None:
                    issues.add(
                        ReferenceCoverageIssue(
                            "exclusion", document.path, document.exclusion_reason
                        )
                    )
                if document.error is not None:
                    issues.add(
                        ReferenceCoverageIssue(
                            "error", document.path, document.error
                        )
                    )
                continue
            parser_types = (
                document.projection.parser_types
                if document.projection is not None
                else inventory._REFERENCE_PARSER_TYPES
            )
            if parser_types != inventory._REFERENCE_PARSER_TYPES:
                issues.add(
                    ReferenceCoverageIssue(
                        "exclusion", document.path, "parser-coverage-incomplete"
                    )
                )
            for kind, raw_target, already_canonical in _reference_targets(document):
                if traversal_counter is not None:
                    traversal_counter.source_reference_visits += 1
                target = (
                    raw_target
                    if already_canonical
                    else _resolve_reference(document.path, raw_target)
                )
                if target is None:
                    continue
                if target != document.path:
                    edges.add(ReferenceEdge(document.path, target, kind))
        ordered_issues = tuple(
            sorted(issues, key=lambda row: (row.kind, row.path, row.reason))
        )
        ordered_edges = tuple(
            sorted(
                edges,
                key=lambda row: (
                    row.source_path,
                    row.target_path,
                    row.reference_kind,
                ),
            )
        )

        root_set = frozenset(roots)

        def covered(path: str) -> bool:
            return _covered_by_roots(path, root_set)

        frontier_complete = (
            bool(roots)
            and all(covered(document.path) for document in ordered_documents)
            and all(document.inspected for document in ordered_documents)
            and not ordered_issues
        )
        documents_manifest = tuple(
            document.manifest_row() for document in ordered_documents
        )
        navigation_sources = tuple(
            {
                "path": document.path,
                "sha256": document.fingerprint,
            }
            for document in ordered_documents
            if document.document_type == "generated-navigation"
            or document.path.endswith("/_projects.md")
        )
        registry_source = {
            "kind": "compiled-registry",
            "sha256": registry_source_sha256,
            "source_id": "placement-registry",
        }
        content_payload = {
            "analyzer_version": self.analyzer_version,
            "coverage_issues": [row.to_dict() for row in ordered_issues],
            "documents": list(documents_manifest),
            "edges": [row.to_dict() for row in ordered_edges],
            "frontier_complete": frontier_complete,
            "navigation_sources": list(navigation_sources),
            "parser_types": list(inventory._REFERENCE_PARSER_TYPES),
            "registry_source": registry_source,
            "scanned_roots": list(roots),
        }
        content_sha256 = sha256_bytes(canonical_json_bytes(content_payload))
        context_id = "reference-context-%s" % content_sha256[:24]
        context_payload = dict(content_payload)
        context_payload.update(
            {
                "content_sha256": content_sha256,
                "context_id": context_id,
                "schema_version": 1,
            }
        )
        context_sha256 = sha256_bytes(canonical_json_bytes(context_payload))
        sealed_context_payload = dict(context_payload)
        sealed_context_payload["context_sha256"] = context_sha256
        sealed_context_bytes = canonical_json_bytes(sealed_context_payload)
        index = _reference_context_index(
            edges=ordered_edges,
            coverage_issues=ordered_issues,
            scanned_roots=roots,
            document_paths=tuple(
                document.path for document in ordered_documents
            ),
            traversal_counter=traversal_counter,
        )
        return ReferenceContext(
            analyzer_version=self.analyzer_version,
            context_id=context_id,
            context_sha256=context_sha256,
            content_sha256=content_sha256,
            parser_types=inventory._REFERENCE_PARSER_TYPES,
            scanned_roots=roots,
            registry_source=_freeze_json(registry_source),
            navigation_sources=tuple(
                _freeze_json(row) for row in navigation_sources
            ),
            documents=tuple(
                _freeze_json(row) for row in documents_manifest
            ),
            coverage_issues=ordered_issues,
            edges=ordered_edges,
            frontier_complete=frontier_complete,
            canonical_bytes=sealed_context_bytes,
            canonical_sha256=sha256_bytes(sealed_context_bytes),
            _index=index,
        )

    def analyze_context(
        self,
        *,
        context: ReferenceContext,
        candidate_path: str,
        traversal_counter: Optional[ReferenceTraversalCounter] = None,
    ) -> ReferenceEnvelope:
        if type(context) is not ReferenceContext:
            raise TypeError("context must be ReferenceContext")
        candidate = _path(candidate_path, "candidate path")
        matches = context.matches_for(
            candidate,
            traversal_counter=traversal_counter,
        )
        return ReferenceEnvelope(
            analyzer_version=self.analyzer_version,
            candidate_path=candidate,
            complete=context.is_complete_for(candidate),
            matches=matches,
            exclusions=context.exclusions,
            errors=context.errors,
            input_manifest=context.canonical_bytes,
            input_manifest_sha256=context.canonical_sha256,
            context_id=context.context_id,
            context_sha256=context.context_sha256,
        )

    def analyze(
        self,
        *,
        candidate_path: str,
        documents: Sequence[ReferenceDocument],
        scanned_roots: Sequence[str],
        registry_source_sha256: str,
        coverage_issues: Sequence[ReferenceCoverageIssue] = (),
    ) -> ReferenceEnvelope:
        context = self.build_context(
            documents=documents,
            scanned_roots=scanned_roots,
            registry_source_sha256=registry_source_sha256,
            coverage_issues=coverage_issues,
        )
        return self.analyze_context(
            context=context,
            candidate_path=candidate_path,
        )


__all__ = [
    "ReferenceAnalysisError",
    "ReferenceAnalyzer",
    "ReferenceContext",
    "ReferenceCoverageIssue",
    "ReferenceDocument",
    "ReferenceEnvelope",
    "ReferenceEdge",
    "ReferenceMatch",
    "ReferenceTraversalCounter",
    "reference_context_from_dict",
    "validate_reference_context",
]
