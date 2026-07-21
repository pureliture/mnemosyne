"""Deterministic, tentative classification evidence for Mnemosyne M2.

This module is deliberately pure.  It turns policy-owned routing facts and
bounded item metadata into evidence and candidates; it never writes a user
decision or treats a candidate as placement authority.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from .canonical_json import canonical_json_bytes, sha256_bytes
from .inventory import RAW_PATH_ENCODING, decode_canonical_raw_path
from .policy import CompiledCategory, CompiledWorkstream


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AXES = frozenset(("workstream", "role", "authority", "lifecycle"))
_CONFIDENCE_BANDS = frozenset(("high", "medium", "low", "unknown"))
_FRESHNESS = frozenset(("fresh", "stale", "unknown"))
_PERSISTENT_FRONTMATTER_AXES = frozenset(
    ("workstream", "role", "authority", "lifecycle")
)
_NO_PROJECTION_SCOPE_CLASSES = frozenset(
    (
        "opaque-private-evidence",
        "evidence",
        "memory",
        "protected",
        "never-touch",
    )
)


class ClassificationError(ValueError):
    """A classifier input would make deterministic provenance ambiguous."""


def _require_identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ClassificationError("%s is invalid" % label)
    return value


def _normalize_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ClassificationError("item path must be raw-relative")
    normalized = posixpath.normpath(value)
    if normalized != value or normalized in (".", "..") or normalized.startswith("../"):
        raise ClassificationError("item path must be canonical")
    if any(ord(character) < 0x20 for character in value):
        raise ClassificationError("item path contains control characters")
    return value


def _raw_relative(absolute_path: str, raw_root: str) -> Optional[str]:
    if not isinstance(absolute_path, str) or not isinstance(raw_root, str):
        return None
    root = raw_root.rstrip("/")
    if not root.startswith("/") or absolute_path == root:
        return None
    prefix = root + "/"
    if not absolute_path.startswith(prefix):
        return None
    relative = absolute_path[len(prefix) :]
    try:
        return _normalize_relative_path(relative)
    except ClassificationError:
        return None


def _route_view_path(canonical_path: str) -> Optional[str]:
    """Return a lossless UTF-8 route view while preserving canonical identity."""

    if not canonical_path.startswith(RAW_PATH_ENCODING):
        return canonical_path
    try:
        components = decode_canonical_raw_path(canonical_path)
        decoded = tuple(component.decode("utf-8", "strict") for component in components)
        return _normalize_relative_path("/".join(decoded))
    except (UnicodeDecodeError, ValueError, ClassificationError):
        return None


@dataclass(frozen=True)
class SafeContentProjection:
    title: Optional[str]
    headings: Tuple[str, ...]
    frontmatter: Tuple[Tuple[str, str], ...]
    references: Tuple[str, ...]
    context_freshness: str

    def __post_init__(self) -> None:
        if self.title is not None:
            _validate_projection_text(self.title, "projection title", 512)
        if type(self.headings) is not tuple:
            raise ClassificationError("projection headings must be immutable")
        for heading in self.headings:
            _validate_projection_text(heading, "projection heading", 512)
        if type(self.frontmatter) is not tuple:
            raise ClassificationError("projection frontmatter must be immutable")
        if tuple(sorted(self.frontmatter)) != self.frontmatter:
            raise ClassificationError("projection frontmatter must be sorted")
        seen_keys = set()
        for key, value in self.frontmatter:
            if key not in _PERSISTENT_FRONTMATTER_AXES or key in seen_keys:
                raise ClassificationError("projection frontmatter key is invalid")
            seen_keys.add(key)
            _require_identifier(value, "projection frontmatter value")
        if type(self.references) is not tuple:
            raise ClassificationError("projection references must be immutable")
        for reference in self.references:
            _validate_projection_text(reference, "projection reference", 1024)
        if self.context_freshness not in _FRESHNESS:
            raise ClassificationError("projection freshness is invalid")


def _validate_projection_text(value: str, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ClassificationError("%s is invalid" % label)
    return value


@dataclass(frozen=True)
class ClassificationInput:
    observation_id: str
    path: str
    scope_class: str
    scope_rule_id: str
    content_allowed: bool
    sensitivity: str = "public"
    access_domain: str = "default"
    projection: Optional[SafeContentProjection] = None
    projection_authorization_id: Optional[str] = None
    reference_workstreams: Tuple[str, ...] = ()
    fingerprint_value: Optional[str] = None
    duplicate_observation_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.observation_id, "observation id")
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        _require_identifier(self.scope_class, "scope class")
        _require_identifier(self.scope_rule_id, "scope rule id")
        if type(self.content_allowed) is not bool:
            raise ClassificationError("content_allowed must be boolean")
        _require_identifier(self.sensitivity, "sensitivity")
        _require_identifier(self.access_domain, "access domain")
        if self.projection is not None and type(self.projection) is not SafeContentProjection:
            raise TypeError("projection must be SafeContentProjection")
        if self.projection is not None and not self.content_allowed:
            raise ClassificationError("content projection is not allowed for this item")
        if (
            self.projection is not None
            and self.scope_class in _NO_PROJECTION_SCOPE_CLASSES
        ):
            raise ClassificationError("content projection is forbidden for opaque scope")
        if self.projection_authorization_id is not None:
            _require_identifier(
                self.projection_authorization_id, "projection authorization id"
            )
        if (
            self.projection is not None
            and (self.sensitivity == "private" or self.scope_class == "private-reviewable")
            and self.projection_authorization_id is None
        ):
            raise ClassificationError(
                "private projection requires exact authorization"
            )
        if type(self.reference_workstreams) is not tuple or tuple(
            sorted(set(self.reference_workstreams))
        ) != self.reference_workstreams:
            raise ClassificationError(
                "reference workstreams must be unique and sorted"
            )
        for workstream_id in self.reference_workstreams:
            _require_identifier(workstream_id, "reference workstream")
        if self.fingerprint_value is not None and re.fullmatch(
            r"[0-9a-f]{64}", self.fingerprint_value
        ) is None:
            raise ClassificationError("fingerprint value is invalid")
        if type(self.duplicate_observation_ids) is not tuple or tuple(
            sorted(set(self.duplicate_observation_ids))
        ) != self.duplicate_observation_ids:
            raise ClassificationError(
                "duplicate observation ids must be unique and sorted"
            )
        for observation_id in self.duplicate_observation_ids:
            _require_identifier(observation_id, "duplicate observation id")
            if observation_id == self.observation_id:
                raise ClassificationError("duplicate observation cannot reference itself")
        if bool(self.fingerprint_value) != bool(self.duplicate_observation_ids):
            raise ClassificationError(
                "duplicate evidence requires fingerprint and observations"
            )
        if (
            self.fingerprint_value is not None
            and (self.sensitivity == "private" or self.scope_class == "private-reviewable")
        ):
            raise ClassificationError(
                "private classification cannot persist content hash evidence"
            )


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    provider: str
    kind: str
    value: str
    provenance: str
    context_freshness: str

    def __post_init__(self) -> None:
        _require_identifier(self.evidence_id, "evidence id")
        _require_identifier(self.provider, "evidence provider")
        _require_identifier(self.kind, "evidence kind")
        if not isinstance(self.value, str) or not self.value:
            raise ClassificationError("evidence value is required")
        if not isinstance(self.provenance, str) or not self.provenance:
            raise ClassificationError("evidence provenance is required")
        if self.context_freshness not in _FRESHNESS:
            raise ClassificationError("evidence freshness is invalid")

    def to_dict(self) -> dict:
        return {
            "context_freshness": self.context_freshness,
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "provenance": self.provenance,
            "provider": self.provider,
            "value": self.value,
        }


@dataclass(frozen=True)
class ClassificationCandidate:
    candidate_id: str
    axis: str
    value: str
    evidence_ids: Tuple[str, ...]
    confidence_band: str
    uncertainty_reason: Optional[str]
    context_freshness: str
    classifier_version: str

    def __post_init__(self) -> None:
        _require_identifier(self.candidate_id, "candidate id")
        if self.axis not in _AXES:
            raise ClassificationError("candidate axis is invalid")
        if not isinstance(self.value, str) or not self.value:
            raise ClassificationError("candidate value is required")
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            raise ClassificationError("candidate evidence ids must be unique and sorted")
        if self.confidence_band not in _CONFIDENCE_BANDS:
            raise ClassificationError("candidate confidence band is invalid")
        if self.context_freshness not in _FRESHNESS:
            raise ClassificationError("candidate freshness is invalid")
        _require_identifier(self.classifier_version, "classifier version")

    def to_dict(self) -> dict:
        return {
            "axis": self.axis,
            "candidate_id": self.candidate_id,
            "classifier_version": self.classifier_version,
            "confidence_band": self.confidence_band,
            "context_freshness": self.context_freshness,
            "evidence_ids": list(self.evidence_ids),
            "uncertainty_reason": self.uncertainty_reason,
            "value": self.value,
        }


@dataclass(frozen=True)
class ClassificationResult:
    observation_id: str
    classifier_version: str
    evidence: Tuple[Evidence, ...]
    candidates: Tuple[ClassificationCandidate, ...]

    def candidates_for(self, axis: str) -> Tuple[ClassificationCandidate, ...]:
        if axis not in _AXES:
            raise ClassificationError("classification axis is invalid")
        return tuple(candidate for candidate in self.candidates if candidate.axis == axis)

    def has_competing_candidates(self, axis: str) -> bool:
        return sum(
            candidate.uncertainty_reason == "competing-top-candidate"
            for candidate in self.candidates_for(axis)
        ) > 1

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "observation_id": self.observation_id,
            "classifier_version": self.classifier_version,
            "evidence": [row.to_dict() for row in self.evidence],
            "candidates": [row.to_dict() for row in self.candidates],
        }

    def classifications_jsonl(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def _stable_id(prefix: str, payload: object) -> str:
    return "%s-%s" % (prefix, sha256_bytes(canonical_json_bytes(payload))[:24])


def _normalized_tokens(value: str) -> str:
    return " ".join(
        part for part in re.split(r"[^a-z0-9]+", value.casefold()) if part
    )


def _matching_alias(
    workstream: CompiledWorkstream,
    normalized_text: str,
) -> Optional[str]:
    for alias in sorted(set((workstream.id,) + workstream.aliases)):
        normalized_alias = _normalized_tokens(alias)
        if normalized_alias and (
            " " + normalized_alias + " "
        ) in (" " + normalized_text + " "):
            return alias
    return None


def _path_workstream_evidence(
    item: ClassificationInput,
    *,
    raw_root: str,
    route_path: Optional[str],
    workstreams: Sequence[CompiledWorkstream],
    classifier_version: str,
) -> Tuple[Tuple[Evidence, int], ...]:
    rows = []
    workstreams_with_evidence = set()
    normalized_item_path = _normalized_tokens(
        "" if route_path is None else route_path
    )
    for workstream in sorted(workstreams, key=lambda value: value.id):
        if type(workstream) is not CompiledWorkstream:
            raise TypeError("workstreams must contain CompiledWorkstream values")
        project_home = _raw_relative(workstream.project_home, raw_root)
        if project_home is not None and route_path is not None and (
            route_path == project_home or route_path.startswith(project_home + "/")
        ):
            payload = {
                "classifier_version": classifier_version,
                "observation_id": item.observation_id,
                "provider": "registry-route",
                "project_home": project_home,
                "workstream": workstream.id,
            }
            evidence_id = _stable_id("evidence", payload)
            rows.append(
                (
                    Evidence(
                        evidence_id=evidence_id,
                        provider="registry-route",
                        kind="project-home",
                        value=workstream.id,
                        provenance="policy.workstreams[%s].project_home"
                        % workstream.id,
                        context_freshness="fresh",
                    ),
                    100,
                )
            )
            workstreams_with_evidence.add(workstream.id)

        matched_alias = _matching_alias(workstream, normalized_item_path)
        if (
            matched_alias is not None
            and workstream.id not in workstreams_with_evidence
        ):
            payload = {
                "alias": matched_alias,
                "classifier_version": classifier_version,
                "observation_id": item.observation_id,
                "provider": "path-alias",
                "workstream": workstream.id,
            }
            evidence_id = _stable_id("evidence", payload)
            rows.append(
                (
                    Evidence(
                        evidence_id=evidence_id,
                        provider="path-alias",
                        kind="alias-token",
                        value=workstream.id,
                        provenance="path:%s" % item.path,
                        context_freshness="fresh",
                    ),
                    20,
                )
            )
            workstreams_with_evidence.add(workstream.id)
    return tuple(rows)


def _reference_workstream_evidence(
    item: ClassificationInput,
    *,
    known_workstream_ids: set,
    classifier_version: str,
) -> Tuple[Tuple[Evidence, int], ...]:
    rows = []
    for workstream_id in item.reference_workstreams:
        if workstream_id not in known_workstream_ids:
            raise ClassificationError(
                "reference graph names an unknown workstream"
            )
        payload = {
            "classifier_version": classifier_version,
            "observation_id": item.observation_id,
            "provider": "source-reference-graph",
            "workstream": workstream_id,
        }
        evidence_id = _stable_id("evidence", payload)
        rows.append(
            (
                Evidence(
                    evidence_id=evidence_id,
                    provider="source-reference-graph",
                    kind="registered-reference",
                    value=workstream_id,
                    provenance="reference-graph:%s" % item.observation_id,
                    context_freshness="fresh",
                ),
                30,
            )
        )
    return tuple(rows)


def _projection_workstream_evidence(
    item: ClassificationInput,
    *,
    workstreams: Sequence[CompiledWorkstream],
    classifier_version: str,
) -> Tuple[Tuple[Evidence, int], ...]:
    if item.projection is None:
        return ()
    projection_parts = tuple(
        part
        for part in (
            (item.projection.title,)
            + item.projection.headings
            + item.projection.references
        )
        if part is not None
    )
    normalized_projection = " ".join(
        token
        for value in projection_parts
        for token in re.split(r"[^a-z0-9]+", value.casefold())
        if token
    )
    private_projection = (
        item.sensitivity == "private"
        or item.scope_class == "private-reviewable"
    )
    provider = (
        "ephemeral-private-projection"
        if private_projection
        else "safe-content-token"
    )
    rows = []
    for workstream in sorted(workstreams, key=lambda value: value.id):
        matched_alias = _matching_alias(workstream, normalized_projection)
        if matched_alias is None:
            continue
        payload = {
            "classifier_version": classifier_version,
            "observation_id": item.observation_id,
            "provider": provider,
            "workstream": workstream.id,
        }
        evidence_id = _stable_id("evidence", payload)
        rows.append(
            (
                Evidence(
                    evidence_id=evidence_id,
                    provider=provider,
                    kind="alias-token",
                    value=workstream.id,
                    provenance=(
                        "authorization:%s:ephemeral-content"
                        % item.projection_authorization_id
                        if private_projection
                        else "projection:title-heading-reference"
                    ),
                    context_freshness=item.projection.context_freshness,
                ),
                40,
            )
        )
    return tuple(rows)


def _workstream_candidates(
    item: ClassificationInput,
    *,
    evidence_rows: Sequence[Evidence],
    evidence_by_workstream: dict,
    score_by_workstream: dict,
    classifier_version: str,
) -> list:
    top_score = max(score_by_workstream.values()) if score_by_workstream else 0
    top_values = tuple(
        value
        for value in sorted(score_by_workstream)
        if score_by_workstream[value] == top_score
    )
    candidates = []
    for workstream_id in sorted(evidence_by_workstream):
        evidence_ids = tuple(sorted(evidence_by_workstream[workstream_id]))
        score = score_by_workstream[workstream_id]
        uncertainty_reason = None
        if len(top_values) > 1 and workstream_id in top_values:
            uncertainty_reason = "competing-top-candidate"
        elif score < 100:
            uncertainty_reason = (
                "single-content-provider"
                if any(
                    evidence.provider
                    in ("safe-content-token", "ephemeral-private-projection")
                    for evidence in evidence_rows
                    if evidence.evidence_id in evidence_ids
                )
                else "single-path-provider"
            )
        payload = {
            "axis": "workstream",
            "classifier_version": classifier_version,
            "evidence_ids": list(evidence_ids),
            "observation_id": item.observation_id,
            "value": workstream_id,
        }
        candidates.append(
            ClassificationCandidate(
                candidate_id=_stable_id("candidate", payload),
                axis="workstream",
                value=workstream_id,
                evidence_ids=evidence_ids,
                confidence_band="high" if score >= 100 else "low",
                uncertainty_reason=uncertainty_reason,
                context_freshness="fresh",
                classifier_version=classifier_version,
            )
        )
    return candidates


def _category_provider(
    item: ClassificationInput,
    *,
    route_path: Optional[str],
    categories: Sequence[CompiledCategory],
    classifier_version: str,
) -> Tuple[list, list]:
    matching_categories = []
    for category in sorted(categories, key=lambda value: value.id):
        if type(category) is not CompiledCategory:
            raise TypeError("categories must contain CompiledCategory values")
        matching_pattern = next(
            (
                pattern
                for pattern in sorted(category.patterns)
                if route_path is not None
                and (
                    fnmatch.fnmatchcase(route_path, pattern)
                    or fnmatch.fnmatchcase(posixpath.basename(route_path), pattern)
                )
            ),
            None,
        )
        if matching_pattern is not None:
            matching_categories.append((category, matching_pattern))

    evidence_rows = []
    candidate_rows = []
    for category, pattern in matching_categories:
        evidence_payload = {
            "category": category.id,
            "classifier_version": classifier_version,
            "observation_id": item.observation_id,
            "pattern": pattern,
            "provider": "path-pattern",
        }
        evidence_id = _stable_id("evidence", evidence_payload)
        evidence_rows.append(
            Evidence(
                evidence_id=evidence_id,
                provider="path-pattern",
                kind="category-pattern",
                value=category.id,
                provenance="policy.categories[%s].patterns:%s"
                % (category.id, pattern),
                context_freshness="fresh",
            )
        )
        candidate_payload = {
            "axis": "role",
            "classifier_version": classifier_version,
            "evidence_ids": [evidence_id],
            "observation_id": item.observation_id,
            "value": category.id,
        }
        candidate_rows.append(
            ClassificationCandidate(
                candidate_id=_stable_id("candidate", candidate_payload),
                axis="role",
                value=category.id,
                evidence_ids=(evidence_id,),
                confidence_band="low",
                uncertainty_reason=(
                    "competing-top-candidate"
                    if len(matching_categories) > 1
                    else "single-path-provider"
                ),
                context_freshness="fresh",
                classifier_version=classifier_version,
            )
        )
    return evidence_rows, candidate_rows


def _frontmatter_provider(
    item: ClassificationInput,
    *,
    candidate_rows: list,
    classifier_version: str,
) -> Tuple[list, list]:
    if item.projection is None:
        return [], candidate_rows
    private_projection = (
        item.sensitivity == "private"
        or item.scope_class == "private-reviewable"
    )
    provider = (
        "ephemeral-private-projection"
        if private_projection
        else "safe-frontmatter"
    )
    evidence_rows = []
    candidates = list(candidate_rows)
    for axis, value in item.projection.frontmatter:
        evidence_payload = {
            "axis": axis,
            "classifier_version": classifier_version,
            "observation_id": item.observation_id,
            "provider": provider,
            "value": value,
        }
        evidence_id = _stable_id("evidence", evidence_payload)
        evidence_rows.append(
            Evidence(
                evidence_id=evidence_id,
                provider=provider,
                kind=axis,
                value=value,
                provenance=(
                    "authorization:%s:frontmatter.%s"
                    % (item.projection_authorization_id, axis)
                    if private_projection
                    else "projection.frontmatter.%s" % axis
                ),
                context_freshness=item.projection.context_freshness,
            )
        )
        matching_candidates = [
            candidate
            for candidate in candidates
            if candidate.axis == axis and candidate.value == value
        ]
        if matching_candidates:
            candidates = [
                candidate
                for candidate in candidates
                if not (candidate.axis == axis and candidate.value == value)
            ]
        combined_evidence_ids = tuple(
            sorted(
                {evidence_id}.union(
                    *(
                        set(candidate.evidence_ids)
                        for candidate in matching_candidates
                    )
                )
            )
        )
        candidate_payload = {
            "axis": axis,
            "classifier_version": classifier_version,
            "evidence_ids": list(combined_evidence_ids),
            "observation_id": item.observation_id,
            "value": value,
        }
        candidates.append(
            ClassificationCandidate(
                candidate_id=_stable_id("candidate", candidate_payload),
                axis=axis,
                value=value,
                evidence_ids=combined_evidence_ids,
                confidence_band=(
                    "medium"
                    if item.projection.context_freshness == "fresh"
                    else "low"
                ),
                uncertainty_reason=(
                    "multiple-tentative-providers"
                    if matching_candidates
                    else "single-content-provider"
                ),
                context_freshness=item.projection.context_freshness,
                classifier_version=classifier_version,
            )
        )
    return evidence_rows, candidates


def _duplicate_provider(
    item: ClassificationInput,
    *,
    classifier_version: str,
) -> Tuple[Optional[Evidence], Optional[ClassificationCandidate]]:
    if item.fingerprint_value is None:
        return None, None
    evidence_payload = {
        "classifier_version": classifier_version,
        "duplicate_observation_ids": list(item.duplicate_observation_ids),
        "fingerprint_value": item.fingerprint_value,
        "observation_id": item.observation_id,
        "provider": "exact-duplicate",
    }
    evidence_id = _stable_id("evidence", evidence_payload)
    evidence = Evidence(
        evidence_id=evidence_id,
        provider="exact-duplicate",
        kind="content-sha256",
        value="duplicate-count:%d" % len(item.duplicate_observation_ids),
        provenance="fingerprint:%s" % item.fingerprint_value,
        context_freshness="fresh",
    )
    candidate_payload = {
        "axis": "authority",
        "classifier_version": classifier_version,
        "evidence_ids": [evidence_id],
        "observation_id": item.observation_id,
        "value": "unknown",
    }
    candidate = ClassificationCandidate(
        candidate_id=_stable_id("candidate", candidate_payload),
        axis="authority",
        value="unknown",
        evidence_ids=(evidence_id,),
        confidence_band="unknown",
        uncertainty_reason="duplicate-authority-unresolved",
        context_freshness="fresh",
        classifier_version=classifier_version,
    )
    return evidence, candidate


def _missing_axis_candidates(
    item: ClassificationInput,
    *,
    candidate_rows: Sequence[ClassificationCandidate],
    classifier_version: str,
) -> list:
    present_axes = {candidate.axis for candidate in candidate_rows}
    candidates = []
    for axis in sorted(_AXES - present_axes):
        value = "unassigned" if axis == "workstream" else "unknown"
        payload = {
            "axis": axis,
            "classifier_version": classifier_version,
            "evidence_ids": [],
            "observation_id": item.observation_id,
            "value": value,
        }
        candidates.append(
            ClassificationCandidate(
                candidate_id=_stable_id("candidate", payload),
                axis=axis,
                value=value,
                evidence_ids=(),
                confidence_band="unknown",
                uncertainty_reason="missing-deterministic-evidence",
                context_freshness="unknown",
                classifier_version=classifier_version,
            )
        )
    return candidates


class EvidenceClassifier:
    """Produce deterministic candidates from explicitly supplied providers."""

    def __init__(self, classifier_version: str) -> None:
        self.classifier_version = _require_identifier(
            classifier_version, "classifier version"
        )

    def classify(
        self,
        item: ClassificationInput,
        *,
        raw_root: str,
        workstreams: Sequence[CompiledWorkstream],
        categories: Sequence[CompiledCategory] = (),
    ) -> ClassificationResult:
        if type(item) is not ClassificationInput:
            raise TypeError("item must be ClassificationInput")
        if not isinstance(workstreams, (tuple, list)):
            raise TypeError("workstreams must be a sequence")

        route_path = _route_view_path(item.path)
        scored_evidence = list(
            _path_workstream_evidence(
                item,
                raw_root=raw_root,
                route_path=route_path,
                workstreams=workstreams,
                classifier_version=self.classifier_version,
            )
        )
        known_workstream_ids = {workstream.id for workstream in workstreams}
        scored_evidence.extend(
            _reference_workstream_evidence(
                item,
                known_workstream_ids=known_workstream_ids,
                classifier_version=self.classifier_version,
            )
        )
        scored_evidence.extend(
            _projection_workstream_evidence(
                item,
                workstreams=workstreams,
                classifier_version=self.classifier_version,
            )
        )

        evidence_rows = [evidence for evidence, _score in scored_evidence]
        evidence_by_workstream = {}
        score_by_workstream = {}
        for evidence, score in scored_evidence:
            evidence_by_workstream.setdefault(evidence.value, []).append(
                evidence.evidence_id
            )
            score_by_workstream[evidence.value] = (
                score_by_workstream.get(evidence.value, 0) + score
            )

        candidate_rows = _workstream_candidates(
            item,
            evidence_rows=evidence_rows,
            evidence_by_workstream=evidence_by_workstream,
            score_by_workstream=score_by_workstream,
            classifier_version=self.classifier_version,
        )
        category_evidence, category_candidates = _category_provider(
            item,
            route_path=route_path,
            categories=categories,
            classifier_version=self.classifier_version,
        )
        evidence_rows.extend(category_evidence)
        candidate_rows.extend(category_candidates)
        frontmatter_evidence, candidate_rows = _frontmatter_provider(
            item,
            candidate_rows=candidate_rows,
            classifier_version=self.classifier_version,
        )
        evidence_rows.extend(frontmatter_evidence)
        duplicate_evidence, duplicate_candidate = _duplicate_provider(
            item,
            classifier_version=self.classifier_version,
        )
        if duplicate_evidence is not None and duplicate_candidate is not None:
            evidence_rows.append(duplicate_evidence)
            candidate_rows.append(duplicate_candidate)
        candidate_rows.extend(
            _missing_axis_candidates(
                item,
                candidate_rows=candidate_rows,
                classifier_version=self.classifier_version,
            )
        )

        return ClassificationResult(
            observation_id=item.observation_id,
            classifier_version=self.classifier_version,
            evidence=tuple(evidence_rows),
            candidates=tuple(
                sorted(candidate_rows, key=lambda value: (value.axis, value.value))
            ),
        )


__all__ = [
    "ClassificationCandidate",
    "ClassificationError",
    "ClassificationInput",
    "ClassificationResult",
    "Evidence",
    "EvidenceClassifier",
    "SafeContentProjection",
]
