"""Pure M2 bridge from one sealed inventory package to a root review model.

The bridge never reopens corpus paths.  It accepts caller-preallocated UUID4
item identities, keeps every classifier result tentative, and emits only the
typed import plan and immutable review inputs needed by the campaign layer.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from . import (
    admission,
    batch_service,
    campaign_ledger,
    classification,
    inventory,
    policy,
    references,
    review_compiler,
    review_context,
    review_units,
    routing_risk,
)
from .canonical_json import canonical_json_bytes, sha256_bytes


_HASH = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_SCOPES = frozenset(
    (
        "opaque-private-evidence",
        "evidence",
        "memory",
        "mirror",
        "protected",
        "never-touch",
        "control",
    )
)
_FROZEN_RULE = "paused-completed"
_ROOT_NAVIGATION_PATH = inventory.canonical_raw_path((b"_projects.md",))
_OBSERVATION_V1_FIELDS = frozenset(
    (
        "schema_version",
        "run_id",
        "path",
        "display_path",
        "kind",
        "physical_kind",
        "scope_class",
        "scope_rule_id",
        "traversal",
        "content_inspected",
        "excluded_reason",
        "stat",
        "fingerprint",
        "errors",
        "descendant_unknown",
        "link_text_status",
        "safe_link_text",
        "direct_file_count",
        "direct_other_count",
        "content_policy_outcome",
    )
)
_OBSERVATION_V2_FIELDS = _OBSERVATION_V1_FIELDS.union(
    ("classification_projection", "reference_projection")
)


class RunReviewError(ValueError):
    """A sealed run cannot be represented as a safe M2 review."""


@dataclass(frozen=True)
class PreparedRootReview:
    import_plan: campaign_ledger.RunImportPlan
    batch_units: Tuple[batch_service.BatchUnit, ...]
    snapshot_payload_json: bytes
    snapshot_sha256: str
    review_document: review_compiler.ReviewDocument


@dataclass(frozen=True)
class _ParsedObservation:
    observation_id: str
    raw: bytes
    value: Mapping[str, Any]
    identity: Optional[inventory.FileIdentity]
    schema_version: int
    reference_projection: Optional[inventory.ReferenceProjection]
    classification_projection: Optional[inventory.ClassificationProjection]


@dataclass(frozen=True)
class _ItemProjection:
    item_id: str
    observation: _ParsedObservation
    classification: classification.ClassificationResult
    primary_workstream: str
    related_workstreams: Tuple[str, ...]
    shared: bool
    document_role: str
    authority: str
    document_lifecycle: str
    lifecycle_class: str
    override_class: str
    sensitivity: str
    access_domain: str
    recommended_action: str
    risk_band: str
    context_freshness: str
    evidence_providers: Tuple[str, ...]
    warning_codes: Tuple[str, ...]
    negative_flags: Tuple[str, ...]
    canonical_conflict: bool
    relation_conflict: bool
    reference_complete: bool
    target_proven: bool
    reference_provenance_json: bytes
    target_provenance_json: bytes
    risk_provenance_json: bytes
    target_candidate: routing_risk.TargetCandidate


def _canonical_json(raw: bytes, label: str) -> Any:
    if not isinstance(raw, bytes):
        raise RunReviewError("%s must be bytes" % label)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunReviewError("%s is not canonical JSON" % label) from exc
    if canonical_json_bytes(value) != raw:
        raise RunReviewError("%s is not canonical JSON" % label)
    return value


def _approved_policy_from_request(
    request: inventory.InventoryRunRequest,
) -> admission.ApprovedPolicyRef:
    payload = _canonical_json(request.canonical_bytes, "inventory request")
    if type(payload) is not dict:
        raise RunReviewError("inventory request is invalid")
    value = payload.get("policy_authority")
    if type(value) is not dict:
        raise RunReviewError("inventory policy authority fields are invalid")
    expected = {
        "raw_hash",
        "full_hash",
        "writer_control_hash",
        "foundation_hash",
        "generation",
        "source_kind",
        "source_run_id",
        "guard_epoch",
    }
    if set(value) != expected:
        raise RunReviewError("inventory policy authority fields are invalid")
    try:
        return admission.ApprovedPolicyRef(
            raw_hash=value["raw_hash"],
            full_hash=value["full_hash"],
            writer_control_hash=value["writer_control_hash"],
            foundation_hash=value["foundation_hash"],
            generation=value["generation"],
            source_kind=value["source_kind"],
            source_run_id=value["source_run_id"],
            guard_epoch=value["guard_epoch"],
        )
    except (TypeError, ValueError) as exc:
        raise RunReviewError("inventory policy authority is invalid") from exc


def _require_policy(
    package: inventory.InventoryPackageReadback,
    compiled: policy.CompiledPolicy,
    approved: admission.ApprovedPolicyRef,
) -> str:
    if not isinstance(compiled, policy.CompiledPolicy):
        raise TypeError("compiled_policy must be CompiledPolicy")
    if not isinstance(approved, admission.ApprovedPolicyRef):
        raise TypeError("approved_policy must be ApprovedPolicyRef")
    sealed = _approved_policy_from_request(package.request)
    if sealed != approved:
        raise RunReviewError("sealed inventory policy is stale")
    if (
        compiled.raw_hash,
        compiled.full_hash,
        compiled.writer_hash,
        compiled.foundation_hash,
    ) != (
        approved.raw_hash,
        approved.full_hash,
        approved.writer_control_hash,
        approved.foundation_hash,
    ):
        raise RunReviewError("compiled policy does not match approved policy")
    request_payload = _canonical_json(
        package.request.canonical_bytes,
        "inventory request",
    )
    scope = request_payload.get("scope") if type(request_payload) is dict else None
    raw_root = scope.get("raw_root") if type(scope) is dict else None
    if (
        not isinstance(raw_root, str)
        or not raw_root.startswith("/")
        or compiled.registry_anchors.registry_root != raw_root + "/_registry"
    ):
        raise RunReviewError("inventory scope and compiled policy root differ")
    return raw_root


def _identity(value: Any) -> Optional[inventory.FileIdentity]:
    if value is None:
        return None
    if type(value) is not dict or set(value) != {
        "device",
        "inode",
        "mode",
        "size",
        "mtime_ns",
    }:
        raise RunReviewError("observation stat is invalid")
    if any(type(value[name]) is not int or value[name] < 0 for name in value):
        raise RunReviewError("observation stat is invalid")
    return inventory.FileIdentity(
        value["device"],
        value["inode"],
        value["mode"],
        value["size"],
        value["mtime_ns"],
    )


def _parse_observation_line(raw: bytes, run_id: str) -> _ParsedObservation:
    value = _canonical_json(raw, "inventory observation")
    if type(value) is not dict:
        raise RunReviewError("inventory observation fields are invalid")
    schema_version = value.get("schema_version")
    expected_fields = {
        1: _OBSERVATION_V1_FIELDS,
        2: _OBSERVATION_V2_FIELDS,
    }.get(schema_version)
    if expected_fields is None or set(value) != expected_fields:
        raise RunReviewError("inventory observation fields are invalid")
    if value["run_id"] != run_id:
        raise RunReviewError("inventory observation run binding is invalid")
    path = value["path"]
    display_path = value["display_path"]
    try:
        components = inventory.decode_canonical_raw_path(path)
    except (TypeError, ValueError) as exc:
        raise RunReviewError("inventory observation path is not canonical") from exc
    if (
        inventory.canonical_raw_path(components) != path
        or inventory.display_raw_path(components) != display_path
        or (
            not components
            and (
                value["kind"] != "directory"
                or value["physical_kind"] != "directory"
            )
        )
    ):
        raise RunReviewError("inventory observation path/display binding is invalid")
    for name in (
        "kind",
        "physical_kind",
        "scope_class",
        "scope_rule_id",
        "traversal",
    ):
        if not isinstance(value[name], str) or not value[name]:
            raise RunReviewError("inventory observation fields are invalid")
    if type(value["content_inspected"]) is not bool:
        raise RunReviewError("inventory observation inspection flag is invalid")
    if type(value["errors"]) is not list or any(
        not isinstance(item, str) or not item for item in value["errors"]
    ):
        raise RunReviewError("inventory observation errors are invalid")
    for name in ("descendant_unknown", "direct_file_count", "direct_other_count"):
        if type(value[name]) is not int or value[name] < 0:
            raise RunReviewError("inventory observation count is invalid")
    fingerprint = value["fingerprint"]
    if type(fingerprint) is not dict or set(fingerprint) != {"kind", "value"}:
        raise RunReviewError("inventory observation fingerprint is invalid")
    if not isinstance(fingerprint["kind"], str) or not fingerprint["kind"]:
        raise RunReviewError("inventory observation fingerprint is invalid")
    if fingerprint["value"] is not None and _HASH.fullmatch(
        fingerprint["value"]
    ) is None:
        raise RunReviewError("inventory observation fingerprint is invalid")
    if value["scope_class"] in _OPAQUE_SCOPES.union(("private-reviewable",)):
        if (
            value["content_inspected"]
            or fingerprint["kind"] == "sha256"
            or (
                value["physical_kind"] == "file"
                and fingerprint["value"] is not None
            )
            or (
                schema_version == 2
                and (
                    value["reference_projection"] is not None
                    or value["classification_projection"] is not None
                )
            )
        ):
            raise RunReviewError("private or opaque inventory persisted content evidence")
    if (
        value["physical_kind"] == "file"
        and not value["content_inspected"]
        and fingerprint["value"] is not None
    ):
        raise RunReviewError("uninspected inventory persisted fingerprint evidence")
    reference_projection = None
    classification_projection = None
    if schema_version == 2:
        projection_value = value["reference_projection"]
        if projection_value is not None:
            if (
                type(projection_value) is not dict
                or set(projection_value)
                not in (
                    {"projection_version", "projection_sha256", "references"},
                    {
                        "parser_types",
                        "projection_version",
                        "projection_sha256",
                        "references",
                    },
                )
                or type(projection_value["references"]) is not list
            ):
                raise RunReviewError("inventory reference projection is invalid")
            try:
                rows = tuple(
                    inventory.InternalReference(
                        kind=row["kind"],
                        target=row["target"],
                    )
                    for row in projection_value["references"]
                    if type(row) is dict and set(row) == {"kind", "target"}
                )
                if len(rows) != len(projection_value["references"]):
                    raise ValueError("reference row fields are invalid")
                reference_projection = inventory.ReferenceProjection(
                    source_path=path,
                    projection_version=projection_value["projection_version"],
                    projection_sha256=projection_value["projection_sha256"],
                    references=rows,
                    parser_types=(
                        tuple(projection_value["parser_types"])
                        if "parser_types" in projection_value
                        and type(projection_value["parser_types"]) is list
                        else inventory._LEGACY_REFERENCE_PARSER_TYPES
                    ),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise RunReviewError(
                    "inventory reference projection is invalid"
                ) from exc
        classification_value = value["classification_projection"]
        if classification_value is not None:
            if (
                type(classification_value) is not dict
                or set(classification_value)
                != {
                    "frontmatter",
                    "headings",
                    "projection_sha256",
                    "projection_version",
                    "title",
                    "tokens",
                }
                or type(classification_value["frontmatter"]) is not list
                or type(classification_value["headings"]) is not list
                or type(classification_value["tokens"]) is not list
            ):
                raise RunReviewError("inventory classification projection is invalid")
            try:
                frontmatter = tuple(
                    (row["axis"], row["value"])
                    for row in classification_value["frontmatter"]
                    if type(row) is dict and set(row) == {"axis", "value"}
                )
                if len(frontmatter) != len(classification_value["frontmatter"]):
                    raise ValueError("classification frontmatter fields are invalid")
                classification_projection = inventory.ClassificationProjection(
                    projection_version=classification_value["projection_version"],
                    projection_sha256=classification_value["projection_sha256"],
                    title=classification_value["title"],
                    headings=tuple(classification_value["headings"]),
                    frontmatter=frontmatter,
                    tokens=tuple(classification_value["tokens"]),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise RunReviewError(
                    "inventory classification projection is invalid"
                ) from exc
        if value["content_inspected"] != (
            reference_projection is not None
            and classification_projection is not None
        ):
            raise RunReviewError(
                "inventory inspection and safe projections disagree"
            )
    observation_id = "observation-%s" % sha256_bytes(
        canonical_json_bytes(
            {
                "kind": value["kind"],
                "path": path,
                "run_id": run_id,
            }
        )
    )[:24]
    return _ParsedObservation(
        observation_id,
        raw,
        value,
        _identity(value["stat"]),
        schema_version,
        reference_projection,
        classification_projection,
    )


def _parse_package(
    package: inventory.InventoryPackageReadback,
) -> Tuple[Mapping[str, Any], Tuple[_ParsedObservation, ...]]:
    if not isinstance(package, inventory.InventoryPackageReadback):
        raise TypeError("package must be InventoryPackageReadback")
    if package.terminal.state != "complete" or (
        package.terminal.run_id != package.request.run_id
    ):
        raise RunReviewError("inventory package is not a complete sealed run")
    if tuple(name for name, _raw in package.artifacts) != (
        "coverage.json",
        "observations.jsonl",
    ):
        raise RunReviewError("inventory package artifact set is invalid")
    coverage = _canonical_json(package.artifacts[0][1], "inventory coverage")
    if type(coverage) is not dict or coverage.get("schema_version") != 1:
        raise RunReviewError("inventory coverage schema is invalid")
    observations_raw = package.artifacts[1][1]
    if observations_raw and not observations_raw.endswith(b"\n"):
        raise RunReviewError("inventory observations JSONL is not canonical")
    lines = observations_raw.splitlines(keepends=True)
    observations = tuple(
        _parse_observation_line(line, package.request.run_id) for line in lines
    )
    if not observations:
        raise RunReviewError("inventory observations are empty")
    if len({row.value["path"] for row in observations}) != len(observations):
        raise RunReviewError("inventory observation paths are duplicated")
    if len({row.observation_id for row in observations}) != len(observations):
        raise RunReviewError("inventory observation ids are duplicated")
    reconstructed = tuple(
        inventory.Observation(
            run_id=value["run_id"],
            path=value["path"],
            display_path=value["display_path"],
            kind=value["kind"],
            physical_kind=value["physical_kind"],
            scope_class=value["scope_class"],
            scope_rule_id=value["scope_rule_id"],
            traversal=value["traversal"],
            content_inspected=value["content_inspected"],
            excluded_reason=value["excluded_reason"],
            identity=row.identity,
            fingerprint_kind=value["fingerprint"]["kind"],
            fingerprint_value=value["fingerprint"]["value"],
            errors=tuple(value["errors"]),
            descendant_unknown=value["descendant_unknown"],
            link_text_status=value["link_text_status"],
            safe_link_text=value["safe_link_text"],
            direct_file_count=value["direct_file_count"],
            direct_other_count=value["direct_other_count"],
            content_policy_outcome=value["content_policy_outcome"],
            reference_projection=row.reference_projection,
            classification_projection=row.classification_projection,
            schema_version=row.schema_version,
        )
        for row in observations
        for value in (row.value,)
    )
    content_bytes_attempted = coverage.get("content_bytes_attempted")
    if type(content_bytes_attempted) is not int or content_bytes_attempted < 0:
        raise RunReviewError("inventory content byte coverage is invalid")
    request_value = _canonical_json(
        package.request.canonical_bytes,
        "inventory request",
    )
    bounds = request_value.get("bounds") if type(request_value) is dict else None
    if type(bounds) is not dict:
        raise RunReviewError("inventory request bounds are invalid")
    maximum_content_bytes = bounds.get("max_content_bytes")
    if (
        maximum_content_bytes is not None
        and (
            type(maximum_content_bytes) is not int
            or maximum_content_bytes < 0
            or content_bytes_attempted > maximum_content_bytes
        )
    ):
        raise RunReviewError("inventory content byte coverage exceeds request")
    if inventory._build_coverage(
        reconstructed,
        content_bytes_attempted=content_bytes_attempted,
    ) != coverage:
        raise RunReviewError("inventory coverage does not match observations")
    return coverage, tuple(
        sorted(observations, key=lambda row: (row.value["path"], row.observation_id))
    )


def _uuid4(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise RunReviewError("item ids must be canonical UUID4") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise RunReviewError("item ids must be canonical UUID4")
    return value


def _axis_candidates(
    result: classification.ClassificationResult, axis: str
) -> Tuple[classification.ClassificationCandidate, ...]:
    return result.candidates_for(axis)


def _axis_value(
    result: classification.ClassificationResult,
    axis: str,
    fallback: str,
    *,
    require_high: bool = False,
) -> str:
    candidates = tuple(
        row
        for row in _axis_candidates(result, axis)
        if row.value not in ("unknown", "unassigned")
    )
    if len(candidates) != 1:
        return fallback
    candidate = candidates[0]
    if candidate.uncertainty_reason == "competing-top-candidate":
        return fallback
    if require_high and candidate.confidence_band != "high":
        return fallback
    return candidate.value


def _freshness(result: classification.ClassificationResult) -> str:
    values = {candidate.context_freshness for candidate in result.candidates}
    if "unknown" in values:
        return "unknown"
    if "stale" in values:
        return "stale"
    return "fresh"


def _scope_domain(
    compiled: policy.CompiledPolicy,
    observation: _ParsedObservation,
) -> Tuple[str, str]:
    rule_id = observation.value["scope_rule_id"]
    matching = tuple(rule for rule in compiled.scope_rules if rule.id == rule_id)
    if len(matching) == 1:
        return matching[0].sensitivity, matching[0].access_domain
    scope_class = observation.value["scope_class"]
    if scope_class == "private-reviewable":
        return "private", "local-restricted"
    if scope_class in _OPAQUE_SCOPES:
        return "opaque", "local-restricted"
    return "unknown", "local"


def _encoded_policy_root(absolute_path: str, raw_root: str) -> Optional[str]:
    prefix = raw_root.rstrip("/") + "/"
    if not absolute_path.startswith(prefix):
        return None
    relative = absolute_path[len(prefix) :]
    if not relative or relative.startswith("/"):
        return None
    try:
        components = tuple(part.encode("utf-8", "strict") for part in relative.split("/"))
        encoded = inventory.canonical_raw_path(components)
        if inventory.decode_canonical_raw_path(encoded) != components:
            return None
        return encoded
    except (UnicodeError, ValueError):
        return None


def _workstream_roots(
    compiled: policy.CompiledPolicy,
    raw_root: str,
) -> Tuple[Tuple[str, str], ...]:
    return tuple(
        sorted(
            (encoded, workstream.id)
            for workstream in compiled.workstreams
            for encoded in (
                _encoded_policy_root(workstream.project_home, raw_root),
            )
            if encoded is not None
        )
    )


def _under_root(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _policy_relevant(row: _ParsedObservation) -> bool:
    """Return whether one sealed observation participates in reference safety.

    Outside Workstream roots, hard control/never-touch observations remain
    inventory evidence but do not expand the reference frontier. Every other
    observed policy lane, including category and fallback lanes, belongs to the
    global frontier.
    """

    return row.value["scope_class"] not in ("never-touch", "control")


def _observed_frontier_root(path: str) -> Optional[str]:
    """Return the canonical top-level root containing an observed raw path."""

    try:
        components = inventory.decode_canonical_raw_path(path)
    except (TypeError, ValueError):
        return None
    if not components:
        return None
    return inventory.canonical_raw_path(components[:1])


def _document_type(value: Mapping[str, Any]) -> str:
    display = value["display_path"].casefold()
    if display == "_projects.md" or display.endswith("/_projects.md"):
        return "generated-navigation"
    if display.endswith((".md", ".markdown")):
        return "markdown"
    if display.endswith((".html", ".htm")):
        return "html"
    return "text"


def _reference_document(row: _ParsedObservation) -> references.ReferenceDocument:
    value = row.value
    restricted = value["scope_class"] in _OPAQUE_SCOPES.union(
        ("private-reviewable",)
    )
    if restricted:
        exclusion = "restricted-scope"
    elif row.reference_projection is not None:
        return references.ReferenceDocument(
            path=value["path"],
            document_type=_document_type(value),
            fingerprint=value["fingerprint"]["value"],
            scope_class=value["scope_class"],
            text=None,
            inspected=True,
            projection=row.reference_projection,
        )
    elif row.schema_version == 1 and value["content_inspected"]:
        exclusion = "projection-unavailable-v1"
    elif value["errors"]:
        exclusion = "inventory-error"
    else:
        exclusion = "content-uninspected"
    return references.ReferenceDocument(
        path=value["path"],
        document_type=_document_type(value),
        fingerprint=(
            value["fingerprint"]["value"]
            if value["fingerprint"]["value"] is not None
            else sha256_bytes(row.raw)
        ),
        scope_class=value["scope_class"],
        text=None,
        inspected=False,
        exclusion_reason=exclusion,
    )


def _reference_coverage_issues(
    observations: Sequence[_ParsedObservation],
    scanned_roots: Sequence[str],
) -> Tuple[references.ReferenceCoverageIssue, ...]:
    issues = set()
    for row in observations:
        value = row.value
        if not any(_under_root(value["path"], root) for root in scanned_roots):
            continue
        for reason in value["errors"]:
            issues.add(
                references.ReferenceCoverageIssue(
                    "error",
                    value["path"],
                    reason,
                )
            )
        if value["descendant_unknown"]:
            issues.add(
                references.ReferenceCoverageIssue(
                    "error",
                    value["path"],
                    "descendant-unknown",
                )
            )
        if (
            value["physical_kind"] != "file"
            and value["excluded_reason"] is not None
        ):
            # Non-file entries are never reference documents.  Keep every
            # unopened object inside a selected frontier explicit instead of
            # silently treating a symlink or special entry as complete.
            issues.add(
                references.ReferenceCoverageIssue(
                    "exclusion",
                    value["path"],
                    value["excluded_reason"],
                )
            )
        if value["physical_kind"] == "directory":
            if value["traversal"] not in ("entered", "full"):
                issues.add(
                    references.ReferenceCoverageIssue(
                        "exclusion",
                        value["path"],
                        "traversal-%s" % value["traversal"],
                    )
                )
    return tuple(
        sorted(
            issues,
            key=lambda issue: (issue.kind, issue.path, issue.reason),
        )
    )


def _reference_context(
    observations: Sequence[_ParsedObservation],
    *,
    raw_root: str,
    compiled: policy.CompiledPolicy,
) -> references.ReferenceContext:
    workstream_roots = {
        root for root, _workstream_id in _workstream_roots(compiled, raw_root)
    }

    observed_roots = {
        root
        for row in observations
        if _policy_relevant(row)
        and not any(
            _under_root(row.value["path"], workstream_root)
            or _under_root(workstream_root, row.value["path"])
            for workstream_root in workstream_roots
        )
        for root in (_observed_frontier_root(row.value["path"]),)
        if root is not None
    }
    explicit_global_roots = {
        _ROOT_NAVIGATION_PATH
        for row in observations
        if row.value["path"] == _ROOT_NAVIGATION_PATH
    }
    scanned_roots = tuple(
        sorted(workstream_roots | observed_roots | explicit_global_roots)
    )
    documents = tuple(
        _reference_document(row)
        for row in observations
        if row.value["physical_kind"] == "file"
        and any(
            _under_root(row.value["path"], root)
            for root in scanned_roots
        )
    )
    coverage_issues = set(
        _reference_coverage_issues(observations, scanned_roots)
    )
    for root in scanned_roots:
        if not any(_under_root(row.value["path"], root) for row in observations):
            coverage_issues.add(
                references.ReferenceCoverageIssue(
                    "error", root, "frontier-missing"
                )
            )
    return references.ReferenceAnalyzer("reference-m2-v2").build_context(
        documents=documents,
        scanned_roots=scanned_roots,
        registry_source_sha256=compiled.raw_hash,
        coverage_issues=tuple(
            sorted(
                coverage_issues,
                key=lambda issue: (issue.kind, issue.path, issue.reason),
            )
        ),
    )


def _reference_workstreams(
    envelope: references.ReferenceEnvelope,
    compiled: policy.CompiledPolicy,
    raw_root: str,
) -> Tuple[str, ...]:
    roots = _workstream_roots(compiled, raw_root)
    paths = {
        path
        for match in envelope.matches
        for path in (match.source_path, match.target_path)
    }
    return tuple(
        sorted(
            {
                workstream_id
                for root, workstream_id in roots
                if any(_under_root(path, root) for path in paths)
            }
        )
    )


def _reference_provenance(envelope: references.ReferenceEnvelope) -> bytes:
    return canonical_json_bytes(
        {
            "candidate_path": envelope.candidate_path,
            "complete": envelope.complete,
            "context_id": envelope.context_id,
            "context_sha256": envelope.context_sha256,
            "input_manifest_sha256": envelope.input_manifest_sha256,
            "matches": [
                {
                    "direction": match.direction,
                    "reference_kind": match.reference_kind,
                    "source_path": match.source_path,
                    "target_path": match.target_path,
                }
                for match in envelope.matches
            ],
            "schema_version": 2,
        }
    )


def _target_provenance(candidate: routing_risk.TargetCandidate) -> bytes:
    return canonical_json_bytes(
        {
            "evidence_ids": list(candidate.evidence_ids),
            "input_sha256": candidate.input_sha256,
            "matched_rule_id": candidate.matched_rule_id,
            "matched_rule_sha256": candidate.matched_rule_sha256,
            "rename_delta": {
                "from": candidate.rename_from,
                "to": candidate.rename_to,
            },
            "resolver_version": candidate.resolver_version,
            "schema_version": 1,
            "status": candidate.status,
            "target_path": candidate.target_path,
            "uncertainty": candidate.uncertainty,
        }
    )


def _risk_provenance(result: routing_risk.RiskResult) -> bytes:
    return canonical_json_bytes(
        {
            "band": result.band,
            "evaluator_version": result.evaluator_version,
            "hard_escalators": list(result.hard_escalators),
            "input_sha256": result.input_sha256,
            "schema_version": 1,
        }
    )


def _project_item(
    parsed: _ParsedObservation,
    *,
    item_id: str,
    raw_root: str,
    compiled: policy.CompiledPolicy,
    reference_envelope: references.ReferenceEnvelope,
    duplicate_observation_ids: Tuple[str, ...],
) -> _ItemProjection:
    value = parsed.value
    fingerprint_value = (
        value["fingerprint"]["value"]
        if duplicate_observation_ids
        else None
    )
    result = classification.EvidenceClassifier("deterministic-m2-v1").classify(
        classification.ClassificationInput(
            observation_id=parsed.observation_id,
            path=value["path"],
            scope_class=value["scope_class"],
            scope_rule_id=value["scope_rule_id"],
            content_allowed=parsed.classification_projection is not None,
            sensitivity=_scope_domain(compiled, parsed)[0],
            access_domain=_scope_domain(compiled, parsed)[1],
            projection=(
                None
                if parsed.classification_projection is None
                else classification.SafeContentProjection(
                    title=parsed.classification_projection.title,
                    headings=parsed.classification_projection.headings,
                    frontmatter=parsed.classification_projection.frontmatter,
                    references=parsed.classification_projection.tokens,
                    context_freshness="fresh",
                )
            ),
            reference_workstreams=_reference_workstreams(
                reference_envelope,
                compiled,
                raw_root,
            ),
            fingerprint_value=fingerprint_value,
            duplicate_observation_ids=duplicate_observation_ids,
        ),
        raw_root=raw_root,
        workstreams=compiled.workstreams,
        categories=compiled.categories,
    )
    primary = _axis_value(
        result, "workstream", "unassigned", require_high=True
    )
    related = tuple(
        sorted(
            {
                row.value
                for row in _axis_candidates(result, "workstream")
                if row.value not in ("unknown", "unassigned", primary)
            }
        )
    )
    role = _axis_value(result, "role", "unknown")
    authority = _axis_value(result, "authority", "unknown")
    document_lifecycle = _axis_value(result, "lifecycle", "unknown")
    workstream_by_id = {row.id: row for row in compiled.workstreams}
    lifecycle_class = (
        workstream_by_id[primary].lifecycle
        if primary in workstream_by_id
        else "unassigned"
    )
    frozen = value["scope_rule_id"] == _FROZEN_RULE or lifecycle_class in (
        "paused",
        "completed",
    )
    sensitivity, access_domain = _scope_domain(compiled, parsed)
    private = sensitivity == "private" or value["scope_class"] == "private-reviewable"
    opaque = value["scope_class"] in _OPAQUE_SCOPES
    competing = any(
        len(
            {
                row.value
                for row in _axis_candidates(result, axis)
                if row.value not in ("unknown", "unassigned")
            }
        )
        > 1
        or result.has_competing_candidates(axis)
        for axis in ("workstream", "role", "authority", "lifecycle")
    )
    recommended_action = (
        "keep"
        if primary != "unassigned" and lifecycle_class == "active" and not private and not opaque
        else "defer"
    )
    evidence_ids = tuple(sorted(row.evidence_id for row in result.evidence))
    target = routing_risk.PlacementTargetResolver("target-m2-v1").resolve(
        routing_risk.TargetRequest(
            source_path=value["path"],
            action="move",
            primary_workstream=primary,
            document_role=role,
            document_lifecycle=document_lifecycle,
            sensitivity=sensitivity,
            access_domain=access_domain,
            classification_confirmed=False,
            evidence_ids=evidence_ids,
        ),
        raw_root=raw_root,
        workstreams=compiled.workstreams,
        categories=compiled.categories,
        archive_roots=compiled.archive_roots,
    )
    target_proven = target.status == "resolved" and target.target_path is not None
    evidence_providers = tuple(
        sorted(
            {row.provider for row in result.evidence}.union(
                ("placement-target", "reference-analysis", "risk-evaluator")
            )
        )
    )
    warnings = {"m2-no-structural-authority"}
    negative = set()
    if not reference_envelope.complete:
        warnings.add("reference-incomplete")
        negative.add("reference-incomplete")
    if reference_envelope.matches:
        negative.add("reference-impact")
    if private:
        warnings.add("private-metadata-only")
        negative.add("private-boundary")
    if opaque:
        warnings.add("opaque-content-unopened")
        negative.add("opaque")
    if frozen:
        warnings.add("lifecycle-frozen")
        negative.add("lifecycle-override-required")
    if competing:
        warnings.add("competing-candidate")
        negative.add("unresolved-ambiguity")
    if value["errors"] or value["descendant_unknown"]:
        warnings.add("inventory-error")
        negative.add("inventory-error")
    risk = routing_risk.RiskEvaluator("risk-m2-v1").evaluate(
        routing_risk.RiskInput(
            action=recommended_action,
            scope_class=value["scope_class"],
            sensitivity=sensitivity,
            access_domain=access_domain,
            confidence_band=(
                "high" if primary != "unassigned" else "unknown"
            ),
            context_freshness=_freshness(result),
            canonical_conflict=competing,
            reference_complete=reference_envelope.complete,
            descendant_count=1,
            descendant_mixed=False,
            target_proven=target_proven,
            archive_domain_safe=(
                recommended_action != "archive"
                or (
                    target_proven
                    and target.matched_rule_id is not None
                    and target.matched_rule_id.startswith("archive-root:")
                )
            ),
            frozen=frozen,
            lifecycle_override_present=False,
            opaque=opaque,
            private=private,
            ambiguity=competing,
            ancestor_descendant_overlap=False,
            named_output_conflict=False,
            reversal_capability_proven=True,
            inverse_plan_complete=True,
            recovery_paths_complete=True,
            provenance_ids=tuple(
                sorted(
                    set(evidence_ids).union(
                        (
                            reference_envelope.input_manifest_sha256,
                            target.input_sha256,
                        )
                    )
                )
            ),
        )
    )
    return _ItemProjection(
        item_id=item_id,
        observation=parsed,
        classification=result,
        primary_workstream=primary,
        related_workstreams=related,
        shared=len(related) > 0,
        document_role=role,
        authority=authority,
        document_lifecycle=document_lifecycle,
        lifecycle_class=lifecycle_class,
        override_class="required" if frozen else "none",
        sensitivity=sensitivity,
        access_domain=access_domain,
        recommended_action=recommended_action,
        risk_band=risk.band,
        context_freshness=_freshness(result),
        evidence_providers=evidence_providers,
        warning_codes=tuple(sorted(warnings)),
        negative_flags=tuple(sorted(negative)),
        canonical_conflict=competing,
        relation_conflict=len(related) > 1,
        reference_complete=reference_envelope.complete,
        target_proven=target_proven,
        reference_provenance_json=_reference_provenance(reference_envelope),
        target_provenance_json=_target_provenance(target),
        risk_provenance_json=_risk_provenance(risk),
        target_candidate=target,
    )


def _import_plan(
    observations: Sequence[_ParsedObservation],
    projections: Sequence[_ItemProjection],
    *,
    snapshot_id: str,
) -> campaign_ledger.RunImportPlan:
    by_observation = {
        row.observation.observation_id: row for row in projections
    }
    imported_observations = tuple(
        campaign_ledger.ImportedObservation(
            observation_key="%s:%s"
            % (row.value["run_id"], row.observation_id),
            observation_id=row.observation_id,
            path=row.value["path"],
            kind=row.value["kind"],
            payload_json=row.raw,
        )
        for row in observations
    )
    links = []
    candidates = []
    target_candidates = []
    for observation_id, projection in sorted(by_observation.items()):
        link_payload = canonical_json_bytes(
            {
                "kind": "first-seen-root-import",
                "observation_id": observation_id,
                "run_id": projection.observation.value["run_id"],
            }
        )
        links.append(
            campaign_ledger.ImportedObservationLink(
                link_id="observation-link-%s"
                % sha256_bytes(
                    canonical_json_bytes(
                        {
                            "item_id": projection.item_id,
                            "observation_id": observation_id,
                        }
                    )
                )[:24],
                observation_id=observation_id,
                item_id=projection.item_id,
                provenance_json=link_payload,
            )
        )
        evidence_by_id = {
            evidence.evidence_id: evidence
            for evidence in projection.classification.evidence
        }
        for candidate in projection.classification.candidates:
            evidence = tuple(
                evidence_by_id[evidence_id]
                for evidence_id in candidate.evidence_ids
            )
            providers = tuple(sorted({row.provider for row in evidence}))
            candidates.append(
                campaign_ledger.ImportedClassificationCandidate(
                    candidate_id=candidate.candidate_id,
                    item_id=projection.item_id,
                    axis=candidate.axis,
                    candidate_value=candidate.value,
                    provider_id=(
                        providers[0]
                        if len(providers) == 1
                        else "deterministic-evidence-set"
                        if providers
                        else "missing-evidence"
                    ),
                    confidence=candidate.confidence_band,
                    uncertainty=candidate.uncertainty_reason,
                    context_freshness=candidate.context_freshness,
                    evidence_json=canonical_json_bytes(
                        {
                            "candidate": candidate.to_dict(),
                            "evidence": [row.to_dict() for row in evidence],
                        }
                    ),
                )
            )
        target = projection.target_candidate
        target_candidates.append(
            campaign_ledger.ImportedPlacementTargetCandidate(
                target_candidate_id="target-%s"
                % sha256_bytes(
                    canonical_json_bytes(
                        {
                            "input_sha256": target.input_sha256,
                            "item_id": projection.item_id,
                            "snapshot_id": snapshot_id,
                        }
                    )
                )[:24],
                item_id=projection.item_id,
                snapshot_id=snapshot_id,
                registry_rule_id=target.matched_rule_id,
                registry_rule_sha256=target.matched_rule_sha256,
                target_path=target.target_path,
                rename_delta_json=canonical_json_bytes(
                    {"from": target.rename_from, "to": target.rename_to}
                ),
                uncertainty=target.uncertainty,
                payload_json=projection.target_provenance_json,
            )
        )
    return campaign_ledger.RunImportPlan(
        items=tuple(
            campaign_ledger.ImportedItem(row.item_id)
            for row in sorted(projections, key=lambda item: item.item_id)
        ),
        observations=imported_observations,
        links=tuple(sorted(links, key=lambda row: row.link_id)),
        classification_candidates=tuple(
            sorted(candidates, key=lambda row: row.candidate_id)
        ),
        placement_target_candidates=tuple(
            sorted(
                target_candidates,
                key=lambda row: row.target_candidate_id,
            )
        ),
    )


def _display_unit_path(path: str) -> str:
    try:
        return inventory.display_raw_path(inventory.decode_canonical_raw_path(path))
    except (TypeError, ValueError):
        return path


def _batch_units(
    projections: Sequence[_ItemProjection],
) -> Tuple[batch_service.BatchUnit, ...]:
    if not projections:
        return ()
    projection_by_item = {row.item_id: row for row in projections}
    unit_set = review_units.ReviewUnitBuilder("adaptive-folder-m2-v1").build(
        tuple(
            review_units.ReviewItem(
                item_id=row.item_id,
                path=row.observation.value["path"],
                size=0 if row.observation.identity is None else row.observation.identity.size,
                scope_class=row.observation.value["scope_class"],
                scope_rule_id=row.observation.value["scope_rule_id"],
                primary_workstream=row.primary_workstream,
                related_workstreams=row.related_workstreams,
                shared=row.shared,
                document_role=row.document_role,
                authority=row.authority,
                document_lifecycle=row.document_lifecycle,
                sensitivity=row.sensitivity,
                access_domain=row.access_domain,
                recommended_action=row.recommended_action,
                risk_band=row.risk_band,
                freeze_state=(
                    "frozen" if row.override_class != "none" else "active"
                ),
                reference_complete=row.reference_complete,
                negative_flags=row.negative_flags,
            )
            for row in projections
        )
    )
    result = []
    for unit in unit_set.units:
        members = tuple(projection_by_item[item_id] for item_id in unit.member_item_ids)
        first = members[0]
        fields = (
            "primary_workstream",
            "related_workstreams",
            "shared",
            "document_role",
            "authority",
            "document_lifecycle",
            "lifecycle_class",
            "override_class",
            "sensitivity",
            "access_domain",
            "recommended_action",
            "risk_band",
            "context_freshness",
            "canonical_conflict",
            "relation_conflict",
            "reference_complete",
            "target_proven",
        )
        if any(
            getattr(member, name) != getattr(first, name)
            for member in members[1:]
            for name in fields
        ):
            raise RunReviewError("review unit projection is not homogeneous")
        member_paths = tuple(
            member.observation.value["path"] for member in members
        )
        result.append(
            batch_service.BatchUnit(
                unit_id=unit.unit_id,
                unit_kind=unit.kind,
                path=unit.path,
                display_path=_display_unit_path(unit.path),
                member_item_ids=unit.member_item_ids,
                member_paths=member_paths,
                scope_class=first.observation.value["scope_class"],
                sensitivity=first.sensitivity,
                access_domain=first.access_domain,
                primary_workstream=first.primary_workstream,
                related_workstreams=first.related_workstreams,
                shared=first.shared,
                document_role=first.document_role,
                authority=first.authority,
                document_lifecycle=first.document_lifecycle,
                lifecycle_class=first.lifecycle_class,
                override_class=first.override_class,
                scope_rule_id=first.observation.value["scope_rule_id"],
                recommended_action=first.recommended_action,
                target_path=(
                    first.target_candidate.target_path
                    if first.target_proven
                    else None
                ),
                reference_complete=first.reference_complete,
                risk_band=first.risk_band,
                context_freshness=first.context_freshness,
                evidence_providers=tuple(
                    sorted({provider for row in members for provider in row.evidence_providers})
                ),
                warning_codes=tuple(
                    sorted({warning for row in members for warning in row.warning_codes})
                ),
                effect_codes=("plan-unavailable-m2",),
                canonical_conflict=first.canonical_conflict,
                relation_conflict=first.relation_conflict,
                target_proven=first.target_proven,
                analysis_provenance_json=canonical_json_bytes(
                    {
                        "items": [
                            {
                                "item_id": member.item_id,
                                "reference": json.loads(
                                    member.reference_provenance_json
                                ),
                                "risk": json.loads(
                                    member.risk_provenance_json
                                ),
                                "target": json.loads(
                                    member.target_provenance_json
                                ),
                            }
                            for member in sorted(
                                members,
                                key=lambda row: row.item_id,
                            )
                        ],
                        "schema_version": 1,
                    }
                ),
                file_count=unit.underlying_file_count,
                total_bytes=unit.total_bytes,
                effect_count=0,
            )
        )
    return tuple(sorted(result, key=lambda row: row.unit_id))


def _coverage_summary(coverage: Mapping[str, Any]) -> review_compiler.CoverageSummary:
    try:
        folders = coverage["folders"]
        folder_outcomes = folders["outcomes"]
        files = coverage["files"]
        file_outcomes = files["outcomes"]
        return review_compiler.CoverageSummary(
            folders_total=folders["denominator"],
            folders_traversed=(
                folder_outcomes["traversed_complete"]
                + folder_outcomes["traversed_partial"]
            ),
            folders_excluded=folder_outcomes["not_entered"],
            folders_error=folder_outcomes["error"],
            files_total=files["denominator"],
            files_inspected=file_outcomes["content_inspected"],
            files_metadata_only=file_outcomes["metadata_only"],
            files_excluded=file_outcomes["not_entered"],
            files_error=file_outcomes["error"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RunReviewError("inventory coverage counters are invalid") from exc


def _workstream_summaries(
    units: Sequence[batch_service.BatchUnit],
    compiled: policy.CompiledPolicy,
) -> Tuple[review_compiler.WorkstreamSummary, ...]:
    lifecycle_by_id = {row.id: row.lifecycle for row in compiled.workstreams}
    ids = set(lifecycle_by_id)
    ids.update(unit.primary_workstream for unit in units)
    return tuple(
        review_compiler.WorkstreamSummary(
            workstream_id=workstream_id,
            lifecycle=lifecycle_by_id.get(workstream_id, "unassigned"),
            review_items=sum(
                unit.primary_workstream == workstream_id for unit in units
            ),
            blocked=sum(
                unit.primary_workstream == workstream_id
                and unit.risk_band == "blocked"
                for unit in units
            ),
            errors=sum(
                unit.primary_workstream == workstream_id
                and "inventory-error" in unit.warning_codes
                for unit in units
            ),
        )
        for workstream_id in sorted(ids)
    )


def _coverage_payload(value: review_compiler.CoverageSummary) -> Dict[str, int]:
    return {
        name: getattr(value, name)
        for name in (
            "folders_total",
            "folders_traversed",
            "folders_excluded",
            "folders_error",
            "files_total",
            "files_inspected",
            "files_metadata_only",
            "files_excluded",
            "files_error",
        )
    }


def _workstream_payload(
    values: Sequence[review_compiler.WorkstreamSummary],
) -> list:
    return [
        {
            "blocked": row.blocked,
            "errors": row.errors,
            "lifecycle": row.lifecycle,
            "review_items": row.review_items,
            "workstream_id": row.workstream_id,
        }
        for row in values
    ]


def review_document_from_campaign_snapshot(
    snapshot_payload_json: bytes,
) -> review_compiler.ReviewDocument:
    """Reconstruct the exact run overview after a process restart."""

    try:
        parsed = review_context.parse_campaign_review_snapshot(
            snapshot_payload_json
        )
        payload = parsed.payload
        context = parsed.context
        return review_compiler.ReviewDocument(
            review_kind="run-overview",
            source_kind="campaign-snapshot",
            source_id=payload["snapshot_id"],
            source_snapshot_sha256=sha256_bytes(snapshot_payload_json),
            rendered_at=context.rendered_at,
            campaign_id=payload["campaign_id"],
            batch_id=None,
            snapshot_id=payload["snapshot_id"],
            snapshot_version=payload["version"],
            policy_binding=context.policy_binding,
            coverage=context.coverage,
            bounds=None,
            workstreams=context.workstreams,
            items=parsed.rows,
            warning_codes=context.warning_codes,
        )
    except (
        KeyError,
        TypeError,
        review_compiler.ReviewCompileError,
        review_context.ReviewContextError,
    ) as exc:
        raise RunReviewError(
            "campaign review context binding cannot be reconstructed: %s" % exc
        ) from exc


def root_review_item_paths(
    package: inventory.InventoryPackageReadback,
) -> Tuple[str, ...]:
    """Return the exact physical-file membership from sealed package bytes."""

    _coverage, observations = _parse_package(package)
    paths = tuple(
        sorted(
            row.value["path"]
            for row in observations
            if row.value["physical_kind"] == "file"
        )
    )
    if len(paths) != len(set(paths)):
        raise RunReviewError("inventory file paths are duplicated")
    return paths


def prepare_root_review(
    package: inventory.InventoryPackageReadback,
    compiled_policy: policy.CompiledPolicy,
    approved_policy: admission.ApprovedPolicyRef,
    *,
    campaign_id: str,
    snapshot_id: str,
    rendered_at: str,
    item_ids_by_path: Mapping[str, str],
) -> PreparedRootReview:
    """Build the exact root campaign review from already-sealed M1 bytes."""

    raw_root = _require_policy(package, compiled_policy, approved_policy)
    coverage, observations = _parse_package(package)
    file_observations = tuple(
        row for row in observations if row.value["physical_kind"] == "file"
    )
    paths = {row.value["path"] for row in file_observations}
    if not isinstance(item_ids_by_path, Mapping) or set(item_ids_by_path) != paths:
        raise RunReviewError("item id mapping must exactly cover file observations")
    item_ids = tuple(_uuid4(item_ids_by_path[path]) for path in sorted(paths))
    if len(set(item_ids)) != len(item_ids):
        raise RunReviewError("item id mapping contains duplicate UUID4 values")
    by_fingerprint: Dict[str, list] = {}
    for row in file_observations:
        sensitivity, _access_domain = _scope_domain(compiled_policy, row)
        fingerprint = row.value["fingerprint"]
        if (
            sensitivity != "private"
            and row.value["scope_class"] not in _OPAQUE_SCOPES
            and fingerprint["kind"] == "sha256"
            and fingerprint["value"] is not None
        ):
            by_fingerprint.setdefault(fingerprint["value"], []).append(
                row.observation_id
            )
    duplicate_ids = {
        observation_id: tuple(
            sorted(other for other in observation_ids if other != observation_id)
        )
        for observation_ids in by_fingerprint.values()
        if len(observation_ids) > 1
        for observation_id in observation_ids
    }
    reference_analyzer = references.ReferenceAnalyzer("reference-m2-v2")
    reference_context = _reference_context(
        observations,
        raw_root=raw_root,
        compiled=compiled_policy,
    )
    envelopes = {
        row.observation_id: reference_analyzer.analyze_context(
            context=reference_context,
            candidate_path=row.value["path"],
        )
        for row in file_observations
    }
    projections = tuple(
        _project_item(
            row,
            item_id=item_ids_by_path[row.value["path"]],
            raw_root=raw_root,
            compiled=compiled_policy,
            reference_envelope=envelopes[row.observation_id],
            duplicate_observation_ids=duplicate_ids.get(
                row.observation_id,
                (),
            ),
        )
        for row in file_observations
    )
    import_plan = _import_plan(
        observations,
        projections,
        snapshot_id=snapshot_id,
    )
    units = _batch_units(projections)
    policy_binding = (
        "generation=%d;source=%s/%s;guard=%d;full=%s"
        % (
            approved_policy.generation,
            approved_policy.source_kind,
            approved_policy.source_run_id,
            approved_policy.guard_epoch,
            approved_policy.full_hash,
        )
    )
    coverage_summary = _coverage_summary(coverage)
    workstream_summaries = _workstream_summaries(units, compiled_policy)
    snapshot_payload = canonical_json_bytes(
        {
            "analysis_contexts": [reference_context.to_dict()],
            "campaign_id": campaign_id,
            "classification_candidate_count": len(
                import_plan.classification_candidates
            ),
            "coverage": coverage,
            "decisions": [],
            "import_payload_sha256": import_plan.sha256,
            "kind": "campaign-genesis-review",
            "parent_snapshot_id": None,
            "review_context": {
                "coverage": _coverage_payload(coverage_summary),
                "policy_binding": policy_binding,
                "rendered_at": rendered_at,
                "warning_codes": ["m2-no-structural-authority"],
                "workstreams": _workstream_payload(workstream_summaries),
            },
            "root_run_id": package.request.run_id,
            "root_run_sha256": package.terminal.package_sha256,
            "schema_version": 2,
            "snapshot_id": snapshot_id,
            "structural_approval_ready": False,
            "units": [unit.to_dict() for unit in units],
            "version": 1,
        }
    )
    snapshot_sha256 = sha256_bytes(snapshot_payload)
    review_document = review_document_from_campaign_snapshot(snapshot_payload)
    return PreparedRootReview(
        import_plan=import_plan,
        batch_units=units,
        snapshot_payload_json=snapshot_payload,
        snapshot_sha256=snapshot_sha256,
        review_document=review_document,
    )


__all__ = [
    "PreparedRootReview",
    "RunReviewError",
    "prepare_root_review",
    "review_document_from_campaign_snapshot",
    "root_review_item_paths",
]
