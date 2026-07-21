"""Restart-safe review context and batch-preview reconstruction for M2."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple

from . import references, review_compiler
from .canonical_json import canonical_json_bytes, sha256_bytes


_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_WARNINGS = frozenset(
    (
        "m2-no-structural-authority",
        "private-metadata-only",
        "opaque-content-unopened",
        "reference-incomplete",
        "lifecycle-frozen",
        "competing-candidate",
        "inventory-error",
    )
)
_COVERAGE_FIELDS = (
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
_WORKSTREAM_FIELDS = frozenset(
    ("workstream_id", "lifecycle", "review_items", "blocked", "errors")
)
REVIEW_UNIT_PAYLOAD_FIELDS = frozenset(
    (
        "access_domain",
        "analysis_provenance",
        "authority",
        "canonical_conflict",
        "canonical_path",
        "context_freshness",
        "display_path",
        "document_lifecycle",
        "document_role",
        "effect_count",
        "effect_codes",
        "evidence_providers",
        "file_count",
        "lifecycle_class",
        "member_item_ids",
        "member_paths",
        "override_class",
        "primary_workstream",
        "recommended_action",
        "reference_complete",
        "relation_conflict",
        "related_workstreams",
        "risk_band",
        "scope_rule_id",
        "scope_class",
        "sensitivity",
        "shared",
        "target_path",
        "target_proven",
        "total_bytes",
        "unit_id",
        "unit_kind",
        "underlying_file_count",
        "warning_codes",
    )
)
_SNAPSHOT_FIELDS = frozenset(
    (
        "analysis_contexts",
        "actor",
        "approval_ready",
        "batch_id",
        "batch_version",
        "bounds",
        "campaign_id",
        "campaign_snapshot_sha256",
        "campaign_review_revision",
        "parent_snapshot_id",
        "parent_snapshot_sha256",
        "request_hash",
        "review_context",
        "schema_version",
        "snapshot_id",
        "structural_approval_ready",
        "structural_blocker",
        "units",
    )
)
_CAMPAIGN_SNAPSHOT_FIELDS = frozenset(
    (
        "campaign_id",
        "classification_candidate_count",
        "coverage",
        "decisions",
        "import_payload_sha256",
        "kind",
        "parent_snapshot_id",
        "review_context",
        "root_run_id",
        "root_run_sha256",
        "schema_version",
        "snapshot_id",
        "structural_approval_ready",
        "units",
        "version",
    )
)


class ReviewContextError(ValueError):
    """Review context or its snapshot binding is malformed."""


def _canonical_json(raw: bytes, label: str) -> Any:
    if type(raw) is not bytes:
        raise TypeError("%s must be bytes" % label)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewContextError("%s is not canonical JSON" % label) from exc
    if canonical_json_bytes(value) != raw:
        raise ReviewContextError("%s is not canonical JSON" % label)
    return value


@dataclass(frozen=True)
class AnalysisContextBundle:
    """Immutable canonical collection of root reference-analysis contexts."""

    canonical_bytes: bytes
    _contexts: Tuple[references.ReferenceContext, ...] = field(
        init=False,
        repr=False,
        compare=False,
    )
    _contexts_by_id: Mapping[str, references.ReferenceContext] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        contexts = _canonical_json(self.canonical_bytes, "analysis contexts")
        if type(contexts) is not list or not contexts:
            raise ReviewContextError("analysis contexts are missing")
        try:
            parsed = tuple(
                references.reference_context_from_dict(value)
                for value in contexts
            )
        except (TypeError, references.ReferenceAnalysisError) as exc:
            raise ReviewContextError("analysis context is invalid: %s" % exc) from exc
        context_ids = tuple(context.context_id for context in parsed)
        if len(set(context_ids)) != len(context_ids):
            raise ReviewContextError("analysis context id is duplicated")
        if context_ids != tuple(sorted(context_ids)):
            raise ReviewContextError("analysis contexts are not sorted")
        if canonical_json_bytes(
            [context.to_dict() for context in parsed]
        ) != self.canonical_bytes:
            raise ReviewContextError("analysis contexts are not canonical")
        object.__setattr__(self, "_contexts", parsed)
        object.__setattr__(
            self,
            "_contexts_by_id",
            MappingProxyType(
                {context.context_id: context for context in parsed}
            ),
        )

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> "AnalysisContextBundle":
        return cls(raw)

    def to_json_value(self) -> list:
        value = _canonical_json(self.canonical_bytes, "analysis contexts")
        assert type(value) is list
        return value

    @staticmethod
    def _unit_payload(unit: Any) -> dict:
        value = unit if type(unit) is dict else None
        if value is None:
            to_dict = getattr(unit, "to_dict", None)
            if callable(to_dict):
                value = to_dict()
        if type(value) is not dict or set(value) != REVIEW_UNIT_PAYLOAD_FIELDS:
            raise ReviewContextError("analysis unit fields are invalid")
        return value

    def _required_context_ids(
        self,
        units: Any,
        *,
        exact_bundle: bool,
    ) -> Tuple[str, ...]:
        if type(units) not in (list, tuple) or not units:
            raise ReviewContextError("analysis units are missing")
        contexts_by_id = self._contexts_by_id
        required = set()
        for unit in units:
            value = self._unit_payload(unit)
            member_item_ids = value["member_item_ids"]
            member_paths = value["member_paths"]
            provenance = value["analysis_provenance"]
            if (
                type(member_item_ids) is not list
                or type(member_paths) is not list
                or not member_item_ids
                or len(member_item_ids) != len(member_paths)
                or len(set(member_item_ids)) != len(member_item_ids)
                or len(set(member_paths)) != len(member_paths)
                or type(provenance) is not dict
                or set(provenance) != {"items", "schema_version"}
                or provenance["schema_version"] != 1
                or type(provenance["items"]) is not list
            ):
                raise ReviewContextError("analysis unit membership is invalid")
            item_ids = [
                row.get("item_id") if type(row) is dict else None
                for row in provenance["items"]
            ]
            if item_ids != sorted(member_item_ids):
                raise ReviewContextError("analysis item references are incomplete")
            paths = dict(zip(member_item_ids, member_paths))
            for item in provenance["items"]:
                if type(item) is not dict or set(item) != {
                    "item_id",
                    "reference",
                    "risk",
                    "target",
                }:
                    raise ReviewContextError("analysis item reference is invalid")
                reference = item["reference"]
                if type(reference) is not dict or set(reference) != {
                    "candidate_path",
                    "complete",
                    "context_id",
                    "context_sha256",
                    "input_manifest_sha256",
                    "matches",
                    "schema_version",
                }:
                    raise ReviewContextError("analysis item reference is invalid")
                candidate_path = paths[item["item_id"]]
                if reference["candidate_path"] != candidate_path:
                    raise ReviewContextError(
                        "analysis item candidate path is invalid"
                    )
                context = contexts_by_id.get(reference["context_id"])
                if context is None:
                    raise ReviewContextError(
                        "analysis item context is missing"
                    )
                required.add(reference["context_id"])
                expected_complete = context.is_complete_for(candidate_path)
                if (
                    reference["schema_version"] != 2
                    or reference["context_sha256"]
                    != context.context_sha256
                    or reference["input_manifest_sha256"]
                    != context.canonical_sha256
                    or reference["complete"] is not expected_complete
                    or reference["matches"]
                    != [
                        match.to_dict()
                        for match in context.matches_for(candidate_path)
                    ]
                ):
                    raise ReviewContextError(
                        "analysis item reference binding is invalid"
                    )
        context_ids = tuple(sorted(contexts_by_id))
        required_ids = tuple(sorted(required))
        if exact_bundle and required_ids != context_ids:
            raise ReviewContextError(
                "analysis contexts include unrelated entries"
            )
        return required_ids

    def require_exact_unit_bindings(self, units: Any) -> None:
        self._required_context_ids(units, exact_bundle=True)

    def select_for_units(self, units: Any) -> "AnalysisContextBundle":
        required_ids = self._required_context_ids(units, exact_bundle=False)
        selected = [
            value
            for value in self.to_json_value()
            if value["context_id"] in required_ids
        ]
        return AnalysisContextBundle.from_canonical_bytes(
            canonical_json_bytes(selected)
        )


@dataclass(frozen=True)
class ReviewContext:
    rendered_at: str
    policy_binding: str
    coverage: review_compiler.CoverageSummary
    workstreams: Tuple[review_compiler.WorkstreamSummary, ...]
    warning_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.rendered_at, str) or _TIME.fullmatch(self.rendered_at) is None:
            raise ReviewContextError("rendered_at is invalid")
        if (
            not isinstance(self.policy_binding, str)
            or not self.policy_binding
            or any(ord(character) < 0x20 for character in self.policy_binding)
        ):
            raise ReviewContextError("policy binding is invalid")
        if type(self.coverage) is not review_compiler.CoverageSummary:
            raise TypeError("coverage must be CoverageSummary")
        if type(self.workstreams) is not tuple or any(
            type(row) is not review_compiler.WorkstreamSummary
            for row in self.workstreams
        ):
            raise TypeError("workstreams must be WorkstreamSummary values")
        if tuple(sorted(self.workstreams, key=lambda row: row.workstream_id)) != self.workstreams:
            raise ReviewContextError("workstreams must be sorted")
        if type(self.warning_codes) is not tuple or tuple(
            sorted(set(self.warning_codes))
        ) != self.warning_codes:
            raise ReviewContextError("warning codes must be unique and sorted")
        if set(self.warning_codes) - _WARNINGS:
            raise ReviewContextError("warning code is unsupported")

    def to_dict(self) -> dict:
        return {
            "coverage": {
                name: getattr(self.coverage, name) for name in _COVERAGE_FIELDS
            },
            "policy_binding": self.policy_binding,
            "rendered_at": self.rendered_at,
            "warning_codes": list(self.warning_codes),
            "workstreams": [
                {
                    "blocked": row.blocked,
                    "errors": row.errors,
                    "lifecycle": row.lifecycle,
                    "review_items": row.review_items,
                    "workstream_id": row.workstream_id,
                }
                for row in self.workstreams
            ],
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> "ReviewContext":
        value = _canonical_json(raw, "review context")
        if type(value) is not dict or set(value) != {
            "coverage",
            "policy_binding",
            "rendered_at",
            "warning_codes",
            "workstreams",
        }:
            raise ReviewContextError("review context fields are invalid")
        coverage = value["coverage"]
        workstreams = value["workstreams"]
        if (
            type(coverage) is not dict
            or set(coverage) != set(_COVERAGE_FIELDS)
            or type(workstreams) is not list
            or any(type(row) is not dict or set(row) != _WORKSTREAM_FIELDS for row in workstreams)
        ):
            raise ReviewContextError("review context projections are invalid")
        try:
            return cls(
                rendered_at=value["rendered_at"],
                policy_binding=value["policy_binding"],
                coverage=review_compiler.CoverageSummary(**coverage),
                workstreams=tuple(
                    review_compiler.WorkstreamSummary(
                        workstream_id=row["workstream_id"],
                        lifecycle=row["lifecycle"],
                        review_items=row["review_items"],
                        blocked=row["blocked"],
                        errors=row["errors"],
                    )
                    for row in workstreams
                ),
                warning_codes=tuple(value["warning_codes"]),
            )
        except (KeyError, TypeError, review_compiler.ReviewCompileError) as exc:
            raise ReviewContextError("review context values are invalid") from exc


def review_row_from_validated_unit_payload(value: dict) -> review_compiler.ReviewRow:
    """Map one already-validated canonical unit payload to its review row."""

    return review_compiler.ReviewRow(
        unit_id=value["unit_id"],
        unit_kind=value["unit_kind"],
        canonical_path=value["canonical_path"],
        display_path=value["display_path"],
        underlying_file_count=value["underlying_file_count"],
        primary_workstream=value["primary_workstream"],
        related_workstreams=tuple(value["related_workstreams"]),
        shared=value["shared"],
        document_role=value["document_role"],
        authority=value["authority"],
        document_lifecycle=value["document_lifecycle"],
        scope_class=value["scope_class"],
        sensitivity=value["sensitivity"],
        access_domain=value["access_domain"],
        recommended_action=value["recommended_action"],
        target_path=value["target_path"],
        risk_band=value["risk_band"],
        context_freshness=value["context_freshness"],
        evidence_providers=tuple(value["evidence_providers"]),
        warning_codes=tuple(value["warning_codes"]),
        effect_codes=tuple(value["effect_codes"]),
    )


def _review_row(value: Any) -> review_compiler.ReviewRow:
    if type(value) is not dict or set(value) != REVIEW_UNIT_PAYLOAD_FIELDS:
        raise ReviewContextError("batch review unit fields are invalid")
    if (
        value["file_count"] != value["underlying_file_count"]
        or type(value["member_item_ids"]) is not list
        or type(value["member_paths"]) is not list
        or len(value["member_item_ids"]) != value["underlying_file_count"]
        or len(value["member_paths"]) != value["underlying_file_count"]
    ):
        raise ReviewContextError("batch review unit membership is invalid")
    try:
        return review_row_from_validated_unit_payload(value)
    except (KeyError, TypeError, review_compiler.ReviewCompileError) as exc:
        raise ReviewContextError("batch review unit values are invalid") from exc


@dataclass(frozen=True)
class BatchSnapshotLineagePolicy:
    """Small lineage hook shared by genesis and copy-on-write renderers."""

    name: str
    minimum_version: int
    exact_version: Optional[int]
    parent_required: Optional[bool]

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or _IDENTIFIER.fullmatch(self.name) is None
            or type(self.minimum_version) is not int
            or self.minimum_version < 1
            or (
                self.exact_version is not None
                and (
                    type(self.exact_version) is not int
                    or self.exact_version < self.minimum_version
                )
            )
            or self.parent_required not in (None, False, True)
        ):
            raise ReviewContextError("batch snapshot lineage policy is invalid")

    def require(self, payload: dict) -> None:
        version = payload.get("batch_version")
        if (
            type(version) is not int
            or version < self.minimum_version
            or (self.exact_version is not None and version != self.exact_version)
        ):
            raise ReviewContextError(
                "%s batch snapshot version is invalid" % self.name
            )
        parent_id = payload.get("parent_snapshot_id")
        parent_sha256 = payload.get("parent_snapshot_sha256")
        parent_required = self.parent_required
        if parent_required is None:
            parent_required = version > 1
        if parent_required:
            if (
                type(parent_id) is not str
                or _IDENTIFIER.fullmatch(parent_id) is None
                or type(parent_sha256) is not str
                or _HASH.fullmatch(parent_sha256) is None
            ):
                raise ReviewContextError(
                    "%s batch snapshot parent is invalid" % self.name
                )
        elif parent_id is not None or parent_sha256 is not None:
            raise ReviewContextError(
                "%s batch snapshot must not have a parent" % self.name
            )


GENESIS_BATCH_LINEAGE = BatchSnapshotLineagePolicy(
    name="genesis",
    minimum_version=1,
    exact_version=1,
    parent_required=False,
)
DESCENDANT_BATCH_LINEAGE = BatchSnapshotLineagePolicy(
    name="descendant",
    minimum_version=2,
    exact_version=None,
    parent_required=True,
)
CURRENT_BATCH_LINEAGE = BatchSnapshotLineagePolicy(
    name="current",
    minimum_version=1,
    exact_version=None,
    parent_required=None,
)


@dataclass(frozen=True)
class ParsedBatchReviewSnapshot:
    """Typed shared projection of an already sealed batch snapshot."""

    canonical_bytes: bytes
    payload: dict
    context: ReviewContext
    analysis_contexts: AnalysisContextBundle
    unit_payloads: Tuple[dict, ...]
    rows: Tuple[review_compiler.ReviewRow, ...]
    bounds: dict


@dataclass(frozen=True)
class ParsedCampaignReviewSnapshot:
    """Typed root-campaign projection shared by producers and persisted readers."""

    canonical_bytes: bytes
    payload: dict
    context: ReviewContext
    analysis_contexts: Optional[AnalysisContextBundle]
    unit_payloads: Tuple[dict, ...]
    rows: Tuple[review_compiler.ReviewRow, ...]


def workstream_summaries_for_unit_payloads(
    unit_payloads: Tuple[dict, ...],
    context: ReviewContext,
) -> Tuple[review_compiler.WorkstreamSummary, ...]:
    """Derive exact workstream counters from validated batch unit payloads."""

    if type(unit_payloads) is not tuple:
        raise ReviewContextError("batch review units must be a tuple")
    if type(context) is not ReviewContext:
        raise TypeError("context must be ReviewContext")
    if any(
        type(value) is not dict
        or set(value) != REVIEW_UNIT_PAYLOAD_FIELDS
        for value in unit_payloads
    ):
        raise ReviewContextError("review unit fields are invalid")
    lifecycle_by_id = {
        row.workstream_id: row.lifecycle for row in context.workstreams
    }
    unknown = sorted(
        {
            value["primary_workstream"]
            for value in unit_payloads
        }
        - set(lifecycle_by_id)
    )
    if unknown:
        raise ReviewContextError(
            "review context does not cover batch workstream"
        )
    try:
        return tuple(
            review_compiler.WorkstreamSummary(
                workstream_id=workstream_id,
                lifecycle=lifecycle_by_id[workstream_id],
                review_items=sum(
                    value["primary_workstream"] == workstream_id
                    for value in unit_payloads
                ),
                blocked=sum(
                    value["primary_workstream"] == workstream_id
                    and value["risk_band"] == "blocked"
                    for value in unit_payloads
                ),
                errors=sum(
                    value["primary_workstream"] == workstream_id
                    and "inventory-error" in value["warning_codes"]
                    for value in unit_payloads
                ),
            )
            for workstream_id in sorted(lifecycle_by_id)
        )
    except (KeyError, TypeError, review_compiler.ReviewCompileError) as exc:
        raise ReviewContextError(
            "batch workstream summaries are invalid"
        ) from exc


def parse_campaign_review_snapshot(
    snapshot_payload: bytes,
) -> ParsedCampaignReviewSnapshot:
    """Strictly parse one root campaign snapshot without batch-only assumptions."""

    payload = _canonical_json(snapshot_payload, "campaign review snapshot")
    schema_version = (
        payload.get("schema_version") if type(payload) is dict else None
    )
    expected_fields = _CAMPAIGN_SNAPSHOT_FIELDS
    if schema_version == 2:
        expected_fields = expected_fields.union(("analysis_contexts",))
    if (
        type(payload) is not dict
        or set(payload) != expected_fields
        or schema_version not in (1, 2)
        or payload.get("kind") != "campaign-genesis-review"
        or payload.get("version") != 1
        or payload.get("parent_snapshot_id") is not None
        or payload.get("decisions") != []
        or payload.get("structural_approval_ready") is not False
        or type(payload.get("classification_candidate_count")) is not int
        or payload["classification_candidate_count"] < 0
        or type(payload.get("import_payload_sha256")) is not str
        or _HASH.fullmatch(payload["import_payload_sha256"]) is None
        or type(payload.get("root_run_sha256")) is not str
        or _HASH.fullmatch(payload["root_run_sha256"]) is None
        or type(payload.get("units")) is not list
        or any(
            type(payload.get(name)) is not str
            or _IDENTIFIER.fullmatch(payload[name]) is None
            for name in ("campaign_id", "root_run_id", "snapshot_id")
        )
    ):
        raise ReviewContextError("campaign review snapshot contract is invalid")

    unit_payloads = tuple(payload["units"])
    analysis_contexts: Optional[AnalysisContextBundle] = None
    if schema_version == 2:
        analysis_contexts = AnalysisContextBundle.from_canonical_bytes(
            canonical_json_bytes(payload["analysis_contexts"])
        )
        if unit_payloads:
            analysis_contexts.require_exact_unit_bindings(unit_payloads)

    context_value = payload["review_context"]
    if type(context_value) is not dict:
        raise ReviewContextError("campaign review context is invalid")
    context = ReviewContext.from_canonical_bytes(
        canonical_json_bytes(context_value)
    )
    rows = tuple(_review_row(value) for value in unit_payloads)
    unit_ids = tuple(row.unit_id for row in rows)
    if unit_ids != tuple(sorted(unit_ids)) or len(set(unit_ids)) != len(unit_ids):
        raise ReviewContextError(
            "campaign review units are duplicated or not sorted"
        )
    if context.workstreams != workstream_summaries_for_unit_payloads(
        unit_payloads,
        context,
    ):
        raise ReviewContextError(
            "campaign review workstream counters do not match units"
        )
    lifecycle_by_id = {
        row.workstream_id: row.lifecycle for row in context.workstreams
    }
    if any(
        lifecycle_by_id[value["primary_workstream"]]
        != value["lifecycle_class"]
        for value in unit_payloads
    ):
        raise ReviewContextError(
            "campaign review workstream lifecycle does not match units"
        )
    return ParsedCampaignReviewSnapshot(
        canonical_bytes=snapshot_payload,
        payload=payload,
        context=context,
        analysis_contexts=analysis_contexts,
        unit_payloads=unit_payloads,
        rows=rows,
    )


def parse_batch_review_snapshot(
    snapshot_payload: bytes,
    *,
    lineage_policy: BatchSnapshotLineagePolicy,
) -> ParsedBatchReviewSnapshot:
    """Parse common batch fields once; leave only lineage-specific policy outside."""

    if type(lineage_policy) is not BatchSnapshotLineagePolicy:
        raise TypeError("lineage_policy must be BatchSnapshotLineagePolicy")
    payload = _canonical_json(snapshot_payload, "batch snapshot")
    if type(payload) is dict and payload.get("schema_version") == 1:
        raise ReviewContextError(
            "batch snapshot v1 requires COW-normalization-required"
        )
    if (
        type(payload) is not dict
        or set(payload) != _SNAPSHOT_FIELDS
        or payload.get("schema_version") != 2
        or payload.get("approval_ready") is not False
        or payload.get("structural_approval_ready") is not False
        or payload.get("structural_blocker")
        != "effect-preview-not-available-m2"
        or type(payload.get("units")) is not list
        or not payload["units"]
        or any(
            type(payload.get(name)) is not str
            or _IDENTIFIER.fullmatch(payload[name]) is None
            for name in ("batch_id", "campaign_id", "snapshot_id")
        )
        or type(payload.get("campaign_review_revision")) is not int
        or payload["campaign_review_revision"] < 1
        or _HASH.fullmatch(payload.get("campaign_snapshot_sha256", "")) is None
        or _HASH.fullmatch(payload.get("request_hash", "")) is None
    ):
        raise ReviewContextError("batch snapshot contract is invalid")
    lineage_policy.require(payload)
    bounds = payload["bounds"]
    if (
        type(bounds) is not dict
        or set(bounds) != {"bytes", "effects", "files", "items"}
        or any(type(value) is not int or value < 1 for value in bounds.values())
    ):
        raise ReviewContextError("batch snapshot bounds are invalid")
    context = ReviewContext.from_canonical_bytes(
        canonical_json_bytes(payload["review_context"])
    )
    analysis_contexts = AnalysisContextBundle.from_canonical_bytes(
        canonical_json_bytes(payload["analysis_contexts"])
    )
    unit_payloads = tuple(payload["units"])
    analysis_contexts.require_exact_unit_bindings(unit_payloads)
    rows = tuple(_review_row(value) for value in unit_payloads)
    if tuple(sorted(rows, key=lambda row: row.unit_id)) != rows:
        raise ReviewContextError("batch review units must be sorted")
    if len({row.unit_id for row in rows}) != len(rows):
        raise ReviewContextError("batch review units are duplicated")
    if context.workstreams != workstream_summaries_for_unit_payloads(
        unit_payloads,
        context,
    ):
        raise ReviewContextError(
            "batch review context counts do not match units"
        )
    member_item_ids = tuple(
        item_id
        for unit in unit_payloads
        for item_id in unit["member_item_ids"]
    )
    if len(member_item_ids) != len(set(member_item_ids)):
        raise ReviewContextError("batch review unit membership overlaps")
    if (
        len(rows) > bounds["items"]
        or sum(row.underlying_file_count for row in rows) > bounds["files"]
        or sum(unit["total_bytes"] for unit in unit_payloads) > bounds["bytes"]
        or sum(unit["effect_count"] for unit in unit_payloads) > bounds["effects"]
    ):
        raise ReviewContextError("batch review units exceed sealed bounds")
    return ParsedBatchReviewSnapshot(
        canonical_bytes=snapshot_payload,
        payload=payload,
        context=context,
        analysis_contexts=analysis_contexts,
        unit_payloads=unit_payloads,
        rows=rows,
        bounds=bounds,
    )


def review_document_from_parsed_batch_snapshot(
    parsed: ParsedBatchReviewSnapshot,
) -> review_compiler.ReviewDocument:
    """Build the common preview document from one typed snapshot parse."""

    if type(parsed) is not ParsedBatchReviewSnapshot:
        raise TypeError("parsed must be ParsedBatchReviewSnapshot")
    payload = parsed.payload
    rows = parsed.rows
    context = parsed.context
    bounds = parsed.bounds
    try:
        return review_compiler.ReviewDocument(
            review_kind="batch-preview",
            source_kind="batch-snapshot",
            source_id=payload["snapshot_id"],
            source_snapshot_sha256=sha256_bytes(parsed.canonical_bytes),
            rendered_at=context.rendered_at,
            campaign_id=payload["campaign_id"],
            batch_id=payload["batch_id"],
            snapshot_id=payload["snapshot_id"],
            snapshot_version=payload["batch_version"],
            policy_binding=context.policy_binding,
            coverage=context.coverage,
            bounds=review_compiler.ReviewBounds(
                review_items=len(rows),
                underlying_files=sum(
                    row.underlying_file_count for row in rows
                ),
                total_bytes=bounds["bytes"],
                leaf_folders=sum(row.unit_kind == "folder" for row in rows),
                effect_count=bounds["effects"],
            ),
            workstreams=context.workstreams,
            items=rows,
            warning_codes=context.warning_codes,
        )
    except (TypeError, review_compiler.ReviewCompileError) as exc:
        raise ReviewContextError("batch review document is invalid") from exc


def batch_review_document_from_snapshot(
    snapshot_payload: bytes,
) -> review_compiler.ReviewDocument:
    """Rebuild a batch preview solely from the exact sealed snapshot bytes."""

    return review_document_from_parsed_batch_snapshot(
        parse_batch_review_snapshot(
            snapshot_payload,
            lineage_policy=GENESIS_BATCH_LINEAGE,
        )
    )


__all__ = [
    "AnalysisContextBundle",
    "BatchSnapshotLineagePolicy",
    "CURRENT_BATCH_LINEAGE",
    "DESCENDANT_BATCH_LINEAGE",
    "GENESIS_BATCH_LINEAGE",
    "ParsedCampaignReviewSnapshot",
    "ParsedBatchReviewSnapshot",
    "REVIEW_UNIT_PAYLOAD_FIELDS",
    "ReviewContext",
    "ReviewContextError",
    "batch_review_document_from_snapshot",
    "parse_campaign_review_snapshot",
    "parse_batch_review_snapshot",
    "review_document_from_parsed_batch_snapshot",
    "review_row_from_validated_unit_payload",
    "workstream_summaries_for_unit_payloads",
]
