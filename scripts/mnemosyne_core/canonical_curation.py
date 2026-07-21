"""Immutable Stage-A Workstream curation plans and human decisions.

Stage A deliberately models only regular-file move/rename effects.  Meaning
changing transformations, relations and projection writes are not representable
by these types, so callers cannot accidentally approve them through this seam.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Mapping, Optional, Tuple

from .canonical_json import canonical_json_bytes, sha256_bytes
from . import context_assembly


PLAN_SCHEMA = "mnemosyne-canonical-curation-plan-v1"
CONTEXT_BOUND_PLAN_SCHEMA = "mnemosyne-context-bound-curation-plan-v1"
APPROVED_REQUIREMENTS_SHA256 = (
    "189e2c5dff2e422d435581509044ad3b3efeaf64a5db3c968d295f5f3a839166"
)
COMMON_SPINE_ROLES = (
    "overview",
    "current_state",
    "decisions",
    "work_results",
    "references",
)
DECISION_ACTIONS = (
    "APPROVE_ALL",
    "APPROVE_SELECTED",
    "REJECT",
    "DEFER",
)
_CONTEXT_BOUND_PLAN_FIELDS = {
    "captured_lifecycle",
    "context_binding",
    "coverage",
    "cutoff_required",
    "effects",
    "findings",
    "irreversible_consequence",
    "out_of_scope_paths",
    "parent_plan_sha256",
    "policy_sha256",
    "primary_workstream_id",
    "project_home",
    "project_identity",
    "root_identity",
    "schema",
    "source_observation_sha256",
    "source_observations",
    "spec_sha256",
    "spine",
    "unchanged_paths",
}

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{1,95}\Z")


class CanonicalCurationError(ValueError):
    """A Stage-A plan or decision is malformed or outside the closed model."""

    def __init__(self, message: str, *, reason_code: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _require_hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise CanonicalCurationError(
            "%s is invalid" % label,
            reason_code="PLAN_INVALID",
        )
    return value


def _require_identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise CanonicalCurationError(
            "%s is invalid" % label,
            reason_code="PLAN_INVALID",
        )
    return value


def _require_relative_path(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CanonicalCurationError(
            "%s is invalid" % label,
            reason_code="PLAN_INVALID",
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise CanonicalCurationError(
            "%s is invalid" % label,
            reason_code="PLAN_INVALID",
        )
    return value


def _public_text(value: object, label: str, maximum: int = 2048) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 and character not in "\n\t" for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise CanonicalCurationError(
            "%s is invalid" % label,
            reason_code="PLAN_INVALID",
        )
    return value


def _require_non_empty_text_tuple(value: object, label: str) -> Tuple[str, ...]:
    if (
        type(value) is not tuple
        or not value
        or any(type(item) is not str or not item for item in value)
    ):
        raise CanonicalCurationError(
            "%s is invalid" % label,
            reason_code="PLAN_INVALID",
        )
    return value


@dataclass(frozen=True)
class SourceObservation:
    observation_id: str
    relative_path: str
    owner_kind: str
    owner_id: str
    lifecycle: str
    document_role: str
    classification: str
    classification_evidence: Tuple[str, ...]
    content_summary: str
    device: int
    inode: int
    owner: int
    mode: int
    link_count: int
    size: int
    modified_time_ns: int
    content_sha256: str
    snapshot_sha256: str

    def __post_init__(self) -> None:
        _require_identifier(self.observation_id, "observation id")
        _require_relative_path(self.relative_path, "observation path")
        if self.owner_kind not in {"workstream", "unassigned"}:
            raise CanonicalCurationError(
                "observation owner kind is invalid",
                reason_code="PLAN_INVALID",
            )
        _require_identifier(self.owner_id, "observation owner id")
        if self.lifecycle not in {"active", "unassigned"}:
            raise CanonicalCurationError(
                "observation lifecycle is invalid",
                reason_code="PLAN_INVALID",
            )
        if self.document_role not in COMMON_SPINE_ROLES:
            raise CanonicalCurationError(
                "observation document role is invalid",
                reason_code="PLAN_INVALID",
            )
        if self.classification not in {"EXACT", "SUPPORTED"}:
            raise CanonicalCurationError(
                "observation classification is invalid",
                reason_code="PLAN_INVALID",
            )
        _require_non_empty_text_tuple(
            self.classification_evidence,
            "observation classification evidence",
        )
        _public_text(self.content_summary, "observation summary", maximum=512)
        for label, value in (
            ("device", self.device),
            ("inode", self.inode),
            ("owner", self.owner),
            ("mode", self.mode),
            ("link count", self.link_count),
            ("size", self.size),
            ("modified time", self.modified_time_ns),
        ):
            if type(value) is not int or value < 0:
                raise CanonicalCurationError(
                    "observation %s is invalid" % label,
                    reason_code="PLAN_INVALID",
                )
        if self.link_count != 1:
            raise CanonicalCurationError(
                "observation link count is unsupported",
                reason_code="PLAN_INVALID",
            )
        _require_hash(self.content_sha256, "observation content hash")
        _require_hash(self.snapshot_sha256, "observation snapshot hash")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "classification": self.classification,
            "classification_evidence": list(self.classification_evidence),
            "content_sha256": self.content_sha256,
            "content_summary": self.content_summary,
            "device": self.device,
            "document_role": self.document_role,
            "inode": self.inode,
            "lifecycle": self.lifecycle,
            "link_count": self.link_count,
            "mode": self.mode,
            "modified_time_ns": self.modified_time_ns,
            "observation_id": self.observation_id,
            "owner": self.owner,
            "owner_id": self.owner_id,
            "owner_kind": self.owner_kind,
            "relative_path": self.relative_path,
            "size": self.size,
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass(frozen=True)
class PlanEffect:
    effect_id: str
    action: str
    input_observation_id: str
    source_path: str
    output_path: str
    expected_output_sha256: str
    risk_codes: Tuple[str, ...]
    review_status: str = "REVIEW_REQUIRED"
    dependency_effect_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.effect_id, "effect id")
        if self.action not in {"move", "rename"}:
            raise CanonicalCurationError(
                "effect action is not implemented",
                reason_code="EFFECT_NOT_IMPLEMENTED",
            )
        _require_identifier(self.input_observation_id, "input observation id")
        _require_relative_path(self.source_path, "effect source path")
        _require_relative_path(self.output_path, "effect output path")
        if self.source_path.casefold() == self.output_path.casefold():
            raise CanonicalCurationError(
                "effect does not change the path",
                reason_code="PLAN_PATH_GRAPH_UNSUPPORTED",
            )
        _require_hash(self.expected_output_sha256, "effect output hash")
        _require_non_empty_text_tuple(self.risk_codes, "effect risk codes")
        if (
            self.review_status != "REVIEW_REQUIRED"
            or type(self.dependency_effect_ids) is not tuple
        ):
            raise CanonicalCurationError(
                "effect review evidence is invalid",
                reason_code="PLAN_INVALID",
            )
        for dependency in self.dependency_effect_ids:
            _require_identifier(dependency, "effect dependency")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "action": self.action,
            "dependency_effect_ids": list(self.dependency_effect_ids),
            "effect_id": self.effect_id,
            "expected_output_sha256": self.expected_output_sha256,
            "input_observation_id": self.input_observation_id,
            "output_path": self.output_path,
            "review_status": self.review_status,
            "risk_codes": list(self.risk_codes),
            "source_path": self.source_path,
        }


def _effect_targets_stay_within_project(
    effects: Tuple[PlanEffect, ...],
    project_home: str,
) -> bool:
    project_prefix = project_home.casefold() + "/"
    return all(
        effect.output_path.casefold().startswith(project_prefix)
        for effect in effects
    )


@dataclass(frozen=True)
class SpineEntry:
    role: str
    current_path: Optional[str]
    current_heading: Optional[str]
    proposed_path: Optional[str]
    proposed_heading: Optional[str]
    status: str

    def __post_init__(self) -> None:
        if self.role not in COMMON_SPINE_ROLES or self.status not in {
            "PRESENT",
            "PROPOSED",
            "MISSING",
        }:
            raise CanonicalCurationError(
                "common spine entry is invalid",
                reason_code="PLAN_INVALID",
            )
        for label, value in (
            ("current path", self.current_path),
            ("proposed path", self.proposed_path),
        ):
            if value is not None:
                _require_relative_path(value, label)
        for label, value in (
            ("current heading", self.current_heading),
            ("proposed heading", self.proposed_heading),
        ):
            if value is not None:
                _public_text(value, label, maximum=256)

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "current_heading": self.current_heading,
            "current_path": self.current_path,
            "proposed_heading": self.proposed_heading,
            "proposed_path": self.proposed_path,
            "role": self.role,
            "status": self.status,
        }


@dataclass(frozen=True)
class CurationFinding:
    finding_id: str
    finding_kind: str
    relative_path: str
    evidence: Tuple[str, ...]
    status: str = "BLOCKED_UNTIL_REINFORCEMENT"

    def __post_init__(self) -> None:
        _require_identifier(self.finding_id, "finding id")
        _require_relative_path(self.relative_path, "finding path")
        if (
            type(self.finding_kind) is not str
            or not self.finding_kind
            or self.status != "BLOCKED_UNTIL_REINFORCEMENT"
        ):
            raise CanonicalCurationError(
                "curation finding is invalid",
                reason_code="PLAN_INVALID",
            )
        _require_non_empty_text_tuple(self.evidence, "curation finding evidence")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "evidence": list(self.evidence),
            "finding_id": self.finding_id,
            "finding_kind": self.finding_kind,
            "relative_path": self.relative_path,
            "status": self.status,
        }


@dataclass(frozen=True)
class CurationPlan:
    primary_workstream_id: str
    captured_lifecycle: str
    project_home: str
    project_identity: Tuple[int, int, int, int]
    root_identity: Tuple[int, int, int, int]
    policy_sha256: str
    source_observations: Tuple[SourceObservation, ...]
    effects: Tuple[PlanEffect, ...]
    spine: Tuple[SpineEntry, ...]
    findings: Tuple[CurationFinding, ...]
    unchanged_paths: Tuple[str, ...]
    out_of_scope_paths: Tuple[str, ...]
    coverage: Tuple[Tuple[str, object], ...]
    parent_plan_sha256: Optional[str] = None
    schema: str = PLAN_SCHEMA
    spec_sha256: str = APPROVED_REQUIREMENTS_SHA256
    cutoff_required: bool = False
    irreversible_consequence: str = "NONE_STAGE_A_PATH_ONLY"

    def __post_init__(self) -> None:
        _require_identifier(self.primary_workstream_id, "primary Workstream id")
        if self.captured_lifecycle != "active":
            raise CanonicalCurationError(
                "Stage-A plan requires an active Workstream",
                reason_code="WORKSTREAM_FROZEN",
            )
        _require_relative_path(self.project_home, "project home")
        for identity in (self.project_identity, self.root_identity):
            if (
                type(identity) is not tuple
                or len(identity) != 4
                or any(type(value) is not int or value < 0 for value in identity)
            ):
                raise CanonicalCurationError(
                    "filesystem identity is invalid",
                    reason_code="PLAN_INVALID",
                )
        _require_hash(self.policy_sha256, "policy hash")
        if self.parent_plan_sha256 is not None:
            _require_hash(self.parent_plan_sha256, "parent plan hash")
        if (
            self.schema != PLAN_SCHEMA
            or self.spec_sha256 != APPROVED_REQUIREMENTS_SHA256
            or self.cutoff_required is not False
            or self.irreversible_consequence != "NONE_STAGE_A_PATH_ONLY"
        ):
            raise CanonicalCurationError(
                "Stage-A plan seal is invalid",
                reason_code="PLAN_INVALID",
            )
        if any(type(value) is not expected for value, expected in (
            (self.source_observations, tuple),
            (self.effects, tuple),
            (self.spine, tuple),
            (self.findings, tuple),
            (self.unchanged_paths, tuple),
            (self.out_of_scope_paths, tuple),
            (self.coverage, tuple),
        )):
            raise CanonicalCurationError(
                "plan collections are invalid",
                reason_code="PLAN_INVALID",
            )
        if tuple(entry.role for entry in self.spine) != COMMON_SPINE_ROLES:
            raise CanonicalCurationError(
                "common spine roles are incomplete",
                reason_code="PLAN_INVALID",
            )
        observation_ids = [value.observation_id for value in self.source_observations]
        effect_ids = [value.effect_id for value in self.effects]
        sources = [value.source_path.casefold() for value in self.effects]
        outputs = [value.output_path.casefold() for value in self.effects]
        if (
            len(observation_ids) != len(set(observation_ids))
            or len(effect_ids) != len(set(effect_ids))
            or len(sources) != len(set(sources))
            or len(outputs) != len(set(outputs))
            or set(sources) & set(outputs)
        ):
            raise CanonicalCurationError(
                "plan path graph is unsupported",
                reason_code="PLAN_PATH_GRAPH_UNSUPPORTED",
            )
        observations = {value.observation_id: value for value in self.source_observations}
        effects = {value.effect_id: value for value in self.effects}
        if not _effect_targets_stay_within_project(
            self.effects,
            self.project_home,
        ):
            raise CanonicalCurationError(
                "effect target is outside the canonical project home",
                reason_code="PLAN_INVALID",
            )
        for effect in self.effects:
            observation = observations.get(effect.input_observation_id)
            if (
                observation is None
                or observation.relative_path != effect.source_path
                or observation.content_sha256 != effect.expected_output_sha256
                or any(dependency not in effects for dependency in effect.dependency_effect_ids)
            ):
                raise CanonicalCurationError(
                    "effect is not bound to its exact source observation",
                    reason_code="PLAN_INVALID",
                )
        for path in (*self.unchanged_paths, *self.out_of_scope_paths):
            _require_relative_path(path, "coverage path")

    @property
    def source_observation_sha256(self) -> str:
        return sha256_bytes(
            canonical_json_bytes(
                [
                    value.canonical_value
                    for value in sorted(
                        self.source_observations,
                        key=lambda item: item.observation_id,
                    )
                ]
            )
        )

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "captured_lifecycle": self.captured_lifecycle,
            "coverage": dict(self.coverage),
            "cutoff_required": self.cutoff_required,
            "effects": [
                value.canonical_value
                for value in sorted(self.effects, key=lambda item: item.effect_id)
            ],
            "findings": [
                value.canonical_value
                for value in sorted(self.findings, key=lambda item: item.finding_id)
            ],
            "irreversible_consequence": self.irreversible_consequence,
            "out_of_scope_paths": sorted(self.out_of_scope_paths),
            "parent_plan_sha256": self.parent_plan_sha256,
            "policy_sha256": self.policy_sha256,
            "primary_workstream_id": self.primary_workstream_id,
            "project_home": self.project_home,
            "project_identity": list(self.project_identity),
            "root_identity": list(self.root_identity),
            "schema": self.schema,
            "source_observation_sha256": self.source_observation_sha256,
            "source_observations": [
                value.canonical_value
                for value in sorted(
                    self.source_observations,
                    key=lambda item: item.observation_id,
                )
            ],
            "spec_sha256": self.spec_sha256,
            "spine": [value.canonical_value for value in self.spine],
            "unchanged_paths": sorted(self.unchanged_paths),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_value)

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes)

    def subset(self, selected_effect_ids: Tuple[str, ...]) -> "CurationPlan":
        if type(selected_effect_ids) is not tuple or not selected_effect_ids:
            raise CanonicalCurationError(
                "selected effect membership is empty",
                reason_code="DECISION_INVALID",
            )
        by_id = {effect.effect_id: effect for effect in self.effects}
        selected = set(selected_effect_ids)
        if len(selected) != len(selected_effect_ids) or not selected <= set(by_id):
            raise CanonicalCurationError(
                "selected effect membership is invalid",
                reason_code="DECISION_INVALID",
            )
        pending = list(selected)
        while pending:
            effect = by_id[pending.pop()]
            for dependency in effect.dependency_effect_ids:
                if dependency not in selected:
                    selected.add(dependency)
                    pending.append(dependency)
        effects = tuple(effect for effect in self.effects if effect.effect_id in selected)
        observation_ids = {effect.input_observation_id for effect in effects}
        observations = tuple(
            observation
            for observation in self.source_observations
            if observation.observation_id in observation_ids
        )
        unselected_sources = tuple(
            effect.source_path for effect in self.effects if effect.effect_id not in selected
        )
        selected_outputs = {effect.output_path for effect in effects}
        selected_sources = {effect.source_path for effect in effects}
        spine = []
        for entry in self.spine:
            if entry.status != "PROPOSED" or entry.proposed_path in selected_outputs:
                spine.append(entry)
            elif entry.current_path is not None:
                spine.append(
                    replace(
                        entry,
                        proposed_path=entry.current_path,
                        proposed_heading=entry.current_heading,
                        status="PRESENT",
                    )
                )
            else:
                spine.append(
                    replace(
                        entry,
                        proposed_path=None,
                        proposed_heading=None,
                        status="MISSING",
                    )
                )
        coverage = dict(self.coverage)
        coverage.update(
            {
                "parent_effect_count": len(self.effects),
                "subset_effect_count": len(effects),
                "subset_source_count": len(observations),
            }
        )
        return replace(
            self,
            source_observations=observations,
            effects=effects,
            spine=tuple(spine),
            findings=tuple(
                finding
                for finding in self.findings
                if finding.relative_path in selected_sources
            ),
            unchanged_paths=tuple(sorted(set(self.unchanged_paths + unselected_sources))),
            coverage=tuple(sorted(coverage.items())),
            parent_plan_sha256=self.sha256,
        )


@dataclass(frozen=True)
class ContextBinding:
    """The minimum authority projection carried by a context-bound Plan."""

    outcome: str
    assembly_sha256: str
    coverage_sha256: str

    def __post_init__(self) -> None:
        if self.outcome != context_assembly.COMPLETE:
            raise CanonicalCurationError(
                "Context binding is not complete",
                reason_code="CONTEXT_INCOMPLETE",
            )
        _require_hash(self.assembly_sha256, "Context Assembly hash")
        _require_hash(self.coverage_sha256, "Context coverage hash")

    @property
    def canonical_value(self) -> dict[str, str]:
        return {
            "assembly_sha256": self.assembly_sha256,
            "coverage_sha256": self.coverage_sha256,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class ContextBoundCurationPlan:
    """A legacy-shaped plan sealed to one exact complete Context Assembly.

    The full assembly intentionally remains out of this object: it is rendered
    once in the later Review Package.  This object carries only the immutable
    binding necessary to prevent an assembly-unaware plan from being created.
    """

    plan: CurationPlan
    context_binding: ContextBinding
    schema: str = CONTEXT_BOUND_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if (
            type(self.plan) is not CurationPlan
            or not isinstance(self.context_binding, ContextBinding)
            or self.schema != CONTEXT_BOUND_PLAN_SCHEMA
        ):
            raise CanonicalCurationError(
                "Context-bound Plan seal is invalid",
                reason_code="PLAN_INVALID",
            )
        coverage = self._coverage_mapping()
        if (
            coverage.get("context_outcome") != self.context_binding.outcome
            or coverage.get("context_assembly_sha256")
            != self.context_binding.assembly_sha256
            or coverage.get("context_coverage_sha256")
            != self.context_binding.coverage_sha256
        ):
            raise CanonicalCurationError(
                "Context-bound Plan coverage differs from binding",
                reason_code="CONTEXT_STALE",
            )

    def _coverage_mapping(self) -> dict[str, object]:
        if len({name for name, _value in self.plan.coverage}) != len(self.plan.coverage):
            raise CanonicalCurationError(
                "Context-bound Plan coverage has duplicate keys",
                reason_code="PLAN_INVALID",
            )
        return dict(self.plan.coverage)

    @property
    def coverage(self) -> Tuple[Tuple[str, object], ...]:
        return self.plan.coverage

    @property
    def source_observations(self) -> Tuple[SourceObservation, ...]:
        return self.plan.source_observations

    @property
    def effects(self) -> Tuple[PlanEffect, ...]:
        return self.plan.effects

    @property
    def primary_workstream_id(self) -> str:
        return self.plan.primary_workstream_id

    @property
    def captured_lifecycle(self) -> str:
        return self.plan.captured_lifecycle

    @property
    def project_home(self) -> str:
        return self.plan.project_home

    @property
    def project_identity(self) -> Tuple[int, int, int, int]:
        return self.plan.project_identity

    @property
    def root_identity(self) -> Tuple[int, int, int, int]:
        return self.plan.root_identity

    @property
    def policy_sha256(self) -> str:
        return self.plan.policy_sha256

    @property
    def source_observation_sha256(self) -> str:
        return self.plan.source_observation_sha256

    @property
    def canonical_value(self) -> dict[str, object]:
        value = dict(self.plan.canonical_value)
        value["context_binding"] = self.context_binding.canonical_value
        value["schema"] = self.schema
        return value

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_value)

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes)

    def subset(
        self,
        selected_effect_ids: Tuple[str, ...],
        *,
        context_assembly: context_assembly.CompleteContextAssembly,
    ) -> "ContextBoundCurationPlan":
        """Create a selected Plan only after rechecking the same capability."""
        selected = self.plan.subset(selected_effect_ids)
        selected = replace(
            selected,
            source_observations=self.plan.source_observations,
            parent_plan_sha256=self.sha256,
        )
        return compile_curation_plan(
            selected,
            context_assembly=context_assembly,
        )


def _raise_context_stale(message: str) -> None:
    raise CanonicalCurationError(message, reason_code="CONTEXT_STALE")


def _verified_context_binding(
    plan: CurationPlan,
    context_assembly_capability: context_assembly.CompleteContextAssembly,
) -> ContextBinding:
    if type(plan) is not CurationPlan:
        raise CanonicalCurationError("Plan input is invalid", reason_code="PLAN_INVALID")
    if not isinstance(
        context_assembly_capability, context_assembly.CompleteContextAssembly
    ):
        raise CanonicalCurationError(
            "complete Context Assembly capability is required",
            reason_code="CONTEXT_INCOMPLETE",
        )

    assembly = context_assembly_capability.assembly
    assembly_sha256 = sha256_bytes(canonical_json_bytes(assembly.canonical_value))
    coverage_sha256 = sha256_bytes(canonical_json_bytes(assembly.coverage.canonical_value))
    if (
        assembly.outcome != context_assembly.COMPLETE
        or context_assembly_capability.assembly_sha256 != assembly_sha256
        or context_assembly_capability.coverage_sha256 != coverage_sha256
    ):
        _raise_context_stale("complete Context Assembly capability changed")
    if (
        plan.primary_workstream_id != assembly.workstream.id
        or plan.captured_lifecycle != assembly.workstream.lifecycle
        or plan.project_home != assembly.workstream.project_home
        or plan.policy_sha256 != assembly.policy_sha256
        or plan.root_identity != assembly.root_identity
        or plan.project_identity != assembly.project_identity
    ):
        _raise_context_stale("Plan authority differs from Context Assembly")

    current_sources = tuple(
        source for source in assembly.sources if source.mode == "CURRENT_LOCAL"
    )
    expected_by_observation_id = {}
    for source in current_sources:
        if source.source_id != source.observation_id:
            _raise_context_stale("current local Context source id is inconsistent")
        expected_by_observation_id[source.observation_id] = source
    actual_by_observation_id = {
        observation.observation_id: observation for observation in plan.source_observations
    }
    if set(actual_by_observation_id) != set(expected_by_observation_id):
        _raise_context_stale("Plan observations differ from current local Context")
    for observation_id, source in expected_by_observation_id.items():
        observation = actual_by_observation_id[observation_id]
        expected_identity = source.identity
        actual_identity = (
            observation.device,
            observation.inode,
            observation.owner,
            observation.mode,
            observation.link_count,
            observation.size,
            observation.modified_time_ns,
        )
        if (
            observation.relative_path != source.relative_path
            or actual_identity != expected_identity
            or observation.content_sha256 != source.content_sha256
            or observation.snapshot_sha256 != source.snapshot_sha256
        ):
            _raise_context_stale("Plan observation differs from current local Context")
    return ContextBinding(
        outcome=context_assembly.COMPLETE,
        assembly_sha256=assembly_sha256,
        coverage_sha256=coverage_sha256,
    )


def compile_curation_plan(
    plan: CurationPlan,
    *,
    context_assembly: context_assembly.CompleteContextAssembly,
) -> ContextBoundCurationPlan:
    """Seal one Plan to every current-local source in a complete assembly."""
    binding = _verified_context_binding(plan, context_assembly)
    coverage = dict(plan.coverage)
    if len(coverage) != len(plan.coverage):
        raise CanonicalCurationError(
            "Plan coverage has duplicate keys", reason_code="PLAN_INVALID"
        )
    expected_scalars = {
        "context_outcome": binding.outcome,
        "context_assembly_sha256": binding.assembly_sha256,
        "context_coverage_sha256": binding.coverage_sha256,
    }
    for key, value in expected_scalars.items():
        if key in coverage and coverage[key] != value:
            _raise_context_stale("Plan coverage Context binding is stale")
        coverage[key] = value
    return ContextBoundCurationPlan(
        plan=replace(plan, coverage=tuple(sorted(coverage.items()))),
        context_binding=binding,
    )


@dataclass(frozen=True)
class CurationDecision:
    action: str
    displayed_plan_sha256: str
    approved_plan: Optional[CurationPlan]
    selected_effect_ids: Tuple[str, ...]
    review_package_hashes: Tuple[Tuple[str, str], ...]
    reason: Optional[str]

    def __post_init__(self) -> None:
        if self.action not in DECISION_ACTIONS:
            raise CanonicalCurationError(
                "decision action is invalid",
                reason_code="DECISION_INVALID",
            )
        _require_hash(self.displayed_plan_sha256, "displayed plan hash")
        if type(self.selected_effect_ids) is not tuple:
            raise CanonicalCurationError(
                "decision membership is invalid",
                reason_code="DECISION_INVALID",
            )
        if self.action in {"APPROVE_ALL", "APPROVE_SELECTED"}:
            if type(self.approved_plan) is not CurationPlan or not self.selected_effect_ids:
                raise CanonicalCurationError(
                    "approval is incomplete",
                    reason_code="DECISION_INVALID",
                )
        elif self.approved_plan is not None or self.selected_effect_ids:
            raise CanonicalCurationError(
                "non-approval decision cannot carry effects",
                reason_code="DECISION_INVALID",
            )
        if self.approved_plan is not None:
            approved_membership = tuple(
                effect.effect_id for effect in self.approved_plan.effects
            )
            if self.selected_effect_ids != approved_membership:
                raise CanonicalCurationError(
                    "approval effect membership differs from approved Plan",
                    reason_code="DECISION_INVALID",
                )
            if self.action == "APPROVE_ALL":
                bound = self.approved_plan.sha256 == self.displayed_plan_sha256
            else:
                bound = (
                    self.approved_plan.parent_plan_sha256
                    == self.displayed_plan_sha256
                )
            if not bound:
                raise CanonicalCurationError(
                    "approved Plan is not bound to the displayed Plan",
                    reason_code="DECISION_INVALID",
                )
        if self.reason is not None:
            _public_text(self.reason, "decision reason", maximum=1024)
        expected_hash_names = {
            "html_sha256",
            "markdown_sha256",
            "meta_sha256",
            "semantic_sha256",
        }
        if (
            type(self.review_package_hashes) is not tuple
            or {name for name, _value in self.review_package_hashes}
            != expected_hash_names
        ):
            raise CanonicalCurationError(
                "review package binding is incomplete",
                reason_code="DECISION_INVALID",
            )
        for _name, value in self.review_package_hashes:
            _require_hash(value, "review package hash")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "action": self.action,
            "approved_plan_sha256": (
                None if self.approved_plan is None else self.approved_plan.sha256
            ),
            "displayed_plan_sha256": self.displayed_plan_sha256,
            "reason": self.reason,
            "review_package_hashes": dict(self.review_package_hashes),
            "selected_effect_ids": list(self.selected_effect_ids),
            "source_observation_sha256": (
                None
                if self.approved_plan is None
                else self.approved_plan.source_observation_sha256
            ),
        }

    @property
    def sha256(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_value))


def compile_decision(
    plan: CurationPlan,
    *,
    action: str,
    review_package_hashes: Mapping[str, str],
    selected_effect_ids: Tuple[str, ...] = (),
    reason: Optional[str] = None,
) -> CurationDecision:
    """Bind one exact human choice to the displayed Plan and Review Package."""

    if type(plan) is not CurationPlan or action not in DECISION_ACTIONS:
        raise CanonicalCurationError(
            "decision input is invalid",
            reason_code="DECISION_INVALID",
        )
    if type(review_package_hashes) is not dict:
        review_package_hashes = dict(review_package_hashes)
    if action == "APPROVE_ALL":
        if selected_effect_ids:
            raise CanonicalCurationError(
                "full approval cannot override effect membership",
                reason_code="DECISION_INVALID",
            )
        approved = plan
        membership = tuple(effect.effect_id for effect in plan.effects)
    elif action == "APPROVE_SELECTED":
        approved = plan.subset(selected_effect_ids)
        membership = tuple(effect.effect_id for effect in approved.effects)
    else:
        approved = None
        membership = ()
    return CurationDecision(
        action=action,
        displayed_plan_sha256=plan.sha256,
        approved_plan=approved,
        selected_effect_ids=membership,
        review_package_hashes=tuple(sorted(review_package_hashes.items())),
        reason=reason,
    )


def _decode_plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _decode_plain(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return [_decode_plain(item) for item in value]
    return value


def _decode_fields(value: object, expected: set[str], label: str) -> dict[str, object]:
    plain = _decode_plain(value)
    if type(plain) is not dict or set(plain) != expected:
        raise ValueError("%s shape is invalid" % label)
    return plain


def _decode_source_observation(value: object) -> SourceObservation:
    payload = _decode_fields(
        value,
        {
            "classification",
            "classification_evidence",
            "content_sha256",
            "content_summary",
            "device",
            "document_role",
            "inode",
            "lifecycle",
            "link_count",
            "mode",
            "modified_time_ns",
            "observation_id",
            "owner",
            "owner_id",
            "owner_kind",
            "relative_path",
            "size",
            "snapshot_sha256",
        },
        "source observation",
    )
    evidence = payload["classification_evidence"]
    if type(evidence) is not list:
        raise ValueError("source observation evidence is invalid")
    return SourceObservation(
        observation_id=payload["observation_id"],
        relative_path=payload["relative_path"],
        owner_kind=payload["owner_kind"],
        owner_id=payload["owner_id"],
        lifecycle=payload["lifecycle"],
        document_role=payload["document_role"],
        classification=payload["classification"],
        classification_evidence=tuple(evidence),
        content_summary=payload["content_summary"],
        device=payload["device"],
        inode=payload["inode"],
        owner=payload["owner"],
        mode=payload["mode"],
        link_count=payload["link_count"],
        size=payload["size"],
        modified_time_ns=payload["modified_time_ns"],
        content_sha256=payload["content_sha256"],
        snapshot_sha256=payload["snapshot_sha256"],
    )


def _decode_plan_effect(value: object) -> PlanEffect:
    payload = _decode_fields(
        value,
        {
            "action",
            "dependency_effect_ids",
            "effect_id",
            "expected_output_sha256",
            "input_observation_id",
            "output_path",
            "review_status",
            "risk_codes",
            "source_path",
        },
        "Plan effect",
    )
    dependencies = payload["dependency_effect_ids"]
    risk_codes = payload["risk_codes"]
    if type(dependencies) is not list or type(risk_codes) is not list:
        raise ValueError("Plan effect collections are invalid")
    return PlanEffect(
        effect_id=payload["effect_id"],
        action=payload["action"],
        input_observation_id=payload["input_observation_id"],
        source_path=payload["source_path"],
        output_path=payload["output_path"],
        expected_output_sha256=payload["expected_output_sha256"],
        risk_codes=tuple(risk_codes),
        review_status=payload["review_status"],
        dependency_effect_ids=tuple(dependencies),
    )


def _decode_spine_entry(value: object) -> SpineEntry:
    payload = _decode_fields(
        value,
        {
            "current_heading",
            "current_path",
            "proposed_heading",
            "proposed_path",
            "role",
            "status",
        },
        "spine entry",
    )
    return SpineEntry(**payload)


def _decode_curation_finding(value: object) -> CurationFinding:
    payload = _decode_fields(
        value,
        {"evidence", "finding_id", "finding_kind", "relative_path", "status"},
        "curation finding",
    )
    evidence = payload["evidence"]
    if type(evidence) is not list:
        raise ValueError("curation finding evidence is invalid")
    return CurationFinding(
        finding_id=payload["finding_id"],
        finding_kind=payload["finding_kind"],
        relative_path=payload["relative_path"],
        evidence=tuple(evidence),
        status=payload["status"],
    )


def _decode_context_plan_payload(value: object) -> tuple[dict[str, object], bytes | None]:
    if type(value) is bytes:
        try:
            payload = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Context-bound Curation Plan bytes are invalid") from exc
        return _decode_fields(payload, _CONTEXT_BOUND_PLAN_FIELDS, "Context-bound Curation Plan"), value
    return _decode_fields(value, _CONTEXT_BOUND_PLAN_FIELDS, "Context-bound Curation Plan"), None


def _is_canonical_json_value(value: object) -> bool:
    if value is None or type(value) in {bool, int, str}:
        return True
    if type(value) is list:
        return all(_is_canonical_json_value(item) for item in value)
    if type(value) is dict:
        return all(
            type(key) is str and key and _is_canonical_json_value(item)
            for key, item in value.items()
        )
    return False


def decode_context_bound_plan(value: object) -> ContextBoundCurationPlan:
    """Strictly decode one canonical V1 context-bound Curation Plan.

    Both the public byte form and an already-decoded mapping are accepted for
    sealed-package rereads.  Every accepted form round-trips to one literal
    canonical authority value.
    """

    payload, canonical_bytes = _decode_context_plan_payload(value)
    if payload["schema"] != CONTEXT_BOUND_PLAN_SCHEMA:
        raise ValueError("Context-bound Curation Plan schema is invalid")
    coverage = payload["coverage"]
    if (
        type(coverage) is not dict
        or any(
            type(key) is not str
            or not key
            or not _is_canonical_json_value(item)
            for key, item in coverage.items()
        )
    ):
        raise ValueError("Context-bound Curation Plan coverage is invalid")
    binding_value = _decode_fields(
        payload["context_binding"],
        {"assembly_sha256", "coverage_sha256", "outcome"},
        "Context-bound Curation Plan binding",
    )
    base_payload = dict(payload)
    base_payload.pop("context_binding")
    base_payload["schema"] = PLAN_SCHEMA
    collections = (
        "effects",
        "findings",
        "out_of_scope_paths",
        "project_identity",
        "root_identity",
        "source_observations",
        "spine",
        "unchanged_paths",
    )
    if any(type(base_payload[name]) is not list for name in collections):
        raise ValueError("Context-bound Curation Plan collection is invalid")
    plan = CurationPlan(
        primary_workstream_id=base_payload["primary_workstream_id"],
        captured_lifecycle=base_payload["captured_lifecycle"],
        project_home=base_payload["project_home"],
        project_identity=tuple(base_payload["project_identity"]),
        root_identity=tuple(base_payload["root_identity"]),
        policy_sha256=base_payload["policy_sha256"],
        source_observations=tuple(
            _decode_source_observation(item)
            for item in base_payload["source_observations"]
        ),
        effects=tuple(_decode_plan_effect(item) for item in base_payload["effects"]),
        spine=tuple(_decode_spine_entry(item) for item in base_payload["spine"]),
        findings=tuple(
            _decode_curation_finding(item) for item in base_payload["findings"]
        ),
        unchanged_paths=tuple(base_payload["unchanged_paths"]),
        out_of_scope_paths=tuple(base_payload["out_of_scope_paths"]),
        coverage=tuple(sorted(coverage.items())),
        parent_plan_sha256=base_payload["parent_plan_sha256"],
        schema=base_payload["schema"],
        spec_sha256=base_payload["spec_sha256"],
        cutoff_required=base_payload["cutoff_required"],
        irreversible_consequence=base_payload["irreversible_consequence"],
    )
    binding = ContextBinding(
        outcome=binding_value["outcome"],
        assembly_sha256=binding_value["assembly_sha256"],
        coverage_sha256=binding_value["coverage_sha256"],
    )
    context_bound = ContextBoundCurationPlan(plan=plan, context_binding=binding)
    if context_bound.canonical_value != payload or (
        canonical_bytes is not None and context_bound.canonical_bytes != canonical_bytes
    ):
        raise ValueError("Context-bound Curation Plan is not canonical")
    return context_bound


__all__ = [
    "APPROVED_REQUIREMENTS_SHA256",
    "COMMON_SPINE_ROLES",
    "CanonicalCurationError",
    "CONTEXT_BOUND_PLAN_SCHEMA",
    "ContextBinding",
    "ContextBoundCurationPlan",
    "CurationDecision",
    "CurationFinding",
    "CurationPlan",
    "PlanEffect",
    "SourceObservation",
    "SpineEntry",
    "compile_curation_plan",
    "compile_decision",
    "decode_context_bound_plan",
]
