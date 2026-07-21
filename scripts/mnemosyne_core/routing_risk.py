"""Deterministic placement-target and risk evaluation for Mnemosyne M2.

Target candidates and risk bands are review inputs only.  They are never user
decisions and never authorize filesystem effects.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from .canonical_json import canonical_json_bytes, sha256_bytes
from .policy import CompiledArchiveRoot, CompiledCategory, CompiledWorkstream


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TARGET_ACTIONS = frozenset(("move", "archive"))
_RISK_ACTIONS = frozenset(("keep", "link", "move", "archive", "defer", "exclude"))
_CONFIDENCE_BANDS = frozenset(("high", "medium", "low", "unknown"))
_FRESHNESS = frozenset(("fresh", "stale", "unknown"))


class RoutingRiskError(ValueError):
    """A target or risk input violates the deterministic review contract."""


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RoutingRiskError("%s is invalid" % label)
    return value


def _relative_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise RoutingRiskError("%s must be raw-relative" % label)
    if posixpath.normpath(value) != value or value in (".", "..") or value.startswith("../"):
        raise RoutingRiskError("%s must be canonical" % label)
    if any(ord(character) < 0x20 for character in value):
        raise RoutingRiskError("%s contains control characters" % label)
    return value


def _relative_from_root(absolute_path: str, raw_root: str) -> Optional[str]:
    if not isinstance(absolute_path, str) or not isinstance(raw_root, str):
        return None
    root = raw_root.rstrip("/")
    prefix = root + "/"
    if not root.startswith("/") or not absolute_path.startswith(prefix):
        return None
    try:
        return _relative_path(absolute_path[len(prefix) :], "policy target")
    except RoutingRiskError:
        return None


@dataclass(frozen=True)
class TargetRequest:
    source_path: str
    action: str
    primary_workstream: str
    document_role: str
    document_lifecycle: str
    sensitivity: str
    access_domain: str
    classification_confirmed: bool
    evidence_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "source_path", _relative_path(self.source_path, "source path")
        )
        if self.action not in _TARGET_ACTIONS:
            raise RoutingRiskError("target action is invalid")
        for label, value in (
            ("primary workstream", self.primary_workstream),
            ("document role", self.document_role),
            ("document lifecycle", self.document_lifecycle),
            ("sensitivity", self.sensitivity),
            ("access domain", self.access_domain),
        ):
            _identifier(value, label)
        if type(self.classification_confirmed) is not bool:
            raise RoutingRiskError("classification_confirmed must be boolean")
        if type(self.evidence_ids) is not tuple or tuple(
            sorted(set(self.evidence_ids))
        ) != self.evidence_ids:
            raise RoutingRiskError("evidence ids must be unique and sorted")
        for evidence_id in self.evidence_ids:
            _identifier(evidence_id, "evidence id")

    def to_dict(self) -> dict:
        return {
            "access_domain": self.access_domain,
            "action": self.action,
            "classification_confirmed": self.classification_confirmed,
            "document_lifecycle": self.document_lifecycle,
            "document_role": self.document_role,
            "evidence_ids": list(self.evidence_ids),
            "primary_workstream": self.primary_workstream,
            "sensitivity": self.sensitivity,
            "source_path": self.source_path,
        }


@dataclass(frozen=True)
class TargetCandidate:
    resolver_version: str
    input_sha256: str
    status: str
    target_path: Optional[str]
    matched_rule_id: Optional[str]
    matched_rule_sha256: Optional[str]
    evidence_ids: Tuple[str, ...]
    uncertainty: Optional[str]
    rename_from: str
    rename_to: Optional[str]


class PlacementTargetResolver:
    def __init__(self, resolver_version: str) -> None:
        self.resolver_version = _identifier(resolver_version, "resolver version")

    def resolve(
        self,
        request: TargetRequest,
        *,
        raw_root: str,
        workstreams: Sequence[CompiledWorkstream],
        categories: Sequence[CompiledCategory],
        archive_roots: Sequence[CompiledArchiveRoot],
    ) -> TargetCandidate:
        if type(request) is not TargetRequest:
            raise TypeError("request must be TargetRequest")
        input_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "request": request.to_dict(),
                    "resolver_version": self.resolver_version,
                }
            )
        )
        if not request.classification_confirmed:
            return TargetCandidate(
                resolver_version=self.resolver_version,
                input_sha256=input_sha256,
                status="blocked",
                target_path=None,
                matched_rule_id=None,
                matched_rule_sha256=None,
                evidence_ids=request.evidence_ids,
                uncertainty="classification-not-confirmed",
                rename_from=posixpath.basename(request.source_path),
                rename_to=None,
            )

        matching_workstreams = [
            workstream
            for workstream in workstreams
            if type(workstream) is CompiledWorkstream
            and workstream.id == request.primary_workstream
        ]
        if len(matching_workstreams) != 1:
            return TargetCandidate(
                self.resolver_version,
                input_sha256,
                "blocked",
                None,
                None,
                None,
                request.evidence_ids,
                "workstream-route-missing-or-ambiguous",
                posixpath.basename(request.source_path),
                None,
            )

        if request.action == "move":
            matching_rules = [
                category
                for category in categories
                if type(category) is CompiledCategory
                and category.id == request.document_role
                and _relative_from_root(category.target, raw_root) is not None
            ]
            rule_kind = "category"
        else:
            matching_rules = [
                archive_root
                for archive_root in archive_roots
                if type(archive_root) is CompiledArchiveRoot
                and archive_root.workstream_id == request.primary_workstream
                and archive_root.sensitivity == request.sensitivity
                and archive_root.access_domain == request.access_domain
                and _relative_from_root(archive_root.root, raw_root) is not None
            ]
            rule_kind = "archive-root"
        if len(matching_rules) != 1:
            return TargetCandidate(
                self.resolver_version,
                input_sha256,
                "blocked",
                None,
                None,
                None,
                request.evidence_ids,
                "target-rule-missing-or-ambiguous",
                posixpath.basename(request.source_path),
                None,
            )

        rule = matching_rules[0]
        if request.action == "move":
            target_root = rule.target
            rule_id = "category:%s" % rule.id
            rule_payload = {
                "id": rule.id,
                "patterns": list(rule.patterns),
                "target": rule.target,
            }
        else:
            target_root = rule.root
            rule_id = "archive-root:%s:%s:%s" % (
                rule.workstream_id,
                rule.sensitivity,
                rule.access_domain,
            )
            rule_payload = {
                "access_domain": rule.access_domain,
                "root": rule.root,
                "sensitivity": rule.sensitivity,
                "workstream_id": rule.workstream_id,
            }
        relative_root = _relative_from_root(target_root, raw_root)
        assert relative_root is not None
        basename = posixpath.basename(request.source_path)
        target_path = _relative_path(
            posixpath.join(relative_root, basename), "resolved target"
        )
        rule_sha256 = sha256_bytes(
            canonical_json_bytes({"kind": rule_kind, "rule": rule_payload})
        )
        input_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "request": request.to_dict(),
                    "resolver_version": self.resolver_version,
                    "rule_id": rule_id,
                    "rule_sha256": rule_sha256,
                }
            )
        )
        return TargetCandidate(
            resolver_version=self.resolver_version,
            input_sha256=input_sha256,
            status="resolved",
            target_path=target_path,
            matched_rule_id=rule_id,
            matched_rule_sha256=rule_sha256,
            evidence_ids=request.evidence_ids,
            uncertainty=None,
            rename_from=basename,
            rename_to=posixpath.basename(target_path),
        )


@dataclass(frozen=True)
class RiskInput:
    action: str
    scope_class: str
    sensitivity: str
    access_domain: str
    confidence_band: str
    context_freshness: str
    canonical_conflict: bool
    reference_complete: bool
    descendant_count: int
    descendant_mixed: bool
    target_proven: bool
    archive_domain_safe: bool
    frozen: bool
    lifecycle_override_present: bool
    opaque: bool
    private: bool
    ambiguity: bool
    ancestor_descendant_overlap: bool
    named_output_conflict: bool
    reversal_capability_proven: bool
    inverse_plan_complete: bool
    recovery_paths_complete: bool
    provenance_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        if self.action not in _RISK_ACTIONS:
            raise RoutingRiskError("risk action is invalid")
        for label, value in (
            ("scope class", self.scope_class),
            ("sensitivity", self.sensitivity),
            ("access domain", self.access_domain),
        ):
            _identifier(value, label)
        if self.confidence_band not in _CONFIDENCE_BANDS:
            raise RoutingRiskError("classification confidence is invalid")
        if self.context_freshness not in _FRESHNESS:
            raise RoutingRiskError("context freshness is invalid")
        for name in (
            "canonical_conflict",
            "reference_complete",
            "descendant_mixed",
            "target_proven",
            "archive_domain_safe",
            "frozen",
            "lifecycle_override_present",
            "opaque",
            "private",
            "ambiguity",
            "ancestor_descendant_overlap",
            "named_output_conflict",
            "reversal_capability_proven",
            "inverse_plan_complete",
            "recovery_paths_complete",
        ):
            if type(getattr(self, name)) is not bool:
                raise RoutingRiskError("%s must be boolean" % name)
        if type(self.descendant_count) is not int or self.descendant_count < 0:
            raise RoutingRiskError("descendant count must be non-negative")
        if type(self.provenance_ids) is not tuple or tuple(
            sorted(set(self.provenance_ids))
        ) != self.provenance_ids:
            raise RoutingRiskError("risk provenance ids must be unique and sorted")
        for provenance_id in self.provenance_ids:
            _identifier(provenance_id, "risk provenance id")

    def to_dict(self) -> dict:
        return {
            name: (
                list(value) if name == "provenance_ids" else value
            )
            for name, value in sorted(self.__dict__.items())
        }


@dataclass(frozen=True)
class RiskResult:
    evaluator_version: str
    input_sha256: str
    band: str
    hard_escalators: Tuple[str, ...]


class RiskEvaluator:
    def __init__(self, evaluator_version: str) -> None:
        self.evaluator_version = _identifier(
            evaluator_version, "risk evaluator version"
        )

    def evaluate(self, value: RiskInput) -> RiskResult:
        if type(value) is not RiskInput:
            raise TypeError("value must be RiskInput")
        input_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "evaluator_version": self.evaluator_version,
                    "input": value.to_dict(),
                }
            )
        )
        escalators = []
        if value.opaque:
            escalators.append("opaque-scope")
        if value.private and not value.lifecycle_override_present:
            escalators.append("private-without-override")
        if value.frozen and not value.lifecycle_override_present:
            escalators.append("frozen-without-override")
        if value.ambiguity:
            escalators.append("classification-ambiguity")
        if not value.reference_complete:
            escalators.append("reference-incomplete")
        if value.ancestor_descendant_overlap:
            escalators.append("ancestor-descendant-overlap")
        if not value.target_proven:
            escalators.append("target-unproven")
        if not value.archive_domain_safe:
            escalators.append("archive-domain-unsafe")
        if not value.reversal_capability_proven:
            escalators.append("reversal-capability-unproven")
        if not value.inverse_plan_complete:
            escalators.append("inverse-plan-incomplete")
        if not value.recovery_paths_complete:
            escalators.append("recovery-paths-incomplete")
        if escalators:
            return RiskResult(
                self.evaluator_version,
                input_sha256,
                "blocked",
                tuple(escalators),
            )
        low = (
            value.confidence_band == "high"
            and value.context_freshness == "fresh"
            and not value.canonical_conflict
            and value.reference_complete
            and value.descendant_count <= 20
            and not value.descendant_mixed
            and value.target_proven
            and value.archive_domain_safe
            and not value.frozen
            and not value.opaque
            and not value.private
            and not value.ambiguity
            and not value.ancestor_descendant_overlap
            and not value.named_output_conflict
            and value.reversal_capability_proven
            and value.inverse_plan_complete
            and value.recovery_paths_complete
        )
        if low:
            return RiskResult(
                self.evaluator_version,
                input_sha256,
                "low",
                (),
            )
        high = (
            value.descendant_mixed
            or value.canonical_conflict
            or value.named_output_conflict
            or (value.private and value.lifecycle_override_present)
            or (value.frozen and value.lifecycle_override_present)
        )
        return RiskResult(
            self.evaluator_version,
            input_sha256,
            "high" if high else "medium",
            (),
        )


__all__ = [
    "PlacementTargetResolver",
    "RoutingRiskError",
    "RiskEvaluator",
    "RiskInput",
    "RiskResult",
    "TargetCandidate",
    "TargetRequest",
]
