"""Exact Stage-A Plan admission and reversible multi-file transaction."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Callable

from .. import canonical_curation as curation_domain
from .. import canonical_curation_review, operation_contract, safety
from ..canonical_json import canonical_json_bytes, sha256_bytes
from . import AuthorityRuntimeError, CanonicalCurationFence
from . import _durable_snapshot, librarian_snapshot


_CONTROL_PARTS = ("_registry", "curation", "canonical-curation-v1")
_TRANSACTION_PARTS = _CONTROL_PARTS + ("transactions",)
_STAGING_PARTS = _CONTROL_PARTS + ("staging",)
_PLAN_DIRECTORY = re.compile(r"p-([0-9a-f]{64})\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EFFECTS = 64
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_TRANSACTIONS = 256
_MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_INTENT_SCHEMA = "mnemosyne-canonical-curation-intent-v1"
_RESULT_SCHEMA = "mnemosyne-canonical-curation-result-v1"
_CONTEXT_DECISION_FIELDS = {
    "action",
    "approved_plan_sha256",
    "displayed_plan_sha256",
    "reason",
    "review_package_hashes",
    "selected_effect_ids",
    "source_observation_sha256",
}
_TransactionPlan = (
    curation_domain.CurationPlan | curation_domain.ContextBoundCurationPlan
)


class _TransactionError(AuthorityRuntimeError):
    pass


class CurationRecoveryRequired(AuthorityRuntimeError):
    """The transaction cannot prove either final or exact rolled-back state."""


def _run_checkpoint(_point: str) -> None:
    """Private deterministic fault-injection seam used only by tests."""


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if type(value) in {tuple, list}:
        return [_plain(item) for item in value]
    return value


def _fields(value: object, expected: set[str], label: str) -> dict[str, object]:
    plain = _plain(value)
    if type(plain) is not dict or set(plain) != expected:
        raise ValueError("%s shape is invalid" % label)
    return plain


def _decode_observation(value: object) -> curation_domain.SourceObservation:
    payload = _fields(
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
    return curation_domain.SourceObservation(
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


def _decode_effect(value: object) -> curation_domain.PlanEffect:
    payload = _fields(
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
    return curation_domain.PlanEffect(
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


def _decode_spine(value: object) -> curation_domain.SpineEntry:
    payload = _fields(
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
    return curation_domain.SpineEntry(**payload)


def _decode_finding(value: object) -> curation_domain.CurationFinding:
    payload = _fields(
        value,
        {"evidence", "finding_id", "finding_kind", "relative_path", "status"},
        "curation Finding",
    )
    evidence = payload["evidence"]
    if type(evidence) is not list:
        raise ValueError("curation Finding evidence is invalid")
    return curation_domain.CurationFinding(
        finding_id=payload["finding_id"],
        finding_kind=payload["finding_kind"],
        relative_path=payload["relative_path"],
        evidence=tuple(evidence),
        status=payload["status"],
    )


def decode_plan(value: object) -> curation_domain.CurationPlan:
    """Strictly reconstruct one canonical Stage-A Plan from request JSON."""

    payload = _fields(
        value,
        {
            "captured_lifecycle",
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
        },
        "Curation Plan",
    )
    for name in (
        "effects",
        "findings",
        "out_of_scope_paths",
        "project_identity",
        "root_identity",
        "source_observations",
        "spine",
        "unchanged_paths",
    ):
        if type(payload[name]) is not list:
            raise ValueError("Curation Plan collection is invalid: %s" % name)
    if type(payload["coverage"]) is not dict:
        raise ValueError("Curation Plan coverage is invalid")
    plan = curation_domain.CurationPlan(
        primary_workstream_id=payload["primary_workstream_id"],
        captured_lifecycle=payload["captured_lifecycle"],
        project_home=payload["project_home"],
        project_identity=tuple(payload["project_identity"]),
        root_identity=tuple(payload["root_identity"]),
        policy_sha256=payload["policy_sha256"],
        source_observations=tuple(
            _decode_observation(item) for item in payload["source_observations"]
        ),
        effects=tuple(_decode_effect(item) for item in payload["effects"]),
        spine=tuple(_decode_spine(item) for item in payload["spine"]),
        findings=tuple(_decode_finding(item) for item in payload["findings"]),
        unchanged_paths=tuple(payload["unchanged_paths"]),
        out_of_scope_paths=tuple(payload["out_of_scope_paths"]),
        coverage=tuple(sorted(payload["coverage"].items())),
        parent_plan_sha256=payload["parent_plan_sha256"],
        schema=payload["schema"],
        spec_sha256=payload["spec_sha256"],
        cutoff_required=payload["cutoff_required"],
        irreversible_consequence=payload["irreversible_consequence"],
    )
    if plan.canonical_value != payload:
        raise ValueError("Curation Plan is not canonical")
    return plan


def decode_context_bound_plan(
    value: object,
) -> curation_domain.ContextBoundCurationPlan:
    """Delegate strict V1 context-bound decoding to its immutable domain."""

    return curation_domain.decode_context_bound_plan(value)


def _validate_decision(
    value: object,
    plan: curation_domain.CurationPlan,
) -> tuple[dict[str, object], str]:
    decision = _fields(
        value,
        {
            "action",
            "approved_plan_sha256",
            "displayed_plan_sha256",
            "reason",
            "review_package_hashes",
            "selected_effect_ids",
            "source_observation_sha256",
        },
        "Curation decision",
    )
    review_hashes = decision["review_package_hashes"]
    selected = decision["selected_effect_ids"]
    expected_membership = [effect.effect_id for effect in plan.effects]
    expected_displayed = (
        plan.sha256
        if decision["action"] == "APPROVE_ALL"
        else plan.parent_plan_sha256
    )
    if (
        decision["action"] not in {"APPROVE_ALL", "APPROVE_SELECTED"}
        or type(selected) is not list
        or selected != expected_membership
        or not selected
        or decision["approved_plan_sha256"] != plan.sha256
        or decision["displayed_plan_sha256"] != expected_displayed
        or decision["source_observation_sha256"]
        != plan.source_observation_sha256
        or type(review_hashes) is not dict
        or set(review_hashes)
        != {
            "html_sha256",
            "markdown_sha256",
            "meta_sha256",
            "semantic_sha256",
        }
        or any(type(item) is not str or _HASH.fullmatch(item) is None for item in review_hashes.values())
        or (decision["reason"] is not None and type(decision["reason"]) is not str)
    ):
        raise ValueError("Curation decision does not approve the exact Plan")
    return decision, sha256_bytes(canonical_json_bytes(decision))


def _review_package_path(value: object) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("Review Package directory is invalid")
    path = Path(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ValueError("Review Package directory is invalid")
    return path


def _require_review_package_binding(
    *,
    root: Path,
    plan: curation_domain.CurationPlan,
    decision: dict[str, object],
    directory: Path,
) -> None:
    try:
        directory.relative_to(root)
    except ValueError:
        pass
    else:
        raise CanonicalCurationFence(
            "Review Package overlaps the authority root",
            reason_code="STALE",
        )
    try:
        (
            hashes,
            displayed_plan_value,
        ) = canonical_curation_review.validate_review_directory_with_plan(
            directory,
            expected_plan_sha256=decision["displayed_plan_sha256"],
        )
    except (TypeError, ValueError, OSError) as exc:
        raise CanonicalCurationFence(
            "sealed Review Package is unavailable or changed",
            reason_code="STALE",
        ) from exc
    actual = {
        "html_sha256": hashes.html_sha256,
        "markdown_sha256": hashes.markdown_sha256,
        "meta_sha256": hashes.meta_sha256,
        "semantic_sha256": hashes.semantic_sha256,
    }
    if actual != decision["review_package_hashes"]:
        raise CanonicalCurationFence(
            "sealed Review Package does not match the approval",
            reason_code="STALE",
        )
    try:
        displayed_plan = decode_plan(displayed_plan_value)
        expected_plan = (
            displayed_plan
            if decision["action"] == "APPROVE_ALL"
            else displayed_plan.subset(tuple(decision["selected_effect_ids"]))
        )
    except (TypeError, ValueError, curation_domain.CanonicalCurationError) as exc:
        raise CanonicalCurationFence(
            "sealed Review Package cannot reconstruct the approved Plan",
            reason_code="STALE",
        ) from exc
    if expected_plan.canonical_value != plan.canonical_value:
        raise CanonicalCurationFence(
            "approved Plan is not the exact displayed Plan selection",
            reason_code="STALE",
        )
    if hashes.source_snapshot_sha256 != displayed_plan.source_observation_sha256:
        raise CanonicalCurationFence(
            "sealed Review Package source observation changed",
            reason_code="STALE",
        )


def _require_context_review_package_binding(
    *,
    root: Path,
    plan: curation_domain.ContextBoundCurationPlan,
    decision: dict[str, object],
    directory: Path,
) -> object:
    """Require the exact sealed V3 Plan and return its Context Assembly."""

    try:
        directory.relative_to(root)
    except ValueError:
        pass
    else:
        raise CanonicalCurationFence(
            "Review Package overlaps the authority root",
            reason_code="STALE",
        )
    try:
        hashes, displayed_plan_value, assembly = (
            canonical_curation_review.validate_context_bound_review_directory(
                directory,
                expected_plan_sha256=decision["displayed_plan_sha256"],
            )
        )
        displayed_plan = decode_context_bound_plan(displayed_plan_value)
    except (TypeError, ValueError, OSError) as exc:
        raise CanonicalCurationFence(
            "sealed Context Review Package is unavailable or changed",
            reason_code="STALE",
        ) from exc
    actual = {
        "html_sha256": hashes.html_sha256,
        "markdown_sha256": hashes.markdown_sha256,
        "meta_sha256": hashes.meta_sha256,
        "semantic_sha256": hashes.semantic_sha256,
    }
    if (
        actual != decision["review_package_hashes"]
        or displayed_plan.canonical_value != plan.canonical_value
        or assembly.sha256 != plan.context_binding.assembly_sha256
        or assembly.coverage_sha256 != plan.context_binding.coverage_sha256
        or assembly.outcome != plan.context_binding.outcome
        or assembly.workstream.id != plan.primary_workstream_id
        or hashes.source_snapshot_sha256 != plan.source_observation_sha256
    ):
        raise CanonicalCurationFence(
            "sealed Context Review Package does not match the approval",
            reason_code="STALE",
        )
    return assembly


def _context_scan_bounds(
    plan: curation_domain.ContextBoundCurationPlan,
) -> tuple[int, int, int]:
    bounds = dict(plan.coverage).get("bounds")
    if (
        type(bounds) is not dict
        or set(bounds)
        != {"max_depth", "max_hint_bytes", "max_items", "max_source_bytes"}
        or type(bounds["max_items"]) is not int
        or type(bounds["max_depth"]) is not int
        or type(bounds["max_hint_bytes"]) is not int
        or type(bounds["max_source_bytes"]) is not int
    ):
        raise CanonicalCurationFence(
            "Context-bound Curation Plan scan bounds are stale",
            reason_code="STALE",
        )
    return bounds["max_items"], bounds["max_depth"], bounds["max_hint_bytes"]


def _require_fresh_context(
    *,
    root: Path,
    compiled_policy: object,
    plan: curation_domain.ContextBoundCurationPlan,
    sealed_assembly: object,
) -> None:
    """Recapture the full Workstream before a new immutable intent exists."""

    from .. import workstream_curation

    max_items, max_depth, max_hint_bytes = _context_scan_bounds(plan)
    try:
        current_policy, registry_sha256 = workstream_curation._read_compiled_policy(
            root
        )
        if (
            getattr(current_policy, "full_hash", None)
            != getattr(compiled_policy, "full_hash", None)
        ):
            raise workstream_curation.WorkstreamCurationError(
                "Context policy changed",
                reason_code="POLICY_CHANGED",
            )
        captured = workstream_curation._capture_context_curation(
            root=root,
            compiled_policy=current_policy,
            registry_sha256=registry_sha256,
            workstream_ref=plan.primary_workstream_id,
            max_items=max_items,
            max_depth=max_depth,
            max_hint_bytes=max_hint_bytes,
        )
    except Exception as exc:
        raise CanonicalCurationFence(
            "current Context cannot reproduce the approved Plan",
            reason_code="STALE",
        ) from exc
    if (
        captured.complete_context is None
        or captured.context_plan is None
        or captured.assembly.canonical_value
        != getattr(sealed_assembly, "canonical_value", None)
    ):
        raise CanonicalCurationFence(
            "current Context differs from the approved Context",
            reason_code="STALE",
        )
    parent_plan_sha256 = plan.plan.parent_plan_sha256
    if parent_plan_sha256 is None:
        current_plan = captured.context_plan
    else:
        if captured.context_plan.sha256 != parent_plan_sha256:
            raise CanonicalCurationFence(
                "current full Context Plan differs from the approved parent",
                reason_code="STALE",
            )
        try:
            current_plan = captured.context_plan.subset(
                tuple(effect.effect_id for effect in plan.effects),
                context_assembly=captured.complete_context,
            )
        except curation_domain.CanonicalCurationError as exc:
            raise CanonicalCurationFence(
                "current Context cannot reproduce the approved subset",
                reason_code="STALE",
            ) from exc
    if current_plan.canonical_value != plan.canonical_value:
        raise CanonicalCurationFence(
            "current Context Plan differs from the approved Plan",
            reason_code="STALE",
        )


def _validated_request(
    request: object,
) -> tuple[curation_domain.CurationPlan, dict[str, object], str]:
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "curation.plan_apply"
        or request.action is not operation_contract.LifecycleAction.APPLY
        or request.claim_mode is not operation_contract.ClaimMode.CURRENT
        or request.requested_authority is not operation_contract.AuthorityMode.WRITE
        or set(request.scope) != {"plan_sha256", "workstream_id"}
        or set(request.bounds) != {"max_effects", "max_total_bytes"}
        or set(request.payload)
        != {"decision", "plan", "review_package_directory"}
        or request.approval_artifact is not None
        or request.prerequisite_artifacts
    ):
        raise ValueError("Curation Plan apply request is invalid")
    max_effects = request.bounds["max_effects"]
    max_total_bytes = request.bounds["max_total_bytes"]
    if (
        type(max_effects) is not int
        or not 1 <= max_effects <= _MAX_EFFECTS
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _MAX_TOTAL_BYTES
    ):
        raise ValueError("Curation Plan apply bounds are invalid")
    plan = decode_plan(request.payload["plan"])
    _review_package_path(request.payload["review_package_directory"])
    decision, decision_sha256 = _validate_decision(
        request.payload["decision"],
        plan,
    )
    if (
        request.scope["plan_sha256"] != plan.sha256
        or request.scope["workstream_id"] != plan.primary_workstream_id
        or len(plan.effects) > max_effects
        or sum(observation.size for observation in plan.source_observations)
        > max_total_bytes
    ):
        raise ValueError("Curation Plan apply scope or bounds mismatch")
    return plan, decision, decision_sha256


def _validate_context_decision(
    value: object,
    plan: curation_domain.ContextBoundCurationPlan,
) -> tuple[dict[str, object], str]:
    decision = _fields(
        value,
        _CONTEXT_DECISION_FIELDS,
        "Context-bound Curation decision",
    )
    expected_effect_ids = [effect.effect_id for effect in plan.effects]
    review_hashes = decision["review_package_hashes"]
    if (
        decision["action"] != "APPROVE_ALL"
        or type(decision["selected_effect_ids"]) is not list
        or decision["selected_effect_ids"] != expected_effect_ids
        or not expected_effect_ids
        or decision["approved_plan_sha256"] != plan.sha256
        or decision["displayed_plan_sha256"] != plan.sha256
        or decision["source_observation_sha256"] != plan.source_observation_sha256
        or type(review_hashes) is not dict
        or set(review_hashes)
        != {
            "html_sha256",
            "markdown_sha256",
            "meta_sha256",
            "semantic_sha256",
        }
        or any(
            type(item) is not str or _HASH.fullmatch(item) is None
            for item in review_hashes.values()
        )
        or (decision["reason"] is not None and type(decision["reason"]) is not str)
    ):
        raise ValueError("Context-bound Curation decision is invalid")
    return decision, sha256_bytes(canonical_json_bytes(decision))


def _validated_context_request(
    request: object,
    plan: curation_domain.ContextBoundCurationPlan,
) -> tuple[dict[str, object], str, int, Path]:
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "curation.plan_apply"
        or request.action is not operation_contract.LifecycleAction.APPLY
        or request.claim_mode is not operation_contract.ClaimMode.CURRENT
        or request.requested_authority is not operation_contract.AuthorityMode.WRITE
        or set(request.scope) != {"plan_sha256", "workstream_id"}
        or set(request.bounds) != {"max_effects", "max_total_bytes"}
        or set(request.payload)
        != {"decision", "plan", "review_package_directory"}
        or request.approval_artifact is not None
        or request.prerequisite_artifacts
    ):
        raise ValueError("Context-bound Curation Plan apply request is invalid")
    max_effects = request.bounds["max_effects"]
    max_total_bytes = request.bounds["max_total_bytes"]
    if (
        type(max_effects) is not int
        or max_effects != len(plan.effects)
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _MAX_TOTAL_BYTES
        or request.scope["plan_sha256"] != plan.sha256
        or request.scope["workstream_id"] != plan.primary_workstream_id
        or not plan.effects
        or bool(plan.plan.findings)
        or any(effect.action not in {"move", "rename"} for effect in plan.effects)
        or sum(observation.size for observation in plan.source_observations)
        > max_total_bytes
    ):
        raise ValueError("Context-bound Curation Plan scope or bounds mismatch")
    review_package_directory = _review_package_path(
        request.payload["review_package_directory"]
    )
    decision, decision_sha256 = _validate_context_decision(
        request.payload["decision"],
        plan,
    )
    return decision, decision_sha256, max_total_bytes, review_package_directory


def decode_admitted_input(
    value: object,
) -> tuple[
    curation_domain.CurationPlan,
    dict[str, object],
    str,
    int,
    Path,
]:
    """Revalidate the exact immutable handler input inside the profile wrapper."""

    if not isinstance(value, Mapping):
        raise ValueError("Curation admitted input is invalid")
    plain = _plain(value)
    if (
        type(plain) is not dict
        or set(plain)
        != {
            "action",
            "approval_artifact",
            "bounds",
            "operation_kind",
            "payload",
            "prerequisite_artifacts",
            "scope",
        }
        or plain["operation_kind"] != "curation.plan_apply"
        or plain["action"] is not operation_contract.LifecycleAction.APPLY
        or plain["approval_artifact"] is not None
        or plain["prerequisite_artifacts"] != []
        or set(plain["payload"])
        != {"decision", "plan", "review_package_directory"}
        or set(plain["bounds"]) != {"max_effects", "max_total_bytes"}
        or set(plain["scope"]) != {"plan_sha256", "workstream_id"}
    ):
        raise ValueError("Curation admitted input is invalid")
    max_effects = plain["bounds"]["max_effects"]
    max_total_bytes = plain["bounds"]["max_total_bytes"]
    plan = decode_plan(plain["payload"]["plan"])
    decision, decision_sha256 = _validate_decision(
        plain["payload"]["decision"],
        plan,
    )
    review_package_directory = _review_package_path(
        plain["payload"]["review_package_directory"]
    )
    if (
        type(max_effects) is not int
        or not 1 <= max_effects <= _MAX_EFFECTS
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _MAX_TOTAL_BYTES
        or len(plan.effects) > max_effects
        or sum(observation.size for observation in plan.source_observations)
        > max_total_bytes
        or plain["scope"]["plan_sha256"] != plan.sha256
        or plain["scope"]["workstream_id"] != plan.primary_workstream_id
    ):
        raise ValueError("Curation admitted input scope or bounds mismatch")
    return (
        plan,
        decision,
        decision_sha256,
        max_total_bytes,
        review_package_directory,
    )


def decode_context_admitted_input(
    value: object,
) -> tuple[
    curation_domain.ContextBoundCurationPlan,
    dict[str, object],
    str,
    int,
    Path,
]:
    """Revalidate one admitted Context request without legacy fallback."""

    if not isinstance(value, Mapping):
        raise ValueError("Context-bound Curation admitted input is invalid")
    plain = _plain(value)
    if (
        type(plain) is not dict
        or set(plain)
        != {
            "action",
            "approval_artifact",
            "bounds",
            "operation_kind",
            "payload",
            "prerequisite_artifacts",
            "scope",
        }
        or plain["operation_kind"] != "curation.plan_apply"
        or plain["action"] is not operation_contract.LifecycleAction.APPLY
        or plain["approval_artifact"] is not None
        or plain["prerequisite_artifacts"] != []
        or set(plain["payload"])
        != {"decision", "plan", "review_package_directory"}
        or set(plain["bounds"]) != {"max_effects", "max_total_bytes"}
        or set(plain["scope"]) != {"plan_sha256", "workstream_id"}
    ):
        raise ValueError("Context-bound Curation admitted input is invalid")
    max_effects = plain["bounds"]["max_effects"]
    max_total_bytes = plain["bounds"]["max_total_bytes"]
    plan = decode_context_bound_plan(plain["payload"]["plan"])
    decision, decision_sha256 = _validate_context_decision(
        plain["payload"]["decision"],
        plan,
    )
    review_package_directory = _review_package_path(
        plain["payload"]["review_package_directory"]
    )
    if (
        type(max_effects) is not int
        or max_effects != len(plan.effects)
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _MAX_TOTAL_BYTES
        or not plan.effects
        or bool(plan.plan.findings)
        or any(effect.action not in {"move", "rename"} for effect in plan.effects)
        or sum(observation.size for observation in plan.source_observations)
        > max_total_bytes
        or plain["scope"]["plan_sha256"] != plan.sha256
        or plain["scope"]["workstream_id"] != plan.primary_workstream_id
    ):
        raise ValueError("Context-bound Curation admitted input scope or bounds mismatch")
    return (
        plan,
        decision,
        decision_sha256,
        max_total_bytes,
        review_package_directory,
    )


def validate_plan_apply_request(request: object) -> None:
    plan_value = (
        request.payload.get("plan")
        if type(request) is operation_contract.OperationRequest
        and isinstance(request.payload, Mapping)
        else None
    )
    if isinstance(plan_value, Mapping) and plan_value.get("schema") == "mnemosyne-canonical-curation-plan-v2":
        from . import canonical_curation_m3

        canonical_curation_m3.validate_plan_apply_request(request)
        return
    if (
        isinstance(plan_value, Mapping)
        and plan_value.get("schema") == curation_domain.CONTEXT_BOUND_PLAN_SCHEMA
    ):
        plan = decode_context_bound_plan(plan_value)
        _validated_context_request(request, plan)
        return
    _validated_request(request)


def validate_plan_apply_result(outcome: object) -> None:
    result = outcome.result if type(outcome) is operation_contract.OperationOutcome else None
    if type(result) is dict and result.get("schema") == "mnemosyne-canonical-curation-result-v2":
        from . import canonical_curation_m3

        canonical_curation_m3.validate_plan_apply_result(outcome)
        return
    if (
        type(outcome) is not operation_contract.OperationOutcome
        or outcome.outcome_kind != "completed"
        or type(result) is not dict
        or set(result)
        != {
            "decision_sha256",
            "effect_count",
            "effects",
            "equality",
            "plan_sha256",
            "reason_code",
            "request_sha256",
            "schema",
            "status",
            "workstream_id",
        }
        or result["schema"] != _RESULT_SCHEMA
        or result["status"] != "FINALIZED"
        or result["reason_code"] is not None
        or type(result["effects"]) is not list
        or not result["effects"]
        or result["effect_count"] != len(result["effects"])
        or result["equality"]
        != {
            "content_hashes_match": True,
            "effect_membership_complete": True,
            "staging_empty": True,
        }
        or any(
            type(result[name]) is not str or _HASH.fullmatch(result[name]) is None
            for name in ("decision_sha256", "plan_sha256", "request_sha256")
        )
        or type(result["workstream_id"]) is not str
        or re.fullmatch(r"[a-z][a-z0-9-]{1,95}", result["workstream_id"])
        is None
    ):
        raise ValueError("Curation Plan apply result is invalid")
    effect_ids = []
    sources = []
    targets = []
    for effect in result["effects"]:
        if (
            type(effect) is not dict
            or set(effect)
            != {
                "content_sha256",
                "effect_id",
                "output_path",
                "source_path",
            }
            or type(effect["content_sha256"]) is not str
            or _HASH.fullmatch(effect["content_sha256"]) is None
        ):
            raise ValueError("Curation Plan apply result effect is invalid")
        try:
            curation_domain._require_identifier(effect["effect_id"], "effect id")
            curation_domain._require_relative_path(effect["source_path"], "source path")
            curation_domain._require_relative_path(effect["output_path"], "output path")
        except curation_domain.CanonicalCurationError as exc:
            raise ValueError("Curation Plan apply result effect is invalid") from exc
        effect_ids.append(effect["effect_id"])
        sources.append(effect["source_path"].casefold())
        targets.append(effect["output_path"].casefold())
    if (
        len(effect_ids) != len(set(effect_ids))
        or len(sources) != len(set(sources))
        or len(targets) != len(set(targets))
        or set(sources) & set(targets)
    ):
        raise ValueError("Curation Plan apply result membership is invalid")


def _root_mode_identity(root: Path) -> tuple[int, int, int, int]:
    descriptor = safety.open_verified_directory(
        root,
        require_owner_only=True,
        error_type=_TransactionError,
    )
    try:
        info = os.fstat(descriptor)
        return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid
    finally:
        os.close(descriptor)


def _require_current_authority(
    root: Path,
    compiled_policy: object,
    plan: _TransactionPlan,
) -> None:
    if (
        _root_mode_identity(root) != plan.root_identity
        or getattr(compiled_policy, "full_hash", None) != plan.policy_sha256
    ):
        raise CanonicalCurationFence(
            "Curation Plan root or policy is stale",
            reason_code="STALE",
        )
    project = root.joinpath(*plan.project_home.split("/"))
    try:
        project_identity = _root_mode_identity(project)
    except _TransactionError as exc:
        raise CanonicalCurationFence(
            "Curation Plan project home is stale",
            reason_code="STALE",
        ) from exc
    matches = [
        workstream
        for workstream in getattr(compiled_policy, "workstreams", ())
        if getattr(workstream, "id", None) == plan.primary_workstream_id
    ]
    expected_home = root.joinpath(*plan.project_home.split("/"))
    if (
        project_identity != plan.project_identity
        or len(matches) != 1
        or getattr(matches[0], "lifecycle", None) != "active"
        or Path(getattr(matches[0], "project_home", "")) != expected_home
    ):
        raise CanonicalCurationFence(
            "Curation Plan Workstream is stale",
            reason_code="STALE",
        )


def _observation_snapshot(
    root: Path,
    compiled_policy: object,
    observation: curation_domain.SourceObservation,
    *,
    max_total_bytes: int,
) -> dict[str, object]:
    try:
        snapshot = librarian_snapshot.observe_regular_file(
            root,
            compiled_policy,
            observation.relative_path,
            max_total_bytes=max_total_bytes,
        )
    except Exception as exc:
        raise CanonicalCurationFence(
            "Curation Plan source changed",
            reason_code="STALE",
        ) from exc
    expected = {
        "content_sha256": observation.content_sha256,
        "device": observation.device,
        "inode": observation.inode,
        "link_count": observation.link_count,
        "mode": observation.mode,
        "modified_time_ns": observation.modified_time_ns,
        "owner": observation.owner,
        "relative_path": observation.relative_path,
        "size": observation.size,
        "snapshot_sha256": observation.snapshot_sha256,
    }
    if any(snapshot.get(name) != value for name, value in expected.items()):
        raise CanonicalCurationFence(
            "Curation Plan source changed",
            reason_code="STALE",
        )
    return snapshot


def _target_parent_identity(root: Path, relative_path: str) -> tuple[int, int]:
    path = root.joinpath(*relative_path.split("/"))
    try:
        descriptor = safety.open_verified_directory(
            path.parent,
            require_owner_only=True,
            error_type=_TransactionError,
        )
    except _TransactionError as exc:
        raise CanonicalCurationFence(
            "Curation Plan target parent changed",
            reason_code="STALE",
        ) from exc
    try:
        info = os.fstat(descriptor)
        try:
            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return info.st_dev, info.st_ino
        except OSError as exc:
            raise CanonicalCurationFence(
                "Curation Plan target cannot be checked",
                reason_code="TARGET_CONFLICT",
            ) from exc
        raise CanonicalCurationFence(
            "Curation Plan target already exists",
            reason_code="TARGET_CONFLICT",
        )
    finally:
        os.close(descriptor)


def _transaction_path(
    anchor: _durable_snapshot._RootAnchor,
    plan_sha256: str,
):
    return anchor.joinpath(*_TRANSACTION_PARTS, "p-" + plan_sha256)


def _staging_path(
    anchor: _durable_snapshot._RootAnchor,
    plan_sha256: str,
):
    return anchor.joinpath(*_STAGING_PARTS, "p-" + plan_sha256)


def _read_record(
    anchor: _durable_snapshot._RootAnchor,
    path,
    *,
    label: str,
) -> tuple[bytes, dict[str, object]] | None:
    raw = anchor.read_bytes(path)
    if raw is None:
        return None
    if len(raw) > _MAX_JOURNAL_BYTES:
        raise CurationRecoveryRequired("Curation transaction record is oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationRecoveryRequired("Curation transaction record is invalid") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise CurationRecoveryRequired("%s is not canonical" % label)
    return raw, value


def _publish_exact(
    anchor: _durable_snapshot._RootAnchor,
    path,
    raw: bytes,
    *,
    label: str,
) -> None:
    existing = anchor.read_bytes(path)
    if existing is not None:
        if existing != raw:
            raise CurationRecoveryRequired("%s differs" % label)
        return
    anchor.publish_bytes(path, raw, label=label)


def _intent_value(
    plan: _TransactionPlan,
    *,
    request_sha256: str,
    decision_sha256: str,
) -> dict[str, object]:
    observations = {item.observation_id: item for item in plan.source_observations}
    return {
        "decision_sha256": decision_sha256,
        "effects": [
            {
                "content_sha256": effect.expected_output_sha256,
                "device": observations[effect.input_observation_id].device,
                "effect_id": effect.effect_id,
                "inode": observations[effect.input_observation_id].inode,
                "link_count": observations[effect.input_observation_id].link_count,
                "mode": observations[effect.input_observation_id].mode,
                "modified_time_ns": observations[
                    effect.input_observation_id
                ].modified_time_ns,
                "output_path": effect.output_path,
                "owner": observations[effect.input_observation_id].owner,
                "size": observations[effect.input_observation_id].size,
                "source_path": effect.source_path,
            }
            for effect in plan.effects
        ],
        "plan_sha256": plan.sha256,
        "request_sha256": request_sha256,
        "schema": _INTENT_SCHEMA,
        "source_observation_sha256": plan.source_observation_sha256,
        "status": "PREPARED",
        "workstream_id": plan.primary_workstream_id,
    }


def _result_value(
    plan: _TransactionPlan,
    *,
    request_sha256: str,
    decision_sha256: str,
    status: str,
    reason_code: str | None,
) -> dict[str, object]:
    equality_proven = status != "RECOVERY_REQUIRED"
    return {
        "decision_sha256": decision_sha256,
        "effect_count": len(plan.effects),
        "effects": [
            {
                "content_sha256": effect.expected_output_sha256,
                "effect_id": effect.effect_id,
                "output_path": effect.output_path,
                "source_path": effect.source_path,
            }
            for effect in plan.effects
        ],
        "equality": {
            "content_hashes_match": equality_proven,
            "effect_membership_complete": equality_proven,
            "staging_empty": equality_proven,
        },
        "plan_sha256": plan.sha256,
        "reason_code": reason_code,
        "request_sha256": request_sha256,
        "schema": _RESULT_SCHEMA,
        "status": status,
        "workstream_id": plan.primary_workstream_id,
    }


def _regular_state(
    anchor: _durable_snapshot._RootAnchor,
    relative_path: str,
    *,
    max_bytes: int,
) -> dict[str, object] | None:
    parts = tuple(relative_path.split("/"))
    try:
        parent_fd = anchor._open_directory(parts[:-1], create=False)
    except FileNotFoundError:
        return None
    try:
        try:
            os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        info, raw = safety.read_regular_file_at(
            parent_fd,
            parts[-1],
            anchor.display_path(parts),
            label="Curation transaction file",
            expected_mode=None,
            max_bytes=max_bytes,
            error_type=_TransactionError,
        )
        parent = os.fstat(parent_fd)
    finally:
        os.close(parent_fd)
    if info.st_nlink != 1:
        raise _TransactionError("Curation transaction file link count is invalid")
    snapshot = {
        "kind": "regular_file",
        "relative_path": relative_path,
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner": info.st_uid,
        "mode": stat.S_IMODE(info.st_mode),
        "link_count": info.st_nlink,
        "size": info.st_size,
        "modified_time_ns": info.st_mtime_ns,
        "parent": {"device": parent.st_dev, "inode": parent.st_ino},
        "content_sha256": hashlib.sha256(raw).hexdigest(),
    }
    snapshot["snapshot_sha256"] = sha256_bytes(canonical_json_bytes(snapshot))
    return snapshot


def _matches_source(
    state: dict[str, object] | None,
    observation: curation_domain.SourceObservation,
) -> bool:
    return state is not None and all(
        state.get(name) == value
        for name, value in {
            "content_sha256": observation.content_sha256,
            "device": observation.device,
            "inode": observation.inode,
            "link_count": observation.link_count,
            "mode": observation.mode,
            "modified_time_ns": observation.modified_time_ns,
            "owner": observation.owner,
            "relative_path": observation.relative_path,
            "size": observation.size,
            "snapshot_sha256": observation.snapshot_sha256,
        }.items()
    )


def _matches_relocated(
    state: dict[str, object] | None,
    observation: curation_domain.SourceObservation,
) -> bool:
    return state is not None and all(
        state.get(name) == value
        for name, value in {
            "content_sha256": observation.content_sha256,
            "device": observation.device,
            "inode": observation.inode,
            "link_count": observation.link_count,
            "mode": observation.mode,
            "modified_time_ns": observation.modified_time_ns,
            "owner": observation.owner,
            "size": observation.size,
        }.items()
    )


def _rename(
    source: Path,
    target: Path,
    observation: curation_domain.SourceObservation,
    *,
    source_parent_identity: tuple[int, int],
    target_parent_identity: tuple[int, int],
) -> None:
    expected_parents = {
        "source": source_parent_identity,
        "target": target_parent_identity,
    }

    def require_parent(_path: Path, descriptor: int, label: str) -> None:
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) != expected_parents[label]:
            raise _TransactionError("Curation transaction parent identity changed")

    safety.rename_path_no_replace(
        source,
        target,
        collision_error="Curation transaction target already exists",
        require_directory=False,
        expected_source_identity=(
            observation.device,
            observation.inode,
            stat.S_IFREG,
        ),
        create_target_parent=False,
        error_type=_TransactionError,
        before_directory_identity_check=require_parent,
    )


def _remove_empty_staging(
    anchor: _durable_snapshot._RootAnchor,
    plan_sha256: str,
) -> None:
    stage = _staging_path(anchor, plan_sha256)
    entries = anchor.list_directory(stage)
    if entries:
        raise CurationRecoveryRequired("Curation staging is not empty")
    try:
        parent_fd = anchor._open_directory(_STAGING_PARTS, create=False)
    except FileNotFoundError:
        return
    try:
        try:
            os.rmdir(stage.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise CurationRecoveryRequired(
                "Curation staging cannot be removed"
            ) from exc
    finally:
        os.close(parent_fd)


def _effect_state_paths(
    anchor: _durable_snapshot._RootAnchor,
    plan: _TransactionPlan,
    effect: curation_domain.PlanEffect,
) -> tuple[str, str, str]:
    stage = _staging_path(anchor, plan.sha256).joinpath(effect.effect_id + ".stage")
    return effect.source_path, "/".join(stage.parts), effect.output_path


def _rollback(
    anchor: _durable_snapshot._RootAnchor,
    root: Path,
    plan: _TransactionPlan,
    *,
    max_total_bytes: int,
) -> None:
    observations = {item.observation_id: item for item in plan.source_observations}
    for effect in reversed(plan.effects):
        observation = observations[effect.input_observation_id]
        source_path, stage_path, target_path = _effect_state_paths(
            anchor,
            plan,
            effect,
        )
        source = _regular_state(anchor, source_path, max_bytes=max_total_bytes)
        stage = _regular_state(anchor, stage_path, max_bytes=max_total_bytes)
        target = _regular_state(anchor, target_path, max_bytes=max_total_bytes)
        present = [source is not None, stage is not None, target is not None]
        if sum(present) != 1:
            raise CurationRecoveryRequired("Curation rollback membership is ambiguous")
        if source is not None:
            if not _matches_source(source, observation):
                raise CurationRecoveryRequired("Curation rollback source differs")
            continue
        candidate = stage if stage is not None else target
        if not _matches_relocated(candidate, observation):
            raise CurationRecoveryRequired("Curation rollback input differs")
        origin_path = stage_path if stage is not None else target_path
        origin = root.joinpath(*origin_path.split("/"))
        destination = root.joinpath(*source_path.split("/"))
        origin_parent = candidate["parent"]
        destination_fd = safety.open_verified_directory(
            destination.parent,
            require_owner_only=True,
            error_type=_TransactionError,
        )
        try:
            destination_parent_identity = (
                os.fstat(destination_fd).st_dev,
                os.fstat(destination_fd).st_ino,
            )
        finally:
            os.close(destination_fd)
        _rename(
            origin,
            destination,
            observation,
            source_parent_identity=(origin_parent["device"], origin_parent["inode"]),
            target_parent_identity=destination_parent_identity,
        )
    for effect in plan.effects:
        observation = observations[effect.input_observation_id]
        source_path, stage_path, target_path = _effect_state_paths(
            anchor,
            plan,
            effect,
        )
        if not _matches_source(
            _regular_state(anchor, source_path, max_bytes=max_total_bytes),
            observation,
        ):
            raise CurationRecoveryRequired("Curation rollback equality is unproven")
        if (
            _regular_state(anchor, stage_path, max_bytes=max_total_bytes) is not None
            or _regular_state(anchor, target_path, max_bytes=max_total_bytes) is not None
        ):
            raise CurationRecoveryRequired("Curation rollback membership is unproven")
    _remove_empty_staging(anchor, plan.sha256)


def _verify_final(
    anchor: _durable_snapshot._RootAnchor,
    plan: _TransactionPlan,
    *,
    max_total_bytes: int,
) -> None:
    observations = {item.observation_id: item for item in plan.source_observations}
    for effect in plan.effects:
        observation = observations[effect.input_observation_id]
        source_path, stage_path, target_path = _effect_state_paths(
            anchor,
            plan,
            effect,
        )
        if (
            _regular_state(anchor, source_path, max_bytes=max_total_bytes) is not None
            or _regular_state(anchor, stage_path, max_bytes=max_total_bytes) is not None
            or not _matches_relocated(
                _regular_state(anchor, target_path, max_bytes=max_total_bytes),
                observation,
            )
        ):
            raise CurationRecoveryRequired("Curation final equality is unproven")


def _validate_result_record(
    value: dict[str, object],
    plan: _TransactionPlan,
    *,
    request_sha256: str,
    decision_sha256: str,
) -> None:
    expected_effects = _result_value(
        plan,
        request_sha256="0" * 64,
        decision_sha256="0" * 64,
        status="FINALIZED",
        reason_code=None,
    )["effects"]
    if (
        set(value)
        != {
            "decision_sha256",
            "effect_count",
            "effects",
            "equality",
            "plan_sha256",
            "reason_code",
            "request_sha256",
            "schema",
            "status",
            "workstream_id",
        }
        or value["schema"] != _RESULT_SCHEMA
        or value["plan_sha256"] != plan.sha256
        or value["workstream_id"] != plan.primary_workstream_id
        or value["request_sha256"] != request_sha256
        or value["decision_sha256"] != decision_sha256
        or value["status"] not in {"FINALIZED", "ROLLED_BACK", "RECOVERY_REQUIRED"}
        or value["effect_count"] != len(plan.effects)
        or value["effects"] != expected_effects
        or value["equality"]
        != (
            {
                "content_hashes_match": False,
                "effect_membership_complete": False,
                "staging_empty": False,
            }
            if value["status"] == "RECOVERY_REQUIRED"
            else {
                "content_hashes_match": True,
                "effect_membership_complete": True,
                "staging_empty": True,
            }
        )
        or any(
            type(value[name]) is not str or _HASH.fullmatch(value[name]) is None
            for name in ("decision_sha256", "request_sha256")
        )
        or (value["status"] == "FINALIZED" and value["reason_code"] is not None)
        or (
            value["status"] != "FINALIZED"
            and (
                type(value["reason_code"]) is not str
                or re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", value["reason_code"])
                is None
            )
        )
    ):
        raise CurationRecoveryRequired("Curation terminal record is invalid")


def _validate_intent_membership(
    value: dict[str, object],
    plan_sha256: str,
) -> dict[str, dict[str, object]]:
    if (
        set(value)
        != {
            "decision_sha256",
            "effects",
            "plan_sha256",
            "request_sha256",
            "schema",
            "source_observation_sha256",
            "status",
            "workstream_id",
        }
        or value["schema"] != _INTENT_SCHEMA
        or value["status"] != "PREPARED"
        or value["plan_sha256"] != plan_sha256
        or type(value["workstream_id"]) is not str
        or re.fullmatch(r"[a-z][a-z0-9-]{1,95}", value["workstream_id"])
        is None
        or any(
            type(value[name]) is not str or _HASH.fullmatch(value[name]) is None
            for name in (
                "decision_sha256",
                "request_sha256",
                "source_observation_sha256",
            )
        )
        or type(value["effects"]) is not list
        or not value["effects"]
    ):
        raise CurationRecoveryRequired("Curation transaction intent is unsafe")
    stage_effects: dict[str, dict[str, object]] = {}
    sources: set[str] = set()
    targets: set[str] = set()
    for effect in value["effects"]:
        if (
            type(effect) is not dict
            or set(effect)
            != {
                "content_sha256",
                "device",
                "effect_id",
                "inode",
                "link_count",
                "mode",
                "modified_time_ns",
                "output_path",
                "owner",
                "size",
                "source_path",
            }
            or type(effect["content_sha256"]) is not str
            or _HASH.fullmatch(effect["content_sha256"]) is None
            or any(
                type(effect[name]) is not int or effect[name] < 0
                for name in (
                    "device",
                    "inode",
                    "link_count",
                    "mode",
                    "modified_time_ns",
                    "owner",
                    "size",
                )
            )
        ):
            raise CurationRecoveryRequired("Curation transaction effect is unsafe")
        try:
            curation_domain._require_identifier(effect["effect_id"], "effect id")
            curation_domain._require_relative_path(
                effect["source_path"],
                "source path",
            )
            curation_domain._require_relative_path(
                effect["output_path"],
                "output path",
            )
        except curation_domain.CanonicalCurationError as exc:
            raise CurationRecoveryRequired(
                "Curation transaction effect is unsafe"
            ) from exc
        stage_name = effect["effect_id"] + ".stage"
        source = effect["source_path"].casefold()
        target = effect["output_path"].casefold()
        if stage_name in stage_effects or source in sources or target in targets:
            raise CurationRecoveryRequired(
                "Curation transaction effect membership is unsafe"
            )
        stage_effects[stage_name] = effect
        sources.add(source)
        targets.add(target)
    if sources & targets:
        raise CurationRecoveryRequired(
            "Curation transaction effect graph is unsafe"
        )
    return stage_effects


def _validate_generic_result(
    value: dict[str, object],
    intent: dict[str, object],
) -> None:
    expected_effects = [
        {
            "content_sha256": effect["content_sha256"],
            "effect_id": effect["effect_id"],
            "output_path": effect["output_path"],
            "source_path": effect["source_path"],
        }
        for effect in intent["effects"]
    ]
    status = value.get("status")
    equality = (
        {
            "content_hashes_match": False,
            "effect_membership_complete": False,
            "staging_empty": False,
        }
        if status == "RECOVERY_REQUIRED"
        else {
            "content_hashes_match": True,
            "effect_membership_complete": True,
            "staging_empty": True,
        }
    )
    if (
        set(value)
        != {
            "decision_sha256",
            "effect_count",
            "effects",
            "equality",
            "plan_sha256",
            "reason_code",
            "request_sha256",
            "schema",
            "status",
            "workstream_id",
        }
        or value["schema"] != _RESULT_SCHEMA
        or status not in {"FINALIZED", "ROLLED_BACK", "RECOVERY_REQUIRED"}
        or value["plan_sha256"] != intent["plan_sha256"]
        or value["workstream_id"] != intent["workstream_id"]
        or value["request_sha256"] != intent["request_sha256"]
        or value["decision_sha256"] != intent["decision_sha256"]
        or value["effect_count"] != len(expected_effects)
        or value["effects"] != expected_effects
        or value["equality"] != equality
        or (status == "FINALIZED" and value["reason_code"] is not None)
        or (
            status != "FINALIZED"
            and (
                type(value["reason_code"]) is not str
                or re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", value["reason_code"])
                is None
            )
        )
    ):
        raise CurationRecoveryRequired("Curation transaction result is unsafe")


def _validate_staging_membership(
    anchor: _durable_snapshot._RootAnchor,
    name: str,
    expected_effects: dict[str, dict[str, object]],
) -> None:
    stage = anchor.joinpath(*_STAGING_PARTS, name)
    members = anchor.list_directory_bounded(
        stage,
        maximum_entries=len(expected_effects),
    )
    if not set(members) <= set(expected_effects):
        raise CurationRecoveryRequired("Curation staging membership is unsafe")
    for member in members:
        effect = expected_effects[member]
        relative_path = "/".join(stage.parts + (member,))
        try:
            state = _regular_state(
                anchor,
                relative_path,
                max_bytes=max(1, effect["size"]),
            )
        except _TransactionError as exc:
            raise CurationRecoveryRequired(
                "Curation staging member is unsafe"
            ) from exc
        if state is None or any(
            state.get(field) != effect[field]
            for field in (
                "content_sha256",
                "device",
                "inode",
                "link_count",
                "mode",
                "modified_time_ns",
                "owner",
                "size",
            )
        ):
            raise CurationRecoveryRequired(
                "Curation staging member differs from immutable intent"
            )


def _control_records(
    anchor: _durable_snapshot._RootAnchor,
) -> tuple[tuple[str, dict[str, object], dict[str, object] | None], ...]:
    control_members = anchor.list_directory_bounded(
        anchor.joinpath(*_CONTROL_PARTS),
        maximum_entries=3,
    )
    if not set(control_members) <= {"staging", "transactions"}:
        raise CurationRecoveryRequired("Curation control member is unknown")
    transaction_names = anchor.list_directory_bounded(
        anchor.joinpath(*_TRANSACTION_PARTS),
        maximum_entries=_MAX_TRANSACTIONS,
    )
    staging_names = anchor.list_directory_bounded(
        anchor.joinpath(*_STAGING_PARTS),
        maximum_entries=_MAX_TRANSACTIONS,
    )
    if any(_PLAN_DIRECTORY.fullmatch(name) is None for name in transaction_names):
        raise CurationRecoveryRequired("Curation transaction member is unknown")
    if any(_PLAN_DIRECTORY.fullmatch(name) is None for name in staging_names):
        raise CurationRecoveryRequired("Curation staging member is unknown")
    if not set(staging_names) <= set(transaction_names):
        raise CurationRecoveryRequired("Curation staging has no transaction")

    records = []
    for name in transaction_names:
        transaction = anchor.joinpath(*_TRANSACTION_PARTS, name)
        entries = set(anchor.list_directory(transaction))
        if not entries <= {"intent.json", "result.json"}:
            raise CurationRecoveryRequired("Curation transaction membership is unsafe")
        intent = _read_record(
            anchor,
            transaction / "intent.json",
            label="Curation transaction intent",
        )
        result = _read_record(
            anchor,
            transaction / "result.json",
            label="Curation transaction result",
        )
        if intent is None:
            raise CurationRecoveryRequired("Curation transaction intent is missing")
        plan_sha256 = _PLAN_DIRECTORY.fullmatch(name).group(1)
        stage_effects = _validate_intent_membership(intent[1], plan_sha256)
        if result is not None:
            _validate_generic_result(result[1], intent[1])
        if name in staging_names:
            if result is not None:
                raise CurationRecoveryRequired(
                    "terminal Curation transaction retains staging"
                )
            _validate_staging_membership(anchor, name, stage_effects)
        records.append((name, intent[1], None if result is None else result[1]))
    return tuple(records)


def _other_active_transaction_check(
    anchor: _durable_snapshot._RootAnchor,
    plan: _TransactionPlan,
) -> None:
    from . import canonical_curation_m3

    later_status = canonical_curation_m3.workstream_mutation_status(
        anchor.display_path(()),
        plan.primary_workstream_id,
    )
    if later_status == "RECOVERY_REQUIRED":
        raise CurationRecoveryRequired("an M3 Plan requires recovery")
    if later_status == "MUTATION_IN_PROGRESS":
        raise CanonicalCurationFence(
            "an M3 Plan is mutating this Workstream",
            reason_code="PLAN_CONFLICT",
        )
    for name, intent, result in _control_records(anchor):
        if name == "p-" + plan.sha256:
            continue
        if intent["workstream_id"] != plan.primary_workstream_id:
            continue
        if result is None:
            raise CanonicalCurationFence(
                "another Plan is mutating this Workstream",
                reason_code="PLAN_CONFLICT",
            )
        if result["status"] == "RECOVERY_REQUIRED":
            raise CurationRecoveryRequired("another Plan requires recovery")


def _terminal_replay(
    anchor: _durable_snapshot._RootAnchor,
    plan: _TransactionPlan,
    result: dict[str, object],
    *,
    request_sha256: str,
    decision_sha256: str,
    max_total_bytes: int,
) -> dict[str, object]:
    _validate_result_record(
        result,
        plan,
        request_sha256=request_sha256,
        decision_sha256=decision_sha256,
    )
    if result["status"] == "FINALIZED":
        _verify_final(anchor, plan, max_total_bytes=max_total_bytes)
        return result
    if result["status"] == "ROLLED_BACK":
        _rollback(anchor, anchor.display_path(()), plan, max_total_bytes=max_total_bytes)
        raise CanonicalCurationFence(
            "Curation Plan was already rolled back",
            reason_code="ROLLED_BACK",
        )
    raise CurationRecoveryRequired("Curation Plan requires recovery")


def _workstream_mutation_status_v1(root: Path, workstream_id: str) -> str | None:
    """Return the Stage-A transaction fence without consulting later schemas."""

    if (
        type(workstream_id) is not str
        or re.fullmatch(r"[a-z][a-z0-9-]{1,95}", workstream_id) is None
    ):
        raise ValueError("Curation Workstream id is invalid")
    root_identity = _root_mode_identity(Path(root))[:2]
    anchor = _durable_snapshot._RootAnchor.open(
        Path(root),
        expected_identity=root_identity,
    )
    try:
        try:
            for _name, intent, result in _control_records(anchor):
                if intent["workstream_id"] != workstream_id:
                    continue
                if result is None:
                    return "MUTATION_IN_PROGRESS"
                if result["status"] == "RECOVERY_REQUIRED":
                    return "RECOVERY_REQUIRED"
            return None
        except (AuthorityRuntimeError, CurationRecoveryRequired, OSError, ValueError):
            return "RECOVERY_REQUIRED"
    finally:
        anchor.close()


def workstream_mutation_status(root: Path, workstream_id: str) -> str | None:
    """Return the fail-closed transaction fence visible to current readers."""

    status = _workstream_mutation_status_v1(root, workstream_id)
    if status is not None:
        return status
    from . import canonical_curation_m3

    return canonical_curation_m3.workstream_mutation_status(root, workstream_id)


def apply_plan(
    *,
    root: Path,
    root_identity: tuple[int, int],
    compiled_policy: object,
    plan: _TransactionPlan,
    decision: dict[str, object],
    review_package_directory: Path,
    request_sha256: str,
    decision_sha256: str,
    max_total_bytes: int,
    revalidate: Callable[[], None],
) -> dict[str, object]:
    """Apply one complete reversible Plan while the caller owns the writer gate."""

    sealed_context_assembly = None
    if type(plan) is curation_domain.ContextBoundCurationPlan:
        sealed_context_assembly = _require_context_review_package_binding(
            root=root,
            plan=plan,
            decision=decision,
            directory=review_package_directory,
        )
    else:
        _require_review_package_binding(
            root=root,
            plan=plan,
            decision=decision,
            directory=review_package_directory,
        )
    _require_current_authority(root, compiled_policy, plan)
    anchor = _durable_snapshot._RootAnchor.open(
        root,
        expected_identity=root_identity,
    )
    intent_value = _intent_value(
        plan,
        request_sha256=request_sha256,
        decision_sha256=decision_sha256,
    )
    intent_raw = canonical_json_bytes(intent_value)
    transaction = _transaction_path(anchor, plan.sha256)
    intent_path = transaction / "intent.json"
    result_path = transaction / "result.json"
    try:
        _other_active_transaction_check(anchor, plan)
        existing_intent = _read_record(
            anchor,
            intent_path,
            label="Curation transaction intent",
        )
        existing_result = _read_record(
            anchor,
            result_path,
            label="Curation transaction result",
        )
        entries = set(anchor.list_directory(transaction))
        if not entries <= {"intent.json", "result.json"}:
            raise CurationRecoveryRequired("Curation transaction membership is unsafe")
        if existing_result is not None:
            if existing_intent is None:
                raise CurationRecoveryRequired(
                    "Curation terminal result has no immutable intent"
                )
            if existing_intent[0] != intent_raw:
                raise CanonicalCurationFence(
                    "terminal Curation Plan belongs to another request",
                    reason_code="PLAN_CONFLICT",
                )
            return _terminal_replay(
                anchor,
                plan,
                existing_result[1],
                request_sha256=request_sha256,
                decision_sha256=decision_sha256,
                max_total_bytes=max_total_bytes,
            )
        if existing_intent is not None:
            if existing_intent[0] != intent_raw:
                raise CanonicalCurationFence(
                    "incomplete Curation Plan belongs to another request",
                    reason_code="PLAN_CONFLICT",
                )
            try:
                _verify_final(anchor, plan, max_total_bytes=max_total_bytes)
            except CurationRecoveryRequired:
                _rollback(anchor, root, plan, max_total_bytes=max_total_bytes)
                rolled_back = _result_value(
                    plan,
                    request_sha256=request_sha256,
                    decision_sha256=decision_sha256,
                    status="ROLLED_BACK",
                    reason_code="ROLLED_BACK",
                )
                _publish_exact(
                    anchor,
                    result_path,
                    canonical_json_bytes(rolled_back),
                    label="Curation rollback result",
                )
                raise CanonicalCurationFence(
                    "interrupted Curation Plan was rolled back",
                    reason_code="ROLLED_BACK",
                )
            _remove_empty_staging(anchor, plan.sha256)
            finalized = _result_value(
                plan,
                request_sha256=request_sha256,
                decision_sha256=decision_sha256,
                status="FINALIZED",
                reason_code=None,
            )
            _publish_exact(
                anchor,
                result_path,
                canonical_json_bytes(finalized),
                label="Curation final result",
            )
            return finalized

        try:
            revalidate()
        except AuthorityRuntimeError as exc:
            raise CanonicalCurationFence(
                "Curation Plan policy or lifecycle changed",
                reason_code="STALE",
            ) from exc
        if sealed_context_assembly is not None:
            _require_fresh_context(
                root=root,
                compiled_policy=compiled_policy,
                plan=plan,
                sealed_assembly=sealed_context_assembly,
            )
        observations = {
            observation.observation_id: observation
            for observation in plan.source_observations
        }
        source_snapshots = {
            observation.observation_id: _observation_snapshot(
                root,
                compiled_policy,
                observation,
                max_total_bytes=max_total_bytes,
            )
            for observation in plan.source_observations
        }
        target_parents = {
            effect.effect_id: _target_parent_identity(root, effect.output_path)
            for effect in plan.effects
        }
        _publish_exact(
            anchor,
            intent_path,
            intent_raw,
            label="Curation transaction intent",
        )
        try:
            _run_checkpoint("after-prepared")
            stage = _staging_path(anchor, plan.sha256)
            stage_fd = anchor._open_directory(stage.parts, create=True)
            try:
                stage_info = os.fstat(stage_fd)
                stage_parent_identity = (stage_info.st_dev, stage_info.st_ino)
            finally:
                os.close(stage_fd)
            if anchor.list_directory(stage):
                raise CurationRecoveryRequired("new Curation staging is not empty")

            for effect in plan.effects:
                try:
                    revalidate()
                except AuthorityRuntimeError as exc:
                    raise CanonicalCurationFence(
                        "Curation Plan policy or lifecycle changed",
                        reason_code="STALE",
                    ) from exc
                observation = observations[effect.input_observation_id]
                snapshot = source_snapshots[effect.input_observation_id]
                stage_file = stage / (effect.effect_id + ".stage")
                _run_checkpoint("before-stage:" + effect.effect_id)
                try:
                    _rename(
                        root.joinpath(*effect.source_path.split("/")),
                        stage_file.display_path,
                        observation,
                        source_parent_identity=(
                            snapshot["parent"]["device"],
                            snapshot["parent"]["inode"],
                        ),
                        target_parent_identity=stage_parent_identity,
                    )
                except (safety.ManualRecoveryRequired, _TransactionError) as exc:
                    raise CanonicalCurationFence(
                        "Curation Plan source changed while staging",
                        reason_code="STALE",
                    ) from exc
                if not _matches_relocated(
                    _regular_state(
                        anchor,
                        "/".join(stage_file.parts),
                        max_bytes=max_total_bytes,
                    ),
                    observation,
                ):
                    raise CurationRecoveryRequired("Curation staging readback differs")
                _run_checkpoint("after-stage:" + effect.effect_id)

            for effect in plan.effects:
                try:
                    revalidate()
                except AuthorityRuntimeError as exc:
                    raise CanonicalCurationFence(
                        "Curation Plan policy or lifecycle changed",
                        reason_code="STALE",
                    ) from exc
                observation = observations[effect.input_observation_id]
                stage_file = stage / (effect.effect_id + ".stage")
                _run_checkpoint("before-publish:" + effect.effect_id)
                try:
                    _rename(
                        stage_file.display_path,
                        root.joinpath(*effect.output_path.split("/")),
                        observation,
                        source_parent_identity=stage_parent_identity,
                        target_parent_identity=target_parents[effect.effect_id],
                    )
                except safety.ManualRecoveryRequired as exc:
                    raise CurationRecoveryRequired(
                        "Curation publish compensation is ambiguous"
                    ) from exc
                except _TransactionError as exc:
                    raise CanonicalCurationFence(
                        "Curation Plan target changed while publishing",
                        reason_code="TARGET_CONFLICT",
                    ) from exc
                _run_checkpoint("after-publish:" + effect.effect_id)

            _verify_final(anchor, plan, max_total_bytes=max_total_bytes)
            _remove_empty_staging(anchor, plan.sha256)
            _run_checkpoint("after-published-verified")
            finalized = _result_value(
                plan,
                request_sha256=request_sha256,
                decision_sha256=decision_sha256,
                status="FINALIZED",
                reason_code=None,
            )
            _publish_exact(
                anchor,
                result_path,
                canonical_json_bytes(finalized),
                label="Curation final result",
            )
            return finalized
        except CurationRecoveryRequired:
            raise
        except CanonicalCurationFence as exc:
            try:
                _rollback(anchor, root, plan, max_total_bytes=max_total_bytes)
                rolled_back = _result_value(
                    plan,
                    request_sha256=request_sha256,
                    decision_sha256=decision_sha256,
                    status="ROLLED_BACK",
                    reason_code=exc.reason_code,
                )
                _publish_exact(
                    anchor,
                    result_path,
                    canonical_json_bytes(rolled_back),
                    label="Curation rollback result",
                )
            except Exception as rollback_error:
                raise CurationRecoveryRequired(
                    "Curation rollback equality is unproven"
                ) from rollback_error
            raise
        except Exception as exc:
            try:
                _rollback(anchor, root, plan, max_total_bytes=max_total_bytes)
                rolled_back = _result_value(
                    plan,
                    request_sha256=request_sha256,
                    decision_sha256=decision_sha256,
                    status="ROLLED_BACK",
                    reason_code="ROLLED_BACK",
                )
                _publish_exact(
                    anchor,
                    result_path,
                    canonical_json_bytes(rolled_back),
                    label="Curation rollback result",
                )
            except Exception as rollback_error:
                raise CurationRecoveryRequired(
                    "Curation rollback equality is unproven"
                ) from rollback_error
            raise CanonicalCurationFence(
                "Curation Plan failed and was rolled back",
                reason_code="ROLLED_BACK",
            ) from exc
    except CurationRecoveryRequired:
        try:
            bound_intent = anchor.read_bytes(intent_path)
        except AuthorityRuntimeError:
            bound_intent = None
        if bound_intent == intent_raw:
            recovery = _result_value(
                plan,
                request_sha256=request_sha256,
                decision_sha256=decision_sha256,
                status="RECOVERY_REQUIRED",
                reason_code="CURATION_PLAN_RECOVERY_REQUIRED",
            )
            try:
                _publish_exact(
                    anchor,
                    result_path,
                    canonical_json_bytes(recovery),
                    label="Curation recovery-required result",
                )
            except Exception:
                pass
        raise
    finally:
        anchor.close()


def plan_apply_handler(
    admitted: object,
    session: object,
) -> operation_contract.OperationOutcome:
    if type(admitted) is not operation_contract.AdmittedOperation:
        raise TypeError("Curation Plan apply admission is invalid")
    apply = getattr(session, "apply_curation_plan", None)
    if not callable(apply):
        raise TypeError("Curation Plan apply session is invalid")
    result = apply()
    if type(result) is not dict:
        raise TypeError("Curation Plan apply result is invalid")
    return operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result=result,
    )


__all__ = [
    "CurationRecoveryRequired",
    "decode_admitted_input",
    "decode_context_admitted_input",
    "decode_context_bound_plan",
    "decode_plan",
    "plan_apply_handler",
    "validate_plan_apply_request",
    "validate_plan_apply_result",
    "workstream_mutation_status",
]
