"""The single static composition owner for Document Curation operations.

This module deliberately contains only immutable operation metadata and direct
callable bindings.  It does not decode requests, access a root, or perform
domain work.
"""

from __future__ import annotations

import json
import re
from types import MappingProxyType

from .. import (
    _verified_source_manifest,
    activation_contract,
    inspect_audit_operation,
    librarian_contract,
    librarian_inspection,
    librarian_placement,
    librarian_records,
    operation_contract,
)
from ..canonical_json import canonical_json_bytes, sha256_bytes
from ..authority_runtime import canonical_curation as curation_plan_apply
from .catalog import OperationAvailability, OperationCatalog, OperationSpec


_INSPECT = operation_contract.LifecycleAction.INSPECT
_PLAN = operation_contract.LifecycleAction.PLAN
_APPROVE = operation_contract.LifecycleAction.APPROVE
_APPLY = operation_contract.LifecycleAction.APPLY
_RESUME = operation_contract.LifecycleAction.RESUME
_CANCEL = operation_contract.LifecycleAction.CANCEL
_RECOVER = operation_contract.LifecycleAction.RECOVER

_NONE = operation_contract.AuthorityMode.NONE
_READ = operation_contract.AuthorityMode.READ
_WRITE = operation_contract.AuthorityMode.WRITE

_HISTORICAL = operation_contract.ClaimMode.HISTORICAL
_CURRENT = operation_contract.ClaimMode.CURRENT
_NO_CLAIM = operation_contract.ClaimMode.NONE
_SHA256 = re.compile(r"[0-9a-f]{64}")


_ROW_SOURCE_MODULE = __name__
_ROW_SOURCE_SYMBOL = "_ROW_SPECS"


def _source_entry(module_name: str) -> tuple[str, str]:
    if type(_verified_source_manifest) is not MappingProxyType:
        raise RuntimeError("verified source manifest is unavailable")
    try:
        entry = _verified_source_manifest[module_name]
    except KeyError as exc:
        raise RuntimeError("verified source manifest entry is missing") from exc
    if type(entry) is not MappingProxyType:
        raise RuntimeError("verified source manifest entry is invalid")
    source_path = entry.get("relative_path")
    source_sha256 = entry.get("sha256")
    if type(source_path) is not str or type(source_sha256) is not str:
        raise RuntimeError("verified source manifest entry is invalid")
    return source_path, source_sha256


def _metadata_sha256(value: dict[str, object]) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _callable_metadata(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not callable(value):
        raise RuntimeError("operation callable binding is invalid")
    module = getattr(value, "__module__", None)
    symbol = getattr(value, "__name__", None)
    if type(module) is not str or type(symbol) is not str:
        raise RuntimeError("operation callable binding is invalid")
    path, source_sha256 = _source_entry(module)
    return {
        "module": module,
        "path": path,
        "sha256": source_sha256,
        "symbol": symbol,
    }


def _capability_payload(maximum: int) -> dict[str, object]:
    ordered = tuple(
        sorted(
            DEFAULT_OPERATION_CATALOG.specs,
            key=lambda spec: spec.operation_kind,
        )
    )
    counts = {"available": 0, "blocked": 0, "deferred": 0}
    capabilities = []
    for spec in ordered:
        counts[spec.availability.value.lower()] += 1
        capabilities.append(
            {
                "schema_version": 1,
                "operation_kind": spec.operation_kind,
                "actions": [action.value for action in spec.admission_contract.allowed_actions],
                "authority_mode": spec.admission_contract.authority_mode.value,
                "availability": spec.availability.value,
                "bounds_schema": list(spec.admission_contract.bounds_schema),
                "prerequisite": spec.availability_reason,
            }
        )
    projected = capabilities[:maximum]
    return {
        "capabilities": projected,
        "returned": len(projected),
        "schema_version": 1,
        "summary": {"total": len(capabilities), **counts},
        "truncated": len(projected) < len(capabilities),
        "view": "capabilities",
    }


def _validated_capability_maximum(
    request: operation_contract.OperationRequest,
) -> int:
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "inspect.capabilities"
        or request.action is not _INSPECT
        or request.claim_mode is not _NO_CLAIM
        or request.requested_authority is not _NONE
        or set(request.scope)
        or set(request.payload)
        or set(request.bounds) != {"max_items"}
    ):
        raise ValueError("capabilities request is invalid")
    maximum = request.bounds["max_items"]
    if type(maximum) is not int or not 1 <= maximum <= 256:
        raise ValueError("capabilities request is invalid")
    return maximum


def _validate_capabilities_request(
    request: operation_contract.OperationRequest,
) -> None:
    _validated_capability_maximum(request)


def _capabilities_handler(admitted: operation_contract.AdmittedOperation):
    try:
        maximum = admitted.input["bounds"]["max_items"]
    except (KeyError, TypeError) as exc:
        raise ValueError("admitted capabilities request is invalid") from exc
    if type(maximum) is not int or not 1 <= maximum <= 256:
        raise ValueError("admitted capabilities request is invalid")
    return operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result=_capability_payload(maximum),
    )


def _validate_capabilities_result(outcome: object) -> None:
    if (
        type(outcome) is not operation_contract.OperationOutcome
        or outcome.outcome_kind != "completed"
        or not isinstance(outcome.result, dict)
        or outcome.result.get("view") != "capabilities"
    ):
        raise ValueError("capabilities result is invalid")


def _validate_workspace_sync_request(request: object) -> None:
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "memory.workspace_sync"
        or request.action is not _APPLY
        or request.claim_mode is not _HISTORICAL
        or request.requested_authority is not _WRITE
        or set(request.scope) != {"plan_sha256", "workstream_id"}
        or set(request.bounds) != {"max_total_bytes"}
        or set(request.payload) != {"plan_text"}
        or request.approval_artifact is not None
        or request.prerequisite_artifacts
    ):
        raise ValueError("workspace sync request is invalid")
    plan_text = request.payload["plan_text"]
    if type(plan_text) is not str:
        raise ValueError("workspace sync request is invalid")
    plan_bytes = plan_text.encode("utf-8")
    if (
        type(request.scope["plan_sha256"]) is not str
        or _SHA256.fullmatch(request.scope["plan_sha256"]) is None
        or sha256_bytes(plan_bytes) != request.scope["plan_sha256"]
        or type(request.bounds["max_total_bytes"]) is not int
        or not 1 <= request.bounds["max_total_bytes"] <= 8 * 1024 * 1024
    ):
        raise ValueError("workspace sync request is invalid")
    try:
        plan = json.loads(plan_text)
    except json.JSONDecodeError as exc:
        raise ValueError("workspace sync Plan is invalid") from exc
    if (
        type(plan) is not dict
        or canonical_json_bytes(plan) + b"\n" != plan_bytes
        or plan.get("schema") != "mnemosyne-workspace-sync-plan-v1"
        or plan.get("root") != request.root
        or plan.get("workstream") != request.scope["workstream_id"]
        or type(plan.get("effects")) is not list
        or len(plan["effects"]) != 2
    ):
        raise ValueError("workspace sync Plan does not match request")


def _workspace_sync_handler(admitted: operation_contract.AdmittedOperation, session: object):
    result = session.apply_workspace_sync_plan()
    reason_code = result.get("reason_code")
    if reason_code is not None:
        return operation_contract.OperationOutcome.blocked(
            admitted.request_sha256,
            reason_code=reason_code,
            next_safe_action=result["next_safe_action"],
        )
    return operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result=result,
    )


def _validate_workspace_sync_result(outcome: object) -> None:
    if type(outcome) is not operation_contract.OperationOutcome:
        raise ValueError("workspace sync result is invalid")
    if outcome.outcome_kind == "completed":
        if isinstance(outcome.result, dict) and outcome.result.get("claim_mode") == "HISTORICAL":
            return
    elif outcome.outcome_kind == "blocked" and outcome.reason_code in {
        "APPLY_FAILED",
        "BASE_CHANGED",
        "PATH_UNSAFE",
        "PLAN_ALREADY_APPLIED",
        "PLAN_MISMATCH",
        "READBACK_MISMATCH",
        "WRITER_BUSY",
    }:
        return
    raise ValueError("workspace sync result is invalid")


_AVAILABLE = OperationAvailability.AVAILABLE
_BLOCKED = OperationAvailability.BLOCKED
_DEFERRED = OperationAvailability.DEFERRED


# This is a static transcription of the pre-cutover capability vocabulary.  A
# row stays BLOCKED/DEFERRED when no D1a-session-compatible owner exists; it
# never acquires an executable stub merely to preserve a name.
_ROW_SPECS = (
    ("control.bootstrap", (_PLAN, _APPLY, _RESUME), _WRITE, _BLOCKED),
    ("control.lock_migration", (_PLAN, _APPLY, _RESUME), _WRITE, _BLOCKED),
    ("control.schema_migration", (_PLAN, _APPROVE, _APPLY), _WRITE, _BLOCKED),
    ("control.writer_cutover", (_PLAN, _APPROVE, _APPLY), _WRITE, _DEFERRED),
    ("curation.activation", (_APPLY,), _WRITE, _AVAILABLE),
    ("curation.plan_apply", (_APPLY,), _WRITE, _AVAILABLE),
    ("graphify.query", (_INSPECT,), _READ, _DEFERRED),
    ("graphify.update", (_APPLY,), _WRITE, _DEFERRED),
    ("inspect.audit", (_INSPECT,), _READ, _AVAILABLE),
    ("inspect.capabilities", (_INSPECT,), _NONE, _AVAILABLE),
    ("inspect.history", (_INSPECT,), _READ, _AVAILABLE),
    ("inspect.pending", (_INSPECT,), _READ, _AVAILABLE),
    ("inspect.recovery", (_INSPECT,), _READ, _DEFERRED),
    ("inspect.scope", (_INSPECT,), _READ, _AVAILABLE),
    ("inspect.status", (_INSPECT,), _READ, _BLOCKED),
    ("inventory.run", (_APPLY, _RESUME), _WRITE, _BLOCKED),
    ("librarian.decision", (_APPLY, _RECOVER), _WRITE, _AVAILABLE),
    ("librarian.placement", (_APPLY, _RECOVER), _WRITE, _AVAILABLE),
    ("librarian.proposal", (_APPLY, _RECOVER), _WRITE, _AVAILABLE),
    ("memory.workspace_sync", (_APPLY,), _WRITE, _AVAILABLE),
    ("movement.placement", (_APPLY,), _WRITE, _DEFERRED),
    ("movement.recovery", (_APPROVE, _RECOVER), _WRITE, _DEFERRED),
    ("movement.reversal", (_PLAN, _APPROVE, _APPLY), _WRITE, _DEFERRED),
    ("navigation.baseline_drift", (_INSPECT,), _READ, _DEFERRED),
    ("navigation.build", (_APPLY,), _WRITE, _DEFERRED),
    ("navigation.projects_baseline", (_PLAN, _APPROVE, _APPLY), _WRITE, _DEFERRED),
    ("navigation.sync", (_APPLY,), _WRITE, _DEFERRED),
    ("navigation.update", (_PLAN, _APPROVE, _APPLY), _WRITE, _DEFERRED),
    ("okf.bundle", (_PLAN, _APPLY), _WRITE, _DEFERRED),
    ("okf.validation", (_INSPECT,), _READ, _DEFERRED),
    ("pilot.expansion", (_PLAN, _APPROVE), _WRITE, _DEFERRED),
    ("pilot.gate", (_RESUME,), _WRITE, _DEFERRED),
    ("pilot.poststate", (_INSPECT,), _READ, _DEFERRED),
    ("pilot.prework", (_RESUME, _CANCEL), _WRITE, _DEFERRED),
    ("pilot.prework_validation", (_INSPECT,), _READ, _DEFERRED),
    ("pilot.rebase", (_PLAN, _APPROVE), _WRITE, _DEFERRED),
    ("pilot.retry", (_PLAN, _APPROVE), _WRITE, _DEFERRED),
    ("policy.bootstrap", (_PLAN, _APPROVE, _APPLY), _WRITE, _BLOCKED),
    ("policy.change", (_PLAN, _APPROVE, _APPLY), _WRITE, _BLOCKED),
    ("policy.drift", (_APPLY, _RESUME, _RECOVER), _WRITE, _BLOCKED),
    ("policy.reconcile", (_PLAN, _APPROVE, _APPLY), _WRITE, _BLOCKED),
    ("review.batch", (_APPROVE, _APPLY), _WRITE, _BLOCKED),
    ("review.batch_event", (_APPLY, _RESUME, _CANCEL), _WRITE, _BLOCKED),
    ("review.batch_split", (_APPLY,), _WRITE, _BLOCKED),
    ("review.decision", (_APPLY,), _WRITE, _BLOCKED),
    ("review.deferral", (_APPLY,), _WRITE, _BLOCKED),
    ("review.deferral_evidence", (_APPLY,), _WRITE, _BLOCKED),
    ("review.draft", (_APPLY,), _WRITE, _BLOCKED),
    ("review.legacy_import", (_PLAN, _APPLY, _RESUME), _WRITE, _BLOCKED),
    ("review.run", (_APPLY,), _WRITE, _BLOCKED),
    ("review.submission", (_APPLY, _RESUME), _WRITE, _BLOCKED),
    ("review.unit_explosion", (_APPLY,), _WRITE, _BLOCKED),
    ("review.validation", (_INSPECT,), _READ, _BLOCKED),
    ("scope.expansion", (_PLAN, _APPROVE), _WRITE, _DEFERRED),
    ("workstream.lifecycle_override", (_PLAN, _APPLY, _CANCEL), _WRITE, _DEFERRED),
)


_OPERATION_BINDINGS = {
    "curation.activation": (
        activation_contract.activation_handler,
        activation_contract.validate_activation_request,
        activation_contract.validate_activation_result,
    ),
    "curation.plan_apply": (
        curation_plan_apply.plan_apply_handler,
        curation_plan_apply.validate_plan_apply_request,
        curation_plan_apply.validate_plan_apply_result,
    ),
    "inspect.audit": (
        inspect_audit_operation.audit_handler,
        inspect_audit_operation.validate_audit_request,
        inspect_audit_operation.validate_audit_result,
    ),
    "inspect.capabilities": (
        _capabilities_handler,
        _validate_capabilities_request,
        _validate_capabilities_result,
    ),
    "inspect.history": (
        librarian_inspection.records_handler,
        librarian_inspection.validate_records_request,
        librarian_inspection.validate_records_result,
    ),
    "inspect.pending": (
        librarian_inspection.records_handler,
        librarian_inspection.validate_records_request,
        librarian_inspection.validate_records_result,
    ),
    "inspect.scope": (
        librarian_inspection.scope_handler,
        librarian_inspection.validate_scope_request,
        librarian_inspection.validate_scope_result,
    ),
    "librarian.decision": (
        librarian_records.decision_handler,
        librarian_records.validate_decision_request,
        librarian_records.validate_decision_result,
    ),
    "librarian.placement": (
        librarian_placement.placement_handler,
        librarian_placement.validate_placement_request,
        librarian_placement.validate_placement_result,
    ),
    "librarian.proposal": (
        librarian_records.proposal_handler,
        librarian_records.validate_proposal_request,
        librarian_records.validate_proposal_result,
    ),
    "memory.workspace_sync": (
        _workspace_sync_handler,
        _validate_workspace_sync_request,
        _validate_workspace_sync_result,
    ),
}


def _claim_modes_for(
    authority_mode: operation_contract.AuthorityMode,
    operation_kind: str,
) -> tuple[operation_contract.ClaimMode, ...]:
    if operation_kind == "memory.workspace_sync":
        return (_HISTORICAL,)
    if authority_mode is _NONE:
        return (_NO_CLAIM,)
    if authority_mode is _READ:
        return (_HISTORICAL,)
    return (_CURRENT,)


def _handler_for(operation_kind: str):
    binding = _OPERATION_BINDINGS.get(operation_kind)
    return None if binding is None else binding[0]


def _request_validator_for(operation_kind: str):
    binding = _OPERATION_BINDINGS.get(operation_kind)
    return None if binding is None else binding[1]


def _result_validator_for(operation_kind: str):
    binding = _OPERATION_BINDINGS.get(operation_kind)
    return None if binding is None else binding[2]


def _bounds_for(operation_kind: str) -> tuple[str, ...]:
    if operation_kind in {"inspect.audit", "inspect.capabilities"}:
        return ("max_items",)
    if operation_kind == "inspect.scope":
        return ("max_items", "max_depth", "max_hint_bytes")
    if operation_kind in {"inspect.pending", "inspect.history"}:
        return ("max_items",)
    if operation_kind == "curation.plan_apply":
        return ("max_effects", "max_total_bytes")
    if operation_kind == "memory.workspace_sync":
        return ("max_total_bytes",)
    if operation_kind == "librarian.proposal":
        return ("max_entries", "max_depth", "max_total_bytes")
    return ()


def _scope_for(operation_kind: str) -> tuple[str, ...]:
    if operation_kind == "curation.activation":
        return ("activation_id",)
    if operation_kind == "curation.plan_apply":
        return ("plan_sha256", "workstream_id")
    if operation_kind == "inspect.scope":
        return ("workstream_ref",)
    if operation_kind in {"inspect.pending", "inspect.history"}:
        return ("relative_path",)
    if operation_kind in {"librarian.proposal", "librarian.placement"}:
        return ("proposal_id", "source_relative_path", "target_relative_path")
    if operation_kind == "librarian.decision":
        return ("proposal_id",)
    if operation_kind == "memory.workspace_sync":
        return ("plan_sha256", "workstream_id")
    return ()


def _read_profile_for(
    operation_kind: str,
) -> operation_contract.ReadProfile:
    if operation_kind == "inspect.audit":
        return operation_contract.ReadProfile.CURATION_AUDIT
    if operation_kind in {"inspect.scope", "inspect.pending", "inspect.history"}:
        return operation_contract.ReadProfile.SAFE_LIBRARIAN
    return operation_contract.ReadProfile.STANDARD


def _write_profile_for(operation_kind: str) -> operation_contract.WriteProfile:
    if operation_kind == "curation.activation":
        return operation_contract.WriteProfile.CURATION_ACTIVATION
    if operation_kind == "curation.plan_apply":
        return operation_contract.WriteProfile.CURATION_PLAN_APPLY
    if operation_kind in {"librarian.proposal", "librarian.decision"}:
        return operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD
    if operation_kind == "librarian.placement":
        return operation_contract.WriteProfile.SAFE_LIBRARIAN_PLACEMENT
    return operation_contract.WriteProfile.STANDARD


def _approval_requirement_for(
    operation_kind: str,
) -> operation_contract.ArtifactRequirement | None:
    if operation_kind == "librarian.placement":
        return librarian_contract.DECISION_REQUIREMENT
    return None


def _prerequisite_requirements_for(
    operation_kind: str,
) -> tuple[operation_contract.ArtifactRequirement, ...]:
    if operation_kind in {"librarian.decision", "librarian.placement"}:
        return (librarian_contract.PROPOSAL_REQUIREMENT,)
    return ()


def _availability_reason(
    operation_kind: str,
    availability: OperationAvailability,
) -> str | None:
    if availability is _AVAILABLE:
        return None
    if availability is _BLOCKED:
        return "owner-migration-pending"
    return "deferred-capability-not-implemented"


def _build_spec(
    operation_kind: str,
    actions: tuple[operation_contract.LifecycleAction, ...],
    authority_mode: operation_contract.AuthorityMode,
    availability: OperationAvailability,
) -> OperationSpec:
    spec_identity = "d1b-%s-v%s" % (
        operation_kind.replace(".", "-"),
        2 if operation_kind == "inspect.scope" else 1,
    )
    source_path, source_sha256 = _source_entry(_ROW_SOURCE_MODULE)
    handler = _handler_for(operation_kind)
    request_validator = _request_validator_for(operation_kind)
    result_validator = _result_validator_for(operation_kind)
    handler_metadata = _callable_metadata(handler)
    request_validator_metadata = _callable_metadata(request_validator)
    result_validator_metadata = _callable_metadata(result_validator)
    read_profile = _read_profile_for(operation_kind)
    write_profile = _write_profile_for(operation_kind)
    claim_modes = _claim_modes_for(authority_mode, operation_kind)
    scope_schema = _scope_for(operation_kind)
    bounds_schema = _bounds_for(operation_kind)
    approval_requirement = _approval_requirement_for(operation_kind)
    prerequisites = _prerequisite_requirements_for(operation_kind)
    approval_required = approval_requirement is not None
    availability_reason = _availability_reason(operation_kind, availability)
    spec_sha256 = _metadata_sha256(
        {
            "actions": [action.value for action in actions],
            "authority_mode": authority_mode.value,
            "availability": availability.value,
            "availability_reason": availability_reason,
            "approval_required": approval_required,
            "approval_requirement": (
                approval_requirement.canonical_value
                if approval_requirement is not None
                else None
            ),
            "bounds_schema": list(bounds_schema),
            "claim_modes": [claim_mode.value for claim_mode in claim_modes],
            "handler": handler_metadata,
            "operation_kind": operation_kind,
            "read_profile": read_profile.value,
            "prerequisite_artifacts": [
                requirement.canonical_value for requirement in prerequisites
            ],
            "request_validator": request_validator_metadata,
            "result_validator": result_validator_metadata,
            "row_source": {
                "module": _ROW_SOURCE_MODULE,
                "path": source_path,
                "sha256": source_sha256,
                "symbol": _ROW_SOURCE_SYMBOL,
            },
            "schema_version": 1,
            "scope_schema": list(scope_schema),
            "spec_identity": spec_identity,
            "write_profile": write_profile.value,
        }
    )
    return OperationSpec(
        operation_kind=operation_kind,
        spec_identity=spec_identity,
        spec_sha256=spec_sha256,
        admission_contract=operation_contract.AdmissionContract(
            spec_identity=spec_identity,
            spec_sha256=spec_sha256,
            operation_kind=operation_kind,
            allowed_actions=actions,
            allowed_claim_modes=claim_modes,
            authority_mode=authority_mode,
            scope_schema=scope_schema,
            bounds_schema=bounds_schema,
            approval_required=approval_required,
            prerequisite_artifacts=prerequisites,
            approval_requirement=approval_requirement,
            read_profile=read_profile,
            write_profile=write_profile,
        ),
        source_module=_ROW_SOURCE_MODULE,
        source_path=source_path,
        source_symbol=_ROW_SOURCE_SYMBOL,
        source_sha256=source_sha256,
        handler=handler,
        handler_module=(
            None if handler_metadata is None else handler_metadata["module"]
        ),
        handler_symbol=(
            None if handler_metadata is None else handler_metadata["symbol"]
        ),
        handler_sha256=(
            None if handler_metadata is None else handler_metadata["sha256"]
        ),
        availability=availability,
        availability_reason=availability_reason,
        request_validator=request_validator,
        result_validator=result_validator,
    )


DEFAULT_OPERATION_CATALOG = OperationCatalog(
    tuple(_build_spec(*row) for row in _ROW_SPECS)
)


__all__ = ["DEFAULT_OPERATION_CATALOG", "OperationAvailability"]
