"""Pure canonical request construction for the public Curation adapters."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .. import (
    activation_contract,
    artifact_contract,
    canonical_curation,
    librarian_contract,
    operation_contract,
)


_PUBLIC_SAFE_LIBRARIAN_VIEWS = frozenset(("audit", "scope", "pending", "history"))
_CONTEXT_REVIEW_HASH_NAMES = frozenset(
    ("html_sha256", "markdown_sha256", "meta_sha256", "semantic_sha256")
)
_MAX_CONTEXT_TOTAL_BYTES = 256 * 1024 * 1024


def _require_text(value: object, label: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 and character != "\t" for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _require_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _require_context_review_hashes(value: object) -> dict[object, object]:
    if not isinstance(value, Mapping):
        raise ValueError("Context activation review hashes are invalid")
    hashes = dict(value)
    if set(hashes) != _CONTEXT_REVIEW_HASH_NAMES:
        raise ValueError("Context activation review hashes are invalid")
    for name, digest in hashes.items():
        _require_sha256(digest, f"Context activation {name}")
    return hashes


def build_context_activation_request(
    *,
    root: object,
    actor: object,
    plan: object,
    review_package_directory: object,
    review_package_hashes: object,
    decision: object,
) -> operation_contract.OperationRequest:
    """Build one exact Context-bound Plan apply request from a sealed review."""

    if (
        type(plan) is not canonical_curation.ContextBoundCurationPlan
        or decision != "APPROVE_ALL"
        or not plan.effects
        or plan.plan.findings
        or any(effect.action not in {"move", "rename"} for effect in plan.effects)
    ):
        raise ValueError("Context activation request fields are invalid")
    if type(review_package_directory) is not str:
        raise ValueError("Context activation review package path is invalid")
    review_path = Path(review_package_directory)
    if (
        not review_path.is_absolute()
        or any(part in {".", ".."} for part in review_path.parts)
        or review_path.as_posix() != review_package_directory
    ):
        raise ValueError("Context activation review package path is invalid")
    hashes = _require_context_review_hashes(review_package_hashes)
    total_bytes = sum(observation.size for observation in plan.source_observations)
    if total_bytes > _MAX_CONTEXT_TOTAL_BYTES:
        raise ValueError("Context activation source bytes exceed the bound")
    request = operation_contract.OperationRequest(
        schema_version=1,
        operation_kind="curation.plan_apply",
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=operation_contract.ClaimMode.CURRENT,
        root=root,
        actor=actor,
        requested_authority=operation_contract.AuthorityMode.WRITE,
        scope={
            "plan_sha256": plan.sha256,
            "workstream_id": plan.primary_workstream_id,
        },
        payload={
            "decision": {
                "action": "APPROVE_ALL",
                "approved_plan_sha256": plan.sha256,
                "displayed_plan_sha256": plan.sha256,
                "reason": None,
                "review_package_hashes": hashes,
                "selected_effect_ids": [
                    effect.effect_id for effect in plan.effects
                ],
                "source_observation_sha256": plan.source_observation_sha256,
            },
            "plan": plan.canonical_value,
            "review_package_directory": review_package_directory,
        },
        bounds={
            "max_effects": len(plan.effects),
            "max_total_bytes": max(1, total_bytes),
        },
    )
    return request


def build_activation_request(
    *,
    root: object,
    actor: object,
    activation_id: object,
    audit_result: object,
) -> operation_contract.OperationRequest:
    """Build one exact activation request from a fresh public audit result."""

    if type(root) is not str or type(activation_id) is not str:
        raise ValueError("activation request fields are invalid")
    audit = activation_contract.require_fresh_audit_result(audit_result, root=root)
    request = operation_contract.OperationRequest(
        schema_version=1,
        operation_kind="curation.activation",
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=operation_contract.ClaimMode.CURRENT,
        root=root,
        actor=actor,
        requested_authority=operation_contract.AuthorityMode.WRITE,
        scope={"activation_id": activation_id},
        payload={
            "allowed_namespace": audit["allowed_namespace"],
            "corpus_effect": audit["corpus_effect"],
            "initial_policy": audit["initial_policy"],
            "root_identity_sha256": audit["root_identity_sha256"],
        },
        bounds={},
    )
    activation_contract.validate_activation_request(request)
    return request


def build_proposal_request(
    *,
    root: object,
    actor: object,
    proposal_id: object,
    source_relative_path: object,
    target_relative_path: object,
    destination_kind: object,
    destination_id: object,
    reason: object,
    max_entries: object,
    max_depth: object,
    max_total_bytes: object,
) -> operation_contract.OperationRequest:
    """Build one immutable Safe Librarian proposal publication request."""

    identifier = librarian_contract.require_proposal_id(proposal_id)
    source = librarian_contract.require_relative_path(source_relative_path)
    target = librarian_contract.require_relative_path(target_relative_path)
    if source == target:
        raise ValueError("proposal source and target must differ")
    if destination_kind not in {"workstream", "manual_category"}:
        raise ValueError("proposal destination kind is invalid")
    destination = _require_text(destination_id, "proposal destination id", 128)
    proposal_reason = _require_text(reason, "proposal reason", 2000)
    if (
        type(max_entries) is not int
        or not 1 <= max_entries <= 4096
        or type(max_depth) is not int
        or not 0 <= max_depth <= 16
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= 256 * 1024 * 1024
    ):
        raise ValueError("proposal bounds are invalid")
    return operation_contract.OperationRequest(
        schema_version=1,
        operation_kind="librarian.proposal",
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=operation_contract.ClaimMode.CURRENT,
        root=root,
        actor=actor,
        requested_authority=operation_contract.AuthorityMode.WRITE,
        scope={
            "proposal_id": identifier,
            "source_relative_path": source,
            "target_relative_path": target,
        },
        payload={
            "destination_kind": destination_kind,
            "destination_id": destination,
            "reason": proposal_reason,
        },
        bounds={
            "max_entries": max_entries,
            "max_depth": max_depth,
            "max_total_bytes": max_total_bytes,
        },
    )


def _require_proposal_request(
    request: object,
) -> operation_contract.OperationRequest:
    if type(request) is not operation_contract.OperationRequest:
        raise ValueError("proposal request is invalid")
    try:
        expected = build_proposal_request(
            root=request.root,
            actor=request.actor,
            proposal_id=request.scope["proposal_id"],
            source_relative_path=request.scope["source_relative_path"],
            target_relative_path=request.scope["target_relative_path"],
            destination_kind=request.payload["destination_kind"],
            destination_id=request.payload["destination_id"],
            reason=request.payload["reason"],
            max_entries=request.bounds["max_entries"],
            max_depth=request.bounds["max_depth"],
            max_total_bytes=request.bounds["max_total_bytes"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("proposal request is invalid") from exc
    if expected.canonical_bytes != request.canonical_bytes:
        raise ValueError("proposal request is invalid")
    return request


def _require_proposal_reference(
    value: object,
    proposal_id: str,
) -> artifact_contract.SealedArtifactRef:
    if (
        type(value) is not artifact_contract.SealedArtifactRef
        or value.schema != librarian_contract.PROPOSAL_SCHEMA
        or value.canonical_path
        != librarian_contract.proposal_artifact_path(proposal_id)
        or value.media_type != "application/json"
    ):
        raise ValueError("proposal artifact reference is invalid")
    return value


def build_decision_request(
    *,
    root: object,
    actor: object,
    proposal_request: object,
    proposal_reference: object,
    decision_id: object,
    decision: object,
    decision_reason: object,
) -> operation_contract.OperationRequest:
    """Build one exact decision for a completed immutable proposal."""

    proposal = _require_proposal_request(proposal_request)
    if root != proposal.root:
        raise ValueError("decision root does not match the proposal")
    proposal_id = proposal.scope["proposal_id"]
    reference = _require_proposal_reference(proposal_reference, proposal_id)
    identifier = librarian_contract.require_decision_id(decision_id)
    if decision not in {"APPROVED", "REJECTED"}:
        raise ValueError("decision value is invalid")
    reason = _require_text(decision_reason, "decision reason", 2000)
    return operation_contract.OperationRequest(
        schema_version=1,
        operation_kind="librarian.decision",
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=operation_contract.ClaimMode.CURRENT,
        root=root,
        actor=actor,
        requested_authority=operation_contract.AuthorityMode.WRITE,
        scope={"proposal_id": proposal_id},
        payload={
            "decision_id": identifier,
            "decision": decision,
            "decision_reason": reason,
        },
        bounds={},
        prerequisite_artifacts=(reference,),
    )


def _require_decision_reference(
    value: object,
    proposal_id: str,
) -> artifact_contract.SealedArtifactRef:
    if (
        type(value) is not artifact_contract.SealedArtifactRef
        or value.schema != librarian_contract.DECISION_SCHEMA
        or value.canonical_path
        != librarian_contract.decision_artifact_path(proposal_id)
        or value.media_type != "application/json"
    ):
        raise ValueError("decision artifact reference is invalid")
    return value


def _require_decision_request(
    request: object,
    *,
    proposal_request: operation_contract.OperationRequest,
    proposal_reference: artifact_contract.SealedArtifactRef,
) -> operation_contract.OperationRequest:
    if type(request) is not operation_contract.OperationRequest:
        raise ValueError("decision request is invalid")
    try:
        expected = build_decision_request(
            root=request.root,
            actor=request.actor,
            proposal_request=proposal_request,
            proposal_reference=proposal_reference,
            decision_id=request.payload["decision_id"],
            decision=request.payload["decision"],
            decision_reason=request.payload["decision_reason"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("decision request is invalid") from exc
    if expected.canonical_bytes != request.canonical_bytes:
        raise ValueError("decision request is invalid")
    return request


def build_placement_request(
    *,
    root: object,
    actor: object,
    proposal_request: object,
    proposal_reference: object,
    decision_request: object,
    decision_reference: object,
) -> operation_contract.OperationRequest:
    """Build the mechanical placement bound to one exact approval."""

    proposal = _require_proposal_request(proposal_request)
    if root != proposal.root:
        raise ValueError("placement root does not match the proposal")
    proposal_id = proposal.scope["proposal_id"]
    sealed_proposal = _require_proposal_reference(proposal_reference, proposal_id)
    approved = _require_decision_request(
        decision_request,
        proposal_request=proposal,
        proposal_reference=sealed_proposal,
    )
    if approved.root != root or approved.payload["decision"] != "APPROVED":
        raise ValueError("placement requires the exact approved decision")
    sealed_decision = _require_decision_reference(decision_reference, proposal_id)
    return operation_contract.OperationRequest(
        schema_version=1,
        operation_kind="librarian.placement",
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=operation_contract.ClaimMode.CURRENT,
        root=root,
        actor=actor,
        requested_authority=operation_contract.AuthorityMode.WRITE,
        scope=dict(proposal.scope),
        payload={},
        bounds={},
        approval_artifact=sealed_decision,
        prerequisite_artifacts=(sealed_proposal,),
    )


def build_view_request(
    *,
    view: object,
    root: object,
    actor: object,
    max_items: object,
    offset: object,
    workstream_ref: object = None,
    relative_path: object = None,
    max_depth: object = None,
    max_hint_bytes: object = None,
) -> operation_contract.OperationRequest:
    """Build one catalog-bound request without opening a root or a ledger."""

    if type(view) is not str or view not in _PUBLIC_SAFE_LIBRARIAN_VIEWS:
        raise ValueError("inspect view is invalid")
    if view == "audit":
        if (
            workstream_ref is not None
            or relative_path is not None
            or max_depth is not None
            or max_hint_bytes is not None
        ):
            raise ValueError("inspect audit does not accept a relative scope")
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.audit",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=root,
            actor=actor,
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={},
            payload={"offset": offset},
            bounds={"max_items": 64 if max_items is None else max_items},
        )
    if view == "scope":
        if type(workstream_ref) is not str or not workstream_ref:
            raise ValueError("inspect scope workstream reference is invalid")
        if relative_path is not None:
            raise ValueError("inspect scope does not accept a relative path")
        if offset != 0:
            raise ValueError("inspect scope offset is invalid")
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=root,
            actor=actor,
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": workstream_ref},
            payload={},
            bounds={
                "max_items": 256 if max_items is None else max_items,
                "max_depth": 8 if max_depth is None else max_depth,
                "max_hint_bytes": (
                    1024 * 1024 if max_hint_bytes is None else max_hint_bytes
                ),
            },
        )
    if workstream_ref is not None:
        raise ValueError("Safe Librarian record view does not accept a workstream")
    if type(relative_path) is not str or not relative_path:
        raise ValueError("Safe Librarian record scope is required")
    if max_depth is not None or max_hint_bytes is not None:
        raise ValueError("Safe Librarian record view does not accept tree bounds")
    maximum = 64 if max_items is None else max_items
    return operation_contract.OperationRequest(
        schema_version=1,
        operation_kind=f"inspect.{view}",
        action=operation_contract.LifecycleAction.INSPECT,
        claim_mode=operation_contract.ClaimMode.HISTORICAL,
        root=root,
        actor=actor,
        requested_authority=operation_contract.AuthorityMode.READ,
        scope={"relative_path": relative_path},
        payload={"offset": offset},
        bounds={"max_items": maximum},
    )


__all__ = [
    "build_activation_request",
    "build_context_activation_request",
    "build_decision_request",
    "build_placement_request",
    "build_proposal_request",
    "build_view_request",
]
