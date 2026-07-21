"""Approved one-item Safe Librarian placement owner."""

from __future__ import annotations

from collections.abc import Mapping
import re

from . import artifact_contract, librarian_contract, operation_contract
from .canonical_json import canonical_json_bytes


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _validate_recovery_identity(
    request: operation_contract.OperationRequest,
) -> operation_contract.OperationRequest:
    recovery = request.payload.get("recovery")
    if (
        not isinstance(recovery, Mapping)
        or set(recovery) != {"continuation_identity", "producer_request_sha256"}
        or type(recovery["continuation_identity"]) is not str
        or _SHA256.fullmatch(recovery["continuation_identity"]) is None
        or type(recovery["producer_request_sha256"]) is not str
        or _SHA256.fullmatch(recovery["producer_request_sha256"]) is None
    ):
        raise ValueError("Safe Librarian placement recovery identity is invalid")
    original = operation_contract.OperationRequest(
        schema_version=request.schema_version,
        operation_kind=request.operation_kind,
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=request.claim_mode,
        root=request.root,
        actor=request.actor,
        requested_authority=request.requested_authority,
        scope=dict(request.scope),
        bounds={},
        payload={},
        approval_artifact=request.approval_artifact,
        prerequisite_artifacts=request.prerequisite_artifacts,
    )
    if original.sha256 != recovery["producer_request_sha256"]:
        raise ValueError("Safe Librarian placement recovery does not match APPLY")
    return original


def validate_placement_request(request: object) -> None:
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "librarian.placement"
        or request.action
        not in {
            operation_contract.LifecycleAction.APPLY,
            operation_contract.LifecycleAction.RECOVER,
        }
        or request.claim_mode is not operation_contract.ClaimMode.CURRENT
        or request.requested_authority is not operation_contract.AuthorityMode.WRITE
        or set(request.scope)
        != {"proposal_id", "source_relative_path", "target_relative_path"}
        or request.bounds
        or len(request.prerequisite_artifacts) != 1
    ):
        raise ValueError("Safe Librarian placement request is invalid")
    if request.action is operation_contract.LifecycleAction.APPLY:
        if request.payload:
            raise ValueError("Safe Librarian placement payload is invalid")
    elif set(request.payload) != {"recovery"}:
        raise ValueError("Safe Librarian placement recovery payload is invalid")
    else:
        _validate_recovery_identity(request)

    proposal_id = librarian_contract.require_proposal_id(
        request.scope["proposal_id"]
    )
    source = librarian_contract.require_relative_path(
        request.scope["source_relative_path"]
    )
    target = librarian_contract.require_relative_path(
        request.scope["target_relative_path"]
    )
    if source == target:
        raise ValueError("Safe Librarian placement paths are invalid")

    decision_reference = request.approval_artifact
    proposal_reference = request.prerequisite_artifacts[0]
    if (
        type(decision_reference) is not artifact_contract.SealedArtifactRef
        or decision_reference.schema != librarian_contract.DECISION_SCHEMA
        or decision_reference.canonical_path
        != librarian_contract.decision_artifact_path(proposal_id)
        or decision_reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian placement decision reference is invalid")
    if (
        type(proposal_reference) is not artifact_contract.SealedArtifactRef
        or proposal_reference.schema != librarian_contract.PROPOSAL_SCHEMA
        or proposal_reference.canonical_path
        != librarian_contract.proposal_artifact_path(proposal_id)
        or proposal_reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian placement proposal reference is invalid")


def _result_reference(value: object) -> artifact_contract.SealedArtifactRef:
    if not isinstance(value, Mapping):
        raise ValueError("Safe Librarian placement result artifact is invalid")
    reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(dict(value))
    )
    proposal_id = reference.canonical_path.rsplit("/", 1)[-1].removesuffix(
        ".json"
    )
    if (
        reference.schema != librarian_contract.RESULT_SCHEMA
        or reference.canonical_path
        != librarian_contract.result_artifact_path(proposal_id)
        or reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian placement result artifact is invalid")
    return reference


def _intent_reference(value: object) -> artifact_contract.SealedArtifactRef:
    if not isinstance(value, Mapping):
        raise ValueError("Safe Librarian placement intent artifact is invalid")
    reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(dict(value))
    )
    proposal_id = reference.canonical_path.rsplit("/", 1)[-1].removesuffix(
        ".json"
    )
    if (
        reference.schema != librarian_contract.INTENT_SCHEMA
        or reference.canonical_path
        != librarian_contract.intent_artifact_path(proposal_id)
        or reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian placement intent artifact is invalid")
    return reference


def _is_public_recovery_outcome(outcome: object) -> bool:
    if type(outcome) is not operation_contract.OperationOutcome:
        return False
    if outcome.recovery_owner != "authority-runtime":
        return False
    if outcome.outcome_kind == "recoverable":
        return outcome.allowed_recovery_action == "recover"
    return outcome.outcome_kind == "blocked_recovery"


def validate_placement_result(outcome: object) -> None:
    if _is_public_recovery_outcome(outcome):
        return
    if (
        type(outcome) is operation_contract.OperationOutcome
        and outcome.outcome_kind == "completed"
    ):
        _result_reference(outcome.result_artifact)
        return
    if (
        type(outcome) is operation_contract.OperationOutcome
        and outcome.outcome_kind == "blocked"
        and outcome.reason_code
        in {
            "DECISION_MISMATCH",
            "DESTINATION_INVALID",
            "PLACEMENT_MISMATCH",
            "PROPOSAL_MISMATCH",
            "SCOPE_UNSAFE",
            "SOURCE_CHANGED",
            "SOURCE_UNSUPPORTED",
            "TARGET_COLLISION",
            "WORKSTREAM_INACTIVE",
        }
        and outcome.next_safe_action
        in {
            "choose-scope",
            "correct-request",
            "create-proposal",
            "inspect",
            "inspect-pending",
        }
    ):
        return
    raise ValueError("Safe Librarian placement result is invalid")


def apply_request_after_recovered_placement(
    request: object,
    outcome: object,
) -> operation_contract.OperationRequest | None:
    """Return the exact original APPLY only when RECOVER finalized an intent."""

    validate_placement_request(request)
    if (
        type(request) is not operation_contract.OperationRequest
        or request.action is not operation_contract.LifecycleAction.RECOVER
        or type(outcome) is not operation_contract.OperationOutcome
        or outcome.outcome_kind != "completed"
        or outcome.request_sha256 != request.sha256
    ):
        raise ValueError("Safe Librarian placement recovery result is invalid")
    try:
        _result_reference(outcome.result_artifact)
    except ValueError:
        intent_reference = _intent_reference(outcome.result_artifact)
        proposal_id = librarian_contract.require_proposal_id(
            request.scope["proposal_id"]
        )
        if (
            intent_reference.canonical_path
            != librarian_contract.intent_artifact_path(proposal_id)
        ):
            raise ValueError("Safe Librarian placement recovery result is invalid")
        return _validate_recovery_identity(request)
    return None


def rebind_recovered_placement_outcome(
    request: object,
    outcome: object,
) -> operation_contract.OperationOutcome:
    """Bind an exact original-APPLY result to its public RECOVER request."""

    if (
        type(request) is not operation_contract.OperationRequest
        or request.action is not operation_contract.LifecycleAction.RECOVER
        or type(outcome) is not operation_contract.OperationOutcome
    ):
        raise ValueError("Safe Librarian placement continuation is invalid")
    if outcome.outcome_kind == "completed":
        rebound = operation_contract.OperationOutcome.completed(
            request.sha256,
            result_artifact=_result_reference(outcome.result_artifact),
        )
    elif outcome.outcome_kind == "blocked":
        rebound = operation_contract.OperationOutcome.blocked(
            request.sha256,
            reason_code=outcome.reason_code,
            next_safe_action=outcome.next_safe_action,
        )
    else:
        raise ValueError("Safe Librarian placement continuation is invalid")
    validate_placement_result(rebound)
    return rebound


def _completed(
    admitted: operation_contract.AdmittedOperation,
    reference: artifact_contract.SealedArtifactRef,
) -> operation_contract.OperationOutcome:
    return operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result_artifact=reference,
    )


def _blocked(
    admitted: operation_contract.AdmittedOperation,
    error: librarian_contract.LibrarianOperationError,
) -> operation_contract.OperationOutcome:
    return operation_contract.OperationOutcome.blocked(
        admitted.request_sha256,
        reason_code=error.reason_code,
        next_safe_action=error.next_safe_action,
    )


def _run_checkpoint(_point: str) -> None:
    """Private test seam for placement-domain crash boundaries."""


def _publish_blocked_result(
    *,
    admitted: operation_contract.AdmittedOperation,
    session: object,
    proposal_reference: artifact_contract.SealedArtifactRef,
    intent_reference: artifact_contract.SealedArtifactRef | None,
    error: librarian_contract.LibrarianOperationError,
) -> operation_contract.OperationOutcome:
    publish = getattr(session, "publish_librarian_placement_result", None)
    if not callable(publish):
        raise TypeError("Safe Librarian placement session is invalid")
    record = {
        "schema": librarian_contract.RESULT_SCHEMA.canonical_value,
        "proposal": proposal_reference.canonical_value,
        "intent": (
            None
            if intent_reference is None
            else intent_reference.canonical_value
        ),
        "status": "BLOCKED",
        "reason_code": error.reason_code,
        "source_absent": False,
        "target_snapshot": None,
        "producer_request_sha256": admitted.request_sha256,
    }
    reference = publish(librarian_contract.encode_result_record(record))
    if type(reference) is not artifact_contract.SealedArtifactRef:
        raise TypeError("Safe Librarian blocked placement result is invalid")
    return _blocked(admitted, error)


def placement_handler(
    admitted: object,
    session: object,
) -> operation_contract.OperationOutcome:
    if type(admitted) is not operation_contract.AdmittedOperation:
        raise TypeError("Safe Librarian placement admission is invalid")
    if admitted.input["action"] is operation_contract.LifecycleAction.RECOVER:
        recover = getattr(session, "recover_librarian_placement", None)
        if not callable(recover):
            raise TypeError("Safe Librarian placement recovery session is invalid")
        reference = recover()
        if type(reference) is not artifact_contract.SealedArtifactRef:
            raise TypeError("Safe Librarian recovered placement is invalid")
        return _completed(admitted, reference)

    replay_result = getattr(session, "existing_librarian_placement_result", None)
    read_inputs = getattr(session, "read_librarian_placement_inputs", None)
    replay_intent = getattr(session, "existing_librarian_placement_intent", None)
    verify_pre = getattr(session, "verify_librarian_placement_pre_move", None)
    verify_post = getattr(session, "verify_librarian_placement_post_move", None)
    classify_state = getattr(session, "classify_librarian_placement_state", None)
    publish_intent = getattr(session, "publish_librarian_placement_intent", None)
    move = getattr(session, "move_librarian_placement", None)
    publish_result = getattr(session, "publish_librarian_placement_result", None)
    fence = getattr(session, "fence_librarian_placement", None)
    if not all(
        callable(value)
        for value in (
            replay_result,
            read_inputs,
            replay_intent,
            verify_pre,
            verify_post,
            classify_state,
            publish_intent,
            move,
            publish_result,
            fence,
        )
    ):
        raise TypeError("Safe Librarian placement session is invalid")

    existing_result = replay_result()
    if existing_result is not None:
        result_reference, _result_bytes = existing_result
        return _completed(admitted, result_reference)

    try:
        proposal_reference, proposal, decision_reference, _decision = read_inputs()
    except librarian_contract.LibrarianOperationError as exc:
        return _blocked(admitted, exc)

    existing_intent = replay_intent()
    intent_reference = None
    if existing_intent is None:
        try:
            verify_pre(proposal)
        except librarian_contract.LibrarianOperationError as exc:
            return _publish_blocked_result(
                admitted=admitted,
                session=session,
                proposal_reference=proposal_reference,
                intent_reference=None,
                error=exc,
            )
        intent_record = {
            "schema": librarian_contract.INTENT_SCHEMA.canonical_value,
            "proposal": proposal_reference.canonical_value,
            "decision": decision_reference.canonical_value,
            "source_snapshot": proposal["source_snapshot"],
            "source_relative_path": proposal["source_relative_path"],
            "target_relative_path": proposal["target_relative_path"],
            "producer_request_sha256": admitted.request_sha256,
            "state": "INTENT_RECORDED",
        }
        intent_reference = publish_intent(
            librarian_contract.encode_intent_record(intent_record)
        )
        _run_checkpoint("after-intent")
    else:
        intent_reference, _intent = existing_intent

    try:
        placement_state = classify_state(proposal)
        if placement_state["state"] == "POST_MOVE":
            post_move = placement_state["evidence"]
        elif placement_state["state"] == "PRE_MOVE":
            move(proposal)
            _run_checkpoint("after-rename")
            post_move = verify_post(proposal)
        else:
            raise TypeError("Safe Librarian placement state is invalid")
    except librarian_contract.LibrarianOperationError as exc:
        if exc.reason_code == "PLACEMENT_RECOVERY_REQUIRED":
            fence()
            raise AssertionError("placement fence returned unexpectedly")
        return _publish_blocked_result(
            admitted=admitted,
            session=session,
            proposal_reference=proposal_reference,
            intent_reference=intent_reference,
            error=exc,
        )

    result_record = {
        "schema": librarian_contract.RESULT_SCHEMA.canonical_value,
        "proposal": proposal_reference.canonical_value,
        "intent": intent_reference.canonical_value,
        "status": "APPLIED",
        "reason_code": None,
        "source_absent": True,
        "target_snapshot": post_move["target_snapshot"],
        "producer_request_sha256": admitted.request_sha256,
    }
    _run_checkpoint("before-result")
    result_reference = publish_result(
        librarian_contract.encode_result_record(result_record)
    )
    _run_checkpoint("after-result")
    return _completed(admitted, result_reference)


__all__ = [
    "apply_request_after_recovered_placement",
    "placement_handler",
    "rebind_recovered_placement_outcome",
    "validate_placement_request",
    "validate_placement_result",
]
