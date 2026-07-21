"""Safe Librarian immutable proposal and decision record owners."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import re

from . import artifact_contract, librarian_contract, operation_contract
from .canonical_json import canonical_json_bytes


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )


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


def _validate_recovery_identity(
    request: operation_contract.OperationRequest,
    domain_payload_fields: set[str],
) -> None:
    recovery = request.payload.get("recovery")
    if (
        not isinstance(recovery, Mapping)
        or set(recovery) != {"continuation_identity", "producer_request_sha256"}
        or type(recovery["continuation_identity"]) is not str
        or _SHA256.fullmatch(recovery["continuation_identity"]) is None
        or type(recovery["producer_request_sha256"]) is not str
        or _SHA256.fullmatch(recovery["producer_request_sha256"]) is None
    ):
        raise ValueError("Safe Librarian recovery identity is invalid")
    original = operation_contract.OperationRequest(
        schema_version=request.schema_version,
        operation_kind=request.operation_kind,
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=request.claim_mode,
        root=request.root,
        actor=request.actor,
        requested_authority=request.requested_authority,
        scope=dict(request.scope),
        bounds=dict(request.bounds),
        payload={field: request.payload[field] for field in domain_payload_fields},
        approval_artifact=request.approval_artifact,
        prerequisite_artifacts=request.prerequisite_artifacts,
    )
    if original.sha256 != recovery["producer_request_sha256"]:
        raise ValueError("Safe Librarian recovery request does not match APPLY")


def validate_proposal_request(request: object) -> None:
    domain_payload_fields = {"destination_kind", "destination_id", "reason"}
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "librarian.proposal"
        or request.action
        not in {
            operation_contract.LifecycleAction.APPLY,
            operation_contract.LifecycleAction.RECOVER,
        }
        or request.claim_mode is not operation_contract.ClaimMode.CURRENT
        or request.requested_authority is not operation_contract.AuthorityMode.WRITE
        or set(request.scope)
        != {"proposal_id", "source_relative_path", "target_relative_path"}
        or set(request.bounds)
        != {"max_entries", "max_depth", "max_total_bytes"}
        or request.approval_artifact is not None
        or request.prerequisite_artifacts
    ):
        raise ValueError("Safe Librarian proposal request is invalid")
    if request.action is operation_contract.LifecycleAction.APPLY:
        if set(request.payload) != domain_payload_fields:
            raise ValueError("Safe Librarian proposal request is invalid")
    elif set(request.payload) != domain_payload_fields | {"recovery"}:
        raise ValueError("Safe Librarian proposal recovery request is invalid")
    else:
        _validate_recovery_identity(request, domain_payload_fields)
    librarian_contract.require_proposal_id(request.scope["proposal_id"])
    source = librarian_contract.require_relative_path(
        request.scope["source_relative_path"]
    )
    target = librarian_contract.require_relative_path(
        request.scope["target_relative_path"]
    )
    if source == target:
        raise ValueError("Safe Librarian proposal source and target must differ")
    if request.payload["destination_kind"] not in {
        "workstream",
        "manual_category",
    }:
        raise ValueError("Safe Librarian proposal destination kind is invalid")
    _require_text(
        request.payload["destination_id"],
        "Safe Librarian proposal destination id",
        128,
    )
    _require_text(
        request.payload["reason"],
        "Safe Librarian proposal reason",
        2000,
    )
    if (
        type(request.bounds["max_entries"]) is not int
        or not 1 <= request.bounds["max_entries"] <= 4096
        or type(request.bounds["max_depth"]) is not int
        or not 0 <= request.bounds["max_depth"] <= 16
        or type(request.bounds["max_total_bytes"]) is not int
        or not 1 <= request.bounds["max_total_bytes"] <= 256 * 1024 * 1024
    ):
        raise ValueError("Safe Librarian proposal bounds are invalid")


def _proposal_reference(value: object) -> artifact_contract.SealedArtifactRef:
    if not isinstance(value, Mapping):
        raise ValueError("Safe Librarian proposal result artifact is invalid")
    reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(dict(value))
    )
    if (
        reference.schema != librarian_contract.PROPOSAL_SCHEMA
        or reference.media_type != "application/json"
        or not reference.canonical_path.startswith(
            "_registry/curation/safe-librarian/v1/proposals/p-"
        )
        or not reference.canonical_path.endswith(".json")
    ):
        raise ValueError("Safe Librarian proposal result artifact is invalid")
    proposal_id = reference.canonical_path.rsplit("/", 1)[1][:-5]
    if reference.canonical_path != librarian_contract.proposal_artifact_path(
        proposal_id
    ):
        raise ValueError("Safe Librarian proposal result artifact is invalid")
    return reference


def validate_proposal_result(outcome: object) -> None:
    if _is_public_record_recovery_outcome(outcome):
        return
    if (
        type(outcome) is operation_contract.OperationOutcome
        and outcome.outcome_kind == "completed"
    ):
        _proposal_reference(outcome.result_artifact)
        return
    if (
        type(outcome) is operation_contract.OperationOutcome
        and outcome.outcome_kind == "blocked"
        and outcome.reason_code
        in {
            "DESTINATION_INVALID",
            "PROPOSAL_MISMATCH",
            "SCOPE_LIMIT_EXCEEDED",
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
            "narrow-scope",
        }
    ):
        return
    raise ValueError("Safe Librarian proposal result is invalid")


def _is_public_record_recovery_outcome(outcome: object) -> bool:
    if type(outcome) is not operation_contract.OperationOutcome:
        return False
    if outcome.recovery_owner != "authority-runtime":
        return False
    if outcome.outcome_kind == "recoverable":
        return outcome.allowed_recovery_action == "recover"
    return outcome.outcome_kind == "blocked_recovery"


def _completed(
    admitted: operation_contract.AdmittedOperation,
    reference: artifact_contract.SealedArtifactRef,
) -> operation_contract.OperationOutcome:
    return operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result_artifact=reference,
    )


def _blocked_from_error(
    admitted: operation_contract.AdmittedOperation,
    error: librarian_contract.LibrarianOperationError,
) -> operation_contract.OperationOutcome:
    return operation_contract.OperationOutcome.blocked(
        admitted.request_sha256,
        reason_code=error.reason_code,
        next_safe_action=error.next_safe_action,
    )


def validate_decision_request(request: object) -> None:
    domain_payload_fields = {"decision_id", "decision", "decision_reason"}
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "librarian.decision"
        or request.action
        not in {
            operation_contract.LifecycleAction.APPLY,
            operation_contract.LifecycleAction.RECOVER,
        }
        or request.claim_mode is not operation_contract.ClaimMode.CURRENT
        or request.requested_authority is not operation_contract.AuthorityMode.WRITE
        or set(request.scope) != {"proposal_id"}
        or request.bounds
        or request.approval_artifact is not None
        or len(request.prerequisite_artifacts) != 1
    ):
        raise ValueError("Safe Librarian decision request is invalid")
    if request.action is operation_contract.LifecycleAction.APPLY:
        if set(request.payload) != domain_payload_fields:
            raise ValueError("Safe Librarian decision request is invalid")
    elif set(request.payload) != domain_payload_fields | {"recovery"}:
        raise ValueError("Safe Librarian decision recovery request is invalid")
    else:
        _validate_recovery_identity(request, domain_payload_fields)
    proposal_id = librarian_contract.require_proposal_id(
        request.scope["proposal_id"]
    )
    librarian_contract.require_decision_id(request.payload["decision_id"])
    if request.payload["decision"] not in {"APPROVED", "REJECTED"}:
        raise ValueError("Safe Librarian decision is invalid")
    _require_text(
        request.payload["decision_reason"],
        "Safe Librarian decision reason",
        2000,
    )
    reference = request.prerequisite_artifacts[0]
    if (
        type(reference) is not artifact_contract.SealedArtifactRef
        or reference.schema != librarian_contract.PROPOSAL_SCHEMA
        or reference.canonical_path
        != librarian_contract.proposal_artifact_path(proposal_id)
        or reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian decision proposal reference is invalid")


def _decision_reference(value: object) -> artifact_contract.SealedArtifactRef:
    if not isinstance(value, Mapping):
        raise ValueError("Safe Librarian decision result artifact is invalid")
    reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(dict(value))
    )
    if (
        reference.schema != librarian_contract.DECISION_SCHEMA
        or reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian decision result artifact is invalid")
    proposal_id = reference.canonical_path.rsplit("/", 1)[-1].removesuffix(
        ".json"
    )
    if reference.canonical_path != librarian_contract.decision_artifact_path(
        proposal_id
    ):
        raise ValueError("Safe Librarian decision result artifact is invalid")
    return reference


def validate_decision_result(outcome: object) -> None:
    if _is_public_record_recovery_outcome(outcome):
        return
    if (
        type(outcome) is operation_contract.OperationOutcome
        and outcome.outcome_kind == "completed"
    ):
        _decision_reference(outcome.result_artifact)
        return
    if (
        type(outcome) is operation_contract.OperationOutcome
        and outcome.outcome_kind == "blocked"
        and outcome.reason_code in {"DECISION_MISMATCH", "PROPOSAL_MISMATCH"}
        and outcome.next_safe_action in {"correct-request", "inspect-pending"}
    ):
        return
    raise ValueError("Safe Librarian decision result is invalid")


def _recover_record(
    admitted: operation_contract.AdmittedOperation,
    session: object,
) -> operation_contract.OperationOutcome:
    recover = getattr(session, "recover_librarian_record", None)
    if not callable(recover):
        raise TypeError("Safe Librarian recovery session is invalid")
    reference = recover()
    if type(reference) is not artifact_contract.SealedArtifactRef:
        raise TypeError("Safe Librarian recovered record is invalid")
    return _completed(admitted, reference)


def proposal_handler(
    admitted: object,
    session: object,
) -> operation_contract.OperationOutcome:
    if type(admitted) is not operation_contract.AdmittedOperation:
        raise TypeError("Safe Librarian proposal admission is invalid")
    if admitted.input["action"] is operation_contract.LifecycleAction.RECOVER:
        return _recover_record(admitted, session)
    replay = getattr(session, "existing_librarian_proposal", None)
    observe = getattr(session, "observe_librarian_proposal", None)
    publish = getattr(session, "publish_librarian_proposal", None)
    if not callable(replay) or not callable(observe) or not callable(publish):
        raise TypeError("Safe Librarian proposal session is invalid")
    try:
        existing = replay()
    except librarian_contract.LibrarianOperationError as exc:
        return _blocked_from_error(admitted, exc)
    if existing is not None:
        reference, _record_bytes = existing
        if type(reference) is not artifact_contract.SealedArtifactRef:
            raise TypeError("Safe Librarian proposal replay is invalid")
        return _completed(admitted, reference)
    try:
        evidence = observe()
    except librarian_contract.LibrarianOperationError as exc:
        return _blocked_from_error(admitted, exc)
    if (
        type(evidence) is not dict
        or set(evidence) != {"source_snapshot", "target_absent"}
    ):
        raise TypeError("Safe Librarian proposal evidence is invalid")
    scope = admitted.input["scope"]
    payload = admitted.input["payload"]
    bounds = admitted.input["bounds"]
    record = {
        "schema": librarian_contract.PROPOSAL_SCHEMA.canonical_value,
        "proposal_id": scope["proposal_id"],
        "producer_request_sha256": admitted.request_sha256,
        "actor": admitted.actor,
        "created_at": _utc_now(),
        "source_relative_path": scope["source_relative_path"],
        "target_relative_path": scope["target_relative_path"],
        "destination_kind": payload["destination_kind"],
        "destination_id": payload["destination_id"],
        "reason": payload["reason"],
        "source_snapshot": evidence["source_snapshot"],
        "target_absent": evidence["target_absent"],
        "bounds": dict(bounds),
        "state": "PENDING",
    }
    try:
        reference = publish(librarian_contract.encode_proposal_record(record))
    except librarian_contract.LibrarianOperationError as exc:
        return _blocked_from_error(admitted, exc)
    if type(reference) is not artifact_contract.SealedArtifactRef:
        raise TypeError("Safe Librarian proposal publication is invalid")
    return _completed(admitted, reference)


def decision_handler(
    admitted: object,
    session: object,
) -> operation_contract.OperationOutcome:
    if type(admitted) is not operation_contract.AdmittedOperation:
        raise TypeError("Safe Librarian decision admission is invalid")
    if admitted.input["action"] is operation_contract.LifecycleAction.RECOVER:
        return _recover_record(admitted, session)
    replay = getattr(session, "existing_librarian_decision", None)
    read_proposal = getattr(session, "read_librarian_proposal", None)
    publish = getattr(session, "publish_librarian_decision", None)
    if not callable(replay) or not callable(read_proposal) or not callable(publish):
        raise TypeError("Safe Librarian decision session is invalid")
    try:
        existing = replay()
    except librarian_contract.LibrarianOperationError as exc:
        return _blocked_from_error(admitted, exc)
    if existing is not None:
        reference, _record_bytes = existing
        if type(reference) is not artifact_contract.SealedArtifactRef:
            raise TypeError("Safe Librarian decision replay is invalid")
        return _completed(admitted, reference)
    try:
        proposal_reference, proposal = read_proposal()
    except librarian_contract.LibrarianOperationError as exc:
        return _blocked_from_error(admitted, exc)
    scope = admitted.input["scope"]
    payload = admitted.input["payload"]
    if proposal["proposal_id"] != scope["proposal_id"]:
        raise TypeError("Safe Librarian decision proposal is invalid")
    record = {
        "schema": librarian_contract.DECISION_SCHEMA.canonical_value,
        "decision_id": payload["decision_id"],
        "proposal": proposal_reference.canonical_value,
        "decision": payload["decision"],
        "actor": admitted.actor,
        "decided_at": _utc_now(),
        "decision_reason": payload["decision_reason"],
        "effect_summary": {
            "proposal_id": proposal["proposal_id"],
            "source_relative_path": proposal["source_relative_path"],
            "target_relative_path": proposal["target_relative_path"],
            "destination_kind": proposal["destination_kind"],
            "destination_id": proposal["destination_id"],
            "reason": proposal["reason"],
        },
        "producer_request_sha256": admitted.request_sha256,
    }
    try:
        reference = publish(librarian_contract.encode_decision_record(record))
    except librarian_contract.LibrarianOperationError as exc:
        return _blocked_from_error(admitted, exc)
    if type(reference) is not artifact_contract.SealedArtifactRef:
        raise TypeError("Safe Librarian decision publication is invalid")
    return _completed(admitted, reference)


__all__ = [
    "decision_handler",
    "proposal_handler",
    "validate_decision_request",
    "validate_decision_result",
    "validate_proposal_request",
    "validate_proposal_result",
]
