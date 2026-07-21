"""Single byte-to-outcome executor for Document Curation operations."""

from __future__ import annotations

from .. import authority_runtime, librarian_placement, operation_contract
from ..authority_runtime import canonical_curation as curation_plan_apply
from ..canonical_json import sha256_bytes
from ..operation_contract.codec import decode_operation_request
from .catalog import OperationAvailability, OperationSpec
from .composition import DEFAULT_OPERATION_CATALOG


def _blocked(
    request_sha256: str,
    *,
    reason_code: str,
    next_safe_action: str,
) -> bytes:
    return operation_contract.OperationOutcome.blocked(
        request_sha256,
        reason_code=reason_code,
        next_safe_action=next_safe_action,
    ).canonical_bytes


def _request_identity(raw: object) -> str:
    if type(raw) is bytes:
        return sha256_bytes(raw)
    return sha256_bytes(b"")


def _require_effective_authority(
    request: operation_contract.OperationRequest,
    spec: OperationSpec,
) -> None:
    if request.requested_authority is not spec.admission_contract.authority_mode:
        raise ValueError("requested authority does not match executable operation")


def _validate_request_for_spec(
    request: operation_contract.OperationRequest,
    spec: OperationSpec,
) -> None:
    if spec.request_validator is not None:
        spec.request_validator(request)


def _recovery_outcome(
    request_sha256: str,
    error: authority_runtime.DurableRecoveryRequired,
) -> operation_contract.OperationOutcome | None:
    directive = error.directive
    if directive is None:
        return None
    if directive.disposition == "recoverable":
        return operation_contract.OperationOutcome.recoverable(
            request_sha256,
            recovery_owner=directive.recovery_owner,
            continuation_identity=directive.continuation_identity,
            allowed_recovery_action=directive.allowed_recovery_action,
        )
    if directive.disposition == "blocked_recovery":
        return operation_contract.OperationOutcome.blocked_recovery(
            request_sha256,
            recovery_owner=directive.recovery_owner,
            continuation_identity=directive.continuation_identity,
            reason_code=directive.reason_code,
        )
    return None


def _execute_admitted(
    admitted: operation_contract.AdmittedOperation,
    spec: OperationSpec,
    *,
    validate_result: bool = True,
) -> operation_contract.OperationOutcome:
    authority_mode = spec.admission_contract.authority_mode
    if authority_mode is operation_contract.AuthorityMode.NONE:
        result = spec.handler(admitted)
    elif authority_mode is operation_contract.AuthorityMode.READ:
        with authority_runtime.open_read(admitted) as session:
            result = spec.handler(admitted, session)
    else:
        with authority_runtime.open_write(admitted) as session:
            result = spec.handler(admitted, session)
    if (
        type(result) is not operation_contract.OperationOutcome
        or result.request_sha256 != admitted.request_sha256
    ):
        raise ValueError("operation handler returned an invalid outcome")
    if validate_result and spec.result_validator is not None:
        spec.result_validator(result)
    return result


def _is_placement_recovery(
    request: operation_contract.OperationRequest,
) -> bool:
    return (
        request.operation_kind == "librarian.placement"
        and request.action is operation_contract.LifecycleAction.RECOVER
    )


def _finish_placement_recovery(
    request: operation_contract.OperationRequest,
    recovered: operation_contract.OperationOutcome,
    spec: OperationSpec,
) -> operation_contract.OperationOutcome:
    apply_request = librarian_placement.apply_request_after_recovered_placement(
        request,
        recovered,
    )
    if apply_request is None:
        spec.result_validator(recovered)
        return recovered

    _validate_request_for_spec(apply_request, spec)
    _require_effective_authority(apply_request, spec)
    admitted = authority_runtime.admit(apply_request, spec.admission_contract)
    apply_outcome = _execute_admitted(admitted, spec)
    return librarian_placement.rebind_recovered_placement_outcome(
        request,
        apply_outcome,
    )


def execute_request_bytes(raw: bytes) -> bytes:
    """Execute one public request and return one canonical outcome."""

    if (
        type(raw) is not bytes
        or len(raw) > operation_contract.MAX_OPERATION_REQUEST_BYTES
    ):
        return _blocked(
            _request_identity(raw),
            reason_code="INVALID_REQUEST",
            next_safe_action="correct-request",
        )
    try:
        request = decode_operation_request(raw)
    except (TypeError, ValueError):
        return _blocked(
            _request_identity(raw),
            reason_code="INVALID_REQUEST",
            next_safe_action="correct-request",
        )
    try:
        spec = DEFAULT_OPERATION_CATALOG.require_spec(request.operation_kind)
    except ValueError:
        return _blocked(
            request.sha256,
            reason_code="UNKNOWN_OPERATION",
            next_safe_action="inspect",
        )
    if spec.availability is OperationAvailability.BLOCKED:
        return _blocked(
            request.sha256,
            reason_code="CAPABILITY_BLOCKED",
            next_safe_action="inspect",
        )
    if spec.availability is OperationAvailability.DEFERRED:
        return _blocked(
            request.sha256,
            reason_code="CAPABILITY_DEFERRED",
            next_safe_action="inspect",
        )
    try:
        _validate_request_for_spec(request, spec)
    except (TypeError, ValueError):
        return _blocked(
            request.sha256,
            reason_code="INVALID_REQUEST",
            next_safe_action="correct-request",
        )
    try:
        _require_effective_authority(request, spec)
        admitted = authority_runtime.admit(request, spec.admission_contract)
        placement_recovery = _is_placement_recovery(request)
        outcome = _execute_admitted(
            admitted,
            spec,
            validate_result=not placement_recovery,
        )
        if placement_recovery:
            outcome = _finish_placement_recovery(request, outcome, spec)
        return outcome.canonical_bytes
    except authority_runtime.ActivationOperationFence as exc:
        return _blocked(
            request.sha256,
            reason_code=exc.reason_code,
            next_safe_action=exc.next_safe_action,
        )
    except authority_runtime.WorkstreamInspectionFence as exc:
        return _blocked(
            request.sha256,
            reason_code=exc.reason_code,
            next_safe_action=exc.next_safe_action,
        )
    except authority_runtime.CanonicalCurationFence as exc:
        return _blocked(
            request.sha256,
            reason_code=exc.reason_code,
            next_safe_action=exc.next_safe_action,
        )
    except authority_runtime.DurableRecoveryRequired as exc:
        recovery = _recovery_outcome(request.sha256, exc)
        if recovery is not None:
            return recovery.canonical_bytes
        return _blocked(
            request.sha256,
            reason_code="ADMISSION_DENIED",
            next_safe_action="inspect",
        )
    except authority_runtime.DurableRecoveryFenceRequired as exc:
        return operation_contract.OperationOutcome.blocked_recovery(
            request.sha256,
            recovery_owner="authority-runtime",
            continuation_identity=exc.observed_evidence_sha256,
            reason_code=exc.reason_code,
        ).canonical_bytes
    except authority_runtime.CurationCleanupRequired as exc:
        return operation_contract.OperationOutcome.blocked_recovery(
            request.sha256,
            recovery_owner="canonical-curation-v2",
            continuation_identity=exc.plan_sha256,
            reason_code=exc.reason_code,
        ).canonical_bytes
    except (TypeError, ValueError, authority_runtime.AuthorityRuntimeError):
        return _blocked(
            request.sha256,
            reason_code="ADMISSION_DENIED",
            next_safe_action="inspect",
        )


__all__ = ["execute_request_bytes"]
