"""Private Authority Runtime foundation; no public parser is connected in D1a."""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Optional, Tuple

from .. import artifact_contract, operation_contract
from ..canonical_json import canonical_json_bytes, sha256_bytes


_ISSUER = object()
_SAFE_ACTION = re.compile(r"[a-z][a-z0-9_-]{1,63}")


class AuthorityRuntimeError(RuntimeError):
    """The private authority-runtime boundary rejected an unsafe operation."""


class WorkstreamInspectionFence(AuthorityRuntimeError):
    """Typed denial for the Workstream-bound inspection read path."""

    _NEXT_SAFE_ACTION = {
        "WORKSTREAM_NOT_FOUND": "choose-workstream",
        "WORKSTREAM_AMBIGUOUS": "inspect-policy",
        "WORKSTREAM_LIFECYCLE_UNSUPPORTED": "inspect-policy",
        "WORKSTREAM_HOME_MISSING": "inspect-workstream",
        "WORKSTREAM_HOME_UNSAFE": "inspect-workstream",
        "RAW_ROOT_CHANGED": "inspect-root",
        "POLICY_CHANGED": "inspect-policy",
        "WORKSTREAM_HOME_CHANGED": "inspect-workstream",
        "SCOPE_LIMIT_EXCEEDED": "narrow-scope",
        "SCOPE_UNSAFE": "inspect",
    }

    def __init__(self, message: str, *, reason_code: str) -> None:
        if (
            type(message) is not str
            or not message
            or type(reason_code) is not str
            or reason_code not in self._NEXT_SAFE_ACTION
        ):
            raise ValueError("Workstream inspection fence is invalid")
        super().__init__(message)
        self.reason_code = reason_code
        self.next_safe_action = self._NEXT_SAFE_ACTION[reason_code]


class CanonicalCurationFence(AuthorityRuntimeError):
    """Typed fail-closed outcome for one exact Stage-A Plan apply."""

    _NEXT_SAFE_ACTION = {
        "MUTATION_IN_PROGRESS": "inspect-transaction",
        "PLAN_CONFLICT": "inspect-transaction",
        "ROLLED_BACK": "inspect-workstream",
        "STALE": "inspect-workstream",
        "TARGET_CONFLICT": "inspect-workstream",
        "WRITER_BUSY": "retry",
    }

    def __init__(self, message: str, *, reason_code: str) -> None:
        if (
            type(message) is not str
            or not message
            or reason_code not in self._NEXT_SAFE_ACTION
        ):
            raise ValueError("canonical curation fence is invalid")
        super().__init__(message)
        self.reason_code = reason_code
        self.next_safe_action = self._NEXT_SAFE_ACTION[reason_code]


@dataclass(frozen=True)
class WorkstreamProjectIdentity:
    device: int
    inode: int
    mode: int
    uid: int


@dataclass(frozen=True)
class WorkstreamInspectionEvidence:
    canonical_id: str
    captured_lifecycle: str
    project_home_relative: Tuple[str, ...]
    project_identity: WorkstreamProjectIdentity


class ActivationOperationFence(AuthorityRuntimeError):
    """Typed Safe Librarian activation denial safe for public projection."""

    _REASON_CODES = frozenset(
        {
            "ALREADY_ACTIVE_DIFFERENT_REQUEST",
            "EXPLICIT_CURATION_REQUIRES_REVIEW",
            "FOUNDATION_READBACK_FAILED",
            "LEGACY_AUTHORITY_PRESENT",
            "POLICY_IDENTITY_CHANGED",
            "PRESEAL_ORPHAN",
            "PUBLICATION_COLLISION",
            "RECOVERY_SAME_REQUEST_ONLY",
            "REQUEST_MISMATCH",
            "ROOT_IDENTITY_CHANGED",
            "UNKNOWN_AUTHORITY_MEMBER",
            "UNSAFE_BOUNDARY",
            "WRITER_BUSY",
        }
    )

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        next_safe_action: str,
    ) -> None:
        if (
            type(message) is not str
            or not message
            or type(reason_code) is not str
            or reason_code not in self._REASON_CODES
            or type(next_safe_action) is not str
            or _SAFE_ACTION.fullmatch(next_safe_action) is None
        ):
            raise ValueError("activation fence is invalid")
        super().__init__(message)
        self.reason_code = reason_code
        self.next_safe_action = next_safe_action


@dataclass(frozen=True)
class _AdmissionEvidence:
    request_sha256: str
    operation_kind: str
    actor: str
    scope_sha256: str
    bounds_sha256: str
    spec_identity: str
    spec_sha256: str
    lifecycle_action: operation_contract.LifecycleAction
    authority_mode: operation_contract.AuthorityMode
    root: Optional[Path] = None
    root_identity: Optional[Tuple[int, int]] = None
    policy_identity: Optional[object] = None
    workstream_id: Optional[str] = None
    workstream_lifecycle: Optional[str] = None
    inspection_evidence: Optional[WorkstreamInspectionEvidence] = None
    handler_input: object = None
    read_profile: operation_contract.ReadProfile = operation_contract.ReadProfile.STANDARD
    write_profile: operation_contract.WriteProfile = operation_contract.WriteProfile.STANDARD
    audit_control_absent: bool = False
    audit_state: Optional[str] = None
    activation_audit_evidence: object = None
    activation_request_bytes: Optional[bytes] = None


def _runtime_session_module():
    from . import session

    return session


def __getattr__(name: str):
    if name == "PolicyIdentity":
        return _runtime_session_module().PolicyIdentity
    if name == "CurationCleanupRequired":
        from .canonical_curation_m3 import CurationCleanupRequired

        return CurationCleanupRequired
    if name in {
        "DurableEffectState",
        "DurableRecoveryDenied",
        "DurableRecoveryDirective",
        "DurableRecoveryFenceRequired",
        "DurableRecoveryRequired",
        "RecoveryToken",
        "StagedEffect",
    }:
        from . import durable

        return getattr(durable, name)
    raise AttributeError(name)


def _require_verified_admission(admitted: object) -> None:
    if not operation_contract._is_issued_admitted_operation(admitted, _ISSUER):
        raise TypeError("unverified admitted operation")


def _validate_artifact_reference(
    reference: object,
    requirement: operation_contract.ArtifactRequirement,
    label: str,
) -> None:
    if type(reference) is not artifact_contract.SealedArtifactRef:
        raise ValueError(f"{label} is invalid")
    schema = reference.schema
    if (
        schema.kind != requirement.kind
        or schema.version != requirement.version
        or schema.schema_sha256 != requirement.schema_sha256
    ):
        raise ValueError(f"{label} does not match its required schema")


def _validate_request_evidence(
    request: operation_contract.OperationRequest,
    contract: operation_contract.AdmissionContract,
) -> None:
    if set(request.scope) != set(contract.scope_schema):
        raise ValueError("operation scope must exactly match its admission contract")
    if set(request.bounds) != set(contract.bounds_schema):
        raise ValueError("operation bounds must exactly match its admission contract")
    if contract.approval_required:
        _validate_artifact_reference(
            request.approval_artifact,
            contract.approval_requirement,
            "approval artifact",
        )
    elif request.approval_artifact is not None:
        raise ValueError("approval artifact is not admitted")
    if len(request.prerequisite_artifacts) != len(contract.prerequisite_artifacts):
        raise ValueError("prerequisite artifact count is invalid")
    for reference, requirement in zip(
        request.prerequisite_artifacts,
        contract.prerequisite_artifacts,
    ):
        _validate_artifact_reference(reference, requirement, "prerequisite artifact")


def _scope_sha256(request: operation_contract.OperationRequest) -> str:
    return sha256_bytes(canonical_json_bytes(dict(request.scope)))


def _bounds_sha256(request: operation_contract.OperationRequest) -> str:
    return sha256_bytes(canonical_json_bytes(dict(request.bounds)))


def _handler_input(
    request: operation_contract.OperationRequest,
) -> MappingProxyType:
    """Seal only validated request fields that a direct owner may need."""

    return MappingProxyType(
        {
            "operation_kind": request.operation_kind,
            "action": request.action,
            "payload": request.payload,
            "bounds": request.bounds,
            "scope": request.scope,
            "approval_artifact": request.approval_artifact,
            "prerequisite_artifacts": request.prerequisite_artifacts,
        }
    )


def admit(
    request: operation_contract.OperationRequest,
    contract: operation_contract.AdmissionContract,
) -> operation_contract.AdmittedOperation:
    """Reject authority widening before any root, policy, or ledger access."""

    if type(request) is not operation_contract.OperationRequest:
        raise TypeError("operation request is invalid")
    if type(contract) is not operation_contract.AdmissionContract:
        raise TypeError("admission contract is invalid")
    if request.operation_kind != contract.operation_kind:
        raise ValueError("operation request does not match its admission contract")
    if request.action not in contract.allowed_actions:
        raise ValueError("operation action is not admitted")
    if request.claim_mode not in contract.allowed_claim_modes:
        raise ValueError("claim mode is not admitted")
    _validate_request_evidence(request, contract)
    if not operation_contract.authority_can_cover(
        request.requested_authority,
        contract.authority_mode,
    ):
        raise ValueError("requested authority cannot widen catalog authority")
    if contract.authority_mode is operation_contract.AuthorityMode.NONE:
        return operation_contract._issue_admitted_operation(
            _ISSUER,
            _AdmissionEvidence(
                request_sha256=request.sha256,
                operation_kind=request.operation_kind,
                actor=request.actor,
                scope_sha256=_scope_sha256(request),
                bounds_sha256=_bounds_sha256(request),
                spec_identity=contract.spec_identity,
                spec_sha256=contract.spec_sha256,
                lifecycle_action=request.action,
                authority_mode=operation_contract.AuthorityMode.NONE,
                handler_input=_handler_input(request),
                read_profile=contract.read_profile,
                write_profile=contract.write_profile,
            ),
        )
    if request.requested_authority is operation_contract.AuthorityMode.READ:
        return _runtime_session_module().admit_read(request, contract, _ISSUER)
    if request.requested_authority is operation_contract.AuthorityMode.WRITE:
        return _runtime_session_module().admit_write(request, contract, _ISSUER)
    raise AuthorityRuntimeError("operation authority admission is unavailable")


@contextmanager
def open_read(admitted: object):
    """Reject caller-created admissions before any read capability can open."""

    _require_verified_admission(admitted)
    if admitted.authority_mode is not operation_contract.AuthorityMode.READ:
        raise ValueError("admitted operation does not admit read")
    with _runtime_session_module().open_read_session(admitted) as session:
        yield session


@contextmanager
def open_write(admitted: object):
    """Reject caller-created admissions before any write capability can open."""

    _require_verified_admission(admitted)
    if admitted.authority_mode is not operation_contract.AuthorityMode.WRITE:
        raise ValueError("admitted operation does not admit write")
    with _runtime_session_module().open_write_session(admitted) as session:
        yield session


__all__ = ["admit", "open_read", "open_write"]
