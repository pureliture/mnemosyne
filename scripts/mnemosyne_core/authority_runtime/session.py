"""Bounded private read capabilities issued by :mod:`authority_runtime`."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Iterator, Tuple

from .. import curation_audit as curation_audit_core
from .. import (
    activation_contract,
    artifact_contract,
    ledger_runtime,
    librarian_contract,
    librarian_projection,
    operation_contract,
    safety,
)
from ..canonical_json import canonical_json_bytes, sha256_bytes
from . import (
    AuthorityRuntimeError,
    CanonicalCurationFence,
    WorkstreamInspectionEvidence,
    WorkstreamInspectionFence,
    _AdmissionEvidence,
    _handler_input,
    activation as activation_runtime,
    durable,
    librarian,
    librarian_snapshot,
    workstream_inspection,
)


# A fork child cannot safely unwind an inherited writer: doing so can make
# SQLite rollback/close I/O or retain parent-owned locks.  This private runtime
# deliberately terminates that child before it touches the inherited boundary.
_FORK_CHILD_EXIT_STATUS = 70
_AUDIT_ACTIVE = "ACTIVE"
_AUDIT_NOT_ACTIVATED = "NOT_ACTIVATED"
_AUDIT_POLICY_BLOCKED = "POLICY_BLOCKED"
_AUDIT_UNAVAILABLE = "UNAVAILABLE"
_AUDIT_BLOCKED = "BLOCKED"
_AUDIT_STATES = frozenset(
    (
        _AUDIT_ACTIVE,
        _AUDIT_NOT_ACTIVATED,
        _AUDIT_POLICY_BLOCKED,
        _AUDIT_UNAVAILABLE,
        _AUDIT_BLOCKED,
    )
)


def _exit_inherited_write_session() -> None:
    os._exit(_FORK_CHILD_EXIT_STATUS)


@dataclass(frozen=True)
class PolicyIdentity:
    """Primitive-only identity of the exact policy observed during admission."""

    raw_hash: str
    full_hash: str
    writer_control_hash: str
    foundation_hash: str
    generation: int
    source_kind: str
    source_run_id: str
    guard_epoch: int

    @classmethod
    def from_approved_policy(cls, approved_policy: object) -> "PolicyIdentity":
        fields = (
            "raw_hash",
            "full_hash",
            "writer_control_hash",
            "foundation_hash",
            "generation",
            "source_kind",
            "source_run_id",
            "guard_epoch",
        )
        try:
            values = {field: getattr(approved_policy, field) for field in fields}
        except AttributeError as exc:
            raise AuthorityRuntimeError("approved policy evidence is invalid") from exc
        return cls(**values)


def _canonical_root_identity(root: Path) -> Tuple[int, int]:
    descriptor = safety.open_verified_directory(
        root,
        require_owner_only=True,
        error_type=AuthorityRuntimeError,
    )
    try:
        info = os.fstat(descriptor)
        return info.st_dev, info.st_ino
    finally:
        os.close(descriptor)


def _evidence_from_admitted(
    admitted: operation_contract.AdmittedOperation,
) -> _AdmissionEvidence:
    evidence = getattr(admitted, "_payload", None)
    if type(evidence) is not _AdmissionEvidence:
        raise TypeError("unverified admitted operation")
    return evidence


def _validate_workstream_evidence(
    request: operation_contract.OperationRequest,
    contract: operation_contract.AdmissionContract,
    compiled_policy: object,
    *,
    allow_recovery_only: bool = False,
) -> tuple[str, str] | None:
    if "workstream_id" not in contract.scope_schema:
        return None
    workstream_id = request.scope.get("workstream_id")
    if type(workstream_id) is not str or not workstream_id:
        raise AuthorityRuntimeError("workstream evidence is invalid")
    workstreams = getattr(compiled_policy, "workstreams", ())
    matches = [
        workstream
        for workstream in workstreams
        if getattr(workstream, "id", None) == workstream_id
    ]
    if len(matches) == 1 and getattr(matches[0], "lifecycle", None) == "active":
        return workstream_id, "active"
    if (
        allow_recovery_only
        and len(matches) == 1
        and getattr(matches[0], "lifecycle", None) in {"paused", "completed"}
    ):
        return workstream_id, "recovery_only"
    raise AuthorityRuntimeError("workstream is not current and active")


def _scope_sha256(request: operation_contract.OperationRequest) -> str:
    return sha256_bytes(canonical_json_bytes(dict(request.scope)))


def _bounds_sha256(request: operation_contract.OperationRequest) -> str:
    return sha256_bytes(canonical_json_bytes(dict(request.bounds)))


def _validate_captured_workstream(
    compiled_policy: object,
    workstream_id: str | None,
    workstream_lifecycle: str | None,
) -> None:
    if workstream_id is None and workstream_lifecycle is None:
        return
    if type(workstream_id) is not str or workstream_lifecycle != "active":
        raise AuthorityRuntimeError("admitted workstream evidence is invalid")
    matches = [
        workstream
        for workstream in getattr(compiled_policy, "workstreams", ())
        if getattr(workstream, "id", None) == workstream_id
    ]
    if len(matches) != 1 or getattr(matches[0], "lifecycle", None) != "active":
        raise AuthorityRuntimeError("workstream is not current and active")


def _uses_workstream_inspection(
    request: operation_contract.OperationRequest,
    contract: operation_contract.AdmissionContract,
) -> bool:
    return (
        request.operation_kind == "inspect.scope"
        and request.requested_authority is operation_contract.AuthorityMode.READ
        and contract.read_profile is operation_contract.ReadProfile.SAFE_LIBRARIAN
        and contract.scope_schema == ("workstream_ref",)
    )


def _inspection_reference(handler_input: object) -> str:
    try:
        reference = handler_input["scope"]["workstream_ref"]
    except (KeyError, TypeError) as exc:
        raise AuthorityRuntimeError(
            "Workstream inspection reference is unavailable"
        ) from exc
    if type(reference) is not str or not reference:
        raise AuthorityRuntimeError("Workstream inspection reference is invalid")
    return reference


def _audit_control_root(root: Path) -> Path:
    return root / "_registry" / "curation"


def _audit_control_absent(root: Path) -> bool:
    try:
        return not curation_audit_core.control_root_present(_audit_control_root(root))
    except curation_audit_core.CurationAuditError as exc:
        raise AuthorityRuntimeError("curation audit control state is unavailable") from exc


def _confirm_audit_failure_state(
    root: Path,
    expected_state: str,
) -> None:
    """Fence a stale failure observation instead of silently reusing it."""

    try:
        with ledger_runtime.open_reader_session(root, immutable=True) as reader:
            reader.current_policy()
    except ledger_runtime.PolicyAdmissionError:
        observed_state = _AUDIT_POLICY_BLOCKED
    except ledger_runtime.LedgerRuntimeError:
        observed_state = _AUDIT_UNAVAILABLE
    else:
        raise AuthorityRuntimeError("curation audit availability changed")
    if observed_state != expected_state:
        raise AuthorityRuntimeError("curation audit failure state changed")


def _issue_read_admission(
    request: operation_contract.OperationRequest,
    contract: operation_contract.AdmissionContract,
    issuer: object,
    *,
    root: Path,
    root_identity: Tuple[int, int],
    policy_identity: PolicyIdentity | None,
    workstream_evidence: tuple[str, str] | None,
    inspection_evidence: WorkstreamInspectionEvidence | None,
    audit_control_absent: bool,
    audit_state: str | None,
    activation_audit_evidence: object = None,
) -> operation_contract.AdmittedOperation:
    return operation_contract._issue_admitted_operation(
        issuer,
        _AdmissionEvidence(
            request_sha256=request.sha256,
            operation_kind=request.operation_kind,
            actor=request.actor,
            scope_sha256=_scope_sha256(request),
            bounds_sha256=_bounds_sha256(request),
            spec_identity=contract.spec_identity,
            spec_sha256=contract.spec_sha256,
            lifecycle_action=request.action,
            authority_mode=operation_contract.AuthorityMode.READ,
            root=root,
            root_identity=root_identity,
            policy_identity=policy_identity,
            workstream_id=(
                workstream_evidence[0] if workstream_evidence is not None else None
            ),
            workstream_lifecycle=(
                workstream_evidence[1] if workstream_evidence is not None else None
            ),
            inspection_evidence=inspection_evidence,
            handler_input=_handler_input(request),
            read_profile=contract.read_profile,
            write_profile=contract.write_profile,
            audit_control_absent=audit_control_absent,
            audit_state=audit_state,
            activation_audit_evidence=activation_audit_evidence,
        ),
    )


def admit_read(
    request: operation_contract.OperationRequest,
    contract: operation_contract.AdmissionContract,
    issuer: object,
) -> operation_contract.AdmittedOperation:
    """Capture exact root and policy evidence without exposing a session."""

    if request.requested_authority is not operation_contract.AuthorityMode.READ:
        raise AuthorityRuntimeError("read admission requires READ authority")
    root = Path(request.root)
    root_identity = _canonical_root_identity(root)
    audit_profile = (
        contract.read_profile is operation_contract.ReadProfile.CURATION_AUDIT
    )
    if audit_profile and _audit_control_absent(root):
        activation_audit_evidence = activation_runtime.capture_audit_evidence(root)
        if (
            _canonical_root_identity(root) != root_identity
            or not _audit_control_absent(root)
            or activation_runtime.capture_audit_evidence(root)
            != activation_audit_evidence
        ):
            raise AuthorityRuntimeError("curation audit control state changed during admission")
        return _issue_read_admission(
            request,
            contract,
            issuer,
            root=root,
            root_identity=root_identity,
            policy_identity=None,
            workstream_evidence=None,
            inspection_evidence=None,
            audit_control_absent=True,
            audit_state=activation_audit_evidence.activation_state,
            activation_audit_evidence=activation_audit_evidence,
        )
    audit_state = _AUDIT_ACTIVE if audit_profile else None
    try:
        with ledger_runtime.open_reader_session(
            root,
            immutable=(
                audit_profile
                or contract.read_profile
                is operation_contract.ReadProfile.SAFE_LIBRARIAN
            ),
        ) as reader:
            if _uses_workstream_inspection(request, contract):
                resolved = workstream_inspection.resolve_workstream_for_inspection(
                    reader.compiled_policy,
                    request.scope["workstream_ref"],
                )
                inspection_evidence = (
                    workstream_inspection.capture_inspection_evidence(root, resolved)
                )
                workstream_evidence = None
            else:
                inspection_evidence = None
                workstream_evidence = _validate_workstream_evidence(
                    request,
                    contract,
                    reader.compiled_policy,
                )
            policy_identity = PolicyIdentity.from_approved_policy(reader.current_policy())
    except ledger_runtime.PolicyAdmissionError as exc:
        if not audit_profile:
            raise AuthorityRuntimeError("read admission evidence is unavailable") from exc
        policy_identity = None
        workstream_evidence = None
        inspection_evidence = None
        audit_state = _AUDIT_POLICY_BLOCKED
    except ledger_runtime.LedgerRuntimeError as exc:
        if not audit_profile:
            raise AuthorityRuntimeError("read admission evidence is unavailable") from exc
        policy_identity = None
        workstream_evidence = None
        inspection_evidence = None
        audit_state = _AUDIT_UNAVAILABLE
    activation_audit_evidence = (
        activation_runtime.capture_audit_evidence(
            root,
            runtime_state=audit_state,
        )
        if audit_profile
        else None
    )
    if (
        _canonical_root_identity(root) != root_identity
        or (audit_profile and _audit_control_absent(root))
        or (
            audit_profile
            and activation_runtime.capture_audit_evidence(
                root,
                runtime_state=audit_state,
            )
            != activation_audit_evidence
        )
    ):
        if inspection_evidence is not None:
            raise WorkstreamInspectionFence(
                "authority root changed during admission",
                reason_code="RAW_ROOT_CHANGED",
            )
        raise AuthorityRuntimeError("authority root changed during admission")
    return _issue_read_admission(
        request,
        contract,
        issuer,
        root=root,
        root_identity=root_identity,
        policy_identity=policy_identity,
        workstream_evidence=workstream_evidence,
        inspection_evidence=inspection_evidence,
        audit_control_absent=False,
        audit_state=audit_state,
        activation_audit_evidence=activation_audit_evidence,
    )


def admit_write(
    request: operation_contract.OperationRequest,
    contract: operation_contract.AdmissionContract,
    issuer: object,
) -> operation_contract.AdmittedOperation:
    """Capture write evidence while keeping legacy writer state private."""

    if request.requested_authority is not operation_contract.AuthorityMode.WRITE:
        raise AuthorityRuntimeError("write admission requires WRITE authority")
    if contract.write_profile is operation_contract.WriteProfile.CURATION_ACTIVATION:
        if request.operation_kind != "curation.activation":
            raise AuthorityRuntimeError("activation write profile is unavailable")
        activation_contract.validate_activation_request(request)
        root = Path(request.root)
        root_identity = _canonical_root_identity(root)
        activation_evidence = activation_runtime.capture_admission_evidence(
            root,
            request,
        )
        if _canonical_root_identity(root) != root_identity:
            raise AuthorityRuntimeError("authority root changed during admission")
        return operation_contract._issue_admitted_operation(
            issuer,
            _AdmissionEvidence(
                request_sha256=request.sha256,
                operation_kind=request.operation_kind,
                actor=request.actor,
                scope_sha256=_scope_sha256(request),
                bounds_sha256=_bounds_sha256(request),
                spec_identity=contract.spec_identity,
                spec_sha256=contract.spec_sha256,
                lifecycle_action=request.action,
                authority_mode=operation_contract.AuthorityMode.WRITE,
                root=root,
                root_identity=root_identity,
                policy_identity=None,
                handler_input=_handler_input(request),
                read_profile=contract.read_profile,
                write_profile=contract.write_profile,
                activation_audit_evidence=activation_evidence,
                activation_request_bytes=request.canonical_bytes,
            ),
        )
    if request.operation_kind == "memory.workspace_sync":
        root = Path(request.root)
        root_identity = _canonical_root_identity(root)
        return operation_contract._issue_admitted_operation(
            issuer,
            _AdmissionEvidence(
                request_sha256=request.sha256,
                operation_kind=request.operation_kind,
                actor=request.actor,
                scope_sha256=_scope_sha256(request),
                bounds_sha256=_bounds_sha256(request),
                spec_identity=contract.spec_identity,
                spec_sha256=contract.spec_sha256,
                lifecycle_action=request.action,
                authority_mode=operation_contract.AuthorityMode.WRITE,
                root=root,
                root_identity=root_identity,
                handler_input=_handler_input(request),
                read_profile=contract.read_profile,
                write_profile=contract.write_profile,
            ),
        )
    root = Path(request.root)
    root_identity = _canonical_root_identity(root)
    try:
        with ledger_runtime.open_writer_session(root) as writer:
            workstream_evidence = _validate_workstream_evidence(
                request,
                contract,
                writer.compiled_policy,
                allow_recovery_only=(
                    request.action is operation_contract.LifecycleAction.RECOVER
                ),
            )
            policy_identity = PolicyIdentity.from_approved_policy(writer.current_policy())
    except (ledger_runtime.LedgerRuntimeError, ledger_runtime.PolicyAdmissionError) as exc:
        if (
            contract.write_profile
            is operation_contract.WriteProfile.CURATION_PLAN_APPLY
            and str(exc) == "curation ledger lock is busy"
        ):
            raise CanonicalCurationFence(
                "another Curation writer is active",
                reason_code="WRITER_BUSY",
            ) from exc
        raise AuthorityRuntimeError("write admission evidence is unavailable") from exc
    if _canonical_root_identity(root) != root_identity:
        raise AuthorityRuntimeError("authority root changed during admission")
    return operation_contract._issue_admitted_operation(
        issuer,
        _AdmissionEvidence(
            request_sha256=request.sha256,
            operation_kind=request.operation_kind,
            actor=request.actor,
            scope_sha256=_scope_sha256(request),
            bounds_sha256=_bounds_sha256(request),
            spec_identity=contract.spec_identity,
            spec_sha256=contract.spec_sha256,
            lifecycle_action=request.action,
            authority_mode=operation_contract.AuthorityMode.WRITE,
            root=root,
            root_identity=root_identity,
            policy_identity=policy_identity,
            workstream_id=(
                workstream_evidence[0] if workstream_evidence is not None else None
            ),
            workstream_lifecycle=(
                workstream_evidence[1] if workstream_evidence is not None else None
            ),
            handler_input=_handler_input(request),
            read_profile=contract.read_profile,
            write_profile=contract.write_profile,
        ),
    )


class ReadSession:
    """A bounded read surface with no root path or SQLite capability export."""

    __slots__ = (
        "__reader",
        "__root",
        "__root_identity",
        "__identity",
        "__workstream_id",
        "__workstream_lifecycle",
        "__inspection_evidence",
        "__read_profile",
        "__audit_control_absent",
        "__audit_state",
        "__activation_audit_evidence",
        "__handler_input",
        "__active",
    )

    def __init__(
        self,
        reader: ledger_runtime.ReaderSession | None,
        root: Path,
        root_identity: Tuple[int, int],
        identity: PolicyIdentity | None,
        workstream_id: str | None,
        workstream_lifecycle: str | None,
        read_profile: operation_contract.ReadProfile,
        audit_control_absent: bool,
        audit_state: str | None,
        handler_input: object,
        activation_audit_evidence: object = None,
        inspection_evidence: WorkstreamInspectionEvidence | None = None,
    ) -> None:
        self.__reader = reader
        self.__root = root
        self.__root_identity = root_identity
        self.__identity = identity
        self.__workstream_id = workstream_id
        self.__workstream_lifecycle = workstream_lifecycle
        self.__inspection_evidence = inspection_evidence
        self.__read_profile = read_profile
        self.__audit_control_absent = audit_control_absent
        self.__audit_state = audit_state
        self.__activation_audit_evidence = activation_audit_evidence
        self.__handler_input = handler_input
        self.__active = True

    def _require_standard_profile(self) -> None:
        if self.__read_profile is not operation_contract.ReadProfile.STANDARD:
            raise ValueError("read profile does not permit this capability")

    def _require_audit_profile(self) -> None:
        if self.__read_profile is not operation_contract.ReadProfile.CURATION_AUDIT:
            raise ValueError("read profile does not permit curation audit")

    def _require_librarian_profile(self) -> None:
        if self.__read_profile is not operation_contract.ReadProfile.SAFE_LIBRARIAN:
            raise ValueError("read profile does not permit Safe Librarian inspection")

    def _require_active(self) -> None:
        if not self.__active:
            raise AuthorityRuntimeError("read session is not active")
        try:
            if _canonical_root_identity(self.__root) != self.__root_identity:
                if self.__inspection_evidence is not None:
                    raise WorkstreamInspectionFence(
                        "authority root identity changed",
                        reason_code="RAW_ROOT_CHANGED",
                    )
                raise AuthorityRuntimeError("authority root identity changed")
        except AuthorityRuntimeError as exc:
            self.__active = False
            if (
                self.__inspection_evidence is not None
                and not isinstance(exc, WorkstreamInspectionFence)
            ):
                raise WorkstreamInspectionFence(
                    "authority root identity changed",
                    reason_code="RAW_ROOT_CHANGED",
                ) from exc
            raise
        if self.__read_profile is operation_contract.ReadProfile.CURATION_AUDIT:
            try:
                control_absent = _audit_control_absent(self.__root)
            except AuthorityRuntimeError:
                self.__active = False
                raise
            if control_absent is not self.__audit_control_absent:
                self.__active = False
                raise AuthorityRuntimeError("curation audit control state changed")
            if (
                self.__activation_audit_evidence is None
                or activation_runtime.capture_audit_evidence(
                    self.__root,
                    runtime_state=(
                        None
                        if self.__audit_control_absent
                        else self.__audit_state
                    ),
                )
                != self.__activation_audit_evidence
            ):
                self.__active = False
                raise AuthorityRuntimeError("curation audit evidence changed")
            if self.__audit_state != _AUDIT_ACTIVE:
                return
        if self.__reader is None or not isinstance(self.__identity, PolicyIdentity):
            self.__active = False
            raise AuthorityRuntimeError("read session evidence is unavailable")
        try:
            observed = PolicyIdentity.from_approved_policy(
                self.__reader.current_policy()
            )
        except ledger_runtime.LedgerRuntimeError as exc:
            self.__active = False
            if self.__inspection_evidence is not None:
                raise WorkstreamInspectionFence(
                    "current policy evidence is no longer current",
                    reason_code="POLICY_CHANGED",
                ) from exc
            raise AuthorityRuntimeError(
                "current policy evidence is no longer current"
            ) from exc
        if observed != self.__identity:
            self.__active = False
            if self.__inspection_evidence is not None:
                raise WorkstreamInspectionFence(
                    "current policy identity changed",
                    reason_code="POLICY_CHANGED",
                )
            raise AuthorityRuntimeError("current policy identity changed")
        try:
            if self.__inspection_evidence is not None:
                workstream_inspection.revalidate_inspection_evidence(
                    self.__reader.compiled_policy,
                    self.__root,
                    _inspection_reference(self.__handler_input),
                    self.__inspection_evidence,
                )
            else:
                _validate_captured_workstream(
                    self.__reader.compiled_policy,
                    self.__workstream_id,
                    self.__workstream_lifecycle,
                )
        except AuthorityRuntimeError:
            self.__active = False
            raise

    def current_policy_identity(self) -> PolicyIdentity:
        self._require_standard_profile()
        self._require_active()
        return self.__identity

    def read_registered(self, identifier: str) -> tuple[tuple[object, ...], ...]:
        """Run a source-registered read only; caller-provided SQL is impossible."""

        self._require_standard_profile()
        self._require_active()
        if identifier != "schema_migrations":
            raise ValueError("registered read is unknown")
        rows = self.__reader.connection.execute(
            "SELECT version, schema_sha256, applied_by_bootstrap_id "
            "FROM schema_migrations ORDER BY version"
        ).fetchall()
        return tuple(tuple(row) for row in rows)

    def read_file(self, relative_path: str, *, max_bytes: int = 1024 * 1024) -> bytes:
        """Read an owner-controlled regular file below the admitted root."""

        self._require_standard_profile()
        self._require_active()
        if type(relative_path) is not str or not relative_path:
            raise ValueError("relative path is invalid")
        components = tuple(relative_path.split("/"))
        if any(component in ("", ".", "..") for component in components):
            raise ValueError("relative path is invalid")
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("max_bytes is invalid")
        candidate = self.__root.joinpath(*components)
        parent_fd = safety.open_verified_directory(
            candidate.parent,
            require_owner_only=True,
            error_type=AuthorityRuntimeError,
        )
        try:
            _info, raw = safety.read_regular_file_at(
                parent_fd,
                candidate.name,
                candidate,
                label="authority read",
                expected_mode=None,
                max_bytes=max_bytes,
                error_type=AuthorityRuntimeError,
            )
            return raw
        finally:
            os.close(parent_fd)

    def curation_audit_report(self) -> dict[str, object]:
        """Return the one bounded audit report allowed by the audit profile."""

        self._require_audit_profile()
        self._require_active()
        if self.__audit_state == _AUDIT_NOT_ACTIVATED:
            payload = curation_audit_core.not_activated_report()
        elif self.__audit_state == _AUDIT_POLICY_BLOCKED:
            payload = curation_audit_core.runtime_failure_report(
                curation_audit_core.AuditRuntimeFailure.POLICY_ADMISSION_BLOCKED
            )
        elif self.__audit_state == _AUDIT_UNAVAILABLE:
            payload = curation_audit_core.runtime_failure_report(
                curation_audit_core.AuditRuntimeFailure.CURATION_STATE_UNAVAILABLE
            )
        elif self.__audit_state == _AUDIT_BLOCKED:
            payload = curation_audit_core.runtime_failure_report(
                curation_audit_core.AuditRuntimeFailure.CURATION_STATE_UNAVAILABLE
            )
        else:
            if self.__reader is None:
                self.__active = False
                raise AuthorityRuntimeError("curation audit reader is unavailable")
            try:
                if (
                    self.__reader.foundation_kind
                    in {
                        ledger_runtime.FoundationKind.SAFE_LIBRARIAN_ACTIVATION_V1,
                        ledger_runtime.FoundationKind.LOCAL_SQLITE,
                    }
                ):
                    payload = curation_audit_core.report_from_findings([])
                else:
                    control_root = Path(
                        self.__reader.compiled_policy.foundation.state_root
                    )
                    if control_root != _audit_control_root(self.__root):
                        raise curation_audit_core.CurationAuditError(
                            "curation audit control root is not canonical"
                        )
                    payload = curation_audit_core.CurationIntegrityQuery(
                        self.__reader.connection,
                        control_root,
                    ).run()
            except (
                curation_audit_core.CurationAuditError,
                ledger_runtime.LedgerRuntimeError,
            ):
                payload = curation_audit_core.runtime_failure_report(
                    curation_audit_core.AuditRuntimeFailure.CURATION_STATE_UNAVAILABLE
                )
        self._require_active()
        return payload

    def activation_audit_evidence(self) -> object:
        """Return sealed activation evidence only to the fixed audit owner."""

        self._require_audit_profile()
        self._require_active()
        return self.__activation_audit_evidence

    def inspect_librarian_scope(self) -> dict[str, object]:
        """Inspect only the exact scope and bounds sealed during admission."""

        self._require_librarian_profile()
        self._require_active()
        if (
            self.__reader is None
            or not isinstance(self.__handler_input, MappingProxyType)
            or self.__handler_input.get("operation_kind") != "inspect.scope"
            or self.__inspection_evidence is None
        ):
            raise AuthorityRuntimeError("Safe Librarian evidence is unavailable")
        try:
            bounds = self.__handler_input["bounds"]
            if self.__inspection_evidence.captured_lifecycle != "active":
                result = workstream_inspection.inspect_frozen_scope(
                    root=self.__root,
                    root_identity=self.__root_identity,
                    evidence=self.__inspection_evidence,
                    bounds=bounds,
                )
            else:
                try:
                    result = librarian.inspect_scope(
                        root=self.__root,
                        compiled_policy=self.__reader.compiled_policy,
                        relative_path="/".join(
                            self.__inspection_evidence.project_home_relative
                        ),
                        max_items=bounds["max_items"],
                        max_depth=bounds["max_depth"],
                        max_hint_bytes=bounds["max_hint_bytes"],
                    )
                except librarian.LibrarianScopeError as exc:
                    result = {
                        "status": "BLOCKED",
                        "reason_code": exc.reason_code,
                        "next_safe_action": exc.next_safe_action,
                    }
        except (KeyError, TypeError) as exc:
            raise AuthorityRuntimeError("Safe Librarian evidence is invalid") from exc
        self._require_active()
        if result.get("status") == "BLOCKED":
            return result
        return {"status": "COMPLETED", "result": result}

    def read_librarian_records(
        self,
    ) -> dict[
        str,
        tuple[tuple[artifact_contract.SealedArtifactRef, bytes], ...],
    ]:
        """Read only finalized Safe Librarian records from immutable D1a history."""

        self._require_librarian_profile()
        self._require_active()
        if (
            not isinstance(self.__handler_input, MappingProxyType)
            or self.__handler_input.get("operation_kind")
            not in {"inspect.pending", "inspect.history"}
        ):
            raise AuthorityRuntimeError("Safe Librarian record evidence is unavailable")
        records = durable._read_finalized_artifacts(
            self.__root,
            root_identity=self.__root_identity,
            effect_prefixes=librarian_projection.EFFECT_PREFIXES,
            offset=0,
            max_items=librarian_projection.READ_LIMIT,
        )
        try:
            evidence = librarian_projection.partition_finalized_records(records)
        except TypeError as exc:
            raise AuthorityRuntimeError(
                "Safe Librarian record projection is invalid"
            ) from exc
        self._require_active()
        return evidence

    def _close(self) -> None:
        self.__active = False


class WriteSession:
    """A bounded durable-write surface with no raw root or SQLite capability export."""

    __slots__ = (
        "__coordinator",
        "__revalidate",
        "__on_invalidate",
        "__outstanding_token",
        "__recovery_directive",
        "__coordinator_invalidation",
        "__active",
        "__owner_pid",
    )

    def __init__(
        self,
        coordinator: durable.DurableCoordinator,
        revalidate,
        on_invalidate,
    ) -> None:
        self.__coordinator = coordinator
        self.__revalidate = revalidate
        self.__on_invalidate = on_invalidate
        self.__outstanding_token = None
        self.__recovery_directive = None
        self.__coordinator_invalidation = None
        self.__active = True
        self.__owner_pid = os.getpid()

    def _mark_coordinator_invalidated(self, error: AuthorityRuntimeError) -> None:
        """Record guard drift until the in-flight coordinator call can unwind."""

        if self.__coordinator_invalidation is None:
            self.__coordinator_invalidation = error

    def _finish_coordinator_invalidation(
        self,
        error: BaseException,
    ) -> None:
        """Close after a coordinator revocation or an exact recovery outcome."""

        if isinstance(error, durable.DurableRecoveryRequired) and error.directive:
            self.__outstanding_token = error.directive.token
            self.__recovery_directive = error.directive
        elif isinstance(error, durable.DurableRecoveryFenceRequired):
            pass
        elif self.__coordinator_invalidation is None:
            return
        try:
            self._close()
        except BaseException as cleanup_error:
            _raise_unexpected_write_cleanup(
                cleanup_error,
                body_error=error,
                message="write session cleanup failed",
            )

    def _unavailable_token_error(
        self,
        token: durable.RecoveryToken,
        error: AuthorityRuntimeError,
    ) -> durable.DurableRecoveryRequired:
        """Keep private coordinator availability failures off the public surface."""

        recovery_error = self.__coordinator._recovery_required_for_token(
            token,
            message="durable snapshot state is unavailable",
            reason_code="RECOVERY_STATE_UNAVAILABLE",
        )
        self.__outstanding_token = token
        self.__recovery_directive = recovery_error.directive
        self._invalidate_and_close(error, body_error=recovery_error)
        return recovery_error

    def _recovery_error_for_outstanding(
        self,
        message: str,
        *,
        reason_code: str,
    ) -> durable.DurableRecoveryRequired | None:
        if self.__recovery_directive is not None:
            return durable.DurableRecoveryRequired(
                message,
                directive=self.__recovery_directive,
            )
        if self.__outstanding_token is None:
            return None
        return self.__coordinator._recovery_required_for_token(
            self.__outstanding_token,
            message=message,
            reason_code=reason_code,
        )

    def _recovery_error_for_body(
        self,
        body_error: BaseException,
    ) -> BaseException:
        if isinstance(
            body_error,
            (
                durable.DurableCapabilityDenied,
                durable.DurableRecoveryRequired,
                durable.DurableRecoveryDenied,
                durable.DurableRecoveryFenceRequired,
            ),
        ):
            return body_error
        recovery_error = self._recovery_error_for_outstanding(
            "durable write session was interrupted after a possible effect",
            reason_code="RECOVERY_SESSION_INTERRUPTED",
        )
        if recovery_error is None:
            return body_error
        recovery_error.__cause__ = body_error
        return recovery_error

    def _require_exact_outstanding_token(self, token: object) -> None:
        if (
            self.__outstanding_token is not None
            and token != self.__outstanding_token
        ):
            raise self.__coordinator._recovery_required_for_token(
                self.__outstanding_token,
                message="durable recovery token does not match the outstanding effect",
                reason_code="RECOVERY_TOKEN_MISMATCH",
            )

    def _invalidate_and_close(
        self,
        invalidation_error: AuthorityRuntimeError,
        *,
        body_error: BaseException,
    ) -> None:
        self.__on_invalidate(invalidation_error)
        try:
            self._close()
        except BaseException as cleanup_error:
            _raise_unexpected_write_cleanup(
                cleanup_error,
                body_error=body_error,
                message="write session cleanup failed",
            )

    def _require_active(self, token: durable.RecoveryToken | None = None) -> None:
        if os.getpid() != self.__owner_pid:
            _exit_inherited_write_session()
        if not self.__active:
            if (
                type(token) is durable.RecoveryToken
                and self.__recovery_directive is not None
            ):
                raise durable.DurableRecoveryRequired(
                    "write session is not active; durable recovery is required",
                    directive=self.__recovery_directive,
                )
            raise AuthorityRuntimeError("write session is not active")
        try:
            self.__revalidate()
        except AuthorityRuntimeError as exc:
            recovery_error = None
            try:
                if type(token) is durable.RecoveryToken:
                    recovery_error = self.__coordinator._block_for_token(
                        token,
                        message=str(exc),
                        reason_code="RECOVERY_ADMISSION_DRIFT",
                    )
                    self.__outstanding_token = token
                    self.__recovery_directive = recovery_error.directive
            except BaseException as block_error:
                self._invalidate_and_close(exc, body_error=block_error)
                raise
            self._invalidate_and_close(exc, body_error=recovery_error or exc)
            if recovery_error is not None:
                raise recovery_error from exc
            raise

    def prepare(
        self,
        effect: durable.StagedEffect,
    ) -> durable.RecoveryToken:
        if type(effect) is not durable.StagedEffect:
            raise TypeError("durable effect is invalid")
        if self.__outstanding_token is not None:
            raise AuthorityRuntimeError("write session already has a durable effect")
        self._require_active()
        try:
            token = self.__coordinator.prepare(effect)
        except durable.DurableCapabilityDenied:
            raise
        except durable.DurableRecoveryRequired as exc:
            self._finish_coordinator_invalidation(exc)
            if exc.directive is not None:
                self.__outstanding_token = exc.directive.token
            raise
        except AuthorityRuntimeError as exc:
            self._finish_coordinator_invalidation(exc)
            raise
        self.__outstanding_token = token
        return token

    def _replay_finalized(
        self,
        effect_id: str,
        target_relative_path: str,
    ) -> tuple[artifact_contract.SealedArtifactRef, bytes] | None:
        """Internal replay seam used only by profile-gated wrappers."""

        if self.__outstanding_token is not None:
            raise AuthorityRuntimeError("write session already has a durable effect")
        self._require_active()
        return self.__coordinator.replay_finalized(
            effect_id,
            target_relative_path,
        )

    def _read_finalized_artifact(
        self,
        effect_id: str,
        target_relative_path: str,
    ) -> tuple[artifact_contract.SealedArtifactRef, bytes] | None:
        """Internal predecessor-read seam for profile-gated wrappers."""

        if self.__outstanding_token is not None:
            raise AuthorityRuntimeError("write session already has a durable effect")
        self._require_active()
        return self.__coordinator.read_finalized_artifact(
            effect_id,
            target_relative_path,
        )

    def _recover_public_continuation(
        self,
        continuation_identity: str,
        producer_request_sha256: str,
    ) -> artifact_contract.SealedArtifactRef | None:
        """Resolve and consume a public continuation without exposing its token."""

        if self.__outstanding_token is not None:
            raise AuthorityRuntimeError("write session already has a durable effect")
        self._require_active()
        token = self.__coordinator.resolve_public_continuation(
            continuation_identity,
            producer_request_sha256,
        )
        return self.recover(token)

    def _fence_root_for_owner(self, *, reason_code: str) -> None:
        """Allow only a profile wrapper to publish a typed root stop."""

        self._require_active()
        try:
            self.__coordinator.fence_root_for_owner(reason_code=reason_code)
        except durable.DurableRecoveryFenceRequired as exc:
            self._finish_coordinator_invalidation(exc)
            raise

    @contextmanager
    def _canonical_curation_gate(self) -> Iterator[None]:
        """Hold the root mutation gate for one complete profile-owned Plan."""

        self._require_active()
        with self.__coordinator._mutation_gate():
            yield

    def _revalidate_canonical_curation(self) -> None:
        """Recheck policy/lifecycle without revoking rollback capability."""

        if os.getpid() != self.__owner_pid or not self.__active:
            raise AuthorityRuntimeError("write session is not active")
        self.__revalidate()

    def publish(self, token: durable.RecoveryToken):
        self._require_exact_outstanding_token(token)
        self._require_active(token)
        prior_token = self.__outstanding_token
        self.__outstanding_token = token
        try:
            return self.__coordinator.publish(token)
        except durable.DurableCapabilityDenied:
            self.__outstanding_token = prior_token
            raise
        except durable.DurableRecoveryDenied as exc:
            self.__outstanding_token = prior_token
            self._finish_coordinator_invalidation(exc)
            raise
        except durable.DurableRecoveryRequired as exc:
            self._finish_coordinator_invalidation(exc)
            raise
        except durable.DurableRecoveryFenceRequired as exc:
            self._finish_coordinator_invalidation(exc)
            raise
        except AuthorityRuntimeError as exc:
            raise self._unavailable_token_error(token, exc) from exc

    def finalize(self, token: durable.RecoveryToken):
        self._require_exact_outstanding_token(token)
        self._require_active(token)
        prior_token = self.__outstanding_token
        self.__outstanding_token = token
        try:
            result = self.__coordinator.finalize(token)
        except durable.DurableCapabilityDenied:
            self.__outstanding_token = prior_token
            raise
        except durable.DurableRecoveryDenied as exc:
            self.__outstanding_token = prior_token
            self._finish_coordinator_invalidation(exc)
            raise
        except durable.DurableRecoveryRequired as exc:
            self._finish_coordinator_invalidation(exc)
            raise
        except durable.DurableRecoveryFenceRequired as exc:
            self._finish_coordinator_invalidation(exc)
            raise
        except AuthorityRuntimeError as exc:
            raise self._unavailable_token_error(token, exc) from exc
        self.__outstanding_token = None
        return result

    def recover(self, token: durable.RecoveryToken):
        self._require_exact_outstanding_token(token)
        self._require_active(token)
        prior_token = self.__outstanding_token
        self.__outstanding_token = token
        try:
            result = self.__coordinator.recover(token)
        except durable.DurableCapabilityDenied:
            self.__outstanding_token = prior_token
            raise
        except durable.DurableRecoveryDenied as exc:
            self.__outstanding_token = prior_token
            self._finish_coordinator_invalidation(exc)
            raise
        except durable.DurableRecoveryRequired as exc:
            self._finish_coordinator_invalidation(exc)
            raise
        except durable.DurableRecoveryFenceRequired as exc:
            self._finish_coordinator_invalidation(exc)
            raise
        except AuthorityRuntimeError as exc:
            raise self._unavailable_token_error(token, exc) from exc
        self.__outstanding_token = None
        return result

    def _close(self) -> None:
        if os.getpid() != self.__owner_pid:
            _exit_inherited_write_session()
        if self.__active:
            self.__active = False
            self.__coordinator.close()


class WorkspaceSyncSession:
    """Apply one validated raw-memory-sync Plan without exporting root access."""

    __slots__ = ("__root", "__evidence")

    def __init__(self, root: Path, evidence: _AdmissionEvidence) -> None:
        self.__root = root
        self.__evidence = evidence

    @staticmethod
    def _blocked(reason_code: str, next_safe_action: str) -> dict[str, str]:
        return {
            "reason_code": reason_code,
            "next_safe_action": next_safe_action,
        }

    @staticmethod
    def _publish(path: Path, content: bytes) -> None:
        safety.publish_bytes_atomic_no_replace(
            path,
            content,
            label="workspace sync staging file",
            mode=0o600,
            create_parent=True,
            collision_error=f"workspace sync staging file exists: {path}",
            final_identity_error=f"workspace sync staging identity changed: {path}",
            parent_error=f"workspace sync staging parent is unsafe: {path.parent}",
            error_type=AuthorityRuntimeError,
            after_fd_readback=lambda _path, _fd, _directory_fd: None,
        )

    @staticmethod
    def _remove(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def apply_workspace_sync_plan(self) -> dict[str, object]:
        evidence = self.__evidence
        if (
            evidence.operation_kind != "memory.workspace_sync"
            or evidence.lifecycle_action is not operation_contract.LifecycleAction.APPLY
            or evidence.root_identity is None
            or not isinstance(evidence.handler_input, MappingProxyType)
        ):
            raise AuthorityRuntimeError("workspace sync capability is unavailable")
        plan_text = evidence.handler_input["payload"]["plan_text"]
        plan_sha256 = evidence.handler_input["scope"]["plan_sha256"]
        if sha256_bytes(plan_text.encode("utf-8")) != plan_sha256:
            return self._blocked("PLAN_MISMATCH", "create-plan")
        plan = json.loads(plan_text)
        workspace = plan["workspace"]
        snapshot = self.__root / "memory" / workspace / "snapshot.md"
        registry = self.__root / "memory" / "workspaces.yml"
        history_prefix = f"memory/{workspace}/history/"
        effects = {effect["path"]: effect for effect in plan["effects"]}
        history_paths = [path for path in effects if path.startswith(history_prefix)]
        if set(plan.get("bases", {})) != {
            "memory/workspaces.yml",
            f"memory/{workspace}/snapshot.md",
        } or len(history_paths) != 1 or set(effects) != {
            f"memory/{workspace}/snapshot.md",
            history_paths[0],
        }:
            return self._blocked("PLAN_MISMATCH", "create-plan")
        history = self.__root / history_paths[0]
        receipt = self.__root / "memory" / "_receipts" / "workspace-sync" / f"{plan_sha256}.json"
        targets = (snapshot, history, receipt)
        try:
            for target in targets:
                safety.require_no_symlink_components(
                    target,
                    self.__root,
                    "workspace sync target",
                    error_type=AuthorityRuntimeError,
                )
            if any(
                type(effect.get("final_text")) is not str
                or sha256_bytes(effect["final_text"].encode("utf-8"))
                != effect.get("final_sha256")
                for effect in effects.values()
            ):
                return self._blocked("PLAN_MISMATCH", "create-plan")
        except AuthorityRuntimeError:
            return self._blocked("PATH_UNSAFE", "inspect")

        memory_fd = safety.open_verified_directory(
            self.__root / "memory",
            require_owner_only=False,
            error_type=AuthorityRuntimeError,
        )
        try:
            try:
                fcntl.flock(memory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return self._blocked("WRITER_BUSY", "retry")
            try:
                original_snapshot = snapshot.read_bytes()
                registry_bytes = registry.read_bytes()
            except OSError:
                return self._blocked("PATH_UNSAFE", "inspect")
            if (
                sha256_bytes(original_snapshot) != plan["bases"][f"memory/{workspace}/snapshot.md"]
                or sha256_bytes(registry_bytes) != plan["bases"]["memory/workspaces.yml"]
                or history.exists()
                or receipt.exists()
            ):
                return self._blocked("BASE_CHANGED", "create-plan")

            tag = plan_sha256[:20]
            history_stage = history.with_name(f".{history.name}.{tag}.stage")
            snapshot_stage = snapshot.with_name(f".{snapshot.name}.{tag}.stage")
            receipt_stage = receipt.with_name(f".{receipt.name}.{tag}.stage")
            rollback_stage = snapshot.with_name(f".{snapshot.name}.{tag}.rollback")
            stage_paths = (history_stage, snapshot_stage, receipt_stage, rollback_stage)
            installed_history = False
            installed_snapshot = False
            installed_receipt = False
            readback_failed = False
            receipt_value = {
                "schema": "mnemosyne-workspace-sync-receipt-v1",
                "schema_version": 1,
                "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "plan_sha256": plan_sha256,
                "operation_sha256": evidence.request_sha256,
                "claim_mode": "HISTORICAL",
                "effects": [
                    {"path": path, "sha256": effect["final_sha256"]}
                    for path, effect in sorted(effects.items())
                ],
            }
            receipt_bytes = canonical_json_bytes(receipt_value) + b"\n"
            try:
                self._publish(history_stage, effects[history_paths[0]]["final_text"].encode("utf-8"))
                self._publish(snapshot_stage, effects[f"memory/{workspace}/snapshot.md"]["final_text"].encode("utf-8"))
                self._publish(receipt_stage, receipt_bytes)
                os.replace(history_stage, history)
                installed_history = True
                os.replace(snapshot_stage, snapshot)
                installed_snapshot = True
                os.replace(receipt_stage, receipt)
                installed_receipt = True
                readback_failed = (
                    sha256_bytes(history.read_bytes()) != effects[history_paths[0]]["final_sha256"]
                    or sha256_bytes(snapshot.read_bytes())
                    != effects[f"memory/{workspace}/snapshot.md"]["final_sha256"]
                    or receipt.read_bytes() != receipt_bytes
                )
                if readback_failed:
                    raise OSError("workspace sync readback mismatch")
            except (OSError, AuthorityRuntimeError):
                if installed_receipt:
                    self._remove(receipt)
                if installed_history:
                    self._remove(history)
                if installed_snapshot:
                    self._publish(rollback_stage, original_snapshot)
                    os.replace(rollback_stage, snapshot)
                for path in stage_paths:
                    self._remove(path)
                for directory in (receipt.parent, receipt.parent.parent, history.parent):
                    try:
                        directory.rmdir()
                    except OSError:
                        pass
                return self._blocked(
                    "READBACK_MISMATCH" if readback_failed else "APPLY_FAILED",
                    "create-plan",
                )
            return {
                "claim_mode": "HISTORICAL",
                "history_path": history_paths[0],
                "snapshot_path": f"memory/{workspace}/snapshot.md",
                "receipt_path": str(receipt.relative_to(self.__root)),
                "plan_sha256": plan_sha256,
            }
        finally:
            os.close(memory_fd)


class CurationPlanApplySession:
    """Profile-gated whole-Plan apply with no raw root or durable API export."""

    __slots__ = ("__writer", "__root", "__compiled_policy", "__evidence")

    def __init__(
        self,
        writer: WriteSession,
        root: Path,
        compiled_policy: object,
        evidence: _AdmissionEvidence,
    ) -> None:
        self.__writer = writer
        self.__root = root
        self.__compiled_policy = compiled_policy
        self.__evidence = evidence

    def apply_curation_plan(self) -> dict[str, object]:
        if (
            self.__evidence.write_profile
            is not operation_contract.WriteProfile.CURATION_PLAN_APPLY
            or self.__evidence.operation_kind != "curation.plan_apply"
            or self.__evidence.lifecycle_action
            is not operation_contract.LifecycleAction.APPLY
            or self.__evidence.root_identity is None
            or not isinstance(self.__evidence.handler_input, MappingProxyType)
        ):
            raise AuthorityRuntimeError("Curation Plan apply capability is unavailable")
        from . import canonical_curation as curation_transaction
        from . import canonical_curation_m3 as curation_transaction_m3

        plan_value = self.__evidence.handler_input.get("payload", {}).get("plan", {})
        plan_schema = plan_value.get("schema")
        if plan_schema == "mnemosyne-canonical-curation-plan-v2":
            runtime = curation_transaction_m3
            decode_input = runtime.decode_admitted_input
        elif plan_schema == "mnemosyne-context-bound-curation-plan-v1":
            runtime = curation_transaction
            decode_input = runtime.decode_context_admitted_input
        else:
            runtime = curation_transaction
            decode_input = runtime.decode_admitted_input
        (
            plan,
            decision,
            decision_sha256,
            max_total_bytes,
            review_package_directory,
        ) = decode_input(self.__evidence.handler_input)
        try:
            with self.__writer._canonical_curation_gate():
                return runtime.apply_plan(
                    root=self.__root,
                    root_identity=self.__evidence.root_identity,
                    compiled_policy=self.__compiled_policy,
                    plan=plan,
                    decision=decision,
                    review_package_directory=review_package_directory,
                    request_sha256=self.__evidence.request_sha256,
                    decision_sha256=decision_sha256,
                    max_total_bytes=max_total_bytes,
                    revalidate=self.__writer._revalidate_canonical_curation,
                )
        except curation_transaction_m3.CurationCleanupRequired:
            raise
        except curation_transaction.CurationRecoveryRequired:
            self.__writer._fence_root_for_owner(
                reason_code="CURATION_PLAN_RECOVERY_REQUIRED"
            )
            raise AssertionError("Curation Plan recovery fence returned unexpectedly")


class LibrarianRecordSession:
    """Profile-gated record publication with no generic durable methods."""

    __slots__ = ("__writer", "__root", "__compiled_policy", "__evidence")

    def __init__(
        self,
        writer: WriteSession,
        root: Path,
        compiled_policy: object,
        evidence: _AdmissionEvidence,
    ) -> None:
        self.__writer = writer
        self.__root = root
        self.__compiled_policy = compiled_policy
        self.__evidence = evidence

    def _require_proposal_operation(self) -> MappingProxyType:
        if (
            self.__evidence.write_profile
            is not operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD
            or self.__evidence.operation_kind != "librarian.proposal"
            or self.__evidence.lifecycle_action
            is not operation_contract.LifecycleAction.APPLY
            or not isinstance(self.__evidence.handler_input, MappingProxyType)
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian proposal capability is unavailable"
            )
        self.__writer._require_active()
        return self.__evidence.handler_input

    def _require_decision_operation(self) -> MappingProxyType:
        if (
            self.__evidence.write_profile
            is not operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD
            or self.__evidence.operation_kind != "librarian.decision"
            or self.__evidence.lifecycle_action
            is not operation_contract.LifecycleAction.APPLY
            or not isinstance(self.__evidence.handler_input, MappingProxyType)
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian decision capability is unavailable"
            )
        self.__writer._require_active()
        return self.__evidence.handler_input

    def _require_record_recovery(self) -> MappingProxyType:
        if (
            self.__evidence.write_profile
            is not operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD
            or self.__evidence.operation_kind
            not in {"librarian.proposal", "librarian.decision"}
            or self.__evidence.lifecycle_action
            is not operation_contract.LifecycleAction.RECOVER
            or not isinstance(self.__evidence.handler_input, MappingProxyType)
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian record recovery capability is unavailable"
            )
        self.__writer._require_active()
        return self.__evidence.handler_input

    def recover_librarian_record(self) -> artifact_contract.SealedArtifactRef:
        admitted_input = self._require_record_recovery()
        recovery = admitted_input["payload"]["recovery"]
        reference = self.__writer._recover_public_continuation(
            recovery["continuation_identity"],
            recovery["producer_request_sha256"],
        )
        proposal_id = admitted_input["scope"]["proposal_id"]
        if self.__evidence.operation_kind == "librarian.proposal":
            expected_schema = librarian_contract.PROPOSAL_SCHEMA
            expected_path = librarian_contract.proposal_artifact_path(proposal_id)
        else:
            expected_schema = librarian_contract.DECISION_SCHEMA
            expected_path = librarian_contract.decision_artifact_path(proposal_id)
        if (
            type(reference) is not artifact_contract.SealedArtifactRef
            or reference.schema != expected_schema
            or reference.canonical_path != expected_path
            or reference.media_type != "application/json"
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian recovered record is invalid"
            )
        return reference

    def observe_librarian_proposal(self) -> dict[str, object]:
        admitted_input = self._require_proposal_operation()
        return librarian_snapshot.observe_proposal(
            root=self.__root,
            compiled_policy=self.__compiled_policy,
            scope=dict(admitted_input["scope"]),
            bounds=dict(admitted_input["bounds"]),
            payload=dict(admitted_input["payload"]),
        )

    def existing_librarian_proposal(
        self,
    ) -> tuple[artifact_contract.SealedArtifactRef, bytes] | None:
        admitted_input = self._require_proposal_operation()
        proposal_id = admitted_input["scope"]["proposal_id"]
        target_path = librarian_contract.proposal_artifact_path(proposal_id)
        try:
            replay = self.__writer._replay_finalized(
                "safe-librarian-proposal-" + proposal_id[2:],
                target_path,
            )
        except durable.DurableRecoveryDenied as exc:
            if exc.reason_code != "RECOVERY_ADMISSION_MISMATCH":
                raise
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian proposal id belongs to different evidence",
                reason_code="PROPOSAL_MISMATCH",
                next_safe_action="correct-request",
            ) from exc
        if replay is None:
            return None
        reference, record_bytes = replay
        record = librarian_contract.decode_proposal_record(record_bytes)
        scope = admitted_input["scope"]
        payload = admitted_input["payload"]
        if (
            reference.schema != librarian_contract.PROPOSAL_SCHEMA
            or reference.canonical_path != target_path
            or record["proposal_id"] != proposal_id
            or record["producer_request_sha256"] != self.__evidence.request_sha256
            or record["actor"] != self.__evidence.actor
            or record["source_relative_path"] != scope["source_relative_path"]
            or record["target_relative_path"] != scope["target_relative_path"]
            or record["destination_kind"] != payload["destination_kind"]
            or record["destination_id"] != payload["destination_id"]
            or record["reason"] != payload["reason"]
            or record["bounds"] != dict(admitted_input["bounds"])
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian proposal replay evidence is invalid"
            )
        return reference, record_bytes

    def publish_librarian_proposal(
        self,
        record_bytes: object,
    ) -> artifact_contract.SealedArtifactRef:
        admitted_input = self._require_proposal_operation()
        record = librarian_contract.decode_proposal_record(record_bytes)
        scope = admitted_input["scope"]
        payload = admitted_input["payload"]
        bounds = admitted_input["bounds"]
        if (
            record["proposal_id"] != scope["proposal_id"]
            or record["producer_request_sha256"] != self.__evidence.request_sha256
            or record["actor"] != self.__evidence.actor
            or record["source_relative_path"] != scope["source_relative_path"]
            or record["target_relative_path"] != scope["target_relative_path"]
            or record["destination_kind"] != payload["destination_kind"]
            or record["destination_id"] != payload["destination_id"]
            or record["reason"] != payload["reason"]
            or record["bounds"] != dict(bounds)
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian proposal record widens admitted evidence"
            )
        current = self.observe_librarian_proposal()
        if (
            record["source_snapshot"] != current["source_snapshot"]
            or record["target_absent"] != current["target_absent"]
        ):
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian proposal evidence changed before publication",
                reason_code="SOURCE_CHANGED",
                next_safe_action="create-proposal",
            )
        proposal_id = record["proposal_id"]
        target_path = librarian_contract.proposal_artifact_path(proposal_id)
        manifest_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "artifact_sha256": sha256_bytes(record_bytes),
                    "canonical_path": target_path,
                    "producer_request_sha256": self.__evidence.request_sha256,
                    "schema": librarian_contract.PROPOSAL_SCHEMA.canonical_value,
                }
            )
        )
        reference = artifact_contract.SealedArtifactRef(
            schema=librarian_contract.PROPOSAL_SCHEMA,
            canonical_path=target_path,
            artifact_sha256=sha256_bytes(record_bytes),
            manifest_sha256=manifest_sha256,
            producer_operation_sha256=self.__evidence.spec_sha256,
            byte_length=len(record_bytes),
            media_type="application/json",
        )
        effect = durable.StagedEffect(
            effect_id="safe-librarian-proposal-" + proposal_id[2:],
            target_relative_path=target_path,
            artifact_ref=reference,
            artifact_bytes=record_bytes,
        )
        token = self.__writer.prepare(effect)
        published = self.__writer.publish(token)
        finalized = self.__writer.finalize(token)
        if published != reference or finalized != reference:
            raise AuthorityRuntimeError(
                "Safe Librarian proposal readback is invalid"
            )
        return reference

    def read_librarian_proposal(
        self,
    ) -> tuple[artifact_contract.SealedArtifactRef, dict[str, object]]:
        admitted_input = self._require_decision_operation()
        references = admitted_input["prerequisite_artifacts"]
        proposal_id = admitted_input["scope"]["proposal_id"]
        expected_path = librarian_contract.proposal_artifact_path(proposal_id)
        if (
            type(references) is not tuple
            or len(references) != 1
            or type(references[0]) is not artifact_contract.SealedArtifactRef
        ):
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian proposal reference is unavailable",
                reason_code="PROPOSAL_MISMATCH",
                next_safe_action="correct-request",
            )
        requested_reference = references[0]
        if (
            requested_reference.schema != librarian_contract.PROPOSAL_SCHEMA
            or requested_reference.canonical_path != expected_path
            or requested_reference.media_type != "application/json"
        ):
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian proposal reference does not match the request",
                reason_code="PROPOSAL_MISMATCH",
                next_safe_action="correct-request",
            )
        existing = self.__writer._read_finalized_artifact(
            "safe-librarian-proposal-" + proposal_id[2:],
            expected_path,
        )
        if existing is None:
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian proposal does not exist",
                reason_code="PROPOSAL_MISMATCH",
                next_safe_action="correct-request",
            )
        authoritative_reference, proposal_bytes = existing
        if authoritative_reference != requested_reference:
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian proposal reference is not authoritative",
                reason_code="PROPOSAL_MISMATCH",
                next_safe_action="correct-request",
            )
        proposal = librarian_contract.decode_proposal_record(proposal_bytes)
        if proposal["proposal_id"] != proposal_id:
            raise AuthorityRuntimeError(
                "Safe Librarian proposal record identity is invalid"
            )
        return authoritative_reference, proposal

    def existing_librarian_decision(
        self,
    ) -> tuple[artifact_contract.SealedArtifactRef, bytes] | None:
        admitted_input = self._require_decision_operation()
        proposal_id = admitted_input["scope"]["proposal_id"]
        target_path = librarian_contract.decision_artifact_path(proposal_id)
        try:
            replay = self.__writer._replay_finalized(
                "safe-librarian-decision-" + proposal_id[2:],
                target_path,
            )
        except durable.DurableRecoveryDenied as exc:
            if exc.reason_code != "RECOVERY_ADMISSION_MISMATCH":
                raise
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian proposal already has a different decision",
                reason_code="DECISION_MISMATCH",
                next_safe_action="inspect-pending",
            ) from exc
        if replay is None:
            return None
        reference, record_bytes = replay
        record = librarian_contract.decode_decision_record(record_bytes)
        prerequisite = admitted_input["prerequisite_artifacts"][0]
        payload = admitted_input["payload"]
        if (
            reference.schema != librarian_contract.DECISION_SCHEMA
            or reference.canonical_path != target_path
            or record["decision_id"] != payload["decision_id"]
            or record["proposal"] != prerequisite.canonical_value
            or record["decision"] != payload["decision"]
            or record["actor"] != self.__evidence.actor
            or record["decision_reason"] != payload["decision_reason"]
            or record["producer_request_sha256"]
            != self.__evidence.request_sha256
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian decision replay evidence is invalid"
            )
        return reference, record_bytes

    def publish_librarian_decision(
        self,
        record_bytes: object,
    ) -> artifact_contract.SealedArtifactRef:
        admitted_input = self._require_decision_operation()
        record = librarian_contract.decode_decision_record(record_bytes)
        payload = admitted_input["payload"]
        proposal_id = admitted_input["scope"]["proposal_id"]
        prerequisite = admitted_input["prerequisite_artifacts"][0]
        if (
            record["decision_id"] != payload["decision_id"]
            or record["proposal"] != prerequisite.canonical_value
            or record["decision"] != payload["decision"]
            or record["actor"] != self.__evidence.actor
            or record["decision_reason"] != payload["decision_reason"]
            or record["producer_request_sha256"]
            != self.__evidence.request_sha256
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian decision record widens admitted evidence"
            )
        authoritative_reference, proposal = self.read_librarian_proposal()
        expected_summary = {
            "proposal_id": proposal_id,
            "source_relative_path": proposal["source_relative_path"],
            "target_relative_path": proposal["target_relative_path"],
            "destination_kind": proposal["destination_kind"],
            "destination_id": proposal["destination_id"],
            "reason": proposal["reason"],
        }
        if (
            record["proposal"] != authoritative_reference.canonical_value
            or record["effect_summary"] != expected_summary
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian decision does not match its proposal"
            )
        target_path = librarian_contract.decision_artifact_path(proposal_id)
        manifest_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "artifact_sha256": sha256_bytes(record_bytes),
                    "canonical_path": target_path,
                    "producer_request_sha256": self.__evidence.request_sha256,
                    "schema": librarian_contract.DECISION_SCHEMA.canonical_value,
                }
            )
        )
        reference = artifact_contract.SealedArtifactRef(
            schema=librarian_contract.DECISION_SCHEMA,
            canonical_path=target_path,
            artifact_sha256=sha256_bytes(record_bytes),
            manifest_sha256=manifest_sha256,
            producer_operation_sha256=self.__evidence.spec_sha256,
            byte_length=len(record_bytes),
            media_type="application/json",
        )
        effect = durable.StagedEffect(
            effect_id="safe-librarian-decision-" + proposal_id[2:],
            target_relative_path=target_path,
            artifact_ref=reference,
            artifact_bytes=record_bytes,
        )
        token = self.__writer.prepare(effect)
        published = self.__writer.publish(token)
        finalized = self.__writer.finalize(token)
        if published != reference or finalized != reference:
            raise AuthorityRuntimeError(
                "Safe Librarian decision readback is invalid"
            )
        return reference


class _PlacementMoveError(AuthorityRuntimeError):
    """Internal error type accepted by the low-level rename primitive."""


class LibrarianPlacementSession:
    """Profile-gated exact placement with no generic durable or path access."""

    __slots__ = ("__writer", "__root", "__compiled_policy", "__evidence")

    def __init__(
        self,
        writer: WriteSession,
        root: Path,
        compiled_policy: object,
        evidence: _AdmissionEvidence,
    ) -> None:
        self.__writer = writer
        self.__root = root
        self.__compiled_policy = compiled_policy
        self.__evidence = evidence

    def _require_apply(self) -> MappingProxyType:
        if (
            self.__evidence.write_profile
            is not operation_contract.WriteProfile.SAFE_LIBRARIAN_PLACEMENT
            or self.__evidence.operation_kind != "librarian.placement"
            or self.__evidence.lifecycle_action
            is not operation_contract.LifecycleAction.APPLY
            or not isinstance(self.__evidence.handler_input, MappingProxyType)
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian placement capability is unavailable"
            )
        self.__writer._require_active()
        return self.__evidence.handler_input

    def _require_recovery(self) -> MappingProxyType:
        if (
            self.__evidence.write_profile
            is not operation_contract.WriteProfile.SAFE_LIBRARIAN_PLACEMENT
            or self.__evidence.operation_kind != "librarian.placement"
            or self.__evidence.lifecycle_action
            is not operation_contract.LifecycleAction.RECOVER
            or not isinstance(self.__evidence.handler_input, MappingProxyType)
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian placement recovery capability is unavailable"
            )
        self.__writer._require_active()
        return self.__evidence.handler_input

    @staticmethod
    def _record_reference(
        *,
        schema: artifact_contract.SchemaIdentity,
        target_path: str,
        record_bytes: bytes,
        request_sha256: str,
        spec_sha256: str,
    ) -> artifact_contract.SealedArtifactRef:
        manifest_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "artifact_sha256": sha256_bytes(record_bytes),
                    "canonical_path": target_path,
                    "producer_request_sha256": request_sha256,
                    "schema": schema.canonical_value,
                }
            )
        )
        return artifact_contract.SealedArtifactRef(
            schema=schema,
            canonical_path=target_path,
            artifact_sha256=sha256_bytes(record_bytes),
            manifest_sha256=manifest_sha256,
            producer_operation_sha256=spec_sha256,
            byte_length=len(record_bytes),
            media_type="application/json",
        )

    def _publish_record(
        self,
        *,
        effect_id: str,
        target_path: str,
        schema: artifact_contract.SchemaIdentity,
        record_bytes: bytes,
    ) -> artifact_contract.SealedArtifactRef:
        reference = self._record_reference(
            schema=schema,
            target_path=target_path,
            record_bytes=record_bytes,
            request_sha256=self.__evidence.request_sha256,
            spec_sha256=self.__evidence.spec_sha256,
        )
        token = self.__writer.prepare(
            durable.StagedEffect(
                effect_id=effect_id,
                target_relative_path=target_path,
                artifact_ref=reference,
                artifact_bytes=record_bytes,
            )
        )
        published = self.__writer.publish(token)
        finalized = self.__writer.finalize(token)
        if published != reference or finalized != reference:
            raise AuthorityRuntimeError(
                "Safe Librarian placement record readback is invalid"
            )
        return reference

    def read_librarian_placement_inputs(
        self,
    ) -> tuple[
        artifact_contract.SealedArtifactRef,
        dict[str, object],
        artifact_contract.SealedArtifactRef,
        dict[str, object],
    ]:
        admitted_input = self._require_apply()
        scope = admitted_input["scope"]
        proposal_id = scope["proposal_id"]
        requested_proposal = admitted_input["prerequisite_artifacts"][0]
        requested_decision = admitted_input["approval_artifact"]
        proposal_path = librarian_contract.proposal_artifact_path(proposal_id)
        decision_path = librarian_contract.decision_artifact_path(proposal_id)
        proposal_existing = self.__writer._read_finalized_artifact(
            "safe-librarian-proposal-" + proposal_id[2:],
            proposal_path,
        )
        decision_existing = self.__writer._read_finalized_artifact(
            "safe-librarian-decision-" + proposal_id[2:],
            decision_path,
        )
        if proposal_existing is None or proposal_existing[0] != requested_proposal:
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian placement proposal is not authoritative",
                reason_code="PROPOSAL_MISMATCH",
                next_safe_action="inspect-pending",
            )
        if decision_existing is None or decision_existing[0] != requested_decision:
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian placement decision is not authoritative",
                reason_code="DECISION_MISMATCH",
                next_safe_action="inspect-pending",
            )
        proposal_reference, proposal_bytes = proposal_existing
        decision_reference, decision_bytes = decision_existing
        proposal = librarian_contract.decode_proposal_record(proposal_bytes)
        decision = librarian_contract.decode_decision_record(decision_bytes)
        expected_summary = {
            "proposal_id": proposal_id,
            "source_relative_path": proposal["source_relative_path"],
            "target_relative_path": proposal["target_relative_path"],
            "destination_kind": proposal["destination_kind"],
            "destination_id": proposal["destination_id"],
            "reason": proposal["reason"],
        }
        if (
            proposal["proposal_id"] != proposal_id
            or proposal["source_relative_path"] != scope["source_relative_path"]
            or proposal["target_relative_path"] != scope["target_relative_path"]
            or decision["proposal"] != proposal_reference.canonical_value
            or decision["effect_summary"] != expected_summary
        ):
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian placement evidence does not match the request",
                reason_code="PROPOSAL_MISMATCH",
                next_safe_action="inspect-pending",
            )
        if decision["decision"] != "APPROVED":
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian placement decision is not approved",
                reason_code="DECISION_MISMATCH",
                next_safe_action="inspect-pending",
            )
        return proposal_reference, proposal, decision_reference, decision

    def existing_librarian_placement_intent(
        self,
    ) -> tuple[artifact_contract.SealedArtifactRef, dict[str, object]] | None:
        admitted_input = self._require_apply()
        proposal_id = admitted_input["scope"]["proposal_id"]
        target_path = librarian_contract.intent_artifact_path(proposal_id)
        existing = self.__writer._read_finalized_artifact(
            "safe-librarian-intent-" + proposal_id[2:],
            target_path,
        )
        if existing is None:
            return None
        reference, record_bytes = existing
        record = librarian_contract.decode_intent_record(record_bytes)
        if (
            reference.schema != librarian_contract.INTENT_SCHEMA
            or reference.canonical_path != target_path
            or record["producer_request_sha256"]
            != self.__evidence.request_sha256
            or record["proposal"]
            != admitted_input["prerequisite_artifacts"][0].canonical_value
            or record["decision"]
            != admitted_input["approval_artifact"].canonical_value
        ):
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian placement intent belongs to different evidence",
                reason_code="PLACEMENT_MISMATCH",
                next_safe_action="inspect-pending",
            )
        return reference, record

    def existing_librarian_placement_result(
        self,
    ) -> tuple[artifact_contract.SealedArtifactRef, bytes] | None:
        admitted_input = self._require_apply()
        proposal_id = admitted_input["scope"]["proposal_id"]
        target_path = librarian_contract.result_artifact_path(proposal_id)
        try:
            replay = self.__writer._replay_finalized(
                "safe-librarian-result-" + proposal_id[2:],
                target_path,
            )
        except durable.DurableRecoveryDenied as exc:
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian placement result belongs to different evidence",
                reason_code="PLACEMENT_MISMATCH",
                next_safe_action="inspect-pending",
            ) from exc
        if replay is None:
            return None
        reference, record_bytes = replay
        record = librarian_contract.decode_result_record(record_bytes)
        if (
            reference.schema != librarian_contract.RESULT_SCHEMA
            or reference.canonical_path != target_path
            or record["producer_request_sha256"]
            != self.__evidence.request_sha256
            or record["proposal"]
            != admitted_input["prerequisite_artifacts"][0].canonical_value
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian placement result replay is invalid"
            )
        return reference, record_bytes

    def verify_librarian_placement_pre_move(
        self,
        proposal: object,
    ) -> dict[str, object]:
        admitted_input = self._require_apply()
        if type(proposal) is not dict:
            raise TypeError("Safe Librarian placement proposal is invalid")
        return librarian_snapshot.verify_placement_pre_move(
            root=self.__root,
            compiled_policy=self.__compiled_policy,
            scope=admitted_input["scope"],
            bounds=proposal["bounds"],
            payload={
                "destination_kind": proposal["destination_kind"],
                "destination_id": proposal["destination_id"],
                "reason": proposal["reason"],
            },
            expected_observation={
                "source_snapshot": proposal["source_snapshot"],
                "target_absent": proposal["target_absent"],
            },
        )

    def verify_librarian_placement_post_move(
        self,
        proposal: object,
    ) -> dict[str, object]:
        admitted_input = self._require_apply()
        if type(proposal) is not dict:
            raise TypeError("Safe Librarian placement proposal is invalid")
        return librarian_snapshot.verify_placement_post_move(
            root=self.__root,
            compiled_policy=self.__compiled_policy,
            scope=admitted_input["scope"],
            bounds=proposal["bounds"],
            payload={
                "destination_kind": proposal["destination_kind"],
                "destination_id": proposal["destination_id"],
                "reason": proposal["reason"],
            },
            expected_observation={
                "source_snapshot": proposal["source_snapshot"],
                "target_absent": proposal["target_absent"],
            },
        )

    def classify_librarian_placement_state(
        self,
        proposal: object,
    ) -> dict[str, object]:
        admitted_input = self._require_apply()
        if type(proposal) is not dict:
            raise TypeError("Safe Librarian placement proposal is invalid")
        return librarian_snapshot.classify_placement_state(
            root=self.__root,
            compiled_policy=self.__compiled_policy,
            scope=admitted_input["scope"],
            bounds=proposal["bounds"],
            payload={
                "destination_kind": proposal["destination_kind"],
                "destination_id": proposal["destination_id"],
                "reason": proposal["reason"],
            },
            expected_observation={
                "source_snapshot": proposal["source_snapshot"],
                "target_absent": proposal["target_absent"],
            },
        )

    def publish_librarian_placement_intent(
        self,
        record_bytes: object,
    ) -> artifact_contract.SealedArtifactRef:
        admitted_input = self._require_apply()
        record = librarian_contract.decode_intent_record(record_bytes)
        proposal_id = admitted_input["scope"]["proposal_id"]
        if (
            record["producer_request_sha256"]
            != self.__evidence.request_sha256
            or record["proposal"]
            != admitted_input["prerequisite_artifacts"][0].canonical_value
            or record["decision"]
            != admitted_input["approval_artifact"].canonical_value
            or record["source_relative_path"]
            != admitted_input["scope"]["source_relative_path"]
            or record["target_relative_path"]
            != admitted_input["scope"]["target_relative_path"]
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian placement intent widens admitted evidence"
            )
        return self._publish_record(
            effect_id="safe-librarian-intent-" + proposal_id[2:],
            target_path=librarian_contract.intent_artifact_path(proposal_id),
            schema=librarian_contract.INTENT_SCHEMA,
            record_bytes=record_bytes,
        )

    def publish_librarian_placement_result(
        self,
        record_bytes: object,
    ) -> artifact_contract.SealedArtifactRef:
        admitted_input = self._require_apply()
        record = librarian_contract.decode_result_record(record_bytes)
        proposal_id = admitted_input["scope"]["proposal_id"]
        if (
            record["producer_request_sha256"]
            != self.__evidence.request_sha256
            or record["proposal"]
            != admitted_input["prerequisite_artifacts"][0].canonical_value
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian placement result widens admitted evidence"
            )
        return self._publish_record(
            effect_id="safe-librarian-result-" + proposal_id[2:],
            target_path=librarian_contract.result_artifact_path(proposal_id),
            schema=librarian_contract.RESULT_SCHEMA,
            record_bytes=record_bytes,
        )

    def move_librarian_placement(self, proposal: object) -> None:
        admitted_input = self._require_apply()
        if type(proposal) is not dict:
            raise TypeError("Safe Librarian placement proposal is invalid")
        self.verify_librarian_placement_pre_move(proposal)
        source_snapshot = proposal["source_snapshot"]
        target_absent = proposal["target_absent"]
        source = self.__root.joinpath(
            *admitted_input["scope"]["source_relative_path"].split("/")
        )
        target = self.__root.joinpath(
            *admitted_input["scope"]["target_relative_path"].split("/")
        )
        expected_parents = {
            "source": source_snapshot["parent"],
            "target": target_absent["parent"],
        }

        def require_expected_parent(_path: Path, fd: int, label: str) -> None:
            expected = expected_parents[label]
            observed = os.fstat(fd)
            if (observed.st_dev, observed.st_ino) != (
                expected["device"],
                expected["inode"],
            ):
                raise _PlacementMoveError(
                    f"Safe Librarian {label} parent identity changed"
                )

        file_type = (
            stat.S_IFREG
            if source_snapshot["kind"] == "regular_file"
            else stat.S_IFDIR
        )
        try:
            safety.rename_path_no_replace(
                source,
                target,
                collision_error="Safe Librarian placement target already exists",
                require_directory=source_snapshot["kind"] == "directory",
                expected_source_identity=(
                    source_snapshot["device"],
                    source_snapshot["inode"],
                    file_type,
                ),
                create_target_parent=False,
                error_type=_PlacementMoveError,
                before_directory_identity_check=require_expected_parent,
            )
        except safety.ManualRecoveryRequired as exc:
            raise librarian_contract.LibrarianOperationError(
                "Safe Librarian placement effect requires manual recovery",
                reason_code="PLACEMENT_RECOVERY_REQUIRED",
                next_safe_action="inspect-recovery",
            ) from exc
        except _PlacementMoveError as exc:
            message = str(exc)
            if "target already exists" in message:
                raise librarian_contract.LibrarianOperationError(
                    message,
                    reason_code="TARGET_COLLISION",
                    next_safe_action="create-proposal",
                ) from exc
            raise librarian_contract.LibrarianOperationError(
                message,
                reason_code="SOURCE_CHANGED",
                next_safe_action="create-proposal",
            ) from exc

    def recover_librarian_placement(self) -> artifact_contract.SealedArtifactRef:
        admitted_input = self._require_recovery()
        recovery = admitted_input["payload"]["recovery"]
        reference = self.__writer._recover_public_continuation(
            recovery["continuation_identity"],
            recovery["producer_request_sha256"],
        )
        proposal_id = admitted_input["scope"]["proposal_id"]
        allowed = {
            (
                librarian_contract.intent_artifact_path(proposal_id),
                librarian_contract.INTENT_SCHEMA,
            ),
            (
                librarian_contract.result_artifact_path(proposal_id),
                librarian_contract.RESULT_SCHEMA,
            ),
        }
        if (
            type(reference) is not artifact_contract.SealedArtifactRef
            or (reference.canonical_path, reference.schema) not in allowed
            or reference.media_type != "application/json"
        ):
            raise AuthorityRuntimeError(
                "Safe Librarian recovered placement record is invalid"
            )
        return reference

    def fence_librarian_placement(self) -> None:
        self._require_apply()
        self.__writer._fence_root_for_owner(
            reason_code="PLACEMENT_RECOVERY_REQUIRED"
        )


def _is_expected_invalidated_writer_cleanup(
    cleanup_error: ledger_runtime.LedgerRuntimeError,
    invalidation_error: AuthorityRuntimeError | None,
    invalidation_ledger_error: ledger_runtime.LedgerRuntimeError | None,
) -> bool:
    return (
        invalidation_error is not None
        and invalidation_ledger_error is not None
        and type(cleanup_error) is ledger_runtime.LedgerRuntimeError
        and str(cleanup_error).startswith("policy drift recorded: ")
        and isinstance(cleanup_error.__cause__, ledger_runtime.PolicyAdmissionError)
    )


def _raise_unexpected_write_cleanup(
    cleanup_error: BaseException,
    *,
    body_error: BaseException | None,
    message: str = "write capability cleanup failed",
) -> None:
    boundary_error = AuthorityRuntimeError(message)
    boundary_error.__cause__ = cleanup_error
    if body_error is not None:
        raise body_error from boundary_error
    raise boundary_error


@contextmanager
def open_read_session(
    admitted: operation_contract.AdmittedOperation,
) -> Iterator[ReadSession]:
    evidence = _evidence_from_admitted(admitted)
    if (
        evidence.authority_mode is not operation_contract.AuthorityMode.READ
        or evidence.root is None
        or evidence.root_identity is None
        or not isinstance(evidence.read_profile, operation_contract.ReadProfile)
    ):
        raise TypeError("read admission evidence is invalid")
    try:
        root_changed = (
            _canonical_root_identity(evidence.root) != evidence.root_identity
        )
    except AuthorityRuntimeError as exc:
        if evidence.inspection_evidence is not None:
            raise WorkstreamInspectionFence(
                "authority root identity changed",
                reason_code="RAW_ROOT_CHANGED",
            ) from exc
        raise
    if root_changed:
        if evidence.inspection_evidence is not None:
            raise WorkstreamInspectionFence(
                "authority root identity changed",
                reason_code="RAW_ROOT_CHANGED",
            )
        raise AuthorityRuntimeError("authority root identity changed")
    if evidence.read_profile is operation_contract.ReadProfile.CURATION_AUDIT:
        if evidence.audit_state not in _AUDIT_STATES:
            raise TypeError("curation audit admission state is invalid")
        if (
            evidence.activation_audit_evidence is None
            or activation_runtime.capture_audit_evidence(
                evidence.root,
                runtime_state=(
                    None if evidence.audit_control_absent else evidence.audit_state
                ),
            )
            != evidence.activation_audit_evidence
        ):
            raise AuthorityRuntimeError("curation audit evidence changed")
    if (
        evidence.read_profile is operation_contract.ReadProfile.CURATION_AUDIT
        and evidence.audit_control_absent
    ):
        if not _audit_control_absent(evidence.root):
            raise AuthorityRuntimeError("curation audit control state changed")
        session = ReadSession(
            None,
            evidence.root,
            evidence.root_identity,
            None,
            None,
            None,
            evidence.read_profile,
            True,
            evidence.audit_state,
            evidence.handler_input,
            evidence.activation_audit_evidence,
        )
        try:
            yield session
        finally:
            session._close()
        return
    if (
        evidence.read_profile is operation_contract.ReadProfile.CURATION_AUDIT
        and evidence.audit_state != _AUDIT_ACTIVE
    ):
        if _audit_control_absent(evidence.root):
            raise AuthorityRuntimeError("curation audit control state changed")
        _confirm_audit_failure_state(evidence.root, evidence.audit_state)
        session = ReadSession(
            None,
            evidence.root,
            evidence.root_identity,
            None,
            None,
            None,
            evidence.read_profile,
            False,
            evidence.audit_state,
            evidence.handler_input,
            evidence.activation_audit_evidence,
        )
        try:
            yield session
        finally:
            session._close()
        return
    if not isinstance(evidence.policy_identity, PolicyIdentity):
        raise TypeError("read admission policy evidence is invalid")
    try:
        with ledger_runtime.open_reader_session(
            evidence.root,
            immutable=(
                evidence.read_profile
                in {
                    operation_contract.ReadProfile.CURATION_AUDIT,
                    operation_contract.ReadProfile.SAFE_LIBRARIAN,
                }
            ),
        ) as reader:
            observed = PolicyIdentity.from_approved_policy(reader.current_policy())
            if observed != evidence.policy_identity:
                if evidence.inspection_evidence is not None:
                    raise WorkstreamInspectionFence(
                        "current policy identity changed",
                        reason_code="POLICY_CHANGED",
                    )
                raise AuthorityRuntimeError("current policy identity changed")
            if evidence.inspection_evidence is not None:
                workstream_inspection.revalidate_inspection_evidence(
                    reader.compiled_policy,
                    evidence.root,
                    _inspection_reference(evidence.handler_input),
                    evidence.inspection_evidence,
                )
            else:
                _validate_captured_workstream(
                    reader.compiled_policy,
                    evidence.workstream_id,
                    evidence.workstream_lifecycle,
                )
            session = ReadSession(
                reader,
                evidence.root,
                evidence.root_identity,
                evidence.policy_identity,
                evidence.workstream_id,
                evidence.workstream_lifecycle,
                evidence.read_profile,
                False,
                evidence.audit_state,
                evidence.handler_input,
                evidence.activation_audit_evidence,
                evidence.inspection_evidence,
            )
            try:
                yield session
            finally:
                session._close()
    except (ledger_runtime.LedgerRuntimeError, ledger_runtime.PolicyAdmissionError) as exc:
        raise AuthorityRuntimeError("read capability evidence is unavailable") from exc


@contextmanager
def open_write_session(
    admitted: operation_contract.AdmittedOperation,
) -> Iterator[object]:
    evidence = _evidence_from_admitted(admitted)
    if (
        evidence.authority_mode is not operation_contract.AuthorityMode.WRITE
        or evidence.root is None
        or evidence.root_identity is None
        or not isinstance(evidence.lifecycle_action, operation_contract.LifecycleAction)
        or not isinstance(evidence.write_profile, operation_contract.WriteProfile)
    ):
        raise TypeError("write admission evidence is invalid")
    if evidence.write_profile is operation_contract.WriteProfile.CURATION_ACTIVATION:
        if (
            evidence.operation_kind != "curation.activation"
            or evidence.lifecycle_action is not operation_contract.LifecycleAction.APPLY
            or type(evidence.activation_request_bytes) is not bytes
            or evidence.activation_audit_evidence is None
        ):
            raise AuthorityRuntimeError("activation write profile is unavailable")
        if _canonical_root_identity(evidence.root) != evidence.root_identity:
            raise AuthorityRuntimeError("authority root identity changed")
        with activation_runtime.open_activation_session(
            evidence.root,
            request_bytes=evidence.activation_request_bytes,
            admitted_evidence=evidence.activation_audit_evidence,
        ) as activation_session:
            yield activation_session
        return
    if evidence.operation_kind == "memory.workspace_sync":
        if (
            evidence.lifecycle_action is not operation_contract.LifecycleAction.APPLY
            or _canonical_root_identity(evidence.root) != evidence.root_identity
        ):
            raise AuthorityRuntimeError("workspace sync capability is unavailable")
        yield WorkspaceSyncSession(evidence.root, evidence)
        return
    if not isinstance(evidence.policy_identity, PolicyIdentity):
        raise TypeError("write admission policy evidence is invalid")
    if evidence.write_profile is operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD:
        if evidence.operation_kind not in {
            "librarian.proposal",
            "librarian.decision",
        }:
            raise AuthorityRuntimeError("write profile is unavailable")
    elif (
        evidence.write_profile
        is operation_contract.WriteProfile.SAFE_LIBRARIAN_PLACEMENT
    ):
        if evidence.operation_kind != "librarian.placement":
            raise AuthorityRuntimeError("write profile is unavailable")
    elif (
        evidence.write_profile
        is operation_contract.WriteProfile.CURATION_PLAN_APPLY
    ):
        if (
            evidence.operation_kind != "curation.plan_apply"
            or evidence.lifecycle_action
            is not operation_contract.LifecycleAction.APPLY
        ):
            raise AuthorityRuntimeError("write profile is unavailable")
    elif evidence.write_profile is not operation_contract.WriteProfile.STANDARD:
        raise AuthorityRuntimeError("write profile is unavailable")
    if _canonical_root_identity(evidence.root) != evidence.root_identity:
        raise AuthorityRuntimeError("authority root identity changed")
    invalidation_error: AuthorityRuntimeError | None = None
    invalidation_ledger_error: ledger_runtime.LedgerRuntimeError | None = None
    body_error: BaseException | None = None
    writer_cleanup_error: ledger_runtime.LedgerRuntimeError | None = None
    session_cleanup_error: BaseException | None = None
    session: WriteSession | None = None
    owner_pid = os.getpid()
    try:
        with ledger_runtime.open_writer_session(evidence.root) as writer:
            recovery_only_drift = (
                evidence.lifecycle_action is operation_contract.LifecycleAction.RECOVER
                and evidence.workstream_lifecycle == "recovery_only"
            )
            observed = PolicyIdentity.from_approved_policy(writer.current_policy())
            if observed != evidence.policy_identity:
                raise AuthorityRuntimeError("current policy identity changed")
            if not recovery_only_drift:
                _validate_captured_workstream(
                    writer.compiled_policy,
                    evidence.workstream_id,
                    evidence.workstream_lifecycle,
                )
            def revalidate() -> None:
                if _canonical_root_identity(evidence.root) != evidence.root_identity:
                    raise AuthorityRuntimeError("authority root identity changed")
                if recovery_only_drift:
                    raise AuthorityRuntimeError(
                        "workstream is not current and active"
                    )
                try:
                    current = PolicyIdentity.from_approved_policy(
                        writer.current_policy()
                    )
                except ledger_runtime.LedgerRuntimeError as exc:
                    raise AuthorityRuntimeError(
                        "current policy evidence is no longer current"
                    ) from exc
                if current != evidence.policy_identity:
                    raise AuthorityRuntimeError("current policy identity changed")
                _validate_captured_workstream(
                    writer.compiled_policy,
                    evidence.workstream_id,
                    evidence.workstream_lifecycle,
                )

            def mark_invalidated(error: AuthorityRuntimeError) -> None:
                nonlocal invalidation_error, invalidation_ledger_error
                if invalidation_error is None:
                    invalidation_error = error
                    if isinstance(error.__cause__, ledger_runtime.LedgerRuntimeError):
                        invalidation_ledger_error = error.__cause__

            def invalidate_from_coordinator(error: AuthorityRuntimeError) -> None:
                mark_invalidated(error)
                if session is not None:
                    session._mark_coordinator_invalidated(error)

            coordinator = durable.DurableCoordinator.open(
                evidence.root,
                root_identity=evidence.root_identity,
                request_sha256=evidence.request_sha256,
                scope_sha256=evidence.scope_sha256,
                bounds_sha256=evidence.bounds_sha256,
                spec_identity=evidence.spec_identity,
                spec_sha256=evidence.spec_sha256,
                policy_identity=evidence.policy_identity,
                action=evidence.lifecycle_action,
                transition_guard=revalidate,
                on_invalidate=invalidate_from_coordinator,
            )

            session = WriteSession(coordinator, revalidate, mark_invalidated)
            public_session: object
            if (
                evidence.write_profile
                is operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD
            ):
                public_session = LibrarianRecordSession(
                    session,
                    evidence.root,
                    writer.compiled_policy,
                    evidence,
                )
            elif (
                evidence.write_profile
                is operation_contract.WriteProfile.SAFE_LIBRARIAN_PLACEMENT
            ):
                public_session = LibrarianPlacementSession(
                    session,
                    evidence.root,
                    writer.compiled_policy,
                    evidence,
                )
            elif (
                evidence.write_profile
                is operation_contract.WriteProfile.CURATION_PLAN_APPLY
            ):
                public_session = CurationPlanApplySession(
                    session,
                    evidence.root,
                    writer.compiled_policy,
                    evidence,
                )
            else:
                public_session = session
            try:
                yield public_session
            except BaseException as exc:
                body_error = session._recovery_error_for_body(exc)
            finally:
                if os.getpid() != owner_pid:
                    _exit_inherited_write_session()
                try:
                    session._close()
                except BaseException as exc:
                    session_cleanup_error = exc
    except (ledger_runtime.LedgerRuntimeError, ledger_runtime.PolicyAdmissionError) as exc:
        writer_cleanup_error = exc
    cleanup_errors: list[BaseException] = []
    if session_cleanup_error is not None:
        cleanup_errors.append(session_cleanup_error)
    if writer_cleanup_error is not None and not _is_expected_invalidated_writer_cleanup(
        writer_cleanup_error,
        invalidation_error,
        invalidation_ledger_error,
    ):
        cleanup_errors.append(writer_cleanup_error)
    if cleanup_errors:
        cleanup_cause: BaseException
        if len(cleanup_errors) == 1:
            cleanup_cause = cleanup_errors[0]
        else:
            cleanup_cause = BaseExceptionGroup(
                "write capability cleanup failures",
                cleanup_errors,
            )
        if body_error is None and session is not None:
            body_error = session._recovery_error_for_outstanding(
                "durable write session cleanup failed after a possible effect",
                reason_code="RECOVERY_SESSION_CLEANUP",
            )
        _raise_unexpected_write_cleanup(cleanup_cause, body_error=body_error)
    if body_error is not None:
        raise body_error
