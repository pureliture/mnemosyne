"""Private immutable operation-contract values for the D1a foundation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from ..canonical_json import canonical_json_bytes, sha256_bytes


_OPERATION_KIND = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_ARTIFACT_KIND = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_OPERATION_REQUEST_BYTES = 1024 * 1024


class LifecycleAction(str, Enum):
    PLAN = "PLAN"
    APPROVE = "APPROVE"
    APPLY = "APPLY"
    RESUME = "RESUME"
    CANCEL = "CANCEL"
    RECOVER = "RECOVER"
    INSPECT = "INSPECT"


class ClaimMode(str, Enum):
    NONE = "NONE"
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"


class AuthorityMode(str, Enum):
    NONE = "NONE"
    READ = "READ"
    WRITE = "WRITE"


class ReadProfile(str, Enum):
    """Closed read capability profiles selected by the static Catalog."""

    STANDARD = "STANDARD"
    CURATION_AUDIT = "CURATION_AUDIT"
    SAFE_LIBRARIAN = "SAFE_LIBRARIAN"


class WriteProfile(str, Enum):
    """Closed write capability profiles selected by the static Catalog."""

    STANDARD = "STANDARD"
    CURATION_ACTIVATION = "CURATION_ACTIVATION"
    CURATION_PLAN_APPLY = "CURATION_PLAN_APPLY"
    SAFE_LIBRARIAN_RECORD = "SAFE_LIBRARIAN_RECORD"
    SAFE_LIBRARIAN_PLACEMENT = "SAFE_LIBRARIAN_PLACEMENT"


class OutcomeKind(str, Enum):
    COMPLETED = "completed"
    COMPLETED_CURRENT = "completed_current"
    BLOCKED = "blocked"
    RECOVERABLE = "recoverable"
    BLOCKED_RECOVERY = "blocked_recovery"


@dataclass(frozen=True)
class ArtifactRequirement:
    """Primitive-only identity required before an operation can be admitted."""

    kind: str
    version: int
    schema_sha256: str

    def __post_init__(self) -> None:
        if type(self.kind) is not str or _ARTIFACT_KIND.fullmatch(self.kind) is None:
            raise ValueError("artifact requirement kind is invalid")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("artifact requirement version is invalid")
        if type(self.schema_sha256) is not str or _SHA256.fullmatch(
            self.schema_sha256
        ) is None:
            raise ValueError("artifact requirement schema hash is invalid")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "version": self.version,
            "schema_sha256": self.schema_sha256,
        }


_AUTHORITY_RANK = {
    AuthorityMode.NONE: 0,
    AuthorityMode.READ: 1,
    AuthorityMode.WRITE: 2,
}


def authority_can_cover(
    requested: AuthorityMode,
    allowed: AuthorityMode,
) -> bool:
    return _AUTHORITY_RANK[requested] <= _AUTHORITY_RANK[allowed]


def _freeze_json(value: object, label: str) -> object:
    if value is None or type(value) in (bool, int, float, str):
        return value
    if type(value) is list:
        return tuple(_freeze_json(item, label) for item in value)
    if type(value) is dict:
        copied = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise ValueError(f"{label} contains an invalid key")
            copied[key] = _freeze_json(item, label)
        return MappingProxyType(copied)
    raise ValueError(f"{label} must contain JSON values")


def _thaw_json(value: object) -> object:
    if isinstance(value, MappingProxyType):
        return {key: _thaw_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_json(item) for item in value]
    return value


def _canonical_artifact_evidence(value: object) -> object:
    if value is None:
        return None
    canonical_value = getattr(value, "canonical_value", None)
    if type(canonical_value) is not dict:
        raise ValueError("artifact evidence is invalid")
    return _thaw_json(_freeze_json(canonical_value, "artifact evidence"))


def _frozen_mapping(value: object, label: str) -> MappingProxyType:
    if type(value) is not dict:
        raise ValueError(f"{label} must be a plain object")
    frozen = _freeze_json(value, label)
    if not isinstance(frozen, MappingProxyType):
        raise AssertionError("plain-object freeze must return a mapping")
    return frozen


@dataclass(frozen=True)
class OperationRequest:
    schema_version: int
    operation_kind: str
    action: LifecycleAction
    claim_mode: ClaimMode
    root: str
    actor: str
    requested_authority: AuthorityMode
    payload: dict[str, Any]
    bounds: dict[str, Any]
    scope: dict[str, Any] = field(default_factory=dict)
    approval_artifact: object = None
    prerequisite_artifacts: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("operation request schema version is invalid")
        if type(self.operation_kind) is not str or not _OPERATION_KIND.fullmatch(
            self.operation_kind
        ):
            raise ValueError("operation kind is invalid")
        if not isinstance(self.action, LifecycleAction):
            raise ValueError("operation action is invalid")
        if not isinstance(self.claim_mode, ClaimMode):
            raise ValueError("claim mode is invalid")
        if (
            type(self.root) is not str
            or not self.root.startswith("/")
            or self.root != self.root.rstrip("/")
            or "/../" in self.root
            or "/./" in self.root
        ):
            raise ValueError("operation root is invalid")
        if type(self.actor) is not str or not self.actor or self.actor != self.actor.strip():
            raise ValueError("operation actor is invalid")
        if not isinstance(self.requested_authority, AuthorityMode):
            raise ValueError("requested authority is invalid")
        object.__setattr__(self, "payload", _frozen_mapping(self.payload, "payload"))
        object.__setattr__(self, "bounds", _frozen_mapping(self.bounds, "bounds"))
        object.__setattr__(self, "scope", _frozen_mapping(self.scope, "scope"))
        if type(self.prerequisite_artifacts) is not tuple:
            raise ValueError("prerequisite artifacts are invalid")
        _canonical_artifact_evidence(self.approval_artifact)
        for artifact in self.prerequisite_artifacts:
            _canonical_artifact_evidence(artifact)

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": self.schema_version,
                "operation_kind": self.operation_kind,
                "action": self.action.value,
                "claim_mode": self.claim_mode.value,
                "root": self.root,
                "actor": self.actor,
                "requested_authority": self.requested_authority.value,
                "payload": _thaw_json(self.payload),
                "bounds": _thaw_json(self.bounds),
                "scope": _thaw_json(self.scope),
                "approval_artifact": _canonical_artifact_evidence(
                    self.approval_artifact
                ),
                "prerequisite_artifacts": [
                    _canonical_artifact_evidence(artifact)
                    for artifact in self.prerequisite_artifacts
                ],
            }
        )

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes)


@dataclass(frozen=True)
class AdmissionContract:
    spec_identity: str
    spec_sha256: str
    operation_kind: str
    allowed_actions: tuple[LifecycleAction, ...]
    allowed_claim_modes: tuple[ClaimMode, ...]
    authority_mode: AuthorityMode
    scope_schema: tuple[str, ...]
    bounds_schema: tuple[str, ...]
    approval_required: bool
    prerequisite_artifacts: tuple[ArtifactRequirement, ...]
    approval_requirement: object = None
    read_profile: ReadProfile = ReadProfile.STANDARD
    write_profile: WriteProfile = WriteProfile.STANDARD

    def __post_init__(self) -> None:
        if (
            type(self.spec_identity) is not str
            or not self.spec_identity
            or type(self.spec_sha256) is not str
            or _SHA256.fullmatch(self.spec_sha256) is None
            or type(self.operation_kind) is not str
            or _OPERATION_KIND.fullmatch(self.operation_kind) is None
            or type(self.allowed_actions) is not tuple
            or not self.allowed_actions
            or any(not isinstance(action, LifecycleAction) for action in self.allowed_actions)
            or len(set(self.allowed_actions)) != len(self.allowed_actions)
            or type(self.allowed_claim_modes) is not tuple
            or not self.allowed_claim_modes
            or any(not isinstance(mode, ClaimMode) for mode in self.allowed_claim_modes)
            or len(set(self.allowed_claim_modes)) != len(self.allowed_claim_modes)
            or not isinstance(self.authority_mode, AuthorityMode)
            or type(self.approval_required) is not bool
            or not isinstance(self.read_profile, ReadProfile)
            or not isinstance(self.write_profile, WriteProfile)
            or (
                self.read_profile is not ReadProfile.STANDARD
                and self.authority_mode is not AuthorityMode.READ
            )
            or (
                self.write_profile is not WriteProfile.STANDARD
                and self.authority_mode is not AuthorityMode.WRITE
            )
        ):
            raise ValueError("admission contract is invalid")
        for label, fields in (
            ("scope schema", self.scope_schema),
            ("bounds schema", self.bounds_schema),
        ):
            if (
                type(fields) is not tuple
                or any(type(field) is not str or not field for field in fields)
                or len(set(fields)) != len(fields)
            ):
                raise ValueError(f"{label} is invalid")
        if (
            type(self.prerequisite_artifacts) is not tuple
            or any(
                type(requirement) is not ArtifactRequirement
                for requirement in self.prerequisite_artifacts
            )
            or len(set(self.prerequisite_artifacts))
            != len(self.prerequisite_artifacts)
        ):
            raise ValueError("prerequisite artifacts are invalid")
        if self.approval_required:
            if type(self.approval_requirement) is not ArtifactRequirement:
                raise ValueError("approval requirement is invalid")
        elif self.approval_requirement is not None:
            raise ValueError("approval requirement is invalid without approval")


_OUTCOME_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
_SAFE_ACTION = re.compile(r"[a-z][a-z0-9_-]{1,63}")
_RECOVERY_OWNER = re.compile(r"[a-z][a-z0-9_-]{1,63}")


def _require_outcome_request_sha256(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError("operation outcome request identity is invalid")
    return value


def _require_outcome_code(value: object, label: str) -> str:
    if type(value) is not str or _OUTCOME_CODE.fullmatch(value) is None:
        raise ValueError(f"operation outcome {label} is invalid")
    return value


def _require_safe_action(value: object, label: str) -> str:
    if type(value) is not str or _SAFE_ACTION.fullmatch(value) is None:
        raise ValueError(f"operation outcome {label} is invalid")
    return value


def _freeze_outcome_identity(value: object, label: str) -> object:
    if value is None:
        return None
    canonical_value = getattr(value, "canonical_value", None)
    if type(canonical_value) is not dict:
        raise ValueError(f"operation outcome {label} is invalid")
    return _frozen_mapping(canonical_value, f"operation outcome {label}")


def _validate_current_freshness(
    request_sha256: str,
    facts: MappingProxyType,
    freshness: object,
) -> MappingProxyType:
    frozen = _frozen_mapping(freshness, "current freshness")
    value = _thaw_json(frozen)
    required_fields = {
        "schema_version",
        "request_sha256",
        "claim_mode",
        "exact_scope",
        "scope_sha256",
        "observation_started_at",
        "observation_completed_at",
        "planned_coverage",
        "observed_coverage",
        "coverage_complete",
        "dependencies",
        "consistency_groups",
        "facts_sha256",
        "status",
        "blockers",
    }
    if set(value) != required_fields:
        raise ValueError("current freshness shape is invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["request_sha256"] != request_sha256
        or value["claim_mode"] != ClaimMode.CURRENT.value
        or type(value["exact_scope"]) is not dict
        or value["scope_sha256"] != sha256_bytes(canonical_json_bytes(value["exact_scope"]))
        or type(value["observation_started_at"]) is not str
        or not value["observation_started_at"]
        or type(value["observation_completed_at"]) is not str
        or not value["observation_completed_at"]
        or type(value["planned_coverage"]) is not list
        or type(value["observed_coverage"]) is not list
        or type(value["coverage_complete"]) is not bool
        or type(value["dependencies"]) is not list
        or type(value["consistency_groups"]) is not list
        or value["facts_sha256"] != sha256_bytes(canonical_json_bytes(_thaw_json(facts)))
        or value["status"] != "FRESH"
        or value["blockers"] != []
    ):
        raise ValueError("current freshness is invalid")
    return frozen


def _validate_blocked_freshness(
    request_sha256: str,
    freshness: object,
) -> MappingProxyType:
    frozen = _frozen_mapping(freshness, "blocked freshness")
    value = _thaw_json(frozen)
    if (
        value.get("request_sha256") != request_sha256
        or value.get("claim_mode") != ClaimMode.CURRENT.value
        or value.get("status") not in {"STALE", "UNKNOWN"}
    ):
        raise ValueError("blocked freshness is invalid")
    return frozen


class OperationOutcome:
    """Closed canonical wire variants; callers cannot construct arbitrary outcomes."""

    __slots__ = (
        "__outcome_kind",
        "__request_sha256",
        "__result_artifact",
        "__result",
        "__facts",
        "__freshness",
        "__reason_code",
        "__next_safe_action",
        "__recovery_owner",
        "__continuation_identity",
        "__allowed_recovery_action",
    )

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError("operation outcomes are issued only by canonical constructors")

    @classmethod
    def _build(
        cls,
        outcome_kind: OutcomeKind,
        request_sha256: str,
        *,
        result_artifact: object = None,
        result: object = None,
        facts: object = None,
        freshness: object = None,
        reason_code: object = None,
        next_safe_action: object = None,
        recovery_owner: object = None,
        continuation_identity: object = None,
        allowed_recovery_action: object = None,
    ) -> "OperationOutcome":
        outcome = object.__new__(cls)
        object.__setattr__(outcome, "_OperationOutcome__outcome_kind", outcome_kind)
        object.__setattr__(outcome, "_OperationOutcome__request_sha256", request_sha256)
        object.__setattr__(outcome, "_OperationOutcome__result_artifact", result_artifact)
        object.__setattr__(outcome, "_OperationOutcome__result", result)
        object.__setattr__(outcome, "_OperationOutcome__facts", facts)
        object.__setattr__(outcome, "_OperationOutcome__freshness", freshness)
        object.__setattr__(outcome, "_OperationOutcome__reason_code", reason_code)
        object.__setattr__(outcome, "_OperationOutcome__next_safe_action", next_safe_action)
        object.__setattr__(outcome, "_OperationOutcome__recovery_owner", recovery_owner)
        object.__setattr__(outcome, "_OperationOutcome__continuation_identity", continuation_identity)
        object.__setattr__(
            outcome,
            "_OperationOutcome__allowed_recovery_action",
            allowed_recovery_action,
        )
        return outcome

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("operation outcome is immutable")

    @property
    def outcome_kind(self) -> str:
        return self.__outcome_kind.value

    @property
    def request_sha256(self) -> str:
        return self.__request_sha256

    @property
    def result_artifact(self) -> object:
        return _thaw_json(self.__result_artifact)

    @property
    def result(self) -> object:
        return _thaw_json(self.__result)

    @property
    def facts(self) -> object:
        return _thaw_json(self.__facts)

    @property
    def freshness(self) -> object:
        return _thaw_json(self.__freshness)

    @property
    def reason_code(self) -> object:
        return self.__reason_code

    @property
    def next_safe_action(self) -> object:
        return self.__next_safe_action

    @property
    def recovery_owner(self) -> object:
        return self.__recovery_owner

    @property
    def continuation_identity(self) -> object:
        return self.__continuation_identity

    @property
    def allowed_recovery_action(self) -> object:
        return self.__allowed_recovery_action

    @property
    def canonical_bytes(self) -> bytes:
        value = {
            "outcome_kind": self.outcome_kind,
            "request_sha256": self.__request_sha256,
        }
        for key, item in (
            ("result_artifact", self.__result_artifact),
            ("result", self.__result),
            ("facts", self.__facts),
            ("freshness", self.__freshness),
            ("reason_code", self.__reason_code),
            ("next_safe_action", self.__next_safe_action),
            ("recovery_owner", self.__recovery_owner),
            ("continuation_identity", self.__continuation_identity),
            ("allowed_recovery_action", self.__allowed_recovery_action),
        ):
            if item is not None:
                value[key] = _thaw_json(item)
        return canonical_json_bytes(value)

    @classmethod
    def completed(
        cls,
        request_sha256: str,
        result_artifact: object = None,
        *,
        result: object = None,
    ) -> "OperationOutcome":
        if result is not None and result_artifact is not None:
            raise ValueError("completed outcome cannot contain both result and artifact")
        return cls._build(
            OutcomeKind.COMPLETED,
            _require_outcome_request_sha256(request_sha256),
            result_artifact=_freeze_outcome_identity(result_artifact, "result artifact"),
            result=(
                _frozen_mapping(result, "completed result")
                if result is not None
                else None
            ),
        )

    @classmethod
    def completed_current(
        cls,
        request_sha256: str,
        facts: object,
        freshness: object,
    ) -> "OperationOutcome":
        request_identity = _require_outcome_request_sha256(request_sha256)
        frozen_facts = _frozen_mapping(facts, "current facts")
        return cls._build(
            OutcomeKind.COMPLETED_CURRENT,
            request_identity,
            facts=frozen_facts,
            freshness=_validate_current_freshness(
                request_identity,
                frozen_facts,
                freshness,
            ),
        )

    @classmethod
    def blocked(
        cls,
        request_sha256: str,
        *,
        reason_code: str,
        next_safe_action: str,
        freshness: object = None,
    ) -> "OperationOutcome":
        request_identity = _require_outcome_request_sha256(request_sha256)
        return cls._build(
            OutcomeKind.BLOCKED,
            request_identity,
            reason_code=_require_outcome_code(reason_code, "reason code"),
            next_safe_action=_require_safe_action(next_safe_action, "next safe action"),
            freshness=(
                _validate_blocked_freshness(request_identity, freshness)
                if freshness is not None
                else None
            ),
        )

    @classmethod
    def recoverable(
        cls,
        request_sha256: str,
        *,
        recovery_owner: str,
        continuation_identity: str,
        allowed_recovery_action: str,
    ) -> "OperationOutcome":
        return cls._build(
            OutcomeKind.RECOVERABLE,
            _require_outcome_request_sha256(request_sha256),
            recovery_owner=_require_safe_action(recovery_owner, "recovery owner"),
            continuation_identity=_require_outcome_request_sha256(continuation_identity),
            allowed_recovery_action=_require_safe_action(
                allowed_recovery_action,
                "allowed recovery action",
            ),
        )

    @classmethod
    def blocked_recovery(
        cls,
        request_sha256: str,
        *,
        recovery_owner: str,
        continuation_identity: str,
        reason_code: str = "RECOVERY_EVIDENCE_UNSAFE",
    ) -> "OperationOutcome":
        return cls._build(
            OutcomeKind.BLOCKED_RECOVERY,
            _require_outcome_request_sha256(request_sha256),
            recovery_owner=_require_safe_action(recovery_owner, "recovery owner"),
            continuation_identity=_require_outcome_request_sha256(continuation_identity),
            reason_code=_require_outcome_code(reason_code, "reason code"),
        )


class AdmittedOperation:
    """An Authority Runtime-issued admission that callers cannot construct."""

    __slots__ = ("_issuer", "_payload")

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError("admitted operations are issued only by Authority Runtime")

    def _payload_field(self, name: str) -> object:
        payload = getattr(self, "_payload", None)
        try:
            return getattr(payload, name)
        except AttributeError as exc:
            raise TypeError("unverified admitted operation") from exc

    @property
    def request_sha256(self) -> str:
        return self._payload_field("request_sha256")

    @property
    def authority_mode(self) -> AuthorityMode:
        return self._payload_field("authority_mode")

    @property
    def actor(self) -> str:
        return self._payload_field("actor")

    @property
    def input(self) -> MappingProxyType:
        """Return the immutable, validated handler input sealed at admission."""

        value = self._payload_field("handler_input")
        if type(value) is not MappingProxyType:
            raise TypeError("admitted operation input is invalid")
        return value


def _issue_admitted_operation(issuer: object, payload: object) -> AdmittedOperation:
    admitted = object.__new__(AdmittedOperation)
    object.__setattr__(admitted, "_issuer", issuer)
    object.__setattr__(admitted, "_payload", payload)
    return admitted


def _is_issued_admitted_operation(value: object, issuer: object) -> bool:
    return (
        type(value) is AdmittedOperation
        and getattr(value, "_issuer", None) is issuer
    )


__all__ = [
    "OperationRequest",
    "AdmissionContract",
    "AdmittedOperation",
    "OperationOutcome",
]
