"""Typed request, result, and capability contracts for Curation Harness."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from .canonical_json import canonical_json_bytes, sha256_bytes


MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_CONTAINER_ITEMS = 256
MAX_TEXT_BYTES = 64 * 1024
_REQUEST_KEYS = frozenset(
    (
        "schema_version",
        "operation_kind",
        "action",
        "root",
        "actor",
        "authority",
        "payload",
        "limits",
    )
)
_OPERATION_KIND = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_LIMIT_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_REFERENCE_KIND = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class CurationContractError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _invalid_request() -> CurationContractError:
    return CurationContractError("INVALID_REQUEST")


def _invalid_result() -> CurationContractError:
    return CurationContractError("HANDLER_RESULT_INVALID")


class _FrozenDict(Mapping):
    __slots__ = ("_data",)

    def __init__(self, value) -> None:
        object.__setattr__(self, "_data", MappingProxyType(dict(value)))

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return repr(dict(self._data))

    def __eq__(self, other) -> bool:
        if not isinstance(other, Mapping):
            return False
        return dict(self.items()) == dict(other.items())

    def _immutable(self, *_args, **_kwargs):
        raise TypeError("curation contract value is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable


class _FrozenList(Sequence):
    __slots__ = ("_data",)

    def __init__(self, value) -> None:
        object.__setattr__(self, "_data", tuple(value))

    def __getitem__(self, index):
        return self._data[index]

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return repr(list(self._data))

    def __eq__(self, other) -> bool:
        if not isinstance(other, Sequence) or isinstance(other, (str, bytes, bytearray)):
            return False
        return tuple(self) == tuple(other)

    def _immutable(self, *_args, **_kwargs):
        raise TypeError("curation contract value is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable


def _freeze_json(value: Any) -> Any:
    if isinstance(value, (dict, _FrozenDict)):
        return _FrozenDict(
            (key, _freeze_json(nested)) for key, nested in value.items()
        )
    if isinstance(value, (list, _FrozenList)):
        return _FrozenList(_freeze_json(nested) for nested in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, (dict, _FrozenDict)):
        return {key: _thaw_json(nested) for key, nested in value.items()}
    if isinstance(value, (list, _FrozenList)):
        return [_thaw_json(nested) for nested in value]
    return value


def _bounded_text(value: Any, *, maximum: int = MAX_TEXT_BYTES) -> str:
    if type(value) is not str or "\x00" in value:
        raise _invalid_request()
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise _invalid_request() from exc
    if len(encoded) > maximum:
        raise _invalid_request()
    return value


def _validate_json(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise _invalid_request()
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if value < -(2**63) or value > 2**63 - 1:
            raise _invalid_request()
        return
    if type(value) is str:
        _bounded_text(value)
        return
    if isinstance(value, (list, _FrozenList)):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise _invalid_request()
        for nested in value:
            _validate_json(nested, depth=depth + 1)
        return
    if isinstance(value, (dict, _FrozenDict)):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise _invalid_request()
        for key, nested in value.items():
            if type(key) is not str or not key:
                raise _invalid_request()
            _bounded_text(key, maximum=128)
            _validate_json(nested, depth=depth + 1)
        return
    raise _invalid_request()


def _strict_object(pairs):
    value = {}
    for key, nested in pairs:
        if key in value:
            raise _invalid_request()
        value[key] = nested
    return value


def _reject_constant(_value: str):
    raise _invalid_request()


class LifecycleAction(str, Enum):
    PLAN = "PLAN"
    APPROVE = "APPROVE"
    APPLY = "APPLY"
    RESUME = "RESUME"
    CANCEL = "CANCEL"
    RECOVER = "RECOVER"
    INSPECT = "INSPECT"


class HarnessOutcome(str, Enum):
    COMPLETE = "COMPLETE"


class CapabilityAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    BLOCKED = "BLOCKED"
    DEFERRED = "DEFERRED"


class HarnessErrorCode(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    UNSAFE_REQUEST_SOURCE = "UNSAFE_REQUEST_SOURCE"
    UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
    CAPABILITY_BLOCKED = "CAPABILITY_BLOCKED"
    CAPABILITY_DEFERRED = "CAPABILITY_DEFERRED"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    STALE_AUTHORITY = "STALE_AUTHORITY"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    HANDLER_RESULT_INVALID = "HANDLER_RESULT_INVALID"
    REGISTRY_INVALID = "REGISTRY_INVALID"


@dataclass(frozen=True)
class RecoveryReference:
    owner_kind: str
    owner_id: str
    owner_sha256: str | None

    def __post_init__(self) -> None:
        if (
            type(self.owner_kind) is not str
            or _REFERENCE_KIND.fullmatch(self.owner_kind) is None
            or type(self.owner_id) is not str
            or not self.owner_id
            or self.owner_id != self.owner_id.strip()
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in self.owner_id
            )
            or (
                self.owner_sha256 is not None
                and (
                    type(self.owner_sha256) is not str
                    or _SHA256.fullmatch(self.owner_sha256) is None
                )
            )
        ):
            raise _invalid_request()
        _bounded_text(self.owner_id, maximum=1024)


class HarnessDomainError(RuntimeError):
    __slots__ = ("_code", "_domain_code", "_recovery_owner", "_blockers")

    def __init__(
        self,
        *,
        code: HarnessErrorCode | str,
        domain_code: str,
        recovery_owner: RecoveryReference,
        blockers: tuple[str, ...],
    ) -> None:
        error_code = HarnessErrorCode(code)
        if error_code not in (
            HarnessErrorCode.STALE_AUTHORITY,
            HarnessErrorCode.RECOVERY_REQUIRED,
        ):
            raise _invalid_request()
        if (
            type(domain_code) is not str
            or _DOMAIN_CODE.fullmatch(domain_code) is None
            or not isinstance(recovery_owner, RecoveryReference)
            or type(blockers) is not tuple
            or len(blockers) > 32
            or blockers != tuple(sorted(set(blockers)))
        ):
            raise _invalid_request()
        for blocker in blockers:
            if (
                type(blocker) is not str
                or not blocker
                or blocker != blocker.strip()
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in blocker
                )
            ):
                raise _invalid_request()
            _bounded_text(blocker, maximum=1024)
        super().__init__(error_code.value)
        self._code = error_code
        self._domain_code = domain_code
        self._recovery_owner = recovery_owner
        self._blockers = blockers

    @property
    def code(self) -> str:
        return self._code.value

    @property
    def payload(self):
        return immutable_json(
            {
                "domain_code": self._domain_code,
                "recovery_owner": {
                    "owner_kind": self._recovery_owner.owner_kind,
                    "owner_id": self._recovery_owner.owner_id,
                    "owner_sha256": self._recovery_owner.owner_sha256,
                },
                "blockers": list(self._blockers),
            }
        )


@dataclass(frozen=True)
class ActionContract:
    action: LifecycleAction
    read_only: bool
    approval_required: bool
    authority_fields: tuple[str, ...] = ()
    payload_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.action, LifecycleAction)
            or type(self.read_only) is not bool
            or type(self.approval_required) is not bool
            or self.read_only is not (self.action is LifecycleAction.INSPECT)
            or (self.read_only and self.approval_required)
        ):
            raise _invalid_request()
        _field_tuple(self.authority_fields)
        _field_tuple(self.payload_fields)


_ACTION_ORDER = {action: index for index, action in enumerate(LifecycleAction)}


def _field_tuple(value: Any) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _invalid_request()
    for field in value:
        if type(field) is not str or _LIMIT_KEY.fullmatch(field) is None:
            raise _invalid_request()
    if value != tuple(sorted(set(value))):
        raise _invalid_request()
    return value


@dataclass(frozen=True)
class CapabilityDescriptor:
    schema_version: int
    operation_kind: str
    actions: tuple[ActionContract, ...]
    availability: CapabilityAvailability
    hard_limits: dict[str, int]
    activation_required: bool
    prerequisite: str | None

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or type(self.operation_kind) is not str
            or _OPERATION_KIND.fullmatch(self.operation_kind) is None
            or type(self.actions) is not tuple
            or not self.actions
            or any(not isinstance(action, ActionContract) for action in self.actions)
            or not isinstance(self.availability, CapabilityAvailability)
            or type(self.activation_required) is not bool
            or type(self.hard_limits) is not dict
        ):
            raise _invalid_request()
        action_values = tuple(action.action for action in self.actions)
        if (
            len(set(action_values)) != len(action_values)
            or action_values
            != tuple(sorted(action_values, key=lambda action: _ACTION_ORDER[action]))
        ):
            raise _invalid_request()
        for key, value in self.hard_limits.items():
            if (
                type(key) is not str
                or _LIMIT_KEY.fullmatch(key) is None
                or type(value) is not int
                or value < 1
            ):
                raise _invalid_request()
        if self.availability is CapabilityAvailability.AVAILABLE:
            if self.prerequisite is not None:
                raise _invalid_request()
        elif (
            type(self.prerequisite) is not str
            or not self.prerequisite
            or self.prerequisite != self.prerequisite.strip()
        ):
            raise _invalid_request()
        if self.prerequisite is not None:
            _bounded_text(self.prerequisite, maximum=1024)
        object.__setattr__(self, "hard_limits", _freeze_json(self.hard_limits))


@dataclass(frozen=True)
class HarnessRequest:
    schema_version: int
    operation_kind: str
    action: LifecycleAction
    root: str
    actor: str
    authority: dict[str, Any]
    payload: dict[str, Any]
    limits: dict[str, Any]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise _invalid_request()
        if (
            type(self.operation_kind) is not str
            or _OPERATION_KIND.fullmatch(self.operation_kind) is None
        ):
            raise _invalid_request()
        if not isinstance(self.action, LifecycleAction):
            raise _invalid_request()
        if type(self.root) is not str or not self.root.startswith("/"):
            raise _invalid_request()
        _bounded_text(self.root, maximum=4096)
        root_parts = self.root.split("/")
        if (
            (self.root != "/" and self.root.endswith("/"))
            or any(part in ("", ".", "..") for part in root_parts[1:])
            or "\\" in self.root
        ):
            raise _invalid_request()
        if (
            type(self.actor) is not str
            or not self.actor
            or self.actor != self.actor.strip()
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in self.actor)
        ):
            raise _invalid_request()
        _bounded_text(self.actor, maximum=256)
        if not isinstance(self.authority, dict) or not isinstance(self.payload, dict):
            raise _invalid_request()
        if not isinstance(self.limits, dict):
            raise _invalid_request()
        _validate_json(self.authority)
        _validate_json(self.payload)
        _validate_json(self.limits)
        for key, value in self.limits.items():
            if (
                _LIMIT_KEY.fullmatch(key) is None
                or type(value) is not int
                or value < 1
            ):
                raise _invalid_request()
        object.__setattr__(self, "authority", _freeze_json(self.authority))
        object.__setattr__(self, "payload", _freeze_json(self.payload))
        object.__setattr__(self, "limits", _freeze_json(self.limits))

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(request_payload(self))

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes)


@dataclass(frozen=True)
class HarnessResult:
    schema_version: int
    operation_kind: str
    action: LifecycleAction
    request_sha256: str
    outcome: HarnessOutcome
    read_only: bool
    artifacts: list[Any]
    effects: list[Any]
    not_modified: list[Any]
    blockers: list[Any]
    next_actions: list[Any]
    payload: dict[str, Any]
    _canonical_bytes: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if type(self.schema_version) is not int or self.schema_version != 1:
                raise _invalid_result()
            if (
                type(self.operation_kind) is not str
                or _OPERATION_KIND.fullmatch(self.operation_kind) is None
                or not isinstance(self.action, LifecycleAction)
                or type(self.request_sha256) is not str
                or _SHA256.fullmatch(self.request_sha256) is None
                or not isinstance(self.outcome, HarnessOutcome)
                or type(self.read_only) is not bool
                or type(self.payload) is not dict
            ):
                raise _invalid_result()
            for field_name in (
                "artifacts",
                "effects",
                "not_modified",
                "blockers",
                "next_actions",
            ):
                if type(getattr(self, field_name)) is not list:
                    raise _invalid_result()
                _validate_json(getattr(self, field_name))
            _validate_json(self.payload)
            for field_name in (
                "artifacts",
                "effects",
                "not_modified",
                "blockers",
                "next_actions",
                "payload",
            ):
                object.__setattr__(self, field_name, _freeze_json(getattr(self, field_name)))
            canonical = canonical_json_bytes(result_payload(self))
            if len(canonical) > MAX_RESULT_BYTES:
                raise _invalid_result()
            object.__setattr__(self, "_canonical_bytes", canonical)
        except CurationContractError as exc:
            if exc.code == "HANDLER_RESULT_INVALID":
                raise
            raise _invalid_result() from exc
        except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
            raise _invalid_result() from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes)


def parse_request_bytes(raw: bytes) -> HarnessRequest:
    try:
        if type(raw) is not bytes or not raw or len(raw) > MAX_REQUEST_BYTES:
            raise _invalid_request()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
        if type(value) is not dict or frozenset(value) != _REQUEST_KEYS:
            raise _invalid_request()
        _validate_json(value)
        action = LifecycleAction(value["action"])
        return HarnessRequest(
            schema_version=value["schema_version"],
            operation_kind=value["operation_kind"],
            action=action,
            root=value["root"],
            actor=value["actor"],
            authority=value["authority"],
            payload=value["payload"],
            limits=value["limits"],
        )
    except CurationContractError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise _invalid_request() from exc


def immutable_json(value: Any) -> Any:
    _validate_json(value)
    return _freeze_json(value)


def request_payload(request: HarnessRequest) -> dict[str, Any]:
    return _thaw_json(
        {
            "schema_version": request.schema_version,
            "operation_kind": request.operation_kind,
            "action": request.action.value,
            "root": request.root,
            "actor": request.actor,
            "authority": request.authority,
            "payload": request.payload,
            "limits": request.limits,
        }
    )


def result_payload(result: HarnessResult) -> dict[str, Any]:
    return _thaw_json(
        {
            "schema_version": result.schema_version,
            "operation_kind": result.operation_kind,
            "action": result.action.value,
            "request_sha256": result.request_sha256,
            "outcome": result.outcome.value,
            "read_only": result.read_only,
            "artifacts": result.artifacts,
            "effects": result.effects,
            "not_modified": result.not_modified,
            "blockers": result.blockers,
            "next_actions": result.next_actions,
            "payload": result.payload,
        }
    )


def capability_descriptor_payload(
    descriptor: CapabilityDescriptor,
) -> dict[str, Any]:
    return _thaw_json(
        {
            "schema_version": descriptor.schema_version,
            "operation_kind": descriptor.operation_kind,
            "actions": [
                {
                    "action": action.action.value,
                    "read_only": action.read_only,
                    "approval_required": action.approval_required,
                    "authority_fields": list(action.authority_fields),
                    "payload_fields": list(action.payload_fields),
                }
                for action in descriptor.actions
            ],
            "availability": descriptor.availability.value,
            "hard_limits": descriptor.hard_limits,
            "activation_required": descriptor.activation_required,
            "prerequisite": descriptor.prerequisite,
        }
    )
