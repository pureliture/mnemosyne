"""Immutable private operation Catalog rows for the D1a foundation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from .. import operation_contract


_OPERATION_KIND = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_MODULE_NAME = re.compile(r"mnemosyne_core(?:\.[a-z][a-z0-9_]*)+")
_SYMBOL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class OperationAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    BLOCKED = "BLOCKED"
    DEFERRED = "DEFERRED"


@dataclass(frozen=True)
class OperationSpec:
    """A complete immutable operation row; handler bindings live nowhere else."""

    operation_kind: str
    spec_identity: str
    spec_sha256: str
    admission_contract: operation_contract.AdmissionContract
    source_module: str
    source_path: str
    source_symbol: str
    source_sha256: str
    handler: object
    handler_module: str | None
    handler_symbol: str | None
    handler_sha256: str | None
    availability: OperationAvailability
    availability_reason: str | None
    request_validator: object = None
    result_validator: object = None

    def __post_init__(self) -> None:
        if type(self.operation_kind) is not str or _OPERATION_KIND.fullmatch(
            self.operation_kind
        ) is None:
            raise ValueError("operation kind is invalid")
        if type(self.spec_identity) is not str or not self.spec_identity:
            raise ValueError("operation spec identity is invalid")
        if type(self.spec_sha256) is not str or _SHA256.fullmatch(self.spec_sha256) is None:
            raise ValueError("operation spec hash is invalid")
        if type(self.admission_contract) is not operation_contract.AdmissionContract:
            raise ValueError("operation admission contract is invalid")
        if (
            self.admission_contract.operation_kind != self.operation_kind
            or self.admission_contract.spec_identity != self.spec_identity
            or self.admission_contract.spec_sha256 != self.spec_sha256
        ):
            raise ValueError("operation admission contract does not match its row")
        if type(self.source_module) is not str or _MODULE_NAME.fullmatch(
            self.source_module
        ) is None:
            raise ValueError("operation source module is invalid")
        if type(self.source_symbol) is not str or _SYMBOL_NAME.fullmatch(
            self.source_symbol
        ) is None:
            raise ValueError("operation source symbol is invalid")
        if (
            type(self.source_path) is not str
            or not self.source_path
            or self.source_path.startswith("/")
            or self.source_path != self.source_path.strip()
            or "/../" in self.source_path
        ):
            raise ValueError("operation source path is invalid")
        if type(self.source_sha256) is not str or _SHA256.fullmatch(
            self.source_sha256
        ) is None:
            raise ValueError("operation source hash is invalid")
        if not isinstance(self.availability, OperationAvailability):
            raise ValueError("operation availability is invalid")
        if self.availability is OperationAvailability.AVAILABLE:
            if not callable(self.handler):
                raise ValueError("available operation requires exactly one handler")
            if type(self.handler_module) is not str or _MODULE_NAME.fullmatch(
                self.handler_module
            ) is None:
                raise ValueError("handler module is invalid")
            if type(self.handler_symbol) is not str or _SYMBOL_NAME.fullmatch(
                self.handler_symbol
            ) is None:
                raise ValueError("handler symbol is invalid")
            if type(self.handler_sha256) is not str or _SHA256.fullmatch(
                self.handler_sha256
            ) is None:
                raise ValueError("handler hash is invalid")
            if self.availability_reason is not None:
                raise ValueError("available operation cannot have an availability reason")
            if not callable(self.request_validator):
                raise ValueError("available operation requires one request validator")
            if not callable(self.result_validator):
                raise ValueError("available operation requires one result validator")
        elif (
            self.handler is not None
            or self.handler_module is not None
            or self.handler_symbol is not None
            or self.handler_sha256 is not None
            or self.request_validator is not None
            or self.result_validator is not None
        ):
            raise ValueError("blocked or deferred operation must not bind a handler")
        elif (
            type(self.availability_reason) is not str
            or not self.availability_reason
            or self.availability_reason != self.availability_reason.strip()
        ):
            raise ValueError("blocked or deferred operation requires an availability reason")


@dataclass(frozen=True)
class OperationCatalog:
    specs: tuple[OperationSpec, ...]

    def __post_init__(self) -> None:
        if (
            type(self.specs) is not tuple
            or not self.specs
            or any(type(spec) is not OperationSpec for spec in self.specs)
        ):
            raise ValueError("operation catalog is invalid")
        kinds = tuple(spec.operation_kind for spec in self.specs)
        if len(set(kinds)) != len(kinds):
            raise ValueError("duplicate operation kind in catalog")
        identities = tuple(spec.spec_identity for spec in self.specs)
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate operation spec identity in catalog")

    @property
    def by_kind(self) -> MappingProxyType:
        return MappingProxyType({spec.operation_kind: spec for spec in self.specs})

    def require_spec(self, operation_kind: str) -> OperationSpec:
        if type(operation_kind) is not str:
            raise ValueError("operation kind is invalid")
        try:
            return self.by_kind[operation_kind]
        except KeyError as exc:
            raise ValueError("operation kind is not cataloged") from exc
