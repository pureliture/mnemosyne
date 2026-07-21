"""Bounded read-only views for the Curation Harness.

Only audit and capability catalog are admitted before the M3 reviewer gate.
The remaining fixed Inspect view names stay represented by blocked or deferred
registry descriptors until their authoritative read models are safe to bind.
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import curation_audit as curation_audit_core
from . import ledger_runtime, progress_query
from .canonical_json import canonical_json_bytes
from .curation_contract import (
    MAX_RESULT_BYTES,
    CapabilityDescriptor,
    HarnessOutcome,
    HarnessRequest,
    HarnessResult,
    LifecycleAction,
    capability_descriptor_payload,
    immutable_json,
)


MAX_INSPECT_ITEMS = 256
DEFAULT_CAPABILITY_ITEMS = MAX_INSPECT_ITEMS
_COMMON_LIMITS = frozenset(("max_items", "max_request_bytes", "max_result_bytes"))
_INSPECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class InspectReadError(ValueError):
    """An internal gated Inspect projection cannot be produced safely."""


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(nested) for key, nested in value.items()}
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return [_thaw(nested) for nested in value]
    return value


def _bounded_projection(payload: dict[str, Any]):
    try:
        if len(canonical_json_bytes(payload)) > MAX_RESULT_BYTES:
            raise InspectReadError("inspect projection exceeds byte budget")
        return immutable_json(payload)
    except InspectReadError:
        raise
    except (
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise InspectReadError("inspect projection is invalid") from exc


def _validate_request(
    request: Any,
    operation_kind: str,
    *,
    maximum_items: int,
    payload_fields: frozenset[str] = frozenset(),
) -> None:
    if (
        not isinstance(request, HarnessRequest)
        or request.operation_kind != operation_kind
        or request.action is not LifecycleAction.INSPECT
        or request.authority != {}
        or not isinstance(request.payload, Mapping)
        or frozenset(request.payload) != payload_fields
        or not set(request.limits).issubset(_COMMON_LIMITS)
    ):
        raise ValueError("INVALID_REQUEST")
    maximum = request.limits.get("max_items", maximum_items)
    if type(maximum) is not int or not 1 <= maximum <= maximum_items:
        raise ValueError("INVALID_REQUEST")


def validate_capabilities_request(request: Any) -> None:
    _validate_request(
        request,
        "inspect.capabilities",
        maximum_items=MAX_INSPECT_ITEMS,
    )


def _base_result(
    request: HarnessRequest,
    *,
    payload: dict[str, Any],
    blockers: list[str] | None = None,
) -> HarnessResult:
    return HarnessResult(
        schema_version=1,
        operation_kind=request.operation_kind,
        action=request.action,
        request_sha256=request.sha256,
        outcome=HarnessOutcome.COMPLETE,
        read_only=True,
        artifacts=[],
        effects=[],
        not_modified=["corpus", "filesystem", "ledger"],
        blockers=[] if blockers is None else blockers,
        next_actions=[],
        payload=payload,
    )


def capabilities_result(
    request: HarnessRequest,
    descriptors: tuple[CapabilityDescriptor, ...],
) -> HarnessResult:
    ordered = tuple(sorted(descriptors, key=lambda value: value.operation_kind))
    maximum = request.limits.get("max_items", DEFAULT_CAPABILITY_ITEMS)
    projected = ordered[:maximum]
    counts = {"available": 0, "blocked": 0, "deferred": 0}
    for descriptor in ordered:
        counts[descriptor.availability.value.lower()] += 1
    payload = {
        "capabilities": [
            capability_descriptor_payload(descriptor) for descriptor in projected
        ],
        "returned": len(projected),
        "schema_version": 1,
        "summary": {"total": len(ordered), **counts},
        "truncated": len(projected) < len(ordered),
        "view": "capabilities",
    }
    return _base_result(request, payload=payload)


def _inspect_root(root: Path) -> Path:
    value = Path(root)
    if not value.is_absolute() or any(part in (".", "..") for part in value.parts):
        raise InspectReadError("raw root is invalid")
    return value


def _inspect_identifier(value: Any, label: str) -> str:
    if type(value) is not str or _INSPECT_ID.fullmatch(value) is None:
        raise InspectReadError("%s is invalid" % label)
    return value


def _inspect_reference(
    value: Any,
    *,
    kinds: tuple[str, ...],
) -> dict[str, str]:
    if type(value) is not dict or set(value) != {"id", "kind"}:
        raise InspectReadError("inspect reference is invalid")
    kind = _inspect_identifier(value["kind"], "inspect reference kind")
    if kind not in kinds:
        raise InspectReadError("inspect reference kind is unsupported")
    return {
        "id": _inspect_identifier(value["id"], "inspect reference id"),
        "kind": kind,
    }


def _inspect_as_of(value: Any) -> datetime.datetime:
    if type(value) is not str or len(value) != 20:
        raise InspectReadError("inspect as-of time is invalid")
    try:
        parsed = datetime.datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=datetime.timezone.utc)
    except ValueError as exc:
        raise InspectReadError("inspect as-of time is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise InspectReadError("inspect as-of time is invalid")
    return parsed


def _inspect_max_items(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_INSPECT_ITEMS:
        raise InspectReadError("inspect max items is invalid")
    return value


def _control_root_present(root: Path) -> bool:
    try:
        return curation_audit_core.control_root_present(
            root / "_registry" / "curation"
        )
    except curation_audit_core.CurationAuditError as exc:
        raise InspectReadError("curation state is unavailable") from exc


def _policy_payload(policy_ref: Any) -> dict[str, Any]:
    return {
        "full_sha256": policy_ref.full_hash,
        "generation": policy_ref.generation,
        "guard_epoch": policy_ref.guard_epoch,
    }


def _query_for_reader(
    reader: ledger_runtime.ReaderSession,
    *,
    as_of: datetime.datetime,
) -> progress_query.ProgressQuery:
    workstreams = {
        workstream.id: workstream.lifecycle
        for workstream in reader.compiled_policy.workstreams
    }

    def lifecycle(workstream_id: str) -> str:
        try:
            return workstreams[workstream_id]
        except KeyError as exc:
            raise progress_query.ProgressQueryError(
                "workstream does not exist"
            ) from exc

    return progress_query.ProgressQuery(
        reader.connection,
        now=lambda: as_of,
        workstream_lifecycle=lifecycle,
        current_policy_hash=lambda: reader.approved_policy_ref.full_hash,
    )


def _missing_status(reference: dict[str, str], as_of: str):
    return _bounded_projection(
        {
            "activation_state": "NOT_ACTIVATED",
            "as_of": as_of,
            "blockers": ["curation-state-not-activated"],
            "policy": None,
            "read_only": True,
            "reference": reference,
            "returned": 0,
            "schema_version": 1,
            "status": None,
            "truncated": False,
            "view": "status",
        }
    )


def read_status(
    root: Path,
    *,
    reference: dict[str, Any],
    as_of: str,
    max_items: int,
):
    canonical = _inspect_root(root)
    exact_reference = _inspect_reference(reference, kinds=("item", "workstream"))
    exact_time = _inspect_as_of(as_of)
    maximum = _inspect_max_items(max_items)
    if not _control_root_present(canonical):
        return _missing_status(exact_reference, as_of)
    try:
        with ledger_runtime.open_reader_session(canonical, immutable=True) as reader:
            query = _query_for_reader(reader, as_of=exact_time)
            if exact_reference["kind"] == "workstream":
                if not any(
                    workstream.id == exact_reference["id"]
                    for workstream in reader.compiled_policy.workstreams
                ):
                    raise InspectReadError("workstream does not exist")
                status = query.workstream_home(
                    exact_reference["id"],
                    max_items=maximum,
                )
                returned = status["returned"]
                truncated = status["truncated"]
            else:
                status = query.item_detail(
                    exact_reference["id"],
                    max_items=maximum,
                )
                returned = 1
                truncated = status["relations_truncated"]
            observed = reader.current_policy()
    except InspectReadError:
        raise
    except progress_query.ProgressQueryError as exc:
        raise InspectReadError(str(exc)) from exc
    except ledger_runtime.PolicyAdmissionError:
        return _bounded_projection(
            {
                **_thaw(_missing_status(exact_reference, as_of)),
                "activation_state": "POLICY_BLOCKED",
                "blockers": ["policy-admission-blocked"],
            }
        )
    except ledger_runtime.LedgerRuntimeError:
        return _bounded_projection(
            {
                **_thaw(_missing_status(exact_reference, as_of)),
                "activation_state": "UNAVAILABLE",
                "blockers": ["curation-state-unavailable"],
            }
        )
    return _bounded_projection(
        {
            "activation_state": "ACTIVATED",
            "as_of": as_of,
            "blockers": [],
            "policy": _policy_payload(observed),
            "read_only": True,
            "reference": exact_reference,
            "returned": returned,
            "schema_version": 1,
            "status": status,
            "truncated": truncated,
            "view": "status",
        }
    )


def _missing_history(reference: dict[str, str]):
    return _bounded_projection(
        {
            "activation_state": "NOT_ACTIVATED",
            "blockers": ["curation-state-not-activated"],
            "entries": [],
            "policy": None,
            "read_only": True,
            "reference": reference,
            "returned": 0,
            "schema_version": 1,
            "truncated": False,
            "view": "history",
        }
    )


def read_history(
    root: Path,
    *,
    reference: dict[str, Any],
    max_items: int,
):
    canonical = _inspect_root(root)
    exact_reference = _inspect_reference(reference, kinds=("item",))
    maximum = _inspect_max_items(max_items)
    if not _control_root_present(canonical):
        return _missing_history(exact_reference)
    try:
        with ledger_runtime.open_reader_session(canonical, immutable=True) as reader:
            query = _query_for_reader(
                reader,
                as_of=datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc),
            )
            history = query.history(exact_reference["id"], max_items=maximum)
            observed = reader.current_policy()
    except progress_query.ProgressQueryError as exc:
        raise InspectReadError(str(exc)) from exc
    except ledger_runtime.PolicyAdmissionError:
        return _bounded_projection(
            {
                **_thaw(_missing_history(exact_reference)),
                "activation_state": "POLICY_BLOCKED",
                "blockers": ["policy-admission-blocked"],
            }
        )
    except ledger_runtime.LedgerRuntimeError:
        return _bounded_projection(
            {
                **_thaw(_missing_history(exact_reference)),
                "activation_state": "UNAVAILABLE",
                "blockers": ["curation-state-unavailable"],
            }
        )
    return _bounded_projection(
        {
            "activation_state": "ACTIVATED",
            "blockers": [],
            "entries": history["entries"],
            "policy": _policy_payload(observed),
            "read_only": True,
            "reference": exact_reference,
            "returned": history["returned"],
            "schema_version": 1,
            "truncated": history["truncated"],
            "view": "history",
        }
    )


def _missing_pending(
    *,
    reference: dict[str, str] | None,
    state: str,
    as_of: str,
):
    return _bounded_projection(
        {
            "activation_state": "NOT_ACTIVATED",
            "as_of": as_of,
            "blockers": ["curation-state-not-activated"],
            "filter": {
                "state": state,
                "workstream_id": None if reference is None else reference["id"],
            },
            "items": [],
            "policy": None,
            "read_only": True,
            "returned": 0,
            "scan_truncated": False,
            "schema_version": 1,
            "truncated": False,
            "view": "pending",
        }
    )


def read_pending(
    root: Path,
    *,
    reference: dict[str, Any] | None,
    state: str,
    as_of: str,
    max_items: int,
):
    canonical = _inspect_root(root)
    exact_reference = (
        None
        if reference is None
        else _inspect_reference(reference, kinds=("workstream",))
    )
    if state not in ("all", "due", "waiting"):
        raise InspectReadError("pending state is invalid")
    exact_time = _inspect_as_of(as_of)
    maximum = _inspect_max_items(max_items)
    if not _control_root_present(canonical):
        return _missing_pending(
            reference=exact_reference,
            state=state,
            as_of=as_of,
        )
    try:
        with ledger_runtime.open_reader_session(canonical, immutable=True) as reader:
            if exact_reference is not None and not any(
                workstream.id == exact_reference["id"]
                for workstream in reader.compiled_policy.workstreams
            ):
                raise InspectReadError("workstream does not exist")
            query = _query_for_reader(reader, as_of=exact_time)
            pending = query.list_deferred(
                state=state,
                workstream_id=(
                    None if exact_reference is None else exact_reference["id"]
                ),
                max_items=maximum,
            )
            observed = reader.current_policy()
    except InspectReadError:
        raise
    except progress_query.ProgressQueryError as exc:
        raise InspectReadError(str(exc)) from exc
    except ledger_runtime.PolicyAdmissionError:
        return _bounded_projection(
            {
                **_thaw(
                    _missing_pending(
                        reference=exact_reference,
                        state=state,
                        as_of=as_of,
                    )
                ),
                "activation_state": "POLICY_BLOCKED",
                "blockers": ["policy-admission-blocked"],
            }
        )
    except ledger_runtime.LedgerRuntimeError:
        return _bounded_projection(
            {
                **_thaw(
                    _missing_pending(
                        reference=exact_reference,
                        state=state,
                        as_of=as_of,
                    )
                ),
                "activation_state": "UNAVAILABLE",
                "blockers": ["curation-state-unavailable"],
            }
        )
    return _bounded_projection(
        {
            "activation_state": "ACTIVATED",
            "as_of": as_of,
            "blockers": [],
            "filter": {
                "state": state,
                "workstream_id": (
                    None if exact_reference is None else exact_reference["id"]
                ),
            },
            "items": pending["items"],
            "policy": _policy_payload(observed),
            "read_only": True,
            "returned": pending["returned"],
            "scan_truncated": pending["truncated"],
            "schema_version": 1,
            "truncated": pending["truncated"],
            "view": "pending",
        }
    )


def _validate_result_base(result: Any, operation_kind: str, view: str) -> dict[str, Any]:
    if (
        not isinstance(result, HarnessResult)
        or result.operation_kind != operation_kind
        or result.action is not LifecycleAction.INSPECT
        or result.outcome is not HarnessOutcome.COMPLETE
        or result.read_only is not True
        or result.artifacts != []
        or result.effects != []
        or result.not_modified != ["corpus", "filesystem", "ledger"]
        or result.next_actions != []
    ):
        raise ValueError("HANDLER_RESULT_INVALID")
    payload = _thaw(result.payload)
    if type(payload) is not dict or payload.get("view") != view:
        raise ValueError("HANDLER_RESULT_INVALID")
    return payload


def validate_capabilities_result(
    result: Any,
    descriptors: tuple[CapabilityDescriptor, ...],
) -> None:
    payload = _validate_result_base(
        result, "inspect.capabilities", "capabilities"
    )
    summary = payload.get("summary")
    capabilities = payload.get("capabilities")
    if (
        set(payload)
        != {
            "capabilities",
            "returned",
            "schema_version",
            "summary",
            "truncated",
            "view",
        }
        or payload["schema_version"] != 1
        or type(capabilities) is not list
        or type(summary) is not dict
        or set(summary) != {"available", "blocked", "deferred", "total"}
        or any(type(value) is not int or value < 0 for value in summary.values())
        or summary["total"]
        != summary["available"] + summary["blocked"] + summary["deferred"]
        or type(payload["returned"]) is not int
        or payload["returned"] != len(capabilities)
        or not 1 <= payload["returned"] <= min(summary["total"], MAX_INSPECT_ITEMS)
        or type(payload["truncated"]) is not bool
        or payload["truncated"] is not (summary["total"] > payload["returned"])
    ):
        raise ValueError("HANDLER_RESULT_INVALID")
    descriptor_keys = {
        "schema_version",
        "operation_kind",
        "actions",
        "availability",
        "hard_limits",
        "activation_required",
        "prerequisite",
    }
    action_keys = {
        "action",
        "read_only",
        "approval_required",
        "authority_fields",
        "payload_fields",
    }
    if _thaw(result.blockers) != []:
        raise ValueError("HANDLER_RESULT_INVALID")
    operation_kinds = []
    for entry in capabilities:
        if (
            type(entry) is not dict
            or set(entry) != descriptor_keys
            or type(entry["operation_kind"]) is not str
            or type(entry["actions"]) is not list
            or any(
                type(action) is not dict or set(action) != action_keys
                for action in entry["actions"]
            )
        ):
            raise ValueError("HANDLER_RESULT_INVALID")
        operation_kinds.append(entry["operation_kind"])
    if (
        operation_kinds != sorted(operation_kinds)
        or len(set(operation_kinds)) != len(operation_kinds)
    ):
        raise ValueError("HANDLER_RESULT_INVALID")
    ordered = tuple(sorted(descriptors, key=lambda value: value.operation_kind))
    expected = [capability_descriptor_payload(descriptor) for descriptor in ordered]
    expected_counts = {"available": 0, "blocked": 0, "deferred": 0}
    for descriptor in ordered:
        expected_counts[descriptor.availability.value.lower()] += 1
    if (
        capabilities != expected[: payload["returned"]]
        or summary != {"total": len(expected), **expected_counts}
        or payload["truncated"] is not (payload["returned"] < len(expected))
    ):
        raise ValueError("HANDLER_RESULT_INVALID")


__all__ = [
    "MAX_INSPECT_ITEMS",
    "InspectReadError",
    "capabilities_result",
    "read_history",
    "read_pending",
    "read_status",
    "validate_capabilities_request",
    "validate_capabilities_result",
]
