"""Direct, session-bound owner for the available ``inspect.audit`` operation.

This module deliberately knows how to validate and project one immutable audit
report.  It never receives a root, opens a ledger, or imports a legacy
workflow.  Those capabilities remain private to the Authority Runtime's
closed ``CURATION_AUDIT`` read profile.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from . import activation_contract, operation_contract
from .canonical_json import canonical_json_bytes


MAX_AUDIT_ITEMS = 64
MAX_AUDIT_RESULT_BYTES = 64 * 1024 * 1024
_AUDIT_FINDING_KEYS = frozenset(
    (
        "batch_event_id",
        "blocking",
        "category",
        "code",
        "item_id",
        "path",
        "primary_state",
        "source_freshness",
        "state",
    )
)
_REPORT_KEYS = frozenset(
    (
        "curation_complete",
        "findings",
        "integrity_ok",
        "kind",
        "read_only",
        "schema_version",
        "scope",
        "summary",
    )
)
def validate_audit_request(request: object) -> None:
    """Validate all audit-specific user input before any root access."""

    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "inspect.audit"
        or request.action is not operation_contract.LifecycleAction.INSPECT
        or request.claim_mode is not operation_contract.ClaimMode.HISTORICAL
        or request.requested_authority is not operation_contract.AuthorityMode.READ
        or set(request.scope)
        or set(request.payload) != {"offset"}
        or set(request.bounds) != {"max_items"}
    ):
        raise ValueError("inspect audit request is invalid")
    offset = request.payload["offset"]
    maximum = request.bounds["max_items"]
    if (
        type(offset) is not int
        or offset < 0
        or type(maximum) is not int
        or not 1 <= maximum <= MAX_AUDIT_ITEMS
    ):
        raise ValueError("inspect audit page is invalid")


def _audit_page(admitted: operation_contract.AdmittedOperation) -> tuple[int, int]:
    value = admitted.input
    try:
        payload = value["payload"]
        bounds = value["bounds"]
        offset = payload["offset"]
        maximum = bounds["max_items"]
    except (KeyError, TypeError) as exc:
        raise ValueError("admitted audit page is invalid") from exc
    if (
        not isinstance(payload, Mapping)
        or not isinstance(bounds, Mapping)
        or set(payload) != {"offset"}
        or set(bounds) != {"max_items"}
        or type(offset) is not int
        or offset < 0
        or type(maximum) is not int
        or not 1 <= maximum <= MAX_AUDIT_ITEMS
    ):
        raise ValueError("admitted audit page is invalid")
    return offset, maximum


def _as_plain_finding(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not set(value).issubset(_AUDIT_FINDING_KEYS):
        raise ValueError("curation audit finding is invalid")
    if (
        type(value.get("blocking")) is not bool
        or value.get("category") not in {"drift", "integrity", "orphan"}
        or type(value.get("code")) is not str
        or not value["code"]
    ):
        raise ValueError("curation audit finding is invalid")
    return {key: value[key] for key in sorted(value)}


def _full_report(source: object) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(source, Mapping) or set(source) != _REPORT_KEYS:
        raise ValueError("curation audit report is invalid")
    findings = source["findings"]
    if (
        not isinstance(findings, Sequence)
        or isinstance(findings, (str, bytes, bytearray))
        or source["kind"] != "CurationAudit"
        or source["read_only"] is not True
        or source["schema_version"] != 1
        or source["curation_complete"] is not None
        or type(source["integrity_ok"]) is not bool
        or not isinstance(source["scope"], Mapping)
        or not isinstance(source["summary"], Mapping)
    ):
        raise ValueError("curation audit report is invalid")
    normalized = [_as_plain_finding(finding) for finding in findings]
    if source["integrity_ok"] is not (not any(item["blocking"] for item in normalized)):
        raise ValueError("curation audit report is invalid")
    report = {
        "curation_complete": None,
        "integrity_ok": source["integrity_ok"],
        "scope": dict(source["scope"]),
        "summary": dict(source["summary"]),
    }
    return report, normalized


def project_activation_audit_report(
    source: object,
    evidence: object,
    *,
    offset: int,
    maximum: int,
) -> dict[str, Any]:
    """Project one sealed audit observation into the sole public v2 shape."""

    if (
        type(offset) is not int
        or offset < 0
        or type(maximum) is not int
        or not 1 <= maximum <= MAX_AUDIT_ITEMS
    ):
        raise ValueError("audit page is invalid")
    report, findings = _full_report(source)
    public_fields = getattr(evidence, "public_fields", None)
    if not callable(public_fields):
        raise ValueError("activation audit evidence is invalid")
    fields = public_fields()
    required_fields = {
        "exact_root",
        "activation_state",
        "activation_eligible",
        "reason_code",
        "next_safe_action",
        "allowed_namespace",
        "corpus_effect",
        "root_identity_sha256",
        "initial_policy",
    }
    if not isinstance(fields, Mapping) or set(fields) != required_fields:
        raise ValueError("activation audit evidence is invalid")
    fields = dict(fields)
    state = fields["activation_state"]
    if state not in {
        "NOT_ACTIVATED",
        "ACTIVE",
        "LOCAL",
        "RECOVERY_REQUIRED",
        "BLOCKED",
    }:
        raise ValueError("activation audit evidence is invalid")
    if state == "ACTIVE" and not report["integrity_ok"]:
        fields.update(
            {
                "activation_state": "BLOCKED",
                "activation_eligible": False,
                "reason_code": "FOUNDATION_READBACK_FAILED",
                "next_safe_action": "Review the activation foundation manually.",
                "initial_policy": None,
            }
        )
        state = "BLOCKED"
    if state == "NOT_ACTIVATED":
        projected = []
        blockers = []
        blocking_total = 0
        next_offset = None
        truncated = False
        integrity_ok = True
        scope = {}
        summary = {}
    else:
        projected = findings[offset : offset + maximum]
        next_index = offset + len(projected)
        truncated = next_index < len(findings)
        next_offset = next_index if truncated else None
        blockers = sorted(
            {finding["code"] for finding in projected if finding["blocking"]}
        )
        if truncated:
            blockers.append("audit-findings-truncated")
            blockers.sort()
        blocking_total = sum(finding["blocking"] for finding in findings)
        integrity_ok = False if state == "BLOCKED" else report["integrity_ok"]
        scope = report["scope"]
        summary = report["summary"]
    result = {
        "schema_version": 2,
        "view": "audit",
        "read_only": True,
        **fields,
        "integrity_ok": integrity_ok,
        "curation_complete": report["curation_complete"],
        "scope": scope,
        "summary": summary,
        "blockers": blockers,
        "findings": projected,
        "blocking_total": blocking_total,
        "offset": offset,
        "returned": len(projected),
        "next_offset": next_offset,
        "truncated": truncated,
    }
    if len(canonical_json_bytes(result)) > MAX_AUDIT_RESULT_BYTES:
        raise ValueError("curation audit result exceeds byte budget")
    return activation_contract.require_audit_result(result)


def validate_audit_result(outcome: object) -> None:
    """Reject a malformed audit outcome before it reaches the public adapter."""

    if (
        type(outcome) is not operation_contract.OperationOutcome
        or outcome.outcome_kind != "completed"
        or not isinstance(outcome.result, Mapping)
    ):
        raise ValueError("curation audit outcome is invalid")
    result = outcome.result
    activation_contract.require_audit_result(result)
    if len(canonical_json_bytes(result)) > MAX_AUDIT_RESULT_BYTES:
        raise ValueError("curation audit outcome exceeds byte budget")


def audit_handler(
    admitted: operation_contract.AdmittedOperation,
    session: object,
) -> operation_contract.OperationOutcome:
    """Project the one audit report yielded by a verified read session."""

    offset, maximum = _audit_page(admitted)
    report = getattr(session, "curation_audit_report", None)
    if not callable(report):
        raise ValueError("curation audit session capability is unavailable")
    source = report()
    activation_evidence = getattr(session, "activation_audit_evidence", None)
    evidence = activation_evidence() if callable(activation_evidence) else None
    if evidence is None:
        raise ValueError("activation audit evidence is unavailable")
    result = project_activation_audit_report(
        source,
        evidence,
        offset=offset,
        maximum=maximum,
    )
    outcome = operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result=result,
    )
    validate_audit_result(outcome)
    return outcome


__all__ = [
    "MAX_AUDIT_ITEMS",
    "audit_handler",
    "project_activation_audit_report",
    "validate_audit_request",
    "validate_audit_result",
]
