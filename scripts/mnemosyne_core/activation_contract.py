"""Pure public contracts for Safe Librarian first activation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from . import artifact_contract, control, ledger_schema, operation_contract
from .canonical_json import canonical_json_bytes, sha256_bytes


_ACTIVATION_ID = re.compile(r"act-[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_INITIAL_POLICY_KEYS = frozenset(
    (
        "effective_policy_source_sha256",
        "foundation_hash",
        "full_hash",
        "mode",
        "overlay_sha256",
        "registry_input_sha256",
        "writer_control_hash",
    )
)
_AUDIT_RESULT_KEYS = frozenset(
    (
        "activation_eligible",
        "activation_state",
        "allowed_namespace",
        "blockers",
        "blocking_total",
        "corpus_effect",
        "curation_complete",
        "exact_root",
        "findings",
        "initial_policy",
        "integrity_ok",
        "next_offset",
        "next_safe_action",
        "offset",
        "read_only",
        "reason_code",
        "returned",
        "root_identity_sha256",
        "schema_version",
        "scope",
        "summary",
        "truncated",
        "view",
    )
)
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
_AUDIT_ACTIONS = {
    "NOT_ACTIVATED": {
        "FRESH_CURATION_STATE": (
            "Review one activation draft; no document will move."
        ),
    },
    "ACTIVE": {
        "ALREADY_ACTIVE": "Inspect one bounded scope.",
    },
    "LOCAL": {
        "LOCAL_SQLITE_RUNTIME": "Use the local SQLite runtime.",
    },
    "RECOVERY_REQUIRED": {
        "PRESEAL_ORPHAN": (
            "Review the pre-seal activation namespace manually."
        ),
        "RECOVERY_SAME_REQUEST_ONLY": (
            "Resend the exact sealed activation request."
        ),
    },
    "BLOCKED": {
        "EXPLICIT_CURATION_REQUIRES_REVIEW": (
            "Review the explicit Curation policy manually."
        ),
        "FOUNDATION_READBACK_FAILED": (
            "Review the activation foundation manually."
        ),
        "LEGACY_AUTHORITY_PRESENT": (
            "Review existing authority evidence manually."
        ),
        "UNKNOWN_AUTHORITY_MEMBER": (
            "Review the activation foundation manually."
        ),
        "UNSAFE_BOUNDARY": (
            "Review the unsafe authority boundary manually."
        ),
    },
}
_RECEIPT_FIELDS = (
    "schema",
    "kind",
    "status",
    "activation_id",
    "request_sha256",
    "actor",
    "exact_root",
    "root_identity_sha256",
    "allowed_namespace",
    "corpus_effect",
    "initial_policy",
    "schema_identity",
    "initial_snapshot_identity",
    "write_set",
    "control_bootstrap_rows",
    "legacy_evidence",
    "logical_readback_sha256",
)

RECEIPT_SCHEMA = artifact_contract.SchemaIdentity(
    kind="SAFE_LIBRARIAN_ACTIVATION_RECEIPT",
    version=1,
    schema_sha256=sha256_bytes(
        canonical_json_bytes(
            {
                "additional_properties": False,
                "canonical_encoding": "mnemosyne-canonical-json-v1",
                "fields": list(_RECEIPT_FIELDS),
                "kind": "SAFE_LIBRARIAN_ACTIVATION_RECEIPT",
                "schema_version": 1,
            }
        )
    ),
)


def audit_next_safe_action(state: object, reason_code: object) -> str:
    """Return the one public action admitted for an audit state and reason."""

    if type(state) is not str or type(reason_code) is not str:
        raise ValueError("activation audit state and reason are invalid")
    try:
        return _AUDIT_ACTIONS[state][reason_code]
    except KeyError as exc:
        raise ValueError("activation audit state and reason are invalid") from exc


RECEIPT_PATH = "_registry/curation/activation/v1/receipt.json"
ACTIVATION_V2_SOURCE_ID = "safe-librarian-activation-v2"
_FINAL_WRITE_SET = (
    ("_registry/curation", "directory", 0o700, False),
    ("_registry/curation/activation", "directory", 0o700, False),
    ("_registry/curation/activation/v1", "directory", 0o700, False),
    ("_registry/curation/activation/v1/request.json", "file", 0o600, True),
    ("_registry/curation/activation/v1/receipt.json", "file", 0o600, True),
    ("_registry/curation/activation/v1/staging", "directory", 0o700, False),
    ("_registry/curation/ledger.lock", "file", 0o600, True),
    ("_registry/curation/ledger.sqlite3", "file", 0o600, True),
    ("_registry/curation/policy.lock", "file", 0o600, True),
)


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def require_initial_policy(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _INITIAL_POLICY_KEYS:
        raise ValueError("initial activation policy is invalid")
    if value.get("mode") != "safe-librarian-initial-curation-v1":
        raise ValueError("initial activation policy is invalid")
    result = {"mode": value["mode"]}
    for field in sorted(_INITIAL_POLICY_KEYS - {"mode"}):
        result[field] = _require_sha256(value[field], field)
    return result


def activation_write_set(uid: int) -> list[dict[str, object]]:
    """Return the exact final persistent activation namespace declaration."""

    if type(uid) is not int or uid < 0:
        raise ValueError("activation write-set uid is invalid")
    result = []
    for path, entry_kind, mode, linked in _FINAL_WRITE_SET:
        entry: dict[str, object] = {
            "kind": entry_kind,
            "mode": mode,
            "path": path,
            "uid": uid,
        }
        if linked:
            entry["nlink"] = 1
        result.append(entry)
    return result


def _require_schema_identity(
    value: object,
    *,
    activation_id: str,
) -> dict[str, object]:
    expected = {
        "control": {
            "applied_by": activation_id,
            "schema_sha256": control.CONTROL_SCHEMA_SHA256,
            "version": control.CONTROL_SCHEMA_VERSION,
        },
        "ledger": {
            "applied_by": ACTIVATION_V2_SOURCE_ID,
            "schema_sha256": ledger_schema.LEDGER_SCHEMA_SHA256,
            "version": ledger_schema.LEDGER_SCHEMA_VERSION,
        },
    }
    if value != expected:
        raise ValueError("activation receipt schema identity is invalid")
    return expected


def _require_snapshot_identity(
    value: object,
    *,
    activation_id: str,
    initial_policy: Mapping[str, str],
) -> dict[str, object]:
    snapshot_id = "policy-00000001-" + initial_policy["full_hash"][:24]
    expected = {
        "foundation_hash": initial_policy["foundation_hash"],
        "full_hash": initial_policy["full_hash"],
        "generation": 1,
        "guard_epoch": 0,
        "snapshot_id": snapshot_id,
        "source_kind": "INITIAL",
        "source_run_id": activation_id,
        "state": "TERMINAL",
        "writer_control_hash": initial_policy["writer_control_hash"],
    }
    if value != expected:
        raise ValueError("activation receipt snapshot identity is invalid")
    return expected


def require_activation_receipt(
    value: object,
    *,
    request: operation_contract.OperationRequest | None = None,
    expected_uid: int | None = None,
) -> dict[str, object]:
    """Validate one exact completion receipt and optional request binding."""

    if not isinstance(value, Mapping) or set(value) != set(_RECEIPT_FIELDS):
        raise ValueError("activation receipt is invalid")
    receipt = dict(value)
    activation_id = receipt.get("activation_id")
    if type(activation_id) is not str or _ACTIVATION_ID.fullmatch(activation_id) is None:
        raise ValueError("activation receipt is invalid")
    initial_policy = require_initial_policy(receipt.get("initial_policy"))
    if (
        receipt.get("schema") != RECEIPT_SCHEMA.canonical_value
        or receipt.get("kind") != RECEIPT_SCHEMA.kind
        or receipt.get("status") != "ACTIVE"
        or type(receipt.get("actor")) is not str
        or not receipt["actor"]
        or type(receipt.get("exact_root")) is not str
        or not receipt["exact_root"].startswith("/")
        or receipt.get("allowed_namespace") != "_registry/curation"
        or receipt.get("corpus_effect") != "none"
        or receipt.get("control_bootstrap_rows") != 0
        or receipt.get("legacy_evidence") is not False
    ):
        raise ValueError("activation receipt is invalid")
    request_sha256 = _require_sha256(
        receipt.get("request_sha256"),
        "activation request identity",
    )
    _require_sha256(receipt.get("root_identity_sha256"), "root identity")
    _require_sha256(
        receipt.get("logical_readback_sha256"),
        "logical readback identity",
    )
    _require_schema_identity(receipt.get("schema_identity"), activation_id=activation_id)
    _require_snapshot_identity(
        receipt.get("initial_snapshot_identity"),
        activation_id=activation_id,
        initial_policy=initial_policy,
    )
    write_set = receipt.get("write_set")
    if type(write_set) is not list or not write_set:
        raise ValueError("activation receipt write set is invalid")
    uid = expected_uid
    if uid is None:
        first = write_set[0]
        uid = first.get("uid") if isinstance(first, Mapping) else None
    if type(uid) is not int or uid < 0 or write_set != activation_write_set(uid):
        raise ValueError("activation receipt write set is invalid")
    if request is not None:
        validate_activation_request(request)
        if (
            request.sha256 != request_sha256
            or request.root != receipt["exact_root"]
            or request.actor != receipt["actor"]
            or request.scope["activation_id"] != activation_id
            or request.payload["root_identity_sha256"]
            != receipt["root_identity_sha256"]
            or dict(request.payload["initial_policy"]) != initial_policy
            or request.payload["allowed_namespace"] != receipt["allowed_namespace"]
            or request.payload["corpus_effect"] != receipt["corpus_effect"]
        ):
            raise ValueError("activation receipt request binding is invalid")
    return receipt


def require_activation_receipt_bytes(
    raw: bytes,
    *,
    request: operation_contract.OperationRequest | None = None,
    expected_uid: int | None = None,
) -> dict[str, object]:
    """Decode canonical receipt bytes and validate their exact contract."""

    if type(raw) is not bytes:
        raise ValueError("activation receipt bytes are invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("activation receipt bytes are invalid") from exc
    receipt = require_activation_receipt(
        value,
        request=request,
        expected_uid=expected_uid,
    )
    if canonical_json_bytes(receipt) != raw:
        raise ValueError("canonical activation receipt is required")
    return receipt


def activation_receipt_reference(
    raw: bytes,
    *,
    request_sha256: str,
) -> artifact_contract.SealedArtifactRef:
    """Seal canonical receipt bytes for the existing operation outcome."""

    require_activation_receipt_bytes(raw)
    request_sha256 = _require_sha256(request_sha256, "activation request identity")
    artifact_sha256 = sha256_bytes(raw)
    manifest_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "artifact_sha256": artifact_sha256,
                "canonical_path": RECEIPT_PATH,
                "producer_request_sha256": request_sha256,
                "schema": RECEIPT_SCHEMA.canonical_value,
            }
        )
    )
    return artifact_contract.SealedArtifactRef(
        schema=RECEIPT_SCHEMA,
        canonical_path=RECEIPT_PATH,
        artifact_sha256=artifact_sha256,
        manifest_sha256=manifest_sha256,
        producer_operation_sha256=request_sha256,
        byte_length=len(raw),
        media_type="application/json",
    )


def _require_audit_finding(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or not set(value).issubset(_AUDIT_FINDING_KEYS)
        or type(value.get("blocking")) is not bool
        or value.get("category") not in {"drift", "integrity", "orphan"}
        or type(value.get("code")) is not str
        or not value["code"]
    ):
        raise ValueError("activation audit result is invalid")
    return {key: value[key] for key in sorted(value)}


def require_audit_result(value: object) -> dict[str, object]:
    """Return one exact public audit v2 result or fail closed."""

    if (
        not isinstance(value, Mapping)
        or set(value) != _AUDIT_RESULT_KEYS
        or value.get("schema_version") != 2
        or value.get("view") != "audit"
        or value.get("read_only") is not True
        or value.get("allowed_namespace") != "_registry/curation"
        or value.get("corpus_effect") != "none"
        or value.get("curation_complete") is not None
        or type(value.get("exact_root")) is not str
        or not value["exact_root"].startswith("/")
        or type(value.get("next_safe_action")) is not str
        or not value["next_safe_action"]
        or type(value.get("offset")) is not int
        or value["offset"] < 0
        or type(value.get("returned")) is not int
        or value["returned"] < 0
        or type(value.get("truncated")) is not bool
        or not isinstance(value.get("findings"), list)
        or not isinstance(value.get("blockers"), list)
        or not isinstance(value.get("scope"), dict)
        or not isinstance(value.get("summary"), dict)
        or type(value.get("integrity_ok")) is not bool
        or type(value.get("blocking_total")) is not int
        or value["blocking_total"] < 0
    ):
        raise ValueError("activation audit result is invalid")
    _require_sha256(value.get("root_identity_sha256"), "root identity")
    state = value.get("activation_state")
    reason_code = value.get("reason_code")
    try:
        expected_action = audit_next_safe_action(state, reason_code)
    except ValueError as exc:
        raise ValueError("activation audit result is invalid") from exc
    if value.get("next_safe_action") != expected_action:
        raise ValueError("activation audit result is invalid")
    if state == "NOT_ACTIVATED":
        if (
            value.get("activation_eligible") is not True
            or value.get("integrity_ok") is not True
            or value.get("scope") != {}
            or value.get("summary") != {}
            or value.get("blockers") != []
            or value.get("findings") != []
            or value.get("blocking_total") != 0
            or value.get("returned") != 0
            or value.get("next_offset") is not None
            or value.get("truncated") is not False
        ):
            raise ValueError("activation audit result is invalid")
        require_initial_policy(value.get("initial_policy"))
    elif state == "ACTIVE":
        if (
            value.get("activation_eligible") is not False
            or value.get("initial_policy") is not None
            or value.get("integrity_ok") is not True
        ):
            raise ValueError("activation audit result is invalid")
    elif state == "LOCAL":
        if (
            value.get("activation_eligible") is not False
            or value.get("initial_policy") is not None
            or value.get("integrity_ok") is not True
        ):
            raise ValueError("activation audit result is invalid")
    elif state == "RECOVERY_REQUIRED":
        if (
            value.get("activation_eligible") is not False
            or value.get("initial_policy") is not None
            or value.get("integrity_ok") is not False
        ):
            raise ValueError("activation audit result is invalid")
    elif state == "BLOCKED":
        if (
            value.get("activation_eligible") is not False
            or value.get("initial_policy") is not None
            or value.get("integrity_ok") is not False
        ):
            raise ValueError("activation audit result is invalid")
    else:
        raise ValueError("activation audit result is invalid")
    findings = [_require_audit_finding(item) for item in value["findings"]]
    if (
        value["returned"] != len(findings)
        or any(
            type(blocker) is not str or not blocker
            for blocker in value["blockers"]
        )
        or value["blockers"] != sorted(set(value["blockers"]))
        or value["blocking_total"]
        < sum(finding["blocking"] for finding in findings)
    ):
        raise ValueError("activation audit result is invalid")
    expected_next_offset = value["offset"] + value["returned"]
    if value["truncated"]:
        if (
            value.get("next_offset") != expected_next_offset
            or "audit-findings-truncated" not in value["blockers"]
        ):
            raise ValueError("activation audit result is invalid")
    elif value.get("next_offset") is not None:
        raise ValueError("activation audit result is invalid")
    return dict(value)


def require_fresh_audit_result(value: object, *, root: object) -> dict[str, object]:
    """Return one exact public v2 fresh result or fail closed."""

    result = require_audit_result(value)
    if (
        type(root) is not str
        or result.get("exact_root") != root
        or result.get("activation_state") != "NOT_ACTIVATED"
    ):
        raise ValueError("activation audit result is invalid")
    return result


def validate_activation_request(request: object) -> None:
    """Validate the exact activation APPLY shape before root access."""

    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "curation.activation"
        or request.action is not operation_contract.LifecycleAction.APPLY
        or request.claim_mode is not operation_contract.ClaimMode.CURRENT
        or request.requested_authority is not operation_contract.AuthorityMode.WRITE
        or set(request.scope) != {"activation_id"}
        or set(request.payload)
        != {
            "allowed_namespace",
            "corpus_effect",
            "initial_policy",
            "root_identity_sha256",
        }
        or set(request.bounds)
        or request.approval_artifact is not None
        or request.prerequisite_artifacts
    ):
        raise ValueError("activation request is invalid")
    if (
        type(request.scope["activation_id"]) is not str
        or _ACTIVATION_ID.fullmatch(request.scope["activation_id"]) is None
        or request.payload["allowed_namespace"] != "_registry/curation"
        or request.payload["corpus_effect"] != "none"
    ):
        raise ValueError("activation request is invalid")
    _require_sha256(request.payload["root_identity_sha256"], "root identity")
    require_initial_policy(request.payload["initial_policy"])


def _require_receipt_reference(
    value: object,
    *,
    request_sha256: str,
) -> artifact_contract.SealedArtifactRef:
    if isinstance(value, Mapping):
        value = artifact_contract.SealedArtifactRef.from_canonical_bytes(
            canonical_json_bytes(dict(value))
        )
    if (
        type(value) is not artifact_contract.SealedArtifactRef
        or value.schema != RECEIPT_SCHEMA
        or value.canonical_path != RECEIPT_PATH
        or value.media_type != "application/json"
        or value.producer_operation_sha256 != request_sha256
    ):
        raise ValueError("activation receipt reference is invalid")
    return value


def activation_handler(
    admitted: operation_contract.AdmittedOperation,
    session: object,
) -> operation_contract.OperationOutcome:
    """Call the one closed activation capability and return its sealed receipt."""

    activate = getattr(session, "activate", None)
    if not callable(activate):
        raise ValueError("activation session capability is unavailable")
    reference = _require_receipt_reference(
        activate(),
        request_sha256=admitted.request_sha256,
    )
    return operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result_artifact=reference,
    )


def validate_activation_result(outcome: object) -> None:
    """Require one completed outcome carrying the exact activation receipt."""

    if (
        type(outcome) is not operation_contract.OperationOutcome
        or outcome.outcome_kind != "completed"
        or outcome.result is not None
    ):
        raise ValueError("activation result is invalid")
    _require_receipt_reference(
        outcome.result_artifact,
        request_sha256=outcome.request_sha256,
    )


__all__ = [
    "ACTIVATION_V2_SOURCE_ID",
    "RECEIPT_PATH",
    "RECEIPT_SCHEMA",
    "activation_handler",
    "activation_receipt_reference",
    "activation_write_set",
    "require_activation_receipt",
    "require_activation_receipt_bytes",
    "require_audit_result",
    "require_fresh_audit_result",
    "require_initial_policy",
    "validate_activation_request",
    "validate_activation_result",
]
