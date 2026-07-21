"""Stable Safe Librarian artifact schema identities."""

from __future__ import annotations

import json
import re

from . import artifact_contract, operation_contract
from .canonical_json import canonical_json_bytes, sha256_bytes


_SHA256 = re.compile(r"[0-9a-f]{64}")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
_PROPOSAL_ID = re.compile(r"p-[0-9a-f]{32}")
_DECISION_ID = re.compile(r"d-[0-9a-f]{32}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z"
)


class LibrarianOperationError(ValueError):
    """One typed Safe Librarian stop that can cross the owner boundary."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        next_safe_action: str,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.next_safe_action = next_safe_action


def _schema_contract(kind: str, fields: tuple[str, ...]):
    schema_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "additional_properties": False,
                "canonical_encoding": "mnemosyne-canonical-json-v1",
                "fields": list(fields),
                "kind": kind,
                "schema_version": 1,
            }
        )
    )
    schema = artifact_contract.SchemaIdentity(
        kind=kind,
        version=1,
        schema_sha256=schema_sha256,
    )
    requirement = operation_contract.ArtifactRequirement(
        kind=kind,
        version=1,
        schema_sha256=schema_sha256,
    )
    return schema, requirement


PROPOSAL_SCHEMA, PROPOSAL_REQUIREMENT = _schema_contract(
    "SAFE_LIBRARIAN_PROPOSAL",
    (
        "schema",
        "proposal_id",
        "producer_request_sha256",
        "actor",
        "created_at",
        "source_relative_path",
        "target_relative_path",
        "destination_kind",
        "destination_id",
        "reason",
        "source_snapshot",
        "target_absent",
        "bounds",
        "state",
    ),
)
DECISION_SCHEMA, DECISION_REQUIREMENT = _schema_contract(
    "SAFE_LIBRARIAN_DECISION",
    (
        "schema",
        "decision_id",
        "proposal",
        "decision",
        "actor",
        "decided_at",
        "decision_reason",
        "effect_summary",
        "producer_request_sha256",
    ),
)
INTENT_SCHEMA, INTENT_REQUIREMENT = _schema_contract(
    "SAFE_LIBRARIAN_PLACEMENT_INTENT",
    (
        "schema",
        "proposal",
        "decision",
        "source_snapshot",
        "source_relative_path",
        "target_relative_path",
        "producer_request_sha256",
        "state",
    ),
)
RESULT_SCHEMA, RESULT_REQUIREMENT = _schema_contract(
    "SAFE_LIBRARIAN_PLACEMENT_RESULT",
    (
        "schema",
        "proposal",
        "intent",
        "status",
        "reason_code",
        "source_absent",
        "target_snapshot",
        "producer_request_sha256",
    ),
)


def require_proposal_id(value: object) -> str:
    if type(value) is not str or _PROPOSAL_ID.fullmatch(value) is None:
        raise ValueError("Safe Librarian proposal id is invalid")
    return value


def require_decision_id(value: object) -> str:
    if type(value) is not str or _DECISION_ID.fullmatch(value) is None:
        raise ValueError("Safe Librarian decision id is invalid")
    return value


def require_relative_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(ord(character) < 32 for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise ValueError("Safe Librarian relative path is invalid")
    if any(component in {"", ".", ".."} for component in value.split("/")):
        raise ValueError("Safe Librarian relative path is invalid")
    return value


def proposal_artifact_path(proposal_id: object) -> str:
    identifier = require_proposal_id(proposal_id)
    return (
        "_registry/curation/safe-librarian/v1/proposals/"
        f"{identifier}.json"
    )


def decision_artifact_path(proposal_id: object) -> str:
    identifier = require_proposal_id(proposal_id)
    return (
        "_registry/curation/safe-librarian/v1/decisions/"
        f"{identifier}.json"
    )


def intent_artifact_path(proposal_id: object) -> str:
    identifier = require_proposal_id(proposal_id)
    return (
        "_registry/curation/safe-librarian/v1/intents/"
        f"{identifier}.json"
    )


def result_artifact_path(proposal_id: object) -> str:
    identifier = require_proposal_id(proposal_id)
    return (
        "_registry/curation/safe-librarian/v1/results/"
        f"{identifier}.json"
    )


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _require_nonempty_text(value: object, label: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 and character not in {"\t"} for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _require_parent_identity(value: object) -> None:
    if (
        type(value) is not dict
        or set(value) != {"device", "inode"}
        or type(value["device"]) is not int
        or value["device"] < 0
        or type(value["inode"]) is not int
        or value["inode"] <= 0
    ):
        raise ValueError("Safe Librarian parent identity is invalid")


def _validate_regular_file_snapshot(value: object, relative_path: str) -> None:
    fields = {
        "kind",
        "relative_path",
        "device",
        "inode",
        "owner",
        "mode",
        "link_count",
        "size",
        "modified_time_ns",
        "parent",
        "content_sha256",
        "snapshot_sha256",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("Safe Librarian source snapshot is invalid")
    if (
        value["kind"] != "regular_file"
        or value["relative_path"] != relative_path
        or any(
            type(value[field]) is not int or value[field] < 0
            for field in ("device", "owner", "mode", "size", "modified_time_ns")
        )
        or type(value["inode"]) is not int
        or value["inode"] <= 0
        or value["link_count"] != 1
        or value["mode"] > 0o7777
    ):
        raise ValueError("Safe Librarian source snapshot is invalid")
    _require_parent_identity(value["parent"])
    _require_sha256(value["content_sha256"], "Safe Librarian content hash")
    expected_snapshot = dict(value)
    observed_snapshot_sha256 = expected_snapshot.pop("snapshot_sha256")
    _require_sha256(observed_snapshot_sha256, "Safe Librarian snapshot hash")
    if sha256_bytes(canonical_json_bytes(expected_snapshot)) != observed_snapshot_sha256:
        raise ValueError("Safe Librarian source snapshot hash is invalid")


def _validate_directory_snapshot(value: object, relative_path: str) -> None:
    fields = {
        "kind",
        "relative_path",
        "device",
        "inode",
        "owner",
        "mode",
        "modified_time_ns",
        "parent",
        "entry_count",
        "file_count",
        "total_bytes",
        "manifest_sha256",
        "snapshot_sha256",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("Safe Librarian directory snapshot is invalid")
    if (
        value["kind"] != "directory"
        or value["relative_path"] != relative_path
        or any(
            type(value[field]) is not int or value[field] < 0
            for field in (
                "device",
                "owner",
                "mode",
                "modified_time_ns",
                "entry_count",
                "file_count",
                "total_bytes",
            )
        )
        or type(value["inode"]) is not int
        or value["inode"] <= 0
        or value["mode"] > 0o7777
        or value["file_count"] > value["entry_count"]
    ):
        raise ValueError("Safe Librarian directory snapshot is invalid")
    _require_parent_identity(value["parent"])
    _require_sha256(value["manifest_sha256"], "Safe Librarian manifest hash")
    expected_snapshot = dict(value)
    observed_snapshot_sha256 = expected_snapshot.pop("snapshot_sha256")
    _require_sha256(observed_snapshot_sha256, "Safe Librarian snapshot hash")
    if sha256_bytes(canonical_json_bytes(expected_snapshot)) != observed_snapshot_sha256:
        raise ValueError("Safe Librarian directory snapshot hash is invalid")


def validate_proposal_record(value: object) -> None:
    fields = {
        "schema",
        "proposal_id",
        "producer_request_sha256",
        "actor",
        "created_at",
        "source_relative_path",
        "target_relative_path",
        "destination_kind",
        "destination_id",
        "reason",
        "source_snapshot",
        "target_absent",
        "bounds",
        "state",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("Safe Librarian proposal record shape is invalid")
    if value["schema"] != PROPOSAL_SCHEMA.canonical_value:
        raise ValueError("Safe Librarian proposal schema is invalid")
    require_proposal_id(value["proposal_id"])
    _require_sha256(
        value["producer_request_sha256"],
        "Safe Librarian producer request identity",
    )
    _require_nonempty_text(value["actor"], "Safe Librarian actor", 256)
    if type(value["created_at"]) is not str or _TIMESTAMP.fullmatch(
        value["created_at"]
    ) is None:
        raise ValueError("Safe Librarian creation time is invalid")
    source_path = require_relative_path(value["source_relative_path"])
    target_path = require_relative_path(value["target_relative_path"])
    if source_path == target_path:
        raise ValueError("Safe Librarian source and target must differ")
    if value["destination_kind"] not in {"workstream", "manual_category"}:
        raise ValueError("Safe Librarian destination kind is invalid")
    _require_nonempty_text(
        value["destination_id"],
        "Safe Librarian destination id",
        128,
    )
    _require_nonempty_text(value["reason"], "Safe Librarian reason", 2000)
    source_snapshot = value["source_snapshot"]
    if type(source_snapshot) is not dict:
        raise ValueError("Safe Librarian source snapshot is invalid")
    if source_snapshot.get("kind") == "regular_file":
        _validate_regular_file_snapshot(source_snapshot, source_path)
    elif source_snapshot.get("kind") == "directory":
        _validate_directory_snapshot(source_snapshot, source_path)
    else:
        raise ValueError("Safe Librarian source snapshot is invalid")
    target_absent = value["target_absent"]
    if (
        type(target_absent) is not dict
        or set(target_absent) != {"observed_absent", "relative_path", "parent"}
        or target_absent["observed_absent"] is not True
        or target_absent["relative_path"] != target_path
    ):
        raise ValueError("Safe Librarian target absence evidence is invalid")
    _require_parent_identity(target_absent["parent"])
    bounds = value["bounds"]
    if (
        type(bounds) is not dict
        or set(bounds) != {"max_entries", "max_depth", "max_total_bytes"}
        or type(bounds["max_entries"]) is not int
        or not 1 <= bounds["max_entries"] <= 4096
        or type(bounds["max_depth"]) is not int
        or not 0 <= bounds["max_depth"] <= 16
        or type(bounds["max_total_bytes"]) is not int
        or not 1 <= bounds["max_total_bytes"] <= 256 * 1024 * 1024
    ):
        raise ValueError("Safe Librarian proposal bounds are invalid")
    if source_snapshot["kind"] == "regular_file":
        if source_snapshot["size"] > bounds["max_total_bytes"]:
            raise ValueError("Safe Librarian proposal bounds are invalid")
    elif (
        source_snapshot["entry_count"] > bounds["max_entries"]
        or source_snapshot["total_bytes"] > bounds["max_total_bytes"]
    ):
        raise ValueError("Safe Librarian proposal bounds are invalid")
    if value["state"] != "PENDING":
        raise ValueError("Safe Librarian proposal state is invalid")


def encode_proposal_record(value: object) -> bytes:
    validate_proposal_record(value)
    return canonical_json_bytes(value)


def decode_proposal_record(raw: object) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValueError("Safe Librarian proposal bytes are invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Safe Librarian proposal bytes are invalid") from exc
    validate_proposal_record(value)
    if canonical_json_bytes(value) != raw:
        raise ValueError("canonical Safe Librarian proposal bytes are required")
    return value


def _proposal_reference(value: object) -> artifact_contract.SealedArtifactRef:
    if type(value) is not dict:
        raise ValueError("Safe Librarian proposal reference is invalid")
    reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(value)
    )
    if (
        reference.schema != PROPOSAL_SCHEMA
        or reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian proposal reference is invalid")
    proposal_id = reference.canonical_path.rsplit("/", 1)[-1].removesuffix(
        ".json"
    )
    if reference.canonical_path != proposal_artifact_path(proposal_id):
        raise ValueError("Safe Librarian proposal reference is invalid")
    return reference


def _decision_reference(value: object) -> artifact_contract.SealedArtifactRef:
    if type(value) is not dict:
        raise ValueError("Safe Librarian decision reference is invalid")
    reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(value)
    )
    if (
        reference.schema != DECISION_SCHEMA
        or reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian decision reference is invalid")
    proposal_id = reference.canonical_path.rsplit("/", 1)[-1].removesuffix(
        ".json"
    )
    if reference.canonical_path != decision_artifact_path(proposal_id):
        raise ValueError("Safe Librarian decision reference is invalid")
    return reference


def _intent_reference(value: object) -> artifact_contract.SealedArtifactRef:
    if type(value) is not dict:
        raise ValueError("Safe Librarian placement intent reference is invalid")
    reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(value)
    )
    if (
        reference.schema != INTENT_SCHEMA
        or reference.media_type != "application/json"
    ):
        raise ValueError("Safe Librarian placement intent reference is invalid")
    proposal_id = reference.canonical_path.rsplit("/", 1)[-1].removesuffix(
        ".json"
    )
    if reference.canonical_path != intent_artifact_path(proposal_id):
        raise ValueError("Safe Librarian placement intent reference is invalid")
    return reference


def _validate_snapshot(value: object, relative_path: str) -> None:
    if type(value) is not dict:
        raise ValueError("Safe Librarian source snapshot is invalid")
    if value.get("kind") == "regular_file":
        _validate_regular_file_snapshot(value, relative_path)
        return
    if value.get("kind") == "directory":
        _validate_directory_snapshot(value, relative_path)
        return
    raise ValueError("Safe Librarian source snapshot is invalid")


def validate_intent_record(value: object) -> None:
    fields = {
        "schema",
        "proposal",
        "decision",
        "source_snapshot",
        "source_relative_path",
        "target_relative_path",
        "producer_request_sha256",
        "state",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("Safe Librarian placement intent shape is invalid")
    if value["schema"] != INTENT_SCHEMA.canonical_value:
        raise ValueError("Safe Librarian placement intent schema is invalid")
    proposal_reference = _proposal_reference(value["proposal"])
    decision_reference = _decision_reference(value["decision"])
    proposal_id = proposal_reference.canonical_path.rsplit("/", 1)[-1][:-5]
    if decision_reference.canonical_path != decision_artifact_path(proposal_id):
        raise ValueError("Safe Librarian placement intent references are invalid")
    source_path = require_relative_path(value["source_relative_path"])
    target_path = require_relative_path(value["target_relative_path"])
    if source_path == target_path:
        raise ValueError("Safe Librarian placement intent paths are invalid")
    _validate_snapshot(value["source_snapshot"], source_path)
    _require_sha256(
        value["producer_request_sha256"],
        "Safe Librarian producer request identity",
    )
    if value["state"] != "INTENT_RECORDED":
        raise ValueError("Safe Librarian placement intent state is invalid")


def encode_intent_record(value: object) -> bytes:
    validate_intent_record(value)
    return canonical_json_bytes(value)


def decode_intent_record(raw: object) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValueError("Safe Librarian placement intent bytes are invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Safe Librarian placement intent bytes are invalid") from exc
    validate_intent_record(value)
    if canonical_json_bytes(value) != raw:
        raise ValueError("canonical Safe Librarian placement intent bytes are required")
    return value


def validate_result_record(value: object) -> None:
    fields = {
        "schema",
        "proposal",
        "intent",
        "status",
        "reason_code",
        "source_absent",
        "target_snapshot",
        "producer_request_sha256",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("Safe Librarian placement result shape is invalid")
    if value["schema"] != RESULT_SCHEMA.canonical_value:
        raise ValueError("Safe Librarian placement result schema is invalid")
    proposal_reference = _proposal_reference(value["proposal"])
    proposal_id = proposal_reference.canonical_path.rsplit("/", 1)[-1][:-5]
    status = value["status"]
    if status not in {"APPLIED", "BLOCKED"}:
        raise ValueError("Safe Librarian placement result status is invalid")
    intent_reference = None
    if value["intent"] is not None:
        intent_reference = _intent_reference(value["intent"])
        if intent_reference.canonical_path != intent_artifact_path(proposal_id):
            raise ValueError("Safe Librarian placement result intent is invalid")
    if status == "APPLIED":
        if (
            intent_reference is None
            or value["reason_code"] is not None
            or value["source_absent"] is not True
        ):
            raise ValueError("Safe Librarian applied result is invalid")
        target_snapshot = value["target_snapshot"]
        if type(target_snapshot) is not dict:
            raise ValueError("Safe Librarian applied target snapshot is invalid")
        target_path = require_relative_path(target_snapshot.get("relative_path"))
        _validate_snapshot(target_snapshot, target_path)
    elif (
        type(value["reason_code"]) is not str
        or _REASON_CODE.fullmatch(value["reason_code"]) is None
        or value["source_absent"] is not False
        or value["target_snapshot"] is not None
    ):
        raise ValueError("Safe Librarian blocked result is invalid")
    _require_sha256(
        value["producer_request_sha256"],
        "Safe Librarian producer request identity",
    )


def encode_result_record(value: object) -> bytes:
    validate_result_record(value)
    return canonical_json_bytes(value)


def decode_result_record(raw: object) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValueError("Safe Librarian placement result bytes are invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Safe Librarian placement result bytes are invalid") from exc
    validate_result_record(value)
    if canonical_json_bytes(value) != raw:
        raise ValueError("canonical Safe Librarian placement result bytes are required")
    return value


def validate_decision_record(value: object) -> None:
    fields = {
        "schema",
        "decision_id",
        "proposal",
        "decision",
        "actor",
        "decided_at",
        "decision_reason",
        "effect_summary",
        "producer_request_sha256",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("Safe Librarian decision record shape is invalid")
    if value["schema"] != DECISION_SCHEMA.canonical_value:
        raise ValueError("Safe Librarian decision schema is invalid")
    require_decision_id(value["decision_id"])
    proposal_reference = _proposal_reference(value["proposal"])
    if value["decision"] not in {"APPROVED", "REJECTED"}:
        raise ValueError("Safe Librarian decision is invalid")
    _require_nonempty_text(value["actor"], "Safe Librarian actor", 256)
    if type(value["decided_at"]) is not str or _TIMESTAMP.fullmatch(
        value["decided_at"]
    ) is None:
        raise ValueError("Safe Librarian decision time is invalid")
    _require_nonempty_text(
        value["decision_reason"],
        "Safe Librarian decision reason",
        2000,
    )
    summary = value["effect_summary"]
    if type(summary) is not dict or set(summary) != {
        "proposal_id",
        "source_relative_path",
        "target_relative_path",
        "destination_kind",
        "destination_id",
        "reason",
    }:
        raise ValueError("Safe Librarian decision effect summary is invalid")
    proposal_id = require_proposal_id(summary["proposal_id"])
    if proposal_reference.canonical_path != proposal_artifact_path(proposal_id):
        raise ValueError("Safe Librarian decision effect summary is invalid")
    source_path = require_relative_path(summary["source_relative_path"])
    target_path = require_relative_path(summary["target_relative_path"])
    if source_path == target_path:
        raise ValueError("Safe Librarian decision effect summary is invalid")
    if summary["destination_kind"] not in {"workstream", "manual_category"}:
        raise ValueError("Safe Librarian decision effect summary is invalid")
    _require_nonempty_text(
        summary["destination_id"],
        "Safe Librarian destination id",
        128,
    )
    _require_nonempty_text(summary["reason"], "Safe Librarian reason", 2000)
    _require_sha256(
        value["producer_request_sha256"],
        "Safe Librarian producer request identity",
    )


def encode_decision_record(value: object) -> bytes:
    validate_decision_record(value)
    return canonical_json_bytes(value)


def decode_decision_record(raw: object) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValueError("Safe Librarian decision bytes are invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Safe Librarian decision bytes are invalid") from exc
    validate_decision_record(value)
    if canonical_json_bytes(value) != raw:
        raise ValueError("canonical Safe Librarian decision bytes are required")
    return value


__all__ = [
    "LibrarianOperationError",
    "DECISION_REQUIREMENT",
    "DECISION_SCHEMA",
    "INTENT_REQUIREMENT",
    "INTENT_SCHEMA",
    "PROPOSAL_REQUIREMENT",
    "PROPOSAL_SCHEMA",
    "RESULT_REQUIREMENT",
    "RESULT_SCHEMA",
    "decision_artifact_path",
    "decode_decision_record",
    "decode_intent_record",
    "decode_proposal_record",
    "decode_result_record",
    "encode_decision_record",
    "encode_intent_record",
    "encode_proposal_record",
    "encode_result_record",
    "intent_artifact_path",
    "proposal_artifact_path",
    "result_artifact_path",
    "require_decision_id",
    "require_proposal_id",
    "require_relative_path",
    "validate_decision_record",
    "validate_intent_record",
    "validate_proposal_record",
    "validate_result_record",
]
