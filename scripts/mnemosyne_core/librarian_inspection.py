"""Exact inspect.scope operation contract and direct read-session owner."""

from __future__ import annotations

from collections.abc import Mapping

from . import (
    artifact_contract,
    librarian_contract,
    librarian_projection,
    operation_contract,
)
from .canonical_json import canonical_json_bytes


def _require_relative_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or any(ord(character) < 32 for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise ValueError("scope relative path is invalid")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ValueError("scope relative path is invalid")
    return value


def _require_workstream_ref(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value.strip() != value
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(ord(character) < 32 for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise ValueError("inspect scope workstream reference is invalid")
    if any(component in {"", ".", ".."} for component in value.split("/")):
        raise ValueError("inspect scope workstream reference is invalid")
    return value


def validate_scope_request(request: object) -> None:
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind != "inspect.scope"
        or request.action is not operation_contract.LifecycleAction.INSPECT
        or request.claim_mode is not operation_contract.ClaimMode.HISTORICAL
        or request.requested_authority is not operation_contract.AuthorityMode.READ
        or set(request.scope) != {"workstream_ref"}
        or set(request.bounds) != {"max_items", "max_depth", "max_hint_bytes"}
        or set(request.payload)
        or request.approval_artifact is not None
        or request.prerequisite_artifacts
    ):
        raise ValueError("inspect scope request is invalid")
    _require_workstream_ref(request.scope["workstream_ref"])
    max_items = request.bounds["max_items"]
    max_depth = request.bounds["max_depth"]
    max_hint_bytes = request.bounds["max_hint_bytes"]
    if (
        type(max_items) is not int
        or not 1 <= max_items <= 4096
        or type(max_depth) is not int
        or not 0 <= max_depth <= 16
        or type(max_hint_bytes) is not int
        or not 0 <= max_hint_bytes <= 1024 * 1024
    ):
        raise ValueError("inspect scope request bounds are invalid")


def _require_descendant_path(value: object, scope_path: str) -> str:
    path = _require_relative_path(value)
    if not path.startswith(scope_path + "/"):
        raise ValueError("inspect scope result path escapes its scope")
    return path


def _validate_hint(value: object) -> None:
    if value is None:
        return
    if (
        type(value) is not str
        or not value
        or len(value) > 200
        or "\n" in value
        or "\r" in value
    ):
        raise ValueError("inspect scope hint is invalid")


def _validate_entry(
    item: object,
    *,
    scope_path: str,
    organized: bool,
) -> str:
    expected = {"relative_path", "entry_type", "size", "hint"}
    if organized:
        expected.update(("destination_kind", "destination_id"))
    if type(item) is not dict or set(item) != expected:
        raise ValueError("inspect scope entry is invalid")
    path = _require_descendant_path(item["relative_path"], scope_path)
    if (
        item["entry_type"] not in {"file", "directory"}
        or type(item["size"]) is not int
        or item["size"] < 0
    ):
        raise ValueError("inspect scope entry is invalid")
    _validate_hint(item["hint"])
    if item["entry_type"] == "directory" and (
        item["size"] != 0 or item["hint"] is not None
    ):
        raise ValueError("inspect scope directory entry is invalid")
    if organized and (
        item["destination_kind"] not in {"workstream", "manual_category"}
        or type(item["destination_id"]) is not str
        or not item["destination_id"]
    ):
        raise ValueError("inspect scope destination is invalid")
    return path


def _validate_reason_entry(
    item: object,
    *,
    scope_path: str,
    allowed_reasons: frozenset[str],
) -> str:
    if type(item) is not dict or set(item) != {"relative_path", "reason_code"}:
        raise ValueError("inspect scope reason entry is invalid")
    path = _require_descendant_path(item["relative_path"], scope_path)
    if item["reason_code"] not in allowed_reasons:
        raise ValueError("inspect scope reason code is invalid")
    return path


def _validate_workstreams(value: object) -> None:
    if type(value) is not list:
        raise ValueError("inspect scope workstreams are invalid")
    identifiers = []
    for item in value:
        if (
            type(item) is not dict
            or set(item) != {"id", "lifecycle", "project_home"}
            or type(item["id"]) is not str
            or not item["id"]
            or item["lifecycle"] not in {"active", "paused", "completed"}
        ):
            raise ValueError("inspect scope workstream is invalid")
        _require_relative_path(item["project_home"])
        identifiers.append(item["id"])
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise ValueError("inspect scope workstreams are not canonical")


_FROZEN_ERROR_CODES = frozenset(
    (
        "directory-count-entry-error",
        "directory-list-failed",
        "directory-open-failed",
        "directory-race",
        "max-depth",
        "max-direct-entries",
        "max-entries",
        "mount-boundary",
        "unsafe-directory",
    )
)
_FROZEN_DRIFT_CODES = frozenset(
    (
        "AUXILIARY_MISSING",
        "AUXILIARY_MALFORMED",
        "AUXILIARY_AMBIGUOUS",
        "AUXILIARY_LIMIT_EXCEEDED",
        "AUXILIARY_ID_MISMATCH",
        "AUXILIARY_ROOT_MISMATCH",
        "AUXILIARY_FRESHNESS_MISSING",
        "AUXILIARY_UNSAFE",
    )
)
_FROZEN_DRIFT_FIELDS = {
    "AUXILIARY_MISSING": "snapshot",
    "AUXILIARY_MALFORMED": "frontmatter",
    "AUXILIARY_AMBIGUOUS": "frontmatter",
    "AUXILIARY_LIMIT_EXCEEDED": "frontmatter",
    "AUXILIARY_ID_MISMATCH": "workspace.slug",
    "AUXILIARY_ROOT_MISMATCH": "workspace.root",
    "AUXILIARY_FRESHNESS_MISSING": "updated_at",
    "AUXILIARY_UNSAFE": "snapshot",
}


def _require_frozen_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise ValueError("inspect frozen %s is invalid" % label)
    return value


def _require_frozen_count(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("inspect frozen %s is invalid" % label)
    return value


def _validate_frozen_result(result: Mapping) -> None:
    if set(result) != {
        "schema_version",
        "view",
        "inspection_mode",
        "workstream",
        "bounds",
        "current_scope",
        "usage",
        "frozen_coverage",
        "excluded",
        "drift",
        "candidates",
        "returned",
        "truncated",
    }:
        raise ValueError("inspect frozen result shape is invalid")
    if (
        result["schema_version"] != 2
        or result["view"] != "scope"
        or result["inspection_mode"] != "frozen-coverage"
        or type(result["truncated"]) is not bool
        or result["candidates"] != []
    ):
        raise ValueError("inspect frozen result is invalid")

    workstream = result["workstream"]
    if (
        type(workstream) is not dict
        or set(workstream)
        != {"id", "lifecycle", "project_home", "identity_status"}
        or workstream["lifecycle"] not in {"paused", "completed"}
        or workstream["identity_status"] != "verified"
    ):
        raise ValueError("inspect frozen Workstream is invalid")
    _require_frozen_text(workstream["id"], "Workstream id", maximum=512)
    project_home = _require_relative_path(workstream["project_home"])

    bounds = result["bounds"]
    if (
        type(bounds) is not dict
        or set(bounds) != {"max_items", "max_depth", "max_hint_bytes"}
        or type(bounds["max_items"]) is not int
        or not 1 <= bounds["max_items"] <= 4096
        or type(bounds["max_depth"]) is not int
        or not 0 <= bounds["max_depth"] <= 16
        or type(bounds["max_hint_bytes"]) is not int
        or not 0 <= bounds["max_hint_bytes"] <= 1024 * 1024
    ):
        raise ValueError("inspect frozen bounds are invalid")
    if result["current_scope"] != {"status": "verified"}:
        raise ValueError("inspect frozen current scope is invalid")

    usage = result["usage"]
    if type(usage) is not dict or set(usage) != {
        "items_used",
        "max_depth_reached",
        "metadata_bytes_used",
        "drift_returned",
    }:
        raise ValueError("inspect frozen usage is invalid")
    for key in usage:
        _require_frozen_count(usage[key], "usage")
    if (
        usage["items_used"] > bounds["max_items"]
        or usage["max_depth_reached"] > bounds["max_depth"]
        or usage["metadata_bytes_used"] > 8192
        or usage["drift_returned"] > 8
    ):
        raise ValueError("inspect frozen usage exceeds its bound")

    coverage = result["frozen_coverage"]
    if type(coverage) is not dict or set(coverage) != {
        "directories",
        "directory_count",
        "file_count",
        "other_count",
        "unreadable_count",
        "unsafe_count",
        "unknown_descendant_count",
        "hint_bytes_used",
    }:
        raise ValueError("inspect frozen coverage is invalid")
    if type(coverage["directories"]) is not list:
        raise ValueError("inspect frozen directories are invalid")
    for key in (
        "directory_count",
        "file_count",
        "other_count",
        "unreadable_count",
        "unsafe_count",
        "unknown_descendant_count",
        "hint_bytes_used",
    ):
        _require_frozen_count(coverage[key], "coverage")
    if coverage["hint_bytes_used"] != 0:
        raise ValueError("inspect frozen hint usage is invalid")

    paths = []
    file_count = 0
    other_count = 0
    unknown_count = 0
    entered_depths = []
    for row in coverage["directories"]:
        if type(row) is not dict or set(row) != {
            "path",
            "direct_file_count",
            "direct_other_count",
            "descendant_unknown_count",
            "errors",
        }:
            raise ValueError("inspect frozen directory is invalid")
        path = _require_relative_path(row["path"])
        if path != project_home and not path.startswith(project_home + "/"):
            raise ValueError("inspect frozen directory escapes Workstream")
        for key in (
            "direct_file_count",
            "direct_other_count",
            "descendant_unknown_count",
        ):
            _require_frozen_count(row[key], "directory count")
        errors = row["errors"]
        if (
            type(errors) is not list
            or errors != sorted(set(errors))
            or any(code not in _FROZEN_ERROR_CODES for code in errors)
        ):
            raise ValueError("inspect frozen directory errors are invalid")
        local = "" if path == project_home else path[len(project_home) + 1 :]
        depth = 0 if not local else local.count("/") + 1
        if depth > bounds["max_depth"]:
            raise ValueError("inspect frozen directory depth is invalid")
        if "directory-open-failed" not in errors:
            entered_depths.append(depth)
        paths.append(path)
        file_count += row["direct_file_count"]
        other_count += row["direct_other_count"]
        unknown_count += row["descendant_unknown_count"]
    if (
        paths != sorted(paths)
        or len(paths) != len(set(paths))
        or (paths and paths[0] != project_home)
        or coverage["directory_count"] != len(paths)
        or coverage["file_count"] != file_count
        or coverage["other_count"] != other_count
        or coverage["unknown_descendant_count"] != unknown_count
        or usage["items_used"] < len(paths)
        or usage["max_depth_reached"] != max(entered_depths, default=0)
    ):
        raise ValueError("inspect frozen coverage accounting is invalid")

    excluded = result["excluded"]
    if type(excluded) is not list or len(excluded) > 8:
        raise ValueError("inspect frozen excluded rows are invalid")
    excluded_reasons = []
    excluded_counts = {}
    for row in excluded:
        if (
            type(row) is not dict
            or set(row) != {"reason_code", "count"}
            or row["reason_code"] not in _FROZEN_ERROR_CODES
        ):
            raise ValueError("inspect frozen excluded row is invalid")
        count = _require_frozen_count(row["count"], "excluded count")
        if count < 1:
            raise ValueError("inspect frozen excluded count is invalid")
        excluded_reasons.append(row["reason_code"])
        excluded_counts[row["reason_code"]] = count
    if excluded_reasons != sorted(set(excluded_reasons)):
        raise ValueError("inspect frozen excluded rows are not canonical")
    unreadable = sum(
        excluded_counts.get(code, 0)
        for code in (
            "directory-count-entry-error",
            "directory-list-failed",
            "directory-open-failed",
        )
    )
    if (
        coverage["unreadable_count"] != unreadable
        or coverage["unsafe_count"] != excluded_counts.get("unsafe-directory", 0)
    ):
        raise ValueError("inspect frozen safety accounting is invalid")

    drift = result["drift"]
    if type(drift) is not list or len(drift) > 8:
        raise ValueError("inspect frozen drift is invalid")
    for row in drift:
        if type(row) is not dict or set(row) != {
            "source_id",
            "field",
            "reason_code",
            "authority_value",
            "observed_value",
            "requires_manual_review",
        }:
            raise ValueError("inspect frozen drift row is invalid")
        if (
            row["reason_code"] not in _FROZEN_DRIFT_CODES
            or row["source_id"] != "auxiliary-snapshot"
            or row["field"] != _FROZEN_DRIFT_FIELDS.get(row["reason_code"])
            or row["requires_manual_review"] is not True
        ):
            raise ValueError("inspect frozen drift row is invalid")
        for key in ("authority_value", "observed_value"):
            if row[key] is not None:
                _require_frozen_text(row[key], "drift value", maximum=512)
    if usage["drift_returned"] != len(drift):
        raise ValueError("inspect frozen drift accounting is invalid")

    returned = result["returned"]
    if (
        type(returned) is not int
        or returned != len(paths) + len(excluded) + len(drift)
        or returned > bounds["max_items"] + 16
    ):
        raise ValueError("inspect frozen returned count is invalid")


def validate_scope_result(outcome: object) -> None:
    if type(outcome) is operation_contract.OperationOutcome and outcome.outcome_kind == "blocked":
        blocked_contract = {
            "SCOPE_UNSAFE": "inspect",
            "SCOPE_LIMIT_EXCEEDED": "narrow-scope",
        }
        if blocked_contract.get(outcome.reason_code) != outcome.next_safe_action:
            raise ValueError("inspect scope blocked result is invalid")
        return
    if (
        type(outcome) is not operation_contract.OperationOutcome
        or outcome.outcome_kind != "completed"
        or not isinstance(outcome.result, Mapping)
    ):
        raise ValueError("inspect scope result is invalid")
    result = outcome.result
    if result.get("schema_version") == 2:
        _validate_frozen_result(result)
        return
    if set(result) != {
        "schema_version",
        "view",
        "scope",
        "bounds",
        "workstreams",
        "organized",
        "candidates",
        "excluded",
        "uncertain",
        "returned",
        "truncated",
    }:
        raise ValueError("inspect scope result shape is invalid")
    if (
        result["schema_version"] != 1
        or result["view"] != "scope"
        or type(result["scope"]) is not dict
        or set(result["scope"]) != {"relative_path"}
        or type(result["bounds"]) is not dict
        or set(result["bounds"])
        != {"max_items", "max_depth", "max_hint_bytes"}
        or type(result["returned"]) is not int
        or result["returned"] < 0
        or type(result["truncated"]) is not bool
    ):
        raise ValueError("inspect scope result is invalid")
    scope_path = _require_relative_path(result["scope"]["relative_path"])
    bounds = result["bounds"]
    if (
        type(bounds["max_items"]) is not int
        or not 1 <= bounds["max_items"] <= 4096
        or type(bounds["max_depth"]) is not int
        or not 0 <= bounds["max_depth"] <= 16
        or type(bounds["max_hint_bytes"]) is not int
        or not 0 <= bounds["max_hint_bytes"] <= 1024 * 1024
    ):
        raise ValueError("inspect scope result bounds are invalid")
    _validate_workstreams(result["workstreams"])
    paths = []
    for item in result["organized"]:
        paths.append(_validate_entry(item, scope_path=scope_path, organized=True))
    for item in result["candidates"]:
        paths.append(_validate_entry(item, scope_path=scope_path, organized=False))
    for item in result["excluded"]:
        paths.append(
            _validate_reason_entry(
                item,
                scope_path=scope_path,
                allowed_reasons=frozenset(
                    ("SCOPE_UNSAFE", "SOURCE_UNSUPPORTED", "WORKSTREAM_INACTIVE")
                ),
            )
        )
    for item in result["uncertain"]:
        paths.append(
            _validate_reason_entry(
                item,
                scope_path=scope_path,
                allowed_reasons=frozenset(
                    ("CONTENT_OPAQUE", "SOURCE_CHANGED", "SOURCE_UNSUPPORTED")
                ),
            )
        )
    if (
        len(paths) != len(set(paths))
        or result["returned"] != len(paths)
        or result["returned"] > bounds["max_items"]
    ):
        raise ValueError("inspect scope result count is invalid")
    for group in ("organized", "candidates", "excluded", "uncertain"):
        ordered = [item["relative_path"] for item in result[group]]
        if ordered != sorted(ordered):
            raise ValueError("inspect scope result order is invalid")


def scope_handler(admitted: object, session: object) -> operation_contract.OperationOutcome:
    if type(admitted) is not operation_contract.AdmittedOperation:
        raise TypeError("inspect scope admission is invalid")
    inspect_scope = getattr(session, "inspect_librarian_scope", None)
    if not callable(inspect_scope):
        raise TypeError("inspect scope session is invalid")
    result = inspect_scope()
    if type(result) is not dict or result.get("status") not in {"COMPLETED", "BLOCKED"}:
        raise TypeError("inspect scope session result is invalid")
    if result["status"] == "BLOCKED":
        return operation_contract.OperationOutcome.blocked(
            admitted.request_sha256,
            reason_code=result.get("reason_code"),
            next_safe_action=result.get("next_safe_action"),
        )
    return operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result=result.get("result"),
    )


def validate_records_request(request: object) -> None:
    if (
        type(request) is not operation_contract.OperationRequest
        or request.operation_kind not in {"inspect.pending", "inspect.history"}
        or request.action is not operation_contract.LifecycleAction.INSPECT
        or request.claim_mode is not operation_contract.ClaimMode.HISTORICAL
        or request.requested_authority is not operation_contract.AuthorityMode.READ
        or set(request.scope) != {"relative_path"}
        or set(request.bounds) != {"max_items"}
        or set(request.payload) != {"offset"}
        or request.approval_artifact is not None
        or request.prerequisite_artifacts
    ):
        raise ValueError("Safe Librarian record inspection request is invalid")
    _require_relative_path(request.scope["relative_path"])
    if (
        type(request.bounds["max_items"]) is not int
        or not 1 <= request.bounds["max_items"] <= 4096
        or type(request.payload["offset"]) is not int
        or not 0 <= request.payload["offset"] <= 1_000_000
    ):
        raise ValueError("Safe Librarian record inspection bounds are invalid")


def _validate_record_projection(value: object, scope_path: str) -> None:
    fields = {
        "proposal_id",
        "status",
        "proposal",
        "decision",
        "intent",
        "placement_result",
        "placement_reason_code",
        "source_relative_path",
        "target_relative_path",
        "destination_kind",
        "destination_id",
        "reason",
        "created_at",
        "proposal_actor",
        "decision_id",
        "decision_value",
        "decided_at",
        "decision_actor",
        "decision_reason",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("Safe Librarian record projection is invalid")
    proposal_id = librarian_contract.require_proposal_id(value["proposal_id"])
    proposal = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(value["proposal"])
    )
    if (
        proposal.schema != librarian_contract.PROPOSAL_SCHEMA
        or proposal.canonical_path
        != librarian_contract.proposal_artifact_path(proposal_id)
    ):
        raise ValueError("Safe Librarian proposal projection is invalid")
    source = librarian_contract.require_relative_path(value["source_relative_path"])
    target = librarian_contract.require_relative_path(value["target_relative_path"])
    if not any(
        path == scope_path or path.startswith(scope_path + "/")
        for path in (source, target)
    ):
        raise ValueError("Safe Librarian record projection escapes its scope")
    if (
        value["destination_kind"] not in {"workstream", "manual_category"}
        or type(value["destination_id"]) is not str
        or not value["destination_id"]
        or type(value["reason"]) is not str
        or not value["reason"]
        or type(value["created_at"]) is not str
        or not value["created_at"]
        or type(value["proposal_actor"]) is not str
        or not value["proposal_actor"]
    ):
        raise ValueError("Safe Librarian record projection is invalid")
    if value["status"] == "PENDING":
        if any(
            value[field] is not None
            for field in (
                "decision",
                "decision_id",
                "decision_value",
                "decided_at",
                "decision_actor",
                "decision_reason",
                "intent",
                "placement_result",
                "placement_reason_code",
            )
        ):
            raise ValueError("Safe Librarian pending projection is invalid")
        return
    if value["status"] not in {
        "APPROVED_PENDING_APPLY",
        "REJECTED",
        "RECOVERY_REQUIRED",
        "APPLIED",
        "BLOCKED",
    }:
        raise ValueError("Safe Librarian record status is invalid")
    decision = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(value["decision"])
    )
    if (
        decision.schema != librarian_contract.DECISION_SCHEMA
        or decision.canonical_path
        != librarian_contract.decision_artifact_path(proposal_id)
        or value["decision_value"]
        != ("REJECTED" if value["status"] == "REJECTED" else "APPROVED")
        or type(value["decision_id"]) is not str
        or type(value["decided_at"]) is not str
        or not value["decided_at"]
        or type(value["decision_actor"]) is not str
        or not value["decision_actor"]
        or type(value["decision_reason"]) is not str
        or not value["decision_reason"]
    ):
        raise ValueError("Safe Librarian decision projection is invalid")
    librarian_contract.require_decision_id(value["decision_id"])
    intent = value["intent"]
    placement_result = value["placement_result"]
    reason_code = value["placement_reason_code"]
    if value["status"] in {"REJECTED", "APPROVED_PENDING_APPLY"}:
        if intent is not None or placement_result is not None or reason_code is not None:
            raise ValueError("Safe Librarian placement projection is invalid")
        return
    intent_reference = None
    if intent is not None:
        intent_reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
            canonical_json_bytes(intent)
        )
        if (
            intent_reference.schema != librarian_contract.INTENT_SCHEMA
            or intent_reference.canonical_path
            != librarian_contract.intent_artifact_path(proposal_id)
        ):
            raise ValueError("Safe Librarian intent projection is invalid")
    if value["status"] == "RECOVERY_REQUIRED":
        if intent_reference is None or placement_result is not None or reason_code is not None:
            raise ValueError("Safe Librarian recovery projection is invalid")
        return
    result_reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(placement_result)
    )
    if (
        result_reference.schema != librarian_contract.RESULT_SCHEMA
        or result_reference.canonical_path
        != librarian_contract.result_artifact_path(proposal_id)
    ):
        raise ValueError("Safe Librarian result projection is invalid")
    if value["status"] == "APPLIED":
        if intent_reference is None or reason_code is not None:
            raise ValueError("Safe Librarian applied projection is invalid")
    elif type(reason_code) is not str or not reason_code:
        raise ValueError("Safe Librarian blocked projection is invalid")


def validate_records_result(outcome: object) -> None:
    if (
        type(outcome) is not operation_contract.OperationOutcome
        or outcome.outcome_kind != "completed"
        or not isinstance(outcome.result, Mapping)
    ):
        raise ValueError("Safe Librarian record inspection result is invalid")
    result = outcome.result
    if set(result) != {
        "schema_version",
        "view",
        "scope",
        "offset",
        "returned",
        "next_offset",
        "truncated",
        "records",
    }:
        raise ValueError("Safe Librarian record inspection result shape is invalid")
    if (
        result["schema_version"] != 1
        or result["view"] not in {"pending", "history"}
        or type(result["scope"]) is not dict
        or set(result["scope"]) != {"relative_path"}
        or type(result["offset"]) is not int
        or result["offset"] < 0
        or type(result["returned"]) is not int
        or result["returned"] < 0
        or type(result["truncated"]) is not bool
        or type(result["records"]) is not list
        or result["returned"] != len(result["records"])
    ):
        raise ValueError("Safe Librarian record inspection result is invalid")
    scope_path = _require_relative_path(result["scope"]["relative_path"])
    proposal_ids = []
    for record in result["records"]:
        _validate_record_projection(record, scope_path)
        if result["view"] == "pending" and record["status"] != "PENDING":
            raise ValueError("Safe Librarian pending result is invalid")
        proposal_ids.append(record["proposal_id"])
    if proposal_ids != sorted(proposal_ids) or len(proposal_ids) != len(
        set(proposal_ids)
    ):
        raise ValueError("Safe Librarian record result order is invalid")
    expected_next = result["offset"] + result["returned"]
    if result["truncated"]:
        if result["next_offset"] != expected_next:
            raise ValueError("Safe Librarian record paging is invalid")
    elif result["next_offset"] is not None:
        raise ValueError("Safe Librarian record paging is invalid")


def records_handler(
    admitted: object,
    session: object,
) -> operation_contract.OperationOutcome:
    if type(admitted) is not operation_contract.AdmittedOperation:
        raise TypeError("Safe Librarian record inspection admission is invalid")
    read_records = getattr(session, "read_librarian_records", None)
    if not callable(read_records):
        raise TypeError("Safe Librarian record inspection session is invalid")
    raw = read_records()
    if type(raw) is not dict or set(raw) != {
        "proposals",
        "decisions",
        "intents",
        "results",
    }:
        raise TypeError("Safe Librarian record evidence is invalid")
    scope_path = admitted.input["scope"]["relative_path"]
    view = admitted.input["operation_kind"].split(".", 1)[1]
    offset = admitted.input["payload"]["offset"]
    maximum = admitted.input["bounds"]["max_items"]
    result = librarian_projection.project_record_page(
        raw,
        scope_path=scope_path,
        view=view,
        offset=offset,
        maximum=maximum,
    )
    return operation_contract.OperationOutcome.completed(
        admitted.request_sha256,
        result=result,
    )


__all__ = [
    "records_handler",
    "scope_handler",
    "validate_records_request",
    "validate_records_result",
    "validate_scope_request",
    "validate_scope_result",
]
