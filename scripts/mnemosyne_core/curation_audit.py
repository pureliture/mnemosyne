"""Read-only integrity, orphan, and drift evidence for Document Curation."""

from __future__ import annotations

import datetime as _datetime
import json
import os
import re
import sqlite3
import stat
from bisect import bisect_right
from collections import deque
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import batch_event_contract, m3_schema, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


_UNRESOLVED_PRIMARY_STATES = frozenset(
    ("BLOCKED", "ERROR", "PENDING", "REVIEW_READY", "CLASSIFIED", "DISCOVERED")
)
_TERMINAL_DECISION_ACTION = {
    "DEFERRED": "DEFER",
    "EXCLUDED": "EXCLUDE",
    "KEEP": "KEEP",
    "LINKED": "LINK",
}
_CONTROL_SCAN_MAX_DEPTH = 12
_CONTROL_SCAN_MAX_ENTRIES = 10000
_AUDIT_MAX_LEDGER_ROWS = 100000
_AUDIT_MAX_PREPARED_BATCH_SUBMISSIONS = 100000
_AUDIT_MAX_TOTAL_BLOB_BYTES = 64 * 1024 * 1024
_BATCH_EVENT_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
_BATCH_EVENT_MAX_TOTAL_SNAPSHOT_BYTES = 64 * 1024 * 1024
_BATCH_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PREPARED_BATCH_SUBMISSIONS_SQL = (
    "SELECT batch_id FROM review_submissions "
    "WHERE lineage_kind = 'BATCH' AND state = 'PREPARED' "
    "ORDER BY batch_id LIMIT ?"
)


class CurationAuditError(ValueError):
    """The curation integrity read model cannot safely inspect its inputs."""


class _MissingAuditEntry(CurationAuditError):
    """A no-follow audit lookup found no directory entry."""


class _AuditByteBudgetExceeded(CurationAuditError):
    """A bounded audit artifact family exceeded its aggregate byte budget."""


class _AuditRowBudgetExceeded(CurationAuditError):
    """A bounded audit ledger family exceeded its aggregate row budget."""


class AuditRuntimeFailure(Enum):
    POLICY_ADMISSION_BLOCKED = "policy-admission-blocked"
    CURATION_STATE_UNAVAILABLE = "curation-state-unavailable"


def _caused_by_missing(error: BaseException) -> bool:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, FileNotFoundError):
            return True
        current = current.__cause__
    return False


def _bounded_directory_entries(
    directory: Path,
    limit: int,
) -> Tuple[Tuple[Tuple[str, bool], ...], bool]:
    """Read at most ``limit + 1`` names through one verified directory fd."""

    if type(limit) is not int or limit < 0:
        raise CurationAuditError("directory scan limit is invalid")
    descriptor = safety.open_verified_directory(
        directory,
        require_owner_only=True,
        error_type=CurationAuditError,
    )
    sampled: List[Tuple[str, bool]] = []
    truncated = False
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                if len(sampled) >= limit:
                    truncated = True
                    break
                sampled.append(
                    (entry.name, entry.is_dir(follow_symlinks=False))
                )
        safety.require_same_directory_identity(
            directory,
            descriptor,
            "curation audit",
            error_type=CurationAuditError,
        )
    except CurationAuditError:
        raise
    except OSError as exc:
        raise CurationAuditError("curation audit directory is unreadable") from exc
    finally:
        os.close(descriptor)
    if truncated:
        return (), True
    return tuple(sorted(sampled)), False


def _read_bounded_regular_file(
    path: Path,
    expected_size: int,
    *,
    aggregate_remaining: int | None = None,
) -> bytes:
    """Read no more than the expected bytes plus one through verified dirfds."""

    if type(expected_size) is not int or expected_size < 0:
        raise CurationAuditError("artifact read bound is invalid")
    if aggregate_remaining is not None and (
        type(aggregate_remaining) is not int or aggregate_remaining < 0
    ):
        raise CurationAuditError("artifact aggregate read bound is invalid")
    read_bound = (
        expected_size
        if aggregate_remaining is None
        else min(expected_size, aggregate_remaining)
    )
    try:
        parent_fd = safety.open_verified_directory(
            path.parent,
            require_owner_only=True,
            error_type=CurationAuditError,
        )
    except CurationAuditError as exc:
        if _caused_by_missing(exc):
            raise _MissingAuditEntry("artifact is missing") from exc
        raise
    descriptor = None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lexical = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise CurationAuditError("artifact identity is unsafe")
        if opened.st_size > read_bound:
            if aggregate_remaining is not None and read_bound < expected_size:
                raise _AuditByteBudgetExceeded(
                    "artifact family exceeds aggregate byte budget"
                )
            raise CurationAuditError("artifact exceeds byte bound")
        remaining = read_bound + 1
        chunks = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        final = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or final.st_nlink != opened.st_nlink
            or final.st_size != opened.st_size
        ):
            raise CurationAuditError("artifact identity changed during read")
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            "batch event artifact",
            error_type=CurationAuditError,
        )
        return b"".join(chunks)
    except CurationAuditError:
        raise
    except FileNotFoundError as exc:
        raise _MissingAuditEntry("artifact is missing") from exc
    except OSError as exc:
        raise CurationAuditError("artifact is unreadable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _entry_present(path: Path) -> bool:
    """Check one lexical entry through a verified parent without following it."""

    try:
        parent_fd = safety.open_verified_directory(
            path.parent,
            require_owner_only=True,
            error_type=CurationAuditError,
        )
    except CurationAuditError as exc:
        if _caused_by_missing(exc):
            return False
        raise
    try:
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            "curation audit entry",
            error_type=CurationAuditError,
        )
        return True
    except CurationAuditError:
        raise
    except OSError as exc:
        raise CurationAuditError("curation audit entry is unreadable") from exc
    finally:
        os.close(parent_fd)


def _safe_context(value: Any, label: str) -> str:
    if type(value) is str:
        if len(value) <= 128:
            try:
                encoded = value.encode("utf-8")
            except UnicodeError:
                encoded = value.encode("utf-8", "surrogatepass")
            if (
                len(encoded) <= 128
                and _BATCH_EVENT_ID.fullmatch(value) is not None
            ):
                return value
        try:
            prefix = value[:128].encode("utf-8")
        except UnicodeError:
            prefix = value[:128].encode("utf-8", "surrogatepass")
        encoded = prefix + b":" + str(len(value)).encode("ascii")
    elif type(value) is bytes:
        encoded = value[:4096]
    else:
        encoded = type(value).__name__.encode("ascii", "replace")
    return "invalid-%s-%s" % (label, sha256_bytes(encoded)[:16])


def _batch_finding(
    event_id: Any,
    code: str,
    *,
    state: Any = None,
    category: str = "integrity",
    path: str | None = None,
) -> Dict[str, Any]:
    finding: Dict[str, Any] = {
        "batch_event_id": _safe_context(event_id, "event"),
        "blocking": True,
        "category": category,
        "code": code,
    }
    if state in ("PREPARED", "PUBLISHED", "BLOCKED"):
        finding["state"] = state
    if path is not None:
        finding["path"] = path
    return finding


def _canonical_blob_value(raw: Any, digest: Any) -> Tuple[bool, Any]:
    if type(raw) is not bytes or type(digest) is not str:
        return False, None
    try:
        encoded = raw
        if sha256_bytes(encoded) != digest:
            return False, None
        value = json.loads(encoded.decode("utf-8"))
        return canonical_json_bytes(value) == encoded, value
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        return False, None


def _split_snapshot_unit_projection(values: Any) -> tuple | None:
    if type(values) is not list:
        return None
    projection = []
    seen = set()
    for value in values:
        if type(value) is not dict:
            return None
        unit_id = value.get("unit_id")
        path = value.get("canonical_path")
        member_item_ids = value.get("member_item_ids")
        if (
            type(unit_id) is not str
            or unit_id in seen
            or type(path) is not str
            or type(member_item_ids) is not list
            or not member_item_ids
            or any(type(item_id) is not str for item_id in member_item_ids)
            or tuple(sorted(set(member_item_ids))) != tuple(member_item_ids)
        ):
            return None
        seen.add(unit_id)
        projection.append((unit_id, path, tuple(member_item_ids)))
    return tuple(sorted(projection))


def _split_membership_unit_projection(values: Any) -> tuple | None:
    if type(values) is not list:
        return None
    grouped: Dict[str, tuple[str, List[str]]] = {}
    for value in values:
        if type(value) is not dict:
            return None
        unit_id = value.get("unit_id")
        path = value.get("path")
        item_id = value.get("item_id")
        if not all(type(item) is str for item in (unit_id, path, item_id)):
            return None
        prior = grouped.get(unit_id)
        if prior is None:
            grouped[unit_id] = (path, [item_id])
        elif prior[0] != path or item_id in prior[1]:
            return None
        else:
            prior[1].append(item_id)
    return tuple(
        sorted(
            (unit_id, path, tuple(sorted(item_ids)))
            for unit_id, (path, item_ids) in grouped.items()
        )
    )


def _canonical_split_snapshot(raw: bytes) -> dict | None:
    try:
        value = json.loads(raw.decode("utf-8"))
        if type(value) is not dict or canonical_json_bytes(value) != raw:
            return None
        return value
    except (
        TypeError,
        ValueError,
        UnicodeError,
        RecursionError,
        OverflowError,
    ):
        return None


def _valid_payload_text(value: Any) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and len(value.encode("utf-8")) <= 16 * 1024
        and not any(ord(character) < 0x20 for character in value)
    )


def _unassigned_condition_matches(raw: Any, digest: Any, reason: Any) -> bool:
    valid, value = _canonical_blob_value(raw, digest)
    return (
        valid
        and type(value) is dict
        and set(value) == {"assignment_condition", "reason"}
        and _valid_payload_text(value["assignment_condition"])
        and _valid_payload_text(reason)
        and value["reason"] == reason
    )


def _required_evidence_matches(raw: Any, digest: Any) -> bool:
    valid, value = _canonical_blob_value(raw, digest)
    return valid and _valid_payload_text(value)


def _valid_deferral_trigger(row: sqlite3.Row) -> bool:
    trigger = row["trigger_kind"]
    if trigger == "DATE":
        try:
            if type(row["revisit_date"]) is not str:
                return False
            _datetime.date.fromisoformat(row["revisit_date"])
            if type(row["timezone"]) is not str or not row["timezone"]:
                return False
            ZoneInfo(row["timezone"])
        except (ValueError, ZoneInfoNotFoundError):
            return False
        return all(
            row[field] is None
            for field in (
                "trigger_workstream_id",
                "captured_lifecycle",
                "captured_policy_sha256",
            )
        )
    if trigger == "WORKSTREAM_RESUME":
        workstream_id = row["trigger_workstream_id"]
        policy_hash = row["captured_policy_sha256"]
        return (
            type(workstream_id) is str
            and _BATCH_EVENT_ID.fullmatch(workstream_id) is not None
            and row["captured_lifecycle"] in ("paused", "completed")
            and type(policy_hash) is str
            and _HASH.fullmatch(policy_hash) is not None
            and row["revisit_date"] is None
            and row["timezone"] is None
        )
    if trigger in ("EVIDENCE", "MANUAL_REOPEN"):
        return all(
            row[field] is None
            for field in (
                "revisit_date",
                "timezone",
                "trigger_workstream_id",
                "captured_lifecycle",
                "captured_policy_sha256",
            )
        )
    return False


def report_from_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered = list(findings)
    integrity_ok = not any(finding["blocking"] for finding in ordered)
    category_counts = {
        category: sum(finding["category"] == category for finding in ordered)
        for category in ("drift", "integrity", "orphan")
    }
    return {
        "curation_complete": None,
        "findings": ordered,
        "integrity_ok": integrity_ok,
        "kind": "CurationAudit",
        "read_only": True,
        "schema_version": 1,
        "scope": {
            "checks": [
                "batch-event-bridge",
                "control-artifact-incompletes",
                "projection-explanations",
            ],
            "curation_completion_evaluated": False,
            "kind": "integrity-slice",
        },
        "summary": {
            **category_counts,
            "total": len(ordered),
            "unexplained": sum(
                finding["code"]
                in (
                    "missing-current-projection",
                    "unexplained-deferred-item",
                    "unexplained-unassigned-item",
                    "unresolved-curation-state",
                )
                for finding in ordered
            ),
        },
    }


def not_activated_report() -> Dict[str, Any]:
    return report_from_findings(
        [
            {
                "blocking": True,
                "category": "integrity",
                "code": "curation-state-not-activated",
            }
        ]
    )


def runtime_failure_report(failure: AuditRuntimeFailure) -> Dict[str, Any]:
    if not isinstance(failure, AuditRuntimeFailure):
        raise TypeError("failure must be AuditRuntimeFailure")
    drift = failure is AuditRuntimeFailure.POLICY_ADMISSION_BLOCKED
    return report_from_findings(
        [
            {
                "blocking": True,
                "category": "drift" if drift else "integrity",
                "code": failure.value,
            }
        ]
    )


def control_root_present(control_root: Path) -> bool:
    return _entry_present(Path(control_root))


class CurationIntegrityQuery:
    """Inspect current curation state without creating repair authority."""

    def __init__(self, connection: sqlite3.Connection, control_root: Path) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if connection.row_factory is not sqlite3.Row:
            raise CurationAuditError("curation audit requires sqlite3.Row records")
        if connection.in_transaction:
            raise CurationAuditError("curation audit requires transaction ownership")
        root = Path(control_root)
        if not root.is_absolute() or any(part in (".", "..") for part in root.parts):
            raise CurationAuditError("curation control root must be canonical")
        try:
            m3_schema.verify_v3_schema(connection)
        except (m3_schema.M3SchemaError, sqlite3.Error) as exc:
            raise CurationAuditError("exact curation ledger v3 is required") from exc
        self.connection = connection
        self.control_root = root

    def _projection_findings(self) -> List[Dict[str, Any]]:
        item_count = self.connection.execute(
            "SELECT COUNT(*) FROM items"
        ).fetchone()[0]
        if item_count > _AUDIT_MAX_LEDGER_ROWS:
            return [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "projection-ledger-scan-truncated",
                }
            ]
        evidence_bytes = self.connection.execute(
            "SELECT "
            "COALESCE((SELECT SUM(octet_length(d.required_evidence_json)) "
            "FROM item_curation_projection AS p "
            "JOIN deferrals AS d ON d.deferral_id = p.current_deferral_id), 0) + "
            "COALESCE((SELECT SUM(octet_length(assignment_condition_json)) "
            "FROM unassigned_exceptions WHERE state = 'CURRENT'), 0)"
        ).fetchone()[0]
        if evidence_bytes > _AUDIT_MAX_TOTAL_BLOB_BYTES:
            return [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "projection-evidence-scan-truncated",
                }
            ]
        rows = self.connection.execute(
            "SELECT i.item_id AS item_id, p.item_id AS projection_item_id, "
            "p.primary_state, p.source_freshness, p.identity_ambiguous, "
            "p.lifecycle_frozen, p.unassigned, p.correction_required, "
            "p.current_deferral_id, d.deferral_id, "
            "d.item_id AS deferral_item_id, d.reason AS deferral_reason, "
            "CASE WHEN typeof(d.required_evidence_json) = 'blob' "
            "THEN d.required_evidence_json ELSE NULL END "
            "AS required_evidence_json, d.required_evidence_sha256, "
            "d.trigger_kind, d.revisit_date, d.timezone, "
            "d.trigger_workstream_id, d.captured_lifecycle, "
            "d.captured_policy_sha256, d.state AS deferral_state, "
            "(SELECT COUNT(*) FROM unassigned_exceptions AS ue "
            " WHERE ue.item_id = i.item_id AND ue.state = 'CURRENT') "
            "AS unassigned_count, "
            "(SELECT ue.reason FROM unassigned_exceptions AS ue "
            " WHERE ue.item_id = i.item_id AND ue.state = 'CURRENT' "
            " ORDER BY ue.exception_generation DESC LIMIT 1) "
            "AS unassigned_reason, "
            "(SELECT CASE WHEN typeof(ue.assignment_condition_json) = 'blob' "
            "THEN ue.assignment_condition_json ELSE NULL END "
            "FROM unassigned_exceptions AS ue "
            " WHERE ue.item_id = i.item_id AND ue.state = 'CURRENT' "
            " ORDER BY ue.exception_generation DESC LIMIT 1) "
            "AS assignment_condition_json, "
            "(SELECT ue.assignment_condition_sha256 "
            " FROM unassigned_exceptions AS ue "
            " WHERE ue.item_id = i.item_id AND ue.state = 'CURRENT' "
            " ORDER BY ue.exception_generation DESC LIMIT 1) "
            "AS assignment_condition_sha256, "
            "(SELECT ue.source_decision_event_id "
            " FROM unassigned_exceptions AS ue "
            " WHERE ue.item_id = i.item_id AND ue.state = 'CURRENT' "
            " ORDER BY ue.exception_generation DESC LIMIT 1) "
            "AS unassigned_decision_id, "
            "(SELECT COUNT(*) FROM workstream_relations AS wr "
            " WHERE wr.item_id = i.item_id AND wr.state = 'CURRENT' "
            " AND wr.relation_kind = 'PRIMARY') AS current_primary_count, "
            "(SELECT COUNT(*) FROM deferrals AS cd "
            " WHERE cd.item_id = i.item_id AND cd.state = 'CURRENT') "
            "AS current_deferral_count, "
            "(SELECT COUNT(*) FROM workstream_relations AS cwr "
            " WHERE cwr.item_id = i.item_id AND cwr.state = 'CURRENT' "
            " AND cwr.source_decision_event_id = p.current_decision_id) "
            "AS decision_workstream_relation_count, "
            "(SELECT COUNT(*) FROM document_relations AS cdr "
            " JOIN document_relation_events AS cdre "
            " ON cdre.relation_event_id = cdr.source_relation_event_id "
            " WHERE cdr.state = 'CURRENT' "
            " AND (cdr.canonical_item_id = i.item_id "
            " OR cdr.related_item_id = i.item_id) "
            " AND cdre.source_decision_event_id = p.current_decision_id) "
            "AS decision_document_relation_count, "
            "p.current_decision_id AS projection_decision_id, "
            "p.source_event_id AS projection_source_event_id, "
            "p.projection_generation, "
            "d.source_decision_event_id AS deferral_decision_id, "
            "pde.item_id AS projection_decision_item_id, "
            "pde.action AS projection_decision_action, "
            "pde.projection_generation AS decision_projection_generation "
            "FROM items AS i "
            "LEFT JOIN item_curation_projection AS p ON p.item_id = i.item_id "
            "LEFT JOIN deferrals AS d ON d.deferral_id = p.current_deferral_id "
            "LEFT JOIN decision_events AS pde "
            "ON pde.decision_event_id = p.current_decision_id "
            "ORDER BY i.item_id LIMIT ?",
            (_AUDIT_MAX_LEDGER_ROWS,),
        )
        findings: List[Dict[str, Any]] = []
        for row in rows:
            item_id = row["item_id"]
            if row["projection_item_id"] is None:
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "missing-current-projection",
                        "item_id": item_id,
                    }
                )
                continue
            if row["source_freshness"] != "FRESH":
                findings.append(
                    {
                        "blocking": True,
                        "category": "drift",
                        "code": "stale-current-projection",
                        "item_id": item_id,
                        "source_freshness": row["source_freshness"],
                    }
                )
            if row["identity_ambiguous"]:
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "identity-ambiguous",
                        "item_id": item_id,
                    }
                )
            if row["correction_required"]:
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "correction-required",
                        "item_id": item_id,
                    }
                )
            if row["primary_state"] == "APPLIED":
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "unsupported-applied-provenance",
                        "item_id": item_id,
                    }
                )
            projection_decision_bound = (
                row["projection_decision_id"] is not None
                and row["projection_source_event_id"]
                == row["projection_decision_id"]
                and row["projection_decision_item_id"] == item_id
                and row["decision_projection_generation"]
                == row["projection_generation"]
            )
            expected_action = _TERMINAL_DECISION_ACTION.get(
                row["primary_state"]
            )
            terminal_decision_explained = (
                projection_decision_bound
                and row["projection_decision_action"] == expected_action
            )
            if expected_action is not None and not terminal_decision_explained:
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "projection-decision-mismatch",
                        "item_id": item_id,
                    }
            )
            explained_unassigned = False
            if row["unassigned"]:
                explained_unassigned = (
                    row["primary_state"] == "REVIEW_READY"
                    and row["unassigned_count"] == 1
                    and type(row["unassigned_reason"]) is str
                    and bool(row["unassigned_reason"])
                    and _unassigned_condition_matches(
                        row["assignment_condition_json"],
                        row["assignment_condition_sha256"],
                        row["unassigned_reason"],
                    )
                    and row["unassigned_decision_id"]
                    == row["projection_decision_id"]
                    and projection_decision_bound
                    and row["projection_decision_action"] == "CORRECTION"
                    and row["current_primary_count"] == 0
                )
                if not explained_unassigned:
                    findings.append(
                        {
                            "blocking": True,
                            "category": "integrity",
                            "code": "unexplained-unassigned-item",
                            "item_id": item_id,
                        }
                    )
            elif row["unassigned_count"]:
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "unexpected-current-unassigned-exception",
                        "item_id": item_id,
                    }
                )
            if row["primary_state"] == "LINKED" and not (
                row["decision_workstream_relation_count"]
                or row["decision_document_relation_count"]
            ):
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "projection-relation-mismatch",
                        "item_id": item_id,
                    }
                )
            if (
                row["primary_state"] != "DEFERRED"
                and (
                    row["current_deferral_id"] is not None
                    or row["current_deferral_count"]
                )
            ):
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "unexpected-current-deferral",
                        "item_id": item_id,
                    }
                )
            if row["primary_state"] == "DEFERRED":
                explained_deferred = (
                    row["current_deferral_id"] is not None
                    and row["current_deferral_count"] == 1
                    and row["deferral_id"] == row["current_deferral_id"]
                    and row["deferral_item_id"] == item_id
                    and _valid_payload_text(row["deferral_reason"])
                    and row["deferral_state"] == "CURRENT"
                    and _required_evidence_matches(
                        row["required_evidence_json"],
                        row["required_evidence_sha256"],
                    )
                    and _valid_deferral_trigger(row)
                    and row["projection_decision_id"]
                    == row["deferral_decision_id"]
                    and terminal_decision_explained
                )
                if not explained_deferred:
                    findings.append(
                        {
                            "blocking": True,
                            "category": "integrity",
                            "code": "unexplained-deferred-item",
                            "item_id": item_id,
                        }
                    )
            if (
                row["primary_state"] in _UNRESOLVED_PRIMARY_STATES
                and not row["lifecycle_frozen"]
                and not explained_unassigned
            ):
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "unresolved-curation-state",
                        "item_id": item_id,
                        "primary_state": row["primary_state"],
                    }
                )
        return findings

    def _batch_membership_cache(self) -> dict:
        rows = tuple(
            tuple(row)
            for row in self.connection.execute(
                "SELECT membership_id, batch_id, unit_id, item_id, path, status "
                "FROM batch_memberships ORDER BY batch_id, membership_id LIMIT ?",
                (_AUDIT_MAX_LEDGER_ROWS + 1,),
            )
        )
        if len(rows) > _AUDIT_MAX_LEDGER_ROWS:
            raise _AuditRowBudgetExceeded(
                "batch membership ledger scan is truncated"
            )
        cache: Dict[str, list] = {}
        for row in rows:
            cache.setdefault(row[1], []).append(row)
        return {
            batch_id: tuple(memberships)
            for batch_id, memberships in cache.items()
        }

    def _prepared_batch_submission_ids(self) -> frozenset[str]:
        rows = tuple(
            row[0]
            for row in self.connection.execute(
                _PREPARED_BATCH_SUBMISSIONS_SQL,
                (_AUDIT_MAX_PREPARED_BATCH_SUBMISSIONS + 1,),
            )
        )
        if len(rows) > _AUDIT_MAX_PREPARED_BATCH_SUBMISSIONS:
            raise _AuditRowBudgetExceeded(
                "prepared batch submission scan is truncated"
            )
        return frozenset(rows)

    @staticmethod
    def _terminal_membership_poststate(
        batch_id: str,
        *,
        membership_cache: dict,
        terminal_cache: dict,
    ) -> tuple:
        cached = terminal_cache.get(batch_id)
        if cached is not None:
            return cached
        rows = membership_cache.get(batch_id, ())
        release = tuple(
            {
                "item_id": item_id,
                "membership_id": membership_id,
                "path": path,
                "unit_id": unit_id,
            }
            for (
                membership_id,
                _batch_id,
                unit_id,
                item_id,
                path,
                _member_state,
            ) in rows
        )
        value = (
            release,
            all(row[-1] == "RELEASED" for row in rows),
        )
        terminal_cache[batch_id] = value
        return value

    @staticmethod
    def _split_side_memberships_are_current(
        batch_id: str,
        memberships: list,
        *,
        membership_cache: dict,
    ) -> bool:
        expected = tuple(
            sorted(
                (
                    membership["membership_id"],
                    batch_id,
                    membership["unit_id"],
                    membership["item_id"],
                    membership["path"],
                    "OPEN",
                )
                for membership in memberships
            )
        )
        return membership_cache.get(batch_id, ()) == expected

    @staticmethod
    def _split_side_has_successor(
        *,
        successor_index: dict,
        event_rowid: int,
        batch_id: str,
        snapshot_id: str,
        snapshot_sha256: str,
        review_revision: int,
        execution_generation: int,
        memberships: list,
    ) -> bool:
        rowids, successors = successor_index.get(
            (
                batch_id,
                snapshot_id,
                snapshot_sha256,
                review_revision,
                execution_generation,
            ),
            ((), ()),
        )
        position = bisect_right(rowids, event_rowid)
        if len(successors) - position != 1:
            return False
        successor = successors[position]
        expected_release = [
            {
                "item_id": membership["item_id"],
                "membership_id": membership["membership_id"],
                "path": membership["path"],
                "unit_id": membership["unit_id"],
            }
            for membership in memberships
        ]
        return (
            successor["event_kind"]
            in ("SPLIT", "CLOSE_REVIEW", "ABANDON")
            and successor["release_valid"]
            and successor["release"] == expected_release
        )

    @staticmethod
    def _split_successor_index(rows: tuple) -> dict:
        index: Dict[tuple, list] = {}
        for row in rows:
            if (
                row["state"] != "PUBLISHED"
                or row["expected_batch_status"] != "OPEN"
            ):
                continue
            key = (
                row["batch_id"],
                row["expected_snapshot_id"],
                row["expected_snapshot_sha256"],
                row["expected_review_revision"],
                row["expected_execution_generation"],
            )
            release_bounded = (
                row["release_storage"] == "blob"
                and type(row["release_size"]) is int
                and 0 <= row["release_size"]
                <= _BATCH_EVENT_MAX_PAYLOAD_BYTES
            )
            if release_bounded:
                release_valid, release = _canonical_blob_value(
                    row["membership_release_json"],
                    row["membership_release_sha256"],
                )
            else:
                release_valid, release = False, None
            index.setdefault(key, []).append(
                (
                    row["event_rowid"],
                    {
                        "event_kind": row["event_kind"],
                        "release": release,
                        "release_valid": release_valid,
                    },
                )
            )
        return {
            key: (
                tuple(candidate[0] for candidate in candidates),
                tuple(candidate[1] for candidate in candidates),
            )
            for key, candidates in index.items()
        }

    def _batch_event_artifact_findings(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        total_blob_bytes = 0
        row_count = 0
        for payload_size, release_size in self.connection.execute(
            "SELECT octet_length(payload_json), "
            "octet_length(membership_release_json) "
            "FROM batch_events ORDER BY rowid LIMIT ?",
            (_AUDIT_MAX_LEDGER_ROWS + 1,),
        ):
            row_count += 1
            if row_count > _AUDIT_MAX_LEDGER_ROWS:
                return [
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "batch-event-ledger-scan-truncated",
                    }
                ]
            if type(payload_size) is int and type(release_size) is int:
                total_blob_bytes += payload_size + release_size
            if total_blob_bytes > _AUDIT_MAX_TOTAL_BLOB_BYTES:
                return [
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "batch-event-payload-scan-truncated",
                    }
                ]

        campaign_namespaces: Dict[str, Tuple[Tuple[str, bool], ...]] = {}
        unsafe_namespaces = set()
        inspected = 0
        campaigns_root = self.control_root / "campaigns"
        try:
            campaign_entries, truncated = _bounded_directory_entries(
                campaigns_root,
                _CONTROL_SCAN_MAX_ENTRIES,
            )
        except CurationAuditError as exc:
            campaign_entries = ()
            truncated = False
            if not _caused_by_missing(exc):
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "unsafe-batch-event-root",
                        "path": "campaigns",
                    }
                )
        if truncated:
            return findings + [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "batch-event-scan-truncated",
                    "path": "campaigns",
                }
            ]
        inspected += len(campaign_entries)
        for campaign_name, is_directory in campaign_entries:
            safe_campaign = _safe_context(campaign_name, "campaign")
            if (
                not is_directory
                or _BATCH_EVENT_ID.fullmatch(campaign_name) is None
            ):
                findings.append(
                    {
                        "blocking": True,
                        "category": "orphan",
                        "code": "unsafe-batch-event-campaign-entry",
                        "path": "campaigns/%s" % safe_campaign,
                    }
                )
                continue
            event_root = campaigns_root / campaign_name / "batch-events"
            remaining = _CONTROL_SCAN_MAX_ENTRIES - inspected
            try:
                entries, event_truncated = _bounded_directory_entries(
                    event_root,
                    remaining,
                )
            except CurationAuditError as exc:
                if _caused_by_missing(exc):
                    continue
                unsafe_namespaces.add(campaign_name)
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "unsafe-batch-event-root",
                        "path": "campaigns/%s/batch-events" % campaign_name,
                    }
                )
                continue
            if event_truncated:
                return findings + [
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "batch-event-scan-truncated",
                        "path": "campaigns/%s/batch-events" % campaign_name,
                    }
                ]
            inspected += len(entries)
            campaign_namespaces[campaign_name] = entries

        legacy_root = self.control_root / "batch-events"
        try:
            _legacy_entries, _legacy_truncated = _bounded_directory_entries(
                legacy_root,
                max(0, _CONTROL_SCAN_MAX_ENTRIES - inspected),
            )
        except CurationAuditError as exc:
            if not _caused_by_missing(exc):
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "unsafe-legacy-batch-event-namespace",
                        "path": "batch-events",
                    }
                )
        else:
            findings.append(
                {
                    "blocking": True,
                    "category": "drift",
                    "code": "legacy-batch-event-namespace",
                    "path": "batch-events",
                }
            )

        rows = tuple(self.connection.execute(
            "SELECT e.rowid AS event_rowid, e.batch_event_id, e.batch_id, "
            "e.event_kind, "
            "e.expected_batch_status, e.expected_snapshot_id, "
            "e.expected_snapshot_sha256, e.expected_review_revision, "
            "e.expected_execution_generation, e.terminal_batch_status, "
            "e.child_batch_id, e.child_snapshot_id, e.child_snapshot_sha256, "
            "e.source_execution_id, e.source_approval_id, e.result_path, "
            "e.result_sha256, CASE "
            "WHEN typeof(e.membership_release_json) = 'blob' "
            "THEN octet_length(e.membership_release_json) ELSE 0 END AS release_size, "
            "CASE WHEN typeof(e.membership_release_json) = 'blob' "
            "THEN substr(e.membership_release_json, 1, ?) ELSE X'' END "
            "AS membership_release_json, e.membership_release_sha256, "
            "CASE WHEN typeof(e.payload_json) = 'blob' "
            "THEN octet_length(e.payload_json) ELSE 0 END AS payload_size, "
            "CASE WHEN typeof(e.payload_json) = 'blob' "
            "THEN substr(e.payload_json, 1, ?) ELSE X'' END AS payload_json, "
            "e.payload_sha256, e.final_path, e.final_sha256, e.state, "
            "typeof(e.membership_release_json) AS release_storage, "
            "typeof(e.payload_json) AS payload_storage, b.campaign_id, "
            "b.status AS observed_batch_status, "
            "b.current_snapshot_id AS observed_snapshot_id, "
            "b.current_snapshot_sha256 AS observed_snapshot_sha256, "
            "b.review_revision AS observed_review_revision, "
            "b.execution_generation AS observed_execution_generation, "
            "b.request_hash AS parent_request_hash, "
            "cb.campaign_id AS child_campaign_id, "
            "cb.request_hash AS child_request_hash, "
            "cb.status AS child_observed_batch_status, "
            "cb.current_snapshot_id AS child_observed_snapshot_id, "
            "cb.current_snapshot_sha256 AS child_observed_snapshot_sha256, "
            "cb.review_revision AS child_observed_review_revision, "
            "cb.execution_generation AS child_observed_execution_generation "
            "FROM batch_events AS e LEFT JOIN review_batches AS b "
            "ON b.batch_id = e.batch_id "
            "LEFT JOIN review_batches AS cb ON cb.batch_id = e.child_batch_id "
            "ORDER BY e.rowid LIMIT ?",
            (
                _BATCH_EVENT_MAX_PAYLOAD_BYTES + 1,
                _BATCH_EVENT_MAX_PAYLOAD_BYTES + 1,
                _AUDIT_MAX_LEDGER_ROWS,
            ),
        ))
        successor_index = self._split_successor_index(rows)
        try:
            membership_cache = self._batch_membership_cache()
        except _AuditRowBudgetExceeded:
            findings.append(
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "batch-membership-ledger-scan-truncated",
                }
            )
            return findings
        if any(
            row["state"] == "PUBLISHED"
            and row["event_kind"] in ("CLOSE_REVIEW", "ABANDON")
            for row in rows
        ):
            try:
                prepared_batch_submission_ids = (
                    self._prepared_batch_submission_ids()
                )
            except _AuditRowBudgetExceeded:
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "review-submission-ledger-scan-truncated",
                    }
                )
                return findings
        else:
            prepared_batch_submission_ids = frozenset()
        terminal_membership_cache: Dict[str, tuple] = {}
        snapshot_bytes_read = 0
        row_ids = set()
        for row in rows:
            event_id = row["batch_event_id"]
            state = row["state"]
            campaign_id = row["campaign_id"]
            if (
                type(event_id) is str
                and _BATCH_EVENT_ID.fullmatch(event_id) is not None
                and type(campaign_id) is str
                and _BATCH_EVENT_ID.fullmatch(campaign_id) is not None
            ):
                row_ids.add((campaign_id, event_id))
            if (
                row["payload_storage"] != "blob"
                or row["release_storage"] != "blob"
                or type(row["payload_size"]) is not int
                or type(row["release_size"]) is not int
            ):
                findings.append(
                    _batch_finding(
                        event_id,
                        "batch-event-storage-invalid",
                        state=state,
                    )
                )
                continue
            if (
                row["payload_size"] > _BATCH_EVENT_MAX_PAYLOAD_BYTES
                or row["release_size"] > _BATCH_EVENT_MAX_PAYLOAD_BYTES
            ):
                findings.append(
                    _batch_finding(
                        event_id,
                        "batch-event-payload-bound-exceeded",
                        state=state,
                    )
                )
                continue
            record = dict(row)
            try:
                validated = batch_event_contract.validate_batch_event(
                    record,
                    max_blob_bytes=_BATCH_EVENT_MAX_PAYLOAD_BYTES,
                )
            except batch_event_contract.BatchEventContractError as exc:
                findings.append(
                    _batch_finding(event_id, exc.code, state=state)
                )
                continue
            if (
                type(campaign_id) is not str
                or _BATCH_EVENT_ID.fullmatch(campaign_id) is None
            ):
                findings.append(
                    _batch_finding(
                        event_id,
                        "batch-event-storage-invalid",
                        state=state,
                    )
                )
                continue
            event_root = (
                campaigns_root / campaign_id / "batch-events"
            )
            artifact = event_root / validated.event_id / "event.json"
            expected_path = str(artifact)
            relative = artifact.relative_to(self.control_root).as_posix()
            if record["final_path"] != expected_path:
                findings.append(
                    _batch_finding(
                        event_id,
                        "unsafe-batch-event-artifact-path",
                        state=state,
                    )
                )
                continue
            if campaign_id in unsafe_namespaces:
                continue
            directory_entries: Tuple[Tuple[str, bool], ...] = ()
            directory_present = True
            try:
                directory_entries, directory_truncated = _bounded_directory_entries(
                    artifact.parent,
                    2,
                )
            except CurationAuditError as exc:
                if _caused_by_missing(exc):
                    directory_present = False
                    directory_truncated = False
                else:
                    findings.append(
                        _batch_finding(
                            event_id,
                            "unsafe-batch-event-artifact",
                            state=state,
                            path=relative,
                        )
                    )
                    continue
            if directory_present and (
                directory_truncated
                or directory_entries != (("event.json", False),)
            ):
                findings.append(
                    _batch_finding(
                        event_id,
                        "unexpected-batch-event-entry",
                        state=state,
                        path=artifact.parent.relative_to(
                            self.control_root
                        ).as_posix(),
                    )
                )
            raw = None
            if directory_present:
                try:
                    raw = _read_bounded_regular_file(
                        artifact,
                        len(record["payload_json"]),
                    )
                except _MissingAuditEntry:
                    raw = None
                except (CurationAuditError, TypeError, ValueError):
                    findings.append(
                        _batch_finding(
                            event_id,
                            "unsafe-batch-event-artifact",
                            state=state,
                            path=relative,
                        )
                    )
                    continue
            if state == "PUBLISHED" and raw is None:
                findings.append(
                    _batch_finding(
                        event_id,
                        "missing-batch-event-artifact",
                        state=state,
                        path=relative,
                    )
                )
            elif raw is not None and (
                raw != record["payload_json"]
                or sha256_bytes(raw) != record["final_sha256"]
            ):
                findings.append(
                    _batch_finding(
                        event_id,
                        "batch-event-artifact-mismatch",
                        state=state,
                        path=relative,
                    )
                )
            if state in ("PREPARED", "BLOCKED"):
                findings.append(
                    _batch_finding(
                        event_id,
                        "unresolved-batch-event",
                        state=state,
                    )
                )
                continue
            if validated.event_kind in ("CLOSE_REVIEW", "ABANDON"):
                memberships, all_memberships_released = (
                    self._terminal_membership_poststate(
                        validated.batch_id,
                        membership_cache=membership_cache,
                        terminal_cache=terminal_membership_cache,
                    )
                )
                lineage_ok = (
                    row["observed_batch_status"]
                    == row["terminal_batch_status"]
                    and row["observed_snapshot_id"]
                    == row["expected_snapshot_id"]
                    and row["observed_snapshot_sha256"]
                    == row["expected_snapshot_sha256"]
                    and row["observed_review_revision"]
                    == row["expected_review_revision"]
                    and row["observed_execution_generation"]
                    == row["expected_execution_generation"]
                    and all_memberships_released
                    and memberships == validated.membership_release
                    and validated.batch_id
                    not in prepared_batch_submission_ids
                )
                if not lineage_ok:
                    findings.append(
                        _batch_finding(
                            event_id,
                            "batch-event-lineage-mismatch",
                            state=state,
                        )
                    )
            elif validated.event_kind == "SPLIT":
                split_payload = validated.payload
                try:
                    expected_child_request_hash = (
                        batch_event_contract.split_child_request_hash(
                            validated.batch_id,
                            split_payload["child_batch_id"],
                        )
                    )
                except batch_event_contract.BatchEventContractError:
                    expected_child_request_hash = None
                parent_superseded = self._split_side_has_successor(
                    successor_index=successor_index,
                    event_rowid=row["event_rowid"],
                    batch_id=validated.batch_id,
                    snapshot_id=split_payload["parent_next_snapshot_id"],
                    snapshot_sha256=split_payload[
                        "parent_next_snapshot_sha256"
                    ],
                    review_revision=(
                        split_payload["expected_review_revision"] + 1
                    ),
                    execution_generation=split_payload[
                        "expected_execution_generation"
                    ],
                    memberships=split_payload["remainder_memberships"],
                )
                parent_current = (
                    not parent_superseded
                    and row["observed_batch_status"] == "OPEN"
                    and row["observed_snapshot_id"]
                    == split_payload["parent_next_snapshot_id"]
                    and row["observed_snapshot_sha256"]
                    == split_payload["parent_next_snapshot_sha256"]
                    and row["observed_review_revision"]
                    == split_payload["expected_review_revision"] + 1
                    and row["observed_execution_generation"]
                    == split_payload["expected_execution_generation"]
                    and self._split_side_memberships_are_current(
                        validated.batch_id,
                        split_payload["remainder_memberships"],
                        membership_cache=membership_cache,
                    )
                )
                child_superseded = self._split_side_has_successor(
                    successor_index=successor_index,
                    event_rowid=row["event_rowid"],
                    batch_id=split_payload["child_batch_id"],
                    snapshot_id=split_payload["child_snapshot_id"],
                    snapshot_sha256=split_payload["child_snapshot_sha256"],
                    review_revision=1,
                    execution_generation=0,
                    memberships=split_payload["selected_memberships"],
                )
                child_current = (
                    not child_superseded
                    and row["child_observed_batch_status"] == "OPEN"
                    and row["child_observed_snapshot_id"]
                    == split_payload["child_snapshot_id"]
                    and row["child_observed_snapshot_sha256"]
                    == split_payload["child_snapshot_sha256"]
                    and row["child_observed_review_revision"] == 1
                    and row["child_observed_execution_generation"] == 0
                    and self._split_side_memberships_are_current(
                        split_payload["child_batch_id"],
                        split_payload["selected_memberships"],
                        membership_cache=membership_cache,
                    )
                )
                poststate_ok = (
                    (parent_current or parent_superseded)
                    and (child_current or child_superseded)
                )
                snapshot_pairs = (
                    {
                        "batch_id": validated.batch_id,
                        "batch_version": (
                            split_payload["expected_review_revision"] + 1
                        ),
                        "memberships": split_payload[
                            "remainder_memberships"
                        ],
                        "request_hash": row["parent_request_hash"],
                        "snapshot_id": split_payload[
                            "parent_next_snapshot_id"
                        ],
                        "snapshot_sha256": split_payload[
                            "parent_next_snapshot_sha256"
                        ],
                    },
                    {
                        "batch_id": split_payload["child_batch_id"],
                        "batch_version": 1,
                        "memberships": split_payload[
                            "selected_memberships"
                        ],
                        "request_hash": expected_child_request_hash,
                        "snapshot_id": split_payload["child_snapshot_id"],
                        "snapshot_sha256": split_payload[
                            "child_snapshot_sha256"
                        ],
                    },
                )
                snapshots_ok = (
                    poststate_ok
                    and row["child_campaign_id"] == campaign_id
                    and row["child_request_hash"]
                    == expected_child_request_hash
                )
                for expected_snapshot in snapshot_pairs:
                    snapshot_id = expected_snapshot["snapshot_id"]
                    snapshot_path = (
                        campaigns_root
                        / campaign_id
                        / "snapshots"
                        / snapshot_id
                        / "snapshot.json"
                    )
                    try:
                        remaining_snapshot_bytes = (
                            _BATCH_EVENT_MAX_TOTAL_SNAPSHOT_BYTES
                            - snapshot_bytes_read
                        )
                        snapshot_raw = _read_bounded_regular_file(
                            snapshot_path,
                            _BATCH_EVENT_MAX_PAYLOAD_BYTES,
                            aggregate_remaining=remaining_snapshot_bytes,
                        )
                    except _AuditByteBudgetExceeded:
                        findings.append(
                            {
                                "blocking": True,
                                "category": "integrity",
                                "code": "batch-event-snapshot-scan-truncated",
                            }
                        )
                        return findings
                    except (CurationAuditError, TypeError, ValueError):
                        snapshots_ok = False
                        break
                    snapshot_bytes_read += len(snapshot_raw)
                    snapshot_payload = _canonical_split_snapshot(snapshot_raw)
                    if (
                        sha256_bytes(snapshot_raw)
                        != expected_snapshot["snapshot_sha256"]
                        or snapshot_payload is None
                        or type(snapshot_payload.get("schema_version")) is not int
                        or snapshot_payload.get("schema_version") != 2
                        or snapshot_payload.get("campaign_id") != campaign_id
                        or snapshot_payload.get("batch_id")
                        != expected_snapshot["batch_id"]
                        or type(snapshot_payload.get("batch_version")) is not int
                        or snapshot_payload.get("batch_version")
                        != expected_snapshot["batch_version"]
                        or snapshot_payload.get("snapshot_id") != snapshot_id
                        or snapshot_payload.get("parent_snapshot_id")
                        != split_payload["expected_snapshot_id"]
                        or snapshot_payload.get("parent_snapshot_sha256")
                        != split_payload["expected_snapshot_sha256"]
                        or snapshot_payload.get("request_hash")
                        != expected_snapshot["request_hash"]
                        or _split_snapshot_unit_projection(
                            snapshot_payload.get("units")
                        )
                        != _split_membership_unit_projection(
                            expected_snapshot["memberships"]
                        )
                    ):
                        snapshots_ok = False
                        break
                if not snapshots_ok:
                    findings.append(
                        _batch_finding(
                            event_id,
                            "batch-event-lineage-mismatch",
                            state=state,
                        )
                    )

        for campaign_id, event_entries in campaign_namespaces.items():
            for name, is_directory in event_entries:
                if (campaign_id, name) in row_ids:
                    continue
                safe_name = _safe_context(name, "entry")
                base = "campaigns/%s/batch-events/%s" % (
                    campaign_id,
                    safe_name,
                )
                findings.append(
                    {
                        "blocking": True,
                        "category": "orphan",
                        "code": (
                            "rowless-batch-event-artifact"
                            if is_directory
                            else "rowless-batch-event-entry"
                        ),
                        "path": "%s/event.json" % base if is_directory else base,
                    }
                )
        return findings

    def _incomplete_artifact_findings(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        pending = deque(((self.control_root, 0),))
        inspected = 0
        while pending:
            directory, depth = pending.popleft()
            remaining = _CONTROL_SCAN_MAX_ENTRIES - inspected
            try:
                entries, truncated = _bounded_directory_entries(
                    directory,
                    remaining,
                )
            except CurationAuditError:
                if directory == self.control_root and not control_root_present(
                    self.control_root
                ):
                    return []
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "unreadable-control-directory",
                        "path": directory.relative_to(self.control_root).as_posix()
                        or ".",
                    }
                )
                continue
            if truncated:
                findings.append(
                    {
                        "blocking": True,
                        "category": "integrity",
                        "code": "control-artifact-scan-truncated",
                        "path": directory.relative_to(self.control_root).as_posix()
                        or ".",
                    }
                )
                return findings
            inspected += len(entries)
            for name, is_directory in entries:
                path = directory / name
                relative = path.relative_to(self.control_root).as_posix()
                if name.startswith(".incomplete-"):
                    findings.append(
                        {
                            "blocking": False,
                            "category": "integrity",
                            "code": "incomplete-control-artifact-observed",
                            "path": relative,
                        }
                    )
                    continue
                if not is_directory:
                    continue
                if depth >= _CONTROL_SCAN_MAX_DEPTH:
                    findings.append(
                        {
                            "blocking": True,
                            "category": "integrity",
                            "code": "control-artifact-scan-depth-truncated",
                            "path": relative,
                        }
                    )
                    continue
                pending.append((path, depth + 1))
        return findings

    def run(self) -> Dict[str, Any]:
        try:
            findings = (
                self._projection_findings()
                + self._batch_event_artifact_findings()
                + self._incomplete_artifact_findings()
            )
        except sqlite3.Error as exc:
            raise CurationAuditError("curation audit query failed") from exc
        return report_from_findings(findings)


__all__ = [
    "AuditRuntimeFailure",
    "CurationAuditError",
    "CurationIntegrityQuery",
    "control_root_present",
    "not_activated_report",
    "report_from_findings",
    "runtime_failure_report",
]
