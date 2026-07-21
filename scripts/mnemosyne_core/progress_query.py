"""Read-only stable JSON projections for M3 curation progress.

The query layer owns no state transition.  Due evaluation is delegated to the
pure deferral evaluator and never appends a trigger event.
"""

from __future__ import annotations

import datetime
import json
import re
import sqlite3
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import deferral_service, m3_schema
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TRIGGER_KIND = {
    "DATE": "date",
    "WORKSTREAM_RESUME": "workstream-resume",
    "EVIDENCE": "evidence",
    "MANUAL_REOPEN": "manual-reopen",
}
_MAX_BOUNDED_ITEMS = 256
_MAX_BOUNDED_QUERY_BYTES = 4 * 1024 * 1024


class ProgressQueryError(ValueError):
    """A read filter, ledger, or stored projection is invalid."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ProgressQueryError("%s is invalid" % label)
    return value


def _canonical_value(raw: Any, digest: str, label: str) -> Any:
    encoded = bytes(raw)
    if type(digest) is not str or _HASH.fullmatch(digest) is None:
        raise ProgressQueryError("%s hash is invalid" % label)
    if sha256_bytes(encoded) != digest:
        raise ProgressQueryError("%s hash mismatch" % label)
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProgressQueryError("%s is invalid JSON" % label) from exc
    if canonical_json_bytes(value) != encoded:
        raise ProgressQueryError("%s is not canonical JSON" % label)
    return value


def _aware(value: Any) -> datetime.datetime:
    if not isinstance(value, datetime.datetime) or value.tzinfo is None:
        raise ProgressQueryError("query clock must be timezone-aware")
    if value.utcoffset() is None:
        raise ProgressQueryError("query clock must be timezone-aware")
    return value


def _bounded_items(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if type(value) is not int or not 1 <= value <= _MAX_BOUNDED_ITEMS:
        raise ProgressQueryError("max items is invalid")
    return value


def _octet_sum(columns: Tuple[str, ...]) -> str:
    return " + ".join(
        "COALESCE(octet_length(%s), 0)" % column for column in columns
    )


def _preflight_bounded_bytes(
    connection: sqlite3.Connection,
    statement: str,
    parameters: Tuple[Any, ...],
    label: str,
) -> int:
    try:
        row = connection.execute(statement, parameters).fetchone()
    except sqlite3.Error as exc:
        raise ProgressQueryError("%s byte preflight failed" % label) from exc
    if (
        row is None
        or type(row[0]) is not int
        or row[0] < 0
        or row[0] > _MAX_BOUNDED_QUERY_BYTES
    ):
        raise ProgressQueryError("%s exceeds byte budget" % label)
    return row[0]


class ProgressQuery:
    """Expose locale-independent Workstream, item, deferred, and history views."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        now: Callable[[], datetime.datetime],
        workstream_lifecycle: Callable[[str], str],
        current_policy_hash: Callable[[], str],
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if connection.in_transaction:
            raise ProgressQueryError("progress query requires transaction ownership")
        for callback, label in (
            (now, "now"),
            (workstream_lifecycle, "workstream_lifecycle"),
            (current_policy_hash, "current_policy_hash"),
        ):
            if not callable(callback):
                raise TypeError("%s must be callable" % label)
        try:
            m3_schema.verify_v3_schema(connection)
        except (m3_schema.M3SchemaError, sqlite3.Error) as exc:
            raise ProgressQueryError("exact curation ledger v3 is required") from exc
        self.connection = connection
        self._now = now
        self._workstream_lifecycle = workstream_lifecycle
        self._current_policy_hash = current_policy_hash
        self._evaluator = deferral_service.DeferralTriggerEvaluator()

    def _clock(self) -> datetime.datetime:
        return _aware(self._now())

    def _record(self, row: sqlite3.Row) -> deferral_service.DeferralRecord:
        try:
            trigger_kind = _TRIGGER_KIND[row[7]]
        except KeyError as exc:
            raise ProgressQueryError("stored deferral trigger kind is invalid") from exc
        return deferral_service.DeferralRecord(
            deferral_id=row[0],
            item_id=row[1],
            version=row[2],
            state="waiting",
            trigger_kind=trigger_kind,
            review_date=row[8],
            timezone=row[9],
            workstream_id=row[10],
            captured_lifecycle=(
                row[11].lower() if isinstance(row[11], str) else row[11]
            ),
            captured_policy_hash=row[12],
        )

    def _published_evidence(
        self,
        record: deferral_service.DeferralRecord,
    ) -> Optional[deferral_service.PublishedEvidence]:
        row = self.connection.execute(
            "SELECT evidence_event_id, final_sha256, deferral_id, "
            "deferral_version, state FROM deferral_evidence_events "
            "WHERE deferral_id = ? AND deferral_version = ? AND state = 'PUBLISHED' "
            "ORDER BY evidence_event_id LIMIT 1",
            (record.deferral_id, record.version),
        ).fetchone()
        if row is None:
            return None
        return deferral_service.PublishedEvidence(
            event_id=row[0],
            event_sha256=row[1],
            deferral_id=row[2],
            deferral_version=row[3],
            state=row[4],
        )

    def _preview(
        self,
        record: deferral_service.DeferralRecord,
    ) -> deferral_service.TriggerPreview:
        arguments: Dict[str, Any] = {"now": self._clock()}
        if record.trigger_kind == "workstream-resume":
            lifecycle = self._workstream_lifecycle(record.workstream_id)
            if type(lifecycle) is not str:
                raise ProgressQueryError("current Workstream lifecycle is invalid")
            policy_hash = self._current_policy_hash()
            if type(policy_hash) is not str or _HASH.fullmatch(policy_hash) is None:
                raise ProgressQueryError("current policy hash is invalid")
            arguments.update(
                {
                    "current_policy_hash": policy_hash,
                    "current_workstream_lifecycle": lifecycle,
                }
            )
        elif record.trigger_kind == "evidence":
            arguments["published_evidence"] = self._published_evidence(record)
        try:
            return self._evaluator.preview(record, **arguments)
        except deferral_service.DeferralValidationError as exc:
            raise ProgressQueryError(str(exc)) from exc

    def _deferral_rows(
        self,
        *,
        workstream_id: Optional[str] = None,
        item_id: Optional[str] = None,
        max_rows: Optional[int] = None,
    ) -> Tuple[sqlite3.Row, ...]:
        if max_rows is not None and (
            type(max_rows) is not int
            or not 1 <= max_rows <= _MAX_BOUNDED_ITEMS + 1
        ):
            raise ProgressQueryError("deferral scan bound is invalid")
        parameters: List[Any] = []
        relation_join = ""
        relation_filter = ""
        if workstream_id is not None:
            identity = _identifier(workstream_id, "workstream id")
            relation_join = (
                " JOIN workstream_relations AS wr ON wr.item_id = d.item_id "
            )
            relation_filter = (
                " AND wr.state = 'CURRENT' AND wr.workstream_id = ?"
            )
            parameters.append(identity)
        item_filter = ""
        if item_id is not None:
            item_filter = " AND d.item_id = ?"
            parameters.append(_identifier(item_id, "item id"))
        limit_clause = ""
        if max_rows is not None:
            limit_clause = " LIMIT ?"
            parameters.append(max_rows)
        from_where = (
            " FROM deferrals AS d"
            + relation_join
            + " WHERE d.state = 'CURRENT'"
            + relation_filter
            + item_filter
            + " GROUP BY d.deferral_id"
            + " ORDER BY d.item_id, d.deferral_id"
            + limit_clause
        )
        if max_rows is not None:
            _preflight_bounded_bytes(
                self.connection,
                "SELECT COALESCE(SUM(row_bytes), 0) FROM (SELECT "
                + _octet_sum(
                    (
                        "d.deferral_id",
                        "d.item_id",
                        "d.reason",
                        "d.required_evidence_json",
                        "d.required_evidence_sha256",
                        "d.owner_actor",
                        "d.trigger_kind",
                        "d.revisit_date",
                        "d.timezone",
                        "d.trigger_workstream_id",
                        "d.captured_lifecycle",
                        "d.captured_policy_sha256",
                    )
                )
                + " AS row_bytes"
                + from_where
                + ")",
                tuple(parameters),
                "bounded deferral query",
            )
        rows = self.connection.execute(
            "SELECT d.deferral_id, d.item_id, d.version, d.reason, "
            "d.required_evidence_json, d.required_evidence_sha256, d.owner_actor, "
            "d.trigger_kind, d.revisit_date, d.timezone, d.trigger_workstream_id, "
            "d.captured_lifecycle, d.captured_policy_sha256"
            + from_where,
            tuple(parameters),
        ).fetchall()
        return tuple(rows)

    def _deferred_item(self, row: sqlite3.Row) -> Dict[str, Any]:
        record = self._record(row)
        preview = self._preview(record)
        required = _canonical_value(
            row[4], row[5], "deferral required evidence"
        )
        return {
            "deferral_id": record.deferral_id,
            "item_id": record.item_id,
            "owner": row[6],
            "reason": row[3],
            "required_evidence": required,
            "review_date": record.review_date,
            "timezone": record.timezone,
            "trigger_evidence_hash": preview.trigger_evidence_hash,
            "trigger_kind": record.trigger_kind,
            "trigger_state": preview.inbox_state,
            "version": record.version,
            "workstream_id": record.workstream_id,
        }

    def list_deferred(
        self,
        *,
        state: str = "due",
        workstream_id: Optional[str] = None,
        max_items: Optional[int] = None,
    ) -> Dict[str, Any]:
        if state not in ("due", "waiting", "all"):
            raise ProgressQueryError("deferred state filter is invalid")
        maximum = _bounded_items(max_items)
        scan_limit = None if maximum is None else _MAX_BOUNDED_ITEMS + 1
        rows = self._deferral_rows(
            workstream_id=workstream_id,
            max_rows=scan_limit,
        )
        scan_truncated = maximum is not None and len(rows) > _MAX_BOUNDED_ITEMS
        if scan_truncated:
            rows = rows[:_MAX_BOUNDED_ITEMS]
        items = [
            self._deferred_item(row)
            for row in rows
        ]
        if state == "due":
            items = [item for item in items if item["trigger_state"] == "due"]
        elif state == "waiting":
            items = [item for item in items if item["trigger_state"] != "due"]
        result = {
            "filter": state,
            "items": items,
            "kind": "DeferredInbox",
            "schema_version": 1,
            "workstream_id": workstream_id,
        }
        if maximum is not None:
            result["items"] = items[:maximum]
            result["returned"] = len(result["items"])
            result["truncated"] = scan_truncated or len(items) > maximum
        return result

    def workstream_home(
        self,
        workstream_id: str,
        *,
        max_items: Optional[int] = None,
    ) -> Dict[str, Any]:
        identity = _identifier(workstream_id, "workstream id")
        maximum = _bounded_items(max_items)
        limit_clause = ""
        parameters: Tuple[Any, ...] = (identity,)
        if maximum is not None:
            limit_clause = " LIMIT ?"
            parameters = (identity, maximum + 1)
        home_from_where = (
            " FROM item_curation_projection AS p "
            "JOIN workstream_relations AS wr ON wr.item_id = p.item_id "
            "WHERE wr.state = 'CURRENT' AND wr.workstream_id = ? "
            "GROUP BY p.item_id ORDER BY p.item_id"
            + limit_clause
        )
        if maximum is not None:
            _preflight_bounded_bytes(
                self.connection,
                "SELECT COALESCE(SUM(row_bytes), 0) FROM (SELECT "
                + _octet_sum(("p.item_id", "p.primary_state"))
                + " AS row_bytes"
                + home_from_where
                + ")",
                parameters,
                "bounded workstream status",
            )
        rows = self.connection.execute(
            "SELECT p.item_id, p.primary_state" + home_from_where,
            parameters,
        ).fetchall()
        truncated = maximum is not None and len(rows) > maximum
        visible_rows = rows if maximum is None else rows[:maximum]
        states: Dict[str, int] = {}
        if maximum is None:
            for row in rows:
                key = row[1].lower().replace("_", "-")
                states[key] = states.get(key, 0) + 1
            denominator = len(rows)
        else:
            state_rows = self.connection.execute(
                "SELECT p.primary_state, COUNT(DISTINCT p.item_id) "
                "FROM item_curation_projection AS p "
                "JOIN workstream_relations AS wr ON wr.item_id = p.item_id "
                "WHERE wr.state = 'CURRENT' AND wr.workstream_id = ? "
                "GROUP BY p.primary_state ORDER BY p.primary_state",
                (identity,),
            ).fetchall()
            for state_row in state_rows:
                states[state_row[0].lower().replace("_", "-")] = state_row[1]
            denominator = sum(states.values())
        deferred_result = self.list_deferred(
            state="all",
            workstream_id=identity,
            max_items=(None if maximum is None else _MAX_BOUNDED_ITEMS),
        )
        deferred = deferred_result["items"]
        due = sum(item["trigger_state"] == "due" for item in deferred)
        deferred_summary = {"due": due, "waiting": len(deferred) - due}
        if maximum is not None:
            deferred_summary["truncated"] = deferred_result["truncated"]
        result = {
            "deferred": deferred_summary,
            "denominator": {"items": denominator},
            "item_ids": [row[0] for row in visible_rows],
            "kind": "WorkstreamHome",
            "schema_version": 1,
            "states": states,
            "workstream_id": identity,
        }
        if maximum is not None:
            result["returned"] = len(visible_rows)
            result["truncated"] = truncated
        return result

    def item_detail(
        self,
        item_id: str,
        *,
        max_items: Optional[int] = None,
    ) -> Dict[str, Any]:
        identity = _identifier(item_id, "item id")
        maximum = _bounded_items(max_items)
        relation_limit = "" if maximum is None else " LIMIT ?"
        workstream_parameters: Tuple[Any, ...] = (identity,)
        document_parameters: Tuple[Any, ...] = (identity, identity)
        if maximum is not None:
            workstream_parameters = (identity, maximum + 1)
            document_parameters = (identity, identity, maximum + 1)
        item_from_where = (
            " FROM items AS i "
            "LEFT JOIN item_curation_projection AS p ON p.item_id = i.item_id "
            "WHERE i.item_id = ?"
        )
        workstream_from_where = (
            " FROM workstream_relations WHERE item_id = ? AND state = 'CURRENT' "
            "ORDER BY relation_kind, workstream_id"
            + relation_limit
        )
        document_from_where = (
            " FROM document_relations "
            "WHERE state = 'CURRENT' AND (canonical_item_id = ? OR related_item_id = ?) "
            "ORDER BY relation_id"
            + relation_limit
        )
        if maximum is not None:
            item_status_bytes = _preflight_bounded_bytes(
                self.connection,
                "SELECT COALESCE(SUM(row_bytes), 0) FROM (SELECT "
                + _octet_sum(
                    (
                        "i.item_id",
                        "i.first_seen_run_id",
                        "i.state",
                        "p.primary_state",
                        "p.source_freshness",
                    )
                )
                + " AS row_bytes"
                + item_from_where
                + ")",
                (identity,),
                "bounded item status",
            )
            workstream_bytes = _preflight_bounded_bytes(
                self.connection,
                "SELECT COALESCE(SUM(row_bytes), 0) FROM (SELECT "
                + _octet_sum(
                    (
                        "workstream_relation_id",
                        "relation_kind",
                        "workstream_id",
                    )
                )
                + " AS row_bytes"
                + workstream_from_where
                + ")",
                workstream_parameters,
                "bounded item Workstream relations",
            )
            document_bytes = _preflight_bounded_bytes(
                self.connection,
                "SELECT COALESCE(SUM(row_bytes), 0) FROM (SELECT "
                + _octet_sum(
                    (
                        "relation_id",
                        "canonical_item_id",
                        "related_item_id",
                        "relation_kind",
                        "direction",
                    )
                )
                + " AS row_bytes"
                + document_from_where
                + ")",
                document_parameters,
                "bounded item document relations",
            )
            if (
                item_status_bytes + workstream_bytes + document_bytes
                > _MAX_BOUNDED_QUERY_BYTES
            ):
                raise ProgressQueryError(
                    "bounded item status exceeds byte budget"
                )
        row = self.connection.execute(
            "SELECT i.item_id, i.first_seen_run_id, i.state, p.primary_state, "
            "p.projection_generation, p.source_freshness, p.identity_ambiguous, "
            "p.lifecycle_frozen, p.unassigned, p.reversal_available, "
            "p.correction_required"
            + item_from_where,
            (identity,),
        ).fetchone()
        if row is None:
            raise ProgressQueryError("item does not exist")
        workstreams = [
            {
                "relation_id": relation[0],
                "relation_kind": relation[1].lower(),
                "workstream_id": relation[2],
            }
            for relation in self.connection.execute(
                "SELECT workstream_relation_id, relation_kind, workstream_id "
                + workstream_from_where,
                workstream_parameters,
            ).fetchall()
        ]
        documents = []
        relations = self.connection.execute(
            "SELECT relation_id, canonical_item_id, related_item_id, "
            "relation_kind, direction"
            + document_from_where,
            document_parameters,
        ).fetchall()
        for relation in relations:
            outbound = relation[1] == identity
            documents.append(
                {
                    "direction": relation[4].lower(),
                    "other_item_id": relation[2] if outbound else relation[1],
                    "relation_id": relation[0],
                    "relation_kind": relation[3].lower(),
                    "traversal": "outbound" if outbound else "inbound",
                }
            )
        relations_truncated = maximum is not None and (
            len(workstreams) > maximum or len(documents) > maximum
        )
        if maximum is not None:
            workstreams = workstreams[:maximum]
            documents = documents[:maximum]
        deferred_rows = self._deferral_rows(
            item_id=identity,
            max_rows=2,
        )
        result = {
            "correction_required": bool(row[10]) if row[3] is not None else False,
            "deferred": (
                self._deferred_item(deferred_rows[0]) if deferred_rows else None
            ),
            "document_relations": documents,
            "first_seen_run_id": row[1],
            "identity_ambiguous": bool(row[6]) if row[3] is not None else False,
            "item_id": row[0],
            "kind": "ItemDetail",
            "lifecycle_frozen": bool(row[7]) if row[3] is not None else False,
            "primary_state": (
                row[3].lower().replace("_", "-") if row[3] is not None else None
            ),
            "projection_generation": row[4],
            "reversal_available": bool(row[9]) if row[3] is not None else False,
            "schema_version": 1,
            "source_freshness": row[5],
            "unassigned": bool(row[8]) if row[3] is not None else False,
            "workstream_relations": workstreams,
        }
        if maximum is not None:
            result["relations_truncated"] = relations_truncated
        return result

    def history(
        self,
        item_id: str,
        *,
        max_items: Optional[int] = None,
    ) -> Dict[str, Any]:
        identity = _identifier(item_id, "item id")
        maximum = _bounded_items(max_items)
        if maximum is not None and self.connection.execute(
            "SELECT 1 FROM items WHERE item_id = ?",
            (identity,),
        ).fetchone() is None:
            raise ProgressQueryError("item does not exist")
        limit_clause = "" if maximum is None else " LIMIT ?"
        one_parameters: Tuple[Any, ...] = (identity,)
        two_parameters: Tuple[Any, ...] = (identity, identity)
        if maximum is not None:
            one_parameters = (identity, maximum + 1)
            two_parameters = (identity, identity, maximum + 1)
            decision_bytes = _preflight_bounded_bytes(
                self.connection,
                "SELECT COALESCE(SUM(row_bytes), 0) FROM (SELECT "
                + _octet_sum(
                    (
                        "decision_event_id",
                        "action",
                        "actor",
                        "occurred_at",
                        "snapshot_id",
                    )
                )
                + " AS row_bytes FROM decision_events WHERE item_id = ? "
                "ORDER BY occurred_at, decision_event_id LIMIT ?)",
                one_parameters,
                "bounded decision history",
            )
            relation_bytes = _preflight_bounded_bytes(
                self.connection,
                "SELECT COALESCE(SUM(row_bytes), 0) FROM (SELECT "
                + _octet_sum(
                    (
                        "relation_event_id",
                        "action",
                        "relation_kind",
                        "occurred_at",
                        "canonical_item_id",
                        "related_item_id",
                    )
                )
                + " AS row_bytes FROM document_relation_events "
                "WHERE canonical_item_id = ? OR related_item_id = ? "
                "ORDER BY occurred_at, relation_event_id LIMIT ?)",
                two_parameters,
                "bounded relation history",
            )
            deferral_bytes = _preflight_bounded_bytes(
                self.connection,
                "SELECT COALESCE(SUM(row_bytes), 0) FROM (SELECT "
                + _octet_sum(
                    (
                        "e.trigger_event_id",
                        "e.trigger_kind",
                        "e.actor",
                        "e.occurred_at",
                    )
                )
                + " AS row_bytes FROM deferral_trigger_events AS e "
                "JOIN deferrals AS d ON d.deferral_id = e.deferral_id "
                "WHERE d.item_id = ? ORDER BY e.occurred_at, "
                "e.trigger_event_id LIMIT ?)",
                one_parameters,
                "bounded deferral history",
            )
            if (
                decision_bytes + relation_bytes + deferral_bytes
                > _MAX_BOUNDED_QUERY_BYTES
            ):
                raise ProgressQueryError(
                    "bounded history exceeds byte budget"
                )
        events: List[Tuple[str, int, str, Dict[str, Any]]] = []
        for row in self.connection.execute(
            "SELECT decision_event_id, action, actor, occurred_at, snapshot_id "
            "FROM decision_events WHERE item_id = ? "
            "ORDER BY occurred_at, decision_event_id"
            + limit_clause,
            one_parameters,
        ).fetchall():
            events.append(
                (
                    row[3],
                    0,
                    row[0],
                    {
                        "action": row[1].lower().replace("_", "-"),
                        "actor": row[2],
                        "event_id": row[0],
                        "event_type": "decision",
                        "snapshot_id": row[4],
                        "timestamp": row[3],
                    },
                )
            )
        for row in self.connection.execute(
            "SELECT relation_event_id, action, relation_kind, occurred_at, "
            "canonical_item_id, related_item_id FROM document_relation_events "
            "WHERE canonical_item_id = ? OR related_item_id = ? "
            "ORDER BY occurred_at, relation_event_id"
            + limit_clause,
            two_parameters,
        ).fetchall():
            events.append(
                (
                    row[3],
                    1,
                    row[0],
                    {
                        "action": row[1].lower(),
                        "event_id": row[0],
                        "event_type": "document-relation",
                        "other_item_id": row[5] if row[4] == identity else row[4],
                        "relation_kind": row[2].lower(),
                        "timestamp": row[3],
                    },
                )
            )
        for row in self.connection.execute(
            "SELECT e.trigger_event_id, e.trigger_kind, e.actor, e.occurred_at "
            "FROM deferral_trigger_events AS e "
            "JOIN deferrals AS d ON d.deferral_id = e.deferral_id "
            "WHERE d.item_id = ? ORDER BY e.occurred_at, e.trigger_event_id"
            + limit_clause,
            one_parameters,
        ).fetchall():
            events.append(
                (
                    row[3],
                    2,
                    row[0],
                    {
                        "actor": row[2],
                        "event_id": row[0],
                        "event_type": "deferral-trigger",
                        "timestamp": row[3],
                        "trigger_kind": _TRIGGER_KIND[row[1]],
                    },
                )
            )
        ordered = sorted(events, key=lambda value: (value[0], value[1], value[2]))
        truncated = maximum is not None and len(ordered) > maximum
        if maximum is not None:
            ordered = ordered[:maximum]
        entries = []
        for sequence, (_timestamp, _rank, _event_id, payload) in enumerate(
            ordered, start=1
        ):
            entry = dict(payload)
            entry["sequence"] = sequence
            entries.append(entry)
        result = {
            "entries": entries,
            "item_id": identity,
            "kind": "History",
            "schema_version": 1,
        }
        if maximum is not None:
            result["returned"] = len(entries)
            result["scope"] = "m3-current-lineage"
            result["truncated"] = truncated
        return result


__all__ = ["ProgressQuery", "ProgressQueryError"]
