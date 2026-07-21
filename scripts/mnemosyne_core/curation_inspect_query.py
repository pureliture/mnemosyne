"""Pure bounded query models for gated Curation Inspect views."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from . import m3_schema


MAX_RECOVERY_ITEMS = 256
_MAX_STORED_TEXT_BYTES = 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RecoveryEvidenceQueryError(ValueError):
    """Stored recovery evidence or a bounded filter is invalid."""


@dataclass(frozen=True)
class _RecoverySource:
    family: str
    owner_kind: str
    table: str
    id_column: str
    sha_column: str
    states: tuple[str, ...]
    context_columns: tuple[tuple[str, str], ...]
    blocker_code: str


_RECOVERY_SOURCES = (
    _RecoverySource(
        family="REVIEW_BRIDGE",
        owner_kind="review.submission",
        table="review_submissions",
        id_column="submission_id",
        sha_column="request_hash",
        states=("BLOCKED", "PREPARED"),
        context_columns=(("batch_id", "batch_id"), ("campaign_id", "campaign_id")),
        blocker_code="unresolved-review-submission",
    ),
    _RecoverySource(
        family="BATCH_EVENT",
        owner_kind="review.batch_event",
        table="batch_events",
        id_column="batch_event_id",
        sha_column="payload_sha256",
        states=("BLOCKED", "PREPARED"),
        context_columns=(("batch_id", "batch_id"),),
        blocker_code="unresolved-batch-event",
    ),
    _RecoverySource(
        family="DEFERRAL_EVIDENCE",
        owner_kind="review.deferral_evidence",
        table="deferral_evidence_events",
        id_column="evidence_event_id",
        sha_column="payload_sha256",
        states=("BLOCKED", "PREPARED"),
        context_columns=(("deferral_id", "deferral_id"),),
        blocker_code="unresolved-deferral-evidence",
    ),
    _RecoverySource(
        family="LEGACY_IMPORT",
        owner_kind="review.legacy_import",
        table="legacy_import_runs",
        id_column="import_run_id",
        sha_column="request_hash",
        states=("BLOCKED", "PREPARED"),
        context_columns=(("result_id", "result_id"),),
        blocker_code="unresolved-legacy-import",
    ),
)
_SOURCE_BY_KIND = {source.owner_kind: source for source in _RECOVERY_SOURCES}


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise RecoveryEvidenceQueryError("%s is invalid" % label)
    return value


def _stored_text(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > _MAX_STORED_TEXT_BYTES
    ):
        raise RecoveryEvidenceQueryError("stored %s is invalid" % label)
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise RecoveryEvidenceQueryError("stored %s is invalid" % label)
    return value


def _stored_hash(value: Any) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise RecoveryEvidenceQueryError("stored recovery owner hash is invalid")
    return value


def not_activated_recovery_projection() -> dict[str, Any]:
    return {
        "activation_state": "NOT_ACTIVATED",
        "advisory_only": True,
        "coverage": "CONTROL_ROOT_ABSENT",
        "entries": [],
        "ledger_schema_version": None,
        "read_only": True,
        "returned": 0,
        "schema_version": 1,
        "truncated": False,
        "view": "recovery",
    }


class RecoveryEvidenceQuery:
    """List M3 operation-owner evidence without proposing a recovery action."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if connection.in_transaction:
            raise RecoveryEvidenceQueryError(
                "recovery query requires transaction ownership"
            )
        try:
            m3_schema.verify_v3_schema(connection)
        except (m3_schema.M3SchemaError, sqlite3.Error) as exc:
            raise RecoveryEvidenceQueryError(
                "exact curation ledger v3 is required"
            ) from exc
        self.connection = connection

    def _rows(
        self,
        source: _RecoverySource,
        *,
        owner_id: str | None,
        limit: int,
    ) -> tuple[sqlite3.Row, ...]:
        columns = (
            source.id_column,
            "state",
            source.sha_column,
            *(column for _label, column in source.context_columns),
        )
        placeholders = ", ".join("?" for _state in source.states)
        from_where = (
            " FROM "
            + source.table
            + " WHERE state IN ("
            + placeholders
            + ")"
        )
        parameters: list[Any] = list(source.states)
        if owner_id is not None:
            from_where += " AND " + source.id_column + " = ?"
            parameters.append(owner_id)
        from_where += " ORDER BY " + source.id_column + " LIMIT ?"
        parameters.append(limit)
        aliases = tuple("column_bytes_%d" % index for index in range(len(columns)))
        preflight = (
            "SELECT COUNT(*), "
            + ", ".join("MAX(%s)" % alias for alias in aliases)
            + " FROM (SELECT "
            + ", ".join(
                "octet_length(%s) AS %s" % (column, alias)
                for column, alias in zip(columns, aliases)
            )
            + from_where
            + ")"
        )
        try:
            sizes = self.connection.execute(
                preflight,
                tuple(parameters),
            ).fetchone()
        except sqlite3.Error as exc:
            raise RecoveryEvidenceQueryError(
                "recovery owner byte preflight failed"
            ) from exc
        if sizes is None or type(sizes[0]) is not int:
            raise RecoveryEvidenceQueryError(
                "recovery owner byte preflight is invalid"
            )
        for index, size in enumerate(sizes[1:]):
            required = index < 3
            maximum = 64 if index == 2 else _MAX_STORED_TEXT_BYTES
            if (
                (required and size is None and sizes[0] > 0)
                or (
                    size is not None
                    and (type(size) is not int or size < 0 or size > maximum)
                )
            ):
                raise RecoveryEvidenceQueryError(
                    "stored recovery owner exceeds byte budget"
                )
        statement = "SELECT " + ", ".join(columns) + from_where
        return tuple(self.connection.execute(statement, tuple(parameters)).fetchall())

    @staticmethod
    def _entry(source: _RecoverySource, row: sqlite3.Row) -> dict[str, Any]:
        owner_id = _stored_text(row[0], "recovery owner id")
        state = _stored_text(row[1], "recovery state")
        if state not in source.states:
            raise RecoveryEvidenceQueryError("stored recovery state is invalid")
        context = {}
        for index, (label, _column) in enumerate(source.context_columns, start=3):
            if row[index] is not None:
                context[label] = _stored_text(row[index], "recovery context")
        return {
            "blockers": sorted(
                ("m3-reviewer-gate-no-go", source.blocker_code)
            ),
            "classification": (
                "BLOCKER_EVIDENCE" if state == "BLOCKED" else "NONTERMINAL_EVIDENCE"
            ),
            "context": context,
            "family": source.family,
            "owner": {
                "id": owner_id,
                "kind": source.owner_kind,
                "sha256": _stored_hash(row[2]),
            },
            "state": state,
        }

    def view(
        self,
        *,
        max_items: int,
        reference: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if type(max_items) is not int or not 1 <= max_items <= MAX_RECOVERY_ITEMS:
            raise RecoveryEvidenceQueryError("max items is invalid")
        sources = _RECOVERY_SOURCES
        owner_id = None
        if reference is not None:
            if type(reference) is not dict or set(reference) != {"id", "kind"}:
                raise RecoveryEvidenceQueryError("recovery reference is invalid")
            kind = _identifier(reference["kind"], "recovery owner kind")
            owner_id = _identifier(reference["id"], "recovery owner id")
            try:
                sources = (_SOURCE_BY_KIND[kind],)
            except KeyError as exc:
                raise RecoveryEvidenceQueryError(
                    "recovery owner kind is unknown"
                ) from exc

        entries = []
        truncated = False
        for source in sources:
            remaining = max_items - len(entries)
            rows = self._rows(
                source,
                owner_id=owner_id,
                limit=max(1, remaining + 1),
            )
            if len(rows) > remaining:
                truncated = True
            entries.extend(
                self._entry(source, row) for row in rows[:remaining]
            )
            if truncated and len(entries) >= max_items:
                break
        return {
            "activation_state": "ACTIVATED",
            "advisory_only": True,
            "coverage": "M3_OPERATION_OWNERS",
            "entries": entries,
            "ledger_schema_version": 3,
            "read_only": True,
            "returned": len(entries),
            "schema_version": 1,
            "truncated": truncated,
            "view": "recovery",
        }


__all__ = [
    "MAX_RECOVERY_ITEMS",
    "RecoveryEvidenceQuery",
    "RecoveryEvidenceQueryError",
    "not_activated_recovery_projection",
]
