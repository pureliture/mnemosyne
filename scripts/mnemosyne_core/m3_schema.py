"""Exact additive SQLite schema delta for Mnemosyne document-curation M3.

Version 3 is deliberately cumulative: the immutable control v1 and ledger v2
schemas must both be exact before this module creates the M3 decision,
deferral, relation, batch-event, projection, and legacy-import objects.  It
never performs a direct v1-to-v3 upgrade.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable, Tuple

from . import control, ledger_schema
from .canonical_json import canonical_json_bytes, sha256_bytes


M3_SCHEMA_VERSION = 3
M3_MIGRATION_ID = "document-curation-m3-v3"


M3_SCHEMA_ALTER_STATEMENTS = (
    """
    ALTER TABLE review_submissions
    ADD COLUMN expected_lineage_status TEXT CHECK (
        expected_lineage_status IS NULL
        OR expected_lineage_status IN ('OPENING', 'READY', 'OPEN')
    )
    """,
    """
    ALTER TABLE review_submissions
    ADD COLUMN expected_review_revision INTEGER CHECK (
        expected_review_revision IS NULL OR expected_review_revision >= 0
    )
    """,
    """
    ALTER TABLE review_submissions
    ADD COLUMN expected_execution_generation INTEGER CHECK (
        expected_execution_generation IS NULL OR expected_execution_generation >= 0
    )
    """,
)


_V2_REVIEW_SUBMISSIONS_TAIL = (
    "        state TEXT NOT NULL CHECK (state IN "
    "('PREPARED', 'COMMITTED', 'BLOCKED', 'CANCELLED')),\n"
    "        CHECK (\n"
)
_V3_REVIEW_SUBMISSIONS_TAIL = (
    """        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'COMMITTED',
            'BLOCKED', 'CANCELLED')),
        expected_lineage_status TEXT CHECK (
            expected_lineage_status IS NULL
            OR expected_lineage_status IN ('OPENING', 'READY', 'OPEN')
        ),
        expected_review_revision INTEGER CHECK (
            expected_review_revision IS NULL OR expected_review_revision >= 0
        ),
        expected_execution_generation INTEGER CHECK (
            expected_execution_generation IS NULL OR expected_execution_generation >= 0
        ),
        CHECK (
"""
)


def _ledger_v3_table_statements() -> Tuple[str, ...]:
    statements = []
    replaced = False
    for name, statement in zip(
        ledger_schema.LEDGER_SCHEMA_TABLES,
        ledger_schema.LEDGER_SCHEMA_STATEMENTS,
    ):
        if name == "review_submissions":
            if statement.count(_V2_REVIEW_SUBMISSIONS_TAIL) != 1:
                raise RuntimeError("version-2 review_submissions statement changed")
            statement = statement.replace(
                _V2_REVIEW_SUBMISSIONS_TAIL,
                _V3_REVIEW_SUBMISSIONS_TAIL,
            )
            replaced = True
        statements.append(statement)
    if not replaced:
        raise RuntimeError("version-2 review_submissions table is missing")
    return tuple(statements)


LEDGER_V3_TABLE_STATEMENTS = _ledger_v3_table_statements()


M3_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE decision_events (
        decision_event_id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
        batch_id TEXT REFERENCES review_batches(batch_id),
        item_id TEXT NOT NULL REFERENCES items(item_id),
        snapshot_id TEXT NOT NULL CHECK (length(trim(snapshot_id)) > 0),
        snapshot_sha256 TEXT NOT NULL CHECK (
            length(snapshot_sha256) = 64
            AND snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        review_revision INTEGER NOT NULL CHECK (review_revision > 0),
        projection_generation INTEGER NOT NULL CHECK (projection_generation > 0),
        actor TEXT NOT NULL CHECK (
            length(trim(actor)) > 0 AND actor = trim(actor)
        ),
        action TEXT NOT NULL CHECK (
            action IN (
                'KEEP', 'LINK', 'DEFER', 'EXCLUDE', 'CORRECTION',
                'PROPOSAL_REJECT', 'REOPEN'
            )
        ),
        current_decision_id TEXT,
        reason TEXT CHECK (
            reason IS NULL OR (length(trim(reason)) > 0 AND reason = trim(reason))
        ),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        occurred_at TEXT NOT NULL CHECK (
            length(trim(occurred_at)) > 0 AND occurred_at = trim(occurred_at)
        )
    )
    """,
    """
    CREATE TABLE classification_decisions (
        classification_decision_id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL REFERENCES items(item_id),
        axis TEXT NOT NULL CHECK (
            axis IN ('workstream', 'role', 'authority', 'lifecycle')
        ),
        decision_value TEXT NOT NULL CHECK (
            length(trim(decision_value)) > 0 AND decision_value = trim(decision_value)
        ),
        source_decision_event_id TEXT NOT NULL
            REFERENCES decision_events(decision_event_id),
        decision_generation INTEGER NOT NULL CHECK (decision_generation > 0),
        evidence_json BLOB NOT NULL,
        evidence_sha256 TEXT NOT NULL CHECK (
            length(evidence_sha256) = 64
            AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN ('CURRENT', 'SUPERSEDED')),
        UNIQUE (item_id, axis, decision_generation)
    )
    """,
    """
    CREATE TABLE workstream_relations (
        workstream_relation_id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL REFERENCES items(item_id),
        workstream_id TEXT NOT NULL CHECK (
            length(trim(workstream_id)) > 0 AND workstream_id = trim(workstream_id)
        ),
        relation_kind TEXT NOT NULL CHECK (
            relation_kind IN ('PRIMARY', 'RELATED', 'SHARED')
        ),
        source_decision_event_id TEXT NOT NULL
            REFERENCES decision_events(decision_event_id),
        relation_generation INTEGER NOT NULL CHECK (relation_generation > 0),
        provenance_json BLOB NOT NULL,
        provenance_sha256 TEXT NOT NULL CHECK (
            length(provenance_sha256) = 64
            AND provenance_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN ('CURRENT', 'SUPERSEDED')),
        UNIQUE (item_id, workstream_id, relation_kind, relation_generation)
    )
    """,
    """
    CREATE TABLE unassigned_exceptions (
        unassigned_exception_id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL REFERENCES items(item_id),
        reason TEXT NOT NULL CHECK (
            length(trim(reason)) > 0 AND reason = trim(reason)
        ),
        assignment_condition_json BLOB NOT NULL,
        assignment_condition_sha256 TEXT NOT NULL CHECK (
            length(assignment_condition_sha256) = 64
            AND assignment_condition_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        source_decision_event_id TEXT NOT NULL
            REFERENCES decision_events(decision_event_id),
        exception_generation INTEGER NOT NULL CHECK (exception_generation > 0),
        state TEXT NOT NULL CHECK (state IN ('CURRENT', 'SUPERSEDED')),
        UNIQUE (item_id, exception_generation)
    )
    """,
    """
    CREATE TABLE document_relation_events (
        relation_event_id TEXT PRIMARY KEY,
        relation_id TEXT NOT NULL CHECK (length(trim(relation_id)) > 0),
        canonical_item_id TEXT NOT NULL REFERENCES items(item_id),
        related_item_id TEXT NOT NULL REFERENCES items(item_id),
        relation_kind TEXT NOT NULL CHECK (
            relation_kind IN ('REFERENCE', 'DERIVED', 'EVIDENCE')
        ),
        direction TEXT NOT NULL CHECK (
            direction IN ('FORWARD', 'REVERSE', 'BIDIRECTIONAL')
        ),
        action TEXT NOT NULL CHECK (
            action IN ('CONFIRM', 'CORRECT', 'SUPERSEDE')
        ),
        source_decision_event_id TEXT NOT NULL
            REFERENCES decision_events(decision_event_id),
        supersedes_event_id TEXT REFERENCES document_relation_events(relation_event_id),
        provenance_json BLOB NOT NULL,
        provenance_sha256 TEXT NOT NULL CHECK (
            length(provenance_sha256) = 64
            AND provenance_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        occurred_at TEXT NOT NULL CHECK (
            length(trim(occurred_at)) > 0 AND occurred_at = trim(occurred_at)
        ),
        CHECK (canonical_item_id <> related_item_id),
        CHECK (
            (action = 'SUPERSEDE' AND supersedes_event_id IS NOT NULL)
            OR action IN ('CONFIRM', 'CORRECT')
        )
    )
    """,
    """
    CREATE TABLE document_relations (
        relation_id TEXT PRIMARY KEY,
        canonical_item_id TEXT NOT NULL REFERENCES items(item_id),
        related_item_id TEXT NOT NULL REFERENCES items(item_id),
        relation_kind TEXT NOT NULL CHECK (
            relation_kind IN ('REFERENCE', 'DERIVED', 'EVIDENCE')
        ),
        direction TEXT NOT NULL CHECK (
            direction IN ('FORWARD', 'REVERSE', 'BIDIRECTIONAL')
        ),
        source_relation_event_id TEXT NOT NULL
            REFERENCES document_relation_events(relation_event_id),
        relation_generation INTEGER NOT NULL CHECK (relation_generation > 0),
        state TEXT NOT NULL CHECK (state IN ('CURRENT', 'SUPERSEDED')),
        CHECK (canonical_item_id <> related_item_id)
    )
    """,
    """
    CREATE TABLE deferrals (
        deferral_id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL REFERENCES items(item_id),
        source_decision_event_id TEXT NOT NULL
            REFERENCES decision_events(decision_event_id),
        version INTEGER NOT NULL CHECK (version > 0),
        reason TEXT NOT NULL CHECK (
            length(trim(reason)) > 0 AND reason = trim(reason)
        ),
        required_evidence_json BLOB NOT NULL,
        required_evidence_sha256 TEXT NOT NULL CHECK (
            length(required_evidence_sha256) = 64
            AND required_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        trigger_kind TEXT NOT NULL CHECK (
            trigger_kind IN ('DATE', 'WORKSTREAM_RESUME', 'EVIDENCE', 'MANUAL_REOPEN')
        ),
        revisit_date TEXT,
        timezone TEXT,
        trigger_workstream_id TEXT,
        captured_lifecycle TEXT,
        captured_policy_sha256 TEXT CHECK (
            captured_policy_sha256 IS NULL OR (
                length(captured_policy_sha256) = 64
                AND captured_policy_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        owner_actor TEXT CHECK (
            owner_actor IS NULL OR (
                length(trim(owner_actor)) > 0 AND owner_actor = trim(owner_actor)
            )
        ),
        state TEXT NOT NULL CHECK (
            state IN ('CURRENT', 'TRIGGERED', 'SUPERSEDED', 'CANCELLED')
        ),
        CHECK (
            (trigger_kind = 'DATE'
             AND revisit_date IS NOT NULL AND length(trim(revisit_date)) > 0
             AND timezone IS NOT NULL AND length(trim(timezone)) > 0
             AND trigger_workstream_id IS NULL AND captured_lifecycle IS NULL
             AND captured_policy_sha256 IS NULL)
            OR
            (trigger_kind = 'WORKSTREAM_RESUME'
             AND revisit_date IS NULL AND timezone IS NULL
             AND trigger_workstream_id IS NOT NULL
             AND length(trim(trigger_workstream_id)) > 0
             AND captured_lifecycle IS NOT NULL
             AND length(trim(captured_lifecycle)) > 0
             AND captured_policy_sha256 IS NOT NULL)
            OR
            (trigger_kind IN ('EVIDENCE', 'MANUAL_REOPEN')
             AND revisit_date IS NULL AND timezone IS NULL
             AND trigger_workstream_id IS NULL AND captured_lifecycle IS NULL
             AND captured_policy_sha256 IS NULL)
        )
    )
    """,
    """
    CREATE TABLE deferral_evidence_events (
        evidence_event_id TEXT PRIMARY KEY,
        deferral_id TEXT NOT NULL REFERENCES deferrals(deferral_id),
        deferral_version INTEGER NOT NULL CHECK (deferral_version > 0),
        actor TEXT NOT NULL CHECK (
            length(trim(actor)) > 0 AND actor = trim(actor)
        ),
        source_reference TEXT,
        supplied_content_sha256 TEXT CHECK (
            supplied_content_sha256 IS NULL OR (
                length(supplied_content_sha256) = 64
                AND supplied_content_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        opaque_source_id TEXT,
        actor_attestation TEXT,
        idempotency_key TEXT NOT NULL CHECK (
            length(idempotency_key) = 64
            AND idempotency_key NOT GLOB '*[^0-9a-f]*'
        ),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        final_path TEXT NOT NULL UNIQUE CHECK (length(final_path) > 0),
        final_sha256 TEXT NOT NULL CHECK (
            length(final_sha256) = 64
            AND final_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (
            state IN ('PREPARED', 'PUBLISHED', 'CONSUMED', 'BLOCKED')
        ),
        UNIQUE (deferral_id, deferral_version, idempotency_key),
        CHECK (
            (source_reference IS NOT NULL
             AND length(trim(source_reference)) > 0
             AND supplied_content_sha256 IS NOT NULL
             AND opaque_source_id IS NULL AND actor_attestation IS NULL)
            OR
            (source_reference IS NULL AND supplied_content_sha256 IS NULL
             AND opaque_source_id IS NOT NULL
             AND length(trim(opaque_source_id)) > 0
             AND actor_attestation IS NOT NULL
             AND length(trim(actor_attestation)) > 0)
        )
    )
    """,
    """
    CREATE TABLE deferral_trigger_events (
        trigger_event_id TEXT PRIMARY KEY,
        deferral_id TEXT NOT NULL REFERENCES deferrals(deferral_id),
        trigger_kind TEXT NOT NULL CHECK (
            trigger_kind IN ('DATE', 'WORKSTREAM_RESUME', 'EVIDENCE', 'MANUAL_REOPEN')
        ),
        trigger_evidence_sha256 TEXT NOT NULL CHECK (
            length(trigger_evidence_sha256) = 64
            AND trigger_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        source_evidence_event_id TEXT
            REFERENCES deferral_evidence_events(evidence_event_id),
        actor TEXT NOT NULL CHECK (
            length(trim(actor)) > 0 AND actor = trim(actor)
        ),
        policy_sha256 TEXT CHECK (
            policy_sha256 IS NULL OR (
                length(policy_sha256) = 64
                AND policy_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        occurred_at TEXT NOT NULL CHECK (
            length(trim(occurred_at)) > 0 AND occurred_at = trim(occurred_at)
        ),
        UNIQUE (deferral_id, trigger_kind, trigger_evidence_sha256),
        CHECK (
            (trigger_kind = 'EVIDENCE' AND source_evidence_event_id IS NOT NULL)
            OR (trigger_kind <> 'EVIDENCE' AND source_evidence_event_id IS NULL)
        )
    )
    """,
    """
    CREATE TABLE item_curation_projection (
        item_id TEXT PRIMARY KEY REFERENCES items(item_id),
        primary_state TEXT NOT NULL CHECK (
            primary_state IN (
                'BLOCKED', 'ERROR', 'PENDING', 'REVIEW_READY', 'CLASSIFIED',
                'DISCOVERED', 'APPLIED', 'KEEP', 'LINKED', 'DEFERRED', 'EXCLUDED'
            )
        ),
        current_decision_id TEXT REFERENCES decision_events(decision_event_id),
        current_deferral_id TEXT REFERENCES deferrals(deferral_id),
        source_run_id TEXT NOT NULL REFERENCES inventory_runs(run_id),
        source_freshness TEXT NOT NULL CHECK (
            source_freshness IN ('FRESH', 'STALE', 'UNKNOWN')
        ),
        source_event_id TEXT,
        source_execution_id TEXT,
        projection_generation INTEGER NOT NULL CHECK (projection_generation > 0),
        identity_ambiguous INTEGER NOT NULL CHECK (identity_ambiguous IN (0, 1)),
        lifecycle_frozen INTEGER NOT NULL CHECK (lifecycle_frozen IN (0, 1)),
        unassigned INTEGER NOT NULL CHECK (unassigned IN (0, 1)),
        reversal_available INTEGER NOT NULL CHECK (reversal_available IN (0, 1)),
        correction_required INTEGER NOT NULL CHECK (correction_required IN (0, 1)),
        CHECK (
            (primary_state = 'DEFERRED' AND current_deferral_id IS NOT NULL)
            OR primary_state <> 'DEFERRED'
        )
    )
    """,
    """
    CREATE TABLE batch_events (
        batch_event_id TEXT PRIMARY KEY,
        batch_id TEXT NOT NULL REFERENCES review_batches(batch_id),
        event_kind TEXT NOT NULL CHECK (
            event_kind IN (
                'CLOSE_REVIEW', 'ABANDON', 'SPLIT',
                'STRUCTURAL_FINALIZATION', 'MEMBERSHIP_RELEASE'
            )
        ),
        expected_batch_status TEXT NOT NULL CHECK (
            expected_batch_status IN ('OPEN', 'CLAIMED')
        ),
        expected_snapshot_id TEXT,
        expected_snapshot_sha256 TEXT CHECK (
            expected_snapshot_sha256 IS NULL OR (
                length(expected_snapshot_sha256) = 64
                AND expected_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        expected_review_revision INTEGER NOT NULL CHECK (expected_review_revision >= 0),
        expected_execution_generation INTEGER NOT NULL CHECK (
            expected_execution_generation >= 0
        ),
        terminal_batch_status TEXT CHECK (
            terminal_batch_status IS NULL OR terminal_batch_status IN (
                'CLOSED_REVIEW', 'ABANDONED', 'APPLIED',
                'CLOSED_WITH_EXCEPTIONS', 'CLOSED_NO_EFFECT'
            )
        ),
        child_batch_id TEXT REFERENCES review_batches(batch_id),
        child_snapshot_id TEXT,
        child_snapshot_sha256 TEXT CHECK (
            child_snapshot_sha256 IS NULL OR (
                length(child_snapshot_sha256) = 64
                AND child_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        source_execution_id TEXT,
        source_approval_id TEXT,
        result_path TEXT,
        result_sha256 TEXT CHECK (
            result_sha256 IS NULL OR (
                length(result_sha256) = 64
                AND result_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        membership_release_json BLOB NOT NULL,
        membership_release_sha256 TEXT NOT NULL CHECK (
            length(membership_release_sha256) = 64
            AND membership_release_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        final_path TEXT NOT NULL UNIQUE CHECK (length(final_path) > 0),
        final_sha256 TEXT NOT NULL CHECK (
            length(final_sha256) = 64
            AND final_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'PUBLISHED', 'BLOCKED')),
        CHECK (
            (expected_snapshot_id IS NULL AND expected_snapshot_sha256 IS NULL)
            OR (expected_snapshot_id IS NOT NULL AND expected_snapshot_sha256 IS NOT NULL)
        ),
        CHECK (
            (child_snapshot_id IS NULL AND child_snapshot_sha256 IS NULL)
            OR (child_snapshot_id IS NOT NULL AND child_snapshot_sha256 IS NOT NULL)
        ),
        CHECK (
            (result_path IS NULL AND result_sha256 IS NULL)
            OR (result_path IS NOT NULL AND result_sha256 IS NOT NULL)
        ),
        CHECK (
            (event_kind = 'STRUCTURAL_FINALIZATION'
             AND source_execution_id IS NOT NULL
             AND source_approval_id IS NOT NULL
             AND result_path IS NOT NULL
             AND terminal_batch_status IS NOT NULL)
            OR event_kind <> 'STRUCTURAL_FINALIZATION'
        )
    )
    """,
    """
    CREATE TABLE legacy_import_runs (
        import_run_id TEXT PRIMARY KEY,
        request_hash TEXT NOT NULL UNIQUE CHECK (
            length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'
        ),
        expected_head_generation INTEGER NOT NULL CHECK (expected_head_generation >= 0),
        source_manifest_json BLOB NOT NULL,
        source_manifest_sha256 TEXT NOT NULL CHECK (
            length(source_manifest_sha256) = 64
            AND source_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        actor TEXT NOT NULL CHECK (
            length(trim(actor)) > 0 AND actor = trim(actor)
        ),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        result_id TEXT NOT NULL UNIQUE CHECK (length(trim(result_id)) > 0),
        result_path TEXT NOT NULL UNIQUE CHECK (length(result_path) > 0),
        result_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(result_sha256) = 64
            AND result_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'COMPLETE', 'BLOCKED'))
    )
    """,
    """
    CREATE TABLE legacy_import_head (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        generation INTEGER NOT NULL CHECK (generation > 0),
        manifest_sha256 TEXT NOT NULL CHECK (
            length(manifest_sha256) = 64
            AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        import_run_id TEXT NOT NULL UNIQUE
            REFERENCES legacy_import_runs(import_run_id),
        result_id TEXT NOT NULL UNIQUE,
        result_sha256 TEXT NOT NULL CHECK (
            length(result_sha256) = 64
            AND result_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    )
    """,
    """
    CREATE TABLE legacy_imports (
        legacy_import_id TEXT PRIMARY KEY,
        import_run_id TEXT NOT NULL REFERENCES legacy_import_runs(import_run_id),
        result_id TEXT NOT NULL CHECK (length(trim(result_id)) > 0),
        normalized_source_path TEXT NOT NULL CHECK (
            length(normalized_source_path) > 0
            AND normalized_source_path NOT LIKE '/%'
            AND normalized_source_path NOT LIKE '%/'
            AND normalized_source_path NOT LIKE '%//%'
            AND normalized_source_path <> '.'
            AND normalized_source_path <> '..'
            AND normalized_source_path NOT LIKE '../%'
            AND normalized_source_path NOT LIKE '%/../%'
            AND normalized_source_path NOT LIKE '%/..'
        ),
        source_filename TEXT NOT NULL CHECK (
            length(source_filename) > 0
            AND source_filename NOT LIKE '%/%'
            AND source_filename NOT IN ('.', '..')
        ),
        content_sha256 TEXT NOT NULL CHECK (
            length(content_sha256) = 64
            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        parse_status TEXT NOT NULL CHECK (
            parse_status IN ('PARSED', 'UNPARSED', 'COLLISION')
        ),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        UNIQUE (normalized_source_path, content_sha256)
    )
    """,
)


M3_SCHEMA_INDEX_STATEMENTS = (
    """
    CREATE UNIQUE INDEX classification_one_current_axis
    ON classification_decisions (item_id, axis)
    WHERE state = 'CURRENT'
    """,
    """
    CREATE UNIQUE INDEX workstream_one_current_primary
    ON workstream_relations (item_id)
    WHERE state = 'CURRENT' AND relation_kind = 'PRIMARY'
    """,
    """
    CREATE UNIQUE INDEX workstream_one_current_relation
    ON workstream_relations (item_id, workstream_id, relation_kind)
    WHERE state = 'CURRENT'
    """,
    """
    CREATE UNIQUE INDEX unassigned_one_current_item
    ON unassigned_exceptions (item_id)
    WHERE state = 'CURRENT'
    """,
    """
    CREATE UNIQUE INDEX document_relation_one_current_edge
    ON document_relations (
        canonical_item_id, related_item_id, relation_kind, direction
    )
    WHERE state = 'CURRENT'
    """,
    """
    CREATE UNIQUE INDEX deferral_one_current_item
    ON deferrals (item_id)
    WHERE state = 'CURRENT'
    """,
    """
    CREATE UNIQUE INDEX deferral_evidence_one_safe_source
    ON deferral_evidence_events (
        deferral_id, deferral_version, source_reference, supplied_content_sha256
    )
    WHERE source_reference IS NOT NULL
    """,
    """
    CREATE UNIQUE INDEX deferral_one_prepared_evidence
    ON deferral_evidence_events (deferral_id)
    WHERE state = 'PREPARED'
    """,
    """
    CREATE UNIQUE INDEX batch_one_prepared_event
    ON batch_events (batch_id)
    WHERE state = 'PREPARED'
    """,
    """
    CREATE UNIQUE INDEX batch_one_structural_finalization
    ON batch_events (source_execution_id)
    WHERE event_kind = 'STRUCTURAL_FINALIZATION'
      AND source_execution_id IS NOT NULL
    """,
    """
    CREATE UNIQUE INDEX legacy_one_prepared_run
    ON legacy_import_runs (state)
    WHERE state = 'PREPARED'
    """,
)


def _append_only_trigger_statements(table: str) -> Tuple[str, str]:
    return (
        """
        CREATE TRIGGER %s_no_update
        BEFORE UPDATE ON %s
        BEGIN SELECT RAISE(ABORT, '%s is append-only'); END
        """ % (table, table, table),
        """
        CREATE TRIGGER %s_no_delete
        BEFORE DELETE ON %s
        BEGIN SELECT RAISE(ABORT, '%s is append-only'); END
        """ % (table, table, table),
    )


M3_SCHEMA_TRIGGER_STATEMENTS = tuple(
    statement
    for table_name in (
        "decision_events",
        "document_relation_events",
        "deferral_trigger_events",
        "legacy_imports",
    )
    for statement in _append_only_trigger_statements(table_name)
)


def _object_names(statements: Iterable[str], marker: str) -> Tuple[str, ...]:
    return tuple(
        statement.split(marker, 1)[1].split()[0].strip()
        for statement in statements
    )


M3_SCHEMA_TABLES = _object_names(M3_SCHEMA_STATEMENTS, "CREATE TABLE ")
M3_SCHEMA_INDEXES = _object_names(
    M3_SCHEMA_INDEX_STATEMENTS,
    "CREATE UNIQUE INDEX ",
)
M3_SCHEMA_TRIGGERS = _object_names(
    M3_SCHEMA_TRIGGER_STATEMENTS,
    "CREATE TRIGGER ",
)
M3_SCHEMA_SHA256 = sha256_bytes(
    canonical_json_bytes(
        {
            "base_schema_sha256": ledger_schema.LEDGER_SCHEMA_SHA256,
            "schema_version": M3_SCHEMA_VERSION,
            "statements": [
                " ".join(statement.split())
                for statement in (
                    M3_SCHEMA_ALTER_STATEMENTS
                    + M3_SCHEMA_STATEMENTS
                    + M3_SCHEMA_INDEX_STATEMENTS
                    + M3_SCHEMA_TRIGGER_STATEMENTS
                )
            ],
        }
    )
)


class M3SchemaError(Exception):
    """The M3 schema delta or its cumulative migration binding is invalid."""


def _normalized_sql(value: str) -> str:
    return " ".join(value.strip().rstrip(";").split())


def _require_no_transaction(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        raise M3SchemaError("schema migration requires transaction ownership")


def _require_migration_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise M3SchemaError("migration_id is required")
    return value


def _verify_object_family(
    connection: sqlite3.Connection,
    *,
    object_type: str,
    expected_names: Tuple[str, ...],
    expected_statements: Tuple[str, ...],
) -> None:
    rows = connection.execute(
        "SELECT name, sql FROM sqlite_master "
        "WHERE type = ? AND name NOT LIKE 'sqlite_%' ORDER BY name",
        (object_type,),
    ).fetchall()
    observed = {name: sql for name, sql in rows}
    if set(observed) != set(expected_names):
        raise M3SchemaError("ledger %s set is invalid" % object_type)
    for name, statement in zip(expected_names, expected_statements):
        if _normalized_sql(observed[name]) != _normalized_sql(statement):
            raise M3SchemaError(
                "ledger %s definition is invalid: %s" % (object_type, name)
            )


def verify_v3_schema(connection: sqlite3.Connection) -> None:
    """Fail closed unless the cumulative v1+v2+v3 schema is exact."""

    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise M3SchemaError("SQLite foreign keys are disabled")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise M3SchemaError("SQLite foreign key check failed")
    integrity = [
        tuple(row) for row in connection.execute("PRAGMA integrity_check").fetchall()
    ]
    if integrity != [("ok",)]:
        raise M3SchemaError("SQLite integrity check failed")

    _verify_object_family(
        connection,
        object_type="table",
        expected_names=(
            control.CONTROL_SCHEMA_TABLES
            + ledger_schema.LEDGER_SCHEMA_TABLES
            + M3_SCHEMA_TABLES
        ),
        expected_statements=(
            control.CONTROL_SCHEMA_STATEMENTS
            + LEDGER_V3_TABLE_STATEMENTS
            + M3_SCHEMA_STATEMENTS
        ),
    )
    _verify_object_family(
        connection,
        object_type="index",
        expected_names=(
            control.CONTROL_SCHEMA_INDEXES
            + ledger_schema.LEDGER_SCHEMA_INDEXES
            + M3_SCHEMA_INDEXES
        ),
        expected_statements=(
            control.CONTROL_SCHEMA_INDEX_STATEMENTS
            + ledger_schema.LEDGER_SCHEMA_INDEX_STATEMENTS
            + M3_SCHEMA_INDEX_STATEMENTS
        ),
    )
    _verify_object_family(
        connection,
        object_type="trigger",
        expected_names=(
            control.CONTROL_SCHEMA_TRIGGERS
            + ledger_schema.LEDGER_SCHEMA_TRIGGERS
            + M3_SCHEMA_TRIGGERS
        ),
        expected_statements=(
            control.CONTROL_SCHEMA_TRIGGER_STATEMENTS
            + ledger_schema.LEDGER_SCHEMA_TRIGGER_STATEMENTS
            + M3_SCHEMA_TRIGGER_STATEMENTS
        ),
    )
    migrations = [
        tuple(row)
        for row in connection.execute(
            "SELECT version, schema_sha256 FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]
    if migrations != [
        (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256),
        (ledger_schema.LEDGER_SCHEMA_VERSION, ledger_schema.LEDGER_SCHEMA_SHA256),
        (M3_SCHEMA_VERSION, M3_SCHEMA_SHA256),
    ]:
        raise M3SchemaError("ledger schema migration binding is invalid")


def ensure_v3_schema(
    connection: sqlite3.Connection,
    *,
    migration_id: str = M3_MIGRATION_ID,
) -> None:
    """Apply the exact v3 delta to an exact v2 database, or verify it."""

    migration_id = _require_migration_id(migration_id)
    _require_no_transaction(connection)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")

    rows = [
        tuple(row)
        for row in connection.execute(
            "SELECT version, schema_sha256, applied_by_bootstrap_id "
            "FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]
    if len(rows) == 3:
        if (
            rows[0][:2]
            != (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256)
            or rows[1][:2]
            != (
                ledger_schema.LEDGER_SCHEMA_VERSION,
                ledger_schema.LEDGER_SCHEMA_SHA256,
            )
            or rows[2]
            != (M3_SCHEMA_VERSION, M3_SCHEMA_SHA256, migration_id)
        ):
            raise M3SchemaError("ledger schema migration binding is invalid")
        verify_v3_schema(connection)
        return

    if len(rows) != 2 or rows[0][:2] != (
        control.CONTROL_SCHEMA_VERSION,
        control.CONTROL_SCHEMA_SHA256,
    ) or rows[1][:2] != (
        ledger_schema.LEDGER_SCHEMA_VERSION,
        ledger_schema.LEDGER_SCHEMA_SHA256,
    ):
        raise M3SchemaError("exact version-2 schema is required")
    try:
        ledger_schema.verify_v2_schema(connection)
    except ledger_schema.LedgerSchemaError as exc:
        raise M3SchemaError("exact version-2 schema is required") from exc

    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in M3_SCHEMA_ALTER_STATEMENTS:
            connection.execute(statement)
        for statement in M3_SCHEMA_STATEMENTS:
            connection.execute(statement)
        for statement in M3_SCHEMA_INDEX_STATEMENTS:
            connection.execute(statement)
        for statement in M3_SCHEMA_TRIGGER_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations "
            "(version, schema_sha256, applied_by_bootstrap_id) VALUES (?, ?, ?)",
            (M3_SCHEMA_VERSION, M3_SCHEMA_SHA256, migration_id),
        )
        verify_v3_schema(connection)
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise M3SchemaError("version-3 schema migration failed") from exc
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


__all__ = [
    "M3_MIGRATION_ID",
    "M3_SCHEMA_ALTER_STATEMENTS",
    "M3_SCHEMA_INDEXES",
    "M3_SCHEMA_INDEX_STATEMENTS",
    "M3_SCHEMA_SHA256",
    "M3_SCHEMA_STATEMENTS",
    "M3_SCHEMA_TABLES",
    "M3_SCHEMA_TRIGGER_STATEMENTS",
    "M3_SCHEMA_TRIGGERS",
    "M3_SCHEMA_VERSION",
    "M3SchemaError",
    "ensure_v3_schema",
    "verify_v3_schema",
]
