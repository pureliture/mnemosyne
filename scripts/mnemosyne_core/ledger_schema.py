"""Exact cumulative SQLite schema for Mnemosyne document-curation M2.

The M1 control schema remains the immutable version-1 base.  This module owns
only the version-2 delta and verifies the complete v1+v2 object set before a
writer may use campaign or review state.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable, Tuple

from . import control
from .canonical_json import canonical_json_bytes, sha256_bytes


LEDGER_SCHEMA_VERSION = 2

LEDGER_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE inventory_runs (
        run_id TEXT PRIMARY KEY,
        run_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(run_sha256) = 64 AND run_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        package_path TEXT NOT NULL UNIQUE CHECK (length(package_path) > 0),
        manifest_sha256 TEXT NOT NULL CHECK (
            length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        policy_raw_hash TEXT NOT NULL CHECK (
            length(policy_raw_hash) = 64
            AND policy_raw_hash NOT GLOB '*[^0-9a-f]*'
        ),
        policy_generation INTEGER NOT NULL CHECK (policy_generation > 0),
        policy_full_hash TEXT NOT NULL CHECK (
            length(policy_full_hash) = 64 AND policy_full_hash NOT GLOB '*[^0-9a-f]*'
        ),
        policy_writer_control_hash TEXT NOT NULL CHECK (
            length(policy_writer_control_hash) = 64
            AND policy_writer_control_hash NOT GLOB '*[^0-9a-f]*'
        ),
        policy_foundation_hash TEXT NOT NULL CHECK (
            length(policy_foundation_hash) = 64
            AND policy_foundation_hash NOT GLOB '*[^0-9a-f]*'
        ),
        policy_source_kind TEXT NOT NULL CHECK (
            policy_source_kind IN ('INITIAL', 'EDIT', 'RECONCILE', 'CUTOVER')
        ),
        policy_source_run_id TEXT NOT NULL,
        policy_guard_epoch INTEGER NOT NULL CHECK (policy_guard_epoch >= 0),
        parent_run_id TEXT REFERENCES inventory_runs(run_id),
        state TEXT NOT NULL CHECK (state = 'OPENED'),
        CHECK (parent_run_id IS NULL OR parent_run_id <> run_id)
    )
    """,
    """
    CREATE TABLE campaigns (
        campaign_id TEXT PRIMARY KEY,
        root_run_id TEXT NOT NULL UNIQUE REFERENCES inventory_runs(run_id),
        root_run_sha256 TEXT NOT NULL CHECK (
            length(root_run_sha256) = 64
            AND root_run_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        status TEXT NOT NULL CHECK (status IN ('OPENING', 'READY', 'BLOCKED')),
        current_snapshot_id TEXT,
        current_snapshot_sha256 TEXT CHECK (
            current_snapshot_sha256 IS NULL OR (
                length(current_snapshot_sha256) = 64
                AND current_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        review_revision INTEGER NOT NULL CHECK (review_revision >= 0),
        active_integration_id TEXT UNIQUE,
        opened_by TEXT NOT NULL CHECK (
            length(trim(opened_by)) > 0 AND opened_by = trim(opened_by)
        ),
        payload_json BLOB NOT NULL,
        campaign_path TEXT NOT NULL UNIQUE CHECK (length(campaign_path) > 0),
        campaign_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(campaign_sha256) = 64
            AND campaign_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        CHECK (
            (status = 'OPENING' AND current_snapshot_id IS NULL
             AND current_snapshot_sha256 IS NULL AND review_revision = 0)
            OR
            (status = 'READY' AND current_snapshot_id IS NOT NULL
             AND current_snapshot_sha256 IS NOT NULL AND review_revision > 0
             AND active_integration_id IS NULL)
            OR status = 'BLOCKED'
        ),
        CHECK (
            (current_snapshot_id IS NULL AND current_snapshot_sha256 IS NULL)
            OR (current_snapshot_id IS NOT NULL AND current_snapshot_sha256 IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE campaign_run_bindings (
        binding_id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
        run_id TEXT NOT NULL UNIQUE REFERENCES inventory_runs(run_id),
        run_sha256 TEXT NOT NULL CHECK (
            length(run_sha256) = 64 AND run_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        binding_kind TEXT NOT NULL CHECK (binding_kind IN ('ROOT', 'DERIVED')),
        parent_binding_id TEXT REFERENCES campaign_run_bindings(binding_id),
        authorization_id TEXT,
        expected_snapshot_id TEXT,
        expected_snapshot_sha256 TEXT CHECK (
            expected_snapshot_sha256 IS NULL OR (
                length(expected_snapshot_sha256) = 64
                AND expected_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        expected_review_revision INTEGER NOT NULL CHECK (expected_review_revision >= 0),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        request_json BLOB NOT NULL,
        request_sha256 TEXT NOT NULL CHECK (
            length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        integration_plan_json BLOB NOT NULL,
        integration_plan_sha256 TEXT NOT NULL CHECK (
            length(integration_plan_sha256) = 64
            AND integration_plan_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        final_path TEXT NOT NULL UNIQUE CHECK (length(final_path) > 0),
        final_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(final_sha256) = 64 AND final_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'PUBLISHED', 'BLOCKED')),
        CHECK (
            (binding_kind = 'ROOT' AND parent_binding_id IS NULL
             AND authorization_id IS NULL AND expected_snapshot_id IS NULL
             AND expected_snapshot_sha256 IS NULL AND expected_review_revision = 0)
            OR
            (binding_kind = 'DERIVED' AND parent_binding_id IS NOT NULL
             AND authorization_id IS NOT NULL)
        ),
        CHECK (
            (expected_snapshot_id IS NULL AND expected_snapshot_sha256 IS NULL)
            OR (expected_snapshot_id IS NOT NULL AND expected_snapshot_sha256 IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE run_integrations (
        integration_id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
        binding_id TEXT NOT NULL UNIQUE REFERENCES campaign_run_bindings(binding_id),
        expected_snapshot_id TEXT,
        expected_snapshot_sha256 TEXT CHECK (
            expected_snapshot_sha256 IS NULL OR (
                length(expected_snapshot_sha256) = 64
                AND expected_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        expected_review_revision INTEGER NOT NULL CHECK (expected_review_revision >= 0),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        imported_payload_sha256 TEXT NOT NULL CHECK (
            length(imported_payload_sha256) = 64
            AND imported_payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        submission_id TEXT NOT NULL UNIQUE,
        snapshot_id TEXT NOT NULL UNIQUE,
        snapshot_path TEXT NOT NULL UNIQUE CHECK (length(snapshot_path) > 0),
        snapshot_payload_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(snapshot_payload_sha256) = 64
            AND snapshot_payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        snapshot_final_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(snapshot_final_sha256) = 64
            AND snapshot_final_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'INTEGRATED', 'BLOCKED')),
        CHECK (
            (expected_snapshot_id IS NULL AND expected_snapshot_sha256 IS NULL)
            OR (expected_snapshot_id IS NOT NULL AND expected_snapshot_sha256 IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE items (
        item_id TEXT PRIMARY KEY CHECK (
            length(item_id) = 36
            AND substr(item_id, 9, 1) = '-'
            AND substr(item_id, 14, 1) = '-'
            AND substr(item_id, 15, 1) = '4'
            AND substr(item_id, 19, 1) = '-'
            AND substr(item_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(item_id, 24, 1) = '-'
            AND length(replace(item_id, '-', '')) = 32
            AND replace(item_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        ),
        first_seen_run_id TEXT NOT NULL REFERENCES inventory_runs(run_id),
        state TEXT NOT NULL CHECK (state IN ('TENTATIVE', 'REVIEW_READY', 'BLOCKED'))
    )
    """,
    """
    CREATE TABLE observations (
        observation_key TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES inventory_runs(run_id),
        observation_id TEXT NOT NULL,
        path TEXT NOT NULL CHECK (length(path) > 0),
        kind TEXT NOT NULL,
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        UNIQUE (run_id, observation_id)
    )
    """,
    """
    CREATE TABLE observation_item_links (
        link_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        observation_id TEXT NOT NULL,
        item_id TEXT NOT NULL REFERENCES items(item_id),
        link_generation INTEGER NOT NULL CHECK (link_generation > 0),
        is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
        provenance_json BLOB NOT NULL,
        provenance_sha256 TEXT NOT NULL CHECK (
            length(provenance_sha256) = 64
            AND provenance_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        FOREIGN KEY (run_id, observation_id)
            REFERENCES observations(run_id, observation_id),
        UNIQUE (run_id, observation_id, link_generation)
    )
    """,
    """
    CREATE TABLE classification_candidates (
        candidate_id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL REFERENCES items(item_id),
        axis TEXT NOT NULL CHECK (axis IN ('workstream', 'role', 'authority', 'lifecycle')),
        candidate_value TEXT,
        provider_id TEXT NOT NULL,
        confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high', 'unknown')),
        uncertainty TEXT,
        context_freshness TEXT NOT NULL CHECK (
            context_freshness IN ('fresh', 'stale', 'unknown')
        ),
        evidence_json BLOB NOT NULL,
        evidence_sha256 TEXT NOT NULL CHECK (
            length(evidence_sha256) = 64 AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state = 'TENTATIVE')
    )
    """,
    """
    CREATE TABLE placement_target_candidates (
        target_candidate_id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL REFERENCES items(item_id),
        snapshot_id TEXT NOT NULL,
        registry_rule_id TEXT,
        registry_rule_sha256 TEXT CHECK (
            registry_rule_sha256 IS NULL OR (
                length(registry_rule_sha256) = 64
                AND registry_rule_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        target_path TEXT,
        rename_delta_json BLOB NOT NULL,
        uncertainty TEXT,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state = 'TENTATIVE')
    )
    """,
    """
    CREATE TABLE review_batches (
        batch_id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
        request_hash TEXT NOT NULL CHECK (
            length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'
        ),
        status TEXT NOT NULL CHECK (
            status IN ('OPEN', 'CLAIMED', 'CLOSED_REVIEW', 'ABANDONED', 'APPLIED',
                       'CLOSED_WITH_EXCEPTIONS', 'CLOSED_NO_EFFECT', 'BLOCKED')
        ),
        current_snapshot_id TEXT,
        current_snapshot_sha256 TEXT CHECK (
            current_snapshot_sha256 IS NULL OR (
                length(current_snapshot_sha256) = 64
                AND current_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        review_revision INTEGER NOT NULL CHECK (review_revision >= 0),
        execution_generation INTEGER NOT NULL CHECK (execution_generation >= 0),
        CHECK (
            (current_snapshot_id IS NULL AND current_snapshot_sha256 IS NULL)
            OR (current_snapshot_id IS NOT NULL AND current_snapshot_sha256 IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE batch_memberships (
        membership_id TEXT PRIMARY KEY,
        batch_id TEXT NOT NULL REFERENCES review_batches(batch_id),
        unit_id TEXT NOT NULL,
        item_id TEXT NOT NULL REFERENCES items(item_id),
        path TEXT NOT NULL CHECK (
            length(path) > 0 AND path NOT LIKE '/%' AND path NOT LIKE '%/'
            AND path NOT LIKE '%//%'
        ),
        status TEXT NOT NULL CHECK (status IN ('OPEN', 'CLAIMED', 'RELEASED')),
        UNIQUE (batch_id, unit_id, item_id, path)
    )
    """,
    """
    CREATE TABLE review_submissions (
        submission_id TEXT PRIMARY KEY,
        lineage_kind TEXT NOT NULL CHECK (lineage_kind IN ('CAMPAIGN', 'BATCH')),
        campaign_id TEXT REFERENCES campaigns(campaign_id),
        batch_id TEXT REFERENCES review_batches(batch_id),
        request_hash TEXT NOT NULL CHECK (
            length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'
        ),
        snapshot_id TEXT NOT NULL UNIQUE,
        base_snapshot_id TEXT,
        base_snapshot_sha256 TEXT CHECK (
            base_snapshot_sha256 IS NULL OR (
                length(base_snapshot_sha256) = 64
                AND base_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        payload_json BLOB NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        final_path TEXT NOT NULL UNIQUE CHECK (length(final_path) > 0),
        final_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(final_sha256) = 64 AND final_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'COMMITTED', 'BLOCKED', 'CANCELLED')),
        CHECK (
            (lineage_kind = 'CAMPAIGN' AND campaign_id IS NOT NULL AND batch_id IS NULL)
            OR (lineage_kind = 'BATCH' AND campaign_id IS NOT NULL AND batch_id IS NOT NULL)
        ),
        CHECK (
            (base_snapshot_id IS NULL AND base_snapshot_sha256 IS NULL)
            OR (base_snapshot_id IS NOT NULL AND base_snapshot_sha256 IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE review_snapshots (
        snapshot_id TEXT PRIMARY KEY,
        lineage_kind TEXT NOT NULL CHECK (lineage_kind IN ('CAMPAIGN', 'BATCH')),
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
        batch_id TEXT REFERENCES review_batches(batch_id),
        version INTEGER NOT NULL CHECK (version > 0),
        parent_snapshot_id TEXT,
        parent_snapshot_sha256 TEXT CHECK (
            parent_snapshot_sha256 IS NULL OR (
                length(parent_snapshot_sha256) = 64
                AND parent_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        payload_sha256 TEXT NOT NULL CHECK (
            length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        final_path TEXT NOT NULL UNIQUE CHECK (length(final_path) > 0),
        final_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(final_sha256) = 64 AND final_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'PUBLISHED', 'BLOCKED')),
        structural_approval_ready INTEGER NOT NULL CHECK (structural_approval_ready IN (0, 1)),
        CHECK (
            (lineage_kind = 'CAMPAIGN' AND batch_id IS NULL)
            OR (lineage_kind = 'BATCH' AND batch_id IS NOT NULL)
        ),
        CHECK (
            (parent_snapshot_id IS NULL AND parent_snapshot_sha256 IS NULL)
            OR (parent_snapshot_id IS NOT NULL AND parent_snapshot_sha256 IS NOT NULL)
        )
    )
    """,
)

LEDGER_SCHEMA_INDEX_STATEMENTS = (
    """
    CREATE UNIQUE INDEX campaign_one_prepared_integration
    ON run_integrations (campaign_id)
    WHERE state = 'PREPARED'
    """,
    """
    CREATE UNIQUE INDEX observation_one_current_item_link
    ON observation_item_links (run_id, observation_id)
    WHERE is_current = 1
    """,
    """
    CREATE UNIQUE INDEX batch_one_unresolved_request
    ON review_batches (campaign_id, request_hash)
    WHERE status IN ('OPEN', 'CLAIMED')
    """,
    """
    CREATE UNIQUE INDEX membership_one_active_item
    ON batch_memberships (item_id)
    WHERE status IN ('OPEN', 'CLAIMED')
    """,
    """
    CREATE UNIQUE INDEX campaign_one_prepared_submission
    ON review_submissions (campaign_id)
    WHERE lineage_kind = 'CAMPAIGN' AND state = 'PREPARED'
    """,
    """
    CREATE UNIQUE INDEX batch_one_prepared_submission
    ON review_submissions (batch_id)
    WHERE lineage_kind = 'BATCH' AND state = 'PREPARED'
    """,
    """
    CREATE UNIQUE INDEX campaign_snapshot_version
    ON review_snapshots (campaign_id, version)
    WHERE lineage_kind = 'CAMPAIGN'
    """,
    """
    CREATE UNIQUE INDEX batch_snapshot_version
    ON review_snapshots (batch_id, version)
    WHERE lineage_kind = 'BATCH'
    """,
)

LEDGER_SCHEMA_TRIGGER_STATEMENTS = (
    """
    CREATE TRIGGER batch_membership_no_path_overlap_insert
    BEFORE INSERT ON batch_memberships
    WHEN NEW.status IN ('OPEN', 'CLAIMED') AND EXISTS (
        SELECT 1 FROM batch_memberships AS existing
        WHERE existing.status IN ('OPEN', 'CLAIMED')
          AND existing.batch_id <> NEW.batch_id
          AND (
              existing.path = NEW.path
              OR substr(existing.path, 1, length(NEW.path) + 1) = NEW.path || '/'
              OR substr(NEW.path, 1, length(existing.path) + 1) = existing.path || '/'
          )
    )
    BEGIN SELECT RAISE(ABORT, 'active batch membership path overlap'); END
    """,
    """
    CREATE TRIGGER batch_membership_no_path_overlap_update
    BEFORE UPDATE OF path, status ON batch_memberships
    WHEN NEW.status IN ('OPEN', 'CLAIMED') AND EXISTS (
        SELECT 1 FROM batch_memberships AS existing
        WHERE existing.membership_id <> OLD.membership_id
          AND existing.status IN ('OPEN', 'CLAIMED')
          AND existing.batch_id <> NEW.batch_id
          AND (
              existing.path = NEW.path
              OR substr(existing.path, 1, length(NEW.path) + 1) = NEW.path || '/'
              OR substr(NEW.path, 1, length(existing.path) + 1) = existing.path || '/'
          )
    )
    BEGIN SELECT RAISE(ABORT, 'active batch membership path overlap'); END
    """,
)


def _object_names(statements: Iterable[str], marker: str) -> Tuple[str, ...]:
    return tuple(
        statement.split(marker, 1)[1].split()[0].strip()
        for statement in statements
    )


LEDGER_SCHEMA_TABLES = _object_names(LEDGER_SCHEMA_STATEMENTS, "CREATE TABLE ")
LEDGER_SCHEMA_INDEXES = _object_names(
    LEDGER_SCHEMA_INDEX_STATEMENTS,
    "CREATE UNIQUE INDEX ",
)
LEDGER_SCHEMA_TRIGGERS = _object_names(
    LEDGER_SCHEMA_TRIGGER_STATEMENTS,
    "CREATE TRIGGER ",
)
LEDGER_SCHEMA_SHA256 = sha256_bytes(
    canonical_json_bytes(
        {
            "base_schema_sha256": control.CONTROL_SCHEMA_SHA256,
            "schema_version": LEDGER_SCHEMA_VERSION,
            "statements": [
                " ".join(statement.split())
                for statement in (
                    LEDGER_SCHEMA_STATEMENTS
                    + LEDGER_SCHEMA_INDEX_STATEMENTS
                    + LEDGER_SCHEMA_TRIGGER_STATEMENTS
                )
            ],
        }
    )
)


class LedgerSchemaError(Exception):
    """The ledger schema or migration binding is not exact and usable."""


def _normalized_sql(value: str) -> str:
    return " ".join(value.strip().rstrip(";").split())


def _require_no_transaction(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        raise LedgerSchemaError("schema migration requires transaction ownership")


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
        raise LedgerSchemaError("ledger %s set is invalid" % object_type)
    for name, statement in zip(expected_names, expected_statements):
        if _normalized_sql(observed[name]) != _normalized_sql(statement):
            raise LedgerSchemaError("ledger %s definition is invalid: %s" % (object_type, name))


def verify_v2_schema(connection: sqlite3.Connection) -> None:
    """Fail closed unless every v1+v2 object and migration binding is exact."""
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise LedgerSchemaError("SQLite foreign keys are disabled")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise LedgerSchemaError("SQLite foreign key check failed")
    integrity = [
        tuple(row) for row in connection.execute("PRAGMA integrity_check").fetchall()
    ]
    if integrity != [("ok",)]:
        raise LedgerSchemaError("SQLite integrity check failed")

    _verify_object_family(
        connection,
        object_type="table",
        expected_names=control.CONTROL_SCHEMA_TABLES + LEDGER_SCHEMA_TABLES,
        expected_statements=control.CONTROL_SCHEMA_STATEMENTS + LEDGER_SCHEMA_STATEMENTS,
    )
    _verify_object_family(
        connection,
        object_type="index",
        expected_names=control.CONTROL_SCHEMA_INDEXES + LEDGER_SCHEMA_INDEXES,
        expected_statements=(
            control.CONTROL_SCHEMA_INDEX_STATEMENTS + LEDGER_SCHEMA_INDEX_STATEMENTS
        ),
    )
    _verify_object_family(
        connection,
        object_type="trigger",
        expected_names=control.CONTROL_SCHEMA_TRIGGERS + LEDGER_SCHEMA_TRIGGERS,
        expected_statements=(
            control.CONTROL_SCHEMA_TRIGGER_STATEMENTS
            + LEDGER_SCHEMA_TRIGGER_STATEMENTS
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
        (LEDGER_SCHEMA_VERSION, LEDGER_SCHEMA_SHA256),
    ]:
        raise LedgerSchemaError("ledger schema migration binding is invalid")


def ensure_v2_schema(
    connection: sqlite3.Connection,
    *,
    migration_id: str,
) -> None:
    """Apply the v2 delta atomically or verify the exact prior application.

    The caller owns the process lock order: placement-policy shared lock, then
    ledger exclusive lock.  This function owns only its ``BEGIN IMMEDIATE``.
    """
    if (
        not isinstance(migration_id, str)
        or not migration_id.strip()
        or migration_id != migration_id.strip()
        or any(ord(character) < 0x20 for character in migration_id)
    ):
        raise LedgerSchemaError("migration_id is required")
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
    if len(rows) == 2:
        if rows != [
            (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256, rows[0][2]),
            (LEDGER_SCHEMA_VERSION, LEDGER_SCHEMA_SHA256, migration_id),
        ]:
            raise LedgerSchemaError("ledger schema migration binding is invalid")
        verify_v2_schema(connection)
        return
    if len(rows) != 1 or rows[0][:2] != (
        control.CONTROL_SCHEMA_VERSION,
        control.CONTROL_SCHEMA_SHA256,
    ):
        raise LedgerSchemaError("version-1 schema binding is invalid")

    try:
        control._verify_schema(connection)
    except control.ControlBootstrapError as exc:
        raise LedgerSchemaError(str(exc)) from exc
    integrity = [
        tuple(row) for row in connection.execute("PRAGMA integrity_check").fetchall()
    ]
    if integrity != [("ok",)]:
        raise LedgerSchemaError("SQLite integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise LedgerSchemaError("SQLite foreign key check failed")

    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in LEDGER_SCHEMA_STATEMENTS:
            connection.execute(statement)
        for statement in LEDGER_SCHEMA_INDEX_STATEMENTS:
            connection.execute(statement)
        for statement in LEDGER_SCHEMA_TRIGGER_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations "
            "(version, schema_sha256, applied_by_bootstrap_id) VALUES (?, ?, ?)",
            (LEDGER_SCHEMA_VERSION, LEDGER_SCHEMA_SHA256, migration_id),
        )
        verify_v2_schema(connection)
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise LedgerSchemaError("version-2 schema migration failed") from exc
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


__all__ = [
    "LEDGER_SCHEMA_INDEXES",
    "LEDGER_SCHEMA_INDEX_STATEMENTS",
    "LEDGER_SCHEMA_SHA256",
    "LEDGER_SCHEMA_STATEMENTS",
    "LEDGER_SCHEMA_TABLES",
    "LEDGER_SCHEMA_TRIGGER_STATEMENTS",
    "LEDGER_SCHEMA_TRIGGERS",
    "LEDGER_SCHEMA_VERSION",
    "LedgerSchemaError",
    "ensure_v2_schema",
    "verify_v2_schema",
]
