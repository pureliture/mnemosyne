import sqlite3
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import control, ledger_schema  # noqa: E402


def create_v1_connection():
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in control.CONTROL_SCHEMA_STATEMENTS:
            connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_INDEX_STATEMENTS:
            connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_TRIGGER_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations "
            "(version, schema_sha256, applied_by_bootstrap_id) VALUES (?, ?, ?)",
            (1, control.CONTROL_SCHEMA_SHA256, "bootstrap-v1"),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        connection.close()
        raise
    return connection


class LedgerSchemaV2Test(unittest.TestCase):
    def test_v2_is_an_idempotent_delta_over_the_unchanged_v1_binding(self):
        connection = create_v1_connection()
        original_v1_hash = control.CONTROL_SCHEMA_SHA256
        try:
            ledger_schema.ensure_v2_schema(
                connection,
                migration_id="document-curation-m2-v2",
            )
            ledger_schema.ensure_v2_schema(
                connection,
                migration_id="document-curation-m2-v2",
            )

            ledger_schema.verify_v2_schema(connection)
            migrations = connection.execute(
                "SELECT version, schema_sha256, applied_by_bootstrap_id "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()
        finally:
            connection.close()

        self.assertEqual(control.CONTROL_SCHEMA_SHA256, original_v1_hash)
        self.assertEqual(
            migrations,
            [
                (1, original_v1_hash, "bootstrap-v1"),
                (
                    ledger_schema.LEDGER_SCHEMA_VERSION,
                    ledger_schema.LEDGER_SCHEMA_SHA256,
                    "document-curation-m2-v2",
                ),
            ],
        )

    def test_migration_rolls_back_every_delta_object_when_one_create_is_denied(self):
        connection = create_v1_connection()

        authorizer = {"deny": True}

        def deny_campaign_table(action, argument1, _argument2, _database, _trigger):
            if (
                authorizer["deny"]
                and action == sqlite3.SQLITE_CREATE_TABLE
                and argument1 == "campaigns"
            ):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(deny_campaign_table)
        try:
            with self.assertRaises(ledger_schema.LedgerSchemaError):
                ledger_schema.ensure_v2_schema(
                    connection,
                    migration_id="document-curation-m2-v2",
                )
        finally:
            authorizer["deny"] = False
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            migrations = connection.execute(
                "SELECT version, schema_sha256 FROM schema_migrations"
            ).fetchall()
        finally:
            connection.close()

        self.assertEqual(tables, set(control.CONTROL_SCHEMA_TABLES))
        self.assertEqual(migrations, [(1, control.CONTROL_SCHEMA_SHA256)])

    def test_unknown_schema_object_is_rejected_without_applying_v2(self):
        connection = create_v1_connection()
        try:
            connection.execute("CREATE TABLE rogue_table (id TEXT PRIMARY KEY)")
            with self.assertRaisesRegex(
                ledger_schema.LedgerSchemaError,
                "control schema table set is invalid",
            ):
                ledger_schema.ensure_v2_schema(
                    connection,
                    migration_id="document-curation-m2-v2",
                )
            migrations = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        finally:
            connection.close()

        self.assertEqual(migrations, [(1,)])

    def test_foreign_key_drift_is_rejected_before_first_delta_ddl(self):
        connection = create_v1_connection()
        value_hash = "1" * 64
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "INSERT INTO policy_head VALUES "
            "(1, 1, ?, ?, ?, 'INITIAL', 'missing-policy-run', 0)",
            (value_hash, value_hash, value_hash),
        )
        connection.execute("PRAGMA foreign_keys = ON")
        statements = []
        connection.set_trace_callback(statements.append)
        try:
            with self.assertRaisesRegex(
                ledger_schema.LedgerSchemaError,
                "foreign key check failed",
            ):
                ledger_schema.ensure_v2_schema(
                    connection,
                    migration_id="document-curation-m2-v2",
                )
        finally:
            connection.close()

        self.assertFalse(
            any("CREATE TABLE inventory_runs" in statement for statement in statements)
        )

    def test_exact_verifier_accepts_sqlite_row_factory(self):
        connection = create_v1_connection()
        try:
            ledger_schema.ensure_v2_schema(
                connection,
                migration_id="document-curation-m2-v2",
            )
            connection.row_factory = sqlite3.Row
            ledger_schema.verify_v2_schema(connection)
        finally:
            connection.close()

    def test_membership_overlap_is_literal_and_only_cross_batch(self):
        connection = create_v1_connection()
        hashes = ["%064x" % value for value in range(1, 14)]
        try:
            ledger_schema.ensure_v2_schema(
                connection,
                migration_id="document-curation-m2-v2",
            )
            connection.execute(
                "INSERT INTO inventory_runs ("
                "run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
                "policy_generation, policy_full_hash, policy_writer_control_hash, "
                "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
                "policy_guard_epoch, parent_run_id, state"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'INITIAL', 'policy-run-1', ?, NULL, 'OPENED')",
                (
                    "run-root",
                    hashes[0],
                    "curation-runs/run-root",
                    hashes[1],
                    hashes[2],
                    1,
                    hashes[3],
                    hashes[4],
                    hashes[5],
                    0,
                ),
            )
            connection.execute(
                "INSERT INTO campaigns ("
                "campaign_id, root_run_id, root_run_sha256, status, "
                "current_snapshot_id, current_snapshot_sha256, review_revision, "
                "active_integration_id, opened_by, payload_json, campaign_path, "
                "campaign_sha256"
                ") VALUES (?, ?, ?, 'READY', ?, ?, 1, NULL, 'test-operator', ?, ?, ?)",
                (
                    "campaign-1",
                    "run-root",
                    hashes[0],
                    "campaign-snapshot-1",
                    hashes[6],
                    b"{}\n",
                    "campaigns/campaign-1/campaign.json",
                    hashes[7],
                ),
            )
            for batch_id, request_hash in (
                ("batch-a", hashes[8]),
                ("batch-b", hashes[9]),
                ("batch-c", hashes[10]),
            ):
                connection.execute(
                    "INSERT INTO review_batches VALUES (?, 'campaign-1', ?, 'OPEN', "
                    "NULL, NULL, 0, 0)",
                    (batch_id, request_hash),
                )
            item_ids = tuple(
                "%08d-0000-4000-8000-%012d" % (number, number)
                for number in range(1, 5)
            )
            for item_id in item_ids:
                connection.execute(
                    "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
                    (item_id,),
                )

            connection.execute(
                "INSERT INTO batch_memberships VALUES "
                "('membership-1', 'batch-a', 'unit-a', ?, 'unit_1', 'OPEN')",
                (item_ids[0],),
            )
            connection.execute(
                "INSERT INTO batch_memberships VALUES "
                "('membership-2', 'batch-a', 'unit-a', ?, 'unit_1', 'OPEN')",
                (item_ids[1],),
            )
            connection.execute(
                "INSERT INTO batch_memberships VALUES "
                "('membership-3', 'batch-b', 'unit-b', ?, 'unitX/file', 'OPEN')",
                (item_ids[2],),
            )

            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "active batch membership path overlap",
            ):
                connection.execute(
                    "INSERT INTO batch_memberships VALUES "
                    "('membership-4', 'batch-c', 'unit-c', ?, "
                    "'unit_1/child', 'OPEN')",
                    (item_ids[3],),
                )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
