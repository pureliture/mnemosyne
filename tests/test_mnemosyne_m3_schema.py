import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import (  # noqa: E402
    control,
    ledger_runtime,
    ledger_schema,
    m3_schema,
    review_state,
)


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
            (1, control.CONTROL_SCHEMA_SHA256, "bootstrap-m3-test"),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        connection.close()
        raise
    return connection


def create_v2_connection():
    connection = create_v1_connection()
    ledger_schema.ensure_v2_schema(
        connection,
        migration_id=ledger_runtime.M2_MIGRATION_ID,
    )
    return connection


class LedgerSchemaV3Test(unittest.TestCase):
    def test_v3_is_an_idempotent_additive_delta_over_exact_v2(self):
        connection = create_v2_connection()
        original_v1_hash = control.CONTROL_SCHEMA_SHA256
        original_v2_hash = ledger_schema.LEDGER_SCHEMA_SHA256
        try:
            m3_schema.ensure_v3_schema(connection)
            m3_schema.ensure_v3_schema(connection)
            m3_schema.verify_v3_schema(connection)

            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            migrations = connection.execute(
                "SELECT version, schema_sha256, applied_by_bootstrap_id "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()
            submission_columns = [
                (row[1], row[3])
                for row in connection.execute(
                    "PRAGMA table_info(review_submissions)"
                ).fetchall()
            ]
        finally:
            connection.close()

        self.assertEqual(control.CONTROL_SCHEMA_SHA256, original_v1_hash)
        self.assertEqual(ledger_schema.LEDGER_SCHEMA_SHA256, original_v2_hash)
        self.assertEqual(
            tables,
            set(control.CONTROL_SCHEMA_TABLES)
            | set(ledger_schema.LEDGER_SCHEMA_TABLES)
            | set(m3_schema.M3_SCHEMA_TABLES),
        )
        self.assertEqual(
            set(m3_schema.M3_SCHEMA_TABLES),
            {
                "batch_events",
                "classification_decisions",
                "decision_events",
                "deferral_evidence_events",
                "deferral_trigger_events",
                "deferrals",
                "document_relation_events",
                "document_relations",
                "item_curation_projection",
                "legacy_import_head",
                "legacy_import_runs",
                "legacy_imports",
                "unassigned_exceptions",
                "workstream_relations",
            },
        )
        self.assertEqual(
            migrations,
            [
                (1, original_v1_hash, "bootstrap-m3-test"),
                (2, original_v2_hash, ledger_runtime.M2_MIGRATION_ID),
                (
                    m3_schema.M3_SCHEMA_VERSION,
                    m3_schema.M3_SCHEMA_SHA256,
                    m3_schema.M3_MIGRATION_ID,
                ),
            ],
        )
        self.assertEqual(
            submission_columns[-3:],
            [
                ("expected_lineage_status", 0),
                ("expected_review_revision", 0),
                ("expected_execution_generation", 0),
            ],
        )

    def test_direct_v1_to_v3_is_rejected_without_any_delta_write(self):
        connection = create_v1_connection()
        try:
            with self.assertRaisesRegex(
                m3_schema.M3SchemaError,
                "exact version-2 schema is required",
            ):
                m3_schema.ensure_v3_schema(connection)
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            migrations = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        finally:
            connection.close()

        self.assertEqual(tables, set(control.CONTROL_SCHEMA_TABLES))
        self.assertEqual(migrations, [(1,)])

    def test_v2_drift_is_rejected_before_first_v3_ddl(self):
        connection = create_v2_connection()
        connection.execute("CREATE TABLE rogue_before_v3 (id TEXT PRIMARY KEY)")
        statements = []
        connection.set_trace_callback(statements.append)
        try:
            with self.assertRaisesRegex(
                m3_schema.M3SchemaError,
                "exact version-2 schema is required",
            ):
                m3_schema.ensure_v3_schema(connection)
            migrations = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        finally:
            connection.close()

        self.assertEqual(migrations, [(1,), (2,)])
        self.assertFalse(
            any("CREATE TABLE decision_events" in statement for statement in statements)
        )

    def test_failed_delta_ddl_rolls_back_every_v3_object(self):
        connection = create_v2_connection()

        def deny_classification_table(
            action, argument1, _argument2, _database, _trigger
        ):
            if (
                authorizer["deny"]
                and action == sqlite3.SQLITE_CREATE_TABLE
                and argument1 == "classification_decisions"
            ):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        authorizer = {"deny": True}
        connection.set_authorizer(deny_classification_table)
        try:
            with self.assertRaisesRegex(
                m3_schema.M3SchemaError,
                "version-3 schema migration failed",
            ):
                m3_schema.ensure_v3_schema(connection)
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
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
            submission_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(review_submissions)"
                ).fetchall()
            }
        finally:
            connection.close()

        self.assertEqual(
            tables,
            set(control.CONTROL_SCHEMA_TABLES) | set(ledger_schema.LEDGER_SCHEMA_TABLES),
        )
        self.assertEqual(migrations, [(1,), (2,)])
        self.assertNotIn("expected_lineage_status", submission_columns)
        self.assertNotIn("expected_review_revision", submission_columns)
        self.assertNotIn("expected_execution_generation", submission_columns)

    def test_append_only_histories_reject_update_and_delete(self):
        connection = create_v2_connection()
        m3_schema.ensure_v3_schema(connection)
        value_hash = "a" * 64
        try:
            connection.execute(
                "INSERT INTO legacy_import_runs ("
                "import_run_id, request_hash, expected_head_generation, "
                "source_manifest_json, source_manifest_sha256, actor, "
                "payload_json, payload_sha256, result_id, result_path, "
                "result_sha256, state"
                ") VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                (
                    "legacy-run-1",
                    value_hash,
                    b"{}\n",
                    value_hash,
                    "test-actor",
                    b"{}\n",
                    value_hash,
                    "legacy-result-1",
                    "curation/legacy-imports/legacy-result-1",
                    value_hash,
                ),
            )
            connection.execute(
                "INSERT INTO legacy_imports ("
                "legacy_import_id, import_run_id, result_id, "
                "normalized_source_path, source_filename, content_sha256, "
                "parse_status, payload_json, payload_sha256"
                ") VALUES (?, ?, ?, ?, ?, ?, 'PARSED', ?, ?)",
                (
                    "legacy-entry-1",
                    "legacy-run-1",
                    "legacy-result-1",
                    "_registry/placement-decisions.jsonl",
                    "placement-decisions.jsonl",
                    value_hash,
                    b"{}\n",
                    value_hash,
                ),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE legacy_imports SET parse_status = 'UNPARSED' "
                    "WHERE legacy_import_id = 'legacy-entry-1'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "DELETE FROM legacy_imports "
                    "WHERE legacy_import_id = 'legacy-entry-1'"
                )
        finally:
            connection.close()

    def test_required_partial_unique_constraints_are_enforced(self):
        connection = create_v2_connection()
        m3_schema.ensure_v3_schema(connection)
        value_hash = "b" * 64
        try:
            values = (
                value_hash,
                b"{}\n",
                value_hash,
                "test-actor",
                b"{}\n",
                value_hash,
                "legacy-result-1",
                "curation/legacy-imports/legacy-result-1",
                value_hash,
            )
            connection.execute(
                "INSERT INTO legacy_import_runs ("
                "import_run_id, request_hash, expected_head_generation, "
                "source_manifest_json, source_manifest_sha256, actor, "
                "payload_json, payload_sha256, result_id, result_path, "
                "result_sha256, state"
                ") VALUES ('legacy-run-1', ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                values,
            )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO legacy_import_runs ("
                    "import_run_id, request_hash, expected_head_generation, "
                    "source_manifest_json, source_manifest_sha256, actor, "
                    "payload_json, payload_sha256, result_id, result_path, "
                    "result_sha256, state"
                    ") VALUES ('legacy-run-2', ?, 0, ?, ?, ?, ?, ?, "
                    "'legacy-result-2', 'curation/legacy-imports/legacy-result-2', ?, "
                    "'PREPARED')",
                    (
                        "c" * 64,
                        b"{}\n",
                        "c" * 64,
                        "test-actor",
                        b"{}\n",
                        "c" * 64,
                        "c" * 64,
                    ),
                )
            index_sql = {
                row[0]: row[1]
                for row in connection.execute(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE type = 'index' AND name IN ("
                    "'classification_one_current_axis', "
                    "'workstream_one_current_primary', "
                    "'document_relation_one_current_edge', "
                    "'deferral_one_current_item', "
                    "'batch_one_prepared_event', "
                    "'batch_one_structural_finalization'"
                    ")"
                ).fetchall()
            }
        finally:
            connection.close()

        self.assertEqual(
            set(index_sql),
            {
                "batch_one_prepared_event",
                "batch_one_structural_finalization",
                "classification_one_current_axis",
                "deferral_one_current_item",
                "document_relation_one_current_edge",
                "workstream_one_current_primary",
            },
        )
        self.assertTrue(all(" WHERE " in sql.upper() for sql in index_sql.values()))

    def test_runtime_and_review_state_accept_exact_v3_without_losing_v2(self):
        v2 = create_v2_connection()
        try:
            self.assertEqual(ledger_runtime._require_exact_schema_preflight(v2), "v2")
        finally:
            v2.close()

        v3 = create_v2_connection()
        m3_schema.ensure_v3_schema(v3)
        try:
            self.assertEqual(ledger_runtime._require_exact_schema_preflight(v3), "v3")
            ledger_runtime._require_bootstrap_schema_binding(
                v3,
                "bootstrap-m3-test",
                "v3",
            )
            with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
                os.chmod(directory, 0o700)
                loader = review_state._HeadLoader(v3, Path(directory))
                loader._begin()
                self.assertTrue(v3.in_transaction)
                loader._rollback()
        finally:
            v3.close()


if __name__ == "__main__":
    unittest.main()
