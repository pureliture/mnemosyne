import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import activation_foundation, control, ledger_schema  # noqa: E402


BASE_REGISTRY = b"""schema_version: 1
root: {root}
registry_root: {root}/_registry
inbox: {root}/inbox
memory_workspaces: {root}/memory/workspaces.yml
workstreams:
  - id: example-service
    lifecycle: active
    project_home: {root}/example-service
    aliases: []
never_touch:
  - worktrees/
  - graphify-out/
categories:
  - id: projects
    target: {root}/projects
    patterns:
      - projects/**
"""


class ActivationFoundationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.registry_bytes = BASE_REGISTRY.replace(
            b"{root}", str(self.root).encode("utf-8")
        )
        self.activation_id = "act-0123456789abcdef0123456789abcdef"
        self.plan = activation_foundation.build_activation_foundation(
            self.registry_bytes,
            str(self.root),
            self.activation_id,
        )
        self.database_path = self.root / "ledger.sqlite3"

    def _create(self):
        descriptor = os.open(
            self.database_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.close(descriptor)
        self.database_path.chmod(0o600)
        readback = activation_foundation.initialize_activation_ledger(
            self.database_path,
            self.plan,
        )
        connection = sqlite3.connect(self.database_path, isolation_level=None)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection, readback

    def test_direct_genesis_installs_exact_v2_schema_and_only_initial_rows(self):
        connection, readback = self._create()

        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone(), (1,))
        self.assertEqual(connection.execute("PRAGMA synchronous").fetchone(), (2,))
        self.assertEqual(
            connection.execute("PRAGMA journal_mode").fetchone()[0].upper(),
            "DELETE",
        )
        self.assertEqual(
            connection.execute(
                "SELECT version, schema_sha256, applied_by_bootstrap_id "
                "FROM schema_migrations ORDER BY version"
            ).fetchall(),
            [
                (
                    control.CONTROL_SCHEMA_VERSION,
                    control.CONTROL_SCHEMA_SHA256,
                    self.activation_id,
                ),
                (
                    ledger_schema.LEDGER_SCHEMA_VERSION,
                    ledger_schema.LEDGER_SCHEMA_SHA256,
                    "safe-librarian-activation-v2",
                ),
            ],
        )

        snapshot_id = "policy-00000001-" + self.plan.initial_policy.full_hash[:24]
        self.assertEqual(
            connection.execute(
                "SELECT snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                "normalized_policy_json, source_kind, source_run_id, source_state "
                "FROM policy_snapshots"
            ).fetchall(),
            [
                (
                    snapshot_id,
                    self.plan.initial_policy.full_hash,
                    self.plan.initial_policy.writer_control_hash,
                    self.plan.initial_policy.foundation_hash,
                    self.plan.compiled_policy.full_json,
                    "INITIAL",
                    self.activation_id,
                    "TERMINAL",
                )
            ],
        )
        self.assertEqual(
            connection.execute(
                "SELECT id, generation, full_hash, writer_control_hash, "
                "foundation_hash, source_kind, source_run_id, guard_epoch "
                "FROM policy_head"
            ).fetchall(),
            [
                (
                    1,
                    1,
                    self.plan.initial_policy.full_hash,
                    self.plan.initial_policy.writer_control_hash,
                    self.plan.initial_policy.foundation_hash,
                    "INITIAL",
                    self.activation_id,
                    0,
                )
            ],
        )
        self.assertEqual(
            connection.execute(
                "SELECT id, generation, state, owner_kind, owner_proposal_id, "
                "owner_approval_id, owner_run_id, owner_process_id "
                "FROM policy_mutation_lane"
            ).fetchall(),
            [(1, 0, "IDLE", None, None, None, None, None)],
        )

        populated = {
            "schema_migrations",
            "policy_snapshots",
            "policy_head",
            "policy_mutation_lane",
        }
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        for table in tables - populated:
            self.assertEqual(
                connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone(),
                (0,),
                table,
            )

        payload = readback.canonical_value
        self.assertEqual(payload["activation_id"], self.activation_id)
        self.assertEqual(payload["initial_snapshot_id"], snapshot_id)
        self.assertEqual(
            readback.sha256,
            activation_foundation.sha256_bytes(readback.canonical_bytes),
        )

    def test_read_only_reopen_returns_the_same_canonical_logical_readback(self):
        connection, created = self._create()
        connection.close()

        observed = activation_foundation.verify_activation_ledger(
            self.database_path,
            self.plan,
        )

        self.assertEqual(observed, created)
        self.assertFalse(
            (self.database_path.parent / "ledger.sqlite3-journal").exists()
        )

    def test_invalid_input_or_tampered_head_fails_closed(self):
        with self.assertRaises(activation_foundation.ActivationFoundationError):
            activation_foundation.build_activation_foundation(
                self.registry_bytes,
                str(self.root),
                "not-an-activation-id",
            )
        self.assertFalse(self.database_path.exists())

        connection, _readback = self._create()
        connection.execute(
            "UPDATE policy_head SET writer_control_hash = ? WHERE id = 1",
            ("f" * 64,),
        )
        with self.assertRaises(activation_foundation.ActivationFoundationError):
            activation_foundation.verify_activation_ledger(
                connection,
                self.plan,
            )

    def test_schema_failure_rolls_back_every_genesis_object(self):
        descriptor = os.open(
            self.database_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.close(descriptor)
        self.database_path.chmod(0o600)
        broken_statements = ledger_schema.LEDGER_SCHEMA_STATEMENTS + (
            "CREATE TABLE intentionally_broken(",
        )

        with mock.patch.object(
            ledger_schema,
            "LEDGER_SCHEMA_STATEMENTS",
            broken_statements,
        ), self.assertRaises(activation_foundation.ActivationFoundationError):
            activation_foundation.initialize_activation_ledger(
                self.database_path,
                self.plan,
            )

        connection = sqlite3.connect(self.database_path, isolation_level=None)
        self.addCleanup(connection.close)
        self.assertEqual(
            connection.execute(
                "SELECT type, name FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall(),
            [],
        )

    def test_initializer_requires_an_empty_precreated_0600_file(self):
        self.database_path.write_bytes(b"not-empty")
        self.database_path.chmod(0o600)
        with self.assertRaises(activation_foundation.ActivationFoundationError):
            activation_foundation.initialize_activation_ledger(
                self.database_path,
                self.plan,
            )
        self.assertEqual(self.database_path.read_bytes(), b"not-empty")

        self.database_path.write_bytes(b"")
        self.database_path.chmod(0o644)
        with self.assertRaises(activation_foundation.ActivationFoundationError):
            activation_foundation.initialize_activation_ledger(
                self.database_path,
                self.plan,
            )
        self.assertEqual(self.database_path.read_bytes(), b"")

    def test_policy_material_exposes_exact_immutable_source_bytes(self):
        identity = activation_foundation.compile_initial_policy(
            self.registry_bytes,
            str(self.root),
        )

        self.assertEqual(self.plan.initial_policy, identity)
        self.assertEqual(self.plan.registry_bytes, self.registry_bytes)
        self.assertTrue(self.plan.overlay_bytes.startswith(b"curation:\n"))
        self.assertTrue(
            self.plan.effective_policy_bytes.startswith(self.registry_bytes)
        )
        self.assertEqual(
            self.plan.snapshot_id,
            "policy-00000001-" + identity.full_hash[:24],
        )
        self.assertEqual(
            activation_foundation.sha256_bytes(self.plan.compiled_policy.full_json),
            identity.full_hash,
        )
        with self.assertRaises((AttributeError, TypeError)):
            self.plan.registry_bytes = b"changed"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
