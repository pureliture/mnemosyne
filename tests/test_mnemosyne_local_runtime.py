import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import activation_foundation, ledger_runtime  # noqa: E402


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


class LocalSQLiteRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.registry_directory = self.root / "_registry"
        self.registry_directory.mkdir(mode=0o700)
        self.registry_path = self.registry_directory / "placement-map.yml"
        self.registry_raw = BASE_REGISTRY.replace(
            b"{root}", str(self.root).encode("utf-8")
        )
        self.registry_path.write_bytes(self.registry_raw)
        self.registry_path.chmod(0o600)

        self.curation_directory = self.registry_directory / "curation"
        self.curation_directory.mkdir(mode=0o700)
        self.policy_lock = self.curation_directory / "policy.lock"
        self.policy_lock.write_bytes(b"")
        self.policy_lock.chmod(0o600)
        self.ledger_lock = self.curation_directory / "ledger.lock"
        self.ledger_lock.write_bytes(b"")
        self.ledger_lock.chmod(0o600)
        self.runtime_mode = self.curation_directory / "runtime-mode"
        self.runtime_mode.write_bytes(b"local-sqlite-v1\n")
        self.runtime_mode.chmod(0o600)

        self.ledger_path = self.curation_directory / "ledger.sqlite3"
        descriptor = os.open(
            self.ledger_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.close(descriptor)
        self.ledger_path.chmod(0o600)
        plan = activation_foundation.build_activation_foundation(
            self.registry_raw,
            str(self.root),
            "act-0123456789abcdef0123456789abcdef",
        )
        activation_foundation.initialize_activation_ledger(self.ledger_path, plan)

    def test_local_mode_opens_existing_sqlite_without_activation_protocol(self):
        activation_directory = self.curation_directory / "activation"
        self.assertFalse(activation_directory.exists())

        with ledger_runtime.open_reader_session(self.root) as session:
            self.assertEqual(
                session.foundation_kind,
                ledger_runtime.FoundationKind.LOCAL_SQLITE,
            )
            self.assertEqual(session.current_policy().generation, 1)
            self.assertIsInstance(session.connection, sqlite3.Connection)

    def test_local_mode_allows_a_writer_without_activation_readback(self):
        with ledger_runtime.open_writer_session(self.root) as session:
            self.assertEqual(
                session.foundation_kind,
                ledger_runtime.FoundationKind.LOCAL_SQLITE,
            )
            self.assertEqual(session.current_policy().generation, 1)


if __name__ == "__main__":
    unittest.main()
