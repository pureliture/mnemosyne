import hashlib
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import closing
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import ledger_runtime  # noqa: E402
from mnemosyne_core.cli.request_builder import (  # noqa: E402
    build_activation_request,
    build_view_request,
)
from mnemosyne_core.operation_control import execute_request_bytes  # noqa: E402


def setUpModule() -> None:
    """Rebind after the facade's discovery-time verified bootstrap reset."""

    global mnemosyne, ledger_runtime
    global build_activation_request, build_view_request, execute_request_bytes
    import mnemosyne as current_facade
    from mnemosyne_core import ledger_runtime as current_ledger_runtime
    from mnemosyne_core.cli.request_builder import (
        build_activation_request as current_build_activation_request,
        build_view_request as current_build_view_request,
    )
    from mnemosyne_core.operation_control import (
        execute_request_bytes as current_execute_request_bytes,
    )

    mnemosyne = current_facade
    ledger_runtime = current_ledger_runtime
    build_activation_request = current_build_activation_request
    build_view_request = current_build_view_request
    execute_request_bytes = current_execute_request_bytes


_REGISTRY_TEMPLATE = b"""schema_version: 1
root: {root}
registry_root: {root}/_registry
inbox: {root}/inbox
memory_workspaces: {root}/memory/workspaces.yml
workstreams:
  - id: integrity-fixture
    lifecycle: active
    project_home: {root}/integrity-fixture
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


def _filesystem_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    snapshot = []
    for path in (root, *sorted(root.rglob("*"))):
        info = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        digest = None
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        snapshot.append(
            (
                relative,
                stat.S_IFMT(info.st_mode),
                stat.S_IMODE(info.st_mode),
                info.st_uid,
                info.st_nlink,
                info.st_size,
                digest,
            )
        )
    return tuple(snapshot)


class SafeLibrarianActivationIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name).resolve()
        registry_directory = self.root / "_registry"
        registry_directory.mkdir(mode=0o755)
        placement = registry_directory / "placement-map.yml"
        placement.write_bytes(
            _REGISTRY_TEMPLATE.replace(b"{root}", str(self.root).encode("utf-8"))
        )
        placement.chmod(0o644)
        self.curation_root = registry_directory / "curation"
        self.activation_protocol = self.curation_root / "activation" / "v1"
        self.ledger_path = self.curation_root / "ledger.sqlite3"
        self._activate_through_public_executor()

    def _public_audit(self) -> dict[str, object]:
        request = build_view_request(
            view="audit",
            root=str(self.root),
            actor="activation-integrity-test",
            max_items=64,
            offset=0,
        )
        return json.loads(execute_request_bytes(request.canonical_bytes))

    def _activate_through_public_executor(self) -> None:
        audit = self._public_audit()
        self.assertEqual(audit["outcome_kind"], "completed")
        audit_result = audit["result"]
        self.assertEqual(audit_result["activation_state"], "NOT_ACTIVATED")
        request = build_activation_request(
            root=str(self.root),
            actor="activation-integrity-test",
            activation_id="act-fedcba9876543210fedcba9876543210",
            audit_result=audit_result,
        )
        outcome = json.loads(execute_request_bytes(request.canonical_bytes))
        self.assertEqual(outcome["outcome_kind"], "completed")

    def _assert_tamper_fails_closed(
        self,
        tamper: Callable[[], None],
    ) -> None:
        tamper()
        before = _filesystem_snapshot(self.root)

        with self.assertRaises(ledger_runtime.LedgerRuntimeError):
            with ledger_runtime.open_reader_session(self.root):
                self.fail("a tampered activation foundation must not open")

        outcome = self._public_audit()
        self.assertEqual(outcome["outcome_kind"], "completed")
        result = outcome["result"]
        self.assertEqual(result["activation_state"], "BLOCKED")
        self.assertEqual(result["reason_code"], "FOUNDATION_READBACK_FAILED")
        self.assertFalse(result["integrity_ok"])
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_request_bytes_tamper_fails_closed(self) -> None:
        request_path = self.activation_protocol / "request.json"
        self._assert_tamper_fails_closed(
            lambda: request_path.write_bytes(request_path.read_bytes() + b"\n")
        )

    def test_receipt_bytes_tamper_fails_closed(self) -> None:
        receipt_path = self.activation_protocol / "receipt.json"
        self._assert_tamper_fails_closed(
            lambda: receipt_path.write_bytes(receipt_path.read_bytes() + b"\n")
        )

    def test_ledger_bytes_tamper_fails_closed(self) -> None:
        def corrupt_ledger_header() -> None:
            raw = self.ledger_path.read_bytes()
            self.ledger_path.write_bytes(b"not a sqlite db!" + raw[16:])

        self._assert_tamper_fails_closed(corrupt_ledger_header)

    def test_ledger_schema_tamper_fails_closed(self) -> None:
        def add_unapproved_schema_object() -> None:
            with closing(sqlite3.connect(self.ledger_path)) as connection:
                with connection:
                    connection.execute(
                        "CREATE TABLE unauthorized_schema (id INTEGER PRIMARY KEY)"
                    )

        self._assert_tamper_fails_closed(add_unapproved_schema_object)

    def test_policy_head_tamper_fails_closed(self) -> None:
        def change_policy_head() -> None:
            with closing(sqlite3.connect(self.ledger_path)) as connection:
                with connection:
                    connection.execute("UPDATE policy_head SET guard_epoch = 1")

        self._assert_tamper_fails_closed(change_policy_head)


if __name__ == "__main__":
    unittest.main()
