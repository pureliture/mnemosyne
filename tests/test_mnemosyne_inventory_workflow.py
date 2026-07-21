import ast
import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

admission = None
control = None
inventory = None
policy_state = None
workflow = None
canonical_json_bytes = None


def setUpModule():
    global admission, control, inventory, policy_state, workflow, canonical_json_bytes
    from mnemosyne_core import admission as admission_module
    from mnemosyne_core import control as control_module
    from mnemosyne_core import inventory as inventory_module
    from mnemosyne_core import inventory_workflow as workflow_module
    from mnemosyne_core import policy_state as policy_state_module
    from mnemosyne_core.canonical_json import canonical_json_bytes as canonical

    admission = admission_module
    control = control_module
    inventory = inventory_module
    policy_state = policy_state_module
    workflow = workflow_module
    canonical_json_bytes = canonical


def tearDownModule():
    facade = sys.modules.get("mnemosyne")
    closure = getattr(facade, "RUNTIME_MODULE_CLOSURE", ())
    verified_names = {item[0] for item in closure}
    if "mnemosyne_core.inventory_workflow" not in verified_names:
        loaded = sys.modules.pop("mnemosyne_core.inventory_workflow", None)
        package = sys.modules.get("mnemosyne_core")
        if package is not None and getattr(package, "inventory_workflow", None) is loaded:
            delattr(package, "inventory_workflow")


BASE_REGISTRY = b"""schema_version: 1
root: {root}
registry_root: {root}/_registry
inbox: {root}/inbox
memory_workspaces: {root}/memory/workspaces.yml
workstreams:
  - id: active-project
    lifecycle: active
    project_home: {root}/projects/active
    aliases: []
never_touch:
  - worktrees/
categories:
  - id: projects
    target: {root}/projects
    patterns:
      - projects/**
  - id: memory
    target: {root}/memory
    patterns:
      - memory/**
"""


class InjectedCrash(RuntimeError):
    pass


class InventoryWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.registry_directory = self.root / "_registry"
        self.registry_directory.mkdir(mode=0o700)
        self.registry_path = self.registry_directory / "placement-map.yml"
        self.base_bytes = BASE_REGISTRY.replace(
            b"{root}", str(self.root).encode("utf-8")
        )
        self.registry_path.write_bytes(self.base_bytes)
        self.registry_path.chmod(0o600)

        active = self.root / "projects" / "active"
        active.mkdir(parents=True, mode=0o700)
        (active / "README.md").write_text("# Active\n", encoding="utf-8")
        (active / "README.md").chmod(0o600)
        paused = self.root / "projects" / "unassigned"
        paused.mkdir(mode=0o700)
        (paused / "note.txt").write_text("metadata only\n", encoding="utf-8")
        (paused / "note.txt").chmod(0o600)

        migration_id = "lockmig-20260715T000000Z-000000000001"
        placement_lock = self.registry_directory / "placement-map.lock"
        placement_lock.write_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "kind": "PLACEMENT_COORDINATION_LOCK",
                    "migration_id": migration_id,
                    "placement_lock_protocol_version": "placement-lock-v1",
                }
            )
        )
        placement_lock.chmod(0o600)
        completed_directory = (
            self.registry_directory / "lock-migrations" / "completed" / migration_id
        )
        completed_directory.mkdir(parents=True, mode=0o700)
        completed_result = completed_directory / "result.json"
        completed_result.write_bytes(
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "kind": "LOCK_MIGRATION_RESULT",
                    "status": "COMPLETE",
                    "migration_id": migration_id,
                    "registry_sha256": self._sha256(self.base_bytes),
                    "placement_lock_protocol_version": "placement-lock-v1",
                    "placement_lock": {
                        "path": str(placement_lock),
                        "sha256": self._sha256(placement_lock.read_bytes()),
                        "mode": "0600",
                        "uid": os.getuid(),
                        "nlink": 1,
                    },
                    "paths": {
                        "active_marker": str(
                            self.registry_directory / "lock-migrations" / "active"
                        ),
                        "completed_result": str(completed_result),
                        "placement_lock": str(placement_lock),
                    },
                }
            )
        )
        completed_result.chmod(0o600)
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="control-requester",
            completed_result_path=completed_result,
        )
        control.apply_bootstrap_state(
            self.root,
            requested_by="control-requester",
            approved_by="control-approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=completed_result,
        )
        self.bootstrap_id = preview["bootstrap_id"]

        policy_preview = policy_state.preview_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            requested_by="policy-requester",
        )
        proposal = policy_state.publish_policy_bootstrap_proposal(
            self.root,
            bootstrap_id=self.bootstrap_id,
            preview=policy_preview,
        )
        approval = policy_state.approve_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="workflow-test-process",
        )
        self.runs_root = self.registry_directory / "curation-runs"

    @staticmethod
    def _sha256(raw):
        return hashlib.sha256(raw).hexdigest()

    def _durable_snapshot_without_runs(self):
        rows = []
        for path in sorted(self.root.rglob("*")):
            if path == self.runs_root or self.runs_root in path.parents:
                continue
            if path.name == "ledger.sqlite3-shm":
                continue
            info = path.lstat()
            relative = str(path.relative_to(self.root))
            if stat.S_ISREG(info.st_mode):
                rows.append((relative, stat.S_IMODE(info.st_mode), self._sha256(path.read_bytes())))
            elif stat.S_ISLNK(info.st_mode):
                rows.append((relative, "symlink", os.readlink(path)))
            else:
                rows.append((relative, stat.S_IMODE(info.st_mode), None))
        return rows

    def _durable_snapshot(self):
        rows = []
        for path in sorted(self.root.rglob("*")):
            if path.name == "ledger.sqlite3-shm":
                continue
            info = path.lstat()
            relative = str(path.relative_to(self.root))
            if stat.S_ISREG(info.st_mode):
                rows.append((relative, stat.S_IMODE(info.st_mode), self._sha256(path.read_bytes())))
            elif stat.S_ISLNK(info.st_mode):
                rows.append((relative, "symlink", os.readlink(path)))
            else:
                rows.append((relative, stat.S_IMODE(info.st_mode), None))
        return rows

    def test_request_derivation_is_exact_and_deterministic(self):
        admitted = admission.admit_inventory(
            self.root,
            bootstrap_id=self.bootstrap_id,
        )
        bounds = inventory.TraversalBounds(
            max_entries=50,
            max_direct_entries=20,
            max_depth=8,
            max_file_bytes=4096,
            max_content_bytes=8192,
        )
        first = workflow.derive_inventory_run_request(admitted, "run-request", bounds)
        second = workflow.derive_inventory_run_request(admitted, "run-request", bounds)

        self.assertEqual(first, second)
        payload = json.loads(first.canonical_bytes)
        self.assertEqual(
            payload["policy_authority"],
            {
                "foundation_hash": admitted.approved_policy.foundation_hash,
                "full_hash": admitted.approved_policy.full_hash,
                "generation": admitted.approved_policy.generation,
                "guard_epoch": admitted.approved_policy.guard_epoch,
                "raw_hash": admitted.approved_policy.raw_hash,
                "source_kind": admitted.approved_policy.source_kind,
                "source_run_id": admitted.approved_policy.source_run_id,
                "writer_control_hash": admitted.approved_policy.writer_control_hash,
            },
        )
        self.assertEqual(
            payload["scope"],
            {
                "raw_root": str(self.root),
                "scope_hash": admitted.scope.scope_hash,
                "scope_json_b64": base64.b64encode(admitted.scope.scope_json).decode("ascii"),
            },
        )
        self.assertEqual(
            payload["bounds"],
            {
                "max_content_bytes": 8192,
                "max_depth": 8,
                "max_direct_entries": 20,
                "max_entries": 50,
                "max_file_bytes": 4096,
            },
        )
        self.assertEqual(first.expected_artifacts, ("coverage.json", "observations.jsonl"))

    def test_start_completes_and_only_writes_inventory_runs_root(self):
        before = self._durable_snapshot_without_runs()
        report = workflow.start_inventory(
            self.root,
            bootstrap_id=self.bootstrap_id,
            run_id="run-complete",
        )

        self.assertEqual(report.terminal.state, "complete")
        self.assertEqual(report.terminal.path, str(self.runs_root / "run-complete"))
        self.assertFalse(report.openable)
        self.assertFalse(report.approval_ready)
        self.assertEqual(self._durable_snapshot_without_runs(), before)
        self.assertEqual(stat.S_IMODE(self.runs_root.stat().st_mode), 0o700)
        self.assertEqual(
            set(path.name for path in (self.runs_root / "run-complete").iterdir()),
            {
                "checkpoints",
                "chunks",
                "coverage.json",
                "manifest.jsonl",
                "observations.jsonl",
                "request.json",
                "run.json",
                "run.lock",
            },
        )
        with self.assertRaises(Exception):
            report.openable = True

    def test_resume_terminal_is_exact_readback(self):
        first = workflow.start_inventory(
            self.root,
            bootstrap_id=self.bootstrap_id,
            run_id="run-retry",
        )
        second = workflow.resume_inventory(
            self.root,
            bootstrap_id=self.bootstrap_id,
            run_id="run-retry",
        )
        self.assertEqual(second.terminal, first.terminal)
        self.assertEqual(second.request_sha256, first.request_sha256)

    def test_resume_missing_runs_root_is_effect_zero(self):
        before = self._durable_snapshot()

        with self.assertRaises(workflow.InventoryWorkflowError):
            workflow.resume_inventory(
                self.root,
                bootstrap_id=self.bootstrap_id,
                run_id="run-does-not-exist",
            )

        self.assertEqual(self._durable_snapshot(), before)
        self.assertFalse(os.path.lexists(self.runs_root))

    def test_scan_failure_publishes_failed_terminal_and_resume_reads_it(self):
        with mock.patch.object(
            workflow.inventory.InventoryEngine,
            "scan",
            side_effect=inventory.InventorySafetyError("injected-scan-failure"),
        ):
            failed = workflow.start_inventory(
                self.root,
                bootstrap_id=self.bootstrap_id,
                run_id="run-failed",
            )
        self.assertEqual(failed.terminal.state, "failed")
        replay = workflow.resume_inventory(
            self.root,
            bootstrap_id=self.bootstrap_id,
            run_id="run-failed",
        )
        self.assertEqual(replay.terminal, failed.terminal)

    def test_mid_publication_crash_resumes_exact_staging(self):
        real_store = inventory.InventoryRunStore
        crashed = {"value": False}

        def store_factory(runs_root, fault_checkpoint=None):
            def checkpoint(event, details):
                if fault_checkpoint is not None:
                    fault_checkpoint(event, details)
                if event == "terminal-before-rename" and not crashed["value"]:
                    crashed["value"] = True
                    raise InjectedCrash("before terminal rename")

            return real_store(runs_root, fault_checkpoint=checkpoint)

        with mock.patch.object(
            workflow.inventory,
            "InventoryRunStore",
            side_effect=store_factory,
        ):
            with self.assertRaises(InjectedCrash):
                workflow.start_inventory(
                    self.root,
                    bootstrap_id=self.bootstrap_id,
                    run_id="run-resume",
                )
        self.assertTrue((self.runs_root / ".incomplete-run-resume").is_dir())
        report = workflow.resume_inventory(
            self.root,
            bootstrap_id=self.bootstrap_id,
            run_id="run-resume",
        )
        self.assertEqual(report.terminal.state, "complete")

    def test_resume_rejects_live_run_lock(self):
        entered = threading.Event()
        release = threading.Event()
        result = {}
        real_scan = inventory.InventoryEngine.scan

        def blocking_scan(engine, run_id):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test timeout")
            return real_scan(engine, run_id)

        def worker():
            try:
                result["report"] = workflow.start_inventory(
                    self.root,
                    bootstrap_id=self.bootstrap_id,
                    run_id="run-busy",
                )
            except BaseException as exc:
                result["error"] = exc

        with mock.patch.object(workflow.inventory.InventoryEngine, "scan", blocking_scan):
            thread = threading.Thread(target=worker)
            thread.start()
            self.assertTrue(entered.wait(5))
            try:
                with self.assertRaises(inventory.RunBusyError):
                    workflow.resume_inventory(
                        self.root,
                        bootstrap_id=self.bootstrap_id,
                        run_id="run-busy",
                    )
            finally:
                release.set()
                thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", result)
        self.assertEqual(result["report"].terminal.state, "complete")

    def test_runs_root_symlink_is_rejected_without_target_write(self):
        target = self.root / "outside-runs"
        target.mkdir(mode=0o700)
        self.runs_root.symlink_to(target, target_is_directory=True)
        with self.assertRaises(workflow.InventoryWorkflowError):
            workflow.start_inventory(
                self.root,
                bootstrap_id=self.bootstrap_id,
                run_id="run-symlink",
            )
        self.assertEqual(list(target.iterdir()), [])

    def test_runs_root_symlink_creation_collision_is_rejected(self):
        target = self.root / "outside-collision-runs"
        target.mkdir(mode=0o700)
        real_mkdir = os.mkdir

        def collide(name, mode=0o777, *, dir_fd=None):
            if name != self.runs_root.name:
                return real_mkdir(name, mode, dir_fd=dir_fd)
            os.symlink(
                str(target),
                name,
                target_is_directory=True,
                dir_fd=dir_fd,
            )
            raise FileExistsError(name)

        with mock.patch.object(workflow.os, "mkdir", side_effect=collide):
            with self.assertRaises(workflow.InventoryWorkflowError):
                workflow.start_inventory(
                    self.root,
                    bootstrap_id=self.bootstrap_id,
                    run_id="run-symlink-collision",
                )

        self.assertTrue(self.runs_root.is_symlink())
        self.assertEqual(list(target.iterdir()), [])

    def test_runs_root_wrong_mode_is_rejected_without_repair(self):
        self.runs_root.mkdir(mode=0o755)
        self.runs_root.chmod(0o755)
        with self.assertRaises(workflow.InventoryWorkflowError):
            workflow.start_inventory(
                self.root,
                bootstrap_id=self.bootstrap_id,
                run_id="run-mode",
            )
        self.assertEqual(stat.S_IMODE(self.runs_root.stat().st_mode), 0o755)

    def test_policy_drift_before_guard_blocks_before_runs_root_write(self):
        real_admit = admission.admit_inventory

        def admit_then_drift(root, *, bootstrap_id):
            admitted = real_admit(root, bootstrap_id=bootstrap_id)
            self.registry_path.write_bytes(
                self.registry_path.read_bytes() + b"\n# drift before guard\n"
            )
            self.registry_path.chmod(0o600)
            return admitted

        with mock.patch.object(
            workflow.admission,
            "admit_inventory",
            side_effect=admit_then_drift,
        ):
            with self.assertRaises(admission.InventoryAdmissionError):
                workflow.start_inventory(
                    self.root,
                    bootstrap_id=self.bootstrap_id,
                    run_id="run-pre-drift",
                )
        self.assertFalse(os.path.lexists(self.runs_root))

    def test_policy_drift_during_scan_blocks_terminal_publish(self):
        real_scan = inventory.InventoryEngine.scan

        def scan_then_drift(engine, run_id):
            result = real_scan(engine, run_id)
            self.registry_path.write_bytes(
                self.registry_path.read_bytes() + b"\n# drift during scan\n"
            )
            self.registry_path.chmod(0o600)
            return result

        with mock.patch.object(workflow.inventory.InventoryEngine, "scan", scan_then_drift):
            with self.assertRaises(workflow.InventoryPolicyDriftError):
                workflow.start_inventory(
                    self.root,
                    bootstrap_id=self.bootstrap_id,
                    run_id="run-drift",
                )
        self.assertFalse(os.path.lexists(self.runs_root / "run-drift"))
        self.assertTrue(os.path.lexists(self.runs_root / ".incomplete-run-drift"))


class InventoryWorkflowPythonCompatibilityTest(unittest.TestCase):
    def test_python_39_ast_compatibility(self):
        path = SCRIPT_DIR / "mnemosyne_core" / "inventory_workflow.py"
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
