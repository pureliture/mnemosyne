import ast
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

admission = None
control = None
policy = None
policy_state = None
policy_authority = None
canonical_json_bytes = None


def setUpModule():
    # Full discovery imports this alphabetically before the compatibility
    # facade.  Defer core imports until execution so mnemosyne.py remains the
    # first source-verifying loader in the process.
    global admission, control, policy, policy_state, policy_authority
    global canonical_json_bytes
    from mnemosyne_core import admission as admission_module
    from mnemosyne_core import control as control_module
    from mnemosyne_core import policy as policy_module
    from mnemosyne_core import policy_state as policy_state_module
    from mnemosyne_core import policy_authority as policy_authority_module
    from mnemosyne_core.canonical_json import canonical_json_bytes as canonical

    admission = admission_module
    control = control_module
    policy = policy_module
    policy_state = policy_state_module
    policy_authority = policy_authority_module
    canonical_json_bytes = canonical


def tearDownModule():
    # Until the main integration slice adds admission.py to the verified
    # runtime closure, do not leave an unverified lazy import behind for the
    # compatibility facade's closure-attestation tests.
    facade = sys.modules.get("mnemosyne")
    closure = getattr(facade, "RUNTIME_MODULE_CLOSURE", ())
    verified_names = {item[0] for item in closure}
    if "mnemosyne_core.admission" not in verified_names:
        loaded = sys.modules.pop("mnemosyne_core.admission", None)
        package = sys.modules.get("mnemosyne_core")
        if package is not None and getattr(package, "admission", None) is loaded:
            delattr(package, "admission")


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
  - id: paused-project
    lifecycle: paused
    project_home: {root}/projects/paused
    aliases: []
  - id: completed-project
    lifecycle: completed
    project_home: {root}/projects/completed
    aliases: []
  - id: private-active-project
    lifecycle: active
    project_home: {root}/sensitive/project
    aliases: []
never_touch:
  - worktrees/
  - special/locked/
categories:
  - id: projects
    target: {root}/projects
    patterns:
      - projects/**
  - id: memory
    target: {root}/memory
    patterns:
      - memory/**
  - id: mirrors
    target: {root}/mirrors
    patterns:
      - mirrors/**
  - id: private
    target: {root}/sensitive
    patterns:
      - sensitive/**
  - id: opaque-evidence
    target: {root}/evidence
    patterns:
      - evidence/**
  - id: inbox-review
    target: {root}/inbox/review
    patterns:
      - inbox/**
"""


class InventoryAdmissionTest(unittest.TestCase):
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

        self.migration_id = "lockmig-20260715T000000Z-000000000001"
        self.placement_lock = self.registry_directory / "placement-map.lock"
        lock_payload = {
            "schema_version": 1,
            "kind": "PLACEMENT_COORDINATION_LOCK",
            "migration_id": self.migration_id,
            "placement_lock_protocol_version": "placement-lock-v1",
        }
        self.placement_lock.write_bytes(canonical_json_bytes(lock_payload))
        self.placement_lock.chmod(0o600)

        completed_directory = (
            self.registry_directory
            / "lock-migrations"
            / "completed"
            / self.migration_id
        )
        completed_directory.mkdir(parents=True, mode=0o700)
        self.completed_result = completed_directory / "result.json"
        completed = {
            "schema_version": 1,
            "kind": "LOCK_MIGRATION_RESULT",
            "status": "COMPLETE",
            "migration_id": self.migration_id,
            "registry_sha256": self._sha256(self.base_bytes),
            "placement_lock_protocol_version": "placement-lock-v1",
            "placement_lock": {
                "path": str(self.placement_lock),
                "sha256": self._sha256(self.placement_lock.read_bytes()),
                "mode": "0600",
                "uid": os.getuid(),
                "nlink": 1,
            },
            "paths": {
                "active_marker": str(
                    self.registry_directory / "lock-migrations" / "active"
                ),
                "completed_result": str(self.completed_result),
                "placement_lock": str(self.placement_lock),
            },
        }
        self.completed_result.write_bytes(canonical_json_bytes(completed))
        self.completed_result.chmod(0o600)

        control_preview = control.preview_bootstrap_state(
            self.root,
            requested_by="control-requester",
            completed_result_path=self.completed_result,
        )
        control.apply_bootstrap_state(
            self.root,
            requested_by="control-requester",
            approved_by="control-approver",
            preview_id=control_preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(control_preview),
            completed_result_path=self.completed_result,
        )
        self.bootstrap_id = control_preview["bootstrap_id"]
        self.ledger_path = self.registry_directory / "curation" / "ledger.sqlite3"
        self._complete_initial_policy()

    @staticmethod
    def _sha256(raw):
        return hashlib.sha256(raw).hexdigest()

    def _complete_initial_policy(self):
        preview = policy_state.preview_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            requested_by="policy-requester",
        )
        proposal = policy_state.publish_policy_bootstrap_proposal(
            self.root,
            bootstrap_id=self.bootstrap_id,
            preview=preview,
        )
        approval = policy_state.approve_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        self.policy_result = policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="admission-test-process",
        )

    def _replace_registry(self, raw):
        replacement = self.registry_path.with_name("placement-map.external")
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        os.replace(replacement, self.registry_path)

    def _archive_edit_postimage(self):
        return self.registry_path.read_bytes().replace(
            b"  archive_roots: []\n",
            (
                b"  archive_roots:\n"
                b"    - workstream_id: active-project\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local\n"
                + ("      root: %s/archive/active-project\n" % self.root).encode(
                    "utf-8"
                )
            ),
            1,
        )

    def _complete_policy_change(self, mode):
        if mode == "EDIT":
            preview = policy_authority.preview_policy_change(
                self.root,
                requested_by="policy-editor",
                postimage=self._archive_edit_postimage(),
            )
            approver = "policy-approver"
            executor = "policy-executor"
            process_id = "admission-edit-process"
        else:
            external = self.registry_path.read_bytes().replace(
                b"    lifecycle: active\n",
                b"    lifecycle: paused\n",
                1,
            )
            self._replace_registry(external)
            policy_authority.observe_policy_drift(
                self.root,
                observed_by="policy-monitor",
            )
            preview = policy_authority.preview_policy_reconcile(
                self.root,
                requested_by="reconcile-requester",
                external_actor="workspace-registry-workflow",
                external_workflow="workstream-lifecycle-update",
            )
            approver = "reconcile-approver"
            executor = "reconcile-executor"
            process_id = "admission-reconcile-process"
        proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by=approver,
            required_sealed_mode=mode,
        )
        return policy_authority.apply_policy_change(
            self.root,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by=executor,
            process_instance_id=process_id,
            required_sealed_mode=mode,
        )

    def _tree_snapshot(self):
        rows = []
        for path in sorted(self.root.rglob("*")):
            # SQLite WAL readers use the -shm file as ephemeral lock memory.
            # It is not a durable curation write or authority artifact.
            if path.name == "ledger.sqlite3-shm":
                continue
            info = path.lstat()
            relative = str(path.relative_to(self.root))
            if stat.S_ISREG(info.st_mode):
                rows.append(
                    (
                        relative,
                        stat.S_IMODE(info.st_mode),
                        info.st_size,
                        self._sha256(path.read_bytes()),
                    )
                )
            else:
                rows.append((relative, stat.S_IMODE(info.st_mode), None, None))
        return rows

    def _admit(self):
        return admission.admit_inventory(
            self.root,
            bootstrap_id=self.bootstrap_id,
        )

    def test_initial_terminal_policy_is_admitted_without_filesystem_writes(self):
        before = self._tree_snapshot()
        result = self._admit()
        after = self._tree_snapshot()

        self.assertEqual(after, before)
        compiled = policy.compile_policy(self.registry_path.read_bytes(), str(self.root))
        self.assertEqual(result.approved_policy.raw_hash, compiled.raw_hash)
        self.assertEqual(result.approved_policy.full_hash, compiled.full_hash)
        self.assertEqual(result.approved_policy.writer_control_hash, compiled.writer_hash)
        self.assertEqual(result.approved_policy.foundation_hash, compiled.foundation_hash)
        self.assertEqual(result.approved_policy.generation, 1)
        self.assertEqual(result.approved_policy.source_kind, "INITIAL")
        self.assertEqual(result.approved_policy.guard_epoch, 0)
        self.assertEqual(result.scope.scope_hash, result.scope_hash)
        with self.assertRaises(TypeError):
            result.scope.bindings[0] = result.scope.bindings[0]

    def test_edit_terminal_policy_is_admitted_from_exact_sealed_source(self):
        terminal = self._complete_policy_change("EDIT")
        before = self._tree_snapshot()

        result = self._admit()

        self.assertEqual(self._tree_snapshot(), before)
        self.assertEqual(result.approved_policy.source_kind, "EDIT")
        self.assertEqual(result.approved_policy.source_run_id, terminal["run_id"])
        self.assertEqual(result.approved_policy.generation, 2)
        self.assertEqual(result.approved_policy.raw_hash, terminal["raw_hash"])

    def test_reconcile_terminal_policy_is_admitted_without_yaml_write(self):
        terminal = self._complete_policy_change("RECONCILE")
        before = self._tree_snapshot()

        result = self._admit()

        self.assertEqual(self._tree_snapshot(), before)
        self.assertEqual(result.approved_policy.source_kind, "RECONCILE")
        self.assertEqual(result.approved_policy.source_run_id, terminal["run_id"])
        self.assertEqual(result.approved_policy.generation, 2)
        self.assertEqual(terminal["yaml_write_effects"], 0)

    def test_raw_only_external_drift_is_durably_guarded_before_admission_fails(self):
        approved_raw = self.registry_path.read_bytes()
        self._replace_registry(approved_raw + b"# external raw-only drift\n")

        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "policy drift guard recorded",
        ):
            self._admit()

        with closing(sqlite3.connect(self.ledger_path)) as connection:
            head = connection.execute(
                "SELECT guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
            episode = connection.execute(
                "SELECT status FROM policy_guard_episodes"
            ).fetchone()
            event = connection.execute(
                "SELECT kind, state FROM policy_guard_events"
            ).fetchone()
        self.assertEqual(head[0], 1)
        self.assertEqual(episode[0], "OPEN")
        self.assertEqual(event, ("FIRST_DRIFT", "COMPLETE"))

    def test_invalid_external_yaml_is_durably_guarded_before_admission_fails(self):
        self._replace_registry(b"not: [valid\n")

        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "policy drift guard recorded",
        ):
            self._admit()

        with closing(sqlite3.connect(self.ledger_path)) as connection:
            head_epoch = connection.execute(
                "SELECT guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()[0]
            event = connection.execute(
                "SELECT kind, state FROM policy_guard_events"
            ).fetchone()
        self.assertEqual(head_epoch, 1)
        self.assertEqual(event, ("FIRST_DRIFT", "COMPLETE"))

    def test_captured_drift_survives_aba_restore_before_guard_lock(self):
        approved_raw = self.registry_path.read_bytes()
        self._replace_registry(approved_raw + b"# transient external drift\n")
        original = policy_authority.observe_policy_drift_from_stable_observation

        def restore_then_observe(root, **kwargs):
            self._replace_registry(approved_raw)
            return original(root, **kwargs)

        with mock.patch.object(
            policy_authority,
            "observe_policy_drift_from_stable_observation",
            side_effect=restore_then_observe,
        ) as observer:
            with self.assertRaisesRegex(
                admission.InventoryAdmissionError,
                "policy drift guard recorded",
            ):
                self._admit()

        observer.assert_called_once()
        self.assertEqual(self.registry_path.read_bytes(), approved_raw)
        with closing(sqlite3.connect(self.ledger_path)) as connection:
            head_epoch = connection.execute(
                "SELECT guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()[0]
            episode = connection.execute(
                "SELECT status FROM policy_guard_episodes"
            ).fetchone()[0]
        self.assertEqual(head_epoch, 1)
        self.assertEqual(episode, "OPEN")

    def test_postcheck_stable_b_survives_restore_before_guard_lock(self):
        approved_raw = self.registry_path.read_bytes()
        drift_raw = b"not: [valid\n"
        original_verify = admission._RegistryObservation.verify_unchanged
        original_observe = policy_authority.observe_policy_drift_from_stable_observation
        changed = False

        def change_then_verify(observation):
            nonlocal changed
            if not changed:
                changed = True
                self._replace_registry(drift_raw)
            return original_verify(observation)

        def restore_then_observe(root, **kwargs):
            self._replace_registry(approved_raw)
            return original_observe(root, **kwargs)

        with (
            mock.patch.object(
                admission._RegistryObservation,
                "verify_unchanged",
                side_effect=change_then_verify,
                autospec=True,
            ),
            mock.patch.object(
                policy_authority,
                "observe_policy_drift_from_stable_observation",
                side_effect=restore_then_observe,
            ) as observer,
            self.assertRaisesRegex(
                admission.InventoryAdmissionError,
                "policy drift guard recorded",
            ),
        ):
            self._admit()

        self.assertTrue(changed)
        observer.assert_called_once()
        self.assertEqual(observer.call_args.kwargs["observed_raw"], drift_raw)
        self.assertEqual(
            observer.call_args.kwargs["observed_identity"]["compile_status"],
            "INVALID",
        )
        with closing(sqlite3.connect(self.ledger_path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT guard_epoch FROM policy_head WHERE id = 1"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM policy_guard_episodes"
                ).fetchone()[0],
                "OPEN",
            )
            observation_path = connection.execute(
                "SELECT observation_path FROM policy_guard_events "
                "WHERE kind = 'FIRST_DRIFT'"
            ).fetchone()[0]
        event_observation = json.loads(Path(observation_path).read_bytes())
        self.assertEqual(
            event_observation["observation"]["raw_sha256"],
            self._sha256(drift_raw),
        )

    def test_terminal_source_corruption_does_not_mislabel_equal_yaml_as_drift(self):
        result_path = Path(self.policy_result["paths"]["result"])
        original = result_path.read_bytes()
        result_path.write_bytes(b"tampered")
        result_path.chmod(0o600)

        with self.assertRaises(admission.InventoryAdmissionError):
            self._admit()

        with closing(sqlite3.connect(self.ledger_path)) as connection:
            head_epoch = connection.execute(
                "SELECT guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()[0]
            episode_count = connection.execute(
                "SELECT COUNT(*) FROM policy_guard_episodes"
            ).fetchone()[0]
        self.assertEqual(head_epoch, 0)
        self.assertEqual(episode_count, 0)
        result_path.write_bytes(original)
        result_path.chmod(0o600)

    def test_scope_projection_uses_typed_anchors_and_most_restrictive_result(self):
        result = self._admit()
        scope_map = result.scope.to_scope_map()

        active = scope_map.decision_for((b"projects", b"active", b"doc.md"))
        self.assertEqual(
            (active.rule_id, active.traversal, active.content_inspection),
            ("active-workstream-content", "full", "bounded-text"),
        )
        paused = scope_map.decision_for((b"projects", b"paused", b"doc.md"))
        self.assertEqual(
            (paused.rule_id, paused.traversal, paused.content_inspection),
            ("paused-completed", "directory-count-only", "none"),
        )
        completed = scope_map.decision_for((b"projects", b"completed", b"doc.md"))
        self.assertEqual(completed.lifecycle, "completed")
        private_active = scope_map.decision_for(
            (b"sensitive", b"project", b"doc.md")
        )
        self.assertEqual(private_active.scope_class, "private-reviewable")
        self.assertEqual(private_active.content_inspection, "none")
        self.assertEqual(scope_map.decision_for((b"memory", b"x")).scope_class, "memory")
        self.assertEqual(
            scope_map.decision_for((b"memory", b"workspaces.yml")).excluded_reason,
            "control",
        )
        self.assertEqual(scope_map.decision_for((b"mirrors", b"x")).scope_class, "mirror")
        self.assertEqual(
            scope_map.decision_for((b"evidence", b"x")).scope_class,
            "opaque-private-evidence",
        )
        self.assertEqual(
            scope_map.decision_for((b"special", b"locked", b"x")).excluded_reason,
            "never-touch",
        )
        self.assertEqual(
            scope_map.decision_for((b"_registry", b"x")).excluded_reason,
            "control",
        )
        self.assertEqual(
            scope_map.decision_for((b"unknown", b"x")).scope_class,
            "unassigned-intake",
        )

    def test_archive_roots_inherit_lifecycle_and_sensitivity_restrictions(self):
        raw = self.registry_path.read_bytes()
        archive_block = (
            "  archive_roots:\n"
            "    - workstream_id: active-project\n"
            "      sensitivity: standard\n"
            "      access_domain: local\n"
            "      root: {root}/archive/active\n"
            "    - workstream_id: active-project\n"
            "      sensitivity: private\n"
            "      access_domain: local-restricted\n"
            "      root: {root}/archive/private\n"
            "    - workstream_id: paused-project\n"
            "      sensitivity: standard\n"
            "      access_domain: local\n"
            "      root: {root}/archive/paused\n"
            "    - workstream_id: completed-project\n"
            "      sensitivity: opaque\n"
            "      access_domain: local-restricted\n"
            "      root: {root}/archive/opaque\n"
        ).replace("{root}", str(self.root)).encode("utf-8")
        compiled = policy.compile_policy(
            raw.replace(b"  archive_roots: []\n", archive_block),
            str(self.root),
        )
        scope_map = admission.compile_inventory_scope(compiled, str(self.root)).to_scope_map()

        self.assertEqual(
            scope_map.decision_for((b"archive", b"active", b"x")).scope_class,
            "eligible",
        )
        self.assertEqual(
            scope_map.decision_for((b"archive", b"private", b"x")).scope_class,
            "private-reviewable",
        )
        self.assertEqual(
            scope_map.decision_for((b"archive", b"paused", b"x")).traversal,
            "directory-count-only",
        )
        self.assertEqual(
            scope_map.decision_for((b"archive", b"opaque", b"x")).scope_class,
            "opaque-private-evidence",
        )

    def test_registry_change_during_compile_is_rejected_by_final_stable_read(self):
        original = policy.compile_policy

        def compile_then_change(raw, root):
            compiled = original(raw, root)
            self.registry_path.write_bytes(raw + b"\n# unowned edit\n")
            self.registry_path.chmod(0o600)
            return compiled

        with mock.patch.object(admission.policy, "compile_policy", compile_then_change):
            with self.assertRaisesRegex(
                admission.InventoryAdmissionError,
                "registry changed during admission",
            ):
                self._admit()

    def test_head_hash_mismatch_is_rejected(self):
        with closing(sqlite3.connect(str(self.ledger_path))) as connection, connection:
            connection.execute(
                "INSERT INTO policy_snapshots "
                "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                "normalized_policy_json, source_kind, source_run_id, source_state) "
                "SELECT 'fake-snapshot', ?, writer_control_hash, foundation_hash, "
                "x'7b7d', 'INITIAL', 'fake-source-run', 'TERMINAL' "
                "FROM policy_head WHERE id = 1",
                ("f" * 64,),
            )
            connection.execute(
                "UPDATE policy_head SET full_hash = ?, source_run_id = "
                "'fake-source-run' WHERE id = 1",
                ("f" * 64,),
            )
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "policy head does not match current registry",
        ):
            self._admit()

    def test_non_idle_lane_is_rejected(self):
        with closing(sqlite3.connect(str(self.ledger_path))) as connection, connection:
            connection.execute(
                "UPDATE policy_mutation_lane SET state = 'RESERVED', "
                "owner_kind = 'EDIT', owner_proposal_id = 'p', "
                "owner_approval_id = 'a' WHERE id = 1"
            )
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "policy mutation lane is not IDLE",
        ):
            self._admit()

    def test_open_guard_episode_is_rejected(self):
        with closing(sqlite3.connect(str(self.ledger_path))) as connection, connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
            connection.execute(
                "INSERT INTO policy_guard_episodes "
                "(episode_id, head_generation, head_full_hash, guard_epoch_before, "
                "guard_epoch_after, first_event_id, current_observed_identity_json, "
                "root_execution_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'OPEN')",
                (
                    "episode-test",
                    head[0],
                    head[1],
                    head[2],
                    head[2] + 1,
                    "event-test",
                    canonical_json_bytes({"state": "mismatch"}),
                ),
            )
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "open policy guard episode",
        ):
            self._admit()

    def test_nonterminal_guard_event_blocks_even_when_episode_is_closed(self):
        with closing(sqlite3.connect(str(self.ledger_path))) as connection, connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
            connection.execute(
                "INSERT INTO policy_guard_episodes "
                "(episode_id, head_generation, head_full_hash, guard_epoch_before, "
                "guard_epoch_after, first_event_id, current_observed_identity_json, "
                "root_execution_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, "
                "'CLEARED_EQUALITY')",
                (
                    "episode-closed",
                    head[0],
                    head[1],
                    head[2],
                    head[2] + 1,
                    "event-prepared",
                    canonical_json_bytes({"state": "equal"}),
                ),
            )
            connection.execute(
                "INSERT INTO policy_guard_events "
                "(event_id, episode_id, kind, head_generation, guard_epoch, "
                "observation_path, observation_sha256, result_path, result_sha256, state) "
                "VALUES ('event-prepared', 'episode-closed', 'FIRST_DRIFT', ?, ?, "
                "'/observation', ?, '/result', NULL, 'PREPARED')",
                (head[0], head[2] + 1, "a" * 64),
            )
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "nonterminal policy guard event",
        ):
            self._admit()

    def test_cleared_guard_epoch_does_not_rewrite_terminal_source_result(self):
        with closing(sqlite3.connect(str(self.ledger_path))) as connection, connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
            connection.execute(
                "INSERT INTO policy_guard_episodes "
                "(episode_id, head_generation, head_full_hash, guard_epoch_before, "
                "guard_epoch_after, first_event_id, current_observed_identity_json, "
                "root_execution_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, "
                "'CLEARED_EQUALITY')",
                (
                    "episode-cleared",
                    head[0],
                    head[1],
                    head[2],
                    head[2] + 1,
                    "event-first",
                    canonical_json_bytes({"state": "equal"}),
                ),
            )
            connection.execute(
                "INSERT INTO policy_guard_events "
                "(event_id, episode_id, kind, head_generation, guard_epoch, "
                "observation_path, observation_sha256, result_path, result_sha256, state) "
                "VALUES ('event-first', 'episode-cleared', 'FIRST_DRIFT', ?, ?, "
                "'/observation', ?, '/result', ?, 'COMPLETE')",
                (head[0], head[2] + 1, "a" * 64, "b" * 64),
            )
            connection.execute(
                "UPDATE policy_head SET guard_epoch = ? WHERE id = 1",
                (head[2] + 1,),
            )

        result = self._admit()
        self.assertEqual(result.approved_policy.guard_epoch, 1)

    def test_terminal_result_tamper_is_rejected(self):
        result_path = Path(self.policy_result["paths"]["result"])
        payload = json.loads(result_path.read_bytes())
        payload["raw_hash"] = "0" * 64
        result_path.write_bytes(canonical_json_bytes(payload))
        result_path.chmod(0o600)
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "source result",
        ):
            self._admit()

    def test_terminal_source_run_rejects_unexpected_member(self):
        run_path = Path(self.policy_result["paths"]["run"])
        unexpected = run_path / "unexpected.txt"
        unexpected.write_bytes(b"not sealed\n")
        unexpected.chmod(0o600)
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "source run membership changed",
        ):
            self._admit()

    def test_terminal_source_run_rejects_missing_member(self):
        plan_path = Path(self.policy_result["paths"]["plan"])
        plan_path.unlink()
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "source run membership changed",
        ):
            self._admit()

    def test_initial_admission_uses_shared_atomic_sealed_run_verifier(self):
        run_path = Path(self.policy_result["paths"]["run"])
        original = policy_state.verify_sealed_run_directory
        injected = False

        def inject_then_verify(path, expected_members, **kwargs):
            nonlocal injected
            if Path(path) == run_path and kwargs.get("source_kind") == "INITIAL":
                injected = True
                unexpected = run_path / "unexpected-race"
                unexpected.write_bytes(b"unexpected")
                unexpected.chmod(0o600)
            return original(path, expected_members, **kwargs)

        with (
            mock.patch.object(
                policy_state,
                "verify_sealed_run_directory",
                side_effect=inject_then_verify,
            ) as verifier,
            self.assertRaises(admission.InventoryAdmissionError),
        ):
            self._admit()

        self.assertTrue(injected)
        verifier.assert_called()

    def test_policy_equality_guard_holds_shared_locks_through_content_read(self):
        admitted = self._admit()
        with admission.policy_equality_guard(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approved_policy=admitted.approved_policy,
        ) as lease:
            self.assertEqual(lease.approved_policy, admitted.approved_policy)
            descriptor = os.open(self.placement_lock, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)

    def test_policy_equality_guard_rejects_forged_or_stale_binding(self):
        admitted = self._admit()
        stale = admission.ApprovedPolicyRef(
            raw_hash=admitted.approved_policy.raw_hash,
            full_hash=admitted.approved_policy.full_hash,
            writer_control_hash=admitted.approved_policy.writer_control_hash,
            foundation_hash=admitted.approved_policy.foundation_hash,
            generation=admitted.approved_policy.generation + 1,
            source_kind=admitted.approved_policy.source_kind,
            source_run_id=admitted.approved_policy.source_run_id,
            guard_epoch=admitted.approved_policy.guard_epoch,
        )
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "approved policy binding is stale",
        ):
            with admission.policy_equality_guard(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approved_policy=stale,
            ):
                pass

    def test_policy_equality_guard_postchecks_even_when_content_reader_raises(self):
        admitted = self._admit()
        original = self.registry_path.read_bytes()
        with self.assertRaisesRegex(
            admission.InventoryAdmissionError,
            "policy drift guard recorded",
        ):
            with admission.policy_equality_guard(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approved_policy=admitted.approved_policy,
            ):
                self.registry_path.write_bytes(original + b"\n# drift during read\n")
                self.registry_path.chmod(0o600)
                raise RuntimeError("content reader failed")
        with closing(sqlite3.connect(self.ledger_path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT guard_epoch FROM policy_head WHERE id = 1"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT kind, state FROM policy_guard_events"
                ).fetchone(),
                ("FIRST_DRIFT", "COMPLETE"),
            )

    def test_policy_equality_guard_pre_yield_preserves_captured_b_across_aba(self):
        admitted = self._admit()
        approved_raw = self.registry_path.read_bytes()
        drift_raw = approved_raw + b"# equality pre-yield drift\n"
        original_verify = admission._RegistryObservation.verify_unchanged
        original_observe = policy_authority.observe_policy_drift_from_stable_observation
        body_entered = False

        def change_then_verify(observation):
            self._replace_registry(drift_raw)
            return original_verify(observation)

        def restore_then_observe(root, **kwargs):
            self._replace_registry(approved_raw)
            return original_observe(root, **kwargs)

        with (
            mock.patch.object(
                admission._RegistryObservation,
                "verify_unchanged",
                side_effect=change_then_verify,
                autospec=True,
            ),
            mock.patch.object(
                policy_authority,
                "observe_policy_drift_from_stable_observation",
                side_effect=restore_then_observe,
            ) as observer,
            self.assertRaisesRegex(
                admission.InventoryAdmissionError,
                "policy drift guard recorded",
            ),
        ):
            with admission.policy_equality_guard(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approved_policy=admitted.approved_policy,
            ):
                body_entered = True

        self.assertFalse(body_entered)
        self.assertEqual(observer.call_args.kwargs["observed_raw"], drift_raw)

    def test_policy_equality_guard_final_postcheck_preserves_captured_b_across_aba(self):
        admitted = self._admit()
        approved_raw = self.registry_path.read_bytes()
        drift_raw = approved_raw + b"# equality final drift\n"
        original_verify = admission._RegistryObservation.verify_unchanged
        original_observe = policy_authority.observe_policy_drift_from_stable_observation
        calls = 0
        body_entered = False

        def change_on_final_verify(observation):
            nonlocal calls
            calls += 1
            if calls == 2:
                self._replace_registry(drift_raw)
            return original_verify(observation)

        def restore_then_observe(root, **kwargs):
            self._replace_registry(approved_raw)
            return original_observe(root, **kwargs)

        with (
            mock.patch.object(
                admission._RegistryObservation,
                "verify_unchanged",
                side_effect=change_on_final_verify,
                autospec=True,
            ),
            mock.patch.object(
                policy_authority,
                "observe_policy_drift_from_stable_observation",
                side_effect=restore_then_observe,
            ) as observer,
            self.assertRaisesRegex(
                admission.InventoryAdmissionError,
                "policy drift guard recorded",
            ),
        ):
            with admission.policy_equality_guard(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approved_policy=admitted.approved_policy,
            ):
                body_entered = True

        self.assertTrue(body_entered)
        self.assertEqual(calls, 2)
        self.assertEqual(observer.call_args.kwargs["observed_raw"], drift_raw)


class AdmissionPythonCompatibilityTest(unittest.TestCase):
    def test_python_39_ast_compatibility(self):
        path = SCRIPT_DIR / "mnemosyne_core" / "admission.py"
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
