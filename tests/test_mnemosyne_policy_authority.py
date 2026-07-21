import importlib
import ast
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


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import control, policy_authority, policy_state  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


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


class InjectedCrash(RuntimeError):
    pass


class PolicyAuthorityPublicApiTest(unittest.TestCase):
    def test_policy_authority_module_exposes_public_entrypoints(self):
        try:
            module = importlib.import_module("mnemosyne_core.policy_authority")
        except ModuleNotFoundError as exc:
            self.fail("policy authority module is missing: %s" % exc)

        self.assertTrue(callable(module.observe_policy_drift))
        self.assertTrue(
            callable(module.observe_policy_drift_from_stable_observation)
        )
        self.assertTrue(callable(module.resume_policy_guard_event))
        self.assertTrue(callable(module.clear_policy_drift_equality))
        self.assertTrue(callable(module.preview_policy_change))
        self.assertTrue(callable(module.preview_policy_reconcile))
        self.assertTrue(callable(module.publish_policy_change_proposal))
        self.assertTrue(callable(module.approve_policy_change))
        self.assertTrue(callable(module.apply_policy_change))
        self.assertTrue(callable(module.verify_normal_policy_authority))
        self.assertTrue(callable(module.verify_terminal_policy_source_locked))

    def test_shared_sealed_run_verifier_uses_the_callers_source_kind(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            run_path = Path(temporary_directory).resolve() / "run"
            run_path.mkdir(mode=0o700)
            unexpected = run_path / "unexpected"
            unexpected.write_bytes(b"unexpected")
            unexpected.chmod(0o600)

            with self.assertRaisesRegex(
                policy_state.PolicyStateError,
                "sealed EDIT run membership changed",
            ):
                policy_state.verify_sealed_run_directory(
                    run_path,
                    {},
                    source_kind="EDIT",
                )


class PolicyAuthorityStateTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.registry_directory = self.root / "_registry"
        self.registry_directory.mkdir(mode=0o700)
        self.registry_path = self.registry_directory / "placement-map.yml"
        base = BASE_REGISTRY.replace(b"{root}", str(self.root).encode("utf-8"))
        self.registry_path.write_bytes(base)
        self.registry_path.chmod(0o600)

        migration_id = "lockmig-20260715T000000Z-000000000001"
        placement_lock = self.registry_directory / "placement-map.lock"
        lock_payload = {
            "schema_version": 1,
            "kind": "PLACEMENT_COORDINATION_LOCK",
            "migration_id": migration_id,
            "placement_lock_protocol_version": "placement-lock-v1",
        }
        placement_lock.write_bytes(canonical_json_bytes(lock_payload))
        placement_lock.chmod(0o600)
        completed_directory = (
            self.registry_directory / "lock-migrations" / "completed" / migration_id
        )
        completed_directory.mkdir(parents=True, mode=0o700)
        completed_result = completed_directory / "result.json"
        completed = {
            "schema_version": 1,
            "kind": "LOCK_MIGRATION_RESULT",
            "status": "COMPLETE",
            "migration_id": migration_id,
            "registry_sha256": hashlib.sha256(base).hexdigest(),
            "placement_lock_protocol_version": "placement-lock-v1",
            "placement_lock": {
                "path": str(placement_lock),
                "sha256": hashlib.sha256(placement_lock.read_bytes()).hexdigest(),
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
        completed_result.write_bytes(canonical_json_bytes(completed))
        completed_result.chmod(0o600)

        control_preview = control.preview_bootstrap_state(
            self.root,
            requested_by="control-requester",
            completed_result_path=completed_result,
        )
        control.apply_bootstrap_state(
            self.root,
            requested_by="control-requester",
            approved_by="control-approver",
            preview_id=control_preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(control_preview),
            completed_result_path=completed_result,
        )
        self.bootstrap_id = control_preview["bootstrap_id"]
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
        self.initial_result = policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="initial-process-instance",
        )
        self.initial_registry = self.registry_path.read_bytes()
        self.ledger_path = self.registry_directory / "curation" / "ledger.sqlite3"

    def _replace_registry(self, raw):
        replacement = self.registry_path.with_name("placement-map.external")
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        os.replace(replacement, self.registry_path)

    def _archive_edit_postimage(self):
        return self.initial_registry.replace(
            b"  archive_roots: []\n",
            (
                b"  archive_roots:\n"
                b"    - workstream_id: example-service\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local\n"
                + ("      root: %s/archive/example-service\n" % self.root).encode(
                    "utf-8"
                )
            ),
            1,
        )

    def _published_edit_proposal(self):
        preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="policy-editor",
            postimage=self._archive_edit_postimage(),
        )
        return preview, policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )

    def _published_reconcile_proposal(self):
        external = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        self._replace_registry(external)
        guard = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        preview = policy_authority.preview_policy_reconcile(
            self.root,
            requested_by="reconcile-requester",
            external_actor="workspace-registry-workflow",
            external_workflow="workstream-lifecycle-update",
        )
        proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        return external, guard, preview, proposal

    def _complete_policy_change(self, mode):
        if mode == "EDIT":
            _preview, proposal = self._published_edit_proposal()
            approver = "policy-approver"
            executor = "policy-executor"
            process_id = "edit-terminal-process"
        else:
            _external, _guard, _preview, proposal = self._published_reconcile_proposal()
            approver = "reconcile-approver"
            executor = "reconcile-executor"
            process_id = "reconcile-terminal-process"
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by=approver,
        )
        result = policy_authority.apply_policy_change(
            self.root,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by=executor,
            process_instance_id=process_id,
        )
        return proposal, approval, result

    def _assert_terminal_run_tampers_rejected(self, result):
        run_path = Path(result["paths"]["run"])
        plan_path = run_path / "plan.json"
        original_plan = plan_path.read_bytes()

        unexpected = run_path / "unexpected"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)
        with self.assertRaises(policy_authority.PolicyAuthorityError):
            policy_authority.verify_normal_policy_authority(self.root)
        unexpected.unlink()

        symlink = run_path / "unexpected-link"
        symlink.symlink_to(run_path / "result.json")
        with self.assertRaises(policy_authority.PolicyAuthorityError):
            policy_authority.verify_normal_policy_authority(self.root)
        symlink.unlink()

        missing_backup = run_path.parent / (run_path.name + "-plan-backup")
        os.replace(plan_path, missing_backup)
        with self.assertRaises(policy_authority.PolicyAuthorityError):
            policy_authority.verify_normal_policy_authority(self.root)
        os.replace(missing_backup, plan_path)

        replacement = run_path.parent / (run_path.name + "-plan-replacement")
        replacement.write_bytes(b"tampered-plan")
        replacement.chmod(0o600)
        os.replace(replacement, plan_path)
        with self.assertRaises(policy_authority.PolicyAuthorityError):
            policy_authority.verify_normal_policy_authority(self.root)
        plan_path.write_bytes(original_plan)
        plan_path.chmod(0o600)
        self.assertEqual(
            policy_authority.verify_normal_policy_authority(self.root)[
                "approved_policy_ref"
            ]["source_run_id"],
            result["run_id"],
        )

    def test_edit_terminal_source_rejects_membership_and_member_tamper(self):
        _proposal, _approval, result = self._complete_policy_change("EDIT")
        self._assert_terminal_run_tampers_rejected(result)

    def test_reconcile_terminal_source_rejects_membership_and_member_tamper(self):
        _proposal, _approval, result = self._complete_policy_change("RECONCILE")
        self._assert_terminal_run_tampers_rejected(result)

    def test_initial_source_corruption_blocks_normal_authority_and_edit_preview(self):
        unexpected = Path(self.initial_result["paths"]["run"]) / "unexpected-source"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)

        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "sealed INITIAL run membership changed",
        ):
            policy_authority.verify_normal_policy_authority(self.root)
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "sealed INITIAL run membership changed",
        ):
            policy_authority.preview_policy_change(
                self.root,
                requested_by="blocked-editor",
                postimage=self._archive_edit_postimage(),
            )

    def test_corrupted_source_is_effect_zero_before_approval_reservation(self):
        _preview, proposal = self._published_edit_proposal()
        unexpected = Path(self.initial_result["paths"]["run"]) / "unexpected-source"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)

        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "sealed INITIAL run membership changed",
        ):
            policy_authority.approve_policy_change(
                self.root,
                proposal_id=proposal["proposal_id"],
                proposal_sha256=proposal["proposal_sha256"],
                approved_by="blocked-approver",
                required_sealed_mode="EDIT",
            )

        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_change_approvals"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "IDLE",
            )

    def test_corrupted_source_is_effect_zero_before_apply_claim(self):
        _preview, proposal = self._published_edit_proposal()
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
            required_sealed_mode="EDIT",
        )
        unexpected = Path(self.initial_result["paths"]["run"]) / "unexpected-source"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)

        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "sealed INITIAL run membership changed",
        ):
            policy_authority.apply_policy_change(
                self.root,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="blocked-executor",
                process_instance_id="blocked-claim-process",
                required_sealed_mode="EDIT",
            )

        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_change_runs"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_change_approvals WHERE approval_id = ?",
                    (approval["approval_id"],),
                ).fetchone()[0],
                "PUBLISHED",
            )

    def test_source_corruption_before_final_cas_blocks_new_authority(self):
        _preview, proposal = self._published_edit_proposal()
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
            required_sealed_mode="EDIT",
        )

        def corrupt_source(point):
            if point == "result-published":
                unexpected = (
                    Path(self.initial_result["paths"]["run"])
                    / "unexpected-before-final-cas"
                )
                unexpected.write_bytes(b"unexpected")
                unexpected.chmod(0o600)

        with self.assertRaises(
            policy_authority.PolicyChangeRecoveryRequired
        ) as caught:
            policy_authority.apply_policy_change(
                self.root,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="source-corrupt-final-cas",
                required_sealed_mode="EDIT",
                checkpoint=corrupt_source,
            )

        self.assertEqual(caught.exception.phase, "RESULT_PUBLISHED")
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT generation FROM policy_head WHERE id = 1"
                ).fetchone()[0],
                1,
            )

    def test_source_corruption_before_reconcile_final_cas_blocks_adoption(self):
        _external, guard, _preview, proposal = self._published_reconcile_proposal()
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="reconcile-approver",
            required_sealed_mode="RECONCILE",
        )

        def corrupt_source(point):
            if point == "result-published":
                unexpected = (
                    Path(self.initial_result["paths"]["run"])
                    / "unexpected-before-reconcile-final-cas"
                )
                unexpected.write_bytes(b"unexpected")
                unexpected.chmod(0o600)

        with self.assertRaises(
            policy_authority.PolicyChangeRecoveryRequired
        ) as caught:
            policy_authority.apply_policy_change(
                self.root,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="reconcile-executor",
                process_instance_id="reconcile-source-corrupt-final-cas",
                required_sealed_mode="RECONCILE",
                checkpoint=corrupt_source,
            )

        self.assertEqual(caught.exception.phase, "RESULT_PUBLISHED")
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT generation, source_kind FROM policy_head WHERE id = 1"
                ).fetchone(),
                (1, "INITIAL"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM policy_guard_episodes WHERE episode_id = ?",
                    (guard["episode_id"],),
                ).fetchone()[0],
                "OPEN",
            )

    def test_corrupted_edit_source_blocks_the_next_edit_preview(self):
        _proposal, _approval, result = self._complete_policy_change("EDIT")
        unexpected = Path(result["paths"]["run"]) / "unexpected-source"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)
        next_postimage = self.registry_path.read_bytes().replace(
            ("      root: %s/archive/example-service\n" % self.root).encode(
                "utf-8"
            ),
            ("      root: %s/archive/example-service-v2\n" % self.root).encode(
                "utf-8"
            ),
            1,
        )

        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "sealed EDIT run membership changed",
        ):
            policy_authority.preview_policy_change(
                self.root,
                requested_by="next-policy-editor",
                postimage=next_postimage,
            )

    def test_corrupted_reconcile_source_blocks_the_next_edit_preview(self):
        _proposal, _approval, result = self._complete_policy_change("RECONCILE")
        unexpected = Path(result["paths"]["run"]) / "unexpected-source"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)
        next_postimage = self.registry_path.read_bytes().replace(
            b"  archive_roots: []\n",
            (
                b"  archive_roots:\n"
                b"    - workstream_id: example-service\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local\n"
                + ("      root: %s/archive/example-service\n" % self.root).encode(
                    "utf-8"
                )
            ),
            1,
        )

        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "sealed RECONCILE run membership changed",
        ):
            policy_authority.preview_policy_change(
                self.root,
                requested_by="next-policy-editor",
                postimage=next_postimage,
            )

    def test_edit_can_return_to_a_historical_normalized_policy_hash(self):
        _proposal, _approval, first = self._complete_policy_change("EDIT")
        preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="return-to-a-editor",
            postimage=self.initial_registry,
        )
        proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="return-to-a-approver",
            required_sealed_mode="EDIT",
        )
        second = policy_authority.apply_policy_change(
            self.root,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="return-to-a-executor",
            process_instance_id="return-to-a-process",
            required_sealed_mode="EDIT",
        )

        self.assertEqual(first["generation"], 2)
        self.assertEqual(second["generation"], 3)
        self.assertEqual(second["normalized_full_hash"], preview["postimage"]["normalized_full_hash"])
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            snapshots = connection.execute(
                "SELECT snapshot_id, source_run_id FROM policy_snapshots "
                "WHERE full_hash = ? ORDER BY snapshot_id",
                (second["normalized_full_hash"],),
            ).fetchall()
            head = connection.execute(
                "SELECT generation, full_hash, source_run_id FROM policy_head WHERE id = 1"
            ).fetchone()
        self.assertEqual(len(snapshots), 2)
        self.assertNotEqual(snapshots[0][0], snapshots[1][0])
        self.assertEqual(tuple(head), (3, second["normalized_full_hash"], second["run_id"]))

    def test_edit_terminal_retry_returns_historical_receipt_after_head_advances(self):
        _proposal, first_approval, first_result = self._complete_policy_change("EDIT")
        second_postimage = self.registry_path.read_bytes().replace(
            ("      root: %s/archive/example-service\n" % self.root).encode("utf-8"),
            ("      root: %s/archive/example-service-v2\n" % self.root).encode(
                "utf-8"
            ),
            1,
        )
        second_preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="second-policy-editor",
            postimage=second_postimage,
        )
        second_proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=second_preview,
        )
        second_approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=second_proposal["proposal_id"],
            proposal_sha256=second_proposal["proposal_sha256"],
            approved_by="second-policy-approver",
        )
        second_result = policy_authority.apply_policy_change(
            self.root,
            approval_id=second_approval["approval_id"],
            approval_sha256=second_approval["export_sha256"],
            executed_by="second-policy-executor",
            process_instance_id="second-edit-process",
        )
        self.assertEqual(second_result["generation"], first_result["generation"] + 1)

        historical = policy_authority.apply_policy_change(
            self.root,
            approval_id=first_approval["approval_id"],
            approval_sha256=first_approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="edit-terminal-process",
        )
        self.assertEqual(historical, first_result)
        self.assertEqual(
            policy_authority.verify_normal_policy_authority(self.root)[
                "approved_policy_ref"
            ]["source_run_id"],
            second_result["run_id"],
        )

    def test_reconcile_terminal_retry_returns_historical_receipt_after_head_advances(self):
        _proposal, first_approval, first_result = self._complete_policy_change(
            "RECONCILE"
        )
        edit_postimage = self.registry_path.read_bytes().replace(
            b"  archive_roots: []\n",
            (
                b"  archive_roots:\n"
                b"    - workstream_id: example-service\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local\n"
                + ("      root: %s/archive/example-service\n" % self.root).encode(
                    "utf-8"
                )
            ),
            1,
        )
        edit_preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="post-reconcile-editor",
            postimage=edit_postimage,
        )
        edit_proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=edit_preview,
        )
        edit_approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=edit_proposal["proposal_id"],
            proposal_sha256=edit_proposal["proposal_sha256"],
            approved_by="post-reconcile-approver",
        )
        second_result = policy_authority.apply_policy_change(
            self.root,
            approval_id=edit_approval["approval_id"],
            approval_sha256=edit_approval["export_sha256"],
            executed_by="post-reconcile-executor",
            process_instance_id="post-reconcile-edit-process",
        )

        historical = policy_authority.apply_policy_change(
            self.root,
            approval_id=first_approval["approval_id"],
            approval_sha256=first_approval["export_sha256"],
            executed_by="reconcile-executor",
            process_instance_id="reconcile-terminal-process",
        )
        self.assertEqual(historical, first_result)
        self.assertEqual(second_result["generation"], first_result["generation"] + 1)

    def test_edit_terminal_source_rejects_proposal_approval_and_result_tamper(self):
        proposal, approval, result = self._complete_policy_change("EDIT")
        paths = (
            Path(proposal["proposal_path"]),
            Path(approval["export_path"]),
            Path(result["paths"]["result"]),
        )
        for path in paths:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaises(policy_authority.PolicyAuthorityError):
                    policy_authority.verify_normal_policy_authority(self.root)
                path.write_bytes(original)
                path.chmod(0o600)
        self.assertEqual(
            policy_authority.verify_normal_policy_authority(self.root)["raw_hash"],
            result["raw_hash"],
        )

    def test_reconcile_terminal_source_rejects_clear_artifact_tamper(self):
        _proposal, _approval, result = self._complete_policy_change("RECONCILE")
        for key in ("clear_event_observation", "clear_event_result"):
            path = Path(result["paths"][key])
            with self.subTest(key=key):
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaises(policy_authority.PolicyAuthorityError):
                    policy_authority.verify_normal_policy_authority(self.root)
                path.write_bytes(original)
                path.chmod(0o600)
        self.assertEqual(
            policy_authority.verify_normal_policy_authority(self.root)["raw_hash"],
            result["raw_hash"],
        )

    def test_proposal_artifact_crash_retries_exact_and_tamper_fails_closed(self):
        preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="policy-editor",
            postimage=self._archive_edit_postimage(),
        )

        def crash_after_artifact(point):
            if point == "proposal-artifact-published":
                raise InjectedCrash("after proposal artifact")

        with self.assertRaisesRegex(InjectedCrash, "after proposal artifact"):
            policy_authority.publish_policy_change_proposal(
                self.root,
                preview=preview,
                checkpoint=crash_after_artifact,
            )
        proposal_path = Path(preview["paths"]["proposal"])
        exact_bytes = proposal_path.read_bytes()
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_change_proposals WHERE proposal_id = ?",
                    (preview["proposal_id"],),
                ).fetchone()[0],
                "PREPARED",
            )

        resumed = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        self.assertEqual(proposal_path.read_bytes(), exact_bytes)
        self.assertEqual(resumed["proposal_sha256"], hashlib.sha256(exact_bytes).hexdigest())

        proposal_path.write_bytes(exact_bytes + b"\n")
        with self.assertRaises(policy_authority.PolicyAuthorityError):
            policy_authority.publish_policy_change_proposal(
                self.root,
                preview=preview,
            )
        self.assertEqual(proposal_path.read_bytes(), exact_bytes + b"\n")

    def test_proposal_rechecks_current_base_inside_publication_lock(self):
        preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="policy-editor",
            postimage=self._archive_edit_postimage(),
        )

        def replace_after_placement_lock(point):
            if point == "placement-lock-acquired":
                self._replace_registry(self.initial_registry + b"# raced raw drift\n")

        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "preview base changed before publication",
        ):
            policy_authority.publish_policy_change_proposal(
                self.root,
                preview=preview,
                checkpoint=replace_after_placement_lock,
            )
        self.assertFalse(Path(preview["paths"]["proposal"]).exists())
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_change_proposals"
                ).fetchone()[0],
                0,
            )

    def test_corrupted_source_blocks_policy_change_publication_effect_zero(self):
        preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="policy-editor",
            postimage=self._archive_edit_postimage(),
        )
        unexpected = Path(self.initial_result["paths"]["run"]) / "unexpected-source"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)

        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "sealed INITIAL run membership changed",
        ):
            policy_authority.publish_policy_change_proposal(
                self.root,
                preview=preview,
            )

        self.assertFalse(Path(preview["paths"]["proposal"]).exists())
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_change_proposals"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "IDLE",
            )

    def test_edit_approval_prepared_crash_retries_exact_reserved_export(self):
        _preview, proposal = self._published_edit_proposal()

        def crash_after_artifact(point):
            if point == "approval-artifact-published":
                raise InjectedCrash("after EDIT approval artifact")

        with self.assertRaisesRegex(InjectedCrash, "after EDIT approval artifact"):
            policy_authority.approve_policy_change(
                self.root,
                proposal_id=proposal["proposal_id"],
                proposal_sha256=proposal["proposal_sha256"],
                approved_by="policy-approver",
                checkpoint=crash_after_artifact,
            )
        approval_path = Path(proposal["payload"]["paths"]["approval"])
        exact_bytes = approval_path.read_bytes()
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            lane_before = connection.execute(
                "SELECT generation, state, owner_kind, owner_proposal_id, "
                "owner_approval_id FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
            approval_before = connection.execute(
                "SELECT approval_id, attempt, export_sha256, state "
                "FROM policy_change_approvals"
            ).fetchone()
        self.assertEqual(lane_before[1:], (
            "RESERVED", "POLICY_EDIT", proposal["proposal_id"], approval_before[0]
        ))
        self.assertEqual(approval_before[1], 1)
        self.assertEqual(approval_before[3], "PREPARED")

        with self.assertRaises(policy_authority.PolicyAuthorityError):
            policy_authority.approve_policy_change(
                self.root,
                proposal_id=proposal["proposal_id"],
                proposal_sha256=proposal["proposal_sha256"],
                approved_by="different-approver",
            )
        resumed = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        self.assertEqual(approval_path.read_bytes(), exact_bytes)
        self.assertEqual(resumed["approval_id"], approval_before[0])
        self.assertEqual(resumed["export_sha256"], approval_before[2])
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*), MIN(attempt), MAX(attempt) "
                    "FROM policy_change_approvals"
                ).fetchone(),
                (1, 1, 1),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT generation, state, owner_kind, owner_proposal_id, "
                    "owner_approval_id FROM policy_mutation_lane WHERE id = 1"
                ).fetchone(),
                lane_before,
            )

    def test_reconcile_approval_prepared_crash_retries_exact_reserved_export(self):
        _external, _guard, _preview, proposal = self._published_reconcile_proposal()

        def crash_after_prepared(point):
            if point == "approval-prepared":
                raise InjectedCrash("after RECONCILE approval prepare")

        with self.assertRaisesRegex(InjectedCrash, "after RECONCILE approval prepare"):
            policy_authority.approve_policy_change(
                self.root,
                proposal_id=proposal["proposal_id"],
                proposal_sha256=proposal["proposal_sha256"],
                approved_by="reconcile-approver",
                checkpoint=crash_after_prepared,
            )
        approval_path = Path(proposal["payload"]["paths"]["approval"])
        self.assertFalse(approval_path.exists())
        resumed = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="reconcile-approver",
        )
        self.assertTrue(approval_path.is_file())
        self.assertEqual(
            hashlib.sha256(approval_path.read_bytes()).hexdigest(),
            resumed["export_sha256"],
        )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*), MIN(attempt), MAX(attempt), MIN(state) "
                    "FROM policy_change_approvals"
                ).fetchone(),
                (1, 1, 1, "PUBLISHED"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state, owner_kind, owner_proposal_id, owner_approval_id "
                    "FROM policy_mutation_lane WHERE id = 1"
                ).fetchone(),
                (
                    "RESERVED",
                    "POLICY_RECONCILE",
                    proposal["proposal_id"],
                    resumed["approval_id"],
                ),
            )

    def test_edit_required_mode_mismatch_is_effect_zero_before_reserve_and_claim(self):
        _preview, proposal = self._published_edit_proposal()
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "does not match required mode",
        ):
            policy_authority.approve_policy_change(
                self.root,
                proposal_id=proposal["proposal_id"],
                proposal_sha256=proposal["proposal_sha256"],
                approved_by="policy-approver",
                required_sealed_mode="RECONCILE",
            )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_change_approvals"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "IDLE",
            )

        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
            required_sealed_mode="EDIT",
        )
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "does not match required mode",
        ):
            policy_authority.apply_policy_change(
                self.root,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="wrong-family-edit-process",
                required_sealed_mode="RECONCILE",
            )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_change_runs"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state, owner_kind FROM policy_mutation_lane WHERE id = 1"
                ).fetchone(),
                ("RESERVED", "POLICY_EDIT"),
            )

    def test_reconcile_required_mode_mismatch_is_effect_zero_before_reserve(self):
        _external, _guard, _preview, proposal = self._published_reconcile_proposal()
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "does not match required mode",
        ):
            policy_authority.approve_policy_change(
                self.root,
                proposal_id=proposal["proposal_id"],
                proposal_sha256=proposal["proposal_sha256"],
                approved_by="reconcile-approver",
                required_sealed_mode="EDIT",
            )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_change_approvals"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "IDLE",
            )
    def test_raw_only_and_invalid_yaml_drift_bump_guard_and_require_exact_restore(self):
        raw_only_drift = self.initial_registry + b"# external comment\n"
        self._replace_registry(raw_only_drift)
        first = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        self.assertEqual(first["kind"], "FIRST_DRIFT")
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "exact approved raw policy|registry/head equality",
        ):
            policy_authority.clear_policy_drift_equality(
                self.root,
                episode_id=first["episode_id"],
                expected_head_generation=head[0],
                expected_head_full_hash=head[1],
                expected_guard_epoch=head[2],
                cleared_by="policy-operator",
            )
        self._replace_registry(self.initial_registry)
        policy_authority.clear_policy_drift_equality(
            self.root,
            episode_id=first["episode_id"],
            expected_head_generation=head[0],
            expected_head_full_hash=head[1],
            expected_guard_epoch=head[2],
            cleared_by="policy-operator",
        )

        self._replace_registry(b"not: [valid\n")
        invalid = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        self.assertEqual(invalid["kind"], "FIRST_DRIFT")
        observation = json.loads(Path(invalid["observation_path"]).read_bytes())
        self.assertEqual(observation["observation"]["compile_status"], "INVALID")
        self.assertIsNone(observation["observation"]["normalized_full_hash"])
        with self.assertRaises(policy_authority.PolicyAuthorityError):
            policy_authority.verify_normal_policy_authority(self.root)

    def test_equality_clear_rejects_corrupted_terminal_source(self):
        self._replace_registry(self.initial_registry + b"# external drift\n")
        first = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        self._replace_registry(self.initial_registry)
        unexpected = Path(self.initial_result["paths"]["run"]) / "unexpected-source"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)

        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "sealed INITIAL run membership changed",
        ):
            policy_authority.clear_policy_drift_equality(
                self.root,
                episode_id=first["episode_id"],
                expected_head_generation=head[0],
                expected_head_full_hash=head[1],
                expected_guard_epoch=head[2],
                cleared_by="policy-operator",
            )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM policy_guard_episodes WHERE episode_id = ?",
                    (first["episode_id"],),
                ).fetchone()[0],
                "OPEN",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_guard_events WHERE kind = "
                    "'DRIFT_CLEARED_EQUALITY'"
                ).fetchone()[0],
                0,
            )

    def test_equality_clear_final_cas_requires_exact_raw_policy(self):
        self._replace_registry(self.initial_registry + b"# external drift\n")
        first = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        self._replace_registry(self.initial_registry)
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()

        def change_after_event_publish(point):
            if point == "guard-result-published":
                self._replace_registry(
                    self.initial_registry + b"# semantically equal late drift\n"
                )

        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "exact terminal policy source",
        ):
            policy_authority.clear_policy_drift_equality(
                self.root,
                episode_id=first["episode_id"],
                expected_head_generation=head[0],
                expected_head_full_hash=head[1],
                expected_guard_epoch=head[2],
                cleared_by="policy-operator",
                checkpoint=change_after_event_publish,
            )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM policy_guard_episodes WHERE episode_id = ?",
                    (first["episode_id"],),
                ).fetchone()[0],
                "OPEN",
            )

    def test_first_drift_bumps_epoch_before_publish_and_exact_resume_completes_event(self):
        drifted = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        self._replace_registry(drifted)

        def crash_after_guard_bump(point):
            if point == "guard-bumped":
                raise InjectedCrash("after guard bump")

        with self.assertRaisesRegex(InjectedCrash, "after guard bump"):
            policy_authority.observe_policy_drift(
                self.root,
                observed_by="policy-monitor",
                checkpoint=crash_after_guard_bump,
            )

        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
            episode = connection.execute(
                "SELECT episode_id, status, guard_epoch_before, guard_epoch_after "
                "FROM policy_guard_episodes"
            ).fetchone()
            event = connection.execute(
                "SELECT event_id, state, kind, observation_path, result_path "
                "FROM policy_guard_events"
            ).fetchone()
        self.assertEqual(head, (1, 1))
        self.assertEqual(episode[1:], ("OPEN", 0, 1))
        self.assertEqual(event[1:3], ("GUARD_BUMPED", "FIRST_DRIFT"))
        self.assertFalse(Path(event[3]).exists())
        self.assertFalse(Path(event[4]).exists())

        resumed = policy_authority.resume_policy_guard_event(
            self.root,
            event_id=event[0],
            resumed_by="policy-monitor",
        )

        self.assertEqual(resumed["event_id"], event[0])
        self.assertEqual(resumed["episode_id"], episode[0])
        self.assertEqual(resumed["state"], "COMPLETE")
        self.assertTrue(Path(resumed["observation_path"]).is_file())
        self.assertTrue(Path(resumed["result_path"]).is_file())
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT guard_epoch FROM policy_head WHERE id = 1"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_guard_events WHERE event_id = ?",
                    (event[0],),
                ).fetchone()[0],
                "COMPLETE",
            )

    def test_captured_b_drift_bumps_epoch_after_registry_returns_to_a(self):
        drifted = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        self._replace_registry(drifted)
        captured_raw, captured_identity = policy_authority._registry_observation(
            self.root
        )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
        self._replace_registry(self.initial_registry)

        observed = policy_authority.observe_policy_drift_from_stable_observation(
            self.root,
            observed_by="admission-policy-monitor",
            observed_raw=captured_raw,
            observed_identity=captured_identity,
            expected_head_generation=head[0],
            expected_head_full_hash=head[1],
            expected_guard_epoch=head[2],
        )
        observation = json.loads(Path(observed["observation_path"]).read_bytes())
        result = json.loads(Path(observed["result_path"]).read_bytes())
        self.assertEqual(observed["kind"], "FIRST_DRIFT")
        self.assertEqual(
            observation["observation"]["raw_sha256"],
            hashlib.sha256(drifted).hexdigest(),
        )
        self.assertEqual(
            result["final_observation"]["raw_sha256"],
            hashlib.sha256(self.initial_registry).hexdigest(),
        )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT generation, guard_epoch FROM policy_head WHERE id = 1"
                ).fetchone(),
                (1, 1),
            )
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "open policy guard episode",
        ):
            policy_authority.verify_normal_policy_authority(self.root)

    def test_stable_observation_binding_mismatch_is_effect_zero(self):
        drifted = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        self._replace_registry(drifted)
        captured_raw, captured_identity = policy_authority._registry_observation(
            self.root
        )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
        forged = dict(captured_identity)
        forged["raw_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "identity is invalid",
        ):
            policy_authority.observe_policy_drift_from_stable_observation(
                self.root,
                observed_by="admission-policy-monitor",
                observed_raw=captured_raw,
                observed_identity=forged,
                expected_head_generation=head[0],
                expected_head_full_hash=head[1],
                expected_guard_epoch=head[2],
            )
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "head binding changed",
        ):
            policy_authority.observe_policy_drift_from_stable_observation(
                self.root,
                observed_by="admission-policy-monitor",
                observed_raw=captured_raw,
                observed_identity=captured_identity,
                expected_head_generation=head[0],
                expected_head_full_hash=head[1],
                expected_guard_epoch=head[2] + 1,
            )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT guard_epoch FROM policy_head WHERE id = 1"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM policy_guard_episodes"
                ).fetchone()[0],
                0,
            )

    def test_later_observation_does_not_rebump_and_equality_clear_preserves_aba_epoch(self):
        drifted = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        self._replace_registry(drifted)
        first = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        later = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )

        self.assertEqual(first["kind"], "FIRST_DRIFT")
        self.assertEqual(later["kind"], "OBSERVATION")
        self.assertEqual(later["episode_id"], first["episode_id"])
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
            event_count = connection.execute(
                "SELECT COUNT(*) FROM policy_guard_events WHERE episode_id = ?",
                (first["episode_id"],),
            ).fetchone()[0]
        self.assertEqual(head[0], 1)
        self.assertEqual(head[2], 1)
        self.assertEqual(event_count, 2)
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "open policy guard episode",
        ):
            policy_authority.verify_normal_policy_authority(self.root)

        self._replace_registry(self.initial_registry)
        cleared = policy_authority.clear_policy_drift_equality(
            self.root,
            episode_id=first["episode_id"],
            expected_head_generation=head[0],
            expected_head_full_hash=head[1],
            expected_guard_epoch=head[2],
            cleared_by="policy-operator",
        )
        authority = policy_authority.verify_normal_policy_authority(self.root)

        self.assertEqual(cleared["state"], "CLEARED_EQUALITY")
        self.assertEqual(authority["approved_policy_ref"]["generation"], 1)
        self.assertEqual(authority["guard_epoch"], 1)
        self.assertNotEqual(authority["guard_epoch"], 0)
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            episode = connection.execute(
                "SELECT status FROM policy_guard_episodes WHERE episode_id = ?",
                (first["episode_id"],),
            ).fetchone()[0]
            clear_event = connection.execute(
                "SELECT kind, state FROM policy_guard_events "
                "WHERE episode_id = ? ORDER BY rowid DESC LIMIT 1",
                (first["episode_id"],),
            ).fetchone()
        self.assertEqual(episode, "CLEARED_EQUALITY")
        self.assertEqual(clear_event, ("DRIFT_CLEARED_EQUALITY", "COMPLETE"))

    def test_edit_preview_approval_and_apply_publish_only_allowed_nonwriter_policy(self):
        postimage = self._archive_edit_postimage()
        before_registry_info = self.registry_path.stat()

        preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="policy-editor",
            postimage=postimage,
        )
        self.assertEqual(self.registry_path.read_bytes(), self.initial_registry)
        self.assertEqual(preview["mode"], "EDIT")
        self.assertEqual(preview["base"]["generation"], 1)
        self.assertEqual(preview["base"]["guard_epoch"], 0)
        self.assertNotEqual(
            preview["base"]["normalized_full_hash"],
            preview["postimage"]["normalized_full_hash"],
        )

        proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        self.assertEqual(proposal["mode"], "EDIT")
        self.assertEqual(
            Path(proposal["proposal_path"]).read_bytes(),
            canonical_json_bytes(proposal["payload"]),
        )
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            lane = connection.execute(
                "SELECT state, owner_kind, owner_proposal_id, owner_approval_id "
                "FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
        self.assertEqual(
            lane,
            (
                "RESERVED",
                "POLICY_EDIT",
                proposal["proposal_id"],
                approval["approval_id"],
            ),
        )

        result = policy_authority.apply_policy_change(
            self.root,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="edit-process-instance",
        )

        self.assertEqual(result["source_kind"], "EDIT")
        self.assertEqual(result["generation"], 2)
        self.assertEqual(self.registry_path.read_bytes(), postimage)
        self.assertNotEqual(self.registry_path.stat().st_ino, before_registry_info.st_ino)
        run_path = Path(result["paths"]["run"])
        self.assertEqual(
            sorted(path.name for path in run_path.iterdir()),
            [
                "plan.json",
                "policy-parking",
                "policy-postimage",
                "policy-preimage",
                "result.json",
            ],
        )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, source_kind, source_run_id, guard_epoch "
                "FROM policy_head WHERE id = 1"
            ).fetchone()
            approval_state = connection.execute(
                "SELECT state FROM policy_change_approvals WHERE approval_id = ?",
                (approval["approval_id"],),
            ).fetchone()[0]
            run_state = connection.execute(
                "SELECT state FROM policy_change_runs WHERE run_id = ?",
                (result["run_id"],),
            ).fetchone()[0]
            lane_state = connection.execute(
                "SELECT state, owner_kind FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
        self.assertEqual(head[0], 2)
        self.assertEqual(head[1], result["normalized_full_hash"])
        self.assertEqual(head[2], "EDIT")
        self.assertEqual(head[3], result["run_id"])
        self.assertEqual(head[4], 0)
        self.assertEqual(approval_state, "CONSUMED")
        self.assertEqual(run_state, "ACTIVE")
        self.assertEqual(lane_state, ("IDLE", None))

        before_retry = (
            self.registry_path.stat().st_ino,
            tuple(path.name for path in sorted(run_path.iterdir())),
        )
        retried = policy_authority.apply_policy_change(
            self.root,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="edit-process-instance",
        )
        self.assertEqual(retried, result)
        self.assertEqual(
            before_retry,
            (
                self.registry_path.stat().st_ino,
                tuple(path.name for path in sorted(run_path.iterdir())),
            ),
        )
        for changed in (
            {"executed_by": "different-executor"},
            {"process_instance_id": "different-process"},
            {"approval_sha256": "0" * 64},
        ):
            arguments = {
                "approval_id": approval["approval_id"],
                "approval_sha256": approval["export_sha256"],
                "executed_by": "policy-executor",
                "process_instance_id": "edit-process-instance",
            }
            arguments.update(changed)
            with self.assertRaises(policy_authority.PolicyAuthorityError):
                policy_authority.apply_policy_change(self.root, **arguments)

        authority = policy_authority.verify_normal_policy_authority(self.root)
        self.assertEqual(authority["source_result"]["path"], result["paths"]["result"])
        self.assertEqual(
            authority["source_result"]["sha256"],
            hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
        )

    def test_edit_preview_rejects_noop_writer_and_external_workstream_changes(self):
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "no-op generation",
        ):
            policy_authority.preview_policy_change(
                self.root,
                requested_by="policy-editor",
                postimage=self.initial_registry,
            )

        writer_change = self.initial_registry.replace(
            b"  structural_apply: disabled\n",
            b"  structural_apply: curation-gated\n",
            1,
        ).replace(
            b"  movement_writer: legacy\n",
            b"  movement_writer: curation\n",
            1,
        ).replace(
            b"  writer_epoch: legacy-v1\n",
            b"  writer_epoch: cutover-test\n",
            1,
        )
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "writer-control",
        ):
            policy_authority.preview_policy_change(
                self.root,
                requested_by="policy-editor",
                postimage=writer_change,
            )

        lifecycle_change = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "non-curation field: workstreams",
        ):
            policy_authority.preview_policy_change(
                self.root,
                requested_by="policy-editor",
                postimage=lifecycle_change,
            )

    def test_edit_failure_after_claim_is_fail_closed_blocked_recovery(self):
        preview = policy_authority.preview_policy_change(
            self.root,
            requested_by="policy-editor",
            postimage=self._archive_edit_postimage(),
        )
        proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )

        def crash_after_claim(point):
            if point == "claimed":
                raise InjectedCrash("after edit claim")

        with self.assertRaises(policy_authority.PolicyChangeRecoveryRequired) as raised:
            policy_authority.apply_policy_change(
                self.root,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="edit-crash-process",
                checkpoint=crash_after_claim,
            )
        self.assertEqual(raised.exception.mode, "EDIT")
        self.assertEqual(raised.exception.phase, "CLAIMED")
        self.assertIsInstance(raised.exception.cause, InjectedCrash)
        self.assertEqual(self.registry_path.read_bytes(), self.initial_registry)
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            run = connection.execute(
                "SELECT state FROM policy_change_runs WHERE run_id = ?",
                (proposal["run_id"],),
            ).fetchone()[0]
            approval_state = connection.execute(
                "SELECT state FROM policy_change_approvals WHERE approval_id = ?",
                (approval["approval_id"],),
            ).fetchone()[0]
            lane = connection.execute(
                "SELECT state, owner_kind, owner_run_id FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
        self.assertEqual(run, "BLOCKED_RECOVERY")
        self.assertEqual(approval_state, "BLOCKED")
        self.assertEqual(lane, ("BLOCKED_RECOVERY", "POLICY_EDIT", proposal["run_id"]))

    def test_reconcile_adopts_only_proven_external_workstream_change_without_yaml_write(self):
        external = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        ).replace(
            ("    project_home: %s/example-service\n" % self.root).encode("utf-8"),
            ("    project_home: %s/example-service-paused\n" % self.root).encode(
                "utf-8"
            ),
            1,
        )
        self._replace_registry(external)
        guard = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        before_apply = self.registry_path.stat()

        preview = policy_authority.preview_policy_reconcile(
            self.root,
            requested_by="reconcile-requester",
            external_actor="workspace-registry-workflow",
            external_workflow="workstream-lifecycle-update",
        )
        self.assertEqual(preview["mode"], "RECONCILE")
        self.assertEqual(preview["guard_episode"]["episode_id"], guard["episode_id"])
        self.assertEqual(preview["guard_episode"]["guard_epoch"], 1)
        proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="reconcile-approver",
        )
        result = policy_authority.apply_policy_change(
            self.root,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="reconcile-executor",
            process_instance_id="reconcile-process-instance",
        )

        after_apply = self.registry_path.stat()
        self.assertEqual(self.registry_path.read_bytes(), external)
        self.assertEqual(
            (after_apply.st_dev, after_apply.st_ino),
            (before_apply.st_dev, before_apply.st_ino),
        )
        self.assertEqual(result["source_kind"], "RECONCILE")
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["guard_epoch"], 1)
        self.assertEqual(
            sorted(path.name for path in Path(result["paths"]["run"]).iterdir()),
            ["plan.json", "result.json"],
        )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, source_kind, source_run_id, guard_epoch "
                "FROM policy_head WHERE id = 1"
            ).fetchone()
            episode = connection.execute(
                "SELECT status FROM policy_guard_episodes WHERE episode_id = ?",
                (guard["episode_id"],),
            ).fetchone()[0]
            clear_event = connection.execute(
                "SELECT kind, state, observation_path, result_path FROM policy_guard_events "
                "WHERE episode_id = ? AND kind = 'DRIFT_CLEARED_RECONCILED'",
                (guard["episode_id"],),
            ).fetchone()
            approval_state = connection.execute(
                "SELECT state FROM policy_change_approvals WHERE approval_id = ?",
                (approval["approval_id"],),
            ).fetchone()[0]
            run_state = connection.execute(
                "SELECT state FROM policy_change_runs WHERE run_id = ?",
                (result["run_id"],),
            ).fetchone()[0]
            lane_state = connection.execute(
                "SELECT state FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()[0]
        self.assertEqual(head[0], 2)
        self.assertEqual(head[1], result["normalized_full_hash"])
        self.assertEqual(head[2], "RECONCILE")
        self.assertEqual(head[3], result["run_id"])
        self.assertEqual(head[4], 1)
        self.assertEqual(episode, "CLEARED_RECONCILED")
        self.assertEqual(clear_event[:2], ("DRIFT_CLEARED_RECONCILED", "COMPLETE"))
        self.assertTrue(Path(clear_event[2]).is_file())
        self.assertTrue(Path(clear_event[3]).is_file())
        self.assertEqual(approval_state, "CONSUMED")
        self.assertEqual(run_state, "ACTIVE")
        self.assertEqual(lane_state, "IDLE")

        retried = policy_authority.apply_policy_change(
            self.root,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="reconcile-executor",
            process_instance_id="reconcile-process-instance",
        )
        self.assertEqual(retried, result)
        for changed in (
            {"executed_by": "different-executor"},
            {"process_instance_id": "different-process"},
            {"approval_sha256": "0" * 64},
        ):
            arguments = {
                "approval_id": approval["approval_id"],
                "approval_sha256": approval["export_sha256"],
                "executed_by": "reconcile-executor",
                "process_instance_id": "reconcile-process-instance",
            }
            arguments.update(changed)
            with self.assertRaises(policy_authority.PolicyAuthorityError):
                policy_authority.apply_policy_change(self.root, **arguments)

        authority = policy_authority.verify_normal_policy_authority(self.root)
        self.assertEqual(authority["source_result"]["path"], result["paths"]["result"])
        self.assertEqual(
            authority["source_result"]["sha256"],
            hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
        )

    def test_reconcile_requires_fresh_open_episode_and_rejects_curation_drift(self):
        lifecycle = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        self._replace_registry(lifecycle)
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "exactly one OPEN guard episode",
        ):
            policy_authority.preview_policy_reconcile(
                self.root,
                requested_by="reconcile-requester",
                external_actor="workspace-registry-workflow",
                external_workflow="workstream-lifecycle-update",
            )

        curation_drift = lifecycle.replace(
            b"  archive_roots: []\n",
            (
                b"  archive_roots:\n"
                b"    - workstream_id: example-service\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local\n"
                + ("      root: %s/archive/example-service\n" % self.root).encode(
                    "utf-8"
                )
            ),
            1,
        )
        self._replace_registry(curation_drift)
        policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        with self.assertRaisesRegex(
            policy_authority.PolicyAuthorityError,
            "raw drift outside lifecycle/project_home|forbidden drift in field: curation",
        ):
            policy_authority.preview_policy_reconcile(
                self.root,
                requested_by="reconcile-requester",
                external_actor="workspace-registry-workflow",
                external_workflow="workstream-lifecycle-update",
            )

    def test_reconcile_failure_after_claim_blocks_lane_and_leaves_episode_open(self):
        external = self.initial_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        self._replace_registry(external)
        guard = policy_authority.observe_policy_drift(
            self.root,
            observed_by="policy-monitor",
        )
        preview = policy_authority.preview_policy_reconcile(
            self.root,
            requested_by="reconcile-requester",
            external_actor="workspace-registry-workflow",
            external_workflow="workstream-lifecycle-update",
        )
        proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="reconcile-approver",
        )

        def crash_after_claim(point):
            if point == "claimed":
                raise InjectedCrash("after reconcile claim")

        with self.assertRaises(policy_authority.PolicyChangeRecoveryRequired) as raised:
            policy_authority.apply_policy_change(
                self.root,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="reconcile-executor",
                process_instance_id="reconcile-crash-process",
                checkpoint=crash_after_claim,
            )
        self.assertEqual(raised.exception.mode, "RECONCILE")
        self.assertEqual(raised.exception.phase, "CLAIMED")
        self.assertIsInstance(raised.exception.cause, InjectedCrash)
        self.assertEqual(self.registry_path.read_bytes(), external)
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            run_state = connection.execute(
                "SELECT state FROM policy_change_runs WHERE run_id = ?",
                (proposal["run_id"],),
            ).fetchone()[0]
            lane_state = connection.execute(
                "SELECT state, owner_kind FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
            episode_state = connection.execute(
                "SELECT status FROM policy_guard_episodes WHERE episode_id = ?",
                (guard["episode_id"],),
            ).fetchone()[0]
            clear_state = connection.execute(
                "SELECT state FROM policy_guard_events WHERE event_id = ?",
                (preview["guard_episode"]["clear_event_id"],),
            ).fetchone()[0]
        self.assertEqual(run_state, "BLOCKED_RECOVERY")
        self.assertEqual(lane_state, ("BLOCKED_RECOVERY", "POLICY_RECONCILE"))
        self.assertEqual(episode_state, "OPEN")
        self.assertEqual(clear_state, "BLOCKED")

    def test_edit_final_cas_rejects_unexpected_sealed_run_member(self):
        _preview, proposal = self._published_edit_proposal()
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )

        def add_unexpected_member(point):
            if point == "result-published":
                unexpected = Path(proposal["payload"]["paths"]["run_final"]) / "extra"
                unexpected.write_bytes(b"extra")
                unexpected.chmod(0o600)

        with self.assertRaises(policy_authority.PolicyChangeRecoveryRequired) as raised:
            policy_authority.apply_policy_change(
                self.root,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="edit-final-tamper-process",
                checkpoint=add_unexpected_member,
            )
        self.assertEqual(raised.exception.phase, "RESULT_PUBLISHED")
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT generation, source_kind FROM policy_head WHERE id = 1"
                ).fetchone(),
                (1, "INITIAL"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_change_runs WHERE run_id = ?",
                    (proposal["run_id"],),
                ).fetchone()[0],
                "BLOCKED_RECOVERY",
            )

    def test_reconcile_final_cas_rejects_unexpected_symlink_member(self):
        _external, _guard, _preview, proposal = self._published_reconcile_proposal()
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="reconcile-approver",
        )

        def add_unexpected_symlink(point):
            if point == "result-published":
                run_path = Path(proposal["payload"]["paths"]["run_final"])
                (run_path / "extra-link").symlink_to(run_path / "result.json")

        with self.assertRaises(policy_authority.PolicyChangeRecoveryRequired) as raised:
            policy_authority.apply_policy_change(
                self.root,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="reconcile-executor",
                process_instance_id="reconcile-final-tamper-process",
                checkpoint=add_unexpected_symlink,
            )
        self.assertEqual(raised.exception.phase, "RESULT_PUBLISHED")
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT generation, source_kind FROM policy_head WHERE id = 1"
                ).fetchone(),
                (1, "INITIAL"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_change_runs WHERE run_id = ?",
                    (proposal["run_id"],),
                ).fetchone()[0],
                "BLOCKED_RECOVERY",
            )

    def test_python_39_ast_compatibility(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "mnemosyne_core"
            / "policy_authority.py"
        ).read_text(encoding="utf-8")
        ast.parse(source, feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
