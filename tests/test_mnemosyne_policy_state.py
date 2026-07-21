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
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import control, policy, policy_state  # noqa: E402
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


class PolicyBootstrapStateTest(unittest.TestCase):
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

    @staticmethod
    def _sha256(raw):
        return hashlib.sha256(raw).hexdigest()

    def _tree_snapshot(self):
        rows = []
        for path in sorted(self.root.rglob("*")):
            info = path.lstat()
            relative = str(path.relative_to(self.root))
            if stat.S_ISREG(info.st_mode):
                rows.append(
                    (
                        relative,
                        stat.S_IMODE(info.st_mode),
                        self._sha256(path.read_bytes()),
                    )
                )
            else:
                rows.append((relative, stat.S_IMODE(info.st_mode), None))
        return rows

    def _preview(self):
        return policy_state.preview_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            requested_by="policy-requester",
        )

    def _published_proposal(self):
        preview = self._preview()
        proposal = policy_state.publish_policy_bootstrap_proposal(
            self.root,
            bootstrap_id=self.bootstrap_id,
            preview=preview,
        )
        return preview, proposal

    def _published_approval(self):
        preview, proposal = self._published_proposal()
        approval = policy_state.approve_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        return preview, proposal, approval

    def _completed_initial_policy(self, process_instance_id):
        _, _, approval = self._published_approval()
        return policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id=process_instance_id,
        )

    def test_preview_is_exact_read_only_and_separates_raw_and_normalized_hashes(self):
        before = self._tree_snapshot()

        first = self._preview()
        second = self._preview()

        self.assertEqual(first, second)
        self.assertEqual(self._tree_snapshot(), before)
        self.assertEqual(first["kind"], "POLICY_BOOTSTRAP_PREVIEW")
        self.assertEqual(first["base"]["raw_sha256"], self._sha256(self.base_bytes))
        self.assertEqual(
            first["postimage"]["raw_sha256"],
            self._sha256(policy.build_additive_curation_postimage(self.base_bytes, str(self.root))),
        )
        self.assertNotEqual(
            first["postimage"]["raw_sha256"],
            first["postimage"]["normalized_full_sha256"],
        )
        self.assertEqual(first["writer_control"]["movement_writer"], "legacy")
        self.assertEqual(first["writer_control"]["structural_apply"], "disabled")
        self.assertEqual(first["writer_control"]["writer_epoch"], "legacy-v1")
        self.assertEqual(first["approval_ready"], True)

    def test_proposal_is_sealed_and_registry_remains_unchanged(self):
        preview, proposal = self._published_proposal()

        self.assertEqual(self.registry_path.read_bytes(), self.base_bytes)
        self.assertEqual(proposal["kind"], "POLICY_BOOTSTRAP_PROPOSAL")
        self.assertEqual(proposal["preview_sha256"], policy_state.preview_sha256(preview))
        artifact = Path(proposal["paths"]["proposal"])
        self.assertEqual(artifact.read_bytes(), canonical_json_bytes(proposal["payload"]))
        self.assertEqual(self._sha256(artifact.read_bytes()), proposal["proposal_sha256"])
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            row = connection.execute(
                "SELECT state, base_hash, expected_post_hash, payload_json, proposal_sha256 "
                "FROM policy_bootstrap_proposals WHERE proposal_id = ?",
                (proposal["proposal_id"],),
            ).fetchone()
        self.assertEqual(row[0], "PUBLISHED")
        self.assertEqual(row[1], preview["base"]["raw_sha256"])
        self.assertEqual(row[2], preview["postimage"]["raw_sha256"])
        self.assertEqual(row[3], canonical_json_bytes(proposal["payload"]))
        self.assertEqual(row[4], proposal["proposal_sha256"])

    def test_approval_reserves_lane_and_publishes_exact_export(self):
        _, proposal, approval = self._published_approval()

        self.assertEqual(approval["kind"], "POLICY_BOOTSTRAP_APPROVAL")
        artifact = Path(approval["export_path"])
        self.assertEqual(artifact.read_bytes(), canonical_json_bytes(approval["payload"]))
        self.assertEqual(self._sha256(artifact.read_bytes()), approval["export_sha256"])
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            approval_row = connection.execute(
                "SELECT proposal_id, approved_by, state FROM policy_bootstrap_approvals "
                "WHERE approval_id = ?",
                (approval["approval_id"],),
            ).fetchone()
            lane = connection.execute(
                "SELECT state, owner_kind, owner_proposal_id, owner_approval_id, "
                "owner_run_id FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
        self.assertEqual(approval_row, (proposal["proposal_id"], "policy-approver", "PUBLISHED"))
        self.assertEqual(
            lane,
            ("RESERVED", "INITIAL", proposal["proposal_id"], approval["approval_id"], None),
        )

    def test_proposal_and_approval_publication_are_exactly_idempotent(self):
        preview = self._preview()
        first_proposal = policy_state.publish_policy_bootstrap_proposal(
            self.root,
            bootstrap_id=self.bootstrap_id,
            preview=preview,
        )
        second_proposal = policy_state.publish_policy_bootstrap_proposal(
            self.root,
            bootstrap_id=self.bootstrap_id,
            preview=preview,
        )
        self.assertEqual(first_proposal, second_proposal)

        first_approval = policy_state.approve_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            proposal_id=first_proposal["proposal_id"],
            proposal_sha256=first_proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        second_approval = policy_state.approve_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            proposal_id=first_proposal["proposal_id"],
            proposal_sha256=first_proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        self.assertEqual(first_approval, second_approval)

    def test_approval_publication_crash_resumes_exact_reserved_export(self):
        _, proposal = self._published_proposal()

        def crash(point):
            if point == "approval-prepared":
                raise InjectedCrash(point)

        with self.assertRaises(
            policy_state.PolicyBootstrapPublicationIncomplete
        ) as caught:
            policy_state.approve_policy_bootstrap(
                self.root,
                bootstrap_id=self.bootstrap_id,
                proposal_id=proposal["proposal_id"],
                proposal_sha256=proposal["proposal_sha256"],
                approved_by="policy-approver",
                checkpoint=crash,
            )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_bootstrap_approvals WHERE approval_id = ?",
                    (caught.exception.approval_id,),
                ).fetchone()[0],
                "PREPARED",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "RESERVED",
            )

        resumed = policy_state.approve_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        self.assertEqual(resumed["approval_id"], caught.exception.approval_id)
        self.assertTrue(Path(resumed["export_path"]).is_file())

    def test_apply_publishes_additive_policy_and_terminal_g0l_authority(self):
        preview, proposal, approval = self._published_approval()
        checkpoints = []

        result = policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="process-0001",
            checkpoint=checkpoints.append,
        )

        expected_postimage = policy.build_additive_curation_postimage(
            self.base_bytes, str(self.root)
        )
        compiled = policy.compile_policy(expected_postimage, str(self.root))
        self.assertEqual(self.registry_path.read_bytes(), expected_postimage)
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["raw_hash"], self._sha256(expected_postimage))
        self.assertEqual(result["normalized_full_hash"], compiled.full_hash)
        self.assertEqual(result["approved_by"], "policy-approver")
        self.assertEqual(result["executed_by"], "policy-executor")
        self.assertEqual(result["source_kind"], "INITIAL")
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["guard_epoch"], 0)
        self.assertEqual(Path(result["paths"]["result"]).read_bytes(), canonical_json_bytes(result))
        self.assertFalse(Path(proposal["paths"]["run_staging"]).exists())
        self.assertTrue(Path(proposal["paths"]["run_final"]).is_dir())
        self.assertIn("placement-lock-acquired", checkpoints)
        self.assertLess(
            checkpoints.index("placement-lock-acquired"),
            checkpoints.index("ledger-lock-acquired"),
        )
        self.assertLess(
            checkpoints.index("ledger-lock-acquired"),
            checkpoints.index("policy-published"),
        )

        authority = policy_state.verify_initial_policy_authority(
            self.root,
            bootstrap_id=self.bootstrap_id,
        )
        self.assertEqual(authority["approved_policy_ref"]["generation"], 1)
        self.assertEqual(authority["approved_policy_ref"]["full_hash"], compiled.full_hash)
        self.assertEqual(authority["approved_policy_ref"]["source_kind"], "INITIAL")
        self.assertEqual(authority["approved_policy_ref"]["source_run_id"], result["run_id"])
        self.assertEqual(authority["guard_epoch"], 0)
        self.assertEqual(authority["raw_hash"], self._sha256(expected_postimage))

        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            head = connection.execute(
                "SELECT generation, full_hash, source_kind, source_run_id, guard_epoch "
                "FROM policy_head WHERE id = 1"
            ).fetchone()
            run = connection.execute(
                "SELECT state, result_sha256, expected_post_hash, executed_by "
                "FROM policy_bootstrap_runs WHERE run_id = ?",
                (result["run_id"],),
            ).fetchone()
            approval_state = connection.execute(
                "SELECT state FROM policy_bootstrap_approvals WHERE approval_id = ?",
                (approval["approval_id"],),
            ).fetchone()[0]
            lane = connection.execute(
                "SELECT state, owner_kind, owner_run_id FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
        self.assertEqual(head, (1, compiled.full_hash, "INITIAL", result["run_id"], 0))
        self.assertEqual(run[0], "ACTIVE")
        self.assertEqual(run[1], self._sha256(canonical_json_bytes(result)))
        self.assertEqual(run[2], self._sha256(expected_postimage))
        self.assertEqual(run[3], "policy-executor")
        self.assertEqual(approval_state, "CONSUMED")
        self.assertEqual(lane, ("IDLE", None, None))

        retried = policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="process-0001",
        )
        self.assertEqual(retried, result)

    def test_apply_blocks_preclaim_when_registry_base_drifted(self):
        _, _, approval = self._published_approval()
        drifted = self.base_bytes + b"# external drift\n"
        self.registry_path.write_bytes(drifted)

        with self.assertRaises(policy_state.PolicyStateError):
            policy_state.apply_policy_bootstrap(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="process-drift",
            )

        self.assertEqual(self.registry_path.read_bytes(), drifted)
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM policy_bootstrap_runs").fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_bootstrap_approvals WHERE approval_id = ?",
                    (approval["approval_id"],),
                ).fetchone()[0],
                "PUBLISHED",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "RESERVED",
            )

    def test_apply_blocks_before_claim_when_approval_export_changed(self):
        _, _, approval = self._published_approval()
        approval_path = Path(approval["export_path"])
        approval_path.write_bytes(b"{}\n")

        with self.assertRaises(policy_state.PolicyStateError):
            policy_state.apply_policy_bootstrap(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="process-bad-approval",
            )

        self.assertEqual(self.registry_path.read_bytes(), self.base_bytes)
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM policy_bootstrap_runs").fetchone()[0],
                0,
            )

    def test_apply_requires_historical_preimage_verifier_before_effect(self):
        _, _, approval = self._published_approval()

        with mock.patch.object(
            policy_state,
            "_verify_control_preimage",
            side_effect=policy_state.PolicyStateError("blocked preimage"),
        ) as verifier:
            with self.assertRaises(policy_state.PolicyStateError):
                policy_state.apply_policy_bootstrap(
                    self.root,
                    bootstrap_id=self.bootstrap_id,
                    approval_id=approval["approval_id"],
                    approval_sha256=approval["export_sha256"],
                    executed_by="policy-executor",
                    process_instance_id="process-no-preimage",
                )

        verifier.assert_called_once_with(self.root, self.bootstrap_id)
        self.assertEqual(self.registry_path.read_bytes(), self.base_bytes)
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM policy_bootstrap_runs").fetchone()[0],
                0,
            )

    def test_postclaim_crash_fails_closed_without_inventing_head(self):
        preview, proposal, approval = self._published_approval()

        def crash(point):
            if point == "policy-published":
                raise InjectedCrash(point)

        with self.assertRaises(policy_state.PolicyBootstrapRecoveryRequired) as caught:
            policy_state.apply_policy_bootstrap(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="process-crash",
                checkpoint=crash,
            )

        self.assertEqual(caught.exception.phase, "POLICY_PUBLISHED")
        self.assertEqual(
            self._sha256(self.registry_path.read_bytes()),
            preview["postimage"]["raw_sha256"],
        )
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM policy_head").fetchone()[0], 0)
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_bootstrap_approvals WHERE approval_id = ?",
                    (approval["approval_id"],),
                ).fetchone()[0],
                "CLAIMED",
            )
            run = connection.execute(
                "SELECT state FROM policy_bootstrap_runs WHERE run_id = ?",
                (proposal["run_id"],),
            ).fetchone()[0]
            lane = connection.execute(
                "SELECT state FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()[0]
        self.assertEqual(run, "BLOCKED_RECOVERY")
        self.assertEqual(lane, "BLOCKED_RECOVERY")

    def test_claimed_checkpoint_exception_is_wrapped_and_terminally_blocked(self):
        _, proposal, approval = self._published_approval()

        def crash(point):
            if point == "claimed":
                raise InjectedCrash(point)

        with self.assertRaises(
            policy_state.PolicyBootstrapRecoveryRequired
        ) as caught:
            policy_state.apply_policy_bootstrap(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="process-claimed-crash",
                checkpoint=crash,
            )

        self.assertEqual(caught.exception.phase, "CLAIMED")
        self.assertIsInstance(caught.exception.cause, InjectedCrash)
        self.assertEqual(self.registry_path.read_bytes(), self.base_bytes)
        self.assertFalse(Path(proposal["paths"]["run_staging"]).exists())
        self.assertFalse(Path(proposal["paths"]["run_final"]).exists())
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_bootstrap_runs WHERE run_id = ?",
                    (proposal["run_id"],),
                ).fetchone()[0],
                "BLOCKED_RECOVERY",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "BLOCKED_RECOVERY",
            )

    def test_final_cas_rejects_sealed_run_membership_change(self):
        _, proposal, approval = self._published_approval()

        def inject_unexpected_member(point):
            if point == "result-published":
                unexpected = (
                    Path(proposal["paths"]["run_final"])
                    / "unexpected-before-final-cas"
                )
                unexpected.write_bytes(b"unexpected")
                unexpected.chmod(0o600)

        with self.assertRaises(
            policy_state.PolicyBootstrapRecoveryRequired
        ) as caught:
            policy_state.apply_policy_bootstrap(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="process-sealed-final-cas",
                checkpoint=inject_unexpected_member,
            )

        self.assertEqual(caught.exception.phase, "RESULT_PUBLISHED")
        self.assertEqual(caught.exception.run_id, proposal["run_id"])
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM policy_head").fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_bootstrap_runs WHERE run_id = ?",
                    (proposal["run_id"],),
                ).fetchone()[0],
                "BLOCKED_RECOVERY",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "BLOCKED_RECOVERY",
            )

    def test_abrupt_restart_surfaces_existing_policy_published_recovery_state(self):
        _, proposal, approval = self._published_approval()

        def terminate(point):
            if point == "policy-published":
                raise SystemExit("simulated process death")

        with self.assertRaises(SystemExit):
            policy_state.apply_policy_bootstrap(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="process-abrupt",
                checkpoint=terminate,
            )

        with self.assertRaises(
            policy_state.PolicyBootstrapRecoveryRequired
        ) as caught:
            policy_state.apply_policy_bootstrap(
                self.root,
                bootstrap_id=self.bootstrap_id,
                approval_id=approval["approval_id"],
                approval_sha256=approval["export_sha256"],
                executed_by="policy-executor",
                process_instance_id="process-abrupt",
            )
        self.assertEqual(caught.exception.run_id, proposal["run_id"])
        self.assertEqual(caught.exception.phase, "POLICY_PUBLISHED")
        with closing(sqlite3.connect(str(self.ledger_path))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM policy_head").fetchone()[0], 0)
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0],
                "ACTIVE",
            )

    def test_raw_byte_drift_invalidates_even_when_normalized_policy_is_equal(self):
        _, _, approval = self._published_approval()
        policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="process-raw-drift",
        )
        current = self.registry_path.read_bytes()
        self.registry_path.write_bytes(current + b"# same semantics, different raw bytes\n")

        with self.assertRaises(policy_state.PolicyStateError):
            policy_state.verify_initial_policy_authority(
                self.root,
                bootstrap_id=self.bootstrap_id,
            )

    def test_g0l_rejects_tampered_sealed_run_evidence(self):
        _, _, approval = self._published_approval()
        result = policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="process-tamper",
        )
        plan_path = Path(result["paths"]["plan"])
        plan_path.write_bytes(plan_path.read_bytes() + b"tamper")

        with self.assertRaises(policy_state.PolicyStateError):
            policy_state.verify_initial_policy_authority(
                self.root,
                bootstrap_id=self.bootstrap_id,
            )

    def test_g0l_rejects_unexpected_regular_sealed_run_member(self):
        result = self._completed_initial_policy("process-extra-regular")
        unexpected = Path(result["paths"]["run"]) / "unexpected.txt"
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)

        with self.assertRaisesRegex(
            policy_state.PolicyStateError,
            "sealed INITIAL run membership changed",
        ):
            policy_state.verify_initial_policy_authority(
                self.root,
                bootstrap_id=self.bootstrap_id,
            )

    def test_g0l_rejects_unexpected_directory_run_member(self):
        result = self._completed_initial_policy("process-extra-directory")
        unexpected = Path(result["paths"]["run"]) / "unexpected-directory"
        unexpected.mkdir(mode=0o700)

        with self.assertRaisesRegex(
            policy_state.PolicyStateError,
            "sealed INITIAL run membership changed",
        ):
            policy_state.verify_initial_policy_authority(
                self.root,
                bootstrap_id=self.bootstrap_id,
            )

    def test_g0l_rejects_unexpected_symlink_run_member(self):
        result = self._completed_initial_policy("process-extra-symlink")
        unexpected = Path(result["paths"]["run"]) / "unexpected-symlink"
        unexpected.symlink_to("plan.json")

        with self.assertRaisesRegex(
            policy_state.PolicyStateError,
            "sealed INITIAL run membership changed",
        ):
            policy_state.verify_initial_policy_authority(
                self.root,
                bootstrap_id=self.bootstrap_id,
            )

    def test_g0l_rejects_deleted_sealed_run_member(self):
        result = self._completed_initial_policy("process-missing-member")
        Path(result["paths"]["plan"]).unlink()

        with self.assertRaisesRegex(
            policy_state.PolicyStateError,
            "sealed INITIAL run membership changed",
        ):
            policy_state.verify_initial_policy_authority(
                self.root,
                bootstrap_id=self.bootstrap_id,
            )

    def test_g0l_rejects_swapped_sealed_run_member(self):
        result = self._completed_initial_policy("process-swapped-member")
        plan_path = Path(result["paths"]["plan"])
        replacement = plan_path.with_name("replacement.tmp")
        replacement.write_bytes(
            Path(result["paths"]["policy_preimage"]).read_bytes()
        )
        replacement.chmod(0o600)
        os.replace(replacement, plan_path)

        with self.assertRaises(policy_state.PolicyStateError):
            policy_state.verify_initial_policy_authority(
                self.root,
                bootstrap_id=self.bootstrap_id,
            )

    def test_g0l_rejects_member_swapped_during_sealed_verification(self):
        result = self._completed_initial_policy("process-swap-during-read")
        original_reader = policy_state.safety.read_regular_file_at
        swapped = False

        def swap_after_plan_read(*args, **kwargs):
            nonlocal swapped
            info, raw = original_reader(*args, **kwargs)
            name = args[1]
            if name == "plan.json" and not swapped:
                swapped = True
                replacement = self.root / "replacement-plan"
                replacement.write_bytes(b"different-plan")
                replacement.chmod(0o600)
                os.replace(replacement, Path(result["paths"]["plan"]))
            return info, raw

        with (
            mock.patch.object(
                policy_state.safety,
                "read_regular_file_at",
                side_effect=swap_after_plan_read,
            ),
            self.assertRaisesRegex(
                policy_state.PolicyStateError,
                "changed during verification",
            ),
        ):
            policy_state.verify_initial_policy_authority(
                self.root,
                bootstrap_id=self.bootstrap_id,
            )
        self.assertTrue(swapped)

    def test_python_39_ast_compatibility(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "mnemosyne_core"
            / "policy_state.py"
        ).read_text(encoding="utf-8")
        ast.parse(source, feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
