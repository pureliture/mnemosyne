import argparse
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402


class MnemosyneM1IntegrationTest(unittest.TestCase):
    @staticmethod
    def _command_args(**kwargs):
        return argparse.Namespace(**kwargs)

    @staticmethod
    def _inventory_workflow_report(root, operation="start"):
        approved = mnemosyne._admission_core.ApprovedPolicyRef(
            raw_hash="a" * 64,
            full_hash="b" * 64,
            writer_control_hash="c" * 64,
            foundation_hash="d" * 64,
            generation=1,
            source_kind="INITIAL",
            source_run_id="polrun-source",
            guard_epoch=0,
        )
        terminal = mnemosyne._inventory_core.InventoryTerminal(
            run_id="inventory-run-001",
            state="complete",
            path=str(root / "_registry" / "curation-runs" / "inventory-run-001"),
            package_sha256="e" * 64,
        )
        return mnemosyne._inventory_workflow_core.InventoryWorkflowReport(
            operation=operation,
            request_sha256="f" * 64,
            scope_hash="1" * 64,
            approved_policy=approved,
            terminal=terminal,
        )

    def test_verified_runtime_closure_contains_all_m1_core_modules(self):
        runtime_paths = [
            relative_path
            for _name, relative_path, _package in mnemosyne.RUNTIME_MODULE_CLOSURE
        ]
        self.assertEqual(
            runtime_paths[:24],
            [
                "__init__.py",
                "canonical_json.py",
                "safety.py",
                "policy.py",
                "context_assembly.py",
                "operation_contract/__init__.py",
                "operation_contract/codec.py",
                "artifact_contract/__init__.py",
                "artifact_contract/compatibility.py",
                "librarian_contract.py",
                "librarian_projection.py",
                "operation_control/__init__.py",
                "operation_control/catalog.py",
                "authority_runtime/__init__.py",
                "control.py",
                "ledger_schema.py",
                "activation_foundation.py",
                "activation_contract.py",
                "activation_markers.py",
                "inventory.py",
                "policy_state.py",
                "policy_authority.py",
                "admission.py",
                "inventory_workflow.py",
            ],
        )
        self.assertEqual(
            runtime_paths[24:],
            [
                "classification.py",
                "routing_risk.py",
                "references.py",
                "review_units.py",
                "review_compiler.py",
                "review_package.py",
                "canonical_curation.py",
                "canonical_curation_review.py",
                "canonical_curation_m3.py",
                "canonical_curation_m3_review.py",
                "projection_refresh.py",
                "review_snapshot.py",
                "review_context.py",
                "review_draft.py",
                "campaign_ledger.py",
                "batch_event_contract.py",
                "m3_schema.py",
                "ledger_runtime.py",
                "curation_audit.py",
                "authority_runtime/activation.py",
                "authority_runtime/_durable_snapshot.py",
                "authority_runtime/durable.py",
                "authority_runtime/librarian.py",
                "authority_runtime/librarian_snapshot.py",
                "authority_runtime/canonical_curation.py",
                "authority_runtime/canonical_curation_m3.py",
                "authority_runtime/auxiliary_index.py",
                "authority_runtime/workstream_inspection.py",
                "workstream_curation.py",
                "navigation_draft.py",
                "curation_scheduler.py",
                "authority_runtime/session.py",
                "schema_migration.py",
                "decision_service.py",
                "deferral_service.py",
                "legacy_import.py",
                "batch_service.py",
                "run_review.py",
                "m2_publishers.py",
                "review_state.py",
                "explode_service.py",
                "m2_workflow.py",
                "m3_schema_migration.py",
                "batch_event_service.py",
                "split_batch_service.py",
                "m4_workflow.py",
                "progress_query.py",
                "curation_inspect_query.py",
                "review_submission.py",
                "deferral_store.py",
                "m3_workflow.py",
                "curation_contract.py",
                "curation_inspect.py",
                "inspect_audit_operation.py",
                "librarian_inspection.py",
                "librarian_records.py",
                "librarian_placement.py",
                "operation_control/composition.py",
                "operation_control/execution.py",
                "cli/__init__.py",
                "cli/canonical_file.py",
                "cli/dispatch.py",
                "cli/request_builder.py",
                "cli/context_activation.py",
                "cli/inspect.py",
                "cli/guide.py",
            ],
        )
        for binding in (
            "_policy_core",
            "_control_core",
            "_inventory_core",
            "_policy_state_core",
            "_policy_authority_core",
            "_admission_core",
            "_inventory_workflow_core",
            "_m2_workflow_core",
            "_m3_workflow_core",
        ):
            with self.subTest(binding=binding):
                self.assertTrue(hasattr(mnemosyne, binding))

    def test_policy_drift_commands_call_guard_service_and_return_exact_reports(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            observed = {
                "kind": "FIRST_DRIFT",
                "event_id": "pgevent-001",
                "episode_id": "pgepisode-001",
                "guard_epoch": 1,
                "observation_path": str(root / "observation.json"),
                "observation_sha256": "a" * 64,
                "result_path": str(root / "result.json"),
                "result_sha256": "b" * 64,
                "state": "COMPLETE",
            }
            with mock.patch.object(
                mnemosyne._policy_authority_core,
                "observe_policy_drift",
                return_value=observed,
            ) as observe_call:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = mnemosyne.command_record_policy_drift(
                        self._command_args(
                            observed_by="monitor",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            observe_call.assert_called_once_with(root, observed_by="monitor")
            report = json.loads(output.getvalue())
            self.assertEqual(set(report), set(mnemosyne.OPERATION_REPORT_KEYS))
            self.assertEqual(report["mode"], "record-policy-drift")
            self.assertEqual(report["registry_updates"][0]["event_id"], "pgevent-001")
            self.assertEqual(report["content_placement_writes"], [])
            self.assertIn("raw corpus", report["not_modified"])

            cleared = {
                "kind": "DRIFT_CLEARED_EQUALITY",
                "episode_id": "pgepisode-001",
                "event_id": "pgevent-clear",
                "head_generation": 2,
                "head_full_hash": "c" * 64,
                "guard_epoch": 1,
                "result_path": str(root / "clear-result.json"),
                "result_sha256": "d" * 64,
                "state": "CLEARED_EQUALITY",
            }
            with mock.patch.object(
                mnemosyne._policy_authority_core,
                "clear_policy_drift_equality",
                return_value=cleared,
            ) as clear_call:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = mnemosyne.command_clear_policy_drift(
                        self._command_args(
                            episode_id="pgepisode-001",
                            expected_head_generation=2,
                            expected_head_full_hash="c" * 64,
                            expected_guard_epoch=1,
                            cleared_by="operator",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            clear_call.assert_called_once_with(
                root,
                episode_id="pgepisode-001",
                expected_head_generation=2,
                expected_head_full_hash="c" * 64,
                expected_guard_epoch=1,
                cleared_by="operator",
            )
            self.assertEqual(json.loads(output.getvalue())["mode"], "clear-policy-drift")

    def test_policy_edit_preview_reads_verified_postimage_and_publishes_proposal(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            postimage_path = Path(temporary) / "policy-postimage.yml"
            postimage = b"policy postimage\n"
            postimage_path.write_bytes(postimage)
            postimage_path.chmod(0o600)
            preview = {
                "mode": "EDIT",
                "preview_id": "polchgprev-preview",
                "proposal_id": "polchg-proposal",
                "proposal_generation": 2,
                "run_id": "polchgrun-run",
                "approval_id": "polchgappr-approval",
                "base": {
                    "generation": 1,
                    "normalized_full_hash": "a" * 64,
                    "raw_sha256": "b" * 64,
                    "guard_epoch": 0,
                },
                "postimage": {
                    "raw_sha256": "c" * 64,
                    "normalized_full_hash": "d" * 64,
                    "writer_control_hash": "e" * 64,
                    "foundation_hash": "f" * 64,
                },
                "approval_ready": True,
            }
            proposal = {
                "mode": "EDIT",
                "proposal_id": "polchg-proposal",
                "proposal_sha256": "1" * 64,
                "proposal_path": str(root / "proposal.json"),
                "run_id": "polchgrun-run",
                "approval_id": "polchgappr-approval",
                "state": "PUBLISHED",
            }
            with (
                mock.patch.object(
                    mnemosyne._policy_authority_core,
                    "preview_policy_change",
                    return_value=preview,
                ) as preview_call,
                mock.patch.object(
                    mnemosyne._policy_authority_core,
                    "publish_policy_change_proposal",
                    return_value=proposal,
                ) as publish_call,
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    status = mnemosyne.command_preview_policy_change(
                        self._command_args(
                            postimage_file=str(postimage_path),
                            requested_by="editor",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            preview_call.assert_called_once_with(
                root,
                requested_by="editor",
                postimage=postimage,
            )
            publish_call.assert_called_once_with(root, preview=preview)
            report = json.loads(output.getvalue())
            self.assertEqual(set(report), set(mnemosyne.OPERATION_REPORT_KEYS))
            self.assertEqual(report["mode"], "preview-policy-change")
            self.assertEqual(report["registry_updates"][0]["proposal_sha256"], "1" * 64)
            self.assertEqual(report["content_placement_writes"], [])

    def test_reconcile_facade_narrows_immutable_mode_before_approval_and_apply(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            approval = {
                "mode": "RECONCILE",
                "approval_id": "polchgappr-approval",
                "export_sha256": "a" * 64,
                "proposal_id": "polchg-proposal",
                "run_id": "polchgrun-run",
                "state": "PUBLISHED",
            }
            with mock.patch.object(
                mnemosyne._policy_authority_core,
                "approve_policy_change",
                return_value=approval,
            ) as approve_call:
                with redirect_stdout(io.StringIO()):
                    status = mnemosyne.command_approve_policy_reconcile(
                        self._command_args(
                            proposal_id="polchg-proposal",
                            proposal_sha256="b" * 64,
                            approved_by="approver",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            approve_call.assert_called_once_with(
                root,
                proposal_id="polchg-proposal",
                proposal_sha256="b" * 64,
                approved_by="approver",
                required_sealed_mode="RECONCILE",
            )

            result = {
                "source_kind": "RECONCILE",
                "status": "COMPLETE",
                "generation": 2,
                "guard_epoch": 1,
                "proposal_id": "polchg-proposal",
                "approval_id": "polchgappr-approval",
                "run_id": "polchgrun-run",
                "raw_hash": "c" * 64,
                "normalized_full_hash": "d" * 64,
                "writer_control_hash": "e" * 64,
                "foundation_hash": "f" * 64,
                "yaml_write_effects": 0,
                "paths": {"run": str(root / "run")},
            }
            process_ids = []

            def apply_side_effect(*_args, **kwargs):
                process_ids.append(kwargs["process_instance_id"])
                return result

            with mock.patch.object(
                mnemosyne._policy_authority_core,
                "apply_policy_change",
                side_effect=apply_side_effect,
            ) as apply_call:
                for _ in range(2):
                    with redirect_stdout(io.StringIO()):
                        status = mnemosyne.command_apply_policy_reconcile(
                            self._command_args(
                                approval_id="polchgappr-approval",
                                approval_sha256="a" * 64,
                                executed_by="operator",
                                root=str(root),
                                json=True,
                            )
                        )
                    self.assertEqual(status, 0)
            self.assertEqual(process_ids[0], process_ids[1])
            self.assertTrue(process_ids[0].startswith("policy-change-cli-"))
            self.assertEqual(apply_call.call_count, 2)
            self.assertEqual(
                apply_call.call_args.kwargs["required_sealed_mode"],
                "RECONCILE",
            )

    def test_reconcile_preview_and_guard_resume_delegate_exact_inputs(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            preview = {
                "mode": "RECONCILE",
                "proposal_id": "polchg-proposal",
                "base": {"generation": 1},
                "postimage": {"raw_sha256": "a" * 64},
                "guard_episode": {"episode_id": "pgepisode-001"},
                "external_provenance": {
                    "actor": "registry-workflow",
                    "workflow": "lifecycle-update",
                },
                "approval_ready": True,
            }
            proposal = {
                "mode": "RECONCILE",
                "proposal_id": "polchg-proposal",
                "proposal_sha256": "b" * 64,
                "proposal_path": str(root / "proposal.json"),
                "run_id": "polchgrun-run",
                "approval_id": "polchgappr-approval",
                "state": "PUBLISHED",
            }
            with (
                mock.patch.object(
                    mnemosyne._policy_authority_core,
                    "preview_policy_reconcile",
                    return_value=preview,
                ) as preview_call,
                mock.patch.object(
                    mnemosyne._policy_authority_core,
                    "publish_policy_change_proposal",
                    return_value=proposal,
                ) as publish_call,
            ):
                with redirect_stdout(io.StringIO()):
                    status = mnemosyne.command_preview_policy_reconcile(
                        self._command_args(
                            requested_by="requester",
                            external_actor="registry-workflow",
                            external_workflow="lifecycle-update",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            preview_call.assert_called_once_with(
                root,
                requested_by="requester",
                external_actor="registry-workflow",
                external_workflow="lifecycle-update",
            )
            publish_call.assert_called_once_with(root, preview=preview)

            resumed = {
                "kind": "FIRST_DRIFT",
                "event_id": "pgevent-001",
                "episode_id": "pgepisode-001",
                "guard_epoch": 1,
                "state": "COMPLETE",
            }
            with mock.patch.object(
                mnemosyne._policy_authority_core,
                "resume_policy_guard_event",
                return_value=resumed,
            ) as resume_call:
                with redirect_stdout(io.StringIO()):
                    status = mnemosyne.command_resume_policy_guard_event(
                        self._command_args(
                            event_id="pgevent-001",
                            resumed_by="operator",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            resume_call.assert_called_once_with(
                root,
                event_id="pgevent-001",
                resumed_by="operator",
            )

    def test_policy_change_manual_recovery_is_persisted_under_outer_guard(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            cause = mnemosyne.ManualRecoveryRequired(
                "policy change rename requires manual recovery",
                source=root / "_registry" / "placement-map.yml",
                target=root / "policy-parking",
                reason="ambiguous policy change compensation",
                expected_source_identity=(1, 2, 3),
                observed_target_identity=None,
            )
            recovery = mnemosyne._policy_authority_core.PolicyChangeRecoveryRequired(
                "policy change requires recovery",
                mode="EDIT",
                phase="POLICY_PARKED",
                run_id="polchgrun-run",
                cause=cause,
            )
            with mock.patch.object(
                mnemosyne._policy_authority_core,
                "apply_policy_change",
                side_effect=recovery,
            ):
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "blocker_sha256",
                ) as raised:
                    mnemosyne.command_apply_policy_change(
                        self._command_args(
                            approval_id="polchgappr-approval",
                            approval_sha256="a" * 64,
                            executed_by="operator",
                            root=str(root),
                            json=False,
                        )
                    )
            blockers = list(
                (root / "_registry" / "lock-migrations" / "manual-recovery").glob(
                    "*.json"
                )
            )
            self.assertEqual(len(blockers), 1)
            payload = json.loads(blockers[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "POLICY_CHANGE_RENAME_MANUAL_RECOVERY")
            self.assertIn("blocker_sha256", str(raised.exception))

    def test_inventory_command_calls_workflow_and_returns_exact_operation_report(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            workflow_report = self._inventory_workflow_report(root)
            with mock.patch.object(
                mnemosyne._inventory_workflow_core,
                "start_inventory",
                return_value=workflow_report,
            ) as start_call:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = mnemosyne.command_inventory(
                        self._command_args(
                            bootstrap_id="curboot-initial",
                            run_id="inventory-run-001",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            start_call.assert_called_once_with(
                root,
                bootstrap_id="curboot-initial",
                run_id="inventory-run-001",
            )
            report = json.loads(output.getvalue())
            self.assertEqual(set(report), set(mnemosyne.OPERATION_REPORT_KEYS))
            self.assertEqual(report["mode"], "inventory")
            update = report["registry_updates"][0]
            self.assertEqual(update["run_id"], "inventory-run-001")
            self.assertEqual(update["state"], "complete")
            self.assertEqual(update["package_sha256"], "e" * 64)
            self.assertEqual(report["content_placement_writes"], [])
            self.assertIn("raw corpus", report["not_modified"])
            self.assertFalse(report["needs_review"][0]["openable"])
            self.assertFalse(report["needs_review"][0]["approval_ready"])

    def test_resume_inventory_command_uses_exact_run_and_reports_resume_mode(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            workflow_report = self._inventory_workflow_report(root, operation="resume")
            with mock.patch.object(
                mnemosyne._inventory_workflow_core,
                "resume_inventory",
                return_value=workflow_report,
            ) as resume_call:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = mnemosyne.command_resume_inventory(
                        self._command_args(
                            bootstrap_id="curboot-initial",
                            run_id="inventory-run-001",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            resume_call.assert_called_once_with(
                root,
                bootstrap_id="curboot-initial",
                run_id="inventory-run-001",
            )
            report = json.loads(output.getvalue())
            self.assertEqual(report["mode"], "resume-inventory")
            self.assertEqual(report["registry_updates"][0]["run_id"], "inventory-run-001")

    def test_policy_preview_command_seals_proposal_and_reports_exact_binding(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            preview = {
                "preview_id": "polprev-preview",
                "proposal_id": "polboot-proposal",
                "run_id": "polrun-run",
                "approval_ready": True,
                "postimage": {"raw_sha256": "a" * 64},
                "writer_control": {
                    "movement_writer": "legacy",
                    "structural_apply": "disabled",
                    "writer_epoch": "legacy-v1",
                },
                "paths": {"proposal": str(root / "proposal.json")},
            }
            proposal = {
                "proposal_id": "polboot-proposal",
                "proposal_sha256": "b" * 64,
                "preview_sha256": "c" * 64,
                "run_id": "polrun-run",
                "state": "PUBLISHED",
                "paths": preview["paths"],
            }
            with (
                mock.patch.object(
                    mnemosyne._policy_state_core,
                    "preview_policy_bootstrap",
                    return_value=preview,
                ) as preview_call,
                mock.patch.object(
                    mnemosyne._policy_state_core,
                    "publish_policy_bootstrap_proposal",
                    return_value=proposal,
                ) as publish_call,
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    status = mnemosyne.command_preview_policy_bootstrap(
                        self._command_args(
                            bootstrap_id="curboot-initial",
                            requested_by="requester",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            preview_call.assert_called_once_with(
                root,
                bootstrap_id="curboot-initial",
                requested_by="requester",
            )
            publish_call.assert_called_once_with(
                root,
                bootstrap_id="curboot-initial",
                preview=preview,
            )
            report = json.loads(output.getvalue())
            self.assertEqual(set(report), set(mnemosyne.OPERATION_REPORT_KEYS))
            self.assertEqual(report["mode"], "preview-policy-bootstrap")
            self.assertEqual(
                report["registry_updates"][0]["proposal_sha256"],
                "b" * 64,
            )
            self.assertEqual(
                report["needs_review"][0]["expected_post_raw_sha256"],
                "a" * 64,
            )
            self.assertIn(str(root / "_registry" / "placement-map.yml"), report["not_modified"])
            self.assertIn("raw corpus", report["not_modified"])

    def test_policy_approve_command_reports_reserved_exact_approval(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            approval = {
                "approval_id": "polappr-approval",
                "approval_sha256": "d" * 64,
                "proposal_id": "polboot-proposal",
                "run_id": "polrun-run",
                "state": "PUBLISHED",
                "export_path": str(root / "approval.json"),
            }
            with mock.patch.object(
                mnemosyne._policy_state_core,
                "approve_policy_bootstrap",
                return_value=approval,
            ) as approve_call:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = mnemosyne.command_approve_policy_bootstrap(
                        self._command_args(
                            bootstrap_id="curboot-initial",
                            proposal_id="polboot-proposal",
                            proposal_sha256="a" * 64,
                            approved_by="approver",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            approve_call.assert_called_once_with(
                root,
                bootstrap_id="curboot-initial",
                proposal_id="polboot-proposal",
                proposal_sha256="a" * 64,
                approved_by="approver",
            )
            report = json.loads(output.getvalue())
            self.assertEqual(report["mode"], "approve-policy-bootstrap")
            self.assertEqual(
                report["registry_updates"][0]["approval_sha256"],
                "d" * 64,
            )
            self.assertEqual(report["content_placement_writes"], [])

    def test_policy_apply_command_uses_deterministic_internal_process_binding(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            result = {
                "status": "COMPLETE",
                "generation": 1,
                "guard_epoch": 0,
                "proposal_id": "polboot-proposal",
                "approval_id": "polappr-approval",
                "run_id": "polrun-run",
                "raw_hash": "a" * 64,
                "normalized_full_hash": "b" * 64,
                "writer_control_hash": "c" * 64,
                "foundation_hash": "d" * 64,
                "paths": {
                    "registry": str(root / "_registry" / "placement-map.yml"),
                    "run": str(root / "run"),
                },
            }
            process_ids = []

            def apply_side_effect(*_args, **kwargs):
                process_ids.append(kwargs["process_instance_id"])
                return result

            with mock.patch.object(
                mnemosyne._policy_state_core,
                "apply_policy_bootstrap",
                side_effect=apply_side_effect,
            ):
                for _ in range(2):
                    with redirect_stdout(io.StringIO()):
                        status = mnemosyne.command_apply_policy_bootstrap(
                            self._command_args(
                                bootstrap_id="curboot-initial",
                                approval_id="polappr-approval",
                                approval_sha256="e" * 64,
                                executed_by="operator",
                                root=str(root),
                                json=True,
                            )
                        )
                    self.assertEqual(status, 0)
            self.assertEqual(len(process_ids), 2)
            self.assertEqual(process_ids[0], process_ids[1])
            self.assertTrue(process_ids[0].startswith("policy-cli-"))

    def test_policy_apply_manual_recovery_cause_is_persisted_under_outer_guard(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            cause = mnemosyne.ManualRecoveryRequired(
                "policy rename requires manual recovery",
                source=root / "_registry" / "placement-map.yml",
                target=root / "policy-parking",
                reason="ambiguous registry rename compensation",
                expected_source_identity=(1, 2, 3),
                observed_target_identity=None,
            )
            recovery = mnemosyne._policy_state_core.PolicyBootstrapRecoveryRequired(
                "policy bootstrap requires recovery",
                phase="POLICY_PARKED",
                run_id="polrun-run",
                cause=cause,
            )
            with mock.patch.object(
                mnemosyne._policy_state_core,
                "apply_policy_bootstrap",
                side_effect=recovery,
            ):
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "blocker_sha256",
                ) as raised:
                    mnemosyne.command_apply_policy_bootstrap(
                        self._command_args(
                            bootstrap_id="curboot-initial",
                            approval_id="polappr-approval",
                            approval_sha256="a" * 64,
                            executed_by="operator",
                            root=str(root),
                            json=False,
                        )
                    )
            blockers = list(
                (root / "_registry" / "lock-migrations" / "manual-recovery").glob(
                    "*.json"
                )
            )
            self.assertEqual(len(blockers), 1)
            payload = json.loads(blockers[0].read_text(encoding="utf-8"))
            self.assertEqual(
                payload["kind"],
                "POLICY_BOOTSTRAP_RENAME_MANUAL_RECOVERY",
            )
            self.assertIn("blocker_sha256", str(raised.exception))

    def test_preview_adapter_returns_exact_operation_report_without_writes(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            before = tuple(root.rglob("*"))
            preview = {
                "approval_ready": True,
                "preview_id": "curboot-preview",
                "paths": {
                    "staging": str(root / "_registry" / ".incomplete-curboot"),
                    "final": str(root / "_registry" / "curation"),
                },
                "control_schema": {"version": 1, "sha256": "a" * 64},
            }
            with (
                mock.patch.object(
                    mnemosyne,
                    "resolve_completed_lock_migration_result",
                    return_value=root / "completed" / "result.json",
                ),
                mock.patch.object(
                    mnemosyne._control_core,
                    "preview_bootstrap_state",
                    return_value=preview,
                ),
                mock.patch.object(
                    mnemosyne._control_core,
                    "bootstrap_preview_sha256",
                    return_value="b" * 64,
                ),
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    status = mnemosyne.command_preview_bootstrap_state(
                        self._command_args(
                            requested_by="requester",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(
                set(report),
                {
                    "mode",
                    "registry_updates",
                    "content_placement_writes",
                    "memory_updates",
                    "not_modified",
                    "needs_review",
                },
            )
            self.assertEqual(report["mode"], "preview-bootstrap-state")
            self.assertEqual(report["registry_updates"], [])
            self.assertEqual(report["needs_review"][0]["preview_sha256"], "b" * 64)
            self.assertEqual(tuple(root.rglob("*")), before)

    def test_apply_requires_complete_binding_before_resolving_m0_evidence(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            with mock.patch.object(
                mnemosyne,
                "resolve_completed_lock_migration_result",
            ) as resolver:
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "requires --preview-id",
                ):
                    mnemosyne.command_bootstrap_state(
                        self._command_args(
                            apply=True,
                            preview_id=None,
                            preview_hash=None,
                            requested_by="requester",
                            approved_by=None,
                            root=str(root),
                            json=False,
                        )
                    )
            resolver.assert_not_called()
            self.assertEqual(tuple(root.rglob("*")), ())

    def test_resume_defers_current_registry_preimage_to_core_complete_fast_path(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            result = {
                "bootstrap_id": "curboot-existing",
                "state": "COMPLETE",
                "schema_sha256": "a" * 64,
                "logical_readback_sha256": "b" * 64,
                "paths": {
                    "final": str(root / "_registry" / "curation"),
                    "ledger": str(
                        root / "_registry" / "curation" / "ledger.sqlite3"
                    ),
                },
            }
            with (
                mock.patch.object(
                    mnemosyne,
                    "resolve_completed_lock_migration_result",
                    return_value=root / "completed" / "result.json",
                ) as resolver,
                mock.patch.object(
                    mnemosyne._control_core,
                    "resume_bootstrap_state",
                    return_value=result,
                ),
            ):
                with redirect_stdout(io.StringIO()):
                    status = mnemosyne.command_resume_bootstrap_state(
                        self._command_args(
                            bootstrap_id="curboot-existing",
                            resumed_by="operator",
                            root=str(root),
                            json=True,
                        )
                    )
            self.assertEqual(status, 0)
            resolver.assert_called_once_with(
                root,
                require_current_registry_state=False,
            )

    def test_control_manual_recovery_is_persisted_under_outer_guard(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            recovery = mnemosyne._control_core.ManualRecoveryRequired(
                "control rename requires manual recovery",
                source=root / "_registry" / ".incomplete-curboot",
                target=root / "_registry" / "curation",
                reason="ambiguous rename compensation",
                expected_source_identity=(1, 2, 3),
                observed_target_identity=None,
            )
            with (
                mock.patch.object(
                    mnemosyne,
                    "resolve_completed_lock_migration_result",
                    return_value=root / "completed" / "result.json",
                ),
                mock.patch.object(
                    mnemosyne._control_core,
                    "apply_bootstrap_state",
                    side_effect=recovery,
                ),
            ):
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "blocker_sha256",
                ) as raised:
                    mnemosyne.command_bootstrap_state(
                        self._command_args(
                            apply=True,
                            preview_id="curboot-preview",
                            preview_hash="a" * 64,
                            requested_by="requester",
                            approved_by="approver",
                            root=str(root),
                            json=False,
                        )
                    )
            blockers = list(
                (root / "_registry" / "lock-migrations" / "manual-recovery").glob(
                    "*.json"
                )
            )
            self.assertEqual(len(blockers), 1)
            payload = json.loads(blockers[0].read_text(encoding="utf-8"))
            self.assertEqual(
                payload["kind"],
                "CONTROL_BOOTSTRAP_RENAME_MANUAL_RECOVERY",
            )
            self.assertEqual(payload["status"], "OPEN")
            self.assertIn("blocker_sha256", str(raised.exception))

    def test_operation_report_renderer_rejects_missing_extra_and_wrong_shapes(self):
        valid = mnemosyne.operation_report(mode="test")
        with redirect_stdout(io.StringIO()):
            mnemosyne.render_operation_report(valid, as_json=True)

        missing = dict(valid)
        missing.pop("needs_review")
        with self.assertRaisesRegex(mnemosyne.MnemosyneError, "exactly six"):
            mnemosyne.render_operation_report(missing, as_json=True)

        extra = dict(valid, unexpected=[])
        with self.assertRaisesRegex(mnemosyne.MnemosyneError, "exactly six"):
            mnemosyne.render_operation_report(extra, as_json=True)

        wrong_shape = dict(valid, registry_updates={})
        with self.assertRaisesRegex(mnemosyne.MnemosyneError, "must be a list"):
            mnemosyne.render_operation_report(wrong_shape, as_json=True)
        with self.assertRaisesRegex(mnemosyne.MnemosyneError, "must be a list"):
            mnemosyne.operation_report(mode="test", registry_updates={})


if __name__ == "__main__":
    unittest.main()
