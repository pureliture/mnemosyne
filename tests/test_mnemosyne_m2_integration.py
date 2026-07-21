import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import (  # noqa: E402
    inventory_workflow,
    ledger_runtime,
    m2_workflow,
    review_snapshot,
    review_state,
    schema_migration,
)
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402
if __package__:
    from .test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402
else:
    from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class M2EndToEndIntegrationTest(LedgerRuntimeFixture):
    def _assert_v2_context_snapshot(self, sealed):
        self.assertEqual(sealed.schema_version, 2)
        contexts = sealed.payload["analysis_contexts"]
        self.assertEqual(len(contexts), 1)
        self.assertEqual(
            sealed.analysis_contexts_json,
            canonical_json_bytes(contexts),
        )
        context_ids = {value["context_id"] for value in contexts}
        referenced_ids = set()
        for unit in sealed.units:
            for item in unit.to_dict()["analysis_provenance"]["items"]:
                reference = item["reference"]
                referenced_ids.add(reference["context_id"])
                self.assertEqual(reference["schema_version"], 2)
                self.assertNotIn("documents", reference)
                self.assertNotIn("edges", reference)
        self.assertEqual(referenced_ids, context_ids)
        return sealed.analysis_contexts_json

    def test_inventory_to_campaign_to_batch_is_control_only_and_restart_safe(self):
        project = self.root / "example-service"
        documents = project / "docs"
        documents.mkdir(parents=True, mode=0o700)
        source = documents / "design.md"
        source_bytes = b"# Scanner design\n\nCurrent architecture reference.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        sibling = documents / "operations.md"
        sibling_bytes = b"# Scanner operations\n\nRuntime notes.\n"
        sibling.write_bytes(sibling_bytes)
        sibling.chmod(0o600)

        inventory_report = inventory_workflow.start_inventory(
            self.root,
            bootstrap_id=self.bootstrap_id,
            run_id="inventory-m2-e2e",
        )
        self.assertEqual(inventory_report.terminal.state, "complete")
        plan = schema_migration.preview_m2_migration(
            self.root,
            plan_id="m2mig-plan-m2-e2e",
            requested_by="m2-e2e-requester",
        )
        approval = schema_migration.approve_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="m2-e2e-approver",
        )
        schema_migration.apply_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="m2-e2e-executor",
        )

        campaign = m2_workflow.open_root_run(
            self.root,
            run_id="inventory-m2-e2e",
            opened_by="reviewer",
            rendered_at="2026-07-15T05:00:00Z",
        )
        self.assertEqual(campaign.status, "READY")
        self.assertFalse(campaign.resumed)

        campaign_validation = m2_workflow.validate_review(
            self.root,
            snapshot_id=campaign.snapshot_id,
        )
        self.assertEqual(campaign_validation.review_kind, "run-overview")
        self.assertFalse(campaign_validation.structural_approval_ready)

        with ledger_runtime.open_reader_session(self.root) as session:
            control_root = Path(session.compiled_policy.foundation.state_root)
            sealed = review_state.ReviewSnapshotLoader(
                session.connection,
                control_root,
            ).load(campaign.snapshot_id)
            campaign_contexts = self._assert_v2_context_snapshot(sealed)
            unit_ids = tuple(unit.unit_id for unit in sealed.units)
            self.assertEqual(len(sealed.units), 1)
            self.assertEqual(sealed.units[0].unit_kind, "folder")
            self.assertTrue(sealed.units[0].reference_complete)
            self.assertFalse(sealed.units[0].target_proven)
            target_rows = session.connection.execute(
                "SELECT target_path, uncertainty, state "
                "FROM placement_target_candidates ORDER BY target_candidate_id"
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in target_rows],
                [
                    (None, "classification-not-confirmed", "TENTATIVE"),
                    (None, "classification-not-confirmed", "TENTATIVE"),
                ],
            )
        self.assertEqual(len(unit_ids), 1)

        batch = m2_workflow.open_batch(
            self.root,
            campaign_id=campaign.campaign_id,
            unit_ids=(unit_ids[0],),
            batch_id="batch-m2-e2e",
            snapshot_id="snapshot-batch-m2-e2e",
            submission_id="submission-batch-m2-e2e",
            actor="reviewer",
            max_items=100,
            max_files=100,
            max_bytes=1024 * 1024,
            max_effects=1,
        )
        self.assertEqual(batch.status, "OPEN")
        self.assertFalse(batch.structural_approval_ready)

        batch_validation = m2_workflow.validate_review(
            self.root,
            snapshot_id=batch.snapshot_id,
        )
        self.assertEqual(batch_validation.review_kind, "batch-preview")
        self.assertFalse(batch_validation.structural_approval_ready)
        with ledger_runtime.open_reader_session(self.root) as session:
            control_root = Path(session.compiled_policy.foundation.state_root)
            batch_snapshot = review_state.ReviewSnapshotLoader(
                session.connection,
                control_root,
            ).load(batch.snapshot_id)
        self.assertEqual(
            self._assert_v2_context_snapshot(batch_snapshot),
            campaign_contexts,
        )

        draft = m2_workflow.checkout_review(
            self.root,
            snapshot_id=batch.snapshot_id,
            snapshot_sha256=batch.snapshot_sha256,
            draft_id="draft-m2-e2e",
            actor="reviewer",
        )
        self.assertFalse(draft.authority)
        self.assertFalse(draft.approval_ready)
        self.assertTrue(Path(draft.draft_markdown_path).is_file())
        self.assertEqual(
            Path(draft.final_path).parent,
            self.root / "_registry" / "curation" / "drafts",
        )

        draft_retry = m2_workflow.checkout_review(
            self.root,
            snapshot_id=batch.snapshot_id,
            snapshot_sha256=batch.snapshot_sha256,
            draft_id="draft-m2-e2e",
            actor="reviewer",
        )
        self.assertEqual(
            draft_retry.current_markdown_sha256,
            draft.current_markdown_sha256,
        )

        batch_retry = m2_workflow.open_batch(
            self.root,
            campaign_id=campaign.campaign_id,
            unit_ids=(unit_ids[0],),
            batch_id="batch-m2-e2e",
            snapshot_id="snapshot-batch-m2-e2e",
            submission_id="submission-batch-m2-e2e",
            actor="reviewer",
            max_items=100,
            max_files=100,
            max_bytes=1024 * 1024,
            max_effects=1,
        )
        self.assertTrue(batch_retry.resumed)
        self.assertEqual(batch_retry.snapshot_sha256, batch.snapshot_sha256)

        explode_arguments = {
            "batch_id": batch.batch_id,
            "snapshot_id": batch.snapshot_id,
            "snapshot_sha256": batch.snapshot_sha256,
            "folder_unit_id": unit_ids[0],
            "next_snapshot_id": "snapshot-batch-m2-exploded",
            "submission_id": "submission-batch-m2-exploded",
            "actor": "reviewer",
        }
        with mock.patch.object(
            review_snapshot.ReviewSnapshotPublisher,
            "publish",
            side_effect=review_snapshot.ReviewSnapshotError(
                "injected crash after PREPARED"
            ),
        ):
            with self.assertRaises(m2_workflow.M2WorkflowError):
                m2_workflow.explode_review_unit(
                    self.root,
                    **explode_arguments,
                )

        with ledger_runtime.open_reader_session(self.root) as session:
            prepared_states = session.connection.execute(
                "SELECT s.state, r.state FROM review_submissions AS s "
                "JOIN review_snapshots AS r ON r.snapshot_id = s.snapshot_id "
                "WHERE s.submission_id = ?",
                (explode_arguments["submission_id"],),
            ).fetchone()
        self.assertEqual(tuple(prepared_states), ("PREPARED", "PREPARED"))

        exploded = m2_workflow.explode_review_unit(
            self.root,
            **explode_arguments,
        )
        self.assertTrue(exploded.resumed)
        self.assertEqual(exploded.parent_snapshot_id, batch.snapshot_id)
        with ledger_runtime.open_reader_session(self.root) as session:
            control_root = Path(session.compiled_policy.foundation.state_root)
            exploded_snapshot = review_state.ReviewSnapshotLoader(
                session.connection,
                control_root,
            ).load(exploded.snapshot_id)
        self.assertEqual(
            self._assert_v2_context_snapshot(exploded_snapshot),
            campaign_contexts,
        )
        self.assertEqual(len(exploded_snapshot.units), 2)
        self.assertEqual(
            {unit.unit_kind for unit in exploded_snapshot.units},
            {"file"},
        )

        resumed = m2_workflow.open_root_run(
            self.root,
            run_id="inventory-m2-e2e",
            opened_by="ignored-on-exact-resume",
            rendered_at="2026-07-15T06:00:00Z",
        )
        self.assertTrue(resumed.resumed)
        self.assertEqual(resumed.campaign_id, campaign.campaign_id)
        self.assertEqual(resumed.snapshot_id, campaign.snapshot_id)
        self.assertTrue(source.is_file())
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertTrue(sibling.is_file())
        self.assertEqual(sibling.read_bytes(), sibling_bytes)


if __name__ == "__main__":
    unittest.main()
