import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

# The verified loader must establish the sealed core module namespace first.
import mnemosyne  # noqa: F401, E402
from mnemosyne_core import (  # noqa: E402
    inventory_workflow,
    ledger_runtime,
    m2_workflow,
    review_state,
    schema_migration,
)
if __package__:
    from .test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402
else:
    from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class MnemosyneM2DirectWorkflowTest(LedgerRuntimeFixture):
    def test_schema_migration_keeps_preview_approval_apply_identity_bound(self):
        plan = schema_migration.preview_m2_migration(
            self.root,
            plan_id="m2mig-direct-boundary",
            requested_by="migration-requester",
        )
        approval = schema_migration.approve_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="migration-approver",
        )
        result = schema_migration.apply_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="migration-executor",
        )

        self.assertEqual(plan["source"]["schema_state"], "v1")
        self.assertEqual(approval["plan_id"], plan["plan_id"])
        self.assertEqual(approval["plan_sha256"], plan["plan_sha256"])
        self.assertEqual(result["plan_id"], plan["plan_id"])
        self.assertEqual(result["approval_id"], approval["approval_id"])
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual([row[0] for row in self.migration_rows()], [1, 2])

    def test_direct_review_workflow_keeps_documents_and_authority_boundaries(self):
        documents = self.root / "example-service" / "docs"
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
            run_id="inventory-m2-direct",
        )
        self.assertEqual(inventory_report.terminal.state, "complete")
        self.migrate_to_v2()

        campaign = m2_workflow.open_root_run(
            self.root,
            run_id="inventory-m2-direct",
            opened_by="reviewer",
            rendered_at="2026-07-15T05:00:00Z",
        )
        campaign_validation = m2_workflow.validate_review(
            self.root,
            snapshot_id=campaign.snapshot_id,
        )
        self.assertEqual(campaign.status, "READY")
        self.assertFalse(campaign.resumed)
        self.assertEqual(campaign_validation.review_kind, "run-overview")
        self.assertFalse(campaign_validation.structural_approval_ready)

        with ledger_runtime.open_reader_session(self.root) as session:
            control_root = Path(session.compiled_policy.foundation.state_root)
            campaign_snapshot = review_state.ReviewSnapshotLoader(
                session.connection,
                control_root,
            ).load(campaign.snapshot_id)
        self.assertEqual(len(campaign_snapshot.units), 1)
        unit = campaign_snapshot.units[0]
        self.assertEqual(unit.unit_kind, "folder")

        batch = m2_workflow.open_batch(
            self.root,
            campaign_id=campaign.campaign_id,
            unit_ids=(unit.unit_id,),
            batch_id="batch-m2-direct",
            snapshot_id="snapshot-batch-m2-direct",
            submission_id="submission-batch-m2-direct",
            actor="reviewer",
            max_items=100,
            max_files=100,
            max_bytes=1024 * 1024,
            max_effects=1,
        )
        batch_validation = m2_workflow.validate_review(
            self.root,
            snapshot_id=batch.snapshot_id,
        )
        self.assertEqual(batch.status, "OPEN")
        self.assertFalse(batch.structural_approval_ready)
        self.assertEqual(batch_validation.review_kind, "batch-preview")
        self.assertFalse(batch_validation.structural_approval_ready)

        draft = m2_workflow.checkout_review(
            self.root,
            snapshot_id=batch.snapshot_id,
            snapshot_sha256=batch.snapshot_sha256,
            draft_id="draft-m2-direct",
            actor="reviewer",
        )
        self.assertFalse(draft.authority)
        self.assertFalse(draft.approval_ready)
        self.assertEqual(
            Path(draft.final_path).parent,
            self.root / "_registry" / "curation" / "drafts",
        )

        exploded = m2_workflow.explode_review_unit(
            self.root,
            batch_id=batch.batch_id,
            snapshot_id=batch.snapshot_id,
            snapshot_sha256=batch.snapshot_sha256,
            folder_unit_id=unit.unit_id,
            next_snapshot_id="snapshot-batch-m2-exploded",
            submission_id="submission-batch-m2-exploded",
            actor="reviewer",
        )
        self.assertEqual(exploded.parent_snapshot_id, batch.snapshot_id)
        self.assertFalse(exploded.structural_approval_ready)
        self.assertEqual(
            exploded.structural_blocker,
            "effect-preview-not-available-m2",
        )

        resumed = m2_workflow.open_root_run(
            self.root,
            run_id="inventory-m2-direct",
            opened_by="ignored-on-exact-resume",
            rendered_at="2026-07-15T06:00:00Z",
        )
        self.assertTrue(resumed.resumed)
        self.assertEqual(resumed.campaign_id, campaign.campaign_id)
        self.assertEqual(resumed.snapshot_id, campaign.snapshot_id)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual(sibling.read_bytes(), sibling_bytes)


if __name__ == "__main__":
    import unittest

    unittest.main()
