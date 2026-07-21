import contextlib
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import (  # noqa: E402
    admission,
    control,
    decision_service,
    ledger_runtime,
    ledger_schema,
    m3_schema,
    review_submission,
)
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


ITEM_ID = "00000001-0000-4000-8000-000000000001"
ITEM_ID_2 = "00000002-0000-4000-8000-000000000002"


def digest(number):
    return "%064x" % number


@dataclass(frozen=True)
class SealedPaths:
    staging_path: Path
    final_path: Path


class FakePublisher:
    def __init__(self):
        self.plan_calls = 0
        self.publish_calls = 0

    def plan(self, publication):
        self.plan_calls += 1
        package_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "snapshot_sha256": publication.snapshot_sha256,
                    "version": publication.version,
                }
            )
        )
        sealed_identity_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "package_sha256": package_sha256,
                    "snapshot_sha256": publication.snapshot_sha256,
                }
            )
        )
        return review_submission.SnapshotPublishPlan(
            publication=publication,
            final_path=publication.final_path,
            package_sha256=package_sha256,
            sealed_identity_sha256=sealed_identity_sha256,
            sealed_payload=SealedPaths(
                staging_path=publication.final_path.parent
                / (".incomplete-%s" % publication.snapshot_id),
                final_path=publication.final_path,
            ),
        )

    def publish(self, plan):
        self.publish_calls += 1
        plan.final_path.mkdir(mode=0o700, parents=True, exist_ok=False)
        payload_path = plan.final_path / "snapshot.json"
        descriptor = os.open(
            payload_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, plan.publication.canonical_payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return review_submission.SnapshotPublishResult(
            final_path=plan.final_path,
            snapshot_sha256=plan.publication.snapshot_sha256,
            package_sha256=plan.package_sha256,
            sealed_identity_sha256=plan.sealed_identity_sha256,
        )


class ReviewSubmissionFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snapshot_root = self.root / "snapshots"
        self.snapshot_root.mkdir(mode=0o700)
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.addCleanup(self.connection.close)
        self._create_schema()
        self.policy = admission.ApprovedPolicyRef(
            raw_hash=digest(1),
            full_hash=digest(2),
            writer_control_hash=digest(3),
            foundation_hash=digest(4),
            generation=1,
            source_kind="INITIAL",
            source_run_id="policy-run-1",
            guard_epoch=0,
        )
        self._seed_lineage()
        self.publisher = FakePublisher()

    def _create_schema(self):
        self.connection.execute("BEGIN IMMEDIATE")
        for statement in control.CONTROL_SCHEMA_STATEMENTS:
            self.connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_INDEX_STATEMENTS:
            self.connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_TRIGGER_STATEMENTS:
            self.connection.execute(statement)
        self.connection.execute(
            "INSERT INTO schema_migrations VALUES (?, ?, ?)",
            (1, control.CONTROL_SCHEMA_SHA256, "bootstrap-v1"),
        )
        self.connection.execute("COMMIT")
        ledger_schema.ensure_v2_schema(
            self.connection,
            migration_id=ledger_runtime.M2_MIGRATION_ID,
        )
        m3_schema.ensure_v3_schema(self.connection)

    def _seed_lineage(self):
        self.connection.execute(
            "INSERT INTO inventory_runs ("
            "run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
            "policy_generation, policy_full_hash, policy_writer_control_hash, "
            "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
            "policy_guard_epoch, parent_run_id, state"
            ") VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, 'INITIAL', ?, 0, NULL, 'OPENED')",
            (
                "run-root",
                digest(10),
                "curation-runs/run-root",
                digest(11),
                self.policy.raw_hash,
                self.policy.full_hash,
                self.policy.writer_control_hash,
                self.policy.foundation_hash,
                self.policy.source_run_id,
            ),
        )
        self.connection.execute(
            "INSERT INTO campaigns ("
            "campaign_id, root_run_id, root_run_sha256, status, "
            "current_snapshot_id, current_snapshot_sha256, review_revision, "
            "active_integration_id, opened_by, payload_json, campaign_path, "
            "campaign_sha256"
            ") VALUES ('campaign-1', 'run-root', ?, 'READY', "
            "'campaign-snapshot-1', ?, 1, NULL, 'operator', ?, ?, ?)",
            (
                digest(10),
                digest(12),
                b"{}\n",
                "campaigns/campaign-1/campaign.json",
                digest(13),
            ),
        )
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_ID,),
        )
        self.connection.execute(
            "INSERT INTO review_batches VALUES ("
            "'batch-1', 'campaign-1', ?, 'OPEN', 'snapshot-1', ?, 1, 0)",
            (digest(14), digest(15)),
        )
        self.connection.execute(
            "INSERT INTO batch_memberships VALUES ("
            "'membership-1', 'batch-1', 'unit-1', ?, "
            "'example-service/review.md', 'OPEN')",
            (ITEM_ID,),
        )
        self.connection.execute(
            "INSERT INTO review_snapshots ("
            "snapshot_id, lineage_kind, campaign_id, batch_id, version, "
            "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
            "final_path, final_sha256, state, structural_approval_ready"
            ") VALUES ('snapshot-1', 'BATCH', 'campaign-1', 'batch-1', 1, "
            "NULL, NULL, ?, ?, ?, 'PUBLISHED', 0)",
            (digest(15), str(self.snapshot_root / "snapshot-1"), digest(16)),
        )

    def request(self, decisions=None):
        if decisions is None:
            decisions = (
                decision_service.ItemDecisionInput(
                    unit_id="unit-1",
                    member_item_ids=(ITEM_ID,),
                    selected_item_ids=(ITEM_ID,),
                    action="keep",
                    reason="current placement is correct",
                ),
            )
        decision_request = decision_service.DecisionRequest(
            campaign_id="campaign-1",
            batch_id="batch-1",
            base_snapshot_id="snapshot-1",
            base_snapshot_sha256=digest(15),
            expected_review_revision=1,
            expected_execution_generation=0,
            submission_id="submission-2",
            next_snapshot_id="snapshot-2",
            actor="reviewer",
            decided_at_utc="2026-07-15T01:02:03Z",
            decisions=decisions,
        )
        compiled = decision_service.DecisionService().compile(decision_request)
        next_payload = canonical_json_bytes(
            {
                "approval_ready": False,
                "batch_id": "batch-1",
                "batch_version": 2,
                "decision_event_ids": [event["event_id"] for event in compiled.events],
                "parent_snapshot_id": "snapshot-1",
                "parent_snapshot_sha256": digest(15),
                "schema_version": 3,
                "snapshot_id": "snapshot-2",
                "structural_approval_ready": False,
            }
        )
        return review_submission.ReviewSubmissionRequest(
            policy=self.policy,
            decision_request=decision_request,
            compiled=compiled,
            next_snapshot_payload=next_payload,
        )

    def reopen_request(
        self,
        prior_result,
        prior_event_id,
        *,
        prior_generation=1,
        submission_id="submission-reopen-1",
        next_snapshot_id="snapshot-3",
    ):
        reopen_decision = decision_service.ReopenDecisionRequest(
            campaign_id="campaign-1",
            batch_id="batch-1",
            base_snapshot_id=prior_result.snapshot_id,
            base_snapshot_sha256=prior_result.snapshot_sha256,
            expected_review_revision=prior_result.review_revision,
            expected_execution_generation=prior_result.execution_generation,
            submission_id=submission_id,
            next_snapshot_id=next_snapshot_id,
            item_id=ITEM_ID,
            current_decision_event_id=prior_event_id,
            current_projection_generation=prior_generation,
            actor="reviewer",
            reason="new evidence requires review",
            reopened_at_utc="2026-07-15T02:03:04Z",
        )
        compiled = decision_service.DecisionService().compile_reopen(reopen_decision)
        next_payload = canonical_json_bytes(
            {
                "approval_ready": False,
                "batch_id": "batch-1",
                "batch_version": prior_result.review_revision + 1,
                "decision_event_ids": [compiled.event["event_id"]],
                "parent_snapshot_id": prior_result.snapshot_id,
                "parent_snapshot_sha256": prior_result.snapshot_sha256,
                "schema_version": 3,
                "snapshot_id": next_snapshot_id,
                "structural_approval_ready": False,
            }
        )
        return review_submission.ReopenReviewSubmissionRequest(
            policy=self.policy,
            reopen_request=reopen_decision,
            compiled=compiled,
            next_snapshot_payload=next_payload,
        )

    def service(self, checkpoint=None):
        return review_submission.ReviewSubmissionPublisher(
            self.connection,
            self.snapshot_root,
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=self.publisher,
            current_policy=lambda: self.policy,
            checkpoint=checkpoint,
        )


class ReviewSubmissionCommitTest(ReviewSubmissionFixture):
    def test_keep_commits_snapshot_decision_projection_and_head_atomically(self):
        result = self.service().submit(self.request())

        self.assertEqual(result.submission_state, "COMMITTED")
        self.assertEqual(result.snapshot_id, "snapshot-2")
        self.assertEqual(result.review_revision, 2)
        submission = tuple(
            self.connection.execute(
                "SELECT state, expected_lineage_status, expected_review_revision, "
                "expected_execution_generation FROM review_submissions "
                "WHERE submission_id = 'submission-2'"
            ).fetchone()
        )
        self.assertEqual(submission, ("COMMITTED", "OPEN", 1, 0))
        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT status, current_snapshot_id, current_snapshot_sha256, "
                    "review_revision, execution_generation FROM review_batches "
                    "WHERE batch_id = 'batch-1'"
                ).fetchone()
            ),
            ("OPEN", "snapshot-2", result.snapshot_sha256, 2, 0),
        )
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM decision_events").fetchone()[0],
            1,
        )
        projection = self.connection.execute(
            "SELECT primary_state, projection_generation, current_decision_id, "
            "reversal_available "
            "FROM item_curation_projection WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()
        self.assertEqual(tuple(projection[:2]), ("KEEP", 1))
        self.assertTrue(projection[2].startswith("decision-"))
        self.assertEqual(projection[3], 0)

    def test_prepare_crash_has_no_decision_or_projection_and_exact_resume_finishes(self):
        def stop(point):
            if point == "prepared":
                raise RuntimeError("simulated crash")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.service(checkpoint=stop).submit(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions WHERE submission_id = 'submission-2'"
            ).fetchone()[0],
            "PREPARED",
        )
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM decision_events").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM item_curation_projection"
            ).fetchone()[0],
            0,
        )

        result = self.service().resume("submission-2")

        self.assertEqual(result.submission_state, "COMMITTED")
        self.assertTrue(result.resumed)
        self.assertEqual(self.publisher.plan_calls, 2)
        self.assertEqual(self.publisher.publish_calls, 1)

    def test_stale_final_cas_blocks_submission_without_partial_projection(self):
        def drift(point):
            if point == "published":
                self.connection.execute(
                    "UPDATE review_batches SET review_revision = 2 "
                    "WHERE batch_id = 'batch-1'"
                )

        with self.assertRaisesRegex(
            review_submission.ReviewSubmissionConflict,
            "stale",
        ):
            self.service(checkpoint=drift).submit(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions WHERE submission_id = 'submission-2'"
            ).fetchone()[0],
            "BLOCKED",
        )
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM decision_events").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM item_curation_projection"
            ).fetchone()[0],
            0,
        )

    def test_unresolved_batch_event_blocks_prepare_before_publication(self):
        self.connection.execute(
            "INSERT INTO batch_events ("
            "batch_event_id, batch_id, event_kind, expected_batch_status, "
            "expected_snapshot_id, expected_snapshot_sha256, "
            "expected_review_revision, expected_execution_generation, "
            "terminal_batch_status, child_batch_id, child_snapshot_id, "
            "child_snapshot_sha256, source_execution_id, source_approval_id, "
            "result_path, result_sha256, membership_release_json, "
            "membership_release_sha256, payload_json, payload_sha256, "
            "final_path, final_sha256, state"
            ") VALUES ('batch-event-1', 'batch-1', 'CLOSE_REVIEW', 'OPEN', "
            "'snapshot-1', ?, 1, 0, 'CLOSED_REVIEW', NULL, NULL, NULL, NULL, "
            "NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, 'PREPARED')",
            (
                digest(15),
                b"[]\n",
                digest(30),
                b"{}\n",
                digest(31),
                str(self.root / "batch-event-1.json"),
                digest(32),
            ),
        )

        with self.assertRaisesRegex(
            review_submission.ReviewSubmissionConflict,
            "batch event",
        ):
            self.service().submit(self.request())

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM review_submissions").fetchone()[0],
            0,
        )
        self.assertEqual(self.publisher.publish_calls, 0)


class ReviewSubmissionNonmovementTest(ReviewSubmissionFixture):
    def test_link_workstream_commits_relation_and_linked_projection(self):
        decisions = (
            decision_service.ItemDecisionInput(
                unit_id="unit-1",
                member_item_ids=(ITEM_ID,),
                selected_item_ids=(ITEM_ID,),
                action="link",
                reason="confirmed reference",
                workstream_relations=(
                    decision_service.WorkstreamRelationInput(
                        workstream_id="example-service",
                        relation_kind="related",
                        evidence="reviewer confirmation",
                        provenance="snapshot-1",
                    ),
                ),
            ),
        )
        result = self.service().submit(self.request(decisions=decisions))

        self.assertEqual(result.submission_state, "COMMITTED")
        relation = self.connection.execute(
            "SELECT workstream_id, relation_kind, state, relation_generation "
            "FROM workstream_relations WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()
        self.assertEqual(
            tuple(relation),
            ("example-service", "RELATED", "CURRENT", 1),
        )
        projection = self.connection.execute(
            "SELECT primary_state, projection_generation, reversal_available "
            "FROM item_curation_projection WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()
        self.assertEqual(tuple(projection), ("LINKED", 1, 0))

    def test_defer_commits_deferral_and_deferred_projection(self):
        decisions = (
            decision_service.ItemDecisionInput(
                unit_id="unit-1",
                member_item_ids=(ITEM_ID,),
                selected_item_ids=(ITEM_ID,),
                action="defer",
                deferral=decision_service.DeferralInput(
                    reason="wait for owner confirmation",
                    required_evidence="signed review note",
                    trigger_kind="evidence",
                    owner="owner-a",
                ),
            ),
        )
        result = self.service().submit(self.request(decisions=decisions))

        self.assertEqual(result.submission_state, "COMMITTED")
        deferral = self.connection.execute(
            "SELECT trigger_kind, state, owner_actor FROM deferrals WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()
        self.assertEqual(tuple(deferral), ("EVIDENCE", "CURRENT", "owner-a"))
        projection = self.connection.execute(
            "SELECT primary_state, current_deferral_id IS NOT NULL "
            "FROM item_curation_projection WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()
        self.assertEqual(tuple(projection), ("DEFERRED", 1))

    def test_exclude_commits_excluded_projection(self):
        decisions = (
            decision_service.ItemDecisionInput(
                unit_id="unit-1",
                member_item_ids=(ITEM_ID,),
                selected_item_ids=(ITEM_ID,),
                action="exclude",
                reason="out of scope for this campaign",
            ),
        )
        result = self.service().submit(self.request(decisions=decisions))

        self.assertEqual(result.submission_state, "COMMITTED")
        projection = self.connection.execute(
            "SELECT primary_state FROM item_curation_projection WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()[0]
        self.assertEqual(projection, "EXCLUDED")

    def test_link_document_relation_commits_edge_and_events(self):
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_ID_2,),
        )
        decisions = (
            decision_service.ItemDecisionInput(
                unit_id="unit-1",
                member_item_ids=(ITEM_ID,),
                selected_item_ids=(ITEM_ID,),
                action="link",
                reason="confirmed document reference",
                document_relations=(
                    decision_service.DocumentRelationInput(
                        canonical_item_id=ITEM_ID,
                        related_item_id=ITEM_ID_2,
                        relation_kind="reference",
                        direction="canonical-to-related",
                        evidence="explicit source link",
                        provenance="snapshot-1",
                    ),
                ),
            ),
        )
        result = self.service().submit(self.request(decisions=decisions))

        self.assertEqual(result.submission_state, "COMMITTED")
        edge = self.connection.execute(
            "SELECT relation_kind, direction, state FROM document_relations "
            "WHERE canonical_item_id = ? AND related_item_id = ?",
            (ITEM_ID, ITEM_ID_2),
        ).fetchone()
        self.assertEqual(tuple(edge), ("REFERENCE", "FORWARD", "CURRENT"))
        event_action = self.connection.execute(
            "SELECT action FROM document_relation_events LIMIT 1"
        ).fetchone()[0]
        self.assertEqual(event_action, "CONFIRM")


class ReviewSubmissionContractClosureTest(ReviewSubmissionFixture):
    def test_correction_commits_review_ready_with_authority_payload(self):
        decisions = (
            decision_service.ItemDecisionInput(
                unit_id="unit-1",
                member_item_ids=(ITEM_ID,),
                selected_item_ids=(ITEM_ID,),
                action="correction",
                reason="authority correction",
                corrections=(("authority", "reference"),),
            ),
        )
        result = self.service().submit(self.request(decisions=decisions))

        self.assertEqual(result.submission_state, "COMMITTED")
        row = self.connection.execute(
            "SELECT primary_state, correction_required FROM item_curation_projection "
            "WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()
        self.assertEqual(tuple(row), ("REVIEW_READY", 0))
        action = self.connection.execute(
            "SELECT action FROM decision_events WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()[0]
        self.assertEqual(action, "CORRECTION")

    def test_proposal_reject_sets_correction_required(self):
        decisions = (
            decision_service.ItemDecisionInput(
                unit_id="unit-1",
                member_item_ids=(ITEM_ID,),
                selected_item_ids=(ITEM_ID,),
                action="proposal-reject",
                reason="reject proposed authority",
            ),
        )
        self.service().submit(self.request(decisions=decisions))

        row = self.connection.execute(
            "SELECT primary_state, correction_required FROM item_curation_projection "
            "WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()
        self.assertEqual(tuple(row), ("REVIEW_READY", 1))

    def test_reopen_after_keep_restores_review_ready(self):
        prior = self.service().submit(self.request())
        compiled = decision_service.DecisionService().compile(
            decision_service.DecisionRequest(
                campaign_id="campaign-1",
                batch_id="batch-1",
                base_snapshot_id="snapshot-1",
                base_snapshot_sha256=digest(15),
                expected_review_revision=1,
                expected_execution_generation=0,
                submission_id="submission-2",
                next_snapshot_id="snapshot-2",
                actor="reviewer",
                decided_at_utc="2026-07-15T01:02:03Z",
                decisions=(
                    decision_service.ItemDecisionInput(
                        unit_id="unit-1",
                        member_item_ids=(ITEM_ID,),
                        selected_item_ids=(ITEM_ID,),
                        action="keep",
                        reason="confirmed canonical",
                    ),
                ),
            )
        )
        prior_event_id = compiled.events[0]["event_id"]
        result = self.service().submit_reopen(
            self.reopen_request(prior, prior_event_id)
        )

        self.assertEqual(result.snapshot_id, "snapshot-3")
        self.assertEqual(result.review_revision, 3)
        projection = self.connection.execute(
            "SELECT primary_state, projection_generation FROM item_curation_projection "
            "WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()
        self.assertEqual(tuple(projection), ("REVIEW_READY", 2))
        reopen_count = self.connection.execute(
            "SELECT COUNT(*) FROM decision_events WHERE action = 'REOPEN'"
        ).fetchone()[0]
        self.assertEqual(reopen_count, 1)


    def test_section_7_1_genesis_keep_projection_has_no_structural_reversal_flag(self):
        self.service().submit(self.request())
        reversal = self.connection.execute(
            "SELECT reversal_available FROM item_curation_projection WHERE item_id = ?",
            (ITEM_ID,),
        ).fetchone()[0]
        self.assertEqual(reversal, 0)


if __name__ == "__main__":
    unittest.main()
