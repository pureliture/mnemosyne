import contextlib
import json
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import batch_event_service, m3_schema  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402

if __package__:
    from .test_mnemosyne_m3_schema import create_v2_connection  # noqa: E402
else:
    from test_mnemosyne_m3_schema import create_v2_connection  # noqa: E402


ITEM_ID = "00000001-0000-4000-8000-000000000001"


def digest(number):
    return "%064x" % number


class BatchEventFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.connection = create_v2_connection()
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        m3_schema.ensure_v3_schema(self.connection)
        self._seed()

    def _seed(self):
        self.connection.execute(
            "INSERT INTO inventory_runs ("
            "run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
            "policy_generation, policy_full_hash, policy_writer_control_hash, "
            "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
            "policy_guard_epoch, parent_run_id, state"
            ") VALUES ('run-root', ?, 'runs/root', ?, ?, 1, ?, ?, ?, 'INITIAL', "
            "'policy-run', 0, NULL, 'OPENED')",
            tuple(digest(value) for value in range(1, 7)),
        )
        self.connection.execute(
            "INSERT INTO campaigns ("
            "campaign_id, root_run_id, root_run_sha256, status, "
            "current_snapshot_id, current_snapshot_sha256, review_revision, "
            "active_integration_id, opened_by, payload_json, campaign_path, "
            "campaign_sha256"
            ") VALUES ('campaign-1', 'run-root', ?, 'READY', 'campaign-snapshot', ?, "
            "1, NULL, 'operator', ?, 'campaigns/campaign-1/campaign.json', ?)",
            (digest(1), digest(7), b"{}\n", digest(8)),
        )
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_ID,),
        )
        self.connection.execute(
            "INSERT INTO review_batches VALUES ("
            "'batch-1', 'campaign-1', ?, 'OPEN', 'snapshot-1', ?, 1, 0)",
            (digest(9), digest(10)),
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
            "NULL, NULL, ?, 'snapshots/snapshot-1', ?, 'PUBLISHED', 0)",
            (digest(10), digest(11)),
        )

    def terminal_projection(self, state="KEEP"):
        payload = canonical_json_bytes({"action": state.lower()})
        self.connection.execute(
            "INSERT INTO decision_events ("
            "decision_event_id, campaign_id, batch_id, item_id, snapshot_id, "
            "snapshot_sha256, review_revision, projection_generation, actor, "
            "action, current_decision_id, reason, payload_json, payload_sha256, "
            "occurred_at"
            ") VALUES ('decision-1', 'campaign-1', 'batch-1', ?, 'snapshot-1', ?, "
            "1, 1, 'reviewer', ?, NULL, 'reviewed', ?, ?, "
            "'2026-07-15T01:00:00Z')",
            (ITEM_ID, digest(10), state, payload, sha256_bytes(payload)),
        )
        self.connection.execute(
            "INSERT INTO item_curation_projection ("
            "item_id, primary_state, current_decision_id, current_deferral_id, "
            "source_run_id, source_freshness, source_event_id, source_execution_id, "
            "projection_generation, identity_ambiguous, lifecycle_frozen, "
            "unassigned, reversal_available, correction_required"
            ") VALUES (?, ?, 'decision-1', NULL, 'run-root', 'FRESH', "
            "'decision-1', NULL, 1, 0, 0, 0, 0, 0)",
            (ITEM_ID, state),
        )

    def request(self, kind="close"):
        return batch_event_service.BatchTerminalRequest(
            event_id="batch-event-1",
            batch_id="batch-1",
            event_kind=kind,
            expected_snapshot_id="snapshot-1",
            expected_snapshot_sha256=digest(10),
            expected_review_revision=1,
            expected_execution_generation=0,
            actor="reviewer",
        )

    def service(self, checkpoint=None):
        return batch_event_service.BatchEventService(
            self.connection,
            self.root / "campaigns" / "campaign-1" / "batch-events",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            checkpoint=checkpoint,
        )


class BatchCloseEventTest(BatchEventFixture):
    def test_close_requires_every_membership_item_to_be_terminal(self):
        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "terminal",
        ):
            self.service().close(self.request())

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_close_rejects_a_terminal_projection_with_stale_source_evidence(self):
        self.terminal_projection("KEEP")
        self.connection.execute(
            "UPDATE item_curation_projection SET source_freshness = 'STALE' "
            "WHERE item_id = ?",
            (ITEM_ID,),
        )

        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "fresh",
        ):
            self.service().close(self.request())

    def test_close_publishes_event_then_atomically_releases_membership(self):
        self.terminal_projection("KEEP")

        result = self.service().close(self.request())

        self.assertEqual(result.batch_status, "CLOSED_REVIEW")
        self.assertEqual(result.event_state, "PUBLISHED")
        self.assertEqual(
            self.connection.execute(
                "SELECT status FROM batch_memberships WHERE membership_id = 'membership-1'"
            ).fetchone()[0],
            "RELEASED",
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT status FROM review_batches WHERE batch_id = 'batch-1'"
            ).fetchone()[0],
            "CLOSED_REVIEW",
        )
        raw = result.final_path.read_bytes()
        self.assertEqual(sha256_bytes(raw), result.event_sha256)
        self.assertEqual(json.loads(raw.decode("utf-8"))["event_kind"], "CLOSE_REVIEW")
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM decision_events").fetchone()[0],
            1,
        )

    def test_prepare_crash_changes_neither_batch_nor_membership_and_resume_finishes(self):
        self.terminal_projection("KEEP")

        def stop(point):
            if point == "prepared":
                raise RuntimeError("simulated crash")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.service(checkpoint=stop).close(self.request())

        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT b.status, m.status, e.state FROM review_batches AS b "
                    "JOIN batch_memberships AS m ON m.batch_id = b.batch_id "
                    "JOIN batch_events AS e ON e.batch_id = b.batch_id "
                    "WHERE b.batch_id = 'batch-1'"
                ).fetchone()
            ),
            ("OPEN", "OPEN", "PREPARED"),
        )

        result = self.service().resume("batch-event-1", resumed_by="reviewer")

        self.assertTrue(result.resumed)
        self.assertEqual(result.batch_status, "CLOSED_REVIEW")

    def test_published_close_retry_rejects_reopened_batch(self):
        self.terminal_projection("KEEP")
        request = self.request()
        self.service().close(request)
        self.connection.execute(
            "UPDATE review_batches SET status = 'OPEN' "
            "WHERE batch_id = 'batch-1'"
        )

        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "published batch terminal",
        ):
            self.service().close(request)

    def test_published_close_resume_rejects_reopened_membership(self):
        self.terminal_projection("KEEP")
        self.service().close(self.request())
        self.connection.execute(
            "UPDATE batch_memberships SET status = 'OPEN' "
            "WHERE membership_id = 'membership-1'"
        )

        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "published batch terminal",
        ):
            self.service().resume("batch-event-1", resumed_by="reviewer")

    def test_published_close_resume_rejects_new_prepared_submission(self):
        self.terminal_projection("KEEP")
        self.service().close(self.request())
        self.connection.execute(
            "INSERT INTO review_submissions ("
            "submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
            "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
            "payload_sha256, final_path, final_sha256, state"
            ") VALUES ("
            "'submission-after-close', 'BATCH', 'campaign-1', 'batch-1', ?, "
            "'snapshot-after-close', 'snapshot-1', ?, ?, ?, "
            "'submissions/submission-after-close', ?, 'PREPARED'"
            ")",
            (digest(12), digest(10), b"{}\n", sha256_bytes(b"{}\n"), digest(13)),
        )

        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "published batch terminal",
        ):
            self.service().resume("batch-event-1", resumed_by="reviewer")

    def test_stale_final_cas_blocks_event_and_preserves_open_membership(self):
        self.terminal_projection("KEEP")

        def drift(point):
            if point == "published":
                self.connection.execute(
                    "UPDATE review_batches SET review_revision = 2 "
                    "WHERE batch_id = 'batch-1'"
                )

        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "stale",
        ):
            self.service(checkpoint=drift).close(self.request())

        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT b.status, m.status, e.state FROM review_batches AS b "
                    "JOIN batch_memberships AS m ON m.batch_id = b.batch_id "
                    "JOIN batch_events AS e ON e.batch_id = b.batch_id "
                    "WHERE b.batch_id = 'batch-1'"
                ).fetchone()
            ),
            ("OPEN", "OPEN", "BLOCKED"),
        )

    def test_resume_rejects_rebound_final_path_before_artifact_access(self):
        self.terminal_projection("KEEP")

        def stop(point):
            if point == "prepared":
                raise RuntimeError("simulated crash")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.service(checkpoint=stop).close(self.request())
        outside = self.root / "outside-event.json"
        outside.write_bytes(b"outside")
        self.connection.execute(
            "UPDATE batch_events SET final_path = ? "
            "WHERE batch_event_id = 'batch-event-1'",
            (str(outside),),
        )

        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "path is rebound",
        ):
            self.service().resume("batch-event-1", resumed_by="reviewer")

        self.assertEqual(outside.read_bytes(), b"outside")


class BatchAbandonEventTest(BatchEventFixture):
    def test_abandon_releases_membership_without_requiring_a_terminal_decision(self):
        result = self.service().abandon(self.request("abandon"))

        self.assertEqual(result.batch_status, "ABANDONED")
        self.assertEqual(
            self.connection.execute(
                "SELECT status FROM batch_memberships WHERE membership_id = 'membership-1'"
            ).fetchone()[0],
            "RELEASED",
        )


class BatchEventHardeningTest(BatchEventFixture):
    def test_service_rejects_event_root_outside_campaign_namespace(self):
        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "campaign namespace",
        ):
            batch_event_service.BatchEventService(
                self.connection,
                self.root / "escaped-events",
                placement_shared=contextlib.nullcontext,
                ledger_exclusive=contextlib.nullcontext,
            )

    def test_oversized_actor_is_rejected_before_event_row_or_artifact(self):
        self.terminal_projection("KEEP")

        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "actor",
        ):
            self.service().close(
                replace(self.request(), actor="a" * (16 * 1024 + 1))
            )

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )
        self.assertFalse(
            (
                self.root
                / "campaigns/campaign-1/batch-events/batch-event-1/event.json"
            ).exists()
        )

    def test_close_blocks_while_prepared_submission_exists(self):
        self.terminal_projection("KEEP")
        self.connection.execute(
            "INSERT INTO review_submissions ("
            "submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
            "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
            "payload_sha256, final_path, final_sha256, state"
            ") VALUES ("
            "'submission-prepared', 'BATCH', 'campaign-1', 'batch-1', ?, "
            "'snapshot-prepared-sub', 'snapshot-1', ?, ?, ?, "
            "'submissions/submission-prepared', ?, 'PREPARED'"
            ")",
            (digest(11), digest(10), b"{}\n", sha256_bytes(b"{}\n"), digest(12)),
        )

        with self.assertRaisesRegex(
            batch_event_service.BatchEventConflict,
            "submission",
        ):
            self.service().close(self.request())

    def test_resume_rejects_oversized_stored_payload_before_decode(self):
        self.terminal_projection("KEEP")
        self.service().close(self.request())
        self.connection.execute(
            "UPDATE batch_events SET payload_json = ? "
            "WHERE batch_event_id = 'batch-event-1'",
            (b"x" * 33,),
        )

        with mock.patch.object(
            batch_event_service,
            "_MAX_EVENT_BLOB_BYTES",
            32,
            create=True,
        ):
            with self.assertRaisesRegex(
                batch_event_service.BatchEventConflict,
                "bounded blob preflight",
            ):
                self.service().resume("batch-event-1", resumed_by="reviewer")


if __name__ == "__main__":
    unittest.main()
