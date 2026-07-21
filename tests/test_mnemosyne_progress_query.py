import datetime
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import (  # noqa: E402
    control,
    curation_inspect_query,
    ledger_runtime,
    ledger_schema,
    m3_schema,
    progress_query,
)
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


ITEM_1 = "00000001-0000-4000-8000-000000000001"
ITEM_2 = "00000002-0000-4000-8000-000000000002"


def digest(number):
    return "%064x" % number


class ProgressQueryFixture(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.addCleanup(self.connection.close)
        self._schema()
        self._seed()
        self.query = progress_query.ProgressQuery(
            self.connection,
            now=lambda: datetime.datetime(
                2026, 7, 15, 0, 0, tzinfo=datetime.timezone.utc
            ),
            workstream_lifecycle=lambda _workstream_id: "active",
            current_policy_hash=lambda: digest(90),
        )

    def _schema(self):
        self.connection.execute("BEGIN IMMEDIATE")
        for statement in control.CONTROL_SCHEMA_STATEMENTS:
            self.connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_INDEX_STATEMENTS:
            self.connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_TRIGGER_STATEMENTS:
            self.connection.execute(statement)
        self.connection.execute(
            "INSERT INTO schema_migrations VALUES (1, ?, 'bootstrap-v1')",
            (control.CONTROL_SCHEMA_SHA256,),
        )
        self.connection.execute("COMMIT")
        ledger_schema.ensure_v2_schema(
            self.connection,
            migration_id=ledger_runtime.M2_MIGRATION_ID,
        )
        m3_schema.ensure_v3_schema(self.connection)

    def _seed(self):
        self.connection.execute(
            "INSERT INTO inventory_runs ("
            "run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
            "policy_generation, policy_full_hash, policy_writer_control_hash, "
            "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
            "policy_guard_epoch, parent_run_id, state"
            ") VALUES ('run-root', ?, 'runs/root', ?, ?, 1, ?, ?, ?, "
            "'INITIAL', 'policy-run', 0, NULL, 'OPENED')",
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
        self.connection.executemany(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            ((ITEM_1,), (ITEM_2,)),
        )
        self.connection.execute(
            "INSERT INTO review_batches VALUES ("
            "'batch-1', 'campaign-1', ?, 'OPEN', 'snapshot-1', ?, 1, 0)",
            (digest(9), digest(10)),
        )
        for index, (item_id, action, occurred_at) in enumerate(
            (
                (ITEM_1, "DEFER", "2026-07-14T01:00:00Z"),
                (ITEM_2, "LINK", "2026-07-14T01:00:00Z"),
            ),
            start=1,
        ):
            payload = canonical_json_bytes(
                {"action": action.lower(), "item_id": item_id}
            )
            self.connection.execute(
                "INSERT INTO decision_events ("
                "decision_event_id, campaign_id, batch_id, item_id, snapshot_id, "
                "snapshot_sha256, review_revision, projection_generation, actor, "
                "action, current_decision_id, reason, payload_json, payload_sha256, "
                "occurred_at"
                ") VALUES (?, 'campaign-1', 'batch-1', ?, 'snapshot-1', ?, 1, 1, "
                "'reviewer', ?, NULL, 'reviewed', ?, ?, ?)",
                (
                    "decision-%d" % index,
                    item_id,
                    digest(10),
                    action,
                    payload,
                    sha256_bytes(payload),
                    occurred_at,
                ),
            )
            self.connection.execute(
                "INSERT INTO workstream_relations ("
                "workstream_relation_id, item_id, workstream_id, relation_kind, "
                "source_decision_event_id, relation_generation, provenance_json, "
                "provenance_sha256, state"
                ") VALUES (?, ?, 'example-service', 'PRIMARY', ?, 1, ?, ?, 'CURRENT')",
                (
                    "workstream-relation-%d" % index,
                    item_id,
                    "decision-%d" % index,
                    b"{}\n",
                    sha256_bytes(b"{}\n"),
                ),
            )
        required = canonical_json_bytes("review evidence")
        self.connection.execute(
            "INSERT INTO deferrals ("
            "deferral_id, item_id, source_decision_event_id, version, reason, "
            "required_evidence_json, required_evidence_sha256, trigger_kind, "
            "revisit_date, timezone, trigger_workstream_id, captured_lifecycle, "
            "captured_policy_sha256, owner_actor, state"
            ") VALUES ('deferral-1', ?, 'decision-1', 1, 'scheduled review', ?, ?, "
            "'DATE', '2026-07-15', 'Asia/Seoul', NULL, NULL, NULL, 'owner-a', 'CURRENT')",
            (ITEM_1, required, sha256_bytes(required)),
        )
        self.connection.execute(
            "INSERT INTO deferrals ("
            "deferral_id, item_id, source_decision_event_id, version, reason, "
            "required_evidence_json, required_evidence_sha256, trigger_kind, "
            "revisit_date, timezone, trigger_workstream_id, captured_lifecycle, "
            "captured_policy_sha256, owner_actor, state"
            ") VALUES ('deferral-2', ?, 'decision-2', 1, 'needs evidence', ?, ?, "
            "'EVIDENCE', NULL, NULL, NULL, NULL, NULL, NULL, 'CURRENT')",
            (ITEM_2, required, sha256_bytes(required)),
        )
        for item_id, decision_id, deferral_id in (
            (ITEM_1, "decision-1", "deferral-1"),
            (ITEM_2, "decision-2", "deferral-2"),
        ):
            self.connection.execute(
                "INSERT INTO item_curation_projection ("
                "item_id, primary_state, current_decision_id, current_deferral_id, "
                "source_run_id, source_freshness, source_event_id, "
                "source_execution_id, projection_generation, identity_ambiguous, "
                "lifecycle_frozen, unassigned, reversal_available, correction_required"
                ") VALUES (?, 'DEFERRED', ?, ?, 'run-root', 'FRESH', ?, NULL, 1, "
                "0, 0, 0, 0, 0)",
                (item_id, decision_id, deferral_id, decision_id),
            )
        relation_payload = canonical_json_bytes({"evidence": "explicit link"})
        self.connection.execute(
            "INSERT INTO document_relation_events ("
            "relation_event_id, relation_id, canonical_item_id, related_item_id, "
            "relation_kind, direction, action, source_decision_event_id, "
            "supersedes_event_id, provenance_json, provenance_sha256, occurred_at"
            ") VALUES ('relation-event-1', 'relation-1', ?, ?, 'REFERENCE', "
            "'FORWARD', 'CONFIRM', 'decision-2', NULL, ?, ?, "
            "'2026-07-14T01:00:01Z')",
            (ITEM_1, ITEM_2, relation_payload, sha256_bytes(relation_payload)),
        )
        self.connection.execute(
            "INSERT INTO document_relations ("
            "relation_id, canonical_item_id, related_item_id, relation_kind, "
            "direction, source_relation_event_id, relation_generation, state"
            ") VALUES ('relation-1', ?, ?, 'REFERENCE', 'FORWARD', "
            "'relation-event-1', 1, 'CURRENT')",
            (ITEM_1, ITEM_2),
        )


class DeferredInboxQueryTest(ProgressQueryFixture):
    def test_default_due_and_explicit_waiting_are_separate_and_read_only(self):
        before = self.connection.total_changes

        due = self.query.list_deferred()
        waiting = self.query.list_deferred(state="waiting")
        all_items = self.query.list_deferred(state="all")

        self.assertEqual([item["item_id"] for item in due["items"]], [ITEM_1])
        self.assertEqual(due["items"][0]["trigger_state"], "due")
        self.assertEqual([item["item_id"] for item in waiting["items"]], [ITEM_2])
        self.assertEqual(
            waiting["items"][0]["trigger_state"],
            "waiting-evidence",
        )
        self.assertEqual(
            [item["item_id"] for item in all_items["items"]],
            [ITEM_1, ITEM_2],
        )
        self.assertEqual(self.connection.total_changes, before)

    def test_bounded_deferred_query_reports_scan_truncation_and_uses_sql_limit(self):
        statements = []
        self.connection.set_trace_callback(statements.append)
        self.addCleanup(self.connection.set_trace_callback, None)

        result = self.query.list_deferred(state="all", max_items=1)

        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["returned"], 1)
        self.assertTrue(result["truncated"])
        self.assertTrue(
            any("FROM deferrals AS d" in sql and "LIMIT" in sql for sql in statements)
        )

    def test_bounded_deferred_query_preflights_aggregate_blob_bytes(self):
        oversized = canonical_json_bytes("x" * (4 * 1024 * 1024))
        self.connection.execute(
            "UPDATE deferrals SET required_evidence_json = ?, "
            "required_evidence_sha256 = ? WHERE deferral_id = 'deferral-1'",
            (oversized, sha256_bytes(oversized)),
        )
        with mock.patch.object(
            progress_query,
            "_canonical_value",
            side_effect=AssertionError("oversized blob must not be materialized"),
        ):
            with self.assertRaises(progress_query.ProgressQueryError):
                self.query.list_deferred(state="all", max_items=1)


class ProgressReadModelTest(ProgressQueryFixture):
    def test_workstream_home_separates_due_and_waiting_counts(self):
        result = self.query.workstream_home("example-service")

        self.assertEqual(result["kind"], "WorkstreamHome")
        self.assertEqual(result["workstream_id"], "example-service")
        self.assertEqual(result["denominator"]["items"], 2)
        self.assertEqual(result["states"]["deferred"], 2)
        self.assertEqual(result["deferred"]["due"], 1)
        self.assertEqual(result["deferred"]["waiting"], 1)

    def test_item_detail_traverses_document_relation_in_both_directions(self):
        canonical = self.query.item_detail(ITEM_1)
        related = self.query.item_detail(ITEM_2)

        self.assertEqual(
            canonical["document_relations"][0]["other_item_id"],
            ITEM_2,
        )
        self.assertEqual(canonical["document_relations"][0]["traversal"], "outbound")
        self.assertEqual(
            related["document_relations"][0]["other_item_id"],
            ITEM_1,
        )
        self.assertEqual(related["document_relations"][0]["traversal"], "inbound")

    def test_history_has_stable_timestamp_then_sequence_order(self):
        history = self.query.history(ITEM_2)

        self.assertEqual(
            [entry["event_type"] for entry in history["entries"]],
            ["decision", "document-relation"],
        )
        self.assertEqual(
            [entry["sequence"] for entry in history["entries"]],
            [1, 2],
        )
        self.assertEqual(
            self.query.history(ITEM_2),
            history,
        )

    def test_workstream_home_deduplicates_duplicate_relation_rows(self):
        self.connection.execute(
            "INSERT INTO workstream_relations ("
            "workstream_relation_id, item_id, workstream_id, relation_kind, "
            "source_decision_event_id, relation_generation, provenance_json, "
            "provenance_sha256, state"
            ") VALUES ('workstream-relation-dup', ?, 'example-service', "
            "'RELATED', 'decision-1', 2, ?, ?, 'CURRENT')",
            (ITEM_1, b"{}\n", sha256_bytes(b"{}\n")),
        )
        result = self.query.workstream_home("example-service")

        self.assertEqual(result["denominator"]["items"], 2)
        self.assertEqual(result["states"]["deferred"], 2)

    def test_bounded_workstream_and_history_views_report_truncation(self):
        statements = []
        self.connection.set_trace_callback(statements.append)
        self.addCleanup(self.connection.set_trace_callback, None)

        home = self.query.workstream_home("example-service", max_items=1)
        history = self.query.history(ITEM_2, max_items=1)

        self.assertEqual(home["denominator"]["items"], 2)
        self.assertEqual(len(home["item_ids"]), 1)
        self.assertEqual(home["returned"], 1)
        self.assertTrue(home["truncated"])
        self.assertEqual(len(history["entries"]), 1)
        self.assertEqual(history["returned"], 1)
        self.assertTrue(history["truncated"])
        self.assertTrue(
            any("FROM decision_events" in sql and "LIMIT" in sql for sql in statements)
        )

    def test_bounded_history_distinguishes_missing_item_from_empty_history(self):
        with self.assertRaises(progress_query.ProgressQueryError):
            self.query.history("missing-item", max_items=1)

    def test_bounded_item_status_limits_relations_and_deferral_lookup(self):
        self.connection.execute(
            "INSERT INTO workstream_relations ("
            "workstream_relation_id, item_id, workstream_id, relation_kind, "
            "source_decision_event_id, relation_generation, provenance_json, "
            "provenance_sha256, state"
            ") VALUES ('workstream-relation-detail-extra', ?, 'example-service', "
            "'RELATED', 'decision-1', 2, ?, ?, 'CURRENT')",
            (ITEM_1, b"{}\n", sha256_bytes(b"{}\n")),
        )
        statements = []
        self.connection.set_trace_callback(statements.append)
        self.addCleanup(self.connection.set_trace_callback, None)

        detail = self.query.item_detail(ITEM_1, max_items=1)

        self.assertEqual(len(detail["workstream_relations"]), 1)
        self.assertTrue(detail["relations_truncated"])
        self.assertTrue(
            any(
                "FROM workstream_relations" in sql and "LIMIT" in sql
                for sql in statements
            )
        )
        self.assertTrue(
            any(
                "FROM deferrals AS d" in sql
                and "d.item_id" in sql
                and "LIMIT" in sql
                for sql in statements
            )
        )

    def test_bounded_item_status_preflights_relation_text_bytes(self):
        oversized_relation_id = "a" * (5 * 1024 * 1024)
        self.connection.execute(
            "INSERT INTO workstream_relations ("
            "workstream_relation_id, item_id, workstream_id, relation_kind, "
            "source_decision_event_id, relation_generation, provenance_json, "
            "provenance_sha256, state"
            ") VALUES (?, ?, 'example-service', 'RELATED', 'decision-1', 2, "
            "?, ?, 'CURRENT')",
            (
                oversized_relation_id,
                ITEM_1,
                b"{}\n",
                sha256_bytes(b"{}\n"),
            ),
        )
        statements = []
        self.connection.set_trace_callback(statements.append)
        self.addCleanup(self.connection.set_trace_callback, None)

        with self.assertRaises(progress_query.ProgressQueryError):
            self.query.item_detail(ITEM_1, max_items=2)
        self.assertTrue(
            any(
                "octet_length" in sql
                and "FROM workstream_relations" in sql
                and "LIMIT" in sql
                for sql in statements
            )
        )

    def test_bounded_history_preflights_aggregate_text_bytes(self):
        payload = canonical_json_bytes(
            {"action": "defer", "item_id": ITEM_1}
        )
        self.connection.execute(
            "INSERT INTO decision_events ("
            "decision_event_id, campaign_id, batch_id, item_id, snapshot_id, "
            "snapshot_sha256, review_revision, projection_generation, actor, "
            "action, current_decision_id, reason, payload_json, payload_sha256, "
            "occurred_at"
            ") VALUES ('decision-oversized', 'campaign-1', 'batch-1', ?, "
            "'snapshot-1', ?, 1, 1, ?, 'DEFER', NULL, 'reviewed', ?, ?, "
            "'2026-07-13T01:00:00Z')",
            (
                ITEM_1,
                digest(10),
                "x" * (4 * 1024 * 1024),
                payload,
                sha256_bytes(payload),
            ),
        )

        with self.assertRaises(progress_query.ProgressQueryError):
            self.query.history(ITEM_1, max_items=1)


class RecoveryEvidenceQueryTest(ProgressQueryFixture):
    def _insert_prepared_submissions(self):
        payload = canonical_json_bytes({})
        for index in (1, 2):
            state = "PREPARED" if index == 1 else "BLOCKED"
            self.connection.execute(
                "INSERT INTO review_submissions ("
                "submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
                "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
                "payload_sha256, final_path, final_sha256, state"
                ") VALUES (?, 'BATCH', 'campaign-1', 'batch-1', ?, ?, NULL, NULL, "
                "?, ?, ?, ?, ?)",
                (
                    "recovery-submission-%d" % index,
                    digest(100 + index),
                    "recovery-snapshot-%d" % index,
                    payload,
                    sha256_bytes(payload),
                    "recovery/submission-%d" % index,
                    digest(110 + index),
                    state,
                ),
            )

    def test_recovery_evidence_is_bounded_advisory_and_read_only(self):
        self._insert_prepared_submissions()
        before = self.connection.total_changes
        statements = []
        self.connection.set_trace_callback(statements.append)
        self.addCleanup(self.connection.set_trace_callback, None)

        result = curation_inspect_query.RecoveryEvidenceQuery(
            self.connection
        ).view(max_items=1)

        self.assertEqual(result["view"], "recovery")
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["coverage"], "M3_OPERATION_OWNERS")
        self.assertEqual(result["returned"], 1)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["entries"][0]["state"], "PREPARED")
        self.assertNotIn("next_actions", result["entries"][0])
        self.assertIn("m3-reviewer-gate-no-go", result["entries"][0]["blockers"])
        self.assertEqual(self.connection.total_changes, before)
        self.assertTrue(
            any("FROM review_submissions" in sql and "LIMIT" in sql for sql in statements)
        )

    def test_recovery_reference_is_exact_and_does_not_claim_global_completeness(self):
        self._insert_prepared_submissions()
        query = curation_inspect_query.RecoveryEvidenceQuery(self.connection)

        result = query.view(
            max_items=1,
            reference={
                "kind": "review.submission",
                "id": "recovery-submission-2",
            },
        )

        self.assertEqual(result["returned"], 1)
        self.assertFalse(result["truncated"])
        self.assertEqual(
            result["entries"][0]["owner"]["id"],
            "recovery-submission-2",
        )
        self.assertNotIn("recommended_action", result["entries"][0])
        self.assertNotIn("can_resume", result["entries"][0])

    def test_recovery_query_does_not_materialize_oversized_owner_text(self):
        self._insert_prepared_submissions()
        self.connection.execute(
            "UPDATE review_submissions SET submission_id = ? "
            "WHERE submission_id = 'recovery-submission-1'",
            ("x" * (1024 * 1024),),
        )
        statements = []
        self.connection.set_trace_callback(statements.append)
        self.addCleanup(self.connection.set_trace_callback, None)

        with self.assertRaises(
            curation_inspect_query.RecoveryEvidenceQueryError
        ):
            curation_inspect_query.RecoveryEvidenceQuery(self.connection).view(
                max_items=1
            )
        self.assertTrue(any("octet_length" in sql for sql in statements))


if __name__ == "__main__":
    unittest.main()
