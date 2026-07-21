import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402

from test_mnemosyne_progress_query import (
    ITEM_1,
    ITEM_2,
    ProgressQueryFixture,
    digest,
)
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture

curation_audit = mnemosyne._mnemosyne_core.curation_audit
m3_schema_migration = mnemosyne._mnemosyne_core.m3_schema_migration
operation_contract = mnemosyne._mnemosyne_core.operation_contract
canonical_json_bytes = mnemosyne._canonical_json_core.canonical_json_bytes
sha256_bytes = mnemosyne._canonical_json_core.sha256_bytes


ITEM_3 = "00000003-0000-4000-8000-000000000003"


class CurationIntegrityQueryTest(ProgressQueryFixture):
    def setUp(self):
        super().setUp()
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'LINKED', "
            "current_deferral_id = NULL "
            "WHERE item_id = ?",
            (ITEM_2,),
        )
        self.connection.execute(
            "UPDATE deferrals SET state = 'SUPERSEDED' "
            "WHERE deferral_id = 'deferral-2'"
        )
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(temporary.cleanup)
        self.control_root = Path(temporary.name) / "curation"
        self.control_root.mkdir(mode=0o700)
        self.event_root = (
            self.control_root
            / "campaigns"
            / "campaign-1"
            / "batch-events"
        )
        self.audit = curation_audit.CurationIntegrityQuery(
            self.connection,
            self.control_root,
        )

    @staticmethod
    def _membership_release():
        return [
            {
                "item_id": ITEM_1,
                "membership_id": "membership-audit",
                "path": "projects/audit.md",
                "unit_id": "unit-audit",
            }
        ]

    def _event_payload(self, event_id, event_kind="CLOSE_REVIEW"):
        release = self._membership_release()
        release_json = canonical_json_bytes(release)
        terminal_status = (
            "CLOSED_REVIEW" if event_kind == "CLOSE_REVIEW" else "ABANDONED"
        )
        return canonical_json_bytes(
            {
                "actor": "reviewer",
                "batch_id": "batch-1",
                "event_id": event_id,
                "event_kind": event_kind,
                "expected_execution_generation": 0,
                "expected_review_revision": 1,
                "expected_snapshot_id": "snapshot-1",
                "expected_snapshot_sha256": digest(10),
                "membership_release": release,
                "membership_release_sha256": sha256_bytes(release_json),
                "schema_version": 1,
                "terminal_batch_status": terminal_status,
            }
        )

    def _insert_batch_event(
        self,
        event_id,
        artifact,
        payload,
        event_kind="CLOSE_REVIEW",
    ):
        release = canonical_json_bytes(self._membership_release())
        terminal_status = (
            "CLOSED_REVIEW" if event_kind == "CLOSE_REVIEW" else "ABANDONED"
        )
        self.connection.execute(
            "UPDATE review_batches SET status = ? WHERE batch_id = 'batch-1'",
            (terminal_status,),
        )
        self.connection.execute(
            "INSERT OR REPLACE INTO batch_memberships ("
            "membership_id, batch_id, unit_id, item_id, path, status"
            ") VALUES ('membership-audit', 'batch-1', 'unit-audit', ?, "
            "'projects/audit.md', 'RELEASED')",
            (ITEM_1,),
        )
        self.connection.execute(
            "INSERT INTO batch_events ("
            "batch_event_id, batch_id, event_kind, expected_batch_status, "
            "expected_snapshot_id, expected_snapshot_sha256, "
            "expected_review_revision, expected_execution_generation, "
            "terminal_batch_status, membership_release_json, "
            "membership_release_sha256, payload_json, payload_sha256, "
            "final_path, final_sha256, state"
            ") VALUES (?, 'batch-1', ?, 'OPEN', "
            "'snapshot-1', ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, "
            "'PUBLISHED')",
            (
                event_id,
                event_kind,
                digest(10),
                terminal_status,
                release,
                sha256_bytes(release),
                payload,
                sha256_bytes(payload),
                str(artifact),
                sha256_bytes(payload),
            ),
        )

    def _published_batch_event(self, event_id, event_kind="CLOSE_REVIEW"):
        payload = self._event_payload(event_id, event_kind)
        artifact = self.event_root / event_id / "event.json"
        artifact.parent.mkdir(parents=True, mode=0o700)
        artifact.write_bytes(payload)
        artifact.chmod(0o600)
        self._insert_batch_event(
            event_id,
            artifact,
            payload,
            event_kind,
        )
        return artifact, payload

    def _prepare_unassigned_projection(self, exception_source_id):
        payload = canonical_json_bytes(
            {"action": "correction", "item_id": ITEM_1}
        )
        self.connection.execute(
            "INSERT INTO decision_events ("
            "decision_event_id, campaign_id, batch_id, item_id, snapshot_id, "
            "snapshot_sha256, review_revision, projection_generation, actor, "
            "action, current_decision_id, reason, payload_json, payload_sha256, "
            "occurred_at"
            ") VALUES ('decision-unassigned', 'campaign-1', 'batch-1', ?, "
            "'snapshot-1', ?, 1, 2, 'reviewer', 'CORRECTION', 'decision-1', "
            "'awaiting assignment', ?, ?, '2026-07-14T01:00:03Z')",
            (ITEM_1, digest(10), payload, sha256_bytes(payload)),
        )
        self.connection.execute(
            "UPDATE workstream_relations SET state = 'SUPERSEDED' "
            "WHERE item_id = ?",
            (ITEM_1,),
        )
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'REVIEW_READY', "
            "current_decision_id = 'decision-unassigned', "
            "current_deferral_id = NULL, source_event_id = 'decision-unassigned', "
            "projection_generation = 2, unassigned = 1 WHERE item_id = ?",
            (ITEM_1,),
        )
        condition = canonical_json_bytes(
            {
                "assignment_condition": "workstream assigned",
                "reason": "awaiting assignment",
            }
        )
        self.connection.execute(
            "INSERT INTO unassigned_exceptions ("
            "unassigned_exception_id, item_id, reason, "
            "assignment_condition_json, assignment_condition_sha256, "
            "source_decision_event_id, exception_generation, state"
            ") VALUES ('unassigned-1', ?, 'awaiting assignment', ?, ?, ?, "
            "1, 'CURRENT')",
            (
                ITEM_1,
                condition,
                sha256_bytes(condition),
                exception_source_id,
            ),
        )

    def test_reports_missing_projection_without_writing(self):
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_3,),
        )
        before = self.connection.total_changes

        result = self.audit.run()

        self.assertEqual(result["kind"], "CurationAudit")
        self.assertEqual(
            result["findings"],
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "missing-current-projection",
                    "item_id": ITEM_3,
                }
            ],
        )
        self.assertEqual(self.connection.total_changes, before)

    def test_reports_stale_projection_as_drift_without_writing(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET source_freshness = 'STALE' "
            "WHERE item_id = ?",
            (ITEM_1,),
        )
        before = self.connection.total_changes

        result = self.audit.run()

        self.assertFalse(result["integrity_ok"])
        self.assertEqual(result["summary"]["drift"], 1)
        self.assertEqual(
            result["findings"],
            [
                {
                    "blocking": True,
                    "category": "drift",
                    "code": "stale-current-projection",
                    "item_id": ITEM_1,
                    "source_freshness": "STALE",
                }
            ],
        )
        self.assertEqual(self.connection.total_changes, before)

    def test_reports_unresolved_primary_state_as_unexplained(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'REVIEW_READY', "
            "current_deferral_id = NULL WHERE item_id = ?",
            (ITEM_2,),
        )
        before = self.connection.total_changes

        result = self.audit.run()

        self.assertFalse(result["integrity_ok"])
        self.assertEqual(result["summary"]["integrity"], 1)
        self.assertEqual(result["summary"]["unexplained"], 1)
        self.assertEqual(
            result["findings"],
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "unresolved-curation-state",
                    "item_id": ITEM_2,
                    "primary_state": "REVIEW_READY",
                }
            ],
        )
        self.assertEqual(self.connection.total_changes, before)

    def test_frozen_lifecycle_does_not_count_unresolved_item_as_active(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'REVIEW_READY', "
            "current_deferral_id = NULL, lifecycle_frozen = 1 WHERE item_id = ?",
            (ITEM_2,),
        )

        result = self.audit.run()

        self.assertNotIn(
            "unresolved-curation-state",
            [finding["code"] for finding in result["findings"]],
        )

    def test_frozen_unassigned_projection_still_requires_current_exception(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'REVIEW_READY', "
            "current_deferral_id = NULL, lifecycle_frozen = 1, unassigned = 1 "
            "WHERE item_id = ?",
            (ITEM_2,),
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-unassigned-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_identity_ambiguity_and_correction_block_completion(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET identity_ambiguous = 1 "
            "WHERE item_id = ?",
            (ITEM_1,),
        )
        self.connection.execute(
            "UPDATE item_curation_projection SET correction_required = 1 "
            "WHERE item_id = ?",
            (ITEM_2,),
        )

        result = self.audit.run()

        self.assertEqual(
            [finding["code"] for finding in result["findings"]],
            ["identity-ambiguous", "correction-required"],
        )
        self.assertFalse(result["integrity_ok"])

    def test_unassigned_requires_current_assignment_condition(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET unassigned = 1 WHERE item_id = ?",
            (ITEM_1,),
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-unassigned-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_current_unassigned_exception_explains_assignment_condition(self):
        self._prepare_unassigned_projection("decision-unassigned")

        result = self.audit.run()

        self.assertNotIn(
            "unexplained-unassigned-item",
            [finding["code"] for finding in result["findings"]],
        )
        self.assertNotIn(
            "unresolved-curation-state",
            [finding["code"] for finding in result["findings"]],
        )

    def test_unassigned_exception_requires_current_decision_provenance(self):
        self._prepare_unassigned_projection("decision-2")

        result = self.audit.run()

        self.assertIn(
            "unexplained-unassigned-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_unassigned_exception_requires_typed_condition_payload(self):
        self._prepare_unassigned_projection("decision-unassigned")
        condition = canonical_json_bytes({})
        self.connection.execute(
            "UPDATE unassigned_exceptions SET assignment_condition_json = ?, "
            "assignment_condition_sha256 = ? WHERE item_id = ?",
            (condition, sha256_bytes(condition), ITEM_1),
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-unassigned-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_unassigned_explanation_requires_projection_source_binding(self):
        self._prepare_unassigned_projection("decision-unassigned")
        self.connection.execute(
            "UPDATE item_curation_projection SET source_event_id = 'decision-2' "
            "WHERE item_id = ?",
            (ITEM_1,),
        )

        result = self.audit.run()

        codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("unexplained-unassigned-item", codes)
        self.assertIn("unresolved-curation-state", codes)

    def test_unassigned_explanation_requires_review_ready_projection(self):
        self._prepare_unassigned_projection("decision-unassigned")
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'DISCOVERED' "
            "WHERE item_id = ?",
            (ITEM_1,),
        )

        result = self.audit.run()

        codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("unexplained-unassigned-item", codes)
        self.assertIn("unresolved-curation-state", codes)

    def test_unassigned_explanation_requires_projection_generation_binding(self):
        self._prepare_unassigned_projection("decision-unassigned")
        self.connection.execute(
            "UPDATE item_curation_projection SET projection_generation = 3 "
            "WHERE item_id = ?",
            (ITEM_1,),
        )

        result = self.audit.run()

        codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("unexplained-unassigned-item", codes)
        self.assertIn("unresolved-curation-state", codes)

    def test_projection_rejects_unexpected_current_unassigned_exception(self):
        self._prepare_unassigned_projection("decision-unassigned")
        self.connection.execute(
            "UPDATE item_curation_projection SET unassigned = 0 WHERE item_id = ?",
            (ITEM_1,),
        )

        result = self.audit.run()

        self.assertIn(
            "unexpected-current-unassigned-exception",
            [finding["code"] for finding in result["findings"]],
        )

    def test_deferred_requires_current_matching_explanation(self):
        self.connection.execute(
            "UPDATE deferrals SET state = 'SUPERSEDED' WHERE deferral_id = 'deferral-1'"
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-deferred-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_deferred_requires_nonempty_text_evidence_payload(self):
        required = canonical_json_bytes({})
        self.connection.execute(
            "UPDATE deferrals SET required_evidence_json = ?, "
            "required_evidence_sha256 = ? WHERE deferral_id = 'deferral-1'",
            (required, sha256_bytes(required)),
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-deferred-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_deferred_invalid_unicode_evidence_fails_closed(self):
        required = b'"\\ud800"\n'
        self.connection.execute(
            "UPDATE deferrals SET required_evidence_json = ?, "
            "required_evidence_sha256 = ? WHERE deferral_id = 'deferral-1'",
            (required, sha256_bytes(required)),
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-deferred-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_deferred_excessively_nested_evidence_fails_closed(self):
        required = (b"[" * 2000) + (b"]" * 2000)
        self.connection.execute(
            "UPDATE deferrals SET required_evidence_json = ?, "
            "required_evidence_sha256 = ? WHERE deferral_id = 'deferral-1'",
            (required, sha256_bytes(required)),
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-deferred-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_non_blob_evidence_is_rejected_without_bytes_allocation(self):
        self.connection.execute(
            "UPDATE deferrals SET required_evidence_json = 100000000, "
            "required_evidence_sha256 = ? WHERE deferral_id = 'deferral-1'",
            ("0" * 64,),
        )

        with mock.patch.object(
            curation_audit,
            "bytes",
            side_effect=AssertionError("non-BLOB payload reached bytes()"),
            create=True,
        ):
            result = self.audit.run()

        self.assertIn(
            "unexplained-deferred-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_multibyte_text_evidence_is_not_materialized_as_blob(self):
        required = "\U0001f600" * 400
        self.connection.execute(
            "UPDATE deferrals SET required_evidence_json = ?, "
            "required_evidence_sha256 = ? WHERE deferral_id = 'deferral-1'",
            (required, sha256_bytes(required.encode("utf-8"))),
        )
        with mock.patch.object(
            curation_audit,
            "_AUDIT_MAX_TOTAL_BLOB_BYTES",
            1024,
        ):
            result = self.audit.run()

        self.assertIn(
            "projection-evidence-scan-truncated",
            [finding["code"] for finding in result["findings"]],
        )

    def test_deferred_requires_valid_date_revisit_condition(self):
        self.connection.execute(
            "UPDATE deferrals SET revisit_date = 'banana', timezone = 'banana' "
            "WHERE deferral_id = 'deferral-1'"
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-deferred-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_deferred_requires_nonactive_workstream_lifecycle(self):
        self.connection.execute(
            "UPDATE deferrals SET trigger_kind = 'WORKSTREAM_RESUME', "
            "revisit_date = NULL, timezone = NULL, "
            "trigger_workstream_id = 'workstream-1', "
            "captured_lifecycle = 'active', captured_policy_sha256 = ? "
            "WHERE deferral_id = 'deferral-1'",
            ("0" * 64,),
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-deferred-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_deferred_requires_matching_defer_decision(self):
        self.connection.execute(
            "UPDATE deferrals SET state = 'CURRENT' "
            "WHERE deferral_id = 'deferral-2'"
        )
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'DEFERRED', "
            "current_decision_id = 'decision-2', current_deferral_id = 'deferral-2' "
            "WHERE item_id = ?",
            (ITEM_2,),
        )

        result = self.audit.run()

        self.assertIn(
            "unexplained-deferred-item",
            [finding["code"] for finding in result["findings"]],
        )

    def test_non_deferred_projection_rejects_unpointed_current_deferral(self):
        self.connection.execute(
            "UPDATE deferrals SET state = 'CURRENT' "
            "WHERE deferral_id = 'deferral-2'"
        )

        result = self.audit.run()

        self.assertIn(
            "unexpected-current-deferral",
            [finding["code"] for finding in result["findings"]],
        )

    def test_non_deferred_projection_rejects_retained_current_deferral(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET current_deferral_id = 'deferral-2' "
            "WHERE item_id = ?",
            (ITEM_2,),
        )

        result = self.audit.run()

        self.assertIn(
            "unexpected-current-deferral",
            [finding["code"] for finding in result["findings"]],
        )

    def test_terminal_projection_requires_matching_decision_action(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'KEEP' "
            "WHERE item_id = ?",
            (ITEM_2,),
        )

        result = self.audit.run()

        self.assertIn(
            "projection-decision-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_applied_projection_fails_closed_without_execution_validator(self):
        self.connection.execute(
            "UPDATE item_curation_projection SET primary_state = 'APPLIED', "
            "source_execution_id = NULL WHERE item_id = ?",
            (ITEM_2,),
        )

        result = self.audit.run()

        self.assertIn(
            "unsupported-applied-provenance",
            [finding["code"] for finding in result["findings"]],
        )

    def test_linked_projection_requires_current_relation_from_decision(self):
        self.connection.execute(
            "UPDATE workstream_relations SET state = 'SUPERSEDED' "
            "WHERE item_id = ?",
            (ITEM_2,),
        )
        self.connection.execute(
            "UPDATE document_relations SET state = 'SUPERSEDED' "
            "WHERE canonical_item_id = ? OR related_item_id = ?",
            (ITEM_2, ITEM_2),
        )

        result = self.audit.run()

        self.assertIn(
            "projection-relation-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_clean_integrity_slice_does_not_claim_curation_completion(self):
        result = self.audit.run()

        self.assertTrue(result["integrity_ok"])
        self.assertIsNone(result["curation_complete"])
        self.assertNotIn("complete", result)
        self.assertEqual(
            result["scope"],
            {
                "checks": [
                    "batch-event-bridge",
                    "control-artifact-incompletes",
                    "projection-explanations",
                ],
                "curation_completion_evaluated": False,
                "kind": "integrity-slice",
            },
        )

    def test_sqlite_query_failure_is_translated_to_audit_error(self):
        with mock.patch.object(
            self.audit,
            "_projection_findings",
            side_effect=sqlite3.OperationalError("simulated query failure"),
        ):
            with self.assertRaises(curation_audit.CurationAuditError):
                self.audit.run()

    def test_reports_rowless_batch_event_artifact_as_orphan(self):
        artifact = self.event_root / "orphan-event" / "event.json"
        artifact.parent.mkdir(parents=True, mode=0o700)
        artifact.write_bytes(b"{}\n")
        artifact.chmod(0o600)
        before = self.connection.total_changes

        result = self.audit.run()

        self.assertFalse(result["integrity_ok"])
        self.assertEqual(result["summary"]["orphan"], 1)
        self.assertEqual(
            result["findings"],
            [
                {
                    "blocking": True,
                    "category": "orphan",
                    "code": "rowless-batch-event-artifact",
                    "path": "campaigns/campaign-1/batch-events/orphan-event/event.json",
                }
            ],
        )
        self.assertEqual(self.connection.total_changes, before)

    def test_reports_empty_rowless_batch_event_directory(self):
        directory = self.event_root / "empty-event"
        directory.mkdir(parents=True, mode=0o700)

        result = self.audit.run()

        self.assertIn(
            "rowless-batch-event-artifact",
            [finding["code"] for finding in result["findings"]],
        )

    def test_reports_rowless_batch_event_file_without_following(self):
        self.event_root.mkdir(parents=True, mode=0o700)
        entry = self.event_root / "rowless-file"
        entry.write_bytes(b"not an event directory")

        result = self.audit.run()

        self.assertIn(
            "rowless-batch-event-entry",
            [finding["code"] for finding in result["findings"]],
        )

    def test_reports_rowless_batch_event_symlink_without_following(self):
        outside = self.control_root.parent / "outside-rowless"
        outside.write_bytes(b"outside")
        self.event_root.mkdir(parents=True, mode=0o700)
        (self.event_root / "rowless-link").symlink_to(outside)

        result = self.audit.run()

        self.assertIn(
            "rowless-batch-event-entry",
            [finding["code"] for finding in result["findings"]],
        )
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_reports_unexpected_entry_in_bound_event_directory(self):
        artifact, _payload = self._published_batch_event("event-extra")
        (artifact.parent / "rogue.json").write_bytes(b"rogue")

        result = self.audit.run()

        self.assertIn(
            "unexpected-batch-event-entry",
            [finding["code"] for finding in result["findings"]],
        )

    def test_invalid_blob_event_identifier_produces_json_safe_finding(self):
        self._published_batch_event("event-invalid-id")
        self.connection.execute(
            "UPDATE batch_events SET batch_event_id = ? "
            "WHERE batch_event_id = 'event-invalid-id'",
            (sqlite3.Binary(b"\xff"),),
        )

        result = self.audit.run()

        rendered = json.dumps(result, ensure_ascii=False)
        self.assertIn("batch-event-storage-invalid", rendered)
        self.assertNotIn("b'", rendered)

    def test_reports_missing_published_batch_event_artifact(self):
        payload = self._event_payload("event-1")
        artifact = self.event_root / "event-1" / "event.json"
        self._insert_batch_event("event-1", artifact, payload)
        before = self.connection.total_changes

        result = self.audit.run()

        self.assertEqual(
            result["findings"],
            [
                {
                    "batch_event_id": "event-1",
                    "blocking": True,
                    "category": "integrity",
                    "code": "missing-batch-event-artifact",
                    "path": "campaigns/campaign-1/batch-events/event-1/event.json",
                    "state": "PUBLISHED",
                }
            ],
        )
        self.assertEqual(self.connection.total_changes, before)

    def test_reports_batch_event_artifact_hash_mismatch_without_content(self):
        payload = self._event_payload("event-2")
        artifact = self.event_root / "event-2" / "event.json"
        artifact.parent.mkdir(parents=True, mode=0o700)
        artifact.write_bytes(canonical_json_bytes({"event_id": "changed"}))
        artifact.chmod(0o600)
        self._insert_batch_event("event-2", artifact, payload)
        before = self.connection.total_changes

        result = self.audit.run()

        self.assertEqual(
            result["findings"],
            [
                {
                    "batch_event_id": "event-2",
                    "blocking": True,
                    "category": "integrity",
                    "code": "batch-event-artifact-mismatch",
                    "path": "campaigns/campaign-1/batch-events/event-2/event.json",
                    "state": "PUBLISHED",
                }
            ],
        )
        self.assertNotIn("changed", str(result))
        self.assertEqual(self.connection.total_changes, before)

    def test_rejects_matching_non_blob_batch_payload_storage(self):
        artifact, _payload = self._published_batch_event("event-nonblob")
        rebound = b"123"
        artifact.write_bytes(rebound)
        self.connection.execute(
            "UPDATE batch_events SET payload_json = 123, payload_sha256 = ?, "
            "final_sha256 = ? WHERE batch_event_id = 'event-nonblob'",
            (sha256_bytes(rebound), sha256_bytes(rebound)),
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-storage-invalid",
            [finding["code"] for finding in result["findings"]],
        )

    def test_multibyte_text_event_payload_is_rejected_without_blob_materialization(self):
        self._published_batch_event("event-multibyte-text")
        payload = "\U0001f600" * 400
        self.connection.execute(
            "UPDATE batch_events SET payload_json = ?, payload_sha256 = ?, "
            "final_sha256 = ? WHERE batch_event_id = 'event-multibyte-text'",
            (
                payload,
                sha256_bytes(payload.encode("utf-8")),
                sha256_bytes(payload.encode("utf-8")),
            ),
        )
        with mock.patch.object(
            curation_audit,
            "_AUDIT_MAX_TOTAL_BLOB_BYTES",
            1024,
        ):
            result = self.audit.run()

        self.assertIn(
            "batch-event-payload-scan-truncated",
            [finding["code"] for finding in result["findings"]],
        )

    def test_rejects_matching_non_blob_membership_release_storage(self):
        self._published_batch_event("event-nonblob-release")
        rebound = b"123"
        self.connection.execute(
            "UPDATE batch_events SET membership_release_json = 123, "
            "membership_release_sha256 = ? "
            "WHERE batch_event_id = 'event-nonblob-release'",
            (sha256_bytes(rebound),),
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-storage-invalid",
            [finding["code"] for finding in result["findings"]],
        )

    def test_rejects_matching_noncanonical_batch_payload(self):
        artifact, _payload = self._published_batch_event("event-noncanonical")
        rebound = b'{"schema_version":1}'
        artifact.write_bytes(rebound)
        self.connection.execute(
            "UPDATE batch_events SET payload_json = ?, payload_sha256 = ?, "
            "final_sha256 = ? WHERE batch_event_id = 'event-noncanonical'",
            (rebound, sha256_bytes(rebound), sha256_bytes(rebound)),
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_rejects_json_boolean_alias_for_integer_event_field(self):
        artifact, payload_json = self._published_batch_event("event-bool-counter")
        payload = json.loads(payload_json.decode("utf-8"))
        payload["expected_review_revision"] = True
        payload["schema_version"] = True
        rebound = canonical_json_bytes(payload)
        artifact.write_bytes(rebound)
        self.connection.execute(
            "UPDATE batch_events SET payload_json = ?, payload_sha256 = ?, "
            "final_sha256 = ? WHERE batch_event_id = 'event-bool-counter'",
            (rebound, sha256_bytes(rebound), sha256_bytes(rebound)),
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_rejects_traversal_membership_path_even_when_fully_rebound(self):
        artifact, payload_json = self._published_batch_event("event-path-traversal")
        release = self._membership_release()
        release[0]["path"] = "../outside"
        release_json = canonical_json_bytes(release)
        payload = json.loads(payload_json.decode("utf-8"))
        payload["membership_release"] = release
        payload["membership_release_sha256"] = sha256_bytes(release_json)
        rebound = canonical_json_bytes(payload)
        artifact.write_bytes(rebound)
        self.connection.execute(
            "UPDATE batch_memberships SET path = '../outside' "
            "WHERE membership_id = 'membership-audit'"
        )
        self.connection.execute(
            "UPDATE batch_events SET membership_release_json = ?, "
            "membership_release_sha256 = ?, payload_json = ?, "
            "payload_sha256 = ?, final_sha256 = ? "
            "WHERE batch_event_id = 'event-path-traversal'",
            (
                release_json,
                sha256_bytes(release_json),
                rebound,
                sha256_bytes(rebound),
                sha256_bytes(rebound),
            ),
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_rejects_rebound_membership_release(self):
        self._published_batch_event("event-release-drift")
        release = canonical_json_bytes(
            [
                {
                    "item_id": ITEM_1,
                    "membership_id": "membership-audit",
                    "path": "projects/rebound.md",
                    "unit_id": "unit-audit",
                }
            ]
        )
        self.connection.execute(
            "UPDATE batch_events SET membership_release_json = ?, "
            "membership_release_sha256 = ? "
            "WHERE batch_event_id = 'event-release-drift'",
            (release, sha256_bytes(release)),
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_rejects_row_to_payload_lineage_rebind(self):
        self._published_batch_event("event-row-rebind")
        self.connection.execute(
            "UPDATE batch_events SET expected_review_revision = 2 "
            "WHERE batch_event_id = 'event-row-rebind'"
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_prepared_batch_event_is_blocking_recovery_evidence(self):
        self._published_batch_event("event-prepared")
        self.connection.execute(
            "UPDATE batch_events SET state = 'PREPARED' "
            "WHERE batch_event_id = 'event-prepared'"
        )

        result = self.audit.run()

        self.assertIn(
            "unresolved-batch-event",
            [finding["code"] for finding in result["findings"]],
        )

    def test_blocked_batch_event_is_blocking_recovery_evidence(self):
        self._published_batch_event("event-blocked")
        self.connection.execute(
            "UPDATE batch_events SET state = 'BLOCKED' "
            "WHERE batch_event_id = 'event-blocked'"
        )

        result = self.audit.run()

        self.assertIn(
            "unresolved-batch-event",
            [finding["code"] for finding in result["findings"]],
        )

    def test_published_terminal_event_requires_stable_batch_lineage(self):
        self._published_batch_event("event-lineage-drift")
        self.connection.execute(
            "UPDATE review_batches SET status = 'OPEN' "
            "WHERE batch_id = 'batch-1'"
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_published_terminal_event_requires_released_memberships(self):
        self._published_batch_event("event-membership-drift")
        self.connection.execute(
            "UPDATE batch_memberships SET status = 'OPEN' "
            "WHERE membership_id = 'membership-audit'"
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_published_terminal_event_rejects_unreleased_extra_membership(self):
        self._published_batch_event("event-extra-open-membership")
        self.connection.execute(
            "INSERT INTO batch_memberships ("
            "membership_id, batch_id, unit_id, item_id, path, status"
            ") VALUES ('membership-extra', 'batch-1', 'unit-extra', ?, "
            "'projects/extra.md', 'OPEN')",
            (ITEM_2,),
        )

        result = self.audit.run()

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in result["findings"]],
        )

    def test_published_abandon_event_satisfies_batch_event_contract(self):
        self._published_batch_event("event-abandon", "ABANDON")

        result = self.audit.run()

        self.assertTrue(result["integrity_ok"])
        self.assertEqual(result["findings"], [])

    def test_future_batch_event_kind_fails_closed_until_supported(self):
        self._published_batch_event("event-future-kind")
        self.connection.execute(
            "UPDATE batch_events SET event_kind = 'STRUCTURAL_FINALIZATION', "
            "expected_batch_status = 'CLAIMED', "
            "terminal_batch_status = 'APPLIED', "
            "source_execution_id = 'execution-future', "
            "source_approval_id = 'approval-future', "
            "result_path = 'results/future.json', result_sha256 = ? "
            "WHERE batch_event_id = 'event-future-kind'",
            ("1" * 64,),
        )

        result = self.audit.run()

        self.assertIn(
            "unsupported-batch-event-kind",
            [finding["code"] for finding in result["findings"]],
        )

    def test_reports_incomplete_control_artifact_without_deleting_it(self):
        incomplete = self.control_root / "recoveries" / ".incomplete-recovery-1"
        incomplete.mkdir(parents=True, mode=0o700)
        before = self.connection.total_changes

        result = self.audit.run()

        self.assertEqual(
            result["findings"],
            [
                {
                    "blocking": False,
                    "category": "integrity",
                    "code": "incomplete-control-artifact-observed",
                    "path": "recoveries/.incomplete-recovery-1",
                }
            ],
        )
        self.assertTrue(result["integrity_ok"])
        self.assertTrue(incomplete.is_dir())
        self.assertEqual(self.connection.total_changes, before)

    def test_rejects_dotdot_batch_event_path_without_reading_target(self):
        payload = self._event_payload("event-dotdot")
        outside = self.control_root.parent / "outside-event.json"
        outside.write_bytes(payload)
        outside.chmod(0o600)
        self.event_root.mkdir(parents=True, mode=0o700)
        artifact = (
            self.control_root
            / "batch-events"
            / ".."
            / ".."
            / outside.name
        )
        self._insert_batch_event("event-dotdot", artifact, payload)

        with mock.patch.object(
            curation_audit,
            "_read_bounded_regular_file",
            side_effect=AssertionError("outside target must not be opened"),
        ) as reader:
            result = self.audit.run()

        reader.assert_not_called()
        self.assertEqual(result["findings"][0]["category"], "integrity")
        self.assertEqual(
            result["findings"][0]["code"],
            "unsafe-batch-event-artifact-path",
        )
        self.assertEqual(outside.read_bytes(), payload)

    def test_rejects_symlinked_batch_event_root_without_reading_target(self):
        payload = self._event_payload("event-symlink")
        outside_root = self.control_root.parent / "outside-batch-events"
        outside_artifact = outside_root / "event-symlink" / "event.json"
        outside_artifact.parent.mkdir(parents=True, mode=0o700)
        outside_artifact.write_bytes(payload)
        outside_artifact.chmod(0o600)
        self.event_root.parent.mkdir(parents=True, mode=0o700)
        self.event_root.symlink_to(
            outside_root,
            target_is_directory=True,
        )
        lexical_artifact = (
            self.event_root / "event-symlink" / "event.json"
        )
        self._insert_batch_event("event-symlink", lexical_artifact, payload)

        result = self.audit.run()

        self.assertEqual(
            result["findings"],
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "unsafe-batch-event-root",
                    "path": "campaigns/campaign-1/batch-events",
                }
            ],
        )
        self.assertEqual(outside_artifact.read_bytes(), payload)

    def test_rejects_noncanonical_batch_event_identifier_before_read(self):
        event_id = "event\\escape"
        payload = self._event_payload(event_id)
        artifact = self.event_root / event_id / "event.json"
        artifact.parent.mkdir(parents=True, mode=0o700)
        artifact.write_bytes(payload)
        artifact.chmod(0o600)
        self._insert_batch_event(event_id, artifact, payload)

        with mock.patch.object(
            curation_audit,
            "_read_bounded_regular_file",
            side_effect=AssertionError("invalid identifier must not be read"),
        ) as reader:
            result = self.audit.run()

        reader.assert_not_called()
        self.assertEqual(
            result["findings"][0]["code"],
            "batch-event-storage-invalid",
        )

    def test_rejects_unsafe_batch_event_file_and_parent_identities(self):
        event_root = self.event_root
        event_root.mkdir(parents=True, mode=0o700)

        mode_payload = self._event_payload("event-mode")
        mode_artifact = event_root / "event-mode" / "event.json"
        mode_artifact.parent.mkdir(mode=0o700)
        mode_artifact.write_bytes(mode_payload)
        mode_artifact.chmod(0o644)
        self._insert_batch_event("event-mode", mode_artifact, mode_payload)

        hardlink_payload = self._event_payload("event-hardlink")
        hardlink_source = self.control_root / "hardlink-source.json"
        hardlink_source.write_bytes(hardlink_payload)
        hardlink_source.chmod(0o600)
        hardlink_artifact = event_root / "event-hardlink" / "event.json"
        hardlink_artifact.parent.mkdir(mode=0o700)
        os.link(hardlink_source, hardlink_artifact)
        self._insert_batch_event(
            "event-hardlink", hardlink_artifact, hardlink_payload
        )

        leaf_payload = self._event_payload("event-leaf")
        outside_file = self.control_root.parent / "outside-leaf.json"
        outside_file.write_bytes(leaf_payload)
        outside_file.chmod(0o600)
        leaf_artifact = event_root / "event-leaf" / "event.json"
        leaf_artifact.parent.mkdir(mode=0o700)
        leaf_artifact.symlink_to(outside_file)
        self._insert_batch_event("event-leaf", leaf_artifact, leaf_payload)

        parent_payload = self._event_payload("event-parent")
        outside_parent = self.control_root.parent / "outside-parent"
        outside_parent.mkdir(mode=0o700)
        (outside_parent / "event.json").write_bytes(parent_payload)
        (outside_parent / "event.json").chmod(0o600)
        parent = event_root / "event-parent"
        parent.symlink_to(outside_parent, target_is_directory=True)
        parent_artifact = parent / "event.json"
        self._insert_batch_event("event-parent", parent_artifact, parent_payload)

        result = self.audit.run()

        self.assertEqual(
            [finding["code"] for finding in result["findings"]],
            ["unsafe-batch-event-artifact"] * 4,
        )
        self.assertNotIn(mode_payload.decode("utf-8").strip(), str(result))

    def test_control_scan_hard_cap_does_not_consume_unbounded_iterator(self):
        def entry(name):
            candidate = mock.Mock()
            candidate.name = name
            candidate.path = str(self.control_root / name)
            candidate.is_dir.return_value = False
            return candidate

        def entries():
            yield entry(".incomplete-a")
            yield entry(".incomplete-b")
            yield entry(".incomplete-c")
            raise AssertionError("scan consumed beyond hard cap witness")

        scanner = mock.MagicMock()
        scanner.__enter__.return_value = entries()
        with mock.patch.object(
            curation_audit,
            "_CONTROL_SCAN_MAX_ENTRIES",
            2,
        ), mock.patch.object(curation_audit.os, "scandir", return_value=scanner):
            findings = self.audit._incomplete_artifact_findings()

        self.assertEqual(
            findings,
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "control-artifact-scan-truncated",
                    "path": ".",
                }
            ],
        )

    def test_reports_control_scan_depth_truncation(self):
        (self.control_root / "nested").mkdir(mode=0o700)

        with mock.patch.object(
            curation_audit,
            "_CONTROL_SCAN_MAX_DEPTH",
            0,
        ):
            findings = self.audit._incomplete_artifact_findings()

        self.assertEqual(
            findings,
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "control-artifact-scan-depth-truncated",
                    "path": "nested",
                }
            ],
        )

    def test_batch_event_scan_hard_cap_reports_only_truncation(self):
        for event_id in ("event-a", "event-b", "event-c"):
            artifact = (
                self.event_root / event_id / "event.json"
            )
            artifact.parent.mkdir(parents=True, mode=0o700)
            artifact.write_bytes(b"{}\n")
            artifact.chmod(0o600)

        with mock.patch.object(
            curation_audit,
            "_CONTROL_SCAN_MAX_ENTRIES",
            2,
        ):
            findings = self.audit._batch_event_artifact_findings()

        self.assertEqual(
            findings,
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "batch-event-scan-truncated",
                    "path": "campaigns/campaign-1/batch-events",
                }
            ],
        )

    def test_batch_event_artifact_size_is_rejected_before_content_read(self):
        payload = self._event_payload("event-bounded")
        artifact = (
            self.event_root / "event-bounded" / "event.json"
        )
        artifact.parent.mkdir(parents=True, mode=0o700)
        artifact.write_bytes(payload + (b"x" * (1024 * 1024)))
        artifact.chmod(0o600)
        self._insert_batch_event("event-bounded", artifact, payload)
        real_read = os.read

        with mock.patch.object(
            curation_audit.os,
            "read",
            wraps=real_read,
        ) as reader:
            findings = self.audit._batch_event_artifact_findings()

        self.assertFalse(reader.called)
        self.assertEqual(findings[0]["code"], "unsafe-batch-event-artifact")

    def test_batch_event_ledger_scan_is_bounded(self):
        for event_id in ("event-row-a", "event-row-b"):
            payload = self._event_payload(event_id)
            artifact = self.event_root / event_id / "event.json"
            self._insert_batch_event(event_id, artifact, payload)

        with mock.patch.object(
            curation_audit,
            "_AUDIT_MAX_LEDGER_ROWS",
            1,
        ):
            findings = self.audit._batch_event_artifact_findings()

        self.assertEqual(
            findings,
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "batch-event-ledger-scan-truncated",
                }
            ],
        )

    def test_batch_event_payloads_share_one_global_byte_budget(self):
        for event_id in ("event-budget-a", "event-budget-b"):
            payload = self._event_payload(event_id)
            artifact = self.event_root / event_id / "event.json"
            self._insert_batch_event(event_id, artifact, payload)

        with mock.patch.object(
            curation_audit,
            "_AUDIT_MAX_TOTAL_BLOB_BYTES",
            1,
        ), mock.patch.object(
            curation_audit,
            "_read_bounded_regular_file",
            side_effect=AssertionError("over-budget scan must not read artifacts"),
        ) as reader:
            findings = self.audit._batch_event_artifact_findings()

        reader.assert_not_called()
        self.assertEqual(
            findings,
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "batch-event-payload-scan-truncated",
                }
            ],
        )

    def test_oversized_batch_event_payload_is_not_loaded_or_read(self):
        payload = self._event_payload("event-payload-bound")
        artifact = (
            self.event_root / "event-payload-bound" / "event.json"
        )
        self._insert_batch_event("event-payload-bound", artifact, payload)

        with mock.patch.object(
            curation_audit,
            "_BATCH_EVENT_MAX_PAYLOAD_BYTES",
            8,
        ), mock.patch.object(
            curation_audit,
            "_read_bounded_regular_file",
            side_effect=AssertionError("oversized payload must not read artifact"),
        ) as reader:
            findings = self.audit._batch_event_artifact_findings()

        reader.assert_not_called()
        self.assertEqual(findings[0]["code"], "batch-event-payload-bound-exceeded")

    def test_projection_ledger_scan_is_bounded(self):
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_3,),
        )

        with mock.patch.object(
            curation_audit,
            "_AUDIT_MAX_LEDGER_ROWS",
            1,
        ):
            findings = self.audit._projection_findings()

        self.assertEqual(
            findings,
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "projection-ledger-scan-truncated",
                }
            ],
        )

    def test_projection_explanations_share_one_global_byte_budget(self):
        with mock.patch.object(
            curation_audit,
            "_AUDIT_MAX_TOTAL_BLOB_BYTES",
            1,
        ):
            findings = self.audit._projection_findings()

        self.assertEqual(
            findings,
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "projection-evidence-scan-truncated",
                }
            ],
        )


class CurationAuditReportTest(unittest.TestCase):
    def test_runtime_failure_report_requires_typed_code(self):
        with self.assertRaises(TypeError):
            curation_audit.runtime_failure_report("policy-admission-blocked")


class CurationAuditPublicOperationTest(LedgerRuntimeFixture):
    def setUp(self):
        super().setUp()
        self.migrate_to_v2()
        plan = m3_schema_migration.preview_m3_migration(
            self.root,
            plan_id="m3mig-plan-curation-audit",
            requested_by="curation-audit-test",
        )
        approval = m3_schema_migration.approve_m3_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="curation-audit-approver",
        )
        m3_schema_migration.apply_m3_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="curation-audit-executor",
        )

    def _tree_snapshot(self):
        entries = []
        for path in self.root.rglob("*"):
            info = path.lstat()
            file_type = stat.S_IFMT(info.st_mode)
            if stat.S_ISREG(info.st_mode):
                content_identity = sha256_bytes(path.read_bytes())
            elif stat.S_ISLNK(info.st_mode):
                content_identity = os.readlink(path)
            else:
                content_identity = None
            entries.append(
                (
                    str(path.relative_to(self.root)),
                    file_type,
                    stat.S_IMODE(info.st_mode),
                    info.st_uid,
                    info.st_nlink,
                    content_identity,
                )
            )
        return tuple(sorted(entries))

    def test_activated_v3_audit_is_query_only_and_preserves_tree(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.audit",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="curation-audit-test",
            requested_authority=operation_contract.AuthorityMode.READ,
            payload={"offset": 0},
            bounds={"max_items": 64},
        )
        before = self._tree_snapshot()

        raw_result = mnemosyne._mnemosyne_core.execute_request_bytes(
            request.canonical_bytes
        )
        result = json.loads(raw_result.decode("utf-8"))

        self.assertEqual(result["outcome_kind"], "completed")
        self.assertEqual(result["request_sha256"], request.sha256)
        self.assertEqual(result["result"]["view"], "audit")
        self.assertEqual(result["result"]["schema_version"], 2)
        self.assertEqual(result["result"]["activation_state"], "BLOCKED")
        self.assertFalse(result["result"]["activation_eligible"])
        self.assertEqual(
            result["result"]["reason_code"],
            "LEGACY_AUTHORITY_PRESENT",
        )
        self.assertFalse(result["result"]["integrity_ok"])
        self.assertNotIn("activation_markers", result["result"])
        self.assertIsNone(result["result"]["curation_complete"])
        self.assertEqual(self._tree_snapshot(), before)


if __name__ == "__main__":
    unittest.main()
