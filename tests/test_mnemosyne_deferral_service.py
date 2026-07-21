import datetime
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import deferral_service  # noqa: E402


HASH = "a" * 64


def record(trigger_kind, **changes):
    values = {
        "deferral_id": "deferral-1",
        "item_id": "item-1",
        "version": 1,
        "state": "waiting",
        "trigger_kind": trigger_kind,
        "review_date": None,
        "timezone": None,
        "workstream_id": None,
        "captured_lifecycle": None,
        "captured_policy_hash": None,
    }
    values.update(changes)
    return deferral_service.DeferralRecord(**values)


class DeferralTriggerPreviewTest(unittest.TestCase):
    def test_date_preview_uses_stored_calendar_and_timezone_without_mutation(self):
        deferred = record(
            "date",
            review_date="2026-03-08",
            timezone="America/Los_Angeles",
        )
        before = deferred

        scheduled = deferral_service.DeferralTriggerEvaluator().preview(
            deferred,
            now=datetime.datetime(
                2026, 3, 8, 7, 59, tzinfo=datetime.timezone.utc
            ),
        )
        due = deferral_service.DeferralTriggerEvaluator().preview(
            deferred,
            now=datetime.datetime(
                2026, 3, 8, 8, 0, tzinfo=datetime.timezone.utc
            ),
        )

        self.assertEqual(scheduled.inbox_state, "scheduled-later")
        self.assertFalse(scheduled.triggered)
        self.assertEqual(due.inbox_state, "due")
        self.assertTrue(due.triggered)
        self.assertEqual(deferred, before)
        self.assertEqual(
            due.trigger_evidence_hash,
            deferral_service.DeferralTriggerEvaluator().preview(
                deferred,
                now=datetime.datetime(
                    2026, 3, 9, 12, 0, tzinfo=datetime.timezone.utc
                ),
            ).trigger_evidence_hash,
        )

    def test_workstream_resume_requires_transition_to_active_and_policy_hash(self):
        deferred = record(
            "workstream-resume",
            workstream_id="example-paused-service",
            captured_lifecycle="paused",
            captured_policy_hash=HASH,
        )
        evaluator = deferral_service.DeferralTriggerEvaluator()

        waiting = evaluator.preview(
            deferred,
            now=datetime.datetime.now(datetime.timezone.utc),
            current_workstream_lifecycle="paused",
            current_policy_hash="b" * 64,
        )
        due = evaluator.preview(
            deferred,
            now=datetime.datetime.now(datetime.timezone.utc),
            current_workstream_lifecycle="active",
            current_policy_hash="b" * 64,
        )

        self.assertEqual(waiting.inbox_state, "waiting-workstream-resume")
        self.assertEqual(due.inbox_state, "due")
        self.assertIn("b" * 64, due.trigger_evidence)

    def test_evidence_trigger_accepts_only_exact_published_version(self):
        deferred = record("evidence")
        evaluator = deferral_service.DeferralTriggerEvaluator()
        waiting = evaluator.preview(
            deferred,
            now=datetime.datetime.now(datetime.timezone.utc),
        )
        self.assertEqual(waiting.inbox_state, "waiting-evidence")

        stale = deferral_service.PublishedEvidence(
            event_id="evidence-1",
            event_sha256=HASH,
            deferral_id="deferral-1",
            deferral_version=2,
            state="PUBLISHED",
        )
        with self.assertRaisesRegex(
            deferral_service.DeferralValidationError,
            "version",
        ):
            evaluator.preview(
                deferred,
                now=datetime.datetime.now(datetime.timezone.utc),
                published_evidence=stale,
            )

        published = deferral_service.PublishedEvidence(
            event_id="evidence-1",
            event_sha256=HASH,
            deferral_id="deferral-1",
            deferral_version=1,
            state="PUBLISHED",
        )
        due = evaluator.preview(
            deferred,
            now=datetime.datetime.now(datetime.timezone.utc),
            published_evidence=published,
        )
        self.assertEqual(due.inbox_state, "due")

    def test_manual_reopen_requires_exact_identity_actor_and_reason(self):
        deferred = record("manual-reopen")
        evidence = deferral_service.ManualReopenEvidence(
            deferral_id="deferral-1",
            deferral_version=1,
            actor="reviewer",
            reason="new source authority is available",
        )

        due = deferral_service.DeferralTriggerEvaluator().preview(
            deferred,
            now=datetime.datetime.now(datetime.timezone.utc),
            manual_reopen=evidence,
        )

        self.assertEqual(due.inbox_state, "due")
        self.assertTrue(due.triggered)


class DeferralTriggerEvaluateTest(unittest.TestCase):
    def test_explicit_evaluate_is_deterministic_and_has_no_effect_authority(self):
        deferred = record(
            "date",
            review_date="2026-07-15",
            timezone="Asia/Seoul",
        )
        evaluator = deferral_service.DeferralTriggerEvaluator()
        preview = evaluator.preview(
            deferred,
            now=datetime.datetime(
                2026, 7, 15, 0, 0, tzinfo=datetime.timezone.utc
            ),
        )

        first = evaluator.evaluate(deferred, preview, actor="reviewer")
        second = evaluator.evaluate(deferred, preview, actor="reviewer")

        self.assertEqual(first, second)
        self.assertEqual(
            first.idempotency_key,
            ("deferral-1", "date", preview.trigger_evidence_hash),
        )
        self.assertEqual(first.projection["primary_state"], "review-ready")
        self.assertFalse(first.approval_created)
        self.assertFalse(first.corpus_effect_created)

    def test_evaluate_rejects_a_waiting_preview(self):
        deferred = record(
            "date",
            review_date="2026-07-16",
            timezone="Asia/Seoul",
        )
        preview = deferral_service.DeferralTriggerEvaluator().preview(
            deferred,
            now=datetime.datetime(
                2026, 7, 15, 0, 0, tzinfo=datetime.timezone.utc
            ),
        )

        with self.assertRaisesRegex(
            deferral_service.DeferralValidationError,
            "not due",
        ):
            deferral_service.DeferralTriggerEvaluator().evaluate(
                deferred,
                preview,
                actor="reviewer",
            )


class DeferralEvidenceCompilerTest(unittest.TestCase):
    def test_restricted_evidence_never_accepts_body_or_content_hash(self):
        compiler = deferral_service.DeferralEvidenceCompiler()
        with self.assertRaisesRegex(
            deferral_service.DeferralValidationError,
            "restricted",
        ):
            compiler.compile(
                deferral_service.EvidenceAttachmentInput(
                    event_id="evidence-1",
                    deferral_id="deferral-1",
                    deferral_version=1,
                    actor="reviewer",
                    scope_class="opaque",
                    opaque_source_id="opaque-source-1",
                    actor_attestation="metadata reviewed",
                    allowed_metadata=(("kind", "private-evidence"),),
                    content_sha256=HASH,
                )
            )

        compiled = compiler.compile(
            deferral_service.EvidenceAttachmentInput(
                event_id="evidence-1",
                deferral_id="deferral-1",
                deferral_version=1,
                actor="reviewer",
                scope_class="opaque",
                opaque_source_id="opaque-source-1",
                actor_attestation="metadata reviewed",
                allowed_metadata=(("kind", "private-evidence"),),
            )
        )
        self.assertNotIn("raw_body", compiled.payload)
        self.assertNotIn("content_sha256", compiled.payload)
        self.assertNotIn("source_ref", compiled.payload)
        self.assertEqual(compiled.payload["opaque_source_id"], "opaque-source-1")

    def test_eligible_evidence_requires_safe_reference_and_content_hash(self):
        compiled = deferral_service.DeferralEvidenceCompiler().compile(
            deferral_service.EvidenceAttachmentInput(
                event_id="evidence-2",
                deferral_id="deferral-1",
                deferral_version=1,
                actor="reviewer",
                scope_class="eligible",
                source_ref="example-service/review.md",
                content_sha256=HASH,
                allowed_metadata=(("kind", "review-note"),),
            )
        )

        self.assertEqual(compiled.payload["content_sha256"], HASH)
        self.assertEqual(compiled.payload["source_ref"], "example-service/review.md")
        self.assertEqual(len(compiled.idempotency_key), 64)


if __name__ == "__main__":
    unittest.main()
