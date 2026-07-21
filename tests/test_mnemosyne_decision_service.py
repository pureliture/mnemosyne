import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import decision_service  # noqa: E402


HASH = "a" * 64


def request(*decisions):
    return decision_service.DecisionRequest(
        campaign_id="campaign-1",
        batch_id="batch-1",
        base_snapshot_id="snapshot-1",
        base_snapshot_sha256=HASH,
        expected_review_revision=1,
        expected_execution_generation=0,
        submission_id="submission-2",
        next_snapshot_id="snapshot-2",
        actor="reviewer",
        decided_at_utc="2026-07-15T01:02:03Z",
        decisions=tuple(decisions),
    )


def item(action, **changes):
    values = {
        "unit_id": "unit-1",
        "member_item_ids": ("item-1",),
        "selected_item_ids": ("item-1",),
        "action": action,
    }
    values.update(changes)
    return decision_service.ItemDecisionInput(**values)


class DecisionServiceCompileTest(unittest.TestCase):
    def test_keep_compiles_deterministic_event_and_terminal_projection(self):
        compiled = decision_service.DecisionService().compile(
            request(item("keep", reason="current placement is correct"))
        )

        self.assertEqual(len(compiled.events), 1)
        self.assertEqual(compiled.events[0]["action"], "keep")
        self.assertEqual(compiled.events[0]["item_id"], "item-1")
        self.assertEqual(compiled.events[0]["actor"], "reviewer")
        self.assertEqual(compiled.projections[0]["primary_state"], "keep")
        self.assertEqual(compiled.projections[0]["projection_generation_delta"], 1)
        self.assertEqual(
            decision_service.DecisionService().compile(
                request(item("keep", reason="current placement is correct"))
            ),
            compiled,
        )

    def test_folder_unit_requires_the_complete_member_set(self):
        partial = item(
            "keep",
            member_item_ids=("item-1", "item-2"),
            selected_item_ids=("item-1",),
            reason="partial folder choice",
        )

        with self.assertRaisesRegex(
            decision_service.DecisionValidationError,
            "explode",
        ):
            decision_service.DecisionService().compile(request(partial))

    def test_link_keeps_workstream_and_document_relations_separate(self):
        link = item(
            "link",
            reason="confirmed reference",
            workstream_relations=(
                decision_service.WorkstreamRelationInput(
                    workstream_id="example-service",
                    relation_kind="related",
                    evidence="reviewer confirmation",
                    provenance="snapshot-1",
                ),
            ),
            document_relations=(
                decision_service.DocumentRelationInput(
                    canonical_item_id="item-1",
                    related_item_id="item-2",
                    relation_kind="reference",
                    direction="canonical-to-related",
                    evidence="explicit source link",
                    provenance="snapshot-1",
                ),
            ),
        )

        compiled = decision_service.DecisionService().compile(request(link))

        self.assertEqual(compiled.projections[0]["primary_state"], "linked")
        self.assertEqual(len(compiled.workstream_relations), 1)
        self.assertEqual(len(compiled.document_relation_events), 1)
        self.assertNotIn("navigation_write", compiled.events[0])

    def test_link_without_a_confirmed_relation_is_rejected(self):
        with self.assertRaisesRegex(
            decision_service.DecisionValidationError,
            "relation",
        ):
            decision_service.DecisionService().compile(
                request(item("link", reason="missing relation"))
            )

    def test_defer_requires_reason_evidence_and_a_well_formed_trigger(self):
        missing = decision_service.DeferralInput(
            reason="needs owner input",
            required_evidence="",
            trigger_kind="evidence",
        )
        with self.assertRaisesRegex(
            decision_service.DecisionValidationError,
            "required evidence",
        ):
            decision_service.DecisionService().compile(
                request(item("defer", deferral=missing))
            )

        date_without_timezone = decision_service.DeferralInput(
            reason="wait until review window",
            required_evidence="review confirmation",
            trigger_kind="date",
            review_date="2026-08-01",
        )
        with self.assertRaisesRegex(
            decision_service.DecisionValidationError,
            "timezone",
        ):
            decision_service.DecisionService().compile(
                request(item("defer", deferral=date_without_timezone))
            )

    def test_valid_defer_compiles_waiting_projection_and_structured_row(self):
        deferred = item(
            "defer",
            deferral=decision_service.DeferralInput(
                reason="wait for owner confirmation",
                required_evidence="signed review note",
                trigger_kind="evidence",
                owner="owner-a",
            ),
        )

        compiled = decision_service.DecisionService().compile(request(deferred))

        self.assertEqual(compiled.projections[0]["primary_state"], "deferred")
        self.assertEqual(compiled.deferrals[0]["trigger_kind"], "evidence")
        self.assertEqual(compiled.deferrals[0]["version"], 1)
        self.assertEqual(compiled.deferrals[0]["state"], "waiting")

    def test_proposal_reject_never_becomes_excluded(self):
        compiled = decision_service.DecisionService().compile(
            request(item("proposal-reject", reason="candidate is incorrect"))
        )

        self.assertEqual(compiled.events[0]["action"], "proposal-reject")
        self.assertEqual(compiled.projections[0]["primary_state"], "review-ready")
        self.assertTrue(compiled.projections[0]["correction_required"])

    def test_correction_requires_a_typed_changed_field(self):
        with self.assertRaisesRegex(
            decision_service.DecisionValidationError,
            "correction",
        ):
            decision_service.DecisionService().compile(
                request(item("correction", reason="nothing changed"))
            )

        compiled = decision_service.DecisionService().compile(
            request(
                item(
                    "correction",
                    reason="authority corrected",
                    corrections=(("authority", "reference"),),
                )
            )
        )
        self.assertEqual(compiled.events[0]["corrections"], {"authority": "reference"})
        self.assertEqual(compiled.projections[0]["primary_state"], "review-ready")

    def test_correction_may_confirm_a_document_relation_without_becoming_linked(self):
        relation = decision_service.DocumentRelationInput(
            canonical_item_id="item-1",
            related_item_id="item-2",
            relation_kind="evidence",
            direction="canonical-to-related",
            evidence="reviewer confirmed evidence lineage",
            provenance="snapshot-1",
        )

        compiled = decision_service.DecisionService().compile(
            request(
                item(
                    "correction",
                    reason="confirm evidence lineage",
                    document_relations=(relation,),
                )
            )
        )

        self.assertEqual(compiled.projections[0]["primary_state"], "review-ready")
        self.assertEqual(compiled.document_relation_events[0]["relation_kind"], "evidence")

    def test_multiple_current_primary_workstreams_are_rejected(self):
        relations = tuple(
            decision_service.WorkstreamRelationInput(
                workstream_id=value,
                relation_kind="primary",
                evidence="reviewer confirmation",
                provenance="snapshot-1",
            )
            for value in ("example-service", "example-project-workstream")
        )

        with self.assertRaisesRegex(
            decision_service.DecisionValidationError,
            "primary",
        ):
            decision_service.DecisionService().compile(
                request(
                    item(
                        "correction",
                        reason="ambiguous primary",
                        workstream_relations=relations,
                    )
                )
            )

    def test_confirmed_unassigned_requires_reason_and_assignment_condition(self):
        incomplete = decision_service.UnassignedInput(
            reason="no matching workstream",
            assignment_condition="",
        )
        with self.assertRaisesRegex(
            decision_service.DecisionValidationError,
            "assignment condition",
        ):
            decision_service.DecisionService().compile(
                request(
                    item(
                        "correction",
                        reason="confirm unassigned",
                        unassigned=incomplete,
                    )
                )
            )

        explained = decision_service.UnassignedInput(
            reason="no matching workstream",
            assignment_condition="owner supplies a candidate Workstream",
        )
        compiled = decision_service.DecisionService().compile(
            request(
                item(
                    "correction",
                    reason="confirm unassigned",
                    unassigned=explained,
                )
            )
        )
        self.assertEqual(compiled.unassigned_exceptions[0]["item_id"], "item-1")
        self.assertTrue(compiled.projections[0]["unassigned"])


class DecisionServiceReopenTest(unittest.TestCase):
    def reopen_request(self, **changes):
        values = {
            "campaign_id": "campaign-1",
            "batch_id": "batch-1",
            "base_snapshot_id": "snapshot-2",
            "base_snapshot_sha256": HASH,
            "expected_review_revision": 2,
            "expected_execution_generation": 0,
            "submission_id": "submission-3",
            "next_snapshot_id": "snapshot-3",
            "item_id": "item-1",
            "current_decision_event_id": "decision-current",
            "current_projection_generation": 4,
            "actor": "reviewer",
            "reason": "new evidence requires review",
            "reopened_at_utc": "2026-07-15T02:03:04Z",
        }
        values.update(changes)
        return decision_service.ReopenDecisionRequest(**values)

    def test_reopen_requires_reason_and_exact_projection_generation(self):
        for request_value, pattern in (
            (self.reopen_request(reason=""), "reason"),
            (self.reopen_request(current_projection_generation=0), "generation"),
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(
                    decision_service.DecisionValidationError,
                    pattern,
                ):
                    decision_service.DecisionService().compile_reopen(request_value)

    def test_reopen_supersedes_selected_relation_and_returns_review_ready(self):
        request_value = self.reopen_request(
            selected_relation_kind="document-relation",
            selected_relation_id="document-relation-current",
        )

        compiled = decision_service.DecisionService().compile_reopen(request_value)

        self.assertEqual(compiled.event["action"], "reopen")
        self.assertEqual(
            compiled.event["current_decision_event_id"],
            "decision-current",
        )
        self.assertEqual(compiled.projection["primary_state"], "review-ready")
        self.assertEqual(compiled.projection["projection_generation"], 5)
        self.assertEqual(
            compiled.supersessions,
            (
                {
                    "kind": "decision-projection",
                    "subject_id": "decision-current",
                },
                {
                    "kind": "document-relation",
                    "subject_id": "document-relation-current",
                },
            ),
        )
        self.assertTrue(compiled.named_output_frontier_stale)
        self.assertFalse(compiled.membership_reuse_allowed)
        self.assertEqual(
            decision_service.DecisionService().compile_reopen(request_value),
            compiled,
        )


if __name__ == "__main__":
    unittest.main()
