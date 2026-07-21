import sys
import unittest
from dataclasses import replace
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import policy, routing_risk  # noqa: E402


class PlacementTargetResolverTest(unittest.TestCase):
    def test_tentative_classification_never_produces_a_target(self):
        request = routing_risk.TargetRequest(
            source_path="inbox/spec.md",
            action="move",
            primary_workstream="alpha",
            document_role="docs",
            document_lifecycle="current",
            sensitivity="public",
            access_domain="default",
            classification_confirmed=False,
            evidence_ids=("evidence-alpha",),
        )

        result = routing_risk.PlacementTargetResolver("target-v1").resolve(
            request,
            raw_root="/private/tmp/raw",
            workstreams=(
                policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="/private/tmp/raw/projects/alpha",
                    aliases=(),
                ),
            ),
            categories=(
                policy.CompiledCategory(
                    id="docs",
                    target="/private/tmp/raw/docs",
                    patterns=("*.md",),
                ),
            ),
            archive_roots=(),
        )

        self.assertEqual(result.status, "blocked")
        self.assertIsNone(result.target_path)
        self.assertEqual(result.uncertainty, "classification-not-confirmed")

    def test_confirmed_move_uses_one_exact_category_route(self):
        request = routing_risk.TargetRequest(
            source_path="inbox/spec.md",
            action="move",
            primary_workstream="alpha",
            document_role="docs",
            document_lifecycle="current",
            sensitivity="public",
            access_domain="default",
            classification_confirmed=True,
            evidence_ids=("evidence-alpha", "evidence-docs"),
        )

        result = routing_risk.PlacementTargetResolver("target-v1").resolve(
            request,
            raw_root="/private/tmp/raw",
            workstreams=(
                policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="/private/tmp/raw/projects/alpha",
                    aliases=(),
                ),
            ),
            categories=(
                policy.CompiledCategory(
                    id="docs",
                    target="/private/tmp/raw/docs",
                    patterns=("*.md",),
                ),
            ),
            archive_roots=(),
        )

        self.assertEqual(result.status, "resolved")
        self.assertEqual(result.target_path, "docs/spec.md")
        self.assertEqual(result.matched_rule_id, "category:docs")
        self.assertEqual(len(result.matched_rule_sha256), 64)
        self.assertEqual(result.rename_from, "spec.md")
        self.assertEqual(result.rename_to, "spec.md")
        self.assertIsNone(result.uncertainty)

    def test_registry_rule_drift_changes_target_binding(self):
        request = routing_risk.TargetRequest(
            source_path="inbox/spec.md",
            action="move",
            primary_workstream="alpha",
            document_role="docs",
            document_lifecycle="current",
            sensitivity="public",
            access_domain="default",
            classification_confirmed=True,
            evidence_ids=("evidence-alpha",),
        )
        workstreams = (
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/alpha",
                aliases=(),
            ),
        )
        resolver = routing_risk.PlacementTargetResolver("target-v1")

        before = resolver.resolve(
            request,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
            categories=(
                policy.CompiledCategory(
                    id="docs",
                    target="/private/tmp/raw/docs",
                    patterns=("*.md",),
                ),
            ),
            archive_roots=(),
        )
        after = resolver.resolve(
            request,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
            categories=(
                policy.CompiledCategory(
                    id="docs",
                    target="/private/tmp/raw/reviewed-docs",
                    patterns=("*.md",),
                ),
            ),
            archive_roots=(),
        )

        self.assertNotEqual(before.matched_rule_sha256, after.matched_rule_sha256)
        self.assertNotEqual(before.input_sha256, after.input_sha256)
        self.assertEqual(before.target_path, "docs/spec.md")
        self.assertEqual(after.target_path, "reviewed-docs/spec.md")


class RiskEvaluatorTest(unittest.TestCase):
    @staticmethod
    def _low_input():
        return routing_risk.RiskInput(
            action="move",
            scope_class="active-workstream-content",
            sensitivity="public",
            access_domain="default",
            confidence_band="high",
            context_freshness="fresh",
            canonical_conflict=False,
            reference_complete=True,
            descendant_count=1,
            descendant_mixed=False,
            target_proven=True,
            archive_domain_safe=True,
            frozen=False,
            lifecycle_override_present=False,
            opaque=False,
            private=False,
            ambiguity=False,
            ancestor_descendant_overlap=False,
            named_output_conflict=False,
            reversal_capability_proven=True,
            inverse_plan_complete=True,
            recovery_paths_complete=True,
            provenance_ids=("evidence-risk",),
        )

    def test_complete_public_active_input_is_low_risk_with_stable_hash(self):
        value = self._low_input()
        evaluator = routing_risk.RiskEvaluator("risk-v1")

        first = evaluator.evaluate(value)
        second = evaluator.evaluate(value)

        self.assertEqual(first.band, "low")
        self.assertEqual(first.hard_escalators, ())
        self.assertEqual(first, second)
        self.assertEqual(len(first.input_sha256), 64)

    def test_hard_safety_escalators_can_never_be_low(self):
        cases = (
            ({"opaque": True}, "opaque-scope"),
            ({"private": True}, "private-without-override"),
            ({"frozen": True}, "frozen-without-override"),
            ({"ambiguity": True}, "classification-ambiguity"),
            ({"reference_complete": False}, "reference-incomplete"),
            ({"ancestor_descendant_overlap": True}, "ancestor-descendant-overlap"),
            ({"target_proven": False}, "target-unproven"),
            ({"archive_domain_safe": False}, "archive-domain-unsafe"),
            ({"reversal_capability_proven": False}, "reversal-capability-unproven"),
            ({"inverse_plan_complete": False}, "inverse-plan-incomplete"),
            ({"recovery_paths_complete": False}, "recovery-paths-incomplete"),
        )
        evaluator = routing_risk.RiskEvaluator("risk-v1")

        for changes, expected in cases:
            with self.subTest(expected=expected):
                result = evaluator.evaluate(replace(self._low_input(), **changes))
                self.assertEqual(result.band, "blocked")
                self.assertIn(expected, result.hard_escalators)

    def test_nonblocking_uncertainty_is_medium_or_high_by_versioned_rules(self):
        cases = (
            ({"confidence_band": "medium"}, "medium"),
            ({"context_freshness": "stale"}, "medium"),
            ({"descendant_count": 25}, "medium"),
            ({"descendant_mixed": True}, "high"),
            ({"canonical_conflict": True}, "high"),
            ({"named_output_conflict": True}, "high"),
            (
                {"private": True, "lifecycle_override_present": True},
                "high",
            ),
            (
                {"frozen": True, "lifecycle_override_present": True},
                "high",
            ),
        )
        evaluator = routing_risk.RiskEvaluator("risk-v1")

        for changes, expected in cases:
            with self.subTest(changes=changes):
                result = evaluator.evaluate(replace(self._low_input(), **changes))
                self.assertEqual(result.band, expected)
                self.assertEqual(result.hard_escalators, ())


if __name__ == "__main__":
    unittest.main()
