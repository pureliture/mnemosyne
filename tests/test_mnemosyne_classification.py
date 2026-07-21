import hashlib
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import classification, inventory, policy  # noqa: E402


class EvidenceClassifierTest(unittest.TestCase):
    def test_all_provider_serialization_is_byte_exact(self):
        item = classification.ClassificationInput(
            observation_id="obs-byte-golden",
            path="projects/alpha/design.md",
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=True,
            projection=classification.SafeContentProjection(
                title="Alpha and Beta design",
                headings=("Current architecture",),
                frontmatter=(
                    ("authority", "canonical"),
                    ("lifecycle", "current"),
                    ("role", "docs"),
                    ("workstream", "alpha"),
                ),
                references=("beta/spec.md",),
                context_freshness="fresh",
            ),
            reference_workstreams=("beta",),
            fingerprint_value="a" * 64,
            duplicate_observation_ids=("obs-byte-copy",),
        )
        workstreams = (
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/alpha",
                aliases=("alpha",),
            ),
            policy.CompiledWorkstream(
                id="beta",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/beta",
                aliases=("beta",),
            ),
        )
        categories = (
            policy.CompiledCategory(
                id="docs",
                target="/private/tmp/raw/docs",
                patterns=("*.md",),
            ),
        )

        encoded = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
            categories=categories,
        ).classifications_jsonl()

        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            "d9322fb6e7dc9860bad9ecbcd86d54ba9a371dd870f2e2d63d46160f06971fba",
        )

    def test_inventory_raw_b64_path_matches_policy_route_without_changing_identity(self):
        canonical_path = inventory.canonical_raw_path(
            (b"workstreams", b"alpha", b"spec.md")
        )
        item = classification.ClassificationInput(
            observation_id="obs-raw-b64-route",
            path=canonical_path,
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=False,
        )
        workstream = policy.CompiledWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="/private/tmp/raw/workstreams/alpha",
            aliases=("alpha",),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=(workstream,),
        )

        self.assertEqual(result.candidates_for("workstream")[0].value, "alpha")
        self.assertEqual(result.evidence[0].provider, "registry-route")
        self.assertEqual(item.path, canonical_path)

    def test_non_utf8_inventory_path_fails_to_unknown_without_lossy_route_guess(self):
        item = classification.ClassificationInput(
            observation_id="obs-non-utf8-route",
            path=inventory.canonical_raw_path((b"workstreams", b"alpha-\xff.md")),
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=False,
        )
        workstream = policy.CompiledWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="/private/tmp/raw/workstreams/alpha",
            aliases=("alpha",),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=(workstream,),
        )

        self.assertEqual(
            result.candidates_for("workstream")[0].confidence_band,
            "unknown",
        )
        self.assertEqual(result.candidates_for("workstream")[0].value, "unassigned")
    def test_project_home_route_produces_stable_high_confidence_workstream_candidate(self):
        item = classification.ClassificationInput(
            observation_id="obs-alpha-spec",
            path="projects/alpha/spec.md",
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=True,
        )
        workstreams = (
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/alpha",
                aliases=("alpha/mobile",),
            ),
        )

        first = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
        )
        second = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
        )

        candidates = first.candidates_for("workstream")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].value, "alpha")
        self.assertEqual(candidates[0].confidence_band, "high")
        self.assertEqual(candidates[0].context_freshness, "fresh")
        self.assertEqual(
            [evidence.provider for evidence in first.evidence],
            ["registry-route"],
        )
        self.assertEqual(first, second)

    def test_filename_alias_collision_preserves_competing_candidates(self):
        item = classification.ClassificationInput(
            observation_id="obs-shared-notes",
            path="artifacts/alpha-beta-notes.md",
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=True,
        )
        workstreams = (
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/alpha",
                aliases=("alpha",),
            ),
            policy.CompiledWorkstream(
                id="beta",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/beta",
                aliases=("beta",),
            ),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
        )

        candidates = result.candidates_for("workstream")
        self.assertEqual([candidate.value for candidate in candidates], ["alpha", "beta"])
        self.assertEqual(
            [candidate.confidence_band for candidate in candidates],
            ["low", "low"],
        )
        self.assertEqual(
            [candidate.uncertainty_reason for candidate in candidates],
            ["competing-top-candidate", "competing-top-candidate"],
        )
        self.assertTrue(result.has_competing_candidates("workstream"))
        self.assertEqual(
            [evidence.provider for evidence in result.evidence],
            ["path-alias", "path-alias"],
        )

    def test_missing_evidence_yields_explicit_unassigned_and_unknown_axes(self):
        item = classification.ClassificationInput(
            observation_id="obs-unassigned",
            path="inbox/note.bin",
            scope_class="fallback-unassigned",
            scope_rule_id="fallback-unassigned",
            content_allowed=False,
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=(),
        )

        self.assertEqual(
            [(candidate.axis, candidate.value) for candidate in result.candidates],
            [
                ("authority", "unknown"),
                ("lifecycle", "unknown"),
                ("role", "unknown"),
                ("workstream", "unassigned"),
            ],
        )
        self.assertTrue(
            all(candidate.confidence_band == "unknown" for candidate in result.candidates)
        )
        self.assertTrue(
            all(
                candidate.uncertainty_reason == "missing-deterministic-evidence"
                for candidate in result.candidates
            )
        )

    def test_safe_frontmatter_produces_independent_axis_candidates(self):
        item = classification.ClassificationInput(
            observation_id="obs-frontmatter",
            path="docs/spec.md",
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=True,
            projection=classification.SafeContentProjection(
                title="Alpha specification",
                headings=("Canonical requirements",),
                frontmatter=(
                    ("authority", "canonical"),
                    ("lifecycle", "current"),
                    ("role", "requirements-design"),
                    ("workstream", "alpha"),
                ),
                references=(),
                context_freshness="fresh",
            ),
        )
        workstreams = (
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/alpha",
                aliases=("alpha",),
            ),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
        )

        self.assertEqual(
            {(candidate.axis, candidate.value) for candidate in result.candidates},
            {
                ("authority", "canonical"),
                ("lifecycle", "current"),
                ("role", "requirements-design"),
                ("workstream", "alpha"),
            },
        )
        self.assertTrue(
            all(candidate.context_freshness == "fresh" for candidate in result.candidates)
        )
        self.assertEqual(
            {evidence.provider for evidence in result.evidence},
            {"safe-content-token", "safe-frontmatter"},
        )
        self.assertEqual(len(result.candidates_for("workstream")), 1)

    def test_private_projection_requires_exact_authorization(self):
        projection = classification.SafeContentProjection(
            title="LEAK_SENTINEL_PRIVATE_BODY",
            headings=(),
            frontmatter=(("workstream", "alpha"),),
            references=(),
            context_freshness="fresh",
        )

        with self.assertRaisesRegex(
            classification.ClassificationError,
            "private projection requires exact authorization",
        ):
            classification.ClassificationInput(
                observation_id="obs-private",
                path="private/alpha.md",
                scope_class="private-reviewable",
                scope_rule_id="private-reviewable",
                content_allowed=True,
                sensitivity="private",
                access_domain="owner",
                projection=projection,
            )

    def test_authorized_private_projection_never_persists_body_or_content_hash(self):
        sentinel = "LEAK_SENTINEL_PRIVATE_BODY"
        content_hash = hashlib.sha256(sentinel.encode("utf-8")).hexdigest()
        item = classification.ClassificationInput(
            observation_id="obs-private-authorized",
            path="private/alpha.md",
            scope_class="private-reviewable",
            scope_rule_id="private-reviewable",
            content_allowed=True,
            sensitivity="private",
            access_domain="owner",
            projection=classification.SafeContentProjection(
                title=sentinel,
                headings=(),
                frontmatter=(("workstream", "alpha"),),
                references=(),
                context_freshness="fresh",
            ),
            projection_authorization_id="scope-auth-001",
        )
        workstreams = (
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/alpha",
                aliases=("alpha",),
            ),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
        )
        serialized = result.classifications_jsonl()

        self.assertNotIn(sentinel.encode("utf-8"), serialized)
        self.assertNotIn(content_hash.encode("ascii"), serialized)
        self.assertIn(b'"provider":"ephemeral-private-projection"', serialized)

    def test_overlapping_path_patterns_preserve_competing_role_candidates(self):
        item = classification.ClassificationInput(
            observation_id="obs-role-conflict",
            path="docs/design.md",
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=False,
        )
        categories = (
            policy.CompiledCategory(
                id="docs",
                target="/private/tmp/raw/docs",
                patterns=("docs/**", "*.md"),
            ),
            policy.CompiledCategory(
                id="project-context",
                target="/private/tmp/raw/projects",
                patterns=("**/design.md",),
            ),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=(),
            categories=categories,
        )

        roles = result.candidates_for("role")
        self.assertEqual([candidate.value for candidate in roles], ["docs", "project-context"])
        self.assertTrue(result.has_competing_candidates("role"))
        self.assertEqual(
            {evidence.provider for evidence in result.evidence},
            {"path-pattern"},
        )

    def test_source_reference_graph_keeps_multiple_workstreams_competing(self):
        item = classification.ClassificationInput(
            observation_id="obs-reference-graph",
            path="notes/shared.md",
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=False,
            reference_workstreams=("alpha", "beta"),
        )
        workstreams = (
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/alpha",
                aliases=(),
            ),
            policy.CompiledWorkstream(
                id="beta",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/beta",
                aliases=(),
            ),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
        )

        self.assertEqual(
            [candidate.value for candidate in result.candidates_for("workstream")],
            ["alpha", "beta"],
        )
        self.assertTrue(result.has_competing_candidates("workstream"))
        self.assertEqual(
            {evidence.provider for evidence in result.evidence},
            {"source-reference-graph"},
        )

    def test_safe_title_alias_is_tentative_content_evidence(self):
        item = classification.ClassificationInput(
            observation_id="obs-title-alias",
            path="notes/shared.md",
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=True,
            projection=classification.SafeContentProjection(
                title="Alpha release notes",
                headings=(),
                frontmatter=(),
                references=(),
                context_freshness="fresh",
            ),
        )
        workstreams = (
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="/private/tmp/raw/projects/alpha",
                aliases=("alpha",),
            ),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=workstreams,
        )

        candidate = result.candidates_for("workstream")[0]
        self.assertEqual(candidate.value, "alpha")
        self.assertEqual(candidate.confidence_band, "low")
        self.assertEqual(candidate.uncertainty_reason, "single-content-provider")
        self.assertEqual(result.evidence[0].provider, "safe-content-token")

    def test_exact_duplicate_hash_is_evidence_but_not_canonical_authority(self):
        item = classification.ClassificationInput(
            observation_id="obs-duplicate-a",
            path="docs/copy.md",
            scope_class="active-workstream-content",
            scope_rule_id="active-workstream-content",
            content_allowed=False,
            fingerprint_value="a" * 64,
            duplicate_observation_ids=("obs-duplicate-b",),
        )

        result = classification.EvidenceClassifier("m2-v1").classify(
            item,
            raw_root="/private/tmp/raw",
            workstreams=(),
        )

        authority = result.candidates_for("authority")
        self.assertEqual(len(authority), 1)
        self.assertEqual(authority[0].value, "unknown")
        self.assertEqual(
            authority[0].uncertainty_reason,
            "duplicate-authority-unresolved",
        )
        self.assertEqual(result.evidence[0].provider, "exact-duplicate")


if __name__ == "__main__":
    unittest.main()
