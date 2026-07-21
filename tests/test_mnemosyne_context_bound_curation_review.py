"""TDD coverage for the Context-bound Review Package V3 boundary."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import canonical_curation, canonical_curation_review, context_assembly


def _complete_context() -> context_assembly.CompleteContextAssembly:
    content_sha256 = "b" * 64
    source = context_assembly.ContextSource(
        source_id="obs-current-local",
        group="OTHER_NESTED",
        mode="CURRENT_LOCAL",
        relative_path="projects/alpha/notes.md",
        observation_id="obs-current-local",
        identity=(11, 12, 1000, 0o600, 1, 26, 900),
        content_sha256=content_sha256,
        snapshot_sha256="c" * 64,
        content_projection=context_assembly.ContextContentProjection(
            title="Alpha Notes",
            headings=("Decision",),
            headings_truncated=False,
            excerpt="# Alpha Notes\n## Decision\n[REDACTED_SECRET]\n",
            excerpt_truncated=False,
            redaction_counts=(("secret", 1),),
            full_content_sha256=content_sha256,
            full_content_byte_count=26,
        ),
    )
    assembly = context_assembly.ContextAssembly(
        workstream=context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=("alpha-project",),
            memory_workspace=None,
        ),
        root_identity=(11, 1, 0o700, 1000),
        project_identity=(11, 2, 0o700, 1000),
        policy_sha256="a" * 64,
        outcome="COMPLETE",
        bounds=context_assembly.ContextAssemblyBounds(),
        sources=(source,),
        claims=(),
        gaps=(),
        coverage=context_assembly.ContextCoverage(
            local_inspected=1,
            local_excluded=0,
            local_unreadable=0,
            local_truncated=0,
            source_group_counts=(("OTHER_NESTED", 1),),
            memory_status="NOT_CONFIGURED",
            memory_history_inspected=0,
            memory_history_included=0,
            memory_history_excluded=0,
            memory_history_malformed=0,
            memory_history_truncated=0,
            external_verified=0,
            external_unverified=0,
            excluded_paths=(),
            gap_paths=(),
            redaction_counts=(("secret", 1),),
        ),
    )
    return assembly.require_complete(
        expected_workstream=assembly.workstream,
        expected_policy_sha256=assembly.policy_sha256,
        expected_root_identity=assembly.root_identity,
        expected_project_identity=assembly.project_identity,
        expected_assembly_sha256=assembly.sha256,
        expected_coverage_sha256=assembly.coverage_sha256,
    )


def _context_bound_plan() -> tuple[canonical_curation.ContextBoundCurationPlan, context_assembly.CompleteContextAssembly]:
    complete = _complete_context()
    observation = canonical_curation.SourceObservation(
        observation_id="obs-current-local",
        relative_path="projects/alpha/notes.md",
        owner_kind="workstream",
        owner_id="alpha",
        lifecycle="active",
        document_role="work_results",
        classification="EXACT",
        classification_evidence=("test",),
        content_summary="Alpha Notes",
        device=11,
        inode=12,
        owner=1000,
        mode=0o600,
        link_count=1,
        size=26,
        modified_time_ns=900,
        content_sha256="b" * 64,
        snapshot_sha256="c" * 64,
    )
    legacy_plan = canonical_curation.CurationPlan(
        primary_workstream_id="alpha",
        captured_lifecycle="active",
        project_home="projects/alpha",
        project_identity=(11, 2, 0o700, 1000),
        root_identity=(11, 1, 0o700, 1000),
        policy_sha256="a" * 64,
        source_observations=(observation,),
        effects=(canonical_curation.PlanEffect(
            effect_id="effect-current-local",
            action="move",
            input_observation_id=observation.observation_id,
            source_path=observation.relative_path,
            output_path="projects/alpha/work-results/notes.md",
            expected_output_sha256=observation.content_sha256,
            risk_codes=("PATH_ONLY_CHANGE",),
        ),),
        spine=tuple(canonical_curation.SpineEntry(
            role=role,
            current_path=None,
            current_heading=None,
            proposed_path=None,
            proposed_heading=None,
            status="MISSING",
        ) for role in canonical_curation.COMMON_SPINE_ROLES),
        findings=(),
        unchanged_paths=(),
        out_of_scope_paths=(),
        coverage=(("inspected_files", 1),),
    )
    return canonical_curation.compile_curation_plan(
        legacy_plan, context_assembly=complete
    ), complete


class ContextBoundCurationReviewTest(unittest.TestCase):
    def test_v3_compiles_one_full_context_assembly_and_visible_local_evidence(self):
        plan, complete = _context_bound_plan()
        compiler = getattr(canonical_curation_review, "compile_context_bound_review", None)
        validator = getattr(canonical_curation_review, "validate_context_bound_review_payload", None)
        self.assertTrue(callable(compiler))
        self.assertTrue(callable(validator))

        payload = compiler(
            plan,
            context_assembly=complete,
            rendered_at="2026-07-19T12:34:56Z",
            renderer_id="test.renderer",
        )
        hashes = validator(payload)
        semantic = json.loads(payload.semantic_json)
        meta = json.loads(payload.meta_json)

        self.assertEqual(meta["schema_version"], 3)
        self.assertEqual(meta["plan_sha256"], plan.sha256)
        self.assertEqual(meta["context_assembly_sha256"], complete.assembly.sha256)
        self.assertEqual(meta["context_coverage_sha256"], complete.assembly.coverage_sha256)
        self.assertEqual(meta["context_assembly_outcome"], "COMPLETE")
        self.assertTrue(meta["sealed"])
        self.assertEqual(meta["context_summary"]["counts"]["current_local"], 1)
        self.assertEqual(meta["context_summary"]["source_group_counts"]["OTHER_NESTED"], 1)
        self.assertEqual(semantic["schema"], "mnemosyne-context-bound-curation-review-semantic-v3")
        self.assertEqual(semantic["plan"], plan.canonical_value)
        self.assertEqual(semantic["context_assembly"], complete.assembly.canonical_value)
        self.assertEqual(semantic["context_assembly_sha256"], complete.assembly.sha256)
        self.assertEqual(semantic["context_coverage_sha256"], complete.assembly.coverage_sha256)
        self.assertEqual(semantic["context_assembly_outcome"], "COMPLETE")
        self.assertEqual(semantic["context_assembly"].get("sources")[0]["content_projection"]["excerpt"], "# Alpha Notes\n## Decision\n[REDACTED_SECRET]\n")
        self.assertIn(b"obs-current-local", payload.markdown)
        self.assertIn(b"projects/alpha/notes.md", payload.markdown)
        self.assertIn(b"Alpha Notes", payload.markdown)
        self.assertIn(b"[REDACTED_SECRET]", payload.markdown)
        self.assertIn(b"obs-current-local", payload.html)
        self.assertIn(b"Decision", payload.html)
        self.assertEqual(hashes.source_snapshot_sha256, plan.plan.source_observation_sha256)

    def test_v3_rejects_v2_payload_and_v2_rejects_v3_payload(self):
        plan, complete = _context_bound_plan()
        v3 = canonical_curation_review.compile_context_bound_review(
            plan, context_assembly=complete, rendered_at="2026-07-19T12:34:56Z", renderer_id="test.renderer"
        )
        v2 = canonical_curation_review.compile_review(
            plan.plan, rendered_at="2026-07-19T12:34:56Z", renderer_id="test.renderer"
        )
        with self.assertRaises(canonical_curation_review.CurationReviewError):
            canonical_curation_review.validate_review_payload(v3)
        with self.assertRaises(canonical_curation_review.CurationReviewError):
            canonical_curation_review.validate_context_bound_review_payload(v2)

    def test_v3_sealed_directory_rereads_only_v3_and_never_creates_context_json(self):
        plan, complete = _context_bound_plan()
        payload = canonical_curation_review.compile_context_bound_review(
            plan, context_assembly=complete, rendered_at="2026-07-19T12:34:56Z", renderer_id="test.renderer"
        )
        writer = getattr(canonical_curation_review, "write_context_bound_review_package", None)
        reader = getattr(canonical_curation_review, "validate_context_bound_review_directory", None)
        self.assertTrue(callable(writer))
        self.assertTrue(callable(reader))
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            package = (Path(temporary) / "review").resolve()
            package.mkdir(mode=0o700)
            first = writer(package, payload)
            second, displayed_plan, displayed_assembly = reader(
                package, expected_plan_sha256=plan.sha256
            )
            self.assertEqual(first, second)
            self.assertEqual(displayed_plan, plan.canonical_value)
            self.assertEqual(displayed_assembly, complete.assembly)
            self.assertFalse((package / "context.json").exists())
            with self.assertRaises(canonical_curation_review.CurationReviewError):
                canonical_curation_review.validate_review_directory(package)
