"""TDD coverage for the complete-context-bound Curation Plan domain."""

from __future__ import annotations

from dataclasses import replace
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import canonical_curation, context_assembly


def _complete_context() -> context_assembly.CompleteContextAssembly:
    content_sha256 = "b" * 64
    source = context_assembly.ContextSource(
        source_id="obs-current-local",
        group="OTHER_NESTED",
        mode="CURRENT_LOCAL",
        relative_path="projects/alpha/notes.md",
        observation_id="obs-current-local",
        identity=(11, 12, 1000, 0o600, 1, 7, 900),
        content_sha256=content_sha256,
        snapshot_sha256="c" * 64,
        content_projection=context_assembly.ContextContentProjection(
            title="Notes",
            headings=(),
            headings_truncated=False,
            excerpt="Notes\n",
            excerpt_truncated=False,
            redaction_counts=(),
            full_content_sha256=content_sha256,
            full_content_byte_count=7,
        ),
    )
    assembly = context_assembly.ContextAssembly(
        workstream=context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=(),
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
            redaction_counts=(),
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


def _plan() -> canonical_curation.CurationPlan:
    observation = canonical_curation.SourceObservation(
        observation_id="obs-current-local",
        relative_path="projects/alpha/notes.md",
        owner_kind="workstream",
        owner_id="alpha",
        lifecycle="active",
        document_role="work_results",
        classification="EXACT",
        classification_evidence=("test",),
        content_summary="Notes",
        device=11,
        inode=12,
        owner=1000,
        mode=0o600,
        link_count=1,
        size=7,
        modified_time_ns=900,
        content_sha256="b" * 64,
        snapshot_sha256="c" * 64,
    )
    effect = canonical_curation.PlanEffect(
        effect_id="effect-current-local",
        action="move",
        input_observation_id=observation.observation_id,
        source_path=observation.relative_path,
        output_path="projects/alpha/work-results/notes.md",
        expected_output_sha256=observation.content_sha256,
        risk_codes=("PATH_ONLY_CHANGE",),
    )
    return canonical_curation.CurationPlan(
        primary_workstream_id="alpha",
        captured_lifecycle="active",
        project_home="projects/alpha",
        project_identity=(11, 2, 0o700, 1000),
        root_identity=(11, 1, 0o700, 1000),
        policy_sha256="a" * 64,
        source_observations=(observation,),
        effects=(effect,),
        spine=tuple(
            canonical_curation.SpineEntry(
                role=role,
                current_path=None,
                current_heading=None,
                proposed_path=None,
                proposed_heading=None,
                status="MISSING",
            )
            for role in canonical_curation.COMMON_SPINE_ROLES
        ),
        findings=(),
        unchanged_paths=(),
        out_of_scope_paths=(),
        coverage=(
            ("bounds", {"max_depth": 4, "max_items": 32}),
            ("inspected_files", 1),
        ),
    )


class ContextBoundCurationPlanTest(unittest.TestCase):
    def test_compiler_requires_complete_capability_and_recomputes_binding(self):
        compiler = getattr(canonical_curation, "compile_curation_plan", None)
        plan_type = getattr(canonical_curation, "ContextBoundCurationPlan", None)
        self.assertTrue(callable(compiler))
        self.assertTrue(callable(plan_type))

        complete = _complete_context()
        plan = compiler(_plan(), context_assembly=complete)

        self.assertIsInstance(plan, plan_type)
        self.assertEqual(plan.schema, "mnemosyne-context-bound-curation-plan-v1")
        self.assertEqual(plan.context_binding.outcome, "COMPLETE")
        self.assertEqual(plan.context_binding.assembly_sha256, complete.assembly.sha256)
        self.assertEqual(plan.context_binding.coverage_sha256, complete.assembly.coverage_sha256)
        self.assertEqual(
            dict(plan.coverage)["context_assembly_sha256"],
            complete.assembly.sha256,
        )
        self.assertEqual(
            dict(plan.coverage)["context_coverage_sha256"],
            complete.assembly.coverage_sha256,
        )
        self.assertNotIn("sources", plan.canonical_value["context_binding"])

        with self.assertRaises(TypeError):
            compiler(_plan())
        with self.assertRaises(canonical_curation.CanonicalCurationError) as raised:
            compiler(_plan(), context_assembly=complete.assembly)
        self.assertEqual(raised.exception.reason_code, "CONTEXT_INCOMPLETE")

    def test_compiler_rejects_authority_or_current_local_identity_mismatch(self):
        complete = _complete_context()
        plan = _plan()
        mismatches = (
            replace(plan, primary_workstream_id="beta"),
            replace(plan, policy_sha256="d" * 64),
            replace(plan, root_identity=(99, 1, 0o700, 1000)),
            replace(plan, project_identity=(99, 2, 0o700, 1000)),
            replace(
                plan,
                source_observations=(
                    replace(plan.source_observations[0], modified_time_ns=901),
                ),
            ),
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                with self.assertRaises(canonical_curation.CanonicalCurationError) as raised:
                    canonical_curation.compile_curation_plan(
                        mismatch,
                        context_assembly=complete,
                    )
                self.assertEqual(raised.exception.reason_code, "CONTEXT_STALE")

    def test_compiler_rejects_effect_target_outside_selected_project_home(self):
        plan = _plan()
        with self.assertRaises(canonical_curation.CanonicalCurationError) as raised:
            canonical_curation.compile_curation_plan(
                replace(
                    plan,
                    effects=(
                        replace(
                            plan.effects[0],
                            output_path="projects/beta/work-results/notes.md",
                        ),
                    ),
                ),
                context_assembly=_complete_context(),
            )

        self.assertEqual(raised.exception.reason_code, "PLAN_INVALID")

    def test_direct_plan_rejects_binding_that_disagrees_with_coverage_scalars(self):
        complete = _complete_context()
        compiled = canonical_curation.compile_curation_plan(
            _plan(), context_assembly=complete
        )
        with self.assertRaises(canonical_curation.CanonicalCurationError) as raised:
            replace(
                compiled,
                context_binding=canonical_curation.ContextBinding(
                    outcome="COMPLETE",
                    assembly_sha256="e" * 64,
                    coverage_sha256=compiled.context_binding.coverage_sha256,
                ),
            )
        self.assertEqual(raised.exception.reason_code, "CONTEXT_STALE")

    def test_subset_keeps_full_context_observation_membership_and_parent_binding(self):
        first_complete = _complete_context()
        first_plan = _plan()
        second_source = replace(
            first_complete.assembly.sources[0],
            source_id="obs-current-local-2",
            relative_path="projects/alpha/second.md",
            observation_id="obs-current-local-2",
            identity=(11, 13, 1000, 0o600, 1, 7, 901),
            content_sha256="d" * 64,
            snapshot_sha256="e" * 64,
            content_projection=replace(
                first_complete.assembly.sources[0].content_projection,
                title="Second",
                excerpt="Second\n",
                full_content_sha256="d" * 64,
            ),
        )
        assembly = replace(
            first_complete.assembly,
            sources=(*first_complete.assembly.sources, second_source),
            coverage=replace(
                first_complete.assembly.coverage,
                local_inspected=2,
                source_group_counts=(("OTHER_NESTED", 2),),
            ),
        )
        complete = assembly.require_complete(
            expected_workstream=assembly.workstream,
            expected_policy_sha256=assembly.policy_sha256,
            expected_root_identity=assembly.root_identity,
            expected_project_identity=assembly.project_identity,
            expected_assembly_sha256=assembly.sha256,
            expected_coverage_sha256=assembly.coverage_sha256,
        )
        second_observation = replace(
            first_plan.source_observations[0],
            observation_id="obs-current-local-2",
            relative_path="projects/alpha/second.md",
            inode=13,
            modified_time_ns=901,
            content_sha256="d" * 64,
            snapshot_sha256="e" * 64,
        )
        second_effect = replace(
            first_plan.effects[0],
            effect_id="effect-current-local-2",
            input_observation_id=second_observation.observation_id,
            source_path=second_observation.relative_path,
            output_path="projects/alpha/work-results/second.md",
            expected_output_sha256=second_observation.content_sha256,
        )
        base = replace(
            first_plan,
            source_observations=(*first_plan.source_observations, second_observation),
            effects=(*first_plan.effects, second_effect),
        )
        displayed = canonical_curation.compile_curation_plan(
            base,
            context_assembly=complete,
        )

        selected = displayed.subset(
            (first_plan.effects[0].effect_id,),
            context_assembly=complete,
        )

        self.assertEqual(selected.context_binding, displayed.context_binding)
        self.assertEqual(selected.plan.parent_plan_sha256, displayed.sha256)
        self.assertEqual(
            {item.observation_id for item in selected.source_observations},
            {"obs-current-local", "obs-current-local-2"},
        )
        self.assertEqual(
            tuple(effect.effect_id for effect in selected.effects),
            (first_plan.effects[0].effect_id,),
        )
