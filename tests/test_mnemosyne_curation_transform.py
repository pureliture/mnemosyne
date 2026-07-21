import hashlib
import html
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import canonical_curation  # noqa: E402
from mnemosyne_core import canonical_curation_m3  # noqa: E402
from mnemosyne_core import canonical_curation_m3_review  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _observation(number: int, path: str, raw: bytes) -> canonical_curation.SourceObservation:
    return canonical_curation.SourceObservation(
        observation_id=f"obs-{number:024d}",
        relative_path=path,
        owner_kind="workstream",
        owner_id="example-project-workstream",
        lifecycle="active",
        document_role="work_results",
        classification="EXACT",
        classification_evidence=("fixture-owned evidence",),
        content_summary=f"fixture source {number}",
        device=1,
        inode=number,
        owner=501,
        mode=0o600,
        link_count=1,
        size=len(raw),
        modified_time_ns=number,
        content_sha256=_sha256(raw),
        snapshot_sha256=_sha256(b"snapshot-" + str(number).encode("ascii")),
    )


def _spine() -> tuple[canonical_curation.SpineEntry, ...]:
    return tuple(
        canonical_curation.SpineEntry(
            role=role,
            current_path=("projects/example-project/README.md" if role == "overview" else None),
            current_heading=("Example Project" if role == "overview" else None),
            proposed_path=("projects/example-project/README.md" if role == "overview" else None),
            proposed_heading=("Example Project" if role == "overview" else None),
            status="PRESENT" if role == "overview" else "MISSING",
        )
        for role in canonical_curation.COMMON_SPINE_ROLES
    )


def _merge_fixture() -> tuple[
    tuple[canonical_curation.SourceObservation, ...],
    canonical_curation_m3.TransformationEffect,
]:
    first = _observation(1, "projects/example-project/notes-a.md", b"# A\n\nAlpha.\n")
    second = _observation(2, "projects/example-project/notes-b.md", b"# B\n\nBeta.\n")
    output_raw = b"# Combined\n\n## Alpha\n\nAlpha.\n\n## Beta\n\nBeta.\n"
    output = canonical_curation_m3.CompleteOutput(
        output_id="output-000000000000000000000001",
        output_path="projects/example-project/combined.md",
        content=output_raw.decode("utf-8"),
        content_sha256=_sha256(output_raw),
        document_role="work_results",
    )
    mappings = (
        canonical_curation_m3.SourceOutputMapping(
            mapping_id="mapping-000000000000000000000001",
            source_observation_id=first.observation_id,
            source_sections=("A",),
            output_id=output.output_id,
            output_sections=("Alpha",),
            disposition="RETAINED",
        ),
        canonical_curation_m3.SourceOutputMapping(
            mapping_id="mapping-000000000000000000000002",
            source_observation_id=second.observation_id,
            source_sections=("B",),
            output_id=output.output_id,
            output_sections=("Beta",),
            disposition="RETAINED",
        ),
    )
    return (
        (first, second),
        canonical_curation_m3.TransformationEffect(
            effect_id="effect-000000000000000000000001",
            action="merge",
            input_observation_ids=(first.observation_id, second.observation_id),
            outputs=(output,),
            source_output_mappings=mappings,
            disappearing_content=(),
            risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
        ),
    )


def _plan() -> canonical_curation_m3.TransformationPlan:
    observations, effect = _merge_fixture()
    return canonical_curation_m3.TransformationPlan(
        primary_workstream_id="example-project-workstream",
        captured_lifecycle="active",
        project_home="projects/example-project",
        project_identity=(1, 2, 0o700, 501),
        root_identity=(1, 1, 0o700, 501),
        policy_sha256="1" * 64,
        source_observations=observations,
        effects=(effect,),
        spine=_spine(),
        findings=(),
        unchanged_paths=("projects/example-project/README.md",),
        out_of_scope_paths=(),
        final_paths=(
            "projects/example-project/README.md",
            "projects/example-project/combined.md",
        ),
        coverage=(("truncated", False),),
    )


def _two_effect_plan() -> canonical_curation_m3.TransformationPlan:
    observations = (
        _observation(11, "projects/example-project/first.md", b"# First\n\nOne.\n"),
        _observation(12, "projects/example-project/second.md", b"# Second\n\nTwo.\n"),
    )
    effects = []
    for index, observation in enumerate(observations, 1):
        raw = ("# Canonical %d\n\n%s\n" % (index, "One." if index == 1 else "Two.")).encode()
        output = canonical_curation_m3.CompleteOutput(
            output_id=f"output-{index + 10:024d}",
            output_path=f"projects/example-project/canonical-{index}.md",
            content=raw.decode(),
            content_sha256=_sha256(raw),
            document_role="work_results",
        )
        effects.append(
            canonical_curation_m3.TransformationEffect(
                effect_id=f"effect-{index + 10:024d}",
                action="rewrite" if index == 1 else "navigation",
                input_observation_ids=(observation.observation_id,),
                outputs=(output,),
                source_output_mappings=(
                    canonical_curation_m3.SourceOutputMapping(
                        mapping_id=f"mapping-{index + 10:024d}",
                        source_observation_id=observation.observation_id,
                        source_sections=("document",),
                        output_id=output.output_id,
                        output_sections=("document",),
                        disposition="REORGANIZED",
                    ),
                ),
                disappearing_content=(),
                risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
                dependency_effect_ids=("effect-000000000000000000000011",)
                if index == 2
                else (),
            )
        )
    return canonical_curation_m3.TransformationPlan(
        primary_workstream_id="example-project-workstream",
        captured_lifecycle="active",
        project_home="projects/example-project",
        project_identity=(1, 2, 0o700, 501),
        root_identity=(1, 1, 0o700, 501),
        policy_sha256="1" * 64,
        source_observations=observations,
        effects=tuple(effects),
        spine=_spine(),
        findings=(),
        unchanged_paths=("projects/example-project/README.md",),
        out_of_scope_paths=(),
        final_paths=(
            "projects/example-project/README.md",
            "projects/example-project/canonical-1.md",
            "projects/example-project/canonical-2.md",
        ),
        coverage=(("truncated", False),),
    )


class MeaningPreservingTransformContractTest(unittest.TestCase):
    def test_transform_effect_requires_complete_output_and_unambiguous_source_mapping(
        self,
    ) -> None:
        first = _observation(1, "projects/example-project/notes-a.md", b"# A\n\nAlpha.\n")
        second = _observation(2, "projects/example-project/notes-b.md", b"# B\n\nBeta.\n")
        output_raw = b"# Combined\n\n## Alpha\n\nAlpha.\n\n## Beta\n\nBeta.\n"
        output = canonical_curation_m3.CompleteOutput(
            output_id="output-000000000000000000000001",
            output_path="projects/example-project/combined.md",
            content=output_raw.decode("utf-8"),
            content_sha256=_sha256(output_raw),
            document_role="work_results",
        )
        mappings = (
            canonical_curation_m3.SourceOutputMapping(
                mapping_id="mapping-000000000000000000000001",
                source_observation_id=first.observation_id,
                source_sections=("A",),
                output_id=output.output_id,
                output_sections=("Alpha",),
                disposition="RETAINED",
            ),
            canonical_curation_m3.SourceOutputMapping(
                mapping_id="mapping-000000000000000000000002",
                source_observation_id=second.observation_id,
                source_sections=("B",),
                output_id=output.output_id,
                output_sections=("Beta",),
                disposition="RETAINED",
            ),
        )

        with self.assertRaisesRegex(
            canonical_curation.CanonicalCurationError,
            "complete output",
        ):
            canonical_curation_m3.TransformationEffect(
                effect_id="effect-000000000000000000000001",
                action="merge",
                input_observation_ids=(first.observation_id, second.observation_id),
                outputs=(),
                source_output_mappings=mappings,
                disappearing_content=(),
                risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
            )

        with self.assertRaisesRegex(
            canonical_curation.CanonicalCurationError,
            "source mapping",
        ):
            canonical_curation_m3.TransformationEffect(
                effect_id="effect-000000000000000000000001",
                action="merge",
                input_observation_ids=(first.observation_id, second.observation_id),
                outputs=(output,),
                source_output_mappings=mappings[:1],
                disappearing_content=(),
                risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
            )

        effect = canonical_curation_m3.TransformationEffect(
            effect_id="effect-000000000000000000000001",
            action="merge",
            input_observation_ids=(first.observation_id, second.observation_id),
            outputs=(output,),
            source_output_mappings=mappings,
            disappearing_content=(),
            risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
        )

        self.assertEqual(effect.canonical_value["outputs"][0]["content"], output_raw.decode())
        self.assertEqual(
            effect.canonical_value["outputs"][0]["content_sha256"],
            _sha256(output_raw),
        )
        self.assertEqual(
            {row["source_observation_id"] for row in effect.canonical_value["source_output_mappings"]},
            {first.observation_id, second.observation_id},
        )

    def test_transform_plan_seals_outputs_and_requires_exact_irreversible_acknowledgement(
        self,
    ) -> None:
        plan = _plan()
        output = plan.effects[0].outputs[0]
        changed_output = replace(
            output,
            content="# Combined\n\nChanged.\n",
            content_sha256=_sha256(b"# Combined\n\nChanged.\n"),
        )
        changed_effect = replace(plan.effects[0], outputs=(changed_output,))
        changed_plan = replace(plan, effects=(changed_effect,))
        review_hashes = {
            "html_sha256": "2" * 64,
            "markdown_sha256": "3" * 64,
            "meta_sha256": "4" * 64,
            "semantic_sha256": "5" * 64,
        }

        self.assertNotEqual(plan.sha256, changed_plan.sha256)
        self.assertTrue(plan.cutoff_required)
        self.assertEqual(
            plan.irreversible_consequence,
            canonical_curation_m3.IRREVERSIBLE_CONSEQUENCE_KO,
        )
        with self.assertRaisesRegex(
            canonical_curation.CanonicalCurationError,
            "irreversible acknowledgement",
        ):
            canonical_curation_m3.compile_decision(
                plan,
                action="APPROVE_ALL",
                review_package_hashes=review_hashes,
            )

        decision = canonical_curation_m3.compile_decision(
            plan,
            action="APPROVE_ALL",
            review_package_hashes=review_hashes,
            irreversible_acknowledgement=canonical_curation_m3.IRREVERSIBLE_CONSEQUENCE_KO,
        )

        self.assertEqual(decision.approved_plan, plan)
        self.assertEqual(decision.displayed_plan_sha256, plan.sha256)
        self.assertEqual(
            decision.canonical_value["irreversible_acknowledgement"],
            canonical_curation_m3.IRREVERSIBLE_CONSEQUENCE_KO,
        )

    def test_m3_review_package_shows_and_independently_seals_complete_output(self) -> None:
        plan = _plan()
        payload = canonical_curation_m3_review.compile_review(
            plan,
            rendered_at="2026-07-19T12:00:00Z",
            renderer_id="m3-independent-test",
        )
        output = plan.effects[0].outputs[0]

        hashes = canonical_curation_m3_review.validate_review_payload(payload)

        self.assertIn(output.content.encode("utf-8"), payload.markdown)
        self.assertIn(html.escape(output.content).encode("utf-8"), payload.html)
        self.assertIn(canonical_curation_m3.IRREVERSIBLE_CONSEQUENCE_KO.encode(), payload.markdown)
        self.assertEqual(hashes.source_snapshot_sha256, plan.source_observation_sha256)

        semantic = json.loads(payload.semantic_json)
        semantic["plan"]["effects"][0]["outputs"][0]["content"] = "# Forged\n"
        tampered_semantic = canonical_json_bytes(semantic)
        tampered_markdown = payload.markdown.replace(payload.semantic_json, tampered_semantic)
        tampered_html = payload.html.replace(
            html.escape(payload.semantic_json.decode()).encode(),
            html.escape(tampered_semantic.decode()).encode(),
        )
        meta = json.loads(payload.meta_json)
        meta["markdown_sha256"] = _sha256(tampered_markdown)
        meta["html_sha256"] = _sha256(tampered_html)
        meta["semantic_sha256"] = _sha256(tampered_semantic)
        tampered = replace(
            payload,
            markdown=tampered_markdown,
            html=tampered_html,
            meta_json=canonical_json_bytes(meta),
            semantic_json=tampered_semantic,
        )

        with self.assertRaisesRegex(
            canonical_curation_m3_review.CurationReviewError,
            "complete output",
        ):
            canonical_curation_m3_review.validate_review_payload(tampered)

    def test_split_rewrite_navigation_and_duplicate_effects_all_require_exact_outputs(
        self,
    ) -> None:
        source = _observation(21, "projects/example-project/mixed.md", b"# A\nOne.\n# B\nTwo.\n")
        outputs = tuple(
            canonical_curation_m3.CompleteOutput(
                output_id=f"output-{index + 20:024d}",
                output_path=f"projects/example-project/part-{index}.md",
                content=content,
                content_sha256=_sha256(content.encode()),
                document_role="work_results",
            )
            for index, content in ((1, "# A\n\nOne.\n"), (2, "# B\n\nTwo.\n"))
        )
        split = canonical_curation_m3.TransformationEffect(
            effect_id="effect-000000000000000000000021",
            action="split",
            input_observation_ids=(source.observation_id,),
            outputs=outputs,
            source_output_mappings=tuple(
                canonical_curation_m3.SourceOutputMapping(
                    mapping_id=f"mapping-{index + 20:024d}",
                    source_observation_id=source.observation_id,
                    source_sections=("A" if index == 1 else "B",),
                    output_id=output.output_id,
                    output_sections=("A" if index == 1 else "B",),
                    disposition="REORGANIZED",
                )
                for index, output in enumerate(outputs, 1)
            ),
            disappearing_content=(),
            risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
        )
        self.assertEqual(split.action, "split")
        self.assertEqual(len(split.outputs), 2)

        for index, action in enumerate(
            ("rewrite", "navigation", "duplicate_consolidation"),
            31,
        ):
            disappearing = (
                canonical_curation_m3.DisappearingContent(
                    source_observation_id=source.observation_id,
                    source_sections=("duplicate heading",),
                    reason="Approved exact duplicate removal",
                    classification="EXACT_DUPLICATE",
                ),
            ) if action == "duplicate_consolidation" else ()
            effect = canonical_curation_m3.TransformationEffect(
                effect_id=f"effect-{index:024d}",
                action=action,
                input_observation_ids=(source.observation_id,),
                outputs=(outputs[0],),
                source_output_mappings=(
                    canonical_curation_m3.SourceOutputMapping(
                        mapping_id=f"mapping-{index:024d}",
                        source_observation_id=source.observation_id,
                        source_sections=("document",),
                        output_id=outputs[0].output_id,
                        output_sections=("document",),
                        disposition=(
                            "EXACT_DUPLICATE_REMOVED"
                            if action == "duplicate_consolidation"
                            else "REORGANIZED"
                        ),
                    ),
                ),
                disappearing_content=disappearing,
                risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
            )
            self.assertEqual(effect.action, action)

    def test_conflict_finding_blocks_approval_but_still_allows_defer(self) -> None:
        plan = _plan()
        blocked = replace(
            plan,
            findings=(
                canonical_curation.CurationFinding(
                    finding_id="finding-000000000000000000000001",
                    finding_kind="UNRESOLVED_CONFLICT",
                    relative_path=plan.source_observations[0].relative_path,
                    evidence=("two sources disagree",),
                ),
            ),
        )
        hashes = {
            "html_sha256": "2" * 64,
            "markdown_sha256": "3" * 64,
            "meta_sha256": "4" * 64,
            "semantic_sha256": "5" * 64,
        }

        with self.assertRaisesRegex(
            canonical_curation.CanonicalCurationError,
            "conflict",
        ) as error:
            canonical_curation_m3.compile_decision(
                blocked,
                action="APPROVE_ALL",
                review_package_hashes=hashes,
                irreversible_acknowledgement=canonical_curation_m3.IRREVERSIBLE_CONSEQUENCE_KO,
            )
        self.assertEqual(error.exception.reason_code, "REVIEW_NOT_READY")

        deferred = canonical_curation_m3.compile_decision(
            blocked,
            action="DEFER",
            review_package_hashes=hashes,
            reason="source conflict must be resolved",
        )
        self.assertIsNone(deferred.approved_plan)

    def test_selected_approval_creates_new_exact_subset_and_repeats_acknowledgement(
        self,
    ) -> None:
        plan = _two_effect_plan()
        hashes = {
            "html_sha256": "2" * 64,
            "markdown_sha256": "3" * 64,
            "meta_sha256": "4" * 64,
            "semantic_sha256": "5" * 64,
        }

        decision = canonical_curation_m3.compile_decision(
            plan,
            action="APPROVE_SELECTED",
            review_package_hashes=hashes,
            selected_effect_ids=("effect-000000000000000000000011",),
            irreversible_acknowledgement=canonical_curation_m3.IRREVERSIBLE_CONSEQUENCE_KO,
        )

        subset = decision.approved_plan
        self.assertEqual(subset.parent_plan_sha256, plan.sha256)
        self.assertEqual(
            tuple(effect.effect_id for effect in subset.effects),
            ("effect-000000000000000000000011",),
        )
        self.assertEqual(len(subset.source_observations), 1)
        self.assertIn("projects/example-project/second.md", subset.unchanged_paths)
        self.assertNotIn("projects/example-project/canonical-2.md", subset.final_paths)


if __name__ == "__main__":
    unittest.main()
