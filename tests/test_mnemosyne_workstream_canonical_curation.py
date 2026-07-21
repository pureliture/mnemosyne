import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unicodedata
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    canonical_curation,
    canonical_curation_review,
    review_package,
    workstream_curation,
)
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


REGISTRY = b"""schema_version: 1
root: {root}
registry_root: {root}/_registry
inbox: {root}/inbox
memory_workspaces: {root}/memory/workspaces.yml
workstreams:
  - id: alpha
    lifecycle: active
    project_home: {root}/projects/alpha
    aliases:
      - Alpha Project
never_touch:
  - worktrees/
  - graphify-out/
categories: []
"""


def _fingerprint_tree(root: Path) -> tuple[tuple[object, ...], ...]:
    rows = []
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        content_sha256 = None
        link_target = None
        if stat.S_ISREG(info.st_mode):
            content_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            link_target = os.readlink(path)
        rows.append(
            (
                relative,
                stat.S_IMODE(info.st_mode),
                info.st_uid,
                info.st_nlink,
                info.st_size,
                content_sha256,
                link_target,
            )
        )
    return tuple(rows)


def _domain_plan() -> canonical_curation.CurationPlan:
    observations = []
    effects = []
    for index, role in enumerate(("decisions", "references"), 1):
        source = f"inbox/source-{index}.md"
        content_hash = hashlib.sha256(f"source-{index}".encode("ascii")).hexdigest()
        snapshot_hash = hashlib.sha256(f"snapshot-{index}".encode("ascii")).hexdigest()
        observation = canonical_curation.SourceObservation(
            observation_id=f"obs-{index:024d}",
            relative_path=source,
            owner_kind="unassigned",
            owner_id="unassigned",
            lifecycle="unassigned",
            document_role=role,
            classification="EXACT",
            classification_evidence=("path-token",),
            content_summary=f"Source {index}",
            device=1,
            inode=index,
            owner=os.getuid(),
            mode=0o600,
            link_count=1,
            size=8,
            modified_time_ns=index,
            content_sha256=content_hash,
            snapshot_sha256=snapshot_hash,
        )
        effect = canonical_curation.PlanEffect(
            effect_id=f"effect-{index:024d}",
            action="move",
            input_observation_id=observation.observation_id,
            source_path=source,
            output_path=f"projects/alpha/{role}/source-{index}.md",
            expected_output_sha256=content_hash,
            risk_codes=("PATH_ONLY_CHANGE",),
        )
        observations.append(observation)
        effects.append(effect)
    spine = tuple(
        canonical_curation.SpineEntry(
            role=role,
            current_path="projects/alpha/README.md" if role == "overview" else None,
            current_heading="Alpha" if role == "overview" else None,
            proposed_path=(
                "projects/alpha/README.md"
                if role == "overview"
                else next(
                    (
                        effect.output_path
                        for effect, observation in zip(effects, observations)
                        if observation.document_role == role
                    ),
                    None,
                )
            ),
            proposed_heading="Alpha" if role == "overview" else None,
            status=(
                "PRESENT"
                if role == "overview"
                else "PROPOSED"
                if role in {"decisions", "references"}
                else "MISSING"
            ),
        )
        for role in (
            "overview",
            "current_state",
            "decisions",
            "work_results",
            "references",
        )
    )
    return canonical_curation.CurationPlan(
        primary_workstream_id="alpha",
        captured_lifecycle="active",
        project_home="projects/alpha",
        project_identity=(1, 2, 0o700, os.getuid()),
        root_identity=(1, 1, 0o700, os.getuid()),
        policy_sha256="a" * 64,
        source_observations=tuple(observations),
        effects=tuple(effects),
        spine=spine,
        findings=(),
        unchanged_paths=("projects/alpha/README.md",),
        out_of_scope_paths=("inbox/unrelated.md",),
        coverage=(
            ("bounds", {"max_depth": 4, "max_items": 32}),
            ("inspected_files", 3),
            ("truncated", False),
        ),
    )


class CanonicalCurationModelTest(unittest.TestCase):
    def test_plan_identity_is_order_independent_and_selected_plan_is_new(self) -> None:
        plan = _domain_plan()
        reordered = replace(
            plan,
            source_observations=tuple(reversed(plan.source_observations)),
            effects=tuple(reversed(plan.effects)),
            unchanged_paths=tuple(reversed(plan.unchanged_paths)),
            out_of_scope_paths=tuple(reversed(plan.out_of_scope_paths)),
        )

        self.assertEqual(reordered.sha256, plan.sha256)
        self.assertEqual(
            reordered.source_observation_sha256,
            plan.source_observation_sha256,
        )
        first_review = canonical_curation_review.compile_review(
            plan,
            rendered_at="2026-07-19T12:00:00Z",
            renderer_id="test-renderer-v2",
        )
        reordered_review = canonical_curation_review.compile_review(
            reordered,
            rendered_at="2026-07-19T12:00:00Z",
            renderer_id="test-renderer-v2",
        )
        self.assertEqual(reordered_review, first_review)

        selected = plan.subset((plan.effects[1].effect_id,))
        self.assertEqual(selected.parent_plan_sha256, plan.sha256)
        self.assertNotEqual(selected.sha256, plan.sha256)
        self.assertEqual(selected.effects, (plan.effects[1],))
        self.assertEqual(
            selected.source_observations,
            (plan.source_observations[1],),
        )
        self.assertIn(plan.effects[0].source_path, selected.unchanged_paths)

    def test_all_selected_reject_and_defer_bind_exact_review_hashes(self) -> None:
        plan = _domain_plan()
        package_hashes = {
            "html_sha256": "b" * 64,
            "markdown_sha256": "c" * 64,
            "meta_sha256": "d" * 64,
            "semantic_sha256": "e" * 64,
        }

        approved_all = canonical_curation.compile_decision(
            plan,
            action="APPROVE_ALL",
            review_package_hashes=package_hashes,
        )
        approved_selected = canonical_curation.compile_decision(
            plan,
            action="APPROVE_SELECTED",
            selected_effect_ids=(plan.effects[0].effect_id,),
            review_package_hashes=package_hashes,
        )
        rejected = canonical_curation.compile_decision(
            plan,
            action="REJECT",
            review_package_hashes=package_hashes,
            reason="The paths should stay unchanged.",
        )
        deferred = canonical_curation.compile_decision(
            plan,
            action="DEFER",
            review_package_hashes=package_hashes,
            reason="Review later.",
        )

        self.assertEqual(approved_all.approved_plan, plan)
        self.assertEqual(
            approved_all.selected_effect_ids,
            tuple(effect.effect_id for effect in plan.effects),
        )
        self.assertEqual(len(approved_selected.approved_plan.effects), 1)
        self.assertIsNone(rejected.approved_plan)
        self.assertIsNone(deferred.approved_plan)
        self.assertEqual(
            dict(approved_all.review_package_hashes),
            package_hashes,
        )

        with self.assertRaises(canonical_curation.CanonicalCurationError):
            replace(approved_all, displayed_plan_sha256="f" * 64)
        with self.assertRaises(canonical_curation.CanonicalCurationError):
            replace(
                approved_selected,
                selected_effect_ids=(plan.effects[1].effect_id,),
            )

    def test_selected_plan_recomposes_spine_and_drops_unrelated_finding(self) -> None:
        plan = _domain_plan()
        unrelated_finding = canonical_curation.CurationFinding(
            finding_id="finding-000000000000000000000002",
            finding_kind="MERGE_REQUIRED",
            relative_path=plan.effects[1].source_path,
            evidence=("the second source needs a later merge",),
        )
        plan = replace(plan, findings=(unrelated_finding,))

        selected = plan.subset((plan.effects[0].effect_id,))

        spine = {entry.role: entry for entry in selected.spine}
        self.assertEqual(spine["decisions"].status, "PROPOSED")
        self.assertEqual(spine["references"].status, "MISSING")
        self.assertIsNone(spine["references"].proposed_path)
        self.assertEqual(selected.findings, ())
        self.assertEqual(dict(selected.coverage)["subset_effect_count"], 1)

    def test_non_path_transform_cannot_be_a_plan_effect(self) -> None:
        plan = _domain_plan()
        with self.assertRaises(canonical_curation.CanonicalCurationError) as raised:
            replace(plan.effects[0], action="merge")
        self.assertEqual(raised.exception.reason_code, "EFFECT_NOT_IMPLEMENTED")

        finding = canonical_curation.CurationFinding(
            finding_id="finding-000000000000000000000001",
            finding_kind="MERGE_REQUIRED",
            relative_path="inbox/source-1.md",
            evidence=("two sources appear to overlap",),
        )
        self.assertNotIn("output", finding.canonical_value)
        with self.assertRaises(canonical_curation.CanonicalCurationError) as selection:
            replace(plan, findings=(finding,)).subset((finding.finding_id,))
        self.assertEqual(selection.exception.reason_code, "DECISION_INVALID")

        with self.assertRaises(canonical_curation.CanonicalCurationError):
            replace(finding, evidence=("valid", ""))


class CurationReviewV2Test(unittest.TestCase):
    REQUIRED_CATEGORIES = (
        "workstream_identity",
        "coverage",
        "structure",
        "item_identity",
        "classification",
        "rationale",
        "relations",
        "content_consequence",
        "uncertainty",
        "untouched_proof",
        "seal",
    )

    def _payload(self) -> review_package.ReviewPackagePayload:
        return canonical_curation_review.compile_review(
            _domain_plan(),
            rendered_at="2026-07-19T12:00:00Z",
            renderer_id="test-renderer-v2",
        )

    @staticmethod
    def _meta_with_hash(
        payload: review_package.ReviewPackagePayload,
        *,
        field: str,
        encoded: bytes,
    ) -> bytes:
        meta = json.loads(payload.meta_json)
        meta[field] = hashlib.sha256(encoded).hexdigest()
        return canonical_json_bytes(meta)

    def test_every_required_markdown_category_is_independently_required(self) -> None:
        payload = self._payload()

        for category in self.REQUIRED_CATEGORIES:
            with self.subTest(category=category):
                markdown = payload.markdown.replace(
                    f"`category:{category}`".encode("ascii"),
                    b"`category:omitted_category`",
                    1,
                )
                tampered = review_package.ReviewPackagePayload(
                    markdown=markdown,
                    html=payload.html,
                    meta_json=self._meta_with_hash(
                        payload,
                        field="markdown_sha256",
                        encoded=markdown,
                    ),
                    semantic_json=payload.semantic_json,
                )
                with self.assertRaises(canonical_curation_review.CurationReviewError):
                    canonical_curation_review.validate_review_payload(tampered)

    def test_html_only_category_omission_and_decision_reordering_are_rejected(self) -> None:
        payload = self._payload()
        omitted = payload.html.replace(
            b'data-category="relations"',
            b'data-omitted-category="relations"',
            1,
        )
        omitted_payload = review_package.ReviewPackagePayload(
            markdown=payload.markdown,
            html=omitted,
            meta_json=self._meta_with_hash(
                payload,
                field="html_sha256",
                encoded=omitted,
            ),
            semantic_json=payload.semantic_json,
        )
        with self.assertRaises(canonical_curation_review.CurationReviewError):
            canonical_curation_review.validate_review_payload(omitted_payload)

        first = '<li data-decision-action="전체 승인">전체 승인</li>'.encode("utf-8")
        second = '<li data-decision-action="선택 승인">선택 승인</li>'.encode("utf-8")
        reordered = payload.html.replace(first, b"__FIRST__", 1)
        reordered = reordered.replace(second, first, 1).replace(b"__FIRST__", second, 1)
        reordered_payload = review_package.ReviewPackagePayload(
            markdown=payload.markdown,
            html=reordered,
            meta_json=self._meta_with_hash(
                payload,
                field="html_sha256",
                encoded=reordered,
            ),
            semantic_json=payload.semantic_json,
        )
        with self.assertRaises(canonical_curation_review.CurationReviewError):
            canonical_curation_review.validate_review_payload(reordered_payload)

    def test_v2_uses_the_shared_three_file_no_replace_store(self) -> None:
        payload = self._payload()
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            package = Path(temporary) / "review"
            package.mkdir(mode=0o700)
            first = canonical_curation_review.write_review_package(package, payload)
            identities = {
                path.name: (path.stat().st_dev, path.stat().st_ino, path.read_bytes())
                for path in package.iterdir()
            }

            second = canonical_curation_review.write_review_package(package, payload)

            self.assertEqual(second, first)
            self.assertEqual(
                canonical_curation_review.validate_review_directory(
                    package,
                    expected_plan_sha256=_domain_plan().sha256,
                ),
                first,
            )
            self.assertEqual(
                sorted(path.name for path in package.iterdir()),
                ["review.html", "review.md", "review.meta.json"],
            )
            self.assertFalse((package / "review.semantic.json").exists())
            self.assertEqual(
                {
                    path.name: (path.stat().st_dev, path.stat().st_ino, path.read_bytes())
                    for path in package.iterdir()
                },
                identities,
            )

            (package / "review.html").write_bytes(payload.html + b"tampered")
            with self.assertRaises(canonical_curation_review.CurationReviewError):
                canonical_curation_review.validate_review_directory(
                    package,
                    expected_plan_sha256=_domain_plan().sha256,
                )

    def test_blocked_finding_is_not_presented_as_ready_or_approvable(self) -> None:
        plan = _domain_plan()
        finding = canonical_curation.CurationFinding(
            finding_id="finding-000000000000000000000003",
            finding_kind="MERGE_REQUIRED",
            relative_path=plan.effects[0].source_path,
            evidence=("possible overlap needs a human decision",),
        )

        payload = canonical_curation_review.compile_review(
            replace(plan, findings=(finding,)),
            rendered_at="2026-07-19T12:00:00Z",
            renderer_id="test-renderer-v2",
        )

        self.assertNotIn("상태: **검토 준비됨**".encode("utf-8"), payload.markdown)
        self.assertNotIn("상태: 검토 준비됨".encode("utf-8"), payload.html)
        for artifact in (payload.markdown, payload.html):
            self.assertIn("차단된 Finding은 승인 대상이 아닙니다".encode("utf-8"), artifact)


class WorkstreamCanonicalCurationPublicTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "raw"
        self.root.mkdir(mode=0o700)
        self.registry = self.root / "_registry"
        self.registry.mkdir(mode=0o700)
        placement_map = self.registry / "placement-map.yml"
        placement_map.write_bytes(
            REGISTRY.replace(b"{root}", str(self.root).encode("utf-8"))
        )
        placement_map.chmod(0o600)

        self.project = self.root / "projects" / "alpha"
        (self.project / "decisions").mkdir(parents=True, mode=0o700)
        (self.project / "references").mkdir(mode=0o700)
        (self.project / "README.md").write_text(
            "# Alpha\n\nProject overview.\n",
            encoding="utf-8",
        )
        self.internal = self.project / "loose-decision.md"
        self.internal.write_text(
            "# Alpha decision\n\nKeep one canonical source.\n",
            encoding="utf-8",
        )
        inbox = self.root / "inbox"
        inbox.mkdir(mode=0o700)
        self.external = inbox / "alpha-reference.md"
        self.external.write_text(
            "# Alpha reference\n\nEvidence for the Alpha workstream.\n",
            encoding="utf-8",
        )
        self.package = self.base / "review-package"
        self.package.mkdir(mode=0o700)

    def _run_inspection(
        self,
        *,
        root: Path | None = None,
        package: Path | None = None,
        workstream: str = "Alpha Project",
    ) -> tuple[int, dict[str, object]]:
        selected_root = self.root if root is None else root
        selected_package = self.package if package is None else package
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = mnemosyne.main(
                [
                    "curation",
                    "inspect",
                    "workstream",
                    "--workstream",
                    workstream,
                    "--root",
                    str(selected_root),
                    "--actor",
                    "test-operator",
                    "--max-items",
                    "32",
                    "--max-depth",
                    "4",
                    "--max-hint-bytes",
                    "8192",
                    "--review-package",
                    str(selected_package),
                    "--json",
                ]
            )
        return exit_code, json.loads(stdout.getvalue())

    def test_reference_document_uses_existing_research_directory_without_references(
        self,
    ) -> None:
        synthetic_root = self.base / "synthetic-raw"
        synthetic_root.mkdir(mode=0o700)
        synthetic_registry = synthetic_root / "_registry"
        synthetic_registry.mkdir(mode=0o700)
        (synthetic_registry / "placement-map.yml").write_bytes(
            REGISTRY.replace(b"{root}", str(synthetic_root).encode("utf-8"))
            .replace(b"id: alpha", b"id: nebula")
            .replace(b"projects/alpha", b"projects/nebula")
            .replace(b"Alpha Project", b"Nebula Project")
        )
        project = synthetic_root / "projects" / "nebula"
        research = project / "docs" / "research"
        research.mkdir(parents=True, mode=0o700)
        (research / "existing-research.md").write_text(
            "# Existing research\n",
            encoding="utf-8",
        )
        (project / "nebula-research.md").write_text(
            "# Nebula research\n",
            encoding="utf-8",
        )
        package = self.base / "synthetic-review-package"
        package.mkdir(mode=0o700)

        exit_code, outcome = self._run_inspection(
            root=synthetic_root,
            package=package,
            workstream="Nebula Project",
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            {
                effect["source"]: effect["target"]
                for effect in outcome["result"]["plan"]["effects"]
            },
            {
                "projects/nebula/nebula-research.md": (
                    "projects/nebula/docs/research/nebula-research.md"
                ),
            },
        )

    def test_reference_target_ambiguity_blocks_review_approval(self) -> None:
        synthetic_root = self.base / "ambiguous-raw"
        synthetic_root.mkdir(mode=0o700)
        synthetic_registry = synthetic_root / "_registry"
        synthetic_registry.mkdir(mode=0o700)
        (synthetic_registry / "placement-map.yml").write_bytes(
            REGISTRY.replace(b"{root}", str(synthetic_root).encode("utf-8"))
            .replace(b"id: alpha", b"id: aurora")
            .replace(b"projects/alpha", b"projects/aurora")
            .replace(b"Alpha Project", b"Aurora Project")
        )
        project = synthetic_root / "projects" / "aurora"
        (project / "references").mkdir(parents=True, mode=0o700)
        (project / "docs" / "research").mkdir(parents=True, mode=0o700)
        (project / "aurora-research.md").write_text(
            "# Aurora research\n",
            encoding="utf-8",
        )
        package = self.base / "ambiguous-review-package"
        package.mkdir(mode=0o700)

        exit_code, outcome = self._run_inspection(
            root=synthetic_root,
            package=package,
            workstream="Aurora Project",
        )

        self.assertEqual(exit_code, 0)
        findings = outcome["result"]["plan"]["findings"]
        self.assertEqual(
            {(finding["kind"], finding["path"]) for finding in findings},
            {("TARGET_AMBIGUOUS", "projects/aurora/aurora-research.md")},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(outcome["result"]["plan"]["effects"], [])
        for artifact in (package / "review.md", package / "review.html"):
            self.assertNotIn("검토 준비됨".encode("utf-8"), artifact.read_bytes())

    def test_explicit_research_readme_outranks_generic_overview(self) -> None:
        synthetic_root = self.base / "readme-research-raw"
        synthetic_root.mkdir(mode=0o700)
        synthetic_registry = synthetic_root / "_registry"
        synthetic_registry.mkdir(mode=0o700)
        (synthetic_registry / "placement-map.yml").write_bytes(
            REGISTRY.replace(b"{root}", str(synthetic_root).encode("utf-8"))
            .replace(b"id: alpha", b"id: polaris")
            .replace(b"projects/alpha", b"projects/polaris")
            .replace(b"Alpha Project", b"Polaris Project")
        )
        project = synthetic_root / "projects" / "polaris"
        (project / "docs" / "research").mkdir(parents=True, mode=0o700)
        (project / "README.md").write_text(
            "# Polaris research reference\n\nResearch reference material.\n",
            encoding="utf-8",
        )
        package = self.base / "readme-research-review-package"
        package.mkdir(mode=0o700)

        exit_code, outcome = self._run_inspection(
            root=synthetic_root,
            package=package,
            workstream="Polaris Project",
        )

        self.assertEqual(exit_code, 0)
        _hashes, displayed_plan, _assembly = (
            canonical_curation_review.validate_context_bound_review_directory(
                package,
                expected_plan_sha256=outcome["result"]["plan"]["sha256"],
            )
        )
        observation = next(
            item
            for item in displayed_plan["source_observations"]
            if item["relative_path"] == "projects/polaris/README.md"
        )
        self.assertEqual(observation["document_role"], "references")
        spine = {entry["role"]: entry for entry in displayed_plan["spine"]}
        proposed_target = "projects/polaris/docs/research/README.md"
        self.assertEqual(spine["references"]["proposed_path"], proposed_target)
        self.assertNotEqual(spine["overview"]["proposed_path"], proposed_target)
        self.assertEqual(
            {
                effect["source"]: effect["target"]
                for effect in outcome["result"]["plan"]["effects"]
            },
            {
                "projects/polaris/README.md": (
                    "projects/polaris/docs/research/README.md"
                ),
            },
        )

    def test_explicit_decision_and_research_conflict_blocks_review(self) -> None:
        synthetic_root = self.base / "role-conflict-raw"
        synthetic_root.mkdir(mode=0o700)
        synthetic_registry = synthetic_root / "_registry"
        synthetic_registry.mkdir(mode=0o700)
        (synthetic_registry / "placement-map.yml").write_bytes(
            REGISTRY.replace(b"{root}", str(synthetic_root).encode("utf-8"))
            .replace(b"id: alpha", b"id: lyra")
            .replace(b"projects/alpha", b"projects/lyra")
            .replace(b"Alpha Project", b"Lyra Project")
        )
        project = synthetic_root / "projects" / "lyra"
        (project / "decisions").mkdir(parents=True, mode=0o700)
        (project / "docs" / "research").mkdir(parents=True, mode=0o700)
        (project / "lyra-decision-research.md").write_text(
            "# Lyra decision research reference\n\nDecision and research reference.\n",
            encoding="utf-8",
        )
        package = self.base / "role-conflict-review-package"
        package.mkdir(mode=0o700)

        exit_code, outcome = self._run_inspection(
            root=synthetic_root,
            package=package,
            workstream="Lyra Project",
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(outcome["result"]["plan"]["effects"], [])
        findings = outcome["result"]["plan"]["findings"]
        self.assertEqual(
            {(finding["kind"], finding["path"]) for finding in findings},
            {("ROLE_AMBIGUOUS", "projects/lyra/lyra-decision-research.md")},
        )
        self.assertEqual(len(findings), 1)
        for artifact in (package / "review.md", package / "review.html"):
            self.assertNotIn("검토 준비됨".encode("utf-8"), artifact.read_bytes())

    def test_research_routing_is_project_relative_across_workstreams(self) -> None:
        synthetic_root = self.base / "multi-workstream-raw"
        synthetic_root.mkdir(mode=0o700)
        registry = synthetic_root / "_registry"
        registry.mkdir(mode=0o700)
        placement_map = registry / "placement-map.yml"
        placement_map.write_text(
            f"""schema_version: 1
root: {synthetic_root}
registry_root: {synthetic_root}/_registry
inbox: {synthetic_root}/inbox
memory_workspaces: {synthetic_root}/memory/workspaces.yml
workstreams:
  - id: atlas
    lifecycle: active
    project_home: {synthetic_root}/projects/atlas-lab
    aliases:
      - Atlas Lab
  - id: zephyr
    lifecycle: active
    project_home: {synthetic_root}/projects/zephyr-notes
    aliases:
      - Zephyr Notes
never_touch:
  - worktrees/
  - graphify-out/
categories: []
""",
            encoding="utf-8",
        )
        placement_map.chmod(0o600)
        layouts = (
            ("Atlas Lab", "projects/atlas-lab"),
            ("Zephyr Notes", "projects/zephyr-notes"),
        )
        for _workstream, project_home in layouts:
            project = synthetic_root / project_home
            (project / "docs" / "research").mkdir(parents=True, mode=0o700)
            (project / "research-reference.md").write_text(
                "# Research reference\n",
                encoding="utf-8",
            )

        for index, (workstream, project_home) in enumerate(layouts):
            package = self.base / f"multi-workstream-review-{index}"
            package.mkdir(mode=0o700)
            exit_code, outcome = self._run_inspection(
                root=synthetic_root,
                package=package,
                workstream=workstream,
            )

            self.assertEqual(exit_code, 0, outcome)
            self.assertEqual(
                {
                    effect["source"]: effect["target"]
                    for effect in outcome["result"]["plan"]["effects"]
                },
                {
                    f"{project_home}/research-reference.md": (
                        f"{project_home}/docs/research/research-reference.md"
                    ),
                },
            )

    def test_nfd_korean_research_filename_routes_to_existing_research_directory(
        self,
    ) -> None:
        synthetic_root = self.base / "nfd-research-raw"
        synthetic_root.mkdir(mode=0o700)
        registry = synthetic_root / "_registry"
        registry.mkdir(mode=0o700)
        placement_map = registry / "placement-map.yml"
        placement_map.write_bytes(
            REGISTRY.replace(b"{root}", str(synthetic_root).encode("utf-8"))
            .replace(b"id: alpha", b"id: hangul")
            .replace(b"projects/alpha", b"projects/hangul-lab")
            .replace(b"Alpha Project", b"Hangul Lab")
        )
        placement_map.chmod(0o600)
        project = synthetic_root / "projects" / "hangul-lab"
        (project / "docs" / "research").mkdir(parents=True, mode=0o700)
        filename = unicodedata.normalize("NFD", "리서치-노트.md")
        self.assertNotEqual(filename, "리서치-노트.md")
        (project / filename).write_text("# Notes\n", encoding="utf-8")
        package = self.base / "nfd-research-review"
        package.mkdir(mode=0o700)

        exit_code, outcome = self._run_inspection(
            root=synthetic_root,
            package=package,
            workstream="Hangul Lab",
        )

        self.assertEqual(exit_code, 0, outcome)
        self.assertEqual(
            {
                effect["source"]: effect["target"]
                for effect in outcome["result"]["plan"]["effects"]
            },
            {
                f"projects/hangul-lab/{filename}": (
                    f"projects/hangul-lab/docs/research/{filename}"
                ),
            },
        )

    def test_category_overlap_does_not_block_active_workstream_research_effect(
        self,
    ) -> None:
        synthetic_root = self.base / "category-overlap-raw"
        synthetic_root.mkdir(mode=0o700)
        registry = synthetic_root / "_registry"
        registry.mkdir(mode=0o700)
        placement_map = registry / "placement-map.yml"
        placement_map.write_bytes(
            REGISTRY.replace(
                b"categories: []",
                b"""categories:
  - id: projects
    target: {root}/projects
    patterns:
      - projects/**
""",
            )
            .replace(b"{root}", str(synthetic_root).encode("utf-8"))
            .replace(b"id: alpha", b"id: solstice")
            .replace(b"projects/alpha", b"projects/solstice-lab")
            .replace(b"Alpha Project", b"Solstice Lab")
        )
        placement_map.chmod(0o600)
        project = synthetic_root / "projects" / "solstice-lab"
        (project / "docs" / "research").mkdir(parents=True, mode=0o700)
        (project / "solstice-research.md").write_text(
            "# Solstice research reference\n",
            encoding="utf-8",
        )
        package = self.base / "category-overlap-review"
        package.mkdir(mode=0o700)

        exit_code, outcome = self._run_inspection(
            root=synthetic_root,
            package=package,
            workstream="Solstice Lab",
        )

        self.assertEqual(exit_code, 0, outcome)
        self.assertEqual(outcome["result"]["plan"]["findings"], [])
        self.assertEqual(
            {
                effect["source"]: effect["target"]
                for effect in outcome["result"]["plan"]["effects"]
            },
            {
                "projects/solstice-lab/solstice-research.md": (
                    "projects/solstice-lab/docs/research/solstice-research.md"
                ),
            },
        )

    def test_active_workstream_review_package_is_fresh_complete_and_read_only(
        self,
    ) -> None:
        before = _fingerprint_tree(self.root)
        exit_code, outcome = self._run_inspection()

        self.assertEqual(exit_code, 0)
        self.assertEqual(outcome["outcome_kind"], "completed")
        result = outcome["result"]
        self.assertEqual(result["view"], "workstream")
        self.assertIs(result["canonical_source_read_only"], True)
        self.assertEqual(
            result["workstream"],
            {
                "id": "alpha",
                "lifecycle": "active",
                "project_home": "projects/alpha",
            },
        )
        self.assertEqual(
            result["not_modified"],
            ["canonical-corpus", "curation-control"],
        )

        plan = result["plan"]
        self.assertRegex(plan["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(
            plan["source_observation_sha256"],
            r"^[0-9a-f]{64}$",
        )
        effects = plan["effects"]
        self.assertEqual(
            {effect["source"]: effect["target"] for effect in effects},
            {
                "inbox/alpha-reference.md": "projects/alpha/references/alpha-reference.md",
                "projects/alpha/loose-decision.md": (
                    "projects/alpha/decisions/loose-decision.md"
                ),
            },
        )
        self.assertEqual(
            {effect["source"] for effect in effects},
            {
                "projects/alpha/loose-decision.md",
                "inbox/alpha-reference.md",
            },
        )
        for effect in effects:
            self.assertIn(effect["action"], {"move", "rename"})
            self.assertNotEqual(effect["source"], effect["target"])
            self.assertTrue(effect["target"].startswith("projects/alpha/"))
            self.assertEqual(effect["source_sha256"], effect["output_sha256"])
            source = self.root / effect["source"]
            self.assertEqual(
                effect["source_sha256"],
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )

        package = result["review_package"]
        self.assertEqual(package["directory"], str(self.package))
        self.assertEqual(
            sorted(path.name for path in self.package.iterdir()),
            ["review.html", "review.md", "review.meta.json"],
        )
        markdown = (self.package / "review.md").read_bytes()
        rendered_html = (self.package / "review.html").read_bytes()
        meta_bytes = (self.package / "review.meta.json").read_bytes()
        meta = json.loads(meta_bytes)
        self.assertEqual(package["markdown_sha256"], hashlib.sha256(markdown).hexdigest())
        self.assertEqual(package["html_sha256"], hashlib.sha256(rendered_html).hexdigest())
        self.assertEqual(package["meta_sha256"], hashlib.sha256(meta_bytes).hexdigest())
        self.assertEqual(meta["plan_sha256"], plan["sha256"])
        self.assertEqual(
            meta["source_observation_sha256"],
            plan["source_observation_sha256"],
        )
        self.assertEqual(meta["semantic_sha256"], package["semantic_sha256"])
        for expected in (
            b"projects/alpha/loose-decision.md",
            b"inbox/alpha-reference.md",
            plan["sha256"].encode("ascii"),
        ):
            self.assertIn(expected, markdown)
            self.assertIn(expected, rendered_html)

        self.assertEqual(_fingerprint_tree(self.root), before)
        self.assertTrue(self.internal.exists())
        self.assertTrue(self.external.exists())

    def test_missing_role_directories_use_logical_spine_without_false_findings(
        self,
    ) -> None:
        (self.project / "decisions").rmdir()
        (self.project / "references").rmdir()
        before = _fingerprint_tree(self.root)

        exit_code, outcome = self._run_inspection()

        self.assertEqual(exit_code, 0)
        result = outcome["result"]
        self.assertEqual(result["plan"]["effects"], [])
        self.assertEqual(result["plan"]["findings"], [])
        _hashes, displayed_plan, _assembly = (
            canonical_curation_review.validate_context_bound_review_directory(
                self.package,
                expected_plan_sha256=result["plan"]["sha256"],
            )
        )
        decisions = next(
            entry
            for entry in displayed_plan["spine"]
            if entry["role"] == "decisions"
        )
        self.assertEqual(
            decisions,
            {
                "current_heading": "Alpha decision",
                "current_path": "projects/alpha/loose-decision.md",
                "proposed_heading": "Alpha decision",
                "proposed_path": "projects/alpha/loose-decision.md",
                "role": "decisions",
                "status": "PRESENT",
            },
        )
        self.assertEqual(_fingerprint_tree(self.root), before)

    def test_adaptive_profile_keeps_derived_outputs_out_of_human_spine(self) -> None:
        generated = self.project / "generated-context-out"
        generated.mkdir(mode=0o700)
        (generated / "current-overview.json").write_text(
            '{"kind":"generated-evidence"}\n',
            encoding="utf-8",
        )
        research = self.project / "docs" / "research"
        research.mkdir(parents=True, mode=0o700)
        (research / "platform-overview.md").write_text(
            "# Platform overview\n\nReference material.\n",
            encoding="utf-8",
        )
        meetings = self.project / "meetings"
        meetings.mkdir(mode=0o700)
        (meetings / "status-notes.md").write_text(
            "# Status notes\n\nMeeting draft.\n",
            encoding="utf-8",
        )

        exit_code, outcome = self._run_inspection()

        self.assertEqual(exit_code, 0)
        result = outcome["result"]
        self.assertEqual(
            {
                effect["source"]: effect["target"]
                for effect in result["plan"]["effects"]
            },
            {
                "projects/alpha/loose-decision.md": (
                    "projects/alpha/decisions/loose-decision.md"
                ),
            },
        )
        findings = result["plan"]["findings"]
        self.assertEqual(
            {(finding["kind"], finding["path"]) for finding in findings},
            {("TARGET_AMBIGUOUS", "inbox/alpha-reference.md")},
        )
        self.assertEqual(len(findings), 1)
        _hashes, displayed_plan, _assembly = (
            canonical_curation_review.validate_context_bound_review_directory(
                self.package,
                expected_plan_sha256=result["plan"]["sha256"],
            )
        )
        observations = {
            observation["relative_path"]: observation
            for observation in displayed_plan["source_observations"]
        }
        generated_path = "projects/alpha/generated-context-out/current-overview.json"
        reference_path = "projects/alpha/docs/research/platform-overview.md"
        meeting_path = "projects/alpha/meetings/status-notes.md"
        self.assertNotIn(generated_path, observations)
        self.assertIn(generated_path, displayed_plan["out_of_scope_paths"])
        self.assertEqual(observations[reference_path]["document_role"], "references")
        self.assertIn(
            "artifact-family:reference-library",
            observations[reference_path]["classification_evidence"],
        )
        self.assertEqual(observations[meeting_path]["document_role"], "work_results")
        self.assertIn(
            "artifact-family:meeting-source",
            observations[meeting_path]["classification_evidence"],
        )
        spine = {entry["role"]: entry for entry in displayed_plan["spine"]}
        self.assertEqual(spine["overview"]["current_path"], "projects/alpha/README.md")
        self.assertEqual(spine["references"]["current_path"], reference_path)
        self.assertEqual(spine["work_results"]["current_path"], meeting_path)

    def test_frozen_workstream_never_opens_content_or_writes_package(self) -> None:
        placement_map = self.registry / "placement-map.yml"
        for lifecycle in ("paused", "completed"):
            with self.subTest(lifecycle=lifecycle):
                raw = REGISTRY.replace(
                    b"lifecycle: active",
                    ("lifecycle: " + lifecycle).encode("ascii"),
                ).replace(b"{root}", str(self.root).encode("utf-8"))
                placement_map.write_bytes(raw)
                placement_map.chmod(0o600)
                before = _fingerprint_tree(self.root)
                with mock.patch.object(
                    workstream_curation.librarian,
                    "inspect_scope",
                    side_effect=AssertionError("frozen content scan attempted"),
                ) as scanned, mock.patch.object(
                    workstream_curation.librarian_snapshot,
                    "observe_proposal",
                    side_effect=AssertionError("frozen content observation attempted"),
                ) as observed:
                    exit_code, outcome = self._run_inspection()

                self.assertEqual(exit_code, 2)
                self.assertEqual(outcome["outcome_kind"], "blocked")
                self.assertEqual(outcome["reason_code"], "WORKSTREAM_FROZEN")
                scanned.assert_not_called()
                observed.assert_not_called()
                self.assertEqual(list(self.package.iterdir()), [])
                self.assertEqual(_fingerprint_tree(self.root), before)

    def test_source_drift_during_render_is_stale_without_package_artifacts(self) -> None:
        compile_review = canonical_curation_review.compile_context_bound_review

        def drift_then_compile(*args: object, **kwargs: object):
            self.internal.write_text("# Changed during render\n", encoding="utf-8")
            return compile_review(*args, **kwargs)

        with mock.patch.object(
            workstream_curation.canonical_curation_review,
            "compile_context_bound_review",
            side_effect=drift_then_compile,
        ):
            exit_code, outcome = self._run_inspection()

        self.assertEqual(exit_code, 2)
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(list(self.package.iterdir()), [])

    def test_unchanged_structure_drift_is_stale_without_package_artifacts(self) -> None:
        compile_review = canonical_curation_review.compile_context_bound_review
        readme = self.project / "README.md"

        def drift_then_compile(*args: object, **kwargs: object):
            original = readme.read_bytes()
            readme.write_bytes(original.replace(b"Project overview", b"Changed overview"))
            return compile_review(*args, **kwargs)

        with mock.patch.object(
            workstream_curation.canonical_curation_review,
            "compile_context_bound_review",
            side_effect=drift_then_compile,
        ):
            exit_code, outcome = self._run_inspection()

        self.assertEqual(exit_code, 2)
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(list(self.package.iterdir()), [])

    def test_policy_drift_during_render_is_stale_without_package_artifacts(self) -> None:
        compile_review = canonical_curation_review.compile_context_bound_review
        placement_map = self.registry / "placement-map.yml"

        def drift_then_compile(*args: object, **kwargs: object):
            placement_map.write_bytes(
                placement_map.read_bytes().replace(
                    b"lifecycle: active",
                    b"lifecycle: paused",
                    1,
                )
            )
            placement_map.chmod(0o600)
            return compile_review(*args, **kwargs)

        with mock.patch.object(
            workstream_curation.canonical_curation_review,
            "compile_context_bound_review",
            side_effect=drift_then_compile,
        ):
            exit_code, outcome = self._run_inspection()

        self.assertEqual(exit_code, 2)
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(list(self.package.iterdir()), [])

    def test_post_write_drift_discards_the_unsealed_package(self) -> None:
        write_package = canonical_curation_review.write_context_bound_review_package

        def write_then_drift(*args: object, **kwargs: object):
            hashes = write_package(*args, **kwargs)
            self.internal.write_text("# Changed after package write\n", encoding="utf-8")
            return hashes

        with mock.patch.object(
            workstream_curation.canonical_curation_review,
            "write_context_bound_review_package",
            side_effect=write_then_drift,
        ):
            exit_code, outcome = self._run_inspection()

        self.assertEqual(exit_code, 2)
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(list(self.package.iterdir()), [])

    def test_review_package_cannot_be_inside_raw_corpus_or_control(self) -> None:
        for package in (
            self.project / "review-package",
            self.registry / "review-package",
        ):
            with self.subTest(package=package):
                package.mkdir(mode=0o700)
                before = _fingerprint_tree(self.root)

                exit_code, outcome = self._run_inspection(package=package)

                self.assertEqual(exit_code, 2)
                self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
                self.assertEqual(list(package.iterdir()), [])
                self.assertEqual(_fingerprint_tree(self.root), before)
                package.rmdir()

    def test_symlink_root_is_not_resolved_into_authority(self) -> None:
        linked_root = self.base / "linked-raw"
        linked_root.symlink_to(self.root, target_is_directory=True)

        exit_code, outcome = self._run_inspection(root=linked_root)

        self.assertEqual(exit_code, 2)
        self.assertEqual(outcome["reason_code"], "WORKSTREAM_HOME_UNSAFE")
        self.assertEqual(list(self.package.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
