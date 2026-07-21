"""TDD coverage for the context-bound Navigation Draft V2 route."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    canonical_curation,
    canonical_curation_review,
    context_assembly,
    navigation_draft,
    review_package,
    workstream_curation,
)
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class _ObservedFile:
    observation_id: str
    relative_path: str
    device: int
    inode: int
    owner: int
    mode: int
    link_count: int
    size: int
    modified_time_ns: int
    content_sha256: str
    snapshot_sha256: str


def _source(root: Path, relative_path: str, *, group: str) -> context_assembly.ContextSource:
    path = root / relative_path
    raw = path.read_bytes()
    info = path.stat()
    identity = (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
    )
    digest = _sha256(raw)
    source_id = "obs-000000000000000000000001" if path.name == "README.md" else "obs-000000000000000000000002"
    return context_assembly.read_current_local_source(
        root,
        _ObservedFile(
            observation_id=source_id, relative_path=relative_path,
            device=identity[0], inode=identity[1], owner=identity[2], mode=identity[3],
            link_count=identity[4], size=identity[5], modified_time_ns=identity[6],
            content_sha256=digest, snapshot_sha256=_sha256((relative_path + digest).encode("utf-8")),
        ),
        group=group,
        bounds=context_assembly.ContextAssemblyBounds(),
    )


def _observation(source: context_assembly.ContextSource, *, root: bool) -> canonical_curation.SourceObservation:
    assert source.identity is not None
    return canonical_curation.SourceObservation(
        observation_id=source.observation_id,
        relative_path=source.relative_path,
        owner_kind="workstream",
        owner_id="alpha",
        lifecycle="active",
        document_role="overview" if root else "work_results",
        classification="EXACT",
        classification_evidence=(
            "active-project-home",
            "artifact-family:canonical-navigation-candidate" if root else "nested",
        ),
        content_summary=source.content_projection.title,
        device=source.identity[0],
        inode=source.identity[1],
        owner=source.identity[2],
        mode=source.identity[3],
        link_count=source.identity[4],
        size=source.identity[5],
        modified_time_ns=source.identity[6],
        content_sha256=source.content_sha256,
        snapshot_sha256=source.snapshot_sha256,
    )


def _complete_context(root: Path) -> tuple[context_assembly.CompleteContextAssembly, tuple[canonical_curation.SourceObservation, ...]]:
    root_source = _source(root, "projects/alpha/README.md", group="PROJECT_ROOT")
    nested_source = _source(root, "projects/alpha/notes/nested.md", group="OTHER_NESTED")
    sources = (root_source, nested_source)
    root_info = root.stat()
    project_info = (root / "projects/alpha").stat()
    assembly = context_assembly.ContextAssembly(
        workstream=context_assembly.ContextWorkstream(
            id="alpha", lifecycle="active", project_home="projects/alpha", aliases=(), memory_workspace=None
        ),
        root_identity=(root_info.st_dev, root_info.st_ino, stat.S_IMODE(root_info.st_mode), root_info.st_uid),
        project_identity=(project_info.st_dev, project_info.st_ino, stat.S_IMODE(project_info.st_mode), project_info.st_uid),
        policy_sha256="a" * 64,
        outcome="COMPLETE",
        bounds=context_assembly.ContextAssemblyBounds(),
        sources=sources,
        claims=(),
        gaps=(),
        coverage=context_assembly.ContextCoverage(
            local_inspected=2, local_excluded=0, local_unreadable=0, local_truncated=0,
            source_group_counts=(("OTHER_NESTED", 1), ("PROJECT_ROOT", 1)),
            memory_status="NOT_CONFIGURED", memory_history_inspected=0, memory_history_included=0,
            memory_history_excluded=0, memory_history_malformed=0, memory_history_truncated=0,
            external_verified=0, external_unverified=0, excluded_paths=(), gap_paths=(), redaction_counts=(),
        ),
    )
    complete = assembly.require_complete(
        expected_workstream=assembly.workstream, expected_policy_sha256=assembly.policy_sha256,
        expected_root_identity=assembly.root_identity, expected_project_identity=assembly.project_identity,
        expected_assembly_sha256=assembly.sha256, expected_coverage_sha256=assembly.coverage_sha256,
    )
    return complete, (_observation(root_source, root=True), _observation(nested_source, root=False))


def _write_policy(root: Path, *, memory_workspace: str | None) -> object:
    registry = root / "_registry"
    registry.mkdir(mode=0o700)
    memory_line = "" if memory_workspace is None else f"    memory_workspace: {memory_workspace}\n"
    source = (
        "schema_version: 1\n"
        f"root: {root}\n"
        f"registry_root: {registry}\n"
        f"inbox: {root}/inbox\n"
        f"memory_workspaces: {root}/memory/workspaces.yml\n"
        "workstreams:\n"
        "  - id: alpha\n"
        "    lifecycle: active\n"
        f"    project_home: {root}/projects/alpha\n"
        "    aliases: []\n"
        f"{memory_line}"
        "never_touch: []\n"
        "categories: []\n"
    )
    placement_map = registry / "placement-map.yml"
    placement_map.write_text(source, encoding="utf-8")
    placement_map.chmod(0o600)
    compiled, _source_sha256 = workstream_curation._read_compiled_policy(root)
    return compiled


def _observed_file(
    root: Path,
    relative_path: str,
    *,
    observation_id: str,
) -> _ObservedFile:
    path = root / relative_path
    raw = path.read_bytes()
    info = path.stat()
    digest = _sha256(raw)
    return _ObservedFile(
        observation_id=observation_id,
        relative_path=relative_path,
        device=info.st_dev,
        inode=info.st_ino,
        owner=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
        link_count=info.st_nlink,
        size=info.st_size,
        modified_time_ns=info.st_mtime_ns,
        content_sha256=digest,
        snapshot_sha256=_sha256((relative_path + digest).encode("utf-8")),
    )


def _configured_parent(
    temporary: str,
    *,
    excluded_history: bool = False,
) -> tuple[
    Path,
    Path,
    canonical_curation.ContextBoundCurationPlan,
    context_assembly.CompleteContextAssembly,
    tuple[canonical_curation.SourceObservation, ...],
]:
    root = Path(temporary) / "raw"
    (root / "projects/alpha/notes").mkdir(parents=True)
    for directory in (root, root / "projects", root / "projects/alpha", root / "projects/alpha/notes"):
        directory.chmod(0o700)
    (root / "projects/alpha/README.md").write_text("# Root\n\nroot text\n", encoding="utf-8")
    (root / "projects/alpha/notes/nested.md").write_text(
        "# Nested\n\ndistinctive nested evidence\n",
        encoding="utf-8",
    )
    for path in root.rglob("*.md"):
        path.chmod(0o600)
    compiled_policy = _write_policy(root, memory_workspace="alpha")
    workspace = root / "memory/alpha"
    history = workspace / "history"
    history.mkdir(parents=True, mode=0o700)
    workspace.chmod(0o700)
    (workspace / "snapshot.md").write_text(
        "---\nupdated_at: \"2026-07-19T10:00:00Z\"\n---\n"
        "## Workstreams\n- id: alpha\n  path: projects/alpha/README.md\n",
        encoding="utf-8",
    )
    (workspace / "snapshot.md").chmod(0o600)
    if excluded_history:
        (history / "beta.md").write_text(
            "---\nworkstream_id: beta\ncreated_at: \"2026-07-19T09:00:00Z\"\n---\n"
            "beta historical body\n",
            encoding="utf-8",
        )
        (history / "beta.md").chmod(0o600)

    local_observations = (
        context_assembly.ContextLocalObservation(
            observation=_observed_file(
                root,
                "projects/alpha/README.md",
                observation_id="obs-000000000000000000000001",
            ),
            group="PROJECT_ROOT",
        ),
        context_assembly.ContextLocalObservation(
            observation=_observed_file(
                root,
                "projects/alpha/notes/nested.md",
                observation_id="obs-000000000000000000000002",
            ),
            group="OTHER_NESTED",
        ),
    )
    root_info = root.stat()
    project_info = (root / "projects/alpha").stat()
    root_identity = (
        root_info.st_dev,
        root_info.st_ino,
        stat.S_IMODE(root_info.st_mode),
        root_info.st_uid,
    )
    project_identity = (
        project_info.st_dev,
        project_info.st_ino,
        stat.S_IMODE(project_info.st_mode),
        project_info.st_uid,
    )
    assembly = context_assembly.build_context_assembly(
        root=root,
        compiled_workstream=workstream_curation._context_workstream_row(
            root=root,
            compiled_policy=compiled_policy,
            workstream_id="alpha",
        ),
        policy_sha256=compiled_policy.full_hash,
        root_identity=root_identity,
        project_identity=project_identity,
        local_observations=local_observations,
        local_gaps=(),
        excluded_paths=(),
        bounds=context_assembly.ContextAssemblyBounds(),
    )
    complete = assembly.require_complete(
        expected_workstream=assembly.workstream,
        expected_policy_sha256=assembly.policy_sha256,
        expected_root_identity=assembly.root_identity,
        expected_project_identity=assembly.project_identity,
        expected_assembly_sha256=assembly.sha256,
        expected_coverage_sha256=assembly.coverage_sha256,
    )
    current_sources = tuple(
        source for source in assembly.sources if source.mode == "CURRENT_LOCAL"
    )
    observations = tuple(
        _observation(source, root=source.group == "PROJECT_ROOT")
        for source in current_sources
    )
    legacy = canonical_curation.CurationPlan(
        primary_workstream_id="alpha",
        captured_lifecycle="active",
        project_home="projects/alpha",
        project_identity=complete.project_identity,
        root_identity=complete.root_identity,
        policy_sha256=complete.policy_sha256,
        source_observations=observations,
        effects=(),
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
        unchanged_paths=tuple(item.relative_path for item in observations),
        out_of_scope_paths=(),
        coverage=(("inspected_files", 2),),
    )
    plan = canonical_curation.compile_curation_plan(legacy, context_assembly=complete)
    parent = Path(temporary) / "parent"
    parent.mkdir(mode=0o700)
    canonical_curation_review.write_context_bound_review_package(
        parent,
        canonical_curation_review.compile_context_bound_review(
            plan,
            context_assembly=complete,
            rendered_at="2026-07-19T12:34:56Z",
            renderer_id="navigation.test",
        ),
    )
    return root, parent, plan, complete, observations


def _navigation_input(
    plan: canonical_curation.ContextBoundCurationPlan,
    complete: context_assembly.CompleteContextAssembly,
    observations: tuple[canonical_curation.SourceObservation, ...],
) -> tuple[bytes, bytes]:
    proposed = b"# Alpha\n\n## Overview\n\nfrom root\n\n## Evidence\n\nfrom nested\n"
    source_map = canonical_json_bytes(
        {
            "context_assembly_sha256": complete.assembly.sha256,
            "context_coverage_sha256": complete.assembly.coverage_sha256,
            "mappings": [
                {
                    "output_sections": ["Overview"],
                    "source_observation_id": observations[0].observation_id,
                    "source_sections": ["Root"],
                },
                {
                    "output_sections": ["Evidence"],
                    "source_observation_id": observations[1].observation_id,
                    "source_sections": ["Nested"],
                },
            ],
            "output_path": "projects/alpha/README.md",
            "output_role": "overview",
            "parent_plan_sha256": plan.sha256,
            "review_notes": [],
            "schema": "mnemosyne-context-bound-navigation-draft-input-v2",
            "spine": [
                {"output_section": "Overview", "role": role}
                for role in canonical_curation.COMMON_SPINE_ROLES
            ],
            "workstream_id": "alpha",
        }
    )
    return proposed, source_map


class ContextBoundNavigationDraftTest(unittest.TestCase):
    def test_v2_binds_only_v3_parent_and_keeps_root_and_full_context_counts_separate(self):
        self.assertTrue(callable(getattr(navigation_draft, "compile_context_bound_navigation_review", None)))
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            (root / "projects/alpha/notes").mkdir(parents=True)
            for directory in (root, root / "projects", root / "projects/alpha", root / "projects/alpha/notes"):
                os.chmod(directory, 0o700)
            (root / "projects/alpha/README.md").write_text("# Root\n\nroot text\n", encoding="utf-8")
            (root / "projects/alpha/notes/nested.md").write_text("# Nested\n\ndistinctive nested evidence\n", encoding="utf-8")
            for path in root.rglob("*.md"):
                os.chmod(path, 0o600)
            complete, observations = _complete_context(root)
            legacy = canonical_curation.CurationPlan(
                primary_workstream_id="alpha", captured_lifecycle="active", project_home="projects/alpha",
                project_identity=complete.project_identity, root_identity=complete.root_identity,
                policy_sha256=complete.policy_sha256, source_observations=observations, effects=(),
                spine=tuple(canonical_curation.SpineEntry(role=role, current_path=None, current_heading=None, proposed_path=None, proposed_heading=None, status="MISSING") for role in canonical_curation.COMMON_SPINE_ROLES),
                findings=(), unchanged_paths=tuple(item.relative_path for item in observations), out_of_scope_paths=(), coverage=(("inspected_files", 2),),
            )
            plan = canonical_curation.compile_curation_plan(legacy, context_assembly=complete)
            parent = Path(temporary) / "parent"
            parent.mkdir(mode=0o700)
            canonical_curation_review.write_context_bound_review_package(parent, canonical_curation_review.compile_context_bound_review(plan, context_assembly=complete, rendered_at="2026-07-19T12:34:56Z", renderer_id="navigation.test"))
            proposed = b"# Alpha\n\n## Overview\n\nfrom root\n\n## Evidence\n\nfrom nested\n"
            source_map = canonical_json_bytes({
                "context_assembly_sha256": complete.assembly.sha256,
                "context_coverage_sha256": complete.assembly.coverage_sha256,
                "mappings": [
                    {"output_sections": ["Overview"], "source_observation_id": observations[0].observation_id, "source_sections": ["Root"]},
                    {"output_sections": ["Evidence"], "source_observation_id": observations[1].observation_id, "source_sections": ["Nested"]},
                ],
                "output_path": "projects/alpha/README.md", "output_role": "overview", "parent_plan_sha256": plan.sha256,
                "review_notes": [], "schema": "mnemosyne-context-bound-navigation-draft-input-v2",
                "spine": [{"output_section": "Overview", "role": role} for role in canonical_curation.COMMON_SPINE_ROLES],
                "workstream_id": "alpha",
            })
            payload, semantic = navigation_draft.compile_context_bound_navigation_review(
                root=root, parent_review_directory=parent, proposed_document=proposed, source_map=source_map,
                rendered_at="2026-07-19T12:34:56Z", renderer_id="navigation.test",
            )
            self.assertEqual(semantic["context_counts"], {"full_current_local": 2, "historical_hint": 0, "root_navigation": 1, "unverified_external": 0})
            self.assertEqual(semantic["context_assembly_sha256"], complete.assembly.sha256)
            self.assertIn(b"distinctive nested evidence", payload.markdown)
            self.assertIn(b"full current-local context source count", payload.markdown)
            self.assertTrue(callable(getattr(navigation_draft, "validate_context_bound_navigation_review", None)))
            navigation_draft.validate_context_bound_navigation_review(payload)

    def test_v2_rejects_legacy_v2_parent(self):
        # The V2 route must never silently treat historical Review V2 as a complete Context parent.
        with self.assertRaises(navigation_draft.NavigationDraftError):
            navigation_draft.compile_context_bound_navigation_review(
                root=Path("/private/tmp"), parent_review_directory=Path("/private/tmp"), proposed_document=b"x", source_map=b"{}",
                rendered_at="2026-07-19T12:34:56Z", renderer_id="navigation.test",
            )

    def test_v2_write_rejects_new_history_membership_without_publishing_package(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root, parent, plan, complete, observations = _configured_parent(temporary)
            proposed, source_map = _navigation_input(plan, complete, observations)
            payload, _semantic = navigation_draft.compile_context_bound_navigation_review(
                root=root,
                parent_review_directory=parent,
                proposed_document=proposed,
                source_map=source_map,
                rendered_at="2026-07-19T12:34:56Z",
                renderer_id="navigation.test",
            )
            output = Path(temporary) / "navigation"
            output.mkdir(mode=0o700)
            history_entry = root / "memory/alpha/history/new.md"
            history_entry.write_text(
                "---\nworkstream_id: alpha\ncreated_at: \"2026-07-19T13:00:00Z\"\n---\n"
                "path: projects/alpha/notes/nested.md\n",
                encoding="utf-8",
            )
            history_entry.chmod(0o600)

            with self.assertRaises(navigation_draft.NavigationDraftError):
                navigation_draft.write_context_bound_navigation_review(
                    output,
                    payload,
                    root=root,
                    parent_review_directory=parent,
                )

            self.assertEqual(list(output.iterdir()), [])

    def test_v2_write_revalidates_after_bodies_before_meta_seal(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root, parent, plan, complete, observations = _configured_parent(temporary)
            proposed, source_map = _navigation_input(plan, complete, observations)
            payload, _semantic = navigation_draft.compile_context_bound_navigation_review(
                root=root,
                parent_review_directory=parent,
                proposed_document=proposed,
                source_map=source_map,
                rendered_at="2026-07-19T12:34:56Z",
                renderer_id="navigation.test",
            )
            output = Path(temporary) / "navigation"
            output.mkdir(mode=0o700)
            nested = root / "projects/alpha/notes/nested.md"
            real_write = review_package.write_validated_review_package

            def drift_after_bodies(
                directory,
                candidate,
                *,
                validate,
                before_final_seal=None,
            ):
                self.assertIsNotNone(before_final_seal)

                def inject_drift_then_revalidate():
                    nested.write_text(
                        "# Nested\n\nchanged after navigation bodies\n",
                        encoding="utf-8",
                    )
                    nested.chmod(0o600)
                    before_final_seal()

                return real_write(
                    directory,
                    candidate,
                    validate=validate,
                    before_final_seal=inject_drift_then_revalidate,
                )

            with mock.patch.object(
                navigation_draft.review_package,
                "write_validated_review_package",
                side_effect=drift_after_bodies,
            ):
                with self.assertRaises(navigation_draft.NavigationDraftError):
                    navigation_draft.write_context_bound_navigation_review(
                        output,
                        payload,
                        root=root,
                        parent_review_directory=parent,
                    )

            self.assertEqual(list(output.iterdir()), [])

    def test_v2_write_rejects_excluded_history_content_drift_before_seal(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root, parent, plan, complete, observations = _configured_parent(
                temporary,
                excluded_history=True,
            )
            proposed, source_map = _navigation_input(plan, complete, observations)
            payload, _semantic = navigation_draft.compile_context_bound_navigation_review(
                root=root,
                parent_review_directory=parent,
                proposed_document=proposed,
                source_map=source_map,
                rendered_at="2026-07-19T12:34:56Z",
                renderer_id="navigation.test",
            )
            output = Path(temporary) / "navigation"
            output.mkdir(mode=0o700)
            excluded = root / "memory/alpha/history/beta.md"
            excluded.write_text(
                "---\nworkstream_id: beta\ncreated_at: \"2026-07-19T09:00:00Z\"\n---\n"
                "zeta historical body\n",
                encoding="utf-8",
            )
            excluded.chmod(0o600)

            with self.assertRaises(navigation_draft.NavigationDraftError):
                navigation_draft.write_context_bound_navigation_review(
                    output,
                    payload,
                    root=root,
                    parent_review_directory=parent,
                )

            self.assertEqual(list(output.iterdir()), [])

    def test_v2_write_rejects_resealed_parent_with_same_plan_and_context(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root, parent, plan, complete, observations = _configured_parent(temporary)
            proposed, source_map = _navigation_input(plan, complete, observations)
            payload, semantic = navigation_draft.compile_context_bound_navigation_review(
                root=root,
                parent_review_directory=parent,
                proposed_document=proposed,
                source_map=source_map,
                rendered_at="2026-07-19T12:34:56Z",
                renderer_id="navigation.test",
            )
            original_parent_hashes = dict(semantic["parent_review_hashes"])
            for artifact in parent.iterdir():
                artifact.unlink()
            canonical_curation_review.write_context_bound_review_package(
                parent,
                canonical_curation_review.compile_context_bound_review(
                    plan,
                    context_assembly=complete,
                    rendered_at="2026-07-19T12:35:57Z",
                    renderer_id="navigation.test",
                ),
            )
            current_hashes, _plan, _assembly = (
                canonical_curation_review.validate_context_bound_review_directory(parent)
            )
            self.assertNotEqual(
                current_hashes.meta_sha256,
                original_parent_hashes["meta_sha256"],
            )
            output = Path(temporary) / "navigation"
            output.mkdir(mode=0o700)

            with self.assertRaises(navigation_draft.NavigationDraftError):
                navigation_draft.write_context_bound_navigation_review(
                    output,
                    payload,
                    root=root,
                    parent_review_directory=parent,
                )

            self.assertEqual(list(output.iterdir()), [])
