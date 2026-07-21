import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    canonical_curation,
    canonical_curation_review,
    navigation_draft,
    policy,
    workstream_curation,
)
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402
from mnemosyne_core.cli import guide  # noqa: E402


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _observation(root: Path, index: int, relative_path: str) -> canonical_curation.SourceObservation:
    path = root / relative_path
    raw = path.read_bytes()
    info = path.stat()
    return canonical_curation.SourceObservation(
        observation_id=f"obs-{index:024d}",
        relative_path=relative_path,
        owner_kind="workstream",
        owner_id="example-project-workstream",
        lifecycle="active",
        document_role="overview" if path.name == "README.md" else "current_state",
        classification="EXACT",
        classification_evidence=(
            "active-project-home",
            "artifact-family:canonical-navigation-candidate",
        ),
        content_summary=path.stem,
        device=info.st_dev,
        inode=info.st_ino,
        owner=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
        link_count=info.st_nlink,
        size=info.st_size,
        modified_time_ns=info.st_mtime_ns,
        content_sha256=_sha256(raw),
        snapshot_sha256=_sha256((relative_path + "\n" + _sha256(raw)).encode()),
    )


def _spine() -> tuple[canonical_curation.SpineEntry, ...]:
    paths = {
        "overview": ("projects/example-project/README.md", "Example Project"),
        "current_state": ("projects/example-project/status.md", "Current"),
    }
    return tuple(
        canonical_curation.SpineEntry(
            role=role,
            current_path=paths.get(role, (None, None))[0],
            current_heading=paths.get(role, (None, None))[1],
            proposed_path=paths.get(role, (None, None))[0],
            proposed_heading=paths.get(role, (None, None))[1],
            status="PRESENT" if role in paths else "MISSING",
        )
        for role in canonical_curation.COMMON_SPINE_ROLES
    )


def _tree_fingerprint(root: Path) -> tuple[tuple[object, ...], ...]:
    result = []
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        result.append(
            (
                "." if path == root else path.relative_to(root).as_posix(),
                stat.S_IMODE(info.st_mode),
                info.st_size,
                _sha256(path.read_bytes()) if path.is_file() else None,
            )
        )
    return tuple(result)


class NavigationDraftPublicTest(unittest.TestCase):
    def test_public_parser_routes_navigation_draft_inputs_through_guide(self) -> None:
        args = mnemosyne.build_parser().parse_args(
            [
                "curation",
                "guide",
                "--draft",
                "navigation",
                "--review-package",
                "/private/tmp/parent-review",
                "--proposed-document-file",
                "/private/tmp/proposed.md",
                "--source-map-file",
                "/private/tmp/source-map.json",
                "--output-directory",
                "/private/tmp/navigation-review",
            ]
        )

        self.assertEqual("navigation", args.draft)
        self.assertEqual("/private/tmp/parent-review", args.review_package)
        self.assertEqual("/private/tmp/proposed.md", args.proposed_document_file)
        self.assertEqual("/private/tmp/source-map.json", args.source_map_file)
        self.assertEqual("/private/tmp/navigation-review", args.output_directory)
        self.assertIs(args.func, mnemosyne.command_curation_guide)

    def test_guide_writes_review_only_and_leaves_every_source_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            base = Path(temporary)
            root = base / "raw"
            project = root / "projects" / "example-project"
            project.mkdir(parents=True)
            os.chmod(root, 0o700)
            os.chmod(root / "projects", 0o700)
            os.chmod(project, 0o700)
            registry_directory = root / "_registry"
            registry_directory.mkdir(mode=0o700)
            registry_raw = (
                "schema_version: 1\n"
                f"root: {root}\n"
                f"registry_root: {root}/_registry\n"
                f"inbox: {root}/inbox\n"
                f"memory_workspaces: {root}/memory/workspaces.yml\n"
                "workstreams:\n"
                "  - id: example-project-workstream\n"
                "    lifecycle: active\n"
                f"    project_home: {project}\n"
                "    aliases:\n"
                "      - Example Project\n"
                "never_touch:\n"
                "  - worktrees/\n"
                "categories: []\n"
            ).encode()
            registry_file = registry_directory / "placement-map.yml"
            registry_file.write_bytes(registry_raw)
            os.chmod(registry_file, 0o600)
            changed_registry_raw = registry_raw.replace(
                b"never_touch:\n  - worktrees/\n",
                b"never_touch:\n  - worktrees/\n  - graphify-out/\n",
            )
            parsed_policy = policy.parse_strict_yaml(registry_raw)
            effective_policy = (
                registry_raw
                if "curation" in parsed_policy
                else policy.build_additive_curation_postimage(registry_raw, str(root))
            )
            compiled_policy = policy.compile_policy(effective_policy, str(root))
            self.assertEqual(
                compiled_policy.full_hash,
                workstream_curation.read_current_policy_sha256(root),
            )
            readme = project / "README.md"
            status_doc = project / "status.md"
            readme.write_text("# Example Project\n\nOld entry.\n", encoding="utf-8")
            status_doc.write_text("# Current\n\nPilot is bounded.\n", encoding="utf-8")
            os.chmod(readme, 0o600)
            os.chmod(status_doc, 0o600)
            observations = (
                _observation(root, 1, "projects/example-project/README.md"),
                _observation(root, 2, "projects/example-project/status.md"),
            )
            project_info = project.stat()
            root_info = root.stat()
            plan = canonical_curation.CurationPlan(
                primary_workstream_id="example-project-workstream",
                captured_lifecycle="active",
                project_home="projects/example-project",
                project_identity=(
                    project_info.st_dev,
                    project_info.st_ino,
                    stat.S_IMODE(project_info.st_mode),
                    project_info.st_uid,
                ),
                root_identity=(
                    root_info.st_dev,
                    root_info.st_ino,
                    stat.S_IMODE(root_info.st_mode),
                    root_info.st_uid,
                ),
                policy_sha256=compiled_policy.full_hash,
                source_observations=observations,
                effects=(),
                spine=_spine(),
                findings=(),
                unchanged_paths=tuple(item.relative_path for item in observations),
                out_of_scope_paths=(),
                coverage=(("truncated", False),),
            )
            parent_package = base / "parent-review"
            parent_package.mkdir(mode=0o700)
            canonical_curation_review.write_review_package(
                parent_package,
                canonical_curation_review.compile_review(
                    plan,
                    rendered_at="2026-07-19T00:00:00Z",
                    renderer_id="navigation-test",
                ),
            )

            proposed_raw = (
                b"# Example Project Mobile Upsell Pilot\n\n"
                b"## Project Overview\n\nBounded pilot orientation.\n\n"
                b"## Current State\n\nPilot is bounded.\n\n"
                b"## Decisions\n\nNo invented decision.\n\n"
                b"## Work Results\n\nSource work remains linked.\n\n"
                b"## References\n\nSee the exact source map.\n"
            )
            proposed_file = base / "proposed-readme.md"
            proposed_file.write_bytes(proposed_raw)
            os.chmod(proposed_file, 0o600)
            mapping_file = base / "source-map.json"
            mapping_file.write_bytes(
                canonical_json_bytes(
                    {
                        "mappings": [
                            {
                                "output_sections": ["Project Overview"],
                                "source_observation_id": observations[0].observation_id,
                                "source_sections": ["Example Project"],
                            },
                            {
                                "output_sections": ["Current State"],
                                "source_observation_id": observations[1].observation_id,
                                "source_sections": ["Current"],
                            },
                        ],
                        "output_path": "projects/example-project/README.md",
                        "output_role": "overview",
                        "parent_plan_sha256": plan.sha256,
                        "review_notes": ["Current runtime state still requires live verification."],
                        "schema": "mnemosyne-navigation-draft-input-v1",
                        "spine": [
                            {"output_section": "Project Overview", "role": "overview"},
                            {"output_section": "Current State", "role": "current_state"},
                            {"output_section": "Decisions", "role": "decisions"},
                            {"output_section": "Work Results", "role": "work_results"},
                            {"output_section": "References", "role": "references"},
                        ],
                        "workstream_id": "example-project-workstream",
                    }
                )
            )
            os.chmod(mapping_file, 0o600)
            output_directory = base / "navigation-review"
            output_directory.mkdir(mode=0o700)
            before = _tree_fingerprint(root)

            payload, _semantic = navigation_draft.compile_navigation_review(
                root=root,
                parent_review_directory=parent_package,
                proposed_document=proposed_raw,
                source_map=mapping_file.read_bytes(),
                rendered_at="2026-07-19T00:00:00Z",
                renderer_id="navigation-test",
            )
            registry_file.write_bytes(changed_registry_raw)
            seal_drift_output = base / "seal-drift-review"
            seal_drift_output.mkdir(mode=0o700)
            with self.assertRaises(navigation_draft.NavigationDraftError):
                navigation_draft.write_navigation_review(
                    seal_drift_output,
                    payload,
                    root=root,
                )
            self.assertEqual((), tuple(seal_drift_output.iterdir()))
            registry_file.write_bytes(registry_raw)
            os.chmod(registry_file, 0o600)

            post_seal_drift_output = base / "post-seal-drift-review"
            post_seal_drift_output.mkdir(mode=0o700)
            write_package = navigation_draft.review_package.write_validated_review_package

            def write_then_change_policy(*args, **kwargs):
                hashes = write_package(*args, **kwargs)
                registry_file.write_bytes(changed_registry_raw)
                os.chmod(registry_file, 0o600)
                return hashes

            with mock.patch.object(
                navigation_draft.review_package,
                "write_validated_review_package",
                side_effect=write_then_change_policy,
            ):
                with self.assertRaises(navigation_draft.NavigationDraftError):
                    navigation_draft.write_navigation_review(
                        post_seal_drift_output,
                        payload,
                        root=root,
                    )
            self.assertEqual((), tuple(post_seal_drift_output.iterdir()))
            registry_file.write_bytes(registry_raw)
            os.chmod(registry_file, 0o600)

            exit_code, rendered, is_error = guide.guide_request(
                root=str(root),
                actor="local-operator",
                draft="navigation",
                view="scope",
                max_items=None,
                offset=0,
                navigation_review_package=str(parent_package),
                navigation_proposed_document_file=str(proposed_file),
                navigation_source_map_file=str(mapping_file),
                navigation_output_directory=str(output_directory),
                stdin_isatty=True,
                stdout_isatty=True,
            )

            self.assertEqual(0, exit_code, rendered)
            self.assertFalse(is_error)
            self.assertIn("적용되지 않았습니다", rendered)
            self.assertNotIn("curation dispatch", rendered)
            self.assertEqual(before, _tree_fingerprint(root))
            self.assertEqual(
                ("review.html", "review.md", "review.meta.json"),
                tuple(sorted(path.name for path in output_directory.iterdir())),
            )
            review_markdown = (output_directory / "review.md").read_bytes()
            self.assertIn(proposed_raw, review_markdown)
            self.assertIn(b"projects/example-project/status.md", review_markdown)
            self.assertIn(b"DRAFT_ONLY_NO_CORPUS_WRITE", review_markdown)
            self.assertIn("원문 2개".encode(), review_markdown)
            self.assertNotIn("원문 12개".encode(), review_markdown)

            bad_map_value = json.loads(mapping_file.read_bytes())
            bad_map_value["mappings"][0]["source_sections"] = ["Invented source heading"]
            bad_map_file = base / "bad-source-map.json"
            bad_map_file.write_bytes(canonical_json_bytes(bad_map_value))
            os.chmod(bad_map_file, 0o600)
            bad_map_output = base / "bad-map-review"
            bad_map_output.mkdir(mode=0o700)

            bad_map_code, bad_map_rendered, bad_map_is_error = guide.guide_request(
                root=str(root),
                actor="local-operator",
                draft="navigation",
                view="scope",
                max_items=None,
                offset=0,
                navigation_review_package=str(parent_package),
                navigation_proposed_document_file=str(proposed_file),
                navigation_source_map_file=str(bad_map_file),
                navigation_output_directory=str(bad_map_output),
                stdin_isatty=True,
                stdout_isatty=True,
            )

            self.assertEqual(2, bad_map_code, bad_map_rendered)
            self.assertTrue(bad_map_is_error)
            self.assertEqual((), tuple(bad_map_output.iterdir()))

            registry_file.write_bytes(changed_registry_raw)
            os.chmod(registry_file, 0o600)
            stale_output = base / "stale-navigation-review"
            stale_output.mkdir(mode=0o700)
            readme_before = readme.read_bytes()
            status_before = status_doc.read_bytes()

            stale_code, stale_rendered, stale_is_error = guide.guide_request(
                root=str(root),
                actor="local-operator",
                draft="navigation",
                view="scope",
                max_items=None,
                offset=0,
                navigation_review_package=str(parent_package),
                navigation_proposed_document_file=str(proposed_file),
                navigation_source_map_file=str(mapping_file),
                navigation_output_directory=str(stale_output),
                stdin_isatty=True,
                stdout_isatty=True,
            )

            self.assertEqual(2, stale_code, stale_rendered)
            self.assertTrue(stale_is_error)
            self.assertEqual((), tuple(stale_output.iterdir()))
            self.assertEqual(readme_before, readme.read_bytes())
            self.assertEqual(status_before, status_doc.read_bytes())


if __name__ == "__main__":
    unittest.main()
