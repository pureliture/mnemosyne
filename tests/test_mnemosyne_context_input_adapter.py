import hashlib
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import canonical_curation, context_assembly, workstream_curation


def _observation(
    source_id: str,
    relative_path: str,
    *,
    owner_kind: str = "workstream",
) -> canonical_curation.SourceObservation:
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()
    return canonical_curation.SourceObservation(
        observation_id=source_id,
        relative_path=relative_path,
        owner_kind=owner_kind,
        owner_id="alpha" if owner_kind == "workstream" else "unassigned",
        lifecycle="active" if owner_kind == "workstream" else "unassigned",
        document_role="work_results",
        classification="EXACT",
        classification_evidence=("test-evidence",),
        content_summary="Safe summary",
        device=1,
        inode=int(digest[:8], 16) + 1,
        owner=501,
        mode=0o600,
        link_count=1,
        size=12,
        modified_time_ns=1,
        content_sha256=digest,
        snapshot_sha256="a" * 64,
    )


def _row(relative_path: str, reason_code: str):
    return workstream_curation._ContextInspectionRow(
        relative_path=relative_path,
        reason_code=reason_code,
    )


class ContextInspectionInputAdapterTest(unittest.TestCase):
    def test_preserves_all_observations_with_exact_group_mapping_and_dedupes(self):
        root = _observation("obs-root", "projects/alpha/README.md")
        meeting = _observation("obs-meeting", "projects/alpha/meetings/2026-07-19.md")
        external = _observation(
            "obs-inbox", "inbox/alpha-brief.md", owner_kind="unassigned"
        )
        bundle = workstream_curation._ContextInspectionEvidence(
            observations=(meeting, root, root, external),
            internal_uncertain=(),
            internal_excluded=(),
            external_uncertain=(),
            external_excluded=(),
        )

        result = workstream_curation._context_input_from_inspection_evidence(
            project_home="projects/alpha",
            evidence=bundle,
            source_groups={
                "obs-root": "PROJECT_ROOT",
                "obs-meeting": "MEETING",
                "obs-inbox": "ALLOWLISTED_EXTERNAL_LOCAL",
            },
        )

        self.assertEqual(
            tuple(item.observation.observation_id for item in result.local_observations),
            ("obs-inbox", "obs-root", "obs-meeting"),
        )
        self.assertEqual(
            tuple(item.group for item in result.local_observations),
            ("ALLOWLISTED_EXTERNAL_LOCAL", "PROJECT_ROOT", "MEETING"),
        )
        self.assertEqual(result.local_gaps, ())
        self.assertEqual(result.excluded_paths, ())

    def test_internal_human_source_changed_becomes_deterministic_unreadable_gap(self):
        bundle = workstream_curation._ContextInspectionEvidence(
            observations=(),
            internal_uncertain=(
                _row("projects/alpha/docs/decision.md", "SOURCE_CHANGED"),
            ),
            internal_excluded=(),
            external_uncertain=(),
            external_excluded=(),
        )

        result = workstream_curation._context_input_from_inspection_evidence(
            project_home="projects/alpha",
            evidence=bundle,
            source_groups={},
        )

        self.assertEqual(len(result.local_gaps), 1)
        gap = result.local_gaps[0]
        self.assertEqual(gap.kind, "UNREADABLE")
        self.assertEqual(gap.group, "OTHER_NESTED")
        self.assertEqual(gap.reason_code, "SOURCE_CHANGED")
        self.assertEqual(gap.relative_path, "projects/alpha/docs/decision.md")
        self.assertEqual(result.excluded_paths, ())

    def test_opaque_and_explicit_generated_or_policy_exclusions_are_nonblocking(self):
        bundle = workstream_curation._ContextInspectionEvidence(
            observations=(),
            internal_uncertain=(
                _row("projects/alpha/data.bin", "CONTENT_OPAQUE"),
            ),
            internal_excluded=(
                _row("projects/alpha/render-out/index.md", "GENERATED"),
                _row("projects/alpha/private/brief.md", "POLICY_EXCLUDED"),
            ),
            external_uncertain=(),
            external_excluded=(),
        )

        result = workstream_curation._context_input_from_inspection_evidence(
            project_home="projects/alpha",
            evidence=bundle,
            source_groups={},
        )

        self.assertEqual(result.local_gaps, ())
        self.assertEqual(
            result.excluded_paths,
            (
                "projects/alpha/data.bin",
                "projects/alpha/private/brief.md",
                "projects/alpha/render-out/index.md",
            ),
        )

    def test_external_inbox_uncertain_and_excluded_paths_stay_nonblocking_without_ownership(self):
        bundle = workstream_curation._ContextInspectionEvidence(
            observations=(),
            internal_uncertain=(),
            internal_excluded=(),
            external_uncertain=(
                _row("inbox/unrelated.bin", "SOURCE_UNSUPPORTED"),
            ),
            external_excluded=(
                _row("inbox/other-workstream.md", "SCOPE_UNSAFE"),
            ),
        )

        result = workstream_curation._context_input_from_inspection_evidence(
            project_home="projects/alpha",
            evidence=bundle,
            source_groups={},
        )

        self.assertEqual(result.local_gaps, ())
        self.assertEqual(
            result.excluded_paths,
            ("inbox/other-workstream.md", "inbox/unrelated.bin"),
        )

    def test_local_unsafe_scan_reason_fails_closed(self):
        bundle = workstream_curation._ContextInspectionEvidence(
            observations=(),
            internal_uncertain=(),
            internal_excluded=(
                _row("projects/alpha/private.md", "SCOPE_UNSAFE"),
            ),
            external_uncertain=(),
            external_excluded=(),
        )

        with self.assertRaises(context_assembly.ContextAssemblyError) as raised:
            workstream_curation._context_input_from_inspection_evidence(
                project_home="projects/alpha",
                evidence=bundle,
                source_groups={},
            )

        self.assertEqual(raised.exception.reason_code, "CONTEXT_BLOCKED_UNSAFE")

    def test_mapping_must_cover_exactly_the_observed_source_ids(self):
        observation = _observation("obs-root", "projects/alpha/README.md")
        bundle = workstream_curation._ContextInspectionEvidence(
            observations=(observation,),
            internal_uncertain=(),
            internal_excluded=(),
            external_uncertain=(),
            external_excluded=(),
        )

        with self.assertRaises(context_assembly.ContextAssemblyError):
            workstream_curation._context_input_from_inspection_evidence(
                project_home="projects/alpha",
                evidence=bundle,
                source_groups={"unexpected": "PROJECT_ROOT"},
            )


if __name__ == "__main__":
    unittest.main()
