import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core.authority_runtime import (  # noqa: E402
    WorkstreamInspectionFence,
)
from mnemosyne_core.authority_runtime import workstream_inspection  # noqa: E402


def _compiled_policy(*workstreams: object) -> object:
    return SimpleNamespace(workstreams=workstreams)


def _workstream(
    *,
    identifier: str,
    lifecycle: str,
    project_home: Path,
    aliases: tuple[str, ...] = (),
) -> object:
    return SimpleNamespace(
        id=identifier,
        lifecycle=lifecycle,
        project_home=str(project_home),
        aliases=aliases,
    )


class WorkstreamResolutionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.project_home = self.root / "projects" / "example-completed-workstream"
        self.project_home.mkdir(parents=True, mode=0o700)
        self.policy = _compiled_policy(
            _workstream(
                identifier="example-completed-workstream",
                lifecycle="completed",
                project_home=self.project_home,
                aliases=("Invest Analyst",),
            )
        )

    def test_exact_id_and_casefolded_alias_resolve_to_the_same_row(self) -> None:
        by_id = workstream_inspection.resolve_workstream_for_inspection(
            self.policy,
            "example-completed-workstream",
        )
        by_alias = workstream_inspection.resolve_workstream_for_inspection(
            self.policy,
            "INVEST ANALYST",
        )

        self.assertEqual(by_id, by_alias)
        self.assertEqual(by_id.canonical_id, "example-completed-workstream")
        self.assertEqual(by_id.lifecycle, "completed")
        self.assertEqual(by_id.project_home, self.project_home)

    def test_prefix_unknown_and_ambiguous_references_fail_typed(self) -> None:
        cases = (
            (self.policy, "invest-analyst", "WORKSTREAM_NOT_FOUND"),
            (self.policy, "missing", "WORKSTREAM_NOT_FOUND"),
            (
                _compiled_policy(
                    *self.policy.workstreams,
                    _workstream(
                        identifier="other-stream",
                        lifecycle="active",
                        project_home=self.root / "other-stream",
                        aliases=("Invest Analyst",),
                    ),
                ),
                "invest analyst",
                "WORKSTREAM_AMBIGUOUS",
            ),
        )
        for policy, reference, reason_code in cases:
            with self.subTest(reference=reference), self.assertRaises(
                WorkstreamInspectionFence
            ) as raised:
                workstream_inspection.resolve_workstream_for_inspection(
                    policy,
                    reference,
                )
            self.assertEqual(raised.exception.reason_code, reason_code)

    def test_unsupported_lifecycle_and_outside_root_fail_typed(self) -> None:
        unsupported = _compiled_policy(
            _workstream(
                identifier="example-completed-workstream",
                lifecycle="archived",
                project_home=self.project_home,
            )
        )
        with self.assertRaises(WorkstreamInspectionFence) as lifecycle_error:
            workstream_inspection.resolve_workstream_for_inspection(
                unsupported,
                "example-completed-workstream",
            )
        self.assertEqual(
            lifecycle_error.exception.reason_code,
            "WORKSTREAM_LIFECYCLE_UNSUPPORTED",
        )

        outside = _compiled_policy(
            _workstream(
                identifier="example-completed-workstream",
                lifecycle="active",
                project_home=self.root.parent,
            )
        )
        resolved = workstream_inspection.resolve_workstream_for_inspection(
            outside,
            "example-completed-workstream",
        )
        with self.assertRaises(WorkstreamInspectionFence) as home_error:
            workstream_inspection.capture_inspection_evidence(self.root, resolved)
        self.assertEqual(home_error.exception.reason_code, "WORKSTREAM_HOME_UNSAFE")


class WorkstreamPhysicalIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.projects = self.root / "projects"
        self.project_home = self.projects / "active-stream"
        self.project_home.mkdir(parents=True, mode=0o700)
        self.policy = _compiled_policy(
            _workstream(
                identifier="active-stream",
                lifecycle="active",
                project_home=self.project_home,
                aliases=("active",),
            )
        )

    def test_capture_and_revalidation_detect_project_directory_replacement(self) -> None:
        resolved = workstream_inspection.resolve_workstream_for_inspection(
            self.policy,
            "ACTIVE",
        )
        evidence = workstream_inspection.capture_inspection_evidence(
            self.root,
            resolved,
        )

        self.assertEqual(evidence.canonical_id, "active-stream")
        self.assertEqual(evidence.captured_lifecycle, "active")
        self.assertEqual(
            evidence.project_home_relative,
            ("projects", "active-stream"),
        )
        workstream_inspection.revalidate_inspection_evidence(
            self.policy,
            self.root,
            "active",
            evidence,
        )

        replaced = self.projects / "replaced"
        self.project_home.rename(replaced)
        self.project_home.mkdir(mode=0o700)
        with self.assertRaises(WorkstreamInspectionFence) as raised:
            workstream_inspection.revalidate_inspection_evidence(
                self.policy,
                self.root,
                "active",
                evidence,
            )
        self.assertEqual(raised.exception.reason_code, "WORKSTREAM_HOME_CHANGED")

    def test_revalidation_detects_selected_policy_row_drift(self) -> None:
        resolved = workstream_inspection.resolve_workstream_for_inspection(
            self.policy,
            "active",
        )
        evidence = workstream_inspection.capture_inspection_evidence(
            self.root,
            resolved,
        )
        changed_policy = _compiled_policy(
            _workstream(
                identifier="active-stream",
                lifecycle="paused",
                project_home=self.project_home,
                aliases=("active",),
            )
        )

        with self.assertRaises(WorkstreamInspectionFence) as raised:
            workstream_inspection.revalidate_inspection_evidence(
                changed_policy,
                self.root,
                "active",
                evidence,
            )

        self.assertEqual(raised.exception.reason_code, "POLICY_CHANGED")

    def test_symlink_and_group_writable_component_are_unsafe(self) -> None:
        target = self.root / "target"
        target.mkdir(mode=0o700)
        linked = self.projects / "linked-stream"
        linked.symlink_to(target, target_is_directory=True)
        symlink_policy = _compiled_policy(
            _workstream(
                identifier="linked-stream",
                lifecycle="paused",
                project_home=linked,
            )
        )
        resolved = workstream_inspection.resolve_workstream_for_inspection(
            symlink_policy,
            "linked-stream",
        )
        with self.assertRaises(WorkstreamInspectionFence) as symlink_error:
            workstream_inspection.capture_inspection_evidence(self.root, resolved)
        self.assertEqual(
            symlink_error.exception.reason_code,
            "WORKSTREAM_HOME_UNSAFE",
        )

        self.projects.chmod(0o770)
        resolved = workstream_inspection.resolve_workstream_for_inspection(
            self.policy,
            "active-stream",
        )
        with self.assertRaises(WorkstreamInspectionFence) as mode_error:
            workstream_inspection.capture_inspection_evidence(self.root, resolved)
        self.assertEqual(mode_error.exception.reason_code, "WORKSTREAM_HOME_UNSAFE")


if __name__ == "__main__":
    unittest.main()
