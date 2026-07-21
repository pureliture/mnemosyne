"""Characterization coverage for the read-only Context capture seam."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import workstream_curation  # noqa: E402


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
        if stat.S_ISREG(info.st_mode):
            content_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(
            (
                relative,
                stat.S_IFMT(info.st_mode),
                stat.S_IMODE(info.st_mode),
                info.st_uid,
                info.st_nlink,
                info.st_size,
                content_sha256,
            )
        )
    return tuple(rows)


class ContextCaptureSeamTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "raw"
        self.root.mkdir(mode=0o700)
        registry = self.root / "_registry"
        registry.mkdir(mode=0o700)
        placement_map = registry / "placement-map.yml"
        placement_map.write_bytes(
            REGISTRY.replace(b"{root}", str(self.root).encode("utf-8"))
        )
        placement_map.chmod(0o600)

        project = self.root / "projects" / "alpha"
        (project / "decisions").mkdir(parents=True, mode=0o700)
        (project / "references").mkdir(mode=0o700)
        (project / "README.md").write_text("# Alpha\n", encoding="utf-8")
        (project / "loose-decision.md").write_text(
            "# Alpha decision\n", encoding="utf-8"
        )
        inbox = self.root / "inbox"
        inbox.mkdir(mode=0o700)
        (inbox / "alpha-reference.md").write_text(
            "# Alpha reference\n", encoding="utf-8"
        )

    def _capture(self, *, max_items: int):
        compiled_policy, registry_sha256 = workstream_curation._read_compiled_policy(
            self.root
        )
        return workstream_curation._capture_context_curation(
            root=self.root,
            compiled_policy=compiled_policy,
            registry_sha256=registry_sha256,
            workstream_ref="Alpha Project",
            max_items=max_items,
            max_depth=4,
            max_hint_bytes=8192,
        )

    def test_complete_capture_returns_context_capabilities_without_package_write(self):
        before = _fingerprint_tree(self.root)
        with mock.patch.object(
            workstream_curation.canonical_curation_review,
            "write_context_bound_review_package",
            side_effect=AssertionError("capture must not write a Review Package"),
        ):
            captured = self._capture(max_items=32)

        self.assertEqual(captured.workstream_id, "alpha")
        self.assertEqual(captured.project_home, "projects/alpha")
        self.assertEqual(captured.assembly.outcome, "COMPLETE")
        self.assertIsNotNone(captured.complete_context)
        self.assertIsNotNone(captured.context_plan)
        self.assertEqual(
            captured.context_plan.context_binding.assembly_sha256,
            captured.assembly.sha256,
        )
        self.assertEqual(_fingerprint_tree(self.root), before)

    def test_incomplete_capture_exposes_no_plan_capabilities_and_does_not_mutate(self):
        before = _fingerprint_tree(self.root)

        captured = self._capture(max_items=1)

        self.assertNotEqual(captured.assembly.outcome, "COMPLETE")
        self.assertIsNone(captured.complete_context)
        self.assertIsNone(captured.context_plan)
        self.assertEqual(_fingerprint_tree(self.root), before)


if __name__ == "__main__":
    unittest.main()
