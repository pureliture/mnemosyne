import contextlib
import hashlib
import io
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
from mnemosyne_core import canonical_curation, canonical_curation_review  # noqa: E402


def _fingerprint_tree(root: Path) -> tuple[tuple[object, ...], ...]:
    rows = []
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else None
        rows.append((relative, stat.S_IMODE(info.st_mode), info.st_size, digest))
    return tuple(rows)


class ContextBoundInspectPublicTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "raw"
        self.root.mkdir(mode=0o700)
        registry = self.root / "_registry"
        registry.mkdir(mode=0o700)
        (registry / "placement-map.yml").write_text(
            "schema_version: 1\n"
            f"root: {self.root}\n"
            f"registry_root: {self.root}/_registry\n"
            f"inbox: {self.root}/inbox\n"
            f"memory_workspaces: {self.root}/memory/workspaces.yml\n"
            "workstreams:\n"
            "  - id: alpha\n"
            "    lifecycle: active\n"
            f"    project_home: {self.root}/projects/alpha\n"
            "    aliases:\n"
            "      - Alpha Project\n"
            "    memory_workspace: alpha\n"
            "never_touch: []\n"
            "categories: []\n",
            encoding="utf-8",
        )
        (registry / "placement-map.yml").chmod(0o600)
        self.project = self.root / "projects" / "alpha"
        (self.project / "decisions").mkdir(parents=True, mode=0o700)
        (self.project / "references").mkdir(mode=0o700)
        (self.project / "README.md").write_text("# Alpha overview\n\nROOT UNIQUE\n", encoding="utf-8")
        (self.project / "loose-decision.md").write_text("# Decision\n\nDECISION UNIQUE\n", encoding="utf-8")
        (self.project / "meetings").mkdir(mode=0o700)
        (self.project / "meetings" / "july.md").write_text("# July meeting\n\nMEETING UNIQUE\n", encoding="utf-8")
        (self.project / "docs" / "research").mkdir(parents=True, mode=0o700)
        (self.project / "docs" / "research" / "source.md").write_text("# Research\n\nRESEARCH UNIQUE\n", encoding="utf-8")
        (self.root / "inbox").mkdir(mode=0o700)
        (self.root / "inbox" / "alpha-evidence.md").write_text("# Evidence\n\nINBOX UNIQUE\n", encoding="utf-8")
        self.workspace = self.root / "memory" / "alpha"
        self.workspace.mkdir(parents=True, mode=0o700)
        (self.workspace / "snapshot.md").write_text(
            "---\nupdated_at: \"2026-07-19T10:00:00Z\"\n---\n"
            "## Workstreams\n- id: alpha\n  path: projects/alpha/README.md\n",
            encoding="utf-8",
        )
        (self.workspace / "snapshot.md").chmod(0o600)
        self.package = self.base / "review"
        self.package.mkdir(mode=0o700)

    def _inspect(
        self,
        *,
        as_json: bool = True,
        max_items: int = 64,
    ) -> tuple[int, dict[str, object] | str]:
        argv = [
            "curation", "inspect", "workstream", "--workstream", "Alpha Project",
            "--root", str(self.root), "--actor", "test-operator", "--max-items", str(max_items),
            "--max-depth", "6", "--max-hint-bytes", "8192", "--review-package", str(self.package),
        ]
        if as_json:
            argv.append("--json")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = mnemosyne.main(argv)
        return exit_code, json.loads(stdout.getvalue()) if as_json else stdout.getvalue()

    def test_missing_history_returns_completed_incomplete_context_without_plan_or_package(self) -> None:
        before = _fingerprint_tree(self.root)

        with mock.patch.object(
            canonical_curation,
            "CurationPlan",
            side_effect=AssertionError("Plan must not exist before the Context gate"),
        ):
            exit_code, outcome = self._inspect()

        self.assertEqual(exit_code, 0)
        self.assertEqual(outcome["outcome_kind"], "completed")
        result = outcome["result"]
        self.assertEqual(result["context"]["outcome"], "INCOMPLETE")
        self.assertEqual(result["context"]["assembly"]["outcome"], "INCOMPLETE")
        self.assertEqual(
            result["context"]["assembly"]["coverage_sha256"],
            result["context"]["coverage_sha256"],
        )
        self.assertTrue(result["context"]["assembly"]["gaps"])
        self.assertNotIn("plan", result)
        self.assertNotIn("review_package", result)
        self.assertEqual(list(self.package.iterdir()), [])
        self.assertEqual(_fingerprint_tree(self.root), before)

        human_exit, human = self._inspect(as_json=False)
        self.assertEqual(human_exit, 0)
        self.assertIn("문맥", human)
        self.assertIn("history", human)
        self.assertIn("다시 검사", human)

    def test_truncated_scan_is_an_incomplete_context_not_a_plan(self) -> None:
        history = self.workspace / "history"
        history.mkdir(mode=0o700)
        (history / "alpha.md").write_text(
            "---\nworkstream_id: alpha\ncreated_at: \"2026-07-19T11:00:00Z\"\n---\n"
            "path: projects/alpha/README.md\n",
            encoding="utf-8",
        )
        (history / "alpha.md").chmod(0o600)
        before = _fingerprint_tree(self.root)

        exit_code, outcome = self._inspect(max_items=1)

        self.assertEqual(exit_code, 0)
        self.assertEqual(outcome["result"]["context"]["outcome"], "INCOMPLETE")
        self.assertNotIn("plan", outcome["result"])
        self.assertEqual(list(self.package.iterdir()), [])
        self.assertEqual(_fingerprint_tree(self.root), before)

    def test_restored_history_seals_context_bound_plan_and_v3_review(self) -> None:
        history = self.workspace / "history"
        history.mkdir(mode=0o700)
        (history / "alpha.md").write_text(
            "---\nworkstream_id: alpha\ncreated_at: \"2026-07-19T11:00:00Z\"\n---\n"
            "path: projects/alpha/meetings/july.md\n",
            encoding="utf-8",
        )
        (history / "alpha.md").chmod(0o600)
        before = _fingerprint_tree(self.root)

        exit_code, outcome = self._inspect()

        self.assertEqual(exit_code, 0)
        result = outcome["result"]
        self.assertEqual(result["context"]["outcome"], "COMPLETE")
        self.assertEqual(result["plan"]["schema"], "mnemosyne-context-bound-curation-plan-v1")
        self.assertEqual(sorted(path.name for path in self.package.iterdir()), ["review.html", "review.md", "review.meta.json"])
        _hashes, _plan, assembly = canonical_curation_review.validate_context_bound_review_directory(
            self.package, expected_plan_sha256=result["plan"]["sha256"]
        )
        self.assertEqual(assembly.outcome, "COMPLETE")
        markdown = (self.package / "review.md").read_text(encoding="utf-8")
        for visible in ("ROOT UNIQUE", "MEETING UNIQUE", "RESEARCH UNIQUE"):
            self.assertIn(visible, markdown)
        self.assertIn("memory/snapshot:alpha".replace("/", ":"), markdown)
        self.assertEqual(_fingerprint_tree(self.root), before)

    def test_memory_drift_before_final_meta_discards_unsealed_bodies(self) -> None:
        history = self.workspace / "history"
        history.mkdir(mode=0o700)
        (history / "alpha.md").write_text(
            "---\nworkstream_id: alpha\ncreated_at: \"2026-07-19T11:00:00Z\"\n---\n"
            "path: projects/alpha/meetings/july.md\n",
            encoding="utf-8",
        )
        (history / "alpha.md").chmod(0o600)
        real_write = canonical_curation_review.write_context_bound_review_package

        def drift_then_write(directory, payload, *, before_final_seal=None):
            (self.workspace / "snapshot.md").write_text(
                "---\nupdated_at: \"2026-07-19T10:00:01Z\"\n---\n"
                "## Workstreams\n- id: alpha\n  path: projects/alpha/README.md\n",
                encoding="utf-8",
            )
            (self.workspace / "snapshot.md").chmod(0o600)
            return real_write(
                directory,
                payload,
                before_final_seal=before_final_seal,
            )

        with mock.patch.object(
            canonical_curation_review,
            "write_context_bound_review_package",
            side_effect=drift_then_write,
        ):
            exit_code, outcome = self._inspect()

        self.assertEqual(exit_code, 2)
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(list(self.package.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
