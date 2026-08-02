from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTROL = REPOSITORY_ROOT / "scripts" / "mnemosyne-control"


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def _directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _fingerprint(root: Path) -> tuple[tuple[object, ...], ...]:
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
                info.st_size,
                content_sha256,
            )
        )
    return tuple(rows)


class RawMemoryQueryCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        temporary = Path(self.temporary.name)
        self.project = _directory(temporary / "project")
        self.raw = _directory(temporary / "raw")
        memory = _directory(self.raw / "memory")
        workspace = _directory(memory / "alpha")
        history = _directory(workspace / "history")
        _write(
            memory / "workspaces.yml",
            "\n".join(
                (
                    "schema_version: 1",
                    "workspaces:",
                    "  alpha:",
                    f"    root: {self.project}",
                    "    confirmed_at: 2026-08-01T00:00:00Z",
                    "    confirmation: fixture",
                    "",
                )
            ),
        )
        _write(
            workspace / "snapshot.md",
            "---\n"
            "schema_version: 1\n"
            "updated_at: 2026-08-02T00:00:00Z\n"
            "source_refs:\n"
            "- fixture: snapshot\n"
            "---\n\n"
            "# Alpha\n\n"
            + "현재 프로젝트 맥락 " * 180
            + "\n",
        )
        _write(
            history / "20260802-alpha.md",
            "---\n"
            "schema_version: 1\n"
            "event_type: snapshot-update\n"
            "workspace: alpha\n"
            f"workspace_root: {self.project}\n"
            "workstream: alpha/core\n"
            "created_at: 2026-08-02T09:00:00Z\n"
            "source_refs:\n"
            "- fixture: session-one\n"
            "---\n\n"
            "# Alpha sync\n\n"
            "## 최신 상태에 반영한 내용\n\n"
            "### 구현\n\n"
            "- 작업 A\n"
            "- 작업 B\n"
            "- 작업 A\n\n"
            "## 이번 기록에 포함하지 않은 내용\n\n"
            "- 제외 작업\n",
        )

    def run_control(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.run_control_exact(*arguments, "--root", str(self.raw))

    def run_control_exact(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CONTROL), *arguments],
            cwd=REPOSITORY_ROOT,
            env={
                **os.environ,
                "MNEMOSYNE_PYTHON": sys.executable,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            capture_output=True,
            check=False,
        )

    def test_context_parent_options_survive_nested_query_parsing(self) -> None:
        collect = self.run_control_exact(
            "context",
            "--root",
            str(self.raw),
            "--json",
            "collect-sync-history",
            "--from-date",
            "2026-08-02",
            "--to-date",
            "2026-08-02",
        )
        self.assertEqual(collect.returncode, 0, collect.stderr)
        self.assertEqual(json.loads(collect.stdout)["status"], "found")

        history = self.raw / "memory" / "alpha" / "history"
        _write(
            history / "20260803-noise.md",
            "---\n"
            "schema_version: 1\n"
            "event_type: snapshot-update\n"
            "workspace: alpha\n"
            f"workspace_root: {self.project}\n"
            "workstream: alpha/noise\n"
            "created_at: 2026-08-03T09:00:00Z\n"
            "source_refs:\n"
            "- fixture: newer-noise\n"
            "---\n\n"
            "# Newer unrelated sync\n\n"
            "## 최신 상태에 반영한 내용\n\n"
            "- 무관한 최신 기록\n",
        )
        lookup = self.run_control_exact(
            "context",
            "--root",
            str(self.raw),
            "--question",
            "작업 B",
            "--history",
            "1",
            "--max-chars",
            "1800",
            "--json",
            "lookup-project-context",
            "--project-root",
            str(self.project),
        )
        self.assertEqual(lookup.returncode, 0, lookup.stderr)
        self.assertLessEqual(len(lookup.stdout.rstrip("\n")), 1800)
        payload = json.loads(lookup.stdout)
        self.assertEqual(payload["status"], "found")
        self.assertEqual(len(payload["history"]), 1)
        self.assertEqual(
            payload["history"][0]["history_path"],
            "memory/alpha/history/20260802-alpha.md",
        )

    def test_collect_public_cli_returns_expanded_read_only_json(self) -> None:
        before = _fingerprint(self.raw)

        completed = self.run_control(
            "context",
            "collect-sync-history",
            "--from-date",
            "2026-08-02",
            "--to-date",
            "2026-08-02",
            "--json",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "found")
        self.assertEqual([item["item"] for item in payload["items"]], ["작업 A", "작업 B"])
        self.assertEqual(payload["items"][0]["workstream"], "alpha/core")
        self.assertEqual(payload["items"][0]["source_refs"], ["fixture: session-one"])
        self.assertNotIn("제외 작업", completed.stdout)
        self.assertEqual(_fingerprint(self.raw), before)

    def test_lookup_public_cli_is_bounded_and_preserves_expected_outcomes(self) -> None:
        found = self.run_control(
            "context",
            "lookup-project-context",
            "--project-root",
            str(self.project),
            "--question",
            "작업 B",
            "--task-context",
            "alpha 구현 확인",
            "--max-chars",
            "1800",
            "--json",
        )
        self.assertEqual(found.returncode, 0, found.stderr)
        self.assertLessEqual(len(found.stdout.rstrip("\n")), 1800)
        found_payload = json.loads(found.stdout)
        self.assertEqual(found_payload["status"], "found")
        self.assertEqual(found_payload["workspace"], "alpha")
        self.assertTrue(found_payload["truncated"])
        self.assertEqual(
            found_payload["history"][0]["history_path"],
            "memory/alpha/history/20260802-alpha.md",
        )

        not_found = self.run_control(
            "context",
            "lookup-project-context",
            "--project-root",
            str(self.project / "other"),
            "--json",
        )
        self.assertEqual(not_found.returncode, 0, not_found.stderr)
        self.assertEqual(json.loads(not_found.stdout)["status"], "not_found")

    def test_invalid_date_is_a_public_cli_error(self) -> None:
        completed = self.run_control(
            "context",
            "collect-sync-history",
            "--from-date",
            "2026-08-03",
            "--to-date",
            "2026-08-02",
            "--json",
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("start_date must not be after end_date", completed.stderr)


if __name__ == "__main__":
    unittest.main()
