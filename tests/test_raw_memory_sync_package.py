import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPOSITORY_ROOT / "tests" / "fixtures" / "raw_memory_sync"
CONTROL = REPOSITORY_ROOT / "scripts" / "mnemosyne-control"
INSTALLER = REPOSITORY_ROOT / "scripts" / "raw_memory_sync_install.py"
PACKAGE = REPOSITORY_ROOT / "raw_memory_sync"


class RawMemorySyncPackageTest(unittest.TestCase):
    def run_control(self, root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["MNEMOSYNE_PYTHON"] = sys.executable
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [str(CONTROL), *arguments, "--root", str(root)],
            cwd=REPOSITORY_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_fixture_flow_binds_receipt_sync_id_to_exact_approved_plan(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            memory = root / "memory"
            workspace = memory / "fixture-service"
            workspace.mkdir(parents=True)
            shutil.copy2(FIXTURE_ROOT / "workspaces.yml", memory / "workspaces.yml")
            shutil.copy2(FIXTURE_ROOT / "snapshot.md", workspace / "snapshot.md")
            plan_path = root / "approved-plan.json"
            review_path = root / "approval-review.json"
            review_path.write_text(
                json.dumps(
                    {
                        "schema": "mnemosyne-workspace-sync-approval-review-v1",
                        "overview": "Fixture source facts and remaining limits are stored separately.",
                        "current_state_groups": [
                            {
                                "title": "Current fixture facts",
                                "items": ["The fixture snapshot is the current local source."],
                            }
                        ],
                        "history_groups": [
                            {
                                "title": "Fixture record",
                                "items": ["The sanitized fixture result is retained in history."],
                            }
                        ],
                        "exclusions": ["Raw command output and credentials"],
                        "references": [
                            {
                                "ref": "fixture: raw-memory-sync",
                                "role": "Fixture source",
                            }
                        ],
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            review_path.chmod(0o600)

            planned = self.run_control(
                root,
                "memory-sync",
                "--workspace",
                "fixture-service",
                "--title",
                "Fixture PLAN applied",
                "--summary",
                "Sanitized fixture result.",
                "--ref",
                "fixture: raw-memory-sync",
                "--workstream",
                "fixture-service",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
            )
            self.assertEqual(planned.returncode, 0, planned.stderr)
            self.assertIn("mode: memory-sync plan", planned.stdout)
            approved_sha256 = next(
                line.partition(":")[2].strip()
                for line in planned.stdout.splitlines()
                if line.startswith("plan_sha256:")
            )
            self.assertEqual(approved_sha256, hashlib.sha256(plan_path.read_bytes()).hexdigest())

            rendered = self.run_control(
                root,
                "memory-sync",
                "--render-approval-card",
                str(plan_path),
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            self.assertTrue(rendered.stdout.startswith("# 승인 요청 — fixture-service\n\n## 한눈에 보기\n"))
            self.assertIn("> - **저장할 요약:** Sanitized fixture result.", rendered.stdout)
            self.assertIn("## 최신 상태에 반영할 내용", rendered.stdout)
            self.assertIn("## 기록으로 남길 내용", rendered.stdout)
            self.assertEqual(
                rendered.stdout.rstrip().splitlines()[-1],
                "이 내용 그대로 적용할까요?",
            )

            applied = self.run_control(
                root,
                "memory-sync",
                "--apply-plan",
                str(plan_path),
                "--expected-plan-sha256",
                approved_sha256,
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertIn("outcome: completed", applied.stdout)
            self.assertIn("snapshot:", applied.stdout)
            self.assertIn("history:", applied.stdout)
            self.assertIn("receipt:", applied.stdout)

            snapshot = memory / "fixture-service" / "snapshot.md"
            history = list((memory / "fixture-service" / "history").glob("*.md"))
            receipt_path = memory / "_receipts" / "workspace-sync" / f"{approved_sha256}.json"
            self.assertTrue(snapshot.is_file())
            self.assertEqual(len(history), 1)
            self.assertTrue(receipt_path.is_file())
            self.assertIn("Sanitized fixture result.", snapshot.read_text(encoding="utf-8"))
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["plan_sha256"], approved_sha256)
            self.assertEqual(receipt["plan_sha256"], hashlib.sha256(plan_path.read_bytes()).hexdigest())

    def test_installed_codex_and_claude_projections_match_canonical_source(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            home_root = Path(temporary_directory) / "isolated-home"
            config = home_root / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text(
                "\n".join(
                    [
                        'model = "fixture"',
                        '[agents."raw_memory_sync"]',
                        'description = "legacy raw-memory-sync agent"',
                        'config_file = "agents/raw_memory_sync.toml"',
                        '[agents."unrelated"]',
                        'description = "must survive"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            installed = subprocess.run(
                [sys.executable, str(INSTALLER), "--home-root", str(home_root), "--install-launcher"],
                cwd=REPOSITORY_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            checked = subprocess.run(
                [sys.executable, str(INSTALLER), "--home-root", str(home_root), "--check", "--install-launcher"],
                cwd=REPOSITORY_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)

            skill = (PACKAGE / "SKILL.md").read_text(encoding="utf-8")
            agent = (PACKAGE / "agent.md").read_text(encoding="utf-8")
            codex_skill = home_root / ".codex" / "skills" / "raw-memory-sync" / "SKILL.md"
            claude_skill = home_root / ".claude" / "skills" / "raw-memory-sync" / "SKILL.md"
            codex_agent = home_root / ".codex" / "agents" / "raw_memory_sync.toml"
            claude_agent = home_root / ".claude" / "agents" / "raw-memory-sync.md"
            self.assertEqual(codex_skill.read_text(encoding="utf-8"), skill)
            self.assertEqual(claude_skill.read_text(encoding="utf-8"), skill)
            self.assertIn(agent, codex_agent.read_text(encoding="utf-8"))
            self.assertIn(agent, claude_agent.read_text(encoding="utf-8"))
            self.assertIn("mnemosyne-control memory-sync --plan-out", codex_agent.read_text(encoding="utf-8"))
            self.assertIn("mnemosyne-control memory-sync --plan-out", claude_agent.read_text(encoding="utf-8"))
            rendered_config = config.read_text(encoding="utf-8")
            self.assertIn("model = \"fixture\"", rendered_config)
            self.assertEqual(rendered_config.count('[agents."raw_memory_sync"]'), 1)
            self.assertIn('[agents."unrelated"]', rendered_config)
            self.assertIn('description = "must survive"', rendered_config)
            launcher = home_root / ".local" / "bin" / "mnemosyne-control"
            self.assertTrue(launcher.is_symlink())
            self.assertEqual(launcher.resolve(), CONTROL.resolve())

    def test_installer_rejects_ambiguous_legacy_registration_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            home_root = Path(temporary_directory) / "isolated-home"
            config = home_root / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            original = "\n".join(
                [
                    '[agents."raw_memory_sync"]',
                    'description = "legacy one"',
                    '[agents."raw_memory_sync"]',
                    'description = "legacy two"',
                    "",
                ]
            )
            config.write_text(original, encoding="utf-8")

            installed = subprocess.run(
                [sys.executable, str(INSTALLER), "--home-root", str(home_root)],
                cwd=REPOSITORY_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(installed.returncode, 2)
            self.assertIn("ambiguous", installed.stderr)
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertFalse((home_root / ".codex" / "agents" / "raw_memory_sync.toml").exists())

    def test_installer_rejects_malformed_legacy_header_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            home_root = Path(temporary_directory) / "isolated-home"
            config = home_root / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            original = '[agents."raw_memory_sync" malformed]\nvalue = "unsafe"\n'
            config.write_text(original, encoding="utf-8")

            installed = subprocess.run(
                [sys.executable, str(INSTALLER), "--home-root", str(home_root)],
                cwd=REPOSITORY_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(installed.returncode, 2)
            self.assertIn("malformed", installed.stderr)
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertFalse((home_root / ".codex" / "agents" / "raw_memory_sync.toml").exists())


if __name__ == "__main__":
    unittest.main()
