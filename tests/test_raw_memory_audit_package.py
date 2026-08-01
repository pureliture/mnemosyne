import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPOSITORY_ROOT / "scripts" / "raw_memory_sync_install.py"
SYNC_PACKAGE = REPOSITORY_ROOT / "raw_memory_sync"
AUDIT_PACKAGE = REPOSITORY_ROOT / "raw_memory_audit"


class RawMemoryAuditPackageTest(unittest.TestCase):
    def run_installer(self, home_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(INSTALLER), "--home-root", str(home_root), *arguments],
            cwd=REPOSITORY_ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            check=False,
        )

    def test_installs_exact_audit_projections_alongside_sync_and_unrelated_config(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            home_root = Path(temporary_directory) / "isolated-home"
            config = home_root / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text(
                "\n".join(
                    [
                        'model = "fixture"',
                        '[agents."raw_memory_audit"]',
                        'description = "legacy raw-memory-audit agent"',
                        '[agents."unrelated"]',
                        'description = "must survive"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            installed = self.run_installer(home_root)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            checked = self.run_installer(home_root, "--check")
            self.assertEqual(checked.returncode, 0, checked.stderr)

            audit_skill = (AUDIT_PACKAGE / "SKILL.md").read_text(encoding="utf-8")
            audit_agent = (AUDIT_PACKAGE / "agent.md").read_text(encoding="utf-8")
            sync_skill = (SYNC_PACKAGE / "SKILL.md").read_text(encoding="utf-8")
            expected_audit_agent = (AUDIT_PACKAGE / "adapters" / "codex-agent.toml.template").read_text(
                encoding="utf-8"
            ).replace("{{AGENT_INSTRUCTIONS}}", audit_agent)
            expected_audit_claude_agent = (
                AUDIT_PACKAGE / "adapters" / "claude-agent.md.template"
            ).read_text(encoding="utf-8").replace("{{AGENT_INSTRUCTIONS}}", audit_agent)

            self.assertEqual(
                (home_root / ".codex" / "skills" / "raw-memory-audit" / "SKILL.md").read_text(
                    encoding="utf-8"
                ),
                audit_skill,
            )
            self.assertEqual(
                (home_root / ".codex" / "agents" / "raw_memory_audit.toml").read_text(
                    encoding="utf-8"
                ),
                expected_audit_agent,
            )
            self.assertEqual(
                (home_root / ".claude" / "skills" / "raw-memory-audit" / "SKILL.md").read_text(
                    encoding="utf-8"
                ),
                audit_skill,
            )
            self.assertEqual(
                (home_root / ".claude" / "agents" / "raw-memory-audit.md").read_text(
                    encoding="utf-8"
                ),
                expected_audit_claude_agent,
            )
            self.assertEqual(
                (home_root / ".hermes" / "skills" / "raw-memory-audit" / "SKILL.md").read_text(
                    encoding="utf-8"
                ),
                audit_skill,
            )
            self.assertEqual(
                (home_root / ".codex" / "skills" / "raw-memory-sync" / "SKILL.md").read_text(
                    encoding="utf-8"
                ),
                sync_skill,
            )

            rendered_config = config.read_text(encoding="utf-8")
            self.assertIn('model = "fixture"', rendered_config)
            self.assertEqual(rendered_config.count('[agents."raw_memory_sync"]'), 1)
            self.assertEqual(rendered_config.count('[agents."raw_memory_audit"]'), 1)
            self.assertIn('[agents."unrelated"]', rendered_config)
            self.assertIn('description = "must survive"', rendered_config)

    def test_check_reports_stale_audit_projection(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            home_root = Path(temporary_directory) / "isolated-home"
            installed = self.run_installer(home_root)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            stale_path = home_root / ".hermes" / "skills" / "raw-memory-audit" / "SKILL.md"
            stale_path.write_text("stale\n", encoding="utf-8")

            checked = self.run_installer(home_root, "--check")
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("stale projection:", checked.stderr)
            self.assertIn(
                ".hermes/skills/raw-memory-audit/SKILL.md",
                checked.stderr,
            )
            self.assertEqual(stale_path.read_text(encoding="utf-8"), "stale\n")

    def test_rejects_ambiguous_audit_legacy_registration_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            home_root = Path(temporary_directory) / "isolated-home"
            config = home_root / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            original = (
                '[agents."raw_memory_audit"]\n'
                'description = "legacy one"\n'
                '[agents."raw_memory_audit"]\n'
                'description = "legacy two"\n'
            )
            config.write_text(original, encoding="utf-8")

            installed = self.run_installer(home_root)

            self.assertEqual(installed.returncode, 2)
            self.assertIn("ambiguous", installed.stderr)
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertFalse((home_root / ".codex" / "agents" / "raw_memory_audit.toml").exists())

    def test_rejects_malformed_audit_legacy_registration_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            home_root = Path(temporary_directory) / "isolated-home"
            config = home_root / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            original = '[agents."raw_memory_audit" malformed]\nvalue = "unsafe"\n'
            config.write_text(original, encoding="utf-8")

            installed = self.run_installer(home_root)

            self.assertEqual(installed.returncode, 2)
            self.assertIn("malformed", installed.stderr)
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertFalse((home_root / ".codex" / "agents" / "raw_memory_audit.toml").exists())


if __name__ == "__main__":
    unittest.main()
