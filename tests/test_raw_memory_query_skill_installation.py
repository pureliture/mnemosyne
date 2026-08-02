import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPOSITORY_ROOT / "scripts" / "raw_memory_sync_install.py"
LOOKUP_PACKAGE = REPOSITORY_ROOT / "lookup_raw_project_context"
COLLECT_PACKAGE = REPOSITORY_ROOT / "collect_raw_sync_history"


class RawMemoryQuerySkillInstallationTest(unittest.TestCase):
    def run_installer(
        self, home_root: Path, raw_root: Path | None = None, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(INSTALLER), "--home-root", str(home_root)]
        if raw_root is not None:
            command.extend(["--raw-root", str(raw_root)])
        command.extend(arguments)
        return subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            check=False,
        )

    def test_projects_global_lookup_and_explicit_raw_collect_without_registration(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home_root = root / "isolated-home"
            raw_root = root / "raw"
            raw_root.mkdir()
            config = home_root / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            original_config = 'model = "fixture"\n[agents."unrelated"]\nname = "preserve"\n'
            config.write_text(original_config, encoding="utf-8")

            installed = self.run_installer(home_root, raw_root)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            reinstalled = self.run_installer(home_root, raw_root)
            self.assertEqual(reinstalled.returncode, 0, reinstalled.stderr)
            checked = self.run_installer(home_root, raw_root, "--check")
            self.assertEqual(checked.returncode, 0, checked.stderr)

            lookup_target = home_root / ".codex" / "skills" / "lookup-raw-project-context"
            hermes_lookup_target = (
                home_root / ".hermes" / "skills" / "lookup-raw-project-context"
            )
            collect_target = raw_root / ".agents" / "skills" / "collect-raw-sync-history"
            self.assertEqual(
                (lookup_target / "SKILL.md").read_text(encoding="utf-8"),
                (LOOKUP_PACKAGE / "SKILL.md").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (lookup_target / "agents" / "openai.yaml").read_text(encoding="utf-8"),
                (LOOKUP_PACKAGE / "agents" / "openai.yaml").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (hermes_lookup_target / "SKILL.md").read_text(encoding="utf-8"),
                (LOOKUP_PACKAGE / "SKILL.md").read_text(encoding="utf-8"),
            )
            self.assertFalse((hermes_lookup_target / "agents").exists())
            self.assertEqual(
                (collect_target / "SKILL.md").read_text(encoding="utf-8"),
                (COLLECT_PACKAGE / "SKILL.md").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (collect_target / "agents" / "openai.yaml").read_text(encoding="utf-8"),
                (COLLECT_PACKAGE / "agents" / "openai.yaml").read_text(encoding="utf-8"),
            )
            self.assertFalse(
                (home_root / ".codex" / "skills" / "collect-raw-sync-history").exists()
            )
            self.assertFalse(
                (home_root / ".claude" / "skills" / "collect-raw-sync-history").exists()
            )
            self.assertFalse(
                (home_root / ".hermes" / "skills" / "collect-raw-sync-history").exists()
            )
            rendered_config = config.read_text(encoding="utf-8")
            self.assertIn('model = "fixture"', rendered_config)
            self.assertIn('[agents."unrelated"]', rendered_config)
            self.assertIn('name = "preserve"', rendered_config)
            self.assertNotIn("lookup_raw_project_context", rendered_config)
            self.assertNotIn("collect_raw_sync_history", rendered_config)

    def test_omitting_raw_root_skips_collect_projection_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            home_root = Path(temporary_directory) / "isolated-home"

            first = self.run_installer(home_root)
            self.assertEqual(first.returncode, 0, first.stderr)
            lookup = home_root / ".codex" / "skills" / "lookup-raw-project-context" / "SKILL.md"
            first_lookup = lookup.read_text(encoding="utf-8")
            second = self.run_installer(home_root)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(lookup.read_text(encoding="utf-8"), first_lookup)
            self.assertFalse(
                (home_root / ".codex" / "skills" / "collect-raw-sync-history").exists()
            )
            self.assertFalse(
                (home_root / ".hermes" / "skills" / "collect-raw-sync-history").exists()
            )
            self.assertEqual(self.run_installer(home_root, None, "--check").returncode, 0)

    def test_check_reports_stale_and_missing_query_skill_projections(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home_root = root / "isolated-home"
            raw_root = root / "raw"
            raw_root.mkdir()
            installed = self.run_installer(home_root, raw_root)
            self.assertEqual(installed.returncode, 0, installed.stderr)

            lookup_agent = (
                home_root
                / ".codex"
                / "skills"
                / "lookup-raw-project-context"
                / "agents"
                / "openai.yaml"
            )
            lookup_agent.write_text("stale\n", encoding="utf-8")
            hermes_lookup_skill = (
                home_root
                / ".hermes"
                / "skills"
                / "lookup-raw-project-context"
                / "SKILL.md"
            )
            hermes_lookup_skill.unlink()
            collect_skill = (
                raw_root / ".agents" / "skills" / "collect-raw-sync-history" / "SKILL.md"
            )
            collect_skill.unlink()

            checked = self.run_installer(home_root, raw_root, "--check")
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("stale projection:", checked.stderr)
            self.assertIn("lookup-raw-project-context/agents/openai.yaml", checked.stderr)
            self.assertIn("missing projection:", checked.stderr)
            self.assertIn(".hermes/skills/lookup-raw-project-context/SKILL.md", checked.stderr)
            self.assertIn("collect-raw-sync-history/SKILL.md", checked.stderr)
            self.assertEqual(lookup_agent.read_text(encoding="utf-8"), "stale\n")
            self.assertFalse(hermes_lookup_skill.exists())
            self.assertFalse(collect_skill.exists())

    def test_hermes_config_registers_raw_skills_and_preserves_profile_state(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home_root = root / "isolated-home"
            raw_root = root / "raw"
            raw_root.mkdir()
            hermes_root = home_root / ".hermes"
            config = hermes_root / "config.yaml"
            profile_config = hermes_root / "profiles" / "mnemosyne" / "config.yaml"
            config.parent.mkdir(parents=True)
            profile_config.parent.mkdir(parents=True)
            config.write_text(
                "# keep this comment\nmodel: fixture\nskills:\n"
                "  external_dirs:\n    - /existing/default\n",
                encoding="utf-8",
            )
            profile_config.write_text(
                "# profile comment\nmodel: profile-fixture\nskills:\n"
                "  external_dirs:\n    - /existing/profile\n",
                encoding="utf-8",
            )

            installed = self.run_installer(home_root, raw_root)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            first_config = config.read_text(encoding="utf-8")
            first_profile_config = profile_config.read_text(encoding="utf-8")
            self.assertEqual(config.stat().st_mode & 0o777, 0o644)
            self.assertEqual(profile_config.stat().st_mode & 0o777, 0o644)
            self.assertIn("# keep this comment", first_config)
            self.assertIn("model: fixture", first_config)
            self.assertIn("/existing/default", first_config)
            self.assertIn("# profile comment", first_profile_config)
            self.assertIn("model: profile-fixture", first_profile_config)
            self.assertIn("/existing/profile", first_profile_config)
            raw_skills = str((raw_root / ".agents" / "skills").resolve())
            hermes_skills = str((hermes_root / "skills").resolve())
            self.assertEqual(first_config.count(raw_skills), 1)
            self.assertEqual(first_profile_config.count(raw_skills), 1)
            self.assertEqual(first_profile_config.count(hermes_skills), 1)

            reinstalled = self.run_installer(home_root, raw_root)
            self.assertEqual(reinstalled.returncode, 0, reinstalled.stderr)
            self.assertEqual(config.read_text(encoding="utf-8"), first_config)
            self.assertEqual(profile_config.read_text(encoding="utf-8"), first_profile_config)
            checked = self.run_installer(home_root, raw_root, "--check")
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_omitting_raw_root_does_not_create_or_mutate_hermes_config(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home_root = root / "isolated-home"
            hermes_config = home_root / ".hermes" / "config.yaml"

            first = self.run_installer(home_root)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertFalse(hermes_config.exists())

            hermes_config.parent.mkdir(parents=True, exist_ok=True)
            original = "# preserve without raw root\nmodel: fixture\n"
            hermes_config.write_text(original, encoding="utf-8")
            second = self.run_installer(home_root)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(hermes_config.read_text(encoding="utf-8"), original)

    def test_rejects_malformed_hermes_config_before_any_projection_write(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home_root = root / "isolated-home"
            raw_root = root / "raw"
            raw_root.mkdir()
            hermes_config = home_root / ".hermes" / "config.yaml"
            hermes_config.parent.mkdir(parents=True)
            malformed = "skills:\n  external_dirs:\n    - /valid\n   - bad-indent\n"
            hermes_config.write_text(malformed, encoding="utf-8")

            installed = self.run_installer(home_root, raw_root)
            self.assertNotEqual(installed.returncode, 0)
            self.assertIn(str(hermes_config), installed.stderr)
            self.assertEqual(hermes_config.read_text(encoding="utf-8"), malformed)
            self.assertFalse(
                (home_root / ".codex" / "skills" / "lookup-raw-project-context").exists()
            )
            self.assertFalse(
                (raw_root / ".agents" / "skills" / "collect-raw-sync-history").exists()
            )

            checked = self.run_installer(home_root, raw_root, "--check")
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn(str(hermes_config), checked.stderr)
            self.assertEqual(hermes_config.read_text(encoding="utf-8"), malformed)

    def test_rejects_forbidden_user_global_collect_projection_without_rewriting(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home_root = root / "isolated-home"
            raw_root = root / "raw"
            raw_root.mkdir()
            forbidden = (
                home_root
                / ".hermes"
                / "skills"
                / "collect-raw-sync-history"
                / "SKILL.md"
            )
            forbidden.parent.mkdir(parents=True)
            forbidden.write_text("user-owned conflict\n", encoding="utf-8")

            installed = self.run_installer(home_root, raw_root)
            self.assertEqual(installed.returncode, 2)
            self.assertIn("forbidden user-global collect projection", installed.stderr)
            self.assertEqual(forbidden.read_text(encoding="utf-8"), "user-owned conflict\n")
            self.assertFalse(
                (home_root / ".codex" / "skills" / "lookup-raw-project-context").exists()
            )
            self.assertFalse(
                (raw_root / ".agents" / "skills" / "collect-raw-sync-history").exists()
            )

            checked = self.run_installer(home_root, raw_root, "--check")
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("forbidden user-global collect projection", checked.stderr)
            self.assertEqual(forbidden.read_text(encoding="utf-8"), "user-owned conflict\n")

    def test_rejects_duplicate_raw_external_dir_in_default_or_named_profile(self):
        for target in ("default", "profile"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                home_root = root / "isolated-home"
                raw_root = root / "raw"
                raw_root.mkdir()
                raw_skills = str((raw_root / ".agents" / "skills").resolve())
                default_config = home_root / ".hermes" / "config.yaml"
                profile_config = (
                    home_root
                    / ".hermes"
                    / "profiles"
                    / "mnemosyne"
                    / "config.yaml"
                )
                config = default_config if target == "default" else profile_config
                config.parent.mkdir(parents=True)
                duplicate = (
                    "skills:\n"
                    "  external_dirs:\n"
                    f"    - {raw_skills}\n"
                    f"    - {raw_skills}\n"
                )
                config.write_text(duplicate, encoding="utf-8")

                installed = self.run_installer(home_root, raw_root)
                self.assertEqual(installed.returncode, 2)
                self.assertIn("duplicate managed target", installed.stderr)
                self.assertEqual(config.read_text(encoding="utf-8"), duplicate)
                self.assertFalse(
                    (
                        home_root
                        / ".hermes"
                        / "skills"
                        / "lookup-raw-project-context"
                    ).exists()
                )
                self.assertFalse(
                    (
                        raw_root
                        / ".agents"
                        / "skills"
                        / "collect-raw-sync-history"
                    ).exists()
                )

                checked = self.run_installer(home_root, raw_root, "--check")
                self.assertNotEqual(checked.returncode, 0)
                self.assertIn("duplicate managed target", checked.stderr)
                self.assertEqual(config.read_text(encoding="utf-8"), duplicate)

    def test_rejects_raw_external_dir_duplicated_inside_and_outside_managed_block(self):
        for target in ("default", "profile"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                home_root = root / "isolated-home"
                raw_root = root / "raw"
                raw_root.mkdir()
                raw_skills = str((raw_root / ".agents" / "skills").resolve())
                default_config = home_root / ".hermes" / "config.yaml"
                profile_config = (
                    home_root
                    / ".hermes"
                    / "profiles"
                    / "mnemosyne"
                    / "config.yaml"
                )
                config = default_config if target == "default" else profile_config
                config.parent.mkdir(parents=True)
                duplicate = (
                    "skills:\n"
                    "  external_dirs:\n"
                    "    # BEGIN Mnemosyne query skill external dirs\n"
                    f"    - {raw_skills}\n"
                    "    # END Mnemosyne query skill external dirs\n"
                    f"    - {raw_skills}\n"
                )
                config.write_text(duplicate, encoding="utf-8")

                installed = self.run_installer(home_root, raw_root)
                self.assertEqual(installed.returncode, 2)
                self.assertIn("duplicate managed target", installed.stderr)
                self.assertEqual(config.read_text(encoding="utf-8"), duplicate)
                self.assertFalse(
                    (
                        home_root
                        / ".hermes"
                        / "skills"
                        / "lookup-raw-project-context"
                    ).exists()
                )
                self.assertFalse(
                    (
                        raw_root
                        / ".agents"
                        / "skills"
                        / "collect-raw-sync-history"
                    ).exists()
                )

                checked = self.run_installer(home_root, raw_root, "--check")
                self.assertNotEqual(checked.returncode, 0)
                self.assertIn("duplicate managed target", checked.stderr)
                self.assertEqual(config.read_text(encoding="utf-8"), duplicate)

    def test_rejects_unbalanced_hermes_query_skill_markers_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home_root = root / "isolated-home"
            raw_root = root / "raw"
            raw_root.mkdir()
            hermes_config = home_root / ".hermes" / "config.yaml"
            hermes_config.parent.mkdir(parents=True)
            malformed = (
                "skills:\n"
                "  external_dirs:\n"
                "    # BEGIN Mnemosyne query skill external dirs\n"
                "    - /existing/raw-skills\n"
            )
            hermes_config.write_text(malformed, encoding="utf-8")

            installed = self.run_installer(home_root, raw_root)
            self.assertNotEqual(installed.returncode, 0)
            self.assertIn("managed", installed.stderr.lower())
            self.assertEqual(hermes_config.read_text(encoding="utf-8"), malformed)
            self.assertFalse(
                (home_root / ".hermes" / "skills" / "lookup-raw-project-context").exists()
            )
            self.assertFalse(
                (raw_root / ".agents" / "skills" / "collect-raw-sync-history").exists()
            )

            checked = self.run_installer(home_root, raw_root, "--check")
            self.assertNotEqual(checked.returncode, 0)
            self.assertIn("managed", checked.stderr.lower())
            self.assertEqual(hermes_config.read_text(encoding="utf-8"), malformed)

    def test_rejects_missing_raw_root_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home_root = root / "isolated-home"
            missing_raw = root / "missing-raw"

            result = self.run_installer(home_root, missing_raw)

            self.assertEqual(result.returncode, 2)
            self.assertIn("raw-root is not an existing directory", result.stderr)
            self.assertFalse((home_root / ".codex" / "skills").exists())


if __name__ == "__main__":
    unittest.main()
