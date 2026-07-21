import ast
import re
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = PACKAGE_ROOT / "scripts" / "mnemosyne_core"
CANONICAL_SKILL = PACKAGE_ROOT / "SKILL.md"


class SafeLibrarianSl4BoundaryTest(unittest.TestCase):
    def test_canonical_skill_documents_only_the_current_three_command_flow(
        self,
    ) -> None:
        text = CANONICAL_SKILL.read_text(encoding="utf-8")

        for command in (
            "curation inspect",
            "curation guide",
            "curation dispatch",
        ):
            self.assertIn(command, text)
        command_names = re.findall(r"\bcuration\s+([a-z][a-z-]*)", text)
        self.assertTrue(command_names)
        self.assertEqual(
            set(command_names),
            {"inspect", "guide", "dispatch"},
        )
        for retired_or_separate in (
            "propose-place",
            "list-pending",
            "list-history",
            "memory-sync",
            "raw-memory-sync",
            "Graphify",
            "OKF",
            "inspect.status",
            "inspect.recovery",
            "inspect.audit",
            "inspect.capabilities",
            "movement.placement",
            "FastAPI",
            "SQLAlchemy",
            "Alembic",
            "M0",
            "M1",
            "M2",
            "M3",
            "M4",
            "M5",
            "M6",
        ):
            self.assertNotIn(retired_or_separate, text)

    def test_canonical_skill_uses_guide_instead_of_a_second_json_template(
        self,
    ) -> None:
        text = CANONICAL_SKILL.read_text(encoding="utf-8")

        self.assertIn("TTY-only", text)
        self.assertIn("draft-only", text)
        self.assertIn("exact request", text)
        self.assertIn("owner-only", text)
        self.assertNotIn("```json", text)
        self.assertNotIn('"operation_kind"', text)
        self.assertNotIn('"approval_artifact"', text)
        self.assertNotIn('"prerequisite_artifacts"', text)

    def test_canonical_skill_requires_exact_human_consent(self) -> None:
        text = CANONICAL_SKILL.read_text(encoding="utf-8")

        for required_rule in (
            "Treat vague organization requests as inspect-only.",
            "proposal id, source, target, and consequence",
            "When more than one proposal is visible, require the proposal id.",
            "Corrections require a new proposal",
            "Rejection never moves the source.",
            "Approval records the decision but does not move the source.",
            "canonical package source; it does not activate the installed Skill",
        ):
            self.assertIn(required_rule, text)

    def test_canonical_skill_teaches_workstream_first_lifecycle_inspection(
        self,
    ) -> None:
        text = " ".join(CANONICAL_SKILL.read_text(encoding="utf-8").split())

        for required_rule in (
            "Choose one exact Workstream before inspecting.",
            "Do not ask the human to choose a folder or session.",
            "The placement map is the authority for lifecycle and project home.",
            "curation inspect scope --workstream <id-or-alias>",
            "Active Workstream",
            "Paused or completed Workstream",
            "count-only frozen coverage",
            "does not read file contents",
            "does not return file names, hints, or move candidates",
            "Auxiliary snapshot metadata is drift evidence only.",
            "never changes the authoritative lifecycle or project home",
            "stop after reporting frozen coverage and drift",
        ):
            self.assertIn(required_rule, text)

        self.assertNotIn("--relative-path", text)

    def test_safe_librarian_modules_have_no_forbidden_imports(self) -> None:
        relative_paths = (
            "librarian_contract.py",
            "librarian_inspection.py",
            "librarian_projection.py",
            "librarian_records.py",
            "librarian_placement.py",
            "authority_runtime/librarian.py",
            "authority_runtime/librarian_snapshot.py",
            "cli/canonical_file.py",
            "cli/request_builder.py",
            "cli/guide.py",
            "cli/dispatch.py",
            "cli/inspect.py",
        )
        forbidden = (
            "legacy",
            "inventory",
            "review",
            "campaign",
            "batch",
            "deferral",
            "memory",
            "graphify",
            "fastapi",
            "sqlalchemy",
            "alembic",
            "policy_state",
            "policy_authority",
            "schema_migration",
            "curation_harness",
            "curation_registry",
        )

        for relative_path in relative_paths:
            source_path = CORE_ROOT / relative_path
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            imported = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.extend(alias.name.lower() for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module is not None:
                        imported.append(node.module.lower())
                    else:
                        imported.extend(alias.name.lower() for alias in node.names)
            with self.subTest(relative_path=relative_path):
                self.assertFalse(
                    [
                        name
                        for name in imported
                        if any(token in name for token in forbidden)
                    ],
                    imported,
                )


if __name__ == "__main__":
    unittest.main()
