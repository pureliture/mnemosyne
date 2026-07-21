import copy
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import librarian_inspection, operation_contract  # noqa: E402
from mnemosyne_core.cli import inspect as inspect_cli  # noqa: E402


def _result() -> dict:
    return {
        "schema_version": 2,
        "view": "scope",
        "inspection_mode": "frozen-coverage",
        "workstream": {
            "id": "example-completed-workstream",
            "lifecycle": "completed",
            "project_home": "projects/example-completed-workstream",
            "identity_status": "verified",
        },
        "bounds": {
            "max_items": 4,
            "max_depth": 2,
            "max_hint_bytes": 1024,
        },
        "current_scope": {"status": "verified"},
        "usage": {
            "items_used": 2,
            "max_depth_reached": 1,
            "metadata_bytes_used": 128,
            "drift_returned": 1,
        },
        "frozen_coverage": {
            "directories": [
                {
                    "path": "projects/example-completed-workstream",
                    "direct_file_count": 1,
                    "direct_other_count": 0,
                    "descendant_unknown_count": 0,
                    "errors": [],
                },
                {
                    "path": "projects/example-completed-workstream/docs",
                    "direct_file_count": 2,
                    "direct_other_count": 1,
                    "descendant_unknown_count": 0,
                    "errors": [],
                },
            ],
            "directory_count": 2,
            "file_count": 3,
            "other_count": 1,
            "unreadable_count": 0,
            "unsafe_count": 0,
            "unknown_descendant_count": 0,
            "hint_bytes_used": 0,
        },
        "excluded": [],
        "drift": [
            {
                "source_id": "auxiliary-snapshot",
                "field": "updated_at",
                "reason_code": "AUXILIARY_FRESHNESS_MISSING",
                "authority_value": "projects/example-completed-workstream",
                "observed_value": None,
                "requires_manual_review": True,
            }
        ],
        "candidates": [],
        "returned": 3,
        "truncated": False,
    }


def _outcome(result: dict) -> operation_contract.OperationOutcome:
    return operation_contract.OperationOutcome.completed("a" * 64, result=result)


class FrozenScopeResultValidatorTest(unittest.TestCase):
    def test_accepts_exact_frozen_schema_v2(self) -> None:
        librarian_inspection.validate_scope_result(_outcome(_result()))

        librarian_inspection.validate_scope_result(
            operation_contract.OperationOutcome.blocked(
                "a" * 64,
                reason_code="SCOPE_UNSAFE",
                next_safe_action="inspect",
            )
        )

    def test_rejects_candidates_leaks_and_inconsistent_accounting(self) -> None:
        cases = []
        candidate = copy.deepcopy(_result())
        candidate["candidates"] = [{"relative_path": "private.md"}]
        cases.append(candidate)
        leak = copy.deepcopy(_result())
        leak["frozen_coverage"]["directories"][0]["fingerprint"] = "secret"
        cases.append(leak)
        wrong_total = copy.deepcopy(_result())
        wrong_total["frozen_coverage"]["file_count"] = 99
        cases.append(wrong_total)
        wrong_returned = copy.deepcopy(_result())
        wrong_returned["returned"] = 99
        cases.append(wrong_returned)
        filename_field = copy.deepcopy(_result())
        filename_field["drift"][0]["field"] = "private-file-name.md"
        cases.append(filename_field)
        for result in cases:
            with self.subTest(result=result):
                with self.assertRaises(ValueError):
                    librarian_inspection.validate_scope_result(_outcome(result))

    def test_human_renderer_explains_frozen_inspection_without_internal_codes(self) -> None:
        text = inspect_cli._human_text("scope", _outcome(_result()).canonical_bytes)

        self.assertIn("example-completed-workstream", text)
        self.assertIn("완료", text)
        self.assertIn("projects/example-completed-workstream", text)
        self.assertIn("디렉터리: 2개", text)
        self.assertIn("파일: 3개", text)
        self.assertIn("파일 내용은 읽지 않았습니다", text)
        self.assertIn("이동 후보를 만들지 않았습니다", text)
        self.assertIn("사람 확인 필요: 1건", text)
        self.assertNotIn("AUXILIARY_FRESHNESS_MISSING", text)

    def test_rejects_paths_outside_project_home_and_unbounded_usage(self) -> None:
        outside = copy.deepcopy(_result())
        outside["frozen_coverage"]["directories"][1]["path"] = "projects/other/docs"
        excessive_items = copy.deepcopy(_result())
        excessive_items["usage"]["items_used"] = 5
        excessive_metadata = copy.deepcopy(_result())
        excessive_metadata["usage"]["metadata_bytes_used"] = 8193
        for result in (outside, excessive_items, excessive_metadata):
            with self.subTest(result=result):
                with self.assertRaises(ValueError):
                    librarian_inspection.validate_scope_result(_outcome(result))


if __name__ == "__main__":
    unittest.main()
