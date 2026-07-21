import stat
import sys
import unittest
from pathlib import Path
from types import MappingProxyType


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import inventory  # noqa: E402
from mnemosyne_core.authority_runtime import (  # noqa: E402
    WorkstreamInspectionEvidence,
    WorkstreamInspectionFence,
    WorkstreamProjectIdentity,
)
from mnemosyne_core.authority_runtime import workstream_inspection  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


PROJECT_HOME = ("projects", "example-completed-workstream")


def _evidence(lifecycle: str = "completed") -> WorkstreamInspectionEvidence:
    return WorkstreamInspectionEvidence(
        canonical_id="example-completed-workstream",
        captured_lifecycle=lifecycle,
        project_home_relative=PROJECT_HOME,
        project_identity=WorkstreamProjectIdentity(
            device=11,
            inode=22,
            mode=0o700,
            uid=33,
        ),
    )


def _bounds(*, max_items: int = 16, max_depth: int = 8) -> MappingProxyType:
    return MappingProxyType(
        {
            "max_items": max_items,
            "max_depth": max_depth,
            "max_hint_bytes": 1_048_576,
        }
    )


def _directory(
    display_path: str,
    *,
    direct_files: int = 0,
    direct_other: int = 0,
    descendant_unknown: int = 0,
    errors: tuple[str, ...] = (),
) -> inventory.Observation:
    sensitive_raw_path = (
        "raw-b64-v1:cHJpdmF0ZS1maWxlLW5hbWUubWQ/" + display_path
    )
    return inventory.Observation(
        run_id="frozen-projection-001",
        path=sensitive_raw_path,
        display_path=display_path,
        kind="directory",
        physical_kind="directory",
        scope_class="coverage-only",
        scope_rule_id="paused-completed",
        traversal="directory-count-only",
        content_inspected=False,
        excluded_reason=None,
        identity=inventory.FileIdentity(
            device=101,
            inode=202,
            mode=stat.S_IFDIR | 0o700,
            size=303,
            mtime_ns=404,
        ),
        fingerprint_kind="direct-entry-manifest",
        fingerprint_value="private-fingerprint-value",
        errors=errors,
        descendant_unknown=descendant_unknown,
        direct_file_count=direct_files,
        direct_other_count=direct_other,
    )


def _file_observation() -> inventory.Observation:
    return inventory.Observation(
        run_id="frozen-projection-001",
        path="raw-b64-v1:cHJpdmF0ZS1maWxlLW5hbWUubWQ",
        display_path="private-file-name.md",
        kind="file",
        physical_kind="file",
        scope_class="coverage-only",
        scope_rule_id="paused-completed",
        traversal="metadata-only",
        content_inspected=False,
        excluded_reason=None,
        identity=None,
        fingerprint_kind="none",
        fingerprint_value=None,
    )


def _coverage(
    observations: tuple[inventory.Observation, ...],
) -> MappingProxyType:
    file_count = sum(row.direct_file_count for row in observations)
    other_count = sum(row.direct_other_count for row in observations)
    unknown_count = sum(row.descendant_unknown for row in observations)
    return MappingProxyType(
        {
            "schema_version": 1,
            "state": "complete" if unknown_count == 0 else "explained-partial",
            "folders": {"denominator": len(observations)},
            "files": {
                "denominator": file_count,
                "content_inspected": 0,
                "metadata_only": file_count,
            },
            "other_items": {
                "denominator": other_count,
                "aggregated": other_count,
            },
            "descendant_unknown": unknown_count,
            "content_bytes_attempted": 0,
            "partial_reasons": {},
            "prework_eligible": False,
            "openable": False,
            "approval_ready": False,
        }
    )


def _inventory_result(
    *observations: inventory.Observation,
) -> inventory.InventoryResult:
    rows = tuple(observations)
    return inventory.InventoryResult(
        run_id="frozen-projection-001",
        observations=rows,
        coverage=_coverage(rows),
    )


def _drift_finding(
    reason_code: str,
    *,
    field: str,
    observed_value: str | None,
) -> MappingProxyType:
    return MappingProxyType(
        {
            "source_id": "auxiliary-snapshot",
            "field": field,
            "reason_code": reason_code,
            "authority_value": "projects/example-completed-workstream",
            "observed_value": observed_value,
            "requires_manual_review": True,
        }
    )


def _drift_evidence(
    findings: tuple[MappingProxyType, ...] = (),
    *,
    metadata_bytes_used: int = 0,
    truncated: bool = False,
) -> MappingProxyType:
    return MappingProxyType(
        {
            "findings": findings,
            "metadata_bytes_used": metadata_bytes_used,
            "truncated": truncated,
        }
    )


class FrozenProjectionFirewallTest(unittest.TestCase):
    def test_projects_exact_filename_free_schema_with_prefixed_sorted_directories(
        self,
    ) -> None:
        inventory_result = _inventory_result(
            _directory("zeta", direct_other=1),
            _directory(".", direct_files=2, direct_other=1),
            _directory("alpha/nested", direct_files=4, direct_other=2),
            _directory("alpha", direct_files=1),
        )
        drift = (
            _drift_finding(
                "AUXILIARY_FRESHNESS_MISSING",
                field="updated_at",
                observed_value=None,
            ),
            _drift_finding(
                "AUXILIARY_ROOT_MISMATCH",
                field="workspace.root",
                observed_value="projects/old-invest-agent",
            ),
        )

        projected = workstream_inspection.build_frozen_scope_result(
            inventory_result,
            _evidence(),
            _bounds(),
            _drift_evidence(drift, metadata_bytes_used=512),
        )

        expected_directories = [
            {
                "path": "projects/example-completed-workstream",
                "direct_file_count": 2,
                "direct_other_count": 1,
                "descendant_unknown_count": 0,
                "errors": [],
            },
            {
                "path": "projects/example-completed-workstream/alpha",
                "direct_file_count": 1,
                "direct_other_count": 0,
                "descendant_unknown_count": 0,
                "errors": [],
            },
            {
                "path": "projects/example-completed-workstream/alpha/nested",
                "direct_file_count": 4,
                "direct_other_count": 2,
                "descendant_unknown_count": 0,
                "errors": [],
            },
            {
                "path": "projects/example-completed-workstream/zeta",
                "direct_file_count": 0,
                "direct_other_count": 1,
                "descendant_unknown_count": 0,
                "errors": [],
            },
        ]
        self.assertEqual(
            projected,
            {
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
                    "max_items": 16,
                    "max_depth": 8,
                    "max_hint_bytes": 1_048_576,
                },
                "current_scope": {"status": "verified"},
                "usage": {
                    "items_used": 4,
                    "max_depth_reached": 2,
                    "metadata_bytes_used": 512,
                    "drift_returned": 2,
                },
                "frozen_coverage": {
                    "directories": expected_directories,
                    "directory_count": 4,
                    "file_count": 7,
                    "other_count": 4,
                    "unreadable_count": 0,
                    "unsafe_count": 0,
                    "unknown_descendant_count": 0,
                    "hint_bytes_used": 0,
                },
                "excluded": [],
                "drift": [dict(row) for row in drift],
                "candidates": [],
                "returned": 6,
                "truncated": False,
            },
        )

        canonical = canonical_json_bytes(projected)
        for forbidden in (
            b"private-file-name.md",
            b"private-fingerprint-value",
            b'"stat":',
            b'"identity":',
            b'"fingerprint":',
            b'"display_path":',
            b'"run_id":',
            b'"physical_kind":',
            b'"scope_class":',
            b'"reference_projection":',
            b'"classification_projection":',
            b'"filename":',
            b'"file_path":',
            b'"hint":',
            b'"candidate":',
            b'"approval":',
            b'"placement":',
            b'"destination":',
            b'"proposal":',
            b'"content":',
            b'"size":',
            b'"mtime_ns":',
        ):
            self.assertNotIn(forbidden, canonical)
        self.assertEqual(projected["candidates"], [])

    def test_caps_drift_and_accounts_returned_rows_as_truncated(self) -> None:
        inventory_result = _inventory_result(
            _directory("."),
            _directory("child", direct_files=3),
        )
        findings = tuple(
            _drift_finding(
                "AUXILIARY_ROOT_MISMATCH",
                field=f"workspace.root.{index:02d}",
                observed_value=f"projects/stale-{index:02d}",
            )
            for index in range(10)
        )

        projected = workstream_inspection.build_frozen_scope_result(
            inventory_result,
            _evidence("paused"),
            _bounds(max_items=2, max_depth=1),
            _drift_evidence(findings, metadata_bytes_used=8192),
        )

        self.assertEqual(projected["usage"]["items_used"], 2)
        self.assertEqual(projected["usage"]["max_depth_reached"], 1)
        self.assertEqual(projected["usage"]["metadata_bytes_used"], 8192)
        self.assertEqual(projected["usage"]["drift_returned"], 8)
        self.assertEqual(projected["drift"], [dict(row) for row in findings[:8]])
        self.assertEqual(projected["returned"], 10)
        self.assertLessEqual(projected["returned"], 2 + 8 + 8)
        self.assertTrue(projected["truncated"])

    def test_file_content_or_content_fingerprint_observation_fails_closed(
        self,
    ) -> None:
        content_observation = inventory.Observation(
            **{
                **_directory("content-bearing").__dict__,
                "content_inspected": True,
                "schema_version": 1,
            }
        )
        fingerprint_observation = inventory.Observation(
            **{
                **_directory("fingerprint-bearing").__dict__,
                "fingerprint_kind": "sha256",
                "fingerprint_value": "private-content-sha256",
            }
        )
        cases = (
            ("file-observation", _file_observation()),
            ("content-observation", content_observation),
            ("content-fingerprint", fingerprint_observation),
        )
        for label, unexpected in cases:
            with self.subTest(label=label):
                with self.assertRaises(WorkstreamInspectionFence) as raised:
                    workstream_inspection.build_frozen_scope_result(
                        _inventory_result(_directory("."), unexpected),
                        _evidence(),
                        _bounds(),
                        _drift_evidence(),
                    )
                self.assertEqual(raised.exception.reason_code, "SCOPE_UNSAFE")


if __name__ == "__main__":
    unittest.main()
