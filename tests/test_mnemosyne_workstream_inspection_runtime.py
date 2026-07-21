import json
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
import mnemosyne_core  # noqa: E402
from mnemosyne_core import operation_contract  # noqa: E402
from mnemosyne_core.authority_runtime import session as authority_session  # noqa: E402

TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class WorkstreamInspectionRuntimeTest(LedgerRuntimeFixture):
    def _tree_snapshot(self) -> tuple[tuple[object, ...], ...]:
        rows = []
        for path in sorted(self.root.rglob("*")):
            info = path.lstat()
            payload = None
            if stat.S_ISREG(info.st_mode):
                payload = path.read_bytes()
            elif stat.S_ISLNK(info.st_mode):
                payload = os.readlink(path)
            rows.append(
                (
                    path.relative_to(self.root).as_posix(),
                    stat.S_IMODE(info.st_mode),
                    info.st_uid,
                    info.st_nlink,
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    payload,
                )
            )
        return tuple(rows)

    def _request(self, workstream_ref: str) -> operation_contract.OperationRequest:
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": workstream_ref},
            bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            payload={},
        )

    def _execute(self, workstream_ref: str) -> dict[str, object]:
        request = self._request(workstream_ref)
        return json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                "utf-8"
            )
        )

    def test_unknown_workstream_returns_the_typed_public_fence(self) -> None:
        self.migrate_to_v2()

        outcome = self._execute("security")

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "WORKSTREAM_NOT_FOUND")
        self.assertEqual(outcome["next_safe_action"], "choose-workstream")

    def test_completed_workstream_returns_filename_free_frozen_coverage(self) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        nested = project_home / "nested"
        nested.mkdir(parents=True, mode=0o700)
        root_note = project_home / "private-root-name.md"
        nested_note = nested / "private-nested-name.md"
        root_note.write_text("root secret", encoding="utf-8")
        nested_note.write_text("nested secret", encoding="utf-8")
        before_tree = self._tree_snapshot()

        resolver = authority_session.workstream_inspection.resolve_workstream_for_inspection

        def completed_resolver(compiled_policy: object, workstream_ref: object) -> object:
            resolved = resolver(compiled_policy, workstream_ref)
            return authority_session.workstream_inspection.ResolvedWorkstream(
                canonical_id=resolved.canonical_id,
                lifecycle="completed",
                project_home=resolved.project_home,
            )

        with mock.patch.object(
            authority_session.workstream_inspection,
            "resolve_workstream_for_inspection",
            side_effect=completed_resolver,
        ):
            outcome = self._execute("example-service")

        self.assertEqual(outcome["outcome_kind"], "completed")
        result = outcome["result"]
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["inspection_mode"], "frozen-coverage")
        self.assertEqual(result["workstream"]["lifecycle"], "completed")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(
            [row["path"] for row in result["frozen_coverage"]["directories"]],
            ["example-service", "example-service/nested"],
        )
        self.assertEqual(result["frozen_coverage"]["file_count"], 2)
        self.assertEqual(
            [row["reason_code"] for row in result["drift"]],
            ["AUXILIARY_MISSING"],
        )
        canonical = json.dumps(result, sort_keys=True).encode("utf-8")
        for forbidden in (
            b"private-root-name.md",
            b"private-nested-name.md",
            b"root secret",
            b"nested secret",
            b'"hint"',
            b'"approval"',
            b'"placement"',
            b'"fingerprint"',
        ):
            self.assertNotIn(forbidden, canonical)
        self.assertEqual(self._tree_snapshot(), before_tree)

    def test_unsafe_project_home_returns_the_typed_public_fence(self) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o700)
        project_home.chmod(0o770)

        outcome = self._execute("example-service")

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "WORKSTREAM_HOME_UNSAFE")
        self.assertEqual(outcome["next_safe_action"], "inspect-workstream")

    def test_project_home_replacement_during_scan_discards_the_result(self) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o700)
        (project_home / "README.md").write_text("# Scanner\n", encoding="utf-8")
        displaced = self.root / "example-service-displaced"

        def replace_project_home(**_kwargs: object) -> dict[str, object]:
            project_home.rename(displaced)
            project_home.mkdir(mode=0o700)
            return {
                "schema_version": 1,
                "view": "scope",
                "scope": {"relative_path": "example-service"},
                "bounds": {
                    "max_items": 16,
                    "max_depth": 4,
                    "max_hint_bytes": 4096,
                },
                "workstreams": [],
                "organized": [],
                "candidates": [],
                "excluded": [],
                "uncertain": [],
                "returned": 0,
                "truncated": False,
            }

        with mock.patch.object(
            authority_session.librarian,
            "inspect_scope",
            side_effect=replace_project_home,
        ):
            outcome = self._execute("example-service")

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "WORKSTREAM_HOME_CHANGED")
        self.assertEqual(outcome["next_safe_action"], "inspect-workstream")

    def test_file_disappearing_during_heading_read_is_bounded_source_changed(
        self,
    ) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o700)
        (project_home / "note.md").write_text("# Note\n", encoding="utf-8")

        with mock.patch.object(
            authority_session.librarian,
            "_safe_heading",
            side_effect=FileNotFoundError("simulated file race"),
        ):
            outcome = self._execute("example-service")

        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertEqual(outcome["result"]["organized"], [])
        self.assertEqual(outcome["result"]["candidates"], [])
        self.assertEqual(
            outcome["result"]["uncertain"],
            [
                {
                    "relative_path": "example-service/note.md",
                    "reason_code": "SOURCE_CHANGED",
                }
            ],
        )

    def test_directory_disappearing_before_open_is_bounded_source_changed(
        self,
    ) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        nested = project_home / "nested"
        nested.mkdir(parents=True, mode=0o700)
        original_open = authority_session.librarian._open_directory_at

        def fail_nested(parent_fd: int, name: str) -> int:
            if name == "nested":
                raise FileNotFoundError("simulated directory race")
            return original_open(parent_fd, name)

        with mock.patch.object(
            authority_session.librarian,
            "_open_directory_at",
            side_effect=fail_nested,
        ):
            outcome = self._execute("example-service")

        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertEqual(outcome["result"]["organized"], [])
        self.assertEqual(outcome["result"]["candidates"], [])
        self.assertEqual(
            outcome["result"]["uncertain"],
            [
                {
                    "relative_path": "example-service/nested",
                    "reason_code": "SOURCE_CHANGED",
                }
            ],
        )

    def test_root_device_observation_race_returns_canonical_scope_stop(self) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o700)
        original_stat = authority_session.librarian.os.stat

        def fail_root(path: object, *args: object, **kwargs: object) -> object:
            if path == self.root and kwargs.get("follow_symlinks") is False:
                raise FileNotFoundError("simulated root race")
            return original_stat(path, *args, **kwargs)

        with mock.patch.object(
            authority_session.librarian.os,
            "stat",
            side_effect=fail_root,
        ):
            outcome = self._execute("example-service")

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "SCOPE_UNSAFE")
        self.assertEqual(outcome["next_safe_action"], "inspect")


if __name__ == "__main__":
    unittest.main()
