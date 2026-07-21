import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
import mnemosyne_core  # noqa: E402
from mnemosyne_core import authority_runtime, operation_contract  # noqa: E402
from mnemosyne_core.canonical_json import sha256_bytes  # noqa: E402
from mnemosyne_core import librarian_inspection  # noqa: E402
from mnemosyne_core.operation_control import composition  # noqa: E402
from mnemosyne_core.operation_control import execution  # noqa: E402
from mnemosyne_core.operation_control.catalog import (  # noqa: E402
    OperationAvailability,
)

TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
import test_mnemosyne_ledger_runtime as ledger_fixture_module  # noqa: E402
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class _CapturedStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, value: str) -> int:
        self.buffer.write(value.encode("utf-8"))
        return len(value)

    def flush(self) -> None:
        return None


class SafeLibrarianSl1PublicCliTest(unittest.TestCase):
    def test_inspect_scope_accepts_workstream_and_builds_exact_read_request(self) -> None:
        captured_requests: list[bytes] = []

        def execute_request(raw: bytes) -> bytes:
            captured_requests.append(raw)
            return operation_contract.OperationOutcome.completed(
                sha256_bytes(raw),
                result={"view": "scope"},
            ).canonical_bytes

        stdout = _CapturedStdout()
        with mock.patch.object(sys, "stdout", stdout), mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            side_effect=execute_request,
        ):
            exit_code = mnemosyne.main(
                [
                    "curation",
                    "inspect",
                    "scope",
                    "--root",
                    "/private/tmp/mnemosyne-safe-librarian",
                    "--actor",
                    "operator",
                    "--workstream",
                    "example-completed-workstream",
                    "--max-items",
                    "17",
                    "--max-depth",
                    "3",
                    "--max-hint-bytes",
                    "4096",
                    "--json",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(captured_requests), 1)
        self.assertEqual(
            json.loads(captured_requests[0].decode("utf-8")),
            {
                "action": "INSPECT",
                "actor": "operator",
                "approval_artifact": None,
                "bounds": {
                    "max_depth": 3,
                    "max_hint_bytes": 4096,
                    "max_items": 17,
                },
                "claim_mode": "HISTORICAL",
                "operation_kind": "inspect.scope",
                "payload": {},
                "prerequisite_artifacts": [],
                "requested_authority": "READ",
                "root": "/private/tmp/mnemosyne-safe-librarian",
                "schema_version": 1,
                "scope": {"workstream_ref": "example-completed-workstream"},
            },
        )

    def test_guide_drafts_the_same_workstream_bound_scope_request(self) -> None:
        exit_code, rendered, is_error = mnemosyne._cli_guide_core.guide_request(
            root="/private/tmp/mnemosyne-safe-librarian",
            actor="operator",
            draft="inspect",
            view="scope",
            max_items=17,
            offset=0,
            workstream_ref="example-completed-workstream",
            max_depth=3,
            max_hint_bytes=4096,
            stdin_isatty=True,
            stdout_isatty=True,
        )

        self.assertEqual(exit_code, 0)
        self.assertFalse(is_error)
        request = json.loads(rendered.splitlines()[-1])
        self.assertEqual(request["operation_kind"], "inspect.scope")
        self.assertEqual(
            request["scope"],
            {"workstream_ref": "example-completed-workstream"},
        )
        self.assertNotIn("relative_path", request["scope"])

    def test_catalog_declares_the_bounded_safe_librarian_contracts(self) -> None:
        catalog = composition.DEFAULT_OPERATION_CATALOG
        scope = catalog.require_spec("inspect.scope")

        self.assertIs(scope.availability, OperationAvailability.AVAILABLE)
        self.assertEqual(
            scope.admission_contract.allowed_actions,
            (operation_contract.LifecycleAction.INSPECT,),
        )
        self.assertEqual(
            scope.admission_contract.allowed_claim_modes,
            (operation_contract.ClaimMode.HISTORICAL,),
        )
        self.assertIs(
            scope.admission_contract.authority_mode,
            operation_contract.AuthorityMode.READ,
        )
        self.assertEqual(scope.admission_contract.scope_schema, ("workstream_ref",))
        self.assertEqual(
            scope.admission_contract.bounds_schema,
            ("max_items", "max_depth", "max_hint_bytes"),
        )
        self.assertIs(
            scope.admission_contract.read_profile,
            operation_contract.ReadProfile.SAFE_LIBRARIAN,
        )
        self.assertTrue(callable(scope.handler))
        self.assertTrue(callable(scope.request_validator))
        self.assertTrue(callable(scope.result_validator))

        for kind, scope_schema, bounds_schema, write_profile, availability in (
            (
                "librarian.proposal",
                ("proposal_id", "source_relative_path", "target_relative_path"),
                ("max_entries", "max_depth", "max_total_bytes"),
                operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD,
                OperationAvailability.AVAILABLE,
            ),
            (
                "librarian.decision",
                ("proposal_id",),
                (),
                operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD,
                OperationAvailability.AVAILABLE,
            ),
            (
                "librarian.placement",
                ("proposal_id", "source_relative_path", "target_relative_path"),
                (),
                operation_contract.WriteProfile.SAFE_LIBRARIAN_PLACEMENT,
                OperationAvailability.AVAILABLE,
            ),
        ):
            with self.subTest(kind=kind):
                spec = catalog.require_spec(kind)
                self.assertIs(spec.availability, availability)
                self.assertEqual(
                    spec.admission_contract.allowed_actions,
                    (
                        operation_contract.LifecycleAction.APPLY,
                        operation_contract.LifecycleAction.RECOVER,
                    ),
                )
                self.assertEqual(spec.admission_contract.scope_schema, scope_schema)
                self.assertEqual(spec.admission_contract.bounds_schema, bounds_schema)
                self.assertIs(spec.admission_contract.write_profile, write_profile)
                if availability is OperationAvailability.AVAILABLE:
                    self.assertTrue(callable(spec.handler))
                    self.assertTrue(callable(spec.request_validator))
                    self.assertTrue(callable(spec.result_validator))
                else:
                    self.assertIsNone(spec.handler)

        for kind in ("inspect.pending", "inspect.history"):
            with self.subTest(kind=kind):
                spec = catalog.require_spec(kind)
                self.assertEqual(
                    spec.admission_contract.scope_schema,
                    ("relative_path",),
                )
                self.assertEqual(
                    spec.admission_contract.bounds_schema,
                    ("max_items",),
                )
                self.assertIs(
                    spec.admission_contract.read_profile,
                    operation_contract.ReadProfile.SAFE_LIBRARIAN,
                )

        movement = catalog.require_spec("movement.placement")
        self.assertIs(movement.availability, OperationAvailability.DEFERRED)
        self.assertIsNone(movement.handler)

    def test_inspect_scope_identity_bump_does_not_change_other_spec_identity(
        self,
    ) -> None:
        catalog = composition.DEFAULT_OPERATION_CATALOG

        self.assertEqual(
            {
                "inspect.pending": catalog.require_spec(
                    "inspect.pending"
                ).spec_identity,
                "inspect.scope": catalog.require_spec("inspect.scope").spec_identity,
            },
            {
                "inspect.pending": "d1b-inspect-pending-v1",
                "inspect.scope": "d1b-inspect-scope-v2",
            },
        )

    def test_invalid_scope_contract_stops_before_authority_admission(self) -> None:
        valid = {
            "action": operation_contract.LifecycleAction.INSPECT,
            "claim_mode": operation_contract.ClaimMode.HISTORICAL,
            "requested_authority": operation_contract.AuthorityMode.READ,
            "scope": {"workstream_ref": "example-completed-workstream"},
            "bounds": {
                "max_items": 16,
                "max_depth": 4,
                "max_hint_bytes": 4096,
            },
            "payload": {},
        }
        cases = (
            {"action": operation_contract.LifecycleAction.APPLY},
            {"claim_mode": operation_contract.ClaimMode.CURRENT},
            {"requested_authority": operation_contract.AuthorityMode.NONE},
            {"scope": {"workstream_ref": ""}},
            {"scope": {"workstream_ref": 17}},
            {
                "scope": {
                    "workstream_ref": "example-completed-workstream",
                    "extra": "x",
                }
            },
            {"scope": {"relative_path": "inbox/example"}},
            {"bounds": {"max_items": 0, "max_depth": 4, "max_hint_bytes": 4096}},
            {"bounds": {"max_items": 16, "max_depth": 17, "max_hint_bytes": 4096}},
            {
                "bounds": {
                    "max_items": 16,
                    "max_depth": 4,
                    "max_hint_bytes": 1024 * 1024 + 1,
                }
            },
            {"payload": {"hidden": "instruction"}},
        )
        for replacement in cases:
            fields = {**valid, **replacement}
            request = operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="inspect.scope",
                root="/private/tmp/mnemosyne-safe-librarian-invalid",
                actor="operator",
                **fields,
            )
            with self.subTest(replacement=replacement), mock.patch.object(
                execution.authority_runtime,
                "admit",
                side_effect=AssertionError("invalid request reached admission"),
            ):
                outcome = json.loads(
                    mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                        "utf-8"
                    )
                )
            self.assertEqual(outcome["outcome_kind"], "blocked")
            self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
            self.assertEqual(outcome["next_safe_action"], "correct-request")

    def test_scope_result_validator_rejects_path_or_payload_widening(self) -> None:
        valid = {
            "schema_version": 1,
            "view": "scope",
            "scope": {"relative_path": "inbox"},
            "bounds": {"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            "workstreams": [],
            "organized": [],
            "candidates": [],
            "excluded": [],
            "uncertain": [],
            "returned": 0,
            "truncated": False,
        }
        widened = (
            {
                **valid,
                "workstreams": [
                    {
                        "id": "example",
                        "lifecycle": "active",
                        "project_home": "/absolute/internal/path",
                    }
                ],
            },
            {
                **valid,
                "candidates": [
                    {
                        "relative_path": "inbox/note.md",
                        "entry_type": "file",
                        "size": 10,
                        "hint": "Title",
                        "body": "full document body",
                    }
                ],
                "returned": 1,
            },
            {
                **valid,
                "candidates": [
                    {
                        "relative_path": "../escape.md",
                        "entry_type": "file",
                        "size": 10,
                        "hint": None,
                    }
                ],
                "returned": 1,
            },
            {**valid, "returned": 1},
        )
        for result in widened:
            outcome = operation_contract.OperationOutcome.completed(
                "a" * 64,
                result=result,
            )
            with self.subTest(result=result), self.assertRaises(ValueError):
                librarian_inspection.validate_scope_result(outcome)

    def test_scope_blocked_result_requires_exact_reason_action_pair(self) -> None:
        cases = (
            ("WORKSTREAM_INACTIVE", "choose-scope"),
            ("SCOPE_LIMIT_EXCEEDED", "inspect"),
            ("SCOPE_UNSAFE", "narrow-scope"),
        )
        for reason_code, next_safe_action in cases:
            outcome = operation_contract.OperationOutcome.blocked(
                "a" * 64,
                reason_code=reason_code,
                next_safe_action=next_safe_action,
            )
            with self.subTest(
                reason_code=reason_code,
                next_safe_action=next_safe_action,
            ), self.assertRaises(ValueError):
                librarian_inspection.validate_scope_result(outcome)


class SafeLibrarianSl1RuntimeTest(LedgerRuntimeFixture):
    def _tree_snapshot(self) -> tuple[tuple[str, str, bytes], ...]:
        snapshot = []
        for path in sorted(self.root.rglob("*")):
            relative = path.relative_to(self.root).as_posix()
            if path.is_symlink():
                snapshot.append((relative, "symlink", str(path.readlink()).encode()))
            elif path.is_dir():
                snapshot.append((relative, "directory", b""))
            elif path.is_file():
                snapshot.append((relative, "file", path.read_bytes()))
        return tuple(snapshot)

    def test_public_scope_inspection_is_bounded_and_changes_no_bytes(self) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o700)
        document = project_home / "notes.md"
        document.write_text("# Notes\nA short safe note.\n", encoding="utf-8")
        document.chmod(0o600)
        before = self._tree_snapshot()
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": "example-service"},
            bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            payload={},
        )

        raw = mnemosyne_core.execute_request_bytes(request.canonical_bytes)

        self.assertEqual(self._tree_snapshot(), before)
        outcome = json.loads(raw.decode("utf-8"))
        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertEqual(outcome["request_sha256"], request.sha256)
        result = outcome["result"]
        self.assertEqual(result["view"], "scope")
        self.assertEqual(result["scope"], {"relative_path": "example-service"})
        self.assertEqual(result["candidates"], [])
        self.assertEqual(
            [item["relative_path"] for item in result["organized"]],
            ["example-service/notes.md"],
        )
        self.assertEqual(
            result["organized"][0]["destination_id"],
            "example-service",
        )
        self.assertEqual(result["excluded"], [])
        self.assertEqual(result["uncertain"], [])
        self.assertFalse(result["truncated"])

    def test_scope_inspection_excludes_unsafe_entries_without_reading_them(self) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o700)
        public = project_home / "public.md"
        public.write_text("# Public title\nordinary body\n", encoding="utf-8")
        public.chmod(0o600)
        secret = project_home / "secret.md"
        secret.write_text(
            "# API token super-secret-body\nsuper-secret-body\n",
            encoding="utf-8",
        )
        secret.chmod(0o600)
        (project_home / "linked.md").symlink_to(public)
        (project_home / "opaque.bin").write_bytes(b"\x00\xffopaque")
        os.mkfifo(project_home / "pipe", mode=0o600)
        before = self._tree_snapshot()
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": "example-service"},
            bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            payload={},
        )

        raw = mnemosyne_core.execute_request_bytes(request.canonical_bytes)

        self.assertEqual(self._tree_snapshot(), before)
        self.assertNotIn(b"super-secret-body", raw)
        result = json.loads(raw.decode("utf-8"))["result"]
        self.assertEqual(result["scope"], {"relative_path": "example-service"})
        organized = {item["relative_path"]: item for item in result["organized"]}
        self.assertEqual(
            organized["example-service/public.md"]["hint"],
            "Public title",
        )
        self.assertIsNone(organized["example-service/secret.md"]["hint"])
        self.assertEqual(
            result["excluded"],
            [
                {
                    "relative_path": "example-service/linked.md",
                    "reason_code": "SOURCE_UNSUPPORTED",
                }
            ],
        )
        self.assertEqual(
            result["uncertain"],
            [
                {
                    "relative_path": "example-service/opaque.bin",
                    "reason_code": "CONTENT_OPAQUE",
                },
                {
                    "relative_path": "example-service/pipe",
                    "reason_code": "SOURCE_UNSUPPORTED",
                }
            ],
        )

    def test_scope_limits_are_reported_without_unbounded_traversal(self) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        nested = project_home / "nested"
        nested.mkdir(parents=True, mode=0o700)
        (nested / "inside.md").write_text("# Inside\n", encoding="utf-8")
        for name in ("a.md", "b.md", "c.md"):
            (project_home / name).write_text(f"# {name}\n", encoding="utf-8")
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": "example-service"},
            bounds={"max_items": 3, "max_depth": 1, "max_hint_bytes": 64},
            payload={},
        )

        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

        result = outcome["result"]
        self.assertEqual(result["scope"], {"relative_path": "example-service"})
        self.assertEqual(result["returned"], 3)
        self.assertTrue(result["truncated"])
        returned_paths = {
            item["relative_path"]
            for group in ("organized", "candidates", "excluded", "uncertain")
            for item in result[group]
        }
        self.assertEqual(
            returned_paths,
            {
                "example-service/a.md",
                "example-service/b.md",
                "example-service/c.md",
            },
        )
        self.assertNotIn("example-service/nested/inside.md", returned_paths)

    def test_unknown_workstream_ref_returns_typed_stop_without_mutation(self) -> None:
        self.migrate_to_v2()
        before = self._tree_snapshot()
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": "unknown-workstream"},
            bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            payload={},
        )

        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

        self.assertEqual(self._tree_snapshot(), before)
        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "WORKSTREAM_NOT_FOUND")
        self.assertEqual(outcome["next_safe_action"], "choose-workstream")

    def test_symlinked_workstream_home_is_not_followed(self) -> None:
        self.migrate_to_v2()
        outside = Path(self.temporary_directory.name).parent / (
            Path(self.temporary_directory.name).name + "-outside"
        )
        outside.mkdir(mode=0o700)
        self.addCleanup(lambda: outside.rmdir() if outside.exists() else None)
        (self.root / "example-service").symlink_to(
            outside,
            target_is_directory=True,
        )
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": "example-service"},
            bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            payload={},
        )

        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "WORKSTREAM_HOME_UNSAFE")
        self.assertEqual(outcome["next_safe_action"], "inspect-workstream")
        self.assertEqual(tuple(outside.iterdir()), ())

    def test_only_registered_active_workstream_is_reported_as_organized(self) -> None:
        self.migrate_to_v2()
        workstream_root = self.root / "example-service"
        workstream_root.mkdir(mode=0o700)
        (workstream_root / "README.md").write_text("# Scanner\n", encoding="utf-8")
        category_root = self.root / "projects"
        category_root.mkdir(mode=0o700)
        (category_root / "manual.md").write_text("# Manual\n", encoding="utf-8")

        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": "example-service"},
            bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            payload={},
        )
        result = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                "utf-8"
            )
        )["result"]

        self.assertEqual(
            result["organized"][0]["destination_kind"],
            "workstream",
        )
        self.assertEqual(
            result["organized"][0]["destination_id"],
            "example-service",
        )
        returned_paths = {
            item["relative_path"]
            for group in ("organized", "candidates", "excluded", "uncertain")
            for item in result[group]
        }
        self.assertEqual(returned_paths, {"example-service/README.md"})
        self.assertNotIn("projects/manual.md", returned_paths)

    def test_safe_librarian_profile_cannot_use_general_read_capabilities(self) -> None:
        self.migrate_to_v2()
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o700)
        (project_home / "note.md").write_text("# Note\n", encoding="utf-8")
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": "example-service"},
            bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            payload={},
        )
        spec = composition.DEFAULT_OPERATION_CATALOG.require_spec("inspect.scope")
        admitted = authority_runtime.admit(request, spec.admission_contract)

        with authority_runtime.open_read(admitted) as session:
            with self.assertRaisesRegex(ValueError, "does not permit this capability"):
                session.read_file("example-service/note.md")
            with self.assertRaisesRegex(ValueError, "does not permit this capability"):
                session.read_registered("schema_migrations")
            result = session.inspect_librarian_scope()

        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["result"]["view"], "scope")
        self.assertEqual(
            result["result"]["scope"],
            {"relative_path": "example-service"},
        )

    def test_unimplemented_librarian_write_profile_cannot_open_generic_writer(self) -> None:
        self.migrate_to_v2()
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.safe_record",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={},
            bounds={},
            payload={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-safe-record-v1",
            spec_sha256="b" * 64,
            operation_kind="test.safe_record",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.CURRENT,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
            write_profile=operation_contract.WriteProfile.SAFE_LIBRARIAN_RECORD,
        )
        admitted = authority_runtime.admit(request, contract)

        with self.assertRaisesRegex(
            authority_runtime.AuthorityRuntimeError,
            "write profile is unavailable",
        ):
            with authority_runtime.open_write(admitted):
                self.fail("a generic writer opened for a Safe Librarian profile")


class SafeLibrarianSl1InactiveWorkstreamTest(LedgerRuntimeFixture):
    def setUp(self) -> None:
        registry = ledger_fixture_module.BASE_REGISTRY.replace(
            b"never_touch:\n",
            b"  - id: paused-stream\n"
            b"    lifecycle: paused\n"
            b"    project_home: {root}/paused-stream\n"
            b"    aliases: []\n"
            b"  - id: completed-stream\n"
            b"    lifecycle: completed\n"
            b"    project_home: {root}/completed-stream\n"
            b"    aliases: []\n"
            b"never_touch:\n",
        )
        with mock.patch.object(ledger_fixture_module, "BASE_REGISTRY", registry):
            super().setUp()

    def test_paused_and_completed_workstream_scopes_return_frozen_coverage(self) -> None:
        self.migrate_to_v2()
        for relative_path in ("paused-stream", "completed-stream"):
            directory = self.root / relative_path
            directory.mkdir(mode=0o700)
            (directory / "note.md").write_text("# Untouched\n", encoding="utf-8")
            request = operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="inspect.scope",
                action=operation_contract.LifecycleAction.INSPECT,
                claim_mode=operation_contract.ClaimMode.HISTORICAL,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.READ,
                scope={"workstream_ref": relative_path},
                bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
                payload={},
            )

            with self.subTest(relative_path=relative_path):
                outcome = json.loads(
                    mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                        "utf-8"
                    )
                )
                self.assertEqual(outcome["outcome_kind"], "completed")
                result = outcome["result"]
                self.assertEqual(result["schema_version"], 2)
                self.assertEqual(result["inspection_mode"], "frozen-coverage")
                self.assertEqual(result["workstream"]["id"], relative_path)
                self.assertEqual(
                    result["workstream"]["lifecycle"],
                    "paused" if relative_path == "paused-stream" else "completed",
                )
                self.assertEqual(result["candidates"], [])
                self.assertEqual(result["frozen_coverage"]["file_count"], 1)
                self.assertNotIn(
                    b"note.md",
                    json.dumps(result, sort_keys=True).encode("utf-8"),
                )
                self.assertEqual((directory / "note.md").read_text(), "# Untouched\n")

    def test_completed_scope_reports_auxiliary_root_drift_without_reading_body(self) -> None:
        self.migrate_to_v2()
        directory = self.root / "completed-stream"
        directory.mkdir(mode=0o700)
        (directory / "note.md").write_text("# Untouched\n", encoding="utf-8")
        snapshot = (
            self.root
            / "_index"
            / "memory"
            / "completed-stream"
            / "snapshot.md"
        )
        snapshot.parent.mkdir(parents=True, mode=0o700)
        snapshot.write_text(
            "---\n"
            "schema_version: 1\n"
            "workspace:\n"
            "  slug: completed-stream\n"
            f'  root: "{self.root / "old-completed-stream"}"\n'
            'updated_at: "2026-07-18T09:30:00+09:00"\n'
            "---\n"
            "Status: active\n"
            "private-file-name.md\n",
            encoding="utf-8",
        )
        snapshot.chmod(0o644)
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.scope",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"workstream_ref": "completed-stream"},
            bounds={"max_items": 16, "max_depth": 4, "max_hint_bytes": 4096},
            payload={},
        )

        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

        self.assertEqual(outcome["outcome_kind"], "completed")
        result = outcome["result"]
        self.assertEqual(result["workstream"]["lifecycle"], "completed")
        self.assertEqual(
            [row["reason_code"] for row in result["drift"]],
            ["AUXILIARY_ROOT_MISMATCH"],
        )
        canonical = json.dumps(result, sort_keys=True)
        self.assertNotIn("Status: active", canonical)
        self.assertNotIn("private-file-name.md", canonical)


if __name__ == "__main__":
    unittest.main()
