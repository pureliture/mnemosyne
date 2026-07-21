import argparse
import ast
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
import mnemosyne_core  # noqa: E402
from mnemosyne_core import operation_contract  # noqa: E402
from mnemosyne_core.cli import request_builder  # noqa: E402


class _CapturedStdout:
    def __init__(self, *, isatty: bool = False) -> None:
        self.buffer = io.BytesIO()
        self.text = io.StringIO()
        self._isatty = isatty

    def write(self, value: str) -> int:
        self.buffer.write(value.encode("utf-8"))
        return self.text.write(value)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return self._isatty


class _CapturedStdin:
    def __init__(self, raw: bytes, *, isatty: bool = False) -> None:
        self.buffer = io.BytesIO(raw)
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


class D1bThreeCommandCliTest(unittest.TestCase):
    @staticmethod
    def _root_commands(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
        return next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )

    @classmethod
    def _curation_commands(cls, parser: argparse.ArgumentParser) -> frozenset[str]:
        root_commands = cls._root_commands(parser)
        curation = root_commands.choices["curation"]
        curation_commands = next(
            action
            for action in curation._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        return frozenset(curation_commands.choices)

    def _capabilities_request(self) -> bytes:
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.capabilities",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root="/private/tmp/mnemosyne-d1b-cli",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.NONE,
            payload={},
            bounds={"max_items": 50},
        ).canonical_bytes

    def _invoke(
        self,
        argv: list[str],
        *,
        stdin: bytes = b"",
        stdin_isatty: bool = False,
        stdout_isatty: bool = False,
    ) -> tuple[int, bytes, str]:
        captured_stdout = _CapturedStdout(isatty=stdout_isatty)
        captured_stderr = io.StringIO()
        captured_stdin = _CapturedStdin(stdin, isatty=stdin_isatty)
        with mock.patch.object(sys, "stdin", captured_stdin), mock.patch.object(
            sys,
            "stdout",
            captured_stdout,
        ), mock.patch.object(sys, "stderr", captured_stderr):
            exit_code = mnemosyne.main(argv)
        return exit_code, captured_stdout.buffer.getvalue(), captured_stderr.getvalue()

    def test_curation_exposes_exactly_three_adapter_commands(self):
        self.assertEqual(
            self._curation_commands(mnemosyne.build_parser()),
            frozenset({"guide", "dispatch", "inspect"}),
        )

    def test_public_inspect_views_keep_safe_librarian_and_workstream_planning(self):
        parser = mnemosyne.build_parser()
        root_commands = self._root_commands(parser)
        curation = root_commands.choices["curation"]
        curation_commands = next(
            action
            for action in curation._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        guide = curation_commands.choices["guide"]
        inspect = curation_commands.choices["inspect"]
        guide_view = next(action for action in guide._actions if action.dest == "view")
        inspect_view = next(
            action for action in inspect._actions if action.dest == "view"
        )

        self.assertEqual(
            frozenset(guide_view.choices),
            frozenset({"scope", "pending", "history"}),
        )
        self.assertEqual(
            frozenset(inspect_view.choices),
            frozenset({"audit", "scope", "pending", "history", "workstream"}),
        )
        self.assertEqual(guide.get_default("view"), "scope")

        for broad_view in ("status", "recovery", "capabilities"):
            with self.subTest(view=broad_view), self.assertRaisesRegex(
                ValueError,
                "inspect view is invalid",
            ):
                request_builder.build_view_request(
                    view=broad_view,
                    root="/private/tmp/mnemosyne-d1b-cli",
                    actor="operator",
                    max_items=None,
                    offset=0,
                )

    def test_root_exposes_only_curation_and_the_separate_workspace_boundary(self):
        root_commands = self._root_commands(mnemosyne.build_parser())
        self.assertEqual(
            frozenset(root_commands.choices),
            frozenset({"context", "curation", "memory-sync"}),
        )

    def test_retired_legacy_curation_surface_modules_are_absent(self):
        core_root = SCRIPT_DIR / "mnemosyne_core"
        for filename in (
            "curation_harness.py",
            "curation_registry.py",
            "curation_legacy_surface.py",
        ):
            with self.subTest(filename=filename):
                self.assertFalse((core_root / filename).exists())

    def test_retired_curation_command_owners_are_not_public_command_symbols(self):
        source = ast.parse((SCRIPT_DIR / "mnemosyne.py").read_text(encoding="utf-8"))
        definitions = {
            node.name
            for node in ast.walk(source)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertTrue(
            definitions.isdisjoint(
                {
                    "command_approve",
                    "command_audit",
                    "command_bootstrap",
                    "command_curation_history",
                    "command_list_history",
                    "command_list_pending",
                    "command_preview_lock_migration",
                    "command_apply_lock_migration",
                    "command_propose_place",
                    "command_reject",
                }
            )
        )

    def test_cli_adapters_do_not_import_legacy_workflows_or_private_runtime_state(self):
        core_root = SCRIPT_DIR / "mnemosyne_core"
        forbidden = {
            "curation_audit",
            "curation_harness",
            "curation_inspect",
            "curation_legacy_surface",
            "curation_registry",
            "ledger_runtime",
            "m3_workflow",
            "m4_workflow",
        }
        for relative_path in (
            "cli/dispatch.py",
            "cli/request_builder.py",
            "cli/inspect.py",
            "cli/guide.py",
        ):
            with self.subTest(relative_path=relative_path):
                tree = ast.parse((core_root / relative_path).read_text(encoding="utf-8"))
                imports = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imports.update(alias.name.rsplit(".", 1)[-1] for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imports.add(node.module.rsplit(".", 1)[-1])
                self.assertTrue(imports.isdisjoint(forbidden))

    def test_dispatch_reads_one_safe_canonical_file_and_preserves_core_bytes(self):
        request = self._capabilities_request()
        expected = mnemosyne_core.execute_request_bytes(request)
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            directory = Path(temporary)
            request_file = directory / "request.json"
            request_file.write_bytes(request)
            os.chmod(request_file, 0o600)

            exit_code, output, stderr = self._invoke(
                [
                    "curation",
                    "dispatch",
                    "--request-file",
                    str(request_file),
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(output, expected)

    def test_dispatch_rejects_an_unsafe_request_file_before_the_executor(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            directory = Path(temporary)
            target = directory / "target.json"
            target.write_bytes(self._capabilities_request())
            os.chmod(target, 0o600)
            unsafe_source = directory / "request.json"
            unsafe_source.symlink_to(target)

            with mock.patch.object(
                mnemosyne._mnemosyne_core,
                "execute_request_bytes",
                side_effect=AssertionError("unsafe source reached the executor"),
            ):
                exit_code, output, stderr = self._invoke(
                    [
                        "curation",
                        "dispatch",
                        "--request-file",
                        str(unsafe_source),
                    ]
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stderr, "")
        result = json.loads(output.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "blocked")
        self.assertEqual(result["reason_code"], "UNSAFE_REQUEST_SOURCE")
        self.assertEqual(result["next_safe_action"], "correct-request-source")

    def test_dispatch_rejects_tty_stdin_without_prompting(self):
        exit_code, output, stderr = self._invoke(
            ["curation", "dispatch"],
            stdin_isatty=True,
        )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stderr, "")
        self.assertEqual(
            json.loads(output.decode("utf-8"))["reason_code"],
            "UNSAFE_REQUEST_SOURCE",
        )

    def test_dispatch_rejects_unsafe_file_shapes_before_the_executor(self):
        request = self._capabilities_request()
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            directory = Path(temporary)
            unsafe_sources = []

            mode = directory / "mode.json"
            mode.write_bytes(request)
            os.chmod(mode, 0o644)
            unsafe_sources.append(mode)

            linked = directory / "linked.json"
            linked.write_bytes(request)
            os.chmod(linked, 0o600)
            hard_link = directory / "hard-link.json"
            os.link(linked, hard_link)
            unsafe_sources.append(hard_link)

            oversized = directory / "oversized.json"
            oversized.write_bytes(b"x" * (1024 * 1024 + 1))
            os.chmod(oversized, 0o600)
            unsafe_sources.append(oversized)

            for unsafe_source in unsafe_sources:
                with self.subTest(source=unsafe_source.name), mock.patch.object(
                    mnemosyne._mnemosyne_core,
                    "execute_request_bytes",
                    side_effect=AssertionError("unsafe source reached the executor"),
                ):
                    exit_code, output, stderr = self._invoke(
                        [
                            "curation",
                            "dispatch",
                            "--request-file",
                            str(unsafe_source),
                        ]
                    )

                self.assertEqual(exit_code, 2)
                self.assertEqual(stderr, "")
                self.assertEqual(
                    json.loads(output.decode("utf-8"))["reason_code"],
                    "UNSAFE_REQUEST_SOURCE",
                )

    def test_dispatch_stdin_preserves_the_same_core_bytes_and_has_no_root_override(self):
        request = self._capabilities_request()
        expected = mnemosyne_core.execute_request_bytes(request)

        exit_code, output, stderr = self._invoke(
            ["curation", "dispatch"],
            stdin=request,
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(output, expected)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            mnemosyne.build_parser().parse_args(
                ["curation", "dispatch", "--root", "/private/tmp/forbidden"]
            )

    def test_operation_control_only_views_are_not_public_parser_choices(self):
        parser = mnemosyne.build_parser()
        for view in ("status", "recovery", "capabilities"):
            for argv in (
                ["curation", "inspect", view],
                ["curation", "guide", "--draft", "inspect", "--view", view],
            ):
                with self.subTest(view=view, argv=argv), redirect_stderr(
                    io.StringIO()
                ), self.assertRaises(SystemExit) as raised:
                    parser.parse_args(argv)
                self.assertEqual(raised.exception.code, 2)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            parser.parse_args(
                ["curation", "guide", "--draft", "inspect", "--view", "audit"]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_record_inspect_requires_scope_before_the_executor(self):
        for view in ("pending", "history"):
            with self.subTest(view=view), mock.patch.object(
                mnemosyne._mnemosyne_core,
                "execute_request_bytes",
                side_effect=AssertionError("invalid view reached the executor"),
            ) as executor:
                exit_code, output, stderr = self._invoke(
                    ["curation", "inspect", view, "--json"]
                )

            self.assertEqual(exit_code, 2)
            self.assertEqual(stderr, "")
            result = json.loads(output.decode("utf-8"))
            self.assertEqual(result["outcome_kind"], "blocked")
            self.assertEqual(result["reason_code"], "INVALID_REQUEST")
            executor.assert_not_called()

    def test_guide_is_tty_only_and_does_not_accept_machine_request_input(self):
        exit_code, output, stderr = self._invoke(
            ["curation", "guide", "--root", "/private/tmp/guide", "--actor", "operator"],
            stdin_isatty=False,
            stdout_isatty=False,
        )

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, b"")
        self.assertIn("TTY", stderr)

    def test_guide_tty_builds_a_separate_unexecuted_request_draft(self):
        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "guide",
                "--root",
                "/private/tmp/mnemosyne-d1b-guide",
                "--actor",
                "operator",
                "--view",
                "scope",
                "--workstream",
                "example-service",
            ],
            stdin_isatty=True,
            stdout_isatty=True,
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        text = output.decode("utf-8")
        self.assertIn("has not been executed", text)
        self.assertIn("curation dispatch", text)
        self.assertIn('"operation_kind":"inspect.scope"', text)
        self.assertIn('"workstream_ref":"example-service"', text)

    def test_removed_curation_command_returns_generic_migration_guidance(self):
        captured_stderr = io.StringIO()
        with mock.patch.object(sys, "stderr", captured_stderr):
            with self.assertRaises(SystemExit) as raised:
                mnemosyne.main(["curation", "audit"])

        self.assertEqual(raised.exception.code, 2)
        message = captured_stderr.getvalue()
        self.assertIn("curation guide", message)
        self.assertIn("curation dispatch", message)
        self.assertIn("curation inspect", message)

    def test_removed_top_level_curation_commands_are_unreachable(self):
        for command in (
            "audit",
            "approve",
            "bootstrap",
            "list-decisions",
            "list-history",
            "list-pending",
            "propose-place",
            "reject",
        ):
            with self.subTest(command=command):
                captured_stderr = io.StringIO()
                with mock.patch.object(sys, "stderr", captured_stderr):
                    with self.assertRaises(SystemExit) as raised:
                        mnemosyne.main([command])

                self.assertEqual(raised.exception.code, 2)
                self.assertIn("curation dispatch", captured_stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
