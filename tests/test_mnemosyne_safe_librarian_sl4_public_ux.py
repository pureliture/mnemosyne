import io
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import operation_contract  # noqa: E402


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class _TtyStdout:
    def __init__(self, *, isatty: bool = True) -> None:
        self.buffer = io.BytesIO()
        self._isatty = isatty

    def write(self, value: str) -> int:
        raw = value.encode("utf-8")
        self.buffer.write(raw)
        return len(value)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return self._isatty


class _TtyStdin:
    def __init__(self, raw: bytes = b"", *, isatty: bool = True) -> None:
        self.buffer = io.BytesIO(raw)
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


class SafeLibrarianSl4PublicUxRedTest(LedgerRuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.migrate_to_v2()

    def _invoke(
        self,
        argv: list[str],
        *,
        stdin: bytes = b"",
        stdin_isatty: bool = False,
        stdout_isatty: bool = False,
    ) -> tuple[int, bytes, str]:
        captured_stdout = _TtyStdout(isatty=stdout_isatty)
        captured_stderr = io.StringIO()
        captured_stdin = _TtyStdin(stdin, isatty=stdin_isatty)
        with mock.patch.object(sys, "stdin", captured_stdin), mock.patch.object(
            sys,
            "stdout",
            captured_stdout,
        ), mock.patch.object(sys, "stderr", captured_stderr):
            try:
                exit_code = mnemosyne.main(argv)
            except SystemExit as exc:
                exit_code = int(exc.code)
        return exit_code, captured_stdout.buffer.getvalue(), captured_stderr.getvalue()

    def _guide(self, argv: list[str]) -> tuple[bytes, str]:
        with mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            side_effect=AssertionError("curation guide must not call the executor"),
        ) as executor:
            exit_code, output, stderr = self._invoke(
                argv,
                stdin_isatty=True,
                stdout_isatty=True,
            )
        self.assertEqual(exit_code, 0, stderr)
        self.assertEqual(stderr, "")
        executor.assert_not_called()
        lines = output.decode("utf-8").splitlines()
        self.assertGreaterEqual(len(lines), 2)
        return lines[-1].encode("utf-8") + b"\n", "\n".join(lines[:-1])

    def _write_exchange_file(self, name: str, raw: bytes) -> Path:
        directory = self.root / "operator-exchange"
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def _record_proposal_exchange(
        self,
        stem: str,
    ) -> tuple[Path, Path, Path, Path]:
        source = self.root / "inbox" / f"{stem}.md"
        source.parent.mkdir(mode=0o700, exist_ok=True)
        source.write_text(f"# {stem}\n", encoding="utf-8")
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / source.name
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        proposal_raw, _ = self._guide(
            [
                "curation",
                "guide",
                "--draft",
                "proposal",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--source-relative-path",
                source.relative_to(self.root).as_posix(),
                "--target-relative-path",
                target.relative_to(self.root).as_posix(),
                "--destination-kind",
                "workstream",
                "--destination-id",
                "example-service",
                "--reason",
                "The document belongs to the example-service Workstream.",
            ]
        )
        proposal_code, proposal_outcome_raw, proposal_error = self._invoke(
            ["curation", "dispatch"],
            stdin=proposal_raw,
        )
        self.assertEqual(proposal_code, 0, proposal_error)
        return (
            self._write_exchange_file(f"{stem}-request.json", proposal_raw),
            self._write_exchange_file(
                f"{stem}-outcome.json",
                proposal_outcome_raw,
            ),
            source,
            target,
        )

    def _control_bytes(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.registry_directory).as_posix(): path.read_bytes()
            for path in sorted(self.registry_directory.rglob("*"))
            if path.is_file()
        }

    def test_tty_guide_drafts_one_exact_proposal_without_execution(self) -> None:
        source = self.root / "inbox" / "guide-note.md"
        source.parent.mkdir(mode=0o700, exist_ok=True)
        source_bytes = b"# Guide proposal\nThis source must remain in place.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "guide-note.md"
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.assertFalse(target.exists())
        source_identity = (source.stat().st_dev, source.stat().st_ino)
        control_before = self._control_bytes()
        captured_stdout = _TtyStdout()
        captured_stderr = io.StringIO()

        with mock.patch.object(sys, "stdin", _TtyStdin()), mock.patch.object(
            sys,
            "stdout",
            captured_stdout,
        ), mock.patch.object(sys, "stderr", captured_stderr), mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            side_effect=AssertionError("curation guide must not call the executor"),
        ) as executor:
            try:
                exit_code = mnemosyne.main(
                    [
                        "curation",
                        "guide",
                        "--draft",
                        "proposal",
                        "--root",
                        str(self.root),
                        "--actor",
                        "operator",
                        "--source-relative-path",
                        "inbox/guide-note.md",
                        "--target-relative-path",
                        "example-service/docs/guide-note.md",
                        "--destination-kind",
                        "workstream",
                        "--destination-id",
                        "example-service",
                        "--reason",
                        "This document belongs to the example-service Workstream.",
                        "--max-entries",
                        "7",
                        "--max-depth",
                        "3",
                        "--max-total-bytes",
                        "4096",
                    ]
                )
            except SystemExit as exc:
                exit_code = exc.code

        self.assertEqual(exit_code, 0, captured_stderr.getvalue())
        self.assertEqual(captured_stderr.getvalue(), "")
        executor.assert_not_called()
        output_lines = captured_stdout.buffer.getvalue().decode("utf-8").splitlines()
        self.assertGreaterEqual(len(output_lines), 2)
        request = operation_contract.codec.decode_operation_request(
            output_lines[-1].encode("utf-8") + b"\n"
        )
        guidance = "\n".join(output_lines[:-1])

        self.assertEqual(request.schema_version, 1)
        self.assertEqual(request.operation_kind, "librarian.proposal")
        self.assertIs(request.action, operation_contract.LifecycleAction.APPLY)
        self.assertIs(request.claim_mode, operation_contract.ClaimMode.CURRENT)
        self.assertEqual(request.root, str(self.root))
        self.assertEqual(request.actor, "operator")
        self.assertIs(
            request.requested_authority,
            operation_contract.AuthorityMode.WRITE,
        )
        proposal_id = request.scope["proposal_id"]
        self.assertIsNotNone(
            re.fullmatch(
                r"p-[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}",
                proposal_id,
            )
        )
        self.assertEqual(
            dict(request.scope),
            {
                "proposal_id": proposal_id,
                "source_relative_path": "inbox/guide-note.md",
                "target_relative_path": "example-service/docs/guide-note.md",
            },
        )
        self.assertEqual(
            dict(request.payload),
            {
                "destination_kind": "workstream",
                "destination_id": "example-service",
                "reason": "This document belongs to the example-service Workstream.",
            },
        )
        self.assertEqual(
            dict(request.bounds),
            {
                "max_entries": 7,
                "max_depth": 3,
                "max_total_bytes": 4096,
            },
        )
        self.assertIsNone(request.approval_artifact)
        self.assertEqual(request.prerequisite_artifacts, ())
        self.assertIn(
            "The source remains unchanged; it has not been moved.",
            guidance,
        )
        self.assertIn(
            "Run the exact request separately through `curation dispatch`.",
            guidance,
        )
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual(
            (source.stat().st_dev, source.stat().st_ino),
            source_identity,
        )
        self.assertFalse(target.exists())
        self.assertEqual(self._control_bytes(), control_before)

    def test_reject_flow_through_three_public_commands(self) -> None:
        source = self.root / "inbox" / "reject-note.md"
        source.parent.mkdir(mode=0o700, exist_ok=True)
        source_bytes = b"# Reject flow\nThis document remains at its source.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        source_identity = (source.stat().st_dev, source.stat().st_ino)
        target = self.root / "example-service" / "docs" / source.name
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        inspected = self.root / "example-service" / "README.md"
        inspected.write_text("# Scanner\n", encoding="utf-8")
        inspected.chmod(0o600)

        inspect_code, inspect_raw, inspect_error = self._invoke(
            [
                "curation",
                "inspect",
                "scope",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--workstream",
                "example-service",
                "--json",
            ]
        )
        self.assertEqual(inspect_code, 0, inspect_error)
        inspection = json.loads(inspect_raw.decode("utf-8"))
        self.assertEqual(inspection["outcome_kind"], "completed")
        self.assertEqual(
            inspection["result"]["scope"],
            {"relative_path": "example-service"},
        )
        organized_paths = {
            item["relative_path"]
            for item in inspection["result"]["organized"]
        }
        self.assertIn("example-service/README.md", organized_paths)
        self.assertEqual(inspection["result"]["candidates"], [])
        self.assertEqual(source.read_bytes(), source_bytes)

        proposal_raw, proposal_guidance = self._guide(
            [
                "curation",
                "guide",
                "--draft",
                "proposal",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--source-relative-path",
                "inbox/reject-note.md",
                "--target-relative-path",
                "example-service/docs/reject-note.md",
                "--destination-kind",
                "workstream",
                "--destination-id",
                "example-service",
                "--reason",
                "The document was considered for the example-service Workstream.",
            ]
        )
        proposal_request = operation_contract.codec.decode_operation_request(
            proposal_raw
        )
        proposal_id = proposal_request.scope["proposal_id"]
        self.assertIn("has not been moved", proposal_guidance)
        original_executor = mnemosyne._mnemosyne_core.execute_request_bytes
        with mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            wraps=original_executor,
        ) as proposal_executor:
            proposal_code, proposal_outcome_raw, proposal_error = self._invoke(
                ["curation", "dispatch"],
                stdin=proposal_raw,
            )
        self.assertEqual(proposal_code, 0, proposal_error)
        proposal_executor.assert_called_once_with(proposal_raw)
        proposal_outcome = json.loads(proposal_outcome_raw.decode("utf-8"))
        self.assertEqual(proposal_outcome["outcome_kind"], "completed")
        self.assertEqual(proposal_outcome["request_sha256"], proposal_request.sha256)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

        proposal_request_file = self._write_exchange_file(
            "proposal-request.json",
            proposal_raw,
        )
        proposal_outcome_file = self._write_exchange_file(
            "proposal-outcome.json",
            proposal_outcome_raw,
        )
        decision_raw, decision_guidance = self._guide(
            [
                "curation",
                "guide",
                "--draft",
                "decision",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--proposal-request-file",
                str(proposal_request_file),
                "--proposal-outcome-file",
                str(proposal_outcome_file),
                "--decision",
                "REJECTED",
                "--decision-reason",
                "The displayed proposal does not match the intended organization.",
            ]
        )
        decision_request = operation_contract.codec.decode_operation_request(
            decision_raw
        )
        self.assertEqual(decision_request.operation_kind, "librarian.decision")
        self.assertEqual(decision_request.scope, {"proposal_id": proposal_id})
        self.assertEqual(decision_request.payload["decision"], "REJECTED")
        self.assertEqual(
            decision_request.prerequisite_artifacts[0].canonical_value,
            proposal_outcome["result_artifact"],
        )
        self.assertIn("will not move", decision_guidance)

        original_executor = mnemosyne._mnemosyne_core.execute_request_bytes
        with mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            wraps=original_executor,
        ) as decision_executor:
            decision_code, decision_outcome_raw, decision_error = self._invoke(
                ["curation", "dispatch"],
                stdin=decision_raw,
            )
        self.assertEqual(decision_code, 0, decision_error)
        decision_executor.assert_called_once_with(decision_raw)
        decision_outcome = json.loads(decision_outcome_raw.decode("utf-8"))
        self.assertEqual(decision_outcome["outcome_kind"], "completed")

        history_code, history_raw, history_error = self._invoke(
            [
                "curation",
                "inspect",
                "history",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--relative-path",
                "inbox",
                "--json",
            ]
        )
        self.assertEqual(history_code, 0, history_error)
        history = json.loads(history_raw.decode("utf-8"))
        record = history["result"]["records"][0]
        self.assertEqual(record["proposal_id"], proposal_id)
        self.assertEqual(record["status"], "REJECTED")
        self.assertEqual(record["decision"], decision_outcome["result_artifact"])
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual(
            (source.stat().st_dev, source.stat().st_ino),
            source_identity,
        )
        self.assertFalse(target.exists())
        artifact_root = self.root / "_registry" / "curation" / "safe-librarian" / "v1"
        self.assertFalse((artifact_root / "intents" / f"{proposal_id}.json").exists())
        self.assertFalse((artifact_root / "results" / f"{proposal_id}.json").exists())

    def test_approve_and_place_flow_through_three_public_commands(self) -> None:
        source = self.root / "inbox" / "approve-note.md"
        source.parent.mkdir(mode=0o700, exist_ok=True)
        source_bytes = b"# Approve flow\nMove these exact bytes once.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        source_identity = (source.stat().st_dev, source.stat().st_ino)
        target = self.root / "example-service" / "docs" / source.name
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        inspected = self.root / "example-service" / "README.md"
        inspected.write_text("# Scanner\n", encoding="utf-8")
        inspected.chmod(0o600)

        inspect_code, inspect_raw, inspect_error = self._invoke(
            [
                "curation",
                "inspect",
                "scope",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--workstream",
                "example-service",
                "--json",
            ]
        )
        self.assertEqual(inspect_code, 0, inspect_error)
        inspection = json.loads(inspect_raw.decode("utf-8"))
        self.assertEqual(
            inspection["result"]["scope"],
            {"relative_path": "example-service"},
        )
        self.assertIn(
            "example-service/README.md",
            {
                item["relative_path"]
                for item in inspection["result"]["organized"]
            },
        )
        self.assertEqual(inspection["result"]["candidates"], [])

        proposal_raw, _proposal_guidance = self._guide(
            [
                "curation",
                "guide",
                "--draft",
                "proposal",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--source-relative-path",
                "inbox/approve-note.md",
                "--target-relative-path",
                "example-service/docs/approve-note.md",
                "--destination-kind",
                "workstream",
                "--destination-id",
                "example-service",
                "--reason",
                "The document belongs to the example-service Workstream.",
            ]
        )
        proposal_request = operation_contract.codec.decode_operation_request(
            proposal_raw
        )
        proposal_id = proposal_request.scope["proposal_id"]
        proposal_code, proposal_outcome_raw, proposal_error = self._invoke(
            ["curation", "dispatch"],
            stdin=proposal_raw,
        )
        self.assertEqual(proposal_code, 0, proposal_error)
        proposal_outcome = json.loads(proposal_outcome_raw.decode("utf-8"))
        proposal_request_file = self._write_exchange_file(
            "approved-proposal-request.json",
            proposal_raw,
        )
        proposal_outcome_file = self._write_exchange_file(
            "approved-proposal-outcome.json",
            proposal_outcome_raw,
        )

        decision_raw, decision_guidance = self._guide(
            [
                "curation",
                "guide",
                "--draft",
                "decision",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--proposal-request-file",
                str(proposal_request_file),
                "--proposal-outcome-file",
                str(proposal_outcome_file),
                "--decision",
                "APPROVED",
                "--decision-reason",
                "The exact displayed proposal is approved.",
            ]
        )
        self.assertIn("has not moved yet", decision_guidance)
        decision_request = operation_contract.codec.decode_operation_request(
            decision_raw
        )
        decision_code, decision_outcome_raw, decision_error = self._invoke(
            ["curation", "dispatch"],
            stdin=decision_raw,
        )
        self.assertEqual(decision_code, 0, decision_error)
        decision_outcome = json.loads(decision_outcome_raw.decode("utf-8"))
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual(
            (source.stat().st_dev, source.stat().st_ino),
            source_identity,
        )
        self.assertFalse(target.exists())

        decision_request_file = self._write_exchange_file(
            "approved-decision-request.json",
            decision_raw,
        )
        decision_outcome_file = self._write_exchange_file(
            "approved-decision-outcome.json",
            decision_outcome_raw,
        )
        placement_raw, placement_guidance = self._guide(
            [
                "curation",
                "guide",
                "--draft",
                "placement",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--proposal-request-file",
                str(proposal_request_file),
                "--proposal-outcome-file",
                str(proposal_outcome_file),
                "--decision-request-file",
                str(decision_request_file),
                "--decision-outcome-file",
                str(decision_outcome_file),
            ]
        )
        placement_request = operation_contract.codec.decode_operation_request(
            placement_raw
        )
        self.assertEqual(placement_request.operation_kind, "librarian.placement")
        self.assertEqual(dict(placement_request.scope), dict(proposal_request.scope))
        self.assertEqual(dict(placement_request.payload), {})
        self.assertEqual(dict(placement_request.bounds), {})
        self.assertEqual(
            placement_request.approval_artifact.canonical_value,
            decision_outcome["result_artifact"],
        )
        self.assertEqual(
            [item.canonical_value for item in placement_request.prerequisite_artifacts],
            [proposal_outcome["result_artifact"]],
        )
        self.assertIn("will move exactly", placement_guidance)

        original_executor = mnemosyne._mnemosyne_core.execute_request_bytes
        with mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            wraps=original_executor,
        ) as placement_executor:
            placement_code, placement_outcome_raw, placement_error = self._invoke(
                ["curation", "dispatch"],
                stdin=placement_raw,
            )
        self.assertEqual(placement_code, 0, placement_error)
        placement_executor.assert_called_once_with(placement_raw)
        placement_outcome = json.loads(placement_outcome_raw.decode("utf-8"))
        self.assertEqual(placement_outcome["outcome_kind"], "completed")
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual(
            (target.stat().st_dev, target.stat().st_ino),
            source_identity,
        )

        replay_code, replay_raw, replay_error = self._invoke(
            ["curation", "dispatch"],
            stdin=placement_raw,
        )
        self.assertEqual(replay_code, 0, replay_error)
        self.assertEqual(replay_raw, placement_outcome_raw)
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual(
            (target.stat().st_dev, target.stat().st_ino),
            source_identity,
        )

        history_code, history_raw, history_error = self._invoke(
            [
                "curation",
                "inspect",
                "history",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--relative-path",
                "inbox",
                "--json",
            ]
        )
        self.assertEqual(history_code, 0, history_error)
        history = json.loads(history_raw.decode("utf-8"))
        record = history["result"]["records"][0]
        self.assertEqual(record["proposal_id"], proposal_id)
        self.assertEqual(record["status"], "APPLIED")
        self.assertEqual(record["decision"], decision_outcome["result_artifact"])
        self.assertEqual(
            record["placement_result"],
            placement_outcome["result_artifact"],
        )
        self.assertEqual(decision_request.payload["decision"], "APPROVED")

    def test_scope_human_view_explains_organized_items_and_safe_stops(self) -> None:
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o700, exist_ok=True)
        public = project_home / "public.md"
        public.write_text("# Public title\nOrdinary body.\n", encoding="utf-8")
        public.chmod(0o600)
        (project_home / "linked.md").symlink_to(public)
        opaque = project_home / "opaque.bin"
        opaque.write_bytes(b"\x00\xffopaque")
        opaque.chmod(0o600)

        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "inspect",
                "scope",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--workstream",
                "example-service",
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        text = output.decode("utf-8")
        self.assertIn("검사 범위: example-service", text)
        self.assertIn("정리된 항목: 1건", text)
        self.assertIn("제안 후보: 0건", text)
        self.assertIn("example-service/public.md", text)
        self.assertIn("workstream: example-service", text)
        self.assertIn("제외: 1건", text)
        self.assertIn("example-service/linked.md", text)
        self.assertIn("안전하게 다룰 수 없는 파일 형식", text)
        self.assertIn("확인 필요: 1건", text)
        self.assertIn("example-service/opaque.bin", text)
        self.assertIn("내용을 안전하게 분류할 수 없음", text)
        self.assertNotIn("SOURCE_UNSUPPORTED", text)
        self.assertNotIn("CONTENT_OPAQUE", text)
        self.assertNotIn("Ordinary body", text)

    def test_decision_guide_rejects_non_owner_only_prior_request(self) -> None:
        request_file, outcome_file, source, target = (
            self._record_proposal_exchange("unsafe-permission")
        )
        request_file.chmod(0o644)
        source_before = source.read_bytes()
        control_before = self._control_bytes()

        with mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            side_effect=AssertionError("curation guide must not call the executor"),
        ) as executor:
            exit_code, output, stderr = self._invoke(
                [
                    "curation",
                    "guide",
                    "--draft",
                    "decision",
                    "--root",
                    str(self.root),
                    "--actor",
                    "operator",
                    "--proposal-request-file",
                    str(request_file),
                    "--proposal-outcome-file",
                    str(outcome_file),
                    "--decision",
                    "APPROVED",
                    "--decision-reason",
                    "The displayed proposal is correct.",
                ],
                stdin_isatty=True,
                stdout_isatty=True,
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, b"")
        self.assertEqual(
            stderr,
            "guide request fields are invalid; correct them and retry\n",
        )
        executor.assert_not_called()
        self.assertEqual(source.read_bytes(), source_before)
        self.assertFalse(target.exists())
        self.assertEqual(self._control_bytes(), control_before)

    def test_decision_guide_rejects_mismatched_request_and_outcome(self) -> None:
        first_request, _, first_source, first_target = (
            self._record_proposal_exchange("first-proposal")
        )
        _, second_outcome, second_source, second_target = (
            self._record_proposal_exchange("second-proposal")
        )
        control_before = self._control_bytes()

        with mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            side_effect=AssertionError("curation guide must not call the executor"),
        ) as executor:
            exit_code, output, stderr = self._invoke(
                [
                    "curation",
                    "guide",
                    "--draft",
                    "decision",
                    "--root",
                    str(self.root),
                    "--actor",
                    "operator",
                    "--proposal-request-file",
                    str(first_request),
                    "--proposal-outcome-file",
                    str(second_outcome),
                    "--decision",
                    "REJECTED",
                    "--decision-reason",
                    "The displayed proposal is not intended.",
                ],
                stdin_isatty=True,
                stdout_isatty=True,
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, b"")
        self.assertEqual(
            stderr,
            "guide request fields are invalid; correct them and retry\n",
        )
        executor.assert_not_called()
        self.assertTrue(first_source.exists())
        self.assertTrue(second_source.exists())
        self.assertFalse(first_target.exists())
        self.assertFalse(second_target.exists())
        self.assertEqual(self._control_bytes(), control_before)


if __name__ == "__main__":
    unittest.main()
