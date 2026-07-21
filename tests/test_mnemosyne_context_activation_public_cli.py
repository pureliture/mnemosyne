"""Public guide coverage for Context-bound Curation activation."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import mnemosyne  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    canonical_curation,
    canonical_curation_review,
    operation_contract,
    workstream_curation,
)
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402
from test_mnemosyne_context_bound_curation_plan import (  # noqa: E402
    _complete_context,
    _plan,
)


class _TtyStdout:
    def __init__(self, *, isatty: bool = True) -> None:
        self.buffer = io.BytesIO()
        self._isatty = isatty

    def write(self, value: str) -> int:
        self.buffer.write(value.encode("utf-8"))
        return len(value)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return self._isatty


class _TtyStdin:
    def __init__(self, *, isatty: bool = True) -> None:
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


def _invoke_guide(
    argv: list[str],
    *,
    tty: bool = True,
) -> tuple[int, bytes, str]:
    stdout = _TtyStdout(isatty=tty)
    stderr = io.StringIO()
    with mock.patch.object(
        sys, "stdin", _TtyStdin(isatty=tty)
    ), mock.patch.object(sys, "stdout", stdout), mock.patch.object(
        sys, "stderr", stderr
    ), mock.patch.object(
        mnemosyne._mnemosyne_core,
        "execute_request_bytes",
        side_effect=AssertionError("curation guide must not execute"),
    ) as executor:
        try:
            exit_code = mnemosyne.main(argv)
        except SystemExit as exc:
            exit_code = int(exc.code)
    executor.assert_not_called()
    return exit_code, stdout.buffer.getvalue(), stderr.getvalue()


def _review_hashes(review_directory: Path) -> dict[str, str]:
    meta_path = review_directory / "review.meta.json"
    return {
        "html_sha256": hashlib.sha256(
            (review_directory / "review.html").read_bytes()
        ).hexdigest(),
        "markdown_sha256": hashlib.sha256(
            (review_directory / "review.md").read_bytes()
        ).hexdigest(),
        "meta_sha256": hashlib.sha256(meta_path.read_bytes()).hexdigest(),
        "semantic_sha256": json.loads(
            meta_path.read_text(encoding="utf-8")
        )["semantic_sha256"],
    }


class ContextActivationPublicCliTest(unittest.TestCase):
    def _sealed_review(self, base: Path, *, inner_plan=None):
        complete = _complete_context()
        plan = canonical_curation.compile_curation_plan(
            _plan() if inner_plan is None else inner_plan,
            context_assembly=complete,
        )
        payload = canonical_curation_review.compile_context_bound_review(
            plan,
            context_assembly=complete,
            rendered_at="2026-07-20T00:00:00Z",
            renderer_id="context-activation-public-test",
        )
        review_directory = base / "review"
        review_directory.mkdir(mode=0o700)
        canonical_curation_review.write_context_bound_review_package(
            review_directory,
            payload,
        )
        return plan, review_directory

    def _guide_args(
        self,
        plan,
        review_directory: Path,
        *,
        expected_plan_sha256: str | None = None,
        decision: str = "APPROVE_ALL",
    ) -> list[str]:
        return [
            "curation",
            "guide",
            "--draft",
            "context-activation",
            "--root",
            "/private/tmp/context-activation-public-root",
            "--actor",
            "operator",
            "--review-package",
            str(review_directory),
            "--expected-plan-sha256",
            plan.sha256 if expected_plan_sha256 is None else expected_plan_sha256,
            "--decision",
            decision,
        ]

    def test_public_guide_builds_exact_context_activation_request_without_execution(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            plan, review_directory = self._sealed_review(Path(temporary))
            exit_code, stdout, stderr = _invoke_guide(
                self._guide_args(plan, review_directory)
            )

            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(stderr, "")
            output_lines = stdout.decode("utf-8").splitlines()
            self.assertIn("sealed effect count: 1", output_lines)
            request_plain = json.loads(output_lines[-1])
            request = operation_contract.codec.decode_operation_request(
                output_lines[-1].encode("utf-8") + b"\n"
            )

            self.assertEqual(request.operation_kind, "curation.plan_apply")
            self.assertEqual(request.scope["plan_sha256"], plan.sha256)
            self.assertEqual(request.scope["workstream_id"], "alpha")
            self.assertEqual(request.bounds, {"max_effects": 1, "max_total_bytes": 7})
            self.assertEqual(
                request_plain["payload"]["plan"],
                plan.canonical_value,
            )
            self.assertEqual(
                request_plain["payload"]["decision"],
                {
                    "action": "APPROVE_ALL",
                    "approved_plan_sha256": plan.sha256,
                    "displayed_plan_sha256": plan.sha256,
                    "reason": None,
                    "review_package_hashes": _review_hashes(review_directory),
                    "selected_effect_ids": ["effect-current-local"],
                    "source_observation_sha256": plan.source_observation_sha256,
                },
            )

    def test_context_activation_guide_fails_closed_for_wrong_plan_or_decision(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            plan, review_directory = self._sealed_review(Path(temporary))

            wrong_sha_code, wrong_sha_output, wrong_sha_error = _invoke_guide(
                self._guide_args(
                    plan,
                    review_directory,
                    expected_plan_sha256="f" * 64,
                )
            )
            wrong_decision_code, wrong_decision_output, wrong_decision_error = (
                _invoke_guide(
                    self._guide_args(
                        plan,
                        review_directory,
                        decision="APPROVED",
                    )
                )
            )

            self.assertEqual(wrong_sha_code, 2)
            self.assertEqual(wrong_sha_output, b"")
            self.assertIn("guide request fields are invalid", wrong_sha_error)
            self.assertEqual(wrong_decision_code, 2)
            self.assertEqual(wrong_decision_output, b"")
            self.assertIn("guide request fields are invalid", wrong_decision_error)

    def test_context_activation_guide_fails_closed_for_tampered_or_blocked_review(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            base = Path(temporary)
            plan, review_directory = self._sealed_review(base)
            markdown = review_directory / "review.md"
            markdown.write_bytes(markdown.read_bytes() + b"tampered")

            tampered_code, tampered_output, tampered_error = _invoke_guide(
                self._guide_args(plan, review_directory)
            )

            finding = canonical_curation.CurationFinding(
                finding_id="finding-000000000000000000000001",
                finding_kind="ROLE_AMBIGUOUS",
                relative_path="projects/alpha/notes.md",
                evidence=("explicit role conflict",),
            )
            blocked_base = base / "blocked"
            blocked_base.mkdir(mode=0o700)
            blocked_plan, blocked_review = self._sealed_review(
                blocked_base,
                inner_plan=replace(_plan(), findings=(finding,)),
            )
            blocked_code, blocked_output, blocked_error = _invoke_guide(
                self._guide_args(blocked_plan, blocked_review)
            )

            self.assertEqual(tampered_code, 2)
            self.assertEqual(tampered_output, b"")
            self.assertIn("guide request fields are invalid", tampered_error)
            self.assertEqual(blocked_code, 2)
            self.assertEqual(blocked_output, b"")
            self.assertIn("guide request fields are invalid", blocked_error)

    def test_context_activation_guide_requires_an_interactive_tty(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            plan, review_directory = self._sealed_review(Path(temporary))

            exit_code, output, error = _invoke_guide(
                self._guide_args(plan, review_directory),
                tty=False,
            )

            self.assertEqual(exit_code, 2)
            self.assertEqual(output, b"")
            self.assertIn("curation guide requires an interactive TTY", error)


class ContextActivationPublicEndToEndTest(LedgerRuntimeFixture):
    def setUp(self) -> None:
        with mock.patch.object(tempfile, "tempdir", "/private/tmp"):
            super().setUp()
        self.migrate_to_v2()
        self.project = self.root / "example-service"
        self.target_directory = self.project / "decisions"
        self.target_directory.mkdir(parents=True, mode=0o700)
        self.source = self.project / "loose-decision.md"
        self.target = self.target_directory / self.source.name
        self.source_bytes = b"# Decision\n\nMove this exact document.\n"
        self.source.write_bytes(self.source_bytes)
        self.source.chmod(0o600)
        self.exchange_temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.exchange_temporary.cleanup)
        self.exchange = Path(self.exchange_temporary.name).resolve()
        self.review_directory = self.exchange / "review"
        self.review_directory.mkdir(mode=0o700)

    def _dispatch_file(self, request_file: Path) -> tuple[int, bytes, str]:
        stdout = _TtyStdout(isatty=False)
        stderr = io.StringIO()
        with mock.patch.object(
            sys, "stdin", _TtyStdin(isatty=False)
        ), mock.patch.object(sys, "stdout", stdout), mock.patch.object(
            sys, "stderr", stderr
        ):
            exit_code = mnemosyne.main(
                ["curation", "dispatch", "--request-file", str(request_file)]
            )
        return exit_code, stdout.buffer.getvalue(), stderr.getvalue()

    def test_public_guide_request_file_dispatch_and_result_readback_move_one_file(self):
        inspection = workstream_curation.inspect_workstream(
            root=self.root,
            workstream_ref="example-service",
            review_package_directory=self.review_directory,
            max_items=16,
            max_depth=4,
            max_hint_bytes=4096,
            actor="context-public-e2e-test",
        )
        plan_sha256 = inspection["result"]["plan"]["sha256"]

        guide_code, guide_output, guide_error = _invoke_guide(
            [
                "curation",
                "guide",
                "--draft",
                "context-activation",
                "--root",
                str(self.root),
                "--actor",
                "context-public-e2e-test",
                "--review-package",
                str(self.review_directory),
                "--expected-plan-sha256",
                plan_sha256,
                "--decision",
                "APPROVE_ALL",
            ]
        )
        self.assertEqual(guide_code, 0, guide_error)
        request_raw = (
            guide_output.decode("utf-8").splitlines()[-1].encode("utf-8") + b"\n"
        )
        request = operation_contract.codec.decode_operation_request(request_raw)
        request_file = self.exchange / "context-activation-request.json"
        request_file.write_bytes(request_raw)
        request_file.chmod(0o600)

        dispatch_code, outcome_raw, dispatch_error = self._dispatch_file(request_file)

        self.assertEqual(dispatch_code, 0, dispatch_error)
        self.assertEqual(request_file.stat().st_mode & 0o777, 0o600)
        outcome = json.loads(outcome_raw)
        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertEqual(outcome["request_sha256"], request.sha256)
        self.assertEqual(outcome["result"]["status"], "FINALIZED")
        self.assertEqual(outcome["result"]["plan_sha256"], plan_sha256)
        self.assertFalse(self.source.exists())
        self.assertEqual(self.target.read_bytes(), self.source_bytes)
        transaction = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "transactions"
            / ("p-" + plan_sha256)
        )
        result = json.loads((transaction / "result.json").read_bytes())
        self.assertEqual(result["status"], "FINALIZED")
        self.assertEqual(result["plan_sha256"], plan_sha256)


if __name__ == "__main__":
    unittest.main()
