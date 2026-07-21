import hashlib
import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    activation_contract,
    artifact_contract,
    control,
    ledger_schema,
    operation_contract,
)
from mnemosyne_core import authority_runtime, ledger_runtime  # noqa: E402
from mnemosyne_core.authority_runtime import activation as activation_runtime  # noqa: E402
from mnemosyne_core.cli.request_builder import build_activation_request  # noqa: E402
from mnemosyne_core.operation_control import composition  # noqa: E402


BASE_REGISTRY = b"""schema_version: 1
root: {root}
registry_root: {root}/_registry
inbox: {root}/inbox
memory_workspaces: {root}/memory/workspaces.yml
workstreams:
  - id: example-service
    lifecycle: active
    project_home: {root}/example-service
    aliases: []
never_touch:
  - worktrees/
  - graphify-out/
categories:
  - id: projects
    target: {root}/projects
    patterns:
      - projects/**
"""


class _BinaryStdout:
    def __init__(self, *, isatty: bool = False) -> None:
        self.buffer = io.BytesIO()
        self._isatty = isatty

    def write(self, value: str) -> int:
        return self.buffer.write(value.encode("utf-8"))

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return self._isatty


class _BinaryStdin:
    def __init__(self, *, isatty: bool = False) -> None:
        self.buffer = io.BytesIO()
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


class _InjectedActivationCrash(BaseException):
    pass


def _filesystem_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    entries = [root, *sorted(root.rglob("*"))]
    captured = []
    for path in entries:
        info = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        digest = None
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        captured.append(
            (
                relative,
                stat.S_IFMT(info.st_mode),
                stat.S_IMODE(info.st_mode),
                info.st_uid,
                info.st_nlink,
                info.st_size,
                digest,
            )
        )
    return tuple(captured)


class SafeLibrarianActivationPublicTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.registry_directory = self.root / "_registry"
        self.registry_directory.mkdir(mode=0o755)
        self.registry_raw = BASE_REGISTRY.replace(
            b"{root}", str(self.root).encode("utf-8")
        )
        self.registry_path = self.registry_directory / "placement-map.yml"
        self.registry_path.write_bytes(self.registry_raw)
        self.registry_path.chmod(0o644)
        self.corpus_path = self.root / "inbox" / "existing-note.md"
        self.corpus_path.parent.mkdir(mode=0o755)
        self.corpus_bytes = b"# Existing note\nThis must remain unchanged.\n"
        self.corpus_path.write_bytes(self.corpus_bytes)
        self.corpus_path.chmod(0o644)
        self.exchange_directory = Path(
            self.enterContext(tempfile.TemporaryDirectory())
        ).resolve()

    def _invoke(
        self,
        argv: list[str],
        *,
        stdin_isatty: bool = False,
        stdout_isatty: bool = False,
    ) -> tuple[int, bytes, str]:
        captured_stdout = _BinaryStdout(isatty=stdout_isatty)
        captured_stderr = io.StringIO()
        captured_stdin = _BinaryStdin(isatty=stdin_isatty)
        with mock.patch.object(sys, "stdin", captured_stdin), mock.patch.object(
            sys, "stdout", captured_stdout
        ), mock.patch.object(sys, "stderr", captured_stderr):
            try:
                exit_code = mnemosyne.main(argv)
            except SystemExit as exc:
                exit_code = int(exc.code)
        return exit_code, captured_stdout.buffer.getvalue(), captured_stderr.getvalue()

    def _activate_via_public_cli(
        self,
    ) -> tuple[operation_contract.OperationRequest, dict[str, object]]:
        audit_code, audit_output, audit_error = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )
        self.assertEqual(audit_code, 0, audit_error)
        audit_file = self.exchange_directory / "activation-audit.json"
        audit_file.write_bytes(audit_output)
        audit_file.chmod(0o600)

        guide_code, guide_output, guide_error = self._invoke(
            [
                "curation",
                "guide",
                "--draft",
                "activation",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--audit-file",
                str(audit_file),
            ],
            stdin_isatty=True,
            stdout_isatty=True,
        )
        self.assertEqual(guide_code, 0, guide_error)
        request_raw = guide_output.splitlines()[-1] + b"\n"
        request = operation_contract.codec.decode_operation_request(request_raw)
        request_file = self.exchange_directory / "activation-request.json"
        request_file.write_bytes(request_raw)
        request_file.chmod(0o600)

        dispatch_code, dispatch_output, dispatch_error = self._invoke(
            [
                "curation",
                "dispatch",
                "--request-file",
                str(request_file),
            ]
        )
        self.assertEqual(dispatch_code, 0, dispatch_error)
        outcome = json.loads(dispatch_output.decode("utf-8"))
        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertEqual(outcome["request_sha256"], request.sha256)
        return request, outcome

    def test_public_fresh_audit_is_read_only_and_activation_eligible(self) -> None:
        before = _filesystem_snapshot(self.root)

        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--max-items",
                "64",
                "--json",
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        self.assertEqual(stderr, "")
        outcome = json.loads(output.decode("utf-8"))
        self.assertEqual(outcome["outcome_kind"], "completed")
        result = outcome["result"]
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["view"], "audit")
        self.assertIs(result["read_only"], True)
        self.assertEqual(result["exact_root"], str(self.root))
        self.assertEqual(result["activation_state"], "NOT_ACTIVATED")
        self.assertIs(result["activation_eligible"], True)
        self.assertEqual(result["reason_code"], "FRESH_CURATION_STATE")
        self.assertEqual(result["allowed_namespace"], "_registry/curation")
        self.assertEqual(result["corpus_effect"], "none")
        self.assertEqual(
            result["initial_policy"]["mode"],
            "safe-librarian-initial-curation-v1",
        )
        self.assertEqual(
            result["initial_policy"]["registry_input_sha256"],
            hashlib.sha256(self.registry_raw).hexdigest(),
        )
        self.assertEqual(_filesystem_snapshot(self.root), before)
        self.assertFalse((self.registry_directory / "curation").exists())
        self.assertEqual(self.corpus_path.read_bytes(), self.corpus_bytes)

    def test_tty_guide_drafts_exact_activation_from_fresh_audit_without_execution(
        self,
    ) -> None:
        audit_code, audit_output, audit_error = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )
        self.assertEqual(audit_code, 0, audit_error)
        audit_value = json.loads(audit_output.decode("utf-8"))
        audit_file = self.exchange_directory / "audit.json"
        audit_file.write_bytes(audit_output)
        audit_file.chmod(0o600)
        before = _filesystem_snapshot(self.root)

        with mock.patch.object(
            mnemosyne._mnemosyne_core,
            "execute_request_bytes",
            side_effect=AssertionError("activation guide must not call the executor"),
        ) as executor:
            exit_code, output, stderr = self._invoke(
                [
                    "curation",
                    "guide",
                    "--draft",
                    "activation",
                    "--root",
                    str(self.root),
                    "--actor",
                    "operator",
                    "--audit-file",
                    str(audit_file),
                ],
                stdin_isatty=True,
                stdout_isatty=True,
            )

        self.assertEqual(exit_code, 0, stderr)
        self.assertEqual(stderr, "")
        executor.assert_not_called()
        lines = output.decode("utf-8").splitlines()
        request = operation_contract.codec.decode_operation_request(
            lines[-1].encode("utf-8") + b"\n"
        )
        self.assertEqual(request.operation_kind, "curation.activation")
        self.assertIs(request.action, operation_contract.LifecycleAction.APPLY)
        self.assertIs(request.claim_mode, operation_contract.ClaimMode.CURRENT)
        self.assertEqual(request.root, str(self.root))
        self.assertEqual(request.actor, "operator")
        self.assertIs(
            request.requested_authority,
            operation_contract.AuthorityMode.WRITE,
        )
        self.assertRegex(request.scope["activation_id"], r"^act-[0-9a-f]{32}$")
        self.assertEqual(
            dict(request.payload),
            {
                "allowed_namespace": "_registry/curation",
                "corpus_effect": "none",
                "initial_policy": audit_value["result"]["initial_policy"],
                "root_identity_sha256": audit_value["result"][
                    "root_identity_sha256"
                ],
            },
        )
        self.assertEqual(dict(request.bounds), {})
        self.assertIsNone(request.approval_artifact)
        self.assertEqual(request.prerequisite_artifacts, ())
        guidance = "\n".join(lines[:-1])
        self.assertIn(f"exact root: {self.root}", guidance)
        self.assertIn(
            f"activation id: {request.scope['activation_id']}",
            guidance,
        )
        self.assertIn("_registry/curation", guidance)
        self.assertIn("corpus effect: none", guidance)
        self.assertIn("has not been executed", guidance)
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_activation_admission_never_falls_through_to_legacy_writer(self) -> None:
        audit_code, audit_output, audit_error = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )
        self.assertEqual(audit_code, 0, audit_error)
        audit_result = json.loads(audit_output.decode("utf-8"))["result"]
        request = build_activation_request(
            root=str(self.root),
            actor="operator",
            activation_id="act-0123456789abcdef0123456789abcdef",
            audit_result=audit_result,
        )
        contract = composition.DEFAULT_OPERATION_CATALOG.require_spec(
            "curation.activation"
        ).admission_contract
        before = _filesystem_snapshot(self.root)

        with mock.patch.object(
            ledger_runtime,
            "open_writer_session",
            side_effect=AssertionError("activation reached the legacy writer"),
        ) as legacy_writer:
            admitted = authority_runtime.admit(request, contract)

        legacy_writer.assert_not_called()
        self.assertEqual(admitted.request_sha256, request.sha256)
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_a2_catalog_exposes_only_the_closed_activation_owner(self) -> None:
        spec = composition.DEFAULT_OPERATION_CATALOG.require_spec(
            "curation.activation"
        )

        self.assertIs(
            spec.availability,
            composition.OperationAvailability.AVAILABLE,
        )
        self.assertIs(spec.handler, activation_contract.activation_handler)
        self.assertIs(
            spec.request_validator,
            activation_contract.validate_activation_request,
        )
        self.assertIs(
            spec.result_validator,
            activation_contract.validate_activation_result,
        )

    def test_each_public_legacy_sentinel_is_blocked_without_mutation(self) -> None:
        sentinels = (
            ("placement-map.lock", "file"),
            ("lock-migrations", "directory"),
            ("curation-runs", "directory"),
        )
        for name, entry_kind in sentinels:
            with self.subTest(sentinel=name):
                legacy = self.registry_directory / name
                if entry_kind == "file":
                    legacy.write_bytes(b"legacy authority evidence\n")
                    legacy.chmod(0o600)
                else:
                    legacy.mkdir(mode=0o700)
                try:
                    before = _filesystem_snapshot(self.root)

                    exit_code, output, stderr = self._invoke(
                        [
                            "curation",
                            "inspect",
                            "audit",
                            "--root",
                            str(self.root),
                            "--actor",
                            "operator",
                            "--json",
                        ]
                    )

                    self.assertEqual(exit_code, 0, stderr)
                    result = json.loads(output.decode("utf-8"))["result"]
                    self.assertEqual(result["schema_version"], 2)
                    self.assertEqual(result["activation_state"], "BLOCKED")
                    self.assertFalse(result["activation_eligible"])
                    self.assertEqual(
                        result["reason_code"],
                        "LEGACY_AUTHORITY_PRESENT",
                    )
                    self.assertIsNone(result["initial_policy"])
                    self.assertEqual(_filesystem_snapshot(self.root), before)
                finally:
                    if entry_kind == "file":
                        legacy.unlink()
                    else:
                        legacy.rmdir()

    def test_public_preseal_orphan_requires_manual_recovery_without_mutation(
        self,
    ) -> None:
        (self.registry_directory / "curation").mkdir(mode=0o700)
        before = _filesystem_snapshot(self.root)

        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        result = json.loads(output.decode("utf-8"))["result"]
        self.assertEqual(result["activation_state"], "RECOVERY_REQUIRED")
        self.assertFalse(result["activation_eligible"])
        self.assertEqual(result["reason_code"], "PRESEAL_ORPHAN")
        self.assertEqual(
            result["next_safe_action"],
            "Review the pre-seal activation namespace manually.",
        )
        self.assertIsNone(result["initial_policy"])
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_public_unknown_activation_member_is_a_typed_manual_fence(self) -> None:
        curation = self.registry_directory / "curation"
        curation.mkdir(mode=0o700)
        unknown = curation / "unknown-member.bin"
        unknown.write_bytes(b"unknown activation evidence\n")
        unknown.chmod(0o600)
        before = _filesystem_snapshot(self.root)

        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        result = json.loads(output.decode("utf-8"))["result"]
        self.assertEqual(result["activation_state"], "BLOCKED")
        self.assertFalse(result["activation_eligible"])
        self.assertEqual(result["reason_code"], "UNKNOWN_AUTHORITY_MEMBER")
        self.assertEqual(
            result["next_safe_action"],
            "Review the activation foundation manually.",
        )
        self.assertIsNone(result["initial_policy"])
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_public_sealed_partial_requires_the_exact_request_without_mutation(
        self,
    ) -> None:
        audit_code, audit_output, audit_error = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )
        self.assertEqual(audit_code, 0, audit_error)
        audit = json.loads(audit_output.decode("utf-8"))["result"]
        request = build_activation_request(
            root=str(self.root),
            actor="operator",
            activation_id="act-0123456789abcdef0123456789abcdef",
            audit_result=audit,
        )

        def crash_after_request(boundary: str) -> None:
            if boundary == "A3":
                raise _InjectedActivationCrash

        with mock.patch.object(
            activation_runtime,
            "_checkpoint",
            side_effect=crash_after_request,
        ):
            with self.assertRaises(_InjectedActivationCrash):
                mnemosyne._mnemosyne_core.execute_request_bytes(
                    request.canonical_bytes
                )
        before = _filesystem_snapshot(self.root)

        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        result = json.loads(output.decode("utf-8"))["result"]
        self.assertEqual(result["activation_state"], "RECOVERY_REQUIRED")
        self.assertFalse(result["activation_eligible"])
        self.assertEqual(result["reason_code"], "RECOVERY_SAME_REQUEST_ONLY")
        self.assertEqual(
            result["next_safe_action"],
            "Resend the exact sealed activation request.",
        )
        self.assertIsNone(result["initial_policy"])
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_active_runtime_cannot_hide_co_present_legacy_evidence(self) -> None:
        (self.registry_directory / "curation").mkdir(mode=0o700)
        legacy = self.registry_directory / "placement-map.lock"
        legacy.write_bytes(b"legacy authority evidence\n")
        legacy.chmod(0o600)
        before = _filesystem_snapshot(self.root)

        evidence = activation_runtime.capture_audit_evidence(
            self.root,
            runtime_state="ACTIVE",
        )

        self.assertEqual(evidence.activation_state, "BLOCKED")
        self.assertFalse(evidence.activation_eligible)
        self.assertEqual(evidence.reason_code, "LEGACY_AUTHORITY_PRESENT")
        self.assertIsNone(evidence.initial_policy)
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_public_missing_registry_input_is_blocked_without_mutation(self) -> None:
        self.registry_path.unlink()
        before = _filesystem_snapshot(self.root)

        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        result = json.loads(output.decode("utf-8"))["result"]
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["activation_state"], "BLOCKED")
        self.assertFalse(result["activation_eligible"])
        self.assertEqual(result["reason_code"], "UNSAFE_BOUNDARY")
        self.assertIsNone(result["initial_policy"])
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_public_explicit_curation_policy_requires_review_without_mutation(
        self,
    ) -> None:
        self.registry_path.write_bytes(
            self.registry_raw + b"curation:\n  profile_version: 1\n"
        )
        self.registry_path.chmod(0o644)
        before = _filesystem_snapshot(self.root)

        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        result = json.loads(output.decode("utf-8"))["result"]
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["activation_state"], "BLOCKED")
        self.assertFalse(result["activation_eligible"])
        self.assertEqual(
            result["reason_code"],
            "EXPLICIT_CURATION_REQUIRES_REVIEW",
        )
        self.assertIsNone(result["initial_policy"])
        self.assertEqual(_filesystem_snapshot(self.root), before)

    def test_activation_handler_exposes_only_one_receipt_capability(self) -> None:
        request_sha256 = "a" * 64
        reference = artifact_contract.SealedArtifactRef(
            schema=activation_contract.RECEIPT_SCHEMA,
            canonical_path="_registry/curation/activation/v1/receipt.json",
            artifact_sha256="b" * 64,
            manifest_sha256="c" * 64,
            producer_operation_sha256=request_sha256,
            byte_length=123,
            media_type="application/json",
        )
        session = SimpleNamespace(activate=mock.Mock(return_value=reference))

        outcome = activation_contract.activation_handler(
            SimpleNamespace(request_sha256=request_sha256),
            session,
        )

        session.activate.assert_called_once_with()
        self.assertEqual(outcome.outcome_kind, "completed")
        self.assertEqual(outcome.request_sha256, request_sha256)
        self.assertEqual(
            outcome.result_artifact["canonical_path"],
            "_registry/curation/activation/v1/receipt.json",
        )
        activation_contract.validate_activation_result(outcome)

    def test_activation_result_rejects_a_receipt_from_another_request(self) -> None:
        reference = artifact_contract.SealedArtifactRef(
            schema=activation_contract.RECEIPT_SCHEMA,
            canonical_path="_registry/curation/activation/v1/receipt.json",
            artifact_sha256="b" * 64,
            manifest_sha256="c" * 64,
            producer_operation_sha256="d" * 64,
            byte_length=123,
            media_type="application/json",
        )
        outcome = operation_contract.OperationOutcome.completed(
            "a" * 64,
            result_artifact=reference,
        )

        with self.assertRaisesRegex(ValueError, "activation receipt reference"):
            activation_contract.validate_activation_result(outcome)

    def test_one_audit_v2_contract_validates_active_and_blocked_combinations(
        self,
    ) -> None:
        audit_code, audit_output, audit_error = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )
        self.assertEqual(audit_code, 0, audit_error)
        fresh = json.loads(audit_output.decode("utf-8"))["result"]

        active = dict(fresh)
        active.update(
            {
                "activation_state": "ACTIVE",
                "activation_eligible": False,
                "reason_code": "ALREADY_ACTIVE",
                "next_safe_action": "Inspect one bounded scope.",
                "initial_policy": None,
            }
        )
        self.assertEqual(
            activation_contract.require_audit_result(active),
            active,
        )
        forged_active = dict(active)
        forged_active["activation_eligible"] = True
        with self.assertRaisesRegex(ValueError, "activation audit result"):
            activation_contract.require_audit_result(forged_active)

        blocked = dict(active)
        blocked.update(
            {
                "activation_state": "BLOCKED",
                "reason_code": "LEGACY_AUTHORITY_PRESENT",
                "next_safe_action": "Review existing authority evidence manually.",
                "integrity_ok": False,
            }
        )
        self.assertEqual(
            activation_contract.require_audit_result(blocked),
            blocked,
        )
        forged_blocked = dict(blocked)
        forged_blocked["initial_policy"] = fresh["initial_policy"]
        with self.assertRaisesRegex(ValueError, "activation audit result"):
            activation_contract.require_audit_result(forged_blocked)

        recovery = dict(active)
        recovery.update(
            {
                "activation_state": "RECOVERY_REQUIRED",
                "reason_code": "PRESEAL_ORPHAN",
                "next_safe_action": (
                    "Review the pre-seal activation namespace manually."
                ),
                "integrity_ok": False,
            }
        )
        self.assertEqual(
            activation_contract.require_audit_result(recovery),
            recovery,
        )
        same_request = dict(recovery)
        same_request.update(
            {
                "reason_code": "RECOVERY_SAME_REQUEST_ONLY",
                "next_safe_action": "Resend the exact sealed activation request.",
            }
        )
        self.assertEqual(
            activation_contract.require_audit_result(same_request),
            same_request,
        )
        forged_recovery = dict(recovery)
        forged_recovery["reason_code"] = "REQUEST_MISMATCH"
        with self.assertRaisesRegex(ValueError, "activation audit result"):
            activation_contract.require_audit_result(forged_recovery)

    def test_fresh_activation_creates_one_v2_foundation_and_replays_read_only(
        self,
    ) -> None:
        audit_code, audit_output, audit_error = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )
        self.assertEqual(audit_code, 0, audit_error)
        audit_result = json.loads(audit_output.decode("utf-8"))["result"]
        request = build_activation_request(
            root=str(self.root),
            actor="operator",
            activation_id="act-0123456789abcdef0123456789abcdef",
            audit_result=audit_result,
        )
        request_file = self.exchange_directory / "activation-request.json"
        request_file.write_bytes(request.canonical_bytes)
        request_file.chmod(0o600)
        registry_before = self.registry_path.read_bytes()
        corpus_before = self.corpus_path.read_bytes()

        exit_code, output, stderr = self._invoke(
            [
                "curation",
                "dispatch",
                "--request-file",
                str(request_file),
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        outcome = json.loads(output.decode("utf-8"))
        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertEqual(outcome["request_sha256"], request.sha256)
        self.assertEqual(
            outcome["result_artifact"]["schema"]["kind"],
            "SAFE_LIBRARIAN_ACTIVATION_RECEIPT",
        )
        self.assertEqual(
            outcome["result_artifact"]["canonical_path"],
            "_registry/curation/activation/v1/receipt.json",
        )
        self.assertEqual(self.registry_path.read_bytes(), registry_before)
        self.assertEqual(self.corpus_path.read_bytes(), corpus_before)
        curation_root = self.registry_directory / "curation"
        self.assertEqual(
            {
                path.relative_to(curation_root).as_posix()
                for path in curation_root.rglob("*")
            },
            {
                "activation",
                "activation/v1",
                "activation/v1/request.json",
                "activation/v1/receipt.json",
                "activation/v1/staging",
                "ledger.lock",
                "ledger.sqlite3",
                "policy.lock",
            },
        )
        for directory in (
            curation_root,
            curation_root / "activation",
            curation_root / "activation" / "v1",
            curation_root / "activation" / "v1" / "staging",
        ):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for file_path in (
            curation_root / "activation" / "v1" / "request.json",
            curation_root / "activation" / "v1" / "receipt.json",
            curation_root / "ledger.lock",
            curation_root / "ledger.sqlite3",
            curation_root / "policy.lock",
        ):
            info = file_path.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
        receipt_raw = (
            curation_root / "activation" / "v1" / "receipt.json"
        ).read_bytes()
        receipt = activation_contract.require_activation_receipt_bytes(
            receipt_raw,
            request=request,
            expected_uid=os.getuid(),
        )
        self.assertEqual(receipt["request_sha256"], request.sha256)
        connection = sqlite3.connect(
            "file:%s?mode=ro" % (curation_root / "ledger.sqlite3"),
            uri=True,
        )
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT version, schema_sha256, applied_by_bootstrap_id "
                    "FROM schema_migrations ORDER BY version"
                ).fetchall(),
                [
                    (
                        control.CONTROL_SCHEMA_VERSION,
                        control.CONTROL_SCHEMA_SHA256,
                        request.scope["activation_id"],
                    ),
                    (
                        ledger_schema.LEDGER_SCHEMA_VERSION,
                        ledger_schema.LEDGER_SCHEMA_SHA256,
                        activation_contract.ACTIVATION_V2_SOURCE_ID,
                    ),
                ],
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM control_bootstraps").fetchone(),
                (0,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT generation, source_kind, source_run_id, guard_epoch "
                    "FROM policy_head"
                ).fetchone(),
                (1, "INITIAL", request.scope["activation_id"], 0),
            )
        finally:
            connection.close()
        after_first = _filesystem_snapshot(self.root)

        active_code, active_output, active_error = self._invoke(
            [
                "curation",
                "inspect",
                "audit",
                "--root",
                str(self.root),
                "--actor",
                "operator",
                "--json",
            ]
        )
        self.assertEqual(active_code, 0, active_error)
        active = json.loads(active_output.decode("utf-8"))["result"]
        self.assertEqual(active["activation_state"], "ACTIVE")
        self.assertFalse(active["activation_eligible"])
        self.assertEqual(active["reason_code"], "ALREADY_ACTIVE")

        replay_code, replay_output, replay_error = self._invoke(
            [
                "curation",
                "dispatch",
                "--request-file",
                str(request_file),
            ]
        )
        self.assertEqual(replay_code, 0, replay_error)
        self.assertEqual(
            json.loads(replay_output.decode("utf-8"))["result_artifact"],
            outcome["result_artifact"],
        )
        self.assertEqual(_filesystem_snapshot(self.root), after_first)

    def test_fresh_activation_immediately_enables_bounded_scope_inspection(
        self,
    ) -> None:
        request, activation = self._activate_via_public_cli()
        durable_runtime = self.registry_directory / "curation" / "authority-runtime"
        self.assertFalse(durable_runtime.exists())
        project_home = self.root / "example-service"
        project_home.mkdir(mode=0o755)
        project_document = project_home / "existing-note.md"
        project_document.write_bytes(self.corpus_bytes)
        project_document.chmod(0o644)
        before_inspect = _filesystem_snapshot(self.root)

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
                "--max-items",
                "1",
                "--max-depth",
                "1",
                "--max-hint-bytes",
                "128",
                "--json",
            ]
        )

        self.assertEqual(exit_code, 0, stderr)
        outcome = json.loads(output.decode("utf-8"))
        self.assertEqual(outcome["outcome_kind"], "completed")
        result = outcome["result"]
        self.assertEqual(result["view"], "scope")
        self.assertEqual(result["scope"], {"relative_path": "example-service"})
        self.assertEqual(
            result["bounds"],
            {"max_items": 1, "max_depth": 1, "max_hint_bytes": 128},
        )
        self.assertEqual(result["returned"], 1)
        self.assertFalse(result["truncated"])
        self.assertEqual(
            [item["relative_path"] for item in result["organized"]],
            ["example-service/existing-note.md"],
        )
        self.assertEqual(result["candidates"], [])
        self.assertEqual(self.corpus_path.read_bytes(), self.corpus_bytes)
        self.assertEqual(_filesystem_snapshot(self.root), before_inspect)
        self.assertFalse(durable_runtime.exists())
        self.assertEqual(activation["request_sha256"], request.sha256)


if __name__ == "__main__":
    unittest.main()
