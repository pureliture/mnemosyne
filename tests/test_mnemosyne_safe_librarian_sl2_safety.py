import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
import mnemosyne_core  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    authority_runtime,
    librarian_contract,
    operation_contract,
)
from mnemosyne_core.operation_control import composition  # noqa: E402
from mnemosyne_core.authority_runtime import librarian_snapshot  # noqa: E402

TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
import test_mnemosyne_ledger_runtime as ledger_fixture_module  # noqa: E402
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class SafeLibrarianSl2ProposalSafetyTest(LedgerRuntimeFixture):
    def setUp(self) -> None:
        registry = ledger_fixture_module.BASE_REGISTRY.replace(
            b"never_touch:\n",
            b"  - id: paused-stream\n"
            b"    lifecycle: paused\n"
            b"    project_home: {root}/paused-stream\n"
            b"    aliases: []\n"
            b"never_touch:\n",
        )
        with mock.patch.object(ledger_fixture_module, "BASE_REGISTRY", registry):
            super().setUp()

    def _proposal_request(
        self,
        *,
        proposal_id: str,
        source_relative_path: str,
        target_relative_path: str,
        bounds: dict[str, int] | None = None,
        destination_id: str = "example-service",
    ) -> operation_contract.OperationRequest:
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="librarian.proposal",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={
                "proposal_id": proposal_id,
                "source_relative_path": source_relative_path,
                "target_relative_path": target_relative_path,
            },
            bounds=(
                {
                    "max_entries": 4096,
                    "max_depth": 16,
                    "max_total_bytes": 256 * 1024 * 1024,
                }
                if bounds is None
                else bounds
            ),
            payload={
                "destination_kind": "workstream",
                "destination_id": destination_id,
                "reason": "The exact source belongs to the declared Workstream.",
            },
        )

    def _execute(self, request: operation_contract.OperationRequest) -> dict[str, object]:
        return json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

    def _assert_blocked_without_artifact(
        self,
        outcome: dict[str, object],
        proposal_id: str,
        reason_code: str,
    ) -> None:
        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], reason_code)
        self.assertNotIn("result_artifact", outcome)
        artifact = self.root.joinpath(
            *librarian_contract.proposal_artifact_path(proposal_id).split("/")
        )
        self.assertFalse(artifact.exists())

    def test_directory_entry_bound_stops_without_artifact_or_corpus_change(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "entry-bound"
        source.mkdir(parents=True, mode=0o700)
        first = source / "a.md"
        second = source / "b.md"
        first.write_bytes(b"A\n")
        second.write_bytes(b"B\n")
        first.chmod(0o600)
        second.chmod(0o600)
        target = self.root / "example-service" / "docs" / "entry-bound"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-50000000000000000000000000000001"
        request = self._proposal_request(
            proposal_id=proposal_id,
            source_relative_path="inbox/entry-bound",
            target_relative_path="example-service/docs/entry-bound",
            bounds={"max_entries": 1, "max_depth": 16, "max_total_bytes": 1024},
        )

        outcome = self._execute(request)

        self._assert_blocked_without_artifact(
            outcome,
            proposal_id,
            "SCOPE_LIMIT_EXCEEDED",
        )
        self.assertEqual(first.read_bytes(), b"A\n")
        self.assertEqual(second.read_bytes(), b"B\n")
        self.assertFalse(target.exists())

    def test_directory_depth_bound_stops_without_artifact_or_corpus_change(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "depth-bound"
        nested = source / "nested"
        nested.mkdir(parents=True, mode=0o700)
        document = nested / "note.md"
        document.write_bytes(b"Nested\n")
        document.chmod(0o600)
        target = self.root / "example-service" / "docs" / "depth-bound"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-50000000000000000000000000000002"
        request = self._proposal_request(
            proposal_id=proposal_id,
            source_relative_path="inbox/depth-bound",
            target_relative_path="example-service/docs/depth-bound",
            bounds={"max_entries": 8, "max_depth": 1, "max_total_bytes": 1024},
        )

        outcome = self._execute(request)

        self._assert_blocked_without_artifact(
            outcome,
            proposal_id,
            "SCOPE_LIMIT_EXCEEDED",
        )
        self.assertEqual(document.read_bytes(), b"Nested\n")
        self.assertTrue(nested.is_dir())
        self.assertFalse(target.exists())

    def test_directory_byte_bound_stops_without_artifact_or_corpus_change(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "byte-bound"
        source.mkdir(parents=True, mode=0o700)
        document_bytes = b"Eight!!!\n"
        document = source / "note.md"
        document.write_bytes(document_bytes)
        document.chmod(0o600)
        target = self.root / "example-service" / "docs" / "byte-bound"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-50000000000000000000000000000003"
        request = self._proposal_request(
            proposal_id=proposal_id,
            source_relative_path="inbox/byte-bound",
            target_relative_path="example-service/docs/byte-bound",
            bounds={
                "max_entries": 8,
                "max_depth": 2,
                "max_total_bytes": len(document_bytes) - 1,
            },
        )

        outcome = self._execute(request)

        self._assert_blocked_without_artifact(
            outcome,
            proposal_id,
            "SCOPE_LIMIT_EXCEEDED",
        )
        self.assertEqual(document.read_bytes(), document_bytes)
        self.assertFalse(target.exists())

    def test_source_symlink_is_unsupported_without_artifact_or_corpus_change(self) -> None:
        self.migrate_to_v2()
        inbox = self.root / "inbox"
        inbox.mkdir(mode=0o700)
        real_bytes = b"Real source\n"
        real_source = inbox / "real.md"
        real_source.write_bytes(real_bytes)
        real_source.chmod(0o600)
        source = inbox / "linked.md"
        source.symlink_to("real.md")
        target = self.root / "example-service" / "docs" / "linked.md"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-50000000000000000000000000000004"
        request = self._proposal_request(
            proposal_id=proposal_id,
            source_relative_path="inbox/linked.md",
            target_relative_path="example-service/docs/linked.md",
        )

        outcome = self._execute(request)

        self._assert_blocked_without_artifact(
            outcome,
            proposal_id,
            "SOURCE_UNSUPPORTED",
        )
        self.assertTrue(source.is_symlink())
        self.assertEqual(os.readlink(source), "real.md")
        self.assertEqual(real_source.read_bytes(), real_bytes)
        self.assertFalse(target.exists())

    def test_source_hardlink_is_unsupported_without_artifact_or_corpus_change(self) -> None:
        self.migrate_to_v2()
        inbox = self.root / "inbox"
        inbox.mkdir(mode=0o700)
        source_bytes = b"Shared inode\n"
        original = inbox / "original.md"
        original.write_bytes(source_bytes)
        original.chmod(0o600)
        source = inbox / "hard-linked.md"
        os.link(original, source)
        original_stat = original.stat()
        target = self.root / "example-service" / "docs" / "hard-linked.md"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-50000000000000000000000000000005"
        request = self._proposal_request(
            proposal_id=proposal_id,
            source_relative_path="inbox/hard-linked.md",
            target_relative_path="example-service/docs/hard-linked.md",
        )

        outcome = self._execute(request)

        self._assert_blocked_without_artifact(
            outcome,
            proposal_id,
            "SOURCE_UNSUPPORTED",
        )
        self.assertEqual(original.read_bytes(), source_bytes)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual(source.stat().st_ino, original_stat.st_ino)
        self.assertEqual(source.stat().st_nlink, 2)
        self.assertFalse(target.exists())

    def test_inactive_workstream_source_and_destination_stop_without_artifact(self) -> None:
        self.migrate_to_v2()
        paused = self.root / "paused-stream"
        paused.mkdir(mode=0o700)
        active = self.root / "example-service" / "docs"
        active.mkdir(parents=True, mode=0o700)
        inbox = self.root / "inbox"
        inbox.mkdir(mode=0o700)
        paused_source = paused / "source.md"
        paused_source.write_bytes(b"Paused source\n")
        paused_source.chmod(0o600)
        inbox_source = inbox / "source.md"
        inbox_source.write_bytes(b"Inbox source\n")
        inbox_source.chmod(0o600)
        cases = (
            (
                "p-50000000000000000000000000000006",
                "paused-stream/source.md",
                "example-service/docs/from-paused.md",
                "example-service",
            ),
            (
                "p-50000000000000000000000000000007",
                "inbox/source.md",
                "paused-stream/from-inbox.md",
                "paused-stream",
            ),
        )

        for proposal_id, source_path, target_path, destination_id in cases:
            with self.subTest(source_path=source_path, target_path=target_path):
                request = self._proposal_request(
                    proposal_id=proposal_id,
                    source_relative_path=source_path,
                    target_relative_path=target_path,
                    destination_id=destination_id,
                )

                outcome = self._execute(request)

                self._assert_blocked_without_artifact(
                    outcome,
                    proposal_id,
                    "WORKSTREAM_INACTIVE",
                )
                self.assertFalse(self.root.joinpath(*target_path.split("/")).exists())

        self.assertEqual(paused_source.read_bytes(), b"Paused source\n")
        self.assertEqual(inbox_source.read_bytes(), b"Inbox source\n")

    def test_safe_librarian_record_session_hides_generic_durable_methods(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "session.md"
        source.parent.mkdir(mode=0o700)
        source.write_bytes(b"Session boundary\n")
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "session.md"
        target.parent.mkdir(parents=True, mode=0o700)
        request = self._proposal_request(
            proposal_id="p-50000000000000000000000000000008",
            source_relative_path="inbox/session.md",
            target_relative_path="example-service/docs/session.md",
        )
        contract = composition.DEFAULT_OPERATION_CATALOG.require_spec(
            "librarian.proposal"
        ).admission_contract
        admitted = authority_runtime.admit(request, contract)

        with authority_runtime.open_write(admitted) as session:
            self.assertTrue(callable(session.observe_librarian_proposal))
            for method_name in ("prepare", "publish", "finalize", "recover"):
                with self.subTest(method_name=method_name):
                    self.assertFalse(hasattr(session, method_name))

        self.assertEqual(source.read_bytes(), b"Session boundary\n")
        self.assertFalse(target.exists())

    def test_policy_drift_before_publication_creates_no_proposal_or_corpus_change(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "policy-drift.md"
        source.parent.mkdir(mode=0o700)
        source_bytes = b"Policy drift source\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "policy-drift.md"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-50000000000000000000000000000009"
        request = self._proposal_request(
            proposal_id=proposal_id,
            source_relative_path="inbox/policy-drift.md",
            target_relative_path="example-service/docs/policy-drift.md",
        )
        original_observe = librarian_snapshot.observe_proposal
        observations = 0

        def observe_then_drift(*args, **kwargs):
            nonlocal observations
            result = original_observe(*args, **kwargs)
            observations += 1
            if observations == 1:
                current = self.registry_path.read_bytes()
                self.registry_path.write_bytes(current + b"\n")
                self.registry_path.chmod(0o600)
            return result

        with mock.patch.object(
            librarian_snapshot,
            "observe_proposal",
            side_effect=observe_then_drift,
        ):
            outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "ADMISSION_DENIED")
        self._assert_blocked_without_artifact(
            outcome,
            proposal_id,
            "ADMISSION_DENIED",
        )
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_hard_protected_source_returns_typed_scope_stop(self) -> None:
        self.migrate_to_v2()
        protected = self.root / "graphify-out"
        protected.mkdir(mode=0o700)
        source = protected / "protected.md"
        source_bytes = b"Protected source\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "protected.md"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-50000000000000000000000000000010"
        request = self._proposal_request(
            proposal_id=proposal_id,
            source_relative_path="graphify-out/protected.md",
            target_relative_path="example-service/docs/protected.md",
        )

        outcome = self._execute(request)

        self._assert_blocked_without_artifact(
            outcome,
            proposal_id,
            "SCOPE_UNSAFE",
        )
        self.assertEqual(outcome["next_safe_action"], "choose-scope")
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_source_change_before_publication_returns_typed_stop(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "source-change.md"
        source.parent.mkdir(mode=0o700)
        original_bytes = b"Original source\n"
        changed_bytes = b"Changed source\n"
        source.write_bytes(original_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "source-change.md"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-50000000000000000000000000000011"
        request = self._proposal_request(
            proposal_id=proposal_id,
            source_relative_path="inbox/source-change.md",
            target_relative_path="example-service/docs/source-change.md",
        )
        original_observe = librarian_snapshot.observe_proposal
        observations = 0

        def observe_then_change(*args, **kwargs):
            nonlocal observations
            result = original_observe(*args, **kwargs)
            observations += 1
            if observations == 1:
                source.write_bytes(changed_bytes)
                source.chmod(0o600)
            return result

        with mock.patch.object(
            librarian_snapshot,
            "observe_proposal",
            side_effect=observe_then_change,
        ):
            outcome = self._execute(request)

        self._assert_blocked_without_artifact(
            outcome,
            proposal_id,
            "SOURCE_CHANGED",
        )
        self.assertEqual(outcome["next_safe_action"], "create-proposal")
        self.assertEqual(source.read_bytes(), changed_bytes)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
