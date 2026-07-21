import json
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
import mnemosyne_core  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    artifact_contract,
    librarian_contract,
    librarian_placement,
    operation_contract,
)
from mnemosyne_core.authority_runtime import durable  # noqa: E402


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402
import test_mnemosyne_safe_librarian_sl3 as _sl3  # noqa: E402


class SimulatedPlacementCrash(RuntimeError):
    pass


class SafeLibrarianSl3RecoveryRedTest(LedgerRuntimeFixture):
    _artifact_path = staticmethod(_sl3.SafeLibrarianSl3PlacementRedTest._artifact_path)
    _artifact_file = _sl3.SafeLibrarianSl3PlacementRedTest._artifact_file
    _execute = _sl3.SafeLibrarianSl3PlacementRedTest._execute
    _reference = _sl3.SafeLibrarianSl3PlacementRedTest._reference
    _publish_proposal = _sl3.SafeLibrarianSl3PlacementRedTest._publish_proposal
    _decision_request = _sl3.SafeLibrarianSl3PlacementRedTest._decision_request
    _publish_decision = _sl3.SafeLibrarianSl3PlacementRedTest._publish_decision
    _placement_request = _sl3.SafeLibrarianSl3PlacementRedTest._placement_request

    def _approved_file_request(
        self,
        *,
        proposal_id: str,
        decision_id: str,
        name: str,
    ) -> tuple[operation_contract.OperationRequest, Path, Path, bytes]:
        self.migrate_to_v2()
        proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name=name)
        )
        _decision_request, decision_ref = self._publish_decision(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id=decision_id,
            decision="APPROVED",
        )
        return (
            self._placement_request(
                proposal_request=proposal_request,
                proposal_reference=proposal_ref,
                decision_reference=decision_ref,
            ),
            source,
            target,
            source_bytes,
        )

    def _recovery_request(
        self,
        request: operation_contract.OperationRequest,
        recoverable: dict[str, object],
    ) -> operation_contract.OperationRequest:
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind=request.operation_kind,
            action=operation_contract.LifecycleAction.RECOVER,
            claim_mode=request.claim_mode,
            root=request.root,
            actor=request.actor,
            requested_authority=request.requested_authority,
            scope=dict(request.scope),
            bounds={},
            payload={
                "recovery": {
                    "continuation_identity": recoverable["continuation_identity"],
                    "producer_request_sha256": request.sha256,
                }
            },
            approval_artifact=request.approval_artifact,
            prerequisite_artifacts=request.prerequisite_artifacts,
        )

    def test_bounded_directory_placement_moves_the_exact_tree_once(self) -> None:
        self.migrate_to_v2()
        proposal_id = "p-81000000000000000000000000000001"
        source = self.root / "inbox" / "bundle"
        nested = source / "nested"
        nested.mkdir(parents=True, mode=0o700)
        first = source / "README.md"
        second = nested / "guide.md"
        first_bytes = b"# Bundle\nExact directory content.\n"
        second_bytes = b"# Guide\nNested exact content.\n"
        first.write_bytes(first_bytes)
        second.write_bytes(second_bytes)
        first.chmod(0o600)
        second.chmod(0o600)
        target = self.root / "example-service" / "docs" / "bundle"
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="librarian.proposal",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={
                "proposal_id": proposal_id,
                "source_relative_path": "inbox/bundle",
                "target_relative_path": "example-service/docs/bundle",
            },
            bounds={
                "max_entries": 4,
                "max_depth": 2,
                "max_total_bytes": 1024,
            },
            payload={
                "destination_kind": "workstream",
                "destination_id": "example-service",
                "reason": (
                    "The bounded bundle belongs to the example-service "
                    "Workstream."
                ),
            },
        )
        proposal_outcome = self._execute(request)
        self.assertEqual(
            proposal_outcome["outcome_kind"],
            "completed",
            proposal_outcome,
        )
        proposal_ref = self._reference(proposal_outcome["result_artifact"])
        _decision_request, decision_ref = self._publish_decision(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-81000000000000000000000000000001",
            decision="APPROVED",
        )
        placement = self._placement_request(
            proposal_request=request,
            proposal_reference=proposal_ref,
            decision_reference=decision_ref,
        )
        source_identity = (source.stat().st_dev, source.stat().st_ino)
        nested_identity = (nested.stat().st_dev, nested.stat().st_ino)

        outcome = self._execute(placement)

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        result_ref = self._reference(outcome["result_artifact"])
        self.assertEqual(result_ref.schema, librarian_contract.RESULT_SCHEMA)
        self.assertEqual(
            result_ref.canonical_path,
            librarian_contract.result_artifact_path(proposal_id),
        )
        self.assertFalse(source.exists())
        self.assertEqual(target.joinpath("README.md").read_bytes(), first_bytes)
        target_nested = target.joinpath("nested")
        self.assertEqual(target_nested.joinpath("guide.md").read_bytes(), second_bytes)
        self.assertEqual((target.stat().st_dev, target.stat().st_ino), source_identity)
        self.assertEqual(
            (target_nested.stat().st_dev, target_nested.stat().st_ino),
            nested_identity,
        )

    def test_after_intent_crash_exact_apply_retry_moves_once_and_completes(
        self,
    ) -> None:
        proposal_id = "p-81000000000000000000000000000002"
        request, source, target, source_bytes = self._approved_file_request(
            proposal_id=proposal_id,
            decision_id="d-81000000000000000000000000000002",
            name="after-intent.md",
        )
        source_identity = (source.stat().st_dev, source.stat().st_ino)

        def interrupt(point: str) -> None:
            if point == "after-intent":
                raise SimulatedPlacementCrash("after intent")

        with mock.patch.object(
            librarian_placement,
            "_run_checkpoint",
            side_effect=interrupt,
        ):
            with self.assertRaises(SimulatedPlacementCrash):
                self._execute(request)

        self.assertTrue(self._artifact_file("intents", proposal_id).is_file())
        self.assertFalse(self._artifact_file("results", proposal_id).exists())
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual((target.stat().st_dev, target.stat().st_ino), source_identity)
        self.assertTrue(self._artifact_file("results", proposal_id).is_file())

    def test_after_rename_crash_exact_apply_retry_finishes_without_second_rename(
        self,
    ) -> None:
        proposal_id = "p-81000000000000000000000000000003"
        request, source, target, source_bytes = self._approved_file_request(
            proposal_id=proposal_id,
            decision_id="d-81000000000000000000000000000003",
            name="after-rename.md",
        )
        source_identity = (source.stat().st_dev, source.stat().st_ino)

        def interrupt(point: str) -> None:
            if point == "after-rename":
                raise SimulatedPlacementCrash("after rename")

        with mock.patch.object(
            librarian_placement,
            "_run_checkpoint",
            side_effect=interrupt,
        ):
            with self.assertRaises(SimulatedPlacementCrash):
                self._execute(request)

        target_identity = (target.stat().st_dev, target.stat().st_ino)
        self.assertTrue(self._artifact_file("intents", proposal_id).is_file())
        self.assertFalse(self._artifact_file("results", proposal_id).exists())
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual(target_identity, source_identity)

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual((target.stat().st_dev, target.stat().st_ino), target_identity)
        self.assertTrue(self._artifact_file("results", proposal_id).is_file())

    def test_d1a_result_publish_recovery_exposes_no_private_effect_and_apply_replays(
        self,
    ) -> None:
        proposal_id = "p-81000000000000000000000000000004"
        request, source, target, source_bytes = self._approved_file_request(
            proposal_id=proposal_id,
            decision_id="d-81000000000000000000000000000004",
            name="result-recovery.md",
        )
        after_publish_count = 0

        def interrupt_result_publish(point: str) -> None:
            nonlocal after_publish_count
            if point != "after-publish":
                return
            after_publish_count += 1
            if after_publish_count == 2:
                raise SimulatedPlacementCrash("after result publication")

        with mock.patch.object(
            durable,
            "_run_checkpoint",
            side_effect=interrupt_result_publish,
        ):
            first_raw = mnemosyne_core.execute_request_bytes(request.canonical_bytes)
        first = json.loads(first_raw.decode("utf-8"))

        self.assertEqual(after_publish_count, 2)
        self.assertEqual(first["outcome_kind"], "recoverable", first)
        self.assertEqual(first["request_sha256"], request.sha256)
        self.assertEqual(first["recovery_owner"], "authority-runtime")
        self.assertEqual(first["allowed_recovery_action"], "recover")
        for private_name in (b"authentication_tag", b"recovery_token", b"effect_id"):
            self.assertNotIn(private_name, first_raw)
        target_identity = (target.stat().st_dev, target.stat().st_ino)
        intent_bytes = self._artifact_file("intents", proposal_id).read_bytes()
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)

        recovery_request = self._recovery_request(request, first)
        recovered_raw = mnemosyne_core.execute_request_bytes(
            recovery_request.canonical_bytes
        )
        recovered = json.loads(recovered_raw.decode("utf-8"))

        self.assertEqual(recovered["outcome_kind"], "completed", recovered)
        self.assertEqual(recovered["request_sha256"], recovery_request.sha256)
        self.assertEqual(
            self._reference(recovered["result_artifact"]).schema,
            librarian_contract.RESULT_SCHEMA,
        )
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual((target.stat().st_dev, target.stat().st_ino), target_identity)
        self.assertEqual(
            self._artifact_file("intents", proposal_id).read_bytes(),
            intent_bytes,
        )
        for private_name in (b"authentication_tag", b"recovery_token", b"effect_id"):
            self.assertNotIn(private_name, recovered_raw)

        replay_raw = mnemosyne_core.execute_request_bytes(request.canonical_bytes)
        replay = json.loads(replay_raw.decode("utf-8"))

        self.assertEqual(replay["outcome_kind"], "completed", replay)
        self.assertEqual(replay["request_sha256"], request.sha256)
        self.assertEqual(replay["result_artifact"], recovered["result_artifact"])
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual((target.stat().st_dev, target.stat().st_ino), target_identity)
        for private_name in (b"authentication_tag", b"recovery_token", b"effect_id"):
            self.assertNotIn(private_name, replay_raw)

    def test_d1a_intent_publish_recovery_finishes_the_approved_placement(
        self,
    ) -> None:
        proposal_id = "p-81000000000000000000000000000005"
        request, source, target, source_bytes = self._approved_file_request(
            proposal_id=proposal_id,
            decision_id="d-81000000000000000000000000000005",
            name="intent-recovery.md",
        )
        source_identity = (source.stat().st_dev, source.stat().st_ino)
        after_publish_count = 0

        def interrupt_intent_publish(point: str) -> None:
            nonlocal after_publish_count
            if point != "after-publish":
                return
            after_publish_count += 1
            if after_publish_count == 1:
                raise SimulatedPlacementCrash("after intent publication")

        with mock.patch.object(
            durable,
            "_run_checkpoint",
            side_effect=interrupt_intent_publish,
        ):
            first_raw = mnemosyne_core.execute_request_bytes(request.canonical_bytes)
        first = json.loads(first_raw.decode("utf-8"))

        self.assertEqual(after_publish_count, 1)
        self.assertEqual(first["outcome_kind"], "recoverable", first)
        self.assertEqual(first["request_sha256"], request.sha256)
        self.assertTrue(self._artifact_file("intents", proposal_id).is_file())
        self.assertFalse(self._artifact_file("results", proposal_id).exists())
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

        recovery_request = self._recovery_request(request, first)
        recovered_raw = mnemosyne_core.execute_request_bytes(
            recovery_request.canonical_bytes
        )
        recovered = json.loads(recovered_raw.decode("utf-8"))

        self.assertEqual(recovered["outcome_kind"], "completed", recovered)
        self.assertEqual(recovered["request_sha256"], recovery_request.sha256)
        self.assertEqual(
            self._reference(recovered["result_artifact"]).schema,
            librarian_contract.RESULT_SCHEMA,
        )
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual(
            (target.stat().st_dev, target.stat().st_ino),
            source_identity,
        )
        result = json.loads(
            self._artifact_file("results", proposal_id).read_text(encoding="utf-8")
        )
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["producer_request_sha256"], request.sha256)
        for private_name in (b"authentication_tag", b"recovery_token", b"effect_id"):
            self.assertNotIn(private_name, recovered_raw)


if __name__ == "__main__":
    unittest.main()
