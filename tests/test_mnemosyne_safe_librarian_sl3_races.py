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
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class SafeLibrarianSl3PublicRaceTest(LedgerRuntimeFixture):
    @staticmethod
    def _artifact_path(kind: str, proposal_id: str) -> str:
        return f"_registry/curation/safe-librarian/v1/{kind}/{proposal_id}.json"

    def _artifact_file(self, kind: str, proposal_id: str) -> Path:
        return self.root.joinpath(*self._artifact_path(kind, proposal_id).split("/"))

    def _execute(
        self,
        request: operation_contract.OperationRequest,
    ) -> dict[str, object]:
        return json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                "utf-8"
            )
        )

    def _reference(self, value: object) -> artifact_contract.SealedArtifactRef:
        if not isinstance(value, dict):
            self.fail("public operation did not return a sealed artifact reference")
        return artifact_contract.SealedArtifactRef.from_canonical_bytes(
            canonical_json_bytes(value)
        )

    def _approved_placement(
        self,
        *,
        proposal_id: str,
        decision_id: str,
        name: str,
    ) -> tuple[
        operation_contract.OperationRequest,
        Path,
        Path,
        bytes,
    ]:
        source = self.root / "inbox" / name
        source.parent.mkdir(mode=0o700, exist_ok=True)
        source_bytes = (f"# {name}\nExact approved source bytes.\n").encode("utf-8")
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / name
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        proposal_request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="librarian.proposal",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={
                "proposal_id": proposal_id,
                "source_relative_path": f"inbox/{name}",
                "target_relative_path": f"example-service/docs/{name}",
            },
            bounds={
                "max_entries": 4096,
                "max_depth": 16,
                "max_total_bytes": 256 * 1024 * 1024,
            },
            payload={
                "destination_kind": "workstream",
                "destination_id": "example-service",
                "reason": "The exact document belongs to this active Workstream.",
            },
        )
        proposal_outcome = self._execute(proposal_request)
        self.assertEqual(proposal_outcome["outcome_kind"], "completed")
        proposal_reference = self._reference(proposal_outcome["result_artifact"])

        decision_request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="librarian.decision",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={"proposal_id": proposal_id},
            bounds={},
            payload={
                "decision_id": decision_id,
                "decision": "APPROVED",
                "decision_reason": "User approved the displayed exact proposal.",
            },
            prerequisite_artifacts=(proposal_reference,),
        )
        decision_outcome = self._execute(decision_request)
        self.assertEqual(decision_outcome["outcome_kind"], "completed")
        decision_reference = self._reference(decision_outcome["result_artifact"])

        placement_request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="librarian.placement",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope=dict(proposal_request.scope),
            bounds={},
            payload={},
            approval_artifact=decision_reference,
            prerequisite_artifacts=(proposal_reference,),
        )
        return placement_request, source, target, source_bytes

    def _assert_blocked_result(
        self,
        *,
        proposal_id: str,
        reason_code: str,
    ) -> None:
        result_path = self._artifact_file("results", proposal_id)
        record = librarian_contract.decode_result_record(result_path.read_bytes())
        self.assertEqual(record["status"], "BLOCKED")
        self.assertEqual(record["reason_code"], reason_code)
        self.assertFalse(record["source_absent"])
        self.assertIsNone(record["target_snapshot"])

    def _assert_root_stop_outcome(
        self,
        outcome: dict[str, object],
        request: operation_contract.OperationRequest,
    ) -> None:
        self.assertEqual(outcome["outcome_kind"], "blocked_recovery", outcome)
        self.assertEqual(outcome["request_sha256"], request.sha256)
        self.assertEqual(outcome["recovery_owner"], "authority-runtime")
        self.assertEqual(outcome["reason_code"], "PLACEMENT_RECOVERY_REQUIRED")
        self.assertRegex(str(outcome["continuation_identity"]), r"^[0-9a-f]{64}$")

    def test_target_appearing_after_intent_is_not_overwritten_and_records_collision(
        self,
    ) -> None:
        self.migrate_to_v2()
        proposal_id = "p-81000000000000000000000000000001"
        request, source, target, source_bytes = self._approved_placement(
            proposal_id=proposal_id,
            decision_id="d-81000000000000000000000000000001",
            name="target-race.md",
        )
        source_identity = (source.stat().st_dev, source.stat().st_ino)
        intruder_bytes = b"pre-existing target must never be overwritten\n"
        checkpoints: list[str] = []

        def create_target(point: str) -> None:
            if point == "after-intent":
                checkpoints.append(point)
                self.assertTrue(self._artifact_file("intents", proposal_id).is_file())
                target.write_bytes(intruder_bytes)
                target.chmod(0o600)

        with mock.patch.object(
            librarian_placement,
            "_run_checkpoint",
            side_effect=create_target,
        ):
            outcome = self._execute(request)

        self.assertEqual(checkpoints, ["after-intent"])
        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "TARGET_COLLISION")
        self.assertEqual(outcome["next_safe_action"], "create-proposal")
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual((source.stat().st_dev, source.stat().st_ino), source_identity)
        self.assertEqual(target.read_bytes(), intruder_bytes)
        self._assert_blocked_result(
            proposal_id=proposal_id,
            reason_code="TARGET_COLLISION",
        )

    def test_source_parent_identity_swap_before_rename_cannot_move_old_source(
        self,
    ) -> None:
        self.migrate_to_v2()
        proposal_id = "p-81000000000000000000000000000002"
        request, source, target, source_bytes = self._approved_placement(
            proposal_id=proposal_id,
            decision_id="d-81000000000000000000000000000002",
            name="source-parent-race.md",
        )
        original_parent = source.parent
        displaced_parent = self.root / "displaced-inbox"

        def swap_source_parent(point: str) -> None:
            if point == "after-intent":
                original_parent.rename(displaced_parent)
                original_parent.mkdir(mode=0o700)

        with mock.patch.object(
            librarian_placement,
            "_run_checkpoint",
            side_effect=swap_source_parent,
        ):
            outcome = self._execute(request)

        displaced_source = displaced_parent / source.name
        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "SOURCE_CHANGED")
        self.assertEqual(outcome["next_safe_action"], "create-proposal")
        self.assertFalse(source.exists())
        self.assertEqual(displaced_source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())
        self._assert_blocked_result(
            proposal_id=proposal_id,
            reason_code="SOURCE_CHANGED",
        )

    def test_target_parent_identity_swap_before_rename_cannot_move_to_new_parent(
        self,
    ) -> None:
        self.migrate_to_v2()
        proposal_id = "p-81000000000000000000000000000003"
        request, source, target, source_bytes = self._approved_placement(
            proposal_id=proposal_id,
            decision_id="d-81000000000000000000000000000003",
            name="target-parent-race.md",
        )
        original_parent = target.parent
        displaced_parent = original_parent.with_name("displaced-docs")

        def swap_target_parent(point: str) -> None:
            if point == "after-intent":
                original_parent.rename(displaced_parent)
                original_parent.mkdir(mode=0o700)

        with mock.patch.object(
            librarian_placement,
            "_run_checkpoint",
            side_effect=swap_target_parent,
        ):
            outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "SOURCE_CHANGED")
        self.assertEqual(outcome["next_safe_action"], "create-proposal")
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())
        self.assertFalse((displaced_parent / target.name).exists())
        self._assert_blocked_result(
            proposal_id=proposal_id,
            reason_code="SOURCE_CHANGED",
        )

    def test_both_paths_absent_after_finalized_intent_root_stops_later_apply(
        self,
    ) -> None:
        self.migrate_to_v2()
        blocked_id = "p-81000000000000000000000000000004"
        blocked_request, source, target, _source_bytes = self._approved_placement(
            proposal_id=blocked_id,
            decision_id="d-81000000000000000000000000000004",
            name="both-absent.md",
        )
        later_id = "p-81000000000000000000000000000005"
        later_request, later_source, later_target, later_bytes = (
            self._approved_placement(
                proposal_id=later_id,
                decision_id="d-81000000000000000000000000000005",
                name="later-valid.md",
            )
        )

        def remove_source(point: str) -> None:
            if point == "after-intent":
                self.assertTrue(self._artifact_file("intents", blocked_id).is_file())
                source.unlink()

        with mock.patch.object(
            librarian_placement,
            "_run_checkpoint",
            side_effect=remove_source,
        ):
            first = self._execute(blocked_request)

        self._assert_root_stop_outcome(first, blocked_request)
        self.assertFalse(source.exists())
        self.assertFalse(target.exists())
        self.assertFalse(self._artifact_file("results", blocked_id).exists())

        later = self._execute(later_request)

        self._assert_root_stop_outcome(later, later_request)
        self.assertEqual(later_source.read_bytes(), later_bytes)
        self.assertFalse(later_target.exists())
        self.assertFalse(self._artifact_file("intents", later_id).exists())
        self.assertFalse(self._artifact_file("results", later_id).exists())

    def test_target_mismatch_after_rename_root_stops_before_applied_result(
        self,
    ) -> None:
        self.migrate_to_v2()
        blocked_id = "p-81000000000000000000000000000006"
        blocked_request, source, target, source_bytes = self._approved_placement(
            proposal_id=blocked_id,
            decision_id="d-81000000000000000000000000000006",
            name="post-rename-mismatch.md",
        )
        later_id = "p-81000000000000000000000000000007"
        later_request, later_source, later_target, later_bytes = (
            self._approved_placement(
                proposal_id=later_id,
                decision_id="d-81000000000000000000000000000007",
                name="later-after-mismatch.md",
            )
        )
        mismatched_bytes = b"target changed after verified rename\n"

        def replace_target(point: str) -> None:
            if point == "after-rename":
                self.assertFalse(source.exists())
                self.assertEqual(target.read_bytes(), source_bytes)
                target.write_bytes(mismatched_bytes)
                target.chmod(0o600)

        with mock.patch.object(
            librarian_placement,
            "_run_checkpoint",
            side_effect=replace_target,
        ):
            first = self._execute(blocked_request)

        self._assert_root_stop_outcome(first, blocked_request)
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), mismatched_bytes)
        self.assertFalse(self._artifact_file("results", blocked_id).exists())

        later = self._execute(later_request)

        self._assert_root_stop_outcome(later, later_request)
        self.assertEqual(later_source.read_bytes(), later_bytes)
        self.assertFalse(later_target.exists())
        self.assertFalse(self._artifact_file("intents", later_id).exists())
        self.assertFalse(self._artifact_file("results", later_id).exists())


if __name__ == "__main__":
    unittest.main()
