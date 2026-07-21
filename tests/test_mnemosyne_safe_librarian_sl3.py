import json
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
import mnemosyne_core  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    artifact_contract,
    librarian_contract,
    operation_contract,
)
from mnemosyne_core.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
)
from mnemosyne_core.operation_control import composition  # noqa: E402


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class SafeLibrarianSl3CatalogRedTest(unittest.TestCase):
    def test_librarian_placement_is_available_with_direct_owner_and_validators(
        self,
    ) -> None:
        spec = composition.DEFAULT_OPERATION_CATALOG.require_spec(
            "librarian.placement"
        )

        self.assertIs(
            spec.availability,
            composition.OperationAvailability.AVAILABLE,
        )
        self.assertEqual(spec.handler_module, "mnemosyne_core.librarian_placement")
        self.assertIs(
            spec.admission_contract.write_profile,
            operation_contract.WriteProfile.SAFE_LIBRARIAN_PLACEMENT,
        )
        for callable_value in (
            spec.handler,
            spec.request_validator,
            spec.result_validator,
        ):
            self.assertTrue(callable(callable_value))
            self.assertEqual(
                callable_value.__module__,
                "mnemosyne_core.librarian_placement",
            )


class SafeLibrarianSl3PlacementRedTest(LedgerRuntimeFixture):
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
            self.fail("public outcome did not contain a sealed result artifact")
        return artifact_contract.SealedArtifactRef.from_canonical_bytes(
            canonical_json_bytes(value)
        )

    def _publish_proposal(
        self,
        *,
        proposal_id: str,
        name: str,
    ) -> tuple[
        operation_contract.OperationRequest,
        artifact_contract.SealedArtifactRef,
        Path,
        Path,
        bytes,
    ]:
        source = self.root / "inbox" / name
        source.parent.mkdir(mode=0o700, exist_ok=True)
        source_bytes = ("# " + name + "\nExact source bytes.\n").encode("utf-8")
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / name
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
                "source_relative_path": "inbox/" + name,
                "target_relative_path": "example-service/docs/" + name,
            },
            bounds={
                "max_entries": 4096,
                "max_depth": 16,
                "max_total_bytes": 256 * 1024 * 1024,
            },
            payload={
                "destination_kind": "workstream",
                "destination_id": "example-service",
                "reason": "The document belongs to the example-service Workstream.",
            },
        )

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        return (
            request,
            self._reference(outcome["result_artifact"]),
            source,
            target,
            source_bytes,
        )

    def _decision_request(
        self,
        *,
        proposal_id: str,
        proposal_reference: artifact_contract.SealedArtifactRef,
        decision_id: str,
        decision: str,
    ) -> operation_contract.OperationRequest:
        return operation_contract.OperationRequest(
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
                "decision": decision,
                "decision_reason": (
                    "User approved the displayed exact proposal."
                    if decision == "APPROVED"
                    else "User rejected the displayed exact proposal."
                ),
            },
            prerequisite_artifacts=(proposal_reference,),
        )

    def _publish_decision(
        self,
        *,
        proposal_id: str,
        proposal_reference: artifact_contract.SealedArtifactRef,
        decision_id: str,
        decision: str,
    ) -> tuple[
        operation_contract.OperationRequest,
        artifact_contract.SealedArtifactRef,
    ]:
        request = self._decision_request(
            proposal_id=proposal_id,
            proposal_reference=proposal_reference,
            decision_id=decision_id,
            decision=decision,
        )
        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        return request, self._reference(outcome["result_artifact"])

    def _placement_request(
        self,
        *,
        proposal_request: operation_contract.OperationRequest,
        proposal_reference: artifact_contract.SealedArtifactRef,
        decision_reference: artifact_contract.SealedArtifactRef,
    ) -> operation_contract.OperationRequest:
        return operation_contract.OperationRequest(
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

    def test_exact_approved_file_placement_moves_once_records_intent_and_retries(
        self,
    ) -> None:
        self.migrate_to_v2()
        proposal_id = "p-80000000000000000000000000000001"
        proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name="approved.md")
        )
        _decision_request, decision_ref = self._publish_decision(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-80000000000000000000000000000001",
            decision="APPROVED",
        )
        request = self._placement_request(
            proposal_request=proposal_request,
            proposal_reference=proposal_ref,
            decision_reference=decision_ref,
        )
        source_before = source.stat()

        first = self._execute(request)

        self.assertEqual(first["outcome_kind"], "completed", first)
        self.assertEqual(first["request_sha256"], request.sha256)
        result_ref = self._reference(first["result_artifact"])
        intent_path = self._artifact_file("intents", proposal_id)
        result_path = self._artifact_file("results", proposal_id)
        intent_bytes = intent_path.read_bytes()
        result_bytes = result_path.read_bytes()
        intent = json.loads(intent_bytes.decode("utf-8"))
        result = json.loads(result_bytes.decode("utf-8"))

        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual(
            (target.stat().st_dev, target.stat().st_ino),
            (source_before.st_dev, source_before.st_ino),
        )
        self.assertEqual(intent_bytes, canonical_json_bytes(intent))
        self.assertEqual(
            intent["schema"],
            librarian_contract.INTENT_SCHEMA.canonical_value,
        )
        self.assertEqual(intent["state"], "INTENT_RECORDED")
        self.assertEqual(intent["proposal"], proposal_ref.canonical_value)
        self.assertEqual(intent["decision"], decision_ref.canonical_value)
        self.assertEqual(intent["producer_request_sha256"], request.sha256)
        self.assertEqual(result_bytes, canonical_json_bytes(result))
        self.assertEqual(
            result["schema"],
            librarian_contract.RESULT_SCHEMA.canonical_value,
        )
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["proposal"], proposal_ref.canonical_value)
        self.assertEqual(result["producer_request_sha256"], request.sha256)
        intent_ref = self._reference(result["intent"])
        self.assertEqual(intent_ref.schema, librarian_contract.INTENT_SCHEMA)
        self.assertEqual(
            intent_ref.canonical_path,
            self._artifact_path("intents", proposal_id),
        )
        self.assertEqual(intent_ref.artifact_sha256, sha256_bytes(intent_bytes))
        self.assertEqual(result_ref.schema, librarian_contract.RESULT_SCHEMA)
        self.assertEqual(
            result_ref.canonical_path,
            self._artifact_path("results", proposal_id),
        )
        self.assertEqual(result_ref.artifact_sha256, sha256_bytes(result_bytes))

        target_identity = (target.stat().st_dev, target.stat().st_ino)
        second = self._execute(request)

        self.assertEqual(second, first)
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)
        self.assertEqual((target.stat().st_dev, target.stat().st_ino), target_identity)
        self.assertEqual(intent_path.read_bytes(), intent_bytes)
        self.assertEqual(result_path.read_bytes(), result_bytes)

        history_request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.history",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"relative_path": "inbox"},
            bounds={"max_items": 10},
            payload={"offset": 0},
        )
        history = self._execute(history_request)
        history_record = history["result"]["records"][0]
        self.assertEqual(history_record["status"], "APPLIED")
        self.assertEqual(history_record["intent"], intent_ref.canonical_value)
        self.assertEqual(
            history_record["placement_result"],
            result_ref.canonical_value,
        )
        self.assertIsNone(history_record["placement_reason_code"])

    def test_rejected_decision_blocks_before_any_filesystem_effect(self) -> None:
        self.migrate_to_v2()
        proposal_id = "p-80000000000000000000000000000002"
        proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name="rejected.md")
        )
        _decision_request, decision_ref = self._publish_decision(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-80000000000000000000000000000002",
            decision="REJECTED",
        )
        request = self._placement_request(
            proposal_request=proposal_request,
            proposal_reference=proposal_ref,
            decision_reference=decision_ref,
        )
        source_identity = (source.stat().st_dev, source.stat().st_ino)

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["request_sha256"], request.sha256)
        self.assertEqual(outcome["reason_code"], "DECISION_MISMATCH")
        self.assertEqual(outcome["next_safe_action"], "inspect-pending")
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual((source.stat().st_dev, source.stat().st_ino), source_identity)
        self.assertFalse(target.exists())
        self.assertFalse(self._artifact_file("intents", proposal_id).exists())
        self.assertFalse(self._artifact_file("results", proposal_id).exists())

    def test_source_changed_after_approval_blocks_without_move(self) -> None:
        self.migrate_to_v2()
        proposal_id = "p-80000000000000000000000000000003"
        proposal_request, proposal_ref, source, target, _source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name="changed.md")
        )
        _decision_request, decision_ref = self._publish_decision(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-80000000000000000000000000000003",
            decision="APPROVED",
        )
        changed_bytes = b"# Changed after approval\nThe proposal snapshot is stale.\n"
        source.write_bytes(changed_bytes)
        source.chmod(0o600)
        changed_identity = (source.stat().st_dev, source.stat().st_ino)
        request = self._placement_request(
            proposal_request=proposal_request,
            proposal_reference=proposal_ref,
            decision_reference=decision_ref,
        )

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["request_sha256"], request.sha256)
        self.assertEqual(outcome["reason_code"], "SOURCE_CHANGED")
        self.assertEqual(outcome["next_safe_action"], "create-proposal")
        self.assertEqual(source.read_bytes(), changed_bytes)
        self.assertEqual((source.stat().st_dev, source.stat().st_ino), changed_identity)
        self.assertFalse(target.exists())
        self.assertFalse(self._artifact_file("intents", proposal_id).exists())
        result_path = self._artifact_file("results", proposal_id)
        result_bytes = result_path.read_bytes()
        result = json.loads(result_bytes.decode("utf-8"))
        self.assertEqual(result_bytes, canonical_json_bytes(result))
        self.assertEqual(
            result["schema"],
            librarian_contract.RESULT_SCHEMA.canonical_value,
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["reason_code"], "SOURCE_CHANGED")
        self.assertEqual(result["proposal"], proposal_ref.canonical_value)
        self.assertEqual(result["producer_request_sha256"], request.sha256)


if __name__ == "__main__":
    unittest.main()
