import copy
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import artifact_contract, librarian_contract  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


class SafeLibrarianSl3ArtifactContractTest(unittest.TestCase):
    proposal_id = "p-80000000000000000000000000000001"

    def _reference(
        self,
        schema: artifact_contract.SchemaIdentity,
        canonical_path: str,
        marker: str,
    ) -> artifact_contract.SealedArtifactRef:
        return artifact_contract.SealedArtifactRef(
            schema=schema,
            canonical_path=canonical_path,
            artifact_sha256=marker * 64,
            manifest_sha256="a" * 64,
            producer_operation_sha256="b" * 64,
            byte_length=123,
            media_type="application/json",
        )

    def _regular_snapshot(self, relative_path: str) -> dict[str, object]:
        snapshot = {
            "kind": "regular_file",
            "relative_path": relative_path,
            "device": 11,
            "inode": 22,
            "owner": 501,
            "mode": 0o600,
            "link_count": 1,
            "size": 12,
            "modified_time_ns": 123456789,
            "parent": {"device": 11, "inode": 21},
            "content_sha256": "c" * 64,
        }
        snapshot["snapshot_sha256"] = sha256_bytes(canonical_json_bytes(snapshot))
        return snapshot

    def _intent_record(self) -> dict[str, object]:
        proposal = self._reference(
            librarian_contract.PROPOSAL_SCHEMA,
            librarian_contract.proposal_artifact_path(self.proposal_id),
            "1",
        )
        decision = self._reference(
            librarian_contract.DECISION_SCHEMA,
            librarian_contract.decision_artifact_path(self.proposal_id),
            "2",
        )
        return {
            "schema": librarian_contract.INTENT_SCHEMA.canonical_value,
            "proposal": proposal.canonical_value,
            "decision": decision.canonical_value,
            "source_snapshot": self._regular_snapshot("inbox/approved.md"),
            "source_relative_path": "inbox/approved.md",
            "target_relative_path": "example-service/docs/approved.md",
            "producer_request_sha256": "d" * 64,
            "state": "INTENT_RECORDED",
        }

    def test_exact_intent_binds_approved_refs_and_source_snapshot(self) -> None:
        intent = self._intent_record()

        encoded = librarian_contract.encode_intent_record(intent)

        self.assertEqual(encoded, canonical_json_bytes(intent))
        self.assertEqual(librarian_contract.decode_intent_record(encoded), intent)
        self.assertEqual(
            librarian_contract.intent_artifact_path(self.proposal_id),
            "_registry/curation/safe-librarian/v1/intents/"
            + self.proposal_id
            + ".json",
        )

    def test_applied_result_requires_intent_and_exact_target_snapshot(self) -> None:
        proposal = self._reference(
            librarian_contract.PROPOSAL_SCHEMA,
            librarian_contract.proposal_artifact_path(self.proposal_id),
            "1",
        )
        intent = self._reference(
            librarian_contract.INTENT_SCHEMA,
            "_registry/curation/safe-librarian/v1/intents/"
            + self.proposal_id
            + ".json",
            "3",
        )
        result = {
            "schema": librarian_contract.RESULT_SCHEMA.canonical_value,
            "proposal": proposal.canonical_value,
            "intent": intent.canonical_value,
            "status": "APPLIED",
            "reason_code": None,
            "source_absent": True,
            "target_snapshot": self._regular_snapshot(
                "example-service/docs/approved.md"
            ),
            "producer_request_sha256": "d" * 64,
        }

        encoded = librarian_contract.encode_result_record(result)

        self.assertEqual(encoded, canonical_json_bytes(result))
        self.assertEqual(librarian_contract.decode_result_record(encoded), result)
        self.assertEqual(
            librarian_contract.result_artifact_path(self.proposal_id),
            "_registry/curation/safe-librarian/v1/results/"
            + self.proposal_id
            + ".json",
        )

    def test_blocked_result_requires_reason_and_proves_source_remains(self) -> None:
        proposal = self._reference(
            librarian_contract.PROPOSAL_SCHEMA,
            librarian_contract.proposal_artifact_path(self.proposal_id),
            "1",
        )
        intent = self._reference(
            librarian_contract.INTENT_SCHEMA,
            librarian_contract.intent_artifact_path(self.proposal_id),
            "3",
        )
        base = {
            "schema": librarian_contract.RESULT_SCHEMA.canonical_value,
            "proposal": proposal.canonical_value,
            "status": "BLOCKED",
            "reason_code": "SOURCE_CHANGED",
            "source_absent": False,
            "target_snapshot": None,
            "producer_request_sha256": "d" * 64,
        }

        for intent_value in (None, intent.canonical_value):
            with self.subTest(intent_present=intent_value is not None):
                result = {**base, "intent": intent_value}
                encoded = librarian_contract.encode_result_record(result)
                self.assertEqual(encoded, canonical_json_bytes(result))
                self.assertEqual(
                    librarian_contract.decode_result_record(encoded),
                    result,
                )

    def test_intent_rejects_cross_proposal_refs_and_noncanonical_bytes(self) -> None:
        intent = self._intent_record()
        other_id = "p-80000000000000000000000000000002"
        wrong_decision = self._reference(
            librarian_contract.DECISION_SCHEMA,
            librarian_contract.decision_artifact_path(other_id),
            "4",
        )
        invalid_records = []
        cross_proposal = copy.deepcopy(intent)
        cross_proposal["decision"] = wrong_decision.canonical_value
        invalid_records.append(cross_proposal)
        wrong_state = copy.deepcopy(intent)
        wrong_state["state"] = "APPLIED"
        invalid_records.append(wrong_state)
        mismatched_snapshot = copy.deepcopy(intent)
        mismatched_snapshot["source_snapshot"] = self._regular_snapshot(
            "inbox/different.md"
        )
        invalid_records.append(mismatched_snapshot)
        extra_field = copy.deepcopy(intent)
        extra_field["unexpected"] = True
        invalid_records.append(extra_field)

        for invalid in invalid_records:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    librarian_contract.encode_intent_record(invalid)
        with self.assertRaisesRegex(ValueError, "canonical"):
            librarian_contract.decode_intent_record(
                b" " + canonical_json_bytes(intent)
            )

    def test_result_status_invariants_and_reference_identity_fail_closed(self) -> None:
        proposal = self._reference(
            librarian_contract.PROPOSAL_SCHEMA,
            librarian_contract.proposal_artifact_path(self.proposal_id),
            "1",
        )
        intent = self._reference(
            librarian_contract.INTENT_SCHEMA,
            librarian_contract.intent_artifact_path(self.proposal_id),
            "3",
        )
        applied = {
            "schema": librarian_contract.RESULT_SCHEMA.canonical_value,
            "proposal": proposal.canonical_value,
            "intent": intent.canonical_value,
            "status": "APPLIED",
            "reason_code": None,
            "source_absent": True,
            "target_snapshot": self._regular_snapshot(
                "example-service/docs/approved.md"
            ),
            "producer_request_sha256": "d" * 64,
        }
        blocked = {
            **applied,
            "intent": None,
            "status": "BLOCKED",
            "reason_code": "TARGET_COLLISION",
            "source_absent": False,
            "target_snapshot": None,
        }
        invalid_records = []
        for field, value in (
            ("intent", None),
            ("reason_code", "SOURCE_CHANGED"),
            ("source_absent", False),
            ("target_snapshot", None),
        ):
            invalid = copy.deepcopy(applied)
            invalid[field] = value
            invalid_records.append(invalid)
        for field, value in (
            ("reason_code", None),
            ("source_absent", True),
            (
                "target_snapshot",
                self._regular_snapshot("example-service/docs/existing.md"),
            ),
        ):
            invalid = copy.deepcopy(blocked)
            invalid[field] = value
            invalid_records.append(invalid)
        wrong_intent = self._reference(
            librarian_contract.INTENT_SCHEMA,
            librarian_contract.intent_artifact_path(
                "p-80000000000000000000000000000002"
            ),
            "4",
        )
        cross_proposal = copy.deepcopy(blocked)
        cross_proposal["intent"] = wrong_intent.canonical_value
        invalid_records.append(cross_proposal)

        for invalid in invalid_records:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    librarian_contract.encode_result_record(invalid)
        with self.assertRaisesRegex(ValueError, "canonical"):
            librarian_contract.decode_result_record(
                b" " + canonical_json_bytes(applied)
            )


if __name__ == "__main__":
    unittest.main()
