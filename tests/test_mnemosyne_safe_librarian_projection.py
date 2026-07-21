import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import (  # noqa: E402
    artifact_contract,
    librarian_contract,
    librarian_projection,
)
from mnemosyne_core.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
)


_EFFECT_PREFIX = {
    "proposal": "safe-librarian-proposal-",
    "decision": "safe-librarian-decision-",
    "intent": "safe-librarian-intent-",
    "result": "safe-librarian-result-",
}


def _snapshot(relative_path: str, *, inode: int) -> dict[str, object]:
    value: dict[str, object] = {
        "kind": "regular_file",
        "relative_path": relative_path,
        "device": 7,
        "inode": inode,
        "owner": 501,
        "mode": 0o640,
        "link_count": 1,
        "size": 12,
        "modified_time_ns": 1_234_567_890,
        "parent": {"device": 7, "inode": inode + 10_000},
        "content_sha256": sha256_bytes(b"fixture-content"),
    }
    value["snapshot_sha256"] = sha256_bytes(canonical_json_bytes(value))
    return value


def _reference(
    schema: artifact_contract.SchemaIdentity,
    canonical_path: str,
    artifact_bytes: bytes,
) -> artifact_contract.SealedArtifactRef:
    return artifact_contract.SealedArtifactRef(
        schema=schema,
        canonical_path=canonical_path,
        artifact_sha256=sha256_bytes(artifact_bytes),
        manifest_sha256=sha256_bytes(b"manifest:" + artifact_bytes),
        producer_operation_sha256=sha256_bytes(b"producer:" + artifact_bytes),
        byte_length=len(artifact_bytes),
        media_type="application/json",
    )


def _finalized(
    kind: str,
    proposal_id: str,
    reference: artifact_contract.SealedArtifactRef,
    artifact_bytes: bytes,
) -> tuple[str, artifact_contract.SealedArtifactRef, bytes]:
    return (
        _EFFECT_PREFIX[kind] + proposal_id[2:],
        reference,
        artifact_bytes,
    )


def _record_chain(
    index: int,
    status: str,
    *,
    source: str | None = None,
    target: str | None = None,
) -> tuple[
    tuple[tuple[str, artifact_contract.SealedArtifactRef, bytes], ...],
    dict[str, artifact_contract.SealedArtifactRef],
]:
    proposal_id = f"p-{index:032x}"
    source_path = source or f"inbox/source-{index}.md"
    target_path = target or f"workstreams/example/source-{index}.md"
    source_snapshot = _snapshot(source_path, inode=1_000 + index)
    proposal = {
        "schema": librarian_contract.PROPOSAL_SCHEMA.canonical_value,
        "proposal_id": proposal_id,
        "producer_request_sha256": sha256_bytes(
            f"proposal-request-{index}".encode("ascii")
        ),
        "actor": "fixture-proposer",
        "created_at": "2026-07-18T01:02:03Z",
        "source_relative_path": source_path,
        "target_relative_path": target_path,
        "destination_kind": "workstream",
        "destination_id": "example",
        "reason": "Place the exact reviewed document.",
        "source_snapshot": source_snapshot,
        "target_absent": {
            "observed_absent": True,
            "relative_path": target_path,
            "parent": {"device": 7, "inode": 20_000 + index},
        },
        "bounds": {
            "max_entries": 1,
            "max_depth": 0,
            "max_total_bytes": 1_024,
        },
        "state": "PENDING",
    }
    proposal_bytes = librarian_contract.encode_proposal_record(proposal)
    proposal_reference = _reference(
        librarian_contract.PROPOSAL_SCHEMA,
        librarian_contract.proposal_artifact_path(proposal_id),
        proposal_bytes,
    )
    artifacts = [
        _finalized("proposal", proposal_id, proposal_reference, proposal_bytes)
    ]
    references = {"proposal": proposal_reference}
    if status == "PENDING":
        return tuple(artifacts), references

    decision_value = "REJECTED" if status == "REJECTED" else "APPROVED"
    decision = {
        "schema": librarian_contract.DECISION_SCHEMA.canonical_value,
        "decision_id": f"d-{index:032x}",
        "proposal": proposal_reference.canonical_value,
        "decision": decision_value,
        "actor": "fixture-decider",
        "decided_at": "2026-07-18T01:03:04Z",
        "decision_reason": "The exact proposal was reviewed.",
        "effect_summary": {
            "proposal_id": proposal_id,
            "source_relative_path": source_path,
            "target_relative_path": target_path,
            "destination_kind": "workstream",
            "destination_id": "example",
            "reason": "Place the exact reviewed document.",
        },
        "producer_request_sha256": sha256_bytes(
            f"decision-request-{index}".encode("ascii")
        ),
    }
    decision_bytes = librarian_contract.encode_decision_record(decision)
    decision_reference = _reference(
        librarian_contract.DECISION_SCHEMA,
        librarian_contract.decision_artifact_path(proposal_id),
        decision_bytes,
    )
    artifacts.append(
        _finalized("decision", proposal_id, decision_reference, decision_bytes)
    )
    references["decision"] = decision_reference
    if status in {"REJECTED", "APPROVED_PENDING_APPLY"}:
        return tuple(artifacts), references

    intent = {
        "schema": librarian_contract.INTENT_SCHEMA.canonical_value,
        "proposal": proposal_reference.canonical_value,
        "decision": decision_reference.canonical_value,
        "source_snapshot": source_snapshot,
        "source_relative_path": source_path,
        "target_relative_path": target_path,
        "producer_request_sha256": sha256_bytes(
            f"intent-request-{index}".encode("ascii")
        ),
        "state": "INTENT_RECORDED",
    }
    intent_bytes = librarian_contract.encode_intent_record(intent)
    intent_reference = _reference(
        librarian_contract.INTENT_SCHEMA,
        librarian_contract.intent_artifact_path(proposal_id),
        intent_bytes,
    )
    artifacts.append(_finalized("intent", proposal_id, intent_reference, intent_bytes))
    references["intent"] = intent_reference
    if status == "RECOVERY_REQUIRED":
        return tuple(artifacts), references

    target_snapshot = (
        _snapshot(target_path, inode=1_000 + index) if status == "APPLIED" else None
    )
    result = {
        "schema": librarian_contract.RESULT_SCHEMA.canonical_value,
        "proposal": proposal_reference.canonical_value,
        "intent": intent_reference.canonical_value,
        "status": status,
        "reason_code": None if status == "APPLIED" else "SOURCE_CHANGED",
        "source_absent": status == "APPLIED",
        "target_snapshot": target_snapshot,
        "producer_request_sha256": sha256_bytes(
            f"result-request-{index}".encode("ascii")
        ),
    }
    result_bytes = librarian_contract.encode_result_record(result)
    result_reference = _reference(
        librarian_contract.RESULT_SCHEMA,
        librarian_contract.result_artifact_path(proposal_id),
        result_bytes,
    )
    artifacts.append(_finalized("result", proposal_id, result_reference, result_bytes))
    references["result"] = result_reference
    return tuple(artifacts), references


class SafeLibrarianProjectionTest(unittest.TestCase):
    def test_effect_partition_contract_is_exact_and_bounded(self) -> None:
        artifacts, references = _record_chain(1, "APPLIED")

        evidence = librarian_projection.partition_finalized_records(artifacts)

        self.assertEqual(
            librarian_projection.EFFECT_PREFIXES,
            (
                "safe-librarian-proposal-",
                "safe-librarian-decision-",
                "safe-librarian-intent-",
                "safe-librarian-result-",
            ),
        )
        self.assertEqual(librarian_projection.READ_LIMIT, 16_385)
        self.assertEqual(
            evidence,
            {
                "proposals": ((references["proposal"], artifacts[0][2]),),
                "decisions": ((references["decision"], artifacts[1][2]),),
                "intents": ((references["intent"], artifacts[2][2]),),
                "results": ((references["result"], artifacts[3][2]),),
            },
        )

    def test_history_projects_all_six_safe_librarian_states(self) -> None:
        expected_states = (
            "PENDING",
            "REJECTED",
            "APPROVED_PENDING_APPLY",
            "RECOVERY_REQUIRED",
            "APPLIED",
            "BLOCKED",
        )
        finalized = []
        expected_references = {}
        for index, status in enumerate(expected_states, start=1):
            artifacts, references = _record_chain(index, status)
            finalized.extend(artifacts)
            expected_references[f"p-{index:032x}"] = references

        page = librarian_projection.project_record_page(
            librarian_projection.partition_finalized_records(tuple(finalized)),
            scope_path="inbox",
            view="history",
            offset=0,
            maximum=20,
        )

        self.assertEqual(page["schema_version"], 1)
        self.assertEqual(page["view"], "history")
        self.assertEqual(page["scope"], {"relative_path": "inbox"})
        self.assertEqual(page["offset"], 0)
        self.assertEqual(page["returned"], 6)
        self.assertIsNone(page["next_offset"])
        self.assertFalse(page["truncated"])
        self.assertEqual(
            [record["status"] for record in page["records"]],
            list(expected_states),
        )
        for record in page["records"]:
            references = expected_references[record["proposal_id"]]
            self.assertEqual(record["proposal"], references["proposal"].canonical_value)
            self.assertEqual(
                record["decision"],
                None
                if "decision" not in references
                else references["decision"].canonical_value,
            )
            self.assertEqual(
                record["intent"],
                None
                if "intent" not in references
                else references["intent"].canonical_value,
            )
            self.assertEqual(
                record["placement_result"],
                None
                if "result" not in references
                else references["result"].canonical_value,
            )
        self.assertIsNone(page["records"][4]["placement_reason_code"])
        self.assertEqual(
            page["records"][5]["placement_reason_code"],
            "SOURCE_CHANGED",
        )

    def test_pending_view_excludes_every_decided_proposal(self) -> None:
        pending, _ = _record_chain(1, "PENDING")
        rejected, _ = _record_chain(2, "REJECTED")
        approved, _ = _record_chain(3, "APPROVED_PENDING_APPLY")

        page = librarian_projection.project_record_page(
            librarian_projection.partition_finalized_records(
                pending + rejected + approved
            ),
            scope_path="inbox",
            view="pending",
            offset=0,
            maximum=10,
        )

        self.assertEqual(
            [(record["proposal_id"], record["status"]) for record in page["records"]],
            [("p-00000000000000000000000000000001", "PENDING")],
        )

    def test_orphan_decision_intent_or_result_is_rejected(self) -> None:
        artifacts, _ = _record_chain(1, "APPLIED")
        orphan_groups = {
            "decision": (artifacts[1],),
            "intent": (artifacts[2],),
            "result": (artifacts[3],),
        }

        for kind, orphan in orphan_groups.items():
            with self.subTest(kind=kind):
                evidence = librarian_projection.partition_finalized_records(orphan)
                with self.assertRaises(TypeError):
                    librarian_projection.project_record_page(
                        evidence,
                        scope_path="inbox",
                        view="history",
                        offset=0,
                        maximum=10,
                    )

    def test_duplicate_proposal_is_rejected(self) -> None:
        artifacts, _ = _record_chain(1, "PENDING")
        evidence = librarian_projection.partition_finalized_records(
            artifacts + artifacts
        )

        with self.assertRaises(TypeError):
            librarian_projection.project_record_page(
                evidence,
                scope_path="inbox",
                view="history",
                offset=0,
                maximum=10,
            )

    def test_effect_prefix_and_reference_schema_mismatch_is_rejected(self) -> None:
        artifacts, _ = _record_chain(1, "PENDING")
        effect_id, reference, artifact_bytes = artifacts[0]
        mismatched_reference = artifact_contract.SealedArtifactRef(
            schema=librarian_contract.DECISION_SCHEMA,
            canonical_path=reference.canonical_path,
            artifact_sha256=reference.artifact_sha256,
            manifest_sha256=reference.manifest_sha256,
            producer_operation_sha256=reference.producer_operation_sha256,
            byte_length=reference.byte_length,
            media_type=reference.media_type,
        )

        with self.assertRaises(TypeError):
            librarian_projection.partition_finalized_records(
                ((effect_id, mismatched_reference, artifact_bytes),)
            )

    def test_scope_filtering_happens_before_offset_and_maximum_paging(self) -> None:
        outside, _ = _record_chain(
            1,
            "PENDING",
            source="elsewhere/one.md",
            target="archive/one.md",
        )
        first_match, _ = _record_chain(
            2,
            "PENDING",
            source="inbox/two.md",
            target="workstreams/security/two.md",
        )
        second_match, _ = _record_chain(
            3,
            "PENDING",
            source="workstreams/security/three.md",
            target="archive/three.md",
        )
        evidence = librarian_projection.partition_finalized_records(
            outside + first_match + second_match
        )

        first_page = librarian_projection.project_record_page(
            evidence,
            scope_path="workstreams/security",
            view="history",
            offset=0,
            maximum=1,
        )
        second_page = librarian_projection.project_record_page(
            evidence,
            scope_path="workstreams/security",
            view="history",
            offset=1,
            maximum=1,
        )

        self.assertEqual(
            [record["proposal_id"] for record in first_page["records"]],
            ["p-00000000000000000000000000000002"],
        )
        self.assertTrue(first_page["truncated"])
        self.assertEqual(first_page["next_offset"], 1)
        self.assertEqual(
            [record["proposal_id"] for record in second_page["records"]],
            ["p-00000000000000000000000000000003"],
        )
        self.assertFalse(second_page["truncated"])
        self.assertIsNone(second_page["next_offset"])


if __name__ == "__main__":
    unittest.main()
