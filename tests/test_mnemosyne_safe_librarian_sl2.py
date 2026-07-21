import json
import stat
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
    authority_runtime,
    librarian_contract,
    librarian_records,
    operation_contract,
)
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402
from mnemosyne_core.authority_runtime import durable  # noqa: E402
from mnemosyne_core.cli import inspect as cli_inspect  # noqa: E402
from mnemosyne_core.cli import request_builder as cli_request_builder  # noqa: E402
from mnemosyne_core.operation_contract import codec as operation_codec  # noqa: E402
from mnemosyne_core.operation_control import composition  # noqa: E402

TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class SafeLibrarianSl2PublicCliTest(unittest.TestCase):
    def test_pending_and_history_build_exact_scoped_paging_requests(self) -> None:
        for view in ("pending", "history"):
            with self.subTest(view=view):
                request = cli_request_builder.build_view_request(
                    view=view,
                    root="/private/tmp/mnemosyne-safe-librarian",
                    actor="operator",
                    max_items=7,
                    offset=3,
                    relative_path="inbox/example",
                )

                self.assertEqual(request.operation_kind, "inspect." + view)
                self.assertIs(
                    request.claim_mode,
                    operation_contract.ClaimMode.HISTORICAL,
                )
                self.assertEqual(dict(request.scope), {"relative_path": "inbox/example"})
                self.assertEqual(dict(request.bounds), {"max_items": 7})
                self.assertEqual(dict(request.payload), {"offset": 3})

    def test_human_history_output_shows_exact_effect_summary_and_next_page(self) -> None:
        request_sha256 = "a" * 64
        raw = operation_contract.OperationOutcome.completed(
            request_sha256,
            result={
                "view": "history",
                "records": [
                    {
                        "proposal_id": "p-0123456789abcdef0123456789abcdef",
                        "status": "REJECTED",
                        "source_relative_path": "inbox/example.md",
                        "target_relative_path": "example-service/docs/example.md",
                    }
                ],
                "truncated": True,
                "next_offset": 4,
            },
        ).canonical_bytes

        exit_code, rendered = cli_inspect.inspect_view(
            view="history",
            root="/private/tmp/mnemosyne-safe-librarian",
            actor="operator",
            max_items=7,
            offset=3,
            relative_path="inbox/example",
            as_json=False,
            execute_request_bytes=lambda _request: raw,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("p-0123456789abcdef0123456789abcdef | REJECTED", rendered)
        self.assertIn(
            "inbox/example.md -> example-service/docs/example.md",
            rendered,
        )
        self.assertIn("다음 offset: 4", rendered)


class SafeLibrarianSl2CodecTest(unittest.TestCase):
    def _proposal_reference(
        self,
        proposal_id: str,
        artifact_sha256: str,
    ) -> artifact_contract.SealedArtifactRef:
        return artifact_contract.SealedArtifactRef(
            schema=librarian_contract.PROPOSAL_SCHEMA,
            canonical_path=librarian_contract.proposal_artifact_path(proposal_id),
            artifact_sha256=artifact_sha256,
            manifest_sha256="a" * 64,
            producer_operation_sha256="b" * 64,
            byte_length=123,
            media_type="application/json",
        )

    def test_canonical_request_codec_preserves_sealed_artifact_references(self) -> None:
        first = self._proposal_reference(
            "p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1" * 64,
        )
        second = self._proposal_reference(
            "p-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "2" * 64,
        )
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="librarian.decision",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root="/tmp/safe-librarian-codec",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={"proposal_id": "p-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            bounds={},
            payload={
                "decision_id": "d-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "decision": "APPROVED",
                "decision_reason": "User approved the displayed exact proposal.",
            },
            prerequisite_artifacts=(first, second),
        )

        decoded = operation_codec.decode_operation_request(
            operation_codec.encode_operation_request(request)
        )

        self.assertIsNone(decoded.approval_artifact)
        self.assertEqual(decoded.prerequisite_artifacts, (first, second))
        self.assertEqual(decoded.canonical_bytes, request.canonical_bytes)

    def test_request_codec_rejects_noncanonical_artifact_reference_shape(self) -> None:
        reference = self._proposal_reference(
            "p-cccccccccccccccccccccccccccccccc",
            "3" * 64,
        )
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="librarian.decision",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root="/tmp/safe-librarian-codec",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={"proposal_id": "p-cccccccccccccccccccccccccccccccc"},
            bounds={},
            payload={
                "decision_id": "d-cccccccccccccccccccccccccccccccc",
                "decision": "REJECTED",
                "decision_reason": "User rejected the displayed exact proposal.",
            },
            prerequisite_artifacts=(reference,),
        )
        value = json.loads(request.canonical_bytes.decode("utf-8"))
        value["prerequisite_artifacts"][0]["unexpected"] = True

        with self.assertRaisesRegex(ValueError, "sealed reference"):
            operation_codec.decode_operation_request(canonical_json_bytes(value))

    def test_record_result_contracts_accept_only_public_recovery_evidence(self) -> None:
        recoverable = operation_contract.OperationOutcome.recoverable(
            "1" * 64,
            recovery_owner="authority-runtime",
            continuation_identity="2" * 64,
            allowed_recovery_action="recover",
        )
        blocked = operation_contract.OperationOutcome.blocked_recovery(
            "1" * 64,
            recovery_owner="authority-runtime",
            continuation_identity="2" * 64,
            reason_code="RECOVERY_EVIDENCE_UNSAFE",
        )

        for validator in (
            librarian_records.validate_proposal_result,
            librarian_records.validate_decision_result,
        ):
            with self.subTest(validator=validator.__name__):
                validator(recoverable)
                validator(blocked)
        for outcome in (recoverable, blocked):
            raw = outcome.canonical_bytes
            self.assertNotIn(b"authentication_tag", raw)
            self.assertNotIn(b"recovery_token", raw)
            self.assertNotIn(b"effect_id", raw)


class SafeLibrarianSl2DecisionTest(LedgerRuntimeFixture):
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
        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )
        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
            canonical_json_bytes(outcome["result_artifact"])
        )
        return request, reference, source, target, source_bytes

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

    def _records_request(
        self,
        *,
        view: str,
        offset: int,
        max_items: int,
    ) -> operation_contract.OperationRequest:
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect." + view,
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            scope={"relative_path": "inbox"},
            bounds={"max_items": max_items},
            payload={"offset": offset},
        )

    def test_approve_and_reject_publish_exact_decisions_without_moving_corpus(self) -> None:
        self.migrate_to_v2()
        cases = (
            (
                "p-60000000000000000000000000000001",
                "d-60000000000000000000000000000001",
                "approved.md",
                "APPROVED",
            ),
            (
                "p-60000000000000000000000000000002",
                "d-60000000000000000000000000000002",
                "rejected.md",
                "REJECTED",
            ),
        )
        for proposal_id, decision_id, name, decision in cases:
            with self.subTest(decision=decision):
                proposal_request, proposal_ref, source, target, source_bytes = (
                    self._publish_proposal(proposal_id=proposal_id, name=name)
                )
                request = self._decision_request(
                    proposal_id=proposal_id,
                    proposal_reference=proposal_ref,
                    decision_id=decision_id,
                    decision=decision,
                )

                outcome = json.loads(
                    mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                        "utf-8"
                    )
                )

                self.assertEqual(outcome["outcome_kind"], "completed", outcome)
                expected_path = (
                    "_registry/curation/safe-librarian/v1/decisions/"
                    + proposal_id
                    + ".json"
                )
                result_ref = outcome["result_artifact"]
                self.assertEqual(
                    result_ref["schema"],
                    librarian_contract.DECISION_SCHEMA.canonical_value,
                )
                self.assertEqual(result_ref["canonical_path"], expected_path)
                record_bytes = self.root.joinpath(*expected_path.split("/")).read_bytes()
                record = json.loads(record_bytes.decode("utf-8"))
                self.assertEqual(record_bytes, canonical_json_bytes(record))
                self.assertEqual(
                    set(record),
                    {
                        "schema",
                        "decision_id",
                        "proposal",
                        "decision",
                        "actor",
                        "decided_at",
                        "decision_reason",
                        "effect_summary",
                        "producer_request_sha256",
                    },
                )
                self.assertEqual(record["schema"], librarian_contract.DECISION_SCHEMA.canonical_value)
                self.assertEqual(record["decision_id"], decision_id)
                self.assertEqual(record["proposal"], proposal_ref.canonical_value)
                self.assertEqual(record["decision"], decision)
                self.assertEqual(record["actor"], "operator")
                self.assertTrue(record["decided_at"])
                self.assertEqual(record["decision_reason"], request.payload["decision_reason"])
                self.assertEqual(
                    record["effect_summary"],
                    {
                        "proposal_id": proposal_id,
                        "source_relative_path": proposal_request.scope[
                            "source_relative_path"
                        ],
                        "target_relative_path": proposal_request.scope[
                            "target_relative_path"
                        ],
                        "destination_kind": proposal_request.payload[
                            "destination_kind"
                        ],
                        "destination_id": proposal_request.payload["destination_id"],
                        "reason": proposal_request.payload["reason"],
                    },
                )
                self.assertEqual(record["producer_request_sha256"], request.sha256)
                self.assertEqual(source.read_bytes(), source_bytes)
                self.assertFalse(target.exists())

    def test_exact_decision_retry_reuses_the_first_record_and_timestamp(self) -> None:
        self.migrate_to_v2()
        proposal_id = "p-60000000000000000000000000000003"
        _proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name="retry-decision.md")
        )
        request = self._decision_request(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-60000000000000000000000000000003",
            decision="APPROVED",
        )
        with mock.patch.object(
            librarian_records,
            "_utc_now",
            return_value="2026-07-18T01:02:03.000001Z",
        ):
            first = json.loads(
                mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                    "utf-8"
                )
            )
        record_path = self.root.joinpath(
            *librarian_contract.decision_artifact_path(proposal_id).split("/")
        )
        first_bytes = record_path.read_bytes()

        with mock.patch.object(
            librarian_records,
            "_utc_now",
            return_value="2026-07-18T09:09:09.999999Z",
        ):
            second = json.loads(
                mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                    "utf-8"
                )
            )

        self.assertEqual(first["outcome_kind"], "completed", first)
        self.assertEqual(second["outcome_kind"], "completed", second)
        self.assertEqual(second["result_artifact"], first["result_artifact"])
        self.assertEqual(record_path.read_bytes(), first_bytes)
        self.assertEqual(
            json.loads(first_bytes.decode("utf-8"))["decided_at"],
            "2026-07-18T01:02:03.000001Z",
        )
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_one_proposal_cannot_receive_a_conflicting_second_decision(self) -> None:
        self.migrate_to_v2()
        proposal_id = "p-60000000000000000000000000000004"
        _proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name="one-decision.md")
        )
        approved = self._decision_request(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-60000000000000000000000000000004",
            decision="APPROVED",
        )
        first = json.loads(
            mnemosyne_core.execute_request_bytes(approved.canonical_bytes).decode("utf-8")
        )
        record_path = self.root.joinpath(
            *librarian_contract.decision_artifact_path(proposal_id).split("/")
        )
        first_bytes = record_path.read_bytes()
        rejected = self._decision_request(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-60000000000000000000000000000005",
            decision="REJECTED",
        )

        conflicting = json.loads(
            mnemosyne_core.execute_request_bytes(rejected.canonical_bytes).decode("utf-8")
        )

        self.assertEqual(first["outcome_kind"], "completed", first)
        self.assertEqual(conflicting["outcome_kind"], "blocked", conflicting)
        self.assertEqual(conflicting["reason_code"], "DECISION_MISMATCH")
        self.assertEqual(conflicting["next_safe_action"], "inspect-pending")
        self.assertEqual(record_path.read_bytes(), first_bytes)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_pending_and_history_are_bounded_historical_record_views(self) -> None:
        self.migrate_to_v2()
        pending_id = "p-60000000000000000000000000000006"
        decided_id = "p-60000000000000000000000000000007"
        _pending_request, pending_ref, pending_source, pending_target, pending_bytes = (
            self._publish_proposal(proposal_id=pending_id, name="pending-view.md")
        )
        _decided_request, decided_ref, decided_source, decided_target, decided_bytes = (
            self._publish_proposal(proposal_id=decided_id, name="history-view.md")
        )
        decision_request = self._decision_request(
            proposal_id=decided_id,
            proposal_reference=decided_ref,
            decision_id="d-60000000000000000000000000000006",
            decision="REJECTED",
        )
        decision_outcome = json.loads(
            mnemosyne_core.execute_request_bytes(decision_request.canonical_bytes).decode(
                "utf-8"
            )
        )
        self.assertEqual(decision_outcome["outcome_kind"], "completed", decision_outcome)

        pending = json.loads(
            mnemosyne_core.execute_request_bytes(
                self._records_request(
                    view="pending",
                    offset=0,
                    max_items=1,
                ).canonical_bytes
            ).decode("utf-8")
        )
        first_history = json.loads(
            mnemosyne_core.execute_request_bytes(
                self._records_request(
                    view="history",
                    offset=0,
                    max_items=1,
                ).canonical_bytes
            ).decode("utf-8")
        )
        second_history = json.loads(
            mnemosyne_core.execute_request_bytes(
                self._records_request(
                    view="history",
                    offset=1,
                    max_items=1,
                ).canonical_bytes
            ).decode("utf-8")
        )

        self.assertEqual(pending["outcome_kind"], "completed", pending)
        self.assertEqual(pending["result"]["view"], "pending")
        self.assertEqual(pending["result"]["returned"], 1)
        self.assertFalse(pending["result"]["truncated"])
        pending_record = pending["result"]["records"][0]
        self.assertEqual(pending_record["proposal_id"], pending_id)
        self.assertEqual(pending_record["status"], "PENDING")
        self.assertEqual(pending_record["proposal"], pending_ref.canonical_value)
        self.assertIsNone(pending_record["decision"])

        self.assertEqual(first_history["outcome_kind"], "completed", first_history)
        self.assertEqual(first_history["result"]["view"], "history")
        self.assertTrue(first_history["result"]["truncated"])
        self.assertEqual(first_history["result"]["next_offset"], 1)
        self.assertEqual(
            first_history["result"]["records"][0]["proposal_id"],
            pending_id,
        )
        self.assertEqual(second_history["outcome_kind"], "completed", second_history)
        self.assertFalse(second_history["result"]["truncated"])
        history_record = second_history["result"]["records"][0]
        self.assertEqual(history_record["proposal_id"], decided_id)
        self.assertEqual(history_record["status"], "REJECTED")
        self.assertEqual(history_record["proposal"], decided_ref.canonical_value)
        self.assertEqual(
            history_record["decision"],
            decision_outcome["result_artifact"],
        )
        self.assertEqual(pending_source.read_bytes(), pending_bytes)
        self.assertEqual(decided_source.read_bytes(), decided_bytes)
        self.assertFalse(pending_target.exists())
        self.assertFalse(decided_target.exists())

    def test_history_uses_one_snapshot_when_a_decision_publishes_during_read(
        self,
    ) -> None:
        self.migrate_to_v2()
        proposal_id = "p-70000000000000000000000000000001"
        _proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(
                proposal_id=proposal_id,
                name="snapshot-consistent-history.md",
            )
        )
        decision_request = self._decision_request(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-70000000000000000000000000000001",
            decision="REJECTED",
        )
        published_decision = json.loads(
            mnemosyne_core.execute_request_bytes(
                decision_request.canonical_bytes
            ).decode("utf-8")
        )
        self.assertEqual(
            published_decision["outcome_kind"],
            "completed",
            published_decision,
        )
        original_read = durable._read_finalized_artifacts
        read_count = 0

        def read_with_tip_change(*args: object, **kwargs: object) -> object:
            nonlocal read_count
            read_count += 1
            records = original_read(*args, **kwargs)
            if read_count == 1:
                return tuple(
                    record
                    for record in records
                    if not record[0].startswith("safe-librarian-decision-")
                )
            return records

        with mock.patch.object(
            durable,
            "_read_finalized_artifacts",
            side_effect=read_with_tip_change,
        ):
            during_publication = json.loads(
                mnemosyne_core.execute_request_bytes(
                    self._records_request(
                        view="history",
                        offset=0,
                        max_items=10,
                    ).canonical_bytes
                ).decode("utf-8")
            )

        self.assertEqual(read_count, 1)
        self.assertEqual(
            during_publication["result"]["records"][0]["status"],
            "PENDING",
        )
        after_publication = json.loads(
            mnemosyne_core.execute_request_bytes(
                self._records_request(
                    view="history",
                    offset=0,
                    max_items=10,
                ).canonical_bytes
            ).decode("utf-8")
        )
        self.assertEqual(
            after_publication["result"]["records"][0]["status"],
            "REJECTED",
        )
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_interrupted_decision_publication_recovers_without_changing_decision(self) -> None:
        self.migrate_to_v2()
        proposal_id = "p-60000000000000000000000000000008"
        _proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name="recover-decision.md")
        )
        request = self._decision_request(
            proposal_id=proposal_id,
            proposal_reference=proposal_ref,
            decision_id="d-60000000000000000000000000000008",
            decision="APPROVED",
        )

        def interrupt(point: str) -> None:
            if point == "after-publish":
                raise RuntimeError("simulated decision interruption")

        with mock.patch.object(durable, "_run_checkpoint", side_effect=interrupt):
            first_raw = mnemosyne_core.execute_request_bytes(request.canonical_bytes)
        first = json.loads(first_raw.decode("utf-8"))
        self.assertEqual(first["outcome_kind"], "recoverable", first)
        recovery_request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind=request.operation_kind,
            action=operation_contract.LifecycleAction.RECOVER,
            claim_mode=request.claim_mode,
            root=request.root,
            actor=request.actor,
            requested_authority=request.requested_authority,
            scope=dict(request.scope),
            bounds=dict(request.bounds),
            payload={
                **dict(request.payload),
                "recovery": {
                    "continuation_identity": first["continuation_identity"],
                    "producer_request_sha256": request.sha256,
                },
            },
            prerequisite_artifacts=request.prerequisite_artifacts,
        )

        recovered_raw = mnemosyne_core.execute_request_bytes(
            recovery_request.canonical_bytes
        )
        recovered = json.loads(recovered_raw.decode("utf-8"))

        self.assertEqual(recovered["outcome_kind"], "completed", recovered)
        self.assertEqual(
            recovered["result_artifact"]["canonical_path"],
            librarian_contract.decision_artifact_path(proposal_id),
        )
        record = librarian_contract.decode_decision_record(
            self.root.joinpath(
                *librarian_contract.decision_artifact_path(proposal_id).split("/")
            ).read_bytes()
        )
        self.assertEqual(record["decision"], "APPROVED")
        self.assertEqual(record["decision_id"], request.payload["decision_id"])
        self.assertEqual(record["proposal"], proposal_ref.canonical_value)
        self.assertEqual(record["producer_request_sha256"], request.sha256)
        for raw in (first_raw, recovered_raw):
            self.assertNotIn(b"authentication_tag", raw)
            self.assertNotIn(b"recovery_token", raw)
            self.assertNotIn(b"effect_id", raw)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_fabricated_proposal_reference_cannot_authorize_a_decision(self) -> None:
        self.migrate_to_v2()
        proposal_id = "p-60000000000000000000000000000009"
        _proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name="fabricated-ref.md")
        )
        fabricated = artifact_contract.SealedArtifactRef(
            schema=proposal_ref.schema,
            canonical_path=proposal_ref.canonical_path,
            artifact_sha256="0" * 64,
            manifest_sha256=proposal_ref.manifest_sha256,
            producer_operation_sha256=proposal_ref.producer_operation_sha256,
            byte_length=proposal_ref.byte_length,
            media_type=proposal_ref.media_type,
        )
        request = self._decision_request(
            proposal_id=proposal_id,
            proposal_reference=fabricated,
            decision_id="d-60000000000000000000000000000009",
            decision="APPROVED",
        )

        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "PROPOSAL_MISMATCH")
        self.assertEqual(outcome["next_safe_action"], "correct-request")
        self.assertFalse(
            self.root.joinpath(
                *librarian_contract.decision_artifact_path(proposal_id).split("/")
            ).exists()
        )
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_wrong_proposal_path_stops_before_write_session_open(self) -> None:
        self.migrate_to_v2()
        proposal_id = "p-60000000000000000000000000000010"
        _proposal_request, proposal_ref, source, target, source_bytes = (
            self._publish_proposal(proposal_id=proposal_id, name="wrong-path.md")
        )
        wrong_path = artifact_contract.SealedArtifactRef(
            schema=proposal_ref.schema,
            canonical_path=librarian_contract.proposal_artifact_path(
                "p-ffffffffffffffffffffffffffffffff"
            ),
            artifact_sha256=proposal_ref.artifact_sha256,
            manifest_sha256=proposal_ref.manifest_sha256,
            producer_operation_sha256=proposal_ref.producer_operation_sha256,
            byte_length=proposal_ref.byte_length,
            media_type=proposal_ref.media_type,
        )
        request = self._decision_request(
            proposal_id=proposal_id,
            proposal_reference=wrong_path,
            decision_id="d-60000000000000000000000000000010",
            decision="APPROVED",
        )

        with mock.patch.object(
            authority_runtime,
            "open_write",
            side_effect=AssertionError("write session must not open"),
        ):
            outcome = json.loads(
                mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                    "utf-8"
                )
            )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())


class SafeLibrarianSl2ProposalTest(LedgerRuntimeFixture):
    def test_proposal_publication_records_exact_evidence_without_moving_source(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "proposal.md"
        source.parent.mkdir(mode=0o700)
        source_bytes = b"# Proposal candidate\nSafe content.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "proposal.md"
        target.parent.mkdir(parents=True, mode=0o700)
        target_parent_stat = target.parent.stat()
        proposal_id = "p-0123456789abcdef0123456789abcdef"
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
                "source_relative_path": "inbox/proposal.md",
                "target_relative_path": "example-service/docs/proposal.md",
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

        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertEqual(outcome["request_sha256"], request.sha256)
        expected_path = (
            "_registry/curation/safe-librarian/v1/proposals/" + proposal_id + ".json"
        )
        artifact_ref = outcome["result_artifact"]
        self.assertEqual(artifact_ref["schema"], librarian_contract.PROPOSAL_SCHEMA.canonical_value)
        self.assertEqual(artifact_ref["canonical_path"], expected_path)
        self.assertEqual(
            artifact_ref["producer_operation_sha256"],
            composition.DEFAULT_OPERATION_CATALOG.require_spec(
                "librarian.proposal"
            ).spec_sha256,
        )
        record_bytes = self.root.joinpath(*expected_path.split("/")).read_bytes()
        self.assertEqual(artifact_ref["artifact_sha256"], sha256_bytes(record_bytes))
        self.assertEqual(artifact_ref["byte_length"], len(record_bytes))
        self.assertEqual(artifact_ref["media_type"], "application/json")
        record = json.loads(record_bytes.decode("utf-8"))
        self.assertEqual(record_bytes, canonical_json_bytes(record))
        self.assertEqual(
            set(record),
            {
                "schema",
                "proposal_id",
                "producer_request_sha256",
                "actor",
                "created_at",
                "source_relative_path",
                "target_relative_path",
                "destination_kind",
                "destination_id",
                "reason",
                "source_snapshot",
                "target_absent",
                "bounds",
                "state",
            },
        )
        self.assertEqual(record["schema"], librarian_contract.PROPOSAL_SCHEMA.canonical_value)
        self.assertEqual(record["proposal_id"], proposal_id)
        self.assertEqual(record["producer_request_sha256"], request.sha256)
        self.assertEqual(record["actor"], "operator")
        self.assertIsInstance(record["created_at"], str)
        self.assertTrue(record["created_at"])
        self.assertEqual(record["source_relative_path"], "inbox/proposal.md")
        self.assertEqual(
            record["target_relative_path"],
            "example-service/docs/proposal.md",
        )
        self.assertEqual(record["destination_kind"], "workstream")
        self.assertEqual(record["destination_id"], "example-service")
        self.assertEqual(
            record["reason"],
            "The document belongs to the example-service Workstream.",
        )
        self.assertEqual(record["source_snapshot"]["kind"], "regular_file")
        self.assertEqual(
            record["source_snapshot"]["relative_path"],
            "inbox/proposal.md",
        )
        self.assertEqual(
            record["source_snapshot"]["content_sha256"],
            sha256_bytes(source_bytes),
        )
        self.assertEqual(record["source_snapshot"]["size"], len(source_bytes))
        self.assertEqual(
            record["target_absent"],
            {
                "observed_absent": True,
                "parent": {
                    "device": target_parent_stat.st_dev,
                    "inode": target_parent_stat.st_ino,
                },
                "relative_path": "example-service/docs/proposal.md",
            },
        )
        self.assertEqual(record["bounds"], dict(request.bounds))
        self.assertEqual(record["state"], "PENDING")
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_exact_proposal_retry_reuses_the_first_record_and_timestamp(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "retry.md"
        source.parent.mkdir(mode=0o700)
        source_bytes = b"# Retry candidate\nSame bytes.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "retry.md"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-11111111111111111111111111111111"
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
                "source_relative_path": "inbox/retry.md",
                "target_relative_path": "example-service/docs/retry.md",
            },
            bounds={
                "max_entries": 4096,
                "max_depth": 16,
                "max_total_bytes": 256 * 1024 * 1024,
            },
            payload={
                "destination_kind": "workstream",
                "destination_id": "example-service",
                "reason": "This exact request must be idempotent.",
            },
        )

        with mock.patch.object(
            librarian_records,
            "_utc_now",
            return_value="2026-07-18T01:02:03.000001Z",
        ):
            first = json.loads(
                mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                    "utf-8"
                )
            )
        expected_path = librarian_contract.proposal_artifact_path(proposal_id)
        first_bytes = self.root.joinpath(*expected_path.split("/")).read_bytes()
        with mock.patch.object(
            librarian_records,
            "_utc_now",
            return_value="2026-07-18T09:09:09.999999Z",
        ):
            second = json.loads(
                mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode(
                    "utf-8"
                )
            )

        self.assertEqual(first["outcome_kind"], "completed", first)
        self.assertEqual(second["outcome_kind"], "completed", second)
        self.assertEqual(second["result_artifact"], first["result_artifact"])
        self.assertEqual(
            self.root.joinpath(*expected_path.split("/")).read_bytes(),
            first_bytes,
        )
        self.assertEqual(
            json.loads(first_bytes.decode("utf-8"))["created_at"],
            "2026-07-18T01:02:03.000001Z",
        )
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_proposal_id_cannot_be_reused_for_different_record_bytes(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "collision.md"
        source.parent.mkdir(mode=0o700)
        source_bytes = b"# Collision candidate\nOriginal bytes.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "collision.md"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-22222222222222222222222222222222"

        def request(reason: str) -> operation_contract.OperationRequest:
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
                    "source_relative_path": "inbox/collision.md",
                    "target_relative_path": "example-service/docs/collision.md",
                },
                bounds={
                    "max_entries": 4096,
                    "max_depth": 16,
                    "max_total_bytes": 256 * 1024 * 1024,
                },
                payload={
                    "destination_kind": "workstream",
                    "destination_id": "example-service",
                    "reason": reason,
                },
            )

        first_request = request("The original exact reason.")
        first = json.loads(
            mnemosyne_core.execute_request_bytes(first_request.canonical_bytes).decode(
                "utf-8"
            )
        )
        expected_path = librarian_contract.proposal_artifact_path(proposal_id)
        record_path = self.root.joinpath(*expected_path.split("/"))
        original_record = record_path.read_bytes()
        conflicting_request = request("A different reason must create a new proposal id.")
        conflicting = json.loads(
            mnemosyne_core.execute_request_bytes(
                conflicting_request.canonical_bytes
            ).decode("utf-8")
        )

        self.assertEqual(first["outcome_kind"], "completed", first)
        self.assertEqual(conflicting["outcome_kind"], "blocked", conflicting)
        self.assertEqual(conflicting["reason_code"], "PROPOSAL_MISMATCH")
        self.assertEqual(conflicting["next_safe_action"], "correct-request")
        self.assertEqual(record_path.read_bytes(), original_record)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_target_collision_blocks_proposal_without_changing_corpus(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "occupied.md"
        source.parent.mkdir(mode=0o700)
        source_bytes = b"# Source\nMust remain.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "occupied.md"
        target.parent.mkdir(parents=True, mode=0o700)
        target_bytes = b"# Existing target\nMust not be overwritten.\n"
        target.write_bytes(target_bytes)
        target.chmod(0o600)
        proposal_id = "p-33333333333333333333333333333333"
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
                "source_relative_path": "inbox/occupied.md",
                "target_relative_path": "example-service/docs/occupied.md",
            },
            bounds={
                "max_entries": 4096,
                "max_depth": 16,
                "max_total_bytes": 256 * 1024 * 1024,
            },
            payload={
                "destination_kind": "workstream",
                "destination_id": "example-service",
                "reason": "An occupied target must stop the proposal.",
            },
        )

        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "TARGET_COLLISION")
        self.assertEqual(outcome["next_safe_action"], "create-proposal")
        self.assertFalse(
            self.root.joinpath(
                *librarian_contract.proposal_artifact_path(proposal_id).split("/")
            ).exists()
        )
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual(target.read_bytes(), target_bytes)

    def test_bounded_directory_proposal_seals_a_sorted_tree_manifest(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "bundle"
        nested = source / "nested"
        nested.mkdir(parents=True, mode=0o700)
        source.chmod(0o700)
        first_bytes = b"# A\nFirst file.\n"
        second_bytes = b"# B\nSecond file.\n"
        first = source / "a.md"
        second = nested / "b.md"
        first.write_bytes(first_bytes)
        second.write_bytes(second_bytes)
        first.chmod(0o600)
        second.chmod(0o600)
        target = self.root / "example-service" / "docs" / "bundle"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-44444444444444444444444444444444"
        first_stat = first.stat()
        nested_stat = nested.stat()
        second_stat = second.stat()
        expected_manifest = [
            {
                "relative_path": "a.md",
                "entry_type": "file",
                "device": first_stat.st_dev,
                "inode": first_stat.st_ino,
                "owner": first_stat.st_uid,
                "mode": stat.S_IMODE(first_stat.st_mode),
                "size": len(first_bytes),
                "modified_time_ns": first_stat.st_mtime_ns,
                "content_sha256": sha256_bytes(first_bytes),
            },
            {
                "relative_path": "nested",
                "entry_type": "directory",
                "device": nested_stat.st_dev,
                "inode": nested_stat.st_ino,
                "owner": nested_stat.st_uid,
                "mode": stat.S_IMODE(nested_stat.st_mode),
                "size": 0,
                "modified_time_ns": nested_stat.st_mtime_ns,
            },
            {
                "relative_path": "nested/b.md",
                "entry_type": "file",
                "device": second_stat.st_dev,
                "inode": second_stat.st_ino,
                "owner": second_stat.st_uid,
                "mode": stat.S_IMODE(second_stat.st_mode),
                "size": len(second_bytes),
                "modified_time_ns": second_stat.st_mtime_ns,
                "content_sha256": sha256_bytes(second_bytes),
            },
        ]
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
                "max_entries": 8,
                "max_depth": 2,
                "max_total_bytes": 1024,
            },
            payload={
                "destination_kind": "workstream",
                "destination_id": "example-service",
                "reason": "The bounded directory belongs to the Workstream.",
            },
        )

        outcome = json.loads(
            mnemosyne_core.execute_request_bytes(request.canonical_bytes).decode("utf-8")
        )

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        record_path = self.root.joinpath(
            *librarian_contract.proposal_artifact_path(proposal_id).split("/")
        )
        record = json.loads(record_path.read_text(encoding="utf-8"))
        snapshot = record["source_snapshot"]
        self.assertEqual(snapshot["kind"], "directory")
        self.assertEqual(snapshot["relative_path"], "inbox/bundle")
        self.assertEqual(snapshot["entry_count"], 3)
        self.assertEqual(snapshot["file_count"], 2)
        self.assertEqual(snapshot["total_bytes"], len(first_bytes) + len(second_bytes))
        self.assertEqual(
            snapshot["manifest_sha256"],
            sha256_bytes(canonical_json_bytes(expected_manifest)),
        )
        self.assertEqual(first.read_bytes(), first_bytes)
        self.assertEqual(second.read_bytes(), second_bytes)
        self.assertFalse(target.exists())

    def test_interrupted_proposal_publication_recovers_from_public_continuation(self) -> None:
        self.migrate_to_v2()
        source = self.root / "inbox" / "recover-proposal.md"
        source.parent.mkdir(mode=0o700)
        source_bytes = b"# Recover proposal\nExact bytes.\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.root / "example-service" / "docs" / "recover-proposal.md"
        target.parent.mkdir(parents=True, mode=0o700)
        proposal_id = "p-70000000000000000000000000000001"
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
                "source_relative_path": "inbox/recover-proposal.md",
                "target_relative_path": "example-service/docs/recover-proposal.md",
            },
            bounds={
                "max_entries": 4096,
                "max_depth": 16,
                "max_total_bytes": 256 * 1024 * 1024,
            },
            payload={
                "destination_kind": "workstream",
                "destination_id": "example-service",
                "reason": "The interrupted publication must recover exactly.",
            },
        )

        def interrupt(point: str) -> None:
            if point == "after-publish":
                raise RuntimeError("simulated proposal interruption")

        with mock.patch.object(durable, "_run_checkpoint", side_effect=interrupt):
            first_raw = mnemosyne_core.execute_request_bytes(request.canonical_bytes)
        first = json.loads(first_raw.decode("utf-8"))

        self.assertEqual(first["outcome_kind"], "recoverable", first)
        self.assertEqual(first["recovery_owner"], "authority-runtime")
        self.assertEqual(first["allowed_recovery_action"], "recover")
        recovery_request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind=request.operation_kind,
            action=operation_contract.LifecycleAction.RECOVER,
            claim_mode=request.claim_mode,
            root=request.root,
            actor=request.actor,
            requested_authority=request.requested_authority,
            scope=dict(request.scope),
            bounds=dict(request.bounds),
            payload={
                **dict(request.payload),
                "recovery": {
                    "continuation_identity": first["continuation_identity"],
                    "producer_request_sha256": request.sha256,
                },
            },
        )
        recovered_raw = mnemosyne_core.execute_request_bytes(
            recovery_request.canonical_bytes
        )
        recovered = json.loads(recovered_raw.decode("utf-8"))

        self.assertEqual(recovered["outcome_kind"], "completed", recovered)
        self.assertEqual(recovered["request_sha256"], recovery_request.sha256)
        self.assertEqual(
            recovered["result_artifact"]["canonical_path"],
            librarian_contract.proposal_artifact_path(proposal_id),
        )
        for raw in (first_raw, recovered_raw):
            self.assertNotIn(b"authentication_tag", raw)
            self.assertNotIn(b"recovery_token", raw)
            self.assertNotIn(b"effect_id", raw)
        record = librarian_contract.decode_proposal_record(
            self.root.joinpath(
                *librarian_contract.proposal_artifact_path(proposal_id).split("/")
            ).read_bytes()
        )
        self.assertEqual(record["producer_request_sha256"], request.sha256)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_prepared_proposal_crashes_retry_to_public_recovery(self) -> None:
        self.migrate_to_v2()
        for index, checkpoint in enumerate(
            ("after-prepared-row", "after-prepare"),
            start=2,
        ):
            with self.subTest(checkpoint=checkpoint):
                proposal_id = f"p-7000000000000000000000000000000{index}"
                name = f"prepared-crash-{index}.md"
                source = self.root / "inbox" / name
                source.parent.mkdir(mode=0o700, exist_ok=True)
                source_bytes = ("# " + checkpoint + "\n").encode("utf-8")
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
                        "reason": "A prepared crash must resume through public recovery.",
                    },
                )

                def interrupt(point: str) -> None:
                    if point == checkpoint:
                        raise RuntimeError("simulated process crash")

                with mock.patch.object(durable, "_run_checkpoint", side_effect=interrupt):
                    with self.assertRaisesRegex(RuntimeError, "simulated process crash"):
                        mnemosyne_core.execute_request_bytes(request.canonical_bytes)

                retry_raw = mnemosyne_core.execute_request_bytes(request.canonical_bytes)
                retry = json.loads(retry_raw.decode("utf-8"))
                self.assertEqual(retry["outcome_kind"], "recoverable", retry)
                recovery_request = operation_contract.OperationRequest(
                    schema_version=1,
                    operation_kind=request.operation_kind,
                    action=operation_contract.LifecycleAction.RECOVER,
                    claim_mode=request.claim_mode,
                    root=request.root,
                    actor=request.actor,
                    requested_authority=request.requested_authority,
                    scope=dict(request.scope),
                    bounds=dict(request.bounds),
                    payload={
                        **dict(request.payload),
                        "recovery": {
                            "continuation_identity": retry[
                                "continuation_identity"
                            ],
                            "producer_request_sha256": request.sha256,
                        },
                    },
                )
                recovered_raw = mnemosyne_core.execute_request_bytes(
                    recovery_request.canonical_bytes
                )
                recovered = json.loads(recovered_raw.decode("utf-8"))
                self.assertEqual(recovered["outcome_kind"], "completed", recovered)
                for raw in (retry_raw, recovered_raw):
                    self.assertNotIn(b"authentication_tag", raw)
                    self.assertNotIn(b"recovery_token", raw)
                    self.assertNotIn(b"effect_id", raw)
                self.assertEqual(source.read_bytes(), source_bytes)
                self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
