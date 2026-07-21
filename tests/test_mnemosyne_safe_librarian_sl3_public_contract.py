import json
import sys
import tempfile
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
    librarian_placement,
    operation_contract,
)
from mnemosyne_core.operation_control import composition  # noqa: E402

TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


PROPOSAL_ID = "p-81000000000000000000000000000001"
OTHER_PROPOSAL_ID = "p-81000000000000000000000000000002"
_DEFAULT = object()


def _reference(
    schema: artifact_contract.SchemaIdentity,
    canonical_path: str,
    marker: str,
    *,
    media_type: str = "application/json",
) -> artifact_contract.SealedArtifactRef:
    return artifact_contract.SealedArtifactRef(
        schema=schema,
        canonical_path=canonical_path,
        artifact_sha256=marker * 64,
        manifest_sha256="a" * 64,
        producer_operation_sha256="b" * 64,
        byte_length=123,
        media_type=media_type,
    )


def _proposal_reference(
    *,
    proposal_id: str = PROPOSAL_ID,
    schema: artifact_contract.SchemaIdentity = librarian_contract.PROPOSAL_SCHEMA,
    marker: str = "1",
    media_type: str = "application/json",
) -> artifact_contract.SealedArtifactRef:
    return _reference(
        schema,
        librarian_contract.proposal_artifact_path(proposal_id),
        marker,
        media_type=media_type,
    )


def _decision_reference(
    *,
    proposal_id: str = PROPOSAL_ID,
    schema: artifact_contract.SchemaIdentity = librarian_contract.DECISION_SCHEMA,
    marker: str = "2",
    media_type: str = "application/json",
) -> artifact_contract.SealedArtifactRef:
    return _reference(
        schema,
        librarian_contract.decision_artifact_path(proposal_id),
        marker,
        media_type=media_type,
    )


def _apply_request(
    root: str,
    *,
    scope: dict[str, object] | None = None,
    bounds: dict[str, object] | None = None,
    payload: dict[str, object] | None = None,
    approval_artifact: object = _DEFAULT,
    prerequisite_artifacts: object = _DEFAULT,
) -> operation_contract.OperationRequest:
    return operation_contract.OperationRequest(
        schema_version=1,
        operation_kind="librarian.placement",
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=operation_contract.ClaimMode.CURRENT,
        root=root,
        actor="operator",
        requested_authority=operation_contract.AuthorityMode.WRITE,
        scope=(
            {
                "proposal_id": PROPOSAL_ID,
                "source_relative_path": "inbox/approved.md",
                "target_relative_path": "example-service/docs/approved.md",
            }
            if scope is None
            else scope
        ),
        bounds={} if bounds is None else bounds,
        payload={} if payload is None else payload,
        approval_artifact=(
            _decision_reference()
            if approval_artifact is _DEFAULT
            else approval_artifact
        ),
        prerequisite_artifacts=(
            (_proposal_reference(),)
            if prerequisite_artifacts is _DEFAULT
            else prerequisite_artifacts
        ),
    )


def _recover_request(
    apply_request: operation_contract.OperationRequest,
    *,
    scope: dict[str, object] | None = None,
    bounds: dict[str, object] | None = None,
    payload: dict[str, object] | None = None,
    approval_artifact: object = _DEFAULT,
    prerequisite_artifacts: object = _DEFAULT,
) -> operation_contract.OperationRequest:
    return operation_contract.OperationRequest(
        schema_version=apply_request.schema_version,
        operation_kind=apply_request.operation_kind,
        action=operation_contract.LifecycleAction.RECOVER,
        claim_mode=apply_request.claim_mode,
        root=apply_request.root,
        actor=apply_request.actor,
        requested_authority=apply_request.requested_authority,
        scope=dict(apply_request.scope) if scope is None else scope,
        bounds={} if bounds is None else bounds,
        payload=(
            {
                "recovery": {
                    "continuation_identity": "c" * 64,
                    "producer_request_sha256": apply_request.sha256,
                }
            }
            if payload is None
            else payload
        ),
        approval_artifact=(
            apply_request.approval_artifact
            if approval_artifact is _DEFAULT
            else approval_artifact
        ),
        prerequisite_artifacts=(
            apply_request.prerequisite_artifacts
            if prerequisite_artifacts is _DEFAULT
            else prerequisite_artifacts
        ),
    )


class SafeLibrarianSl3PublicRequestContractTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = str(Path(temporary_directory.name).resolve())

    def test_invalid_paths_schemas_refs_and_widening_stop_before_session(self) -> None:
        valid_apply = _apply_request(self.root)
        invalid_requests = {
            "proposal-path": _apply_request(
                self.root,
                prerequisite_artifacts=(
                    _proposal_reference(proposal_id=OTHER_PROPOSAL_ID),
                ),
            ),
            "decision-path": _apply_request(
                self.root,
                approval_artifact=_decision_reference(
                    proposal_id=OTHER_PROPOSAL_ID
                ),
            ),
            "proposal-schema": _apply_request(
                self.root,
                prerequisite_artifacts=(
                    _proposal_reference(schema=librarian_contract.DECISION_SCHEMA),
                ),
            ),
            "decision-schema": _apply_request(
                self.root,
                approval_artifact=_decision_reference(
                    schema=librarian_contract.PROPOSAL_SCHEMA
                ),
            ),
            "proposal-ref-missing": _apply_request(
                self.root,
                prerequisite_artifacts=(),
            ),
            "proposal-ref-extra": _apply_request(
                self.root,
                prerequisite_artifacts=(
                    _proposal_reference(),
                    _proposal_reference(marker="3"),
                ),
            ),
            "decision-ref-missing": _apply_request(
                self.root,
                approval_artifact=None,
            ),
            "decision-ref-wrong-media": _apply_request(
                self.root,
                approval_artifact=_decision_reference(media_type="text/plain"),
            ),
            "proposal-ref-wrong-media": _apply_request(
                self.root,
                prerequisite_artifacts=(
                    _proposal_reference(media_type="text/plain"),
                ),
            ),
            "apply-payload-widened": _apply_request(
                self.root,
                payload={"unexpected": True},
            ),
            "apply-bounds-widened": _apply_request(
                self.root,
                bounds={"max_entries": 1},
            ),
            "recover-payload-widened": _recover_request(
                valid_apply,
                payload={
                    "recovery": {
                        "continuation_identity": "c" * 64,
                        "producer_request_sha256": valid_apply.sha256,
                    },
                    "unexpected": True,
                },
            ),
            "recover-bounds-widened": _recover_request(
                valid_apply,
                bounds={"max_entries": 1},
            ),
        }

        for label, request in invalid_requests.items():
            with self.subTest(label=label):
                with mock.patch.object(
                    authority_runtime,
                    "open_write",
                    side_effect=AssertionError("write session must not open"),
                ):
                    outcome = json.loads(
                        mnemosyne_core.execute_request_bytes(
                            request.canonical_bytes
                        ).decode("utf-8")
                    )
                self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
                self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
                self.assertEqual(
                    outcome["next_safe_action"],
                    "correct-request",
                )

    def test_recover_preserves_scope_refs_and_exact_original_apply_sha(self) -> None:
        apply_request = _apply_request(self.root)
        recover_request = _recover_request(apply_request)

        librarian_placement.validate_placement_request(apply_request)
        librarian_placement.validate_placement_request(recover_request)
        self.assertEqual(
            recover_request.payload["recovery"]["producer_request_sha256"],
            apply_request.sha256,
        )

        wrong_hash_payload = {
            "recovery": {
                "continuation_identity": "c" * 64,
                "producer_request_sha256": "f" * 64,
            }
        }
        changed_source = dict(apply_request.scope)
        changed_source["source_relative_path"] = "inbox/rebound.md"
        changed_target = dict(apply_request.scope)
        changed_target["target_relative_path"] = (
            "example-service/docs/rebound.md"
        )
        invalid_recoveries = {
            "wrong-apply-sha": _recover_request(
                apply_request,
                payload=wrong_hash_payload,
            ),
            "changed-source-scope": _recover_request(
                apply_request,
                scope=changed_source,
            ),
            "changed-target-scope": _recover_request(
                apply_request,
                scope=changed_target,
            ),
            "changed-proposal-ref": _recover_request(
                apply_request,
                prerequisite_artifacts=(
                    _proposal_reference(marker="3"),
                ),
            ),
            "changed-decision-ref": _recover_request(
                apply_request,
                approval_artifact=_decision_reference(marker="4"),
            ),
        }

        for label, request in invalid_recoveries.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "does not match APPLY"):
                    librarian_placement.validate_placement_request(request)


class SafeLibrarianSl3PlacementSessionSurfaceTest(LedgerRuntimeFixture):
    def test_placement_session_exposes_no_generic_writer_or_path_capability(self) -> None:
        self.migrate_to_v2()
        request = _apply_request(str(self.root))
        spec = composition.DEFAULT_OPERATION_CATALOG.require_spec(
            "librarian.placement"
        )
        librarian_placement.validate_placement_request(request)
        admitted = authority_runtime.admit(request, spec.admission_contract)

        with authority_runtime.open_write(admitted) as session:
            for capability in (
                "prepare",
                "publish",
                "finalize",
                "recover",
                "root",
                "path",
            ):
                with self.subTest(capability=capability):
                    self.assertFalse(hasattr(session, capability))


class SafeLibrarianSl3PublicResultContractTest(unittest.TestCase):
    def test_completed_placement_result_rejects_an_intent_artifact(self) -> None:
        outcome = operation_contract.OperationOutcome.completed(
            "1" * 64,
            result_artifact=_reference(
                librarian_contract.INTENT_SCHEMA,
                librarian_contract.intent_artifact_path(PROPOSAL_ID),
                "3",
            ),
        )

        with self.assertRaisesRegex(ValueError, "result artifact is invalid"):
            librarian_placement.validate_placement_result(outcome)

    def test_recovery_results_accept_only_public_authority_runtime_evidence(self) -> None:
        valid = (
            operation_contract.OperationOutcome.recoverable(
                "1" * 64,
                recovery_owner="authority-runtime",
                continuation_identity="2" * 64,
                allowed_recovery_action="recover",
            ),
            operation_contract.OperationOutcome.blocked_recovery(
                "1" * 64,
                recovery_owner="authority-runtime",
                continuation_identity="2" * 64,
                reason_code="RECOVERY_EVIDENCE_UNSAFE",
            ),
        )
        invalid = (
            operation_contract.OperationOutcome.recoverable(
                "1" * 64,
                recovery_owner="operator",
                continuation_identity="2" * 64,
                allowed_recovery_action="recover",
            ),
            operation_contract.OperationOutcome.recoverable(
                "1" * 64,
                recovery_owner="authority-runtime",
                continuation_identity="2" * 64,
                allowed_recovery_action="resume",
            ),
            operation_contract.OperationOutcome.blocked_recovery(
                "1" * 64,
                recovery_owner="operator",
                continuation_identity="2" * 64,
                reason_code="RECOVERY_EVIDENCE_UNSAFE",
            ),
        )

        for outcome in valid:
            with self.subTest(kind=outcome.outcome_kind):
                librarian_placement.validate_placement_result(outcome)
                for forbidden in (
                    b"authentication_tag",
                    b"recovery_token",
                    b"effect_id",
                ):
                    self.assertNotIn(forbidden, outcome.canonical_bytes)
        for outcome in invalid:
            with self.subTest(
                kind=outcome.outcome_kind,
                owner=outcome.recovery_owner,
                action=outcome.allowed_recovery_action,
            ):
                with self.assertRaisesRegex(ValueError, "result is invalid"):
                    librarian_placement.validate_placement_result(outcome)


if __name__ == "__main__":
    unittest.main()
