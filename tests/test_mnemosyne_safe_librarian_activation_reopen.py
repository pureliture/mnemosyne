import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import (  # noqa: E402
    activation_foundation,
    artifact_contract,
    authority_runtime,
    ledger_runtime,
    operation_contract,
)
from mnemosyne_core.authority_runtime import activation as activation_runtime  # noqa: E402
from mnemosyne_core.canonical_json import sha256_bytes  # noqa: E402


def setUpModule() -> None:
    """Rebind after the facade's discovery-time verified bootstrap reset."""

    global mnemosyne, activation_foundation, artifact_contract
    global authority_runtime, ledger_runtime, operation_contract
    global activation_runtime, sha256_bytes
    import mnemosyne as current_facade
    from mnemosyne_core import (
        activation_foundation as current_activation_foundation,
        artifact_contract as current_artifact_contract,
        authority_runtime as current_authority_runtime,
        ledger_runtime as current_ledger_runtime,
        operation_contract as current_operation_contract,
    )
    from mnemosyne_core.authority_runtime import (
        activation as current_activation_runtime,
    )
    from mnemosyne_core.canonical_json import sha256_bytes as current_sha256_bytes

    mnemosyne = current_facade
    activation_foundation = current_activation_foundation
    artifact_contract = current_artifact_contract
    authority_runtime = current_authority_runtime
    ledger_runtime = current_ledger_runtime
    operation_contract = current_operation_contract
    activation_runtime = current_activation_runtime
    sha256_bytes = current_sha256_bytes


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


def _filesystem_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    captured = []
    for path in (root, *sorted(root.rglob("*"))):
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


class ActivationReopenTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        registry = self.root / "_registry"
        registry.mkdir(mode=0o755)
        self.registry_raw = BASE_REGISTRY.replace(
            b"{root}",
            str(self.root).encode("utf-8"),
        )
        placement = registry / "placement-map.yml"
        placement.write_bytes(self.registry_raw)
        placement.chmod(0o644)
        self.activation_id = "act-0123456789abcdef0123456789abcdef"

    def _activate(self) -> activation_foundation.ActivationFoundationPlan:
        audit = activation_runtime.capture_audit_evidence(self.root)
        self.assertTrue(audit.activation_eligible)
        self.assertIsNotNone(audit.initial_policy)
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="curation.activation",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="activation-reopen-test",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={
                "allowed_namespace": "_registry/curation",
                "corpus_effect": "none",
                "initial_policy": audit.initial_policy.as_dict(),
                "root_identity_sha256": audit.root_identity_sha256,
            },
            bounds={},
            scope={"activation_id": self.activation_id},
        )
        admitted = activation_runtime.capture_admission_evidence(self.root, request)
        with activation_runtime.open_activation_session(
            self.root,
            request_bytes=request.canonical_bytes,
            admitted_evidence=admitted,
        ) as session:
            session.activate()
        return activation_foundation.build_activation_foundation(
            self.registry_raw,
            str(self.root),
            self.activation_id,
        )

    def test_reader_and_writer_reopen_activation_with_its_initial_source(self) -> None:
        plan = self._activate()

        with ledger_runtime.open_reader_session(self.root) as reader:
            self.assertIs(
                reader.foundation_kind,
                ledger_runtime.FoundationKind.SAFE_LIBRARIAN_ACTIVATION_V1,
            )
            self.assertEqual(reader.approved_policy_ref.source_kind, "INITIAL")
            self.assertEqual(
                reader.approved_policy_ref.source_run_id,
                self.activation_id,
            )
            self.assertEqual(reader.approved_policy_ref.generation, 1)
            self.assertEqual(reader.approved_policy_ref.guard_epoch, 0)
            self.assertEqual(reader.compiled_policy, plan.compiled_policy)
            self.assertEqual(reader.current_policy(), reader.approved_policy_ref)

        with ledger_runtime.open_writer_session(self.root) as writer:
            self.assertIs(
                writer.foundation_kind,
                ledger_runtime.FoundationKind.SAFE_LIBRARIAN_ACTIVATION_V1,
            )
            self.assertEqual(writer.approved_policy_ref.source_kind, "INITIAL")
            self.assertEqual(
                writer.approved_policy_ref.source_run_id,
                self.activation_id,
            )
            self.assertEqual(writer.compiled_policy, plan.compiled_policy)
            self.assertEqual(writer.current_policy(), writer.approved_policy_ref)
            self.assertEqual(
                writer.connection.execute(
                    "SELECT COUNT(*) FROM control_bootstraps"
                ).fetchone()[0],
                0,
            )

    def test_post_active_record_namespaces_preserve_active_reopen(self) -> None:
        self._activate()
        proposals = (
            self.root
            / "_registry"
            / "curation"
            / "safe-librarian"
            / "v1"
            / "proposals"
        )
        proposals.mkdir(parents=True, mode=0o700)
        for directory in (
            proposals.parent.parent,
            proposals.parent,
            proposals,
        ):
            directory.chmod(0o700)
        for name in ("canonical-curation-v1", "canonical-curation-v2"):
            directory = self.root / "_registry" / "curation" / name
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)

        audit = activation_runtime.capture_audit_evidence(self.root)

        self.assertEqual(audit.activation_state, "ACTIVE")
        self.assertEqual(audit.reason_code, "ALREADY_ACTIVE")
        with ledger_runtime.open_reader_session(self.root) as reader:
            self.assertIs(
                reader.foundation_kind,
                ledger_runtime.FoundationKind.SAFE_LIBRARIAN_ACTIVATION_V1,
            )

    def test_preseal_orphan_fences_before_legacy_lock_selection(self) -> None:
        (self.root / "_registry" / "curation").mkdir(mode=0o700)

        with mock.patch.object(
            ledger_runtime,
            "_open_lock",
            side_effect=AssertionError("partial activation reached a lock path"),
        ) as lock_open:
            with self.assertRaisesRegex(
                ledger_runtime.LedgerRuntimeError,
                "activation foundation is incomplete",
            ):
                with ledger_runtime.open_reader_session(self.root):
                    pass

        lock_open.assert_not_called()

    def test_first_durable_write_remains_part_of_the_active_foundation(self) -> None:
        self._activate()
        activation_request_path = (
            self.root
            / "_registry"
            / "curation"
            / "activation"
            / "v1"
            / "request.json"
        )
        activation_request_raw = activation_request_path.read_bytes()
        contract = operation_contract.AdmissionContract(
            spec_identity="test-activation-durable-write-v1",
            spec_sha256="e" * 64,
            operation_kind="test.activation_durable_write",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind=contract.operation_kind,
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="activation-durable-write-test",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        artifact_bytes = b'{"effect":"activation-durable-write"}\n'
        target = "outputs/activation-durable-write.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-activation-durable-write",
            target_relative_path=target,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="ACTIVATION_DURABLE_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(b"activation-durable-manifest"),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )

        admitted = authority_runtime.admit(request, contract)
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        self.assertTrue(
            (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
            ).is_dir()
        )
        audit = activation_runtime.capture_audit_evidence(self.root)
        self.assertEqual(audit.activation_state, "ACTIVE")
        self.assertEqual(audit.reason_code, "ALREADY_ACTIVE")
        with ledger_runtime.open_reader_session(self.root) as reader:
            self.assertIs(
                reader.foundation_kind,
                ledger_runtime.FoundationKind.SAFE_LIBRARIAN_ACTIVATION_V1,
            )
        before_replay = _filesystem_snapshot(self.root)

        replay = json.loads(
            mnemosyne._mnemosyne_core.execute_request_bytes(
                activation_request_raw
            )
        )

        self.assertEqual(replay["outcome_kind"], "completed")
        self.assertEqual(
            replay["request_sha256"],
            hashlib.sha256(activation_request_raw).hexdigest(),
        )
        self.assertEqual(_filesystem_snapshot(self.root), before_replay)


if __name__ == "__main__":
    unittest.main()
