import ast
import errno
import hmac
import inspect
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import unittest
import warnings
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import (  # noqa: E402
    artifact_contract,
    authority_runtime,
    ledger_runtime,
    operation_control,
    operation_contract,
    policy_authority,
)
from mnemosyne_core.authority_runtime import session as authority_session  # noqa: E402
from mnemosyne_core.authority_runtime import _durable_snapshot as authority_snapshot  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402
from mnemosyne_core.operation_contract import codec  # noqa: E402

if __package__:
    from .test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402
else:
    from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class D1aAdmittedOperationTrustBoundaryTest(unittest.TestCase):
    def test_open_read_rejects_caller_created_admitted_operation(self):
        forged = object.__new__(operation_contract.AdmittedOperation)

        with self.assertRaisesRegex(TypeError, "unverified admitted operation"):
            with authority_runtime.open_read(forged):
                self.fail("an unverified admission must not open a read capability")

    def test_admission_rejects_request_authority_that_widens_catalog_authority(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.none",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root="/private/tmp/d1a-authority-runtime",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-none-v1",
            spec_sha256="a" * 64,
            operation_kind="test.none",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.NONE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )

        with self.assertRaisesRegex(ValueError, "cannot widen catalog authority"):
            authority_runtime.admit(request, contract)

    def test_none_admission_seals_the_request_without_opening_a_read_session(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.none",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root="/private/tmp/d1a-authority-runtime",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.NONE,
            payload={"query": "status"},
            bounds={"max_items": 1},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-none-v1",
            spec_sha256="a" * 64,
            operation_kind="test.none",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.NONE,
            scope_schema=(),
            bounds_schema=("max_items",),
            approval_required=False,
            prerequisite_artifacts=(),
        )

        admitted = authority_runtime.admit(request, contract)

        self.assertEqual(admitted.request_sha256, request.sha256)
        self.assertIs(admitted.authority_mode, operation_contract.AuthorityMode.NONE)
        with self.assertRaisesRegex(ValueError, "does not admit read"):
            with authority_runtime.open_read(admitted):
                self.fail("NONE admission must not construct a null read session")

    def test_admission_requires_exact_contract_scope_and_bounds(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.exact",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root="/private/tmp/d1a-authority-runtime",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.NONE,
            payload={},
            bounds={},
            scope={"workstream_id": "example-service"},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-exact-v1",
            spec_sha256="b" * 64,
            operation_kind="test.exact",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.NONE,
            scope_schema=("workstream_id", "corpus_id"),
            bounds_schema=("max_items",),
            approval_required=False,
            prerequisite_artifacts=(),
        )

        with self.assertRaisesRegex(ValueError, "exactly match"):
            authority_runtime.admit(request, contract)


class D1aSnapshotModuleArchitectureTest(unittest.TestCase):
    def test_snapshot_module_has_no_durable_or_session_reverse_import(self):
        source_tree = ast.parse(Path(authority_snapshot.__file__).read_text())
        reverse_imports = []
        for node in ast.walk(source_tree):
            if isinstance(node, ast.ImportFrom):
                if node.module in {"durable", "session"}:
                    reverse_imports.append(node.module)
            elif isinstance(node, ast.Import):
                reverse_imports.extend(
                    alias.name
                    for alias in node.names
                    if alias.name.endswith(".durable")
                    or alias.name.endswith(".session")
                )
        self.assertEqual(reverse_imports, [])

    def test_coordinator_owns_snapshot_store_not_raw_sqlite_connection(self):
        slots = authority_session.durable.DurableCoordinator.__slots__
        self.assertIn("__snapshot_store", slots)
        self.assertNotIn("__connection", slots)
        self.assertNotIn("__root", slots)

    def test_retained_legacy_database_opener_has_no_runtime_call_site(self):
        source_tree = ast.parse(
            Path(authority_session.durable.__file__).read_text()
        )
        call_sites = [
            node
            for node in ast.walk(source_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_open_durable_database"
        ]
        self.assertEqual(call_sites, [])

    def test_snapshot_authorizer_denies_attach_and_detach(self):
        self.assertEqual(
            authority_snapshot._DurableSnapshotStore._authorizer(
                sqlite3.SQLITE_ATTACH,
                None,
                None,
                None,
                None,
            ),
            sqlite3.SQLITE_DENY,
        )
        self.assertEqual(
            authority_snapshot._DurableSnapshotStore._authorizer(
                sqlite3.SQLITE_DETACH,
                None,
                None,
                None,
                None,
            ),
            sqlite3.SQLITE_DENY,
        )


class D1aSnapshotStoreBoundaryTest(LedgerRuntimeFixture):
    def setUp(self):
        super().setUp()
        self.migrate_to_v2()

    def test_snapshot_store_uses_memory_only_sqlite_and_denies_attach_detach(self):
        root_info = self.root.stat()
        anchor = authority_snapshot._RootAnchor.open(
            self.root,
            expected_identity=(root_info.st_dev, root_info.st_ino),
        )
        store = authority_snapshot._DurableSnapshotStore.open(anchor)
        try:
            self.assertFalse(hasattr(store, "connection"))
        finally:
            store.close()
        reopened_anchor = authority_snapshot._RootAnchor.open(
            self.root,
            expected_identity=(root_info.st_dev, root_info.st_ino),
        )
        reopened = authority_snapshot._DurableSnapshotStore.open(reopened_anchor)
        try:
            self.assertFalse(hasattr(reopened, "connection"))
        finally:
            reopened.close()

    def test_snapshot_history_is_rejected_from_a_different_root_anchor(self):
        source_info = self.root.stat()
        source_anchor = authority_snapshot._RootAnchor.open(
            self.root,
            expected_identity=(source_info.st_dev, source_info.st_ino),
        )
        source_store = authority_snapshot._DurableSnapshotStore.open(source_anchor)
        source_store.close()

        foreign_root = self.root / "foreign-snapshot-root"
        foreign_root.mkdir(mode=0o700)
        foreign_root.chmod(0o700)
        shutil.copytree(self.root / "_registry", foreign_root / "_registry")
        foreign_info = foreign_root.stat()
        foreign_anchor = authority_snapshot._RootAnchor.open(
            foreign_root,
            expected_identity=(foreign_info.st_dev, foreign_info.st_ino),
        )
        try:
            with self.assertRaises(authority_runtime.AuthorityRuntimeError):
                authority_snapshot._DurableSnapshotStore.open(foreign_anchor)
        finally:
            foreign_anchor.close()


class D1aOperationRequestCodecTest(unittest.TestCase):
    def test_codec_round_trips_only_canonical_operation_request_bytes(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.codec",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root="/private/tmp/d1a-authority-runtime",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.NONE,
            payload={"query": "status"},
            bounds={"max_items": 1},
            scope={"workstream_id": "example-service"},
        )

        decoded = codec.decode_operation_request(request.canonical_bytes)

        self.assertEqual(decoded.canonical_bytes, request.canonical_bytes)
        with self.assertRaisesRegex(ValueError, "canonical operation request"):
            codec.decode_operation_request(b" " + request.canonical_bytes)


class D1aReadSessionBoundaryTest(LedgerRuntimeFixture):
    def setUp(self):
        super().setUp()
        self.migrate_to_v2()
        with ledger_runtime.open_writer_session(self.root):
            pass

    def test_read_admission_exposes_only_registered_read_capabilities(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.read",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-read-v1",
            spec_sha256="b" * 64,
            operation_kind="test.read",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.READ,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )

        admitted = authority_runtime.admit(request, contract)

        with authority_runtime.open_read(admitted) as session:
            self.assertFalse(hasattr(session, "connection"))
            self.assertFalse(hasattr(session, "root"))
            self.assertFalse(hasattr(session, "compiled_policy"))
            self.assertIsInstance(
                session.current_policy_identity(),
                authority_runtime.PolicyIdentity,
            )
            rows = session.read_registered("schema_migrations")
            self.assertGreaterEqual(len(rows), 2)
            with self.assertRaisesRegex(ValueError, "registered read"):
                session.read_registered("SELECT * FROM sqlite_master")

    def test_read_admission_binds_a_current_policy_workstream(self):
        contract = operation_contract.AdmissionContract(
            spec_identity="test-workstream-v1",
            spec_sha256="f" * 64,
            operation_kind="test.workstream",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.READ,
            scope_schema=("workstream_id",),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        admitted = authority_runtime.admit(
            operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="test.workstream",
                action=operation_contract.LifecycleAction.INSPECT,
                claim_mode=operation_contract.ClaimMode.NONE,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.READ,
                payload={},
                bounds={},
                scope={"workstream_id": "example-service"},
            ),
            contract,
        )

        with authority_runtime.open_read(admitted) as session:
            self.assertGreaterEqual(len(session.read_registered("schema_migrations")), 2)

        missing_workstream = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.workstream",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            payload={},
            bounds={},
            scope={"workstream_id": "not-in-current-policy"},
        )
        with self.assertRaisesRegex(authority_runtime.AuthorityRuntimeError, "workstream"):
            authority_runtime.admit(missing_workstream, contract)

    def test_read_session_revokes_when_the_authority_root_identity_changes(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.read_root_identity",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-read-root-identity-v1",
            spec_sha256="c" * 64,
            operation_kind="test.read_root_identity",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.READ,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        admitted = authority_runtime.admit(request, contract)
        replaced_root = self.root.with_name(f"{self.root.name}-read-replaced")

        with authority_runtime.open_read(admitted) as session:
            os.rename(self.root, replaced_root)
            shutil.copytree(replaced_root, self.root)
            try:
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "root identity changed",
                ):
                    session.read_registered("schema_migrations")
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "not active",
                ):
                    session.read_registered("schema_migrations")
            finally:
                if self.root.exists():
                    shutil.rmtree(self.root)
                os.rename(replaced_root, self.root)

    def test_read_session_blocks_post_admission_workstream_pause(self):
        contract = operation_contract.AdmissionContract(
            spec_identity="test-read-workstream-v1",
            spec_sha256="f" * 64,
            operation_kind="test.read_workstream",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.READ,
            scope_schema=("workstream_id",),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        admitted = authority_runtime.admit(
            operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="test.read_workstream",
                action=operation_contract.LifecycleAction.INSPECT,
                claim_mode=operation_contract.ClaimMode.NONE,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.READ,
                payload={},
                bounds={},
                scope={"workstream_id": "example-service"},
            ),
            contract,
        )
        original_registry = self.registry_path.read_bytes()
        paused_registry = original_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )

        with authority_runtime.open_read(admitted) as session:
            replacement = self.registry_directory / "placement-map.read-paused"
            replacement.write_bytes(paused_registry)
            replacement.chmod(0o600)
            os.replace(replacement, self.registry_path)
            try:
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "current policy",
                ):
                    session.read_registered("schema_migrations")
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "not active",
                ):
                    session.read_registered("schema_migrations")
            finally:
                replacement.write_bytes(original_registry)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)


class SimulatedDurableCrash(RuntimeError):
    pass


class D1aWriteRecoveryTest(LedgerRuntimeFixture):
    def setUp(self):
        super().setUp()
        self.migrate_to_v2()

    @contextmanager
    def _independent_write_fixture(self):
        """Run one fault-matrix cell against a fresh temporary authority root."""

        case = type(self)(methodName="runTest")
        case.setUp()
        try:
            yield case
        finally:
            case.doCleanups()

    def _admit_durable_write_effect(
        self,
        *,
        effect_id: str,
        target_path: str,
        artifact_bytes: bytes,
        action: operation_contract.LifecycleAction = operation_contract.LifecycleAction.APPLY,
        actor: str = "operator",
    ):
        contract = operation_contract.AdmissionContract(
            spec_identity="test-durable-write-v1",
            spec_sha256="e" * 64,
            operation_kind="test.durable_write",
            allowed_actions=(
                operation_contract.LifecycleAction.APPLY,
                operation_contract.LifecycleAction.RECOVER,
            ),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.durable_write",
            action=action,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor=actor,
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        effect = authority_runtime.StagedEffect(
            effect_id=effect_id,
            target_relative_path=target_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(
                    f"manifest:{effect_id}".encode("utf-8")
                ),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )
        return authority_runtime.admit(request, contract), effect

    def _durable_state(self, effect_id: str) -> str:
        for record in reversed(self._snapshot_head_records()):
            for observed_effect_id, state in record["effect_rows"]:
                if observed_effect_id == effect_id:
                    return state
        self.fail(f"durable snapshot does not contain effect {effect_id!r}")

    def _write_empty_legacy_v1_database(
        self,
        *,
        extra_state_constraint: bool = False,
    ) -> tuple[Path, Path]:
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        runtime_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        runtime_directory.chmod(0o700)
        legacy_database = runtime_directory / "authority-runtime.sqlite3"
        state_definition = "state TEXT NOT NULL" + (
            " CHECK(state <> '')" if extra_state_constraint else ""
        )
        connection = sqlite3.connect(str(legacy_database))
        try:
            connection.execute(
                "CREATE TABLE durable_effects ("
                "effect_id TEXT NOT NULL PRIMARY KEY, "
                "target_relative_path TEXT NOT NULL UNIQUE, "
                "artifact_ref BLOB NOT NULL, "
                "artifact_bytes BLOB NOT NULL, "
                "request_sha256 TEXT NOT NULL, "
                "scope_sha256 TEXT NOT NULL, "
                "spec_identity TEXT NOT NULL, "
                "spec_sha256 TEXT NOT NULL, "
                "policy_identity_sha256 TEXT NOT NULL, "
                + state_definition
                + ")"
            )
            connection.commit()
        finally:
            connection.close()
        legacy_database.chmod(0o600)
        return runtime_directory, legacy_database

    def _write_legacy_v1_aborted_effect(
        self,
        effect: authority_runtime.StagedEffect,
    ) -> tuple[Path, Path]:
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        connection = sqlite3.connect(str(legacy_database))
        try:
            connection.execute(
                "INSERT INTO durable_effects "
                "(effect_id, target_relative_path, artifact_ref, artifact_bytes, "
                "request_sha256, scope_sha256, spec_identity, spec_sha256, "
                "policy_identity_sha256, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ",
                (
                    effect.effect_id,
                    effect.target_relative_path,
                    effect.artifact_ref.canonical_bytes,
                    effect.artifact_bytes,
                    "a" * 64,
                    "b" * 64,
                    "legacy-aborted-v1",
                    "c" * 64,
                    "d" * 64,
                    authority_runtime.DurableEffectState.ABORTED.value,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        legacy_database.chmod(0o600)
        return runtime_directory, legacy_database

    def _snapshot_stage_path(self, effect_id: str) -> Path:
        return (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "staging"
            / f"{effect_id}.artifact"
        )

    def _snapshot_root_stop_records(self) -> list[dict[str, object]]:
        directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "root-stops"
        )
        if not directory.exists():
            return []
        records: list[dict[str, object]] = []
        for path in sorted(directory.glob("f-*.json")):
            raw = path.read_bytes()
            record = json.loads(raw)
            self.assertEqual(canonical_json_bytes(record), raw)
            self.assertEqual(sha256_bytes(raw), path.stem[2:])
            records.append(record)
        return records

    def _snapshot_head_records(self) -> list[dict[str, object]]:
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        snapshot_directory = runtime_directory / "snapshot-v1"
        objects_directory = snapshot_directory / "objects"
        heads_directory = snapshot_directory / "heads"
        self.assertTrue(heads_directory.is_dir())
        records: list[dict[str, object]] = []
        for head_path in heads_directory.glob("h-*.json"):
            head_raw = head_path.read_bytes()
            head = json.loads(head_raw)
            self.assertEqual(sha256_bytes(head_raw), head_path.stem[2:])
            manifest_raw = (
                objects_directory / f"o-{head['manifest_object_sha256']}"
            ).read_bytes()
            manifest = json.loads(manifest_raw)
            self.assertEqual(
                sha256_bytes(manifest_raw),
                head["manifest_object_sha256"],
            )
            snapshot_raw = (
                objects_directory / f"o-{head['snapshot_object_sha256']}"
            ).read_bytes()
            self.assertEqual(
                sha256_bytes(snapshot_raw),
                head["snapshot_object_sha256"],
            )
            connection = sqlite3.connect(":memory:")
            try:
                connection.row_factory = sqlite3.Row
                connection.deserialize(snapshot_raw)
                transition_row = connection.execute(
                    "SELECT transition_kind FROM snapshot_meta"
                ).fetchone()
                self.assertIsNotNone(transition_row)
                effect_rows = tuple(
                    (row["effect_id"], row["state"])
                    for row in connection.execute(
                        "SELECT effect_id, state FROM durable_effects "
                        "ORDER BY effect_id"
                    )
                )
                binding_rows = tuple(
                    (
                        row["effect_id"],
                        row["target_relative_path"],
                        row["binding_sha256"],
                    )
                    for row in connection.execute(
                        "SELECT effect_id, target_relative_path, binding_sha256 "
                        "FROM durable_effect_bindings ORDER BY effect_id"
                    )
                )
                claim_rows = tuple(
                    (
                        row["effect_id"],
                        row["expected_predecessor_head_sha256"],
                        row["claim_generation"],
                        row["active"],
                    )
                    for row in connection.execute(
                        "SELECT effect_id, expected_predecessor_head_sha256, "
                        "claim_generation, active FROM durable_claims "
                        "ORDER BY effect_id"
                    )
                )
                target_claim_rows = tuple(
                    (
                        row["target_relative_path"],
                        row["effect_id"],
                        row["binding_sha256"],
                    )
                    for row in connection.execute(
                        "SELECT target_relative_path, effect_id, binding_sha256 "
                        "FROM durable_target_claims ORDER BY target_relative_path"
                    )
                )
                published_attestation_rows = tuple(
                    tuple(row)
                    for row in connection.execute(
                        "SELECT effect_id, target_relative_path, binding_sha256, "
                        "artifact_bytes_sha256, byte_length, target_device, target_inode, "
                        "target_nlink, attestation_sha256 "
                        "FROM durable_published_attestations ORDER BY effect_id"
                    )
                )
                final_cas_rows = tuple(
                    tuple(row)
                    for row in connection.execute(
                        "SELECT effect_id, binding_sha256, published_attestation_sha256, "
                        "expected_state, resulting_state, result_sha256 "
                        "FROM durable_final_cas_results ORDER BY effect_id"
                    )
                )
                recovery_blocker_rows = tuple(
                    tuple(row)
                    for row in connection.execute(
                        "SELECT effect_id, binding_sha256, reason_code, "
                        "observed_evidence_sha256, token_request_sha256, "
                        "token_continuation_identity, blocker_sha256 "
                        "FROM durable_recovery_blockers ORDER BY effect_id"
                    )
                )
                migration_provenance_rows = tuple(
                    tuple(row)
                    for row in connection.execute(
                        "SELECT singleton, legacy_provenance_sha256, "
                        "retired_witness_sha256 FROM durable_migration_provenance "
                        "ORDER BY singleton"
                    )
                )
            finally:
                connection.close()
            records.append(
                {
                    "head": head,
                    "manifest": manifest,
                    "transition_kind": transition_row["transition_kind"],
                    "effect_rows": effect_rows,
                    "binding_rows": binding_rows,
                    "claim_rows": claim_rows,
                    "target_claim_rows": target_claim_rows,
                    "published_attestation_rows": published_attestation_rows,
                    "final_cas_rows": final_cas_rows,
                    "recovery_blocker_rows": recovery_blocker_rows,
                    "migration_provenance_rows": migration_provenance_rows,
                }
            )
        return sorted(records, key=lambda record: record["head"]["generation"])

    def _snapshot_binding_for_effect(self, effect_id: str):
        records = self._snapshot_head_records()
        self.assertTrue(records)
        head = records[-1]["head"]
        self.assertIsInstance(head, dict)
        snapshot_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "objects"
            / f"o-{head['snapshot_object_sha256']}"
        )
        connection = sqlite3.connect(":memory:")
        try:
            connection.row_factory = sqlite3.Row
            connection.deserialize(snapshot_path.read_bytes())
            row = connection.execute(
                "SELECT effect_id, target_relative_path, artifact_ref_sha256, "
                "request_sha256, scope_sha256, bounds_sha256, spec_identity, "
                "spec_sha256, policy_identity_sha256, token_request_sha256, "
                "token_continuation_identity, token_authentication_tag, binding_sha256 "
                "FROM durable_effect_bindings WHERE effect_id = ?",
                (effect_id,),
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(row)
        value = authority_snapshot._SnapshotBindingValue(
            effect_id=row["effect_id"],
            target_relative_path=row["target_relative_path"],
            artifact_ref_sha256=row["artifact_ref_sha256"],
            request_sha256=row["request_sha256"],
            scope_sha256=row["scope_sha256"],
            bounds_sha256=row["bounds_sha256"],
            spec_identity=row["spec_identity"],
            spec_sha256=row["spec_sha256"],
            policy_identity_sha256=row["policy_identity_sha256"],
            token_request_sha256=row["token_request_sha256"],
            token_continuation_identity=row["token_continuation_identity"],
            token_authentication_tag=row["token_authentication_tag"],
            binding_sha256=row["binding_sha256"],
        )
        return authority_session.durable.DurableCoordinator._binding_from_snapshot_value(
            value,
            expected_effect_id=effect_id,
        )

    def _add_snapshot_head_candidate(
        self,
        raw: bytes,
        *,
        receipt_token: str,
    ) -> str:
        """Add one isolated, sealed head candidate without making it valid history."""

        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        head_sha256 = sha256_bytes(raw)
        receipt_path = receipts_directory / f"r-{head_sha256}-{receipt_token}"
        head_path = heads_directory / f"h-{head_sha256}.json"
        self.assertFalse(receipt_path.exists())
        self.assertFalse(head_path.exists())
        receipt_path.write_bytes(raw)
        receipt_path.chmod(0o600)
        os.link(receipt_path, head_path)
        return head_sha256

    @staticmethod
    def _seal_snapshot_binding(
        value: authority_snapshot._SnapshotBindingValue,
        *,
        token_key: bytes,
        **changes: object,
    ) -> authority_snapshot._SnapshotBindingValue:
        provisional = replace(
            value,
            token_continuation_identity="",
            token_authentication_tag="",
            binding_sha256="",
            **changes,
        )
        continuation_identity = (
            authority_snapshot._DurableSnapshotStore._binding_continuation_identity(
                provisional
            )
        )
        authentication_tag = hmac.new(
            token_key,
            canonical_json_bytes(
                {
                    "schema_version": 1,
                    "effect_id": provisional.effect_id,
                    "request_sha256": provisional.token_request_sha256,
                    "continuation_identity": continuation_identity,
                }
            ),
            sha256,
        ).hexdigest()
        signed = replace(
            provisional,
            token_continuation_identity=continuation_identity,
            token_authentication_tag=authentication_tag,
        )
        return replace(
            signed,
            binding_sha256=sha256_bytes(
                authority_snapshot._DurableSnapshotStore._binding_canonical_bytes(
                    signed
                )
            ),
        )

    @staticmethod
    def _seal_published_attestation(
        value: authority_snapshot._SnapshotPublishedAttestationValue,
        **changes: object,
    ) -> authority_snapshot._SnapshotPublishedAttestationValue:
        provisional = replace(value, attestation_sha256="", **changes)
        return replace(
            provisional,
            attestation_sha256=(
                authority_snapshot._DurableSnapshotStore.published_attestation_sha256(
                    provisional
                )
            ),
        )

    @staticmethod
    def _seal_final_cas_result(
        value: authority_snapshot._SnapshotFinalCasResultValue,
        **changes: object,
    ) -> authority_snapshot._SnapshotFinalCasResultValue:
        provisional = replace(value, result_sha256="", **changes)
        return replace(
            provisional,
            result_sha256=(
                authority_snapshot._DurableSnapshotStore.final_cas_result_sha256(
                    provisional
                )
            ),
        )

    def _assert_namespace_parent_replacement_fences(
        self,
        *,
        directory_name: str,
    ) -> None:
        admitted, _effect = self._admit_durable_write_effect(
            effect_id=f"effect-{directory_name}-parent-replacement",
            target_path=f"outputs/{directory_name}-parent-replacement.json",
            artifact_bytes=(
                f'{{"effect":"{directory_name}-parent-replacement"}}\n'.encode(
                    "utf-8"
                )
            ),
        )
        with authority_runtime.open_write(admitted):
            pass

        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        directory = snapshot_directory / directory_name
        retired_directory = snapshot_directory / f"{directory_name}-retired-for-test"
        original_list_directory = authority_snapshot._RootAnchor.list_directory
        original_validate_hydrated_snapshot = (
            authority_snapshot._DurableSnapshotStore._validate_hydrated_snapshot.__func__
        )
        replacement_done = False
        hydration_attempted = False

        def replace_parent_after_head_enumeration(anchor, path):
            nonlocal replacement_done
            names = original_list_directory(anchor, path)
            if (
                not replacement_done
                and path.parts == authority_snapshot._SNAPSHOT_HEADS_PARTS
            ):
                replacement_done = True
                os.rename(directory, retired_directory)
                os.mkdir(directory, 0o700)
                for name in os.listdir(retired_directory):
                    os.rename(retired_directory / name, directory / name)
                retired_directory.rmdir()
            return names

        def record_hydration(cls, root, snapshot_raw, head, manifest):
            nonlocal hydration_attempted
            hydration_attempted = True
            return original_validate_hydrated_snapshot(
                cls,
                root,
                snapshot_raw,
                head,
                manifest,
            )

        with mock.patch.object(
            authority_snapshot._RootAnchor,
            "list_directory",
            new=replace_parent_after_head_enumeration,
        ):
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "_validate_hydrated_snapshot",
                new=classmethod(record_hydration),
            ):
                with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
                    with authority_runtime.open_write(admitted):
                        self.fail("a replaced snapshot namespace parent must not be adopted")
        self.assertTrue(replacement_done)
        self.assertFalse(hydration_attempted)

    @staticmethod
    def _snapshot_recovery_projection(connection: sqlite3.Connection) -> str:
        projection = {
            "snapshot_meta": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT transition_kind, generation, parent_head_sha256, "
                    "publication_nonce FROM snapshot_meta ORDER BY singleton"
                )
            ),
            "durable_effects": tuple(
                (
                    row["effect_id"],
                    row["target_relative_path"],
                    sha256_bytes(bytes(row["artifact_ref"])),
                    sha256_bytes(bytes(row["artifact_bytes"])),
                    row["request_sha256"],
                    row["scope_sha256"],
                    row["spec_identity"],
                    row["spec_sha256"],
                    row["policy_identity_sha256"],
                    row["state"],
                )
                for row in connection.execute(
                    "SELECT effect_id, target_relative_path, artifact_ref, artifact_bytes, "
                    "request_sha256, scope_sha256, spec_identity, spec_sha256, "
                    "policy_identity_sha256, state FROM durable_effects ORDER BY effect_id"
                )
            ),
            "durable_claims": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT claim_key_sha256, effect_id, target_relative_path, "
                    "artifact_ref_sha256, artifact_bytes_sha256, request_sha256, "
                    "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                    "policy_identity_sha256, expected_predecessor_head_sha256, "
                    "claim_generation, active FROM durable_claims ORDER BY claim_key_sha256"
                )
            ),
            "recovery_token_keys": tuple(
                (
                    row["singleton"],
                    sha256_bytes(bytes(row["token_key"])),
                    row["key_sha256"],
                )
                for row in connection.execute(
                    "SELECT singleton, token_key, key_sha256 "
                    "FROM recovery_token_keys ORDER BY singleton"
                )
            ),
            "durable_effect_bindings": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT effect_id, target_relative_path, artifact_ref_sha256, "
                    "request_sha256, scope_sha256, bounds_sha256, spec_identity, "
                    "spec_sha256, policy_identity_sha256, token_request_sha256, "
                    "token_continuation_identity, token_authentication_tag, binding_sha256 "
                    "FROM durable_effect_bindings ORDER BY effect_id"
                )
            ),
            "durable_target_claims": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT target_relative_path, effect_id, binding_sha256 "
                    "FROM durable_target_claims ORDER BY target_relative_path"
                )
            ),
            "durable_published_attestations": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT effect_id, target_relative_path, binding_sha256, "
                    "artifact_bytes_sha256, byte_length, target_device, target_inode, "
                    "target_nlink, attestation_sha256 "
                    "FROM durable_published_attestations ORDER BY effect_id"
                )
            ),
            "durable_final_cas_results": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT effect_id, binding_sha256, published_attestation_sha256, "
                    "expected_state, resulting_state, result_sha256 "
                    "FROM durable_final_cas_results ORDER BY effect_id"
                )
            ),
            "durable_recovery_blockers": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT effect_id, binding_sha256, reason_code, "
                    "observed_evidence_sha256, token_request_sha256, "
                    "token_continuation_identity, blocker_sha256 "
                    "FROM durable_recovery_blockers ORDER BY effect_id"
                )
            ),
            "durable_migration_provenance": tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT singleton, legacy_provenance_sha256, retired_witness_sha256 "
                    "FROM durable_migration_provenance ORDER BY singleton"
                )
            ),
        }
        return sha256_bytes(canonical_json_bytes(projection))

    @staticmethod
    def _snapshot_schema_fingerprint(connection: sqlite3.Connection) -> str:
        rows = tuple(
            (row["type"], row["name"], row["tbl_name"], row["sql"])
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        )
        return sha256_bytes(canonical_json_bytes(rows))

    def _rekey_claimed_snapshot_predecessor(
        self,
        forged_predecessor: str,
        *,
        transition_kind: str | None = None,
    ) -> None:
        """Rewrite C while preserving a syntactically sealed history."""

        records = self._snapshot_head_records()
        self.assertEqual([record["transition_kind"] for record in records], [
            "EMPTY_GENESIS",
            "CLAIMED",
        ])
        claimed = records[-1]
        old_head = claimed["head"]
        self.assertIsInstance(old_head, dict)
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        objects_directory = snapshot_directory / "objects"
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        snapshot_path = objects_directory / f"o-{old_head['snapshot_object_sha256']}"
        connection = sqlite3.connect(":memory:")
        try:
            connection.row_factory = sqlite3.Row
            connection.deserialize(snapshot_path.read_bytes())
            claim = connection.execute(
                "SELECT claim_key_sha256, effect_id, target_relative_path, "
                "artifact_ref_sha256, artifact_bytes_sha256, request_sha256, "
                "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                "policy_identity_sha256 FROM durable_claims WHERE active = 1"
            ).fetchone()
            self.assertIsNotNone(claim)
            claim_key = authority_snapshot._DurableSnapshotStore._claim_key(
                effect_id=claim["effect_id"],
                target_relative_path=claim["target_relative_path"],
                artifact_ref_sha256=claim["artifact_ref_sha256"],
                artifact_bytes_sha256=claim["artifact_bytes_sha256"],
                request_sha256=claim["request_sha256"],
                scope_sha256=claim["scope_sha256"],
                bounds_sha256=claim["bounds_sha256"],
                spec_identity=claim["spec_identity"],
                spec_sha256=claim["spec_sha256"],
                policy_identity_sha256=claim["policy_identity_sha256"],
                anchor_identity_sha256=sha256_bytes(
                    canonical_json_bytes(
                        (self.root.stat().st_dev, self.root.stat().st_ino)
                    )
                ),
                expected_predecessor_head_sha256=forged_predecessor,
            )
            connection.execute(
                "UPDATE durable_claims SET claim_key_sha256 = ?, "
                "expected_predecessor_head_sha256 = ? WHERE active = 1",
                (claim_key, forged_predecessor),
            )
            if transition_kind is not None:
                connection.execute(
                    "UPDATE snapshot_meta SET transition_kind = ? "
                    "WHERE singleton = 1",
                    (transition_kind,),
                )
            connection.commit()
            snapshot_raw = connection.serialize()
            snapshot_sha256 = sha256_bytes(snapshot_raw)
            recovery_projection = self._snapshot_recovery_projection(connection)
            schema_fingerprint = self._snapshot_schema_fingerprint(connection)
        finally:
            connection.close()

        manifest = claimed["manifest"]
        self.assertIsInstance(manifest, dict)
        manifest = dict(manifest)
        manifest.update(
            {
                "snapshot_object_sha256": snapshot_sha256,
                "snapshot_byte_length": len(snapshot_raw),
                "sqlite_schema_fingerprint_sha256": schema_fingerprint,
                "recovery_projection_sha256": recovery_projection,
            }
        )
        manifest_raw = canonical_json_bytes(manifest)
        manifest_sha256 = sha256_bytes(manifest_raw)
        new_head = dict(old_head)
        new_head.update(
            {
                "manifest_object_sha256": manifest_sha256,
                "snapshot_object_sha256": snapshot_sha256,
                "recovery_projection_sha256": recovery_projection,
                "sqlite_schema_fingerprint_sha256": schema_fingerprint,
            }
        )
        new_head_raw = canonical_json_bytes(new_head)
        new_head_sha256 = sha256_bytes(new_head_raw)
        self.assertNotEqual(new_head_sha256, sha256_bytes(canonical_json_bytes(old_head)))

        for path, raw in (
            (objects_directory / f"o-{snapshot_sha256}", snapshot_raw),
            (objects_directory / f"o-{manifest_sha256}", manifest_raw),
            (
                receipts_directory
                / f"r-{new_head_sha256}-{new_head['receipt_token']}",
                new_head_raw,
            ),
        ):
            path.write_bytes(raw)
            path.chmod(0o600)
        new_receipt = (
            receipts_directory / f"r-{new_head_sha256}-{new_head['receipt_token']}"
        )
        os.link(new_receipt, heads_directory / f"h-{new_head_sha256}.json")
        old_head_sha256 = sha256_bytes(canonical_json_bytes(old_head))
        (heads_directory / f"h-{old_head_sha256}.json").unlink()
        (
            receipts_directory / f"r-{old_head_sha256}-{old_head['receipt_token']}"
        ).unlink()

    def _replace_tip_manifest_raw(self, raw: bytes) -> None:
        """Replace one tip manifest with arbitrary sealed test bytes."""

        tip = self._snapshot_head_records()[-1]
        old_head = tip["head"]
        self.assertIsInstance(old_head, dict)
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        objects_directory = snapshot_directory / "objects"
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        manifest_sha256 = sha256_bytes(raw)
        new_head = dict(old_head)
        new_head["manifest_object_sha256"] = manifest_sha256
        new_head_raw = canonical_json_bytes(new_head)
        new_head_sha256 = sha256_bytes(new_head_raw)
        (objects_directory / f"o-{manifest_sha256}").write_bytes(raw)
        (objects_directory / f"o-{manifest_sha256}").chmod(0o600)
        new_receipt = (
            receipts_directory / f"r-{new_head_sha256}-{new_head['receipt_token']}"
        )
        new_receipt.write_bytes(new_head_raw)
        new_receipt.chmod(0o600)
        os.link(new_receipt, heads_directory / f"h-{new_head_sha256}.json")
        old_head_sha256 = sha256_bytes(canonical_json_bytes(old_head))
        (heads_directory / f"h-{old_head_sha256}.json").unlink()
        (
            receipts_directory / f"r-{old_head_sha256}-{old_head['receipt_token']}"
        ).unlink()

    def _replace_tip_snapshot_raw(self, raw: bytes) -> None:
        """Replace one tip SQLite payload while keeping head bindings sealed."""

        tip = self._snapshot_head_records()[-1]
        old_head = tip["head"]
        old_manifest = tip["manifest"]
        self.assertIsInstance(old_head, dict)
        self.assertIsInstance(old_manifest, dict)
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        objects_directory = snapshot_directory / "objects"
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        snapshot_sha256 = sha256_bytes(raw)
        manifest = dict(old_manifest)
        manifest.update(
            {
                "snapshot_object_sha256": snapshot_sha256,
                "snapshot_byte_length": len(raw),
            }
        )
        manifest_raw = canonical_json_bytes(manifest)
        manifest_sha256 = sha256_bytes(manifest_raw)
        new_head = dict(old_head)
        new_head.update(
            {
                "snapshot_object_sha256": snapshot_sha256,
                "manifest_object_sha256": manifest_sha256,
            }
        )
        new_head_raw = canonical_json_bytes(new_head)
        new_head_sha256 = sha256_bytes(new_head_raw)
        for path, value in (
            (objects_directory / f"o-{snapshot_sha256}", raw),
            (objects_directory / f"o-{manifest_sha256}", manifest_raw),
            (
                receipts_directory / f"r-{new_head_sha256}-{new_head['receipt_token']}",
                new_head_raw,
            ),
        ):
            path.write_bytes(value)
            path.chmod(0o600)
        new_receipt = (
            receipts_directory / f"r-{new_head_sha256}-{new_head['receipt_token']}"
        )
        os.link(new_receipt, heads_directory / f"h-{new_head_sha256}.json")
        old_head_sha256 = sha256_bytes(canonical_json_bytes(old_head))
        (heads_directory / f"h-{old_head_sha256}.json").unlink()
        (
            receipts_directory / f"r-{old_head_sha256}-{old_head['receipt_token']}"
        ).unlink()

    def _reseal_tip_manifest(
        self,
        *,
        head_updates: dict[str, object] | None = None,
        **updates: object,
    ) -> None:
        """Rewrite the terminal manifest/head/receipt with valid content hashes."""

        tip = self._snapshot_head_records()[-1]
        old_head = tip["head"]
        manifest = tip["manifest"]
        self.assertIsInstance(old_head, dict)
        self.assertIsInstance(manifest, dict)
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        objects_directory = snapshot_directory / "objects"
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        new_manifest = dict(manifest)
        new_manifest.update(updates)
        manifest_raw = canonical_json_bytes(new_manifest)
        manifest_sha256 = sha256_bytes(manifest_raw)
        new_head = dict(old_head)
        new_head["manifest_object_sha256"] = manifest_sha256
        if head_updates is not None:
            new_head.update(head_updates)
        new_head_raw = canonical_json_bytes(new_head)
        new_head_sha256 = sha256_bytes(new_head_raw)
        (objects_directory / f"o-{manifest_sha256}").write_bytes(manifest_raw)
        (objects_directory / f"o-{manifest_sha256}").chmod(0o600)
        new_receipt = (
            receipts_directory / f"r-{new_head_sha256}-{new_head['receipt_token']}"
        )
        new_receipt.write_bytes(new_head_raw)
        new_receipt.chmod(0o600)
        os.link(new_receipt, heads_directory / f"h-{new_head_sha256}.json")
        old_head_sha256 = sha256_bytes(canonical_json_bytes(old_head))
        (heads_directory / f"h-{old_head_sha256}.json").unlink()
        (
            receipts_directory / f"r-{old_head_sha256}-{old_head['receipt_token']}"
        ).unlink()

    def _reseal_tip_snapshot(self, mutator) -> None:
        """Replace a terminal snapshot and re-seal every direct reference to it."""

        tip = self._snapshot_head_records()[-1]
        old_head = tip["head"]
        manifest = tip["manifest"]
        self.assertIsInstance(old_head, dict)
        self.assertIsInstance(manifest, dict)
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        objects_directory = snapshot_directory / "objects"
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        snapshot_path = objects_directory / f"o-{old_head['snapshot_object_sha256']}"
        connection = sqlite3.connect(":memory:")
        try:
            connection.row_factory = sqlite3.Row
            connection.deserialize(snapshot_path.read_bytes())
            mutator(connection)
            connection.commit()
            snapshot_raw = connection.serialize()
            snapshot_sha256 = sha256_bytes(snapshot_raw)
            recovery_projection = self._snapshot_recovery_projection(connection)
            schema_fingerprint = self._snapshot_schema_fingerprint(connection)
        finally:
            connection.close()
        new_manifest = dict(manifest)
        new_manifest.update(
            {
                "snapshot_object_sha256": snapshot_sha256,
                "snapshot_byte_length": len(snapshot_raw),
                "sqlite_schema_fingerprint_sha256": schema_fingerprint,
                "recovery_projection_sha256": recovery_projection,
            }
        )
        manifest_raw = canonical_json_bytes(new_manifest)
        manifest_sha256 = sha256_bytes(manifest_raw)
        new_head = dict(old_head)
        new_head.update(
            {
                "manifest_object_sha256": manifest_sha256,
                "snapshot_object_sha256": snapshot_sha256,
                "sqlite_schema_fingerprint_sha256": schema_fingerprint,
                "recovery_projection_sha256": recovery_projection,
            }
        )
        new_head_raw = canonical_json_bytes(new_head)
        new_head_sha256 = sha256_bytes(new_head_raw)
        for path, raw in (
            (objects_directory / f"o-{snapshot_sha256}", snapshot_raw),
            (objects_directory / f"o-{manifest_sha256}", manifest_raw),
            (
                receipts_directory
                / f"r-{new_head_sha256}-{new_head['receipt_token']}",
                new_head_raw,
            ),
        ):
            path.write_bytes(raw)
            path.chmod(0o600)
        new_receipt = (
            receipts_directory / f"r-{new_head_sha256}-{new_head['receipt_token']}"
        )
        os.link(new_receipt, heads_directory / f"h-{new_head_sha256}.json")
        old_head_sha256 = sha256_bytes(canonical_json_bytes(old_head))
        (heads_directory / f"h-{old_head_sha256}.json").unlink()
        (
            receipts_directory / f"r-{old_head_sha256}-{old_head['receipt_token']}"
        ).unlink()

    def _rebuild_history_suffix(self, start_generation: int, mutator) -> None:
        """Re-seal a changed generation and every child that names its head."""

        records = self._snapshot_head_records()
        self.assertGreaterEqual(start_generation, 0)
        self.assertLess(start_generation, len(records))
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        objects_directory = snapshot_directory / "objects"
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        previous_head_sha256 = (
            None
            if start_generation == 0
            else sha256_bytes(canonical_json_bytes(records[start_generation - 1]["head"]))
        )
        for record in records[start_generation:]:
            old_head = record["head"]
            manifest = record["manifest"]
            self.assertIsInstance(old_head, dict)
            self.assertIsInstance(manifest, dict)
            snapshot_path = (
                objects_directory / f"o-{old_head['snapshot_object_sha256']}"
            )
            connection = sqlite3.connect(":memory:")
            try:
                connection.row_factory = sqlite3.Row
                connection.deserialize(snapshot_path.read_bytes())
                if old_head["generation"] == start_generation:
                    mutator(connection)
                if previous_head_sha256 is not None:
                    connection.execute(
                        "UPDATE snapshot_meta SET parent_head_sha256 = ? "
                        "WHERE singleton = 1",
                        (previous_head_sha256,),
                    )
                connection.commit()
                snapshot_raw = connection.serialize()
                snapshot_sha256 = sha256_bytes(snapshot_raw)
                recovery_projection = self._snapshot_recovery_projection(connection)
                schema_fingerprint = self._snapshot_schema_fingerprint(connection)
            finally:
                connection.close()
            new_manifest = dict(manifest)
            new_manifest.update(
                {
                    "snapshot_object_sha256": snapshot_sha256,
                    "snapshot_byte_length": len(snapshot_raw),
                    "sqlite_schema_fingerprint_sha256": schema_fingerprint,
                    "recovery_projection_sha256": recovery_projection,
                }
            )
            manifest_raw = canonical_json_bytes(new_manifest)
            manifest_sha256 = sha256_bytes(manifest_raw)
            new_head = dict(old_head)
            new_head.update(
                {
                    "parent_head_sha256": previous_head_sha256,
                    "manifest_object_sha256": manifest_sha256,
                    "snapshot_object_sha256": snapshot_sha256,
                    "sqlite_schema_fingerprint_sha256": schema_fingerprint,
                    "recovery_projection_sha256": recovery_projection,
                }
            )
            new_head_raw = canonical_json_bytes(new_head)
            new_head_sha256 = sha256_bytes(new_head_raw)
            for path, raw in (
                (objects_directory / f"o-{snapshot_sha256}", snapshot_raw),
                (objects_directory / f"o-{manifest_sha256}", manifest_raw),
                (
                    receipts_directory
                    / f"r-{new_head_sha256}-{new_head['receipt_token']}",
                    new_head_raw,
                ),
            ):
                path.write_bytes(raw)
                path.chmod(0o600)
            new_receipt = (
                receipts_directory
                / f"r-{new_head_sha256}-{new_head['receipt_token']}"
            )
            os.link(new_receipt, heads_directory / f"h-{new_head_sha256}.json")
            old_head_sha256 = sha256_bytes(canonical_json_bytes(old_head))
            (heads_directory / f"h-{old_head_sha256}.json").unlink()
            (
                receipts_directory
                / f"r-{old_head_sha256}-{old_head['receipt_token']}"
            ).unlink()
            previous_head_sha256 = new_head_sha256

    def test_staged_effect_rejects_payload_larger_than_durable_limit(self):
        oversized_payload = b"x" * (64 * 1024 * 1024 + 1)

        with self.assertRaisesRegex(ValueError, "maximum"):
            self._admit_durable_write_effect(
                effect_id="effect-oversized-payload",
                target_path="outputs/oversized-payload.json",
                artifact_bytes=oversized_payload,
            )

    def test_fresh_root_prepares_snapshot_claim_and_effect_without_v1_database(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-snapshot-first-vertical",
            target_path="outputs/snapshot-first-vertical.json",
            artifact_bytes=b'{"effect":"snapshot-first-vertical"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
        )
        self.assertEqual(
            [record["head"]["generation"] for record in records],
            [0, 1, 2],
        )
        self.assertEqual(records[1]["effect_rows"], ())
        self.assertEqual(records[1]["binding_rows"], ())
        self.assertEqual(records[1]["target_claim_rows"], ())
        self.assertEqual(
            records[2]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )
        self.assertEqual(
            [row[:2] for row in records[2]["binding_rows"]],
            [(effect.effect_id, effect.target_relative_path)],
        )
        self.assertEqual(
            [row[:2] for row in records[2]["target_claim_rows"]],
            [(effect.target_relative_path, effect.effect_id)],
        )
        self.assertFalse((runtime_directory / "authority-runtime.sqlite3").exists())
        self.assertFalse((runtime_directory / "database-bridge-leases").exists())
        self.assertFalse((runtime_directory / "recovery-token.key").exists())
        self.assertFalse(
            (runtime_directory / "recovery-token-key-attestation.json").exists()
        )
        self.assertFalse((runtime_directory / "recovery-bindings").exists())
        self.assertFalse((runtime_directory / "recovery-target-claims").exists())

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            (self.root / effect.target_relative_path).read_bytes(),
            effect.artifact_bytes,
        )
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            [
                "EMPTY_GENESIS",
                "CLAIMED",
                "PREPARED",
                "PUBLISHED",
                "FINALIZED",
            ],
        )
        completed_records = self._snapshot_head_records()
        binding_sha256 = completed_records[2]["binding_rows"][0][2]
        self.assertEqual(completed_records[2]["published_attestation_rows"], ())
        published = completed_records[3]["published_attestation_rows"]
        self.assertEqual(len(published), 1)
        self.assertEqual(
            published[0][:5],
            (
                effect.effect_id,
                effect.target_relative_path,
                binding_sha256,
                sha256_bytes(effect.artifact_bytes),
                len(effect.artifact_bytes),
            ),
        )
        self.assertGreaterEqual(published[0][5], 0)
        self.assertGreaterEqual(published[0][6], 0)
        self.assertGreaterEqual(published[0][7], 1)
        self.assertRegex(published[0][8], r"^[0-9a-f]{64}$")
        self.assertEqual(completed_records[3]["final_cas_rows"], ())
        final_cas = completed_records[4]["final_cas_rows"]
        self.assertEqual(len(final_cas), 1)
        self.assertEqual(
            final_cas[0][:5],
            (
                effect.effect_id,
                binding_sha256,
                published[0][8],
                authority_runtime.DurableEffectState.PUBLISHED.value,
                authority_runtime.DurableEffectState.FINALIZED.value,
            ),
        )
        self.assertRegex(final_cas[0][5], r"^[0-9a-f]{64}$")
        with authority_runtime.open_write(admitted):
            pass
        self.assertFalse((runtime_directory / "authority-runtime.sqlite3").exists())

    def test_fresh_snapshot_blocks_with_sealed_recovery_evidence(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-snapshot-blocker-evidence",
            target_path="outputs/snapshot-blocker-evidence.json",
            artifact_bytes=b'{"effect":"snapshot-blocker-evidence"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            coordinator = session._WriteSession__coordinator
            blocked = coordinator._block_for_token(
                token,
                message="isolated blocker evidence test",
                reason_code="RECOVERY_TEST_BLOCK",
            )

        self.assertIsInstance(blocked, authority_runtime.DurableRecoveryRequired)
        self.assertIsNotNone(blocked.directive)
        self.assertEqual(blocked.directive.token, token)
        self.assertEqual(blocked.directive.reason_code, "RECOVERY_TEST_BLOCK")
        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED", "BLOCKED_RECOVERY"],
        )
        binding = self._snapshot_binding_for_effect(effect.effect_id)
        blocker_rows = records[-1]["recovery_blocker_rows"]
        self.assertEqual(len(blocker_rows), 1)
        self.assertEqual(
            blocker_rows[0][:6],
            (
                effect.effect_id,
                binding.binding_sha256,
                "RECOVERY_TEST_BLOCK",
                blocked.directive.observed_evidence_sha256,
                token.request_sha256,
                token.continuation_identity,
            ),
        )
        self.assertRegex(blocker_rows[0][6], r"^[0-9a-f]{64}$")
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "recovery-blockers"
                / f"{effect.effect_id}.json"
            ).exists()
        )

        with authority_runtime.open_write(admitted):
            pass

    def test_v2_prepared_snapshot_fences_a_new_legacy_database(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-new-legacy-database",
            target_path="outputs/new-legacy-database.json",
            artifact_bytes=b'{"effect":"new-legacy-database"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)
        before_records = self._snapshot_head_records()
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        before_bytes = legacy_database.read_bytes()
        before_info = legacy_database.stat()

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("a new V1 database must fence the normal V2 lineage")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(legacy_database.read_bytes(), before_bytes)
        after_info = legacy_database.stat()
        self.assertEqual(
            (after_info.st_dev, after_info.st_ino, after_info.st_size),
            (before_info.st_dev, before_info.st_ino, before_info.st_size),
        )
        self.assertEqual(self._snapshot_head_records(), before_records)
        self.assertEqual(self._snapshot_root_stop_records(), [])
        self.assertFalse((self.root / effect.target_relative_path).exists())
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

    def test_l9_legacy_schema_mismatch_fences_without_mutating_v1_input(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-schema-fence",
            target_path="outputs/legacy-schema-fence.json",
            artifact_bytes=b'{"effect":"legacy-schema-fence"}\n',
        )
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        runtime_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        runtime_directory.chmod(0o700)
        legacy_database = runtime_directory / "authority-runtime.sqlite3"
        connection = sqlite3.connect(str(legacy_database))
        try:
            connection.execute(
                "CREATE TABLE durable_effects ("
                "effect_id TEXT NOT NULL PRIMARY KEY, "
                "target_relative_path TEXT NOT NULL, "
                "artifact_ref BLOB NOT NULL, "
                "artifact_bytes BLOB NOT NULL, "
                "request_sha256 TEXT NOT NULL, "
                "scope_sha256 TEXT NOT NULL, "
                "spec_identity TEXT NOT NULL, "
                "spec_sha256 TEXT NOT NULL, "
                "policy_identity_sha256 TEXT NOT NULL, "
                "state TEXT NOT NULL"
                ")"
            )
            connection.commit()
        finally:
            connection.close()
        legacy_database.chmod(0o600)
        before_bytes = legacy_database.read_bytes()
        before_info = legacy_database.stat()
        before_identity = (
            before_info.st_dev,
            before_info.st_ino,
            before_info.st_nlink,
            before_info.st_uid,
            stat.S_IMODE(before_info.st_mode),
            before_info.st_size,
        )
        self.assertFalse((runtime_directory / "snapshot-v1" / "heads").exists())

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as first:
            with authority_runtime.open_write(admitted):
                self.fail("a mismatched V1 schema must not become V2 genesis")

        self.assertEqual(first.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(legacy_database.read_bytes(), before_bytes)
        after_info = legacy_database.stat()
        self.assertEqual(
            (
                after_info.st_dev,
                after_info.st_ino,
                after_info.st_nlink,
                after_info.st_uid,
                stat.S_IMODE(after_info.st_mode),
                after_info.st_size,
            ),
            before_identity,
        )
        self.assertFalse(
            (runtime_directory / "snapshot-v1").exists(),
            "a non-L1 manual fence must not create a V2 namespace",
        )
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as second:
            with authority_runtime.open_write(admitted):
                self.fail("the same mismatched V1 schema must remain fenced")
        self.assertEqual(second.exception.reason_code, first.exception.reason_code)
        self.assertEqual(second.exception.observed_evidence_sha256, first.exception.observed_evidence_sha256)
        self.assertEqual(legacy_database.read_bytes(), before_bytes)
        self.assertFalse((runtime_directory / "snapshot-v1").exists())

    def test_non_l1_legacy_artifacts_return_manual_review_without_root_stop(self):
        cases = (
            ("sidecar", ("legacy-sidecar.json",)),
            ("bridge", ("database-bridge-leases", "lease.json")),
            ("stage", ("staging", "old-stage.artifact")),
            ("root-fence", ("recovery-fences", "root-recovery-fence.json")),
            ("unknown", ("unknown-legacy-artifact",)),
        )
        for label, relative_parts in cases:
            with self.subTest(label=label), self._independent_write_fixture() as case:
                admitted, _effect = case._admit_durable_write_effect(
                    effect_id=f"effect-legacy-{label}",
                    target_path=f"outputs/legacy-{label}.json",
                    artifact_bytes=f'{{"effect":"legacy-{label}"}}\n'.encode("utf-8"),
                )
                runtime_directory = (
                    case.root / "_registry" / "curation" / "authority-runtime"
                )
                artifact = runtime_directory.joinpath(*relative_parts)
                artifact.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                artifact.write_bytes(f"legacy-{label}\n".encode("utf-8"))
                artifact.chmod(0o600)
                before_bytes = artifact.read_bytes()

                with case.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
                    with authority_runtime.open_write(admitted):
                        case.fail("a non-L1 legacy artifact must stop for manual review")

                case.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
                case.assertEqual(artifact.read_bytes(), before_bytes)
                case.assertFalse(
                    (runtime_directory / "snapshot-v1").exists(),
                    "a non-L1 manual fence must not create a V2 namespace",
                )
                case.assertFalse(
                    (runtime_directory / "snapshot-v1" / "root-stops").exists()
                )

    def test_l12_old_root_staging_without_legacy_database_fences_v2_lineage(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-old-root-staging-reopen",
            target_path="outputs/old-root-staging-reopen.json",
            artifact_bytes=b'{"effect":"old-root-staging-reopen"}\n',
        )
        with authority_runtime.open_write(admitted):
            pass
        before_records = self._snapshot_head_records()
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        legacy_stage = runtime_directory / "staging"
        legacy_stage.mkdir(mode=0o700)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("an old-root stage must never be ignored as V2 state")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(self._snapshot_head_records(), before_records)
        self.assertEqual(self._snapshot_root_stop_records(), [])
        self.assertTrue(legacy_stage.is_dir())
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

    def test_active_v2_session_fences_when_old_root_staging_appears(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-old-root-staging-active",
            target_path="outputs/old-root-staging-active.json",
            artifact_bytes=b'{"effect":"old-root-staging-active"}\n',
        )
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )

        with authority_runtime.open_write(admitted) as session:
            before_records = self._snapshot_head_records()
            legacy_stage = runtime_directory / "staging"
            legacy_stage.mkdir(mode=0o700)
            with self.assertRaises(
                authority_runtime.DurableRecoveryFenceRequired
            ) as captured:
                session.prepare(effect)

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(self._snapshot_head_records(), before_records)
        self.assertEqual(self._snapshot_root_stop_records(), [])
        self.assertFalse((self.root / effect.target_relative_path).exists())
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

    def test_unknown_v2_root_stop_member_fences_without_history_adoption(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-unknown-root-stop",
            target_path="outputs/unknown-root-stop.json",
            artifact_bytes=b'{"effect":"unknown-root-stop"}\n',
        )
        with authority_runtime.open_write(admitted):
            pass
        before_records = self._snapshot_head_records()
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        unknown_stop = (
            runtime_directory / "snapshot-v1" / "root-stops" / "unexpected.json"
        )
        unknown_stop.write_bytes(b"unexpected\n")
        unknown_stop.chmod(0o600)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("an unknown root-stop member must fence before history adoption")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_ROOT_STOP_INVALID")
        self.assertEqual(self._snapshot_head_records(), before_records)
        self.assertEqual(unknown_stop.read_bytes(), b"unexpected\n")
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

    def test_l12_snapshot_staging_residue_fences_l1_before_migration(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-snapshot-stage-residue",
            target_path="outputs/legacy-snapshot-stage-residue.json",
            artifact_bytes=b'{"effect":"legacy-snapshot-stage-residue"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        before_legacy_bytes = legacy_database.read_bytes()
        stage_directory = runtime_directory / "snapshot-v1" / "staging"
        stage_directory.mkdir(mode=0o700, parents=True)
        stage = stage_directory / "legacy-residue.artifact"
        stage.write_bytes(b"legacy-stage-residue\n")
        stage.chmod(0o600)
        before_stage_bytes = stage.read_bytes()

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("a stage residue must not become an L1 empty migration")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(legacy_database.read_bytes(), before_legacy_bytes)
        self.assertEqual(stage.read_bytes(), before_stage_bytes)
        self.assertEqual(self._snapshot_head_records(), [])
        self.assertEqual(self._snapshot_root_stop_records(), [])

    def test_nonempty_legacy_v1_aborted_effect_returns_manual_review_fence(self):
        admitted, legacy_effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-aborted",
            target_path="outputs/legacy-aborted.json",
            artifact_bytes=b'{"effect":"legacy-aborted"}\n',
        )
        runtime_directory, legacy_database = self._write_legacy_v1_aborted_effect(
            legacy_effect
        )
        before_legacy_bytes = legacy_database.read_bytes()

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("a nonempty legacy database must stop for manual review")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(legacy_database.read_bytes(), before_legacy_bytes)
        self.assertFalse(
            (runtime_directory / "snapshot-v1").exists(),
            "a non-L1 manual fence must not create a V2 namespace",
        )
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )

    def test_empty_legacy_database_with_sidecar_returns_manual_review_fence(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-sidecar",
            target_path="outputs/legacy-sidecar.json",
            artifact_bytes=b'{"effect":"legacy-sidecar"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        sidecar = runtime_directory / "recovery-token.key"
        sidecar.write_bytes(b"legacy-sidecar\n")
        sidecar.chmod(0o600)
        before_database_bytes = legacy_database.read_bytes()
        before_sidecar_bytes = sidecar.read_bytes()

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("a legacy sidecar must prevent L1 migration")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(legacy_database.read_bytes(), before_database_bytes)
        self.assertEqual(sidecar.read_bytes(), before_sidecar_bytes)
        self.assertFalse(
            (runtime_directory / "snapshot-v1").exists(),
            "a non-L1 manual fence must not create a V2 namespace",
        )

    def test_l1_empty_v1_database_migrates_once_to_one_legacy_head(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-empty-migration",
            target_path="outputs/legacy-empty-migration.json",
            artifact_bytes=b'{"effect":"legacy-empty-migration"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        before_bytes = legacy_database.read_bytes()
        before_info = legacy_database.stat()
        before_identity = (
            before_info.st_dev,
            before_info.st_ino,
            before_info.st_nlink,
            before_info.st_uid,
            stat.S_IMODE(before_info.st_mode),
            before_info.st_size,
        )

        with authority_runtime.open_write(admitted):
            pass

        records = self._snapshot_head_records()
        self.assertEqual(len(records), 1)
        first = records[0]
        self.assertEqual(first["transition_kind"], "EMPTY_GENESIS")
        self.assertEqual(first["head"]["generation"], 0)
        self.assertIsNone(first["head"]["parent_head_sha256"])
        self.assertEqual(first["head"]["origin"], "LEGACY_D1A_V1")
        provenance = first["manifest"]["legacy_provenance_sha256"]
        self.assertRegex(provenance, r"^[0-9a-f]{64}$")
        retired_witness = first["migration_provenance_rows"][0][2]
        self.assertRegex(retired_witness, r"^[0-9a-f]{64}$")
        self.assertEqual(
            first["migration_provenance_rows"],
            ((1, provenance, retired_witness),),
        )
        self.assertEqual(legacy_database.read_bytes(), before_bytes)
        after_info = legacy_database.stat()
        self.assertEqual(
            (
                after_info.st_dev,
                after_info.st_ino,
                after_info.st_nlink,
                after_info.st_uid,
                stat.S_IMODE(after_info.st_mode),
                after_info.st_size,
            ),
            before_identity,
        )
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

        with authority_runtime.open_write(admitted):
            pass
        reopened = self._snapshot_head_records()
        self.assertEqual(len(reopened), 1)
        self.assertEqual(reopened[0]["head"], first["head"])
        self.assertEqual(legacy_database.read_bytes(), before_bytes)

    def test_l1_migration_seals_canonical_legacy_provenance_payload(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-provenance-payload",
            target_path="outputs/legacy-provenance-payload.json",
            artifact_bytes=b'{"effect":"legacy-provenance-payload"}\n',
        )
        _runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        before_bytes = legacy_database.read_bytes()
        before_info = legacy_database.stat()

        with authority_runtime.open_write(admitted):
            pass

        record = self._snapshot_head_records()[0]
        snapshot_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "objects"
            / f"o-{record['head']['snapshot_object_sha256']}"
        )
        connection = sqlite3.connect(":memory:")
        try:
            connection.row_factory = sqlite3.Row
            connection.deserialize(snapshot_path.read_bytes())
            row = connection.execute(
                "SELECT legacy_provenance_sha256, retired_witness_sha256, "
                "legacy_provenance_canonical_json "
                "FROM durable_migration_provenance WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(row)
        assert row is not None
        provenance_raw = row["legacy_provenance_canonical_json"]
        self.assertIsInstance(provenance_raw, bytes)
        self.assertEqual(sha256_bytes(provenance_raw), row["legacy_provenance_sha256"])
        self.assertEqual(
            row["legacy_provenance_sha256"],
            record["manifest"]["legacy_provenance_sha256"],
        )
        provenance = json.loads(provenance_raw)
        self.assertEqual(canonical_json_bytes(provenance), provenance_raw)
        self.assertEqual(provenance["schema_version"], 1)
        self.assertEqual(provenance["kind"], "LEGACY_D1A_V1_PROVENANCE")
        self.assertEqual(provenance["classification"], "L1")
        self.assertEqual(
            provenance["legacy_input_digest_sha256"],
            row["retired_witness_sha256"],
        )
        self.assertEqual(
            provenance["legacy_runtime_names"],
            ["authority-runtime.sqlite3"],
        )
        self.assertEqual(
            provenance["members"],
            [
                {
                    "relative_parts": [
                        "_registry",
                        "curation",
                        "authority-runtime",
                        "authority-runtime.sqlite3",
                    ],
                    "raw_sha256": sha256_bytes(before_bytes),
                    "identity": {
                        "device": before_info.st_dev,
                        "inode": before_info.st_ino,
                        "link_count": before_info.st_nlink,
                        "owner": before_info.st_uid,
                        "mode": stat.S_IMODE(before_info.st_mode),
                        "byte_length": before_info.st_size,
                    },
                }
            ],
        )
        self.assertRegex(
            provenance["legacy_database_schema_fingerprint_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertTrue(provenance["sidecar_absence_proof"])
        self.assertTrue(provenance["bridge_absence_proof"])
        self.assertTrue(provenance["stage_absence_proof"])
        self.assertEqual(legacy_database.read_bytes(), before_bytes)

    def test_l14_legacy_lineage_reopens_after_a_normal_successor(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-lineage-successor",
            target_path="outputs/legacy-lineage-successor.json",
            artifact_bytes=b'{"effect":"legacy-lineage-successor"}\n',
        )
        _runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        before_bytes = legacy_database.read_bytes()
        before_info = legacy_database.stat()

        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        before_reopen = self._snapshot_head_records()
        self.assertEqual(
            [record["head"]["origin"] for record in before_reopen],
            ["LEGACY_D1A_V1", "NORMAL", "NORMAL"],
        )

        with authority_runtime.open_write(admitted):
            pass

        reopened = self._snapshot_head_records()
        self.assertEqual(
            [record["head"] for record in reopened],
            [record["head"] for record in before_reopen],
        )
        self.assertEqual(legacy_database.read_bytes(), before_bytes)
        after_info = legacy_database.stat()
        self.assertEqual(
            (after_info.st_dev, after_info.st_ino, after_info.st_size),
            (before_info.st_dev, before_info.st_ino, before_info.st_size),
        )

    def test_l13_active_legacy_session_fences_before_prepare_after_witness_change(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-active-witness-change",
            target_path="outputs/legacy-active-witness-change.json",
            artifact_bytes=b'{"effect":"legacy-active-witness-change"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()

        with authority_runtime.open_write(admitted) as session:
            before_records = self._snapshot_head_records()
            self.assertEqual(len(before_records), 1)
            connection = sqlite3.connect(str(legacy_database))
            try:
                connection.execute("PRAGMA user_version = 7")
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
                session.prepare(effect)

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(
            [record["head"] for record in self._snapshot_head_records()],
            [record["head"] for record in before_records],
        )
        self.assertFalse(
            self._snapshot_stage_path(effect.effect_id).exists()
        )
        stops = self._snapshot_root_stop_records()
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["reason_code"], captured.exception.reason_code)
        self.assertEqual(
            stops[0]["observed_evidence_sha256"],
            captured.exception.observed_evidence_sha256,
        )
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as reopened:
            with authority_runtime.open_write(admitted):
                self.fail("a root stop must fence every later opener")
        self.assertEqual(reopened.exception.reason_code, captured.exception.reason_code)
        self.assertEqual(self._snapshot_root_stop_records(), stops)

    def test_l9_legacy_extra_constraint_fences_without_a_v2_head(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-extra-constraint",
            target_path="outputs/legacy-extra-constraint.json",
            artifact_bytes=b'{"effect":"legacy-extra-constraint"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database(
            extra_state_constraint=True,
        )
        before_bytes = legacy_database.read_bytes()
        before_info = legacy_database.stat()

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("an extra V1 constraint must not become a legacy genesis")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(legacy_database.read_bytes(), before_bytes)
        after_info = legacy_database.stat()
        self.assertEqual(
            (after_info.st_dev, after_info.st_ino, after_info.st_size),
            (before_info.st_dev, before_info.st_ino, before_info.st_size),
        )
        self.assertFalse(
            (runtime_directory / "snapshot-v1").exists(),
            "a non-L1 manual fence must not create a V2 namespace",
        )

    def test_l1_migration_rechecks_witness_before_the_first_object_seal(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-preseal-recheck",
            target_path="outputs/legacy-preseal-recheck.json",
            artifact_bytes=b'{"effect":"legacy-preseal-recheck"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        original_checkpoint = authority_snapshot._run_snapshot_checkpoint
        mutated = False

        def mutate_witness_after_serialize(point):
            nonlocal mutated
            if point == "after-snapshot-serialize" and not mutated:
                mutated = True
                connection = sqlite3.connect(str(legacy_database))
                try:
                    connection.execute("PRAGMA user_version = 7")
                    connection.commit()
                finally:
                    connection.close()
            original_checkpoint(point)

        with mock.patch.object(
            authority_snapshot,
            "_run_snapshot_checkpoint",
            new=mutate_witness_after_serialize,
        ):
            with self.assertRaises(
                authority_runtime.DurableRecoveryFenceRequired
            ) as captured:
                with authority_runtime.open_write(admitted):
                    self.fail("a changed witness must stop before the first object seal")

        self.assertTrue(mutated)
        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(self._snapshot_head_records(), [])
        self.assertEqual(
            tuple(
                (runtime_directory / "snapshot-v1" / "objects").glob("o-*")
            ),
            (),
        )
        self.assertEqual(
            tuple(
                (runtime_directory / "snapshot-v1" / "head-receipts").glob("r-*")
            ),
            (),
        )
        stops = self._snapshot_root_stop_records()
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["reason_code"], captured.exception.reason_code)
        self.assertEqual(
            stops[0]["observed_evidence_sha256"],
            captured.exception.observed_evidence_sha256,
        )
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as reopened:
            with authority_runtime.open_write(admitted):
                self.fail("a root stop must fence before another legacy migration")
        self.assertEqual(reopened.exception.reason_code, captured.exception.reason_code)
        self.assertEqual(
            reopened.exception.observed_evidence_sha256,
            captured.exception.observed_evidence_sha256,
        )
        self.assertEqual(self._snapshot_root_stop_records(), stops)

    def test_l1_preflight_witness_delete_cannot_downgrade_to_fresh_v2(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-preflight-delete",
            target_path="outputs/legacy-preflight-delete.json",
            artifact_bytes=b'{"effect":"legacy-preflight-delete"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        original_acquire = authority_snapshot._SnapshotWriterLease.acquire
        deleted = False

        def acquire_then_delete_preflight_witness(root):
            nonlocal deleted
            lease = original_acquire(root)
            legacy_database.unlink()
            deleted = True
            return lease

        with mock.patch.object(
            authority_snapshot._SnapshotWriterLease,
            "acquire",
            side_effect=acquire_then_delete_preflight_witness,
        ):
            with self.assertRaises(
                authority_runtime.DurableRecoveryFenceRequired
            ) as captured:
                with authority_runtime.open_write(admitted):
                    self.fail("a preflight L1 delete must not become fresh V2 genesis")

        self.assertTrue(deleted)
        self.assertFalse(legacy_database.exists())
        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(self._snapshot_head_records(), [])
        self.assertEqual(
            tuple((runtime_directory / "snapshot-v1" / "objects").glob("o-*")),
            (),
        )
        stops = self._snapshot_root_stop_records()
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["reason_code"], captured.exception.reason_code)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as reopened:
            with authority_runtime.open_write(admitted):
                self.fail("a root stop must prevent fresh V2 after L1 preflight drift")
        self.assertEqual(reopened.exception.reason_code, captured.exception.reason_code)
        self.assertEqual(self._snapshot_root_stop_records(), stops)

    def test_l1_migration_rechecks_witness_after_head_directory_fsync(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-post-head-recheck",
            target_path="outputs/legacy-post-head-recheck.json",
            artifact_bytes=b'{"effect":"legacy-post-head-recheck"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        original_checkpoint = authority_snapshot._run_snapshot_checkpoint
        mutated = False

        def mutate_witness_after_head_fsync(point):
            nonlocal mutated
            if point == "after-heads-directory-fsync" and not mutated:
                mutated = True
                connection = sqlite3.connect(str(legacy_database))
                try:
                    connection.execute("PRAGMA user_version = 7")
                    connection.commit()
                finally:
                    connection.close()
            original_checkpoint(point)

        with mock.patch.object(
            authority_snapshot,
            "_run_snapshot_checkpoint",
            new=mutate_witness_after_head_fsync,
        ):
            with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
                with authority_runtime.open_write(admitted):
                    self.fail("a changed witness must stop after the canonical head barrier")

        self.assertTrue(mutated)
        records = self._snapshot_head_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["head"]["origin"], "LEGACY_D1A_V1")
        stops = self._snapshot_root_stop_records()
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["reason_code"], "RECOVERY_LEGACY_V1_FENCE")
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as reopened:
            with authority_runtime.open_write(admitted):
                self.fail("a root stop must fence before the published head is adopted")
        self.assertEqual(reopened.exception.reason_code, stops[0]["reason_code"])
        self.assertEqual(
            reopened.exception.observed_evidence_sha256,
            stops[0]["observed_evidence_sha256"],
        )
        self.assertEqual(self._snapshot_head_records(), records)
        self.assertEqual(self._snapshot_root_stop_records(), stops)

    def test_l13_replaced_legacy_witness_fences_the_existing_legacy_lineage(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-witness-replacement",
            target_path="outputs/legacy-witness-replacement.json",
            artifact_bytes=b'{"effect":"legacy-witness-replacement"}\n',
        )
        runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        with authority_runtime.open_write(admitted):
            pass
        before_records = self._snapshot_head_records()
        self.assertEqual(before_records[0]["head"]["origin"], "LEGACY_D1A_V1")
        before_bytes = legacy_database.read_bytes()
        before_info = legacy_database.stat()
        replacement = self.root / "replacement-legacy-database.sqlite"
        shutil.copyfile(legacy_database, replacement)
        replacement.chmod(0o600)
        os.replace(replacement, legacy_database)
        after_info = legacy_database.stat()
        self.assertEqual(legacy_database.read_bytes(), before_bytes)
        self.assertNotEqual(
            (after_info.st_dev, after_info.st_ino),
            (before_info.st_dev, before_info.st_ino),
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("a replaced retired witness must not reopen the lineage")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(self._snapshot_head_records(), before_records)
        stops = self._snapshot_root_stop_records()
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["reason_code"], captured.exception.reason_code)
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

    def test_l1_reopen_root_stops_when_retired_witness_becomes_nonempty(self):
        admitted, legacy_effect = self._admit_durable_write_effect(
            effect_id="effect-legacy-witness-becomes-nonempty",
            target_path="outputs/legacy-witness-becomes-nonempty.json",
            artifact_bytes=b'{"effect":"legacy-witness-becomes-nonempty"}\n',
        )
        _runtime_directory, legacy_database = self._write_empty_legacy_v1_database()
        with authority_runtime.open_write(admitted):
            pass
        before_records = self._snapshot_head_records()
        connection = sqlite3.connect(str(legacy_database))
        try:
            connection.execute(
                "INSERT INTO durable_effects "
                "(effect_id, target_relative_path, artifact_ref, artifact_bytes, "
                "request_sha256, scope_sha256, spec_identity, spec_sha256, "
                "policy_identity_sha256, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    legacy_effect.effect_id,
                    legacy_effect.target_relative_path,
                    legacy_effect.artifact_ref.canonical_bytes,
                    legacy_effect.artifact_bytes,
                    "a" * 64,
                    "b" * 64,
                    "legacy-witness-v1",
                    "c" * 64,
                    "d" * 64,
                    authority_runtime.DurableEffectState.ABORTED.value,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        before_reopen_bytes = legacy_database.read_bytes()

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("a nonempty retired witness must stop the V2 legacy lineage")

        self.assertEqual(captured.exception.reason_code, "RECOVERY_LEGACY_V1_FENCE")
        self.assertEqual(self._snapshot_head_records(), before_records)
        self.assertEqual(legacy_database.read_bytes(), before_reopen_bytes)
        stops = self._snapshot_root_stop_records()
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["reason_code"], captured.exception.reason_code)

    def test_prepared_row_lookup_failure_closes_session_without_sidecar_or_root_fence(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-row-lookup-unavailable",
            target_path="outputs/prepared-row-lookup-unavailable.json",
            artifact_bytes=b'{"effect":"prepared-row-lookup-unavailable"}\n',
        )
        original_row = authority_session.durable.DurableCoordinator._row

        def fail_effect_row_lookup(coordinator, effect_id):
            if effect_id == effect.effect_id:
                raise sqlite3.OperationalError("simulated prepared row lookup error")
            return original_row(coordinator, effect_id)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_row",
                new=fail_effect_row_lookup,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable effect lookup is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertEqual(captured.exception.directive.token, token)
            self.assertEqual(captured.exception.directive.disposition, "recoverable")
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.publish(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (runtime_directory / "recovery-blockers" / f"{effect.effect_id}.json").exists()
        )
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_block_row_lookup_failure_closes_the_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-block-row-lookup-unavailable",
            target_path="outputs/block-row-lookup-unavailable.json",
            artifact_bytes=b'{"effect":"block-row-lookup-unavailable"}\n',
        )
        original_row = authority_session.durable.DurableCoordinator._row
        row_calls = 0

        def fail_only_block_row_lookup(coordinator, effect_id):
            nonlocal row_calls
            row_calls += 1
            if row_calls == 2:
                raise sqlite3.OperationalError("simulated block row lookup error")
            return original_row(coordinator, effect_id)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            (self.root / effect.target_relative_path).unlink()
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_row",
                new=fail_only_block_row_lookup,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "published durable effect is absent",
                ) as captured:
                    session.finalize(token)
            self.assertEqual(captured.exception.directive.token, token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.finalize(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        self.assertEqual(row_calls, 2)
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )

    def test_prepare_rejects_an_unrelated_effect_while_one_is_prepared(self):
        admitted, prepared_effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-excludes-next-claim",
            target_path="outputs/prepared-excludes-next-claim.json",
            artifact_bytes=b'{"effect":"prepared-excludes-next-claim"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(prepared_effect)

        other_admitted, other_effect = self._admit_durable_write_effect(
            effect_id="effect-rejected-next-claim",
            target_path="outputs/rejected-next-claim.json",
            artifact_bytes=b'{"effect":"rejected-next-claim"}\n',
            actor="another-operator",
        )
        with authority_runtime.open_write(other_admitted) as session:
            with self.assertRaises(authority_runtime.DurableRecoveryDenied) as caught:
                session.prepare(other_effect)
        self.assertEqual(caught.exception.reason_code, "RECOVERY_OUTSTANDING_EFFECT")

        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
        )
        self.assertFalse((self.root / other_effect.target_relative_path).exists())

    def test_prepare_rejects_an_unrelated_effect_while_one_is_published(self):
        admitted, published_effect = self._admit_durable_write_effect(
            effect_id="effect-published-excludes-next-claim",
            target_path="outputs/published-excludes-next-claim.json",
            artifact_bytes=b'{"effect":"published-excludes-next-claim"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(published_effect)
            session.publish(token)

        other_admitted, other_effect = self._admit_durable_write_effect(
            effect_id="effect-rejected-after-publish",
            target_path="outputs/rejected-after-publish.json",
            artifact_bytes=b'{"effect":"rejected-after-publish"}\n',
            actor="another-operator",
        )
        with authority_runtime.open_write(other_admitted) as session:
            with self.assertRaises(authority_runtime.DurableRecoveryDenied) as caught:
                session.prepare(other_effect)
        self.assertEqual(caught.exception.reason_code, "RECOVERY_OUTSTANDING_EFFECT")

        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED", "PUBLISHED"],
        )
        self.assertTrue((self.root / published_effect.target_relative_path).is_file())
        self.assertFalse((self.root / other_effect.target_relative_path).exists())

    def test_prepare_rejects_an_unrelated_effect_after_recovery_is_blocked(self):
        admitted, blocked_effect = self._admit_durable_write_effect(
            effect_id="effect-blocked-excludes-next-claim",
            target_path="outputs/blocked-excludes-next-claim.json",
            artifact_bytes=b'{"effect":"blocked-excludes-next-claim"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(blocked_effect)
            blocked = session._WriteSession__coordinator._block_for_token(
                token,
                message="isolated blocked-history test",
                reason_code="RECOVERY_TEST_BLOCK",
            )
        self.assertIsInstance(blocked, authority_runtime.DurableRecoveryRequired)

        other_admitted, other_effect = self._admit_durable_write_effect(
            effect_id="effect-rejected-after-block",
            target_path="outputs/rejected-after-block.json",
            artifact_bytes=b'{"effect":"rejected-after-block"}\n',
            actor="another-operator",
        )
        with authority_runtime.open_write(other_admitted) as session:
            with self.assertRaises(authority_runtime.DurableRecoveryDenied) as caught:
                session.prepare(other_effect)
        self.assertEqual(caught.exception.reason_code, "RECOVERY_BLOCKED_HISTORY")

        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED", "BLOCKED_RECOVERY"],
        )
        self.assertFalse((self.root / other_effect.target_relative_path).exists())

    def test_reopen_fences_when_a_canonical_head_receipt_is_missing(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-missing-head-receipt",
            target_path="outputs/missing-head-receipt.json",
            artifact_bytes=b'{"effect":"missing-head-receipt"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        records = self._snapshot_head_records()
        tip = records[-1]["head"]
        self.assertIsInstance(tip, dict)
        tip_sha256 = sha256_bytes(canonical_json_bytes(tip))
        receipt = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "head-receipts"
            / f"r-{tip_sha256}-{tip['receipt_token']}"
        )
        receipt.unlink()

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired) as captured:
            with authority_runtime.open_write(admitted):
                self.fail("a missing receipt must not be adopted as a head")

        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_SNAPSHOT_HISTORY_CHANGED",
        )
        stops = self._snapshot_root_stop_records()
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["reason_code"], captured.exception.reason_code)
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

    def test_reopen_fences_when_head_and_receipt_are_equal_but_not_linked(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-separate-head-receipt",
            target_path="outputs/separate-head-receipt.json",
            artifact_bytes=b'{"effect":"separate-head-receipt"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        tip_sha256 = sha256_bytes(canonical_json_bytes(tip))
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        head_path = snapshot_directory / "heads" / f"h-{tip_sha256}.json"
        receipt_path = (
            snapshot_directory
            / "head-receipts"
            / f"r-{tip_sha256}-{tip['receipt_token']}"
        )
        head_raw = head_path.read_bytes()
        head_path.unlink()
        head_path.write_bytes(head_raw)
        head_path.chmod(0o600)
        self.assertNotEqual(head_path.stat().st_ino, receipt_path.stat().st_ino)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("matching bytes cannot replace the receipt hard link")

    def test_reopen_fences_when_head_bytes_do_not_match_their_filename_hash(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-head-filename-hash",
            target_path="outputs/head-filename-hash.json",
            artifact_bytes=b'{"effect":"head-filename-hash"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        tip_sha256 = sha256_bytes(canonical_json_bytes(tip))
        head_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "heads"
            / f"h-{tip_sha256}.json"
        )
        corrupted = bytearray(head_path.read_bytes())
        corrupted[-1] = ord(" ")
        head_path.write_bytes(corrupted)
        head_path.chmod(0o600)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("head filename hashes bind exact raw head bytes")

    def test_reopen_fences_when_a_tip_manifest_object_is_corrupted(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-tip-manifest-corruption",
            target_path="outputs/tip-manifest-corruption.json",
            artifact_bytes=b'{"effect":"tip-manifest-corruption"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        manifest_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "objects"
            / f"o-{tip['manifest_object_sha256']}"
        )
        corrupted = bytearray(manifest_path.read_bytes())
        corrupted[-1] ^= 0x01
        manifest_path.write_bytes(corrupted)
        manifest_path.chmod(0o600)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a corrupted tip manifest object must not be adopted")

    def test_reopen_fences_when_a_head_has_an_extra_hard_link(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-head-extra-hard-link",
            target_path="outputs/head-extra-hard-link.json",
            artifact_bytes=b'{"effect":"head-extra-hard-link"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        tip_sha256 = sha256_bytes(canonical_json_bytes(tip))
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        os.link(
            snapshot_directory / "heads" / f"h-{tip_sha256}.json",
            snapshot_directory / "head-receipts" / "extra-head-hard-link",
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a head with a third hard link must not be adopted")

    def test_reopen_fences_when_a_referenced_object_has_an_extra_hard_link(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-object-extra-hard-link",
            target_path="outputs/object-extra-hard-link.json",
            artifact_bytes=b'{"effect":"object-extra-hard-link"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        objects_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "objects"
        )
        os.link(
            objects_directory / f"o-{tip['snapshot_object_sha256']}",
            objects_directory / "extra-object-hard-link",
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a referenced object with a second hard link must not be adopted")

    def test_reopen_fences_when_manifest_anchor_does_not_match_its_head(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-manifest-anchor-mismatch",
            target_path="outputs/manifest-anchor-mismatch.json",
            artifact_bytes=b'{"effect":"manifest-anchor-mismatch"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        self._reseal_tip_manifest(anchor_identity_sha256="f" * 64)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a manifest with a mismatched anchor must not be adopted")

    def test_reopen_fences_when_manifest_snapshot_length_is_wrong(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-manifest-length-mismatch",
            target_path="outputs/manifest-length-mismatch.json",
            artifact_bytes=b'{"effect":"manifest-length-mismatch"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        tip = self._snapshot_head_records()[-1]["manifest"]
        self.assertIsInstance(tip, dict)
        self._reseal_tip_manifest(snapshot_byte_length=tip["snapshot_byte_length"] + 1)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a manifest with a wrong snapshot length must not be adopted")

    def test_reopen_fences_when_resealed_projection_does_not_match_snapshot(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-stale-recovery-projection",
            target_path="outputs/stale-recovery-projection.json",
            artifact_bytes=b'{"effect":"stale-recovery-projection"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        forged_projection = "f" * 64
        self._reseal_tip_manifest(
            head_updates={"recovery_projection_sha256": forged_projection},
            recovery_projection_sha256=forged_projection,
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a stale recovery projection must not be adopted")

    def test_reopen_fences_when_resealed_snapshot_has_an_unknown_table(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-unknown-snapshot-table",
            target_path="outputs/unknown-snapshot-table.json",
            artifact_bytes=b'{"effect":"unknown-snapshot-table"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        self._reseal_tip_snapshot(
            lambda connection: connection.execute(
                "CREATE TABLE unexpected_snapshot_table (value TEXT NOT NULL)"
            )
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a snapshot with an unknown table must not be adopted")

    def test_reopen_fences_when_a_hash_consistent_snapshot_has_integrity_damage(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-hash-consistent-integrity-damage",
            target_path="outputs/hash-consistent-integrity-damage.json",
            artifact_bytes=b'{"effect":"hash-consistent-integrity-damage"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        snapshot_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "objects"
            / f"o-{tip['snapshot_object_sha256']}"
        )
        corrupted = bytearray(snapshot_path.read_bytes())
        self.assertGreater(len(corrupted), 100)
        corrupted[100] ^= 0x01
        self._replace_tip_snapshot_raw(bytes(corrupted))

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a hash-consistent damaged SQLite snapshot must not be adopted")

    def test_reopen_fences_when_a_non_tip_snapshot_object_is_corrupted(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-non-tip-snapshot-corruption",
            target_path="outputs/non-tip-snapshot-corruption.json",
            artifact_bytes=b'{"effect":"non-tip-snapshot-corruption"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        genesis_head = self._snapshot_head_records()[0]["head"]
        self.assertIsInstance(genesis_head, dict)
        snapshot_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "objects"
            / f"o-{genesis_head['snapshot_object_sha256']}"
        )
        corrupted = bytearray(snapshot_path.read_bytes())
        self.assertTrue(corrupted)
        corrupted[-1] ^= 0x01
        snapshot_path.write_bytes(corrupted)
        snapshot_path.chmod(0o600)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a corrupted non-tip snapshot must not be adopted")

    def test_reopen_fences_when_resealed_non_tip_snapshot_has_unknown_table(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-resealed-non-tip-unknown-table",
            target_path="outputs/resealed-non-tip-unknown-table.json",
            artifact_bytes=b'{"effect":"resealed-non-tip-unknown-table"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        self._rebuild_history_suffix(
            0,
            lambda connection: connection.execute(
                "CREATE TABLE non_tip_unexpected_table (value TEXT NOT NULL)"
            ),
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a hash-consistent non-tip schema change must not be adopted")

    def test_reopen_fences_when_heads_parent_is_replaced_during_discovery(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-head-parent-replacement",
            target_path="outputs/head-parent-replacement.json",
            artifact_bytes=b'{"effect":"head-parent-replacement"}\n',
        )
        with authority_runtime.open_write(admitted):
            pass

        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        retired_directory = snapshot_directory / "heads-retired-for-test"
        original_list_directory = authority_snapshot._RootAnchor.list_directory
        original_validate_hydrated_snapshot = (
            authority_snapshot._DurableSnapshotStore._validate_hydrated_snapshot.__func__
        )
        replacement_done = False
        hydration_attempted = False

        def replace_parent_after_enumeration(anchor, path):
            nonlocal replacement_done
            names = original_list_directory(anchor, path)
            if (
                not replacement_done
                and path.parts == authority_snapshot._SNAPSHOT_HEADS_PARTS
            ):
                replacement_done = True
                os.rename(heads_directory, retired_directory)
                os.mkdir(heads_directory, 0o700)
                for name in names:
                    old_head = retired_directory / name
                    head = json.loads(old_head.read_bytes())
                    old_head.unlink()
                    os.link(
                        receipts_directory
                        / f"r-{name[2:-5]}-{head['receipt_token']}",
                        heads_directory / name,
                    )
                retired_directory.rmdir()
            return names

        def record_hydration(cls, root, snapshot_raw, head, manifest):
            nonlocal hydration_attempted
            hydration_attempted = True
            return original_validate_hydrated_snapshot(
                cls,
                root,
                snapshot_raw,
                head,
                manifest,
            )

        with mock.patch.object(
            authority_snapshot._RootAnchor,
            "list_directory",
            new=replace_parent_after_enumeration,
        ):
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "_validate_hydrated_snapshot",
                new=classmethod(record_hydration),
            ):
                with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
                    with authority_runtime.open_write(admitted):
                        self.fail("a replaced heads parent must not be adopted")
        self.assertTrue(replacement_done)
        self.assertFalse(hydration_attempted)

    def test_reopen_fences_when_objects_parent_is_replaced_during_discovery(self):
        self._assert_namespace_parent_replacement_fences(directory_name="objects")

    def test_reopen_fences_when_receipts_parent_is_replaced_during_discovery(self):
        self._assert_namespace_parent_replacement_fences(
            directory_name="head-receipts"
        )

    def test_reopen_fences_when_a_candidate_head_has_duplicate_json_keys(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-duplicate-head-json",
            target_path="outputs/duplicate-head-json.json",
            artifact_bytes=b'{"effect":"duplicate-head-json"}\n',
        )
        with authority_runtime.open_write(admitted):
            pass

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        forged_head = dict(tip)
        forged_head["receipt_token"] = "a" * 32
        forged_head.pop("protocol_version")
        raw = (
            b'{"protocol_version":1,"protocol_version":1,'
            + canonical_json_bytes(forged_head)[1:]
        )
        self._add_snapshot_head_candidate(raw, receipt_token="a" * 32)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a duplicate-key head must not be adopted")

    def test_reopen_fences_when_a_candidate_head_uses_nan(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-head-nan",
            target_path="outputs/head-nan.json",
            artifact_bytes=b'{"effect":"head-nan"}\n',
        )
        with authority_runtime.open_write(admitted):
            pass

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        forged_head = dict(tip)
        forged_head["receipt_token"] = "e" * 32
        forged_head.pop("generation")
        raw = b'{"generation":NaN,' + canonical_json_bytes(forged_head)[1:]
        self._add_snapshot_head_candidate(raw, receipt_token="e" * 32)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a NaN head value must not be adopted")

    def test_reopen_fences_when_a_manifest_has_noncanonical_whitespace(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-manifest-whitespace",
            target_path="outputs/manifest-whitespace.json",
            artifact_bytes=b'{"effect":"manifest-whitespace"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        manifest = self._snapshot_head_records()[-1]["manifest"]
        self.assertIsInstance(manifest, dict)
        self._replace_tip_manifest_raw(canonical_json_bytes(manifest) + b" ")

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a noncanonical manifest must not be adopted")

    def test_reopen_fences_when_a_candidate_head_has_a_missing_parent(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-missing-head-parent",
            target_path="outputs/missing-head-parent.json",
            artifact_bytes=b'{"effect":"missing-head-parent"}\n',
        )
        with authority_runtime.open_write(admitted):
            pass

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        forged_head = dict(tip)
        forged_head.update(
            {
                "receipt_token": "b" * 32,
                "generation": 1,
                "parent_head_sha256": "f" * 64,
                "origin": "NORMAL",
            }
        )
        self._add_snapshot_head_candidate(
            canonical_json_bytes(forged_head),
            receipt_token="b" * 32,
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a candidate head with a missing parent must not be adopted")

    def test_reopen_fences_when_a_candidate_head_has_a_wrong_generation(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-wrong-head-generation",
            target_path="outputs/wrong-head-generation.json",
            artifact_bytes=b'{"effect":"wrong-head-generation"}\n',
        )
        with authority_runtime.open_write(admitted):
            pass

        records = self._snapshot_head_records()
        tip = records[-1]["head"]
        self.assertIsInstance(tip, dict)
        forged_head = dict(tip)
        forged_head.update(
            {
                "receipt_token": "c" * 32,
                "generation": 2,
                "parent_head_sha256": sha256_bytes(canonical_json_bytes(tip)),
                "origin": "NORMAL",
            }
        )
        self._add_snapshot_head_candidate(
            canonical_json_bytes(forged_head),
            receipt_token="c" * 32,
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a candidate head with a gap must not be adopted")

    def test_reopen_fences_when_a_candidate_head_branches_from_a_non_tip(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-branching-head",
            target_path="outputs/branching-head.json",
            artifact_bytes=b'{"effect":"branching-head"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
        )
        tip = records[-1]["head"]
        branch_parent = records[1]["head"]
        self.assertIsInstance(tip, dict)
        self.assertIsInstance(branch_parent, dict)
        forged_head = dict(tip)
        forged_head.update(
            {
                "receipt_token": "d" * 32,
                "generation": 3,
                "parent_head_sha256": sha256_bytes(
                    canonical_json_bytes(branch_parent)
                ),
                "origin": "NORMAL",
            }
        )
        self._add_snapshot_head_candidate(
            canonical_json_bytes(forged_head),
            receipt_token="d" * 32,
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a second child of a non-tip head must not be adopted")

    def test_reopen_fences_when_two_heads_reference_the_same_snapshot_objects(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-duplicated-head-object-reference",
            target_path="outputs/duplicated-head-object-reference.json",
            artifact_bytes=b'{"effect":"duplicated-head-object-reference"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        tip = self._snapshot_head_records()[-1]["head"]
        self.assertIsInstance(tip, dict)
        forged_head = dict(tip)
        forged_head.update(
            {
                "receipt_token": "f" * 32,
                "generation": tip["generation"] + 1,
                "parent_head_sha256": sha256_bytes(canonical_json_bytes(tip)),
                "origin": "NORMAL",
            }
        )
        self._add_snapshot_head_candidate(
            canonical_json_bytes(forged_head),
            receipt_token="f" * 32,
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("referenced snapshot objects belong to exactly one head")

    def test_reopen_history_selection_ignores_head_order_and_mtime(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-history-order-independence",
            target_path="outputs/history-order-independence.json",
            artifact_bytes=b'{"effect":"history-order-independence"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        heads_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "heads"
        )
        for index, head_path in enumerate(sorted(heads_directory.glob("h-*.json"))):
            os.utime(head_path, (1_700_000_000 + index, 1_700_000_000 + index))

        original_list_directory = authority_snapshot._RootAnchor.list_directory

        def reverse_head_enumeration(anchor, path):
            names = original_list_directory(anchor, path)
            if path.parts == authority_snapshot._SNAPSHOT_HEADS_PARTS:
                return tuple(reversed(names))
            return names

        with mock.patch.object(
            authority_snapshot._RootAnchor,
            "list_directory",
            new=reverse_head_enumeration,
        ):
            with authority_runtime.open_write(admitted) as session:
                self.assertEqual(session.prepare(effect), token)
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
        )

    def test_reopen_fences_when_resealed_terminal_effect_payload_changes(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-terminal-payload-rewrite",
            target_path="outputs/terminal-payload-rewrite.json",
            artifact_bytes=b'{"effect":"terminal-payload-rewrite"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            session.finalize(token)

        self._reseal_tip_snapshot(
            lambda connection: connection.execute(
                "UPDATE durable_effects SET artifact_bytes = ? WHERE effect_id = ?",
                (b'{"effect":"forged-terminal-payload"}\n', effect.effect_id),
            )
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a terminal effect payload rewrite must not be adopted")

    def test_reopen_fences_when_terminal_path_and_evidence_are_coherently_rewritten(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-coherent-terminal-path-rewrite",
            target_path="outputs/coherent-terminal-path-rewrite.json",
            artifact_bytes=b'{"effect":"coherent-terminal-path-rewrite"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            session.finalize(token)

        rewritten_path = "outputs/coherent-terminal-path-rewrite-forged.json"
        rewritten_target = self.root / rewritten_path
        rewritten_target.write_bytes(effect.artifact_bytes)
        rewritten_target.chmod(0o600)
        rewritten_info = rewritten_target.stat()

        def rewrite_terminal_path(connection: sqlite3.Connection) -> None:
            token_key_row = connection.execute(
                "SELECT token_key FROM recovery_token_keys WHERE singleton = 1"
            ).fetchone()
            self.assertIsNotNone(token_key_row)
            token_key = token_key_row["token_key"]
            self.assertIsInstance(token_key, bytes)
            binding_row = connection.execute(
                "SELECT effect_id, target_relative_path, artifact_ref_sha256, "
                "request_sha256, scope_sha256, bounds_sha256, spec_identity, "
                "spec_sha256, policy_identity_sha256, token_request_sha256, "
                "token_continuation_identity, token_authentication_tag, binding_sha256 "
                "FROM durable_effect_bindings WHERE effect_id = ?",
                (effect.effect_id,),
            ).fetchone()
            self.assertIsNotNone(binding_row)
            binding = self._seal_snapshot_binding(
                authority_snapshot._SnapshotBindingValue(*tuple(binding_row)),
                token_key=token_key,
                target_relative_path=rewritten_path,
            )
            connection.execute(
                "UPDATE durable_effects SET target_relative_path = ? "
                "WHERE effect_id = ?",
                (rewritten_path, effect.effect_id),
            )
            connection.execute(
                "UPDATE durable_effect_bindings SET target_relative_path = ?, "
                "token_continuation_identity = ?, token_authentication_tag = ?, "
                "binding_sha256 = ? WHERE effect_id = ?",
                (
                    binding.target_relative_path,
                    binding.token_continuation_identity,
                    binding.token_authentication_tag,
                    binding.binding_sha256,
                    binding.effect_id,
                ),
            )
            connection.execute(
                "UPDATE durable_target_claims SET target_relative_path = ?, "
                "binding_sha256 = ? WHERE effect_id = ?",
                (
                    rewritten_path,
                    binding.binding_sha256,
                    effect.effect_id,
                ),
            )
            attestation_row = connection.execute(
                "SELECT effect_id, target_relative_path, binding_sha256, "
                "artifact_bytes_sha256, byte_length, target_device, target_inode, "
                "target_nlink, attestation_sha256 "
                "FROM durable_published_attestations WHERE effect_id = ?",
                (effect.effect_id,),
            ).fetchone()
            self.assertIsNotNone(attestation_row)
            attestation = self._seal_published_attestation(
                authority_snapshot._SnapshotPublishedAttestationValue(
                    *tuple(attestation_row)
                ),
                target_relative_path=rewritten_path,
                binding_sha256=binding.binding_sha256,
                target_device=rewritten_info.st_dev,
                target_inode=rewritten_info.st_ino,
                target_nlink=rewritten_info.st_nlink,
            )
            connection.execute(
                "UPDATE durable_published_attestations "
                "SET target_relative_path = ?, binding_sha256 = ?, "
                "target_device = ?, target_inode = ?, target_nlink = ?, "
                "attestation_sha256 = ? WHERE effect_id = ?",
                (
                    attestation.target_relative_path,
                    attestation.binding_sha256,
                    attestation.target_device,
                    attestation.target_inode,
                    attestation.target_nlink,
                    attestation.attestation_sha256,
                    attestation.effect_id,
                ),
            )
            final_row = connection.execute(
                "SELECT effect_id, binding_sha256, published_attestation_sha256, "
                "expected_state, resulting_state, result_sha256 "
                "FROM durable_final_cas_results WHERE effect_id = ?",
                (effect.effect_id,),
            ).fetchone()
            self.assertIsNotNone(final_row)
            final_result = self._seal_final_cas_result(
                authority_snapshot._SnapshotFinalCasResultValue(*tuple(final_row)),
                binding_sha256=binding.binding_sha256,
                published_attestation_sha256=attestation.attestation_sha256,
            )
            connection.execute(
                "UPDATE durable_final_cas_results SET binding_sha256 = ?, "
                "published_attestation_sha256 = ?, result_sha256 = ? "
                "WHERE effect_id = ?",
                (
                    final_result.binding_sha256,
                    final_result.published_attestation_sha256,
                    final_result.result_sha256,
                    final_result.effect_id,
                ),
            )

        self._reseal_tip_snapshot(rewrite_terminal_path)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a coherent terminal path rewrite must not be adopted")

    def test_reopen_fences_when_terminal_snapshot_omits_old_claim_evidence(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-terminal-missing-claim-evidence",
            target_path="outputs/terminal-missing-claim-evidence.json",
            artifact_bytes=b'{"effect":"terminal-missing-claim-evidence"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            session.finalize(token)

        self._reseal_tip_snapshot(
            lambda connection: connection.execute(
                "DELETE FROM durable_claims WHERE effect_id = ?",
                (effect.effect_id,),
            )
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a terminal snapshot cannot omit old claim evidence")

    def test_reopen_fences_when_manifest_nonce_does_not_match_its_snapshot(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-manifest-nonce-mismatch",
            target_path="outputs/manifest-nonce-mismatch.json",
            artifact_bytes=b'{"effect":"manifest-nonce-mismatch"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        self._reseal_tip_manifest(publication_nonce="f" * 32)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a manifest nonce must bind its snapshot generation")

    def test_reopen_fences_when_resealed_prepared_binding_token_changes(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-binding-token-rewrite",
            target_path="outputs/prepared-binding-token-rewrite.json",
            artifact_bytes=b'{"effect":"prepared-binding-token-rewrite"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        self._reseal_tip_snapshot(
            lambda connection: connection.execute(
                "UPDATE durable_effect_bindings "
                "SET token_continuation_identity = ? WHERE effect_id = ?",
                ("f" * 64, effect.effect_id),
            )
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a changed sealed recovery token must not be adopted")

    def test_reopen_fences_when_prepared_binding_is_coherently_rekeyed(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-coherent-prepared-binding-rekey",
            target_path="outputs/coherent-prepared-binding-rekey.json",
            artifact_bytes=b'{"effect":"coherent-prepared-binding-rekey"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        def rekey_binding(connection: sqlite3.Connection) -> None:
            token_key = b"r" * 32
            connection.execute(
                "UPDATE recovery_token_keys SET token_key = ?, key_sha256 = ? "
                "WHERE singleton = 1",
                (token_key, sha256_bytes(token_key)),
            )
            row = connection.execute(
                "SELECT effect_id, target_relative_path, artifact_ref_sha256, "
                "request_sha256, scope_sha256, bounds_sha256, spec_identity, "
                "spec_sha256, policy_identity_sha256, token_request_sha256, "
                "token_continuation_identity, token_authentication_tag, binding_sha256 "
                "FROM durable_effect_bindings WHERE effect_id = ?",
                (effect.effect_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            original = authority_snapshot._SnapshotBindingValue(*tuple(row))
            authentication_tag = hmac.new(
                token_key,
                canonical_json_bytes(
                    {
                        "schema_version": 1,
                        "effect_id": original.effect_id,
                        "request_sha256": original.token_request_sha256,
                        "continuation_identity": original.token_continuation_identity,
                    }
                ),
                sha256,
            ).hexdigest()
            provisional = authority_snapshot._SnapshotBindingValue(
                effect_id=original.effect_id,
                target_relative_path=original.target_relative_path,
                artifact_ref_sha256=original.artifact_ref_sha256,
                request_sha256=original.request_sha256,
                scope_sha256=original.scope_sha256,
                bounds_sha256=original.bounds_sha256,
                spec_identity=original.spec_identity,
                spec_sha256=original.spec_sha256,
                policy_identity_sha256=original.policy_identity_sha256,
                token_request_sha256=original.token_request_sha256,
                token_continuation_identity=original.token_continuation_identity,
                token_authentication_tag=authentication_tag,
                binding_sha256="",
            )
            resealed = authority_snapshot._SnapshotBindingValue(
                effect_id=provisional.effect_id,
                target_relative_path=provisional.target_relative_path,
                artifact_ref_sha256=provisional.artifact_ref_sha256,
                request_sha256=provisional.request_sha256,
                scope_sha256=provisional.scope_sha256,
                bounds_sha256=provisional.bounds_sha256,
                spec_identity=provisional.spec_identity,
                spec_sha256=provisional.spec_sha256,
                policy_identity_sha256=provisional.policy_identity_sha256,
                token_request_sha256=provisional.token_request_sha256,
                token_continuation_identity=provisional.token_continuation_identity,
                token_authentication_tag=provisional.token_authentication_tag,
                binding_sha256=sha256_bytes(
                    authority_snapshot._DurableSnapshotStore._binding_canonical_bytes(
                        provisional
                    )
                ),
            )
            connection.execute(
                "UPDATE durable_effect_bindings "
                "SET token_authentication_tag = ?, binding_sha256 = ? "
                "WHERE effect_id = ?",
                (
                    resealed.token_authentication_tag,
                    resealed.binding_sha256,
                    resealed.effect_id,
                ),
            )
            connection.execute(
                "UPDATE durable_target_claims SET binding_sha256 = ? "
                "WHERE effect_id = ?",
                (resealed.binding_sha256, resealed.effect_id),
            )

        self._reseal_tip_snapshot(rekey_binding)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a coherently rekeyed prepared binding must not be adopted")

    def test_reopen_fences_when_published_head_keeps_a_prepared_effect(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-published-state-rewrite",
            target_path="outputs/published-state-rewrite.json",
            artifact_bytes=b'{"effect":"published-state-rewrite"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)

        self._reseal_tip_snapshot(
            lambda connection: connection.execute(
                "UPDATE durable_effects SET state = ? WHERE effect_id = ?",
                (authority_runtime.DurableEffectState.PREPARED.value, effect.effect_id),
            )
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a PUBLISHED generation must advance its prepared effect")

    def test_reopen_fences_when_prepared_snapshot_creates_an_aborted_effect(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-to-aborted",
            target_path="outputs/prepared-to-aborted.json",
            artifact_bytes=b'{"effect":"prepared-to-aborted"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            session.prepare(effect)

        self._rebuild_history_suffix(
            2,
            lambda connection: connection.execute(
                "UPDATE durable_effects SET state = 'ABORTED' WHERE effect_id = ?",
                (effect.effect_id,),
            ),
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a V2 PREPARED snapshot must not create ABORTED")

    def test_reopen_fences_when_published_snapshot_creates_an_aborted_effect(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-published-to-aborted",
            target_path="outputs/published-to-aborted.json",
            artifact_bytes=b'{"effect":"published-to-aborted"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)

        self._rebuild_history_suffix(
            3,
            lambda connection: connection.execute(
                "UPDATE durable_effects SET state = 'ABORTED' WHERE effect_id = ?",
                (effect.effect_id,),
            ),
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a V2 PUBLISHED snapshot must not create ABORTED")

    def test_reopen_fences_when_finalized_head_keeps_a_published_effect(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-finalized-state-rewrite",
            target_path="outputs/finalized-state-rewrite.json",
            artifact_bytes=b'{"effect":"finalized-state-rewrite"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            session.finalize(token)

        self._reseal_tip_snapshot(
            lambda connection: connection.execute(
                "UPDATE durable_effects SET state = ? WHERE effect_id = ?",
                (authority_runtime.DurableEffectState.PUBLISHED.value, effect.effect_id),
            )
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a FINALIZED generation must advance its published effect")

    def test_reopen_fences_when_resealed_published_readback_changes(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-published-readback-rewrite",
            target_path="outputs/published-readback-rewrite.json",
            artifact_bytes=b'{"effect":"published-readback-rewrite"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)

        self._reseal_tip_snapshot(
            lambda connection: connection.execute(
                "UPDATE durable_published_attestations "
                "SET attestation_sha256 = ? WHERE effect_id = ?",
                ("f" * 64, effect.effect_id),
            )
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a changed published readback must not be adopted")

    def test_reopen_fences_when_published_readback_is_coherently_resealed(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-coherent-published-readback-rewrite",
            target_path="outputs/coherent-published-readback-rewrite.json",
            artifact_bytes=b'{"effect":"coherent-published-readback-rewrite"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)

        def reseal_changed_inode(connection: sqlite3.Connection) -> None:
            row = connection.execute(
                "SELECT effect_id, target_relative_path, binding_sha256, "
                "artifact_bytes_sha256, byte_length, target_device, target_inode, "
                "target_nlink, attestation_sha256 "
                "FROM durable_published_attestations WHERE effect_id = ?",
                (effect.effect_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            original = authority_snapshot._SnapshotPublishedAttestationValue(*tuple(row))
            provisional = authority_snapshot._SnapshotPublishedAttestationValue(
                effect_id=original.effect_id,
                target_relative_path=original.target_relative_path,
                binding_sha256=original.binding_sha256,
                artifact_bytes_sha256=original.artifact_bytes_sha256,
                byte_length=original.byte_length,
                target_device=original.target_device,
                target_inode=original.target_inode + 1,
                target_nlink=original.target_nlink,
                attestation_sha256="",
            )
            resealed = authority_snapshot._SnapshotPublishedAttestationValue(
                effect_id=provisional.effect_id,
                target_relative_path=provisional.target_relative_path,
                binding_sha256=provisional.binding_sha256,
                artifact_bytes_sha256=provisional.artifact_bytes_sha256,
                byte_length=provisional.byte_length,
                target_device=provisional.target_device,
                target_inode=provisional.target_inode,
                target_nlink=provisional.target_nlink,
                attestation_sha256=(
                    authority_snapshot._DurableSnapshotStore.published_attestation_sha256(
                        provisional
                    )
                ),
            )
            connection.execute(
                "UPDATE durable_published_attestations "
                "SET target_inode = ?, attestation_sha256 = ? WHERE effect_id = ?",
                (
                    resealed.target_inode,
                    resealed.attestation_sha256,
                    resealed.effect_id,
                ),
            )

        self._reseal_tip_snapshot(reseal_changed_inode)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a coherent but false readback must not be adopted")

    def test_reopen_fences_when_resealed_final_cas_result_changes(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-final-cas-rewrite",
            target_path="outputs/final-cas-rewrite.json",
            artifact_bytes=b'{"effect":"final-cas-rewrite"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            session.finalize(token)

        self._reseal_tip_snapshot(
            lambda connection: connection.execute(
                "UPDATE durable_final_cas_results SET result_sha256 = ? "
                "WHERE effect_id = ?",
                ("f" * 64, effect.effect_id),
            )
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a changed final CAS result must not be adopted")

    def test_reopen_fences_when_terminal_generation_adds_a_claim(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-terminal-extra-claim",
            target_path="outputs/terminal-extra-claim.json",
            artifact_bytes=b'{"effect":"terminal-extra-claim"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)

        def insert_forged_claim(connection: sqlite3.Connection) -> None:
            connection.execute(
                "INSERT INTO durable_claims "
                "(claim_key_sha256, effect_id, target_relative_path, "
                "artifact_ref_sha256, artifact_bytes_sha256, request_sha256, "
                "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                "policy_identity_sha256, expected_predecessor_head_sha256, "
                "claim_generation, active) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "f" * 64,
                    "effect-forged-terminal-claim",
                    "outputs/forged-terminal-claim.json",
                    "f" * 64,
                    "f" * 64,
                    "f" * 64,
                    "f" * 64,
                    "f" * 64,
                    "forged-terminal-spec",
                    "f" * 64,
                    "f" * 64,
                    None,
                    999,
                    1,
                ),
            )

        self._reseal_tip_snapshot(insert_forged_claim)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a terminal generation cannot append a new claim")

    def test_reopen_fences_when_genesis_contains_claim_evidence(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-forged-genesis-claim",
            target_path="outputs/forged-genesis-claim.json",
            artifact_bytes=b'{"effect":"forged-genesis-claim"}\n',
        )
        with authority_runtime.open_write(admitted):
            pass

        def insert_forged_claim(connection: sqlite3.Connection) -> None:
            connection.execute(
                "INSERT INTO durable_claims "
                "(claim_key_sha256, effect_id, target_relative_path, "
                "artifact_ref_sha256, artifact_bytes_sha256, request_sha256, "
                "scope_sha256, bounds_sha256, spec_identity, spec_sha256, "
                "policy_identity_sha256, expected_predecessor_head_sha256, "
                "claim_generation, active) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "f" * 64,
                    "effect-forged-genesis-claim",
                    "outputs/forged-genesis-claim.json",
                    "f" * 64,
                    "f" * 64,
                    "f" * 64,
                    "f" * 64,
                    "f" * 64,
                    "forged-genesis-spec",
                    "f" * 64,
                    "f" * 64,
                    None,
                    0,
                    1,
                ),
            )

        self._reseal_tip_snapshot(insert_forged_claim)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("EMPTY_GENESIS cannot contain recovery claim evidence")

    def test_claimed_snapshot_crash_replays_only_the_matching_effect(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-replay",
            target_path="outputs/claimed-replay.json",
            artifact_bytes=b'{"effect":"claimed-replay"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-claimed-head"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED"],
        )
        self.assertEqual(records[-1]["effect_rows"], ())
        self.assertFalse((self.root / effect.target_relative_path).exists())

        _, different_effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-intruder",
            target_path="outputs/claimed-intruder.json",
            artifact_bytes=b'{"effect":"claimed-intruder"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            with self.assertRaises(authority_runtime.DurableRecoveryDenied):
                session.prepare(different_effect)

        reissued_admission, reissued_effect = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
        )
        with authority_runtime.open_write(reissued_admission) as session:
            token = session.prepare(reissued_effect)
        with authority_runtime.open_write(reissued_admission) as session:
            self.assertEqual(session.prepare(reissued_effect), token)
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
        )

    def test_claim_checkpoint_crash_after_heads_directory_fsync_reopens_exact_new_head(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-head-fsync-crash",
            target_path="outputs/claimed-head-fsync-crash.json",
            artifact_bytes=b'{"effect":"claimed-head-fsync-crash"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                create=True,
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-heads-directory-fsync"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED"],
        )
        parent = records[0]["head"]
        child = records[1]["head"]
        self.assertIsInstance(parent, dict)
        self.assertIsInstance(child, dict)
        self.assertEqual(
            child["parent_head_sha256"],
            sha256_bytes(canonical_json_bytes(parent)),
        )
        self.assertEqual(child["generation"], 1)
        self.assertEqual(
            records[-1]["claim_rows"],
            (
                (
                    effect.effect_id,
                    sha256_bytes(canonical_json_bytes(parent)),
                    1,
                    1,
                ),
            ),
        )
        self.assertEqual(records[-1]["effect_rows"], ())
        self.assertFalse((self.root / effect.target_relative_path).exists())

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
        )
        self.assertEqual(token.effect_id, effect.effect_id)

    def _assert_block_checkpoint_crash_selects_exact_head(
        self,
        *,
        checkpoint_point: str,
        expected_transitions: list[str],
        expect_blocked_recovery: bool,
    ) -> None:
        admitted, effect = self._admit_durable_write_effect(
            effect_id=(
                "effect-block-checkpoint-"
                f"{checkpoint_point.removeprefix('after-')}"
            ),
            target_path=(
                "outputs/block-checkpoint-"
                f"{checkpoint_point.removeprefix('after-')}.json"
            ),
            artifact_bytes=(f'{{"effect":"{checkpoint_point}"}}\n'.encode("utf-8")),
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            coordinator = session._WriteSession__coordinator
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == checkpoint_point
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    coordinator._block_for_token(
                        token,
                        message="block checkpoint crash test",
                        reason_code="RECOVERY_TEST_BLOCK",
                    )

        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            expected_transitions,
        )
        self.assertFalse((self.root / effect.target_relative_path).exists())
        if expect_blocked_recovery:
            recovery_admitted, _ = self._admit_durable_write_effect(
                effect_id=effect.effect_id,
                target_path=effect.target_relative_path,
                artifact_bytes=effect.artifact_bytes,
                action=operation_contract.LifecycleAction.RECOVER,
            )
            with authority_runtime.open_write(recovery_admitted) as session:
                with self.assertRaises(
                    authority_runtime.DurableRecoveryRequired
                ) as captured:
                    session.recover(token)
            self.assertEqual(
                captured.exception.directive.reason_code,
                "RECOVERY_TEST_BLOCK",
            )

    def test_block_checkpoint_crash_before_head_link_reopens_exact_old_head(self):
        self._assert_block_checkpoint_crash_selects_exact_head(
            checkpoint_point="after-receipt-directory-fsync",
            expected_transitions=["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
            expect_blocked_recovery=False,
        )

    def test_block_checkpoint_crash_after_heads_directory_fsync_reopens_exact_new_head(
        self,
    ):
        self._assert_block_checkpoint_crash_selects_exact_head(
            checkpoint_point="after-heads-directory-fsync",
            expected_transitions=[
                "EMPTY_GENESIS",
                "CLAIMED",
                "PREPARED",
                "BLOCKED_RECOVERY",
            ],
            expect_blocked_recovery=True,
        )

    def _assert_transition_checkpoint_crash_reopens_exact_new_state(
        self,
        *,
        state: authority_runtime.DurableEffectState,
    ) -> None:
        name = state.value.lower()
        admitted, effect = self._admit_durable_write_effect(
            effect_id=f"effect-{name}-head-fsync-crash",
            target_path=f"outputs/{name}-head-fsync-crash.json",
            artifact_bytes=f'{{"effect":"{name}-head-fsync-crash"}}\n'.encode(
                "utf-8"
            ),
        )

        if state is authority_runtime.DurableEffectState.PREPARED:
            head_fsyncs = 0

            def crash_after_prepared_head(point: str) -> None:
                nonlocal head_fsyncs
                if point != "after-heads-directory-fsync":
                    return
                head_fsyncs += 1
                if head_fsyncs == 2:
                    raise SimulatedDurableCrash()

            with authority_runtime.open_write(admitted) as session:
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=crash_after_prepared_head,
                ):
                    with self.assertRaises(SimulatedDurableCrash):
                        session.prepare(effect)
            token = self._snapshot_binding_for_effect(effect.effect_id).token
            self.assertEqual(head_fsyncs, 2)
            self.assertFalse((self.root / effect.target_relative_path).exists())
        elif state is authority_runtime.DurableEffectState.PUBLISHED:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=lambda point: (
                        (_ for _ in ()).throw(SimulatedDurableCrash())
                        if point == "after-heads-directory-fsync"
                        else None
                    ),
                ):
                    with self.assertRaises(SimulatedDurableCrash):
                        session.publish(token)
            self.assertEqual(
                (self.root / effect.target_relative_path).read_bytes(),
                effect.artifact_bytes,
            )
        elif state is authority_runtime.DurableEffectState.FINALIZED:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                session.publish(token)
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=lambda point: (
                        (_ for _ in ()).throw(SimulatedDurableCrash())
                        if point == "after-heads-directory-fsync"
                        else None
                    ),
                ):
                    with self.assertRaises(SimulatedDurableCrash):
                        session.finalize(token)
            self.assertEqual(
                (self.root / effect.target_relative_path).read_bytes(),
                effect.artifact_bytes,
            )
        else:
            self.fail(f"unsupported transition crash state: {state!r}")

        records = self._snapshot_head_records()
        self.assertEqual(records[-1]["transition_kind"], state.value)
        self.assertEqual(
            records[-1]["effect_rows"],
            ((effect.effect_id, state.value),),
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_prepared_checkpoint_crash_after_heads_directory_fsync_reopens_exact_new_state(
        self,
    ):
        self._assert_transition_checkpoint_crash_reopens_exact_new_state(
            state=authority_runtime.DurableEffectState.PREPARED,
        )

    def test_published_checkpoint_crash_after_heads_directory_fsync_reopens_exact_new_state(
        self,
    ):
        self._assert_transition_checkpoint_crash_reopens_exact_new_state(
            state=authority_runtime.DurableEffectState.PUBLISHED,
        )

    def test_finalized_checkpoint_crash_after_heads_directory_fsync_reopens_exact_new_state(
        self,
    ):
        self._assert_transition_checkpoint_crash_reopens_exact_new_state(
            state=authority_runtime.DurableEffectState.FINALIZED,
        )

    def _assert_transition_checkpoint_crash_before_head_link_reopens_exact_old_state(
        self,
        *,
        state: authority_runtime.DurableEffectState,
    ) -> None:
        name = state.value.lower()
        admitted, effect = self._admit_durable_write_effect(
            effect_id=f"effect-{name}-receipt-crash",
            target_path=f"outputs/{name}-receipt-crash.json",
            artifact_bytes=f'{{"effect":"{name}-receipt-crash"}}\n'.encode(
                "utf-8"
            ),
        )
        checkpoint_point = "after-receipt-directory-fsync"

        if state is authority_runtime.DurableEffectState.PREPARED:
            receipt_directory_fsyncs = 0

            def crash_before_prepared_head_link(point: str) -> None:
                nonlocal receipt_directory_fsyncs
                if point != checkpoint_point:
                    return
                receipt_directory_fsyncs += 1
                if receipt_directory_fsyncs == 2:
                    raise SimulatedDurableCrash()

            with authority_runtime.open_write(admitted) as session:
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=crash_before_prepared_head_link,
                ):
                    with self.assertRaises(SimulatedDurableCrash):
                        session.prepare(effect)
            self.assertEqual(receipt_directory_fsyncs, 2)
            expected_transition = "CLAIMED"
            expected_effect_rows = ()
            self.assertFalse((self.root / effect.target_relative_path).exists())
        elif state is authority_runtime.DurableEffectState.PUBLISHED:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=lambda point: (
                        (_ for _ in ()).throw(SimulatedDurableCrash())
                        if point == checkpoint_point
                        else None
                    ),
                ):
                    with self.assertRaises(SimulatedDurableCrash):
                        session.publish(token)
            expected_transition = "PREPARED"
            expected_effect_rows = (
                (effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),
            )
            self.assertEqual(
                (self.root / effect.target_relative_path).read_bytes(),
                effect.artifact_bytes,
            )
        elif state is authority_runtime.DurableEffectState.FINALIZED:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                session.publish(token)
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=lambda point: (
                        (_ for _ in ()).throw(SimulatedDurableCrash())
                        if point == checkpoint_point
                        else None
                    ),
                ):
                    with self.assertRaises(SimulatedDurableCrash):
                        session.finalize(token)
            expected_transition = "PUBLISHED"
            expected_effect_rows = (
                (effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),
            )
            self.assertEqual(
                (self.root / effect.target_relative_path).read_bytes(),
                effect.artifact_bytes,
            )
        else:
            self.fail(f"unsupported transition crash state: {state!r}")

        records = self._snapshot_head_records()
        self.assertEqual(records[-1]["transition_kind"], expected_transition)
        self.assertEqual(records[-1]["effect_rows"], expected_effect_rows)
        if state is authority_runtime.DurableEffectState.PREPARED:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_prepared_checkpoint_crash_before_head_link_reopens_exact_old_state(
        self,
    ):
        self._assert_transition_checkpoint_crash_before_head_link_reopens_exact_old_state(
            state=authority_runtime.DurableEffectState.PREPARED,
        )

    def test_published_checkpoint_crash_before_head_link_reopens_exact_old_state(
        self,
    ):
        self._assert_transition_checkpoint_crash_before_head_link_reopens_exact_old_state(
            state=authority_runtime.DurableEffectState.PUBLISHED,
        )

    def test_finalized_checkpoint_crash_before_head_link_reopens_exact_old_state(
        self,
    ):
        self._assert_transition_checkpoint_crash_before_head_link_reopens_exact_old_state(
            state=authority_runtime.DurableEffectState.FINALIZED,
        )

    def test_claim_checkpoint_crash_after_receipt_directory_fsync_reopens_exact_old_head(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-receipt-fsync-crash",
            target_path="outputs/claimed-receipt-fsync-crash.json",
            artifact_bytes=b'{"effect":"claimed-receipt-fsync-crash"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-receipt-directory-fsync"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS"],
        )
        self.assertEqual(records[-1]["effect_rows"], ())
        self.assertFalse((self.root / effect.target_relative_path).exists())

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
        )
        self.assertEqual(token.effect_id, effect.effect_id)

    def test_claim_checkpoint_crash_after_snapshot_object_seal_reopens_exact_old_head(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-snapshot-object-crash",
            target_path="outputs/claimed-snapshot-object-crash.json",
            artifact_bytes=b'{"effect":"claimed-snapshot-object-crash"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-snapshot-object-seal"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS"],
        )
        self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_claim_checkpoint_crash_after_manifest_object_seal_reopens_exact_old_head(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-manifest-object-crash",
            target_path="outputs/claimed-manifest-object-crash.json",
            artifact_bytes=b'{"effect":"claimed-manifest-object-crash"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-manifest-object-seal"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS"],
        )
        self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_claim_checkpoint_crash_before_snapshot_object_seal_reopens_exact_old_head(
        self,
    ):
        for checkpoint_point in (
            "after-snapshot-commit",
            "after-snapshot-serialize",
        ):
            with self.subTest(checkpoint_point=checkpoint_point):
                admitted, effect = self._admit_durable_write_effect(
                    effect_id=(
                        "effect-claimed-"
                        f"{checkpoint_point.removeprefix('after-snapshot-')}"
                    ),
                    target_path=(
                        "outputs/claimed-"
                        f"{checkpoint_point.removeprefix('after-snapshot-')}.json"
                    ),
                    artifact_bytes=(
                        f'{{"effect":"{checkpoint_point}"}}\n'.encode("utf-8")
                    ),
                )

                with authority_runtime.open_write(admitted) as session:
                    with mock.patch.object(
                        authority_snapshot,
                        "_run_snapshot_checkpoint",
                        side_effect=lambda point: (
                            (_ for _ in ()).throw(SimulatedDurableCrash())
                            if point == checkpoint_point
                            else None
                        ),
                    ):
                        with self.assertRaises(SimulatedDurableCrash):
                            session.prepare(effect)

                self.assertEqual(
                    [
                        record["transition_kind"]
                        for record in self._snapshot_head_records()
                    ],
                    ["EMPTY_GENESIS"],
                )
                self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_checkpoint_rejects_an_active_sqlite_transaction_before_serialize(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-active-snapshot-transaction",
            target_path="outputs/active-snapshot-transaction.json",
            artifact_bytes=b'{"effect":"active-snapshot-transaction"}\n',
        )
        original_configure = (
            authority_snapshot._DurableSnapshotStore._configure_connection.__func__
        )

        def configure_then_begin(cls, connection):
            original_configure(cls, connection)
            connection.execute("BEGIN")

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "_verify_expected_history",
                return_value=None,
            ):
                with mock.patch.object(
                    authority_snapshot._DurableSnapshotStore,
                    "_configure_connection",
                    new=classmethod(configure_then_begin),
                ):
                    with self.assertRaisesRegex(
                        authority_runtime.AuthorityRuntimeError,
                        "transaction is active",
                    ):
                        session.prepare(effect)

        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS"],
        )
        self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_claim_checkpoint_crash_within_snapshot_object_seal_reopens_exact_old_head(
        self,
    ):
        for checkpoint_point in (
            "after-snapshot-object-file-fsync",
            "after-snapshot-object-readback",
            "after-snapshot-object-directory-fsync",
        ):
            with self.subTest(checkpoint_point=checkpoint_point):
                suffix = checkpoint_point.removeprefix("after-snapshot-")
                admitted, effect = self._admit_durable_write_effect(
                    effect_id=f"effect-claimed-{suffix}",
                    target_path=f"outputs/claimed-{suffix}.json",
                    artifact_bytes=(
                        f'{{"effect":"{checkpoint_point}"}}\n'.encode("utf-8")
                    ),
                )

                with authority_runtime.open_write(admitted) as session:
                    with mock.patch.object(
                        authority_snapshot,
                        "_run_snapshot_checkpoint",
                        side_effect=lambda point: (
                            (_ for _ in ()).throw(SimulatedDurableCrash())
                            if point == checkpoint_point
                            else None
                        ),
                    ):
                        with self.assertRaises(SimulatedDurableCrash):
                            session.prepare(effect)

                self.assertEqual(
                    [
                        record["transition_kind"]
                        for record in self._snapshot_head_records()
                    ],
                    ["EMPTY_GENESIS"],
                )
                self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_claim_checkpoint_crash_before_head_link_reopens_exact_old_head(self):
        for checkpoint_point in (
            "after-manifest-object-file-fsync",
            "after-manifest-object-readback",
            "after-manifest-object-directory-fsync",
            "after-receipt-file-fsync",
            "after-receipt-readback",
            "after-receipt-directory-fsync",
        ):
            with self.subTest(checkpoint_point=checkpoint_point):
                suffix = checkpoint_point.removeprefix("after-")
                admitted, effect = self._admit_durable_write_effect(
                    effect_id=f"effect-claimed-{suffix}",
                    target_path=f"outputs/claimed-{suffix}.json",
                    artifact_bytes=(
                        f'{{"effect":"{checkpoint_point}"}}\n'.encode("utf-8")
                    ),
                )

                with authority_runtime.open_write(admitted) as session:
                    with mock.patch.object(
                        authority_snapshot,
                        "_run_snapshot_checkpoint",
                        side_effect=lambda point: (
                            (_ for _ in ()).throw(SimulatedDurableCrash())
                            if point == checkpoint_point
                            else None
                        ),
                    ):
                        with self.assertRaises(SimulatedDurableCrash):
                            session.prepare(effect)

                self.assertEqual(
                    [
                        record["transition_kind"]
                        for record in self._snapshot_head_records()
                    ],
                    ["EMPTY_GENESIS"],
                )
                self.assertFalse((self.root / effect.target_relative_path).exists())

    def _assert_claim_checkpoint_crash_reopens_exact_new_head(
        self,
        *,
        checkpoint_point: str,
    ) -> None:
        suffix = checkpoint_point.removeprefix("after-")
        admitted, effect = self._admit_durable_write_effect(
            effect_id=f"effect-claimed-{suffix}",
            target_path=f"outputs/claimed-{suffix}.json",
            artifact_bytes=f'{{"effect":"{checkpoint_point}"}}\n'.encode("utf-8"),
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == checkpoint_point
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED"],
        )
        self.assertEqual(records[-1]["effect_rows"], ())
        self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_claim_checkpoint_crash_after_canonical_head_readback_reopens_exact_new_head(
        self,
    ):
        self._assert_claim_checkpoint_crash_reopens_exact_new_head(
            checkpoint_point="after-canonical-head-readback"
        )

    def test_claim_checkpoint_crash_after_head_file_fsync_reopens_exact_new_head(
        self,
    ):
        self._assert_claim_checkpoint_crash_reopens_exact_new_head(
            checkpoint_point="after-head-file-fsync"
        )

    def test_claim_checkpoint_crash_after_head_link_reopens_exact_new_head(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-head-link-crash",
            target_path="outputs/claimed-head-link-crash.json",
            artifact_bytes=b'{"effect":"claimed-head-link-crash"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-receipt-link"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED"],
        )
        self.assertEqual(records[-1]["effect_rows"], ())
        self.assertFalse((self.root / effect.target_relative_path).exists())

    def _assert_persisted_checkpoint_fault_reopens_exact_history(
        self,
        *,
        state: str,
        checkpoint_point: str,
        surviving_new_head: bool,
        discard_linked_head_before_reopen: bool = False,
    ) -> None:
        if discard_linked_head_before_reopen and checkpoint_point not in {
            "after-receipt-link",
            "after-canonical-head-readback",
            "after-head-file-fsync",
            "after-heads-directory-fsync",
        }:
            self.fail("only a linked immutable head may be discarded in this fixture")
        state_name = state.lower().replace("_", "-")
        admitted, effect = self._admit_durable_write_effect(
            effect_id=f"effect-{state_name}-{checkpoint_point.removeprefix('after-')}",
            target_path=(
                "outputs/"
                f"{state_name}-{checkpoint_point.removeprefix('after-')}.json"
            ),
            artifact_bytes=(
                f'{{"effect":"{state_name}-{checkpoint_point}"}}\n'.encode("utf-8")
            ),
        )
        observed_checkpoint_calls = 0

        def crash_at_requested_checkpoint(point: str) -> None:
            nonlocal observed_checkpoint_calls
            if point != checkpoint_point:
                return
            observed_checkpoint_calls += 1
            raise SimulatedDurableCrash()

        heads_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "heads"
        )
        head_names_before_fault: set[str] | None = None

        def capture_heads_before_fault() -> None:
            nonlocal head_names_before_fault
            head_names_before_fault = {
                path.name for path in heads_directory.glob("h-*.json")
            }

        if state in (
            authority_runtime.DurableEffectState.PREPARED.value,
            "CLAIMED",
        ):
            target_occurrence = (
                1
                if state == "CLAIMED"
                else 2
            )

            def crash_at_requested_transition(point: str) -> None:
                nonlocal observed_checkpoint_calls
                if point != checkpoint_point:
                    return
                observed_checkpoint_calls += 1
                if observed_checkpoint_calls == target_occurrence - 1:
                    capture_heads_before_fault()
                if observed_checkpoint_calls == target_occurrence:
                    raise SimulatedDurableCrash()

            with authority_runtime.open_write(admitted) as session:
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=crash_at_requested_transition,
                ):
                    if target_occurrence == 1:
                        capture_heads_before_fault()
                    with self.assertRaises(SimulatedDurableCrash):
                        session.prepare(effect)
            self.assertEqual(observed_checkpoint_calls, target_occurrence)
        elif state == authority_runtime.DurableEffectState.PUBLISHED.value:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=crash_at_requested_checkpoint,
                ):
                    capture_heads_before_fault()
                    with self.assertRaises(SimulatedDurableCrash):
                        session.publish(token)
        elif state == authority_runtime.DurableEffectState.FINALIZED.value:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                session.publish(token)
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=crash_at_requested_checkpoint,
                ):
                    capture_heads_before_fault()
                    with self.assertRaises(SimulatedDurableCrash):
                        session.finalize(token)
        elif state == authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                coordinator = session._WriteSession__coordinator
                with mock.patch.object(
                    authority_snapshot,
                    "_run_snapshot_checkpoint",
                    side_effect=crash_at_requested_checkpoint,
                ):
                    capture_heads_before_fault()
                    with self.assertRaises(SimulatedDurableCrash):
                        coordinator._block_for_token(
                            token,
                            message="persisted checkpoint matrix",
                            reason_code="RECOVERY_TEST_BLOCK",
                        )
        else:
            self.fail(f"unsupported persisted checkpoint state: {state!r}")

        if discard_linked_head_before_reopen:
            self.assertIsNotNone(head_names_before_fault)
            new_head_paths = [
                path
                for path in heads_directory.glob("h-*.json")
                if path.name not in head_names_before_fault
            ]
            self.assertEqual(len(new_head_paths), 1)
            # The temporary fixture models a power loss after the final
            # directory fsync call was issued but before that new immutable
            # head survived.  Its receipt/object residue intentionally stays.
            new_head_paths[0].unlink()

        old_transitions: dict[str, list[str]] = {
            "CLAIMED": ["EMPTY_GENESIS"],
            authority_runtime.DurableEffectState.PREPARED.value: [
                "EMPTY_GENESIS",
                "CLAIMED",
            ],
            authority_runtime.DurableEffectState.PUBLISHED.value: [
                "EMPTY_GENESIS",
                "CLAIMED",
                "PREPARED",
            ],
            authority_runtime.DurableEffectState.FINALIZED.value: [
                "EMPTY_GENESIS",
                "CLAIMED",
                "PREPARED",
                "PUBLISHED",
            ],
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value: [
                "EMPTY_GENESIS",
                "CLAIMED",
                "PREPARED",
            ],
        }
        old_effect_rows: dict[str, tuple[tuple[str, str], ...]] = {
            "CLAIMED": (),
            authority_runtime.DurableEffectState.PREPARED.value: (),
            authority_runtime.DurableEffectState.PUBLISHED.value: (
                (effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),
            ),
            authority_runtime.DurableEffectState.FINALIZED.value: (
                (effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),
            ),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value: (
                (effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),
            ),
        }
        expected_transitions = old_transitions[state] + (
            [state] if surviving_new_head else []
        )
        expected_effect_rows = (
            ()
            if state == "CLAIMED"
            else ((effect.effect_id, state),)
        ) if surviving_new_head else old_effect_rows[state]

        # The first operation after a simulated process crash must be a real
        # fresh open, not direct SQLite/object inspection.  Only after that
        # strict chain selection do fixture assertions inspect its result.
        with authority_runtime.open_write(admitted):
            pass
        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            expected_transitions,
        )
        self.assertEqual(records[-1]["effect_rows"], expected_effect_rows)
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )
        if state in (
            "CLAIMED",
            authority_runtime.DurableEffectState.PREPARED.value,
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        ):
            self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_every_persisted_checkpoint_fault_reopens_exact_old_or_new_history(self):
        pre_link_points = (
            "after-snapshot-commit",
            "after-snapshot-serialize",
            "after-snapshot-object-file-fsync",
            "after-snapshot-object-readback",
            "after-snapshot-object-directory-fsync",
            "after-snapshot-object-seal",
            "after-manifest-object-file-fsync",
            "after-manifest-object-readback",
            "after-manifest-object-directory-fsync",
            "after-manifest-object-seal",
            "after-receipt-file-fsync",
            "after-receipt-readback",
            "after-receipt-directory-fsync",
        )
        linked_head_points = (
            "after-receipt-link",
            "after-canonical-head-readback",
            "after-head-file-fsync",
            "after-heads-directory-fsync",
        )
        states = (
            "CLAIMED",
            authority_runtime.DurableEffectState.PREPARED.value,
            authority_runtime.DurableEffectState.PUBLISHED.value,
            authority_runtime.DurableEffectState.FINALIZED.value,
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )
        for state in states:
            for checkpoint_point in pre_link_points:
                with self.subTest(state=state, checkpoint_point=checkpoint_point):
                    with self._independent_write_fixture() as fixture:
                        fixture._assert_persisted_checkpoint_fault_reopens_exact_history(
                            state=state,
                            checkpoint_point=checkpoint_point,
                            surviving_new_head=False,
                        )
            for checkpoint_point in linked_head_points:
                with self.subTest(state=state, checkpoint_point=checkpoint_point):
                    with self._independent_write_fixture() as fixture:
                        fixture._assert_persisted_checkpoint_fault_reopens_exact_history(
                            state=state,
                            checkpoint_point=checkpoint_point,
                            surviving_new_head=True,
                        )
            with self.subTest(
                state=state,
                checkpoint_point="after-heads-directory-fsync",
                surviving_new_head=False,
            ):
                with self._independent_write_fixture() as fixture:
                    fixture._assert_persisted_checkpoint_fault_reopens_exact_history(
                        state=state,
                        checkpoint_point="after-heads-directory-fsync",
                        surviving_new_head=False,
                        discard_linked_head_before_reopen=True,
                    )

    def test_prepared_head_publication_error_closes_the_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-head-publication-error",
            target_path="outputs/prepared-head-publication-error.json",
            artifact_bytes=b'{"effect":"prepared-head-publication-error"}\n',
        )
        checkpoint_calls = 0

        def fail_after_prepared_head(point: str) -> None:
            nonlocal checkpoint_calls
            if point != "after-heads-directory-fsync":
                return
            checkpoint_calls += 1
            if checkpoint_calls == 2:
                raise authority_runtime.AuthorityRuntimeError(
                    "simulated prepared head publication error"
                )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=fail_after_prepared_head,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable prepare state is unavailable",
                ) as captured:
                    session.prepare(effect)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.publish(captured.exception.directive.token)
            self.assertEqual(
                closed.exception.directive,
                captured.exception.directive,
            )

        self.assertEqual(checkpoint_calls, 2)
        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED"],
        )
        self.assertFalse((self.root / effect.target_relative_path).exists())
        token = self._snapshot_binding_for_effect(effect.effect_id).token
        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "recoverable")

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_published_head_publication_error_closes_the_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-published-head-publication-error",
            target_path="outputs/published-head-publication-error.json",
            artifact_bytes=b'{"effect":"published-head-publication-error"}\n',
        )
        checkpoint_calls = 0

        def fail_after_published_head(point: str) -> None:
            nonlocal checkpoint_calls
            if point != "after-heads-directory-fsync":
                return
            checkpoint_calls += 1
            if checkpoint_calls == 1:
                raise authority_runtime.AuthorityRuntimeError(
                    "simulated published head publication error"
                )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=fail_after_published_head,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable state transition is unavailable",
                ) as captured:
                    session.publish(token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active",
            ):
                session.finalize(token)

        self.assertEqual(checkpoint_calls, 1)
        records = self._snapshot_head_records()
        self.assertEqual(
            [record["transition_kind"] for record in records],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED", "PUBLISHED"],
        )
        self.assertEqual(
            records[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),),
        )
        self.assertEqual(len(records[-1]["published_attestation_rows"]), 1)
        self.assertTrue((self.root / effect.target_relative_path).is_file())

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )
        self.assertEqual(captured.exception.directive.token, token)

    def test_published_head_link_oserror_closes_the_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-published-head-link-oserror",
            target_path="outputs/published-head-link-oserror.json",
            artifact_bytes=b'{"effect":"published-head-link-oserror"}\n',
        )

        def fail_snapshot_head_link(*args, **kwargs):
            raise OSError("simulated snapshot head link error")

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot.os,
                "link",
                side_effect=fail_snapshot_head_link,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable state transition is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertEqual(captured.exception.directive.token, token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.finalize(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )
        self.assertEqual(
            (self.root / effect.target_relative_path).read_bytes(),
            effect.artifact_bytes,
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_root_fence_closes_the_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-root-fence-session-close",
            target_path="outputs/root-fence-session-close.json",
            artifact_bytes=b'{"effect":"root-fence-session-close"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            coordinator = session._WriteSession__coordinator
            coordinator._root_fence(
                "simulated durable root fence",
                reason_code="RECOVERY_TEST_FENCE",
            )
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "durable snapshot root is stopped",
            ):
                session.publish(token)
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "write session is not active",
            ):
                session.publish(token)

    def test_published_snapshot_object_file_fsync_oserror_closes_current_write_session(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-published-object-fsync-oserror",
            target_path="outputs/published-object-fsync-oserror.json",
            artifact_bytes=b'{"effect":"published-object-fsync-oserror"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            objects_directory = (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "snapshot-v1"
                / "objects"
            )
            original_fsync = os.fsync

            def fail_only_new_snapshot_object_staging_file(fd: int) -> None:
                info = os.fstat(fd)
                if stat.S_ISREG(info.st_mode):
                    for candidate in objects_directory.iterdir():
                        candidate_info = candidate.stat()
                        if (
                            candidate.name.startswith(".o-")
                            and (candidate_info.st_dev, candidate_info.st_ino)
                            == (info.st_dev, info.st_ino)
                        ):
                            raise OSError(
                                "simulated snapshot object file fsync error"
                            )
                original_fsync(fd)

            with mock.patch.object(
                authority_snapshot.os,
                "fsync",
                side_effect=fail_only_new_snapshot_object_staging_file,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable state transition is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertEqual(captured.exception.directive.token, token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.finalize(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_published_heads_directory_fsync_oserror_closes_current_write_session(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-published-head-fsync-oserror",
            target_path="outputs/published-head-fsync-oserror.json",
            artifact_bytes=b'{"effect":"published-head-fsync-oserror"}\n',
        )
        heads_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "heads"
        )
        with authority_runtime.open_write(admitted):
            pass
        heads_info = heads_directory.stat()
        original_fsync = os.fsync

        def fail_only_snapshot_heads_directory(fd: int) -> None:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (heads_info.st_dev, heads_info.st_ino):
                raise OSError("simulated snapshot heads directory fsync error")
            original_fsync(fd)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot.os,
                "fsync",
                side_effect=fail_only_snapshot_heads_directory,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable state transition is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertEqual(captured.exception.directive.token, token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.finalize(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),),
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_prepared_staging_file_fsync_oserror_closes_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-staging-fsync-oserror",
            target_path="outputs/prepared-staging-fsync-oserror.json",
            artifact_bytes=b'{"effect":"prepared-staging-fsync-oserror"}\n',
        )
        staging_directory = self._snapshot_stage_path(effect.effect_id).parent
        original_fsync = os.fsync

        def fail_only_staging_file_fsync(fd: int) -> None:
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and staging_directory.is_dir():
                for candidate in staging_directory.iterdir():
                    candidate_info = candidate.stat()
                    if (
                        candidate.name.startswith(
                            f".{effect.effect_id}.artifact.incomplete-"
                        )
                        and (candidate_info.st_dev, candidate_info.st_ino)
                        == (info.st_dev, info.st_ino)
                    ):
                        raise OSError("simulated durable staging file fsync error")
            original_fsync(fd)

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable.os,
                "fsync",
                side_effect=fail_only_staging_file_fsync,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "staging artifact is unavailable",
                ) as captured:
                    session.prepare(effect)
            token = captured.exception.directive.token
            self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.publish(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((
                effect.effect_id,
                authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
            ),),
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "blocked for recovery",
            ):
                session.recover(token)

    def test_finalized_head_link_oserror_closes_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-finalized-head-link-oserror",
            target_path="outputs/finalized-head-link-oserror.json",
            artifact_bytes=b'{"effect":"finalized-head-link-oserror"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            with mock.patch.object(
                authority_snapshot.os,
                "link",
                side_effect=OSError("simulated finalized snapshot head link error"),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable state transition is unavailable",
                ) as captured:
                    session.finalize(token)
            self.assertEqual(captured.exception.directive.token, token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.finalize(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),),
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_finalized_head_publication_error_closes_the_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-finalized-head-publication-error",
            target_path="outputs/finalized-head-publication-error.json",
            artifact_bytes=b'{"effect":"finalized-head-publication-error"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(
                        authority_runtime.AuthorityRuntimeError(
                            "simulated finalized head publication error"
                        )
                    )
                    if point == "after-heads-directory-fsync"
                    else None
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable state transition is unavailable",
                ):
                    session.finalize(token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active",
            ):
                session.finalize(token)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_final_cas_record_error_after_insert_closes_the_current_write_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-final-cas-after-insert-error",
            target_path="outputs/final-cas-after-insert-error.json",
            artifact_bytes=b'{"effect":"final-cas-after-insert-error"}\n',
        )
        original_record = authority_snapshot._DurableSnapshotStore.record_final_cas_result

        def record_then_fail(store, value):
            original_record(store, value)
            raise authority_runtime.AuthorityRuntimeError(
                "simulated final CAS record error"
            )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "record_final_cas_result",
                new=record_then_fail,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable final CAS evidence is unavailable",
                ):
                    session.finalize(token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active",
            ):
                session.finalize(token)

        records = self._snapshot_head_records()
        self.assertEqual(
            records[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),),
        )
        self.assertEqual(records[-1]["final_cas_rows"], ())

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_final_cas_record_error_before_insert_closes_the_current_write_session(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-final-cas-before-insert-error",
            target_path="outputs/final-cas-before-insert-error.json",
            artifact_bytes=b'{"effect":"final-cas-before-insert-error"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "record_final_cas_result",
                side_effect=authority_runtime.AuthorityRuntimeError(
                    "simulated final CAS record error"
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable final CAS evidence is unavailable",
                ):
                    session.finalize(token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active",
            ):
                session.finalize(token)

        records = self._snapshot_head_records()
        self.assertEqual(
            records[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),),
        )
        self.assertEqual(records[-1]["final_cas_rows"], ())

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_block_checkpoint_publication_error_closes_the_current_write_session(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-block-head-publication-error",
            target_path="outputs/block-head-publication-error.json",
            artifact_bytes=b'{"effect":"block-head-publication-error"}\n',
        )
        heads_directory_fsyncs = 0

        def fail_on_block_head(point):
            nonlocal heads_directory_fsyncs
            if point != "after-heads-directory-fsync":
                return
            heads_directory_fsyncs += 1
            if heads_directory_fsyncs == 1:
                raise authority_runtime.AuthorityRuntimeError(
                    "simulated blocked head publication error"
                )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            (self.root / effect.target_relative_path).unlink()
            with mock.patch.object(
                authority_snapshot,
                "_run_snapshot_checkpoint",
                side_effect=fail_on_block_head,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "published durable effect is absent",
                ):
                    session.finalize(token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active",
            ):
                session.finalize(token)

        self.assertEqual(heads_directory_fsyncs, 1)
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED", "PREPARED", "PUBLISHED", "BLOCKED_RECOVERY"],
        )
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )
        self.assertFalse(
            (runtime_directory / "recovery-blockers" / f"{effect.effect_id}.json").exists()
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "durable effect is blocked for recovery",
            ) as blocked:
                session.recover(token)
        self.assertEqual(blocked.exception.directive.token, token)
        self.assertEqual(blocked.exception.directive.disposition, "blocked_recovery")

    def test_published_attestation_error_after_insert_closes_the_current_write_session(
        self,
    ):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-published-attestation-after-insert-error",
            target_path="outputs/published-attestation-after-insert-error.json",
            artifact_bytes=b'{"effect":"published-attestation-after-insert-error"}\n',
        )
        original_record = authority_snapshot._DurableSnapshotStore.record_published_attestation

        def record_then_fail(store, value):
            original_record(store, value)
            raise authority_runtime.AuthorityRuntimeError(
                "simulated published attestation record error"
            )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "record_published_attestation",
                new=record_then_fail,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable published readback is unavailable",
                ):
                    session.publish(token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active",
            ):
                session.publish(token)

        records = self._snapshot_head_records()
        self.assertEqual(
            records[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )
        self.assertEqual(records[-1]["published_attestation_rows"], ())
        self.assertTrue((self.root / effect.target_relative_path).is_file())

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_claimed_snapshot_rejects_same_effect_under_different_admission(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-admission-mismatch",
            target_path="outputs/claimed-admission-mismatch.json",
            artifact_bytes=b'{"effect":"claimed-admission-mismatch"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-claimed-head"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        different_admission, same_effect = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            actor="different-operator",
        )
        with authority_runtime.open_write(different_admission) as session:
            with self.assertRaises(authority_runtime.DurableRecoveryDenied) as captured:
                session.prepare(same_effect)
        self.assertEqual(captured.exception.reason_code, "RECOVERY_ADMISSION_MISMATCH")
        self.assertFalse((self.root / effect.target_relative_path).exists())
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED"],
        )

    def test_claimed_snapshot_rejects_rekeyed_forged_predecessor(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-forged-predecessor",
            target_path="outputs/claimed-forged-predecessor.json",
            artifact_bytes=b'{"effect":"claimed-forged-predecessor"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-claimed-head"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        original_predecessor = self._snapshot_head_records()[-1]["head"][
            "parent_head_sha256"
        ]
        self.assertIsInstance(original_predecessor, str)
        forged_predecessor = "f" * 64
        self.assertNotEqual(forged_predecessor, original_predecessor)
        self._rekey_claimed_snapshot_predecessor(forged_predecessor)

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted):
                self.fail("a forged CLAIMED predecessor must not be adopted")
        self.assertFalse((self.root / effect.target_relative_path).exists())
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS", "CLAIMED"],
        )

    def test_claimed_snapshot_rejects_wrong_transition_kind(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-claimed-wrong-transition",
            target_path="outputs/claimed-wrong-transition.json",
            artifact_bytes=b'{"effect":"claimed-wrong-transition"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-claimed-head"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        original_predecessor = self._snapshot_head_records()[-1]["head"][
            "parent_head_sha256"
        ]
        self.assertIsInstance(original_predecessor, str)
        self._rekey_claimed_snapshot_predecessor(
            original_predecessor,
            transition_kind="PREPARED",
        )

        with self.assertRaises(authority_runtime.DurableRecoveryFenceRequired):
            with authority_runtime.open_write(admitted) as session:
                session.prepare(effect)
        self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_crash_after_publish_recovers_exactly_one_sealed_effect(self):
        contract = operation_contract.AdmissionContract(
            spec_identity="test-write-v1",
            spec_sha256="6" * 64,
            operation_kind="test.write",
            allowed_actions=(
                operation_contract.LifecycleAction.APPLY,
                operation_contract.LifecycleAction.RECOVER,
            ),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        admitted = authority_runtime.admit(
            operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="test.write",
                action=operation_contract.LifecycleAction.APPLY,
                claim_mode=operation_contract.ClaimMode.NONE,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.WRITE,
                payload={},
                bounds={},
            ),
            contract,
        )
        artifact_bytes = b'{"effect":"sealed"}\n'
        effect = authority_runtime.StagedEffect(
            effect_id="effect-001",
            target_relative_path="outputs/sealed.json",
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path="outputs/sealed.json",
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(b"manifest:effect-001"),
                producer_operation_sha256="6" * 64,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-publish"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.publish(token)
            self.assertEqual(
                self._snapshot_head_records()[-1]["effect_rows"],
                ((token.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
            )

        target = self.root / "outputs" / "sealed.json"
        self.assertEqual(target.read_bytes(), artifact_bytes)
        recovery_admitted = authority_runtime.admit(
            operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="test.write",
                action=operation_contract.LifecycleAction.RECOVER,
                claim_mode=operation_contract.ClaimMode.NONE,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.WRITE,
                payload={},
                bounds={},
            ),
            contract,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((token.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )
        with authority_runtime.open_write(admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "not prepared for publish",
            ) as captured:
                session.publish(token)
        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(target.read_bytes(), artifact_bytes)
        self.assertEqual(effect.artifact_ref.verify_bytes(target.read_bytes()), effect.artifact_ref)

    def test_recovery_rejects_the_same_request_under_a_different_operation_spec(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        predecessor_contract = operation_contract.AdmissionContract(
            spec_identity="test-write-v1",
            spec_sha256="6" * 64,
            operation_kind="test.write",
            allowed_actions=(
                operation_contract.LifecycleAction.APPLY,
                operation_contract.LifecycleAction.RECOVER,
            ),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        replacement_contract = operation_contract.AdmissionContract(
            spec_identity="test-write-v2",
            spec_sha256="8" * 64,
            operation_kind="test.write",
            allowed_actions=(operation_contract.LifecycleAction.RECOVER,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"predecessor-bound"}\n'
        effect = authority_runtime.StagedEffect(
            effect_id="effect-002",
            target_relative_path="outputs/predecessor-bound.json",
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path="outputs/predecessor-bound.json",
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(b"manifest:effect-002"),
                producer_operation_sha256=predecessor_contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )

        predecessor = authority_runtime.admit(request, predecessor_contract)
        with authority_runtime.open_write(predecessor) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-publish"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.publish(token)

        recovery_request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write",
            action=operation_contract.LifecycleAction.RECOVER,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        replacement = authority_runtime.admit(recovery_request, replacement_contract)
        with authority_runtime.open_write(replacement) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "different operation spec",
            ):
                session.recover(token)

        predecessor_recovery = authority_runtime.admit(
            recovery_request,
            predecessor_contract,
        )
        with authority_runtime.open_write(predecessor_recovery) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
            self.assertEqual(
                self._durable_state(effect.effect_id),
                authority_runtime.DurableEffectState.FINALIZED.value,
            )

    def _deferred_legacy_v1_foreign_prepare_cannot_backfill_a_missing_predecessor_binding(self):
        artifact_bytes = b'{"effect":"unbound-predecessor"}\n'
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-unbound-predecessor",
            target_path="outputs/unbound-predecessor.json",
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        binding_path = (
            runtime_directory / "recovery-bindings" / f"{effect.effect_id}.json"
        )
        claim_path = (
            runtime_directory
            / "recovery-target-claims"
            / f"{sha256_bytes(effect.target_relative_path.encode('utf-8'))}.json"
        )
        binding_path.unlink()
        claim_path.unlink()

        foreign_contract = operation_contract.AdmissionContract(
            spec_identity="test-durable-write-v2",
            spec_sha256="b" * 64,
            operation_kind="test.durable_write",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        foreign_request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.durable_write",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="foreign-operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        foreign_admitted = authority_runtime.admit(foreign_request, foreign_contract)

        with authority_runtime.open_write(foreign_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryDenied,
                "predecessor binding",
            ) as captured:
                session.prepare(effect)

        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_ADMISSION_MISMATCH",
        )
        self.assertFalse(binding_path.exists())
        self.assertFalse(claim_path.exists())
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def test_recovery_rejects_changed_admitted_bounds_without_mutating_effect(self):
        contract = operation_contract.AdmissionContract(
            spec_identity="test-bounded-write-v1",
            spec_sha256="c" * 64,
            operation_kind="test.bounded_write",
            allowed_actions=(
                operation_contract.LifecycleAction.APPLY,
                operation_contract.LifecycleAction.RECOVER,
            ),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=("max_items",),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"bound-identity"}\n'
        target_path = "outputs/bound-identity.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-bound-identity",
            target_relative_path=target_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(b"manifest:bound-identity"),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )

        def request(action, max_items):
            return operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="test.bounded_write",
                action=action,
                claim_mode=operation_contract.ClaimMode.NONE,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.WRITE,
                payload={},
                bounds={"max_items": max_items},
            )

        admitted = authority_runtime.admit(
            request(operation_contract.LifecycleAction.APPLY, 1),
            contract,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        changed_bounds_recovery = authority_runtime.admit(
            request(operation_contract.LifecycleAction.RECOVER, 2),
            contract,
        )
        with authority_runtime.open_write(changed_bounds_recovery) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryDenied,
                "different admitted bounds",
            ) as captured:
                session.recover(token)

        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_ADMISSION_MISMATCH",
        )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )
        self.assertFalse((self.root / target_path).exists())

    def _deferred_legacy_v1_recovery_fails_closed_when_predecessor_schema_has_no_spec_identity(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write",
            action=operation_contract.LifecycleAction.RECOVER,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-write-v2",
            spec_sha256="8" * 64,
            operation_kind="test.write",
            allowed_actions=(
                operation_contract.LifecycleAction.APPLY,
                operation_contract.LifecycleAction.RECOVER,
            ),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        durable_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        durable_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        durable_directory.chmod(0o700)
        database_path = durable_directory / "authority-runtime.sqlite3"
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "CREATE TABLE durable_effects ("
                "effect_id TEXT PRIMARY KEY, "
                "target_relative_path TEXT NOT NULL UNIQUE, "
                "artifact_ref BLOB NOT NULL, "
                "request_sha256 TEXT NOT NULL, "
                "policy_identity_sha256 TEXT NOT NULL, "
                "state TEXT NOT NULL"
                ")"
            )
            connection.execute(
                "INSERT INTO durable_effects "
                "(effect_id, target_relative_path, artifact_ref, request_sha256, "
                "policy_identity_sha256, state) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "effect-legacy",
                    "outputs/legacy.json",
                    b"legacy-reference-without-predecessor-identity",
                    request.sha256,
                    "0" * 64,
                    authority_runtime.DurableEffectState.PREPARED.value,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        database_path.chmod(0o600)

        admitted = authority_runtime.admit(request, contract)
        with self.assertRaisesRegex(
            authority_runtime.DurableRecoveryRequired,
            "predecessor identity",
        ):
            with authority_runtime.open_write(admitted) as session:
                self.fail(f"legacy durable schema unexpectedly opened: {session!r}")

        connection = sqlite3.connect(str(database_path))
        try:
            state = connection.execute(
                "SELECT state FROM durable_effects WHERE effect_id = ?",
                ("effect-legacy",),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(state, authority_runtime.DurableEffectState.PREPARED.value)

    def _deferred_legacy_v1_recovery_fails_closed_when_durable_schema_has_no_constraints(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write",
            action=operation_contract.LifecycleAction.RECOVER,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-write-v2",
            spec_sha256="8" * 64,
            operation_kind="test.write",
            allowed_actions=(operation_contract.LifecycleAction.RECOVER,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        durable_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        durable_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        durable_directory.chmod(0o700)
        database_path = durable_directory / "authority-runtime.sqlite3"
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "CREATE TABLE durable_effects ("
                "effect_id TEXT, "
                "target_relative_path TEXT, "
                "artifact_ref BLOB, "
                "request_sha256 TEXT, "
                "spec_identity TEXT, "
                "spec_sha256 TEXT, "
                "policy_identity_sha256 TEXT, "
                "state TEXT"
                ")"
            )
            connection.execute(
                "INSERT INTO durable_effects "
                "(effect_id, target_relative_path, artifact_ref, request_sha256, "
                "spec_identity, spec_sha256, policy_identity_sha256, state) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "effect-constraintless",
                    "outputs/constraintless.json",
                    b"constraintless-reference",
                    request.sha256,
                    contract.spec_identity,
                    contract.spec_sha256,
                    "0" * 64,
                    authority_runtime.DurableEffectState.PREPARED.value,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        database_path.chmod(0o600)

        admitted = authority_runtime.admit(request, contract)
        with self.assertRaisesRegex(
            authority_runtime.DurableRecoveryRequired,
            "schema identity",
        ):
            with authority_runtime.open_write(admitted):
                self.fail("constraintless durable schema must not open")

        connection = sqlite3.connect(str(database_path))
        try:
            state = connection.execute(
                "SELECT state FROM durable_effects WHERE effect_id = ?",
                ("effect-constraintless",),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(state, authority_runtime.DurableEffectState.PREPARED.value)

    def test_staged_effect_rejects_a_target_that_differs_from_its_sealed_path(self):
        artifact_bytes = b'{"effect":"path-bound"}\n'
        reference = artifact_contract.SealedArtifactRef(
            schema=artifact_contract.SchemaIdentity(
                kind="D1A_EFFECT",
                version=1,
                schema_sha256="7" * 64,
            ),
            canonical_path="outputs/sealed-path.json",
            artifact_sha256=sha256_bytes(artifact_bytes),
            manifest_sha256=sha256_bytes(b"manifest:effect-path-bound"),
            producer_operation_sha256="6" * 64,
            byte_length=len(artifact_bytes),
            media_type="application/json",
        )

        with self.assertRaisesRegex(ValueError, "sealed artifact path"):
            authority_runtime.StagedEffect(
                effect_id="effect-path-bound",
                target_relative_path="outputs/different-path.json",
                artifact_ref=reference,
                artifact_bytes=artifact_bytes,
            )

    def _deferred_legacy_v1_recovery_blocks_a_persisted_effect_when_its_target_differs_from_the_sealed_path(
        self,
    ):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-write-v1",
            spec_sha256="6" * 64,
            operation_kind="test.write",
            allowed_actions=(
                operation_contract.LifecycleAction.APPLY,
                operation_contract.LifecycleAction.RECOVER,
            ),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"persisted-path-mismatch"}\n'
        sealed_path = "outputs/sealed-row.json"
        wrong_path = "outputs/wrong-row.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-row-path",
            target_relative_path=sealed_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=sealed_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(b"manifest:effect-row-path"),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )
        admitted = authority_runtime.admit(request, contract)
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
        effect_id = token.effect_id

        database_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "authority-runtime.sqlite3"
        )
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "UPDATE durable_effects SET target_relative_path = ? WHERE effect_id = ?",
                (wrong_path, effect_id),
            )
            connection.commit()
        finally:
            connection.close()
        wrong_target = self.root / wrong_path
        wrong_target.parent.mkdir(mode=0o700, exist_ok=True)
        wrong_target.write_bytes(artifact_bytes)
        wrong_target.chmod(0o600)

        recovery_admitted = authority_runtime.admit(
            operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="test.write",
                action=operation_contract.LifecycleAction.RECOVER,
                claim_mode=operation_contract.ClaimMode.NONE,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.WRITE,
                payload={},
                bounds={},
            ),
            contract,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "identity does not match",
            ) as captured:
                session.recover(token)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")

        connection = sqlite3.connect(str(database_path))
        try:
            state = connection.execute(
                "SELECT state FROM durable_effects WHERE effect_id = ?",
                (effect_id,),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(
            state,
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )
        self.assertFalse((self.root / sealed_path).exists())
        self.assertEqual(wrong_target.read_bytes(), artifact_bytes)

    def test_write_session_blocks_post_admission_workstream_pause_before_publish(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.workstream_write",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
            scope={"workstream_id": "example-service"},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-workstream-write-v1",
            spec_sha256="9" * 64,
            operation_kind="test.workstream_write",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=("workstream_id",),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"workstream-pause"}\n'
        target_path = "outputs/workstream-pause.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-workstream-pause",
            target_relative_path=target_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(b"manifest:effect-workstream-pause"),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )
        admitted = authority_runtime.admit(request, contract)
        original_registry = self.registry_path.read_bytes()
        paused_registry = original_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            replacement = self.registry_directory / "placement-map.paused"
            replacement.write_bytes(paused_registry)
            replacement.chmod(0o600)
            os.replace(replacement, self.registry_path)
            try:
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "current policy",
                ) as captured:
                    session.publish(token)
                self.assertEqual(captured.exception.directive.token, token)
                self.assertEqual(
                    captured.exception.directive.disposition,
                    "blocked_recovery",
                )
                self.assertEqual(
                    captured.exception.directive.reason_code,
                    "RECOVERY_ADMISSION_DRIFT",
                )
                self.assertIsNone(captured.exception.directive.allowed_recovery_action)
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "not active",
                ) as repeated:
                    session.publish(token)
                self.assertEqual(repeated.exception.directive.token, token)
            finally:
                replacement.write_bytes(original_registry)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)

        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )
        self.assertFalse((self.root / target_path).exists())

    def test_write_context_propagates_post_admission_workstream_pause_once(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.workstream_write",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
            scope={"workstream_id": "example-service"},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-workstream-write-v1",
            spec_sha256="9" * 64,
            operation_kind="test.workstream_write",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=("workstream_id",),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"workstream-pause-propagation"}\n'
        target_path = "outputs/workstream-pause-propagation.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-workstream-pause-propagation",
            target_relative_path=target_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(
                    b"manifest:effect-workstream-pause-propagation"
                ),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )
        admitted = authority_runtime.admit(request, contract)
        original_registry = self.registry_path.read_bytes()
        paused_registry = original_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        replacement = self.registry_directory / "placement-map.propagation-paused"

        try:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "current policy",
            ) as captured:
                with authority_runtime.open_write(admitted) as session:
                    token = session.prepare(effect)
                    replacement.write_bytes(paused_registry)
                    replacement.chmod(0o600)
                    os.replace(replacement, self.registry_path)
                    session.publish(token)
        finally:
            replacement.write_bytes(original_registry)
            replacement.chmod(0o600)
            os.replace(replacement, self.registry_path)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(
            captured.exception.directive.disposition,
            "blocked_recovery",
        )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )
        self.assertFalse((self.root / target_path).exists())

    def test_recovery_after_restart_blocks_a_now_paused_workstream(self):
        contract = operation_contract.AdmissionContract(
            spec_identity="test-workstream-recovery-v1",
            spec_sha256="c" * 64,
            operation_kind="test.workstream_recovery",
            allowed_actions=(
                operation_contract.LifecycleAction.APPLY,
                operation_contract.LifecycleAction.RECOVER,
            ),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=("workstream_id",),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"paused-workstream-recovery"}\n'
        target_path = "outputs/paused-workstream-recovery.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-paused-workstream-recovery",
            target_relative_path=target_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(
                    b"manifest:effect-paused-workstream-recovery"
                ),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )

        def request_for(action):
            return operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="test.workstream_recovery",
                action=action,
                claim_mode=operation_contract.ClaimMode.NONE,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.WRITE,
                payload={},
                bounds={},
                scope={"workstream_id": "example-service"},
            )

        apply_admitted = authority_runtime.admit(
            request_for(operation_contract.LifecycleAction.APPLY),
            contract,
        )
        with authority_runtime.open_write(apply_admitted) as session:
            token = session.prepare(effect)

        paused_registry = self.registry_path.read_bytes().replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        replacement = self.registry_directory / "placement-map.restart-paused"
        replacement.write_bytes(paused_registry)
        replacement.chmod(0o600)
        os.replace(replacement, self.registry_path)
        policy_authority.observe_policy_drift(
            self.root,
            observed_by="d1a-policy-monitor",
        )
        preview = policy_authority.preview_policy_reconcile(
            self.root,
            requested_by="d1a-reconcile-requester",
            external_actor="workspace-registry-workflow",
            external_workflow="workstream-lifecycle-update",
        )
        proposal = policy_authority.publish_policy_change_proposal(
            self.root,
            preview=preview,
        )
        approval = policy_authority.approve_policy_change(
            self.root,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="d1a-reconcile-approver",
            required_sealed_mode="RECONCILE",
        )
        policy_authority.apply_policy_change(
            self.root,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="d1a-reconcile-executor",
            process_instance_id="d1a-reconcile-process",
            required_sealed_mode="RECONCILE",
        )
        recovery_admitted = authority_runtime.admit(
            request_for(operation_contract.LifecycleAction.RECOVER),
            contract,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "workstream is not current and active",
            ) as captured:
                session.recover(token)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_ADMISSION_DRIFT",
        )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )

    def test_recovery_only_foreign_workstream_cannot_block_origin_effect(self):
        contract = operation_contract.AdmissionContract(
            spec_identity="test-workstream-recovery-scope-v1",
            spec_sha256="d" * 64,
            operation_kind="test.workstream_recovery_scope",
            allowed_actions=(
                operation_contract.LifecycleAction.APPLY,
                operation_contract.LifecycleAction.RECOVER,
            ),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=("workstream_id",),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"workstream-recovery-scope"}\n'
        effect = authority_runtime.StagedEffect(
            effect_id="effect-workstream-recovery-scope",
            target_relative_path="outputs/workstream-recovery-scope.json",
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path="outputs/workstream-recovery-scope.json",
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(
                    b"manifest:effect-workstream-recovery-scope"
                ),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )

        def admit_for(
            action: operation_contract.LifecycleAction,
            workstream_id: str,
        ):
            return authority_runtime.admit(
                operation_contract.OperationRequest(
                    schema_version=1,
                    operation_kind="test.workstream_recovery_scope",
                    action=action,
                    claim_mode=operation_contract.ClaimMode.NONE,
                    root=str(self.root),
                    actor="operator",
                    requested_authority=operation_contract.AuthorityMode.WRITE,
                    payload={},
                    bounds={},
                    scope={"workstream_id": workstream_id},
                ),
                contract,
            )

        with authority_runtime.open_write(
            admit_for(operation_contract.LifecycleAction.APPLY, "example-service")
        ) as session:
            token = session.prepare(effect)

        with self.assertRaisesRegex(
            authority_runtime.AuthorityRuntimeError,
            "workstream is not current and active",
        ):
            admit_for(
                operation_contract.LifecycleAction.RECOVER,
                "missing-workstream",
            )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def test_unrelated_write_cleanup_error_remains_observable(self):
        cleanup_error = ledger_runtime.LedgerRuntimeError("unrelated cleanup failure")
        primary_error = authority_runtime.AuthorityRuntimeError("primary denial")

        with self.assertRaisesRegex(
            authority_runtime.AuthorityRuntimeError,
            "cleanup failed",
        ) as without_primary:
            authority_session._raise_unexpected_write_cleanup(
                cleanup_error,
                body_error=None,
            )
        self.assertIs(without_primary.exception.__cause__, cleanup_error)

        with self.assertRaisesRegex(
            authority_runtime.AuthorityRuntimeError,
            "primary denial",
        ) as with_primary:
            authority_session._raise_unexpected_write_cleanup(
                cleanup_error,
                body_error=primary_error,
            )
        self.assertIs(with_primary.exception, primary_error)
        self.assertIsInstance(
            primary_error.__cause__,
            authority_runtime.AuthorityRuntimeError,
        )
        self.assertIs(primary_error.__cause__.__cause__, cleanup_error)

    def test_unrelated_writer_cleanup_is_chained_to_primary_drift_denial(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.workstream_write",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
            scope={"workstream_id": "example-service"},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-workstream-write-v1",
            spec_sha256="9" * 64,
            operation_kind="test.workstream_write",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=("workstream_id",),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"unrelated-cleanup"}\n'
        target_path = "outputs/unrelated-cleanup.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-unrelated-cleanup",
            target_relative_path=target_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(
                    b"manifest:effect-unrelated-cleanup"
                ),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )
        admitted = authority_runtime.admit(request, contract)
        real_open_writer_session = ledger_runtime.open_writer_session
        unrelated_cleanup = ledger_runtime.LedgerRuntimeError(
            "unrelated cleanup failure"
        )

        @contextmanager
        def writer_with_unrelated_cleanup(*args, **kwargs):
            with real_open_writer_session(*args, **kwargs) as writer:
                original_current_policy = writer.current_policy
                current_policy_calls = 0

                def current_policy():
                    nonlocal current_policy_calls
                    current_policy_calls += 1
                    if current_policy_calls == 3:
                        raise ledger_runtime.LedgerRuntimeError(
                            "simulated policy lookup failure"
                        )
                    return original_current_policy()

                writer.current_policy = current_policy
                yield writer
            raise unrelated_cleanup

        with mock.patch.object(
            ledger_runtime,
            "open_writer_session",
            writer_with_unrelated_cleanup,
        ):
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "current policy",
            ) as captured:
                with authority_runtime.open_write(admitted) as session:
                    token = session.prepare(effect)
                    session.publish(token)

        self.assertIsInstance(
            captured.exception.__cause__,
            authority_runtime.AuthorityRuntimeError,
        )
        self.assertEqual(
            str(captured.exception.__cause__),
            "write capability cleanup failed",
        )
        self.assertIs(captured.exception.__cause__.__cause__, unrelated_cleanup)
        self.assertFalse((self.root / target_path).exists())

    def test_coordinator_cleanup_failure_is_chained_to_primary_drift_denial(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.workstream_write",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
            scope={"workstream_id": "example-service"},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-workstream-write-v1",
            spec_sha256="9" * 64,
            operation_kind="test.workstream_write",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=("workstream_id",),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"coordinator-cleanup"}\n'
        target_path = "outputs/coordinator-cleanup.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-coordinator-cleanup",
            target_relative_path=target_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(
                    b"manifest:effect-coordinator-cleanup"
                ),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )
        admitted = authority_runtime.admit(request, contract)
        original_registry = self.registry_path.read_bytes()
        paused_registry = original_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        replacement = self.registry_directory / "placement-map.coordinator-paused"
        original_close = authority_session.durable.DurableCoordinator.close

        def fail_close(coordinator):
            original_close(coordinator)
            raise RuntimeError("coordinator cleanup failure")

        try:
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "close",
                fail_close,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "current policy",
                ) as captured:
                    with authority_runtime.open_write(admitted) as session:
                        token = session.prepare(effect)
                        replacement.write_bytes(paused_registry)
                        replacement.chmod(0o600)
                        os.replace(replacement, self.registry_path)
                        session.publish(token)
        finally:
            replacement.write_bytes(original_registry)
            replacement.chmod(0o600)
            os.replace(replacement, self.registry_path)

        self.assertIsInstance(
            captured.exception.__cause__,
            authority_runtime.AuthorityRuntimeError,
        )
        self.assertEqual(
            str(captured.exception.__cause__),
            "write session cleanup failed",
        )
        self.assertIsInstance(captured.exception.__cause__.__cause__, RuntimeError)
        self.assertFalse((self.root / target_path).exists())

    def test_context_finalizer_cleanup_failure_is_chained_to_body_error(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write_cleanup",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-write-cleanup-v1",
            spec_sha256="a" * 64,
            operation_kind="test.write_cleanup",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        admitted = authority_runtime.admit(request, contract)
        original_close = authority_session.durable.DurableCoordinator.close

        def fail_close(coordinator):
            original_close(coordinator)
            raise RuntimeError("context finalizer cleanup failure")

        with mock.patch.object(
            authority_session.durable.DurableCoordinator,
            "close",
            fail_close,
        ):
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "body failure",
            ) as captured:
                with authority_runtime.open_write(admitted):
                    raise authority_runtime.AuthorityRuntimeError("body failure")

        self.assertIsInstance(
            captured.exception.__cause__,
            authority_runtime.AuthorityRuntimeError,
        )
        self.assertEqual(
            str(captured.exception.__cause__),
            "write capability cleanup failed",
        )
        self.assertIsInstance(captured.exception.__cause__.__cause__, RuntimeError)

    def test_multiple_cleanup_failures_are_grouped_under_body_error(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write_cleanup_group",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-write-cleanup-group-v1",
            spec_sha256="b" * 64,
            operation_kind="test.write_cleanup_group",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        admitted = authority_runtime.admit(request, contract)
        original_close = authority_session.durable.DurableCoordinator.close
        real_open_writer_session = ledger_runtime.open_writer_session
        session_cleanup = RuntimeError("session cleanup failure")
        writer_cleanup = ledger_runtime.LedgerRuntimeError("writer cleanup failure")

        def fail_close(coordinator):
            original_close(coordinator)
            raise session_cleanup

        @contextmanager
        def writer_with_cleanup_failure(*args, **kwargs):
            with real_open_writer_session(*args, **kwargs) as writer:
                yield writer
            raise writer_cleanup

        with mock.patch.object(
            authority_session.durable.DurableCoordinator,
            "close",
            fail_close,
        ), mock.patch.object(
            ledger_runtime,
            "open_writer_session",
            writer_with_cleanup_failure,
        ):
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "body failure",
            ) as captured:
                with authority_runtime.open_write(admitted):
                    raise authority_runtime.AuthorityRuntimeError("body failure")

        self.assertIsInstance(
            captured.exception.__cause__,
            authority_runtime.AuthorityRuntimeError,
        )
        cleanup_group = captured.exception.__cause__.__cause__
        self.assertIsInstance(cleanup_group, BaseExceptionGroup)
        self.assertEqual(
            cleanup_group.exceptions,
            (session_cleanup, writer_cleanup),
        )

    def test_write_session_exposes_only_durable_operations(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write_surface",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-write-surface-v1",
            spec_sha256="c" * 64,
            operation_kind="test.write_surface",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        admitted = authority_runtime.admit(request, contract)

        with authority_runtime.open_write(admitted) as session:
            public_names = {
                name for name in dir(session) if not name.startswith("_")
            }
            self.assertEqual(
                public_names,
                {
                    "prepare",
                    "publish",
                    "finalize",
                    "recover",
                },
            )
            self.assertFalse(hasattr(session, "__dict__"))
            for leaked_name in (
                "root",
                "connection",
                "compiled_policy",
                "policy",
                "coordinator",
                "durable",
                "close",
            ):
                self.assertFalse(hasattr(session, leaked_name))

    def test_write_session_methods_do_not_expose_fault_injection_parameters(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-private-fault-seam",
            target_path="outputs/private-fault-seam.json",
            artifact_bytes=b'{"effect":"private-fault-seam"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            self.assertEqual(tuple(inspect.signature(session.prepare).parameters), ("effect",))
            self.assertEqual(tuple(inspect.signature(session.publish).parameters), ("token",))
            self.assertEqual(tuple(inspect.signature(session.finalize).parameters), ("token",))
            self.assertEqual(tuple(inspect.signature(session.recover).parameters), ("token",))

    def test_publish_blocks_recovery_when_possible_effect_is_unverified(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.write_possible_effect",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.NONE,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={},
            bounds={},
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-write-possible-effect-v1",
            spec_sha256="d" * 64,
            operation_kind="test.write_possible_effect",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        artifact_bytes = b'{"effect":"possible"}\n'
        target_path = "outputs/possible-effect.json"
        effect = authority_runtime.StagedEffect(
            effect_id="effect-possible-effect",
            target_relative_path=target_path,
            artifact_ref=artifact_contract.SealedArtifactRef(
                schema=artifact_contract.SchemaIdentity(
                    kind="D1A_EFFECT",
                    version=1,
                    schema_sha256="7" * 64,
                ),
                canonical_path=target_path,
                artifact_sha256=sha256_bytes(artifact_bytes),
                manifest_sha256=sha256_bytes(
                    b"manifest:effect-possible-effect"
                ),
                producer_operation_sha256=contract.spec_sha256,
                byte_length=len(artifact_bytes),
                media_type="application/json",
            ),
            artifact_bytes=artifact_bytes,
        )
        admitted = authority_runtime.admit(request, contract)
        target = self.root / target_path
        original_publish = authority_session.durable._publish_exact_bytes

        def fail_target_publish(path, raw, *, label):
            if path == target:
                raise authority_runtime.AuthorityRuntimeError(
                    "possible publish outcome is unavailable"
                )
            return original_publish(path, raw, label=label)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable,
                "_publish_exact_bytes",
                side_effect=fail_target_publish,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "publish outcome",
                ) as captured:
                    session.publish(token)
            self.assertIsNotNone(captured.exception.directive)
            self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")
            self.assertEqual(
                self._durable_state(token.effect_id),
                authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
            )

        self.assertFalse((self.root / target_path).exists())

    def test_publish_blocks_when_post_publish_readback_is_unavailable(self):
        artifact_bytes = b'{"effect":"uncertain-readback"}\n'
        target_path = "outputs/uncertain-readback.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-uncertain-readback",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        target = self.root / target_path
        original_publish = authority_session.durable._publish_exact_bytes
        original_read = authority_session.durable._try_read_verified_bytes
        target_published = False

        def publish_then_lose_readback(path, raw, *, label):
            nonlocal target_published
            if path == target:
                original_publish(path, raw, label=label)
                target_published = True
                raise authority_runtime.AuthorityRuntimeError(
                    "post-publish readback is unavailable"
                )
            return original_publish(path, raw, label=label)

        def lose_only_post_publish_target_readback(path):
            if target_published and path == target:
                raise authority_runtime.AuthorityRuntimeError(
                    "post-publish target readback is unavailable"
                )
            return original_read(path)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable,
                "_publish_exact_bytes",
                publish_then_lose_readback,
            ), mock.patch.object(
                authority_session.durable,
                "_try_read_verified_bytes",
                lose_only_post_publish_target_readback,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "target readback",
                ):
                    session.publish(token)
            self.assertEqual(
                self._durable_state(token.effect_id),
                authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
            )

        self.assertEqual(target.read_bytes(), artifact_bytes)
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "blocked for recovery",
            ) as captured:
                session.recover(token)
        self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")

    def test_publish_post_write_proof_error_closes_current_write_session(self):
        """A post-write ambiguity must be resolved only by a fresh recovery session."""

        artifact_bytes = b'{"effect":"post-write-proof-error"}\n'
        target_path = "outputs/post-write-proof-error.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-post-write-proof-error",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        target = self.root / target_path
        original_publish = authority_session.durable._publish_exact_bytes

        def publish_then_report_ambiguous(path, raw, *, label):
            if path == target:
                original_publish(path, raw, label=label)
                raise authority_runtime.AuthorityRuntimeError(
                    "post-write durability proof is unavailable"
                )
            return original_publish(path, raw, label=label)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable,
                "_publish_exact_bytes",
                side_effect=publish_then_report_ambiguous,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "publish durability proof is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertIsNotNone(captured.exception.directive)
            self.assertEqual(captured.exception.directive.token, token)
            self.assertEqual(captured.exception.directive.disposition, "recoverable")
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as repeated:
                session.publish(token)
            self.assertEqual(repeated.exception.directive, captured.exception.directive)

        self.assertEqual(target.read_bytes(), artifact_bytes)
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((token.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_publish_snapshot_binding_read_error_preserves_exact_recovery(self):
        """A readable valid PREPARED head must not become a root-wide stop."""

        artifact_bytes = b'{"effect":"binding-read-error"}\n'
        target_path = "outputs/binding-read-error.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-binding-read-error",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "binding",
                side_effect=authority_runtime.AuthorityRuntimeError(
                    "snapshot binding read unavailable"
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable snapshot state is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertIsNotNone(captured.exception.directive)
            self.assertEqual(captured.exception.directive.token, token)
            self.assertEqual(captured.exception.directive.disposition, "recoverable")
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as repeated:
                session.publish(token)
            self.assertEqual(repeated.exception.directive, captured.exception.directive)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (
                runtime_directory
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def _assert_publish_snapshot_availability_error_preserves_exact_recovery(
        self,
        *,
        effect_id: str,
        snapshot_method: str,
        failure: BaseException,
    ) -> None:
        artifact_bytes = f'{{"effect":"{effect_id}"}}\n'.encode("utf-8")
        target_path = f"outputs/{effect_id}.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id=effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                snapshot_method,
                side_effect=failure,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable snapshot state is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertIsNotNone(captured.exception.directive)
            self.assertEqual(captured.exception.directive.token, token)
            self.assertEqual(captured.exception.directive.disposition, "recoverable")
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as repeated:
                session.publish(token)
            self.assertEqual(repeated.exception.directive, captured.exception.directive)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (
                runtime_directory
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_publish_snapshot_blocker_and_target_claim_read_errors_preserve_recovery(
        self,
    ):
        for snapshot_method, failure in (
            (
                "recovery_blocker",
                authority_runtime.AuthorityRuntimeError(
                    "snapshot blocker read unavailable"
                ),
            ),
            ("target_claim", sqlite3.OperationalError("target claim read unavailable")),
        ):
            with self.subTest(snapshot_method=snapshot_method):
                with self._independent_write_fixture() as fixture:
                    fixture._assert_publish_snapshot_availability_error_preserves_exact_recovery(
                        effect_id=(
                            f"effect-{snapshot_method.replace('_', '-')}-read-error"
                        ),
                        snapshot_method=snapshot_method,
                        failure=failure,
                    )

    def test_publish_snapshot_identity_read_error_preserves_exact_recovery(self):
        """A token-bearing public operation may not leak a private store error."""

        artifact_bytes = b'{"effect":"snapshot-identity-read-error"}\n'
        target_path = "outputs/snapshot-identity-read-error.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-snapshot-identity-read-error",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "verify_canonical_database_identity",
                side_effect=authority_runtime.AuthorityRuntimeError(
                    "snapshot identity read unavailable"
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable snapshot state is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertIsNotNone(captured.exception.directive)
            self.assertEqual(captured.exception.directive.token, token)
            self.assertEqual(captured.exception.directive.disposition, "recoverable")
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as repeated:
                session.publish(token)
            self.assertEqual(repeated.exception.directive, captured.exception.directive)

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_finalize_and_recover_identity_read_errors_preserve_exact_recovery(self):
        for operation in ("finalize", "recover"):
            with self.subTest(operation=operation):
                with self._independent_write_fixture() as fixture:
                    fixture._assert_token_bound_identity_read_error(
                        operation=operation
                    )

    def _assert_token_bound_identity_read_error(self, *, operation: str) -> None:
        if operation not in {"finalize", "recover"}:
            self.fail(f"unsupported token-bound identity operation: {operation!r}")
        artifact_bytes = f'{{"effect":"identity-{operation}-read-error"}}\n'.encode(
            "utf-8"
        )
        target_path = f"outputs/identity-{operation}-read-error.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id=f"effect-identity-{operation}-read-error",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        if operation == "finalize":
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                session.publish(token)
                with mock.patch.object(
                    authority_snapshot._DurableSnapshotStore,
                    "verify_canonical_database_identity",
                    side_effect=authority_runtime.AuthorityRuntimeError(
                        "snapshot identity read unavailable"
                    ),
                ):
                    with self.assertRaisesRegex(
                        authority_runtime.DurableRecoveryRequired,
                        "durable snapshot state is unavailable",
                    ) as captured:
                        session.finalize(token)
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "write session is not active; durable recovery is required",
                ) as repeated:
                    session.finalize(token)
                self.assertEqual(repeated.exception.directive, captured.exception.directive)
        else:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
            recovery_admitted, _ = self._admit_durable_write_effect(
                effect_id=effect.effect_id,
                target_path=target_path,
                artifact_bytes=artifact_bytes,
                action=operation_contract.LifecycleAction.RECOVER,
            )
            with authority_runtime.open_write(recovery_admitted) as session:
                with mock.patch.object(
                    authority_snapshot._DurableSnapshotStore,
                    "verify_canonical_database_identity",
                    side_effect=authority_runtime.AuthorityRuntimeError(
                        "snapshot identity read unavailable"
                    ),
                ):
                    with self.assertRaisesRegex(
                        authority_runtime.DurableRecoveryRequired,
                        "durable snapshot state is unavailable",
                    ) as captured:
                        session.recover(token)
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "write session is not active; durable recovery is required",
                ) as repeated:
                    session.recover(token)
                self.assertEqual(repeated.exception.directive, captured.exception.directive)

        self.assertIsNotNone(captured.exception.directive)
        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_publish_blocks_when_target_metadata_lookup_is_permission_denied(self):
        artifact_bytes = b'{"effect":"target-stat-permission"}\n'
        target_path = "outputs/target-stat-permission.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-target-stat-permission",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        target = self.root / target_path
        original_stat = authority_session.durable.os.stat

        def deny_target_stat(path, *args, **kwargs):
            if (
                path == target.name
                and kwargs.get("dir_fd") is not None
            ):
                raise PermissionError("target metadata access denied")
            return original_stat(path, *args, **kwargs)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable.os,
                "stat",
                deny_target_stat,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "target readback",
                ) as captured:
                    session.publish(token)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )

    def test_publish_transition_error_after_database_update_closes_current_write_session(
        self,
    ):
        artifact_bytes = b'{"effect":"publish-transition-after-update"}\n'
        target_path = "outputs/publish-transition-after-update.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-publish-transition-after-update",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        original_transition = authority_snapshot._DurableSnapshotStore.transition_effect

        def transition_then_fail(store, row, *, expected_state, target_state):
            updated = original_transition(
                store,
                row,
                expected_state=expected_state,
                target_state=target_state,
            )
            if (
                expected_state == authority_runtime.DurableEffectState.PREPARED.value
                and target_state
                == authority_runtime.DurableEffectState.PUBLISHED.value
            ):
                raise sqlite3.OperationalError(
                    "simulated transition error after database update"
                )
            return updated

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "transition_effect",
                new=transition_then_fail,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable state transition is unavailable",
                ) as captured:
                    session.publish(token)
            self.assertEqual(captured.exception.directive.token, token)
            self.assertEqual(captured.exception.directive.disposition, "recoverable")
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.finalize(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        target = self.root / target_path
        self.assertEqual(target.read_bytes(), artifact_bytes)
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_publish_transition_zero_row_closes_current_write_session(self):
        artifact_bytes = b'{"effect":"publish-transition-zero-row"}\n'
        target_path = "outputs/publish-transition-zero-row.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-publish-transition-zero-row",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        original_transition = authority_snapshot._DurableSnapshotStore.transition_effect

        def transition_returns_zero(store, row, *, expected_state, target_state):
            if (
                expected_state == authority_runtime.DurableEffectState.PREPARED.value
                and target_state
                == authority_runtime.DurableEffectState.PUBLISHED.value
            ):
                return 0
            return original_transition(
                store,
                row,
                expected_state=expected_state,
                target_state=target_state,
            )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "transition_effect",
                new=transition_returns_zero,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable effect state changed unexpectedly",
                ) as captured:
                    session.publish(token)
            self.assertEqual(captured.exception.directive.token, token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.finalize(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_finalization_transition_error_after_database_update_closes_current_write_session(
        self,
    ):
        artifact_bytes = b'{"effect":"final-transition-after-update"}\n'
        target_path = "outputs/final-transition-after-update.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-final-transition-after-update",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        original_transition = authority_snapshot._DurableSnapshotStore.transition_effect

        def transition_then_fail(store, row, *, expected_state, target_state):
            updated = original_transition(
                store,
                row,
                expected_state=expected_state,
                target_state=target_state,
            )
            if (
                expected_state == authority_runtime.DurableEffectState.PUBLISHED.value
                and target_state
                == authority_runtime.DurableEffectState.FINALIZED.value
            ):
                raise sqlite3.OperationalError(
                    "simulated final transition error after database update"
                )
            return updated

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "transition_effect",
                new=transition_then_fail,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable state transition is unavailable",
                ) as captured:
                    session.finalize(token)
            self.assertEqual(captured.exception.directive.token, token)
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as closed:
                session.finalize(token)
            self.assertEqual(closed.exception.directive, captured.exception.directive)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),),
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_publish_transition_failure_is_typed_and_recovers_exact_effect(self):
        artifact_bytes = b'{"effect":"publish-transition"}\n'
        target_path = "outputs/publish-transition.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-publish-transition",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        original_transition = authority_session.durable.DurableCoordinator._transition

        def fail_publish_transition(coordinator, row, expected, target):
            if (
                expected is authority_runtime.DurableEffectState.PREPARED
                and target is authority_runtime.DurableEffectState.PUBLISHED
            ):
                raise sqlite3.OperationalError("publish transition unavailable")
            return original_transition(coordinator, row, expected, target)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_transition",
                fail_publish_transition,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "publish state transition",
                ) as captured:
                    session.publish(token)
            self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )

        target = self.root / target_path
        self.assertEqual(target.read_bytes(), artifact_bytes)
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_finalization_transition_failure_is_typed_and_recovers_exact_effect(self):
        artifact_bytes = b'{"effect":"final-transition"}\n'
        target_path = "outputs/final-transition.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-final-transition",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        original_transition = authority_session.durable.DurableCoordinator._transition

        def fail_finalization_transition(coordinator, row, expected, target):
            if (
                expected is authority_runtime.DurableEffectState.PUBLISHED
                and target is authority_runtime.DurableEffectState.FINALIZED
            ):
                raise sqlite3.OperationalError("finalization transition unavailable")
            return original_transition(coordinator, row, expected, target)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_transition",
                fail_finalization_transition,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "finalization state transition",
                ) as captured:
                    session.finalize(token)
            self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PUBLISHED.value),),
        )

        target = self.root / target_path
        self.assertEqual(target.read_bytes(), artifact_bytes)
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def _deferred_legacy_v1_final_cas_blocks_a_row_tampered_after_admission_revalidation(self):
        artifact_bytes = b'{"effect":"final-cas-binding"}\n'
        target_path = "outputs/final-cas-binding.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-final-cas-binding",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        original_transition = authority_session.durable.DurableCoordinator._transition

        def tamper_before_final_cas(coordinator, row, expected, target):
            if (
                expected is authority_runtime.DurableEffectState.PUBLISHED
                and target is authority_runtime.DurableEffectState.FINALIZED
            ):
                database_path = (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                    / "authority-runtime.sqlite3"
                )
                connection = sqlite3.connect(str(database_path))
                try:
                    connection.execute(
                        "UPDATE durable_effects SET policy_identity_sha256 = ? "
                        "WHERE effect_id = ?",
                        ("0" * 64, row["effect_id"]),
                    )
                    connection.commit()
                finally:
                    connection.close()
            return original_transition(coordinator, row, expected, target)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_transition",
                tamper_before_final_cas,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "identity changed",
                ) as captured:
                    session.finalize(token)

        self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_EVIDENCE_UNSAFE",
        )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )

    def test_prepared_staging_resumes_to_an_exact_finalized_effect(self):
        artifact_bytes = b'{"effect":"prepare-crash"}\n'
        target_path = "outputs/prepare-crash.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepare-crash",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            self.assertEqual(
                self._durable_state(token.effect_id),
                authority_runtime.DurableEffectState.PREPARED.value,
            )

        target = self.root / target_path
        self.assertFalse(target.exists())
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
            self.assertEqual(
                self._durable_state(token.effect_id),
                authority_runtime.DurableEffectState.FINALIZED.value,
            )
        self.assertEqual(target.read_bytes(), artifact_bytes)

    def test_prepare_crash_after_prepared_row_retries_the_exact_effect(self):
        artifact_bytes = b'{"effect":"prepared-row-crash"}\n'
        target_path = "outputs/prepared-row-crash.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-row-crash",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-prepared-row"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )
        self.assertFalse((self.root / target_path).exists())
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            self.assertEqual(session.finalize(token), effect.artifact_ref)

        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.FINALIZED.value,
        )
        self.assertEqual((self.root / target_path).read_bytes(), artifact_bytes)

    def test_recovery_resumes_a_prepared_row_after_crash_before_staging(self):
        artifact_bytes = b'{"effect":"prepared-row-recovery"}\n'
        target_path = "outputs/prepared-row-recovery.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-row-recovery",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-prepared-row"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        binding = self._snapshot_binding_for_effect(effect.effect_id)
        token = binding.token
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((
                effect.effect_id,
                authority_runtime.DurableEffectState.PREPARED.value,
            ),),
        )
        stage = self._snapshot_stage_path(effect.effect_id)
        self.assertFalse(stage.exists())

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((
                effect.effect_id,
                authority_runtime.DurableEffectState.FINALIZED.value,
            ),),
        )
        self.assertEqual((self.root / target_path).read_bytes(), artifact_bytes)

    def test_prepare_target_claim_collision_never_issues_an_unbound_token(self):
        admitted, origin = self._admit_durable_write_effect(
            effect_id="effect-target-claim-origin",
            target_path="outputs/target-claim-collision.json",
            artifact_bytes=b'{"effect":"target-claim-origin"}\n',
        )
        _, colliding = self._admit_durable_write_effect(
            effect_id="effect-target-claim-collision",
            target_path=origin.target_relative_path,
            artifact_bytes=b'{"effect":"target-claim-collision"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            origin_token = session.prepare(origin)

        with authority_runtime.open_write(admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryDenied,
                "outstanding effect",
            ) as captured:
                session.prepare(colliding)
        self.assertIsInstance(
            captured.exception,
            authority_runtime.DurableRecoveryDenied,
        )
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((
                origin_token.effect_id,
                authority_runtime.DurableEffectState.PREPARED.value,
            ),),
        )
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (
                runtime_directory
                / "recovery-bindings"
                / f"{colliding.effect_id}.json"
            ).exists()
        )
        self.assertFalse(
            (
                runtime_directory
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )

    def _deferred_legacy_v1_prepare_fences_a_lost_binding_race_after_claiming_a_target(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-binding-race-fence",
            target_path="outputs/binding-race-fence.json",
            artifact_bytes=b'{"effect":"binding-race-fence"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_record_binding",
                return_value=object(),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryFenceRequired,
                    "target claim",
                ) as captured:
                    session.prepare(effect)

        self.assertEqual(captured.exception.reason_code, "RECOVERY_EVIDENCE_UNSAFE")
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertTrue(
            (
                runtime_directory
                / "recovery-target-claims"
                / f"{sha256_bytes(effect.target_relative_path.encode())}.json"
            ).is_file()
        )
        self.assertTrue(
            (
                runtime_directory
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).is_file()
        )
        self.assertFalse(
            (
                runtime_directory
                / "recovery-bindings"
                / f"{effect.effect_id}.json"
            ).exists()
        )

    def _deferred_legacy_v1_prepare_lookup_failure_before_binding_uses_a_root_fence_not_a_token(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepare-prebinding-lookup",
            target_path="outputs/prepare-prebinding-lookup.json",
            artifact_bytes=b'{"effect":"prepare-prebinding-lookup"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_row",
                side_effect=sqlite3.OperationalError("initial lookup unavailable"),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryFenceRequired,
                    "prepare state is unavailable",
                ) as captured:
                    session.prepare(effect)

        self.assertEqual(captured.exception.reason_code, "RECOVERY_STATE_UNAVAILABLE")
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (
                runtime_directory
                / "recovery-bindings"
                / f"{effect.effect_id}.json"
            ).exists()
        )
        self.assertTrue(
            (
                runtime_directory
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).is_file()
        )

    def _assert_claimed_storage_failure_does_not_create_root_fence(
        self,
        *,
        effect_id: str,
        patch_target: object,
        patch_attribute: str,
        failure: BaseException,
    ) -> None:
        artifact_bytes = f'{{"effect":"{effect_id}"}}\n'.encode("utf-8")
        target_path = f"outputs/{effect_id}.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id=effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                patch_target,
                patch_attribute,
                side_effect=failure,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "durable .* is unavailable",
                ) as captured:
                    session.prepare(effect)
            self.assertIs(type(captured.exception), authority_runtime.AuthorityRuntimeError)
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "write session is not active",
            ):
                session.prepare(effect)

        self.assertFalse(
            (
                runtime_directory
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def test_claimed_storage_failures_do_not_create_root_fences(self):
        cases = (
            (
                "binding-read",
                authority_session.durable.DurableCoordinator,
                "_snapshot_binding_for_effect_id",
                authority_runtime.AuthorityRuntimeError("binding read unavailable"),
            ),
            (
                "row-read",
                authority_session.durable.DurableCoordinator,
                "_row",
                sqlite3.OperationalError("row read unavailable"),
            ),
            (
                "target-claim-write",
                authority_snapshot._DurableSnapshotStore,
                "record_target_claim",
                authority_runtime.AuthorityRuntimeError("target claim write unavailable"),
            ),
            (
                "binding-write",
                authority_snapshot._DurableSnapshotStore,
                "record_binding",
                authority_runtime.AuthorityRuntimeError("binding write unavailable"),
            ),
        )
        for suffix, patch_target, patch_attribute, failure in cases:
            with self.subTest(suffix=suffix):
                with self._independent_write_fixture() as fixture:
                    fixture._assert_claimed_storage_failure_does_not_create_root_fence(
                        effect_id=f"effect-claimed-{suffix}",
                        patch_target=patch_target,
                        patch_attribute=patch_attribute,
                        failure=failure,
                    )

    def test_prepared_insert_storage_failure_closes_without_root_fence(
        self,
    ):
        artifact_bytes = b'{"effect":"bound-target-claim-storage-error"}\n'
        target_path = "outputs/bound-target-claim-storage-error.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-bound-target-claim-storage-error",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "insert_effect",
                side_effect=authority_runtime.AuthorityRuntimeError(
                    "prepared row write unavailable"
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "prepared row write unavailable",
                ) as first_failure:
                    session.prepare(effect)
            self.assertIs(type(first_failure.exception), authority_runtime.AuthorityRuntimeError)
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "write session is not active",
            ):
                session.prepare(effect)

        self.assertFalse(
            (
                runtime_directory
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)

    def _deferred_legacy_v1_recovery_rejects_a_sidecar_whose_token_no_longer_binds_its_identity(self):
        artifact_bytes = b'{"effect":"continuation-binding-tamper"}\n'
        target_path = "outputs/continuation-binding-tamper.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-continuation-binding-tamper",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        binding_path = (
            runtime_directory / "recovery-bindings" / f"{effect.effect_id}.json"
        )
        binding_payload = json.loads(binding_path.read_text())
        binding_payload["scope_sha256"] = "f" * 64
        binding_path.write_bytes(canonical_json_bytes(binding_payload))
        binding_path.chmod(0o600)
        database_path = runtime_directory / "authority-runtime.sqlite3"
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "UPDATE durable_effects SET scope_sha256 = ? WHERE effect_id = ?",
                ("f" * 64, effect.effect_id),
            )
            connection.commit()
        finally:
            connection.close()

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "binding is unavailable",
            ) as captured:
                session.recover(token)

        self.assertEqual(captured.exception.reason_code, "RECOVERY_EVIDENCE_UNSAFE")
        self.assertEqual(
            self._durable_state(effect.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def _deferred_legacy_v1_recovery_blocks_a_prepared_payload_that_no_longer_matches_its_ref(self):
        artifact_bytes = b'{"effect":"prepared-payload-tamper"}\n'
        target_path = "outputs/prepared-payload-tamper.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-payload-tamper",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        database_path = runtime_directory / "authority-runtime.sqlite3"
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "UPDATE durable_effects SET artifact_bytes = ? WHERE effect_id = ?",
                (b'{"effect":"tampered"}\n', effect.effect_id),
            )
            connection.commit()
        finally:
            connection.close()

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "prepared payload is invalid",
            ) as captured:
                session.recover(token)

        self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((
                effect.effect_id,
                authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
            ),),
        )

    def _deferred_legacy_v1_apply_retry_never_restages_caller_bytes_over_an_invalid_prepared_payload(self):
        artifact_bytes = b'{"effect":"prepared-payload-retry-tamper"}\n'
        target_path = "outputs/prepared-payload-retry-tamper.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-payload-retry-tamper",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        stage_path = self._snapshot_stage_path(effect.effect_id)
        stage_path.unlink()
        database_path = runtime_directory / "authority-runtime.sqlite3"
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "UPDATE durable_effects SET artifact_bytes = ? WHERE effect_id = ?",
                (b'{"effect":"tampered"}\n', effect.effect_id),
            )
            connection.commit()
        finally:
            connection.close()

        with authority_runtime.open_write(admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "prepared payload is invalid",
            ) as captured:
                session.prepare(effect)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(
            self._durable_state(effect.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )
        self.assertFalse(stage_path.exists())

    def _deferred_legacy_v1_keyless_recovery_fences_a_binding_not_committed_by_its_target_claim(self):
        artifact_bytes = b'{"effect":"keyless-claim-binding-tamper"}\n'
        target_path = "outputs/keyless-claim-binding-tamper.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-keyless-claim-binding-tamper",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        binding_path = (
            runtime_directory / "recovery-bindings" / f"{effect.effect_id}.json"
        )
        binding_payload = json.loads(binding_path.read_text())
        original_tag = binding_payload["recovery_token"]["authentication_tag"]
        forged_tag = (
            ("0" if original_tag[0] != "0" else "1") + original_tag[1:]
        )
        binding_payload["recovery_token"]["authentication_tag"] = forged_tag
        binding_path.write_bytes(canonical_json_bytes(binding_payload))
        binding_path.chmod(0o600)
        forged_token = authority_runtime.RecoveryToken(
            effect_id=token.effect_id,
            request_sha256=token.request_sha256,
            continuation_identity=token.continuation_identity,
            authentication_tag=forged_tag,
        )
        (runtime_directory / "recovery-token.key").unlink()

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "target claim",
            ) as captured:
                session.recover(forged_token)

        self.assertEqual(captured.exception.reason_code, "RECOVERY_EVIDENCE_UNSAFE")
        self.assertEqual(
            self._durable_state(effect.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )
        self.assertFalse(
            (
                runtime_directory
                / "recovery-blockers"
                / f"{effect.effect_id}.json"
            ).exists()
        )

    def test_prepare_revalidates_before_recording_any_durable_effect(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepare-prewrite-revalidation",
            target_path="outputs/prepare-prewrite-revalidation.json",
            artifact_bytes=b'{"effect":"prepare-prewrite-revalidation"}\n',
        )
        original_registry = self.registry_path.read_bytes()
        paused_registry = original_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        replacement = self.registry_directory / "placement-map.prepare-prewrite-paused"
        original_token_for_effect = (
            authority_session.durable.DurableCoordinator._token_for_effect
        )
        paused = False

        def pause_after_session_revalidation(coordinator, candidate):
            nonlocal paused
            token = original_token_for_effect(coordinator, candidate)
            if not paused:
                replacement.write_bytes(paused_registry)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)
                paused = True
            return token

        with authority_runtime.open_write(admitted) as session:
            try:
                with mock.patch.object(
                    authority_session.durable.DurableCoordinator,
                    "_token_for_effect",
                    pause_after_session_revalidation,
                ):
                    with self.assertRaisesRegex(
                        authority_runtime.AuthorityRuntimeError,
                        "current policy",
                    ):
                        session.prepare(effect)
            finally:
                replacement.write_bytes(original_registry)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "not active",
            ):
                session.prepare(effect)

        self.assertTrue(paused)
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (
                runtime_directory
                / "recovery-bindings"
                / f"{effect.effect_id}.json"
            ).exists()
        )
        self.assertFalse(
            (
                self._snapshot_stage_path(effect.effect_id)
            ).exists()
        )
        self.assertTrue(
            all(
                observed_effect_id != effect.effect_id
                for record in self._snapshot_head_records()
                for observed_effect_id, _state in record["effect_rows"]
            )
        )

    def test_write_session_revalidates_the_authority_root_identity_before_prepare(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-root-revalidation",
            target_path="outputs/root-revalidation.json",
            artifact_bytes=b'{"effect":"root-revalidation"}\n',
        )
        replaced_root = self.root.with_name(f"{self.root.name}-replaced")

        with authority_runtime.open_write(admitted) as session:
            os.rename(self.root, replaced_root)
            shutil.copytree(replaced_root, self.root)
            try:
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "root identity changed",
                ):
                    session.prepare(effect)
                self.assertTrue(
                    all(
                        observed_effect_id != effect.effect_id
                        for record in self._snapshot_head_records()
                        for observed_effect_id, _state in record["effect_rows"]
                    )
                )
            finally:
                if self.root.exists():
                    shutil.rmtree(self.root)
                os.rename(replaced_root, self.root)

    def test_prepared_root_identity_drift_never_writes_a_replacement_root(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-root-drift-prepared",
            target_path="outputs/root-drift-prepared.json",
            artifact_bytes=b'{"effect":"root-drift-prepared"}\n',
        )
        replaced_root = self.root.with_name(f"{self.root.name}-replaced")

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            os.rename(self.root, replaced_root)
            shutil.copytree(replaced_root, self.root)
            try:
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "root identity changed",
                ):
                    session.publish(token)
                replacement_runtime = (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                )
                self.assertFalse(
                    (
                        replacement_runtime
                        / "recovery-blockers"
                        / f"{effect.effect_id}.json"
                    ).exists()
                )
                self.assertFalse(
                    (
                        replacement_runtime
                        / "recovery-fences"
                        / "root-recovery-fence.json"
                    ).exists()
                )
                self.assertFalse((self.root / effect.target_relative_path).exists())
            finally:
                if self.root.exists():
                    shutil.rmtree(self.root)
                os.rename(replaced_root, self.root)

    def test_published_root_identity_drift_never_writes_a_replacement_root(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-root-drift-published",
            target_path="outputs/root-drift-published.json",
            artifact_bytes=b'{"effect":"root-drift-published"}\n',
        )
        replaced_root = self.root.with_name(f"{self.root.name}-replaced")

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            session.publish(token)
            os.rename(self.root, replaced_root)
            shutil.copytree(replaced_root, self.root)
            try:
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "root identity changed",
                ):
                    session.finalize(token)
                replacement_runtime = (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                )
                self.assertFalse(
                    (
                        replacement_runtime
                        / "recovery-blockers"
                        / f"{effect.effect_id}.json"
                    ).exists()
                )
                self.assertFalse(
                    (
                        replacement_runtime
                        / "recovery-fences"
                        / "root-recovery-fence.json"
                    ).exists()
                )
            finally:
                if self.root.exists():
                    shutil.rmtree(self.root)
                os.rename(replaced_root, self.root)

    def test_recovery_root_identity_drift_never_writes_a_replacement_root(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-root-drift-recovery",
            target_path="outputs/root-drift-recovery.json",
            artifact_bytes=b'{"effect":"root-drift-recovery"}\n',
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
        recovery_admitted, _ignored_effect = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        replaced_root = self.root.with_name(f"{self.root.name}-replaced")

        with authority_runtime.open_write(recovery_admitted) as session:
            os.rename(self.root, replaced_root)
            shutil.copytree(replaced_root, self.root)
            try:
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "root identity changed",
                ):
                    session.recover(token)
                replacement_runtime = (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                )
                self.assertFalse(
                    (
                        replacement_runtime
                        / "recovery-blockers"
                        / f"{effect.effect_id}.json"
                    ).exists()
                )
                self.assertFalse(
                    (
                        replacement_runtime
                        / "recovery-fences"
                        / "root-recovery-fence.json"
                    ).exists()
                )
                self.assertFalse((self.root / effect.target_relative_path).exists())
            finally:
                if self.root.exists():
                    shutil.rmtree(self.root)
                os.rename(replaced_root, self.root)

    def test_root_replacement_before_coordinator_open_cannot_create_runtime_state(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-root-drift-open",
            target_path="outputs/root-drift-open.json",
            artifact_bytes=b'{"effect":"root-drift-open"}\n',
        )
        replaced_root = self.root.with_name(f"{self.root.name}-replaced")
        original_open = authority_session.durable.DurableCoordinator.open
        swapped = False

        def replace_root_before_open(root, **kwargs):
            nonlocal swapped
            if not swapped:
                os.rename(self.root, replaced_root)
                shutil.copytree(replaced_root, self.root)
                swapped = True
            return original_open(root, **kwargs)

        try:
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "open",
                side_effect=replace_root_before_open,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "root identity changed",
                ):
                    with authority_runtime.open_write(admitted):
                        pass
            self.assertTrue(swapped)
            self.assertFalse(
                (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                ).exists()
            )
        finally:
            if self.root.exists():
                shutil.rmtree(self.root)
            if replaced_root.exists():
                os.rename(replaced_root, self.root)

    def test_copied_root_identity_cannot_admit_a_recovery_session(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-root-identity-recovery",
            target_path="outputs/root-identity-recovery.json",
            artifact_bytes=b'{"effect":"root-identity-recovery"}\n',
        )
        replaced_root = self.root.with_name(f"{self.root.name}-replaced")

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        os.rename(self.root, replaced_root)
        shutil.copytree(replaced_root, self.root)
        try:
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "write admission evidence is unavailable",
            ):
                self._admit_durable_write_effect(
                    effect_id=effect.effect_id,
                    target_path=effect.target_relative_path,
                    artifact_bytes=effect.artifact_bytes,
                    action=operation_contract.LifecycleAction.RECOVER,
                )
            self.assertEqual(
                self._durable_state(effect.effect_id),
                authority_runtime.DurableEffectState.PREPARED.value,
            )
            replacement_runtime = (
                self.root / "_registry" / "curation" / "authority-runtime"
            )
            self.assertFalse(
                (
                    replacement_runtime
                    / "recovery-blockers"
                    / f"{effect.effect_id}.json"
                ).exists()
            )
            self.assertFalse(
                (
                    replacement_runtime
                    / "recovery-fences"
                    / "root-recovery-fence.json"
                ).exists()
            )
            self.assertFalse((self.root / effect.target_relative_path).exists())
        finally:
            if self.root.exists():
                shutil.rmtree(self.root)
            os.rename(replaced_root, self.root)

    def test_durable_root_mutation_gate_serializes_distinct_anchors(self):
        identity = authority_session._canonical_root_identity(self.root)
        first = authority_snapshot._RootAnchor.open(
            self.root,
            expected_identity=identity,
        )
        second = authority_snapshot._RootAnchor.open(
            self.root,
            expected_identity=identity,
        )
        first_entered = threading.Event()
        release_first = threading.Event()
        second_entered = threading.Event()
        failures: list[BaseException] = []

        def hold_first_gate():
            try:
                with first.mutation_gate():
                    first_entered.set()
                    if not release_first.wait(timeout=2):
                        raise AssertionError("first gate release timed out")
            except BaseException as exc:
                failures.append(exc)

        def enter_second_gate():
            try:
                if not first_entered.wait(timeout=2):
                    raise AssertionError("first gate was never acquired")
                with second.mutation_gate():
                    second_entered.set()
            except BaseException as exc:
                failures.append(exc)

        first_thread = threading.Thread(target=hold_first_gate)
        second_thread = threading.Thread(target=enter_second_gate)
        try:
            first_thread.start()
            self.assertTrue(first_entered.wait(timeout=2))
            second_thread.start()
            self.assertFalse(second_entered.wait(timeout=0.2))
            release_first.set()
            first_thread.join(timeout=2)
            second_thread.join(timeout=2)
            self.assertFalse(first_thread.is_alive())
            self.assertFalse(second_thread.is_alive())
            self.assertTrue(second_entered.is_set())
            self.assertEqual(failures, [])
        finally:
            release_first.set()
            first_thread.join(timeout=2)
            second_thread.join(timeout=2)
            first.close()
            second.close()

    def test_fork_during_lock_acquisition_inherits_only_a_tracked_ofd(self):
        lock_name = "fork-acquisition-race.lock"
        parent_fd = os.open(str(self.root), os.O_RDONLY)
        child_read, child_write = os.pipe()
        fork_started = threading.Event()
        fork_before_entered = threading.Event()
        release_fork_before = threading.Event()
        armed = threading.Event()
        child_pids: list[int] = []
        child_pids_lock = threading.Lock()
        original_open = authority_snapshot.os.open

        def before_fork() -> None:
            if armed.is_set():
                fork_before_entered.set()
                release_fork_before.wait(timeout=2)

        def after_fork_child() -> None:
            if armed.is_set():
                marker = (
                    b"1"
                    if authority_snapshot._fork_child_lock_state_poisoned()
                    else b"0"
                )
                os.write(child_write, marker)

        os.register_at_fork(
            before=before_fork,
            after_in_child=after_fork_child,
        )

        def fork_from_second_thread() -> None:
            fork_started.set()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                child_pid = os.fork()
            if child_pid == 0:
                os._exit(0)
            with child_pids_lock:
                child_pids.append(child_pid)

        def open_during_race(name, flags, mode=0o777, *, dir_fd=None):
            descriptor = original_open(name, flags, mode, dir_fd=dir_fd)
            if name != lock_name:
                return descriptor
            self.assertTrue(fork_started.wait(timeout=2))
            self.assertTrue(fork_before_entered.wait(timeout=2))
            release_fork_before.set()
            return descriptor

        fork_thread = threading.Thread(target=fork_from_second_thread)
        lock_fd: int | None = None
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        armed.set()
        try:
            fork_thread.start()
            with mock.patch.object(
                authority_snapshot.os,
                "open",
                open_during_race,
            ):
                lock_fd = authority_snapshot._acquire_fork_safe_lock(
                    directory_fd=parent_fd,
                    name=lock_name,
                    flags=flags,
                    label="fork acquisition test lock",
                    wait=True,
                    verify=lambda descriptor: self.assertTrue(
                        stat.S_ISREG(os.fstat(descriptor).st_mode)
                    ),
                )
            self.assertIsNotNone(lock_fd)
            fork_thread.join(timeout=2)
            self.assertFalse(fork_thread.is_alive())
            with child_pids_lock:
                self.assertEqual(len(child_pids), 1)
                child_pid = child_pids[0]
            waited_pid, status = os.waitpid(child_pid, 0)
            self.assertEqual(waited_pid, child_pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
            self.assertEqual(os.read(child_read, 1), b"1")
        finally:
            armed.clear()
            release_fork_before.set()
            fork_thread.join(timeout=2)
            if lock_fd is not None:
                authority_snapshot._release_tracked_lock(
                    lock_fd,
                    label="fork acquisition test lock",
                )
            os.close(child_read)
            os.close(child_write)
            os.close(parent_fd)

    def test_root_anchor_normalizes_duplicate_fd_failure(self):
        identity = authority_session._canonical_root_identity(self.root)
        anchor = authority_snapshot._RootAnchor.open(
            self.root,
            expected_identity=identity,
        )
        try:
            with mock.patch.object(
                authority_snapshot.os,
                "dup",
                side_effect=OSError("descriptor table exhausted"),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "durable root directory is unavailable",
                ):
                    anchor.read_bytes(anchor / "optional-artifact.json")
        finally:
            anchor.close()

    def test_live_snapshot_writer_denies_a_second_coordinator_without_fencing(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-live-snapshot-writer",
            target_path="outputs/live-snapshot-writer.json",
            artifact_bytes=b'{"effect":"live-snapshot-writer"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)

        def open_coordinator():
            return authority_session.durable.DurableCoordinator.open(
                evidence.root,
                root_identity=evidence.root_identity,
                request_sha256=evidence.request_sha256,
                scope_sha256=evidence.scope_sha256,
                bounds_sha256=evidence.bounds_sha256,
                spec_identity=evidence.spec_identity,
                spec_sha256=evidence.spec_sha256,
                policy_identity=evidence.policy_identity,
                action=evidence.lifecycle_action,
                transition_guard=lambda: None,
                on_invalidate=lambda _error: None,
            )

        first = open_coordinator()
        second = None
        try:
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "durable snapshot writer is active",
            ):
                open_coordinator()
            self.assertFalse(
                (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                    / "recovery-fences"
                    / "root-recovery-fence.json"
                ).exists()
            )
        finally:
            first.close()

        try:
            second = open_coordinator()
            self.assertFalse(
                (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                    / "recovery-fences"
                    / "root-recovery-fence.json"
                ).exists()
            )
        finally:
            if second is not None:
                second.close()

    def test_second_process_snapshot_opener_reports_busy_without_root_fence(self):
        """A live snapshot lease is busy, not evidence that the root is unsafe."""

        identity = authority_session._canonical_root_identity(self.root)
        anchor = authority_snapshot._RootAnchor.open(
            self.root,
            expected_identity=identity,
        )
        store = authority_snapshot._DurableSnapshotStore.open(anchor)
        fence_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "recovery-fences"
            / "root-recovery-fence.json"
        )
        child_code = """
import os
import sys
from pathlib import Path

import mnemosyne
from mnemosyne_core import operation_contract
from mnemosyne_core.authority_runtime import AuthorityRuntimeError, durable


class PolicyIdentity:
    raw_hash = "a" * 64
    full_hash = "b" * 64
    writer_control_hash = "c" * 64
    foundation_hash = "d" * 64
    generation = 1
    source_kind = "test"
    source_run_id = "test-run"
    guard_epoch = 1


root = Path(sys.argv[1])
info = os.stat(root, follow_symlinks=False)
try:
    coordinator = durable.DurableCoordinator.open(
        root,
        root_identity=(info.st_dev, info.st_ino),
        request_sha256="1" * 64,
        scope_sha256="2" * 64,
        bounds_sha256="3" * 64,
        spec_identity="test-second-snapshot-opener-v1",
        spec_sha256="4" * 64,
        policy_identity=PolicyIdentity(),
        action=operation_contract.LifecycleAction.APPLY,
        transition_guard=lambda: None,
        on_invalidate=lambda _error: None,
    )
except AuthorityRuntimeError as exc:
    if str(exc) == "durable snapshot writer is active":
        raise SystemExit(0)
    raise SystemExit(41)
else:
    coordinator.close()
    raise SystemExit(42)
"""
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(SCRIPT_DIR)
        try:
            result = subprocess.run(
                [sys.executable, "-c", child_code, str(self.root)],
                check=False,
                capture_output=True,
                cwd=self.root,
                env=environment,
                text=True,
                timeout=10,
            )
            self.assertEqual(
                result.returncode,
                0,
                msg=result.stderr or result.stdout,
            )
            self.assertFalse(fence_path.exists())
        finally:
            store.close()

    def test_active_tip_head_receipt_replacement_fences_before_publish(self):
        """An active session must not publish through a same-bytes tip ABA."""

        artifact_bytes = b'{"effect":"active-tip-replacement"}\n'
        target_path = "outputs/active-tip-replacement.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-active-tip-replacement",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            head_path = max(
                heads_directory.glob("h-*.json"),
                key=lambda candidate: json.loads(candidate.read_bytes())["generation"],
            )
            head_raw = head_path.read_bytes()
            head = json.loads(head_raw)
            receipt_path = receipts_directory / (
                f"r-{head_path.stem[2:]}-{head['receipt_token']}"
            )
            original_inode = head_path.stat(follow_symlinks=False).st_ino

            os.unlink(head_path)
            os.unlink(receipt_path)
            receipt_path.write_bytes(head_raw)
            receipt_path.chmod(0o600)
            os.link(receipt_path, head_path, follow_symlinks=False)

            self.assertNotEqual(
                head_path.stat(follow_symlinks=False).st_ino,
                original_inode,
            )
            self.assertEqual(head_path.read_bytes(), head_raw)
            self.assertEqual(receipt_path.read_bytes(), head_raw)
            self.assertEqual(
                head_path.stat(follow_symlinks=False).st_ino,
                receipt_path.stat(follow_symlinks=False).st_ino,
            )

            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "snapshot history changed",
            ) as captured:
                session.publish(token)

        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_SNAPSHOT_HISTORY_CHANGED",
        )
        self.assertFalse((self.root / target_path).exists())
        self.assertEqual(head_path.read_bytes(), head_raw)
        self.assertEqual(receipt_path.read_bytes(), head_raw)
        stops = self._snapshot_root_stop_records()
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["reason_code"], captured.exception.reason_code)
        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        self.assertFalse(
            (runtime_directory / "recovery-fences" / "root-recovery-fence.json").exists()
        )

    def test_active_tip_unlink_relink_same_inode_fences_before_publish(self):
        """A head entry ABA is unsafe even when its final inode is unchanged."""

        artifact_bytes = b'{"effect":"active-tip-same-inode-aba"}\n'
        target_path = "outputs/active-tip-same-inode-aba.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-active-tip-same-inode-aba",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            head_path = max(
                heads_directory.glob("h-*.json"),
                key=lambda candidate: json.loads(candidate.read_bytes())["generation"],
            )
            head_raw = head_path.read_bytes()
            head = json.loads(head_raw)
            receipt_path = receipts_directory / (
                f"r-{head_path.stem[2:]}-{head['receipt_token']}"
            )
            original_inode = head_path.stat(follow_symlinks=False).st_ino
            temporary_link = receipts_directory / "tip-aba-temporary-link"

            os.link(receipt_path, temporary_link, follow_symlinks=False)
            os.unlink(head_path)
            os.unlink(temporary_link)
            os.link(receipt_path, head_path, follow_symlinks=False)

            self.assertEqual(
                head_path.stat(follow_symlinks=False).st_ino,
                original_inode,
            )
            self.assertEqual(
                receipt_path.stat(follow_symlinks=False).st_ino,
                original_inode,
            )
            self.assertEqual(head_path.read_bytes(), head_raw)
            self.assertEqual(receipt_path.read_bytes(), head_raw)

            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "snapshot history changed",
            ) as captured:
                session.publish(token)

        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_SNAPSHOT_HISTORY_CHANGED",
        )
        self.assertFalse((self.root / target_path).exists())
        self.assertEqual(head_path.read_bytes(), head_raw)
        self.assertEqual(receipt_path.read_bytes(), head_raw)

    def test_publish_rechecks_history_immediately_before_target_publication(self):
        """The pre-effect guard closes the gap after publish entry verification."""

        artifact_bytes = b'{"effect":"pre-effect-history-recheck"}\n'
        target_path = "outputs/pre-effect-history-recheck.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-pre-effect-history-recheck",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        original_guard = (
            authority_session.durable.DurableCoordinator._guard_before_possible_effect
        )
        mutation_ran = False

        def replace_tip_then_guard(coordinator, row, *, message):
            nonlocal mutation_ran
            if not mutation_ran:
                mutation_ran = True
                head_path = max(
                    heads_directory.glob("h-*.json"),
                    key=lambda candidate: json.loads(candidate.read_bytes())["generation"],
                )
                head_raw = head_path.read_bytes()
                head = json.loads(head_raw)
                receipt_path = receipts_directory / (
                    f"r-{head_path.stem[2:]}-{head['receipt_token']}"
                )
                os.unlink(head_path)
                os.unlink(receipt_path)
                receipt_path.write_bytes(head_raw)
                receipt_path.chmod(0o600)
                os.link(receipt_path, head_path, follow_symlinks=False)
            return original_guard(coordinator, row, message=message)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_guard_before_possible_effect",
                new=replace_tip_then_guard,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryFenceRequired,
                    "snapshot history changed",
                ) as captured:
                    session.publish(token)

        self.assertTrue(mutation_ran)
        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_SNAPSHOT_HISTORY_CHANGED",
        )
        self.assertFalse((self.root / target_path).exists())

    def test_prepare_rechecks_history_immediately_before_claim(self):
        """The expected tip is checked again before creating a CLAIMED head."""

        artifact_bytes = b'{"effect":"pre-claim-history-recheck"}\n'
        target_path = "outputs/pre-claim-history-recheck.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-pre-claim-history-recheck",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        original_guard = (
            authority_session.durable.DurableCoordinator._guard_before_unbound_write
        )
        mutation_ran = False

        def replace_tip_then_guard(coordinator):
            nonlocal mutation_ran
            if not mutation_ran:
                mutation_ran = True
                head_path = max(
                    heads_directory.glob("h-*.json"),
                    key=lambda candidate: json.loads(candidate.read_bytes())["generation"],
                )
                head_raw = head_path.read_bytes()
                head = json.loads(head_raw)
                receipt_path = receipts_directory / (
                    f"r-{head_path.stem[2:]}-{head['receipt_token']}"
                )
                os.unlink(head_path)
                os.unlink(receipt_path)
                receipt_path.write_bytes(head_raw)
                receipt_path.chmod(0o600)
                os.link(receipt_path, head_path, follow_symlinks=False)
            return original_guard(coordinator)

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_guard_before_unbound_write",
                new=replace_tip_then_guard,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryFenceRequired,
                    "snapshot history changed",
                ) as captured:
                    session.prepare(effect)

        self.assertTrue(mutation_ran)
        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_SNAPSHOT_HISTORY_CHANGED",
        )
        self.assertFalse((self.root / target_path).exists())
        self.assertEqual(
            [record["transition_kind"] for record in self._snapshot_head_records()],
            ["EMPTY_GENESIS"],
        )

    def test_active_transient_protocol_read_preserves_token_recovery(self):
        """A transient protocol-read failure is not immutable-history drift."""

        artifact_bytes = b'{"effect":"active-history-read-unavailable"}\n'
        target_path = "outputs/active-history-read-unavailable.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-active-history-read-unavailable",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        read_attempted = False
        original_read_regular_file_at = authority_snapshot.safety.read_regular_file_at

        def unreadable_protocol_file(*args, **kwargs):
            nonlocal read_attempted
            if kwargs["label"] != "durable snapshot head" or read_attempted:
                return original_read_regular_file_at(*args, **kwargs)
            read_attempted = True
            error_type = kwargs["error_type"]
            try:
                raise OSError(errno.EIO, "injected protocol read failure")
            except OSError as exc:
                raise error_type(
                    f"{kwargs['label']} is unreadable: {args[2]}"
                ) from exc

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot.safety,
                "read_regular_file_at",
                side_effect=unreadable_protocol_file,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable snapshot state is unavailable",
                ) as captured:
                    session.publish(token)

        self.assertTrue(read_attempted)
        self.assertIsNotNone(captured.exception.directive)
        self.assertEqual(captured.exception.directive.token, token)
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )

    def test_active_transient_namespace_read_preserves_token_recovery(self):
        """A transient canonical-directory read is not immutable-history drift."""

        artifact_bytes = b'{"effect":"active-namespace-read-unavailable"}\n'
        target_path = "outputs/active-namespace-read-unavailable.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-active-namespace-read-unavailable",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        directory_read_attempted = False
        original_open_directory = authority_snapshot._RootAnchor._open_directory

        def transient_namespace_read(anchor, parts, *, create):
            nonlocal directory_read_attempted
            if (
                parts == authority_snapshot._SNAPSHOT_HEADS_PARTS
                and not create
                and not directory_read_attempted
            ):
                directory_read_attempted = True
                raise OSError(errno.EIO, "injected namespace read failure")
            return original_open_directory(anchor, parts, create=create)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_snapshot._RootAnchor,
                "_open_directory",
                new=transient_namespace_read,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable snapshot state is unavailable",
                ) as captured:
                    session.publish(token)

        self.assertTrue(directory_read_attempted)
        self.assertIsNotNone(captured.exception.directive)
        self.assertEqual(captured.exception.directive.token, token)
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "recovery-fences"
                / "root-recovery-fence.json"
            ).exists()
        )

    def _assert_active_snapshot_mutation_fences_before_publish(
        self,
        mutation: str,
    ) -> None:
        artifact_bytes = f'{{"effect":"{mutation}"}}\n'.encode("utf-8")
        target_path = f"outputs/{mutation}.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id=f"effect-active-{mutation}",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        snapshot_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
        )
        heads_directory = snapshot_directory / "heads"
        receipts_directory = snapshot_directory / "head-receipts"
        objects_directory = snapshot_directory / "objects"

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            head_path = max(
                heads_directory.glob("h-*.json"),
                key=lambda candidate: json.loads(candidate.read_bytes())["generation"],
            )
            head = json.loads(head_path.read_bytes())
            receipt_path = receipts_directory / (
                f"r-{head_path.stem[2:]}-{head['receipt_token']}"
            )
            retained_path: Path
            retained_raw: bytes | None = None
            if mutation == "receipt-delete":
                retained_path = receipt_path
                os.unlink(receipt_path)
            elif mutation == "manifest-object-replacement":
                retained_path = objects_directory / (
                    f"o-{head['manifest_object_sha256']}"
                )
                retained_raw = retained_path.read_bytes()
                original_inode = retained_path.stat(follow_symlinks=False).st_ino
                os.unlink(retained_path)
                retained_path.write_bytes(retained_raw)
                retained_path.chmod(0o600)
                self.assertNotEqual(
                    retained_path.stat(follow_symlinks=False).st_ino,
                    original_inode,
                )
            elif mutation == "snapshot-object-hard-link":
                source_path = objects_directory / (
                    f"o-{head['snapshot_object_sha256']}"
                )
                retained_path = objects_directory / "tamper-snapshot-hard-link"
                os.link(source_path, retained_path, follow_symlinks=False)
            elif mutation == "heads-parent-replacement":
                original_parent = snapshot_directory / "heads-original"
                os.rename(heads_directory, original_parent)
                shutil.copytree(original_parent, heads_directory)
                retained_path = heads_directory
            else:
                raise AssertionError(f"unknown active snapshot mutation: {mutation}")

            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "snapshot history changed",
            ) as captured:
                session.publish(token)

        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_SNAPSHOT_HISTORY_CHANGED",
        )
        self.assertFalse((self.root / target_path).exists())
        if mutation == "receipt-delete":
            self.assertFalse(retained_path.exists())
        else:
            self.assertTrue(retained_path.exists())
        if retained_raw is not None:
            self.assertEqual(retained_path.read_bytes(), retained_raw)

    def test_active_snapshot_member_mutations_fence_before_publish(self):
        """Delete, link, object, and parent drift stay visible and fail closed."""

        for mutation in (
            "receipt-delete",
            "manifest-object-replacement",
            "snapshot-object-hard-link",
            "heads-parent-replacement",
        ):
            with self.subTest(mutation=mutation):
                with self._independent_write_fixture() as fixture:
                    fixture._assert_active_snapshot_mutation_fences_before_publish(
                        mutation
                    )

    def _mutate_active_snapshot_history_from_process(
        self,
        *,
        mutation: str,
    ) -> None:
        """Run one hostile canonical-history mutation outside the writer process."""

        child_code = """
import json
import os
import shutil
import sys
from pathlib import Path


root = Path(sys.argv[1])
mutation = sys.argv[2]
snapshot_directory = (
    root / "_registry" / "curation" / "authority-runtime" / "snapshot-v1"
)
heads_directory = snapshot_directory / "heads"
receipts_directory = snapshot_directory / "head-receipts"
objects_directory = snapshot_directory / "objects"
head_path = max(
    heads_directory.glob("h-*.json"),
    key=lambda candidate: json.loads(candidate.read_bytes())["generation"],
)
head_raw = head_path.read_bytes()
head = json.loads(head_raw)
receipt_path = receipts_directory / (
    f"r-{head_path.stem[2:]}-{head['receipt_token']}"
)

if mutation == "head-receipt-replacement":
    os.unlink(head_path)
    os.unlink(receipt_path)
    receipt_path.write_bytes(head_raw)
    receipt_path.chmod(0o600)
    os.link(receipt_path, head_path, follow_symlinks=False)
elif mutation == "expected-tip-aba":
    temporary_link = receipts_directory / "process-tip-aba-temporary-link"
    os.link(receipt_path, temporary_link, follow_symlinks=False)
    os.unlink(head_path)
    os.unlink(temporary_link)
    os.link(receipt_path, head_path, follow_symlinks=False)
elif mutation == "receipt-delete":
    os.unlink(receipt_path)
elif mutation == "manifest-object-delete":
    os.unlink(objects_directory / f"o-{head['manifest_object_sha256']}")
elif mutation == "snapshot-object-delete":
    os.unlink(objects_directory / f"o-{head['snapshot_object_sha256']}")
elif mutation == "manifest-object-replacement":
    object_path = objects_directory / f"o-{head['manifest_object_sha256']}"
    object_raw = object_path.read_bytes()
    os.unlink(object_path)
    object_path.write_bytes(object_raw)
    object_path.chmod(0o600)
elif mutation == "snapshot-object-hard-link":
    object_path = objects_directory / f"o-{head['snapshot_object_sha256']}"
    os.link(
        object_path,
        root / "process-tamper-snapshot-hard-link",
        follow_symlinks=False,
    )
    if object_path.stat(follow_symlinks=False).st_nlink != 2:
        raise SystemExit(65)
elif mutation == "heads-parent-replacement":
    original_parent = snapshot_directory / "process-heads-original"
    os.rename(heads_directory, original_parent)
    shutil.copytree(original_parent, heads_directory)
elif mutation == "heads-parent-delete":
    for entry in heads_directory.iterdir():
        os.unlink(entry)
    os.rmdir(heads_directory)
elif mutation == "heads-parent-type-replacement":
    for entry in heads_directory.iterdir():
        os.unlink(entry)
    os.rmdir(heads_directory)
    heads_directory.write_bytes(b"not a directory\\n")
    heads_directory.chmod(0o600)
else:
    raise SystemExit(64)
"""
        result = subprocess.run(
            [sys.executable, "-c", child_code, str(self.root), mutation],
            check=False,
            capture_output=True,
            cwd=self.root,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)

    def _assert_active_snapshot_process_mutation_fences_before_publish(
        self,
        mutation: str,
    ) -> None:
        artifact_bytes = f'{{"effect":"process-{mutation}"}}\n'.encode("utf-8")
        target_path = f"outputs/process-{mutation}.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id=f"effect-process-{mutation}",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            self._mutate_active_snapshot_history_from_process(mutation=mutation)

            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "snapshot history changed",
            ) as captured:
                session.publish(token)

        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_SNAPSHOT_HISTORY_CHANGED",
        )
        self.assertFalse((self.root / target_path).exists())

    def test_active_snapshot_process_mutations_fence_before_publish(self):
        """A separate process cannot replace, delete, link, or ABA active history."""

        for mutation in (
            "head-receipt-replacement",
            "expected-tip-aba",
            "receipt-delete",
            "manifest-object-delete",
            "snapshot-object-delete",
            "manifest-object-replacement",
            "snapshot-object-hard-link",
            "heads-parent-replacement",
            "heads-parent-delete",
            "heads-parent-type-replacement",
        ):
            with self.subTest(mutation=mutation):
                with self._independent_write_fixture() as fixture:
                    fixture._assert_active_snapshot_process_mutation_fences_before_publish(
                        mutation
                    )

    def test_active_snapshot_parent_delete_returns_typed_fence_when_root_stop_observation_is_unavailable(
        self,
    ) -> None:
        """A missing heads directory cannot turn a history fence into an interruption."""

        with self._independent_write_fixture() as fixture:
            fixture._assert_active_snapshot_process_mutation_fences_before_publish(
                "heads-parent-delete"
            )

    def test_clean_snapshot_writer_close_allows_a_new_coordinator_without_fencing(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-snapshot-writer-close-race",
            target_path="outputs/snapshot-writer-close-race.json",
            artifact_bytes=b'{"effect":"snapshot-writer-close-race"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)

        def open_coordinator():
            return authority_session.durable.DurableCoordinator.open(
                evidence.root,
                root_identity=evidence.root_identity,
                request_sha256=evidence.request_sha256,
                scope_sha256=evidence.scope_sha256,
                bounds_sha256=evidence.bounds_sha256,
                spec_identity=evidence.spec_identity,
                spec_sha256=evidence.spec_sha256,
                policy_identity=evidence.policy_identity,
                action=evidence.lifecycle_action,
                transition_guard=lambda: None,
                on_invalidate=lambda _error: None,
            )

        first = open_coordinator()
        try:
            first.close()
            second = open_coordinator()
            try:
                self.assertFalse(
                    (
                        self.root
                        / "_registry"
                        / "curation"
                        / "authority-runtime"
                        / "recovery-fences"
                        / "root-recovery-fence.json"
                    ).exists()
                )
            finally:
                second.close()
        finally:
            # close() is idempotent; retain cleanup even if a RED implementation
            # fails before the normal release path is available.
            first.close()

    def test_abrupt_snapshot_owner_exit_allows_a_clean_reopen(self):
        """An unclosed in-memory writer leaves no mutable bridge to fence."""

        identity = authority_session._canonical_root_identity(self.root)
        ready_read, ready_write = os.pipe()
        owner_pid = os.fork()
        if owner_pid == 0:
            try:
                os.close(ready_read)
                anchor = authority_snapshot._RootAnchor.open(
                    self.root,
                    expected_identity=identity,
                )
                authority_snapshot._DurableSnapshotStore.open(anchor)
                os.write(ready_write, b"r")
            except BaseException:
                os._exit(48)
            os._exit(47)

        os.close(ready_write)
        reopened: authority_snapshot._DurableSnapshotStore | None = None
        try:
            self.assertEqual(os.read(ready_read, 1), b"r")
            waited_pid, status = os.waitpid(owner_pid, 0)
            self.assertEqual(waited_pid, owner_pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 47)
            anchor = authority_snapshot._RootAnchor.open(
                self.root,
                expected_identity=identity,
            )
            reopened = authority_snapshot._DurableSnapshotStore.open(anchor)
            self.assertFalse(
                (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                    / "recovery-fences"
                    / "root-recovery-fence.json"
                ).exists()
            )
        finally:
            if reopened is not None:
                reopened.close()
            os.close(ready_read)

    def test_fork_survivor_cannot_hold_a_crashed_snapshot_writer_lease(self):
        """A grandchild never keeps its crashed parent's snapshot lease alive."""

        identity = authority_session._canonical_root_identity(self.root)
        ready_read, ready_write = os.pipe()
        release_read, release_write = os.pipe()
        done_read, done_write = os.pipe()
        owner_pid = os.fork()
        survivor_pid: int | None = None
        if owner_pid == 0:
            try:
                os.close(ready_read)
                os.close(release_write)
                os.close(done_read)
                anchor = authority_snapshot._RootAnchor.open(
                    self.root,
                    expected_identity=identity,
                )
                authority_snapshot._DurableSnapshotStore.open(anchor)
                survivor_pid = os.fork()
                if survivor_pid == 0:
                    try:
                        os.close(ready_write)
                        os.read(release_read, 1)
                        os.write(done_write, b"x")
                    finally:
                        os._exit(0)
                os.write(ready_write, str(survivor_pid).encode("ascii"))
            except BaseException:
                os._exit(48)
            os._exit(47)

        os.close(ready_write)
        os.close(release_read)
        os.close(done_write)
        reopened: authority_snapshot._DurableSnapshotStore | None = None
        try:
            survivor_value = os.read(ready_read, 32)
            self.assertTrue(survivor_value)
            survivor_pid = int(survivor_value.decode("ascii"))
            waited_pid, status = os.waitpid(owner_pid, 0)
            self.assertEqual(waited_pid, owner_pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 47)

            anchor = authority_snapshot._RootAnchor.open(
                self.root,
                expected_identity=identity,
            )
            reopened = authority_snapshot._DurableSnapshotStore.open(anchor)
            self.assertFalse(
                (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                    / "recovery-fences"
                    / "root-recovery-fence.json"
                ).exists()
            )
        finally:
            if reopened is not None:
                reopened.close()
            os.close(ready_read)
            try:
                os.write(release_write, b"x")
            except OSError:
                pass
            os.close(release_write)
            if survivor_pid is not None:
                self.assertEqual(os.read(done_read, 1), b"x")
            os.close(done_read)

    def test_fork_child_reopen_does_not_fence_a_healthy_parent_snapshot_writer(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-snapshot-fork-reopen",
            target_path="outputs/snapshot-fork-reopen.json",
            artifact_bytes=b'{"effect":"snapshot-fork-reopen"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)

        def open_coordinator():
            return authority_session.durable.DurableCoordinator.open(
                evidence.root,
                root_identity=evidence.root_identity,
                request_sha256=evidence.request_sha256,
                scope_sha256=evidence.scope_sha256,
                bounds_sha256=evidence.bounds_sha256,
                spec_identity=evidence.spec_identity,
                spec_sha256=evidence.spec_sha256,
                policy_identity=evidence.policy_identity,
                action=evidence.lifecycle_action,
                transition_guard=lambda: None,
                on_invalidate=lambda _error: None,
            )

        fence_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "recovery-fences"
            / "root-recovery-fence.json"
        )
        coordinator = open_coordinator()
        child_pid = os.fork()
        if child_pid == 0:
            try:
                try:
                    open_coordinator()
                except authority_runtime.AuthorityRuntimeError:
                    os._exit(0 if not fence_path.exists() else 48)
                os._exit(47)
            except BaseException:
                os._exit(49)

        try:
            waited_pid, status = os.waitpid(child_pid, 0)
            self.assertEqual(waited_pid, child_pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
            self.assertFalse(fence_path.exists())
        finally:
            coordinator.close()

        reopened = open_coordinator()
        reopened.close()

    def test_fork_child_close_rejects_before_touching_inherited_snapshot_store(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-snapshot-fork-close",
            target_path="outputs/snapshot-fork-close.json",
            artifact_bytes=b'{"effect":"snapshot-fork-close"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)
        coordinator = authority_session.durable.DurableCoordinator.open(
            evidence.root,
            root_identity=evidence.root_identity,
            request_sha256=evidence.request_sha256,
            scope_sha256=evidence.scope_sha256,
            bounds_sha256=evidence.bounds_sha256,
            spec_identity=evidence.spec_identity,
            spec_sha256=evidence.spec_sha256,
            policy_identity=evidence.policy_identity,
            action=evidence.lifecycle_action,
            transition_guard=lambda: None,
            on_invalidate=lambda _error: None,
        )
        original_store = coordinator._DurableCoordinator__snapshot_store
        inherited_store = mock.Mock()
        coordinator._DurableCoordinator__snapshot_store = inherited_store
        child_pid = os.fork()
        if child_pid == 0:
            try:
                try:
                    coordinator.close()
                except authority_runtime.AuthorityRuntimeError:
                    os._exit(0 if not inherited_store.close.called else 48)
                os._exit(47)
            except BaseException:
                os._exit(49)

        try:
            waited_pid, status = os.waitpid(child_pid, 0)
            self.assertEqual(waited_pid, child_pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
        finally:
            coordinator._DurableCoordinator__snapshot_store = original_store
            coordinator.close()

    def test_fork_child_write_session_exits_before_inherited_cleanup(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-snapshot-fork-write-session",
            target_path="outputs/snapshot-fork-write-session.json",
            artifact_bytes=b'{"effect":"snapshot-fork-write-session"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    session.prepare(effect)
                except BaseException:
                    os._exit(48)
                os._exit(47)

            waited_pid, status = os.waitpid(child_pid, 0)
            self.assertEqual(waited_pid, child_pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(
                os.WEXITSTATUS(status),
                authority_session._FORK_CHILD_EXIT_STATUS,
            )

        with authority_runtime.open_write(admitted):
            self.assertFalse(
                (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                    / "recovery-fences"
                    / "root-recovery-fence.json"
                ).exists()
            )

    def test_fork_child_exit_preserves_live_parent_writer_and_snapshot_lease(self):
        """A child exit neither closes nor poisons its parent's live writer."""

        artifact_bytes = b'{"effect":"fork-parent-continuity"}\n'
        target_path = "outputs/fork-parent-continuity.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-fork-parent-continuity",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        child_code = """
import os
import sys
from pathlib import Path

import mnemosyne
from mnemosyne_core.authority_runtime import AuthorityRuntimeError
from mnemosyne_core.authority_runtime import _durable_snapshot as snapshot


root = Path(sys.argv[1])
info = os.stat(root, follow_symlinks=False)
anchor = snapshot._RootAnchor.open(
    root,
    expected_identity=(info.st_dev, info.st_ino),
)
try:
    store = snapshot._DurableSnapshotStore.open(anchor)
except AuthorityRuntimeError as exc:
    if str(exc) == "durable snapshot writer is active":
        raise SystemExit(0)
    raise SystemExit(41)
else:
    store.close()
    raise SystemExit(42)
"""
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(SCRIPT_DIR)

        with authority_runtime.open_write(admitted) as session:
            child_pid = os.fork()
            if child_pid == 0:
                session.prepare(effect)
                os._exit(47)

            waited_pid, status = os.waitpid(child_pid, 0)
            self.assertEqual(waited_pid, child_pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(
                os.WEXITSTATUS(status),
                authority_session._FORK_CHILD_EXIT_STATUS,
            )
            busy_result = subprocess.run(
                [sys.executable, "-c", child_code, str(self.root)],
                check=False,
                capture_output=True,
                cwd=self.root,
                env=environment,
                text=True,
                timeout=10,
            )
            self.assertEqual(
                busy_result.returncode,
                0,
                msg=busy_result.stderr or busy_result.stdout,
            )

            token = session.prepare(effect)
            self.assertEqual(session.publish(token), effect.artifact_ref)
            self.assertEqual(session.finalize(token), effect.artifact_ref)

        self.assertEqual((self.root / target_path).read_bytes(), artifact_bytes)
        with authority_runtime.open_write(admitted):
            self.assertFalse(
                (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                    / "recovery-fences"
                    / "root-recovery-fence.json"
                ).exists()
            )

    def test_fork_child_context_exit_does_not_unwind_inherited_writer(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-snapshot-fork-context-exit",
            target_path="outputs/snapshot-fork-context-exit.json",
            artifact_bytes=b'{"effect":"snapshot-fork-context-exit"}\n',
        )

        def fork_inside_write_context() -> int | None:
            with authority_runtime.open_write(admitted):
                child_pid = os.fork()
                if child_pid == 0:
                    return None
                return child_pid

        child_pid = fork_inside_write_context()
        if child_pid is None:
            os._exit(47)
        waited_pid, status = os.waitpid(child_pid, 0)
        self.assertEqual(waited_pid, child_pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(
            os.WEXITSTATUS(status),
            authority_session._FORK_CHILD_EXIT_STATUS,
        )

    def _deferred_legacy_v1_canonical_database_replacement_preserves_lease_and_fences_reopen(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-canonical-database-replacement",
            target_path="outputs/canonical-database-replacement.json",
            artifact_bytes=b'{"effect":"canonical-database-replacement"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)
        bridge_parent = self.root / "canonical-database-replacement-bridge"
        bridge_parent.mkdir(mode=0o700)
        bridge_directory = bridge_parent / "bridge"

        def child_mkdtemp(*, prefix: str) -> str:
            self.assertEqual(prefix, "mnemosyne-durable-")
            bridge_directory.mkdir(mode=0o700)
            return str(bridge_directory)

        def open_coordinator():
            return authority_session.durable.DurableCoordinator.open(
                evidence.root,
                root_identity=evidence.root_identity,
                request_sha256=evidence.request_sha256,
                scope_sha256=evidence.scope_sha256,
                bounds_sha256=evidence.bounds_sha256,
                spec_identity=evidence.spec_identity,
                spec_sha256=evidence.spec_sha256,
                policy_identity=evidence.policy_identity,
                action=evidence.lifecycle_action,
                transition_guard=lambda: None,
                on_invalidate=lambda _error: None,
            )

        with mock.patch.object(
            authority_session.durable.tempfile,
            "mkdtemp",
            child_mkdtemp,
        ):
            coordinator = open_coordinator()
        canonical_database = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "authority-runtime.sqlite3"
        )
        replacement_database = canonical_database.with_name("replacement.sqlite3")
        source = sqlite3.connect(str(canonical_database))
        replacement = sqlite3.connect(str(replacement_database))
        try:
            source.backup(replacement)
        finally:
            replacement.close()
            source.close()
        replacement_database.chmod(0o600)
        os.replace(replacement_database, canonical_database)

        with self.assertRaisesRegex(
            authority_runtime.AuthorityRuntimeError,
            "durable database identity",
        ):
            coordinator.close()
        lease_directory = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "database-bridge-leases"
        )
        self.assertEqual(len(tuple(lease_directory.glob("*.json"))), 1)
        with self.assertRaisesRegex(
            authority_runtime.DurableRecoveryFenceRequired,
            "durable database bridge",
        ):
            open_coordinator()

    def _deferred_legacy_v1_bridge_open_oserror_becomes_a_typed_recovery_fence(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-bridge-open-oserror",
            target_path="outputs/bridge-open-oserror.json",
            artifact_bytes=b'{"effect":"bridge-open-oserror"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)

        with mock.patch.object(
            authority_session.durable._DurableDatabaseBridge,
            "verify_sqlite_path",
            side_effect=OSError("bridge stat failed"),
        ):
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "durable recovery state is unavailable",
            ):
                authority_session.durable.DurableCoordinator.open(
                    evidence.root,
                    root_identity=evidence.root_identity,
                    request_sha256=evidence.request_sha256,
                    scope_sha256=evidence.scope_sha256,
                    bounds_sha256=evidence.bounds_sha256,
                    spec_identity=evidence.spec_identity,
                    spec_sha256=evidence.spec_sha256,
                    policy_identity=evidence.policy_identity,
                    action=evidence.lifecycle_action,
                    transition_guard=lambda: None,
                    on_invalidate=lambda _error: None,
                )

    def _deferred_legacy_v1_bridge_directory_swap_preserves_lease_and_never_cleans_replacement(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-bridge-directory-swap",
            target_path="outputs/bridge-directory-swap.json",
            artifact_bytes=b'{"effect":"bridge-directory-swap"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)
        bridge_parent = self.root / "bridge-directory-swap"
        bridge_parent.mkdir(mode=0o700)
        bridge_directory = bridge_parent / "bridge"

        def child_mkdtemp(*, prefix: str) -> str:
            self.assertEqual(prefix, "mnemosyne-durable-")
            bridge_directory.mkdir(mode=0o700)
            return str(bridge_directory)

        def open_coordinator():
            return authority_session.durable.DurableCoordinator.open(
                evidence.root,
                root_identity=evidence.root_identity,
                request_sha256=evidence.request_sha256,
                scope_sha256=evidence.scope_sha256,
                bounds_sha256=evidence.bounds_sha256,
                spec_identity=evidence.spec_identity,
                spec_sha256=evidence.spec_sha256,
                policy_identity=evidence.policy_identity,
                action=evidence.lifecycle_action,
                transition_guard=lambda: None,
                on_invalidate=lambda _error: None,
            )

        with mock.patch.object(
            authority_session.durable.tempfile,
            "mkdtemp",
            child_mkdtemp,
        ):
            coordinator = open_coordinator()
        original_bridge = bridge_parent / "bridge-original"
        os.rename(bridge_directory, original_bridge)
        bridge_directory.mkdir(mode=0o700)
        replacement_target = bridge_directory / "authority-runtime.sqlite3"
        replacement_target.write_bytes(b"replacement database sentinel")
        replacement_target.chmod(0o600)
        try:
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "durable database bridge",
            ):
                coordinator.close()
            self.assertTrue(original_bridge.exists())
            self.assertTrue(bridge_directory.exists())
            self.assertEqual(
                replacement_target.read_bytes(),
                b"replacement database sentinel",
            )
            lease_directory = (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "database-bridge-leases"
            )
            self.assertEqual(len(tuple(lease_directory.glob("*.json"))), 1)
            self.assertFalse(
                (
                    self.root
                    / "_registry"
                    / "curation"
                    / "authority-runtime"
                    / "recovery-fences"
                    / "root-recovery-fence.json"
                ).exists()
            )
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryFenceRequired,
                "durable database bridge",
            ):
                open_coordinator()
        finally:
            # A failed close intentionally leaves the lease for the recovery fence.
            # The temp-root fixture owns the residual external bridge directories.
            pass

    def _deferred_legacy_v1_bridge_parent_swap_cleans_only_the_retained_original_alias(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-bridge-parent-swap",
            target_path="outputs/bridge-parent-swap.json",
            artifact_bytes=b'{"effect":"bridge-parent-swap"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)
        bridge_parent = self.root / "bridge-parent-swap"
        bridge_parent.mkdir(mode=0o700)
        bridge_directory = bridge_parent / "bridge"

        def child_mkdtemp(*, prefix: str) -> str:
            self.assertEqual(prefix, "mnemosyne-durable-")
            bridge_directory.mkdir(mode=0o700)
            return str(bridge_directory)

        def open_coordinator():
            return authority_session.durable.DurableCoordinator.open(
                evidence.root,
                root_identity=evidence.root_identity,
                request_sha256=evidence.request_sha256,
                scope_sha256=evidence.scope_sha256,
                bounds_sha256=evidence.bounds_sha256,
                spec_identity=evidence.spec_identity,
                spec_sha256=evidence.spec_sha256,
                policy_identity=evidence.policy_identity,
                action=evidence.lifecycle_action,
                transition_guard=lambda: None,
                on_invalidate=lambda _error: None,
            )

        with mock.patch.object(
            authority_session.durable.tempfile,
            "mkdtemp",
            child_mkdtemp,
        ):
            coordinator = open_coordinator()
        original_parent = self.root / "bridge-parent-swap-original"
        os.rename(bridge_parent, original_parent)
        bridge_parent.mkdir(mode=0o700)
        replacement_directory = bridge_parent / "bridge"
        replacement_directory.mkdir(mode=0o700)
        replacement_target = replacement_directory / "authority-runtime.sqlite3"
        replacement_target.write_bytes(b"replacement parent sentinel")
        replacement_target.chmod(0o600)

        coordinator.close()

        self.assertFalse((original_parent / "bridge").exists())
        self.assertEqual(
            replacement_target.read_bytes(),
            b"replacement parent sentinel",
        )
        reopened = open_coordinator()
        reopened.close()

    def _deferred_legacy_v1_bridge_parent_fsync_failure_preserves_a_fencing_lease(self):
        admitted, _effect = self._admit_durable_write_effect(
            effect_id="effect-bridge-parent-fsync",
            target_path="outputs/bridge-parent-fsync.json",
            artifact_bytes=b'{"effect":"bridge-parent-fsync"}\n',
        )
        evidence = authority_session._evidence_from_admitted(admitted)
        bridge_parent = self.root / "bridge-parent-fsync"
        bridge_parent.mkdir(mode=0o700)
        bridge_directory = bridge_parent / "bridge"

        def child_mkdtemp(*, prefix: str) -> str:
            self.assertEqual(prefix, "mnemosyne-durable-")
            bridge_directory.mkdir(mode=0o700)
            return str(bridge_directory)

        def open_coordinator():
            return authority_session.durable.DurableCoordinator.open(
                evidence.root,
                root_identity=evidence.root_identity,
                request_sha256=evidence.request_sha256,
                scope_sha256=evidence.scope_sha256,
                bounds_sha256=evidence.bounds_sha256,
                spec_identity=evidence.spec_identity,
                spec_sha256=evidence.spec_sha256,
                policy_identity=evidence.policy_identity,
                action=evidence.lifecycle_action,
                transition_guard=lambda: None,
                on_invalidate=lambda _error: None,
            )

        with mock.patch.object(
            authority_session.durable.tempfile,
            "mkdtemp",
            child_mkdtemp,
        ):
            coordinator = open_coordinator()
        original_fsync = authority_session.durable.os.fsync
        calls = 0

        def fail_parent_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("bridge parent fsync failed")
            original_fsync(descriptor)

        with mock.patch.object(
            authority_session.durable.os,
            "fsync",
            fail_parent_fsync,
        ):
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "bridge cleanup",
            ):
                coordinator.close()
        self.assertEqual(calls, 2)
        self.assertFalse(bridge_directory.exists())
        with self.assertRaisesRegex(
            authority_runtime.DurableRecoveryFenceRequired,
            "durable database bridge",
        ):
            open_coordinator()

    def test_prepare_revalidates_before_staging_publication(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepare-stage-revalidation",
            target_path="outputs/prepare-stage-revalidation.json",
            artifact_bytes=b'{"effect":"prepare-stage-revalidation"}\n',
        )
        original_registry = self.registry_path.read_bytes()
        paused_registry = original_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        replacement = self.registry_directory / "placement-map.prepare-stage-paused"
        paused = False

        def pause_after_prepared_row(point):
            nonlocal paused
            if point == "after-prepared-row" and not paused:
                replacement.write_bytes(paused_registry)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)
                paused = True

        with authority_runtime.open_write(admitted) as session:
            try:
                with mock.patch.object(
                    authority_session.durable,
                    "_run_checkpoint",
                    side_effect=pause_after_prepared_row,
                ):
                    with self.assertRaisesRegex(
                        authority_runtime.DurableRecoveryRequired,
                        "before staging publication",
                    ) as captured:
                        session.prepare(effect)
            finally:
                replacement.write_bytes(original_registry)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)

        self.assertTrue(paused)
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_ADMISSION_DRIFT",
        )
        self.assertEqual(
            self._durable_state(effect.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )
        stage = self._snapshot_stage_path(effect.effect_id)
        self.assertFalse(stage.exists())
        self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_publish_revalidates_before_final_target_publication(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-publish-prewrite-revalidation",
            target_path="outputs/publish-prewrite-revalidation.json",
            artifact_bytes=b'{"effect":"publish-prewrite-revalidation"}\n',
        )
        original_registry = self.registry_path.read_bytes()
        paused_registry = original_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        replacement = self.registry_directory / "placement-map.publish-prewrite-paused"
        original_verify_stage = (
            authority_session.durable.DurableCoordinator._verify_stage_or_block
        )
        paused = False

        def pause_after_stage_verification(coordinator, row):
            nonlocal paused
            raw = original_verify_stage(coordinator, row)
            if not paused:
                replacement.write_bytes(paused_registry)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)
                paused = True
            return raw

        with authority_runtime.open_write(admitted) as session:
            try:
                token = session.prepare(effect)
                with mock.patch.object(
                    authority_session.durable.DurableCoordinator,
                    "_verify_stage_or_block",
                    pause_after_stage_verification,
                ):
                    with self.assertRaisesRegex(
                        authority_runtime.DurableRecoveryRequired,
                        "before publication",
                    ) as captured:
                        session.publish(token)
            finally:
                replacement.write_bytes(original_registry)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)

        self.assertTrue(paused)
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_ADMISSION_DRIFT",
        )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )
        self.assertFalse((self.root / effect.target_relative_path).exists())

    def test_prepare_blocks_recovery_when_staging_publication_is_unavailable(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-staging-unavailable",
            target_path="outputs/staging-unavailable.json",
            artifact_bytes=b'{"effect":"staging-unavailable"}\n',
        )

        with authority_runtime.open_write(admitted) as session:
            original_publish = authority_session.durable._publish_exact_bytes

            def fail_staging_only(path, raw, *, label):
                if label == "durable staging artifact":
                    raise authority_runtime.AuthorityRuntimeError(
                        "staging publication is unavailable"
                    )
                return original_publish(path, raw, label=label)

            with mock.patch.object(
                authority_session.durable,
                "_publish_exact_bytes",
                side_effect=fail_staging_only,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "staging artifact",
                ) as captured:
                    session.prepare(effect)
            token = captured.exception.directive.token
            self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as repeated_in_same_session:
                session.publish(token)
            self.assertEqual(
                repeated_in_same_session.exception.directive,
                captured.exception.directive,
            )

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((
                effect.effect_id,
                authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
            ),),
        )
        self.assertFalse((self.root / effect.target_relative_path).exists())
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "blocked for recovery",
            ) as repeated:
                session.recover(token)
        self.assertEqual(
            repeated.exception.directive.continuation_identity,
            captured.exception.directive.continuation_identity,
        )
        self.assertEqual(
            repeated.exception.directive.observed_evidence_sha256,
            captured.exception.directive.observed_evidence_sha256,
        )

    def test_prepare_post_insert_lookup_fault_preserves_exact_retry_and_recovery(self):
        artifact_bytes = b'{"effect":"prepare-lookup-fault"}\n'
        target_path = "outputs/prepare-lookup-fault.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepare-lookup-fault",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        original_row = authority_session.durable.DurableCoordinator._row
        row_calls = 0

        def lose_first_post_insert_lookup(coordinator, effect_id):
            nonlocal row_calls
            if effect_id == effect.effect_id:
                row_calls += 1
                # prepare now re-checks after sealing its sidecars, before the
                # INSERT, so the post-insert lookup is the third observation.
                if row_calls == 3:
                    raise sqlite3.OperationalError("post-insert lookup unavailable")
            return original_row(coordinator, effect_id)

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_row",
                lose_first_post_insert_lookup,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "prepare state is unavailable",
                ) as captured:
                    session.prepare(effect)
            token = captured.exception.directive.token
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "write session is not active; durable recovery is required",
            ) as repeated_in_same_session:
                session.publish(token)
            self.assertEqual(
                repeated_in_same_session.exception.directive,
                captured.exception.directive,
            )

        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )

        retry_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(retry_admitted) as session:
            self.assertEqual(session.prepare(effect), token)

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )
        self.assertEqual((self.root / target_path).read_bytes(), artifact_bytes)

    def test_prepare_checkpoint_crash_reissues_the_exact_token_on_retry(self):
        artifact_bytes = b'{"effect":"prepare-checkpoint-crash"}\n'
        target_path = "outputs/prepare-checkpoint-crash.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepare-checkpoint-crash",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_run_checkpoint",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(SimulatedDurableCrash())
                    if point == "after-prepare"
                    else None
                ),
            ):
                with self.assertRaises(SimulatedDurableCrash):
                    session.prepare(effect)

        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.PREPARED.value),),
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._snapshot_head_records()[-1]["effect_rows"],
            ((effect.effect_id, authority_runtime.DurableEffectState.FINALIZED.value),),
        )

    def test_prepare_never_issues_a_token_for_a_different_effect_with_a_claimed_id(self):
        admitted_a, effect_a = self._admit_durable_write_effect(
            effect_id="effect-claimed-identity",
            target_path="outputs/claimed-identity-a.json",
            artifact_bytes=b'{"effect":"claimed-identity-a"}\n',
        )
        admitted_b, effect_b = self._admit_durable_write_effect(
            effect_id="effect-claimed-identity",
            target_path="outputs/claimed-identity-b.json",
            artifact_bytes=b'{"effect":"claimed-identity-b"}\n',
        )

        with authority_runtime.open_write(admitted_a) as session:
            token_a = session.prepare(effect_a)
        with authority_runtime.open_write(admitted_b) as session:
            with self.assertRaises(
                authority_runtime.DurableRecoveryDenied,
            ) as captured:
                session.prepare(effect_b)
        self.assertEqual(captured.exception.reason_code, "RECOVERY_ADMISSION_MISMATCH")
        self.assertIn(
            "predecessor binding belongs to another admission",
            str(captured.exception),
        )

        self.assertEqual(
            self._durable_state(token_a.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )
        self.assertFalse((self.root / effect_b.target_relative_path).exists())

    def test_preexisting_target_requires_a_file_fsync_attestation_before_publish(self):
        artifact_bytes = b'{"effect":"preexisting-file-fsync"}\n'
        target_path = "outputs/preexisting-file-fsync.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-preexisting-file-fsync",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        target = self.root / target_path
        original_fsync = authority_session.durable.os.fsync

        def fail_target_file_fsync(descriptor):
            info = os.fstat(descriptor)
            try:
                target_info = os.stat(target, follow_symlinks=False)
            except FileNotFoundError:
                return original_fsync(descriptor)
            if (info.st_dev, info.st_ino) == (target_info.st_dev, target_info.st_ino):
                raise OSError("target file fsync attestation is unavailable")
            return original_fsync(descriptor)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(artifact_bytes)
            target.chmod(0o600)
            with mock.patch.object(
                authority_session.durable.os,
                "fsync",
                side_effect=fail_target_file_fsync,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "published readback is unavailable",
                ) as captured:
                    session.publish(token)

        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_DURABILITY_UNPROVEN",
        )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def test_publish_does_not_claim_published_before_directory_fsync_proof(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-publish-fsync-proof",
            target_path="outputs/publish-fsync-proof.json",
            artifact_bytes=b'{"effect":"publish-fsync-proof"}\n',
        )
        original_publish = authority_session.durable._publish_exact_bytes

        def publish_then_fail(path, raw, *, label):
            original_publish(path, raw, label=label)
            if label == "durable published artifact":
                raise authority_runtime.AuthorityRuntimeError(
                    "directory fsync proof is unavailable"
                )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with mock.patch.object(
                authority_session.durable,
                "_publish_exact_bytes",
                side_effect=publish_then_fail,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durability proof is unavailable",
                ) as captured:
                    session.publish(token)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_DURABILITY_UNPROVEN",
        )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )
        self.assertEqual(
            (self.root / effect.target_relative_path).read_bytes(),
            effect.artifact_bytes,
        )

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=effect.target_relative_path,
            artifact_bytes=effect.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.FINALIZED.value,
        )

    def _deferred_legacy_v1_recovery_blocks_a_tampered_persisted_policy_identity(self):
        artifact_bytes = b'{"effect":"policy-mismatch"}\n'
        target_path = "outputs/policy-mismatch.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-policy-mismatch",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        database_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "authority-runtime.sqlite3"
        )
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "UPDATE durable_effects SET policy_identity_sha256 = ? WHERE effect_id = ?",
                ("0" * 64, token.effect_id),
            )
            connection.commit()
        finally:
            connection.close()

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "identity does not match",
            ) as captured:
                session.recover(token)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_EVIDENCE_UNSAFE",
        )
        self.assertEqual(
            self._durable_state(effect.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )

    def _deferred_legacy_v1_post_admission_drift_blocks_an_authenticated_token_with_tampered_row_identity(
        self,
    ):
        artifact_bytes = b'{"effect":"drift-tampered-row"}\n'
        target_path = "outputs/drift-tampered-row.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-drift-tampered-row",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        database_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "authority-runtime.sqlite3"
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            connection = sqlite3.connect(str(database_path))
            try:
                connection.execute(
                    "UPDATE durable_effects SET policy_identity_sha256 = ? "
                    "WHERE effect_id = ?",
                    ("0" * 64, token.effect_id),
                )
                connection.commit()
            finally:
                connection.close()
            with mock.patch.object(
                session,
                "_WriteSession__revalidate",
                side_effect=authority_runtime.AuthorityRuntimeError(
                    "current policy identity changed"
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "current policy",
                ) as captured:
                    session.publish(token)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(
            captured.exception.directive.disposition,
            "blocked_recovery",
        )
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_EVIDENCE_UNSAFE",
        )
        self.assertEqual(
            self._durable_state(effect.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )

    def test_drifted_other_spec_cannot_block_an_authenticated_effect_token(self):
        admitted_a, effect_a = self._admit_durable_write_effect(
            effect_id="effect-other-spec-drift",
            target_path="outputs/other-spec-drift.json",
            artifact_bytes=b'{"effect":"other-spec-drift"}\n',
        )
        with authority_runtime.open_write(admitted_a) as session:
            token_a = session.prepare(effect_a)

        other_contract = operation_contract.AdmissionContract(
            spec_identity="test-other-write-v1",
            spec_sha256="e" * 64,
            operation_kind="test.other_write",
            allowed_actions=(operation_contract.LifecycleAction.APPLY,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.WRITE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        other_admitted = authority_runtime.admit(
            operation_contract.OperationRequest(
                schema_version=1,
                operation_kind="test.other_write",
                action=operation_contract.LifecycleAction.APPLY,
                claim_mode=operation_contract.ClaimMode.NONE,
                root=str(self.root),
                actor="operator",
                requested_authority=operation_contract.AuthorityMode.WRITE,
                payload={},
                bounds={},
            ),
            other_contract,
        )

        with authority_runtime.open_write(other_admitted) as session:
            with mock.patch.object(
                session,
                "_WriteSession__revalidate",
                side_effect=authority_runtime.AuthorityRuntimeError(
                    "current policy identity changed"
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryDenied,
                    "does not belong to this admission",
                ) as captured:
                    session.publish(token_a)
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "not active",
            ):
                session.prepare(effect_a)

        self.assertEqual(captured.exception.reason_code, "RECOVERY_ADMISSION_MISMATCH")
        self.assertEqual(
            self._durable_state(token_a.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def test_recovery_blocks_an_authenticated_token_after_policy_identity_drift(self):
        artifact_bytes = b'{"effect":"policy-identity-drift"}\n'
        target_path = "outputs/policy-identity-drift.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-policy-identity-drift",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        original_identity = authority_session.PolicyIdentity.from_approved_policy

        def shifted_identity(approved_policy):
            identity = original_identity(approved_policy)
            return authority_session.PolicyIdentity(
                raw_hash="0" * 64,
                full_hash=identity.full_hash,
                writer_control_hash=identity.writer_control_hash,
                foundation_hash=identity.foundation_hash,
                generation=identity.generation,
                source_kind=identity.source_kind,
                source_run_id=identity.source_run_id,
                guard_epoch=identity.guard_epoch,
            )

        with mock.patch.object(
            authority_session.PolicyIdentity,
            "from_approved_policy",
            side_effect=shifted_identity,
        ):
            recovery_admitted, _ = self._admit_durable_write_effect(
                effect_id=effect.effect_id,
                target_path=target_path,
                artifact_bytes=artifact_bytes,
                action=operation_contract.LifecycleAction.RECOVER,
            )
            with authority_runtime.open_write(recovery_admitted) as session:
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "different admission evidence",
                ) as captured:
                    session.recover(token)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(
            captured.exception.directive.disposition,
            "blocked_recovery",
        )
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_POLICY_MISMATCH",
        )
        self.assertEqual(
            self._durable_state(effect.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )

    def _deferred_legacy_v1_recovery_of_a_missing_durable_row_records_a_durable_blocker(self):
        artifact_bytes = b'{"effect":"missing-durable-row"}\n'
        target_path = "outputs/missing-durable-row.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-missing-durable-row",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        database_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "authority-runtime.sqlite3"
        )
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "DELETE FROM durable_effects WHERE effect_id = ?",
                (token.effect_id,),
            )
            connection.commit()
        finally:
            connection.close()

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "does not exist",
                ) as captured:
                    session.recover(token)
        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "blocked_recovery")
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_ROW_MISSING",
        )
        self.assertIsNone(captured.exception.directive.allowed_recovery_action)
        blocker_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "recovery-blockers"
            / f"{token.effect_id}.json"
        )
        self.assertTrue(blocker_path.is_file())
        self.assertEqual(os.stat(blocker_path).st_mode & 0o777, 0o600)
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "blocked for recovery",
            ) as repeated:
                session.recover(token)
        self.assertEqual(
            repeated.exception.directive.observed_evidence_sha256,
            captured.exception.directive.observed_evidence_sha256,
        )
        self.assertEqual(
            repeated.exception.directive.reason_code,
            captured.exception.directive.reason_code,
        )

    def _deferred_legacy_v1_missing_row_blocker_write_failure_keeps_the_exact_typed_continuation(self):
        artifact_bytes = b'{"effect":"missing-row-blocker-failure"}\n'
        target_path = "outputs/missing-row-blocker-failure.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-missing-row-blocker-failure",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        database_path = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "authority-runtime.sqlite3"
        )
        connection = sqlite3.connect(str(database_path))
        try:
            connection.execute(
                "DELETE FROM durable_effects WHERE effect_id = ?",
                (token.effect_id,),
            )
            connection.commit()
        finally:
            connection.close()

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with mock.patch.object(
                authority_session.durable,
                "_publish_exact_bytes",
                side_effect=authority_runtime.AuthorityRuntimeError(
                    "blocker persistence is unavailable"
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryFenceRequired,
                    "fence is unavailable",
                ) as captured:
                    session.recover(token)

        self.assertEqual(
            captured.exception.reason_code,
            "RECOVERY_FENCE_UNAVAILABLE",
        )

    def _assert_recovery_authority_loss_blocks_only_the_presented_effect(
        self,
        *,
        replace_key: bool,
    ) -> None:
        suffix = "replaced" if replace_key else "missing"
        admitted, origin = self._admit_durable_write_effect(
            effect_id=f"effect-token-key-{suffix}-origin",
            target_path=f"outputs/token-key-{suffix}-origin.json",
            artifact_bytes=f'{{"effect":"token-key-{suffix}-origin"}}\n'.encode(),
        )
        _, unrelated = self._admit_durable_write_effect(
            effect_id=f"effect-token-key-{suffix}-unrelated",
            target_path=f"outputs/token-key-{suffix}-unrelated.json",
            artifact_bytes=f'{{"effect":"token-key-{suffix}-unrelated"}}\n'.encode(),
        )
        with authority_runtime.open_write(admitted) as session:
            origin_token = session.prepare(origin)
        with authority_runtime.open_write(admitted) as session:
            unrelated_token = session.prepare(unrelated)

        runtime_directory = (
            self.root / "_registry" / "curation" / "authority-runtime"
        )
        key_path = runtime_directory / "recovery-token.key"
        if replace_key:
            key_path.write_bytes(b"r" * 32)
            key_path.chmod(0o600)
        else:
            key_path.unlink()
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=origin.effect_id,
            target_path=origin.target_relative_path,
            artifact_bytes=origin.artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )

        forged_token = authority_runtime.RecoveryToken(
            effect_id=origin_token.effect_id,
            request_sha256=origin_token.request_sha256,
            continuation_identity=origin_token.continuation_identity,
            authentication_tag=(
                ("0" if origin_token.authentication_tag[0] != "0" else "1")
                + origin_token.authentication_tag[1:]
            ),
        )
        self.assertNotEqual(forged_token, origin_token)
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaises(authority_runtime.DurableRecoveryDenied) as denied:
                session.recover(forged_token)
        self.assertEqual(denied.exception.reason_code, "RECOVERY_TOKEN_MISMATCH")

        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "authority is unavailable",
            ) as captured:
                session.recover(origin_token)

        directive = captured.exception.directive
        self.assertEqual(directive.token, origin_token)
        self.assertEqual(directive.disposition, "blocked_recovery")
        self.assertEqual(directive.reason_code, "RECOVERY_AUTHORITY_UNAVAILABLE")
        self.assertIsNone(directive.allowed_recovery_action)
        self.assertEqual(
            self._durable_state(origin_token.effect_id),
            authority_runtime.DurableEffectState.BLOCKED_RECOVERY.value,
        )
        self.assertEqual(
            self._durable_state(unrelated_token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )
        origin_blocker = (
            runtime_directory
            / "recovery-blockers"
            / f"{origin_token.effect_id}.json"
        )
        unrelated_blocker = (
            runtime_directory
            / "recovery-blockers"
            / f"{unrelated_token.effect_id}.json"
        )
        fence_path = (
            runtime_directory / "recovery-fences" / "root-recovery-fence.json"
        )
        self.assertTrue(origin_blocker.is_file())
        self.assertEqual(os.stat(origin_blocker).st_mode & 0o777, 0o600)
        self.assertFalse(unrelated_blocker.exists())
        self.assertFalse(fence_path.exists())

        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "blocked for recovery",
            ) as repeated:
                session.recover(origin_token)
        self.assertEqual(repeated.exception.directive, directive)
        self.assertEqual(
            self._durable_state(unrelated_token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )
        self.assertFalse(unrelated_blocker.exists())
        self.assertFalse(fence_path.exists())

    def _deferred_legacy_v1_missing_recovery_token_key_blocks_only_the_presented_effect(self):
        self._assert_recovery_authority_loss_blocks_only_the_presented_effect(
            replace_key=False,
        )

    def _deferred_legacy_v1_replaced_recovery_token_key_blocks_only_the_presented_effect(self):
        self._assert_recovery_authority_loss_blocks_only_the_presented_effect(
            replace_key=True,
        )

    def test_prepared_body_error_keeps_the_exact_recovery_directive(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-body-error",
            target_path="outputs/prepared-body-error.json",
            artifact_bytes=b'{"effect":"prepared-body-error"}\n',
        )
        body_error = RuntimeError("caller body failed")

        with self.assertRaises(authority_runtime.DurableRecoveryRequired) as captured:
            with authority_runtime.open_write(admitted) as session:
                token = session.prepare(effect)
                raise body_error

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertIs(captured.exception.__cause__, body_error)
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def test_prepared_cleanup_failure_keeps_the_exact_recovery_directive(self):
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-prepared-cleanup-error",
            target_path="outputs/prepared-cleanup-error.json",
            artifact_bytes=b'{"effect":"prepared-cleanup-error"}\n',
        )
        original_close = authority_session.durable.DurableCoordinator.close
        cleanup_error = RuntimeError("prepared coordinator cleanup failed")

        def fail_close(coordinator):
            original_close(coordinator)
            raise cleanup_error

        with mock.patch.object(
            authority_session.durable.DurableCoordinator,
            "close",
            fail_close,
        ):
            with self.assertRaises(authority_runtime.DurableRecoveryRequired) as captured:
                with authority_runtime.open_write(admitted) as session:
                    token = session.prepare(effect)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertIsInstance(
            captured.exception.__cause__,
            authority_runtime.AuthorityRuntimeError,
        )
        self.assertIs(captured.exception.__cause__.__cause__, cleanup_error)

    def test_recovery_restores_the_exact_payload_when_prepared_stage_is_absent(self):
        artifact_bytes = b'{"effect":"absent-prepared-effect"}\n'
        target_path = "outputs/absent-prepared-effect.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-absent-prepared-effect",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        stage_path = self._snapshot_stage_path(token.effect_id)
        stage_path.unlink()
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            self.assertEqual(session.recover(token), effect.artifact_ref)
        self.assertEqual(
            self._durable_state(effect.effect_id),
            authority_runtime.DurableEffectState.FINALIZED.value,
        )
        self.assertEqual((self.root / target_path).read_bytes(), artifact_bytes)

    def test_apply_session_cannot_invoke_recovery_or_manual_blocking(self):
        artifact_bytes = b'{"effect":"recovery-capability"}\n'
        target_path = "outputs/recovery-capability.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-recovery-capability",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            with self.assertRaisesRegex(
                authority_runtime.AuthorityRuntimeError,
                "recovery capability",
            ):
                session.recover(token)
            self.assertFalse(hasattr(session, "block_recovery"))

        self.assertFalse((self.root / target_path).exists())
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def test_recovery_session_cannot_prepare_publish_or_finalize(self):
        artifact_bytes = b'{"effect":"apply-capability"}\n'
        target_path = "outputs/apply-capability.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-apply-capability",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            for invoke in (
                lambda: session.prepare(effect),
                lambda: session.publish(token),
                lambda: session.finalize(token),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.AuthorityRuntimeError,
                    "apply capability",
                ):
                    invoke()

    def test_recovery_rejects_a_token_that_is_not_bound_to_the_persisted_row(self):
        artifact_bytes = b'{"effect":"forged-token"}\n'
        target_path = "outputs/forged-token.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-forged-token",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        forged = authority_runtime.RecoveryToken(
            effect_id=token.effect_id,
            request_sha256=token.request_sha256,
            continuation_identity="0" * 64,
            authentication_tag="0" * 64,
        )
        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryDenied,
                "token does not match",
            ) as captured:
                session.recover(forged)
        self.assertEqual(captured.exception.reason_code, "RECOVERY_TOKEN_MISMATCH")
        with authority_runtime.open_write(recovery_admitted) as session:
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryDenied,
                "token does not match",
            ) as repeated:
                session.recover(forged)
        self.assertEqual(repeated.exception.reason_code, "RECOVERY_TOKEN_MISMATCH")
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def test_write_session_never_replaces_an_outstanding_token_with_a_forged_one(self):
        artifact_bytes = b'{"effect":"outstanding-token"}\n'
        target_path = "outputs/outstanding-token.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-outstanding-token",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            forged = authority_runtime.RecoveryToken(
                effect_id=token.effect_id,
                request_sha256=token.request_sha256,
                continuation_identity="0" * 64,
                authentication_tag="0" * 64,
            )
            with self.assertRaisesRegex(
                authority_runtime.DurableRecoveryRequired,
                "does not match the outstanding effect",
            ) as captured:
                session.publish(forged)

        self.assertEqual(captured.exception.directive.token, token)
        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_TOKEN_MISMATCH",
        )
        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.PREPARED.value,
        )

    def test_recovery_snapshot_identity_failure_keeps_the_exact_typed_continuation(self):
        artifact_bytes = b'{"effect":"lookup-unavailable"}\n'
        target_path = "outputs/lookup-unavailable.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-lookup-unavailable",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)

        recovery_admitted, _ = self._admit_durable_write_effect(
            effect_id=effect.effect_id,
            target_path=target_path,
            artifact_bytes=artifact_bytes,
            action=operation_contract.LifecycleAction.RECOVER,
        )
        with authority_runtime.open_write(recovery_admitted) as session:
            with mock.patch.object(
                authority_snapshot._DurableSnapshotStore,
                "verify_canonical_database_identity",
                side_effect=authority_runtime.AuthorityRuntimeError(
                    "snapshot identity read unavailable"
                ),
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "durable snapshot state is unavailable",
                ) as captured:
                    session.recover(token)
        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(captured.exception.directive.token, token)

    def _deferred_legacy_v1_automatic_block_cas_never_overwrites_a_terminal_effect(self):
        artifact_bytes = b'{"effect":"block-cas"}\n'
        target_path = "outputs/block-cas.json"
        admitted, effect = self._admit_durable_write_effect(
            effect_id="effect-block-cas",
            target_path=target_path,
            artifact_bytes=artifact_bytes,
        )
        original_block = authority_session.durable.DurableCoordinator._block

        def finalize_before_block(coordinator, row):
            database_path = (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "authority-runtime.sqlite3"
            )
            connection = sqlite3.connect(str(database_path))
            try:
                connection.execute(
                    "UPDATE durable_effects SET state = ? WHERE effect_id = ?",
                    (authority_runtime.DurableEffectState.FINALIZED.value, row["effect_id"]),
                )
                connection.commit()
            finally:
                connection.close()
            return original_block(coordinator, row)

        with authority_runtime.open_write(admitted) as session:
            token = session.prepare(effect)
            original_read = authority_session.durable._try_read_verified_bytes
            target = self.root / target_path

            def read_invalid_artifact(path):
                if path == target:
                    return b"not-the-sealed-artifact"
                return original_read(path)

            with mock.patch.object(
                authority_session.durable,
                "_try_read_verified_bytes",
                side_effect=read_invalid_artifact,
            ), mock.patch.object(
                authority_session.durable.DurableCoordinator,
                "_block",
                finalize_before_block,
            ):
                with self.assertRaisesRegex(
                    authority_runtime.DurableRecoveryRequired,
                    "terminal",
                ) as captured:
                    session.publish(token)

        self.assertEqual(captured.exception.directive.disposition, "recoverable")
        self.assertEqual(
            captured.exception.directive.reason_code,
            "RECOVERY_STATE_CHANGED",
        )

        self.assertEqual(
            self._durable_state(token.effect_id),
            authority_runtime.DurableEffectState.FINALIZED.value,
        )
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "authority-runtime"
                / "recovery-blockers"
                / f"{token.effect_id}.json"
            ).exists()
        )


class D1aArtifactContractTest(unittest.TestCase):
    def test_sealed_reference_requires_canonical_bytes_and_exact_compatibility(self):
        schema = artifact_contract.SchemaIdentity(
            kind="TEST_ARTIFACT",
            version=1,
            schema_sha256="c" * 64,
        )
        artifact_bytes = b'{"artifact":"test"}\n'
        reference = artifact_contract.SealedArtifactRef(
            schema=schema,
            canonical_path="artifacts/test.json",
            artifact_sha256=sha256_bytes(artifact_bytes),
            manifest_sha256="d" * 64,
            producer_operation_sha256="e" * 64,
            byte_length=len(artifact_bytes),
            media_type="application/json",
        )
        manifest = artifact_contract.ArtifactManifest(
            schema=schema,
            artifact_refs=(reference,),
            metadata={"purpose": "d1a-test"},
        )

        self.assertEqual(reference.verify_bytes(artifact_bytes), reference)
        self.assertEqual(
            artifact_contract.SealedArtifactRef.from_canonical_bytes(
                reference.canonical_bytes
            ),
            reference,
        )
        self.assertEqual(manifest.artifact_refs, (reference,))
        self.assertEqual(reference.canonical_path, "artifacts/test.json")
        self.assertTrue(
            artifact_contract.compatibility.is_compatible(schema, schema)
        )
        self.assertFalse(
            artifact_contract.compatibility.is_compatible(
                schema,
                artifact_contract.SchemaIdentity(
                    kind="TEST_ARTIFACT",
                    version=2,
                    schema_sha256="c" * 64,
                ),
            )
        )
        with self.assertRaisesRegex(ValueError, "canonical sealed reference"):
            artifact_contract.SealedArtifactRef.from_canonical_bytes(
                b" " + reference.canonical_bytes
            )


class D1aOperationCatalogTest(unittest.TestCase):
    def test_catalog_owns_one_immutable_handler_and_admission_contract_per_row(self):
        def inspect_catalog(*_args, **_kwargs):
            return None

        def validate_request(*_args, **_kwargs):
            return None

        def validate_result(*_args, **_kwargs):
            return None

        contract = operation_contract.AdmissionContract(
            spec_identity="test-catalog-v1",
            spec_sha256="d" * 64,
            operation_kind="test.catalog",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.NONE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=False,
            prerequisite_artifacts=(),
        )
        spec = operation_control.OperationSpec(
            operation_kind="test.catalog",
            spec_identity="test-catalog-v1",
            spec_sha256="d" * 64,
            admission_contract=contract,
            source_module="mnemosyne_core.operation_control.catalog",
            source_path="operation_control/catalog.py",
            source_symbol="OperationSpec",
            source_sha256="f" * 64,
            handler=inspect_catalog,
            handler_module="mnemosyne_core.operation_control.handlers",
            handler_symbol="inspect_catalog",
            handler_sha256="e" * 64,
            availability=operation_control.OperationAvailability.AVAILABLE,
            availability_reason=None,
            request_validator=validate_request,
            result_validator=validate_result,
        )
        catalog = operation_control.OperationCatalog((spec,))

        self.assertIs(catalog.require_spec("test.catalog"), spec)
        with self.assertRaisesRegex(ValueError, "duplicate operation kind"):
            operation_control.OperationCatalog((spec, spec))
        blocked = operation_control.OperationSpec(
            operation_kind="test.catalog_blocked",
            spec_identity="test-catalog-blocked-v1",
            spec_sha256="a" * 64,
            admission_contract=operation_contract.AdmissionContract(
                spec_identity="test-catalog-blocked-v1",
                spec_sha256="a" * 64,
                operation_kind="test.catalog_blocked",
                allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
                allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
                authority_mode=operation_contract.AuthorityMode.NONE,
                scope_schema=(),
                bounds_schema=(),
                approval_required=False,
                prerequisite_artifacts=(),
            ),
            source_module="mnemosyne_core.operation_control.catalog",
            source_path="operation_control/catalog.py",
            source_symbol="OperationSpec",
            source_sha256="f" * 64,
            handler=None,
            handler_module=None,
            handler_symbol=None,
            handler_sha256=None,
            availability=operation_control.OperationAvailability.BLOCKED,
            availability_reason="policy-not-current",
        )
        self.assertIsNone(blocked.handler)
        with self.assertRaisesRegex(ValueError, "available operation requires exactly one handler"):
            operation_control.OperationSpec(
                operation_kind="test.catalog",
                spec_identity="test-catalog-v1",
                spec_sha256="d" * 64,
                admission_contract=contract,
                source_module="mnemosyne_core.operation_control.catalog",
                source_path="operation_control/catalog.py",
                source_symbol="OperationSpec",
                source_sha256="f" * 64,
                handler=None,
                handler_module="mnemosyne_core.operation_control.handlers",
                handler_symbol="inspect_catalog",
                handler_sha256="e" * 64,
                availability=operation_control.OperationAvailability.AVAILABLE,
                availability_reason=None,
            )


class D1aOperationOutcomeTest(unittest.TestCase):
    def test_only_canonical_outcome_variants_can_be_constructed(self):
        request_sha256 = "f" * 64
        facts = {"value": "fresh"}
        exact_scope = {"workstream_id": "example-service"}
        freshness = {
            "schema_version": 1,
            "request_sha256": request_sha256,
            "claim_mode": "CURRENT",
            "exact_scope": exact_scope,
            "scope_sha256": sha256_bytes(canonical_json_bytes(exact_scope)),
            "observation_started_at": "2026-07-16T00:00:00Z",
            "observation_completed_at": "2026-07-16T00:00:01Z",
            "planned_coverage": [],
            "observed_coverage": [],
            "coverage_complete": True,
            "dependencies": [],
            "consistency_groups": [],
            "facts_sha256": sha256_bytes(canonical_json_bytes(facts)),
            "status": "FRESH",
            "blockers": [],
        }

        completed = operation_contract.OperationOutcome.completed(request_sha256)
        completed_current = operation_contract.OperationOutcome.completed_current(
            request_sha256,
            facts,
            freshness,
        )
        blocked = operation_contract.OperationOutcome.blocked(
            request_sha256,
            reason_code="POLICY_NOT_CURRENT",
            next_safe_action="refresh",
        )
        recoverable = operation_contract.OperationOutcome.recoverable(
            request_sha256,
            recovery_owner="authority-runtime",
            continuation_identity="a" * 64,
            allowed_recovery_action="resume",
        )
        blocked_recovery = operation_contract.OperationOutcome.blocked_recovery(
            request_sha256,
            recovery_owner="authority-runtime",
            continuation_identity="b" * 64,
        )

        self.assertEqual(completed.outcome_kind, "completed")
        self.assertEqual(completed_current.outcome_kind, "completed_current")
        self.assertEqual(blocked.outcome_kind, "blocked")
        self.assertIsNone(blocked.facts)
        self.assertEqual(recoverable.outcome_kind, "recoverable")
        self.assertEqual(blocked_recovery.outcome_kind, "blocked_recovery")
        with self.assertRaises(TypeError):
            operation_contract.OperationOutcome()
        self.assertFalse(hasattr(operation_contract.OperationOutcome, "failed"))


class D1aAdmissionArtifactEvidenceTest(unittest.TestCase):
    def test_required_approval_and_prerequisite_evidence_are_exact_and_sealed(self):
        approval_requirement = operation_contract.ArtifactRequirement(
            kind="OPERATION_APPROVAL",
            version=1,
            schema_sha256="1" * 64,
        )
        prerequisite_requirement = operation_contract.ArtifactRequirement(
            kind="PREREQUISITE_EVIDENCE",
            version=1,
            schema_sha256="2" * 64,
        )
        approval_reference = artifact_contract.SealedArtifactRef(
            schema=artifact_contract.SchemaIdentity(
                kind=approval_requirement.kind,
                version=approval_requirement.version,
                schema_sha256=approval_requirement.schema_sha256,
            ),
            canonical_path="approvals/operation.json",
            artifact_sha256="3" * 64,
            manifest_sha256="6" * 64,
            producer_operation_sha256="7" * 64,
            byte_length=0,
            media_type="application/json",
        )
        prerequisite_reference = artifact_contract.SealedArtifactRef(
            schema=artifact_contract.SchemaIdentity(
                kind=prerequisite_requirement.kind,
                version=prerequisite_requirement.version,
                schema_sha256=prerequisite_requirement.schema_sha256,
            ),
            canonical_path="prerequisites/evidence.json",
            artifact_sha256="4" * 64,
            manifest_sha256="8" * 64,
            producer_operation_sha256="9" * 64,
            byte_length=0,
            media_type="application/json",
        )
        contract = operation_contract.AdmissionContract(
            spec_identity="test-evidence-v1",
            spec_sha256="5" * 64,
            operation_kind="test.evidence",
            allowed_actions=(operation_contract.LifecycleAction.INSPECT,),
            allowed_claim_modes=(operation_contract.ClaimMode.NONE,),
            authority_mode=operation_contract.AuthorityMode.NONE,
            scope_schema=(),
            bounds_schema=(),
            approval_required=True,
            prerequisite_artifacts=(prerequisite_requirement,),
            approval_requirement=approval_requirement,
        )
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.evidence",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root="/private/tmp/d1a-authority-runtime",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.NONE,
            payload={},
            bounds={},
            scope={},
            approval_artifact=approval_reference,
            prerequisite_artifacts=(prerequisite_reference,),
        )

        admitted = authority_runtime.admit(request, contract)

        self.assertEqual(admitted.request_sha256, request.sha256)
        missing_approval = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="test.evidence",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root="/private/tmp/d1a-authority-runtime",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.NONE,
            payload={},
            bounds={},
            scope={},
            approval_artifact=None,
            prerequisite_artifacts=(prerequisite_reference,),
        )
        with self.assertRaisesRegex(ValueError, "approval artifact"):
            authority_runtime.admit(missing_approval, contract)


if __name__ == "__main__":
    unittest.main()
