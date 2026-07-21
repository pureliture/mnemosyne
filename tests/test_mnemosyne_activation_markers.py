import dataclasses
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import (  # noqa: E402
    activation_contract,
    activation_foundation,
    activation_markers,
    control,
    ledger_schema,
    operation_contract,
)
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


_POST_ACTIVE_RECORD_NAMESPACES = (
    "safe-librarian",
    "canonical-curation-v1",
    "canonical-curation-v2",
)


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
    pending = [root]
    while pending:
        path = pending.pop()
        info = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        payload_sha256 = None
        link_target = None
        if stat.S_ISREG(info.st_mode):
            payload_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            link_target = os.readlink(path)
        elif stat.S_ISDIR(info.st_mode):
            pending.extend(sorted(path.iterdir(), reverse=True))
        captured.append(
            (
                relative,
                stat.S_IFMT(info.st_mode),
                stat.S_IMODE(info.st_mode),
                info.st_uid,
                info.st_nlink,
                info.st_size,
                payload_sha256,
                link_target,
            )
        )
    return tuple(sorted(captured))


def _root_identity(root: Path) -> str:
    info = os.stat(root, follow_symlinks=False)
    raw = json.dumps(
        {
            "canonical_path": str(root),
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    return hashlib.sha256(raw).hexdigest()


class _MarkerFixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(mode=0o700)
        self.registry = self.root / "_registry"
        self.registry.mkdir(mode=0o755)
        self.registry_raw = BASE_REGISTRY.replace(
            b"{root}", str(self.root).encode("utf-8")
        )
        self.registry_file = self.registry / "placement-map.yml"
        self.registry_file.write_bytes(self.registry_raw)
        self.registry_file.chmod(0o644)
        initial_policy = activation_foundation.compile_initial_policy(
            self.registry_raw,
            str(self.root),
        )
        self.request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="curation.activation",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={"activation_id": "act-0123456789abcdef0123456789abcdef"},
            payload={
                "allowed_namespace": "_registry/curation",
                "corpus_effect": "none",
                "initial_policy": initial_policy.as_dict(),
                "root_identity_sha256": _root_identity(self.root),
            },
            bounds={},
        )

    @property
    def curation(self) -> Path:
        return self.registry / "curation"

    @property
    def version(self) -> Path:
        return self.curation / "activation" / "v1"

    @property
    def staging(self) -> Path:
        return self.version / "staging"

    def make_prefix(self, depth: int = 4) -> None:
        paths = (
            self.curation,
            self.curation / "activation",
            self.version,
            self.staging,
        )
        for path in paths[:depth]:
            path.mkdir(mode=0o700)

    @staticmethod
    def write_owner_file(path: Path, raw: bytes = b"") -> None:
        path.write_bytes(raw)
        path.chmod(0o600)

    def seal_request(self, *, temporary: bool = False) -> Path:
        self.make_prefix()
        name = (
            f".request-{self.request.sha256}.tmp"
            if temporary
            else "request.json"
        )
        path = self.version / name
        self.write_owner_file(path, self.request.canonical_bytes)
        return path

    def make_locks(self, count: int = 2) -> None:
        for name in ("ledger.lock", "policy.lock")[:count]:
            self.write_owner_file(self.curation / name)

    def make_post_active_directory(self, name: str) -> Path:
        path = self.curation / name
        path.mkdir(mode=0o700)
        return path

    def make_staging_ledger(self, *, ready: bool) -> object | None:
        path = self.staging / "ledger.sqlite3"
        self.write_owner_file(path)
        if not ready:
            return None
        plan = activation_foundation.build_activation_foundation(
            self.registry_raw,
            str(self.root),
            self.request.scope["activation_id"],
        )
        return activation_foundation.initialize_activation_ledger(path, plan)

    def make_final_ledger(self) -> object:
        readback = self.make_staging_ledger(ready=True)
        os.rename(self.staging / "ledger.sqlite3", self.curation / "ledger.sqlite3")
        return readback

    def receipt_bytes(self, readback: object) -> bytes:
        initial_policy = dict(self.request.payload["initial_policy"])
        activation_id = self.request.scope["activation_id"]
        snapshot_id = activation_foundation.initial_snapshot_id(
            initial_policy["full_hash"]
        )
        receipt = {
            "schema": activation_contract.RECEIPT_SCHEMA.canonical_value,
            "kind": activation_contract.RECEIPT_SCHEMA.kind,
            "status": "ACTIVE",
            "activation_id": activation_id,
            "request_sha256": self.request.sha256,
            "actor": self.request.actor,
            "exact_root": str(self.root),
            "root_identity_sha256": self.request.payload[
                "root_identity_sha256"
            ],
            "allowed_namespace": "_registry/curation",
            "corpus_effect": "none",
            "initial_policy": initial_policy,
            "schema_identity": {
                "control": {
                    "applied_by": activation_id,
                    "schema_sha256": control.CONTROL_SCHEMA_SHA256,
                    "version": control.CONTROL_SCHEMA_VERSION,
                },
                "ledger": {
                    "applied_by": activation_contract.ACTIVATION_V2_SOURCE_ID,
                    "schema_sha256": ledger_schema.LEDGER_SCHEMA_SHA256,
                    "version": ledger_schema.LEDGER_SCHEMA_VERSION,
                },
            },
            "initial_snapshot_identity": {
                "foundation_hash": initial_policy["foundation_hash"],
                "full_hash": initial_policy["full_hash"],
                "generation": 1,
                "guard_epoch": 0,
                "snapshot_id": snapshot_id,
                "source_kind": "INITIAL",
                "source_run_id": activation_id,
                "state": "TERMINAL",
                "writer_control_hash": initial_policy["writer_control_hash"],
            },
            "write_set": activation_contract.activation_write_set(os.getuid()),
            "control_bootstrap_rows": 0,
            "legacy_evidence": False,
            "logical_readback_sha256": readback.sha256,
        }
        return canonical_json_bytes(receipt)

    def classify(
        self,
        incoming_request: operation_contract.OperationRequest | None = None,
    ) -> activation_markers.ActivationMarkerEvidence:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        registry_fd = os.open(self.registry, flags)
        try:
            return activation_markers.classify_activation_markers(
                registry_fd,
                self.root,
                incoming_request=incoming_request,
            )
        finally:
            os.close(registry_fd)


class ActivationMarkerClassifierTest(unittest.TestCase):
    def _exercise_state(
        self,
        setup,
        expected_state: activation_markers.ActivationMarkerState,
        expected_reason: activation_markers.ActivationReasonCode,
    ) -> activation_markers.ActivationMarkerEvidence:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            fixture = _MarkerFixture(Path(temporary) / "raw")
            setup_result = setup(fixture)
            before = _filesystem_snapshot(fixture.root)
            evidence = fixture.classify()
            self.assertEqual(_filesystem_snapshot(fixture.root), before)
            self.assertIs(evidence.state, expected_state)
            self.assertIs(evidence.reason_code, expected_reason)
            if setup_result == "request-bound":
                self.assertEqual(evidence.stored_request, fixture.request)
                self.assertEqual(
                    evidence.stored_request_bytes,
                    fixture.request.canonical_bytes,
                )
                self.assertEqual(
                    evidence.stored_request_sha256,
                    fixture.request.sha256,
                )
            else:
                self.assertIsNone(evidence.stored_request)
                self.assertIsNone(evidence.stored_request_bytes)
                self.assertIsNone(evidence.stored_request_sha256)
            return evidence

    def test_exact_marker_sequence_is_closed_and_read_only(self) -> None:
        def request_temp(fixture):
            fixture.seal_request(temporary=True)
            return "request-bound"

        def request_sealed(fixture):
            fixture.seal_request()
            return "request-bound"

        def ledger_lock_only(fixture):
            fixture.seal_request()
            fixture.make_locks(1)
            return "request-bound"

        def locks_ready(fixture):
            fixture.seal_request()
            fixture.make_locks()
            return "request-bound"

        def empty_staging(fixture):
            fixture.seal_request()
            fixture.make_locks()
            fixture.make_staging_ledger(ready=False)
            return "request-bound"

        def staging_ready(fixture):
            fixture.seal_request()
            fixture.make_locks()
            fixture.make_staging_ledger(ready=True)
            return "request-bound"

        def final_ready(fixture):
            fixture.seal_request()
            fixture.make_locks()
            fixture.make_final_ledger()
            return "request-bound"

        def receipt_temp(fixture):
            fixture.seal_request()
            fixture.make_locks()
            readback = fixture.make_final_ledger()
            raw = fixture.receipt_bytes(readback)
            fixture.write_owner_file(
                fixture.version
                / f".receipt-{hashlib.sha256(raw).hexdigest()}.tmp",
                raw,
            )
            return "request-bound"

        def active(fixture):
            fixture.seal_request()
            fixture.make_locks()
            readback = fixture.make_final_ledger()
            fixture.write_owner_file(
                fixture.version / "receipt.json",
                fixture.receipt_bytes(readback),
            )
            return "request-bound"

        cases = (
            (
                "fresh",
                lambda fixture: None,
                activation_markers.ActivationMarkerState.FRESH,
                activation_markers.ActivationReasonCode.FRESH_CURATION_STATE,
            ),
            (
                "request-temp",
                request_temp,
                activation_markers.ActivationMarkerState.REQUEST_TEMP,
                activation_markers.ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            ),
            (
                "request-sealed",
                request_sealed,
                activation_markers.ActivationMarkerState.REQUEST_SEALED,
                activation_markers.ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            ),
            (
                "ledger-lock-only",
                ledger_lock_only,
                activation_markers.ActivationMarkerState.LEDGER_LOCK_ONLY,
                activation_markers.ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            ),
            (
                "locks-ready",
                locks_ready,
                activation_markers.ActivationMarkerState.LOCKS_READY,
                activation_markers.ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            ),
            (
                "empty-staging-ledger",
                empty_staging,
                activation_markers.ActivationMarkerState.EMPTY_STAGING_LEDGER,
                activation_markers.ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            ),
            (
                "staging-ledger-ready",
                staging_ready,
                activation_markers.ActivationMarkerState.STAGING_LEDGER_READY,
                activation_markers.ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            ),
            (
                "final-ledger-ready",
                final_ready,
                activation_markers.ActivationMarkerState.FINAL_LEDGER_READY,
                activation_markers.ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            ),
            (
                "receipt-temp",
                receipt_temp,
                activation_markers.ActivationMarkerState.RECEIPT_TEMP,
                activation_markers.ActivationReasonCode.RECOVERY_SAME_REQUEST_ONLY,
            ),
            (
                "active",
                active,
                activation_markers.ActivationMarkerState.ACTIVE,
                activation_markers.ActivationReasonCode.ALREADY_ACTIVE,
            ),
        )
        for label, setup, state, reason in cases:
            with self.subTest(label=label):
                self._exercise_state(setup, state, reason)

    def test_every_exact_empty_prefix_is_a_preseal_orphan(self) -> None:
        for depth in range(1, 5):
            with self.subTest(depth=depth):
                self._exercise_state(
                    lambda fixture, depth=depth: fixture.make_prefix(depth),
                    activation_markers.ActivationMarkerState.PRESEAL_ORPHAN,
                    activation_markers.ActivationReasonCode.PRESEAL_ORPHAN,
                )

    def test_owner_only_post_active_record_namespaces_preserve_active_foundation(
        self,
    ) -> None:
        for name in _POST_ACTIVE_RECORD_NAMESPACES:
            with self.subTest(name=name):
                def active_with_record_namespace(fixture, name=name):
                    fixture.seal_request()
                    fixture.make_locks()
                    readback = fixture.make_final_ledger()
                    fixture.write_owner_file(
                        fixture.version / "receipt.json",
                        fixture.receipt_bytes(readback),
                    )
                    fixture.make_post_active_directory(name)
                    return "request-bound"

                self._exercise_state(
                    active_with_record_namespace,
                    activation_markers.ActivationMarkerState.ACTIVE,
                    activation_markers.ActivationReasonCode.ALREADY_ACTIVE,
                )

    def test_post_active_namespaces_require_an_active_foundation(self) -> None:
        for name in _POST_ACTIVE_RECORD_NAMESPACES:
            with self.subTest(name=name):
                def before_active(fixture, name=name):
                    fixture.seal_request()
                    fixture.make_post_active_directory(name)

                self._exercise_state(
                    before_active,
                    activation_markers.ActivationMarkerState.MANUAL_FENCE,
                    activation_markers.ActivationReasonCode.FOUNDATION_READBACK_FAILED,
                )

    def test_post_active_namespaces_reject_unsafe_shapes(self) -> None:
        for name in _POST_ACTIVE_RECORD_NAMESPACES:
            def regular_file(fixture, name=name):
                fixture.seal_request()
                fixture.write_owner_file(fixture.curation / name)

            def unsafe_mode(fixture, name=name):
                fixture.curation.mkdir(mode=0o700)
                path = fixture.make_post_active_directory(name)
                path.chmod(0o755)

            def symlink(fixture, name=name):
                fixture.curation.mkdir(mode=0o700)
                outside = fixture.root / "outside"
                outside.mkdir(mode=0o700)
                os.symlink(outside, fixture.curation / name)

            for shape, setup in (
                ("regular-file", regular_file),
                ("unsafe-mode", unsafe_mode),
                ("symlink", symlink),
            ):
                with self.subTest(name=name, shape=shape):
                    self._exercise_state(
                        setup,
                        activation_markers.ActivationMarkerState.MANUAL_FENCE,
                        activation_markers.ActivationReasonCode.UNSAFE_BOUNDARY,
                    )

    def test_arbitrary_curation_sibling_remains_unknown(self) -> None:
        def arbitrary_sibling(fixture):
            fixture.curation.mkdir(mode=0o700)
            fixture.write_owner_file(fixture.curation / "surprise.bin")

        self._exercise_state(
            arbitrary_sibling,
            activation_markers.ActivationMarkerState.MANUAL_FENCE,
            activation_markers.ActivationReasonCode.UNKNOWN_AUTHORITY_MEMBER,
        )

    def test_valid_legacy_is_distinct_and_activation_co_presence_fences(self) -> None:
        def legacy(fixture):
            fixture.write_owner_file(fixture.registry / "placement-map.lock", b"{}")

        self._exercise_state(
            legacy,
            activation_markers.ActivationMarkerState.LEGACY,
            activation_markers.ActivationReasonCode.LEGACY_AUTHORITY_PRESENT,
        )

        def co_present(fixture):
            legacy(fixture)
            fixture.make_prefix()

        self._exercise_state(
            co_present,
            activation_markers.ActivationMarkerState.MANUAL_FENCE,
            activation_markers.ActivationReasonCode.LEGACY_AUTHORITY_PRESENT,
        )

    def test_malformed_and_wrong_order_shapes_fail_closed_without_mutation(self) -> None:
        def unknown(fixture):
            fixture.make_prefix()
            fixture.write_owner_file(fixture.version / "surprise.bin", b"x")

        def wrong_order(fixture):
            fixture.curation.mkdir(mode=0o700)
            fixture.write_owner_file(fixture.curation / "policy.lock")

        def unsafe_mode(fixture):
            path = fixture.seal_request()
            path.chmod(0o644)

        def hard_link(fixture):
            path = fixture.seal_request()
            os.link(path, fixture.root / "request-copy.json")

        def journal(fixture):
            fixture.seal_request()
            fixture.make_locks()
            fixture.make_staging_ledger(ready=True)
            fixture.write_owner_file(fixture.staging / "ledger.sqlite3-journal")

        cases = (
            (
                "unknown",
                unknown,
                activation_markers.ActivationReasonCode.UNKNOWN_AUTHORITY_MEMBER,
            ),
            (
                "wrong-order",
                wrong_order,
                activation_markers.ActivationReasonCode.FOUNDATION_READBACK_FAILED,
            ),
            (
                "unsafe-mode",
                unsafe_mode,
                activation_markers.ActivationReasonCode.UNSAFE_BOUNDARY,
            ),
            (
                "hard-link",
                hard_link,
                activation_markers.ActivationReasonCode.UNSAFE_BOUNDARY,
            ),
            (
                "journal",
                journal,
                activation_markers.ActivationReasonCode.UNKNOWN_AUTHORITY_MEMBER,
            ),
        )
        for label, setup, reason in cases:
            with self.subTest(label=label):
                self._exercise_state(
                    setup,
                    activation_markers.ActivationMarkerState.MANUAL_FENCE,
                    reason,
                )

    def test_symlink_boundary_is_not_followed(self) -> None:
        def symlink(fixture):
            outside = fixture.root / "outside"
            outside.mkdir(mode=0o700)
            os.symlink(outside, fixture.curation)

        self._exercise_state(
            symlink,
            activation_markers.ActivationMarkerState.MANUAL_FENCE,
            activation_markers.ActivationReasonCode.UNSAFE_BOUNDARY,
        )

    def test_request_policy_drift_and_noncanonical_temp_fence(self) -> None:
        def policy_drift(fixture):
            fixture.seal_request()
            fixture.registry_file.write_bytes(fixture.registry_raw + b"\n")
            fixture.registry_file.chmod(0o644)

        def malformed_temp(fixture):
            fixture.make_prefix()
            fixture.write_owner_file(
                fixture.version / (".request-" + "0" * 64 + ".tmp"),
                b"{}",
            )

        for label, setup in (
            ("policy-drift", policy_drift),
            ("malformed-temp", malformed_temp),
        ):
            with self.subTest(label=label):
                self._exercise_state(
                    setup,
                    activation_markers.ActivationMarkerState.MANUAL_FENCE,
                    activation_markers.ActivationReasonCode.FOUNDATION_READBACK_FAILED,
                )

    def test_incoming_request_mismatch_is_typed_for_partial_and_active(self) -> None:
        for active in (False, True):
            with self.subTest(active=active), tempfile.TemporaryDirectory(
                dir="/private/tmp"
            ) as temporary:
                fixture = _MarkerFixture(Path(temporary) / "raw")
                fixture.seal_request()
                if active:
                    fixture.make_locks()
                    readback = fixture.make_final_ledger()
                    fixture.write_owner_file(
                        fixture.version / "receipt.json",
                        fixture.receipt_bytes(readback),
                    )
                other = operation_contract.OperationRequest(
                    schema_version=fixture.request.schema_version,
                    operation_kind=fixture.request.operation_kind,
                    action=fixture.request.action,
                    claim_mode=fixture.request.claim_mode,
                    root=fixture.request.root,
                    actor="another-operator",
                    requested_authority=fixture.request.requested_authority,
                    scope=dict(fixture.request.scope),
                    payload=json.loads(
                        fixture.request.canonical_bytes.decode("utf-8")
                    )["payload"],
                    bounds={},
                )
                before = _filesystem_snapshot(fixture.root)
                evidence = fixture.classify(other)
                self.assertEqual(_filesystem_snapshot(fixture.root), before)
                self.assertIs(
                    evidence.state,
                    activation_markers.ActivationMarkerState.MANUAL_FENCE,
                )
                self.assertIs(
                    evidence.reason_code,
                    (
                        activation_markers.ActivationReasonCode.ALREADY_ACTIVE_DIFFERENT_REQUEST
                        if active
                        else activation_markers.ActivationReasonCode.REQUEST_MISMATCH
                    ),
                )
                self.assertEqual(evidence.stored_request, fixture.request)

    def test_evidence_is_typed_immutable_and_contains_no_open_handle(self) -> None:
        fields = {field.name for field in dataclasses.fields(
            activation_markers.ActivationMarkerEvidence
        )}
        self.assertEqual(
            fields,
            {
                "state",
                "reason_code",
                "stored_request",
                "stored_request_bytes",
                "stored_request_sha256",
                "receipt_sha256",
            },
        )
        self.assertTrue(
            issubclass(activation_markers.ActivationMarkerState, str)
        )
        self.assertTrue(
            issubclass(activation_markers.ActivationReasonCode, str)
        )


if __name__ == "__main__":
    unittest.main()
