import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import operation_contract  # noqa: E402
from mnemosyne_core.authority_runtime import activation as activation_runtime  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402
from mnemosyne_core.operation_control import execution  # noqa: E402


def setUpModule() -> None:
    """Rebind after the facade's discovery-time verified bootstrap reset."""

    global mnemosyne, operation_contract, activation_runtime
    global canonical_json_bytes, execution
    import mnemosyne as current_facade
    from mnemosyne_core import operation_contract as current_operation_contract
    from mnemosyne_core.authority_runtime import (
        activation as current_activation_runtime,
    )
    from mnemosyne_core.canonical_json import (
        canonical_json_bytes as current_canonical_json_bytes,
    )
    from mnemosyne_core.operation_control import execution as current_execution

    mnemosyne = current_facade
    operation_contract = current_operation_contract
    activation_runtime = current_activation_runtime
    canonical_json_bytes = current_canonical_json_bytes
    execution = current_execution


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


class _InjectedCrash(BaseException):
    pass


class ActivationRecoveryTest(unittest.TestCase):
    def _fresh_root_and_request(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, operation_contract.OperationRequest]:
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        root = (Path(temporary.name) / "raw").resolve()
        registry = root / "_registry"
        registry.mkdir(parents=True, mode=0o755)
        registry_raw = BASE_REGISTRY.replace(
            b"{root}", str(root).encode("utf-8")
        )
        placement = registry / "placement-map.yml"
        placement.write_bytes(registry_raw)
        placement.chmod(0o644)
        audit = activation_runtime.capture_audit_evidence(root)
        assert audit.initial_policy is not None
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="curation.activation",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            scope={"activation_id": "act-0123456789abcdef0123456789abcdef"},
            payload={
                "allowed_namespace": "_registry/curation",
                "corpus_effect": "none",
                "initial_policy": audit.initial_policy.as_dict(),
                "root_identity_sha256": audit.root_identity_sha256,
            },
            bounds={},
        )
        return temporary, root, request

    @staticmethod
    def _different_request(
        request: operation_contract.OperationRequest,
    ) -> operation_contract.OperationRequest:
        value = json.loads(request.canonical_bytes.decode("utf-8"))
        value["actor"] = "different-operator"
        return operation_contract.codec.decode_operation_request(
            canonical_json_bytes(value)
        )

    @staticmethod
    def _decode_outcome(raw: bytes) -> dict[str, object]:
        value = json.loads(raw.decode("utf-8"))
        if type(value) is not dict:
            raise AssertionError("operation outcome must be an object")
        return value

    @staticmethod
    def _filesystem_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
        captured = []
        pending = [root]
        while pending:
            path = pending.pop()
            info = os.lstat(path)
            relative = "." if path == root else path.relative_to(root).as_posix()
            digest = None
            if stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
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
                    digest,
                )
            )
        return tuple(sorted(captured))

    def test_request_temp_crash_continues_only_the_same_request(self) -> None:
        temporary, root, request = self._fresh_root_and_request()
        self.addCleanup(temporary.cleanup)

        def crash_after_request_temp(boundary: str) -> None:
            if boundary == "A3_TEMP":
                raise _InjectedCrash

        with mock.patch.object(
            activation_runtime,
            "_checkpoint",
            side_effect=crash_after_request_temp,
        ):
            with self.assertRaises(_InjectedCrash):
                execution.execute_request_bytes(request.canonical_bytes)

        version = root / "_registry" / "curation" / "activation" / "v1"
        request_temp = version / f".request-{request.sha256}.tmp"
        self.assertEqual(request_temp.read_bytes(), request.canonical_bytes)
        self.assertFalse((version / "request.json").exists())

        completed = self._decode_outcome(
            execution.execute_request_bytes(request.canonical_bytes)
        )

        self.assertEqual(completed["outcome_kind"], "completed")
        self.assertEqual(completed["request_sha256"], request.sha256)
        self.assertFalse(request_temp.exists())
        self.assertEqual(
            {
                path.relative_to(root / "_registry" / "curation").as_posix()
                for path in (root / "_registry" / "curation").rglob("*")
            },
            {
                "activation",
                "activation/v1",
                "activation/v1/request.json",
                "activation/v1/receipt.json",
                "activation/v1/staging",
                "ledger.lock",
                "ledger.sqlite3",
                "policy.lock",
            },
        )
        for path in (root / "_registry" / "curation").rglob("*"):
            info = path.stat()
            if path.is_dir():
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            else:
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual(info.st_nlink, 1)

    def test_every_checkpoint_has_one_closed_continuation(self) -> None:
        checkpoints = (
            "A1_LOCKED",
            "A2",
            "A3_TEMP",
            "A3",
            "A4_LEDGER_LOCK",
            "A4",
            "A5_EMPTY",
            "A5",
            "A6",
            "A7",
            "A8_TEMP",
            "A8",
            "A9",
        )
        for checkpoint in checkpoints:
            with self.subTest(checkpoint=checkpoint):
                temporary, root, request = self._fresh_root_and_request()
                self.addCleanup(temporary.cleanup)

                def inject(boundary: str, *, target: str = checkpoint) -> None:
                    if boundary == target:
                        raise _InjectedCrash

                with mock.patch.object(
                    activation_runtime,
                    "_checkpoint",
                    side_effect=inject,
                ):
                    with self.assertRaises(_InjectedCrash):
                        execution.execute_request_bytes(request.canonical_bytes)

                interrupted = self._filesystem_snapshot(root)
                outcome = self._decode_outcome(
                    execution.execute_request_bytes(request.canonical_bytes)
                )
                if checkpoint == "A2":
                    self.assertEqual(outcome["outcome_kind"], "blocked")
                    self.assertEqual(outcome["reason_code"], "PRESEAL_ORPHAN")
                    self.assertEqual(self._filesystem_snapshot(root), interrupted)
                else:
                    self.assertEqual(
                        outcome["outcome_kind"],
                        "completed",
                        outcome,
                    )
                    self.assertEqual(outcome["request_sha256"], request.sha256)
                    self.assertTrue(
                        (
                            root
                            / "_registry"
                            / "curation"
                            / "activation"
                            / "v1"
                            / "receipt.json"
                        ).is_file()
                    )

    def test_policy_drift_stops_before_the_next_persistent_effect(self) -> None:
        temporary, root, request = self._fresh_root_and_request()
        self.addCleanup(temporary.cleanup)
        placement = root / "_registry" / "placement-map.yml"

        def change_policy_after_request(boundary: str) -> None:
            if boundary == "A3":
                placement.write_bytes(placement.read_bytes() + b"\n")
                placement.chmod(0o644)

        with mock.patch.object(
            activation_runtime,
            "_checkpoint",
            side_effect=change_policy_after_request,
        ):
            outcome = self._decode_outcome(
                execution.execute_request_bytes(request.canonical_bytes)
            )

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "POLICY_IDENTITY_CHANGED")
        curation = root / "_registry" / "curation"
        self.assertTrue(
            (curation / "activation" / "v1" / "request.json").is_file()
        )
        self.assertFalse((curation / "ledger.lock").exists())
        self.assertFalse((curation / "policy.lock").exists())
        self.assertFalse((curation / "ledger.sqlite3").exists())

    def test_root_replacement_is_a_typed_no_write_fence(self) -> None:
        temporary, root, request = self._fresh_root_and_request()
        self.addCleanup(temporary.cleanup)
        moved_root = root.parent / "moved-raw"

        def replace_root_after_lock(boundary: str) -> None:
            if boundary == "A1_LOCKED":
                os.rename(root, moved_root)
                root.mkdir(mode=0o700)

        with mock.patch.object(
            activation_runtime,
            "_checkpoint",
            side_effect=replace_root_after_lock,
        ):
            outcome = self._decode_outcome(
                execution.execute_request_bytes(request.canonical_bytes)
            )

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "ROOT_IDENTITY_CHANGED")
        self.assertFalse((moved_root / "_registry" / "curation").exists())
        self.assertEqual(tuple(root.iterdir()), ())

    def test_registry_replacement_is_a_typed_no_write_fence(self) -> None:
        temporary, root, request = self._fresh_root_and_request()
        self.addCleanup(temporary.cleanup)
        registry = root / "_registry"
        moved_registry = root / "moved-registry"

        def replace_registry_after_lock(boundary: str) -> None:
            if boundary == "A1_LOCKED":
                os.rename(registry, moved_registry)
                registry.mkdir(mode=0o700)
                replacement = registry / "placement-map.yml"
                replacement.write_bytes(
                    (moved_registry / "placement-map.yml").read_bytes()
                )
                replacement.chmod(0o644)

        with mock.patch.object(
            activation_runtime,
            "_checkpoint",
            side_effect=replace_registry_after_lock,
        ):
            outcome = self._decode_outcome(
                execution.execute_request_bytes(request.canonical_bytes)
            )

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "ROOT_IDENTITY_CHANGED")
        self.assertFalse((moved_registry / "curation").exists())
        self.assertFalse((registry / "curation").exists())

    def test_parent_swap_is_a_typed_no_write_fence(self) -> None:
        temporary, root, request = self._fresh_root_and_request()
        self.addCleanup(temporary.cleanup)
        original_parent = root.parent
        moved_parent = original_parent.with_name(original_parent.name + "-moved")
        self.addCleanup(shutil.rmtree, moved_parent, True)

        def swap_parent_after_lock(boundary: str) -> None:
            if boundary == "A1_LOCKED":
                os.rename(original_parent, moved_parent)
                original_parent.mkdir(mode=0o700)
                root.mkdir(mode=0o700)

        with mock.patch.object(
            activation_runtime,
            "_checkpoint",
            side_effect=swap_parent_after_lock,
        ):
            outcome = self._decode_outcome(
                execution.execute_request_bytes(request.canonical_bytes)
            )

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "ROOT_IDENTITY_CHANGED")
        self.assertFalse(
            (moved_parent / root.name / "_registry" / "curation").exists()
        )
        self.assertEqual(tuple(root.iterdir()), ())

    def test_wrong_request_never_claims_partial_or_active_state(self) -> None:
        for active in (False, True):
            with self.subTest(active=active):
                temporary, root, request = self._fresh_root_and_request()
                self.addCleanup(temporary.cleanup)
                if active:
                    completed = self._decode_outcome(
                        execution.execute_request_bytes(request.canonical_bytes)
                    )
                    self.assertEqual(completed["outcome_kind"], "completed")
                else:
                    def crash_after_request(boundary: str) -> None:
                        if boundary == "A3":
                            raise _InjectedCrash

                    with mock.patch.object(
                        activation_runtime,
                        "_checkpoint",
                        side_effect=crash_after_request,
                    ):
                        with self.assertRaises(_InjectedCrash):
                            execution.execute_request_bytes(request.canonical_bytes)
                before = self._filesystem_snapshot(root)

                outcome = self._decode_outcome(
                    execution.execute_request_bytes(
                        self._different_request(request).canonical_bytes
                    )
                )

                self.assertEqual(outcome["outcome_kind"], "blocked")
                self.assertEqual(
                    outcome["reason_code"],
                    (
                        "ALREADY_ACTIVE_DIFFERENT_REQUEST"
                        if active
                        else "REQUEST_MISMATCH"
                    ),
                )
                self.assertEqual(self._filesystem_snapshot(root), before)

    def test_two_writers_have_one_winner_and_one_typed_busy_result(self) -> None:
        temporary, _root, request = self._fresh_root_and_request()
        self.addCleanup(temporary.cleanup)
        winner_locked = threading.Event()
        release_winner = threading.Event()
        result: dict[str, dict[str, object]] = {}

        def hold_winner(boundary: str) -> None:
            if (
                boundary == "A1_LOCKED"
                and threading.current_thread().name == "activation-winner"
            ):
                winner_locked.set()
                if not release_winner.wait(timeout=5):
                    raise AssertionError("winner release timed out")

        def run_winner() -> None:
            result["winner"] = self._decode_outcome(
                execution.execute_request_bytes(request.canonical_bytes)
            )

        with mock.patch.object(
            activation_runtime,
            "_checkpoint",
            side_effect=hold_winner,
        ):
            winner = threading.Thread(
                target=run_winner,
                name="activation-winner",
                daemon=True,
            )
            winner.start()
            self.assertTrue(winner_locked.wait(timeout=5))
            result["loser"] = self._decode_outcome(
                execution.execute_request_bytes(request.canonical_bytes)
            )
            release_winner.set()
            winner.join(timeout=5)
            self.assertFalse(winner.is_alive())

        self.assertEqual(result["winner"]["outcome_kind"], "completed")
        self.assertEqual(result["loser"]["outcome_kind"], "blocked")
        self.assertEqual(result["loser"]["reason_code"], "WRITER_BUSY")

    def test_no_replace_collision_never_overwrites_the_existing_member(self) -> None:
        temporary, root, request = self._fresh_root_and_request()
        self.addCleanup(temporary.cleanup)
        collision_bytes = b"independent-writer\n"

        def occupy_final_request(boundary: str) -> None:
            if boundary == "A3_TEMP":
                path = (
                    root
                    / "_registry"
                    / "curation"
                    / "activation"
                    / "v1"
                    / "request.json"
                )
                path.write_bytes(collision_bytes)
                path.chmod(0o600)

        with mock.patch.object(
            activation_runtime,
            "_checkpoint",
            side_effect=occupy_final_request,
        ):
            outcome = self._decode_outcome(
                execution.execute_request_bytes(request.canonical_bytes)
            )

        version = root / "_registry" / "curation" / "activation" / "v1"
        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "PUBLICATION_COLLISION")
        self.assertEqual((version / "request.json").read_bytes(), collision_bytes)
        self.assertEqual(
            (version / f".request-{request.sha256}.tmp").read_bytes(),
            request.canonical_bytes,
        )
        self.assertFalse((root / "_registry" / "curation" / "ledger.lock").exists())


if __name__ == "__main__":
    unittest.main()
