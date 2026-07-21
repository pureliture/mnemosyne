import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import control  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


class ControlBootstrapTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.registry_directory = self.root / "_registry"
        self.registry_directory.mkdir(mode=0o700)
        self.registry_path = self.registry_directory / "placement-map.yml"
        self.registry_path.write_bytes(b"schema_version: 1\nworkstreams: []\n")
        self.registry_path.chmod(0o644)

        self.migration_id = "lockmig-20260715T000000Z-000000000001"
        self.placement_lock = self.registry_directory / "placement-map.lock"
        lock_payload = {
            "schema_version": 1,
            "kind": "PLACEMENT_COORDINATION_LOCK",
            "migration_id": self.migration_id,
            "placement_lock_protocol_version": "placement-lock-v1",
        }
        self.placement_lock.write_bytes(canonical_json_bytes(lock_payload))
        self.placement_lock.chmod(0o600)

        completed_directory = (
            self.registry_directory
            / "lock-migrations"
            / "completed"
            / self.migration_id
        )
        completed_directory.mkdir(parents=True, mode=0o700)
        self.completed_result = completed_directory / "result.json"
        active_marker = self.registry_directory / "lock-migrations" / "active"
        result = {
            "schema_version": 1,
            "kind": "LOCK_MIGRATION_RESULT",
            "status": "COMPLETE",
            "migration_id": self.migration_id,
            "registry_sha256": hashlib.sha256(
                self.registry_path.read_bytes()
            ).hexdigest(),
            "placement_lock_protocol_version": "placement-lock-v1",
            "placement_lock": {
                "path": str(self.placement_lock),
                "sha256": hashlib.sha256(self.placement_lock.read_bytes()).hexdigest(),
                "mode": "0600",
                "uid": os.getuid(),
                "nlink": 1,
            },
            "paths": {
                "active_marker": str(active_marker),
                "completed_result": str(self.completed_result),
                "placement_lock": str(self.placement_lock),
            },
        }
        self.completed_result.write_bytes(canonical_json_bytes(result))
        self.completed_result.chmod(0o600)

    def tree_snapshot(self):
        snapshot = []
        for path in sorted(self.root.rglob("*")):
            info = path.lstat()
            relative = str(path.relative_to(self.root))
            if stat.S_ISREG(info.st_mode):
                snapshot.append(
                    (
                        relative,
                        stat.S_IMODE(info.st_mode),
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                    )
                )
            else:
                snapshot.append((relative, stat.S_IMODE(info.st_mode), None))
        return snapshot

    def test_preview_is_write_free_and_exactly_recomputable(self):
        before = self.tree_snapshot()

        first = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        second = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )

        self.assertEqual(first, second)
        self.assertEqual(self.tree_snapshot(), before)
        self.assertEqual(first["kind"], "CONTROL_BOOTSTRAP_PREVIEW")
        self.assertEqual(first["requested_by"], "requester")
        self.assertEqual(first["bootstrap_id"], first["preview_id"])
        self.assertEqual(first["completed_lock_migration"]["id"], self.migration_id)
        self.assertEqual(first["settings"]["staging_journal_mode"], "DELETE")
        self.assertEqual(first["settings"]["terminal_journal_mode"], "WAL")
        self.assertEqual(first["paths"]["final"], str(self.registry_directory / "curation"))
        self.assertFalse((self.registry_directory / "curation").exists())
        self.assertEqual(
            control.bootstrap_preview_sha256(first),
            hashlib.sha256(canonical_json_bytes(first)).hexdigest(),
        )

    def test_apply_publishes_complete_wal_ledger_with_policy_foundation(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        checkpoints = []

        result = control.apply_bootstrap_state(
            self.root,
            requested_by="requester",
            approved_by="approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=self.completed_result,
            checkpoint=checkpoints.append,
        )

        final = Path(preview["paths"]["final"])
        ledger = Path(preview["paths"]["final_ledger"])
        self.assertEqual(result["state"], "COMPLETE")
        self.assertEqual(result["bootstrap_id"], preview["bootstrap_id"])
        self.assertFalse(Path(preview["paths"]["staging"]).exists())
        self.assertTrue(final.is_dir())
        self.assertEqual(stat.S_IMODE(final.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o600)
        self.assertEqual(
            checkpoints,
            [
                "placement-lock-acquired",
                "staging-created",
                "ledger-lock-acquired",
                "manifest-published",
                "ledger-file-created",
                "prepared",
                "final-directory-published",
                "files-published",
                "wal-mode-enabled",
                "wal-ready",
                "complete",
            ],
        )

        connection = sqlite3.connect(str(ledger))
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertTrue(set(control.CONTROL_SCHEMA_TABLES).issubset(tables))
            indexes = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='index' AND name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(indexes, set(control.CONTROL_SCHEMA_INDEXES))
            triggers = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            self.assertEqual(triggers, set(control.CONTROL_SCHEMA_TRIGGERS))
            row = connection.execute(
                "SELECT state, requested_by, approved_by, logical_readback_sha256 "
                "FROM control_bootstraps WHERE bootstrap_id = ?",
                (preview["bootstrap_id"],),
            ).fetchone()
            self.assertEqual(row[:3], ("COMPLETE", "requester", "approver"))
            self.assertRegex(row[3], r"^[0-9a-f]{64}$")
            self.assertEqual(
                connection.execute(
                    "SELECT id, generation, state FROM policy_mutation_lane"
                ).fetchone(),
                (1, 0, "IDLE"),
            )
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM policy_head").fetchone()[0], 0)
        finally:
            connection.close()

        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(ledger) + suffix)
            if sidecar.exists():
                sidecar.unlink()
        verified = control.verify_complete_bootstrap(
            self.root,
            bootstrap_id=preview["bootstrap_id"],
        )
        self.assertEqual(verified, result)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(ledger) + suffix)
            if sidecar.exists():
                info = sidecar.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual(info.st_uid, os.getuid())
                self.assertEqual(info.st_nlink, 1)

    def test_schema_rejects_invalid_authority_shapes_and_immutable_mutation(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        result = control.apply_bootstrap_state(
            self.root,
            requested_by="requester",
            approved_by="approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=self.completed_result,
        )
        connection = sqlite3.connect(result["paths"]["ledger"])
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO policy_snapshots "
                    "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                    "normalized_policy_json, source_kind, source_run_id, source_state) "
                    "VALUES ('uppercase', ?, ?, ?, x'7b7d', 'INITIAL', 'run-upper', 'TERMINAL')",
                    ("A" * 64, "b" * 64, "c" * 64),
                )
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE policy_mutation_lane SET state = 'RESERVED' WHERE id = 1"
                )
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO policy_bootstrap_proposals "
                    "(proposal_id, proposal_generation, base_hash, semantic_hash, "
                    "expected_post_hash, payload_json, proposal_path, proposal_sha256, "
                    "requested_by, state) VALUES "
                    "('empty-actor', 1, ?, ?, ?, x'7b7d', '/proposal/empty', ?, '', 'PREPARED')",
                    ("a" * 64, "b" * 64, "c" * 64, "d" * 64),
                )
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO policy_bootstrap_proposals "
                    "(proposal_id, proposal_generation, base_hash, semantic_hash, "
                    "expected_post_hash, payload_json, proposal_path, proposal_sha256, "
                    "requested_by, state) VALUES "
                    "('tab-actor', 1, ?, ?, ?, x'7b7d', '/proposal/tab', ?, ?, 'PREPARED')",
                    ("a" * 64, "b" * 64, "c" * 64, "e" * 64, "\t"),
                )
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE control_bootstraps "
                    "SET wal_checkpoint_status = NULL WHERE state = 'COMPLETE'"
                )
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE control_bootstraps "
                    "SET logical_readback_sha256 = NULL WHERE state = 'COMPLETE'"
                )
            connection.rollback()
            connection.execute(
                "INSERT INTO policy_snapshots "
                "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                "normalized_policy_json, source_kind, source_run_id, source_state) "
                "VALUES ('immutable', ?, ?, ?, x'7b7d', 'INITIAL', 'run-immutable', 'TERMINAL')",
                ("a" * 64, "b" * 64, "c" * 64),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable policy_snapshots"):
                connection.execute(
                    "UPDATE policy_snapshots SET normalized_policy_json = x'5b5d' "
                    "WHERE snapshot_id = 'immutable'"
                )
            connection.rollback()
            connection.execute(
                "INSERT INTO policy_bootstrap_proposals "
                "(proposal_id, proposal_generation, base_hash, semantic_hash, "
                "expected_post_hash, payload_json, proposal_path, proposal_sha256, "
                "requested_by, state) VALUES "
                "('immutable-proposal', 1, ?, ?, ?, x'7b7d', '/proposal/immutable', ?, "
                "'requester', 'PREPARED')",
                ("a" * 64, "b" * 64, "c" * 64, "d" * 64),
            )
            connection.execute(
                "UPDATE policy_bootstrap_proposals SET state = 'PUBLISHED' "
                "WHERE proposal_id = 'immutable-proposal'"
            )
            connection.commit()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable policy_bootstrap_proposals",
            ):
                connection.execute(
                    "UPDATE policy_bootstrap_proposals SET payload_json = x'5b5d' "
                    "WHERE proposal_id = 'immutable-proposal'"
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable policy_bootstrap_proposals",
            ):
                connection.execute(
                    "DELETE FROM policy_bootstrap_proposals "
                    "WHERE proposal_id = 'immutable-proposal'"
                )
            connection.rollback()
            for snapshot_id, source_kind, source_run_id in (
                ("same-hash-initial", "INITIAL", "same-hash-run-initial"),
                ("same-hash-edit", "EDIT", "same-hash-run-edit"),
            ):
                connection.execute(
                    "INSERT INTO policy_snapshots "
                    "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                    "normalized_policy_json, source_kind, source_run_id, source_state) "
                    "VALUES (?, ?, ?, ?, x'7b7d', ?, ?, 'TERMINAL')",
                    (
                        snapshot_id,
                        "f" * 64,
                        "e" * 64,
                        "d" * 64,
                        source_kind,
                        source_run_id,
                    ),
                )
            connection.execute(
                "INSERT INTO policy_head "
                "(id, generation, full_hash, writer_control_hash, foundation_hash, "
                "source_kind, source_run_id, guard_epoch) "
                "VALUES (1, 1, ?, ?, ?, 'INITIAL', 'same-hash-run-initial', 0)",
                ("f" * 64, "e" * 64, "d" * 64),
            )
            connection.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE policy_head SET source_kind = 'EDIT' WHERE id = 1"
                )
            connection.rollback()
        finally:
            connection.close()

    def test_terminal_verifier_rejects_missing_wal_checkpoint_evidence(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        result = control.apply_bootstrap_state(
            self.root,
            requested_by="requester",
            approved_by="approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=self.completed_result,
        )
        connection = sqlite3.connect(result["paths"]["ledger"])
        try:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE control_bootstraps SET wal_checkpoint_status = NULL "
                "WHERE bootstrap_id = ?",
                (preview["bootstrap_id"],),
            )
            connection.commit()
        finally:
            connection.close()

        with mock.patch.object(
            control,
            "_verify_database_health",
            return_value=None,
        ), self.assertRaisesRegex(
            control.ControlBootstrapError,
            "WAL evidence",
        ):
            control.verify_complete_bootstrap(
                self.root,
                bootstrap_id=preview["bootstrap_id"],
            )

    def test_resume_completes_only_missing_steps_from_each_durable_state(self):
        class SimulatedCrash(Exception):
            pass

        for crash_at in (
            "manifest-published",
            "ledger-file-created",
            "prepared",
            "final-directory-published",
            "wal-mode-enabled",
            "files-published",
            "wal-ready",
        ):
            with self.subTest(crash_at=crash_at):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    original_root = self.root
                    original_registry_directory = self.registry_directory
                    original_registry_path = self.registry_path
                    original_placement_lock = self.placement_lock
                    original_completed_result = self.completed_result
                    try:
                        self.root = Path(temporary_directory).resolve()
                        self.registry_directory = self.root / "_registry"
                        self.registry_directory.mkdir(mode=0o700)
                        self.registry_path = self.registry_directory / "placement-map.yml"
                        self.registry_path.write_bytes(b"schema_version: 1\nworkstreams: []\n")
                        self.registry_path.chmod(0o644)
                        self.placement_lock = self.registry_directory / "placement-map.lock"
                        self.placement_lock.write_bytes(original_placement_lock.read_bytes())
                        self.placement_lock.chmod(0o600)
                        completed_directory = (
                            self.registry_directory
                            / "lock-migrations"
                            / "completed"
                            / self.migration_id
                        )
                        completed_directory.mkdir(parents=True, mode=0o700)
                        self.completed_result = completed_directory / "result.json"
                        completed = json.loads(original_completed_result.read_text(encoding="utf-8"))
                        completed["registry_sha256"] = hashlib.sha256(
                            self.registry_path.read_bytes()
                        ).hexdigest()
                        completed["placement_lock"] = {
                            **completed["placement_lock"],
                            "path": str(self.placement_lock),
                            "sha256": hashlib.sha256(
                                self.placement_lock.read_bytes()
                            ).hexdigest(),
                        }
                        completed["paths"] = {
                            **completed["paths"],
                            "active_marker": str(
                                self.registry_directory / "lock-migrations" / "active"
                            ),
                            "completed_result": str(self.completed_result),
                            "placement_lock": str(self.placement_lock),
                        }
                        self.completed_result.write_bytes(canonical_json_bytes(completed))
                        self.completed_result.chmod(0o600)

                        preview = control.preview_bootstrap_state(
                            self.root,
                            requested_by="requester",
                            completed_result_path=self.completed_result,
                        )

                        def crash(name):
                            if name == crash_at:
                                raise SimulatedCrash(name)

                        with self.assertRaisesRegex(SimulatedCrash, crash_at):
                            control.apply_bootstrap_state(
                                self.root,
                                requested_by="requester",
                                approved_by="approver",
                                preview_id=preview["preview_id"],
                                preview_sha256=control.bootstrap_preview_sha256(preview),
                                completed_result_path=self.completed_result,
                                checkpoint=crash,
                            )

                        resumed = control.resume_bootstrap_state(
                            self.root,
                            bootstrap_id=preview["bootstrap_id"],
                            resumed_by="resumer",
                            completed_result_path=self.completed_result,
                        )
                        self.assertEqual(resumed["state"], "COMPLETE")
                        self.assertEqual(
                            control.resume_bootstrap_state(
                                self.root,
                                bootstrap_id=preview["bootstrap_id"],
                                resumed_by="resumer",
                                completed_result_path=self.completed_result,
                            ),
                            resumed,
                        )
                    finally:
                        self.root = original_root
                        self.registry_directory = original_registry_directory
                        self.registry_path = original_registry_path
                        self.placement_lock = original_placement_lock
                        self.completed_result = original_completed_result

    def test_resume_reports_manual_blocker_after_staging_directory_only(self):
        class SimulatedCrash(Exception):
            pass

        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )

        def crash(name):
            if name == "staging-created":
                raise SimulatedCrash(name)

        with self.assertRaises(SimulatedCrash):
            control.apply_bootstrap_state(
                self.root,
                requested_by="requester",
                approved_by="approver",
                preview_id=preview["preview_id"],
                preview_sha256=control.bootstrap_preview_sha256(preview),
                completed_result_path=self.completed_result,
                checkpoint=crash,
            )
        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "manual blocker: control bootstrap manifest was not durably published",
        ):
            control.resume_bootstrap_state(
                self.root,
                bootstrap_id=preview["bootstrap_id"],
                resumed_by="resumer",
                completed_result_path=self.completed_result,
            )
        self.assertTrue(Path(preview["paths"]["staging"]).is_dir())
        self.assertFalse(Path(preview["paths"]["final"]).exists())

    def test_resume_reports_manual_blocker_after_ledger_lock_before_manifest(self):
        class SimulatedCrash(Exception):
            pass

        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )

        def crash(name):
            if name == "ledger-lock-acquired":
                raise SimulatedCrash(name)

        with self.assertRaises(SimulatedCrash):
            control.apply_bootstrap_state(
                self.root,
                requested_by="requester",
                approved_by="approver",
                preview_id=preview["preview_id"],
                preview_sha256=control.bootstrap_preview_sha256(preview),
                completed_result_path=self.completed_result,
                checkpoint=crash,
            )
        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "manual blocker: control bootstrap manifest was not durably published",
        ):
            control.resume_bootstrap_state(
                self.root,
                bootstrap_id=preview["bootstrap_id"],
                resumed_by="resumer",
                completed_result_path=self.completed_result,
            )
        self.assertTrue(Path(preview["paths"]["staging_ledger_lock"]).is_file())
        self.assertFalse(Path(preview["paths"]["staging_manifest"]).exists())

    def test_apply_rechecks_manifest_before_complete(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )

        def tamper(name):
            if name == "wal-ready":
                manifest = Path(preview["paths"]["final_manifest"])
                manifest.write_bytes(canonical_json_bytes({}))
                manifest.chmod(0o600)

        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "control bootstrap manifest changed before COMPLETE",
        ):
            control.apply_bootstrap_state(
                self.root,
                requested_by="requester",
                approved_by="approver",
                preview_id=preview["preview_id"],
                preview_sha256=control.bootstrap_preview_sha256(preview),
                completed_result_path=self.completed_result,
                checkpoint=tamper,
            )
        connection = sqlite3.connect(preview["paths"]["final_ledger"])
        try:
            state = connection.execute(
                "SELECT state FROM control_bootstraps WHERE bootstrap_id = ?",
                (preview["bootstrap_id"],),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(state, "WAL_READY")

    def test_control_exposes_manual_recovery_signal_for_facade_blocker_handling(self):
        from mnemosyne_core import safety

        self.assertIs(control.ManualRecoveryRequired, safety.ManualRecoveryRequired)
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        signal = safety.ManualRecoveryRequired(
            "rename requires recovery",
            source=Path(preview["paths"]["staging"]),
            target=Path(preview["paths"]["final"]),
            reason="test-rename-effect",
            expected_source_identity=(1, 2, stat.S_IFDIR),
            observed_target_identity=None,
        )
        with mock.patch.object(
            control.safety,
            "rename_path_no_replace",
            side_effect=signal,
        ):
            with self.assertRaises(control.ManualRecoveryRequired) as raised:
                control.apply_bootstrap_state(
                    self.root,
                    requested_by="requester",
                    approved_by="approver",
                    preview_id=preview["preview_id"],
                    preview_sha256=control.bootstrap_preview_sha256(preview),
                    completed_result_path=self.completed_result,
                )
        self.assertIs(raised.exception, signal)
        self.assertTrue(Path(preview["paths"]["staging"]).is_dir())
        self.assertFalse(Path(preview["paths"]["final"]).exists())

    def test_bootstrap_logical_evidence_survives_later_policy_state(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        result = control.apply_bootstrap_state(
            self.root,
            requested_by="requester",
            approved_by="approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=self.completed_result,
        )
        ledger = Path(result["paths"]["ledger"])
        digest = "a" * 64
        connection = sqlite3.connect(str(ledger))
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                "INSERT INTO policy_snapshots "
                "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                "normalized_policy_json, source_kind, source_run_id, source_state) "
                "VALUES (?, ?, ?, ?, ?, 'INITIAL', ?, 'TERMINAL')",
                ("snapshot-1", digest, "b" * 64, "c" * 64, b"{}", "policy-run-1"),
            )
            connection.execute(
                "INSERT INTO policy_head "
                "(id, generation, full_hash, writer_control_hash, foundation_hash, "
                "source_kind, source_run_id, guard_epoch) "
                "VALUES (1, 1, ?, ?, ?, 'INITIAL', ?, 0)",
                (digest, "b" * 64, "c" * 64, "policy-run-1"),
            )
            connection.execute(
                "UPDATE policy_mutation_lane SET generation = 2 WHERE id = 1"
            )
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(
            control.verify_complete_bootstrap(
                self.root,
                bootstrap_id=preview["bootstrap_id"],
            )["state"],
            "COMPLETE",
        )

    def test_structural_complete_survives_initial_policy_registry_postimage(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        result = control.apply_bootstrap_state(
            self.root,
            requested_by="requester",
            approved_by="approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=self.completed_result,
        )
        self.registry_path.write_bytes(
            self.registry_path.read_bytes()
            + b"curation:\n  movement_writer: legacy\n  structural_apply: disabled\n"
        )
        self.registry_path.chmod(0o644)

        self.assertEqual(
            control.verify_complete_bootstrap(
                self.root,
                bootstrap_id=result["bootstrap_id"],
            )["state"],
            "COMPLETE",
        )
        self.assertEqual(
            control.resume_bootstrap_state(
                self.root,
                bootstrap_id=result["bootstrap_id"],
                resumed_by="resumer",
                completed_result_path=self.completed_result,
            )["state"],
            "COMPLETE",
        )
        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "placement registry preimage changed",
        ):
            control.verify_bootstrap_registry_preimage(
                self.root,
                bootstrap_id=result["bootstrap_id"],
            )

    def test_database_open_rejects_ledger_inode_change_during_connect(self):
        ledger = self.root / "ledger.sqlite3"
        replacement = self.root / "replacement.sqlite3"
        for path in (ledger, replacement):
            connection = sqlite3.connect(str(path))
            connection.execute("CREATE TABLE marker (value TEXT NOT NULL)")
            connection.close()
            path.chmod(0o600)

        original_connect = sqlite3.connect
        returned_connection = None

        def replace_then_connect(path, *args, **kwargs):
            os.replace(replacement, ledger)
            return original_connect(path, *args, **kwargs)

        try:
            with mock.patch.object(
                control.sqlite3,
                "connect",
                side_effect=replace_then_connect,
            ):
                with self.assertRaisesRegex(
                    control.ControlBootstrapError,
                    "control ledger identity changed during open",
                ):
                    returned_connection = control._connect_database(ledger)
        finally:
            if returned_connection is not None:
                returned_connection.close()

    def test_database_open_rejects_parent_change_during_connect(self):
        control_root = self.root / "control-root"
        moved_root = self.root / "control-root-before-open"
        control_root.mkdir(mode=0o700)
        ledger = control_root / "ledger.sqlite3"
        connection = sqlite3.connect(str(ledger))
        connection.execute("CREATE TABLE marker (value TEXT NOT NULL)")
        connection.close()
        ledger.chmod(0o600)

        original_connect = sqlite3.connect
        returned_connection = None

        def replace_parent_then_connect(path, *args, **kwargs):
            os.rename(control_root, moved_root)
            control_root.mkdir(mode=0o700)
            os.rename(moved_root / ledger.name, ledger)
            return original_connect(path, *args, **kwargs)

        try:
            with mock.patch.object(
                control.sqlite3,
                "connect",
                side_effect=replace_parent_then_connect,
            ):
                with self.assertRaisesRegex(
                    control.ControlBootstrapError,
                    "control ledger parent identity changed during open",
                ):
                    returned_connection = control._connect_database(ledger)
        finally:
            if returned_connection is not None:
                returned_connection.close()

    def test_resume_rejects_corrupt_partial_database_without_repair(self):
        class SimulatedCrash(Exception):
            pass

        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )

        def crash(name):
            if name == "prepared":
                raise SimulatedCrash(name)

        with self.assertRaises(SimulatedCrash):
            control.apply_bootstrap_state(
                self.root,
                requested_by="requester",
                approved_by="approver",
                preview_id=preview["preview_id"],
                preview_sha256=control.bootstrap_preview_sha256(preview),
                completed_result_path=self.completed_result,
                checkpoint=crash,
            )
        ledger = Path(preview["paths"]["staging_ledger"])
        corrupted = b"not-a-sqlite-database\n" + ledger.read_bytes()[22:]
        ledger.write_bytes(corrupted)
        ledger.chmod(0o600)

        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "control ledger is corrupt",
        ):
            control.resume_bootstrap_state(
                self.root,
                bootstrap_id=preview["bootstrap_id"],
                resumed_by="resumer",
                completed_result_path=self.completed_result,
            )

        self.assertEqual(ledger.read_bytes(), corrupted)
        self.assertTrue(Path(preview["paths"]["staging"]).is_dir())
        self.assertFalse(Path(preview["paths"]["final"]).exists())

    def test_resume_rejects_sqlite_sidecar_symlink_without_touching_target(self):
        class SimulatedCrash(Exception):
            pass

        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )

        def crash(name):
            if name == "files-published":
                raise SimulatedCrash(name)

        with self.assertRaises(SimulatedCrash):
            control.apply_bootstrap_state(
                self.root,
                requested_by="requester",
                approved_by="approver",
                preview_id=preview["preview_id"],
                preview_sha256=control.bootstrap_preview_sha256(preview),
                completed_result_path=self.completed_result,
                checkpoint=crash,
            )
        ledger = Path(preview["paths"]["final_ledger"])
        with tempfile.TemporaryDirectory() as outside_directory:
            outside = Path(outside_directory).resolve() / "outside.db-wal"
            outside.write_bytes(b"outside-must-remain-unchanged\n")
            sidecar = Path(str(ledger) + "-wal")
            sidecar.symlink_to(outside)

            with self.assertRaisesRegex(
                control.ControlBootstrapError,
                "SQLite sidecar is unsafe",
            ):
                control.resume_bootstrap_state(
                    self.root,
                    bootstrap_id=preview["bootstrap_id"],
                    resumed_by="resumer",
                    completed_result_path=self.completed_result,
                )

            self.assertEqual(outside.read_bytes(), b"outside-must-remain-unchanged\n")
            self.assertTrue(sidecar.is_symlink())

    def test_apply_holds_placement_then_ledger_lock_for_writer_lifetime(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        observed = []

        def assert_exclusively_locked(path):
            descriptor = os.open(path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)

        def checkpoint(name):
            if name == "placement-lock-acquired":
                assert_exclusively_locked(self.placement_lock)
                observed.append("placement")
            if name == "prepared":
                assert_exclusively_locked(Path(preview["paths"]["staging_ledger_lock"]))
                observed.append("ledger")

        result = control.apply_bootstrap_state(
            self.root,
            requested_by="requester",
            approved_by="approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=self.completed_result,
            checkpoint=checkpoint,
        )

        self.assertEqual(observed, ["placement", "ledger"])
        for path in (self.placement_lock, Path(result["paths"]["ledger_lock"])):
            descriptor = os.open(path, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def test_apply_fails_fast_when_placement_lock_is_held(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        holder = os.open(self.placement_lock, os.O_RDWR)
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        outcome = {}

        def invoke():
            try:
                control.apply_bootstrap_state(
                    self.root,
                    requested_by="requester",
                    approved_by="approver",
                    preview_id=preview["preview_id"],
                    preview_sha256=control.bootstrap_preview_sha256(preview),
                    completed_result_path=self.completed_result,
                )
            except Exception as exc:  # test captures the public error boundary
                outcome["error"] = exc

        worker = threading.Thread(target=invoke)
        worker.start()
        worker.join(0.2)
        blocked = worker.is_alive()
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
        worker.join(2)

        self.assertFalse(blocked, "apply used an unbounded placement flock")
        self.assertIsInstance(outcome.get("error"), control.ControlBootstrapError)
        self.assertEqual(str(outcome["error"]), "placement policy lock is busy")
        self.assertFalse(Path(preview["paths"]["staging"]).exists())

    def test_resume_fails_fast_when_ledger_lock_is_held(self):
        class SimulatedCrash(Exception):
            pass

        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )

        def crash(name):
            if name == "prepared":
                raise SimulatedCrash(name)

        with self.assertRaises(SimulatedCrash):
            control.apply_bootstrap_state(
                self.root,
                requested_by="requester",
                approved_by="approver",
                preview_id=preview["preview_id"],
                preview_sha256=control.bootstrap_preview_sha256(preview),
                completed_result_path=self.completed_result,
                checkpoint=crash,
            )
        ledger_lock = Path(preview["paths"]["staging_ledger_lock"])
        holder = os.open(ledger_lock, os.O_RDWR)
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        outcome = {}

        def invoke():
            try:
                control.resume_bootstrap_state(
                    self.root,
                    bootstrap_id=preview["bootstrap_id"],
                    resumed_by="resumer",
                    completed_result_path=self.completed_result,
                )
            except Exception as exc:  # test captures the public error boundary
                outcome["error"] = exc

        worker = threading.Thread(target=invoke)
        worker.start()
        worker.join(0.2)
        blocked = worker.is_alive()
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
        worker.join(2)

        self.assertFalse(blocked, "resume used an unbounded ledger flock")
        self.assertIsInstance(outcome.get("error"), control.ControlBootstrapError)
        self.assertEqual(str(outcome["error"]), "control ledger lock is busy")
        self.assertTrue(Path(preview["paths"]["staging"]).is_dir())
        self.assertFalse(Path(preview["paths"]["final"]).exists())

    def test_apply_rejects_preview_drift_before_first_write(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        before = self.tree_snapshot()

        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "bootstrap preview binding changed",
        ):
            control.apply_bootstrap_state(
                self.root,
                requested_by="different-requester",
                approved_by="approver",
                preview_id=preview["preview_id"],
                preview_sha256=control.bootstrap_preview_sha256(preview),
                completed_result_path=self.completed_result,
            )

        self.assertEqual(self.tree_snapshot(), before)
        self.assertFalse(Path(preview["paths"]["staging"]).exists())
        self.assertFalse(Path(preview["paths"]["final"]).exists())

    def test_preview_rejects_hardlinked_or_wrong_mode_control_evidence(self):
        extra_link = self.registry_directory / "placement-map.lock.extra"
        os.link(self.placement_lock, extra_link)
        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "placement policy lock link count is invalid",
        ):
            control.preview_bootstrap_state(
                self.root,
                requested_by="requester",
                completed_result_path=self.completed_result,
            )
        extra_link.unlink()
        self.completed_result.chmod(0o644)
        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "completed lock migration result identity is invalid",
        ):
            control.preview_bootstrap_state(
                self.root,
                requested_by="requester",
                completed_result_path=self.completed_result,
            )

    def test_resume_refuses_staging_final_collision_without_cleanup(self):
        class SimulatedCrash(Exception):
            pass

        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )

        def crash(name):
            if name == "prepared":
                raise SimulatedCrash(name)

        with self.assertRaises(SimulatedCrash):
            control.apply_bootstrap_state(
                self.root,
                requested_by="requester",
                approved_by="approver",
                preview_id=preview["preview_id"],
                preview_sha256=control.bootstrap_preview_sha256(preview),
                completed_result_path=self.completed_result,
                checkpoint=crash,
            )
        staging_ledger = Path(preview["paths"]["staging_ledger"])
        staging_bytes = staging_ledger.read_bytes()
        final = Path(preview["paths"]["final"])
        final.mkdir(mode=0o700)

        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "both exist; refusing repair",
        ):
            control.resume_bootstrap_state(
                self.root,
                bootstrap_id=preview["bootstrap_id"],
                resumed_by="resumer",
                completed_result_path=self.completed_result,
            )

        self.assertEqual(staging_ledger.read_bytes(), staging_bytes)
        self.assertEqual(list(final.iterdir()), [])

    def test_terminal_verification_rejects_same_inode_placement_lock_drift(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        result = control.apply_bootstrap_state(
            self.root,
            requested_by="requester",
            approved_by="approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=self.completed_result,
        )
        original_inode = self.placement_lock.stat().st_ino
        altered = json.loads(self.placement_lock.read_text(encoding="utf-8"))
        altered["placement_lock_protocol_version"] = "placement-lock-v2"
        self.placement_lock.write_bytes(canonical_json_bytes(altered))
        self.placement_lock.chmod(0o600)
        self.assertEqual(self.placement_lock.stat().st_ino, original_inode)

        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "placement policy lock identity changed",
        ):
            control.verify_complete_bootstrap(
                self.root,
                bootstrap_id=result["bootstrap_id"],
            )

    def test_terminal_verification_rejects_completed_migration_result_drift(self):
        preview = control.preview_bootstrap_state(
            self.root,
            requested_by="requester",
            completed_result_path=self.completed_result,
        )
        result = control.apply_bootstrap_state(
            self.root,
            requested_by="requester",
            approved_by="approver",
            preview_id=preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(preview),
            completed_result_path=self.completed_result,
        )
        completed = json.loads(self.completed_result.read_text(encoding="utf-8"))
        completed["unexpected"] = True
        self.completed_result.write_bytes(canonical_json_bytes(completed))
        self.completed_result.chmod(0o600)

        with self.assertRaisesRegex(
            control.ControlBootstrapError,
            "completed lock migration result identity changed",
        ):
            control.verify_complete_bootstrap(
                self.root,
                bootstrap_id=result["bootstrap_id"],
            )


if __name__ == "__main__":
    unittest.main()
