import hashlib
import json
import os
import sqlite3
import stat
from unittest import mock
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402
from mnemosyne_core import control, ledger_schema  # noqa: E402
if __package__:
    from .test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402
else:
    from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class M2SchemaMigrationPreviewTest(LedgerRuntimeFixture):
    def _tree_snapshot(self):
        observed = {}
        for current, directories, files in os.walk(self.root):
            directories.sort()
            for name in sorted(files):
                path = Path(current) / name
                info = path.lstat()
                observed[str(path.relative_to(self.root))] = (
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    info.st_mode,
                    info.st_uid,
                    info.st_nlink,
                )
        return observed

    def test_preview_is_write_free_and_binds_exact_v1_authority(self):
        from mnemosyne_core import schema_migration

        before = self._tree_snapshot()

        plan = schema_migration.preview_m2_migration(
            self.root,
            plan_id="m2mig-plan-0001",
            requested_by="migration-requester",
        )

        self.assertEqual(self._tree_snapshot(), before)
        self.assertEqual(plan["kind"], "MNEMOSYNE_M2_SCHEMA_MIGRATION_PLAN")
        self.assertEqual(plan["plan_id"], "m2mig-plan-0001")
        self.assertEqual(plan["requested_by"], "migration-requester")
        self.assertEqual(plan["source"]["schema_state"], "v1")
        self.assertEqual(plan["source"]["bootstrap_id"], self.bootstrap_id)
        self.assertEqual(
            plan["plan_sha256"],
            schema_migration.plan_sha256(plan),
        )
        self.assertEqual(
            canonical_json_bytes(
                {key: value for key, value in plan.items() if key != "plan_sha256"}
            ),
            schema_migration.plan_bytes(plan),
        )
        self.assertEqual(
            Path(plan["paths"]["backup"]),
            self.curation_directory
            / "schema-migrations"
            / "backups"
            / "m2mig-plan-0001"
            / "ledger-v1.sqlite3",
        )
        self.assertEqual(
            Path(plan["paths"]["result"]),
            self.curation_directory
            / "schema-migrations"
            / "runs"
            / "m2mig-plan-0001"
            / "result.json",
        )
        self.assertEqual(
            self.migration_rows(),
            [(1, plan["source"]["control_schema_sha256"], self.bootstrap_id)],
        )

    def test_preview_fails_closed_instead_of_ignoring_uncheckpointed_wal_rows(self):
        from mnemosyne_core import schema_migration

        writer = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        writer.execute("PRAGMA foreign_keys = ON")
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        head = writer.execute(
            "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
        ).fetchone()
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "INSERT INTO policy_guard_episodes ("
            "episode_id, head_generation, head_full_hash, guard_epoch_before, "
            "guard_epoch_after, first_event_id, current_observed_identity_json, "
            "root_execution_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
            (
                "episode-checkpointed-preview",
                head[0],
                head[1],
                head[2],
                head[2] + 1,
                "event-checkpointed-preview",
                b"{}\n",
                "CLEARED_EQUALITY",
            ),
        )
        writer.execute(
            "INSERT INTO policy_guard_events ("
            "event_id, episode_id, kind, head_generation, guard_epoch, "
            "observation_path, observation_sha256, result_path, result_sha256, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETE')",
            (
                "event-checkpointed-preview",
                "episode-checkpointed-preview",
                "DRIFT_CLEARED_EQUALITY",
                head[0],
                head[2],
                "observation.json",
                "0" * 64,
                "result.json",
                "1" * 64,
            ),
        )
        writer.execute("COMMIT")
        try:
            wal_path = Path(str(self.ledger_path) + "-wal")
            self.assertGreater(wal_path.stat().st_size, 0)

            with self.assertRaisesRegex(
                schema_migration.SchemaMigrationError,
                "WAL.*write-free preview",
            ):
                schema_migration.preview_m2_migration(
                    self.root,
                    plan_id="m2mig-plan-wal",
                    requested_by="migration-requester",
                )
        finally:
            writer.close()


class M2SchemaMigrationApprovalTest(LedgerRuntimeFixture):
    def test_approval_recomputes_and_seals_the_exact_plan(self):
        from mnemosyne_core import schema_migration

        plan = schema_migration.preview_m2_migration(
            self.root,
            plan_id="m2mig-plan-approval",
            requested_by="migration-requester",
        )

        approval = schema_migration.approve_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="migration-approver",
        )

        approval_path = Path(plan["paths"]["approval"])
        info = approval_path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_nlink, 1)
        raw = approval_path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(canonical_json_bytes(payload), raw)
        self.assertEqual(payload["kind"], schema_migration.APPROVAL_KIND)
        self.assertEqual(payload["plan"], plan)
        self.assertEqual(payload["plan_sha256"], plan["plan_sha256"])
        self.assertEqual(payload["approved_by"], "migration-approver")
        self.assertEqual(approval["approval_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(approval["approval_id"], payload["approval_id"])
        self.assertEqual(self.migration_rows()[0][0], 1)


class M2SchemaMigrationApplyTest(LedgerRuntimeFixture):
    def _approved_plan(self, plan_id="m2mig-plan-apply"):
        from mnemosyne_core import schema_migration

        plan = schema_migration.preview_m2_migration(
            self.root,
            plan_id=plan_id,
            requested_by="migration-requester",
        )
        approval = schema_migration.approve_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="migration-approver",
        )
        return plan, approval

    def test_apply_validates_backup_before_the_one_transaction_v2_delta(self):
        from mnemosyne_core import schema_migration

        plan, approval = self._approved_plan()

        result = schema_migration.apply_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="migration-executor",
        )

        backup_path = Path(plan["paths"]["backup"])
        backup_info = backup_path.lstat()
        self.assertTrue(stat.S_ISREG(backup_info.st_mode))
        self.assertEqual(stat.S_IMODE(backup_info.st_mode), 0o600)
        self.assertEqual(backup_info.st_nlink, 1)
        backup = __import__("sqlite3").connect(
            backup_path.as_uri() + "?mode=ro&immutable=1",
            uri=True,
        )
        try:
            control._verify_schema(backup)
            self.assertEqual(
                backup.execute(
                    "SELECT version, schema_sha256, applied_by_bootstrap_id "
                    "FROM schema_migrations ORDER BY version"
                ).fetchall(),
                [(1, control.CONTROL_SCHEMA_SHA256, self.bootstrap_id)],
            )
            self.assertEqual(backup.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
        finally:
            backup.close()

        live = __import__("sqlite3").connect(str(self.ledger_path), isolation_level=None)
        try:
            live.execute("PRAGMA foreign_keys = ON")
            ledger_schema.verify_v2_schema(live)
        finally:
            live.close()

        result_path = Path(plan["paths"]["result"])
        raw = result_path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(canonical_json_bytes(payload), raw)
        self.assertEqual(payload["kind"], schema_migration.RESULT_KIND)
        self.assertEqual(payload["plan_id"], plan["plan_id"])
        self.assertEqual(payload["approval_id"], approval["approval_id"])
        self.assertEqual(payload["backup"]["path"], str(backup_path))
        self.assertEqual(result["result_sha256"], hashlib.sha256(raw).hexdigest())

    def test_source_change_creates_neither_backup_nor_v2_schema(self):
        from mnemosyne_core import schema_migration

        plan, approval = self._approved_plan("m2mig-plan-source-drift")
        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        try:
            connection.execute(
                "UPDATE policy_mutation_lane SET generation = generation + 1 WHERE id = 1"
            )
        finally:
            connection.close()

        with self.assertRaisesRegex(
            schema_migration.SchemaMigrationError,
            "source bytes changed",
        ):
            schema_migration.apply_m2_migration(
                self.root,
                plan_id=plan["plan_id"],
                expected_plan_sha256=plan["plan_sha256"],
                requested_by=plan["requested_by"],
                approval_id=approval["approval_id"],
                approval_sha256=approval["approval_sha256"],
                executed_by="migration-executor",
            )

        self.assertFalse(Path(plan["paths"]["backup"]).exists())
        self.assertFalse(Path(plan["paths"]["result"]).exists())
        self.assertEqual(
            self.migration_rows(),
            [(1, control.CONTROL_SCHEMA_SHA256, self.bootstrap_id)],
        )

    def test_crash_after_schema_commit_resumes_from_exact_backup_and_approval(self):
        from mnemosyne_core import schema_migration

        plan, approval = self._approved_plan("m2mig-plan-crash-resume")

        def crash_after_commit(point):
            if point == "migration-committed":
                raise RuntimeError("simulated process loss")

        with self.assertRaisesRegex(RuntimeError, "simulated process loss"):
            schema_migration.apply_m2_migration(
                self.root,
                plan_id=plan["plan_id"],
                expected_plan_sha256=plan["plan_sha256"],
                requested_by=plan["requested_by"],
                approval_id=approval["approval_id"],
                approval_sha256=approval["approval_sha256"],
                executed_by="migration-executor",
                checkpoint=crash_after_commit,
            )

        backup_path = Path(plan["paths"]["backup"])
        backup_sha256 = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        self.assertFalse(Path(plan["paths"]["result"]).exists())
        self.assertEqual(len(self.migration_rows()), 2)

        result = schema_migration.apply_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="migration-executor",
        )

        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(
            hashlib.sha256(backup_path.read_bytes()).hexdigest(),
            backup_sha256,
        )
        self.assertTrue(Path(plan["paths"]["result"]).is_file())

    def test_tampered_backup_blocks_schema_delta_without_overwrite(self):
        from mnemosyne_core import schema_migration

        plan, approval = self._approved_plan("m2mig-plan-backup-tamper")

        def stop_after_backup(point):
            if point == "backup-published":
                raise RuntimeError("stop before migration")

        with self.assertRaisesRegex(RuntimeError, "stop before migration"):
            schema_migration.apply_m2_migration(
                self.root,
                plan_id=plan["plan_id"],
                expected_plan_sha256=plan["plan_sha256"],
                requested_by=plan["requested_by"],
                approval_id=approval["approval_id"],
                approval_sha256=approval["approval_sha256"],
                executed_by="migration-executor",
                checkpoint=stop_after_backup,
            )
        backup_path = Path(plan["paths"]["backup"])
        original = backup_path.read_bytes()
        backup_path.write_bytes(original[:-1] + bytes((original[-1] ^ 1,)))
        backup_path.chmod(0o600)
        tampered = backup_path.read_bytes()

        with self.assertRaises(schema_migration.SchemaMigrationError):
            schema_migration.apply_m2_migration(
                self.root,
                plan_id=plan["plan_id"],
                expected_plan_sha256=plan["plan_sha256"],
                requested_by=plan["requested_by"],
                approval_id=approval["approval_id"],
                approval_sha256=approval["approval_sha256"],
                executed_by="migration-executor",
            )

        self.assertEqual(backup_path.read_bytes(), tampered)
        self.assertEqual(
            self.migration_rows(),
            [(1, control.CONTROL_SCHEMA_SHA256, self.bootstrap_id)],
        )

    def test_tampered_approval_creates_neither_backup_nor_v2_schema(self):
        from mnemosyne_core import schema_migration

        plan, approval = self._approved_plan("m2mig-plan-approval-tamper")
        approval_path = Path(approval["approval_path"])
        payload = json.loads(approval_path.read_text(encoding="utf-8"))
        payload["approved_by"] = "different-approver"
        approval_path.write_bytes(canonical_json_bytes(payload))
        approval_path.chmod(0o600)

        with self.assertRaisesRegex(
            schema_migration.SchemaMigrationError,
            "approval hash changed",
        ):
            schema_migration.apply_m2_migration(
                self.root,
                plan_id=plan["plan_id"],
                expected_plan_sha256=plan["plan_sha256"],
                requested_by=plan["requested_by"],
                approval_id=approval["approval_id"],
                approval_sha256=approval["approval_sha256"],
                executed_by="migration-executor",
            )

        self.assertFalse(Path(plan["paths"]["backup"]).exists())
        self.assertFalse(Path(plan["paths"]["result"]).exists())
        self.assertEqual(len(self.migration_rows()), 1)

    def test_partial_backup_is_preserved_and_retry_uses_a_new_attempt(self):
        from mnemosyne_core import schema_migration

        plan, approval = self._approved_plan("m2mig-plan-partial-backup")

        def fail_mid_backup(_source, destination):
            destination.execute("CREATE TABLE partial_backup_marker (id INTEGER)")
            raise RuntimeError("simulated backup interruption")

        with mock.patch.object(
            schema_migration,
            "_backup_database",
            side_effect=fail_mid_backup,
        ):
            with self.assertRaisesRegex(RuntimeError, "backup interruption"):
                schema_migration.apply_m2_migration(
                    self.root,
                    plan_id=plan["plan_id"],
                    expected_plan_sha256=plan["plan_sha256"],
                    requested_by=plan["requested_by"],
                    approval_id=approval["approval_id"],
                    approval_sha256=approval["approval_sha256"],
                    executed_by="migration-executor",
                )

        attempts_root = Path(plan["paths"]["backup_attempts"])
        first_attempt = attempts_root / ".incomplete-ledger-v1-0001.sqlite3"
        self.assertTrue(first_attempt.is_file())
        first_bytes = first_attempt.read_bytes()

        second_attempt = attempts_root / ".incomplete-ledger-v1-0002.sqlite3"
        second_attempt_identity = []

        def capture_second_attempt(label):
            if label == "backup-attempt-ready":
                info = second_attempt.lstat()
                second_attempt_identity.append((info.st_dev, info.st_ino))

        result = schema_migration.apply_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="migration-executor",
            checkpoint=capture_second_attempt,
        )

        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(first_attempt.read_bytes(), first_bytes)
        self.assertEqual(len(second_attempt_identity), 1)
        final_backup = Path(plan["paths"]["backup"])
        final_info = final_backup.lstat()
        self.assertEqual(
            (final_info.st_dev, final_info.st_ino),
            second_attempt_identity[0],
        )
        self.assertFalse(second_attempt.exists())


class M2SchemaMigrationRuntimeBoundaryTest(LedgerRuntimeFixture):
    def test_writer_session_flag_cannot_bypass_explicit_migration_workflow(self):
        from mnemosyne_core import ledger_runtime

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "explicit schema migration workflow",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                allow_m2_migration=True,
            ):
                self.fail("legacy flag must never run DDL")

        self.assertEqual(
            self.migration_rows(),
            [(1, control.CONTROL_SCHEMA_SHA256, self.bootstrap_id)],
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
