import hashlib
import json
import os
import sqlite3
import stat
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import ledger_schema, m3_schema, m3_schema_migration  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402

if __package__:
    from .test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402
else:
    from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


class SimulatedMigrationCrash(RuntimeError):
    pass


class M3SchemaMigrationTest(LedgerRuntimeFixture):
    def setUp(self):
        super().setUp()
        self.migrate_to_v2()

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

    def _preview(self, plan_id="m3mig-plan-test"):
        return m3_schema_migration.preview_m3_migration(
            self.root,
            plan_id=plan_id,
            requested_by="m3-migration-requester",
        )

    def _approved(self, plan_id="m3mig-plan-test"):
        plan = self._preview(plan_id)
        approval = m3_schema_migration.approve_m3_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="m3-migration-approver",
        )
        return plan, approval

    def _apply(self, plan, approval, *, checkpoint=None):
        return m3_schema_migration.apply_m3_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="m3-migration-executor",
            checkpoint=checkpoint,
        )

    def test_preview_is_write_free_and_binds_exact_v2_to_v3(self):
        before = self._tree_snapshot()

        plan = self._preview("m3mig-plan-preview")

        self.assertEqual(self._tree_snapshot(), before)
        self.assertEqual(plan["kind"], m3_schema_migration.PLAN_KIND)
        self.assertEqual(plan["source"]["schema_state"], "v2")
        self.assertEqual(
            plan["source"]["ledger_schema_sha256"],
            ledger_schema.LEDGER_SCHEMA_SHA256,
        )
        self.assertEqual(
            plan["target"],
            {
                "migration_id": m3_schema.M3_MIGRATION_ID,
                "schema_sha256": m3_schema.M3_SCHEMA_SHA256,
                "schema_version": m3_schema.M3_SCHEMA_VERSION,
            },
        )
        self.assertEqual(
            plan["plan_sha256"],
            m3_schema_migration.plan_sha256(plan),
        )
        self.assertEqual(
            Path(plan["paths"]["backup"]),
            self.curation_directory
            / "schema-migrations"
            / "backups"
            / "m3mig-plan-preview"
            / "ledger-v2.sqlite3",
        )
        self.assertEqual(len(self.migration_rows()), 2)

    def test_approval_seals_the_exact_recomputed_plan(self):
        plan = self._preview("m3mig-plan-approval")

        approval = m3_schema_migration.approve_m3_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="m3-migration-approver",
        )

        approval_path = Path(plan["paths"]["approval"])
        info = approval_path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_nlink, 1)
        raw = approval_path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(raw, canonical_json_bytes(payload))
        self.assertEqual(payload["plan"], plan)
        self.assertEqual(payload["kind"], m3_schema_migration.APPROVAL_KIND)
        self.assertEqual(approval["approval_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(self.migration_rows()), 2)

    def test_apply_backs_up_exact_v2_then_commits_and_seals_v3(self):
        plan, approval = self._approved("m3mig-plan-apply")

        result = self._apply(plan, approval)

        backup_path = Path(plan["paths"]["backup"])
        backup_info = backup_path.lstat()
        self.assertTrue(stat.S_ISREG(backup_info.st_mode))
        self.assertEqual(stat.S_IMODE(backup_info.st_mode), 0o600)
        self.assertEqual(backup_info.st_nlink, 1)
        backup = sqlite3.connect(
            backup_path.as_uri() + "?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
        try:
            backup.execute("PRAGMA foreign_keys = ON")
            ledger_schema.verify_v2_schema(backup)
            self.assertEqual(len(backup.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()), 2)
        finally:
            backup.close()

        live = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        try:
            live.execute("PRAGMA foreign_keys = ON")
            m3_schema.verify_v3_schema(live)
        finally:
            live.close()

        result_path = Path(plan["paths"]["result"])
        raw = result_path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(raw, canonical_json_bytes(payload))
        self.assertEqual(payload["kind"], m3_schema_migration.RESULT_KIND)
        self.assertEqual(payload["migration_id"], m3_schema.M3_MIGRATION_ID)
        self.assertEqual(payload["backup"]["path"], str(backup_path))
        self.assertEqual(result["result_sha256"], hashlib.sha256(raw).hexdigest())

    def test_source_drift_after_approval_creates_no_backup_or_v3_delta(self):
        plan, approval = self._approved("m3mig-plan-drift")

        self.mutate_ledger(
            lambda connection: connection.execute(
                "UPDATE control_bootstraps SET logical_readback_sha256 = ?",
                ("f" * 64,),
            )
        )

        with self.assertRaises(m3_schema_migration.M3SchemaMigrationError):
            self._apply(plan, approval)

        self.assertFalse(Path(plan["paths"]["backup"]).exists())
        self.assertFalse(Path(plan["paths"]["result"]).exists())
        self.assertEqual(len(self.migration_rows()), 2)

    def test_retry_after_backup_publish_reuses_verified_backup(self):
        plan, approval = self._approved("m3mig-plan-backup-retry")

        def crash_after_backup(phase):
            if phase == "backup-published":
                raise SimulatedMigrationCrash(phase)

        with self.assertRaises(SimulatedMigrationCrash):
            self._apply(plan, approval, checkpoint=crash_after_backup)

        backup_path = Path(plan["paths"]["backup"])
        before = backup_path.read_bytes()
        self.assertEqual(len(self.migration_rows()), 2)
        result = self._apply(plan, approval)
        self.assertEqual(backup_path.read_bytes(), before)
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(len(self.migration_rows()), 3)

    def test_retry_after_v3_commit_finishes_same_result_idempotently(self):
        plan, approval = self._approved("m3mig-plan-v3-retry")

        def crash_after_migration(phase):
            if phase == "migration-committed":
                raise SimulatedMigrationCrash(phase)

        with self.assertRaises(SimulatedMigrationCrash):
            self._apply(plan, approval, checkpoint=crash_after_migration)

        self.assertEqual(len(self.migration_rows()), 3)
        self.assertFalse(Path(plan["paths"]["result"]).exists())
        first = self._apply(plan, approval)
        sealed = Path(plan["paths"]["result"]).read_bytes()
        second = self._apply(plan, approval)
        self.assertEqual(Path(plan["paths"]["result"]).read_bytes(), sealed)
        self.assertEqual(first, second)

    def test_tampered_approval_is_rejected_before_backup_or_schema_write(self):
        plan, approval = self._approved("m3mig-plan-approval-tamper")
        approval_path = Path(plan["paths"]["approval"])
        approval_path.write_bytes(b"{}\n")
        approval_path.chmod(0o600)

        with self.assertRaisesRegex(
            m3_schema_migration.M3SchemaMigrationError,
            "approval hash changed",
        ):
            self._apply(plan, approval)

        self.assertFalse(Path(plan["paths"]["backup"]).exists())
        self.assertEqual(len(self.migration_rows()), 2)

    def test_different_result_collision_is_never_replaced(self):
        plan, approval = self._approved("m3mig-plan-result-collision")
        result_path = Path(plan["paths"]["result"])
        result_path.parent.mkdir(parents=True, mode=0o700)
        collision = b"different sealed result\n"
        result_path.write_bytes(collision)
        result_path.chmod(0o600)

        with self.assertRaisesRegex(
            m3_schema_migration.M3SchemaMigrationError,
            "collision differs from sealed bytes",
        ):
            self._apply(plan, approval)

        self.assertEqual(result_path.read_bytes(), collision)
        self.assertEqual(len(self.migration_rows()), 3)


if __name__ == "__main__":
    import unittest

    unittest.main()
