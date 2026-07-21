import fcntl
import hashlib
import importlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import (  # noqa: E402
    admission,
    batch_service,
    campaign_ledger,
    control,
    ledger_schema,
    policy,
    policy_state,
    schema_migration,
)
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


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


class LedgerRuntimeFixture(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.registry_directory = self.root / "_registry"
        self.registry_directory.mkdir(mode=0o700)
        self.registry_path = self.registry_directory / "placement-map.yml"
        registry_raw = BASE_REGISTRY.replace(
            b"{root}", str(self.root).encode("utf-8")
        )
        self.registry_path.write_bytes(registry_raw)
        self.registry_path.chmod(0o600)

        migration_id = "lockmig-20260715T000000Z-000000000001"
        self.placement_lock = self.registry_directory / "placement-map.lock"
        placement_payload = {
            "schema_version": 1,
            "kind": "PLACEMENT_COORDINATION_LOCK",
            "migration_id": migration_id,
            "placement_lock_protocol_version": "placement-lock-v1",
        }
        self.placement_lock.write_bytes(canonical_json_bytes(placement_payload))
        self.placement_lock.chmod(0o600)

        completed_directory = (
            self.registry_directory
            / "lock-migrations"
            / "completed"
            / migration_id
        )
        completed_directory.mkdir(parents=True, mode=0o700)
        completed_result = completed_directory / "result.json"
        completed_payload = {
            "schema_version": 1,
            "kind": "LOCK_MIGRATION_RESULT",
            "status": "COMPLETE",
            "migration_id": migration_id,
            "registry_sha256": hashlib.sha256(registry_raw).hexdigest(),
            "placement_lock_protocol_version": "placement-lock-v1",
            "placement_lock": {
                "path": str(self.placement_lock),
                "sha256": hashlib.sha256(
                    self.placement_lock.read_bytes()
                ).hexdigest(),
                "mode": "0600",
                "uid": os.getuid(),
                "nlink": 1,
            },
            "paths": {
                "active_marker": str(
                    self.registry_directory / "lock-migrations" / "active"
                ),
                "completed_result": str(completed_result),
                "placement_lock": str(self.placement_lock),
            },
        }
        completed_result.write_bytes(canonical_json_bytes(completed_payload))
        completed_result.chmod(0o600)

        control_preview = control.preview_bootstrap_state(
            self.root,
            requested_by="control-requester",
            completed_result_path=completed_result,
        )
        control.apply_bootstrap_state(
            self.root,
            requested_by="control-requester",
            approved_by="control-approver",
            preview_id=control_preview["preview_id"],
            preview_sha256=control.bootstrap_preview_sha256(control_preview),
            completed_result_path=completed_result,
        )
        self.bootstrap_id = control_preview["bootstrap_id"]
        self.curation_directory = self.registry_directory / "curation"
        self.ledger_lock = self.curation_directory / "ledger.lock"
        self.ledger_path = self.curation_directory / "ledger.sqlite3"

        policy_preview = policy_state.preview_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            requested_by="policy-requester",
        )
        proposal = policy_state.publish_policy_bootstrap_proposal(
            self.root,
            bootstrap_id=self.bootstrap_id,
            preview=policy_preview,
        )
        approval = policy_state.approve_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            proposal_id=proposal["proposal_id"],
            proposal_sha256=proposal["proposal_sha256"],
            approved_by="policy-approver",
        )
        policy_state.apply_policy_bootstrap(
            self.root,
            bootstrap_id=self.bootstrap_id,
            approval_id=approval["approval_id"],
            approval_sha256=approval["export_sha256"],
            executed_by="policy-executor",
            process_instance_id="ledger-runtime-test-process",
        )

    def migration_rows(self):
        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        try:
            return connection.execute(
                "SELECT version, schema_sha256, applied_by_bootstrap_id "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()
        finally:
            connection.close()

    def mutate_ledger(self, operation):
        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            operation(connection)
        finally:
            connection.close()

    def approve_v2_migration(self):
        plan = schema_migration.preview_m2_migration(
            self.root,
            plan_id="m2mig-plan-ledger-runtime-test",
            requested_by="ledger-runtime-requester",
        )
        approval = schema_migration.approve_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="ledger-runtime-approver",
        )
        return plan, approval

    def migrate_to_v2(self, *, checkpoint=None):
        plan, approval = self.approve_v2_migration()
        result = schema_migration.apply_m2_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="ledger-runtime-executor",
            checkpoint=checkpoint,
        )
        return plan, approval, result


class LedgerRuntimeWriterSessionTest(LedgerRuntimeFixture):
    def test_writer_observed_by_rejects_an_invalid_actor(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        with self.assertRaisesRegex(
            ValueError,
            "observed_by is invalid",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                observed_by=" actor-with-whitespace ",
            ):
                pass

    def test_v1_requires_explicit_m2_migration_without_changing_the_ledger(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "explicit schema migration workflow",
        ):
            with ledger_runtime.open_writer_session(self.root):
                self.fail("v1 must not open without explicit migration authority")

        self.assertEqual(
            self.migration_rows(),
            [(1, control.CONTROL_SCHEMA_SHA256, self.bootstrap_id)],
        )

    def test_migration_authority_requires_a_literal_boolean(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        with self.assertRaisesRegex(TypeError, "must be a boolean"):
            with ledger_runtime.open_writer_session(
                self.root,
                allow_m2_migration=1,
            ):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_explicit_migration_opens_v2_and_exposes_injectable_session_state(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()

        with ledger_runtime.open_writer_session(
            self.root,
        ) as session:
            self.assertIsInstance(session.connection, sqlite3.Connection)
            self.assertIsInstance(
                session.approved_policy_ref,
                admission.ApprovedPolicyRef,
            )
            self.assertIsInstance(session.compiled_policy, policy.CompiledPolicy)
            self.assertEqual(session.current_policy(), session.approved_policy_ref)
            with session.placement_shared():
                with session.ledger_exclusive():
                    ledger_schema.verify_v2_schema(session.connection)
            binder = campaign_ledger.CampaignRunBinder(
                connection=session.connection,
                placement_shared=session.placement_shared,
                ledger_exclusive=session.ledger_exclusive,
                current_policy=session.current_policy,
                campaign_publisher=object(),
                integration_publisher=object(),
            )
            batches = batch_service.BatchService(
                session.connection,
                self.curation_directory / "review-snapshots",
                placement_shared=session.placement_shared,
                ledger_exclusive=session.ledger_exclusive,
                publisher=mock.Mock(
                    plan=mock.Mock(),
                    publish=mock.Mock(),
                ),
                current_policy=session.current_policy,
            )
            self.assertIsInstance(binder, campaign_ledger.CampaignRunBinder)
            self.assertIsInstance(batches, batch_service.BatchService)

        self.assertEqual(
            self.migration_rows(),
            [
                (1, control.CONTROL_SCHEMA_SHA256, self.bootstrap_id),
                (
                    ledger_schema.LEDGER_SCHEMA_VERSION,
                    ledger_schema.LEDGER_SCHEMA_SHA256,
                    ledger_runtime.M2_MIGRATION_ID,
                ),
            ],
        )

    def test_exact_v2_reopens_without_migration_authority(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        with ledger_runtime.open_writer_session(
            self.root,
        ):
            pass

        with ledger_runtime.open_writer_session(self.root) as session:
            self.assertEqual(
                session.connection.execute(
                    "SELECT COUNT(*) FROM schema_migrations"
                ).fetchone()[0],
                2,
            )

    def test_guard_factories_are_nested_assertions_for_the_active_session_only(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()

        with ledger_runtime.open_writer_session(
            self.root,
        ) as session:
            with self.assertRaisesRegex(
                ledger_runtime.LedgerRuntimeError,
                "placement_shared",
            ):
                with session.ledger_exclusive():
                    pass
            with session.placement_shared():
                with session.placement_shared():
                    with session.ledger_exclusive():
                        with session.ledger_exclusive():
                            self.assertEqual(session.current_policy().generation, 1)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "not active",
        ):
            session.current_policy()
        with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
            session.connection.execute("SELECT 1")

    def test_lock_order_is_placement_shared_then_nonblocking_ledger_exclusive(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        placement_fd = os.open(self.placement_lock, os.O_RDONLY)
        ledger_fd = os.open(self.ledger_lock, os.O_RDONLY)
        try:
            fcntl.flock(placement_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(ledger_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaisesRegex(
                ledger_runtime.LedgerRuntimeError,
                "placement policy lock is busy",
            ):
                with ledger_runtime.open_writer_session(
                    self.root,
                ):
                    pass
            self.assertEqual(len(self.migration_rows()), 1)
        finally:
            fcntl.flock(placement_fd, fcntl.LOCK_UN)
            os.close(placement_fd)

        try:
            with self.assertRaisesRegex(
                ledger_runtime.LedgerRuntimeError,
                "curation ledger lock is busy",
            ):
                with ledger_runtime.open_writer_session(
                    self.root,
                ):
                    pass
            self.assertEqual(len(self.migration_rows()), 1)
        finally:
            fcntl.flock(ledger_fd, fcntl.LOCK_UN)
            os.close(ledger_fd)

    def test_both_lock_descriptors_remain_held_for_the_session_lifetime(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()

        with ledger_runtime.open_writer_session(
            self.root,
        ):
            placement_probe = os.open(self.placement_lock, os.O_RDONLY)
            ledger_probe = os.open(self.ledger_lock, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(
                        placement_probe,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(
                        ledger_probe,
                        fcntl.LOCK_SH | fcntl.LOCK_NB,
                    )
            finally:
                os.close(ledger_probe)
                os.close(placement_probe)

    def test_symlink_lock_is_rejected_as_a_runtime_identity_error(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        original = self.registry_directory / "placement-map.original-lock"
        self.placement_lock.rename(original)
        self.placement_lock.symlink_to(original)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "placement policy lock.*invalid",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass

    def test_hardlinked_ledger_lock_is_rejected(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        os.link(self.ledger_lock, self.curation_directory / "ledger-lock-alias")

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "curation ledger lock identity is invalid",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass

    def test_non_0600_ledger_is_rejected_before_sqlite_connect(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.ledger_path.chmod(0o640)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "curation ledger identity is invalid",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass

    def test_ledger_identity_swap_during_connect_is_rejected(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        real_connect = sqlite3.connect

        def connect_then_swap(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            original = self.curation_directory / "ledger.before-connect-swap"
            self.ledger_path.rename(original)
            self.ledger_path.write_bytes(original.read_bytes())
            self.ledger_path.chmod(0o600)
            return connection

        with mock.patch.object(
            ledger_runtime.sqlite3,
            "connect",
            side_effect=connect_then_swap,
        ):
            with self.assertRaisesRegex(
                ledger_runtime.LedgerRuntimeError,
                "identity changed while opening",
            ):
                with ledger_runtime.open_writer_session(
                    self.root,
                ):
                    pass

    def test_mode_change_during_writer_connect_is_rejected_before_migration(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        real_connect = sqlite3.connect

        def connect_then_chmod(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            self.ledger_path.chmod(0o640)
            return connection

        try:
            with mock.patch.object(
                ledger_runtime.sqlite3,
                "connect",
                side_effect=connect_then_chmod,
            ):
                with self.assertRaisesRegex(
                    ledger_runtime.LedgerRuntimeError,
                    "identity changed while opening writer",
                ):
                    with ledger_runtime.open_writer_session(
                        self.root,
                    ):
                        self.fail("writer identity must fail before yielding")
        finally:
            self.ledger_path.chmod(0o600)
        self.assertEqual(len(self.migration_rows()), 1)

    def test_hardlink_added_during_writer_connect_is_rejected_before_migration(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        real_connect = sqlite3.connect
        alias = self.curation_directory / "ledger.connect-alias"

        def connect_then_link(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            os.link(self.ledger_path, alias)
            return connection

        try:
            with mock.patch.object(
                ledger_runtime.sqlite3,
                "connect",
                side_effect=connect_then_link,
            ):
                with self.assertRaisesRegex(
                    ledger_runtime.LedgerRuntimeError,
                    "identity changed while opening writer",
                ):
                    with ledger_runtime.open_writer_session(
                        self.root,
                    ):
                        self.fail("writer link count must fail before yielding")
        finally:
            if alias.exists():
                alias.unlink()
        self.assertEqual(len(self.migration_rows()), 1)

    def test_ledger_identity_swap_before_close_is_rejected_after_cleanup(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        session = None

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "identity changed.*close",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ) as session:
                original = self.curation_directory / "ledger.before-close-swap"
                self.ledger_path.rename(original)
                self.ledger_path.write_bytes(original.read_bytes())
                self.ledger_path.chmod(0o600)

        self.assertIsNotNone(session)
        with self.assertRaises(sqlite3.ProgrammingError):
            session.connection.execute("SELECT 1")

    def test_lock_path_identity_swap_is_detected_before_session_release(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        session = None

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "curation ledger lock identity changed",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ) as session:
                original = self.curation_directory / "ledger.original-lock"
                self.ledger_lock.rename(original)
                self.ledger_lock.write_bytes(b"")
                self.ledger_lock.chmod(0o600)

        self.assertIsNotNone(session)
        with self.assertRaises(sqlite3.ProgrammingError):
            session.connection.execute("SELECT 1")

    def test_guard_leak_deactivates_session_before_reporting_the_leak(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        session = None
        guard = None

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "guard is still active",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ) as session:
                guard = session.placement_shared()
                guard.__enter__()

        self.assertIsNotNone(session)
        self.assertIsNotNone(guard)
        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "not active",
        ):
            session.current_policy()

    def test_current_policy_drift_latch_survives_registry_aba(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        original_raw = self.registry_path.read_bytes()
        drifted_raw = original_raw.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        first_rejected = False
        restored_rejected = False

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy drift recorded",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                observed_by="ledger-runtime-current-policy-test",
            ) as session:
                replacement = self.registry_directory / "placement-map.drifted"
                replacement.write_bytes(drifted_raw)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)
                try:
                    session.current_policy()
                except ledger_runtime.LedgerRuntimeError:
                    first_rejected = True

                replacement.write_bytes(original_raw)
                replacement.chmod(0o600)
                os.replace(replacement, self.registry_path)
                try:
                    session.current_policy()
                except ledger_runtime.LedgerRuntimeError:
                    restored_rejected = True

        self.assertTrue(first_rejected)
        self.assertTrue(restored_rejected)

    def test_nonidle_policy_lane_blocks_writer_session(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        self.mutate_ledger(
            lambda connection: connection.execute(
                "UPDATE policy_mutation_lane SET state = 'ACTIVE', "
                "owner_kind = 'EDIT', owner_proposal_id = 'proposal-test', "
                "owner_approval_id = 'approval-test', owner_run_id = 'run-test', "
                "owner_process_id = 'process-test' WHERE id = 1"
            )
        )
        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy mutation lane is not IDLE",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_open_policy_guard_blocks_writer_session(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        def install_guard(connection):
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
            connection.execute(
                "INSERT INTO policy_guard_episodes ("
                "episode_id, head_generation, head_full_hash, guard_epoch_before, "
                "guard_epoch_after, first_event_id, current_observed_identity_json, "
                "root_execution_id, status) VALUES "
                "('episode-test', ?, ?, ?, ?, 'event-test', ?, NULL, 'OPEN')",
                (
                    head["generation"],
                    head["full_hash"],
                    head["guard_epoch"],
                    head["guard_epoch"] + 1,
                    b"{}\n",
                ),
            )

        self.mutate_ledger(install_guard)
        with self.assertRaisesRegex(
            ledger_runtime.PolicyAdmissionError,
            "open policy guard episode",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_nonterminal_policy_guard_event_blocks_with_policy_error(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        def install_guard_event(connection):
            head = connection.execute(
                "SELECT generation, full_hash, guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()
            connection.execute(
                "INSERT INTO policy_guard_episodes ("
                "episode_id, head_generation, head_full_hash, guard_epoch_before, "
                "guard_epoch_after, first_event_id, current_observed_identity_json, "
                "root_execution_id, status) VALUES "
                "('episode-test', ?, ?, ?, ?, 'event-test', ?, NULL, "
                "'CLEARED_EQUALITY')",
                (
                    head["generation"],
                    head["full_hash"],
                    head["guard_epoch"],
                    head["guard_epoch"] + 1,
                    b"{}\n",
                ),
            )
            connection.execute(
                "INSERT INTO policy_guard_events ("
                "event_id, episode_id, kind, head_generation, guard_epoch, "
                "observation_path, observation_sha256, result_path, "
                "result_sha256, state) VALUES "
                "('event-test', 'episode-test', 'OBSERVATION', ?, ?, "
                "'observation.json', ?, 'result.json', NULL, 'PREPARED')",
                (head["generation"], head["guard_epoch"] + 1, "0" * 64),
            )

        self.mutate_ledger(install_guard_event)
        with self.assertRaisesRegex(
            ledger_runtime.PolicyAdmissionError,
            "nonterminal policy guard event",
        ):
            with ledger_runtime.open_writer_session(self.root):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_policy_drift_blocks_writer_session_before_v2_migration(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        drifted_raw = self.registry_path.read_bytes().replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        self.registry_path.write_bytes(drifted_raw)
        self.registry_path.chmod(0o600)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy binding is not exact",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_bootstrap_requires_exact_0700_curation_directory(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.curation_directory.chmod(0o750)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "curation control root mode is invalid",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_bootstrap_requires_empty_ledger_lock_payload(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.ledger_lock.write_bytes(b"not-empty")
        self.ledger_lock.chmod(0o600)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "ledger lock content is invalid",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_bootstrap_requires_exact_placement_lock_content_hash(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.placement_lock.write_bytes(b"tampered-placement-lock\n")
        self.placement_lock.chmod(0o600)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "placement lock evidence changed",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_bootstrap_requires_exact_completed_lock_migration_result(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        def tamper_completed_result(connection):
            path = Path(
                connection.execute(
                    "SELECT completed_result_path FROM control_bootstraps"
                ).fetchone()[0]
            )
            path.write_bytes(b"tampered-completed-result\n")
            path.chmod(0o600)

        self.mutate_ledger(tamper_completed_result)
        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "completed lock migration result.*changed",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
            ):
                pass
        self.assertEqual(len(self.migration_rows()), 1)

    def test_unknown_schema_suffix_is_not_accepted_as_v2(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        with ledger_runtime.open_writer_session(
            self.root,
        ):
            pass
        self.mutate_ledger(
            lambda connection: connection.execute(
                "INSERT INTO schema_migrations "
                "(version, schema_sha256, applied_by_bootstrap_id) VALUES (3, ?, ?)",
                ("f" * 64, "unexpected-v3"),
            )
        )

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "schema binding is unknown",
        ):
            with ledger_runtime.open_writer_session(self.root):
                pass

    def test_exact_v2_verifier_rejects_an_unknown_schema_object(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        with ledger_runtime.open_writer_session(
            self.root,
        ):
            pass
        self.mutate_ledger(
            lambda connection: connection.execute(
                "CREATE TABLE rogue_runtime_table (id TEXT PRIMARY KEY)"
            )
        )

        with mock.patch.object(
            ledger_runtime.control,
            "_verify_manifest_for_row",
            wraps=ledger_runtime.control._verify_manifest_for_row,
        ) as manifest_verifier:
            with self.assertRaisesRegex(
                ledger_runtime.LedgerRuntimeError,
                "v2 schema is not exact",
            ):
                with ledger_runtime.open_writer_session(self.root):
                    pass
        manifest_verifier.assert_not_called()

    def test_v1_migration_failure_rolls_back_the_entire_v2_delta(self):
        plan, approval = self.approve_v2_migration()
        real_migrate = schema_migration.ledger_schema.ensure_v2_schema

        def migrate_with_denied_delta(connection, *, migration_id):
            def deny_campaign_table(action, argument1, _arg2, _db, _trigger):
                if (
                    action == sqlite3.SQLITE_CREATE_TABLE
                    and argument1 == "campaigns"
                ):
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.set_authorizer(deny_campaign_table)
            return real_migrate(connection, migration_id=migration_id)

        with mock.patch.object(
            schema_migration.ledger_schema,
            "ensure_v2_schema",
            side_effect=migrate_with_denied_delta,
        ):
            with self.assertRaises(schema_migration.SchemaMigrationError):
                schema_migration.apply_m2_migration(
                    self.root,
                    plan_id=plan["plan_id"],
                    expected_plan_sha256=plan["plan_sha256"],
                    requested_by=plan["requested_by"],
                    approval_id=approval["approval_id"],
                    approval_sha256=approval["approval_sha256"],
                    executed_by="ledger-runtime-executor",
                )

        self.assertEqual(
            self.migration_rows(),
            [(1, control.CONTROL_SCHEMA_SHA256, self.bootstrap_id)],
        )
        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
        finally:
            connection.close()
        self.assertEqual(tables, set(control.CONTROL_SCHEMA_TABLES))

    def test_lock_swap_during_migration_denies_commit_and_preserves_v1(self):
        plan, approval = self.approve_v2_migration()
        real_migrate = schema_migration.ledger_schema.ensure_v2_schema

        def swap_then_migrate(connection, *, migration_id):
            original = self.curation_directory / "ledger.migration-lock"
            self.ledger_lock.rename(original)
            self.ledger_lock.write_bytes(b"")
            self.ledger_lock.chmod(0o600)
            try:
                return real_migrate(connection, migration_id=migration_id)
            finally:
                self.ledger_lock.unlink()
                original.rename(self.ledger_lock)

        with mock.patch.object(
            schema_migration.ledger_schema,
            "ensure_v2_schema",
            side_effect=swap_then_migrate,
        ):
            with self.assertRaises(schema_migration.SchemaMigrationError):
                schema_migration.apply_m2_migration(
                    self.root,
                    plan_id=plan["plan_id"],
                    expected_plan_sha256=plan["plan_sha256"],
                    requested_by=plan["requested_by"],
                    approval_id=approval["approval_id"],
                    approval_sha256=approval["approval_sha256"],
                    executed_by="ledger-runtime-executor",
                )
        self.assertEqual(len(self.migration_rows()), 1)

    def test_lock_swap_denies_service_commit_before_it_becomes_durable(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()

        with ledger_runtime.open_writer_session(
            self.root,
        ) as session:
            before = session.connection.execute(
                "SELECT generation FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()[0]
            with session.placement_shared():
                with session.ledger_exclusive():
                    session.connection.execute("BEGIN IMMEDIATE")
                    session.connection.execute(
                        "UPDATE policy_mutation_lane SET generation = generation + 1 "
                        "WHERE id = 1"
                    )
                    original = self.curation_directory / "ledger.commit-lock"
                    self.ledger_lock.rename(original)
                    self.ledger_lock.write_bytes(b"")
                    self.ledger_lock.chmod(0o600)
                    try:
                        with self.assertRaises(sqlite3.DatabaseError):
                            session.connection.execute("COMMIT")
                    finally:
                        if session.connection.in_transaction:
                            session.connection.execute("ROLLBACK")
                        self.ledger_lock.unlink()
                        original.rename(self.ledger_lock)
            after = session.connection.execute(
                "SELECT generation FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()[0]
            self.assertEqual(after, before)

    def test_registry_drift_at_commit_rolls_back_and_records_first_drift_after_aba(
        self,
    ):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        original_raw = self.registry_path.read_bytes()
        drifted_raw = original_raw.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        before_generation = None
        before_guard_epoch = None
        session = None

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy drift recorded",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                observed_by="ledger-runtime-drift-test",
            ) as session:
                before_generation = session.connection.execute(
                    "SELECT generation FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()[0]
                before_guard_epoch = session.approved_policy_ref.guard_epoch
                with session.placement_shared():
                    with session.ledger_exclusive():
                        session.connection.execute("BEGIN IMMEDIATE")
                        session.connection.execute(
                            "UPDATE policy_mutation_lane "
                            "SET generation = generation + 1 WHERE id = 1"
                        )
                        self.registry_path.write_bytes(drifted_raw)
                        self.registry_path.chmod(0o600)
                        try:
                            with mock.patch.object(
                                ledger_runtime,
                                "_current_policy_binding",
                                side_effect=AssertionError(
                                    "COMMIT authorizer entered the SQL policy verifier"
                                ),
                            ):
                                with self.assertRaises(sqlite3.DatabaseError):
                                    session.connection.execute("COMMIT")
                        finally:
                            if session.connection.in_transaction:
                                session.connection.execute("ROLLBACK")
                            self.registry_path.write_bytes(original_raw)
                            self.registry_path.chmod(0o600)

        self.assertIsNotNone(session)
        with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
            session.connection.execute("SELECT 1")

        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            after_generation = connection.execute(
                "SELECT generation FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()[0]
            after_guard_epoch = connection.execute(
                "SELECT guard_epoch FROM policy_head WHERE id = 1"
            ).fetchone()[0]
            episode = connection.execute(
                "SELECT episode_id, first_event_id, status "
                "FROM policy_guard_episodes"
            ).fetchone()
            event = connection.execute(
                "SELECT event_id, kind, observation_path, result_path, state "
                "FROM policy_guard_events"
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(after_generation, before_generation)
        self.assertEqual(after_guard_epoch, before_guard_epoch + 1)
        self.assertIsNotNone(episode)
        self.assertIsNotNone(event)
        self.assertEqual(episode["status"], "OPEN")
        self.assertEqual(episode["first_event_id"], event["event_id"])
        self.assertEqual(event["kind"], "FIRST_DRIFT")
        self.assertEqual(event["state"], "COMPLETE")

        observation = json.loads(Path(event["observation_path"]).read_bytes())
        result = json.loads(Path(event["result_path"]).read_bytes())
        self.assertEqual(
            observation["observation"]["raw_sha256"],
            hashlib.sha256(drifted_raw).hexdigest(),
        )
        self.assertEqual(
            result["final_observation"]["raw_sha256"],
            hashlib.sha256(original_raw).hexdigest(),
        )
        self.assertEqual(self.registry_path.read_bytes(), original_raw)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "open policy guard episode",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                observed_by="ledger-runtime-after-drift-test",
            ):
                pass


class LedgerRuntimeReaderSessionTest(LedgerRuntimeFixture):
    def test_reader_requires_exact_v2_and_never_migrates_v1(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "reader requires exact v2",
        ):
            with ledger_runtime.open_reader_session(self.root):
                pass

        self.assertEqual(
            self.migration_rows(),
            [(1, control.CONTROL_SCHEMA_SHA256, self.bootstrap_id)],
        )

    def test_reader_holds_shared_locks_and_exposes_readonly_current_policy(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        with ledger_runtime.open_writer_session(
            self.root,
        ):
            pass

        external_shared = os.open(self.ledger_lock, os.O_RDONLY)
        fcntl.flock(external_shared, fcntl.LOCK_SH | fcntl.LOCK_NB)
        try:
            with ledger_runtime.open_reader_session(self.root) as session:
                self.assertIsInstance(session, ledger_runtime.ReaderSession)
                self.assertIsInstance(session.connection, sqlite3.Connection)
                self.assertIsInstance(
                    session.approved_policy_ref,
                    admission.ApprovedPolicyRef,
                )
                self.assertIsInstance(session.compiled_policy, policy.CompiledPolicy)
                self.assertEqual(
                    session.current_policy(),
                    session.approved_policy_ref,
                )
                self.assertEqual(
                    session.connection.execute("PRAGMA query_only").fetchone()[0],
                    1,
                )
                with self.assertRaises(sqlite3.OperationalError):
                    session.connection.execute(
                        "INSERT INTO schema_migrations "
                        "(version, schema_sha256, applied_by_bootstrap_id) "
                        "VALUES (3, ?, 'reader-write')",
                        ("f" * 64,),
                    )
        finally:
            fcntl.flock(external_shared, fcntl.LOCK_UN)
            os.close(external_shared)

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "not active",
        ):
            session.current_policy()
        self.assertEqual(len(self.migration_rows()), 2)

    def test_reader_rejects_policy_drift_and_nonidle_lane(self):
        ledger_runtime = importlib.import_module("mnemosyne_core.ledger_runtime")
        self.migrate_to_v2()
        with ledger_runtime.open_writer_session(
            self.root,
        ):
            pass
        original_raw = self.registry_path.read_bytes()
        drifted_raw = original_raw.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )
        replacement = self.registry_directory / "placement-map.reader-drift"
        replacement.write_bytes(drifted_raw)
        replacement.chmod(0o600)
        os.replace(replacement, self.registry_path)
        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy binding is not exact",
        ):
            with ledger_runtime.open_reader_session(self.root):
                pass

        replacement.write_bytes(original_raw)
        replacement.chmod(0o600)
        os.replace(replacement, self.registry_path)
        self.mutate_ledger(
            lambda connection: connection.execute(
                "UPDATE policy_mutation_lane SET state = 'ACTIVE', "
                "owner_kind = 'EDIT', owner_proposal_id = 'proposal-test', "
                "owner_approval_id = 'approval-test', owner_run_id = 'run-test', "
                "owner_process_id = 'process-test' WHERE id = 1"
            )
        )
        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy mutation lane is not IDLE",
        ):
            with ledger_runtime.open_reader_session(self.root):
                pass


if __name__ == "__main__":
    unittest.main()
