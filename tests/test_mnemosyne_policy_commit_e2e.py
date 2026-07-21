import contextlib
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from types import FunctionType, SimpleNamespace


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import (  # noqa: E402
    batch_service,
    campaign_ledger,
    explode_service,
    ledger_runtime,
    m2_publishers,
    review_compiler,
    review_context,
    review_snapshot,
)
from mnemosyne_core.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
)
import test_mnemosyne_batch_service as batch_test_helpers  # noqa: E402
from test_mnemosyne_batch_service import (  # noqa: E402
    COMPLETE_CONTEXT,
    ITEM_A,
)
from test_mnemosyne_ledger_runtime import (  # noqa: E402
    LedgerRuntimeFixture,
)
import test_mnemosyne_campaign_ledger as campaign_test_helpers  # noqa: E402
import test_mnemosyne_explode_service as explode_test_helpers  # noqa: E402


def _bind_helper(function, **bindings):
    namespace = dict(function.__globals__)
    namespace.update(bindings)
    return FunctionType(
        function.__code__,
        namespace,
        function.__name__,
        function.__defaults__,
        function.__closure__,
    )


# Build cross-test fixtures from this test's verified core load without
# mutating the imported helper modules used by their own test cases.
unit = _bind_helper(batch_test_helpers.unit, batch_service=batch_service)
make_campaign_request = _bind_helper(
    campaign_test_helpers.make_request,
    campaign_ledger=campaign_ledger,
    canonical_json_bytes=canonical_json_bytes,
)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _CampaignPublisher:
    def plan(self, draft):
        return campaign_ledger.CampaignPublicationPlan(
            campaign_path=draft.campaign_path,
            campaign_bytes=draft.campaign_bytes,
            campaign_sha256=sha256_bytes(draft.campaign_bytes),
            binding_path=draft.binding_path,
            binding_bytes=draft.binding_bytes,
            binding_sha256=sha256_bytes(draft.binding_bytes),
        )

    def publish(self, plan):
        return campaign_ledger.CampaignPublishResult(
            campaign_path=plan.campaign_path,
            campaign_sha256=plan.campaign_sha256,
            binding_path=plan.binding_path,
            binding_sha256=plan.binding_sha256,
        )


class _IntegrationPublisher:
    def plan(self, draft):
        package_sha256 = digest("campaign-integration-package")
        snapshot_payload_sha256 = sha256_bytes(draft.snapshot_payload_json)
        return campaign_ledger.RootIntegrationPlan(
            final_path=draft.snapshot_path,
            snapshot_payload_json=draft.snapshot_payload_json,
            snapshot_payload_sha256=snapshot_payload_sha256,
            package_sha256=package_sha256,
            plan_json=canonical_json_bytes(
                {
                    "final_path": draft.snapshot_path,
                    "package_sha256": package_sha256,
                    "snapshot_payload_sha256": snapshot_payload_sha256,
                }
            ),
        )

    def publish(self, plan):
        return campaign_ledger.RootIntegrationPublishResult(
            final_path=plan.final_path,
            package_sha256=plan.package_sha256,
        )


class PolicyCommitAuthorizerE2ETest(LedgerRuntimeFixture):
    def setUp(self):
        super().setUp()
        self.migrate_to_v2()
        self.original_registry = self.registry_path.read_bytes()
        self.drifted_registry = self.original_registry.replace(
            b"    lifecycle: active\n",
            b"    lifecycle: paused\n",
            1,
        )

    def _write_registry(self, encoded):
        self.registry_path.write_bytes(encoded)
        self.registry_path.chmod(0o600)

    def _seed_ready_campaign(self, connection, policy):
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "INSERT INTO inventory_runs "
                "(run_id, run_sha256, package_path, manifest_sha256, "
                "policy_raw_hash, policy_generation, policy_full_hash, "
                "policy_writer_control_hash, policy_foundation_hash, "
                "policy_source_kind, policy_source_run_id, policy_guard_epoch, "
                "parent_run_id, state) "
                "VALUES ('batch-run-1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "NULL, 'OPENED')",
                (
                    digest("batch-run"),
                    "curation-runs/batch-run-1",
                    digest("batch-manifest"),
                    policy.raw_hash,
                    policy.generation,
                    policy.full_hash,
                    policy.writer_control_hash,
                    policy.foundation_hash,
                    policy.source_kind,
                    policy.source_run_id,
                    policy.guard_epoch,
                ),
            )
            connection.execute(
                "INSERT INTO campaigns "
                "(campaign_id, root_run_id, root_run_sha256, status, "
                "current_snapshot_id, current_snapshot_sha256, review_revision, "
                "active_integration_id, opened_by, payload_json, campaign_path, "
                "campaign_sha256) "
                "VALUES ('batch-campaign-1', 'batch-run-1', ?, 'READY', "
                "'campaign-snapshot-1', ?, 1, NULL, 'e2e-operator', ?, ?, ?)",
                (
                    digest("batch-run"),
                    digest("batch-campaign-head"),
                    b"{}\n",
                    "curation/campaigns/batch-campaign-1/campaign.json",
                    digest("batch-campaign"),
                ),
            )
            connection.execute(
                "INSERT INTO items (item_id, first_seen_run_id, state) "
                "VALUES (?, 'batch-run-1', 'REVIEW_READY')",
                (ITEM_A,),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def _assert_durable_first_drift(self):
        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        try:
            episode = connection.execute(
                "SELECT first_event_id, status FROM policy_guard_episodes"
            ).fetchone()
            event = connection.execute(
                "SELECT event_id, kind, state, observation_path, result_path "
                "FROM policy_guard_events"
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(episode)
        self.assertIsNotNone(event)
        self.assertEqual(episode[:], (event[0], "OPEN"))
        self.assertEqual(event[1:3], ("FIRST_DRIFT", "COMPLETE"))
        observation = json.loads(Path(event[3]).read_bytes())
        result = json.loads(Path(event[4]).read_bytes())
        self.assertEqual(
            observation["observation"]["raw_sha256"],
            hashlib.sha256(self.drifted_registry).hexdigest(),
        )
        self.assertEqual(
            result["final_observation"]["raw_sha256"],
            hashlib.sha256(self.original_registry).hexdigest(),
        )

    def _assert_old_writer_is_blocked(self):
        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "open policy guard episode",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                observed_by="e2e-stale-retry",
            ):
                pass

    def test_batch_final_commit_authorizer_rolls_back_and_records_aba_drift(self):
        final_snapshot_id = "batch-snapshot-1"

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy drift recorded",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                observed_by="batch-policy-commit-e2e",
            ) as session:
                policy = session.approved_policy_ref
                self._seed_ready_campaign(session.connection, policy)
                snapshot_root = (
                    self.curation_directory
                    / "campaigns"
                    / "batch-campaign-1"
                    / "snapshots"
                )
                publisher = m2_publishers.BatchReviewPublisherAdapter(
                    review_publisher=review_snapshot.ReviewSnapshotPublisher(
                        snapshot_root,
                        renderer_id="policy-commit-e2e-v1",
                    ),
                    review_document_factory=(
                        review_context.batch_review_document_from_snapshot
                    ),
                )
                context = review_context.ReviewContext(
                    rendered_at="2026-07-15T08:00:00Z",
                    policy_binding="generation=1;source=INITIAL/e2e;guard=0",
                    coverage=review_compiler.CoverageSummary(
                        0, 0, 0, 0, 1, 0, 1, 0, 0
                    ),
                    workstreams=(
                        review_compiler.WorkstreamSummary(
                            "alpha", "active", 1, 0, 0
                        ),
                    ),
                    warning_codes=("m2-no-structural-authority",),
                )
                request = batch_service.OpenBatchRequest(
                    campaign_id="batch-campaign-1",
                    expected_campaign_head_sha256=digest(
                        "batch-campaign-head"
                    ),
                    expected_campaign_review_revision=1,
                    policy=policy,
                    batch_id="batch-1",
                    snapshot_id=final_snapshot_id,
                    submission_id="batch-submission-1",
                    actor="e2e-operator",
                    review_context_json=context.canonical_bytes(),
                    analysis_contexts_json=canonical_json_bytes(
                        [COMPLETE_CONTEXT]
                    ),
                    units=(unit("unit-a", "projects/alpha/a.md", ITEM_A),),
                    max_items=1,
                    max_files=1,
                    max_bytes=10,
                    max_effects=1,
                )
                flipped = {"value": False}

                def current_policy():
                    observed = session.current_policy()
                    head = session.connection.execute(
                        "SELECT current_snapshot_id FROM review_batches "
                        "WHERE batch_id = 'batch-1'"
                    ).fetchone()
                    if (
                        head is not None
                        and tuple(head) == (final_snapshot_id,)
                        and not flipped["value"]
                    ):
                        self._write_registry(self.drifted_registry)
                        flipped["value"] = True
                    return observed

                service = batch_service.BatchService(
                    session.connection,
                    snapshot_root,
                    placement_shared=session.placement_shared,
                    ledger_exclusive=session.ledger_exclusive,
                    publisher=publisher,
                    current_policy=current_policy,
                )
                try:
                    with self.assertRaises(sqlite3.DatabaseError):
                        service.open_batch(request)
                finally:
                    self._write_registry(self.original_registry)
                self.assertTrue(flipped["value"])

        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        try:
            head = connection.execute(
                "SELECT current_snapshot_id, current_snapshot_sha256, "
                "review_revision FROM review_batches WHERE batch_id = 'batch-1'"
            ).fetchone()
            states = connection.execute(
                "SELECT s.state, r.state FROM review_submissions AS s "
                "JOIN review_snapshots AS r ON r.snapshot_id = s.snapshot_id "
                "WHERE s.submission_id = 'batch-submission-1'"
            ).fetchone()
            membership = connection.execute(
                "SELECT unit_id, item_id, path, status FROM batch_memberships "
                "WHERE batch_id = 'batch-1'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(head, (None, None, 0))
        self.assertEqual(states, ("PREPARED", "PREPARED"))
        self.assertEqual(
            membership,
            ("unit-a", ITEM_A, "projects/alpha/a.md", "OPEN"),
        )
        self.assertEqual(self.registry_path.read_bytes(), self.original_registry)
        self._assert_durable_first_drift()
        self._assert_old_writer_is_blocked()

    def test_campaign_final_commit_authorizer_rolls_back_and_records_aba_drift(self):
        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy drift recorded",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                observed_by="campaign-policy-commit-e2e",
            ) as session:
                request = make_campaign_request(session.approved_policy_ref)
                flipped = {"value": False}

                def current_policy():
                    observed = session.current_policy()
                    row = session.connection.execute(
                        "SELECT status FROM campaigns WHERE campaign_id = ?",
                        (request.campaign_id,),
                    ).fetchone()
                    if (
                        row is not None
                        and tuple(row) == ("READY",)
                        and not flipped["value"]
                    ):
                        self._write_registry(self.drifted_registry)
                        flipped["value"] = True
                    return observed

                binder = campaign_ledger.CampaignRunBinder(
                    connection=session.connection,
                    placement_shared=session.placement_shared,
                    ledger_exclusive=session.ledger_exclusive,
                    current_policy=current_policy,
                    campaign_publisher=_CampaignPublisher(),
                    integration_publisher=_IntegrationPublisher(),
                )
                try:
                    try:
                        binder.open_root_run(request)
                    except (
                        campaign_ledger.CampaignLedgerError,
                        ledger_runtime.LedgerRuntimeError,
                        sqlite3.DatabaseError,
                    ):
                        if not flipped["value"]:
                            raise
                    else:
                        self.fail("campaign final COMMIT was not rejected")
                finally:
                    self._write_registry(self.original_registry)
                self.assertTrue(flipped["value"])

        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        try:
            campaign = connection.execute(
                "SELECT status, current_snapshot_id, current_snapshot_sha256, "
                "review_revision, active_integration_id FROM campaigns "
                "WHERE campaign_id = 'campaign-1'"
            ).fetchone()
            states = connection.execute(
                "SELECT i.state, s.state, r.state FROM run_integrations AS i "
                "JOIN review_submissions AS s ON s.submission_id = i.submission_id "
                "JOIN review_snapshots AS r ON r.snapshot_id = i.snapshot_id "
                "WHERE i.integration_id = 'integration-1'"
            ).fetchone()
            imported = connection.execute(
                "SELECT (SELECT count(*) FROM items), "
                "(SELECT count(*) FROM observations), "
                "(SELECT count(*) FROM observation_item_links), "
                "(SELECT count(*) FROM classification_candidates)"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(
            campaign,
            ("OPENING", None, None, 0, "integration-1"),
        )
        self.assertEqual(states, ("PREPARED", "PREPARED", "PREPARED"))
        self.assertEqual(imported, (0, 0, 0, 0))
        self.assertEqual(self.registry_path.read_bytes(), self.original_registry)
        self._assert_durable_first_drift()
        self._assert_old_writer_is_blocked()

    def test_explode_final_commit_authorizer_rolls_back_and_records_aba_drift(self):
        base_snapshot_id = "explode-snapshot-1"
        next_snapshot_id = "explode-snapshot-2"

        with self.assertRaisesRegex(
            ledger_runtime.LedgerRuntimeError,
            "policy drift recorded",
        ):
            with ledger_runtime.open_writer_session(
                self.root,
                observed_by="explode-policy-commit-e2e",
            ) as session:
                policy = session.approved_policy_ref
                harness = SimpleNamespace(
                    connection=session.connection,
                    policy=policy,
                )
                explode_test_helpers.ExplodeServiceTest._insert_campaign_and_observations(
                    harness
                )
                session.connection.execute(
                    "UPDATE inventory_runs SET policy_raw_hash = ?, "
                    "policy_generation = ?, policy_full_hash = ?, "
                    "policy_writer_control_hash = ?, policy_foundation_hash = ?, "
                    "policy_source_kind = ?, policy_source_run_id = ?, "
                    "policy_guard_epoch = ? WHERE run_id = 'run-1'",
                    (
                        policy.raw_hash,
                        policy.generation,
                        policy.full_hash,
                        policy.writer_control_hash,
                        policy.foundation_hash,
                        policy.source_kind,
                        policy.source_run_id,
                        policy.guard_epoch,
                    ),
                )
                folder = explode_test_helpers.ExplodeServiceTest._folder_unit(
                    harness
                )
                snapshot_root = (
                    self.curation_directory
                    / "campaigns"
                    / "campaign-1"
                    / "snapshots"
                )
                genesis_publisher = m2_publishers.BatchReviewPublisherAdapter(
                    review_publisher=review_snapshot.ReviewSnapshotPublisher(
                        snapshot_root,
                        renderer_id="policy-commit-e2e-v1",
                    ),
                    review_document_factory=(
                        review_context.batch_review_document_from_snapshot
                    ),
                )
                context = review_context.ReviewContext(
                    rendered_at="2026-07-15T08:30:00Z",
                    policy_binding="generation=1;source=INITIAL/e2e;guard=0",
                    coverage=review_compiler.CoverageSummary(
                        1, 1, 0, 0, 2, 2, 0, 0, 0
                    ),
                    workstreams=(
                        review_compiler.WorkstreamSummary(
                            "alpha", "active", 1, 0, 0
                        ),
                    ),
                    warning_codes=("m2-no-structural-authority",),
                )
                genesis = batch_service.BatchService(
                    session.connection,
                    snapshot_root,
                    placement_shared=session.placement_shared,
                    ledger_exclusive=session.ledger_exclusive,
                    publisher=genesis_publisher,
                    current_policy=session.current_policy,
                ).open_batch(
                    batch_service.OpenBatchRequest(
                        campaign_id="campaign-1",
                        expected_campaign_head_sha256=digest("campaign-head"),
                        expected_campaign_review_revision=1,
                        policy=policy,
                        batch_id="explode-batch-1",
                        snapshot_id=base_snapshot_id,
                        submission_id="explode-submission-1",
                        actor="e2e-operator",
                        review_context_json=context.canonical_bytes(),
                        analysis_contexts_json=(
                            explode_test_helpers.ANALYSIS_CONTEXTS_JSON
                        ),
                        units=(folder,),
                        max_items=2,
                        max_files=2,
                        max_bytes=30,
                        max_effects=1,
                    )
                )
                publisher = m2_publishers.BatchReviewPublisherAdapter(
                    review_publisher=review_snapshot.ReviewSnapshotPublisher(
                        snapshot_root,
                        renderer_id="policy-commit-e2e-v1",
                    ),
                    review_document_factory=(
                        explode_service.exploded_batch_review_document_from_snapshot
                    ),
                )
                request = explode_service.ExplodeReviewUnitRequest(
                    batch_id="explode-batch-1",
                    expected_snapshot_id=base_snapshot_id,
                    expected_snapshot_sha256=genesis.snapshot_sha256,
                    expected_review_revision=1,
                    expected_execution_generation=0,
                    policy=policy,
                    folder_unit_id=folder.unit_id,
                    next_snapshot_id=next_snapshot_id,
                    submission_id="explode-submission-2",
                    actor="e2e-operator",
                    analysis_contexts_json=(
                        explode_test_helpers.ANALYSIS_CONTEXTS_JSON
                    ),
                )
                flipped = {"value": False}

                def current_policy():
                    observed = session.current_policy()
                    row = session.connection.execute(
                        "SELECT current_snapshot_id FROM review_batches "
                        "WHERE batch_id = 'explode-batch-1'"
                    ).fetchone()
                    if (
                        row is not None
                        and tuple(row) == (next_snapshot_id,)
                        and not flipped["value"]
                    ):
                        self._write_registry(self.drifted_registry)
                        flipped["value"] = True
                    return observed

                service = explode_service.ExplodeReviewUnitService(
                    session.connection,
                    self.curation_directory,
                    placement_shared=session.placement_shared,
                    ledger_exclusive=session.ledger_exclusive,
                    publisher=publisher,
                    current_policy=current_policy,
                )
                try:
                    with self.assertRaises(sqlite3.DatabaseError):
                        service.explode(request)
                finally:
                    self._write_registry(self.original_registry)
                self.assertTrue(flipped["value"])

        connection = sqlite3.connect(str(self.ledger_path), isolation_level=None)
        try:
            head = connection.execute(
                "SELECT current_snapshot_id, current_snapshot_sha256, "
                "review_revision FROM review_batches "
                "WHERE batch_id = 'explode-batch-1'"
            ).fetchone()
            states = connection.execute(
                "SELECT s.state, r.state FROM review_submissions AS s "
                "JOIN review_snapshots AS r ON r.snapshot_id = s.snapshot_id "
                "WHERE s.submission_id = 'explode-submission-2'"
            ).fetchone()
            memberships = connection.execute(
                "SELECT unit_id, item_id, path, status FROM batch_memberships "
                "WHERE batch_id = 'explode-batch-1' ORDER BY item_id"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(
            head,
            (base_snapshot_id, genesis.snapshot_sha256, 1),
        )
        self.assertEqual(states, ("PREPARED", "PREPARED"))
        self.assertEqual(
            memberships,
            [
                (folder.unit_id, ITEM_A, folder.path, "OPEN"),
                (
                    folder.unit_id,
                    explode_test_helpers.ITEM_B,
                    folder.path,
                    "OPEN",
                ),
            ],
        )
        self.assertEqual(self.registry_path.read_bytes(), self.original_registry)
        self._assert_durable_first_drift()
        self._assert_old_writer_is_blocked()


if __name__ == "__main__":
    import unittest

    unittest.main()
