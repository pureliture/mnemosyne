import sqlite3
import sys
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import admission, campaign_ledger, control, ledger_schema  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


def create_v2_connection():
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in control.CONTROL_SCHEMA_STATEMENTS:
            connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_INDEX_STATEMENTS:
            connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_TRIGGER_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations VALUES (?, ?, ?)",
            (1, control.CONTROL_SCHEMA_SHA256, "bootstrap-v1"),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        connection.close()
        raise
    ledger_schema.ensure_v2_schema(connection, migration_id="document-curation-m2-v2")
    return connection


def make_policy():
    values = ["%064x" % value for value in range(1, 5)]
    return admission.ApprovedPolicyRef(
        raw_hash=values[0],
        full_hash=values[1],
        writer_control_hash=values[2],
        foundation_hash=values[3],
        generation=1,
        source_kind="INITIAL",
        source_run_id="policy-run-1",
        guard_epoch=0,
    )


def install_policy_head(connection, policy):
    connection.execute(
        "INSERT INTO policy_snapshots VALUES (?, ?, ?, ?, ?, ?, ?, 'TERMINAL')",
        (
            "policy-snapshot-1",
            policy.full_hash,
            policy.writer_control_hash,
            policy.foundation_hash,
            b"{}\n",
            policy.source_kind,
            policy.source_run_id,
        ),
    )
    connection.execute(
        "INSERT INTO policy_head VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
        (
            policy.generation,
            policy.full_hash,
            policy.writer_control_hash,
            policy.foundation_hash,
            policy.source_kind,
            policy.source_run_id,
            policy.guard_epoch,
        ),
    )


class GuardRecorder:
    def __init__(self, events):
        self.events = events
        self.placement_held = False
        self.ledger_held = False

    @contextmanager
    def placement_shared(self):
        self.events.append("placement-enter")
        self.placement_held = True
        try:
            yield
        finally:
            self.placement_held = False
            self.events.append("placement-exit")

    @contextmanager
    def ledger_exclusive(self):
        if not self.placement_held:
            raise AssertionError("ledger lock acquired before placement lock")
        self.events.append("ledger-enter")
        self.ledger_held = True
        try:
            yield
        finally:
            self.ledger_held = False
            self.events.append("ledger-exit")


class FakeCampaignPublisher:
    def __init__(self, guards, events):
        self.guards = guards
        self.events = events
        self.publish_count = 0

    def plan(self, draft):
        self.events.append("campaign-plan")
        return campaign_ledger.CampaignPublicationPlan(
            campaign_path=draft.campaign_path,
            campaign_bytes=draft.campaign_bytes,
            campaign_sha256=sha256_bytes(draft.campaign_bytes),
            binding_path=draft.binding_path,
            binding_bytes=draft.binding_bytes,
            binding_sha256=sha256_bytes(draft.binding_bytes),
        )

    def publish(self, plan):
        if not self.guards.placement_held or not self.guards.ledger_held:
            raise AssertionError("publication escaped writer lock lifetime")
        self.events.append("campaign-publish")
        self.publish_count += 1
        return campaign_ledger.CampaignPublishResult(
            campaign_path=plan.campaign_path,
            campaign_sha256=plan.campaign_sha256,
            binding_path=plan.binding_path,
            binding_sha256=plan.binding_sha256,
        )


class FakeIntegrationPublisher:
    def __init__(self, guards, events):
        self.guards = guards
        self.events = events
        self.publish_count = 0

    def plan(self, draft):
        self.events.append("integration-plan")
        snapshot_payload_sha256 = sha256_bytes(draft.snapshot_payload_json)
        package_sha256 = "%064x" % 100
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
        if not self.guards.placement_held or not self.guards.ledger_held:
            raise AssertionError("integration publication escaped writer lock lifetime")
        self.events.append("integration-publish")
        self.publish_count += 1
        return campaign_ledger.RootIntegrationPublishResult(
            final_path=plan.final_path,
            package_sha256=plan.package_sha256,
        )


class CrashOnceCampaignPublisher(FakeCampaignPublisher):
    def publish(self, plan):
        self.publish_count += 1
        self.events.append("campaign-publish")
        if self.publish_count == 1:
            raise RuntimeError("simulated campaign publish crash")
        return campaign_ledger.CampaignPublishResult(
            campaign_path=plan.campaign_path,
            campaign_sha256=plan.campaign_sha256,
            binding_path=plan.binding_path,
            binding_sha256=plan.binding_sha256,
        )


class CrashOnceIntegrationPublisher(FakeIntegrationPublisher):
    def publish(self, plan):
        self.publish_count += 1
        self.events.append("integration-publish")
        if self.publish_count == 1:
            raise RuntimeError("simulated integration publish crash")
        return campaign_ledger.RootIntegrationPublishResult(
            final_path=plan.final_path,
            package_sha256=plan.package_sha256,
        )


class MismatchingIntegrationPublisher(FakeIntegrationPublisher):
    def publish(self, plan):
        self.publish_count += 1
        self.events.append("integration-publish")
        return campaign_ledger.RootIntegrationPublishResult(
            final_path=plan.final_path,
            package_sha256="f" * 64,
        )


def make_request(policy):
    item_id = "11111111-1111-4111-8111-111111111111"
    import_plan = campaign_ledger.RunImportPlan(
        items=(campaign_ledger.ImportedItem(item_id=item_id),),
        observations=(
            campaign_ledger.ImportedObservation(
                observation_key="inventory-root-1:observation-1",
                observation_id="observation-1",
                path="workstreams/alpha/spec.md",
                kind="file",
                payload_json=canonical_json_bytes(
                    {
                        "kind": "file",
                        "path": "workstreams/alpha/spec.md",
                        "scope_class": "active-workstream-content",
                    }
                ),
            ),
        ),
        links=(
            campaign_ledger.ImportedObservationLink(
                link_id="observation-link-1",
                observation_id="observation-1",
                item_id=item_id,
                provenance_json=canonical_json_bytes(
                    {"provider": "root-import", "reason": "first-seen"}
                ),
            ),
        ),
        classification_candidates=(
            campaign_ledger.ImportedClassificationCandidate(
                candidate_id="candidate-1",
                item_id=item_id,
                axis="workstream",
                candidate_value="alpha",
                provider_id="registry-route",
                confidence="high",
                uncertainty=None,
                context_freshness="fresh",
                evidence_json=canonical_json_bytes(
                    {"evidence_id": "evidence-1", "source": "placement-map"}
                ),
            ),
        ),
    )
    snapshot_payload = canonical_json_bytes(
        {
            "campaign_id": "campaign-1",
            "decisions": [],
            "import_payload_sha256": import_plan.sha256,
            "kind": "campaign-genesis-review",
            "root_run_id": "inventory-root-1",
            "schema_version": 1,
            "snapshot_id": "snapshot-1",
            "structural_approval_ready": False,
            "units": [{"unit_id": "unit-from-sealed-run"}],
            "version": 1,
        }
    )
    return campaign_ledger.RootRunRequest(
        run_id="inventory-root-1",
        run_sha256="%064x" % 10,
        run_package_path="curation-runs/inventory-root-1",
        manifest_sha256="%064x" % 11,
        policy=policy,
        campaign_id="campaign-1",
        binding_id="binding-1",
        integration_id="integration-1",
        submission_id="submission-1",
        snapshot_id="snapshot-1",
        campaign_path="curation/campaigns/campaign-1/campaign.json",
        binding_path="curation/campaigns/campaign-1/run-bindings/binding-1/binding.json",
        snapshot_path="curation/campaigns/campaign-1/snapshots/snapshot-1",
        import_plan=import_plan,
        opened_by="test-operator",
        snapshot_payload_json=snapshot_payload,
    )


def rebound_snapshot(request, *, campaign_id=None, snapshot_id=None, import_plan=None):
    payload = __import__("json").loads(request.snapshot_payload_json)
    payload["campaign_id"] = campaign_id or request.campaign_id
    payload["snapshot_id"] = snapshot_id or request.snapshot_id
    payload["import_payload_sha256"] = (
        import_plan or request.import_plan
    ).sha256
    return canonical_json_bytes(payload)


def placement_target(item_id, *, snapshot_id="snapshot-1", uncertainty=None):
    payload_uncertainty = "classification-not-confirmed"
    return campaign_ledger.ImportedPlacementTargetCandidate(
        target_candidate_id="target-candidate-1",
        item_id=item_id,
        snapshot_id=snapshot_id,
        registry_rule_id=None,
        registry_rule_sha256=None,
        target_path=None,
        rename_delta_json=canonical_json_bytes(
            {"from": "spec.md", "to": None}
        ),
        uncertainty=(
            payload_uncertainty if uncertainty is None else uncertainty
        ),
        payload_json=canonical_json_bytes(
            {
                "evidence_ids": ["evidence-1"],
                "input_sha256": "a" * 64,
                "matched_rule_id": None,
                "matched_rule_sha256": None,
                "rename_delta": {"from": "spec.md", "to": None},
                "resolver_version": "target-m2-v1",
                "schema_version": 1,
                "status": "blocked",
                "target_path": None,
                "uncertainty": payload_uncertainty,
            }
        ),
    )


class CampaignRunBinderTest(unittest.TestCase):
    def test_root_request_accepts_exact_snapshot_v2_and_round_trips_it(self):
        request = make_request(make_policy())
        payload = __import__("json").loads(request.snapshot_payload_json)
        payload["schema_version"] = 2
        payload["analysis_contexts"] = [
            {"context_id": "reference-context-aaaaaaaaaaaaaaaaaaaaaaaa"}
        ]
        upgraded = replace(
            request,
            snapshot_payload_json=canonical_json_bytes(payload),
        )

        restored = campaign_ledger.RootRunRequest.from_canonical_bytes(
            upgraded.canonical_bytes()
        )

        self.assertEqual(restored, upgraded)

    def test_root_request_rejects_missing_duplicate_or_unsorted_v2_contexts(self):
        request = make_request(make_policy())
        payload = __import__("json").loads(request.snapshot_payload_json)
        payload["schema_version"] = 2
        invalid = (
            None,
            [],
            [
                {"context_id": "reference-context-bbbbbbbbbbbbbbbbbbbbbbbb"},
                {"context_id": "reference-context-aaaaaaaaaaaaaaaaaaaaaaaa"},
            ],
            [
                {"context_id": "reference-context-aaaaaaaaaaaaaaaaaaaaaaaa"},
                {"context_id": "reference-context-aaaaaaaaaaaaaaaaaaaaaaaa"},
            ],
        )

        for contexts in invalid:
            with self.subTest(contexts=contexts):
                candidate = dict(payload)
                if contexts is not None:
                    candidate["analysis_contexts"] = contexts
                with self.assertRaisesRegex(ValueError, "snapshot payload"):
                    replace(
                        request,
                        snapshot_payload_json=canonical_json_bytes(candidate),
                    )

    def test_target_candidate_payload_fields_are_exactly_bound(self):
        item_id = "11111111-1111-4111-8111-111111111111"
        with self.assertRaisesRegex(ValueError, "payload"):
            placement_target(item_id, uncertainty="different-uncertainty")

    def test_root_request_rejects_target_from_a_different_snapshot(self):
        request = make_request(make_policy())
        plan = replace(
            request.import_plan,
            placement_target_candidates=(
                placement_target(
                    request.import_plan.items[0].item_id,
                    snapshot_id="snapshot-other",
                ),
            ),
        )

        with self.assertRaisesRegex(ValueError, "snapshot"):
            replace(
                request,
                import_plan=plan,
                snapshot_payload_json=rebound_snapshot(
                    request,
                    import_plan=plan,
                ),
            )

    @staticmethod
    def make_fixture(
        campaign_publisher_type=FakeCampaignPublisher,
        integration_publisher_type=FakeIntegrationPublisher,
        current_policy=None,
    ):
        connection = create_v2_connection()
        policy = make_policy()
        install_policy_head(connection, policy)
        events = []
        guards = GuardRecorder(events)
        campaign_publisher = campaign_publisher_type(guards, events)
        integration_publisher = integration_publisher_type(guards, events)
        binder = campaign_ledger.CampaignRunBinder(
            connection=connection,
            placement_shared=guards.placement_shared,
            ledger_exclusive=guards.ledger_exclusive,
            current_policy=current_policy or (lambda: policy),
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )
        return (
            connection,
            policy,
            events,
            campaign_publisher,
            integration_publisher,
            binder,
        )

    def test_root_run_reserves_publishes_and_integrates_under_ordered_locks(self):
        connection = create_v2_connection()
        policy = make_policy()
        install_policy_head(connection, policy)
        events = []
        guards = GuardRecorder(events)
        campaign_publisher = FakeCampaignPublisher(guards, events)
        integration_publisher = FakeIntegrationPublisher(guards, events)
        connection.set_trace_callback(
            lambda statement: events.append("sql:" + " ".join(statement.split()))
        )
        binder = campaign_ledger.CampaignRunBinder(
            connection=connection,
            placement_shared=guards.placement_shared,
            ledger_exclusive=guards.ledger_exclusive,
            current_policy=lambda: policy,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )
        try:
            result = binder.open_root_run(make_request(policy))
            campaign = connection.execute(
                "SELECT status, current_snapshot_id, current_snapshot_sha256, "
                "review_revision, active_integration_id FROM campaigns"
            ).fetchone()
            binding = connection.execute(
                "SELECT state FROM campaign_run_bindings"
            ).fetchone()
            integration = connection.execute(
                "SELECT state FROM run_integrations"
            ).fetchone()
            submission = connection.execute(
                "SELECT state FROM review_submissions"
            ).fetchone()
            snapshot = connection.execute(
                "SELECT state, structural_approval_ready FROM review_snapshots"
            ).fetchone()
            imported_counts = tuple(
                connection.execute("SELECT count(*) FROM " + table).fetchone()[0]
                for table in (
                    "items",
                    "observations",
                    "observation_item_links",
                    "classification_candidates",
                )
            )
        finally:
            connection.close()

        self.assertEqual(result.status, "READY")
        self.assertEqual(result.campaign_id, "campaign-1")
        self.assertEqual(
            campaign,
            ("READY", "snapshot-1", sha256_bytes(result.snapshot_payload_json), 1, None),
        )
        self.assertEqual(binding, ("PUBLISHED",))
        self.assertEqual(integration, ("INTEGRATED",))
        self.assertEqual(submission, ("COMMITTED",))
        self.assertEqual(snapshot, ("PUBLISHED", 0))
        self.assertEqual(imported_counts, (1, 1, 1, 1))
        self.assertEqual(
            result.snapshot_payload_json,
            make_request(policy).snapshot_payload_json,
        )
        first_begin = next(
            index for index, event in enumerate(events) if event == "sql:BEGIN IMMEDIATE"
        )
        self.assertLess(events.index("integration-plan"), events.index("placement-enter"))
        self.assertLess(events.index("campaign-plan"), events.index("placement-enter"))
        self.assertLess(events.index("placement-enter"), events.index("ledger-enter"))
        self.assertLess(events.index("ledger-enter"), first_begin)
        self.assertEqual(campaign_publisher.publish_count, 1)
        self.assertEqual(integration_publisher.publish_count, 1)

    def test_public_prepared_root_executes_without_replanning_under_guards(self):
        (
            connection,
            policy,
            events,
            campaign_publisher,
            integration_publisher,
            binder,
        ) = self.make_fixture()
        request = make_request(policy)
        try:
            prepared = campaign_ledger.prepare_root_publication(
                request,
                campaign_publisher=campaign_publisher,
                integration_publisher=integration_publisher,
            )
            self.assertIsInstance(
                prepared,
                campaign_ledger.PreparedRootPublication,
            )
            self.assertEqual(
                events,
                ["integration-plan", "campaign-plan"],
            )

            result = binder.open_prepared_root_run(request, prepared)
        finally:
            connection.close()

        self.assertEqual(result.status, "READY")
        self.assertEqual(events.count("integration-plan"), 1)
        self.assertEqual(events.count("campaign-plan"), 1)
        self.assertLess(events.index("campaign-plan"), events.index("placement-enter"))

    def test_prepared_root_rejects_rebound_request_before_any_write(self):
        (
            connection,
            policy,
            _events,
            campaign_publisher,
            integration_publisher,
            binder,
        ) = self.make_fixture()
        request = make_request(policy)
        prepared = campaign_ledger.prepare_root_publication(
            request,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )
        rebound = replace(request, opened_by="different-operator")
        try:
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "changed canonical request",
            ):
                binder.open_prepared_root_run(rebound, prepared)
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM campaigns), "
                "(SELECT count(*) FROM campaign_run_bindings)"
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(counts, (0, 0))
        self.assertEqual(campaign_publisher.publish_count, 0)
        self.assertEqual(integration_publisher.publish_count, 0)

    def test_prepared_root_rejects_tampered_plan_before_any_write(self):
        (
            connection,
            policy,
            _events,
            campaign_publisher,
            integration_publisher,
            binder,
        ) = self.make_fixture()
        request = make_request(policy)
        prepared = campaign_ledger.prepare_root_publication(
            request,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )
        tampered = replace(
            prepared,
            integration_plan=replace(
                prepared.integration_plan,
                package_sha256="f" * 64,
            ),
        )
        try:
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "does not bind the exact draft",
            ):
                binder.open_prepared_root_run(request, tampered)
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM campaigns), "
                "(SELECT count(*) FROM campaign_run_bindings)"
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(counts, (0, 0))
        self.assertEqual(campaign_publisher.publish_count, 0)
        self.assertEqual(integration_publisher.publish_count, 0)

    def test_compatibility_resume_replans_only_between_guard_lifetimes(self):
        (
            connection,
            policy,
            events,
            _campaign_publisher,
            _integration_publisher,
            binder,
        ) = self.make_fixture()
        request = make_request(policy)
        try:
            binder.open_root_run(request)
            events.clear()
            result = binder.resume_root_run(request.run_id)
        finally:
            connection.close()

        placement_enters = [
            index
            for index, event in enumerate(events)
            if event == "placement-enter"
        ]
        self.assertTrue(result.resumed)
        self.assertEqual(len(placement_enters), 2)
        self.assertLess(events.index("placement-exit"), events.index("integration-plan"))
        self.assertLess(events.index("campaign-plan"), placement_enters[1])

    def test_ready_retry_returns_exact_campaign_without_republishing(self):
        (
            connection,
            policy,
            _events,
            campaign_publisher,
            integration_publisher,
            binder,
        ) = self.make_fixture()
        request = make_request(policy)
        try:
            first = binder.open_root_run(request)
            second = binder.open_root_run(request)
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM campaigns), "
                "(SELECT count(*) FROM campaign_run_bindings), "
                "(SELECT count(*) FROM run_integrations)"
            ).fetchone()
        finally:
            connection.close()

        self.assertFalse(first.resumed)
        self.assertTrue(second.resumed)
        self.assertEqual(counts, (1, 1, 1))
        self.assertEqual(campaign_publisher.publish_count, 1)
        self.assertEqual(integration_publisher.publish_count, 1)

    def test_ready_retry_rejects_import_row_drift_even_when_counts_match(self):
        (
            connection,
            policy,
            _events,
            _campaign_publisher,
            _integration_publisher,
            binder,
        ) = self.make_fixture()
        request = make_request(policy)
        try:
            binder.open_root_run(request)
            connection.execute(
                "UPDATE observations SET path = 'workstreams/other/spec.md' "
                "WHERE observation_id = 'observation-1'"
            )
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "integrated import data mismatch",
            ):
                binder.resume_root_run(request.run_id)
        finally:
            connection.close()

    def test_binder_accepts_sqlite_row_factory(self):
        (
            connection,
            policy,
            _events,
            _campaign_publisher,
            _integration_publisher,
            binder,
        ) = self.make_fixture()
        connection.row_factory = sqlite3.Row
        try:
            result = binder.open_root_run(make_request(policy))
        finally:
            connection.close()

        self.assertEqual(result.status, "READY")

    def test_campaign_publish_crash_resumes_the_same_prepared_binding(self):
        (
            connection,
            policy,
            _events,
            campaign_publisher,
            integration_publisher,
            binder,
        ) = self.make_fixture(campaign_publisher_type=CrashOnceCampaignPublisher)
        request = make_request(policy)
        try:
            with self.assertRaisesRegex(RuntimeError, "campaign publish crash"):
                binder.open_root_run(request)
            prepared = connection.execute(
                "SELECT c.status, b.state, c.active_integration_id "
                "FROM campaigns c JOIN campaign_run_bindings b "
                "ON b.campaign_id = c.campaign_id"
            ).fetchone()

            result = binder.resume_root_run(request.run_id)
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM campaigns), "
                "(SELECT count(*) FROM campaign_run_bindings)"
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(prepared, ("OPENING", "PREPARED", None))
        self.assertEqual(result.status, "READY")
        self.assertTrue(result.resumed)
        self.assertEqual(counts, (1, 1))
        self.assertEqual(campaign_publisher.publish_count, 2)
        self.assertEqual(integration_publisher.publish_count, 1)

    def test_integration_publish_crash_resumes_without_republishing_binding(self):
        (
            connection,
            policy,
            _events,
            campaign_publisher,
            integration_publisher,
            binder,
        ) = self.make_fixture(
            integration_publisher_type=CrashOnceIntegrationPublisher
        )
        request = make_request(policy)
        try:
            with self.assertRaisesRegex(RuntimeError, "integration publish crash"):
                binder.open_root_run(request)
            prepared = connection.execute(
                "SELECT c.status, b.state, i.state, s.state, r.state "
                "FROM campaigns c "
                "JOIN campaign_run_bindings b ON b.campaign_id = c.campaign_id "
                "JOIN run_integrations i ON i.binding_id = b.binding_id "
                "JOIN review_submissions s ON s.submission_id = i.submission_id "
                "JOIN review_snapshots r ON r.snapshot_id = i.snapshot_id"
            ).fetchone()

            result = binder.resume_root_run(request.run_id)
        finally:
            connection.close()

        self.assertEqual(
            prepared,
            ("OPENING", "PUBLISHED", "PREPARED", "PREPARED", "PREPARED"),
        )
        self.assertEqual(result.status, "READY")
        self.assertTrue(result.resumed)
        self.assertEqual(campaign_publisher.publish_count, 1)
        self.assertEqual(integration_publisher.publish_count, 2)

    def test_resume_uses_stored_uuid_plan_and_rejects_new_caller_uuid(self):
        (
            connection,
            policy,
            _events,
            _campaign_publisher,
            _integration_publisher,
            binder,
        ) = self.make_fixture(campaign_publisher_type=CrashOnceCampaignPublisher)
        request = make_request(policy)
        try:
            with self.assertRaises(RuntimeError):
                binder.open_root_run(request)
            stored = connection.execute(
                "SELECT request_json, request_sha256, integration_plan_json, "
                "integration_plan_sha256 FROM campaign_run_bindings"
            ).fetchone()
            stored_request = campaign_ledger.RootRunRequest.from_canonical_bytes(
                bytes(stored[0])
            )

            replacement_item_id = "22222222-2222-4222-8222-222222222222"
            changed_plan = campaign_ledger.RunImportPlan(
                items=(campaign_ledger.ImportedItem(replacement_item_id),),
                observations=request.import_plan.observations,
                links=(
                    replace(
                        request.import_plan.links[0],
                        item_id=replacement_item_id,
                    ),
                ),
                classification_candidates=(
                    replace(
                        request.import_plan.classification_candidates[0],
                        item_id=replacement_item_id,
                    ),
                ),
            )
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "already bound to another campaign",
            ):
                binder.open_root_run(
                    replace(
                        request,
                        import_plan=changed_plan,
                        snapshot_payload_json=rebound_snapshot(
                            request,
                            import_plan=changed_plan,
                        ),
                    )
                )

            result = binder.resume_root_run(request.run_id)
        finally:
            connection.close()

        self.assertEqual(
            stored_request.import_plan.items[0].item_id,
            request.import_plan.items[0].item_id,
        )
        self.assertEqual(sha256_bytes(bytes(stored[0])), stored[1])
        self.assertEqual(sha256_bytes(bytes(stored[2])), stored[3])
        self.assertEqual(result.status, "READY")

    def test_wrong_policy_is_rejected_before_any_campaign_reservation(self):
        connection = create_v2_connection()
        policy = make_policy()
        install_policy_head(connection, policy)
        wrong_policy = replace(policy, raw_hash="e" * 64)
        events = []
        guards = GuardRecorder(events)
        campaign_publisher = FakeCampaignPublisher(guards, events)
        integration_publisher = FakeIntegrationPublisher(guards, events)
        binder = campaign_ledger.CampaignRunBinder(
            connection=connection,
            placement_shared=guards.placement_shared,
            ledger_exclusive=guards.ledger_exclusive,
            current_policy=lambda: wrong_policy,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )
        try:
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "current policy authority drifted",
            ):
                binder.open_root_run(make_request(policy))
            count = connection.execute("SELECT count(*) FROM campaigns").fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(count, 0)
        self.assertEqual(campaign_publisher.publish_count, 0)
        self.assertEqual(integration_publisher.publish_count, 0)

    def test_policy_drift_before_prepared_commit_rolls_back_reservation(self):
        connection = create_v2_connection()
        policy = make_policy()
        install_policy_head(connection, policy)
        wrong_policy = replace(policy, raw_hash="e" * 64)
        drifted = {"value": False}

        def policy_reader():
            return wrong_policy if drifted["value"] else policy

        events = []
        guards = GuardRecorder(events)
        campaign_publisher = FakeCampaignPublisher(guards, events)
        integration_publisher = FakeIntegrationPublisher(guards, events)
        binder = campaign_ledger.CampaignRunBinder(
            connection=connection,
            placement_shared=guards.placement_shared,
            ledger_exclusive=guards.ledger_exclusive,
            current_policy=policy_reader,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )

        def trace(statement):
            if "INSERT INTO CAMPAIGN_RUN_BINDINGS" in statement.upper():
                drifted["value"] = True

        connection.set_trace_callback(trace)
        try:
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "current policy authority drifted",
            ):
                binder.open_root_run(make_request(policy))
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM campaigns), "
                "(SELECT count(*) FROM campaign_run_bindings), "
                "(SELECT count(*) FROM inventory_runs)"
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(counts, (0, 0, 0))
        self.assertEqual(campaign_publisher.publish_count, 0)
        self.assertEqual(integration_publisher.publish_count, 0)

    def test_policy_drift_after_campaign_publish_preserves_prepared_opening(self):
        connection = create_v2_connection()
        policy = make_policy()
        install_policy_head(connection, policy)
        wrong_policy = replace(policy, raw_hash="e" * 64)

        events = []
        guards = GuardRecorder(events)
        campaign_publisher = FakeCampaignPublisher(guards, events)
        integration_publisher = FakeIntegrationPublisher(guards, events)

        def policy_reader():
            return (
                wrong_policy
                if campaign_publisher.publish_count
                else policy
            )

        binder = campaign_ledger.CampaignRunBinder(
            connection=connection,
            placement_shared=guards.placement_shared,
            ledger_exclusive=guards.ledger_exclusive,
            current_policy=policy_reader,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )
        try:
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "current policy authority drifted",
            ):
                binder.open_root_run(make_request(policy))
            states = connection.execute(
                "SELECT c.status, c.current_snapshot_id, c.review_revision, "
                "c.active_integration_id, b.state FROM campaigns c "
                "JOIN campaign_run_bindings b ON b.campaign_id = c.campaign_id"
            ).fetchone()
            imported = connection.execute(
                "SELECT count(*) FROM items"
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(states, ("OPENING", None, 0, None, "PREPARED"))
        self.assertEqual(imported, 0)
        self.assertEqual(campaign_publisher.publish_count, 1)
        self.assertEqual(integration_publisher.publish_count, 0)

    def test_policy_drift_after_integration_publish_preserves_prepared_state(self):
        connection = create_v2_connection()
        policy = make_policy()
        install_policy_head(connection, policy)
        wrong_policy = replace(policy, raw_hash="e" * 64)
        events = []
        guards = GuardRecorder(events)
        campaign_publisher = FakeCampaignPublisher(guards, events)
        integration_publisher = FakeIntegrationPublisher(guards, events)

        def policy_reader():
            return (
                wrong_policy
                if integration_publisher.publish_count
                else policy
            )

        binder = campaign_ledger.CampaignRunBinder(
            connection=connection,
            placement_shared=guards.placement_shared,
            ledger_exclusive=guards.ledger_exclusive,
            current_policy=policy_reader,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )
        try:
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "current policy authority drifted",
            ):
                binder.open_root_run(make_request(policy))
            states = connection.execute(
                "SELECT c.status, c.current_snapshot_id, c.review_revision, "
                "c.active_integration_id, b.state, i.state, s.state, r.state "
                "FROM campaigns c "
                "JOIN campaign_run_bindings b ON b.campaign_id = c.campaign_id "
                "JOIN run_integrations i ON i.binding_id = b.binding_id "
                "JOIN review_submissions s ON s.submission_id = i.submission_id "
                "JOIN review_snapshots r ON r.snapshot_id = i.snapshot_id"
            ).fetchone()
            imported = connection.execute(
                "SELECT count(*) FROM items"
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(
            states,
            (
                "OPENING",
                None,
                0,
                "integration-1",
                "PUBLISHED",
                "PREPARED",
                "PREPARED",
                "PREPARED",
            ),
        )
        self.assertEqual(imported, 0)
        self.assertEqual(campaign_publisher.publish_count, 1)
        self.assertEqual(integration_publisher.publish_count, 1)

    def test_policy_drift_at_final_commit_rolls_back_import_and_head(self):
        connection = create_v2_connection()
        policy = make_policy()
        install_policy_head(connection, policy)
        wrong_policy = replace(policy, raw_hash="e" * 64)
        drifted = {"value": False}

        def policy_reader():
            return wrong_policy if drifted["value"] else policy

        events = []
        guards = GuardRecorder(events)
        campaign_publisher = FakeCampaignPublisher(guards, events)
        integration_publisher = FakeIntegrationPublisher(guards, events)
        binder = campaign_ledger.CampaignRunBinder(
            connection=connection,
            placement_shared=guards.placement_shared,
            ledger_exclusive=guards.ledger_exclusive,
            current_policy=policy_reader,
            campaign_publisher=campaign_publisher,
            integration_publisher=integration_publisher,
        )

        def trace(statement):
            if "UPDATE CAMPAIGNS SET STATUS = 'READY'" in statement.upper():
                drifted["value"] = True

        connection.set_trace_callback(trace)
        try:
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "current policy authority drifted",
            ):
                binder.open_root_run(make_request(policy))
            states = connection.execute(
                "SELECT c.status, c.current_snapshot_id, c.current_snapshot_sha256, "
                "c.review_revision, c.active_integration_id, i.state, s.state, r.state "
                "FROM campaigns c "
                "JOIN run_integrations i ON i.campaign_id = c.campaign_id "
                "JOIN review_submissions s ON s.submission_id = i.submission_id "
                "JOIN review_snapshots r ON r.snapshot_id = i.snapshot_id"
            ).fetchone()
            imported = connection.execute(
                "SELECT (SELECT count(*) FROM items), "
                "(SELECT count(*) FROM observations), "
                "(SELECT count(*) FROM observation_item_links), "
                "(SELECT count(*) FROM classification_candidates), "
                "(SELECT count(*) FROM placement_target_candidates)"
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(
            states,
            (
                "OPENING",
                None,
                None,
                0,
                "integration-1",
                "PREPARED",
                "PREPARED",
                "PREPARED",
            ),
        )
        self.assertEqual(imported, (0, 0, 0, 0, 0))

    def test_one_root_run_cannot_open_a_second_campaign(self):
        (
            connection,
            policy,
            _events,
            _campaign_publisher,
            _integration_publisher,
            binder,
        ) = self.make_fixture()
        request = make_request(policy)
        try:
            binder.open_root_run(request)
            conflicting = replace(
                request,
                campaign_id="campaign-2",
                binding_id="binding-2",
                integration_id="integration-2",
                submission_id="submission-2",
                snapshot_id="snapshot-2",
                campaign_path="curation/campaigns/campaign-2/campaign.json",
                binding_path=(
                    "curation/campaigns/campaign-2/run-bindings/binding-2/binding.json"
                ),
                snapshot_path="curation/campaigns/campaign-2/snapshots/snapshot-2",
                snapshot_payload_json=rebound_snapshot(
                    request,
                    campaign_id="campaign-2",
                    snapshot_id="snapshot-2",
                ),
            )
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "already bound to another campaign",
            ):
                binder.open_root_run(conflicting)
            count = connection.execute("SELECT count(*) FROM campaigns").fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(count, 1)

    def test_mismatching_snapshot_readback_blocks_without_importing_rows(self):
        (
            connection,
            policy,
            _events,
            _campaign_publisher,
            _integration_publisher,
            binder,
        ) = self.make_fixture(
            integration_publisher_type=MismatchingIntegrationPublisher
        )
        try:
            with self.assertRaisesRegex(
                campaign_ledger.CampaignLedgerError,
                "integration publication readback mismatch",
            ):
                binder.open_root_run(make_request(policy))
            states = connection.execute(
                "SELECT c.status, i.state, s.state, r.state "
                "FROM campaigns c "
                "JOIN run_integrations i ON i.campaign_id = c.campaign_id "
                "JOIN review_submissions s ON s.submission_id = i.submission_id "
                "JOIN review_snapshots r ON r.snapshot_id = i.snapshot_id"
            ).fetchone()
            imported = connection.execute("SELECT count(*) FROM items").fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(states, ("BLOCKED", "BLOCKED", "BLOCKED", "BLOCKED"))
        self.assertEqual(imported, 0)


if __name__ == "__main__":
    unittest.main()
