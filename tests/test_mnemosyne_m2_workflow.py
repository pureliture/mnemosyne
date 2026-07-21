import fcntl
import inspect
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import (  # noqa: E402
    admission,
    batch_service,
    campaign_ledger,
    explode_service,
    inventory,
    m2_workflow,
    policy,
    policy_authority,
    review_compiler,
    review_context,
    review_draft,
)
from mnemosyne_core.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
)


def approved_policy():
    return admission.ApprovedPolicyRef(
        raw_hash="1" * 64,
        full_hash="2" * 64,
        writer_control_hash="3" * 64,
        foundation_hash="4" * 64,
        generation=1,
        source_kind="INITIAL",
        source_run_id="policy-run-1",
        guard_epoch=0,
    )


def analysis_context(*, context_suffix="a"):
    content = {
        "analyzer_version": "reference-m2-v2",
        "coverage_issues": [],
        "documents": [],
        "edges": [],
        "frontier_complete": True,
        "navigation_sources": [],
        "parser_types": list(inventory._REFERENCE_PARSER_TYPES),
        "registry_source": {
            "kind": "compiled-registry",
            "sha256": context_suffix * 64,
            "source_id": "placement-registry",
        },
        "scanned_roots": ["projects/alpha"],
    }
    content_sha256 = sha256_bytes(canonical_json_bytes(content))
    value = dict(content)
    value.update(
        {
            "content_sha256": content_sha256,
            "context_id": "reference-context-%s" % content_sha256[:24],
            "schema_version": 1,
        }
    )
    value["context_sha256"] = sha256_bytes(canonical_json_bytes(value))
    return value


def workflow_batch_unit(source_context, *, unit_kind="file"):
    path = "projects/alpha" if unit_kind == "folder" else "projects/alpha/a.md"
    member_paths = (
        ("projects/alpha/a.md", "projects/alpha/b.md")
        if unit_kind == "folder"
        else (path,)
    )
    member_ids = (
        (
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        )
        if unit_kind == "folder"
        else ("11111111-1111-4111-8111-111111111111",)
    )
    provenance_items = []
    for item_id, member_path in zip(member_ids, member_paths):
        provenance_items.append(
            {
                "item_id": item_id,
                "reference": {
                    "candidate_path": member_path,
                    "complete": False,
                    "context_id": source_context["context_id"],
                    "context_sha256": source_context["context_sha256"],
                    "input_manifest_sha256": sha256_bytes(
                        canonical_json_bytes(source_context)
                    ),
                    "matches": [],
                    "schema_version": 2,
                },
                "risk": {"band": "medium", "input_sha256": "b" * 64},
                "target": {"input_sha256": "c" * 64, "status": "blocked"},
            }
        )
    return batch_service.BatchUnit(
        unit_id="unit-folder" if unit_kind == "folder" else "unit-a",
        unit_kind=unit_kind,
        path=path,
        display_path=path,
        member_item_ids=member_ids,
        member_paths=member_paths,
        scope_class="eligible",
        sensitivity="standard",
        access_domain="local",
        primary_workstream="alpha",
        related_workstreams=(),
        shared=False,
        document_role="docs",
        authority="reference",
        document_lifecycle="current",
        lifecycle_class="active",
        override_class="none",
        scope_rule_id="active-workstream-content",
        recommended_action="keep",
        target_path=None,
        reference_complete=False,
        risk_band="medium",
        context_freshness="fresh",
        evidence_providers=("registry-route",),
        warning_codes=(
            "m2-no-structural-authority",
            "reference-incomplete",
        ),
        effect_codes=("plan-unavailable-m2",),
        canonical_conflict=False,
        relation_conflict=False,
        target_proven=False,
        analysis_provenance_json=canonical_json_bytes(
            {"items": provenance_items, "schema_version": 1}
        ),
        file_count=len(member_ids),
        total_bytes=12 * len(member_ids),
        effect_count=0,
    )


def create_sealed_package_members(final_path):
    review_path = final_path / "review"
    final_path.mkdir(parents=True, mode=0o700)
    review_path.mkdir(mode=0o700)
    members = {
        final_path / "manifest.json": b"manifest-a\n",
        final_path / "snapshot.json": b"snapshot-a\n",
        review_path / "review.html": b"html-a\n",
        review_path / "review.md": b"markdown-a\n",
        review_path / "review.meta.json": b"meta-a\n",
    }
    for path, payload in members.items():
        path.write_bytes(payload)
        path.chmod(0o600)
    return members


def root_request(
    policy_ref,
    *,
    run_id="run-1",
    campaign_id="campaign-existing",
):
    import_plan = campaign_ledger.RunImportPlan(
        items=(),
        observations=(
            campaign_ledger.ImportedObservation(
                observation_key="%s:obs-1" % run_id,
                observation_id="obs-1",
                path="projects/alpha/a.md",
                kind="file",
                payload_json=canonical_json_bytes(
                    {"path": "projects/alpha/a.md"}
                ),
            ),
        ),
        links=(),
        classification_candidates=(),
    )
    snapshot_id = "snapshot-existing"
    snapshot_payload = canonical_json_bytes(
        {
            "campaign_id": campaign_id,
            "decisions": [],
            "import_payload_sha256": import_plan.sha256,
            "kind": "campaign-genesis-review",
            "root_run_id": run_id,
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "structural_approval_ready": False,
            "version": 1,
        }
    )
    return campaign_ledger.RootRunRequest(
        run_id=run_id,
        run_sha256="5" * 64,
        run_package_path="_registry/curation-runs/%s" % run_id,
        manifest_sha256="5" * 64,
        policy=policy_ref,
        campaign_id=campaign_id,
        binding_id="binding-existing",
        integration_id="integration-existing",
        submission_id="submission-existing",
        snapshot_id=snapshot_id,
        campaign_path="campaigns/%s/campaign.json" % campaign_id,
        binding_path=(
            "campaigns/%s/run-bindings/binding-existing/binding.json"
            % campaign_id
        ),
        snapshot_path="campaigns/%s/snapshots/%s" % (
            campaign_id,
            snapshot_id,
        ),
        import_plan=import_plan,
        opened_by="reviewer",
        snapshot_payload_json=snapshot_payload,
    )


class FakeSession:
    def __init__(self, root):
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute(
            "CREATE TABLE campaign_run_bindings "
            "(run_id TEXT PRIMARY KEY, request_json BLOB NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE campaigns ("
            "campaign_id TEXT PRIMARY KEY, status TEXT NOT NULL, "
            "current_snapshot_id TEXT, current_snapshot_sha256 TEXT, "
            "review_revision INTEGER NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE review_batches ("
            "batch_id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, "
            "status TEXT NOT NULL, current_snapshot_id TEXT, "
            "current_snapshot_sha256 TEXT, review_revision INTEGER NOT NULL, "
            "execution_generation INTEGER NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE review_snapshots ("
            "snapshot_id TEXT PRIMARY KEY, lineage_kind TEXT NOT NULL, "
            "campaign_id TEXT NOT NULL, batch_id TEXT, version INTEGER NOT NULL, "
            "payload_sha256 TEXT NOT NULL, final_path TEXT NOT NULL, "
            "final_sha256 TEXT NOT NULL, state TEXT NOT NULL, "
            "structural_approval_ready INTEGER NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE review_submissions ("
            "submission_id TEXT PRIMARY KEY, campaign_id TEXT, "
            "payload_json BLOB NOT NULL, "
            "payload_sha256 TEXT NOT NULL, state TEXT NOT NULL)"
        )
        self.approved_policy_ref = approved_policy()
        self.compiled_policy = SimpleNamespace(
            foundation=policy.CompiledFoundation(
                profile_version=1,
                state_root=str(root / "_registry" / "curation"),
                runs_root=str(root / "_registry" / "curation-runs"),
            )
        )

    def current_policy(self):
        return self.approved_policy_ref

    @contextmanager
    def placement_shared(self):
        yield

    @contextmanager
    def ledger_exclusive(self):
        yield


class RootPlanProbeCampaignPublisher:
    def __init__(self, active, events):
        self.active = active
        self.events = events

    def plan(self, draft):
        if self.active["writer"]:
            raise AssertionError("campaign plan ran under writer lifetime")
        self.events.append("campaign-plan")
        return campaign_ledger.CampaignPublicationPlan(
            campaign_path=draft.campaign_path,
            campaign_bytes=draft.campaign_bytes,
            campaign_sha256=sha256_bytes(draft.campaign_bytes),
            binding_path=draft.binding_path,
            binding_bytes=draft.binding_bytes,
            binding_sha256=sha256_bytes(draft.binding_bytes),
        )

    def publish(self, _plan):
        raise AssertionError("fake binder must own publication")


class RootPlanProbeIntegrationPublisher:
    def __init__(self, active, events):
        self.active = active
        self.events = events

    def plan(self, draft):
        if self.active["writer"]:
            raise AssertionError("integration review plan ran under writer lifetime")
        self.events.append("integration-plan")
        snapshot_sha256 = sha256_bytes(draft.snapshot_payload_json)
        package_sha256 = "6" * 64
        return campaign_ledger.RootIntegrationPlan(
            final_path=draft.snapshot_path,
            snapshot_payload_json=draft.snapshot_payload_json,
            snapshot_payload_sha256=snapshot_sha256,
            package_sha256=package_sha256,
            plan_json=canonical_json_bytes(
                {
                    "final_path": draft.snapshot_path,
                    "package_sha256": package_sha256,
                    "snapshot_payload_sha256": snapshot_sha256,
                }
            ),
        )

    def publish(self, _plan):
        raise AssertionError("fake binder must own publication")


class M2WorkflowTest(unittest.TestCase):
    def fake_session(self, root):
        session = FakeSession(root)
        self.addCleanup(session.connection.close)
        return session

    @staticmethod
    def seed_campaign_head(session, head, *, final_path, package_sha256):
        session.connection.execute(
            "INSERT INTO campaigns "
            "(campaign_id, status, current_snapshot_id, "
            "current_snapshot_sha256, review_revision) "
            "VALUES (?, 'READY', ?, ?, ?)",
            (
                head.campaign_id,
                head.current_snapshot_id,
                head.current_snapshot_sha256,
                head.review_revision,
            ),
        )
        session.connection.execute(
            "INSERT INTO review_snapshots "
            "(snapshot_id, lineage_kind, campaign_id, batch_id, version, "
            "payload_sha256, final_path, final_sha256, state, "
            "structural_approval_ready) "
            "VALUES (?, 'CAMPAIGN', ?, NULL, ?, ?, ?, ?, 'PUBLISHED', 0)",
            (
                head.current_snapshot_id,
                head.campaign_id,
                head.review_revision,
                head.current_snapshot_sha256,
                str(final_path),
                package_sha256,
            ),
        )

    @staticmethod
    def seed_batch_head(session, head, *, final_path, package_sha256):
        session.connection.execute(
            "INSERT INTO review_batches "
            "(batch_id, campaign_id, status, current_snapshot_id, "
            "current_snapshot_sha256, review_revision, execution_generation) "
            "VALUES (?, ?, 'OPEN', ?, ?, ?, ?)",
            (
                head.batch_id,
                head.campaign_id,
                head.current_snapshot_id,
                head.current_snapshot_sha256,
                head.review_revision,
                head.execution_generation,
            ),
        )
        session.connection.execute(
            "INSERT INTO review_snapshots "
            "(snapshot_id, lineage_kind, campaign_id, batch_id, version, "
            "payload_sha256, final_path, final_sha256, state, "
            "structural_approval_ready) "
            "VALUES (?, 'BATCH', ?, ?, ?, ?, ?, ?, 'PUBLISHED', 0)",
            (
                head.current_snapshot_id,
                head.campaign_id,
                head.batch_id,
                head.review_revision,
                head.current_snapshot_sha256,
                str(final_path),
                package_sha256,
            ),
        )

    def test_new_root_snapshot_guard_rejects_legacy_v1(self):
        snapshot = canonical_json_bytes(
            {
                "campaign_id": "campaign-1",
                "schema_version": 1,
                "snapshot_id": "snapshot-1",
            }
        )

        with self.assertRaisesRegex(
            m2_workflow.M2WorkflowError,
            "new root review snapshot must use schema version 2",
        ):
            m2_workflow._require_new_root_snapshot_v2(snapshot)

    def test_workflow_has_no_private_service_protocol_adapters(self):
        for name in (
            "_BatchPlanBuilder",
            "_ExplodePlanBuilder",
            "_PreparedBatchPublisher",
            "_PreparedExplodeReviewUnitService",
            "_explode_preparer",
            "_explode_request_from_stored",
            "_run_prepared_explode",
        ):
            self.assertFalse(hasattr(m2_workflow, name), name)

    def test_stored_explode_campaign_cannot_escape_snapshot_namespace(self):
        root = Path("/private/tmp/mnemosyne-m2-stored-campaign")
        session = self.fake_session(root)
        envelope = b"{}\n"
        session.connection.execute(
            "INSERT INTO review_submissions "
            "(submission_id, campaign_id, payload_json, payload_sha256, state) "
            "VALUES (?, ?, ?, ?, 'PREPARED')",
            (
                "submission-escape",
                "../escape",
                envelope,
                sha256_bytes(envelope),
            ),
        )

        with self.assertRaisesRegex(
            m2_workflow.M2WorkflowError,
            "not exactly resumable",
        ):
            m2_workflow._stored_explode_envelope(
                session.connection,
                "submission-escape",
            )

    def test_sealed_package_witness_rejects_same_size_in_place_drift(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        final_path = Path(directory.name) / "snapshot-1"
        review_path = final_path / "review"
        final_path.mkdir(mode=0o700)
        review_path.mkdir(mode=0o700)
        members = {
            final_path / "manifest.json": b"manifest-a\n",
            final_path / "snapshot.json": b"snapshot-a\n",
            review_path / "review.html": b"html-a\n",
            review_path / "review.md": b"markdown-a\n",
            review_path / "review.meta.json": b"meta-a\n",
        }
        for path, payload in members.items():
            path.write_bytes(payload)
            path.chmod(0o600)
        snapshot = SimpleNamespace(
            final_path=final_path,
            snapshot_id="snapshot-1",
            snapshot_sha256="7" * 64,
            package_sha256="8" * 64,
        )
        with mock.patch.object(
            m2_workflow.review_state,
            "read_sealed_review_snapshot",
            return_value=snapshot,
        ) as readback:
            witness = m2_workflow._sealed_package_witness(snapshot)

        readback.assert_called_once_with(
            final_path,
            expected_snapshot_id="snapshot-1",
            expected_snapshot_sha256="7" * 64,
            expected_package_sha256="8" * 64,
        )
        snapshot_path = final_path / "snapshot.json"
        before = snapshot_path.stat()
        snapshot_path.write_bytes(b"snapshot-b\n")
        snapshot_path.chmod(0o600)
        os.utime(
            snapshot_path,
            ns=(before.st_atime_ns, before.st_mtime_ns),
        )

        with self.assertRaisesRegex(
            m2_workflow.M2WorkflowError,
            "filesystem identity changed",
        ):
            m2_workflow._require_live_package_witness(snapshot, witness)

    def test_new_root_plans_review_and_campaign_before_writer_lifetime(self):
        root = Path("/private/tmp/mnemosyne-m2-workflow")
        session = self.fake_session(root)
        captured = {}
        events = []
        active = {"reader": False, "writer": False}
        lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(lock_directory.cleanup)
        lock_path = Path(lock_directory.name) / "ledger.lock"
        lock_path.touch(mode=0o600)
        reader_lock_fd = os.open(lock_path, os.O_RDONLY)
        probe_lock_fd = os.open(lock_path, os.O_RDONLY)
        self.addCleanup(os.close, probe_lock_fd)
        self.addCleanup(os.close, reader_lock_fd)
        import_plan = campaign_ledger.RunImportPlan(
            items=(),
            observations=(
                campaign_ledger.ImportedObservation(
                    observation_key="run-1:obs-1",
                    observation_id="obs-1",
                    path="projects/alpha/a.md",
                    kind="file",
                    payload_json=canonical_json_bytes({"path": "projects/alpha/a.md"}),
                ),
            ),
            links=(),
            classification_candidates=(),
        )

        @contextmanager
        def reader_session_factory(_root):
            self.assertEqual(_root, root)
            fcntl.flock(reader_lock_fd, fcntl.LOCK_SH)
            active["reader"] = True
            events.append("reader-enter")
            try:
                yield session
            finally:
                events.append("reader-exit")
                active["reader"] = False
                fcntl.flock(reader_lock_fd, fcntl.LOCK_UN)

        @contextmanager
        def writer_session_factory(_root, *, observed_by):
            self.assertEqual(_root, root)
            self.assertEqual(observed_by, "reviewer")
            active["writer"] = True
            events.append("writer-enter")
            try:
                yield session
            finally:
                events.append("writer-exit")
                active["writer"] = False

        package = SimpleNamespace(
            terminal=SimpleNamespace(
                run_id="run-1",
                path=str(root / "_registry" / "curation-runs" / "run-1"),
                package_sha256="5" * 64,
            )
        )

        class FakeStore:
            def __init__(self, runs_root):
                self.runs_root = Path(runs_root)

            def read_complete_package(self, run_id):
                if run_id != "run-1":
                    raise AssertionError("unexpected inventory run")
                events.append("package-read")
                return package

        def prepare(
            package,
            compiled,
            approved,
            *,
            campaign_id,
            snapshot_id,
            rendered_at,
            item_ids_by_path,
        ):
            self.assertFalse(active["writer"])
            try:
                fcntl.flock(
                    probe_lock_fd,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except BlockingIOError as exc:
                self.fail("prepare_root_review still runs under a ledger lock")
            finally:
                fcntl.flock(probe_lock_fd, fcntl.LOCK_UN)
            events.append("prepare")
            captured["item_ids_by_path"] = item_ids_by_path
            snapshot = canonical_json_bytes(
                {
                    "analysis_contexts": [
                        {"context_id": "reference-context-test"}
                    ],
                    "campaign_id": campaign_id,
                    "decisions": [],
                    "import_payload_sha256": import_plan.sha256,
                    "kind": "campaign-genesis-review",
                    "root_run_id": package.terminal.run_id,
                    "schema_version": 2,
                    "snapshot_id": snapshot_id,
                    "structural_approval_ready": False,
                    "version": 1,
                }
            )
            return SimpleNamespace(
                import_plan=import_plan,
                snapshot_payload_json=snapshot,
            )

        class FakeBinder:
            def __init__(self, **kwargs):
                captured["binder"] = kwargs

            def open_prepared_root_run(self, request, prepared):
                if prepared is None:
                    raise AssertionError("prepared root publication is missing")
                captured["request"] = request
                return campaign_ledger.CampaignOpenResult(
                    campaign_id=request.campaign_id,
                    binding_id=request.binding_id,
                    integration_id=request.integration_id,
                    snapshot_id=request.snapshot_id,
                    status="READY",
                    snapshot_payload_json=request.snapshot_payload_json,
                    resumed=False,
                )

        uuid_values = iter(
            (
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
            )
        )

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.inventory, "InventoryRunStore", FakeStore
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "root_review_item_paths",
                return_value=("projects/alpha/a.md",),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review, "prepare_root_review", prepare
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.campaign_ledger,
                "CampaignRunBinder",
                FakeBinder,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "CampaignArtifactPublisher",
                return_value=RootPlanProbeCampaignPublisher(active, events),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "CampaignReviewPublisherAdapter",
                return_value=RootPlanProbeIntegrationPublisher(active, events),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_snapshot,
                "ReviewSnapshotPublisher",
                return_value="review-publisher",
            ))
            # The workflow accepts an injected UUID supplier so a retry test can
            # prove that only the first reservation allocates identities.
            report = m2_workflow.open_root_run(
                root,
                run_id="run-1",
                opened_by="reviewer",
                rendered_at="2026-07-15T05:00:00Z",
                id_supplier=lambda: next(uuid_values),
            )

        request = captured["request"]
        self.assertEqual(
            captured["item_ids_by_path"],
            {"projects/alpha/a.md": "ffffffff-ffff-4fff-8fff-ffffffffffff"},
        )
        self.assertEqual(
            request.campaign_path,
            "campaigns/campaign-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa/campaign.json",
        )
        self.assertEqual(
            request.binding_path,
            "campaigns/campaign-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa/run-bindings/"
            "binding-bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb/binding.json",
        )
        self.assertEqual(
            request.snapshot_path,
            "campaigns/campaign-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa/snapshots/"
            "snapshot-eeeeeeeeeeee4eee8eeeeeeeeeeeeeee",
        )
        self.assertEqual(report.status, "READY")
        self.assertFalse(report.resumed)
        self.assertEqual(
            report.snapshot_payload_sha256,
            sha256_bytes(request.snapshot_payload_json),
        )
        self.assertEqual(
            events,
            [
                "reader-enter",
                "package-read",
                "reader-exit",
                "prepare",
                "integration-plan",
                "campaign-plan",
                "writer-enter",
                "package-read",
                "writer-exit",
            ],
        )

    def test_exact_resume_plans_review_and_campaign_before_writer_lifetime(self):
        root = Path("/private/tmp/mnemosyne-m2-workflow-resume")
        session = self.fake_session(root)
        active = {"writer": False}
        events = []
        import_plan = campaign_ledger.RunImportPlan(
            items=(),
            observations=(
                campaign_ledger.ImportedObservation(
                    observation_key="run-existing:obs-1",
                    observation_id="obs-1",
                    path="projects/alpha/a.md",
                    kind="file",
                    payload_json=canonical_json_bytes({"path": "projects/alpha/a.md"}),
                ),
            ),
            links=(),
            classification_candidates=(),
        )
        snapshot_payload = canonical_json_bytes(
            {
                "campaign_id": "campaign-existing",
                "decisions": [],
                "import_payload_sha256": import_plan.sha256,
                "kind": "campaign-genesis-review",
                "root_run_id": "run-existing",
                "schema_version": 1,
                "snapshot_id": "snapshot-existing",
                "structural_approval_ready": False,
                "version": 1,
            }
        )
        request = campaign_ledger.RootRunRequest(
            run_id="run-existing",
            run_sha256="5" * 64,
            run_package_path="_registry/curation-runs/run-existing",
            manifest_sha256="5" * 64,
            policy=session.approved_policy_ref,
            campaign_id="campaign-existing",
            binding_id="binding-existing",
            integration_id="integration-existing",
            submission_id="submission-existing",
            snapshot_id="snapshot-existing",
            campaign_path="campaigns/campaign-existing/campaign.json",
            binding_path=(
                "campaigns/campaign-existing/run-bindings/"
                "binding-existing/binding.json"
            ),
            snapshot_path=(
                "campaigns/campaign-existing/snapshots/snapshot-existing"
            ),
            import_plan=import_plan,
            opened_by="reviewer",
            snapshot_payload_json=snapshot_payload,
        )
        session.connection.execute(
            "INSERT INTO campaign_run_bindings (run_id, request_json) VALUES (?, ?)",
            (request.run_id, request.canonical_bytes()),
        )

        @contextmanager
        def reader_session_factory(_root):
            self.assertEqual(_root, root)
            events.append("reader-enter")
            yield session
            events.append("reader-exit")

        @contextmanager
        def writer_session_factory(_root, *, observed_by):
            self.assertEqual(observed_by, "reviewer")
            active["writer"] = True
            events.append("writer-enter")
            try:
                yield session
            finally:
                events.append("writer-exit")
                active["writer"] = False

        class FakeBinder:
            def __init__(self, **_kwargs):
                pass

            def resume_prepared_root_run(self, run_id, prepared):
                if run_id != request.run_id or prepared is None:
                    raise AssertionError("resume lost its exact prepared request")
                return campaign_ledger.CampaignOpenResult(
                    campaign_id=request.campaign_id,
                    binding_id=request.binding_id,
                    integration_id=request.integration_id,
                    snapshot_id=request.snapshot_id,
                    status="READY",
                    snapshot_payload_json=request.snapshot_payload_json,
                    resumed=True,
                )

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.inventory,
                "InventoryRunStore",
                side_effect=AssertionError("resume read inventory package"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "prepare_root_review",
                side_effect=AssertionError("resume recomputed root review"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.campaign_ledger,
                "CampaignRunBinder",
                FakeBinder,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "CampaignArtifactPublisher",
                return_value=RootPlanProbeCampaignPublisher(active, events),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "CampaignReviewPublisherAdapter",
                return_value=RootPlanProbeIntegrationPublisher(active, events),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_snapshot,
                "ReviewSnapshotPublisher",
                return_value="review-publisher",
            ))
            report = m2_workflow.open_root_run(
                root,
                run_id=request.run_id,
                opened_by="reviewer",
                rendered_at="2026-07-15T05:00:00Z",
                id_supplier=lambda: self.fail("resume allocated a new identity"),
            )

        self.assertTrue(report.resumed)
        self.assertEqual(report.campaign_id, "campaign-existing")
        self.assertEqual(
            events,
            [
                "reader-enter",
                "reader-exit",
                "integration-plan",
                "campaign-plan",
                "writer-enter",
                "writer-exit",
            ],
        )

    def test_open_root_run_resumes_a_concurrent_binding_that_wins_after_precompute(self):
        root = Path("/private/tmp/mnemosyne-m2-workflow-binding-race")
        session = self.fake_session(root)
        winner = root_request(
            session.approved_policy_ref,
            campaign_id="campaign-race-winner",
        )
        package = SimpleNamespace(
            terminal=SimpleNamespace(
                run_id="run-1",
                path=str(root / "_registry" / "curation-runs" / "run-1"),
                package_sha256="5" * 64,
            )
        )
        calls = {"prepare": 0, "resume": 0, "open": 0}
        active = {"writer": False}
        plan_events = []

        @contextmanager
        def reader_session_factory(_root):
            self.assertEqual(_root, root)
            yield session

        @contextmanager
        def writer_session_factory(_root, *, observed_by):
            self.assertEqual(_root, root)
            self.assertEqual(observed_by, "reviewer")
            if session.connection.execute(
                "SELECT count(*) FROM campaign_run_bindings WHERE run_id = ?",
                (winner.run_id,),
            ).fetchone() == (0,):
                session.connection.execute(
                    "INSERT INTO campaign_run_bindings (run_id, request_json) "
                    "VALUES (?, ?)",
                    (winner.run_id, winner.canonical_bytes()),
                )
            active["writer"] = True
            try:
                yield session
            finally:
                active["writer"] = False

        class FakeStore:
            def __init__(self, _runs_root):
                pass

            def read_complete_package(self, _run_id):
                return package

        def prepare(
            prepared_package,
            _compiled,
            _approved,
            *,
            campaign_id,
            snapshot_id,
            rendered_at,
            item_ids_by_path,
        ):
            self.assertIs(prepared_package, package)
            self.assertEqual(rendered_at, "2026-07-15T05:00:00Z")
            self.assertEqual(
                tuple(item_ids_by_path),
                ("projects/alpha/a.md",),
            )
            calls["prepare"] += 1
            snapshot = canonical_json_bytes(
                {
                    "analysis_contexts": [
                        {"context_id": "reference-context-test"}
                    ],
                    "campaign_id": campaign_id,
                    "decisions": [],
                    "import_payload_sha256": winner.import_plan.sha256,
                    "kind": "campaign-genesis-review",
                    "root_run_id": "run-1",
                    "schema_version": 2,
                    "snapshot_id": snapshot_id,
                    "structural_approval_ready": False,
                    "version": 1,
                }
            )
            return SimpleNamespace(
                import_plan=winner.import_plan,
                snapshot_payload_json=snapshot,
            )

        class FakeBinder:
            def __init__(self, **_kwargs):
                pass

            def open_prepared_root_run(self, _request, _prepared):
                calls["open"] += 1
                raise AssertionError("concurrent winner was not resumed")

            def resume_prepared_root_run(self, run_id, prepared):
                if run_id != winner.run_id:
                    raise AssertionError("resumed the wrong run")
                if prepared.request_json != winner.canonical_bytes():
                    raise AssertionError("winner plan changed stored request")
                calls["resume"] += 1
                return campaign_ledger.CampaignOpenResult(
                    campaign_id=winner.campaign_id,
                    binding_id=winner.binding_id,
                    integration_id=winner.integration_id,
                    snapshot_id=winner.snapshot_id,
                    status="READY",
                    snapshot_payload_json=winner.snapshot_payload_json,
                    resumed=True,
                )

        uuid_values = iter(
            (
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
            )
        )
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.inventory,
                "InventoryRunStore",
                FakeStore,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "root_review_item_paths",
                return_value=("projects/alpha/a.md",),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "prepare_root_review",
                prepare,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.campaign_ledger,
                "CampaignRunBinder",
                FakeBinder,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "CampaignArtifactPublisher",
                return_value=RootPlanProbeCampaignPublisher(
                    active,
                    plan_events,
                ),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "CampaignReviewPublisherAdapter",
                return_value=RootPlanProbeIntegrationPublisher(
                    active,
                    plan_events,
                ),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_snapshot,
                "ReviewSnapshotPublisher",
                return_value="review-publisher",
            ))
            report = m2_workflow.open_root_run(
                root,
                run_id="run-1",
                opened_by="reviewer",
                rendered_at="2026-07-15T05:00:00Z",
                id_supplier=lambda: next(uuid_values),
            )

        self.assertTrue(report.resumed)
        self.assertEqual(report.campaign_id, winner.campaign_id)
        self.assertEqual(calls, {"prepare": 1, "resume": 1, "open": 0})
        self.assertEqual(
            plan_events,
            [
                "integration-plan",
                "campaign-plan",
                "integration-plan",
                "campaign-plan",
            ],
        )
        self.assertEqual(
            session.connection.execute(
                "SELECT count(*) FROM campaign_run_bindings WHERE run_id = ?",
                (winner.run_id,),
            ).fetchone(),
            (1,),
        )

    def test_open_root_run_rejects_policy_change_after_precompute_before_reservation(self):
        root = Path("/private/tmp/mnemosyne-m2-workflow-policy-race")
        reader = self.fake_session(root)
        writer = self.fake_session(root)
        writer.approved_policy_ref = admission.ApprovedPolicyRef(
            raw_hash="6" * 64,
            full_hash="7" * 64,
            writer_control_hash="3" * 64,
            foundation_hash="4" * 64,
            generation=2,
            source_kind="EDIT",
            source_run_id="policy-run-2",
            guard_epoch=0,
        )
        seed = root_request(reader.approved_policy_ref)
        package = SimpleNamespace(
            terminal=SimpleNamespace(
                run_id="run-1",
                path=str(root / "_registry" / "curation-runs" / "run-1"),
                package_sha256="5" * 64,
            )
        )
        store_reads = []

        @contextmanager
        def reader_session_factory(_root):
            yield reader

        @contextmanager
        def writer_session_factory(_root, *, observed_by):
            self.assertEqual(observed_by, "reviewer")
            yield writer

        class FakeStore:
            def __init__(self, _runs_root):
                pass

            def read_complete_package(self, _run_id):
                store_reads.append("read")
                return package

        def prepare(
            _package,
            _compiled,
            _approved,
            *,
            campaign_id,
            snapshot_id,
            rendered_at,
            item_ids_by_path,
        ):
            snapshot = canonical_json_bytes(
                {
                    "analysis_contexts": [
                        {"context_id": "reference-context-test"}
                    ],
                    "campaign_id": campaign_id,
                    "decisions": [],
                    "import_payload_sha256": seed.import_plan.sha256,
                    "kind": "campaign-genesis-review",
                    "root_run_id": "run-1",
                    "schema_version": 2,
                    "snapshot_id": snapshot_id,
                    "structural_approval_ready": False,
                    "version": 1,
                }
            )
            return SimpleNamespace(
                import_plan=seed.import_plan,
                snapshot_payload_json=snapshot,
            )

        uuid_values = iter(
            (
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
            )
        )
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.inventory,
                "InventoryRunStore",
                FakeStore,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "root_review_item_paths",
                return_value=("projects/alpha/a.md",),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "prepare_root_review",
                prepare,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.campaign_ledger,
                "CampaignRunBinder",
                side_effect=AssertionError("policy drift reached reservation"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow,
                "_prepare_root_publication",
                return_value=(object(), object(), object()),
            ))
            with self.assertRaisesRegex(
                m2_workflow.M2WorkflowError,
                "approved policy changed during root preparation",
            ):
                m2_workflow.open_root_run(
                    root,
                    run_id="run-1",
                    opened_by="reviewer",
                    rendered_at="2026-07-15T05:00:00Z",
                    id_supplier=lambda: next(uuid_values),
                )

        self.assertEqual(store_reads, ["read"])
        self.assertEqual(
            writer.connection.execute(
                "SELECT count(*) FROM campaign_run_bindings"
            ).fetchone(),
            (0,),
        )

    def test_open_root_run_durably_records_reader_observed_policy_drift(self):
        root = Path("/private/tmp/mnemosyne-m2-workflow-reader-drift")
        reader = self.fake_session(root)
        observation = SimpleNamespace(
            observed_raw=b"drifted registry bytes",
            observed_identity={"raw_sha256": "6" * 64},
            expected_head_generation=1,
            expected_head_full_hash="2" * 64,
            expected_guard_epoch=0,
        )
        reader._policy_verifier = SimpleNamespace(
            filesystem_guard=SimpleNamespace(observation=observation)
        )

        def current_policy():
            raise m2_workflow.ledger_runtime.LedgerRuntimeError(
                "placement registry drifted during writer session"
            )

        reader.current_policy = current_policy
        package = SimpleNamespace(
            terminal=SimpleNamespace(
                run_id="run-1",
                path=str(root / "_registry" / "curation-runs" / "run-1"),
                package_sha256="5" * 64,
            )
        )

        @contextmanager
        def reader_session_factory(_root):
            yield reader

        class FakeStore:
            def __init__(self, _runs_root):
                pass

            def read_complete_package(self, _run_id):
                return package

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                side_effect=AssertionError("reader drift reached writer session"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.inventory,
                "InventoryRunStore",
                FakeStore,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "root_review_item_paths",
                side_effect=AssertionError("reader drift reached precompute"),
            ))
            observe = stack.enter_context(mock.patch.object(
                policy_authority,
                "observe_policy_drift_from_stable_observation",
                return_value={
                    "episode_id": "episode-1",
                    "event_id": "event-1",
                },
            ))
            with self.assertRaisesRegex(
                m2_workflow.M2WorkflowError,
                "policy drift recorded: episode episode-1 event event-1",
            ):
                m2_workflow.open_root_run(
                    root,
                    run_id="run-1",
                    opened_by="reader-drift-actor",
                    rendered_at="2026-07-15T05:00:00Z",
                )

        observe.assert_called_once_with(
            root,
            observed_by="reader-drift-actor",
            observed_raw=observation.observed_raw,
            observed_identity=observation.observed_identity,
            expected_head_generation=observation.expected_head_generation,
            expected_head_full_hash=observation.expected_head_full_hash,
            expected_guard_epoch=observation.expected_guard_epoch,
        )

    def test_open_root_run_rejects_sealed_package_drift_before_reservation(self):
        root = Path("/private/tmp/mnemosyne-m2-workflow-package-race")
        session = self.fake_session(root)
        seed = root_request(session.approved_policy_ref)
        before = SimpleNamespace(
            terminal=SimpleNamespace(
                run_id="run-1",
                path=str(root / "_registry" / "curation-runs" / "run-1"),
                package_sha256="5" * 64,
            )
        )
        after = SimpleNamespace(
            terminal=SimpleNamespace(
                run_id="run-1",
                path=str(
                    root
                    / "_registry"
                    / "curation-runs"
                    / "run-1-replaced"
                ),
                package_sha256="6" * 64,
            )
        )
        packages = iter((before, after))
        store_reads = []

        @contextmanager
        def reader_session_factory(_root):
            yield session

        @contextmanager
        def writer_session_factory(_root, *, observed_by):
            self.assertEqual(observed_by, "reviewer")
            yield session

        class FakeStore:
            def __init__(self, _runs_root):
                pass

            def read_complete_package(self, _run_id):
                store_reads.append("read")
                return next(packages)

        def prepare(
            prepared_package,
            _compiled,
            _approved,
            *,
            campaign_id,
            snapshot_id,
            rendered_at,
            item_ids_by_path,
        ):
            self.assertIs(prepared_package, before)
            snapshot = canonical_json_bytes(
                {
                    "analysis_contexts": [
                        {"context_id": "reference-context-test"}
                    ],
                    "campaign_id": campaign_id,
                    "decisions": [],
                    "import_payload_sha256": seed.import_plan.sha256,
                    "kind": "campaign-genesis-review",
                    "root_run_id": "run-1",
                    "schema_version": 2,
                    "snapshot_id": snapshot_id,
                    "structural_approval_ready": False,
                    "version": 1,
                }
            )
            return SimpleNamespace(
                import_plan=seed.import_plan,
                snapshot_payload_json=snapshot,
            )

        uuid_values = iter(
            (
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
            )
        )
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.inventory,
                "InventoryRunStore",
                FakeStore,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "root_review_item_paths",
                return_value=("projects/alpha/a.md",),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.run_review,
                "prepare_root_review",
                prepare,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.campaign_ledger,
                "CampaignRunBinder",
                side_effect=AssertionError("package drift reached reservation"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow,
                "_prepare_root_publication",
                return_value=(object(), object(), object()),
            ))
            with self.assertRaisesRegex(
                m2_workflow.M2WorkflowError,
                "sealed inventory package changed during root preparation",
            ):
                m2_workflow.open_root_run(
                    root,
                    run_id="run-1",
                    opened_by="reviewer",
                    rendered_at="2026-07-15T05:00:00Z",
                    id_supplier=lambda: next(uuid_values),
                )

        self.assertEqual(store_reads, ["read", "read"])
        self.assertEqual(
            session.connection.execute(
                "SELECT count(*) FROM campaign_run_bindings"
            ).fetchone(),
            (0,),
        )

    def test_open_batch_uses_verified_campaign_head_and_full_review_publisher(self):
        root = Path("/private/tmp/mnemosyne-m2-open-batch")
        session = self.fake_session(root)
        context = review_context.ReviewContext(
            rendered_at="2026-07-15T05:00:00Z",
            policy_binding="generation=1;source=INITIAL/policy-run-1;guard=0",
            coverage=review_compiler.CoverageSummary(1, 1, 0, 0, 1, 0, 1, 0, 0),
            workstreams=(
                review_compiler.WorkstreamSummary("alpha", "active", 2, 0, 0),
            ),
            warning_codes=(
                "m2-no-structural-authority",
                "reference-incomplete",
            ),
        )
        source_context = analysis_context()
        unrelated_context = analysis_context(context_suffix="b")
        unit = batch_service.BatchUnit(
            unit_id="unit-a",
            unit_kind="file",
            path="projects/alpha/a.md",
            display_path="projects/alpha/a.md",
            member_item_ids=("11111111-1111-4111-8111-111111111111",),
            member_paths=("projects/alpha/a.md",),
            scope_class="eligible",
            sensitivity="standard",
            access_domain="local",
            primary_workstream="alpha",
            related_workstreams=(),
            shared=False,
            document_role="docs",
            authority="reference",
            document_lifecycle="current",
            lifecycle_class="active",
            override_class="none",
            scope_rule_id="active-workstream-content",
            recommended_action="keep",
            target_path=None,
            reference_complete=False,
            risk_band="medium",
            context_freshness="fresh",
            evidence_providers=("registry-route",),
            warning_codes=(
                "m2-no-structural-authority",
                "reference-incomplete",
            ),
            effect_codes=("plan-unavailable-m2",),
            canonical_conflict=False,
            relation_conflict=False,
            target_proven=False,
            analysis_provenance_json=canonical_json_bytes(
                {
                    "items": [
                        {
                            "item_id": "11111111-1111-4111-8111-111111111111",
                            "reference": {
                                "candidate_path": "projects/alpha/a.md",
                                "complete": False,
                                "context_id": source_context["context_id"],
                                "context_sha256": source_context[
                                    "context_sha256"
                                ],
                                "input_manifest_sha256": sha256_bytes(
                                    canonical_json_bytes(source_context)
                                ),
                                "matches": [],
                                "schema_version": 2,
                            },
                            "risk": {
                                "band": "medium",
                                "input_sha256": "b" * 64,
                            },
                            "target": {
                                "input_sha256": "c" * 64,
                                "status": "blocked",
                            },
                        }
                    ],
                    "schema_version": 1,
                }
            ),
            file_count=1,
            total_bytes=12,
            effect_count=0,
        )
        base_final_path = (
            root
            / "_registry"
            / "curation"
            / "campaigns"
            / "campaign-1"
            / "snapshots"
            / "campaign-snapshot-1"
        )
        head = SimpleNamespace(
            campaign_id="campaign-1",
            current_snapshot_id="campaign-snapshot-1",
            current_snapshot_sha256="6" * 64,
            review_revision=1,
            snapshot=SimpleNamespace(
                snapshot_id="campaign-snapshot-1",
                final_path=base_final_path,
                snapshot_sha256="6" * 64,
                package_sha256="a" * 64,
                payload={
                    "review_context": context.to_dict(),
                    "structural_approval_ready": False,
                },
                schema_version=2,
                analysis_contexts_json=canonical_json_bytes(
                    sorted(
                        [source_context, unrelated_context],
                        key=lambda value: value["context_id"],
                    )
                ),
            ),
            units=(unit,),
        )
        self.seed_campaign_head(
            session,
            head,
            final_path=base_final_path,
            package_sha256="a" * 64,
        )
        captured = {}
        active = {"reader": False, "writer": False}
        lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(lock_directory.cleanup)
        lock_path = Path(lock_directory.name) / "ledger.lock"
        lock_path.touch(mode=0o600)
        reader_lock_fd = os.open(lock_path, os.O_RDONLY)
        writer_lock_fd = os.open(lock_path, os.O_RDONLY)
        probe_lock_fd = os.open(lock_path, os.O_RDONLY)
        self.addCleanup(os.close, probe_lock_fd)
        self.addCleanup(os.close, writer_lock_fd)
        self.addCleanup(os.close, reader_lock_fd)
        @contextmanager
        def reader_session_factory(_root):
            self.assertEqual(_root, root)
            fcntl.flock(reader_lock_fd, fcntl.LOCK_SH)
            active["reader"] = True
            try:
                yield session
            finally:
                active["reader"] = False
                fcntl.flock(reader_lock_fd, fcntl.LOCK_UN)

        @contextmanager
        def writer_session_factory(_root, *, observed_by):
            self.assertEqual(observed_by, "reviewer")
            fcntl.flock(writer_lock_fd, fcntl.LOCK_EX)
            active["writer"] = True
            try:
                yield session
            finally:
                active["writer"] = False
                fcntl.flock(writer_lock_fd, fcntl.LOCK_UN)

        class FakeLoader:
            def __init__(self, connection, control_root):
                self.connection = connection
                self.control_root = control_root

            def load(self, campaign_id, unit_ids):
                self_test = (campaign_id, unit_ids)
                captured["load"] = self_test
                return head

        class FakeBatchPublisher:
            def plan(self, publication):
                self.assert_unlocked()
                captured["request_prepared_without_lock"] = True
                captured["planned_publication"] = publication
                staging_path = publication.final_path.parent / (
                    ".incomplete-%s" % publication.snapshot_id
                )
                return batch_service.SnapshotPublishPlan(
                    publication=publication,
                    final_path=publication.final_path,
                    package_sha256="8" * 64,
                    sealed_identity_sha256="9" * 64,
                    sealed_payload=SimpleNamespace(
                        staging_path=staging_path,
                        final_path=publication.final_path,
                    ),
                )

            def assert_unlocked(self):
                self_test.assertFalse(active["reader"])
                self_test.assertFalse(active["writer"])
                try:
                    fcntl.flock(
                        probe_lock_fd,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    self_test.fail(
                        "open-batch package planning still runs under the "
                        "global ledger lock"
                    )
                finally:
                    fcntl.flock(probe_lock_fd, fcntl.LOCK_UN)

            def publish(self, _plan):
                raise AssertionError("fake batch service unexpectedly published")

        self_test = self
        batch_publisher = FakeBatchPublisher()

        class FakeBatchService:
            def __init__(self, connection, snapshot_root, **kwargs):
                captured["service"] = (connection, snapshot_root, kwargs)

            def open_prepared_batch(self, request, prepared):
                captured["batch_request"] = request
                captured["prepared_publication"] = prepared
                return batch_service.OpenBatchResult(
                    batch_id=request.batch_id,
                    status="OPEN",
                    snapshot_id=request.snapshot_id,
                    snapshot_state="COMMITTED",
                    snapshot_version=1,
                    review_revision=1,
                    snapshot_sha256="7" * 64,
                    package_sha256="8" * 64,
                    final_path=(
                        root
                        / "_registry"
                        / "curation"
                        / "campaigns"
                        / request.campaign_id
                        / "snapshots"
                        / request.snapshot_id
                    ),
                    structural_approval_ready=False,
                    structural_blocker="effect-preview-not-available-m2",
                    resumed=False,
                )

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow,
                "_sealed_package_witness",
                return_value=("filesystem-witness",),
            ))
            live_witness = stack.enter_context(mock.patch.object(
                m2_workflow,
                "_require_live_package_witness",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "CampaignHeadLoader",
                FakeLoader,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_snapshot,
                "ReviewSnapshotPublisher",
                return_value="full-review-publisher",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "BatchReviewPublisherAdapter",
                return_value=batch_publisher,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.batch_service,
                "BatchService",
                FakeBatchService,
            ))
            report = m2_workflow.open_batch(
                root,
                campaign_id="campaign-1",
                unit_ids=("unit-a",),
                batch_id="batch-1",
                snapshot_id="batch-snapshot-1",
                submission_id="batch-submission-1",
                actor="reviewer",
                max_items=2,
                max_files=2,
                max_bytes=100,
                max_effects=1,
            )

        request = captured["batch_request"]
        self.assertEqual(captured["load"], ("campaign-1", ("unit-a",)))
        prepared_context = review_context.ReviewContext.from_canonical_bytes(
            request.review_context_json
        )
        self.assertEqual(prepared_context.rendered_at, context.rendered_at)
        self.assertEqual(prepared_context.policy_binding, context.policy_binding)
        self.assertEqual(prepared_context.coverage, context.coverage)
        self.assertEqual(prepared_context.warning_codes, context.warning_codes)
        self.assertEqual(
            prepared_context.workstreams,
            (review_compiler.WorkstreamSummary("alpha", "active", 1, 0, 0),),
        )
        self.assertTrue(captured["request_prepared_without_lock"])
        self.assertEqual(
            request.analysis_contexts_json,
            canonical_json_bytes([source_context]),
        )
        self.assertTrue(callable(captured["service"][2]["publisher"].plan))
        self.assertTrue(callable(captured["service"][2]["publisher"].publish))
        self.assertEqual(
            captured["planned_publication"].snapshot_id,
            "batch-snapshot-1",
        )
        self.assertEqual(
            captured["prepared_publication"].publication,
            captured["planned_publication"],
        )
        self.assertEqual(request.policy, session.approved_policy_ref)
        self.assertEqual(
            captured["service"][2]["current_policy"](),
            session.approved_policy_ref,
        )
        self.assertEqual(report.status, "OPEN")
        self.assertFalse(report.structural_approval_ready)
        live_witness.assert_called_once_with(
            head.snapshot,
            ("filesystem-witness",),
        )

    def test_open_batch_requires_explicit_v1_cow_normalization(self):
        root = Path("/private/tmp/mnemosyne-m2-open-batch-v1")
        session = self.fake_session(root)
        head = SimpleNamespace(
            snapshot=SimpleNamespace(schema_version=1),
        )
        test_case = self

        @contextmanager
        def session_factory(_root):
            yield session

        class FakeLoader:
            def __init__(self, _connection, _control_root):
                pass

            def load(self, campaign_id, unit_ids):
                test_case.assertEqual(
                    (campaign_id, unit_ids),
                    ("campaign-1", ("unit-a",)),
                )
                return head

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                session_factory,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                side_effect=AssertionError("v1 reached writer session"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "CampaignHeadLoader",
                FakeLoader,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.batch_service,
                "BatchService",
                side_effect=AssertionError("v1 reached batch service"),
            ))
            with self.assertRaisesRegex(
                m2_workflow.M2WorkflowError,
                "COW-normalization-required",
            ):
                m2_workflow.open_batch(
                    root,
                    campaign_id="campaign-1",
                    unit_ids=("unit-a",),
                    batch_id="batch-1",
                    snapshot_id="batch-snapshot-1",
                    submission_id="batch-submission-1",
                    actor="reviewer",
                    max_items=2,
                    max_files=2,
                    max_bytes=100,
                    max_effects=1,
                )

    def test_open_batch_rejects_package_identity_drift_after_reader_preparation(self):
        root = Path("/private/tmp/mnemosyne-m2-open-batch-package-race")
        reader = self.fake_session(root)
        writer = self.fake_session(root)
        context = review_context.ReviewContext(
            rendered_at="2026-07-15T05:00:00Z",
            policy_binding="generation=1;source=INITIAL/policy-run-1;guard=0",
            coverage=review_compiler.CoverageSummary(1, 1, 0, 0, 1, 0, 1, 0, 0),
            workstreams=(
                review_compiler.WorkstreamSummary("alpha", "active", 1, 0, 0),
            ),
            warning_codes=("m2-no-structural-authority",),
        )
        source_context = analysis_context()
        unit = workflow_batch_unit(source_context)
        final_path = (
            root
            / "_registry"
            / "curation"
            / "campaigns"
            / "campaign-1"
            / "snapshots"
            / "campaign-snapshot-1"
        )
        head = SimpleNamespace(
            campaign_id="campaign-1",
            current_snapshot_id="campaign-snapshot-1",
            current_snapshot_sha256="6" * 64,
            review_revision=1,
            snapshot=SimpleNamespace(
                snapshot_id="campaign-snapshot-1",
                final_path=final_path,
                snapshot_sha256="6" * 64,
                package_sha256="a" * 64,
                payload={
                    "review_context": context.to_dict(),
                    "structural_approval_ready": False,
                },
                schema_version=2,
                analysis_contexts_json=canonical_json_bytes([source_context]),
            ),
            units=(unit,),
        )
        self.seed_campaign_head(
            reader,
            head,
            final_path=final_path,
            package_sha256="a" * 64,
        )
        self.seed_campaign_head(
            writer,
            head,
            final_path=final_path,
            package_sha256="b" * 64,
        )

        @contextmanager
        def reader_session(_root):
            self.assertEqual(_root, root)
            yield reader

        @contextmanager
        def writer_session(_root, *, observed_by):
            self.assertEqual((_root, observed_by), (root, "reviewer"))
            yield writer

        class FakeLoader:
            def __init__(self, connection, control_root):
                self.assert_reader(connection, control_root)

            def assert_reader(self, connection, control_root):
                test_case.assertIs(connection, reader.connection)
                test_case.assertEqual(
                    control_root,
                    root / "_registry" / "curation",
                )

            def load(self, campaign_id, unit_ids):
                test_case.assertEqual(
                    (campaign_id, unit_ids),
                    ("campaign-1", ("unit-a",)),
                )
                return head

        test_case = self
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow,
                "_sealed_package_witness",
                return_value=("filesystem-witness",),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "CampaignHeadLoader",
                FakeLoader,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_snapshot,
                "ReviewSnapshotPublisher",
                return_value="review-publisher",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "BatchReviewPublisherAdapter",
                return_value="batch-publisher",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.batch_service,
                "prepare_batch_publication",
                return_value="prepared-publication",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.batch_service,
                "BatchService",
                side_effect=AssertionError("package drift reached reservation"),
            ))
            with self.assertRaisesRegex(
                m2_workflow.M2WorkflowError,
                "sealed campaign package changed during batch preparation",
            ):
                m2_workflow.open_batch(
                    root,
                    campaign_id="campaign-1",
                    unit_ids=("unit-a",),
                    batch_id="batch-1",
                    snapshot_id="batch-snapshot-1",
                    submission_id="batch-submission-1",
                    actor="reviewer",
                    max_items=1,
                    max_files=1,
                    max_bytes=100,
                    max_effects=1,
                )

    def test_open_batch_rejects_package_rename_replacement_between_locks(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        reader = self.fake_session(root)
        writer = self.fake_session(root)
        context = review_context.ReviewContext(
            rendered_at="2026-07-15T05:00:00Z",
            policy_binding="generation=1;source=INITIAL/policy-run-1;guard=0",
            coverage=review_compiler.CoverageSummary(1, 1, 0, 0, 1, 0, 1, 0, 0),
            workstreams=(
                review_compiler.WorkstreamSummary("alpha", "active", 1, 0, 0),
            ),
            warning_codes=("m2-no-structural-authority",),
        )
        source_context = analysis_context()
        unit = workflow_batch_unit(source_context)
        final_path = (
            root
            / "_registry"
            / "curation"
            / "campaigns"
            / "campaign-1"
            / "snapshots"
            / "campaign-snapshot-1"
        )
        create_sealed_package_members(final_path)
        head = SimpleNamespace(
            campaign_id="campaign-1",
            current_snapshot_id="campaign-snapshot-1",
            current_snapshot_sha256="6" * 64,
            review_revision=1,
            snapshot=SimpleNamespace(
                snapshot_id="campaign-snapshot-1",
                final_path=final_path,
                snapshot_sha256="6" * 64,
                package_sha256="a" * 64,
                payload={
                    "review_context": context.to_dict(),
                    "structural_approval_ready": False,
                },
                schema_version=2,
                analysis_contexts_json=canonical_json_bytes([source_context]),
            ),
            units=(unit,),
        )
        self.seed_campaign_head(
            reader,
            head,
            final_path=final_path,
            package_sha256="a" * 64,
        )
        self.seed_campaign_head(
            writer,
            head,
            final_path=final_path,
            package_sha256="a" * 64,
        )

        @contextmanager
        def reader_session(_root):
            self.assertEqual(_root, root)
            yield reader

        @contextmanager
        def writer_session(_root, *, observed_by):
            self.assertEqual((_root, observed_by), (root, "reviewer"))
            snapshot_path = final_path / "snapshot.json"
            replacement = final_path / ".snapshot-replacement"
            replacement.write_bytes(b"snapshot-b\n")
            replacement.chmod(0o600)
            os.replace(replacement, snapshot_path)
            yield writer

        class FakeLoader:
            def __init__(self, connection, control_root):
                test_case.assertIs(connection, reader.connection)
                test_case.assertEqual(
                    control_root,
                    root / "_registry" / "curation",
                )

            def load(self, campaign_id, unit_ids):
                test_case.assertEqual(
                    (campaign_id, unit_ids),
                    ("campaign-1", ("unit-a",)),
                )
                return head

        test_case = self
        with ExitStack() as stack:
            readback = stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "read_sealed_review_snapshot",
                return_value=head.snapshot,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "CampaignHeadLoader",
                FakeLoader,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_snapshot,
                "ReviewSnapshotPublisher",
                return_value="review-publisher",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "BatchReviewPublisherAdapter",
                return_value="batch-publisher",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.batch_service,
                "prepare_batch_publication",
                return_value="prepared-publication",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.batch_service,
                "BatchService",
                side_effect=AssertionError(
                    "filesystem replacement reached reservation"
                ),
            ))
            with self.assertRaisesRegex(
                m2_workflow.M2WorkflowError,
                "sealed package filesystem identity changed during preparation",
            ):
                m2_workflow.open_batch(
                    root,
                    campaign_id="campaign-1",
                    unit_ids=("unit-a",),
                    batch_id="batch-1",
                    snapshot_id="batch-snapshot-1",
                    submission_id="batch-submission-1",
                    actor="reviewer",
                    max_items=1,
                    max_files=1,
                    max_bytes=100,
                    max_effects=1,
                )

        readback.assert_called_once_with(
            final_path,
            expected_snapshot_id="campaign-snapshot-1",
            expected_snapshot_sha256="6" * 64,
            expected_package_sha256="a" * 64,
        )

    def test_validate_review_uses_reader_session_and_snapshot_identifier_only(self):
        root = Path("/private/tmp/mnemosyne-m2-validate-review")
        session = self.fake_session(root)
        sealed = SimpleNamespace(
            snapshot_id="snapshot-validated",
            final_path=(
                root
                / "_registry"
                / "curation"
                / "campaigns"
                / "campaign-1"
                / "snapshots"
                / "snapshot-validated"
            ),
            snapshot_sha256="7" * 64,
            package_sha256="8" * 64,
            sealed_identity_sha256="9" * 64,
            review_kind="run-overview",
            source_kind="campaign-snapshot",
            source_id="snapshot-validated",
            units=(SimpleNamespace(unit_id="unit-a"),),
            payload={"structural_approval_ready": False},
        )
        captured = {}

        @contextmanager
        def reader_session(_root):
            captured["root"] = _root
            yield session

        class FakeSnapshotLoader:
            def __init__(self, connection, control_root):
                captured["loader"] = (connection, control_root)

            def load(self, snapshot_id):
                captured["snapshot_id"] = snapshot_id
                return sealed

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                side_effect=AssertionError("validation opened a writer session"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "ReviewSnapshotLoader",
                FakeSnapshotLoader,
            ))
            report = m2_workflow.validate_review(
                root,
                snapshot_id="snapshot-validated",
            )

        self.assertEqual(captured["root"], root)
        self.assertEqual(captured["snapshot_id"], "snapshot-validated")
        self.assertEqual(report.unit_count, 1)
        self.assertFalse(report.structural_approval_ready)

    def test_checkout_review_uses_exact_ledger_snapshot_and_non_authoritative_drafts_root(self):
        root = Path("/private/tmp/mnemosyne-m2-checkout-review")
        session = self.fake_session(root)
        sealed = SimpleNamespace(
            snapshot_id="snapshot-checked-out",
            snapshot_payload=b'{"snapshot_id":"snapshot-checked-out"}\n',
            snapshot_sha256="7" * 64,
            review_markdown=b"# sealed review\n",
            review_hashes=SimpleNamespace(markdown_sha256="8" * 64),
        )
        captured = {}

        @contextmanager
        def reader_session(_root):
            captured["root"] = _root
            yield session

        class FakeSnapshotLoader:
            def __init__(self, connection, control_root):
                captured["loader"] = (connection, control_root)

            def load(self, snapshot_id):
                captured["snapshot_id"] = snapshot_id
                return sealed

        def fake_checkout(request, *, drafts_root, snapshot_loader):
            captured["request"] = request
            captured["drafts_root"] = drafts_root
            trusted = snapshot_loader(
                request.base_snapshot_id,
                request.base_snapshot_sha256,
            )
            captured["trusted"] = trusted
            return review_draft.ReviewDraft(
                path=drafts_root / request.draft_id,
                draft_id=request.draft_id,
                base_snapshot_id=request.base_snapshot_id,
                base_snapshot_sha256=request.base_snapshot_sha256,
                actor=request.actor,
                authority=False,
                approval_ready=False,
                template_markdown_sha256="9" * 64,
                current_markdown_sha256="a" * 64,
                edits=(),
            )

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                side_effect=AssertionError("draft checkout opened a writer session"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "ReviewSnapshotLoader",
                FakeSnapshotLoader,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_draft,
                "checkout_review",
                fake_checkout,
            ))
            report = m2_workflow.checkout_review(
                root,
                snapshot_id="snapshot-checked-out",
                snapshot_sha256="7" * 64,
                draft_id="draft-1",
                actor="reviewer",
            )

        control_root = root / "_registry" / "curation"
        self.assertEqual(captured["root"], root)
        self.assertEqual(captured["snapshot_id"], "snapshot-checked-out")
        self.assertEqual(captured["drafts_root"], control_root / "drafts")
        self.assertEqual(captured["trusted"].snapshot_bytes, sealed.snapshot_payload)
        self.assertEqual(captured["trusted"].review_markdown, sealed.review_markdown)
        self.assertEqual(report.final_path, str(control_root / "drafts" / "draft-1"))
        self.assertFalse(report.authority)
        self.assertFalse(report.approval_ready)

    def test_explode_review_unit_binds_exact_open_head_and_full_publisher(self):
        root = Path("/private/tmp/mnemosyne-m2-explode-workflow")
        session = self.fake_session(root)
        source_context = analysis_context()
        base_final_path = (
            root
            / "_registry"
            / "curation"
            / "campaigns"
            / "campaign-1"
            / "snapshots"
            / "snapshot-1"
        )
        head = SimpleNamespace(
            batch_id="batch-1",
            campaign_id="campaign-1",
            current_snapshot_id="snapshot-1",
            current_snapshot_sha256="7" * 64,
            review_revision=3,
            execution_generation=2,
            snapshot=SimpleNamespace(
                snapshot_id="snapshot-1",
                snapshot_sha256="7" * 64,
                package_sha256="a" * 64,
                final_path=base_final_path,
                payload={"structural_approval_ready": False},
                schema_version=2,
                analysis_contexts_json=canonical_json_bytes(
                    [source_context]
                ),
            ),
        )
        self.seed_batch_head(
            session,
            head,
            final_path=base_final_path,
            package_sha256="a" * 64,
        )
        captured = {}
        active = {"reader": False, "writer": False}
        lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(lock_directory.cleanup)
        lock_path = Path(lock_directory.name) / "ledger.lock"
        lock_path.touch(mode=0o600)
        reader_lock_fd = os.open(lock_path, os.O_RDONLY)
        writer_lock_fd = os.open(lock_path, os.O_RDONLY)
        probe_lock_fd = os.open(lock_path, os.O_RDONLY)
        self.addCleanup(os.close, probe_lock_fd)
        self.addCleanup(os.close, writer_lock_fd)
        self.addCleanup(os.close, reader_lock_fd)

        @contextmanager
        def reader_session(_root):
            self.assertEqual(_root, root)
            fcntl.flock(reader_lock_fd, fcntl.LOCK_SH)
            active["reader"] = True
            try:
                yield session
            finally:
                active["reader"] = False
                fcntl.flock(reader_lock_fd, fcntl.LOCK_UN)

        @contextmanager
        def writer_session(_root, *, observed_by):
            captured["root"] = _root
            captured["observed_by"] = observed_by
            publication = captured["planned_publication"]
            session.connection.execute(
                "UPDATE review_batches SET current_snapshot_id = ?, "
                "current_snapshot_sha256 = ?, review_revision = ? "
                "WHERE batch_id = ?",
                (
                    publication.snapshot_id,
                    publication.snapshot_sha256,
                    publication.version,
                    "batch-1",
                ),
            )
            fcntl.flock(writer_lock_fd, fcntl.LOCK_EX)
            active["writer"] = True
            try:
                yield session
            finally:
                active["writer"] = False
                fcntl.flock(writer_lock_fd, fcntl.LOCK_UN)

        class FakeHeadLoader:
            def __init__(self, connection, control_root):
                captured["loader"] = (connection, control_root)

            def load(self, batch_id, unit_ids):
                captured["load"] = (batch_id, unit_ids)
                return head

        class FakeBatchPublisher:
            def plan(self, publication):
                self.assert_no_writer_lock()
                captured["planned_publication"] = publication
                return batch_service.SnapshotPublishPlan(
                    publication=publication,
                    final_path=publication.final_path,
                    package_sha256="9" * 64,
                    sealed_identity_sha256="b" * 64,
                    sealed_payload=SimpleNamespace(
                        staging_path=publication.final_path.parent
                        / (".incomplete-%s" % publication.snapshot_id),
                        final_path=publication.final_path,
                    ),
                )

            def assert_no_writer_lock(self):
                test_case.assertFalse(active["writer"])
                try:
                    fcntl.flock(
                        probe_lock_fd,
                        fcntl.LOCK_SH | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    test_case.fail(
                        "explode preparation still runs under the writer lock"
                    )
                finally:
                    fcntl.flock(probe_lock_fd, fcntl.LOCK_UN)

            def publish(self, _plan):
                raise AssertionError("fake runner unexpectedly published")

        class FakePreparer:
            def __init__(self, connection, control_root, publisher):
                captured["preparer"] = (
                    connection,
                    control_root,
                    publisher,
                )

            def prepare(self, request, observed_head):
                test_case.assertIs(observed_head, head)
                captured["request"] = request
                payload = canonical_json_bytes(
                    {
                        "batch_id": request.batch_id,
                        "campaign_id": head.campaign_id,
                        "snapshot_id": request.next_snapshot_id,
                    }
                )
                publication = batch_service.SnapshotPublication(
                    snapshot_id=request.next_snapshot_id,
                    batch_id=request.batch_id,
                    version=request.expected_review_revision + 1,
                    canonical_payload=payload,
                    snapshot_sha256=sha256_bytes(payload),
                    final_path=(
                        root
                        / "_registry"
                        / "curation"
                        / "campaigns"
                        / "campaign-1"
                        / "snapshots"
                        / request.next_snapshot_id
                    ),
                    structural_approval_ready=False,
                    structural_blocker="effect-preview-not-available-m2",
                )
                plan = batch_publisher.plan(publication)
                return SimpleNamespace(
                    request=request,
                    campaign_id=head.campaign_id,
                    publication=publication,
                    plan=plan,
                    envelope=b"prepared-envelope",
                    base_memberships=(),
                    next_memberships=(),
                )

            def from_stored(self, *_args, **_kwargs):
                raise AssertionError("new explode unexpectedly resumed stored work")

        class FakeExplodeService:
            def __init__(self, connection, control_root, **kwargs):
                captured["service"] = (connection, control_root, kwargs)

            def explode_prepared(self, transition):
                captured["transition"] = transition
                request = transition.request
                return explode_service.ExplodeReviewUnitResult(
                    batch_id=request.batch_id,
                    status="OPEN",
                    snapshot_id=request.next_snapshot_id,
                    snapshot_state="PUBLISHED",
                    snapshot_version=4,
                    review_revision=4,
                    execution_generation=2,
                    parent_snapshot_id=request.expected_snapshot_id,
                    parent_snapshot_sha256=request.expected_snapshot_sha256,
                    snapshot_sha256="8" * 64,
                    package_sha256="9" * 64,
                    final_path=(
                        root
                        / "_registry"
                        / "curation"
                        / "campaigns"
                        / "campaign-1"
                        / "snapshots"
                        / request.next_snapshot_id
                    ),
                    structural_approval_ready=False,
                    structural_blocker="effect-preview-not-available-m2",
                    resumed=True,
                )

        test_case = self
        batch_publisher = FakeBatchPublisher()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow,
                "_sealed_package_witness",
                return_value=("filesystem-witness",),
            ))
            live_witness = stack.enter_context(mock.patch.object(
                m2_workflow,
                "_require_live_package_witness",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "BatchHeadLoader",
                FakeHeadLoader,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_snapshot,
                "ReviewSnapshotPublisher",
                return_value="full-review-publisher",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "BatchReviewPublisherAdapter",
                return_value=batch_publisher,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.explode_service,
                "ExplodeTransitionPreparer",
                FakePreparer,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.explode_service,
                "ExplodeReviewUnitService",
                FakeExplodeService,
            ))
            report = m2_workflow.explode_review_unit(
                root,
                batch_id="batch-1",
                snapshot_id="snapshot-1",
                snapshot_sha256="7" * 64,
                folder_unit_id="unit-folder",
                next_snapshot_id="snapshot-2",
                submission_id="submission-2",
                actor="reviewer",
            )

        control_root = root / "_registry" / "curation"
        request = captured["request"]
        self.assertEqual(captured["observed_by"], "reviewer")
        self.assertEqual(captured["load"], ("batch-1", ("unit-folder",)))
        self.assertEqual(request.expected_review_revision, 3)
        self.assertEqual(request.expected_execution_generation, 2)
        self.assertEqual(
            request.analysis_contexts_json,
            canonical_json_bytes([source_context]),
        )
        self.assertEqual(captured["service"][1], control_root)
        self.assertIs(captured["service"][2]["publisher"], batch_publisher)
        self.assertIs(
            captured["transition"].publication,
            captured["planned_publication"],
        )
        self.assertEqual(request.policy, session.approved_policy_ref)
        self.assertEqual(
            captured["service"][2]["current_policy"](),
            session.approved_policy_ref,
        )
        self.assertEqual(report.parent_snapshot_id, "snapshot-1")
        self.assertEqual(report.snapshot_id, "snapshot-2")
        self.assertFalse(report.structural_approval_ready)
        self.assertTrue(report.resumed)
        live_witness.assert_called_once_with(
            head.snapshot,
            ("filesystem-witness",),
        )

    def test_explode_review_unit_requires_explicit_v1_cow_normalization(self):
        root = Path("/private/tmp/mnemosyne-m2-explode-v1")
        session = self.fake_session(root)
        head = SimpleNamespace(
            current_snapshot_id="snapshot-1",
            current_snapshot_sha256="7" * 64,
            snapshot=SimpleNamespace(schema_version=1),
        )

        @contextmanager
        def reader_session(_root):
            yield session

        class FakeHeadLoader:
            def __init__(self, _connection, _control_root):
                pass

            def load(self, _batch_id, _unit_ids):
                return head

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                side_effect=AssertionError("v1 reached writer session"),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "BatchHeadLoader",
                FakeHeadLoader,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.explode_service,
                "ExplodeReviewUnitService",
                side_effect=AssertionError("v1 reached explode service"),
            ))
            with self.assertRaisesRegex(
                m2_workflow.M2WorkflowError,
                "COW-normalization-required",
            ):
                m2_workflow.explode_review_unit(
                    root,
                    batch_id="batch-1",
                    snapshot_id="snapshot-1",
                    snapshot_sha256="7" * 64,
                    folder_unit_id="unit-folder",
                    next_snapshot_id="snapshot-2",
                    submission_id="submission-2",
                    actor="reviewer",
                )

    def test_explode_review_unit_rejects_head_drift_after_reader_preparation(self):
        root = Path("/private/tmp/mnemosyne-m2-explode-head-race")
        reader = self.fake_session(root)
        writer = self.fake_session(root)
        source_context = analysis_context()
        final_path = (
            root
            / "_registry"
            / "curation"
            / "campaigns"
            / "campaign-1"
            / "snapshots"
            / "snapshot-1"
        )
        head = SimpleNamespace(
            batch_id="batch-1",
            campaign_id="campaign-1",
            current_snapshot_id="snapshot-1",
            current_snapshot_sha256="7" * 64,
            review_revision=3,
            execution_generation=2,
            snapshot=SimpleNamespace(
                snapshot_id="snapshot-1",
                snapshot_sha256="7" * 64,
                package_sha256="a" * 64,
                final_path=final_path,
                payload={"structural_approval_ready": False},
                schema_version=2,
                analysis_contexts_json=canonical_json_bytes([source_context]),
            ),
        )
        self.seed_batch_head(
            reader,
            head,
            final_path=final_path,
            package_sha256="a" * 64,
        )
        self.seed_batch_head(
            writer,
            head,
            final_path=final_path,
            package_sha256="a" * 64,
        )
        writer.connection.execute(
            "UPDATE review_batches SET current_snapshot_id = ?, "
            "current_snapshot_sha256 = ?, review_revision = ? "
            "WHERE batch_id = ?",
            ("snapshot-other", "8" * 64, 4, "batch-1"),
        )

        @contextmanager
        def reader_session(_root):
            yield reader

        @contextmanager
        def writer_session(_root, *, observed_by):
            self.assertEqual(observed_by, "reviewer")
            yield writer

        class FakeHeadLoader:
            def __init__(self, connection, _control_root):
                test_case.assertIs(connection, reader.connection)

            def load(self, _batch_id, _unit_ids):
                return head

        class FakePublisher:
            def plan(self, publication):
                return batch_service.SnapshotPublishPlan(
                    publication=publication,
                    final_path=publication.final_path,
                    package_sha256="9" * 64,
                    sealed_identity_sha256="b" * 64,
                    sealed_payload=SimpleNamespace(
                        staging_path=publication.final_path.parent
                        / (".incomplete-%s" % publication.snapshot_id),
                        final_path=publication.final_path,
                    ),
                )

            def publish(self, _plan):
                raise AssertionError("head drift unexpectedly published")

        class FakePreparer:
            def __init__(self, _connection, _control_root, publisher_value):
                self.publisher = publisher_value

            def prepare(self, request, _head):
                payload = canonical_json_bytes(
                    {
                        "batch_id": request.batch_id,
                        "campaign_id": "campaign-1",
                        "snapshot_id": request.next_snapshot_id,
                    }
                )
                publication = batch_service.SnapshotPublication(
                    snapshot_id=request.next_snapshot_id,
                    batch_id=request.batch_id,
                    version=request.expected_review_revision + 1,
                    canonical_payload=payload,
                    snapshot_sha256=sha256_bytes(payload),
                    final_path=final_path.parent / request.next_snapshot_id,
                    structural_approval_ready=False,
                    structural_blocker="effect-preview-not-available-m2",
                )
                return SimpleNamespace(
                    request=request,
                    campaign_id="campaign-1",
                    publication=publication,
                    plan=self.publisher.plan(publication),
                    envelope=b"prepared-envelope",
                    base_memberships=(),
                    next_memberships=(),
                )

            def from_stored(self, *_args, **_kwargs):
                raise AssertionError("head drift unexpectedly resumed")

        test_case = self
        publisher = FakePublisher()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m2_workflow,
                "_sealed_package_witness",
                return_value=("filesystem-witness",),
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_reader_session",
                reader_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.ledger_runtime,
                "open_writer_session",
                writer_session,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_state,
                "BatchHeadLoader",
                FakeHeadLoader,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.review_snapshot,
                "ReviewSnapshotPublisher",
                return_value="review-publisher",
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.m2_publishers,
                "BatchReviewPublisherAdapter",
                return_value=publisher,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.explode_service,
                "ExplodeTransitionPreparer",
                FakePreparer,
            ))
            stack.enter_context(mock.patch.object(
                m2_workflow.explode_service,
                "ExplodeReviewUnitService",
                side_effect=AssertionError("head drift reached reservation"),
            ))
            with self.assertRaisesRegex(
                m2_workflow.M2WorkflowError,
                "batch head changed during explode preparation",
            ):
                m2_workflow.explode_review_unit(
                    root,
                    batch_id="batch-1",
                    snapshot_id="snapshot-1",
                    snapshot_sha256="7" * 64,
                    folder_unit_id="unit-folder",
                    next_snapshot_id="snapshot-2",
                    submission_id="submission-2",
                    actor="reviewer",
                )

    def test_workflow_public_api_has_no_inline_migration_authority(self):
        self.assertNotIn(
            "allow_m2_migration",
            inspect.signature(m2_workflow.open_root_run).parameters,
        )
        self.assertNotIn(
            "allow_m2_migration",
            inspect.signature(m2_workflow.open_batch).parameters,
        )
        self.assertNotIn(
            "allow_m2_migration",
            inspect.signature(m2_workflow.explode_review_unit).parameters,
        )


if __name__ == "__main__":
    unittest.main()
