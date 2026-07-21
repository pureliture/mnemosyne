import contextlib
import hashlib
import inspect
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import (  # noqa: E402
    admission,
    batch_service,
    control,
    explode_service,
    inventory,
    ledger_schema,
    m2_publishers,
    review_compiler,
    review_context,
    review_snapshot,
    review_state,
)
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


ITEM_A = "00000000-0000-4000-8000-00000000000a"
ITEM_B = "00000000-0000-4000-8000-00000000000b"


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def analysis_context(analyzer_version="reference-m2-v2"):
    document_paths = (
        "projects/alpha/a.md",
        "projects/alpha/nested/b.md",
    )
    content = {
        "analyzer_version": analyzer_version,
        "coverage_issues": [],
        "documents": [
            {
                "document_type": "markdown",
                "error": None,
                "exclusion_reason": None,
                "fingerprint": digest("document:%s" % path),
                "inspected": True,
                "path": path,
                "projection": None,
                "scope_class": "eligible",
            }
            for path in document_paths
        ],
        "edges": [
            {
                "reference_kind": "markdown-inline",
                "source_path": "projects/alpha/a.md",
                "target_path": "projects/alpha/nested/b.md",
            }
        ],
        "frontier_complete": True,
        "navigation_sources": [],
        "parser_types": [
            "generated-navigation-source",
            "html-attribute",
            "markdown-autolink",
            "markdown-inline",
            "markdown-reference",
            "registry-path",
            "safe-path-literal",
        ],
        "registry_source": {
            "kind": "compiled-registry",
            "sha256": digest("registry:%s" % analyzer_version),
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


ANALYSIS_CONTEXT = analysis_context()
ANALYSIS_CONTEXTS_JSON = canonical_json_bytes([ANALYSIS_CONTEXT])


def item_reference(item_id, path):
    edge = ANALYSIS_CONTEXT["edges"][0]
    direction = "outbound" if edge["source_path"] == path else "inbound"
    return {
        "candidate_path": path,
        "complete": True,
        "context_id": ANALYSIS_CONTEXT["context_id"],
        "context_sha256": ANALYSIS_CONTEXT["context_sha256"],
        "input_manifest_sha256": sha256_bytes(
            canonical_json_bytes(ANALYSIS_CONTEXT)
        ),
        "matches": [
            {
                "direction": direction,
                "reference_kind": edge["reference_kind"],
                "source_path": edge["source_path"],
                "target_path": edge["target_path"],
            }
        ],
        "schema_version": 2,
    }


class ExplodeServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(str(self.root), 0o700)
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("BEGIN IMMEDIATE")
        for statement in control.CONTROL_SCHEMA_STATEMENTS:
            self.connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_INDEX_STATEMENTS:
            self.connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_TRIGGER_STATEMENTS:
            self.connection.execute(statement)
        self.connection.execute(
            "INSERT INTO schema_migrations "
            "(version, schema_sha256, applied_by_bootstrap_id) VALUES (1, ?, ?)",
            (control.CONTROL_SCHEMA_SHA256, "bootstrap-explode-test"),
        )
        self.connection.execute("COMMIT")
        ledger_schema.ensure_v2_schema(
            self.connection,
            migration_id="explode-test-v2",
        )
        self.policy = admission.ApprovedPolicyRef(
            raw_hash=digest("raw-policy"),
            full_hash=digest("full-policy"),
            writer_control_hash=digest("writer-policy"),
            foundation_hash=digest("foundation-policy"),
            generation=1,
            source_kind="INITIAL",
            source_run_id="policy-1",
            guard_epoch=0,
        )
        self._insert_campaign_and_observations()
        self.root = self.root.resolve()
        self.snapshot_root = (
            self.root / "campaigns" / "campaign-1" / "snapshots"
        )
        self.genesis_publisher = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=review_snapshot.ReviewSnapshotPublisher(
                self.snapshot_root,
                renderer_id="explode-test-renderer-v1",
            ),
            review_document_factory=review_context.batch_review_document_from_snapshot,
        )
        self.folder = self._folder_unit()
        self.analysis_contexts_json = ANALYSIS_CONTEXTS_JSON
        context = review_context.ReviewContext(
            rendered_at="2026-07-15T05:00:00Z",
            policy_binding="generation=1;source=INITIAL/policy-1;guard=0",
            coverage=review_compiler.CoverageSummary(1, 1, 0, 0, 2, 2, 0, 0, 0),
            workstreams=(
                review_compiler.WorkstreamSummary("alpha", "active", 1, 0, 0),
            ),
            warning_codes=("m2-no-structural-authority",),
        )
        genesis = batch_service.BatchService(
            self.connection,
            self.snapshot_root,
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=self.genesis_publisher,
            current_policy=lambda: self.policy,
        ).open_batch(
            batch_service.OpenBatchRequest(
                campaign_id="campaign-1",
                expected_campaign_head_sha256=digest("campaign-head"),
                expected_campaign_review_revision=1,
                policy=self.policy,
                batch_id="batch-1",
                snapshot_id="snapshot-1",
                submission_id="submission-1",
                actor="operator@example.test",
                review_context_json=context.canonical_bytes(),
                analysis_contexts_json=self.analysis_contexts_json,
                units=(self.folder,),
                max_items=2,
                max_files=2,
                max_bytes=30,
                max_effects=1,
            )
        )
        self.base_snapshot_sha256 = genesis.snapshot_sha256
        self.base_snapshot_bytes = (genesis.final_path / "snapshot.json").read_bytes()
        self.publisher = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=review_snapshot.ReviewSnapshotPublisher(
                self.snapshot_root,
                renderer_id="explode-test-renderer-v1",
            ),
            review_document_factory=(
                explode_service.exploded_batch_review_document_from_snapshot
            ),
        )
        self.corpus = self.root / "corpus-marker.md"
        self.corpus.write_bytes(b"source corpus must remain byte exact\n")
        os.chmod(str(self.corpus), 0o600)

    def tearDown(self):
        self.connection.close()
        self.temp.cleanup()

    def _insert_campaign_and_observations(self):
        self.connection.execute(
            "INSERT INTO inventory_runs "
            "(run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
            "policy_generation, policy_full_hash, policy_writer_control_hash, "
            "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
            "policy_guard_epoch, parent_run_id, state) "
            "VALUES ('run-1', ?, ?, ?, ?, 1, ?, ?, ?, 'INITIAL', 'policy-1', 0, NULL, 'OPENED')",
            (
                digest("run"),
                "curation-runs/run-1",
                digest("manifest"),
                self.policy.raw_hash,
                self.policy.full_hash,
                self.policy.writer_control_hash,
                self.policy.foundation_hash,
            ),
        )
        self.connection.execute(
            "INSERT INTO campaigns "
            "(campaign_id, root_run_id, root_run_sha256, status, current_snapshot_id, "
            "current_snapshot_sha256, review_revision, active_integration_id, opened_by, "
            "payload_json, campaign_path, campaign_sha256) "
            "VALUES ('campaign-1', 'run-1', ?, 'READY', 'campaign-snapshot-1', ?, 1, "
            "NULL, 'operator@example.test', ?, ?, ?)",
            (
                digest("run"),
                digest("campaign-head"),
                canonical_json_bytes({"campaign_id": "campaign-1"}),
                "campaigns/campaign-1/campaign.json",
                digest("campaign"),
            ),
        )
        rows = (
            (ITEM_A, "projects/alpha/a.md", 10),
            (ITEM_B, "projects/alpha/nested/b.md", 20),
        )
        for index, (item_id, path, size) in enumerate(rows, start=1):
            observation_id = "observation-%d" % index
            observation = inventory.Observation(
                run_id="run-1",
                path=path,
                display_path=path,
                kind="file",
                physical_kind="file",
                scope_class="active-workstream-content",
                scope_rule_id="active-workstream-content",
                traversal="entered",
                content_inspected=False,
                excluded_reason=None,
                identity=inventory.FileIdentity(
                    device=1,
                    inode=index,
                    mode=stat.S_IFREG | 0o600,
                    size=size,
                    mtime_ns=100 + index,
                ),
                fingerprint_kind="metadata",
                fingerprint_value=None,
                content_policy_outcome="metadata-only",
            )
            payload = canonical_json_bytes(observation.to_dict())
            self.connection.execute(
                "INSERT INTO items VALUES (?, 'run-1', 'REVIEW_READY')",
                (item_id,),
            )
            self.connection.execute(
                "INSERT INTO observations VALUES (?, 'run-1', ?, ?, 'file', ?, ?)",
                (
                    "run-1:%s" % observation_id,
                    observation_id,
                    path,
                    payload,
                    sha256_bytes(payload),
                ),
            )
            provenance = canonical_json_bytes(
                {"kind": "first-seen-root-import", "observation_id": observation_id}
            )
            self.connection.execute(
                "INSERT INTO observation_item_links VALUES (?, 'run-1', ?, ?, 1, 1, ?, ?)",
                (
                    "link-%d" % index,
                    observation_id,
                    item_id,
                    provenance,
                    sha256_bytes(provenance),
                ),
            )

    def _folder_unit(self):
        return batch_service.BatchUnit(
            unit_id="unit-folder",
            unit_kind="folder",
            path="projects/alpha",
            display_path="projects/alpha",
            member_item_ids=(ITEM_A, ITEM_B),
            member_paths=("projects/alpha/a.md", "projects/alpha/nested/b.md"),
            scope_class="active-workstream-content",
            sensitivity="public",
            access_domain="default",
            primary_workstream="alpha",
            related_workstreams=(),
            shared=False,
            document_role="reference",
            authority="reference",
            document_lifecycle="current",
            lifecycle_class="current",
            override_class="none",
            scope_rule_id="active-workstream-content",
            recommended_action="defer",
            target_path=None,
            reference_complete=True,
            risk_band="low",
            context_freshness="fresh",
            evidence_providers=("path-pattern",),
            warning_codes=("m2-no-structural-authority",),
            effect_codes=("plan-unavailable-m2",),
            canonical_conflict=False,
            relation_conflict=False,
            target_proven=False,
            analysis_provenance_json=canonical_json_bytes(
                {
                    "items": [
                        {
                            "item_id": item_id,
                            "reference": item_reference(
                                item_id,
                                {
                                    ITEM_A: "projects/alpha/a.md",
                                    ITEM_B: "projects/alpha/nested/b.md",
                                }[item_id],
                            ),
                            "risk": {
                                "band": "low",
                                "input_sha256": digest("risk:%s" % item_id),
                            },
                            "target": {
                                "input_sha256": digest("target:%s" % item_id),
                                "status": "blocked",
                            },
                        }
                        for item_id in (ITEM_A, ITEM_B)
                    ],
                    "schema_version": 1,
                }
            ),
            file_count=2,
            total_bytes=30,
            effect_count=0,
        )

    def request(self, **changes):
        values = {
            "batch_id": "batch-1",
            "expected_snapshot_id": "snapshot-1",
            "expected_snapshot_sha256": self.base_snapshot_sha256,
            "expected_review_revision": 1,
            "expected_execution_generation": 0,
            "policy": self.policy,
            "folder_unit_id": "unit-folder",
            "next_snapshot_id": "snapshot-2",
            "submission_id": "submission-2",
            "actor": "operator@example.test",
            "analysis_contexts_json": self.analysis_contexts_json,
        }
        values.update(changes)
        return explode_service.ExplodeReviewUnitRequest(**values)

    def service(
        self,
        *,
        checkpoint=None,
        events=None,
        current_policy=None,
        active_guards=None,
    ):
        events = events if events is not None else []

        @contextlib.contextmanager
        def placement_shared():
            events.append("placement-enter")
            if active_guards is not None:
                active_guards.append("placement")
            try:
                yield
            finally:
                if active_guards is not None:
                    self.assertEqual(active_guards.pop(), "placement")
                events.append("placement-exit")

        @contextlib.contextmanager
        def ledger_exclusive():
            events.append("ledger-enter")
            if active_guards is not None:
                active_guards.append("ledger")
            try:
                yield
            finally:
                if active_guards is not None:
                    self.assertEqual(active_guards.pop(), "ledger")
                events.append("ledger-exit")

        return explode_service.ExplodeReviewUnitService(
            self.connection,
            self.root,
            placement_shared=placement_shared,
            ledger_exclusive=ledger_exclusive,
            publisher=self.publisher,
            current_policy=(
                current_policy
                if current_policy is not None
                else lambda: self.policy
            ),
            checkpoint=checkpoint,
        )

    def _corpus_identity(self):
        info = self.corpus.stat()
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            sha256_bytes(self.corpus.read_bytes()),
        )

    def test_request_hash_binds_the_exact_approved_policy(self):
        request = self.request()
        rebound = self.request(
            policy=replace(request.policy, guard_epoch=1),
        )

        self.assertNotEqual(request.request_hash, rebound.request_hash)
        self.assertEqual(request.request_payload()["schema_version"], 2)
        self.assertEqual(
            request.request_payload()["analysis_contexts"],
            json.loads(request.analysis_contexts_json),
        )

    def test_context_mismatch_is_rejected_before_prepare_or_publish(self):
        unrelated = analysis_context("reference-m2-v2-unrelated")
        request = self.request(
            analysis_contexts_json=canonical_json_bytes([unrelated])
        )

        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "do not match exact descendants",
        ):
            self.service().explode(request)

        self.assertIsNone(
            self.connection.execute(
                "SELECT state FROM review_submissions "
                "WHERE submission_id = 'submission-2'"
            ).fetchone()
        )
        self.assertFalse((self.snapshot_root / "snapshot-2").exists())

    def test_request_rejects_tampered_analysis_context(self):
        tampered = json.loads(self.analysis_contexts_json)
        tampered[0]["frontier_complete"] = False

        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "analysis contexts",
        ):
            self.request(
                analysis_contexts_json=canonical_json_bytes(tampered)
            )

    def test_prepared_envelope_seals_the_exact_policy_payload(self):
        request = self.request()

        self.service().explode(request)

        envelope = json.loads(
            self.connection.execute(
                "SELECT payload_json FROM review_submissions "
                "WHERE submission_id = 'submission-2'"
            ).fetchone()[0]
        )
        self.assertEqual(envelope["request"], request.request_payload())
        self.assertEqual(envelope["schema_version"], 2)
        self.assertEqual(
            envelope["request"]["policy"]["guard_epoch"],
            request.policy.guard_epoch,
        )

    def test_public_transition_prepares_with_reader_and_applies_without_replanning(self):
        request = self.request()
        head = review_state.BatchHeadLoader(
            self.connection,
            self.root,
        ).load(request.batch_id, (request.folder_unit_id,))
        transition = explode_service.ExplodeTransitionPreparer(
            self.connection,
            self.root,
            self.publisher,
        ).prepare(request, head)

        self.assertIsInstance(
            transition,
            explode_service.PreparedExplodeTransition,
        )
        self.assertEqual(transition.request, request)
        self.assertEqual(transition.campaign_id, head.campaign_id)
        with mock.patch.object(
            self.publisher,
            "plan",
            side_effect=AssertionError("writer path must not replan"),
        ):
            result = self.service().explode_prepared(transition)

        self.assertEqual(result.snapshot_state, "PUBLISHED")
        self.assertEqual(result.snapshot_sha256, transition.publication.snapshot_sha256)

    def test_public_explode_prepares_new_transition_before_writer_guards(self):
        active_guards = []
        original_plan = self.publisher.plan

        def plan_without_writer_guard(publication):
            self.assertEqual(active_guards, [])
            return original_plan(publication)

        with mock.patch.object(
            self.publisher,
            "plan",
            side_effect=plan_without_writer_guard,
        ):
            result = self.service(active_guards=active_guards).explode(
                self.request()
            )

        self.assertEqual(active_guards, [])
        self.assertEqual(result.snapshot_state, "PUBLISHED")

    def test_public_explode_replans_stored_transition_before_writer_guards(self):
        request = self.request()

        def stop_after_prepare(point):
            if point == "prepared":
                raise RuntimeError("stop after prepare")

        with self.assertRaisesRegex(RuntimeError, "stop after prepare"):
            self.service(checkpoint=stop_after_prepare).explode(request)

        active_guards = []
        original_from_stored = (
            explode_service.ExplodeTransitionPreparer.from_stored
        )
        original_plan = self.publisher.plan

        def from_stored_without_writer_guard(preparer, *args, **kwargs):
            self.assertEqual(active_guards, [])
            return original_from_stored(preparer, *args, **kwargs)

        def plan_without_writer_guard(publication):
            self.assertEqual(active_guards, [])
            return original_plan(publication)

        with mock.patch.object(
            explode_service.ExplodeTransitionPreparer,
            "from_stored",
            autospec=True,
            side_effect=from_stored_without_writer_guard,
        ), mock.patch.object(
            self.publisher,
            "plan",
            side_effect=plan_without_writer_guard,
        ):
            result = self.service(active_guards=active_guards).explode(request)

        self.assertEqual(active_guards, [])
        self.assertTrue(result.resumed)
        self.assertEqual(result.snapshot_state, "PUBLISHED")

    def test_public_stored_transition_parser_resumes_exact_prepared_envelope(self):
        request = self.request()

        def stop_after_prepare(point):
            if point == "prepared":
                raise RuntimeError("stop after prepare")

        with self.assertRaisesRegex(RuntimeError, "stop after prepare"):
            self.service(checkpoint=stop_after_prepare).explode(request)
        envelope = bytes(
            self.connection.execute(
                "SELECT payload_json FROM review_submissions "
                "WHERE submission_id = ?",
                (request.submission_id,),
            ).fetchone()[0]
        )
        identity = explode_service.ExplodeInvocationIdentity(
            batch_id=request.batch_id,
            expected_snapshot_id=request.expected_snapshot_id,
            expected_snapshot_sha256=request.expected_snapshot_sha256,
            folder_unit_id=request.folder_unit_id,
            next_snapshot_id=request.next_snapshot_id,
            submission_id=request.submission_id,
            actor=request.actor,
        )
        transition = explode_service.ExplodeTransitionPreparer(
            self.connection,
            self.root,
            self.publisher,
        ).from_stored(
            envelope,
            policy=self.policy,
            expected_identity=identity,
        )

        self.assertEqual(transition.request, request)
        with mock.patch.object(
            self.publisher,
            "plan",
            side_effect=AssertionError("resume writer path must not replan"),
        ):
            result = self.service().explode_prepared(transition)

        self.assertTrue(result.resumed)
        self.assertEqual(result.snapshot_state, "PUBLISHED")

    def test_public_stored_transition_parser_rejects_invocation_rebinding(self):
        request = self.request()
        head = review_state.BatchHeadLoader(
            self.connection,
            self.root,
        ).load(request.batch_id, (request.folder_unit_id,))
        transition = explode_service.ExplodeTransitionPreparer(
            self.connection,
            self.root,
            self.publisher,
        ).prepare(request, head)
        forged = explode_service.ExplodeInvocationIdentity(
            batch_id=request.batch_id,
            expected_snapshot_id=request.expected_snapshot_id,
            expected_snapshot_sha256=request.expected_snapshot_sha256,
            folder_unit_id=request.folder_unit_id,
            next_snapshot_id="snapshot-forged",
            submission_id=request.submission_id,
            actor=request.actor,
        )

        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "another explode request",
        ):
            explode_service.ExplodeTransitionPreparer(
                self.connection,
                self.root,
                self.publisher,
            ).from_stored(
                transition.envelope,
                policy=self.policy,
                expected_identity=forged,
            )

    def test_service_requires_a_current_policy_callback(self):
        parameter = inspect.signature(
            explode_service.ExplodeReviewUnitService
        ).parameters["current_policy"]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        with self.assertRaisesRegex(TypeError, "current_policy"):
            explode_service.ExplodeReviewUnitService(
                self.connection,
                self.root,
                placement_shared=contextlib.nullcontext,
                ledger_exclusive=contextlib.nullcontext,
                publisher=self.publisher,
            )

    def test_policy_drift_is_rejected_before_prepare(self):
        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "current policy authority drifted",
        ):
            self.service(
                current_policy=lambda: replace(self.policy, guard_epoch=1),
            ).explode(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_submissions "
                "WHERE submission_id = 'submission-2'"
            ).fetchone()[0],
            0,
        )

    def test_campaign_root_policy_must_match_request_authority(self):
        self.connection.execute(
            "UPDATE inventory_runs SET policy_guard_epoch = 1 "
            "WHERE run_id = 'run-1'"
        )

        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "lineage policy authority is stale",
        ):
            self.service().explode(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_submissions "
                "WHERE submission_id = 'submission-2'"
            ).fetchone()[0],
            0,
        )

    def test_policy_drift_after_publish_preserves_base_projection(self):
        current = {"policy": self.policy}
        before_memberships = self.connection.execute(
            "SELECT unit_id, item_id, path, status FROM batch_memberships "
            "WHERE batch_id = 'batch-1' ORDER BY item_id"
        ).fetchall()

        def checkpoint(point):
            if point == "published":
                current["policy"] = replace(self.policy, guard_epoch=1)

        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "current policy authority drifted",
        ):
            self.service(
                checkpoint=checkpoint,
                current_policy=lambda: current["policy"],
            ).explode(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT current_snapshot_id, current_snapshot_sha256, "
                "review_revision FROM review_batches WHERE batch_id = 'batch-1'"
            ).fetchone(),
            ("snapshot-1", self.base_snapshot_sha256, 1),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions "
                "WHERE submission_id = 'submission-2'"
            ).fetchone(),
            ("PREPARED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_snapshots "
                "WHERE snapshot_id = 'snapshot-2'"
            ).fetchone(),
            ("PREPARED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT unit_id, item_id, path, status FROM batch_memberships "
                "WHERE batch_id = 'batch-1' ORDER BY item_id"
            ).fetchall(),
            before_memberships,
        )

    def test_policy_drift_immediately_before_final_commit_rolls_back_projection(self):
        calls = []
        current = {"policy": self.policy}
        before_memberships = self.connection.execute(
            "SELECT unit_id, item_id, path, status FROM batch_memberships "
            "WHERE batch_id = 'batch-1' ORDER BY item_id"
        ).fetchall()

        def current_policy():
            calls.append("check")
            observed = current["policy"]
            if len(calls) == 5:
                current["policy"] = replace(self.policy, guard_epoch=1)
            return observed

        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "current policy authority drifted",
        ):
            self.service(current_policy=current_policy).explode(self.request())

        self.assertGreaterEqual(len(calls), 6)
        self.assertEqual(
            self.connection.execute(
                "SELECT current_snapshot_id, current_snapshot_sha256, "
                "review_revision FROM review_batches WHERE batch_id = 'batch-1'"
            ).fetchone(),
            ("snapshot-1", self.base_snapshot_sha256, 1),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions "
                "WHERE submission_id = 'submission-2'"
            ).fetchone(),
            ("PREPARED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_snapshots "
                "WHERE snapshot_id = 'snapshot-2'"
            ).fetchone(),
            ("PREPARED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT unit_id, item_id, path, status FROM batch_memberships "
                "WHERE batch_id = 'batch-1' ORDER BY item_id"
            ).fetchall(),
            before_memberships,
        )

    def test_explode_publishes_copy_on_write_v2_and_conserves_membership(self):
        before_corpus = self._corpus_identity()
        events = []

        result = self.service(events=events).explode(self.request())

        self.assertEqual(result.status, "OPEN")
        self.assertEqual(result.snapshot_state, "PUBLISHED")
        self.assertEqual(result.snapshot_version, 2)
        self.assertEqual(result.review_revision, 2)
        self.assertEqual(result.parent_snapshot_id, "snapshot-1")
        self.assertEqual(result.parent_snapshot_sha256, self.base_snapshot_sha256)
        self.assertFalse(result.structural_approval_ready)
        self.assertFalse(result.resumed)
        self.assertEqual(
            events,
            ["placement-enter", "ledger-enter", "ledger-exit", "placement-exit"],
        )
        self.assertEqual(before_corpus, self._corpus_identity())
        self.assertEqual(
            (self.snapshot_root / "snapshot-1" / "snapshot.json").read_bytes(),
            self.base_snapshot_bytes,
        )

        payload = json.loads((result.final_path / "snapshot.json").read_bytes())
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(
            payload["analysis_contexts"],
            json.loads(self.analysis_contexts_json),
        )
        self.assertEqual(payload["batch_version"], 2)
        self.assertEqual(payload["parent_snapshot_id"], "snapshot-1")
        self.assertEqual(
            payload["parent_snapshot_sha256"], self.base_snapshot_sha256
        )
        self.assertFalse(payload["approval_ready"])
        self.assertFalse(payload["structural_approval_ready"])
        self.assertEqual(
            [(row["unit_kind"], row["canonical_path"]) for row in payload["units"]],
            [
                ("file", "projects/alpha/a.md"),
                ("file", "projects/alpha/nested/b.md"),
            ],
        )
        member_ids = [
            item_id for row in payload["units"] for item_id in row["member_item_ids"]
        ]
        self.assertEqual(sorted(member_ids), [ITEM_A, ITEM_B])
        self.assertEqual(len(member_ids), len(set(member_ids)))
        self.assertEqual(
            self.connection.execute(
                "SELECT unit_id, item_id, path, status FROM batch_memberships "
                "WHERE batch_id = 'batch-1' ORDER BY item_id"
            ).fetchall(),
            [
                (payload["units"][0]["unit_id"], ITEM_A, "projects/alpha/a.md", "OPEN"),
                (
                    payload["units"][1]["unit_id"],
                    ITEM_B,
                    "projects/alpha/nested/b.md",
                    "OPEN",
                ),
            ],
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT current_snapshot_id, current_snapshot_sha256, review_revision, "
                "execution_generation FROM review_batches WHERE batch_id = 'batch-1'"
            ).fetchone(),
            ("snapshot-2", result.snapshot_sha256, 2, 0),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT version, parent_snapshot_id, parent_snapshot_sha256, state, "
                "structural_approval_ready FROM review_snapshots "
                "WHERE snapshot_id = 'snapshot-2'"
            ).fetchone(),
            (2, "snapshot-1", self.base_snapshot_sha256, "PUBLISHED", 0),
        )

    def test_exploded_preview_reuses_shared_typed_snapshot_parser_and_builder(self):
        result = self.service().explode(self.request())
        snapshot_payload = (result.final_path / "snapshot.json").read_bytes()

        with mock.patch.object(
            review_context,
            "parse_batch_review_snapshot",
            wraps=review_context.parse_batch_review_snapshot,
        ) as parser, mock.patch.object(
            review_context,
            "review_document_from_parsed_batch_snapshot",
            wraps=review_context.review_document_from_parsed_batch_snapshot,
        ) as builder:
            document = explode_service.exploded_batch_review_document_from_snapshot(
                snapshot_payload
            )

        self.assertEqual(document.snapshot_version, 2)
        parser.assert_called_once_with(
            snapshot_payload,
            lineage_policy=review_context.DESCENDANT_BATCH_LINEAGE,
        )
        builder.assert_called_once()

    def test_v1_base_requires_explicit_cow_normalization(self):
        payload = json.loads(self.base_snapshot_bytes)
        payload.pop("analysis_contexts")
        payload["schema_version"] = 1

        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "COW-normalization-required",
        ):
            explode_service.exploded_batch_review_document_from_snapshot(
                canonical_json_bytes(payload)
            )

    def test_exact_committed_retry_returns_same_snapshot_without_fork(self):
        first = self.service().explode(self.request())
        snapshot_count = self.connection.execute(
            "SELECT count(*) FROM review_snapshots WHERE batch_id = 'batch-1'"
        ).fetchone()[0]

        second = self.service().explode(self.request())

        self.assertTrue(second.resumed)
        self.assertEqual(second.snapshot_sha256, first.snapshot_sha256)
        self.assertEqual(second.package_sha256, first.package_sha256)
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_snapshots WHERE batch_id = 'batch-1'"
            ).fetchone()[0],
            snapshot_count,
        )

    def test_crash_after_publish_resumes_from_stored_payload_not_observations(self):
        def checkpoint(point):
            if point == "published":
                raise RuntimeError("simulated crash")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.service(checkpoint=checkpoint).explode(self.request())
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions WHERE submission_id = 'submission-2'"
            ).fetchone(),
            ("PREPARED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT current_snapshot_id, review_revision FROM review_batches "
                "WHERE batch_id = 'batch-1'"
            ).fetchone(),
            ("snapshot-1", 1),
        )
        corrupt = canonical_json_bytes({"not": "an inventory observation"})
        self.connection.execute(
            "UPDATE observations SET payload_json = ?, payload_sha256 = ?",
            (corrupt, sha256_bytes(corrupt)),
        )

        resumed = self.service().explode(self.request())

        self.assertTrue(resumed.resumed)
        self.assertEqual(resumed.review_revision, 2)
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions WHERE submission_id = 'submission-2'"
            ).fetchone(),
            ("COMMITTED",),
        )

    def test_stale_claimed_nonfolder_or_incomplete_descendant_fails_before_prepare(self):
        cases = (
            self.request(expected_snapshot_sha256="f" * 64),
            self.request(expected_review_revision=2),
            self.request(folder_unit_id="missing-unit"),
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(explode_service.ExplodeReviewUnitError):
                    self.service().explode(request)
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_submissions WHERE submission_id = 'submission-2'"
            ).fetchone()[0],
            0,
        )

        self.connection.execute(
            "UPDATE review_batches SET status = 'CLAIMED' WHERE batch_id = 'batch-1'"
        )
        self.connection.execute(
            "UPDATE batch_memberships SET status = 'CLAIMED' WHERE batch_id = 'batch-1'"
        )
        with self.assertRaises(explode_service.ExplodeReviewUnitError):
            self.service().explode(self.request())

        self.connection.execute(
            "UPDATE review_batches SET status = 'OPEN' WHERE batch_id = 'batch-1'"
        )
        self.connection.execute(
            "UPDATE batch_memberships SET status = 'OPEN' WHERE batch_id = 'batch-1'"
        )
        self.connection.execute(
            "UPDATE observation_item_links SET is_current = 0 WHERE item_id = ?",
            (ITEM_B,),
        )
        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "descendant",
        ):
            self.service().explode(self.request())

    def test_unresolved_submission_and_global_identity_collision_fail_closed(self):
        def checkpoint(point):
            if point == "prepared":
                raise RuntimeError("stop after prepare")

        with self.assertRaisesRegex(RuntimeError, "stop after prepare"):
            self.service(checkpoint=checkpoint).explode(self.request())

        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "unresolved",
        ):
            self.service().explode(
                self.request(
                    next_snapshot_id="snapshot-3",
                    submission_id="submission-3",
                )
            )

        resumed = self.service().explode(self.request())
        self.assertTrue(resumed.resumed)
        with self.assertRaises(explode_service.ExplodeReviewUnitError):
            self.service().explode(
                self.request(
                    expected_snapshot_id="snapshot-2",
                    expected_snapshot_sha256=resumed.snapshot_sha256,
                    expected_review_revision=2,
                    next_snapshot_id="snapshot-1",
                    submission_id="submission-4",
                )
            )

    def test_prepared_final_cas_that_becomes_claimed_is_blocked_without_projection(self):
        def checkpoint(point):
            if point == "published":
                raise RuntimeError("stop before final CAS")

        with self.assertRaisesRegex(RuntimeError, "stop before final CAS"):
            self.service(checkpoint=checkpoint).explode(self.request())
        before_memberships = self.connection.execute(
            "SELECT unit_id, item_id, path FROM batch_memberships "
            "WHERE batch_id = 'batch-1' ORDER BY item_id"
        ).fetchall()
        self.connection.execute(
            "UPDATE review_batches SET status = 'CLAIMED', execution_generation = 1 "
            "WHERE batch_id = 'batch-1'"
        )
        self.connection.execute(
            "UPDATE batch_memberships SET status = 'CLAIMED' "
            "WHERE batch_id = 'batch-1'"
        )

        with self.assertRaises(explode_service.ExplodeReviewUnitError):
            self.service().explode(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions WHERE submission_id = 'submission-2'"
            ).fetchone(),
            ("BLOCKED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_snapshots WHERE snapshot_id = 'snapshot-2'"
            ).fetchone(),
            ("BLOCKED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT current_snapshot_id, current_snapshot_sha256, review_revision "
                "FROM review_batches WHERE batch_id = 'batch-1'"
            ).fetchone(),
            ("snapshot-1", self.base_snapshot_sha256, 1),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT unit_id, item_id, path FROM batch_memberships "
                "WHERE batch_id = 'batch-1' ORDER BY item_id"
            ).fetchall(),
            before_memberships,
        )

    def test_preallocated_snapshot_and_submission_ids_are_global(self):
        self.connection.execute(
            "INSERT INTO review_snapshots "
            "(snapshot_id, lineage_kind, campaign_id, batch_id, version, "
            "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, "
            "final_path, final_sha256, state, structural_approval_ready) "
            "VALUES ('snapshot-collision', 'CAMPAIGN', 'campaign-1', NULL, 1, "
            "NULL, NULL, ?, ?, ?, 'PUBLISHED', 0)",
            (
                digest("collision-payload"),
                str(self.root / "collision-snapshot"),
                digest("collision-package"),
            ),
        )
        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "globally bound",
        ):
            self.service().explode(
                self.request(next_snapshot_id="snapshot-collision")
            )
        with self.assertRaisesRegex(
            explode_service.ExplodeReviewUnitError,
            "another or nonresumable",
        ):
            self.service().explode(self.request(submission_id="submission-1"))


if __name__ == "__main__":
    unittest.main()
