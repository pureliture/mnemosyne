import contextlib
import hashlib
import inspect
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import (  # noqa: E402
    admission,
    batch_service,
    control,
    ledger_schema,
    m2_publishers,
    review_compiler,
    review_context,
    review_snapshot,
)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def analysis_context(*, frontier_complete, analyzer_version):
    document_paths = (
        "private/notes.md",
        "projects",
        "projects/alpha/a.md",
        "projects/alpha/b.md",
        "projects/alpha/nested/b.md",
        "projects/alpha/nested/c.md",
        "projects/alpha/x.md",
        "projects/beta/c.md",
    )
    content = {
        "analyzer_version": analyzer_version,
        "coverage_issues": (
            []
            if frontier_complete
            else [
                {
                    "kind": "exclusion",
                    "path": "projects/uninspected.md",
                    "reason": "fixture-frontier-incomplete",
                }
            ]
        ),
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
        "edges": [],
        "frontier_complete": frontier_complete,
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
            "sha256": digest(analyzer_version),
            "source_id": "placement-registry",
        },
        "scanned_roots": ["private", "projects"],
    }
    content_sha256 = batch_service.sha256_bytes(
        batch_service.canonical_json_bytes(content)
    )
    value = dict(content)
    value.update(
        {
            "content_sha256": content_sha256,
            "context_id": "reference-context-%s" % content_sha256[:24],
            "schema_version": 1,
        }
    )
    value["context_sha256"] = batch_service.sha256_bytes(
        batch_service.canonical_json_bytes(value)
    )
    return value


COMPLETE_CONTEXT = analysis_context(
    frontier_complete=True,
    analyzer_version="reference-m2-v2-complete",
)
INCOMPLETE_CONTEXT = analysis_context(
    frontier_complete=False,
    analyzer_version="reference-m2-v2-incomplete",
)
CONTEXTS_BY_ID = {
    value["context_id"]: value
    for value in (COMPLETE_CONTEXT, INCOMPLETE_CONTEXT)
}


ITEM_A = "00000000-0000-4000-8000-00000000000a"
ITEM_B = "00000000-0000-4000-8000-00000000000b"
ITEM_C = "00000000-0000-4000-8000-00000000000c"
ITEM_X = "00000000-0000-4000-8000-00000000000d"
ITEM_Z = "00000000-0000-4000-8000-00000000000e"


def policy_for_campaign(campaign_id):
    return admission.ApprovedPolicyRef(
        raw_hash=digest("policy-raw-%s" % campaign_id),
        full_hash=digest("policy-%s" % campaign_id),
        writer_control_hash=digest("policy-writer-%s" % campaign_id),
        foundation_hash=digest("policy-foundation-%s" % campaign_id),
        generation=1,
        source_kind="INITIAL",
        source_run_id="policy-source-%s" % campaign_id,
        guard_epoch=0,
    )


def unit(unit_id, path, item_id, **changes):
    values = {
        "unit_id": unit_id,
        "unit_kind": "file",
        "path": path,
        "display_path": path,
        "member_item_ids": (item_id,),
        "member_paths": (path,),
        "scope_class": "active-workstream-content",
        "sensitivity": "public",
        "access_domain": "default",
        "primary_workstream": "alpha",
        "related_workstreams": (),
        "shared": False,
        "document_role": "reference",
        "authority": "reference",
        "document_lifecycle": "current",
        "lifecycle_class": "current",
        "override_class": "none",
        "scope_rule_id": "active-workstream-content",
        "recommended_action": "move",
        "target_path": "organized/%s" % path,
        "reference_complete": True,
        "risk_band": "low",
        "context_freshness": "fresh",
        "evidence_providers": ("path-pattern",),
        "warning_codes": ("m2-no-structural-authority",),
        "effect_codes": ("plan-unavailable-m2",),
        "canonical_conflict": False,
        "relation_conflict": False,
        "file_count": 1,
        "total_bytes": 10,
        "effect_count": 1,
    }
    values.update(changes)
    if "unit_kind" not in changes and (
        len(values["member_item_ids"]) > 1
        or values["member_paths"] != (values["path"],)
    ):
        values["unit_kind"] = "folder"
    if "display_path" not in changes:
        values["display_path"] = values["path"]
    warnings = set(values["warning_codes"])
    private = (
        values["sensitivity"] == "private"
        or values["scope_class"] == "private-reviewable"
    )
    opaque = values["scope_class"] in ("opaque-private-evidence", "opaque")
    if private:
        warnings.add("private-metadata-only")
    if opaque:
        warnings.add("opaque-content-unopened")
    if (private or opaque) and "risk_band" not in changes:
        values["risk_band"] = "blocked"
    if not values["reference_complete"]:
        warnings.add("reference-incomplete")
    if values["override_class"] != "none":
        warnings.add("lifecycle-frozen")
    if values["canonical_conflict"] or values["relation_conflict"]:
        warnings.add("competing-candidate")
    values["warning_codes"] = tuple(sorted(warnings))
    if (
        private
        or opaque
        or values["recommended_action"] not in ("move", "archive")
    ) and "target_path" not in changes:
        values["target_path"] = None
    if (private or opaque) and "recommended_action" not in changes:
        values["recommended_action"] = "defer"
    values["target_proven"] = values["target_path"] is not None
    context_value = (
        COMPLETE_CONTEXT if values["reference_complete"] else INCOMPLETE_CONTEXT
    )
    values["analysis_provenance_json"] = batch_service.canonical_json_bytes(
        {
            "items": [
                {
                    "item_id": member_item_id,
                    "reference": {
                        "candidate_path": values["member_paths"][
                            values["member_item_ids"].index(member_item_id)
                        ],
                        "complete": values["reference_complete"],
                        "context_id": context_value["context_id"],
                        "context_sha256": context_value["context_sha256"],
                        "input_manifest_sha256": batch_service.sha256_bytes(
                            batch_service.canonical_json_bytes(context_value)
                        ),
                        "matches": [],
                        "schema_version": 2,
                    },
                    "risk": {
                        "band": values["risk_band"],
                        "input_sha256": digest("risk:%s" % member_item_id),
                    },
                    "target": {
                        "input_sha256": digest("target:%s" % member_item_id),
                        "status": (
                            "resolved" if values["target_proven"] else "blocked"
                        ),
                    },
                }
                for member_item_id in sorted(values["member_item_ids"])
            ],
            "schema_version": 1,
        }
    )
    return batch_service.BatchUnit(**values)


class BatchServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.connection = sqlite3.connect(
            str(self.root / "ledger.sqlite3"),
            isolation_level=None,
        )
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
            "(version, schema_sha256, applied_by_bootstrap_id) VALUES (?, ?, ?)",
            (1, control.CONTROL_SCHEMA_SHA256, "bootstrap-v1-batch-test"),
        )
        self.connection.execute("COMMIT")
        ledger_schema.ensure_v2_schema(
            self.connection,
            migration_id="test-m2-batch-service",
        )
        self.policy = policy_for_campaign("campaign-001")
        self._insert_ready_campaign("campaign-001", digest("campaign-head-001"), 7)
        self.connection.executemany(
            "INSERT INTO items (item_id, first_seen_run_id, state) "
            "VALUES (?, ?, 'REVIEW_READY')",
            [
                (item_id, "run-campaign-001")
                for item_id in (
                    ITEM_A,
                    ITEM_B,
                    ITEM_C,
                    ITEM_X,
                    ITEM_Z,
                )
            ],
        )
        self.publisher = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=review_snapshot.ReviewSnapshotPublisher(
                (self.root / "snapshots").resolve(),
                renderer_id="batch-service-test-renderer-v1",
            ),
            review_document_factory=review_context.batch_review_document_from_snapshot,
        )
        self.service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=self.publisher,
            current_policy=lambda: self.policy,
        )

    def tearDown(self):
        self.connection.close()
        self.temp.cleanup()

    def test_service_requires_an_explicit_full_snapshot_publisher(self):
        parameter = inspect.signature(batch_service.BatchService).parameters[
            "publisher"
        ]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        with self.assertRaisesRegex(TypeError, "publisher"):
            batch_service.BatchService(
                self.connection,
                self.root / "snapshots",
                placement_shared=contextlib.nullcontext,
                ledger_exclusive=contextlib.nullcontext,
            )

    def test_service_requires_a_current_policy_callback(self):
        parameter = inspect.signature(batch_service.BatchService).parameters[
            "current_policy"
        ]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        with self.assertRaisesRegex(TypeError, "current_policy"):
            batch_service.BatchService(
                self.connection,
                self.root / "snapshots",
                placement_shared=contextlib.nullcontext,
                ledger_exclusive=contextlib.nullcontext,
                publisher=self.publisher,
            )

    def test_request_hash_binds_the_exact_approved_policy(self):
        request = self.request()
        rebound = self.request(policy=replace(request.policy, guard_epoch=1))

        self.assertNotEqual(request.request_hash, rebound.request_hash)
        self.assertEqual(request.request_payload()["schema_version"], 2)
        self.assertEqual(
            request.request_payload()["analysis_contexts"],
            json.loads(request.analysis_contexts_json),
        )

    def test_request_rejects_unrelated_context_and_tampered_item_reference(self):
        extra = analysis_context(
            frontier_complete=True,
            analyzer_version="reference-m2-v2-unrelated",
        )
        contexts = sorted(
            (COMPLETE_CONTEXT, extra),
            key=lambda row: row["context_id"],
        )
        with self.assertRaisesRegex(
            batch_service.BatchValidationError,
            "analysis contexts",
        ):
            self.request(
                analysis_contexts_json=batch_service.canonical_json_bytes(
                    contexts
                )
            )

        original = unit("unit-a", "projects/alpha/a.md", ITEM_A)
        provenance = json.loads(original.analysis_provenance_json)
        provenance["items"][0]["reference"]["candidate_path"] = (
            "projects/alpha/forged.md"
        )
        forged = replace(
            original,
            analysis_provenance_json=batch_service.canonical_json_bytes(
                provenance
            ),
        )
        with self.assertRaisesRegex(
            batch_service.BatchValidationError,
            "analysis contexts",
        ):
            self.request(units=(forged,), max_items=1, max_files=1)

    def test_prepared_envelope_seals_the_exact_policy_payload(self):
        request = self.request()

        self.service.open_batch(request)

        envelope = json.loads(
            self.connection.execute(
                "SELECT payload_json FROM review_submissions "
                "WHERE submission_id = 'submission-001'"
            ).fetchone()[0]
        )
        self.assertEqual(envelope["request"], request.request_payload())
        self.assertEqual(envelope["schema_version"], 2)
        self.assertEqual(
            envelope["request"]["policy"]["guard_epoch"],
            request.policy.guard_epoch,
        )

    def test_public_prepared_publication_executes_without_replanning_under_writer(self):
        request = self.request()
        prepared = batch_service.prepare_batch_publication(
            self.root / "snapshots",
            self.publisher,
            request,
        )

        self.assertIsInstance(
            prepared,
            batch_service.PreparedBatchPublication,
        )
        self.assertEqual(
            json.loads(prepared.envelope)["request"],
            request.request_payload(),
        )
        with mock.patch.object(
            self.publisher,
            "plan",
            side_effect=AssertionError("writer path must not replan"),
        ):
            result = self.service.open_prepared_batch(request, prepared)

        self.assertEqual(result.snapshot_state, "COMMITTED")
        self.assertEqual(result.snapshot_sha256, prepared.publication.snapshot_sha256)

    def test_public_open_batch_prepares_before_writer_guards(self):
        active_guards = []

        @contextlib.contextmanager
        def guard(name):
            active_guards.append(name)
            try:
                yield
            finally:
                self.assertEqual(active_guards.pop(), name)

        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=lambda: guard("placement"),
            ledger_exclusive=lambda: guard("ledger"),
            publisher=self.publisher,
            current_policy=lambda: self.policy,
        )
        original_plan = self.publisher.plan

        def plan_without_writer_guard(publication):
            self.assertEqual(active_guards, [])
            return original_plan(publication)

        with mock.patch.object(
            self.publisher,
            "plan",
            side_effect=plan_without_writer_guard,
        ):
            result = service.open_batch(self.request())

        self.assertEqual(active_guards, [])
        self.assertEqual(result.snapshot_state, "COMMITTED")

    def test_public_prepared_publication_rejects_rebound_envelope_before_write(self):
        request = self.request()
        prepared = batch_service.prepare_batch_publication(
            self.root / "snapshots",
            self.publisher,
            request,
        )
        rebound = replace(prepared, envelope=b"{}\n")

        with self.assertRaisesRegex(
            batch_service.BatchPublicationError,
            "prepared batch publication",
        ):
            self.service.open_prepared_batch(request, rebound)

        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_batches"
            ).fetchone()[0],
            0,
        )

    def test_policy_drift_is_rejected_before_batch_prepare(self):
        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=self.publisher,
            current_policy=lambda: replace(self.policy, guard_epoch=1),
        )

        with self.assertRaisesRegex(
            batch_service.BatchConflictError,
            "current policy authority drifted",
        ):
            service.open_batch(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_batches"
            ).fetchone()[0],
            0,
        )
        self.assertFalse((self.root / "snapshots" / "snapshot-001").exists())

    def test_campaign_root_policy_must_match_the_request_authority(self):
        self.connection.execute(
            "UPDATE inventory_runs SET policy_guard_epoch = 1 "
            "WHERE run_id = 'run-campaign-001'"
        )

        with self.assertRaisesRegex(
            batch_service.BatchConflictError,
            "campaign policy authority is stale",
        ):
            self.service.open_batch(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_batches"
            ).fetchone()[0],
            0,
        )

    def test_policy_drift_after_publish_keeps_non_authoritative_genesis(self):
        current = {"policy": self.policy}

        def checkpoint(point):
            if point == "published":
                current["policy"] = replace(self.policy, guard_epoch=1)

        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=self.publisher,
            current_policy=lambda: current["policy"],
            checkpoint=checkpoint,
        )

        with self.assertRaisesRegex(
            batch_service.BatchConflictError,
            "current policy authority drifted",
        ):
            service.open_batch(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT current_snapshot_id, review_revision "
                "FROM review_batches WHERE batch_id = 'batch-001'"
            ).fetchone(),
            (None, 0),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions "
                "WHERE submission_id = 'submission-001'"
            ).fetchone(),
            ("PREPARED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM batch_memberships "
                "WHERE batch_id = 'batch-001' AND status = 'OPEN'"
            ).fetchone()[0],
            2,
        )
        self.assertTrue((self.root / "snapshots" / "snapshot-001").is_dir())

    def test_policy_drift_immediately_before_final_commit_rolls_back_head(self):
        calls = []
        current = {"policy": self.policy}

        def current_policy():
            calls.append("check")
            observed = current["policy"]
            if len(calls) == 5:
                current["policy"] = replace(self.policy, guard_epoch=1)
            return observed

        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=self.publisher,
            current_policy=current_policy,
        )

        with self.assertRaisesRegex(
            batch_service.BatchConflictError,
            "current policy authority drifted",
        ):
            service.open_batch(self.request())

        self.assertGreaterEqual(len(calls), 6)
        self.assertEqual(
            self.connection.execute(
                "SELECT current_snapshot_id, current_snapshot_sha256, "
                "review_revision FROM review_batches WHERE batch_id = 'batch-001'"
            ).fetchone(),
            (None, None, 0),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_snapshots "
                "WHERE snapshot_id = 'snapshot-001'"
            ).fetchone(),
            ("PREPARED",),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT unit_id, item_id, path, status FROM batch_memberships "
                "WHERE batch_id = 'batch-001' ORDER BY item_id"
            ).fetchall(),
            [
                ("unit-a", ITEM_A, "projects/alpha/a.md", "OPEN"),
                ("unit-b", ITEM_B, "projects/alpha/b.md", "OPEN"),
            ],
        )

    def _insert_ready_campaign(
        self,
        campaign_id,
        head_sha256,
        review_revision,
        policy=None,
    ):
        policy = self.policy if policy is None else policy
        run_id = "run-%s" % campaign_id
        run_sha256 = digest("run-sha-%s" % campaign_id)
        self.connection.execute(
            "INSERT INTO inventory_runs "
            "(run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
            "policy_generation, policy_full_hash, policy_writer_control_hash, "
            "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
            "policy_guard_epoch, parent_run_id, state) "
            "VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, 'INITIAL', ?, 0, NULL, 'OPENED')",
            (
                run_id,
                run_sha256,
                "/tmp/%s" % run_id,
                digest("manifest-%s" % campaign_id),
                policy.raw_hash,
                policy.full_hash,
                policy.writer_control_hash,
                policy.foundation_hash,
                policy.source_run_id,
            ),
        )
        self.connection.execute(
            "INSERT INTO campaigns "
            "(campaign_id, root_run_id, root_run_sha256, status, "
            "current_snapshot_id, current_snapshot_sha256, review_revision, "
            "active_integration_id, opened_by, payload_json, campaign_path, "
            "campaign_sha256) "
            "VALUES (?, ?, ?, 'READY', ?, ?, ?, NULL, ?, ?, ?, ?)",
            (
                campaign_id,
                run_id,
                run_sha256,
                "overview-%s" % campaign_id,
                head_sha256,
                review_revision,
                "reviewer@example.test",
                b"{}\n",
                "/tmp/%s.json" % campaign_id,
                digest("campaign-%s" % campaign_id),
            ),
        )

    def request(self, **changes):
        values = {
            "campaign_id": "campaign-001",
            "expected_campaign_head_sha256": digest("campaign-head-001"),
            "expected_campaign_review_revision": 7,
            "batch_id": "batch-001",
            "snapshot_id": "snapshot-001",
            "submission_id": "submission-001",
            "actor": "reviewer@example.test",
            "units": (
                unit("unit-a", "projects/alpha/a.md", ITEM_A),
                unit("unit-b", "projects/alpha/b.md", ITEM_B),
            ),
            "max_items": 2,
            "max_files": 2,
            "max_bytes": 20,
            "max_effects": 2,
        }
        values.update(changes)
        if "policy" not in changes:
            values["policy"] = self.policy
        if "review_context_json" not in changes:
            unit_payloads = tuple(value.to_dict() for value in values["units"])
            workstreams = tuple(
                review_compiler.WorkstreamSummary(
                    workstream_id,
                    "active",
                    sum(
                        value["primary_workstream"] == workstream_id
                        for value in unit_payloads
                    ),
                    sum(
                        value["primary_workstream"] == workstream_id
                        and value["risk_band"] == "blocked"
                        for value in unit_payloads
                    ),
                    sum(
                        value["primary_workstream"] == workstream_id
                        and "inventory-error" in value["warning_codes"]
                        for value in unit_payloads
                    ),
                )
                for workstream_id in sorted(
                    {value["primary_workstream"] for value in unit_payloads}
                )
            )
            context = review_context.ReviewContext(
                rendered_at="2026-07-15T04:00:00Z",
                policy_binding="generation=1;source=INITIAL/policy-1;guard=0",
                coverage=review_compiler.CoverageSummary(
                    0, 0, 0, 0, 2, 0, 2, 0, 0
                ),
                workstreams=workstreams,
                warning_codes=("m2-no-structural-authority",),
            )
            values["review_context_json"] = context.canonical_bytes()
        if "analysis_contexts_json" not in changes:
            context_ids = sorted(
                {
                    row["reference"]["context_id"]
                    for value in values["units"]
                    for row in json.loads(value.analysis_provenance_json)["items"]
                }
            )
            values["analysis_contexts_json"] = batch_service.canonical_json_bytes(
                [CONTEXTS_BY_ID[context_id] for context_id in context_ids]
            )
        return batch_service.OpenBatchRequest(**values)

    def test_open_batch_accepts_runtime_sqlite_row_factory(self):
        self.connection.row_factory = sqlite3.Row

        result = self.service.open_batch(self.request())

        self.assertEqual(result.status, "OPEN")
        self.assertEqual(result.snapshot_state, "COMMITTED")

    def test_open_batch_commits_genesis_v2_and_same_band_membership(self):
        result = self.service.open_batch(self.request())

        self.assertEqual(result.status, "OPEN")
        self.assertEqual(result.snapshot_state, "COMMITTED")
        self.assertEqual(result.snapshot_id, "snapshot-001")
        self.assertEqual(result.snapshot_version, 1)
        self.assertEqual(result.review_revision, 1)
        self.assertFalse(result.structural_approval_ready)
        self.assertEqual(result.structural_blocker, "effect-preview-not-available-m2")
        self.assertTrue(result.final_path.is_dir())
        self.assertEqual(len(result.snapshot_sha256), 64)
        self.assertEqual(len(result.package_sha256), 64)
        snapshot_payload = json.loads(
            (result.final_path / "snapshot.json").read_text(encoding="utf-8")
        )
        self.assertEqual(snapshot_payload["schema_version"], 2)
        self.assertEqual(
            snapshot_payload["analysis_contexts"],
            json.loads(self.request().analysis_contexts_json),
        )
        first_unit = snapshot_payload["units"][0]
        self.assertEqual(first_unit["unit_kind"], "file")
        self.assertEqual(first_unit["canonical_path"], "projects/alpha/a.md")
        self.assertEqual(first_unit["display_path"], "projects/alpha/a.md")
        self.assertEqual(first_unit["document_role"], "reference")
        self.assertEqual(first_unit["authority"], "reference")
        self.assertEqual(first_unit["document_lifecycle"], "current")
        self.assertEqual(first_unit["target_path"], "organized/projects/alpha/a.md")
        self.assertEqual(first_unit["context_freshness"], "fresh")
        self.assertEqual(first_unit["evidence_providers"], ["path-pattern"])
        self.assertEqual(
            first_unit["warning_codes"],
            ["m2-no-structural-authority"],
        )
        self.assertEqual(first_unit["effect_codes"], ["plan-unavailable-m2"])
        self.assertEqual(
            snapshot_payload["review_context"],
            json.loads(self.request().review_context_json),
        )
        self.assertFalse(
            (self.root.resolve() / "snapshots" / ".incomplete-snapshot-001").exists()
        )

        self.connection.row_factory = sqlite3.Row
        batch = self.connection.execute(
            "SELECT * FROM review_batches WHERE batch_id = ?",
            ("batch-001",),
        ).fetchone()
        self.assertEqual(batch["status"], "OPEN")
        self.assertEqual(batch["current_snapshot_id"], "snapshot-001")
        self.assertEqual(batch["current_snapshot_sha256"], result.snapshot_sha256)
        self.assertEqual(batch["review_revision"], 1)
        submission = self.connection.execute(
            "SELECT * FROM review_submissions WHERE submission_id = ?",
            ("submission-001",),
        ).fetchone()
        self.assertEqual(submission["state"], "COMMITTED")
        self.assertEqual(submission["final_sha256"], result.package_sha256)
        snapshot = self.connection.execute(
            "SELECT * FROM review_snapshots WHERE snapshot_id = ?",
            ("snapshot-001",),
        ).fetchone()
        self.assertEqual(snapshot["state"], "PUBLISHED")
        self.assertEqual(snapshot["version"], 1)
        self.assertEqual(snapshot["structural_approval_ready"], 0)
        self.connection.row_factory = None

    def test_mixed_risk_or_other_homogeneity_axis_is_rejected_before_write(self):
        axes = (
            {"risk_band": "medium"},
            {"scope_class": "fallback-unassigned"},
            {"sensitivity": "private"},
            {"access_domain": "owner"},
            {"primary_workstream": "beta"},
            {"related_workstreams": ("beta",)},
            {"shared": True},
            {"lifecycle_class": "draft"},
            {"override_class": "required"},
            {"scope_rule_id": "fallback-unassigned"},
            {"recommended_action": "defer"},
            {"reference_complete": False},
            {"canonical_conflict": True},
            {"relation_conflict": True},
        )
        for changes in axes:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(
                    batch_service.BatchValidationError,
                    "homogeneous",
                ):
                    self.service.open_batch(
                        self.request(
                            units=(
                                unit(
                                    "unit-a",
                                    "projects/alpha/a.md",
                                    ITEM_A,
                                ),
                                unit(
                                    "unit-b",
                                    "projects/alpha/b.md",
                                    ITEM_B,
                                    **changes,
                                ),
                            )
                        )
                    )
        count = self.connection.execute(
            "SELECT count(*) FROM review_batches"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_sensitive_or_escalated_units_require_individual_batch(self):
        individual_changes = (
            {"sensitivity": "private"},
            {"scope_class": "private-reviewable"},
            {"scope_class": "opaque-private-evidence"},
            {"reference_complete": False},
            {"override_class": "required"},
            {"risk_band": "high"},
            {"risk_band": "blocked"},
            {"canonical_conflict": True},
            {"relation_conflict": True},
        )
        for changes in individual_changes:
            with self.subTest(changes=changes):
                single = self.request(
                    units=(
                        unit(
                            "unit-a",
                            "projects/alpha/a.md",
                            ITEM_A,
                            **changes,
                        ),
                    ),
                    max_items=1,
                    max_files=1,
                    max_bytes=10,
                    max_effects=1,
                )
                self.assertEqual(len(single.units), 1)
                with self.assertRaisesRegex(
                    batch_service.BatchValidationError,
                    "individual batch",
                ):
                    self.request(
                        units=(
                            unit(
                                "unit-a",
                                "projects/alpha/a.md",
                                ITEM_A,
                                **changes,
                            ),
                            unit(
                                "unit-b",
                                "projects/alpha/b.md",
                                ITEM_B,
                                **changes,
                            ),
                        )
                    )

    def test_private_snapshot_is_metadata_only_and_never_movement_ready(self):
        private_unit = unit(
            "unit-private",
            "private/notes.md",
            ITEM_A,
            sensitivity="private",
            scope_class="private-reviewable",
        )
        self.assertEqual(private_unit.recommended_action, "defer")
        self.assertEqual(private_unit.target_path, None)

        result = self.service.open_batch(
            self.request(
                units=(private_unit,),
                max_items=1,
                max_files=1,
                max_bytes=10,
                max_effects=1,
            )
        )
        payload = json.loads(
            (result.final_path / "snapshot.json").read_text(encoding="utf-8")
        )
        row = payload["units"][0]
        self.assertEqual(row["target_path"], None)
        self.assertIn("private-metadata-only", row["warning_codes"])
        encoded = json.dumps(payload, sort_keys=True)
        for forbidden in ("body", "excerpt", "content_hash"):
            self.assertNotIn(forbidden, encoded)

    def test_overlapping_units_inside_one_request_are_rejected(self):
        with self.assertRaisesRegex(
            batch_service.BatchValidationError,
            "resource paths overlap",
        ):
            self.request(
                units=(
                    unit(
                        "unit-folder",
                        "projects/alpha",
                        ITEM_A,
                        member_paths=("projects/alpha/a.md",),
                    ),
                    unit(
                        "unit-child",
                        "projects/alpha/nested/b.md",
                        ITEM_B,
                    ),
                )
            )

    def test_open_batch_blocks_legacy_pending_source_collision(self):
        canonical = self.root.resolve()
        pending = canonical / "_registry" / "pending"
        pending.mkdir(parents=True, mode=0o700)
        source = canonical / "projects" / "alpha" / "a.md"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("body\n", encoding="utf-8")
        pending_file = pending / "place-pending.yml"
        pending_file.write_text(
            (
                'id: "place-pending"\n'
                'status: "pending"\n'
                'source: "%s"\n'
                'target: "%s"\n'
            )
            % (source, canonical / "organized/projects/alpha/a.md"),
            encoding="utf-8",
        )
        os.chmod(pending_file, 0o600)
        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=self.publisher,
            current_policy=lambda: self.policy,
            canonical_root=canonical,
        )

        with self.assertRaisesRegex(
            batch_service.BatchConflictError,
            "legacy pending collision",
        ):
            service.open_batch(self.request())

    def test_open_or_claimed_membership_blocks_exact_and_ancestor_overlap(self):
        folder = unit(
            "unit-folder",
            "projects/alpha",
            ITEM_A,
            member_item_ids=(ITEM_A, ITEM_B),
            member_paths=(
                "projects/alpha/a.md",
                "projects/alpha/nested/b.md",
            ),
            file_count=2,
            total_bytes=20,
            effect_count=2,
        )
        self.service.open_batch(
            self.request(
                units=(folder,),
                max_items=2,
                max_files=2,
                max_bytes=20,
                max_effects=2,
            )
        )
        memberships = self.connection.execute(
            "SELECT item_id, path FROM batch_memberships "
            "WHERE batch_id = ? ORDER BY item_id",
            ("batch-001",),
        ).fetchall()
        self.assertEqual(
            memberships,
            [
                (ITEM_A, "projects/alpha"),
                (ITEM_B, "projects/alpha"),
            ],
        )
        self._insert_ready_campaign("campaign-002", digest("campaign-head-002"), 3)

        cases = (
            unit("unit-exact", "projects/alpha/a.md", ITEM_A),
            unit("unit-descendant", "projects/alpha/nested/c.md", ITEM_C),
            unit("unit-ancestor", "projects", ITEM_Z),
        )
        for index, candidate in enumerate(cases, start=2):
            with self.subTest(path=candidate.path):
                request = self.request(
                    campaign_id="campaign-002",
                    expected_campaign_head_sha256=digest("campaign-head-002"),
                    expected_campaign_review_revision=3,
                    batch_id="batch-00%d" % index,
                    snapshot_id="snapshot-00%d" % index,
                    submission_id="submission-00%d" % index,
                    units=(candidate,),
                    max_items=1,
                    max_files=1,
                    max_bytes=10,
                    max_effects=1,
                )
                with self.assertRaisesRegex(
                    batch_service.BatchConflictError,
                    "overlap",
                ):
                    self.service.open_batch(request)

        self.connection.execute(
            "UPDATE review_batches SET status = 'CLAIMED' WHERE batch_id = ?",
            ("batch-001",),
        )
        self.connection.execute(
            "UPDATE batch_memberships SET status = 'CLAIMED' WHERE batch_id = ?",
            ("batch-001",),
        )
        self.connection.commit()
        with self.assertRaisesRegex(batch_service.BatchConflictError, "overlap"):
            self.service.open_batch(
                self.request(
                    campaign_id="campaign-002",
                    expected_campaign_head_sha256=digest("campaign-head-002"),
                    expected_campaign_review_revision=3,
                    batch_id="batch-010",
                    snapshot_id="snapshot-010",
                    submission_id="submission-010",
                    units=(unit("unit-claimed", "projects/alpha/x.md", ITEM_X),),
                    max_items=1,
                    max_files=1,
                    max_bytes=10,
                    max_effects=1,
                )
            )

    def test_crash_after_publish_resumes_exact_prepared_submission(self):
        observed = []

        def checkpoint(point):
            observed.append(point)
            if observed.count("published") == 1 and point == "published":
                raise RuntimeError("simulated crash")

        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            checkpoint=checkpoint,
            publisher=self.publisher,
            current_policy=lambda: self.policy,
        )
        request = self.request()
        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            service.open_batch(request)

        batch = self.connection.execute(
            "SELECT current_snapshot_id, review_revision FROM review_batches "
            "WHERE batch_id = ?",
            ("batch-001",),
        ).fetchone()
        self.assertEqual(batch, (None, 0))
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions WHERE submission_id = ?",
                ("submission-001",),
            ).fetchone()[0],
            "PREPARED",
        )

        retry = service.open_batch(request)
        self.assertEqual(retry.snapshot_state, "COMMITTED")
        self.assertEqual(retry.review_revision, 1)
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_batches"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_snapshots"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(observed.count("prepared"), 2)
        self.assertEqual(observed.count("published"), 2)

    def test_retry_with_changed_request_is_rejected_and_does_not_fork_genesis(self):
        def checkpoint(point):
            if point == "prepared":
                raise RuntimeError("stop after prepare")

        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            checkpoint=checkpoint,
            publisher=self.publisher,
            current_policy=lambda: self.policy,
        )
        with self.assertRaises(RuntimeError):
            service.open_batch(self.request())

        with self.assertRaisesRegex(batch_service.BatchConflictError, "request"):
            self.service.open_batch(
                self.request(
                    snapshot_id="snapshot-other",
                    submission_id="submission-other",
                )
            )
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM review_batches"
            ).fetchone()[0],
            1,
        )

    def test_publisher_readback_must_exactly_match_prepared_plan(self):
        inner = self.publisher

        class TamperingPublisher:
            def plan(self, publication):
                return inner.plan(publication)

            def publish(self, plan):
                result = inner.publish(plan)
                return batch_service.SnapshotPublishResult(
                    final_path=result.final_path,
                    snapshot_sha256=result.snapshot_sha256,
                    package_sha256=digest("tampered-package-readback"),
                    sealed_identity_sha256=result.sealed_identity_sha256,
                )

        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=TamperingPublisher(),
            current_policy=lambda: self.policy,
        )
        with self.assertRaisesRegex(
            batch_service.BatchPublicationError,
            "readback",
        ):
            service.open_batch(self.request())

        prepared = self.connection.execute(
            "SELECT state, final_sha256 FROM review_submissions "
            "WHERE submission_id = ?",
            ("submission-001",),
        ).fetchone()
        planned_hash = batch_service.prepare_batch_publication(
            self.root / "snapshots",
            inner,
            self.request(),
        ).plan.package_sha256
        self.assertEqual(prepared, ("PREPARED", planned_hash))

        retry = self.service.open_batch(self.request())
        self.assertEqual(retry.snapshot_state, "COMMITTED")
        self.assertEqual(retry.package_sha256, planned_hash)

    def test_publish_success_rejects_final_with_conflicting_staging(self):
        inner = self.publisher

        class ConflictingStagingPublisher:
            def plan(self, publication):
                return inner.plan(publication)

            def publish(self, plan):
                result = inner.publish(plan)
                plan.sealed_payload.staging_path.mkdir(mode=0o700)
                return result

        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
            publisher=ConflictingStagingPublisher(),
            current_policy=lambda: self.policy,
        )

        with self.assertRaisesRegex(
            batch_service.BatchPublicationError,
            "conflicting snapshot staging",
        ):
            service.open_batch(self.request())

        self.assertEqual(
            self.connection.execute(
                "SELECT current_snapshot_id, review_revision "
                "FROM review_batches WHERE batch_id = 'batch-001'"
            ).fetchone(),
            (None, 0),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM review_submissions "
                "WHERE submission_id = 'submission-001'"
            ).fetchone(),
            ("PREPARED",),
        )

    def test_writer_guards_cover_prepare_publish_commit_in_required_order(self):
        events = []

        @contextlib.contextmanager
        def placement_shared():
            events.append("placement-shared-enter")
            try:
                yield
            finally:
                events.append("placement-shared-exit")

        @contextlib.contextmanager
        def ledger_exclusive():
            events.append("ledger-exclusive-enter")
            try:
                yield
            finally:
                events.append("ledger-exclusive-exit")

        service = batch_service.BatchService(
            self.connection,
            self.root / "snapshots",
            placement_shared=placement_shared,
            ledger_exclusive=ledger_exclusive,
            publisher=self.publisher,
            current_policy=lambda: self.policy,
            checkpoint=lambda point: events.append(point),
        )

        service.open_batch(self.request())

        self.assertEqual(
            events,
            [
                "placement-shared-enter",
                "ledger-exclusive-enter",
                "prepared",
                "published",
                "committed",
                "ledger-exclusive-exit",
                "placement-shared-exit",
            ],
        )

    def test_snapshot_id_is_global_across_batches(self):
        self.service.open_batch(self.request())
        self._insert_ready_campaign("campaign-002", digest("campaign-head-002"), 3)
        with self.assertRaisesRegex(batch_service.BatchConflictError, "snapshot id"):
            self.service.open_batch(
                self.request(
                    campaign_id="campaign-002",
                    expected_campaign_head_sha256=digest("campaign-head-002"),
                    expected_campaign_review_revision=3,
                    batch_id="batch-002",
                    snapshot_id="snapshot-001",
                    submission_id="submission-002",
                    units=(unit("unit-c", "projects/beta/c.md", ITEM_C),),
                    max_items=1,
                    max_files=1,
                    max_bytes=10,
                    max_effects=1,
                )
            )

    def test_bounds_and_duplicate_member_paths_fail_before_write(self):
        with self.assertRaises(batch_service.BatchValidationError):
            self.service.open_batch(
                self.request(
                    units=(
                        unit(
                            "unit-folder",
                            "projects/alpha",
                            ITEM_A,
                            member_item_ids=(ITEM_A, ITEM_B),
                            member_paths=(
                                "projects/alpha/a.md",
                                "projects/alpha/a.md",
                            ),
                            file_count=2,
                            total_bytes=20,
                            effect_count=2,
                        ),
                    )
                )
            )
        with self.assertRaisesRegex(batch_service.BatchValidationError, "bytes bound"):
            self.service.open_batch(self.request(max_bytes=19))


if __name__ == "__main__":
    unittest.main()
