import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import (  # noqa: E402
    batch_service,
    control,
    inventory,
    ledger_schema,
    review_compiler,
    review_snapshot,
    review_state,
)
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


ITEM_A = "00000000-0000-4000-8000-00000000000a"
ITEM_B = "00000000-0000-4000-8000-00000000000b"


def make_analysis_context(*, context_suffix="a"):
    candidate_path = "projects/alpha/a.md"
    content = {
        "analyzer_version": "reference-m2-v2",
        "coverage_issues": [],
        "documents": [
            {
                "document_type": "markdown",
                "error": None,
                "exclusion_reason": None,
                "fingerprint": sha256_bytes(candidate_path.encode("utf-8")),
                "inspected": True,
                "path": candidate_path,
                "projection": None,
                "scope_class": "eligible",
            }
        ],
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
    context = dict(content)
    context.update(
        {
            "content_sha256": content_sha256,
            "context_id": "reference-context-%s" % content_sha256[:24],
            "schema_version": 1,
        }
    )
    context["context_sha256"] = sha256_bytes(canonical_json_bytes(context))
    return context


def make_unit(
    unit_id,
    path,
    item_id,
    *,
    total_bytes=10,
    context=None,
    reference_complete=True,
):
    if context is None:
        reference = {
            "complete": True,
            "input_manifest_sha256": "a" * 64,
        }
    else:
        reference = {
            "candidate_path": path,
            "complete": reference_complete,
            "context_id": context["context_id"],
            "context_sha256": context["context_sha256"],
            "input_manifest_sha256": sha256_bytes(
                canonical_json_bytes(context)
            ),
            "matches": [],
            "schema_version": 2,
        }
    return batch_service.BatchUnit(
        unit_id=unit_id,
        unit_kind="file",
        path=path,
        display_path=path,
        member_item_ids=(item_id,),
        member_paths=(path,),
        scope_class="active-workstream-content",
        sensitivity="public",
        access_domain="default",
        primary_workstream="alpha",
        related_workstreams=(),
        shared=False,
        document_role="reference",
        authority="reference",
        document_lifecycle="current",
        lifecycle_class="active",
        override_class="none",
        scope_rule_id="active-workstream-content",
        recommended_action="move",
        target_path="organized/%s" % path,
        reference_complete=reference_complete,
        risk_band="low",
        context_freshness="fresh",
        evidence_providers=("path-pattern",),
        warning_codes=(
            ("m2-no-structural-authority",)
            if reference_complete
            else ("m2-no-structural-authority", "reference-incomplete")
        ),
        effect_codes=("plan-unavailable-m2",),
        canonical_conflict=False,
        relation_conflict=False,
        target_proven=True,
        analysis_provenance_json=canonical_json_bytes(
            {
                "items": [
                    {
                        "item_id": item_id,
                        "reference": reference,
                        "risk": {"band": "low", "input_sha256": "b" * 64},
                        "target": {
                            "input_sha256": "c" * 64,
                            "status": "resolved",
                        },
                    }
                ],
                "schema_version": 1,
            }
        ),
        file_count=1,
        total_bytes=total_bytes,
        effect_count=1,
    )


def make_campaign_v2_payload(*, snapshot_id, context, unit):
    return {
        "analysis_contexts": [context],
        "campaign_id": "campaign-001",
        "classification_candidate_count": 1,
        "coverage": {},
        "decisions": [],
        "import_payload_sha256": "1" * 64,
        "kind": "campaign-genesis-review",
        "parent_snapshot_id": None,
        "review_context": {
            "coverage": {
                "folders_total": 1,
                "folders_traversed": 1,
                "folders_excluded": 0,
                "folders_error": 0,
                "files_total": 1,
                "files_inspected": 1,
                "files_metadata_only": 0,
                "files_excluded": 0,
                "files_error": 0,
            },
            "policy_binding": "generation=1;source=INITIAL/run-001;guard=0",
            "rendered_at": "2026-07-15T01:00:00Z",
            "warning_codes": ["m2-no-structural-authority"],
            "workstreams": [
                {
                    "blocked": 0,
                    "errors": 0,
                    "lifecycle": "active",
                    "review_items": 1,
                    "workstream_id": "alpha",
                }
            ],
        },
        "root_run_id": "run-001",
        "root_run_sha256": "2" * 64,
        "schema_version": 2,
        "snapshot_id": snapshot_id,
        "structural_approval_ready": False,
        "units": [unit.to_dict()],
        "version": 1,
    }


def create_v2_connection():
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("BEGIN IMMEDIATE")
    for statement in control.CONTROL_SCHEMA_STATEMENTS:
        connection.execute(statement)
    for statement in control.CONTROL_SCHEMA_INDEX_STATEMENTS:
        connection.execute(statement)
    for statement in control.CONTROL_SCHEMA_TRIGGER_STATEMENTS:
        connection.execute(statement)
    connection.execute(
        "INSERT INTO schema_migrations "
        "(version, schema_sha256, applied_by_bootstrap_id) VALUES (1, ?, ?)",
        (control.CONTROL_SCHEMA_SHA256, "bootstrap-review-state"),
    )
    connection.execute("COMMIT")
    ledger_schema.ensure_v2_schema(
        connection,
        migration_id="review-state-v2",
    )
    return connection


class ReviewStateFixture:
    def __init__(self, root, connection):
        self.root = root
        self.connection = connection
        self.units = (
            make_unit("unit-a", "projects/alpha/a.md", ITEM_A),
            make_unit("unit-b", "projects/alpha/b.md", ITEM_B),
        )

    def _document(self, *, lineage, snapshot_id, snapshot_bytes, units):
        is_batch = lineage == "BATCH"
        rows = tuple(
            review_compiler.ReviewRow(
                unit_id=unit.unit_id,
                unit_kind=unit.unit_kind,
                canonical_path=unit.path,
                display_path=unit.display_path,
                underlying_file_count=unit.file_count,
                primary_workstream=unit.primary_workstream,
                related_workstreams=unit.related_workstreams,
                shared=unit.shared,
                document_role=unit.document_role,
                authority=unit.authority,
                document_lifecycle=unit.document_lifecycle,
                scope_class=unit.scope_class,
                sensitivity=unit.sensitivity,
                access_domain=unit.access_domain,
                recommended_action=unit.recommended_action,
                target_path=unit.target_path,
                risk_band=unit.risk_band,
                context_freshness=unit.context_freshness,
                evidence_providers=unit.evidence_providers,
                warning_codes=unit.warning_codes,
                effect_codes=unit.effect_codes,
            )
            for unit in units
        )
        return review_compiler.ReviewDocument(
            review_kind="batch-preview" if is_batch else "run-overview",
            source_kind="batch-snapshot" if is_batch else "campaign-snapshot",
            source_id=snapshot_id,
            source_snapshot_sha256=sha256_bytes(snapshot_bytes),
            rendered_at="2026-07-15T01:00:00Z",
            campaign_id="campaign-001",
            batch_id="batch-001" if is_batch else None,
            snapshot_id=snapshot_id,
            snapshot_version=1,
            policy_binding="generation=1;source=INITIAL/run-001;guard=0",
            coverage=review_compiler.CoverageSummary(
                folders_total=1,
                folders_traversed=1,
                folders_excluded=0,
                folders_error=0,
                files_total=len(units),
                files_inspected=len(units),
                files_metadata_only=0,
                files_excluded=0,
                files_error=0,
            ),
            bounds=(
                review_compiler.ReviewBounds(
                    review_items=len(units),
                    underlying_files=sum(unit.file_count for unit in units),
                    total_bytes=sum(unit.total_bytes for unit in units),
                    leaf_folders=1,
                    effect_count=sum(unit.effect_count for unit in units),
                )
                if is_batch
                else None
            ),
            workstreams=(
                review_compiler.WorkstreamSummary(
                    workstream_id="alpha",
                    lifecycle="active",
                    review_items=len(units),
                    blocked=0,
                    errors=0,
                ),
            ),
            items=rows,
            warning_codes=("m2-no-structural-authority",),
        )

    def publish(self, *, lineage="CAMPAIGN", snapshot_id=None, payload=None, units=None):
        is_batch = lineage == "BATCH"
        identity = snapshot_id or ("batch-snapshot-001" if is_batch else "campaign-snapshot-001")
        selected_units = units or self.units
        if payload is None:
            payload = {
                "batch_id": "batch-001" if is_batch else None,
                "campaign_id": "campaign-001",
                "schema_version": 1,
                "snapshot_id": identity,
                "structural_approval_ready": False,
                "units": [unit.to_dict() for unit in selected_units],
            }
            if is_batch:
                payload["batch_version"] = 1
            else:
                payload.pop("batch_id")
                payload["version"] = 1
        snapshot_bytes = canonical_json_bytes(payload)
        publisher = review_snapshot.ReviewSnapshotPublisher(
            self.root / "campaigns" / "campaign-001" / "snapshots",
            renderer_id="review-state-renderer-v1",
        )
        plan = publisher.plan(
            snapshot_id=identity,
            snapshot_payload=snapshot_bytes,
            review_document=self._document(
                lineage=lineage,
                snapshot_id=identity,
                snapshot_bytes=snapshot_bytes,
                units=selected_units,
            ),
        )
        result = publisher.publish(plan)
        return result, payload

    def insert_campaign(self, result, *, status="READY", revision=1, head_id=None, head_hash=None):
        run_hash = "1" * 64
        self.connection.execute(
            "INSERT OR IGNORE INTO inventory_runs VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, 'INITIAL', ?, 0, NULL, 'OPENED')",
            (
                "run-001",
                run_hash,
                "curation-runs/run-001",
                "2" * 64,
                "3" * 64,
                1,
                "4" * 64,
                "5" * 64,
                "8" * 64,
                "run-001",
            ),
        )
        self.connection.execute(
            "INSERT INTO campaigns VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)",
            (
                "campaign-001",
                "run-001",
                run_hash,
                status,
                head_id if head_id is not None else result.snapshot_id,
                head_hash if head_hash is not None else result.snapshot_sha256,
                revision,
                "operator",
                canonical_json_bytes({"campaign_id": "campaign-001"}),
                "curation/campaigns/campaign-001/campaign.json",
                "6" * 64,
            ),
        )

    def insert_snapshot(self, result, *, lineage="CAMPAIGN", path=None, payload_hash=None, package_hash=None, state="PUBLISHED"):
        is_batch = lineage == "BATCH"
        self.connection.execute(
            "INSERT INTO review_snapshots VALUES (?, ?, ?, ?, 1, NULL, NULL, ?, ?, ?, ?, 0)",
            (
                result.snapshot_id,
                lineage,
                "campaign-001",
                "batch-001" if is_batch else None,
                payload_hash if payload_hash is not None else result.snapshot_sha256,
                path if path is not None else str(result.final_path),
                package_hash if package_hash is not None else result.package_sha256,
                state,
            ),
        )

    def insert_batch(self, result, *, status="OPEN", revision=1, generation=0):
        self.connection.execute(
            "INSERT INTO review_batches VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "batch-001",
                "campaign-001",
                "7" * 64,
                status,
                result.snapshot_id,
                result.snapshot_sha256,
                revision,
                generation,
            ),
        )


class ReviewStateTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.connection = create_v2_connection()
        self.fixture = ReviewStateFixture(self.root, self.connection)

    def tearDown(self):
        self.connection.close()
        self.temporary.cleanup()

    def test_reader_and_campaign_loader_return_typed_exact_requested_subset(self):
        result, _payload = self.fixture.publish()
        sealed = review_state.read_sealed_review_snapshot(
            result.final_path,
            expected_snapshot_id=result.snapshot_id,
            expected_snapshot_sha256=result.snapshot_sha256,
            expected_package_sha256=result.package_sha256,
        )
        self.assertIsInstance(sealed, review_state.SealedReviewSnapshot)
        self.assertEqual(sealed.schema_version, 1)
        self.assertEqual(sealed.analysis_contexts_json, b"[]\n")
        self.assertEqual(tuple(unit.unit_id for unit in sealed.units), ("unit-a", "unit-b"))
        self.assertEqual(sealed.sealed_identity_sha256, result.sealed_identity_sha256)

        self.fixture.insert_campaign(result)
        self.fixture.insert_snapshot(
            result,
            path=result.final_path.relative_to(self.root).as_posix(),
        )
        head = review_state.CampaignHeadLoader(self.connection, self.root).load(
            "campaign-001",
            ("unit-b", "unit-a"),
        )
        self.assertEqual(head.review_revision, 1)
        self.assertEqual(tuple(unit.unit_id for unit in head.units), ("unit-b", "unit-a"))
        self.assertEqual(tuple(unit.unit_id for unit in head.snapshot.units), ("unit-a", "unit-b"))

    def test_reader_accepts_and_exposes_exact_snapshot_v2_context_bundle(self):
        context = make_analysis_context()
        units = (
            make_unit(
                "unit-a",
                "projects/alpha/a.md",
                ITEM_A,
                context=context,
            ),
        )
        payload = make_campaign_v2_payload(
            snapshot_id="campaign-snapshot-v2",
            context=context,
            unit=units[0],
        )
        result, _payload = self.fixture.publish(
            snapshot_id="campaign-snapshot-v2",
            payload=payload,
            units=units,
        )

        sealed = review_state.read_sealed_review_snapshot(
            result.final_path,
            expected_snapshot_id=result.snapshot_id,
            expected_snapshot_sha256=result.snapshot_sha256,
            expected_package_sha256=result.package_sha256,
        )

        self.assertEqual(sealed.schema_version, 2)
        self.assertEqual(
            sealed.analysis_contexts_json,
            canonical_json_bytes([context]),
        )
        self.assertEqual(sealed.units, units)

    def test_campaign_loader_rejects_resealed_v2_workstream_projection_tamper(self):
        context = make_analysis_context()
        unit = make_unit(
            "unit-a",
            "projects/alpha/a.md",
            ITEM_A,
            context=context,
        )
        payload = make_campaign_v2_payload(
            snapshot_id="campaign-snapshot-v2-tampered-workstream",
            context=context,
            unit=unit,
        )
        projection = payload["review_context"]["workstreams"][0]
        projection["lifecycle"] = "paused"
        projection["review_items"] = 0
        result, _payload = self.fixture.publish(
            snapshot_id=payload["snapshot_id"],
            payload=payload,
            units=(unit,),
        )
        self.fixture.insert_campaign(result)
        self.fixture.insert_snapshot(result)

        with self.assertRaisesRegex(
            review_state.ReviewStateError,
            "workstream|context",
        ):
            review_state.CampaignHeadLoader(
                self.connection,
                self.root,
            ).load("campaign-001", ("unit-a",))

    def test_reader_rejects_snapshot_v2_context_binding_tamper(self):
        context = make_analysis_context()
        unit = make_unit(
            "unit-a",
            "projects/alpha/a.md",
            ITEM_A,
            context=context,
        )

        def base_payload(snapshot_id):
            return {
                "analysis_contexts": [context],
                "campaign_id": "campaign-001",
                "schema_version": 2,
                "snapshot_id": snapshot_id,
                "structural_approval_ready": False,
                "units": [unit.to_dict()],
                "version": 1,
            }

        def mutate_reference(payload, field, value):
            payload["units"][0]["analysis_provenance"]["items"][0][
                "reference"
            ][field] = value

        cases = []

        unrelated = base_payload("campaign-snapshot-v2-unrelated")
        unrelated["analysis_contexts"].append(
            make_analysis_context(context_suffix="b")
        )
        unrelated["analysis_contexts"].sort(
            key=lambda value: value["context_id"]
        )
        cases.append(("unrelated context", unrelated, unit))

        missing = base_payload("campaign-snapshot-v2-missing")
        missing["analysis_contexts"] = [
            make_analysis_context(context_suffix="b")
        ]
        cases.append(("missing context", missing, unit))

        wrong_context_hash = base_payload(
            "campaign-snapshot-v2-wrong-context-hash"
        )
        mutate_reference(
            wrong_context_hash,
            "context_sha256",
            "f" * 64,
        )
        cases.append(("context hash", wrong_context_hash, unit))

        wrong_path = base_payload("campaign-snapshot-v2-wrong-path")
        mutate_reference(
            wrong_path,
            "candidate_path",
            "projects/alpha/other.md",
        )
        cases.append(("candidate path", wrong_path, unit))

        wrong_complete = base_payload("campaign-snapshot-v2-wrong-complete")
        incomplete_unit = make_unit(
            "unit-a",
            "projects/alpha/a.md",
            ITEM_A,
            context=context,
            reference_complete=False,
        )
        wrong_complete["units"] = [incomplete_unit.to_dict()]
        cases.append(("complete", wrong_complete, incomplete_unit))

        wrong_matches = base_payload("campaign-snapshot-v2-wrong-matches")
        mutate_reference(
            wrong_matches,
            "matches",
            [
                {
                    "direction": "outbound",
                    "reference_kind": "markdown-link",
                    "source_path": "projects/alpha/a.md",
                    "target_path": "projects/alpha/b.md",
                }
            ],
        )
        cases.append(("matches", wrong_matches, unit))

        for label, payload, rendered_unit in cases:
            with self.subTest(label=label):
                result, _payload = self.fixture.publish(
                    snapshot_id=payload["snapshot_id"],
                    payload=payload,
                    units=(rendered_unit,),
                )
                with self.assertRaisesRegex(
                    review_state.ReviewStateError,
                    "analysis context binding",
                ):
                    review_state.read_sealed_review_snapshot(
                        result.final_path,
                        expected_snapshot_id=result.snapshot_id,
                        expected_snapshot_sha256=result.snapshot_sha256,
                        expected_package_sha256=result.package_sha256,
                    )

    def test_batch_loader_binds_open_head_and_is_read_only(self):
        result, _payload = self.fixture.publish(lineage="BATCH")
        self.fixture.insert_campaign(result)
        self.fixture.insert_batch(result, generation=3)
        self.fixture.insert_snapshot(result, lineage="BATCH")
        traced = []
        self.connection.set_trace_callback(traced.append)
        try:
            head = review_state.BatchHeadLoader(self.connection, self.root).load(
                "batch-001",
                ("unit-a",),
            )
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(head.execution_generation, 3)
        self.assertEqual(tuple(unit.unit_id for unit in head.units), ("unit-a",))
        mutating = ("INSERT ", "UPDATE ", "DELETE ", "CREATE ", "DROP ", "ALTER ")
        self.assertFalse(any(statement.lstrip().upper().startswith(mutating) for statement in traced))

    def test_snapshot_loader_accepts_published_historical_nonhead_by_id(self):
        result, _payload = self.fixture.publish(snapshot_id="historical-snapshot-001")
        self.fixture.insert_campaign(
            result,
            revision=2,
            head_id="newer-snapshot-002",
            head_hash="9" * 64,
        )
        self.fixture.insert_snapshot(result)
        traced = []
        self.connection.set_trace_callback(traced.append)
        try:
            sealed = review_state.ReviewSnapshotLoader(
                self.connection,
                self.root,
            ).load(result.snapshot_id)
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(sealed.snapshot_id, result.snapshot_id)
        self.assertEqual(sealed.snapshot_sha256, result.snapshot_sha256)
        self.assertEqual(tuple(unit.unit_id for unit in sealed.units), ("unit-a", "unit-b"))
        mutating = ("INSERT ", "UPDATE ", "DELETE ", "CREATE ", "DROP ", "ALTER ")
        self.assertFalse(any(statement.lstrip().upper().startswith(mutating) for statement in traced))

        self.connection.execute(
            "UPDATE review_snapshots SET state = 'PREPARED' WHERE snapshot_id = ?",
            (result.snapshot_id,),
        )
        with self.assertRaises(review_state.ReviewStateError):
            review_state.ReviewSnapshotLoader(self.connection, self.root).load(
                result.snapshot_id
            )

    def test_snapshot_loader_rejects_ledger_path_outside_canonical_campaign_namespace(self):
        result, _payload = self.fixture.publish(snapshot_id="wrong-namespace")
        wrong_parent = self.root / "orphaned-snapshots"
        wrong_parent.mkdir(mode=0o700)
        wrong_path = wrong_parent / result.snapshot_id
        result.final_path.rename(wrong_path)
        self.fixture.insert_campaign(result)
        self.fixture.insert_snapshot(result, path=str(wrong_path))

        with self.assertRaisesRegex(
            review_state.ReviewStateError,
            "canonical campaign namespace",
        ):
            review_state.ReviewSnapshotLoader(
                self.connection,
                self.root,
            ).load(result.snapshot_id)

    def test_reader_rejects_tamper_links_modes_and_member_set_drift(self):
        mutations = (
            ("missing", lambda path: (path / "review" / "review.html").unlink()),
            ("extra", lambda path: (path / "extra").write_bytes(b"x")),
            ("mode", lambda path: os.chmod(path / "snapshot.json", 0o640)),
            (
                "symlink",
                lambda path: (
                    (path / "review" / "review.md").unlink(),
                    (path / "review" / "review.md").symlink_to(path / "snapshot.json"),
                ),
            ),
            (
                "hardlink",
                lambda path: os.link(
                    path / "snapshot.json",
                    path.parent / ("outside-hardlink-%s" % path.name),
                ),
            ),
            (
                "tamper",
                lambda path: (path / "snapshot.json").write_bytes(
                    (path / "snapshot.json").read_bytes() + b" "
                ),
            ),
        )
        for index, (label, mutate) in enumerate(mutations):
            with self.subTest(label=label):
                snapshot_id = "drift-%d" % index
                result, _payload = self.fixture.publish(snapshot_id=snapshot_id)
                mutate(result.final_path)
                with self.assertRaises(review_state.ReviewStateError):
                    review_state.read_sealed_review_snapshot(
                        result.final_path,
                        expected_snapshot_id=result.snapshot_id,
                        expected_snapshot_sha256=result.snapshot_sha256,
                        expected_package_sha256=result.package_sha256,
                    )

    def test_reader_rejects_manifest_hash_drift_and_read_race(self):
        result, _payload = self.fixture.publish(snapshot_id="hash-drift")
        for snapshot_hash, package_hash in (
            ("f" * 64, result.package_sha256),
            (result.snapshot_sha256, "e" * 64),
        ):
            with self.subTest(snapshot_hash=snapshot_hash, package_hash=package_hash):
                with self.assertRaises(review_state.ReviewStateError):
                    review_state.read_sealed_review_snapshot(
                        result.final_path,
                        expected_snapshot_id=result.snapshot_id,
                        expected_snapshot_sha256=snapshot_hash,
                        expected_package_sha256=package_hash,
                    )

        raced = {"done": False}

        def race(path, _descriptor, _directory_fd):
            if path.name == "snapshot.json" and not raced["done"]:
                raced["done"] = True
                path.write_bytes(path.read_bytes() + b" ")

        with mock.patch.object(review_state, "_after_file_read", side_effect=race):
            with self.assertRaisesRegex(review_state.ReviewStateError, "changed while read"):
                review_state.read_sealed_review_snapshot(
                    result.final_path,
                    expected_snapshot_id=result.snapshot_id,
                    expected_snapshot_sha256=result.snapshot_sha256,
                    expected_package_sha256=result.package_sha256,
                )

        directory_result, _payload = self.fixture.publish(snapshot_id="directory-race")
        changed = {"done": False}

        def directory_race(path, _descriptor, _directory_fd):
            if path.name == "snapshot.json" and not changed["done"]:
                changed["done"] = True
                os.chmod(path.parent, 0o755)

        with mock.patch.object(
            review_state,
            "_after_file_read",
            side_effect=directory_race,
        ):
            with self.assertRaises(review_state.ReviewStateError):
                review_state.read_sealed_review_snapshot(
                    directory_result.final_path,
                    expected_snapshot_id=directory_result.snapshot_id,
                    expected_snapshot_sha256=directory_result.snapshot_sha256,
                    expected_package_sha256=directory_result.package_sha256,
                )

    def test_duplicate_snapshot_units_and_bounds_fail_closed(self):
        duplicate = [self.fixture.units[0].to_dict(), self.fixture.units[0].to_dict()]
        payload = {
            "campaign_id": "campaign-001",
            "schema_version": 1,
            "snapshot_id": "duplicate-units",
            "structural_approval_ready": False,
            "units": duplicate,
            "version": 1,
        }
        result, _payload = self.fixture.publish(
            snapshot_id="duplicate-units",
            payload=payload,
            units=(self.fixture.units[0],),
        )
        with self.assertRaises(review_state.ReviewStateError):
            review_state.read_sealed_review_snapshot(
                result.final_path,
                expected_snapshot_id=result.snapshot_id,
                expected_snapshot_sha256=result.snapshot_sha256,
                expected_package_sha256=result.package_sha256,
            )

        mixed_duplicate = [
            self.fixture.units[0].to_dict(),
            self.fixture.units[1].to_dict(),
        ]
        mixed_duplicate[1]["member_item_ids"] = [ITEM_A]
        mixed_duplicate[1]["analysis_provenance"]["items"][0]["item_id"] = ITEM_A
        mixed_payload = {
            "campaign_id": "campaign-001",
            "schema_version": 1,
            "snapshot_id": "mixed-duplicate",
            "structural_approval_ready": False,
            "units": mixed_duplicate,
            "version": 1,
        }
        mixed_result, _payload = self.fixture.publish(
            snapshot_id="mixed-duplicate",
            payload=mixed_payload,
        )
        with self.assertRaisesRegex(review_state.ReviewStateError, "item ids overlap"):
            review_state.read_sealed_review_snapshot(
                mixed_result.final_path,
                expected_snapshot_id=mixed_result.snapshot_id,
                expected_snapshot_sha256=mixed_result.snapshot_sha256,
                expected_package_sha256=mixed_result.package_sha256,
            )

        bounded_result, _payload = self.fixture.publish(snapshot_id="bounded")
        with self.assertRaisesRegex(review_state.ReviewStateError, "unit bound"):
            review_state.read_sealed_review_snapshot(
                bounded_result.final_path,
                expected_snapshot_id=bounded_result.snapshot_id,
                expected_snapshot_sha256=bounded_result.snapshot_sha256,
                expected_package_sha256=bounded_result.package_sha256,
                bounds=review_state.ReviewStateBounds(max_units=1),
            )

    def test_loaders_reject_unknown_duplicate_and_stale_heads(self):
        result, _payload = self.fixture.publish()
        self.fixture.insert_campaign(result)
        self.fixture.insert_snapshot(result)
        loader = review_state.CampaignHeadLoader(self.connection, self.root)
        for unit_ids in (("unknown",), ("unit-a", "unit-a")):
            with self.subTest(unit_ids=unit_ids):
                with self.assertRaises(review_state.ReviewStateError):
                    loader.load("campaign-001", unit_ids)

        self.connection.execute(
            "UPDATE campaigns SET current_snapshot_sha256 = ? WHERE campaign_id = ?",
            ("e" * 64, "campaign-001"),
        )
        with self.assertRaisesRegex(review_state.ReviewStateError, "head"):
            loader.load("campaign-001", ("unit-a",))

    def test_package_directory_and_files_are_exact_owner_only_objects(self):
        result, _payload = self.fixture.publish(snapshot_id="mode-proof")
        sealed = review_state.read_sealed_review_snapshot(
            result.final_path,
            expected_snapshot_id=result.snapshot_id,
            expected_snapshot_sha256=result.snapshot_sha256,
            expected_package_sha256=result.package_sha256,
        )
        self.assertEqual(stat.S_IMODE(sealed.final_path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((sealed.final_path / "snapshot.json").stat().st_mode), 0o600)

    def test_loader_rejects_nonexact_v2_schema_before_head_lookup(self):
        self.connection.execute("CREATE TABLE rogue_review_state (value TEXT)")
        loader = review_state.CampaignHeadLoader(self.connection, self.root)
        with self.assertRaisesRegex(review_state.ReviewStateError, "exact version-2"):
            loader.load("campaign-001", ("unit-a",))
        self.assertFalse(self.connection.in_transaction)


if __name__ == "__main__":
    unittest.main()
