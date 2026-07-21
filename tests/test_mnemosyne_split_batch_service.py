import contextlib
import hashlib
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

from mnemosyne_core import (  # noqa: E402
    admission,
    batch_event_contract,
    batch_event_service,
    batch_service,
    curation_audit,
    m3_schema,
    split_batch_service,
)
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402

if __package__:
    from .test_mnemosyne_batch_service import ITEM_A, ITEM_B, ITEM_C, policy_for_campaign, unit  # noqa: E402
    from .test_mnemosyne_m3_schema import create_v2_connection  # noqa: E402
else:
    from test_mnemosyne_batch_service import ITEM_A, ITEM_B, ITEM_C, policy_for_campaign, unit  # noqa: E402
    from test_mnemosyne_m3_schema import create_v2_connection  # noqa: E402

def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SplitBatchSelectionTest(unittest.TestCase):
    def test_rejects_empty_selection(self):
        units = (unit("unit-a", "projects/a.md", ITEM_A), unit("unit-b", "projects/b.md", ITEM_B))
        with self.assertRaisesRegex(split_batch_service.SplitBatchValidationError, "empty"):
            split_batch_service.validate_split_selection(units, ())

    def test_rejects_selecting_every_unit(self):
        units = (unit("unit-a", "projects/a.md", ITEM_A), unit("unit-b", "projects/b.md", ITEM_B))
        with self.assertRaisesRegex(split_batch_service.SplitBatchValidationError, "every"):
            split_batch_service.validate_split_selection(units, ("unit-a", "unit-b"))

    def test_rejects_unknown_unit_id(self):
        units = (unit("unit-a", "projects/a.md", ITEM_A),)
        with self.assertRaisesRegex(split_batch_service.SplitBatchValidationError, "unknown"):
            split_batch_service.validate_split_selection(units, ("unit-missing",))

    def test_rejects_non_resource_disjoint_selected_units(self):
        units = (
            unit("unit-a", "projects/a/x.md", ITEM_A),
            unit(
                "unit-b",
                "projects/a",
                ITEM_B,
                member_item_ids=(ITEM_B,),
                member_paths=("projects/a/y.md",),
                unit_kind="file",
            ),
            unit("unit-c", "projects/c.md", ITEM_C),
        )
        with self.assertRaisesRegex(
            split_batch_service.SplitBatchValidationError,
            "resource-disjoint",
        ):
            split_batch_service.validate_split_selection(
                units,
                ("unit-a", "unit-b"),
            )

    def test_rejects_partial_folder_without_explode(self):
        folder = unit(
            "folder-1",
            "projects/alpha",
            ITEM_A,
            member_item_ids=(ITEM_A, ITEM_B),
            member_paths=("projects/alpha/a.md", "projects/alpha/b.md"),
            unit_kind="folder",
            file_count=2,
            total_bytes=20,
            effect_count=2,
        )
        child = unit("file-a", "projects/alpha/a.md", ITEM_A)
        units = (folder, child)
        with self.assertRaisesRegex(
            split_batch_service.SplitBatchValidationError,
            "explode",
        ):
            split_batch_service.validate_split_selection(units, ("file-a",))

    def test_accepts_complete_folder_selection(self):
        folder = unit(
            "folder-1",
            "projects/alpha",
            ITEM_A,
            member_item_ids=(ITEM_A, ITEM_B),
            member_paths=("projects/alpha/a.md", "projects/alpha/b.md"),
            unit_kind="folder",
            file_count=2,
            total_bytes=20,
            effect_count=2,
        )
        other = unit("unit-b", "projects/beta/b.md", ITEM_C)
        selection = split_batch_service.validate_split_selection(
            (folder, other),
            ("folder-1",),
        )
        self.assertEqual(selection.selected_unit_ids, ("folder-1",))
        self.assertEqual(selection.remainder_unit_ids, ("unit-b",))

    def test_accepts_disjoint_file_units_after_explode_shape(self):
        file_a = unit("file-a", "projects/alpha/a.md", ITEM_A)
        file_b = unit("file-b", "projects/alpha/b.md", ITEM_B)
        other = unit("unit-b", "projects/beta/b.md", ITEM_C)
        selection = split_batch_service.validate_split_selection(
            (file_a, file_b, other),
            ("file-a",),
        )
        self.assertEqual(selection.selected_unit_ids, ("file-a",))
        self.assertEqual(len(selection.selected_units), 1)


class _CheckpointSplitService(split_batch_service.SplitBatchService):
    def __init__(self, connection, event_root, *, checkpoint):
        super().__init__(
            connection,
            event_root,
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
        )
        self._checkpoint = checkpoint

    def split(self, request, bundle):
        prepared = self.prepare(request)
        return self._under_guards(
            prepared,
            bundle,
            resumed=False,
            checkpoint=self._checkpoint,
        )


class SplitBatchPreparedRowTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.connection = create_v2_connection()
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        m3_schema.ensure_v3_schema(self.connection)
        self._seed_batch()

    def _seed_batch(self):
        self.connection.execute(
            "INSERT INTO inventory_runs ("
            "run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
            "policy_generation, policy_full_hash, policy_writer_control_hash, "
            "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
            "policy_guard_epoch, parent_run_id, state"
            ") VALUES ('run-root', ?, 'runs/root', ?, ?, 1, ?, ?, ?, 'INITIAL', "
            "'policy-run', 0, NULL, 'OPENED')",
            tuple(digest("seed-%s" % index) for index in range(1, 7)),
        )
        self.connection.execute(
            "INSERT INTO campaigns ("
            "campaign_id, root_run_id, root_run_sha256, status, "
            "current_snapshot_id, current_snapshot_sha256, review_revision, "
            "active_integration_id, opened_by, payload_json, campaign_path, "
            "campaign_sha256"
            ") VALUES ('campaign-1', 'run-root', ?, 'READY', 'campaign-snapshot', ?, "
            "1, NULL, 'operator', ?, 'campaigns/campaign-1/campaign.json', ?)",
            (digest("campaign-head"), digest("campaign-snap"), b"{}\n", digest("campaign-payload")),
        )
        self.connection.execute(
            "INSERT INTO review_batches VALUES ("
            "'batch-1', 'campaign-1', ?, 'OPEN', 'snapshot-1', ?, 1, 0)",
            (digest("batch-request"), digest("snapshot-hash")),
        )
        for item_id, membership_id, unit_id, path in (
            (ITEM_A, "membership-a", "unit-a", "projects/a.md"),
            (ITEM_B, "membership-b", "unit-b", "projects/b.md"),
        ):
            self.connection.execute(
                "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
                (item_id,),
            )
            self.connection.execute(
                "INSERT INTO batch_memberships VALUES (?, 'batch-1', ?, ?, ?, 'OPEN')",
                (membership_id, unit_id, item_id, path),
            )

    @staticmethod
    def _default_units():
        return (
            unit("unit-a", "projects/a.md", ITEM_A),
            unit("unit-b", "projects/b.md", ITEM_B),
        )

    def _bundle(
        self,
        *,
        units=None,
        selected=("unit-a",),
        child_batch_id="batch-child-1",
    ):
        units = self._default_units() if units is None else tuple(units)
        selected_ids = frozenset(selected)
        parent_payload = canonical_json_bytes(
            {
                "analysis_contexts": [],
                "batch_id": "batch-1",
                "batch_version": 2,
                "campaign_id": "campaign-1",
                "parent_snapshot_id": "snapshot-1",
                "parent_snapshot_sha256": digest("snapshot-hash"),
                "request_hash": digest("batch-request"),
                "schema_version": 2,
                "snapshot_id": "parent-snapshot-2",
                "units": [
                    value.to_dict()
                    for value in units
                    if value.unit_id not in selected_ids
                ],
            }
        )
        child_payload = canonical_json_bytes(
            {
                "analysis_contexts": [],
                "batch_id": child_batch_id,
                "batch_version": 1,
                "campaign_id": "campaign-1",
                "parent_snapshot_id": "snapshot-1",
                "parent_snapshot_sha256": digest("snapshot-hash"),
                "request_hash": batch_event_contract.split_child_request_hash(
                    "batch-1",
                    child_batch_id,
                ),
                "schema_version": 2,
                "snapshot_id": "child-snapshot-1",
                "units": [
                    value.to_dict()
                    for value in units
                    if value.unit_id in selected_ids
                ],
            }
        )
        return split_batch_service.SplitSnapshotBundle(
            parent_snapshot_final_path=(
                self.root
                / "campaigns/campaign-1/snapshots/parent-snapshot-2/snapshot.json"
            ),
            parent_snapshot_payload_json=parent_payload,
            child_snapshot_final_path=(
                self.root
                / "campaigns/campaign-1/snapshots/child-snapshot-1/snapshot.json"
            ),
            child_snapshot_payload_json=child_payload,
        ), sha256_bytes(parent_payload), sha256_bytes(child_payload)

    def _request(self, selected=("unit-a",)):
        units = self._default_units()
        _bundle, parent_hash, child_hash = self._bundle(
            units=units,
            selected=selected,
        )
        return split_batch_service.SplitReviewBatchRequest(
            event_id="split-event-1",
            batch_id="batch-1",
            expected_snapshot_id="snapshot-1",
            expected_snapshot_sha256=digest("snapshot-hash"),
            expected_review_revision=1,
            expected_execution_generation=0,
            selected_unit_ids=selected,
            child_batch_id="batch-child-1",
            child_snapshot_id="child-snapshot-1",
            child_snapshot_sha256=child_hash,
            child_submission_id="child-submission-1",
            parent_next_snapshot_id="parent-snapshot-2",
            parent_next_snapshot_sha256=parent_hash,
            parent_submission_id="parent-submission-1",
            policy=policy_for_campaign("campaign-1"),
            actor="reviewer",
            units=units,
        )

    def service(self, checkpoint=None):
        event_root = self.root / "campaigns/campaign-1/batch-events"
        return split_batch_service.SplitBatchService(
            self.connection,
            event_root,
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
        ) if checkpoint is None else _CheckpointSplitService(
            self.connection,
            event_root,
            checkpoint=checkpoint,
        )

    def _next_split(
        self,
        *,
        batch_id,
        batch_request_hash,
        source_snapshot_id,
        source_snapshot_sha256,
        source_revision,
        units,
        selected,
        event_id,
        child_batch_id,
        child_snapshot_id,
        parent_next_snapshot_id,
    ):
        selected_ids = frozenset(selected)
        parent_payload = canonical_json_bytes(
            {
                "analysis_contexts": [],
                "batch_id": batch_id,
                "batch_version": source_revision + 1,
                "campaign_id": "campaign-1",
                "parent_snapshot_id": source_snapshot_id,
                "parent_snapshot_sha256": source_snapshot_sha256,
                "request_hash": batch_request_hash,
                "schema_version": 2,
                "snapshot_id": parent_next_snapshot_id,
                "units": [
                    value.to_dict()
                    for value in units
                    if value.unit_id not in selected_ids
                ],
            }
        )
        child_payload = canonical_json_bytes(
            {
                "analysis_contexts": [],
                "batch_id": child_batch_id,
                "batch_version": 1,
                "campaign_id": "campaign-1",
                "parent_snapshot_id": source_snapshot_id,
                "parent_snapshot_sha256": source_snapshot_sha256,
                "request_hash": batch_event_contract.split_child_request_hash(
                    batch_id,
                    child_batch_id,
                ),
                "schema_version": 2,
                "snapshot_id": child_snapshot_id,
                "units": [
                    value.to_dict()
                    for value in units
                    if value.unit_id in selected_ids
                ],
            }
        )
        parent_hash = sha256_bytes(parent_payload)
        child_hash = sha256_bytes(child_payload)
        bundle = split_batch_service.SplitSnapshotBundle(
            parent_snapshot_final_path=(
                self.root
                / "campaigns/campaign-1/snapshots"
                / parent_next_snapshot_id
                / "snapshot.json"
            ),
            parent_snapshot_payload_json=parent_payload,
            child_snapshot_final_path=(
                self.root
                / "campaigns/campaign-1/snapshots"
                / child_snapshot_id
                / "snapshot.json"
            ),
            child_snapshot_payload_json=child_payload,
        )
        request = split_batch_service.SplitReviewBatchRequest(
            event_id=event_id,
            batch_id=batch_id,
            expected_snapshot_id=source_snapshot_id,
            expected_snapshot_sha256=source_snapshot_sha256,
            expected_review_revision=source_revision,
            expected_execution_generation=0,
            selected_unit_ids=selected,
            child_batch_id=child_batch_id,
            child_snapshot_id=child_snapshot_id,
            child_snapshot_sha256=child_hash,
            child_submission_id="%s-child" % event_id,
            parent_next_snapshot_id=parent_next_snapshot_id,
            parent_next_snapshot_sha256=parent_hash,
            parent_submission_id="%s-parent" % event_id,
            policy=policy_for_campaign("campaign-1"),
            actor="reviewer",
            units=tuple(units),
        )
        return request, bundle, parent_hash, child_hash

    def _abandon(
        self,
        *,
        event_id,
        batch_id,
        snapshot_id,
        snapshot_sha256,
        review_revision,
    ):
        service = batch_event_service.BatchEventService(
            self.connection,
            self.root / "campaigns/campaign-1/batch-events",
            placement_shared=contextlib.nullcontext,
            ledger_exclusive=contextlib.nullcontext,
        )
        return service.abandon(
            batch_event_service.BatchTerminalRequest(
                event_id=event_id,
                batch_id=batch_id,
                event_kind="abandon",
                expected_snapshot_id=snapshot_id,
                expected_snapshot_sha256=snapshot_sha256,
                expected_review_revision=review_revision,
                expected_execution_generation=0,
                actor="reviewer",
            )
        )

    def audit_batch_findings(self):
        return curation_audit.CurationIntegrityQuery(
            self.connection,
            self.root,
        )._batch_event_artifact_findings()

    def test_prepare_inserts_split_prepared_batch_event_row(self):
        prepared = self.service().prepare(self._request())
        self.assertEqual(prepared.request.event_id, "split-event-1")
        self.assertEqual(prepared.payload["event_kind"], "SPLIT")
        self.assertEqual(prepared.payload["schema_version"], 1)
        self.assertIn("selected_memberships", prepared.payload)
        self.assertIn("remainder_memberships", prepared.payload)

        resumed = self.service().prepare_locked(prepared)
        self.assertFalse(resumed)

        _bundle, _parent_hash, child_hash = self._bundle()
        row = self.connection.execute(
            "SELECT event_kind, expected_batch_status, terminal_batch_status, "
            "child_batch_id, child_snapshot_id, child_snapshot_sha256, state "
            "FROM batch_events WHERE batch_event_id = 'split-event-1'"
        ).fetchone()
        self.assertEqual(
            tuple(row),
            (
                "SPLIT",
                "OPEN",
                None,
                "batch-child-1",
                "child-snapshot-1",
                child_hash,
                "PREPARED",
            ),
        )
        stored_payload = json.loads(
            self.connection.execute(
                "SELECT payload_json FROM batch_events WHERE batch_event_id = 'split-event-1'"
            ).fetchone()[0].decode("utf-8")
        )
        self.assertEqual(stored_payload["selected_unit_ids"], ["unit-a"])
        stored_sha256 = self.connection.execute(
            "SELECT payload_sha256 FROM batch_events WHERE batch_event_id = 'split-event-1'"
        ).fetchone()[0]
        self.assertEqual(sha256_bytes(prepared.payload_json), stored_sha256)

    def test_request_rejects_parent_batch_as_child_before_prepare(self):
        with self.assertRaisesRegex(
            split_batch_service.SplitBatchValidationError,
            "child batch",
        ):
            replace(self._request(), child_batch_id="batch-1")

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_request_rejects_snapshot_identity_collisions_before_prepare(self):
        request = self._request()
        for changes in (
            {"child_snapshot_id": request.parent_next_snapshot_id},
            {"child_snapshot_id": request.expected_snapshot_id},
            {"parent_next_snapshot_id": request.expected_snapshot_id},
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                split_batch_service.SplitBatchValidationError,
                "snapshot",
            ):
                replace(request, **changes)

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_request_rejects_oversized_actor_before_prepare(self):
        with self.assertRaisesRegex(
            split_batch_service.SplitBatchValidationError,
            "actor",
        ):
            replace(self._request(), actor="a" * (16 * 1024 + 1))

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_prepare_rejects_noncanonical_membership_path_before_row(self):
        self.connection.execute(
            "UPDATE batch_memberships SET path = '../outside' "
            "WHERE membership_id = 'membership-a'"
        )

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchConflict,
            "request units do not match current batch membership",
        ):
            self.service().split(self._request(), self._bundle()[0])

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_split_rejects_unrelated_existing_child_batch(self):
        request_hash = digest("foreign-child-request")
        snapshot_hash = digest("foreign-child-snapshot")
        self.connection.execute(
            "INSERT INTO inventory_runs ("
            "run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
            "policy_generation, policy_full_hash, policy_writer_control_hash, "
            "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
            "policy_guard_epoch, parent_run_id, state"
            ") VALUES ('run-foreign', ?, 'runs/foreign', ?, ?, 1, ?, ?, ?, "
            "'INITIAL', 'policy-run-foreign', 0, NULL, 'OPENED')",
            tuple(digest("foreign-seed-%s" % index) for index in range(1, 7)),
        )
        self.connection.execute(
            "INSERT INTO campaigns ("
            "campaign_id, root_run_id, root_run_sha256, status, "
            "current_snapshot_id, current_snapshot_sha256, review_revision, "
            "active_integration_id, opened_by, payload_json, campaign_path, "
            "campaign_sha256"
            ") VALUES ('campaign-2', 'run-foreign', ?, 'READY', "
            "'campaign-2-snapshot', ?, 1, NULL, 'operator', ?, "
            "'campaigns/campaign-2/campaign.json', ?)",
            (
                digest("campaign-2-root"),
                digest("campaign-2-snapshot"),
                b"{}\n",
                digest("campaign-2-payload"),
            ),
        )
        self.connection.execute(
            "INSERT INTO review_batches VALUES ("
            "'batch-existing', 'campaign-2', ?, 'OPEN', "
            "'foreign-snapshot', ?, 7, 3)",
            (request_hash, snapshot_hash),
        )
        bundle, parent_hash, child_hash = self._bundle(
            child_batch_id="batch-existing"
        )
        request = replace(
            self._request(),
            child_batch_id="batch-existing",
            child_snapshot_sha256=child_hash,
            parent_next_snapshot_sha256=parent_hash,
        )

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchConflict,
            "child batch",
        ):
            self.service().split(request, bundle)

        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT request_hash, current_snapshot_id, "
                    "current_snapshot_sha256, review_revision, execution_generation "
                    "FROM review_batches WHERE batch_id = 'batch-existing'"
                ).fetchone()
            ),
            (request_hash, "foreign-snapshot", snapshot_hash, 7, 3),
        )
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def _assert_request_unit_membership_rebind_is_rejected(
        self,
        column,
        value,
    ):
        if column == "item_id":
            self.connection.execute(
                "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
                (value,),
            )
        self.connection.execute(
            "UPDATE batch_memberships SET %s = ? "
            "WHERE membership_id = 'membership-a'" % column,
            (value,),
        )
        bundle, _parent_hash, _child_hash = self._bundle()

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchConflict,
            "request units.*batch membership",
        ):
            self.service().split(self._request(), bundle)

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )
        self.assertFalse(bundle.parent_snapshot_final_path.exists())
        self.assertFalse(bundle.child_snapshot_final_path.exists())

    def test_split_rejects_request_unit_path_rebound_in_batch_membership(self):
        self._assert_request_unit_membership_rebind_is_rejected(
            "path",
            "projects/rebound.md",
        )

    def test_split_rejects_request_unit_item_rebound_in_batch_membership(self):
        self._assert_request_unit_membership_rebind_is_rejected(
            "item_id",
            ITEM_C,
        )

    def test_split_rejects_request_unit_id_rebound_in_batch_membership(self):
        self._assert_request_unit_membership_rebind_is_rejected(
            "unit_id",
            "unit-rebound",
        )

    def test_split_accepts_folder_unit_membership_bound_to_unit_path(self):
        self.connection.execute(
            "UPDATE batch_memberships SET unit_id = 'folder-1', path = 'projects' "
            "WHERE membership_id = 'membership-a'"
        )
        folder = unit(
            "folder-1",
            "projects",
            ITEM_A,
            unit_kind="folder",
            member_paths=("projects/a.md",),
        )
        request_units = (
            folder,
            unit("unit-b", "projects/b.md", ITEM_B),
        )
        bundle, parent_hash, child_hash = self._bundle(
            units=request_units,
            selected=("folder-1",),
        )
        request = replace(
            self._request(),
            selected_unit_ids=("folder-1",),
            units=request_units,
            child_snapshot_sha256=child_hash,
            parent_next_snapshot_sha256=parent_hash,
        )

        result = self.service().split(request, bundle)

        self.assertEqual(result.event_state, "PUBLISHED")
        self.assertEqual(
            self.connection.execute(
                "SELECT batch_id FROM batch_memberships "
                "WHERE membership_id = 'membership-a'"
            ).fetchone()[0],
            "batch-child-1",
        )

    def test_split_rejects_snapshot_bundle_path_outside_campaign_namespace(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        escaped = self.root / "escaped" / "snapshot.json"

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchValidationError,
            "snapshot path",
        ):
            self.service().split(
                self._request(),
                replace(bundle, parent_snapshot_final_path=escaped),
            )

        self.assertFalse(escaped.exists())
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_split_rejects_child_snapshot_unit_partition_rebound(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        child = json.loads(bundle.child_snapshot_payload_json.decode("utf-8"))
        child["units"] = [self._default_units()[1].to_dict()]
        rebound = canonical_json_bytes(child)
        request = replace(
            self._request(),
            child_snapshot_sha256=sha256_bytes(rebound),
        )

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchValidationError,
            "snapshot payload binding",
        ):
            self.service().split(
                request,
                replace(bundle, child_snapshot_payload_json=rebound),
            )

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_split_rejects_child_snapshot_identity_rebound(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        child = json.loads(bundle.child_snapshot_payload_json.decode("utf-8"))
        child["batch_version"] = 2
        rebound = canonical_json_bytes(child)
        request = replace(
            self._request(),
            child_snapshot_sha256=sha256_bytes(rebound),
        )

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchValidationError,
            "snapshot payload binding",
        ):
            self.service().split(
                request,
                replace(bundle, child_snapshot_payload_json=rebound),
            )

    def test_split_rejects_parent_snapshot_source_binding_rebound(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        parent = json.loads(bundle.parent_snapshot_payload_json.decode("utf-8"))
        parent["parent_snapshot_id"] = "snapshot-rebound"
        rebound = canonical_json_bytes(parent)
        request = replace(
            self._request(),
            parent_next_snapshot_sha256=sha256_bytes(rebound),
        )

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchValidationError,
            "snapshot payload binding",
        ):
            self.service().split(
                request,
                replace(bundle, parent_snapshot_payload_json=rebound),
            )

    def test_split_rejects_symlinked_existing_snapshot_without_following(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        outside = self.root / "outside-snapshot.json"
        outside.write_bytes(bundle.parent_snapshot_payload_json)
        bundle.parent_snapshot_final_path.parent.mkdir(parents=True, mode=0o700)
        bundle.parent_snapshot_final_path.symlink_to(outside)

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchPublicationError,
            "snapshot",
        ):
            self.service().split(self._request(), bundle)

        self.assertEqual(outside.read_bytes(), bundle.parent_snapshot_payload_json)
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_split_rejects_rowless_exact_snapshot_before_event_prepare(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        bundle.parent_snapshot_final_path.parent.mkdir(parents=True, mode=0o700)
        bundle.parent_snapshot_final_path.write_bytes(
            bundle.parent_snapshot_payload_json
        )
        bundle.parent_snapshot_final_path.chmod(0o600)

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchPublicationError,
            "rowless split snapshot",
        ):
            self.service().split(self._request(), bundle)

        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM batch_events").fetchone()[0],
            0,
        )

    def test_split_rejects_rowless_exact_snapshot_appearing_after_prepare(self):
        bundle, _parent_hash, _child_hash = self._bundle()

        def inject_rowless_snapshot(point):
            if point == "published":
                bundle.parent_snapshot_final_path.parent.mkdir(
                    parents=True,
                    mode=0o700,
                )
                bundle.parent_snapshot_final_path.write_bytes(
                    bundle.parent_snapshot_payload_json
                )
                bundle.parent_snapshot_final_path.chmod(0o600)

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchPublicationError,
            "rowless split snapshot",
        ):
            self.service(checkpoint=inject_rowless_snapshot).split(
                self._request(),
                bundle,
            )

        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM batch_events "
                "WHERE batch_event_id = 'split-event-1'"
            ).fetchone()[0],
            "PREPARED",
        )
        self.assertFalse(bundle.child_snapshot_final_path.exists())

    def test_split_transfers_selected_membership_and_advances_parent_head(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        request = self._request()
        result = self.service().split(request, bundle)

        self.assertEqual(result.event_state, "PUBLISHED")
        self.assertEqual(result.transferred_memberships, 1)
        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT batch_id, status FROM batch_memberships "
                    "WHERE membership_id = 'membership-a'"
                ).fetchone()
            ),
            ("batch-child-1", "OPEN"),
        )
        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT batch_id, status FROM batch_memberships "
                    "WHERE membership_id = 'membership-b'"
                ).fetchone()
            ),
            ("batch-1", "OPEN"),
        )
        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT status, current_snapshot_id, review_revision "
                    "FROM review_batches WHERE batch_id = 'batch-1'"
                ).fetchone()
            ),
            ("OPEN", "parent-snapshot-2", 2),
        )
        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT status, current_snapshot_id, review_revision "
                    "FROM review_batches WHERE batch_id = 'batch-child-1'"
                ).fetchone()
            ),
            ("OPEN", "child-snapshot-1", 1),
        )

    def test_published_split_satisfies_batch_event_audit_contract(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)

        self.assertEqual(self.audit_batch_findings(), [])

    def test_split_audit_accepts_sequential_parent_splits(self):
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_C,),
        )
        self.connection.execute(
            "INSERT INTO batch_memberships VALUES ("
            "'membership-c', 'batch-1', 'unit-c', ?, "
            "'projects/c.md', 'OPEN')",
            (ITEM_C,),
        )
        units = (
            unit("unit-a", "projects/a.md", ITEM_A),
            unit("unit-b", "projects/b.md", ITEM_B),
            unit("unit-c", "projects/c.md", ITEM_C),
        )
        first_bundle, first_parent_hash, first_child_hash = self._bundle(
            units=units,
            selected=("unit-a",),
        )
        first_request = replace(
            self._request(),
            units=units,
            child_snapshot_sha256=first_child_hash,
            parent_next_snapshot_sha256=first_parent_hash,
        )
        self.service().split(first_request, first_bundle)
        second_request, second_bundle, _parent_hash, _child_hash = (
            self._next_split(
                batch_id="batch-1",
                batch_request_hash=digest("batch-request"),
                source_snapshot_id="parent-snapshot-2",
                source_snapshot_sha256=first_parent_hash,
                source_revision=2,
                units=units[1:],
                selected=("unit-b",),
                event_id="split-event-2",
                child_batch_id="batch-child-2",
                child_snapshot_id="child-snapshot-2",
                parent_next_snapshot_id="parent-snapshot-3",
            )
        )
        self.service().split(second_request, second_bundle)

        self.assertEqual(self.audit_batch_findings(), [])

    def test_split_audit_accepts_sequential_child_split(self):
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_C,),
        )
        self.connection.execute(
            "INSERT INTO batch_memberships VALUES ("
            "'membership-c', 'batch-1', 'unit-c', ?, "
            "'projects/c.md', 'OPEN')",
            (ITEM_C,),
        )
        units = (
            unit("unit-a", "projects/a.md", ITEM_A),
            unit("unit-b", "projects/b.md", ITEM_B),
            unit("unit-c", "projects/c.md", ITEM_C),
        )
        first_bundle, first_parent_hash, first_child_hash = self._bundle(
            units=units,
            selected=("unit-a", "unit-b"),
        )
        first_request = replace(
            self._request(),
            selected_unit_ids=("unit-a", "unit-b"),
            units=units,
            child_snapshot_sha256=first_child_hash,
            parent_next_snapshot_sha256=first_parent_hash,
        )
        self.service().split(first_request, first_bundle)
        second_request, second_bundle, _parent_hash, _child_hash = (
            self._next_split(
                batch_id="batch-child-1",
                batch_request_hash=(
                    batch_event_contract.split_child_request_hash(
                        "batch-1",
                        "batch-child-1",
                    )
                ),
                source_snapshot_id="child-snapshot-1",
                source_snapshot_sha256=first_child_hash,
                source_revision=1,
                units=units[:2],
                selected=("unit-a",),
                event_id="split-event-2",
                child_batch_id="batch-grandchild-1",
                child_snapshot_id="grandchild-snapshot-1",
                parent_next_snapshot_id="child-parent-snapshot-2",
            )
        )
        self.service().split(second_request, second_bundle)

        self.assertEqual(self.audit_batch_findings(), [])

    def test_split_audit_accepts_parent_terminal_successor(self):
        bundle, parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        self._abandon(
            event_id="abandon-event-1",
            batch_id="batch-1",
            snapshot_id="parent-snapshot-2",
            snapshot_sha256=parent_hash,
            review_revision=2,
        )

        self.assertEqual(self.audit_batch_findings(), [])

    def test_split_audit_accepts_child_terminal_successor(self):
        bundle, _parent_hash, child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        self._abandon(
            event_id="abandon-event-1",
            batch_id="batch-child-1",
            snapshot_id="child-snapshot-1",
            snapshot_sha256=child_hash,
            review_revision=1,
        )

        self.assertEqual(self.audit_batch_findings(), [])

    def test_split_audit_rejects_successor_membership_gap(self):
        first_bundle, first_parent_hash, _first_child_hash = self._bundle()
        self.service().split(self._request(), first_bundle)
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_C,),
        )
        self.connection.execute(
            "INSERT INTO batch_memberships VALUES ("
            "'membership-c', 'batch-1', 'unit-c', ?, "
            "'projects/c.md', 'OPEN')",
            (ITEM_C,),
        )
        successor_units = (
            unit("unit-b", "projects/b.md", ITEM_B),
            unit("unit-c", "projects/c.md", ITEM_C),
        )
        second_request, second_bundle, _parent_hash, _child_hash = (
            self._next_split(
                batch_id="batch-1",
                batch_request_hash=digest("batch-request"),
                source_snapshot_id="parent-snapshot-2",
                source_snapshot_sha256=first_parent_hash,
                source_revision=2,
                units=successor_units,
                selected=("unit-b",),
                event_id="split-event-2",
                child_batch_id="batch-child-2",
                child_snapshot_id="child-snapshot-2",
                parent_next_snapshot_id="parent-snapshot-3",
            )
        )
        self.service().split(second_request, second_bundle)

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_successor_lookup_does_not_scan_same_key_bucket(self):
        class NoIterSequence(tuple):
            def __iter__(self):
                raise AssertionError("successor lookup must not scan the bucket")

        membership = {
            "item_id": ITEM_B,
            "membership_id": "membership-b",
            "path": "projects/b.md",
            "status": "OPEN",
            "unit_id": "unit-b",
        }
        release = [
            {
                "item_id": ITEM_B,
                "membership_id": "membership-b",
                "path": "projects/b.md",
                "unit_id": "unit-b",
            }
        ]
        candidates = NoIterSequence(
            {
                "event_kind": "SPLIT",
                "release": release,
                "release_valid": True,
            }
            for _rowid in range(1, 5001)
        )
        rowids = NoIterSequence(range(1, 5001))
        key = (
            "batch-1",
            "parent-snapshot-2",
            "a" * 64,
            2,
            0,
        )
        query = object.__new__(curation_audit.CurationIntegrityQuery)

        self.assertTrue(
            query._split_side_has_successor(
                successor_index={key: (rowids, candidates)},
                event_rowid=4999,
                batch_id="batch-1",
                snapshot_id="parent-snapshot-2",
                snapshot_sha256="a" * 64,
                review_revision=2,
                execution_generation=0,
                memberships=[membership],
            )
        )

    def test_split_membership_poststate_is_read_once_per_batch(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        memberships = [
            {
                "item_id": ITEM_B,
                "membership_id": "membership-b",
                "path": "projects/b.md",
                "status": "OPEN",
                "unit_id": "unit-b",
            }
        ]
        query = curation_audit.CurationIntegrityQuery(
            self.connection,
            self.root,
        )
        membership_cache = {}
        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            membership_cache.update(query._batch_membership_cache())
            self.assertTrue(
                query._split_side_memberships_are_current(
                    "batch-1",
                    memberships,
                    membership_cache=membership_cache,
                )
            )
            self.assertTrue(
                query._split_side_memberships_are_current(
                    "batch-1",
                    memberships,
                    membership_cache=membership_cache,
                )
            )
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(
            sum("FROM batch_memberships" in statement for statement in statements),
            1,
        )

    def test_split_audit_stops_at_aggregate_snapshot_byte_budget(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        aggregate_budget = (
            len(bundle.parent_snapshot_payload_json)
            + len(bundle.child_snapshot_payload_json)
            - 1
        )

        with mock.patch.object(
            curation_audit,
            "_BATCH_EVENT_MAX_TOTAL_SNAPSHOT_BYTES",
            aggregate_budget,
            create=True,
        ):
            findings = self.audit_batch_findings()

        self.assertIn(
            "batch-event-snapshot-scan-truncated",
            [finding["code"] for finding in findings],
        )

    def test_split_audit_stops_at_aggregate_membership_row_budget(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)

        with mock.patch.object(
            curation_audit,
            "_AUDIT_MAX_LEDGER_ROWS",
            1,
        ):
            findings = self.audit_batch_findings()

        self.assertIn(
            "batch-membership-ledger-scan-truncated",
            [finding["code"] for finding in findings],
        )

    def test_terminal_submission_preflight_uses_one_indexed_read(self):
        query = curation_audit.CurationIntegrityQuery(
            self.connection,
            self.root,
        )
        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            prepared_batches = query._prepared_batch_submission_ids()
            self.assertNotIn("batch-1", prepared_batches)
            self.assertNotIn("batch-1", prepared_batches)
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(
            sum("FROM review_submissions" in value for value in statements),
            1,
        )
        plan = self.connection.execute(
            "EXPLAIN QUERY PLAN "
            + curation_audit._PREPARED_BATCH_SUBMISSIONS_SQL,
            (curation_audit._AUDIT_MAX_PREPARED_BATCH_SUBMISSIONS + 1,),
        ).fetchall()
        self.assertTrue(
            any(
                "batch_one_prepared_submission" in row[-1]
                for row in plan
            )
        )

    def test_terminal_submission_preflight_is_bounded(self):
        bundle, parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        self._abandon(
            event_id="abandon-event-1",
            batch_id="batch-1",
            snapshot_id="parent-snapshot-2",
            snapshot_sha256=parent_hash,
            review_revision=2,
        )
        payload = b"{}\n"
        self.connection.execute(
            "INSERT INTO review_submissions ("
            "submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
            "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
            "payload_sha256, final_path, final_sha256, state"
            ") VALUES ("
            "'submission-prepared', 'BATCH', 'campaign-1', 'batch-1', ?, "
            "'snapshot-prepared', 'parent-snapshot-2', ?, ?, ?, "
            "'submissions/submission-prepared', ?, 'PREPARED'"
            ")",
            (
                digest("prepared-request"),
                digest("prepared-base"),
                payload,
                sha256_bytes(payload),
                digest("prepared-final"),
            ),
        )

        with mock.patch.object(
            curation_audit,
            "_AUDIT_MAX_PREPARED_BATCH_SUBMISSIONS",
            0,
            create=True,
        ):
            findings = self.audit_batch_findings()

        self.assertIn(
            "review-submission-ledger-scan-truncated",
            [finding["code"] for finding in findings],
        )

    def test_split_audit_rejects_parent_poststate_drift(self):
        bundle, parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        cases = (
            ("status", "CLAIMED", "OPEN"),
            ("current_snapshot_id", "snapshot-1", "parent-snapshot-2"),
            (
                "current_snapshot_sha256",
                digest("snapshot-hash"),
                parent_hash,
            ),
            ("review_revision", 1, 2),
            ("execution_generation", 1, 0),
        )

        for column, drifted, restored in cases:
            with self.subTest(column=column):
                self.connection.execute(
                    "UPDATE review_batches SET %s = ? WHERE batch_id = 'batch-1'"
                    % column,
                    (drifted,),
                )
                try:
                    self.assertIn(
                        "batch-event-lineage-mismatch",
                        [
                            finding["code"]
                            for finding in self.audit_batch_findings()
                        ],
                    )
                finally:
                    self.connection.execute(
                        "UPDATE review_batches SET %s = ? "
                        "WHERE batch_id = 'batch-1'" % column,
                        (restored,),
                    )

    def test_split_audit_rejects_child_poststate_drift(self):
        bundle, _parent_hash, child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        cases = (
            ("status", "CLAIMED", "OPEN"),
            (
                "current_snapshot_id",
                "parent-snapshot-2",
                "child-snapshot-1",
            ),
            (
                "current_snapshot_sha256",
                digest("snapshot-hash"),
                child_hash,
            ),
            ("review_revision", 2, 1),
            ("execution_generation", 1, 0),
        )

        for column, drifted, restored in cases:
            with self.subTest(column=column):
                self.connection.execute(
                    "UPDATE review_batches SET %s = ? "
                    "WHERE batch_id = 'batch-child-1'" % column,
                    (drifted,),
                )
                try:
                    self.assertIn(
                        "batch-event-lineage-mismatch",
                        [
                            finding["code"]
                            for finding in self.audit_batch_findings()
                        ],
                    )
                finally:
                    self.connection.execute(
                        "UPDATE review_batches SET %s = ? "
                        "WHERE batch_id = 'batch-child-1'" % column,
                        (restored,),
                    )

    def test_split_audit_rejects_membership_transfer_rollback(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        self.connection.execute(
            "UPDATE batch_memberships SET batch_id = 'batch-1' "
            "WHERE membership_id = 'membership-a'"
        )

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_extra_split_membership(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_C,),
        )
        self.connection.execute(
            "INSERT INTO batch_memberships VALUES ("
            "'membership-c', 'batch-child-1', 'unit-c', ?, "
            "'projects/c.md', 'OPEN')",
            (ITEM_C,),
        )

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_split_membership_status_drift(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        self.connection.execute(
            "UPDATE batch_memberships SET status = 'CLAIMED' "
            "WHERE membership_id = 'membership-a'"
        )

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_child_row_to_payload_rebind(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        self.connection.execute(
            "UPDATE batch_events SET child_batch_id = 'batch-1' "
            "WHERE batch_event_id = 'split-event-1'"
        )

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_parent_rebound_as_child_in_row_and_payload(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        row = self.connection.execute(
            "SELECT payload_json, final_path FROM batch_events "
            "WHERE batch_event_id = 'split-event-1'"
        ).fetchone()
        payload = json.loads(row["payload_json"].decode("utf-8"))
        payload["child_batch_id"] = "batch-1"
        rebound = canonical_json_bytes(payload)
        Path(row["final_path"]).write_bytes(rebound)
        self.connection.execute(
            "UPDATE batch_events SET child_batch_id = 'batch-1', "
            "payload_json = ?, payload_sha256 = ?, final_sha256 = ? "
            "WHERE batch_event_id = 'split-event-1'",
            (rebound, sha256_bytes(rebound), sha256_bytes(rebound)),
        )

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_child_genesis_request_hash_drift(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        self.connection.execute(
            "UPDATE review_batches SET request_hash = ? "
            "WHERE batch_id = 'batch-child-1'",
            (digest("rebound-child-genesis"),),
        )

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_snapshot_partition_rebound_with_matching_hashes(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        child = json.loads(bundle.child_snapshot_payload_json.decode("utf-8"))
        child["units"] = [self._default_units()[1].to_dict()]
        rebound_snapshot = canonical_json_bytes(child)
        rebound_snapshot_sha256 = sha256_bytes(rebound_snapshot)
        bundle.child_snapshot_final_path.write_bytes(rebound_snapshot)
        row = self.connection.execute(
            "SELECT payload_json, final_path FROM batch_events "
            "WHERE batch_event_id = 'split-event-1'"
        ).fetchone()
        event_payload = json.loads(row["payload_json"].decode("utf-8"))
        event_payload["child_snapshot_sha256"] = rebound_snapshot_sha256
        rebound_event = canonical_json_bytes(event_payload)
        Path(row["final_path"]).write_bytes(rebound_event)
        self.connection.execute(
            "UPDATE batch_events SET child_snapshot_sha256 = ?, "
            "payload_json = ?, payload_sha256 = ?, final_sha256 = ? "
            "WHERE batch_event_id = 'split-event-1'",
            (
                rebound_snapshot_sha256,
                rebound_event,
                sha256_bytes(rebound_event),
                sha256_bytes(rebound_event),
            ),
        )

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_partition_drift_with_matching_artifact(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        row = self.connection.execute(
            "SELECT payload_json, final_path FROM batch_events "
            "WHERE batch_event_id = 'split-event-1'"
        ).fetchone()
        payload = json.loads(row["payload_json"].decode("utf-8"))
        payload["selected_unit_ids"] = ["unit-b"]
        rebound = canonical_json_bytes(payload)
        Path(row["final_path"]).write_bytes(rebound)
        self.connection.execute(
            "UPDATE batch_events SET payload_json = ?, payload_sha256 = ?, "
            "final_sha256 = ? WHERE batch_event_id = 'split-event-1'",
            (rebound, sha256_bytes(rebound), sha256_bytes(rebound)),
        )

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_reordered_partition_memberships(self):
        self.connection.execute(
            "INSERT INTO items VALUES (?, 'run-root', 'REVIEW_READY')",
            (ITEM_C,),
        )
        self.connection.execute(
            "INSERT INTO batch_memberships VALUES ("
            "'membership-c', 'batch-1', 'unit-c', ?, "
            "'projects/c.md', 'OPEN')",
            (ITEM_C,),
        )
        request_units = (
            unit("unit-a", "projects/a.md", ITEM_A),
            unit("unit-b", "projects/b.md", ITEM_B),
            unit("unit-c", "projects/c.md", ITEM_C),
        )
        bundle, parent_hash, child_hash = self._bundle(
            units=request_units,
            selected=("unit-a", "unit-b"),
        )
        request = replace(
            self._request(),
            selected_unit_ids=("unit-a", "unit-b"),
            units=request_units,
            child_snapshot_sha256=child_hash,
            parent_next_snapshot_sha256=parent_hash,
        )
        self.service().split(request, bundle)
        row = self.connection.execute(
            "SELECT payload_json, final_path FROM batch_events "
            "WHERE batch_event_id = 'split-event-1'"
        ).fetchone()
        payload = json.loads(row["payload_json"].decode("utf-8"))
        payload["selected_memberships"].reverse()
        rebound = canonical_json_bytes(payload)
        Path(row["final_path"]).write_bytes(rebound)
        self.connection.execute(
            "UPDATE batch_events SET payload_json = ?, payload_sha256 = ?, "
            "final_sha256 = ? WHERE batch_event_id = 'split-event-1'",
            (rebound, sha256_bytes(rebound), sha256_bytes(rebound)),
        )

        self.assertIn(
            "batch-event-envelope-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_split_audit_rejects_tampered_sealed_snapshot(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        self.service().split(self._request(), bundle)
        bundle.child_snapshot_final_path.write_bytes(b"tampered")

        self.assertIn(
            "batch-event-lineage-mismatch",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_prepared_split_is_blocking_recovery_evidence(self):
        prepared = self.service().prepare(self._request())
        self.service().prepare_locked(prepared)

        self.assertIn(
            "unresolved-batch-event",
            [finding["code"] for finding in self.audit_batch_findings()],
        )

    def test_prepare_crash_preserves_membership_and_resume_finishes(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        request = self._request()

        def stop(point):
            if point == "prepared":
                raise RuntimeError("simulated crash")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.service(checkpoint=stop).split(request, bundle)

        self.assertEqual(
            tuple(
                self.connection.execute(
                    "SELECT b.status, m.status, e.state FROM review_batches AS b "
                    "JOIN batch_memberships AS m ON m.batch_id = b.batch_id "
                    "JOIN batch_events AS e ON e.batch_id = b.batch_id "
                    "WHERE b.batch_id = 'batch-1' AND m.membership_id = 'membership-a'"
                ).fetchone()
            ),
            ("OPEN", "OPEN", "PREPARED"),
        )

        result = self.service().resume(
            "split-event-1",
            bundle,
            resumed_by="reviewer",
            policy=policy_for_campaign("campaign-1"),
        )
        self.assertTrue(result.resumed)
        self.assertEqual(result.event_state, "PUBLISHED")
        self.assertEqual(
            self.connection.execute(
                "SELECT batch_id FROM batch_memberships WHERE membership_id = 'membership-a'"
            ).fetchone()[0],
            "batch-child-1",
        )

    def test_published_split_retry_and_resume_are_idempotent(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        request = self._request()
        first = self.service().split(request, bundle)

        repeated = self.service().split(request, bundle)
        resumed = self.service().resume(
            request.event_id,
            bundle,
            resumed_by="reviewer",
            policy=policy_for_campaign("campaign-1"),
        )

        self.assertEqual(first.event_state, "PUBLISHED")
        self.assertTrue(repeated.resumed)
        self.assertTrue(resumed.resumed)
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM batch_events "
                "WHERE batch_event_id = 'split-event-1' AND state = 'PUBLISHED'"
            ).fetchone()[0],
            1,
        )

    def test_published_split_retry_rejects_missing_child_snapshot(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        request = self._request()
        self.service().split(request, bundle)
        bundle.child_snapshot_final_path.unlink()

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchPublicationError,
            "snapshot artifact is missing",
        ):
            self.service().split(request, bundle)

    def test_published_split_resume_rejects_missing_parent_snapshot(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        request = self._request()
        self.service().split(request, bundle)
        bundle.parent_snapshot_final_path.unlink()

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchPublicationError,
            "snapshot artifact is missing",
        ):
            self.service().resume(
                request.event_id,
                bundle,
                resumed_by="reviewer",
                policy=policy_for_campaign("campaign-1"),
            )

    def test_published_split_retry_rejects_hardlinked_event_artifact(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        request = self._request()
        result = self.service().split(request, bundle)
        hardlink = self.root / "split-event-hardlink.json"
        os.link(result.final_path, hardlink)

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchPublicationError,
            "identity is invalid",
        ):
            self.service().split(request, bundle)

    def test_published_split_resume_rejects_hardlinked_snapshot_artifact(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        request = self._request()
        self.service().split(request, bundle)
        hardlink = self.root / "split-snapshot-hardlink.json"
        os.link(bundle.child_snapshot_final_path, hardlink)

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchPublicationError,
            "identity is invalid",
        ):
            self.service().resume(
                request.event_id,
                bundle,
                resumed_by="reviewer",
                policy=policy_for_campaign("campaign-1"),
            )

    def test_resume_rejects_oversized_stored_split_payload_before_decode(self):
        bundle, _parent_hash, _child_hash = self._bundle()
        request = self._request()
        self.service().split(request, bundle)
        self.connection.execute(
            "UPDATE batch_events SET payload_json = ? "
            "WHERE batch_event_id = 'split-event-1'",
            (b"x" * 33,),
        )

        with mock.patch.object(
            split_batch_service,
            "_MAX_EVENT_BLOB_BYTES",
            32,
            create=True,
        ):
            with self.assertRaisesRegex(
                split_batch_service.SplitBatchConflict,
                "bounded blob preflight",
            ):
                self.service().resume(
                    request.event_id,
                    bundle,
                    resumed_by="reviewer",
                    policy=policy_for_campaign("campaign-1"),
                )

    def test_prepared_resume_rejects_rebound_child_genesis_before_publication(self):
        bundle, _parent_hash, _child_hash = self._bundle()

        def stop(point):
            if point == "prepared":
                raise RuntimeError("simulated crash")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.service(checkpoint=stop).split(self._request(), bundle)
        self.connection.execute(
            "UPDATE review_batches SET execution_generation = 3 "
            "WHERE batch_id = 'batch-child-1'"
        )

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchConflict,
            "child genesis",
        ):
            self.service().resume(
                "split-event-1",
                bundle,
                resumed_by="reviewer",
                policy=policy_for_campaign("campaign-1"),
            )

        event_path = (
            self.root
            / "campaigns/campaign-1/batch-events/split-event-1/event.json"
        )
        self.assertFalse(event_path.exists())
        self.assertFalse(bundle.parent_snapshot_final_path.exists())

    def test_resume_rejects_rebound_split_event_path_before_artifact_access(self):
        bundle, _parent_hash, _child_hash = self._bundle()

        def stop(point):
            if point == "prepared":
                raise RuntimeError("simulated crash")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.service(checkpoint=stop).split(self._request(), bundle)
        outside = self.root / "outside-split-event.json"
        outside.write_bytes(b"outside")
        self.connection.execute(
            "UPDATE batch_events SET final_path = ? "
            "WHERE batch_event_id = 'split-event-1'",
            (str(outside),),
        )

        with self.assertRaisesRegex(
            split_batch_service.SplitBatchConflict,
            "path is rebound",
        ):
            self.service().resume(
                "split-event-1",
                bundle,
                resumed_by="reviewer",
                policy=policy_for_campaign("campaign-1"),
            )

        self.assertEqual(outside.read_bytes(), b"outside")


if __name__ == "__main__":
    unittest.main()
