import contextlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402


class MnemosyneM4CliTest(unittest.TestCase):
    @staticmethod
    def _session(control_root, connection, *, policy=None):
        return SimpleNamespace(
            approved_policy_ref=policy,
            compiled_policy=SimpleNamespace(
                foundation=SimpleNamespace(state_root=control_root)
            ),
            connection=connection,
            ledger_exclusive=contextlib.nullcontext,
            placement_shared=contextlib.nullcontext,
        )

    def test_split_review_batch_uses_campaign_scoped_event_and_snapshot_roots(self):
        workflow = mnemosyne._m4_workflow_core
        canonical_json_bytes = mnemosyne._canonical_json_core.canonical_json_bytes
        sha256_bytes = mnemosyne._canonical_json_core.sha256_bytes
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            control_root = root / "_registry" / "curation"
            head_root = Path(temporary) / "head"
            head_root.mkdir(mode=0o700)
            head_payload = {
                "batch_id": "batch-1",
                "batch_version": 1,
                "campaign_id": "campaign-1",
                "parent_snapshot_id": None,
                "parent_snapshot_sha256": None,
                "request_hash": "b" * 64,
                "schema_version": 2,
                "snapshot_id": "snapshot-1",
                "units": [
                    {"path": "a.md", "unit_id": "unit-a"},
                    {"path": "b.md", "unit_id": "unit-b"},
                ],
            }
            (head_root / "snapshot.json").write_text(
                json.dumps(head_payload),
                encoding="utf-8",
            )
            parent_payload = dict(head_payload)
            parent_payload["batch_version"] = 2
            parent_payload["parent_snapshot_id"] = "snapshot-1"
            parent_payload["parent_snapshot_sha256"] = "a" * 64
            parent_payload["snapshot_id"] = "parent-next"
            parent_payload["units"] = [head_payload["units"][1]]
            child_payload = dict(head_payload)
            child_payload["batch_id"] = "batch-child"
            child_payload["batch_version"] = 1
            child_payload["parent_snapshot_id"] = "snapshot-1"
            child_payload["parent_snapshot_sha256"] = "a" * 64
            child_payload["request_hash"] = (
                workflow.batch_event_contract.split_child_request_hash(
                    "batch-1",
                    "batch-child",
                )
            )
            child_payload["snapshot_id"] = "child-snapshot"
            child_payload["units"] = [head_payload["units"][0]]
            policy = object()
            reader_connection = mock.Mock()
            reader_connection.execute.side_effect = (
                SimpleNamespace(fetchone=lambda: ("campaign-1",)),
                SimpleNamespace(fetchone=lambda: (str(head_root),)),
            )
            writer_connection = mock.Mock()
            writer_connection.execute.return_value.fetchone.return_value = (
                "campaign-1",
            )
            reader = self._session(control_root, reader_connection)
            reader.current_policy = mock.Mock(return_value=policy)
            writer = self._session(
                control_root,
                writer_connection,
                policy=policy,
            )
            result = workflow.split_batch_service.SplitBatchResult(
                event_id="event-split",
                event_state="PUBLISHED",
                parent_batch_id="batch-1",
                child_batch_id="batch-child",
                parent_snapshot_id="parent-next",
                child_snapshot_id="child-snapshot",
                transferred_memberships=1,
                final_path=(
                    control_root
                    / "campaigns"
                    / "campaign-1"
                    / "batch-events"
                    / "event-split"
                    / "event.json"
                ),
                resumed=False,
            )
            with mock.patch.object(
                workflow.ledger_runtime,
                "open_reader_session",
                return_value=contextlib.nullcontext(reader),
            ), mock.patch.object(
                workflow.ledger_runtime,
                "open_writer_session",
                return_value=contextlib.nullcontext(writer),
            ), mock.patch.object(
                workflow.review_state,
                "ReviewSnapshotLoader",
            ) as loader, mock.patch.object(
                workflow.split_batch_service,
                "SplitBatchService",
            ) as service_class:
                loader.return_value.load.return_value = SimpleNamespace(
                    schema_version=2,
                    payload=head_payload,
                    snapshot_id="snapshot-1",
                    snapshot_sha256="a" * 64,
                    units=(),
                )
                service_class.return_value.split.return_value = result
                report = workflow.split_review_batch(
                    root,
                    event_id="event-split",
                    batch_id="batch-1",
                    expected_snapshot_id="snapshot-1",
                    expected_snapshot_sha256="a" * 64,
                    expected_review_revision=1,
                    expected_execution_generation=0,
                    selected_unit_ids=("unit-a",),
                    child_batch_id="batch-child",
                    child_snapshot_id="child-snapshot",
                    child_snapshot_sha256=sha256_bytes(
                        canonical_json_bytes(child_payload)
                    ),
                    child_submission_id="submission-child",
                    parent_next_snapshot_id="parent-next",
                    parent_next_snapshot_sha256=sha256_bytes(
                        canonical_json_bytes(parent_payload)
                    ),
                    parent_submission_id="submission-parent",
                    actor="reviewer",
                )

            event_root = (
                control_root / "campaigns" / "campaign-1" / "batch-events"
            )
            snapshot_root = (
                control_root / "campaigns" / "campaign-1" / "snapshots"
            )
            self.assertEqual(report.state, "PUBLISHED")
            self.assertEqual(reader_connection.execute.call_count, 1)
            loader.return_value.load.assert_called_once_with("snapshot-1")
            self.assertEqual(service_class.call_args.args[1], event_root)
            bundle = service_class.return_value.split.call_args.args[1]
            self.assertEqual(
                bundle.parent_snapshot_final_path,
                snapshot_root / "parent-next" / "snapshot.json",
            )
            self.assertEqual(
                bundle.child_snapshot_final_path,
                snapshot_root / "child-snapshot" / "snapshot.json",
            )
            parent_snapshot = json.loads(
                bundle.parent_snapshot_payload_json.decode("utf-8")
            )
            child_snapshot = json.loads(
                bundle.child_snapshot_payload_json.decode("utf-8")
            )
            self.assertEqual(
                (
                    parent_snapshot["batch_id"],
                    parent_snapshot["batch_version"],
                    parent_snapshot["parent_snapshot_id"],
                    parent_snapshot["parent_snapshot_sha256"],
                    parent_snapshot["request_hash"],
                ),
                ("batch-1", 2, "snapshot-1", "a" * 64, "b" * 64),
            )
            self.assertEqual(
                (
                    child_snapshot["batch_id"],
                    child_snapshot["batch_version"],
                    child_snapshot["parent_snapshot_id"],
                    child_snapshot["parent_snapshot_sha256"],
                    child_snapshot["request_hash"],
                ),
                (
                    "batch-child",
                    1,
                    "snapshot-1",
                    "a" * 64,
                    workflow.batch_event_contract.split_child_request_hash(
                        "batch-1",
                        "batch-child",
                    ),
                ),
            )

    def test_resume_split_event_uses_campaign_scoped_event_root(self):
        workflow = mnemosyne._m4_workflow_core
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            control_root = root / "_registry" / "curation"
            head_root = Path(temporary) / "head"
            head_root.mkdir(mode=0o700)
            (head_root / "snapshot.json").write_text(
                '{"units": []}',
                encoding="utf-8",
            )
            connection = mock.Mock()
            connection.execute.side_effect = (
                SimpleNamespace(fetchone=lambda: ("campaign-1",)),
                SimpleNamespace(fetchone=lambda: (str(head_root),)),
            )
            policy = object()
            writer = self._session(control_root, connection, policy=policy)
            prepared = SimpleNamespace(
                request=SimpleNamespace(
                    batch_id="batch-1",
                    expected_snapshot_id="snapshot-1",
                    expected_snapshot_sha256="a" * 64,
                    expected_review_revision=1,
                )
            )
            bundle = SimpleNamespace()
            result = workflow.split_batch_service.SplitBatchResult(
                event_id="event-split",
                event_state="PUBLISHED",
                parent_batch_id="batch-1",
                child_batch_id="batch-child",
                parent_snapshot_id="parent-next",
                child_snapshot_id="child-snapshot",
                transferred_memberships=1,
                final_path=(
                    control_root
                    / "campaigns"
                    / "campaign-1"
                    / "batch-events"
                    / "event-split"
                    / "event.json"
                ),
                resumed=True,
            )
            with mock.patch.object(
                workflow.ledger_runtime,
                "open_writer_session",
                return_value=contextlib.nullcontext(writer),
            ), mock.patch.object(
                workflow,
                "_split_bundle",
                return_value=bundle,
            ), mock.patch.object(
                workflow.review_state,
                "ReviewSnapshotLoader",
            ) as loader, mock.patch.object(
                workflow.split_batch_service,
                "SplitBatchService",
            ) as service_class:
                loader.return_value.load.return_value = SimpleNamespace(
                    payload={
                        "batch_id": "batch-1",
                        "batch_version": 1,
                        "campaign_id": "campaign-1",
                        "request_hash": "b" * 64,
                        "snapshot_id": "snapshot-1",
                        "units": [],
                    },
                    schema_version=2,
                    snapshot_id="snapshot-1",
                    snapshot_sha256="a" * 64,
                )
                service_class.return_value.load_prepared.return_value = prepared
                service_class.return_value.resume.return_value = result
                report = workflow.resume_split_batch_event(
                    root,
                    event_id="event-split",
                    resumed_by="reviewer",
                )

            expected_root = (
                control_root / "campaigns" / "campaign-1" / "batch-events"
            )
            self.assertTrue(report.resumed)
            self.assertEqual(service_class.call_args.args[1], expected_root)
            loader.assert_called_once_with(connection, control_root)
            loader.return_value.load.assert_called_once_with("snapshot-1")
            service_class.return_value.resume.assert_called_once_with(
                "event-split",
                bundle,
                resumed_by="reviewer",
                policy=policy,
            )

    def test_resume_split_rejects_source_snapshot_loader_failure(self):
        workflow = mnemosyne._m4_workflow_core
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            control_root = root / "_registry" / "curation"
            head_root = Path(temporary) / "poisoned-head"
            head_root.mkdir(mode=0o700)
            (head_root / "snapshot.json").write_text(
                '{"units": []}',
                encoding="utf-8",
            )
            connection = mock.Mock()
            connection.execute.side_effect = (
                SimpleNamespace(fetchone=lambda: ("campaign-1",)),
                SimpleNamespace(fetchone=lambda: (str(head_root),)),
            )
            policy = object()
            writer = self._session(control_root, connection, policy=policy)
            prepared = SimpleNamespace(
                request=SimpleNamespace(
                    batch_id="batch-1",
                    expected_snapshot_id="snapshot-1",
                    expected_snapshot_sha256="a" * 64,
                )
            )
            with mock.patch.object(
                workflow.ledger_runtime,
                "open_writer_session",
                return_value=contextlib.nullcontext(writer),
            ), mock.patch.object(
                workflow,
                "_split_bundle",
                return_value=SimpleNamespace(),
            ), mock.patch.object(
                workflow.review_state,
                "ReviewSnapshotLoader",
            ) as loader, mock.patch.object(
                workflow.split_batch_service,
                "SplitBatchService",
            ) as service_class:
                service_class.return_value.load_prepared.return_value = prepared
                loader.return_value.load.side_effect = (
                    workflow.review_state.ReviewStateError("poisoned snapshot")
                )

                with self.assertRaisesRegex(
                    workflow.M4WorkflowError,
                    "poisoned snapshot",
                ):
                    workflow.resume_split_batch_event(
                        root,
                        event_id="event-split",
                        resumed_by="reviewer",
                    )

            service_class.return_value.resume.assert_not_called()


if __name__ == "__main__":
    unittest.main()
