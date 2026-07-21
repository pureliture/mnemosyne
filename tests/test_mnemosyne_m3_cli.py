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


class MnemosyneM3WorkflowTest(unittest.TestCase):
    def test_decide_builds_submission_without_structural_authority(self):
        workflow = mnemosyne._m3_workflow_core
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            expected_report = workflow.SubmitReviewReport(
                batch_id="batch-1",
                snapshot_id="snapshot-next",
                submission_id="submission-1",
                submission_state="COMMITTED",
                review_revision=2,
                execution_generation=1,
                snapshot_sha256="c" * 64,
                package_sha256="d" * 64,
                final_path=str(root / "snapshot-next"),
                review_directory=str(root / "snapshot-next" / "review"),
                structural_approval_ready=False,
                resumed=False,
            )
            with mock.patch.object(
                workflow,
                "submit_review_decision",
                return_value=expected_report,
            ) as submit:
                report = workflow.decide(
                    root,
                    campaign_id="campaign-1",
                    batch_id="batch-1",
                    base_snapshot_id="snapshot-base",
                    base_snapshot_sha256="a" * 64,
                    expected_review_revision=1,
                    expected_execution_generation=1,
                    submission_id="submission-1",
                    next_snapshot_id="snapshot-next",
                    actor="reviewer",
                    unit_id="unit-a",
                    member_item_ids=("item-1",),
                    action="keep",
                    reason="accepted",
                    decided_at_utc="2026-07-18T00:00:00Z",
                )

            self.assertIs(report, expected_report)
            submit.assert_called_once()
            request = submit.call_args.kwargs["decision_request"]
            self.assertEqual(request.campaign_id, "campaign-1")
            self.assertEqual(request.batch_id, "batch-1")
            self.assertEqual(request.expected_review_revision, 1)
            self.assertEqual(request.expected_execution_generation, 1)
            self.assertEqual(request.decisions[0].member_item_ids, ("item-1",))
            self.assertEqual(request.decisions[0].action, "keep")
            self.assertFalse(report.structural_approval_ready)

    def test_submit_review_rejects_invalid_draft_identity_before_ledger_access(self):
        workflow = mnemosyne._m3_workflow_core
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            with mock.patch.object(
                workflow.ledger_runtime,
                "open_reader_session",
                side_effect=AssertionError("invalid draft reached ledger access"),
            ) as reader:
                with self.assertRaisesRegex(
                    workflow.M3WorkflowError,
                    "draft id is invalid",
                ):
                    workflow.submit_review(
                        root,
                        draft_id="../draft-1",
                        submission_id="submission-2",
                        next_snapshot_id="snapshot-after",
                        actor="reviewer",
                    )
            reader.assert_not_called()

    def test_submit_review_builds_decision_request_from_checked_out_draft(self):
        workflow = mnemosyne._m3_workflow_core
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            control_root = root / "_registry" / "curation"
            draft_path = control_root / "drafts" / "draft-1"
            draft_path.mkdir(mode=0o700, parents=True)
            (draft_path / "draft.json").write_text(
                json.dumps(
                    {
                        "base_snapshot_id": "snapshot-base",
                        "base_snapshot_sha256": "a" * 64,
                        "owner_actor": "draft-owner",
                    }
                ),
                encoding="utf-8",
            )
            reader_connection = mock.Mock()
            reader_connection.execute.return_value.fetchone.return_value = (3, 5)
            reader = SimpleNamespace(
                compiled_policy=SimpleNamespace(
                    foundation=SimpleNamespace(state_root=control_root)
                ),
                connection=reader_connection,
            )
            sealed = SimpleNamespace(
                snapshot_id="snapshot-base",
                snapshot_sha256="a" * 64,
                snapshot_payload=(
                    b'{"batch_id":"batch-1","campaign_id":"campaign-1",'
                    b'"units":[{"member_item_ids":["item-1"],'
                    b'"unit_id":"unit-a"}]}'
                ),
                review_markdown=b"# Review\n",
                review_hashes=SimpleNamespace(markdown_sha256="b" * 64),
            )
            draft = SimpleNamespace(
                edits=(
                    workflow.review_draft.DraftItemEdit(
                        unit_id="unit-a",
                        decision="keep",
                        corrections=(),
                    ),
                )
            )
            expected_report = workflow.SubmitReviewReport(
                batch_id="batch-1",
                snapshot_id="snapshot-next",
                submission_id="submission-2",
                submission_state="COMMITTED",
                review_revision=4,
                execution_generation=5,
                snapshot_sha256="c" * 64,
                package_sha256="d" * 64,
                final_path=str(root / "snapshot-next"),
                review_directory=str(root / "snapshot-next" / "review"),
                structural_approval_ready=False,
                resumed=False,
            )
            with mock.patch.object(
                workflow.ledger_runtime,
                "open_reader_session",
                return_value=contextlib.nullcontext(reader),
            ), mock.patch.object(
                workflow.review_state,
                "ReviewSnapshotLoader",
            ) as loader_class, mock.patch.object(
                workflow.review_draft,
                "checkout_review",
                return_value=draft,
            ) as checkout, mock.patch.object(
                workflow,
                "submit_review_decision",
                return_value=expected_report,
            ) as submit:
                loader_class.return_value.load.return_value = sealed
                report = workflow.submit_review(
                    root,
                    draft_id="draft-1",
                    submission_id="submission-2",
                    next_snapshot_id="snapshot-next",
                    actor="reviewer",
                    reason="approved review",
                    decided_at_utc="2026-07-18T00:00:00Z",
                )

            self.assertIs(report, expected_report)
            checkout.assert_called_once()
            self.assertEqual(
                checkout.call_args.kwargs["drafts_root"],
                control_root / "drafts",
            )
            submit.assert_called_once()
            request = submit.call_args.kwargs["decision_request"]
            self.assertEqual(request.campaign_id, "campaign-1")
            self.assertEqual(request.batch_id, "batch-1")
            self.assertEqual(request.expected_review_revision, 3)
            self.assertEqual(request.expected_execution_generation, 5)
            self.assertEqual(request.actor, "reviewer")
            self.assertEqual(request.decisions[0].member_item_ids, ("item-1",))
            self.assertEqual(request.decisions[0].action, "keep")
            self.assertEqual(request.decisions[0].reason, "approved review")

    def test_reopen_decision_builds_reopen_submission_request(self):
        workflow = mnemosyne._m3_workflow_core
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            expected_report = workflow.ReopenDecisionReport(
                batch_id="batch-1",
                snapshot_id="snapshot-reopen",
                submission_id="submission-reopen",
                submission_state="COMMITTED",
                review_revision=3,
                execution_generation=1,
                snapshot_sha256="1" * 64,
                package_sha256="2" * 64,
                final_path=str(root / "snapshot-reopen"),
                review_directory=str(root / "snapshot-reopen" / "review"),
                structural_approval_ready=False,
                resumed=False,
            )
            with mock.patch.object(
                workflow,
                "reopen_review_decision",
                return_value=expected_report,
            ) as reopen:
                report = workflow.reopen_decision(
                    root,
                    campaign_id="campaign-1",
                    batch_id="batch-1",
                    base_snapshot_id="snapshot-keep",
                    base_snapshot_sha256="a" * 64,
                    expected_review_revision=2,
                    expected_execution_generation=1,
                    submission_id="submission-reopen",
                    next_snapshot_id="snapshot-reopen",
                    item_id="item-1",
                    current_decision_event_id="event-keep",
                    current_projection_generation=1,
                    actor="reviewer",
                    reason="reopen",
                    reopened_at_utc="2026-07-18T00:00:00Z",
                )

            self.assertIs(report, expected_report)
            reopen.assert_called_once()
            request = reopen.call_args.kwargs["reopen_request"]
            self.assertEqual(request.item_id, "item-1")
            self.assertEqual(request.current_decision_event_id, "event-keep")
            self.assertEqual(request.current_projection_generation, 1)
            self.assertEqual(request.reopened_at_utc, "2026-07-18T00:00:00Z")
            self.assertFalse(report.structural_approval_ready)

    @staticmethod
    def _writer_session(control_root, campaign_id="campaign-1"):
        connection = mock.Mock()
        connection.execute.return_value.fetchone.return_value = (campaign_id,)
        session = SimpleNamespace(
            compiled_policy=SimpleNamespace(
                foundation=SimpleNamespace(state_root=control_root)
            ),
            connection=connection,
            ledger_exclusive=contextlib.nullcontext,
            placement_shared=contextlib.nullcontext,
        )
        return session

    def test_close_and_abandon_use_campaign_scoped_event_root(self):
        workflow = mnemosyne._m3_workflow_core
        service_core = workflow.batch_event_service
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            control_root = root / "_registry" / "curation"
            expected_root = (
                control_root / "campaigns" / "campaign-1" / "batch-events"
            )
            for kind, operation, status in (
                ("close", workflow.close_review_batch, "CLOSED_REVIEW"),
                ("abandon", workflow.abandon_review_batch, "ABANDONED"),
            ):
                with self.subTest(kind=kind):
                    session = self._writer_session(control_root)
                    result = service_core.BatchEventResult(
                        event_id="event-1",
                        event_state="PUBLISHED",
                        event_sha256="c" * 64,
                        batch_id="batch-1",
                        batch_status=status,
                        released_memberships=1,
                        final_path=expected_root / "event-1" / "event.json",
                        resumed=False,
                    )
                    with mock.patch.object(
                        workflow.ledger_runtime,
                        "open_writer_session",
                        return_value=contextlib.nullcontext(session),
                    ), mock.patch.object(
                        service_core,
                        "BatchEventService",
                    ) as service_class:
                        getattr(service_class.return_value, kind).return_value = result
                        operation(
                            root,
                            event_id="event-1",
                            batch_id="batch-1",
                            expected_snapshot_id="snapshot-1",
                            expected_snapshot_sha256="a" * 64,
                            expected_review_revision=1,
                            expected_execution_generation=0,
                            actor="reviewer",
                        )

                    self.assertEqual(service_class.call_args.args[1], expected_root)
                    getattr(service_class.return_value, kind).assert_called_once()

    def test_resume_batch_event_uses_campaign_scoped_event_root(self):
        workflow = mnemosyne._m3_workflow_core
        service_core = workflow.batch_event_service
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            control_root = root / "_registry" / "curation"
            expected_root = (
                control_root / "campaigns" / "campaign-1" / "batch-events"
            )
            reader_connection = mock.Mock()
            reader_connection.execute.return_value.fetchone.return_value = (
                "CLOSE_REVIEW",
            )
            reader = SimpleNamespace(connection=reader_connection)
            writer = self._writer_session(control_root)
            result = service_core.BatchEventResult(
                event_id="event-1",
                event_state="PUBLISHED",
                event_sha256="c" * 64,
                batch_id="batch-1",
                batch_status="CLOSED_REVIEW",
                released_memberships=1,
                final_path=expected_root / "event-1" / "event.json",
                resumed=True,
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
                service_core,
                "BatchEventService",
            ) as service_class:
                service_class.return_value.resume.return_value = result
                report = workflow.resume_batch_event(
                    root,
                    event_id="event-1",
                    resumed_by="reviewer",
                )

            self.assertTrue(report.resumed)
            self.assertEqual(service_class.call_args.args[1], expected_root)
            service_class.return_value.resume.assert_called_once_with(
                "event-1",
                resumed_by="reviewer",
            )


if __name__ == "__main__":
    unittest.main()
