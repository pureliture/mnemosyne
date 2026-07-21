import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402


class MnemosyneM3M2BoundaryTest(unittest.TestCase):
    def test_m3_submission_report_cannot_claim_structural_authority(self):
        workflow = mnemosyne._m3_workflow_core

        with self.assertRaisesRegex(
            workflow.M3WorkflowError,
            "cannot grant structural authority",
        ):
            workflow.SubmitReviewReport(
                batch_id="batch-1",
                snapshot_id="snapshot-1",
                submission_id="submission-1",
                submission_state="COMMITTED",
                review_revision=1,
                execution_generation=0,
                snapshot_sha256="a" * 64,
                package_sha256="b" * 64,
                final_path="/private/tmp/snapshot-1",
                review_directory="/private/tmp/snapshot-1/review",
                structural_approval_ready=True,
                resumed=False,
            )

    def test_reopened_m3_submission_stays_non_authoritative(self):
        workflow = mnemosyne._m3_workflow_core

        report = workflow.ReopenDecisionReport(
            batch_id="batch-1",
            snapshot_id="snapshot-2",
            submission_id="submission-2",
            submission_state="COMMITTED",
            review_revision=2,
            execution_generation=0,
            snapshot_sha256="c" * 64,
            package_sha256="d" * 64,
            final_path="/private/tmp/snapshot-2",
            review_directory="/private/tmp/snapshot-2/review",
            structural_approval_ready=False,
            resumed=True,
        )

        self.assertFalse(report.structural_approval_ready)


if __name__ == "__main__":
    unittest.main()
