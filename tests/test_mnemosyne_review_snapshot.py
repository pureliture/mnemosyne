import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import review_compiler, review_package, review_snapshot  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


def make_snapshot_payload(snapshot_id="snapshot-001"):
    return canonical_json_bytes(
        {
            "approval_ready": False,
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "structural_approval_ready": False,
        }
    )


def make_review_document(snapshot_bytes, snapshot_id="snapshot-001"):
    return review_compiler.ReviewDocument(
        review_kind="batch-preview",
        source_kind="batch-snapshot",
        source_id=snapshot_id,
        source_snapshot_sha256=sha256_bytes(snapshot_bytes),
        rendered_at="2026-07-15T01:00:00Z",
        campaign_id="campaign-001",
        batch_id="batch-001",
        snapshot_id=snapshot_id,
        snapshot_version=1,
        policy_binding="generation=1;source=INITIAL/policy-run-001;guard=0",
        coverage=review_compiler.CoverageSummary(
            folders_total=1,
            folders_traversed=1,
            folders_excluded=0,
            folders_error=0,
            files_total=1,
            files_inspected=1,
            files_metadata_only=0,
            files_excluded=0,
            files_error=0,
        ),
        bounds=review_compiler.ReviewBounds(
            review_items=1,
            underlying_files=1,
            total_bytes=8,
            leaf_folders=1,
            effect_count=0,
        ),
        workstreams=(
            review_compiler.WorkstreamSummary(
                workstream_id="alpha",
                lifecycle="active",
                review_items=1,
                blocked=0,
                errors=0,
            ),
        ),
        items=(
            review_compiler.ReviewRow(
                unit_id="unit-alpha",
                unit_kind="file",
                canonical_path="projects/alpha/spec.md",
                display_path="projects/alpha/spec.md",
                underlying_file_count=1,
                primary_workstream="alpha",
                related_workstreams=(),
                shared=False,
                document_role="requirements",
                authority="reference",
                document_lifecycle="current",
                scope_class="active-workstream-content",
                sensitivity="public",
                access_domain="default",
                recommended_action="defer",
                target_path=None,
                risk_band="medium",
                context_freshness="fresh",
                evidence_providers=("path-pattern",),
                warning_codes=(),
                effect_codes=("plan-unavailable-m2",),
            ),
        ),
        warning_codes=("m2-no-structural-authority",),
    )


def tree_identity(root):
    return {
        path.relative_to(root).as_posix() or ".": (
            path.lstat().st_dev,
            path.lstat().st_ino,
            path.lstat().st_mtime_ns,
            path.read_bytes() if path.is_file() else None,
        )
        for path in (root,) + tuple(sorted(root.rglob("*")))
    }


class ReviewSnapshotPublisherTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "snapshots"
        self.snapshot_bytes = make_snapshot_payload()
        self.document = make_review_document(self.snapshot_bytes)
        self.publisher = review_snapshot.ReviewSnapshotPublisher(
            self.root,
            renderer_id="renderer-v1",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_plan_binds_exact_snapshot_review_and_manifest_bytes(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )

        self.assertEqual(plan.staging_path, self.root / ".incomplete-snapshot-001")
        self.assertEqual(plan.final_path, self.root / "snapshot-001")
        self.assertEqual(plan.snapshot_sha256, sha256_bytes(self.snapshot_bytes))
        self.assertEqual(
            json.loads(plan.review_artifacts.meta_json)["source_snapshot_sha256"],
            plan.snapshot_sha256,
        )
        manifest = json.loads(plan.manifest_bytes)
        self.assertEqual(
            [member["path"] for member in manifest["members"]],
            [
                "review/review.html",
                "review/review.md",
                "review/review.meta.json",
                "snapshot.json",
            ],
        )
        self.assertEqual(plan.package_sha256, sha256_bytes(plan.manifest_bytes))
        self.assertFalse(self.root.exists())

    def test_publish_seals_owner_only_complete_package(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )

        result = self.publisher.publish(plan)

        self.assertEqual(result.final_path, plan.final_path)
        self.assertEqual(result.snapshot_sha256, plan.snapshot_sha256)
        self.assertEqual(result.package_sha256, plan.package_sha256)
        self.assertFalse(result.resumed)
        self.assertFalse(plan.staging_path.exists())
        self.assertEqual(
            sorted(path.name for path in plan.final_path.iterdir()),
            ["manifest.json", "review", "snapshot.json"],
        )
        self.assertEqual(
            sorted(path.name for path in (plan.final_path / "review").iterdir()),
            ["review.html", "review.md", "review.meta.json"],
        )
        for directory in (self.root, plan.final_path, plan.final_path / "review"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for file_path in (
            plan.final_path / "snapshot.json",
            plan.final_path / "manifest.json",
            plan.final_path / "review" / "review.md",
            plan.final_path / "review" / "review.html",
            plan.final_path / "review" / "review.meta.json",
        ):
            self.assertEqual(stat.S_IMODE(file_path.stat().st_mode), 0o600)
        self.assertEqual(
            (plan.final_path / "snapshot.json").read_bytes(),
            plan.snapshot_payload,
        )
        self.assertEqual(
            (plan.final_path / "manifest.json").read_bytes(),
            plan.manifest_bytes,
        )
        review_package.validate_review_directory(
            plan.final_path / "review",
            expected_source_snapshot_sha256=plan.snapshot_sha256,
        )

    def test_exact_retry_preserves_every_inode_mtime_and_byte(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        first = self.publisher.publish(plan)
        before = tree_identity(first.final_path)

        second = self.publisher.publish(plan)

        self.assertTrue(second.resumed)
        self.assertEqual(tree_identity(second.final_path), before)

    def test_exact_final_with_conflicting_staging_fails_closed(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        self.publisher.publish(plan)
        plan.staging_path.mkdir(mode=0o700)
        (plan.staging_path / "unexpected").write_bytes(b"tamper")

        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "unexpected review snapshot member",
        ):
            self.publisher.publish(plan)

    def test_rename_collision_never_reports_success_with_retained_staging(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )

        def publish_competing_exact_final(source, target, **_kwargs):
            shutil.copytree(source, target)
            raise review_snapshot.ReviewSnapshotError(
                "snapshot final path already exists"
            )

        with mock.patch.object(
            review_snapshot.safety,
            "rename_path_no_replace",
            side_effect=publish_competing_exact_final,
        ):
            with self.assertRaisesRegex(
                review_snapshot.ReviewSnapshotError,
                "conflicting snapshot staging exists beside final package",
            ):
                self.publisher.publish(plan)

        self.assertTrue(plan.final_path.is_dir())
        self.assertTrue(plan.staging_path.is_dir())

    def test_partial_exact_staging_resumes_without_replacing_existing_member(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        self.root.mkdir(mode=0o700)
        plan.staging_path.mkdir(mode=0o700)
        staged_snapshot = plan.staging_path / "snapshot.json"
        staged_snapshot.write_bytes(plan.snapshot_payload)
        staged_snapshot.chmod(0o600)
        before_inode = staged_snapshot.stat().st_ino

        result = self.publisher.publish(plan)

        self.assertTrue(result.resumed)
        self.assertEqual(
            (result.final_path / "snapshot.json").stat().st_ino,
            before_inode,
        )
        self.assertEqual(
            (result.final_path / "snapshot.json").read_bytes(),
            plan.snapshot_payload,
        )

    def test_plan_rejects_noncanonical_snapshot_or_review_hash_mismatch(self):
        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "not canonical JSON",
        ):
            self.publisher.plan(
                snapshot_id="snapshot-001",
                snapshot_payload=self.snapshot_bytes + b" ",
                review_document=self.document,
            )

        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "review source snapshot hash",
        ):
            self.publisher.plan(
                snapshot_id="snapshot-001",
                snapshot_payload=self.snapshot_bytes,
                review_document=replace(
                    self.document,
                    source_snapshot_sha256="f" * 64,
                ),
            )

    def test_final_review_tamper_fails_closed_without_repair(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        self.publisher.publish(plan)
        markdown_path = plan.final_path / "review" / "review.md"
        markdown_path.write_bytes(b"tampered\n")

        with self.assertRaises(review_snapshot.ReviewSnapshotError):
            self.publisher.publish(plan)

        self.assertEqual(markdown_path.read_bytes(), b"tampered\n")

    def test_staging_review_mismatch_uses_publisher_error_without_repair(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        self.root.mkdir(mode=0o700)
        plan.staging_path.mkdir(mode=0o700)
        review_path = plan.staging_path / "review"
        review_path.mkdir(mode=0o700)
        markdown_path = review_path / "review.md"
        markdown_path.write_bytes(b"wrong\n")
        markdown_path.chmod(0o600)

        with self.assertRaises(review_snapshot.ReviewSnapshotError):
            self.publisher.publish(plan)

        self.assertEqual(markdown_path.read_bytes(), b"wrong\n")

    def test_staging_symlink_fails_without_following_target(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        self.root.mkdir(mode=0o700)
        outside = Path(self.temporary.name).resolve() / "outside"
        outside.mkdir(mode=0o700)
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"unchanged")
        plan.staging_path.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(review_snapshot.ReviewSnapshotError):
            self.publisher.publish(plan)

        self.assertEqual(sentinel.read_bytes(), b"unchanged")
        self.assertFalse(plan.final_path.exists())

    def test_extra_final_member_fails_closed_without_cleanup(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        self.publisher.publish(plan)
        extra = plan.final_path / "unexpected"
        extra.write_bytes(b"preserve-as-evidence")
        extra.chmod(0o600)

        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "unexpected review snapshot member",
        ):
            self.publisher.publish(plan)

        self.assertEqual(extra.read_bytes(), b"preserve-as-evidence")

    def test_staged_hardlink_member_fails_closed(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        self.root.mkdir(mode=0o700)
        plan.staging_path.mkdir(mode=0o700)
        staged_snapshot = plan.staging_path / "snapshot.json"
        staged_snapshot.write_bytes(plan.snapshot_payload)
        staged_snapshot.chmod(0o600)
        external_link = Path(self.temporary.name).resolve() / "snapshot-hardlink"
        os.link(staged_snapshot, external_link)

        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "link count",
        ):
            self.publisher.publish(plan)

        self.assertEqual(staged_snapshot.read_bytes(), plan.snapshot_payload)
        self.assertEqual(external_link.read_bytes(), plan.snapshot_payload)

    def test_plan_rejects_review_source_id_mismatch(self):
        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "review source id",
        ):
            self.publisher.plan(
                snapshot_id="snapshot-001",
                snapshot_payload=self.snapshot_bytes,
                review_document=replace(
                    self.document,
                    source_id="snapshot-other",
                ),
            )

    def test_publish_rejects_forged_plan_review_source_id(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        forged_artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            replace(self.document, source_id="snapshot-other")
        )

        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "source id",
        ):
            self.publisher.publish(
                replace(plan, review_artifacts=forged_artifacts)
            )

    def test_publish_rejects_forged_plan_artifact_type_at_public_boundary(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )

        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "artifact type",
        ):
            self.publisher.publish(replace(plan, review_artifacts=None))

    def test_retry_rejects_review_directory_that_is_not_mode_0700(self):
        plan = self.publisher.plan(
            snapshot_id="snapshot-001",
            snapshot_payload=self.snapshot_bytes,
            review_document=self.document,
        )
        self.publisher.publish(plan)
        review_directory = plan.final_path / "review"
        review_directory.chmod(0o755)

        with self.assertRaisesRegex(
            review_snapshot.ReviewSnapshotError,
            "mode 0700",
        ):
            self.publisher.publish(plan)


if __name__ == "__main__":
    unittest.main()
