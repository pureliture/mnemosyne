import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import review_compiler, review_package  # noqa: E402


def review_artifacts():
    document = review_compiler.ReviewDocument(
        review_kind="run-overview",
        source_kind="inventory-run",
        source_id="run-package-001",
        source_snapshot_sha256="a" * 64,
        rendered_at="2026-07-15T01:00:00Z",
        campaign_id=None,
        batch_id=None,
        snapshot_id=None,
        snapshot_version=None,
        policy_binding="generation=1;source=INITIAL/polrun-001;guard=0",
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
        bounds=None,
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
                document_role="docs",
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
    return review_compiler.ReviewCompiler("renderer-v1").compile(document)


def identities(directory):
    return {
        name: (
            (directory / name).stat().st_dev,
            (directory / name).stat().st_ino,
            (directory / name).stat().st_mtime_ns,
            (directory / name).read_bytes(),
        )
        for name in review_package.REVIEW_PACKAGE_FILENAMES
    }


class ReviewPackageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temporary.name).resolve()
        self.package = self.root / "owned-staging"
        self.package.mkdir(mode=0o700)
        self.artifacts = review_artifacts()

    def tearDown(self):
        self.temporary.cleanup()

    def validated_payload(self):
        return review_package.ReviewPackagePayload(
            markdown=self.artifacts.markdown,
            html=self.artifacts.html,
            meta_json=self.artifacts.meta_json,
            semantic_json=self.artifacts.semantic_json,
        )

    def validate_payload(self, candidate):
        return review_package._validate_bytes(
            candidate.markdown,
            candidate.html,
            candidate.meta_json,
            expected_source_snapshot_sha256=None,
        )

    def test_write_persists_exact_outputs_and_validation_derives_semantics(self):
        hashes = review_package.write_review_package(
            self.package,
            self.artifacts,
        )

        self.assertEqual(
            sorted(path.name for path in self.package.iterdir()),
            sorted(review_package.REVIEW_PACKAGE_FILENAMES),
        )
        self.assertEqual(
            (self.package / "review.md").read_bytes(),
            self.artifacts.markdown,
        )
        self.assertEqual(
            (self.package / "review.html").read_bytes(),
            self.artifacts.html,
        )
        self.assertEqual(
            (self.package / "review.meta.json").read_bytes(),
            self.artifacts.meta_json,
        )
        self.assertFalse((self.package / "review.semantic.json").exists())
        self.assertEqual(hashes.markdown_sha256, review_compiler.sha256_bytes(self.artifacts.markdown))
        self.assertEqual(hashes.html_sha256, review_compiler.sha256_bytes(self.artifacts.html))
        self.assertEqual(hashes.meta_sha256, review_compiler.sha256_bytes(self.artifacts.meta_json))
        self.assertEqual(hashes.source_snapshot_sha256, "a" * 64)
        self.assertEqual(
            review_package.validate_review_directory(
                self.package,
                expected_source_snapshot_sha256="a" * 64,
            ),
            hashes,
        )

    def test_exact_retry_accepts_existing_bytes_without_replacing_files(self):
        first = review_package.write_review_package(self.package, self.artifacts)
        before = identities(self.package)

        second = review_package.write_review_package(self.package, self.artifacts)

        self.assertEqual(second, first)
        self.assertEqual(identities(self.package), before)

    def test_retry_blocks_different_existing_bytes_and_preserves_them(self):
        existing = self.package / "review.md"
        existing.write_bytes(b"different\n")
        existing.chmod(0o600)
        before = existing.stat()

        with self.assertRaisesRegex(
            review_package.ReviewPackageError,
            "existing review.md bytes differ",
        ):
            review_package.write_review_package(self.package, self.artifacts)

        after = existing.stat()
        self.assertEqual(existing.read_bytes(), b"different\n")
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(sorted(path.name for path in self.package.iterdir()), ["review.md"])

    def test_dedicated_review_directory_rejects_unrelated_entry_before_write(self):
        (self.package / "unowned.txt").write_text("unexpected", encoding="utf-8")

        with self.assertRaisesRegex(
            review_package.ReviewPackageError,
            "unexpected review package entry",
        ):
            review_package.write_review_package(self.package, self.artifacts)

        self.assertEqual(
            sorted(path.name for path in self.package.iterdir()),
            ["unowned.txt"],
        )

    def test_review_package_can_be_nested_below_batch_snapshot_files(self):
        batch = self.root / "batch-snapshot"
        batch.mkdir(mode=0o700)
        snapshot = batch / "snapshot.json"
        snapshot.write_bytes(b"sealed batch bytes\n")
        review = batch / "review"
        review.mkdir(mode=0o700)

        review_package.write_review_package(review, self.artifacts)

        self.assertEqual(snapshot.read_bytes(), b"sealed batch bytes\n")
        self.assertEqual(
            sorted(path.name for path in batch.iterdir()),
            ["review", "snapshot.json"],
        )
        self.assertEqual(
            sorted(path.name for path in review.iterdir()),
            sorted(review_package.REVIEW_PACKAGE_FILENAMES),
        )

    def test_validation_rejects_missing_extra_symlink_and_nonregular_entries(self):
        review_package.write_review_package(self.package, self.artifacts)
        (self.package / "review.html").unlink()
        with self.assertRaisesRegex(review_package.ReviewPackageError, "missing"):
            review_package.validate_review_directory(self.package)

        (self.package / "review.html").write_bytes(self.artifacts.html)
        (self.package / "review.html").chmod(0o600)
        (self.package / "extra").write_bytes(b"x")
        with self.assertRaisesRegex(review_package.ReviewPackageError, "unexpected"):
            review_package.validate_review_directory(self.package)
        (self.package / "extra").unlink()

        outside = self.root / "outside.html"
        outside.write_bytes(self.artifacts.html)
        (self.package / "review.html").unlink()
        (self.package / "review.html").symlink_to(outside)
        outside_before = outside.read_bytes()
        with self.assertRaisesRegex(review_package.ReviewPackageError, "regular file"):
            review_package.validate_review_directory(self.package)
        self.assertEqual(outside.read_bytes(), outside_before)

        (self.package / "review.html").unlink()
        os.mkfifo(self.package / "review.html", mode=0o600)
        with self.assertRaisesRegex(review_package.ReviewPackageError, "regular file"):
            review_package.validate_review_directory(self.package)

    def test_validation_is_read_only_and_binds_expected_source_snapshot(self):
        review_package.write_review_package(self.package, self.artifacts)
        before = identities(self.package)

        with self.assertRaisesRegex(
            review_package.ReviewPackageError,
            "source snapshot hash mismatch",
        ):
            review_package.validate_review_directory(
                self.package,
                expected_source_snapshot_sha256="b" * 64,
            )

        self.assertEqual(identities(self.package), before)

    def test_validation_rejects_semantic_tamper_without_rewriting(self):
        review_package.write_review_package(self.package, self.artifacts)
        html_path = self.package / "review.html"
        tampered = self.artifacts.html.replace(b"unit-alpha", b"unit-forged", 1)
        html_path.write_bytes(tampered)
        html_path.chmod(0o600)
        before = html_path.read_bytes()

        with self.assertRaises(review_package.ReviewPackageError):
            review_package.validate_review_directory(self.package)

        self.assertEqual(html_path.read_bytes(), before)

    def test_writer_uses_exclusive_creation_for_every_new_artifact(self):
        real_open = os.open
        create_flags = {}

        def observe_open(path, flags, *args, **kwargs):
            if path in review_package.REVIEW_PACKAGE_FILENAMES and flags & os.O_CREAT:
                create_flags[path] = flags
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(review_package.os, "open", side_effect=observe_open):
            review_package.write_review_package(self.package, self.artifacts)

        self.assertEqual(set(create_flags), {"review.md", "review.html"})
        for flags in create_flags.values():
            self.assertTrue(flags & os.O_EXCL)
            if hasattr(os, "O_NOFOLLOW"):
                self.assertTrue(flags & os.O_NOFOLLOW)

    def test_validated_writer_exposes_only_verified_bodies_before_final_meta_seal(self):
        observed = []
        creation_order = []
        real_create = review_package._create_artifact_no_replace

        def observe_create(directory_fd, name, encoded):
            creation_order.append(name)
            return real_create(directory_fd, name, encoded)

        def before_final_seal():
            observed.append(sorted(path.name for path in self.package.iterdir()))
            with self.assertRaisesRegex(
                review_package.ReviewPackageError,
                "review package artifact is missing: review.meta.json",
            ):
                review_package.read_review_package_payload(
                    self.package,
                    derive_semantic=review_compiler.semantic_json_from_markdown,
                )

        with mock.patch.object(
            review_package,
            "_create_artifact_no_replace",
            side_effect=observe_create,
        ):
            result = review_package.write_validated_review_package(
                self.package,
                self.validated_payload(),
                validate=self.validate_payload,
                before_final_seal=before_final_seal,
            )

        self.assertEqual(creation_order, ["review.md", "review.html"])
        self.assertEqual(observed, [["review.html", "review.md"]])
        self.assertEqual(
            result,
            review_package.validate_review_directory(self.package),
        )

    def test_pre_final_seal_failure_leaves_only_bodies_and_readers_reject(self):
        def abort_before_final_seal():
            raise RuntimeError("simulated crash before final seal")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            review_package.write_validated_review_package(
                self.package,
                self.validated_payload(),
                validate=self.validate_payload,
                before_final_seal=abort_before_final_seal,
            )

        self.assertEqual(
            sorted(path.name for path in self.package.iterdir()),
            ["review.html", "review.md"],
        )
        for reader in (
            lambda: review_package.read_review_package_payload(
                self.package,
                derive_semantic=review_compiler.semantic_json_from_markdown,
            ),
            lambda: review_package.validate_review_directory(self.package),
        ):
            with self.assertRaisesRegex(
                review_package.ReviewPackageError,
                "review package artifact is missing: review.meta.json",
            ):
                reader()

    def test_retry_completes_body_only_package_without_replacing_bodies(self):
        with self.assertRaises(RuntimeError):
            review_package.write_validated_review_package(
                self.package,
                self.validated_payload(),
                validate=self.validate_payload,
                before_final_seal=lambda: (_ for _ in ()).throw(RuntimeError()),
            )
        body_before = {
            name: (
                (self.package / name).stat().st_dev,
                (self.package / name).stat().st_ino,
                (self.package / name).stat().st_mtime_ns,
                (self.package / name).read_bytes(),
            )
            for name in ("review.md", "review.html")
        }

        result = review_package.write_validated_review_package(
            self.package,
            self.validated_payload(),
            validate=self.validate_payload,
        )

        self.assertEqual(
            {
                name: (
                    (self.package / name).stat().st_dev,
                    (self.package / name).stat().st_ino,
                    (self.package / name).stat().st_mtime_ns,
                    (self.package / name).read_bytes(),
                )
                for name in ("review.md", "review.html")
            },
            body_before,
        )
        self.assertEqual(result, review_package.validate_review_directory(self.package))

    def test_retry_rejects_different_existing_final_meta_bytes(self):
        payload = self.validated_payload()
        (self.package / "review.md").write_bytes(payload.markdown)
        (self.package / "review.md").chmod(0o600)
        (self.package / "review.html").write_bytes(payload.html)
        (self.package / "review.html").chmod(0o600)
        meta = self.package / "review.meta.json"
        meta.write_bytes(b"different meta\\n")
        meta.chmod(0o600)
        before = meta.stat()

        with self.assertRaisesRegex(
            review_package.ReviewPackageError,
            "existing review.meta.json bytes differ",
        ):
            review_package.write_validated_review_package(
                self.package,
                payload,
                validate=self.validate_payload,
            )

        after = meta.stat()
        self.assertEqual(meta.read_bytes(), b"different meta\\n")
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))

    def test_size_limits_block_write_and_bound_read_only_validation(self):
        markdown_limit = len(self.artifacts.markdown) - 1
        with mock.patch.dict(
            review_package._MAX_ARTIFACT_BYTES,
            {"review.md": markdown_limit},
            clear=False,
        ):
            with self.assertRaisesRegex(
                review_package.ReviewPackageError,
                "exceeds size limit: review.md",
            ):
                review_package.write_review_package(self.package, self.artifacts)
        self.assertEqual(list(self.package.iterdir()), [])

        review_package.write_review_package(self.package, self.artifacts)
        before = identities(self.package)
        with mock.patch.dict(
            review_package._MAX_ARTIFACT_BYTES,
            {"review.md": markdown_limit},
            clear=False,
        ):
            with self.assertRaisesRegex(
                review_package.ReviewPackageError,
                "exceeds size limit: review.md",
            ):
                review_package.validate_review_directory(self.package)
        self.assertEqual(identities(self.package), before)

    def test_writer_requires_compiler_artifacts_and_accepts_no_private_body(self):
        private_input = {
            "artifacts": self.artifacts,
            "private_body": "must never cross this boundary",
        }

        with self.assertRaisesRegex(TypeError, "ReviewArtifacts"):
            review_package.write_review_package(self.package, private_input)

        self.assertEqual(list(self.package.iterdir()), [])

        forged_semantic = replace(
            self.artifacts,
            semantic_json=b'{"private_body":"must never cross this boundary"}\n',
        )
        with self.assertRaisesRegex(
            review_package.ReviewPackageError,
            "semantic manifest differs",
        ):
            review_package.write_review_package(self.package, forged_semantic)
        self.assertEqual(list(self.package.iterdir()), [])

    def test_directory_must_exist_and_be_owner_only(self):
        missing = self.root / "missing"
        with self.assertRaises(review_package.ReviewPackageError):
            review_package.write_review_package(missing, self.artifacts)
        self.assertFalse(missing.exists())

        self.package.chmod(0o777)
        with self.assertRaisesRegex(review_package.ReviewPackageError, "owner-only"):
            review_package.write_review_package(self.package, self.artifacts)

    def test_outputs_are_owner_only_regular_files(self):
        review_package.write_review_package(self.package, self.artifacts)

        for name in review_package.REVIEW_PACKAGE_FILENAMES:
            info = (self.package / name).lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.getuid())


if __name__ == "__main__":
    unittest.main()
