import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import canonical_json, review_compiler, review_draft  # noqa: E402


def snapshot_fixture():
    snapshot_payload = {
        "approval_ready": False,
        "batch_id": "batch-001",
        "schema_version": 1,
        "snapshot_id": "snapshot-001",
        "structural_approval_ready": False,
        "units": [{"unit_id": "unit-alpha"}],
    }
    snapshot_bytes = canonical_json.canonical_json_bytes(snapshot_payload)
    snapshot_sha256 = canonical_json.sha256_bytes(snapshot_bytes)
    document = review_compiler.ReviewDocument(
        review_kind="batch-preview",
        source_kind="batch-snapshot",
        source_id="snapshot-001",
        source_snapshot_sha256=snapshot_sha256,
        rendered_at="2026-07-15T00:00:00Z",
        campaign_id="campaign-001",
        batch_id="batch-001",
        snapshot_id="snapshot-001",
        snapshot_version=1,
        policy_binding="generation=1;source=INITIAL/polrun-001;guard=0",
        coverage=review_compiler.CoverageSummary(
            folders_total=0,
            folders_traversed=0,
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
            total_bytes=10,
            leaf_folders=0,
            effect_count=1,
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
                document_role="docs",
                authority="reference",
                document_lifecycle="current",
                scope_class="active-workstream-content",
                sensitivity="public",
                access_domain="default",
                recommended_action="move",
                target_path="organized/alpha/spec.md",
                risk_band="low",
                context_freshness="fresh",
                evidence_providers=("path-pattern",),
                warning_codes=(),
                effect_codes=("plan-unavailable-m2",),
            ),
        ),
        warning_codes=("m2-no-structural-authority",),
    )
    artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(document)
    return review_draft.TrustedReviewSnapshot(
        snapshot_id="snapshot-001",
        snapshot_sha256=snapshot_sha256,
        snapshot_bytes=snapshot_bytes,
        review_markdown=artifacts.markdown,
        review_markdown_sha256=canonical_json.sha256_bytes(artifacts.markdown),
    )


def replace_marker(markdown, *, unit_id, field, before, after):
    old = canonical_json.canonical_json_bytes(
        {"field": field, "unit_id": unit_id, "value": before}
    ).rstrip(b"\n")
    new = canonical_json.canonical_json_bytes(
        {"field": field, "unit_id": unit_id, "value": after}
    ).rstrip(b"\n")
    if markdown.count(old) != 1:
        raise AssertionError("test marker was not unique")
    return markdown.replace(old, new, 1)


class ReviewDraftTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.drafts_root = self.root / "curation" / "drafts"
        self.snapshot = snapshot_fixture()
        self.request = review_draft.ReviewDraftRequest(
            draft_id="draft-001",
            base_snapshot_id=self.snapshot.snapshot_id,
            base_snapshot_sha256=self.snapshot.snapshot_sha256,
            actor="reviewer@example.test",
        )
        self.loader_calls = []

        def loader(snapshot_id, snapshot_sha256):
            self.loader_calls.append((snapshot_id, snapshot_sha256))
            return self.snapshot

        self.loader = loader

    def tearDown(self):
        self.temp.cleanup()

    def checkout(self):
        return review_draft.checkout_review(
            self.request,
            drafts_root=self.drafts_root,
            snapshot_loader=self.loader,
        )

    def load(self):
        return review_draft.validate_review_draft(
            self.request,
            drafts_root=self.drafts_root,
            snapshot_loader=self.loader,
        )

    def test_validate_review_draft_is_the_only_public_existing_draft_reader(self):
        self.assertFalse(hasattr(review_draft, "load_review_draft"))
        self.assertNotIn("load_review_draft", review_draft.__all__)
        self.assertIn("validate_review_draft", review_draft.__all__)

    def test_checkout_seals_owner_only_non_authoritative_draft_without_touching_snapshot(self):
        original_snapshot = self.snapshot.snapshot_bytes
        result = self.checkout()

        self.assertEqual(result.path, self.drafts_root / "draft-001")
        self.assertFalse(result.authority)
        self.assertFalse(result.approval_ready)
        self.assertEqual(result.base_snapshot_sha256, self.snapshot.snapshot_sha256)
        self.assertEqual(self.snapshot.snapshot_bytes, original_snapshot)
        self.assertFalse((self.drafts_root / ".incomplete-draft-001").exists())
        self.assertEqual(
            sorted(path.name for path in result.path.iterdir()),
            ["draft.json", "review.draft.md"],
        )
        self.assertEqual(stat.S_IMODE(result.path.stat().st_mode), 0o700)
        for name in ("draft.json", "review.draft.md"):
            info = (result.path / name).stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual(info.st_nlink, 1)
        manifest_bytes = (result.path / "draft.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        self.assertEqual(
            canonical_json.canonical_json_bytes(manifest),
            manifest_bytes,
        )
        self.assertFalse(manifest["authority"])
        self.assertFalse(manifest["approval_ready"])
        self.assertEqual(manifest["item_ids"], ["unit-alpha"])
        self.assertIn(
            b"[draft-notice:non-authoritative]",
            (result.path / "review.draft.md").read_bytes(),
        )
        self.assertTrue(
            (result.path / "review.draft.md")
            .read_bytes()
            .startswith(self.snapshot.review_markdown)
        )

    def test_exact_checkout_retry_is_idempotent_but_edited_bytes_are_not_republished(self):
        first = self.checkout()
        second = self.checkout()
        self.assertEqual(second.current_markdown_sha256, first.current_markdown_sha256)

        draft_path = first.path / "review.draft.md"
        edited = replace_marker(
            draft_path.read_bytes(),
            unit_id="unit-alpha",
            field="decision",
            before="pending",
            after="keep",
        )
        draft_path.write_bytes(edited)
        loaded = self.load()
        self.assertEqual(loaded.edits[0].decision, "keep")
        with self.assertRaisesRegex(review_draft.ReviewDraftConflict, "different bytes"):
            self.checkout()

    def test_rename_collision_never_reports_success_with_retained_staging(self):
        staging = self.drafts_root / ".incomplete-draft-001"
        final = self.drafts_root / "draft-001"

        def publish_competing_exact_final(source, target, **_kwargs):
            shutil.copytree(source, target)
            raise review_draft.ReviewDraftConflict(
                "review draft final path already exists"
            )

        with mock.patch.object(
            review_draft.safety,
            "rename_path_no_replace",
            side_effect=publish_competing_exact_final,
        ):
            with self.assertRaisesRegex(
                review_draft.ReviewDraftConflict,
                "conflicting review draft staging exists beside final package",
            ):
                self.checkout()

        self.assertTrue(final.is_dir())
        self.assertTrue(staging.is_dir())

    def test_allowed_correction_markers_parse_to_typed_non_authoritative_edits(self):
        result = self.checkout()
        path = result.path / "review.draft.md"
        edited = replace_marker(
            path.read_bytes(),
            unit_id="unit-alpha",
            field="decision",
            before="pending",
            after="correction",
        )
        edited = replace_marker(
            edited,
            unit_id="unit-alpha",
            field="correction.primary_workstream",
            before="unchanged",
            after="beta",
        )
        edited = replace_marker(
            edited,
            unit_id="unit-alpha",
            field="correction.target_path",
            before="unchanged",
            after="organized/beta/spec.md",
        )
        path.write_bytes(edited)

        loaded = review_draft.validate_review_draft(
            self.request,
            drafts_root=self.drafts_root,
            snapshot_loader=self.loader,
        )

        self.assertFalse(loaded.authority)
        self.assertFalse(loaded.approval_ready)
        self.assertEqual(loaded.edits[0].decision, "correction")
        self.assertEqual(
            loaded.edits[0].corrections,
            (
                ("primary_workstream", "beta"),
                ("target_path", "organized/beta/spec.md"),
            ),
        )

    def test_invalid_marker_value_raw_html_and_nonmarker_edit_are_rejected(self):
        result = self.checkout()
        path = result.path / "review.draft.md"
        original = path.read_bytes()
        invalid = replace_marker(
            original,
            unit_id="unit-alpha",
            field="decision",
            before="pending",
            after="delete-everything",
        )
        path.write_bytes(invalid)
        with self.assertRaisesRegex(review_draft.ReviewDraftValidationError, "decision"):
            self.load()

        path.write_bytes(original + b"<script>alert(1)</script>\n")
        with self.assertRaisesRegex(review_draft.ReviewDraftValidationError, "raw HTML"):
            self.load()

        path.write_bytes(original.replace(b"## Coverage", b"## Hidden Coverage", 1))
        with self.assertRaisesRegex(review_draft.ReviewDraftValidationError, "non-marker"):
            self.load()

    def test_correction_markers_and_decision_must_be_consistent(self):
        result = self.checkout()
        path = result.path / "review.draft.md"
        original = path.read_bytes()
        changed_without_decision = replace_marker(
            original,
            unit_id="unit-alpha",
            field="correction.primary_workstream",
            before="unchanged",
            after="beta",
        )
        path.write_bytes(changed_without_decision)
        with self.assertRaisesRegex(
            review_draft.ReviewDraftValidationError,
            "corrections require",
        ):
            self.load()

        correction_without_change = replace_marker(
            original,
            unit_id="unit-alpha",
            field="decision",
            before="pending",
            after="correction",
        )
        path.write_bytes(correction_without_change)
        with self.assertRaisesRegex(
            review_draft.ReviewDraftValidationError,
            "requires at least one",
        ):
            self.load()

    def test_hidden_row_membership_or_base_identity_changes_are_rejected(self):
        result = self.checkout()
        path = result.path / "review.draft.md"
        original = path.read_bytes()

        path.write_bytes(original.replace(b"unit-alpha", b"unit-hidden", 1))
        with self.assertRaises(review_draft.ReviewDraftValidationError):
            self.load()

        extra_marker = canonical_json.canonical_json_bytes(
            {
                "field": "decision",
                "unit_id": "unit-hidden",
                "value": "pending",
            }
        ).rstrip(b"\n")
        path.write_bytes(original + b"- [mnemosyne-draft-field-v1] " + extra_marker + b"\n")
        with self.assertRaisesRegex(review_draft.ReviewDraftValidationError, "membership"):
            self.load()

        path.write_bytes(
            original.replace(
                self.snapshot.snapshot_sha256.encode("ascii"),
                ("f" * 64).encode("ascii"),
                1,
            )
        )
        with self.assertRaises(review_draft.ReviewDraftValidationError):
            self.load()

    def test_draft_json_identity_manipulation_and_extra_files_are_rejected(self):
        result = self.checkout()
        manifest_path = result.path / "draft.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["owner_actor"] = "attacker@example.test"
        manifest_path.write_bytes(canonical_json.canonical_json_bytes(manifest))
        with self.assertRaisesRegex(review_draft.ReviewDraftConflict, "identity"):
            self.load()

        manifest["owner_actor"] = self.request.actor
        manifest_path.write_bytes(canonical_json.canonical_json_bytes(manifest))
        (result.path / "hidden.txt").write_text("hidden", encoding="utf-8")
        with self.assertRaisesRegex(review_draft.ReviewDraftValidationError, "members"):
            self.load()

    def test_symlink_member_and_mismatched_staging_retry_are_rejected(self):
        result = self.checkout()
        review_path = result.path / "review.draft.md"
        target = self.root / "outside.md"
        target.write_text("outside", encoding="utf-8")
        review_path.unlink()
        review_path.symlink_to(target)
        with self.assertRaisesRegex(review_draft.ReviewDraftValidationError, "identity"):
            self.load()
        self.assertEqual(target.read_text(encoding="utf-8"), "outside")

        other_request = review_draft.ReviewDraftRequest(
            draft_id="draft-002",
            base_snapshot_id=self.snapshot.snapshot_id,
            base_snapshot_sha256=self.snapshot.snapshot_sha256,
            actor=self.request.actor,
        )
        staging = self.drafts_root / ".incomplete-draft-002"
        staging.mkdir(mode=0o700)
        (staging / "review.draft.md").write_bytes(b"wrong\n")
        os.chmod(staging / "review.draft.md", 0o600)
        with self.assertRaisesRegex(review_draft.ReviewDraftConflict, "different bytes"):
            review_draft.checkout_review(
                other_request,
                drafts_root=self.drafts_root,
                snapshot_loader=self.loader,
            )
        self.assertEqual((staging / "review.draft.md").read_bytes(), b"wrong\n")
        self.assertFalse((staging / "draft.json").exists())

    def test_loader_mismatch_is_rejected_before_draft_write(self):
        wrong = review_draft.TrustedReviewSnapshot(
            snapshot_id="snapshot-other",
            snapshot_sha256=self.snapshot.snapshot_sha256,
            snapshot_bytes=self.snapshot.snapshot_bytes,
            review_markdown=self.snapshot.review_markdown,
            review_markdown_sha256=self.snapshot.review_markdown_sha256,
        )
        with self.assertRaisesRegex(review_draft.ReviewDraftConflict, "loader"):
            review_draft.checkout_review(
                self.request,
                drafts_root=self.drafts_root,
                snapshot_loader=lambda _id, _sha: wrong,
            )
        self.assertFalse(self.drafts_root.exists())

    def test_draft_read_is_bounded_before_opening_content(self):
        result = self.checkout()

        with mock.patch.dict(
            review_draft._MAX_DRAFT_FILE_BYTES,
            {"review.draft.md": 16},
        ):
            with self.assertRaisesRegex(
                review_draft.ReviewDraftValidationError,
                "exceeds size limit",
            ):
                self.load()

        self.assertTrue((result.path / "review.draft.md").is_file())

    def test_draft_read_rejects_same_inode_content_change(self):
        result = self.checkout()
        path = result.path / "review.draft.md"
        original = path.read_bytes()
        original_read = os.read
        target_identity = (path.stat().st_dev, path.stat().st_ino)
        changed = False

        def change_after_first_chunk(descriptor, size):
            nonlocal changed
            chunk = original_read(descriptor, size)
            opened = os.fstat(descriptor)
            if (
                chunk
                and not changed
                and (opened.st_dev, opened.st_ino) == target_identity
            ):
                changed = True
                path.write_bytes(b"X" + original[1:])
            return chunk

        with mock.patch.object(
            review_draft.os,
            "read",
            side_effect=change_after_first_chunk,
        ):
            with self.assertRaisesRegex(
                review_draft.ReviewDraftValidationError,
                "changed while read",
            ):
                self.load()


if __name__ == "__main__":
    unittest.main()
