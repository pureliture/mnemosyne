import json
import os
import sys
import tempfile
import unittest
import stat
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import (  # noqa: E402
    batch_service,
    campaign_ledger,
    m2_publishers,
    review_compiler,
    review_snapshot,
)
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


def make_campaign_draft():
    campaign_bytes = canonical_json_bytes(
        {
            "campaign_id": "campaign-001",
            "kind": "curation-campaign",
            "schema_version": 1,
        }
    )
    binding_bytes = canonical_json_bytes(
        {
            "binding_id": "binding-001",
            "campaign_id": "campaign-001",
            "kind": "campaign-run-binding",
            "schema_version": 1,
        }
    )
    return campaign_ledger.CampaignPublicationDraft(
        campaign_id="campaign-001",
        binding_id="binding-001",
        campaign_path="curation/campaigns/campaign-001/campaign.json",
        binding_path=(
            "curation/campaigns/campaign-001/"
            "run-bindings/binding-001/binding.json"
        ),
        campaign_bytes=campaign_bytes,
        binding_bytes=binding_bytes,
    )


def make_snapshot_payload(
    snapshot_id="snapshot-001",
    campaign_id="campaign-001",
    batch_id=None,
):
    payload = {
        "campaign_id": campaign_id,
        "schema_version": 1,
        "snapshot_id": snapshot_id,
        "structural_approval_ready": False,
    }
    if batch_id is not None:
        payload.update(
            {
                "batch_id": batch_id,
                "batch_version": 1,
                "structural_blocker": "m2-review-only",
            }
        )
    return canonical_json_bytes(payload)


def make_review_document(
    snapshot_payload,
    *,
    snapshot_id="snapshot-001",
    campaign_id="campaign-001",
    batch_id=None,
):
    is_batch = batch_id is not None
    return review_compiler.ReviewDocument(
        review_kind="batch-preview" if is_batch else "run-overview",
        source_kind="batch-snapshot" if is_batch else "campaign-snapshot",
        source_id=snapshot_id,
        source_snapshot_sha256=sha256_bytes(snapshot_payload),
        rendered_at="2026-07-15T01:00:00Z",
        campaign_id=campaign_id,
        batch_id=batch_id,
        snapshot_id=snapshot_id,
        snapshot_version=1,
        policy_binding="generation=1;source=INITIAL/policy-run-001;guard=0",
        coverage=review_compiler.CoverageSummary(
            folders_total=0,
            folders_traversed=0,
            folders_excluded=0,
            folders_error=0,
            files_total=0,
            files_inspected=0,
            files_metadata_only=0,
            files_excluded=0,
            files_error=0,
        ),
        bounds=(
            review_compiler.ReviewBounds(
                review_items=0,
                underlying_files=0,
                total_bytes=0,
                leaf_folders=0,
                effect_count=0,
            )
            if is_batch
            else None
        ),
        workstreams=(),
        items=(),
        warning_codes=(),
    )


def make_root_integration_draft():
    payload = make_snapshot_payload()
    return campaign_ledger.RootIntegrationDraft(
        campaign_id="campaign-001",
        binding_id="binding-001",
        integration_id="integration-001",
        submission_id="submission-001",
        snapshot_id="snapshot-001",
        snapshot_path=(
            "curation/campaigns/campaign-001/snapshots/snapshot-001"
        ),
        snapshot_payload_json=payload,
    )


def make_snapshot_publication(snapshot_root):
    payload = make_snapshot_payload(batch_id="batch-001")
    return batch_service.SnapshotPublication(
        snapshot_id="snapshot-001",
        batch_id="batch-001",
        version=1,
        canonical_payload=payload,
        snapshot_sha256=sha256_bytes(payload),
        final_path=snapshot_root / "snapshot-001",
        structural_approval_ready=False,
        structural_blocker="m2-review-only",
    )


class CampaignArtifactPublisherTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.control_root = Path(self.temporary.name).resolve() / "control"

    def test_plan_binds_canonical_paths_and_bytes_without_writes(self):
        draft = make_campaign_draft()
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)

        plan = publisher.plan(draft)

        self.assertEqual(
            plan,
            campaign_ledger.CampaignPublicationPlan(
                campaign_path=draft.campaign_path,
                campaign_bytes=draft.campaign_bytes,
                campaign_sha256=sha256_bytes(draft.campaign_bytes),
                binding_path=draft.binding_path,
                binding_bytes=draft.binding_bytes,
                binding_sha256=sha256_bytes(draft.binding_bytes),
            ),
        )
        self.assertFalse(self.control_root.exists())

    def test_plan_requires_exact_campaign_draft_type(self):
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)

        with self.assertRaisesRegex(
            TypeError,
            "CampaignPublicationDraft",
        ):
            publisher.plan(object())

    def test_plan_rejects_path_traversal_before_writing(self):
        draft = replace(
            make_campaign_draft(),
            campaign_path="../campaign.json",
        )
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)

        with self.assertRaisesRegex(
            campaign_ledger.CampaignLedgerError,
            "canonical relative path",
        ):
            publisher.plan(draft)

        self.assertFalse(self.control_root.exists())

    def test_plan_requires_paths_to_bind_artifact_names_and_draft_ids(self):
        draft = make_campaign_draft()
        invalid_drafts = (
            replace(
                draft,
                campaign_path="curation/campaigns/other/campaign.json",
            ),
            replace(
                draft,
                campaign_path="curation/campaigns/campaign-001/campaign.txt",
            ),
            replace(
                draft,
                binding_path=(
                    "curation/campaigns/campaign-001/"
                    "run-bindings/other/binding.json"
                ),
            ),
            replace(
                draft,
                binding_path=(
                    "curation/campaigns/campaign-001/"
                    "bindings/binding-001/binding.json"
                ),
            ),
        )
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)

        for invalid in invalid_drafts:
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    campaign_ledger.CampaignLedgerError,
                    "does not bind draft identity",
                ):
                    publisher.plan(invalid)

        self.assertFalse(self.control_root.exists())

    def test_plan_requires_canonical_payloads_bound_to_draft_ids(self):
        draft = make_campaign_draft()
        invalid_drafts = (
            replace(
                draft,
                campaign_bytes=b'{"campaign_id": "campaign-001"}\n',
            ),
            replace(
                draft,
                campaign_bytes=canonical_json_bytes(
                    {"campaign_id": "other", "kind": "curation-campaign"}
                ),
            ),
            replace(
                draft,
                binding_bytes=canonical_json_bytes(
                    {
                        "binding_id": "other",
                        "campaign_id": "campaign-001",
                        "kind": "campaign-run-binding",
                    }
                ),
            ),
        )
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)

        for invalid in invalid_drafts:
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    campaign_ledger.CampaignLedgerError,
                    "canonical JSON and draft identity",
                ):
                    publisher.plan(invalid)

        self.assertFalse(self.control_root.exists())

    def test_publish_creates_owner_only_exact_artifacts_and_readback_result(self):
        draft = make_campaign_draft()
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(draft)

        result = publisher.publish(plan)

        self.assertEqual(
            result,
            campaign_ledger.CampaignPublishResult(
                campaign_path=plan.campaign_path,
                campaign_sha256=plan.campaign_sha256,
                binding_path=plan.binding_path,
                binding_sha256=plan.binding_sha256,
            ),
        )
        campaign_path = self.control_root / plan.campaign_path
        binding_path = self.control_root / plan.binding_path
        self.assertEqual(campaign_path.read_bytes(), plan.campaign_bytes)
        self.assertEqual(binding_path.read_bytes(), plan.binding_bytes)
        self.assertEqual(stat.S_IMODE(campaign_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(binding_path.stat().st_mode), 0o600)
        for directory in (
            self.control_root,
            campaign_path.parent,
            binding_path.parent.parent,
            binding_path.parent,
        ):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_exact_retry_preserves_inode_mtime_and_bytes(self):
        draft = make_campaign_draft()
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(draft)
        publisher.publish(plan)
        paths = (
            self.control_root / plan.campaign_path,
            self.control_root / plan.binding_path,
        )
        before = tuple(
            (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            for path in paths
        )

        result = publisher.publish(plan)

        after = tuple(
            (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            for path in paths
        )
        self.assertEqual(after, before)
        self.assertEqual(result.campaign_sha256, plan.campaign_sha256)
        self.assertEqual(result.binding_sha256, plan.binding_sha256)

    def test_partial_retry_preserves_existing_campaign_and_finishes_binding(self):
        draft = make_campaign_draft()
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(draft)
        publisher.publish(plan)
        campaign_path = self.control_root / plan.campaign_path
        binding_path = self.control_root / plan.binding_path
        binding_path.unlink()
        campaign_before = (
            campaign_path.stat().st_ino,
            campaign_path.stat().st_mtime_ns,
            campaign_path.read_bytes(),
        )

        publisher.publish(plan)

        self.assertEqual(
            (
                campaign_path.stat().st_ino,
                campaign_path.stat().st_mtime_ns,
                campaign_path.read_bytes(),
            ),
            campaign_before,
        )
        self.assertEqual(binding_path.read_bytes(), plan.binding_bytes)

    def test_publish_rejects_unexpected_binding_leaf_member(self):
        draft = make_campaign_draft()
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(draft)
        publisher.publish(plan)
        binding_path = self.control_root / plan.binding_path
        unexpected = binding_path.parent / "unexpected.json"
        unexpected.write_bytes(b"not part of the sealed plan")
        before = unexpected.read_bytes()

        with self.assertRaisesRegex(
            campaign_ledger.CampaignLedgerError,
            "unexpected campaign publication member",
        ):
            publisher.publish(plan)

        self.assertEqual(unexpected.read_bytes(), before)

    def test_publish_rejects_unexpected_campaign_namespace_member(self):
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(make_campaign_draft())
        publisher.publish(plan)
        campaign_path = self.control_root / plan.campaign_path
        unexpected = campaign_path.parent / "unexpected.json"
        unexpected.write_bytes(b"not part of the root campaign publication")

        with self.assertRaisesRegex(
            campaign_ledger.CampaignLedgerError,
            "unexpected campaign publication member",
        ):
            publisher.publish(plan)

        self.assertEqual(
            unexpected.read_bytes(),
            b"not part of the root campaign publication",
        )

    def test_publish_rejects_different_existing_bytes_without_repair(self):
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(make_campaign_draft())
        publisher.publish(plan)
        binding_path = self.control_root / plan.binding_path
        binding_path.write_bytes(b"different bytes")

        with self.assertRaisesRegex(
            campaign_ledger.CampaignLedgerError,
            "bytes differ",
        ):
            publisher.publish(plan)

        self.assertEqual(binding_path.read_bytes(), b"different bytes")

    def test_conflicting_partial_state_fails_before_creating_missing_artifact(self):
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(make_campaign_draft())
        publisher.publish(plan)
        campaign_path = self.control_root / plan.campaign_path
        binding_path = self.control_root / plan.binding_path
        campaign_path.unlink()
        binding_path.write_bytes(b"different bytes")

        with self.assertRaisesRegex(
            campaign_ledger.CampaignLedgerError,
            "bytes differ",
        ):
            publisher.publish(plan)

        self.assertFalse(campaign_path.exists())
        self.assertEqual(binding_path.read_bytes(), b"different bytes")

    def test_publish_rejects_symlink_target_without_following_it(self):
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(make_campaign_draft())
        publisher.publish(plan)
        binding_path = self.control_root / plan.binding_path
        outside = self.control_root / "outside.json"
        outside.write_bytes(b"outside")
        binding_path.unlink()
        binding_path.symlink_to(outside)

        with self.assertRaises(campaign_ledger.CampaignLedgerError):
            publisher.publish(plan)

        self.assertTrue(binding_path.is_symlink())
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_publish_rejects_hardlinked_target_without_repair(self):
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(make_campaign_draft())
        publisher.publish(plan)
        binding_path = self.control_root / plan.binding_path
        hardlink = self.control_root / "binding-hardlink.json"
        os.link(binding_path, hardlink)

        with self.assertRaisesRegex(
            campaign_ledger.CampaignLedgerError,
            "link count",
        ):
            publisher.publish(plan)

        self.assertEqual(binding_path.stat().st_ino, hardlink.stat().st_ino)

    def test_publish_rejects_non_owner_only_file_mode_without_repair(self):
        publisher = m2_publishers.CampaignArtifactPublisher(self.control_root)
        plan = publisher.plan(make_campaign_draft())
        publisher.publish(plan)
        binding_path = self.control_root / plan.binding_path
        binding_path.chmod(0o644)

        with self.assertRaisesRegex(
            campaign_ledger.CampaignLedgerError,
            "identity is invalid",
        ):
            publisher.publish(plan)

        self.assertEqual(stat.S_IMODE(binding_path.stat().st_mode), 0o644)


class CampaignReviewPublisherAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.control_root = Path(self.temporary.name).resolve() / "control"
        self.snapshot_root = (
            self.control_root
            / "curation/campaigns/campaign-001/snapshots"
        )
        self.review_publisher = review_snapshot.ReviewSnapshotPublisher(
            self.snapshot_root,
            renderer_id="mnemosyne-review-v1",
        )

    def test_plan_prebinds_review_package_identity_and_paths_without_writes(self):
        draft = make_root_integration_draft()
        adapter = m2_publishers.CampaignReviewPublisherAdapter(
            self.control_root,
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(payload),
        )

        plan = adapter.plan(draft)

        self.assertIs(type(plan), campaign_ledger.RootIntegrationPlan)
        self.assertEqual(plan.final_path, draft.snapshot_path)
        self.assertEqual(plan.snapshot_payload_json, draft.snapshot_payload_json)
        self.assertEqual(
            plan.snapshot_payload_sha256,
            sha256_bytes(draft.snapshot_payload_json),
        )
        self.assertIs(
            type(plan.sealed_payload),
            review_snapshot.ReviewSnapshotPlan,
        )
        self.assertEqual(
            plan.sealed_payload.snapshot_payload,
            draft.snapshot_payload_json,
        )
        self.assertEqual(len(plan.package_sha256), 64)
        plan_value = json.loads(plan.plan_json.decode("utf-8"))
        self.assertEqual(canonical_json_bytes(plan_value), plan.plan_json)
        self.assertEqual(plan_value["snapshot_id"], draft.snapshot_id)
        self.assertEqual(plan_value["final_path"], draft.snapshot_path)
        self.assertEqual(
            plan_value["publisher_final_path"],
            str(self.snapshot_root / draft.snapshot_id),
        )
        self.assertEqual(plan_value["package_sha256"], plan.package_sha256)
        self.assertEqual(len(plan_value["sealed_identity_sha256"]), 64)
        self.assertEqual(
            plan_value["snapshot_payload_sha256"],
            plan.snapshot_payload_sha256,
        )
        self.assertFalse(self.control_root.exists())

    def test_publish_writes_full_review_package_and_returns_campaign_result(self):
        draft = make_root_integration_draft()
        adapter = m2_publishers.CampaignReviewPublisherAdapter(
            self.control_root,
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(payload),
        )
        plan = adapter.plan(draft)

        result = adapter.publish(plan)

        self.assertEqual(
            result,
            campaign_ledger.RootIntegrationPublishResult(
                final_path=plan.final_path,
                package_sha256=plan.package_sha256,
            ),
        )
        final_path = self.snapshot_root / draft.snapshot_id
        self.assertEqual(
            tuple(sorted(path.name for path in final_path.iterdir())),
            ("manifest.json", "review", "snapshot.json"),
        )
        self.assertEqual(
            tuple(sorted(path.name for path in (final_path / "review").iterdir())),
            ("review.html", "review.md", "review.meta.json"),
        )
        self.assertEqual(
            (final_path / "snapshot.json").read_bytes(),
            draft.snapshot_payload_json,
        )
        self.assertEqual(
            sha256_bytes((final_path / "manifest.json").read_bytes()),
            plan.package_sha256,
        )

    def test_publish_uses_prepared_campaign_review_plan_without_replanning(self):
        draft = make_root_integration_draft()
        adapter = m2_publishers.CampaignReviewPublisherAdapter(
            self.control_root,
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(payload),
        )
        plan = adapter.plan(draft)

        with mock.patch.object(
            adapter,
            "_review_plan",
            side_effect=AssertionError("heavy campaign replan under writer"),
        ):
            result = adapter.publish(plan)

        self.assertEqual(result.package_sha256, plan.package_sha256)

    def test_plan_rejects_factory_source_id_or_hash_mismatch(self):
        draft = make_root_integration_draft()
        mismatched_documents = (
            replace(
                make_review_document(draft.snapshot_payload_json),
                source_id="snapshot-other",
            ),
            replace(
                make_review_document(draft.snapshot_payload_json),
                source_snapshot_sha256="f" * 64,
            ),
        )

        for document in mismatched_documents:
            with self.subTest(document=document):
                adapter = m2_publishers.CampaignReviewPublisherAdapter(
                    self.control_root,
                    review_publisher=self.review_publisher,
                    review_document_factory=lambda _payload, value=document: value,
                )
                with self.assertRaisesRegex(
                    campaign_ledger.CampaignLedgerError,
                    "does not bind root integration draft",
                ):
                    adapter.plan(draft)

        self.assertFalse(self.control_root.exists())

    def test_publish_rejects_tampered_package_or_sealed_identity_before_writing(self):
        draft = make_root_integration_draft()
        adapter = m2_publishers.CampaignReviewPublisherAdapter(
            self.control_root,
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(payload),
        )
        plan = adapter.plan(draft)
        plan_value = json.loads(plan.plan_json.decode("utf-8"))
        plan_value["sealed_identity_sha256"] = "f" * 64
        tampered_payload = replace(
            plan.sealed_payload,
            sealed_identity_sha256="f" * 64,
        )
        tampered_plans = (
            replace(plan, package_sha256="f" * 64),
            replace(plan, plan_json=canonical_json_bytes(plan_value)),
            replace(plan, sealed_payload=tampered_payload),
        )

        for tampered in tampered_plans:
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(
                    campaign_ledger.CampaignLedgerError,
                    "does not match sealed package identity",
                ):
                    adapter.publish(tampered)

        self.assertFalse(self.control_root.exists())

    def test_exact_retry_preserves_review_package_members(self):
        draft = make_root_integration_draft()
        adapter = m2_publishers.CampaignReviewPublisherAdapter(
            self.control_root,
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(payload),
        )
        plan = adapter.plan(draft)
        adapter.publish(plan)
        final_path = self.snapshot_root / draft.snapshot_id
        members = (
            final_path / "snapshot.json",
            final_path / "manifest.json",
            final_path / "review/review.md",
            final_path / "review/review.html",
            final_path / "review/review.meta.json",
        )
        before = tuple(
            (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            for path in members
        )

        result = adapter.publish(plan)

        after = tuple(
            (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            for path in members
        )
        self.assertEqual(after, before)
        self.assertEqual(result.package_sha256, plan.package_sha256)


class BatchReviewPublisherAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.snapshot_root = (
            Path(self.temporary.name).resolve() / "control/batch-snapshots"
        )
        self.review_publisher = review_snapshot.ReviewSnapshotPublisher(
            self.snapshot_root,
            renderer_id="mnemosyne-review-v1",
        )

    def test_plan_prebinds_full_review_snapshot_as_batch_sealed_payload(self):
        publication = make_snapshot_publication(self.snapshot_root)
        adapter = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(
                payload,
                batch_id="batch-001",
            ),
        )

        plan = adapter.plan(publication)

        self.assertIs(type(plan), batch_service.SnapshotPublishPlan)
        self.assertEqual(plan.publication, publication)
        self.assertEqual(plan.final_path, publication.final_path)
        self.assertEqual(len(plan.package_sha256), 64)
        self.assertEqual(len(plan.sealed_identity_sha256), 64)
        self.assertIs(type(plan.sealed_payload), review_snapshot.ReviewSnapshotPlan)
        self.assertEqual(plan.sealed_payload.final_path, publication.final_path)
        self.assertEqual(
            plan.sealed_payload.snapshot_sha256,
            publication.snapshot_sha256,
        )
        self.assertEqual(
            plan.sealed_payload.package_sha256,
            plan.package_sha256,
        )
        self.assertEqual(
            plan.sealed_payload.sealed_identity_sha256,
            plan.sealed_identity_sha256,
        )
        self.assertFalse(self.snapshot_root.exists())

    def test_publish_writes_full_review_package_and_returns_batch_result(self):
        publication = make_snapshot_publication(self.snapshot_root)
        adapter = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(
                payload,
                batch_id="batch-001",
            ),
        )
        plan = adapter.plan(publication)

        result = adapter.publish(plan)

        self.assertEqual(
            result,
            batch_service.SnapshotPublishResult(
                final_path=plan.final_path,
                snapshot_sha256=publication.snapshot_sha256,
                package_sha256=plan.package_sha256,
                sealed_identity_sha256=plan.sealed_identity_sha256,
            ),
        )
        self.assertEqual(
            tuple(sorted(path.name for path in publication.final_path.iterdir())),
            ("manifest.json", "review", "snapshot.json"),
        )
        self.assertEqual(
            tuple(
                sorted(
                    path.name
                    for path in (publication.final_path / "review").iterdir()
                )
            ),
            ("review.html", "review.md", "review.meta.json"),
        )
        self.assertEqual(
            (publication.final_path / "snapshot.json").read_bytes(),
            publication.canonical_payload,
        )

    def test_publish_uses_prepared_batch_review_plan_without_replanning(self):
        publication = make_snapshot_publication(self.snapshot_root)
        adapter = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(
                payload,
                batch_id="batch-001",
            ),
        )
        plan = adapter.plan(publication)

        with mock.patch.object(
            adapter,
            "_review_plan",
            side_effect=AssertionError("heavy batch replan under writer"),
        ):
            result = adapter.publish(plan)

        self.assertEqual(result.package_sha256, plan.package_sha256)

    def test_plan_rejects_factory_source_id_or_hash_mismatch(self):
        publication = make_snapshot_publication(self.snapshot_root)
        mismatched_documents = (
            replace(
                make_review_document(
                    publication.canonical_payload,
                    batch_id="batch-001",
                ),
                source_id="snapshot-other",
            ),
            replace(
                make_review_document(
                    publication.canonical_payload,
                    batch_id="batch-001",
                ),
                source_snapshot_sha256="f" * 64,
            ),
        )

        for document in mismatched_documents:
            with self.subTest(document=document):
                adapter = m2_publishers.BatchReviewPublisherAdapter(
                    review_publisher=self.review_publisher,
                    review_document_factory=lambda _payload, value=document: value,
                )
                with self.assertRaisesRegex(
                    batch_service.BatchPublicationError,
                    "does not bind batch publication",
                ):
                    adapter.plan(publication)

        self.assertFalse(self.snapshot_root.exists())

    def test_publish_rejects_tampered_package_or_sealed_payload_before_writing(self):
        publication = make_snapshot_publication(self.snapshot_root)
        adapter = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(
                payload,
                batch_id="batch-001",
            ),
        )
        plan = adapter.plan(publication)
        tampered_payload = replace(
            plan.sealed_payload,
            sealed_identity_sha256="f" * 64,
        )
        tampered_plans = (
            replace(plan, package_sha256="f" * 64),
            replace(plan, sealed_payload=tampered_payload),
        )

        for tampered in tampered_plans:
            with self.subTest(tampered=tampered):
                with self.assertRaisesRegex(
                    batch_service.BatchPublicationError,
                    "does not match sealed package identity",
                ):
                    adapter.publish(tampered)

        self.assertFalse(self.snapshot_root.exists())

    def test_adapter_publishes_full_package_without_staging_residue(self):
        publication = make_snapshot_publication(self.snapshot_root)
        adapter = m2_publishers.BatchReviewPublisherAdapter(
            review_publisher=self.review_publisher,
            review_document_factory=lambda payload: make_review_document(
                payload,
                batch_id="batch-001",
            ),
        )

        plan = adapter.plan(publication)
        result = adapter.publish(plan)

        self.assertEqual(result.package_sha256, plan.package_sha256)
        self.assertFalse(plan.sealed_payload.staging_path.exists())
        self.assertEqual(result.final_path, plan.sealed_payload.final_path)


if __name__ == "__main__":
    unittest.main()
