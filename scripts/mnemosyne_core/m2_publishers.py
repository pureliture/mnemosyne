"""Bounded M2 campaign and review snapshot publication adapters."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Callable, Dict

from . import batch_service, campaign_ledger, review_compiler, review_snapshot, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


def _prepared_review_plan(
    value: object,
    *,
    publisher: review_snapshot.ReviewSnapshotPublisher,
    snapshot_id: str,
    snapshot_payload: bytes,
    final_path: Path,
    error_type: Callable[[str], Exception],
    error_message: str,
) -> review_snapshot.ReviewSnapshotPlan:
    """Validate one already-rendered immutable plan without regenerating it."""

    if type(value) is not review_snapshot.ReviewSnapshotPlan or (
        publisher.snapshot_root != final_path.parent
        or value.snapshot_id != snapshot_id
        or value.staging_path
        != final_path.parent / (".incomplete-%s" % snapshot_id)
        or value.final_path != final_path
        or value.snapshot_payload != snapshot_payload
        or value.snapshot_sha256 != sha256_bytes(snapshot_payload)
    ):
        raise error_type(error_message)
    return value


def _canonical_relative_path(value: str, label: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 0x20 for character in value)
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise campaign_ledger.CampaignLedgerError(
            "%s must be a canonical relative path" % label
        )
    path = PurePosixPath(value)
    if str(path) != value:
        raise campaign_ledger.CampaignLedgerError(
            "%s must be a canonical relative path" % label
        )
    return path


def _validate_campaign_paths(
    draft: campaign_ledger.CampaignPublicationDraft,
) -> None:
    campaign_path = _canonical_relative_path(
        draft.campaign_path,
        "campaign_path",
    )
    binding_path = _canonical_relative_path(
        draft.binding_path,
        "binding_path",
    )
    if (
        campaign_path.name != "campaign.json"
        or campaign_path.parent.name != draft.campaign_id
        or binding_path.name != "binding.json"
        or binding_path.parent.name != draft.binding_id
        or binding_path.parent.parent.name != "run-bindings"
        or binding_path.parent.parent.parent != campaign_path.parent
    ):
        raise campaign_ledger.CampaignLedgerError(
            "campaign publication path does not bind draft identity"
        )


def _canonical_object(raw: bytes) -> Dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise campaign_ledger.CampaignLedgerError(
            "campaign artifacts must be canonical JSON and draft identity bound"
        ) from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise campaign_ledger.CampaignLedgerError(
            "campaign artifacts must be canonical JSON and draft identity bound"
        )
    return value


def _validate_campaign_payloads(
    draft: campaign_ledger.CampaignPublicationDraft,
) -> None:
    campaign = _canonical_object(draft.campaign_bytes)
    binding = _canonical_object(draft.binding_bytes)
    if (
        campaign.get("campaign_id") != draft.campaign_id
        or campaign.get("kind") != "curation-campaign"
        or binding.get("binding_id") != draft.binding_id
        or binding.get("campaign_id") != draft.campaign_id
        or binding.get("kind") != "campaign-run-binding"
    ):
        raise campaign_ledger.CampaignLedgerError(
            "campaign artifacts must be canonical JSON and draft identity bound"
        )


def _validate_campaign_plan(
    plan: campaign_ledger.CampaignPublicationPlan,
) -> None:
    if type(plan) is not campaign_ledger.CampaignPublicationPlan:
        raise TypeError("plan must be CampaignPublicationPlan")
    campaign = _canonical_object(plan.campaign_bytes)
    binding = _canonical_object(plan.binding_bytes)
    draft = campaign_ledger.CampaignPublicationDraft(
        campaign_id=campaign.get("campaign_id"),
        binding_id=binding.get("binding_id"),
        campaign_path=plan.campaign_path,
        binding_path=plan.binding_path,
        campaign_bytes=plan.campaign_bytes,
        binding_bytes=plan.binding_bytes,
    )
    _validate_campaign_paths(draft)
    _validate_campaign_payloads(draft)
    if (
        plan.campaign_sha256 != sha256_bytes(plan.campaign_bytes)
        or plan.binding_sha256 != sha256_bytes(plan.binding_bytes)
    ):
        raise campaign_ledger.CampaignLedgerError(
            "campaign publication plan hash is invalid"
        )


def _open_owner_directory(path: Path, label: str) -> int:
    descriptor = safety.open_verified_directory(
        path,
        require_owner_only=True,
        error_type=campaign_ledger.CampaignLedgerError,
    )
    opened = os.fstat(descriptor)
    if (
        opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise campaign_ledger.CampaignLedgerError(
            "%s directory must be owner-only mode 0700" % label
        )
    return descriptor


def _read_campaign_file(path: Path, expected: bytes, label: str) -> None:
    directory_fd = _open_owner_directory(path.parent, "%s parent" % label)
    try:
        info, observed = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label=label,
            expected_mode=0o600,
            error_type=campaign_ledger.CampaignLedgerError,
        )
    finally:
        os.close(directory_fd)
    if info.st_nlink != 1:
        raise campaign_ledger.CampaignLedgerError(
            "%s link count is invalid" % label
        )
    if observed != expected:
        raise campaign_ledger.CampaignLedgerError(
            "%s bytes differ from the sealed plan" % label
        )


def _require_allowed_entries(path: Path, allowed: tuple) -> None:
    descriptor = _open_owner_directory(path, "campaign publication")
    try:
        observed = tuple(sorted(os.listdir(descriptor)))
    finally:
        os.close(descriptor)
    unexpected = tuple(name for name in observed if name not in allowed)
    if unexpected:
        raise campaign_ledger.CampaignLedgerError(
            "unexpected campaign publication member: %s" % unexpected[0]
        )


class CampaignArtifactPublisher:
    """Plan and publish immutable root campaign control artifacts."""

    def __init__(self, control_root: Path) -> None:
        root = Path(control_root)
        if not root.is_absolute() or any(part in (".", "..") for part in root.parts):
            raise campaign_ledger.CampaignLedgerError(
                "control root must be a canonical absolute path"
            )
        self.control_root = root

    def _absolute(self, relative: str) -> Path:
        parts = _canonical_relative_path(relative, "artifact path").parts
        return self.control_root.joinpath(*parts)

    def _ensure_owner_tree(self, directory: Path) -> None:
        root_fd = safety.open_or_create_verified_directory(
            self.control_root,
            mode=0o700,
            error_type=campaign_ledger.CampaignLedgerError,
        )
        os.close(root_fd)
        root_fd = _open_owner_directory(self.control_root, "control root")
        os.close(root_fd)
        try:
            relative = directory.relative_to(self.control_root)
        except ValueError as exc:
            raise campaign_ledger.CampaignLedgerError(
                "artifact parent escapes control root"
            ) from exc
        current = self.control_root
        for part in relative.parts:
            current = current / part
            if os.path.lexists(current):
                descriptor = _open_owner_directory(current, "artifact parent")
                os.close(descriptor)
                continue
            safety.create_verified_directory_no_replace(
                current,
                label="artifact parent",
                collision_error="artifact parent already exists",
                mode=0o700,
                error_type=campaign_ledger.CampaignLedgerError,
            )
            descriptor = _open_owner_directory(current, "artifact parent")
            os.close(descriptor)

    @staticmethod
    def _ensure_file(path: Path, encoded: bytes, label: str) -> None:
        if os.path.lexists(path):
            _read_campaign_file(path, encoded, label)
            return
        safety.publish_bytes_atomic_no_replace(
            path,
            encoded,
            label=label,
            mode=0o600,
            create_parent=False,
            collision_error="%s already exists" % label,
            final_identity_error="%s identity mismatch" % label,
            parent_error="%s parent is invalid" % label,
            error_type=campaign_ledger.CampaignLedgerError,
            after_fd_readback=lambda _path, _fd, _directory_fd: None,
        )

    def plan(
        self,
        draft: campaign_ledger.CampaignPublicationDraft,
    ) -> campaign_ledger.CampaignPublicationPlan:
        if type(draft) is not campaign_ledger.CampaignPublicationDraft:
            raise TypeError("draft must be CampaignPublicationDraft")
        _validate_campaign_paths(draft)
        _validate_campaign_payloads(draft)
        return campaign_ledger.CampaignPublicationPlan(
            campaign_path=draft.campaign_path,
            campaign_bytes=draft.campaign_bytes,
            campaign_sha256=sha256_bytes(draft.campaign_bytes),
            binding_path=draft.binding_path,
            binding_bytes=draft.binding_bytes,
            binding_sha256=sha256_bytes(draft.binding_bytes),
        )

    def publish(
        self,
        plan: campaign_ledger.CampaignPublicationPlan,
    ) -> campaign_ledger.CampaignPublishResult:
        _validate_campaign_plan(plan)
        campaign_path = self._absolute(plan.campaign_path)
        binding_path = self._absolute(plan.binding_path)
        self._ensure_owner_tree(campaign_path.parent)
        self._ensure_owner_tree(binding_path.parent)
        campaign_staging = ".campaign.json.incomplete-%s" % plan.campaign_sha256[:24]
        binding_staging = ".binding.json.incomplete-%s" % plan.binding_sha256[:24]
        _require_allowed_entries(
            campaign_path.parent,
            ("campaign.json", campaign_staging, "run-bindings"),
        )
        _require_allowed_entries(
            binding_path.parent.parent,
            (binding_path.parent.name,),
        )
        _require_allowed_entries(
            binding_path.parent,
            ("binding.json", binding_staging),
        )
        for path, encoded, label in (
            (campaign_path, plan.campaign_bytes, "campaign artifact"),
            (binding_path, plan.binding_bytes, "binding artifact"),
        ):
            if os.path.lexists(path):
                _read_campaign_file(path, encoded, label)
        self._ensure_file(campaign_path, plan.campaign_bytes, "campaign artifact")
        self._ensure_file(binding_path, plan.binding_bytes, "binding artifact")
        _require_allowed_entries(
            campaign_path.parent,
            ("campaign.json", "run-bindings"),
        )
        _require_allowed_entries(
            binding_path.parent.parent,
            (binding_path.parent.name,),
        )
        _require_allowed_entries(binding_path.parent, ("binding.json",))
        _read_campaign_file(
            campaign_path,
            plan.campaign_bytes,
            "campaign artifact",
        )
        _read_campaign_file(
            binding_path,
            plan.binding_bytes,
            "binding artifact",
        )
        return campaign_ledger.CampaignPublishResult(
            campaign_path=plan.campaign_path,
            campaign_sha256=plan.campaign_sha256,
            binding_path=plan.binding_path,
            binding_sha256=plan.binding_sha256,
        )


class CampaignReviewPublisherAdapter:
    """Map root-integration drafts onto the full immutable review package."""

    def __init__(
        self,
        control_root: Path,
        *,
        review_publisher: review_snapshot.ReviewSnapshotPublisher,
        review_document_factory: Callable[[bytes], review_compiler.ReviewDocument],
    ) -> None:
        root = Path(control_root)
        if not root.is_absolute() or any(part in (".", "..") for part in root.parts):
            raise campaign_ledger.CampaignLedgerError(
                "control root must be a canonical absolute path"
            )
        if type(review_publisher) is not review_snapshot.ReviewSnapshotPublisher:
            raise TypeError("review_publisher must be ReviewSnapshotPublisher")
        if not callable(review_document_factory):
            raise TypeError("review_document_factory must be callable")
        self.control_root = root
        self.review_publisher = review_publisher
        self.review_document_factory = review_document_factory

    def _expected_final(
        self,
        draft: campaign_ledger.RootIntegrationDraft,
    ) -> Path:
        relative = _canonical_relative_path(draft.snapshot_path, "snapshot_path")
        if (
            relative.name != draft.snapshot_id
            or relative.parent.name != "snapshots"
            or relative.parent.parent.name != draft.campaign_id
        ):
            raise campaign_ledger.CampaignLedgerError(
                "snapshot path does not bind root integration identity"
            )
        return self.control_root.joinpath(*relative.parts)

    def _review_plan(
        self,
        draft: campaign_ledger.RootIntegrationDraft,
    ) -> review_snapshot.ReviewSnapshotPlan:
        if type(draft) is not campaign_ledger.RootIntegrationDraft:
            raise TypeError("draft must be RootIntegrationDraft")
        expected_final = self._expected_final(draft)
        if self.review_publisher.snapshot_root != expected_final.parent:
            raise campaign_ledger.CampaignLedgerError(
                "review publisher root does not match integration path"
            )
        try:
            document = self.review_document_factory(draft.snapshot_payload_json)
            if type(document) is not review_compiler.ReviewDocument:
                raise campaign_ledger.CampaignLedgerError(
                    "review document factory returned an invalid document"
                )
            if (
                document.source_kind != "campaign-snapshot"
                or document.campaign_id != draft.campaign_id
                or document.batch_id is not None
                or document.snapshot_id != draft.snapshot_id
            ):
                raise campaign_ledger.CampaignLedgerError(
                    "review document does not bind root integration identity"
                )
            planned = self.review_publisher.plan(
                snapshot_id=draft.snapshot_id,
                snapshot_payload=draft.snapshot_payload_json,
                review_document=document,
            )
        except campaign_ledger.CampaignLedgerError:
            raise
        except (review_snapshot.ReviewSnapshotError, review_compiler.ReviewCompileError) as exc:
            raise campaign_ledger.CampaignLedgerError(
                "review package plan does not bind root integration draft"
            ) from exc
        if planned.final_path != expected_final:
            raise campaign_ledger.CampaignLedgerError(
                "review package final path does not bind integration path"
            )
        return planned

    @staticmethod
    def _plan_json(
        draft: campaign_ledger.RootIntegrationDraft,
        planned: review_snapshot.ReviewSnapshotPlan,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "adapter_kind": "campaign-review-snapshot",
                "binding_id": draft.binding_id,
                "campaign_id": draft.campaign_id,
                "final_path": draft.snapshot_path,
                "integration_id": draft.integration_id,
                "package_sha256": planned.package_sha256,
                "publisher_final_path": str(planned.final_path),
                "publisher_staging_path": str(planned.staging_path),
                "schema_version": 1,
                "sealed_identity_sha256": planned.sealed_identity_sha256,
                "snapshot_id": draft.snapshot_id,
                "snapshot_payload_sha256": planned.snapshot_sha256,
                "submission_id": draft.submission_id,
            }
        )

    def plan(
        self,
        draft: campaign_ledger.RootIntegrationDraft,
    ) -> campaign_ledger.RootIntegrationPlan:
        planned = self._review_plan(draft)
        return campaign_ledger.RootIntegrationPlan(
            final_path=draft.snapshot_path,
            snapshot_payload_json=draft.snapshot_payload_json,
            snapshot_payload_sha256=planned.snapshot_sha256,
            package_sha256=planned.package_sha256,
            plan_json=self._plan_json(draft, planned),
            sealed_payload=planned,
        )

    def _validated_review_plan(
        self,
        plan: campaign_ledger.RootIntegrationPlan,
    ) -> review_snapshot.ReviewSnapshotPlan:
        if type(plan) is not campaign_ledger.RootIntegrationPlan:
            raise TypeError("plan must be RootIntegrationPlan")
        try:
            value = json.loads(plan.plan_json.decode("utf-8"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise campaign_ledger.CampaignLedgerError(
                "campaign review plan_json is invalid"
            ) from exc
        if type(value) is not dict or canonical_json_bytes(value) != plan.plan_json:
            raise campaign_ledger.CampaignLedgerError(
                "campaign review plan_json is invalid"
            )
        try:
            draft = campaign_ledger.RootIntegrationDraft(
                campaign_id=value["campaign_id"],
                binding_id=value["binding_id"],
                integration_id=value["integration_id"],
                submission_id=value["submission_id"],
                snapshot_id=value["snapshot_id"],
                snapshot_path=plan.final_path,
                snapshot_payload_json=plan.snapshot_payload_json,
            )
        except KeyError as exc:
            raise campaign_ledger.CampaignLedgerError(
                "campaign review plan identity is incomplete"
            ) from exc
        expected_final = self._expected_final(draft)
        planned = _prepared_review_plan(
            plan.sealed_payload,
            publisher=self.review_publisher,
            snapshot_id=draft.snapshot_id,
            snapshot_payload=draft.snapshot_payload_json,
            final_path=expected_final,
            error_type=campaign_ledger.CampaignLedgerError,
            error_message=(
                "campaign review plan does not match sealed package identity"
            ),
        )
        expected = campaign_ledger.RootIntegrationPlan(
            final_path=draft.snapshot_path,
            snapshot_payload_json=draft.snapshot_payload_json,
            snapshot_payload_sha256=planned.snapshot_sha256,
            package_sha256=planned.package_sha256,
            plan_json=self._plan_json(draft, planned),
            sealed_payload=planned,
        )
        if plan != expected:
            raise campaign_ledger.CampaignLedgerError(
                "campaign review plan does not match sealed package identity"
            )
        return planned

    def publish(
        self,
        plan: campaign_ledger.RootIntegrationPlan,
    ) -> campaign_ledger.RootIntegrationPublishResult:
        planned = self._validated_review_plan(plan)
        try:
            result = self.review_publisher.publish(planned)
        except review_snapshot.ReviewSnapshotError as exc:
            raise campaign_ledger.CampaignLedgerError(
                "campaign review package publication failed"
            ) from exc
        if type(result) is not review_snapshot.ReviewSnapshotResult or (
            result.snapshot_id,
            result.final_path,
            result.snapshot_sha256,
            result.package_sha256,
            result.sealed_identity_sha256,
        ) != (
            planned.snapshot_id,
            planned.final_path,
            planned.snapshot_sha256,
            planned.package_sha256,
            planned.sealed_identity_sha256,
        ):
            raise campaign_ledger.CampaignLedgerError(
                "campaign review package readback does not match sealed plan"
            )
        return campaign_ledger.RootIntegrationPublishResult(
            final_path=plan.final_path,
            package_sha256=plan.package_sha256,
        )


class BatchReviewPublisherAdapter:
    """Production batch adapter for full snapshots; never uses the default publisher."""

    def __init__(
        self,
        *,
        review_publisher: review_snapshot.ReviewSnapshotPublisher,
        review_document_factory: Callable[[bytes], review_compiler.ReviewDocument],
    ) -> None:
        if type(review_publisher) is not review_snapshot.ReviewSnapshotPublisher:
            raise TypeError("review_publisher must be ReviewSnapshotPublisher")
        if not callable(review_document_factory):
            raise TypeError("review_document_factory must be callable")
        self.review_publisher = review_publisher
        self.review_document_factory = review_document_factory

    @staticmethod
    def _publication_payload(
        publication: batch_service.SnapshotPublication,
    ) -> Dict[str, object]:
        try:
            value = json.loads(publication.canonical_payload.decode("utf-8"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise batch_service.BatchPublicationError(
                "batch snapshot payload is not canonical JSON"
            ) from exc
        if (
            type(value) is not dict
            or canonical_json_bytes(value) != publication.canonical_payload
            or sha256_bytes(publication.canonical_payload)
            != publication.snapshot_sha256
            or value.get("snapshot_id") != publication.snapshot_id
            or value.get("batch_id") != publication.batch_id
            or value.get("batch_version") != publication.version
            or value.get("structural_approval_ready")
            is not publication.structural_approval_ready
            or value.get("structural_blocker") != publication.structural_blocker
        ):
            raise batch_service.BatchPublicationError(
                "batch snapshot payload does not bind publication identity"
            )
        return value

    def _review_plan(
        self,
        publication: batch_service.SnapshotPublication,
    ) -> review_snapshot.ReviewSnapshotPlan:
        if type(publication) is not batch_service.SnapshotPublication:
            raise TypeError("publication must be SnapshotPublication")
        payload = self._publication_payload(publication)
        final_path = publication.final_path
        if (
            not isinstance(final_path, Path)
            or not final_path.is_absolute()
            or any(part in (".", "..") for part in final_path.parts)
            or final_path.name != publication.snapshot_id
            or final_path.parent != self.review_publisher.snapshot_root
        ):
            raise batch_service.BatchPublicationError(
                "batch snapshot final path does not bind publisher root"
            )
        try:
            document = self.review_document_factory(publication.canonical_payload)
            if type(document) is not review_compiler.ReviewDocument:
                raise batch_service.BatchPublicationError(
                    "review document factory returned an invalid document"
                )
            if (
                document.source_kind != "batch-snapshot"
                or document.campaign_id != payload.get("campaign_id")
                or document.batch_id != publication.batch_id
                or document.snapshot_id != publication.snapshot_id
                or document.snapshot_version != publication.version
            ):
                raise batch_service.BatchPublicationError(
                    "review document does not bind batch publication identity"
                )
            planned = self.review_publisher.plan(
                snapshot_id=publication.snapshot_id,
                snapshot_payload=publication.canonical_payload,
                review_document=document,
            )
        except batch_service.BatchPublicationError:
            raise
        except (review_snapshot.ReviewSnapshotError, review_compiler.ReviewCompileError) as exc:
            raise batch_service.BatchPublicationError(
                "review package plan does not bind batch publication"
            ) from exc
        if (
            planned.final_path != publication.final_path
            or planned.snapshot_sha256 != publication.snapshot_sha256
        ):
            raise batch_service.BatchPublicationError(
                "review package plan changed batch publication identity"
            )
        return planned

    def plan(
        self,
        publication: batch_service.SnapshotPublication,
    ) -> batch_service.SnapshotPublishPlan:
        planned = self._review_plan(publication)
        return batch_service.SnapshotPublishPlan(
            publication=publication,
            final_path=planned.final_path,
            package_sha256=planned.package_sha256,
            sealed_identity_sha256=planned.sealed_identity_sha256,
            sealed_payload=planned,
        )

    def _validated_review_plan(
        self,
        plan: batch_service.SnapshotPublishPlan,
    ) -> review_snapshot.ReviewSnapshotPlan:
        if type(plan) is not batch_service.SnapshotPublishPlan:
            raise TypeError("plan must be SnapshotPublishPlan")
        self._publication_payload(plan.publication)
        planned = _prepared_review_plan(
            plan.sealed_payload,
            publisher=self.review_publisher,
            snapshot_id=plan.publication.snapshot_id,
            snapshot_payload=plan.publication.canonical_payload,
            final_path=plan.publication.final_path,
            error_type=batch_service.BatchPublicationError,
            error_message=(
                "batch review plan does not match sealed package identity"
            ),
        )
        expected = batch_service.SnapshotPublishPlan(
            publication=plan.publication,
            final_path=planned.final_path,
            package_sha256=planned.package_sha256,
            sealed_identity_sha256=planned.sealed_identity_sha256,
            sealed_payload=planned,
        )
        if plan != expected:
            raise batch_service.BatchPublicationError(
                "batch review plan does not match sealed package identity"
            )
        return planned

    def publish(
        self,
        plan: batch_service.SnapshotPublishPlan,
    ) -> batch_service.SnapshotPublishResult:
        planned = self._validated_review_plan(plan)
        try:
            result = self.review_publisher.publish(planned)
        except review_snapshot.ReviewSnapshotError as exc:
            raise batch_service.BatchPublicationError(
                "batch review package publication failed"
            ) from exc
        if type(result) is not review_snapshot.ReviewSnapshotResult or (
            result.snapshot_id,
            result.final_path,
            result.snapshot_sha256,
            result.package_sha256,
            result.sealed_identity_sha256,
        ) != (
            planned.snapshot_id,
            planned.final_path,
            planned.snapshot_sha256,
            planned.package_sha256,
            planned.sealed_identity_sha256,
        ):
            raise batch_service.BatchPublicationError(
                "batch review package readback does not match sealed plan"
            )
        return batch_service.SnapshotPublishResult(
            final_path=result.final_path,
            snapshot_sha256=result.snapshot_sha256,
            package_sha256=result.package_sha256,
            sealed_identity_sha256=result.sealed_identity_sha256,
        )


__all__ = [
    "BatchReviewPublisherAdapter",
    "CampaignArtifactPublisher",
    "CampaignReviewPublisherAdapter",
]
