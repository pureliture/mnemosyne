"""Root inventory-run binding and atomic initial campaign integration.

This M2 service is deliberately root-only.  It records a bounded import plan,
publishes immutable campaign/binding artifacts through caller-owned plan/publish
seams, and advances ``OPENING`` to ``READY`` only in the same final transaction
that imports the run evidence and commits the genesis review snapshot.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, ContextManager, Dict, Optional, Tuple

from . import admission, ledger_schema
from .canonical_json import canonical_json_bytes, sha256_bytes


_HASH_CHARACTERS = frozenset("0123456789abcdef")
_MAX_IMPORT_ROWS = 50_000
_MAX_IMPORT_BYTES = 64 * 1024 * 1024
_CANDIDATE_AXES = frozenset(("workstream", "role", "authority", "lifecycle"))
_CONFIDENCE = frozenset(("low", "medium", "high", "unknown"))
_FRESHNESS = frozenset(("fresh", "stale", "unknown"))


class CampaignLedgerError(Exception):
    """A root binding, publication, or exact-CAS precondition failed."""


class _CampaignPolicyDriftError(CampaignLedgerError):
    """Policy authority changed across one campaign operation boundary."""


def _require_text(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError("%s is required" % label)
    return value


def _require_hash(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HASH_CHARACTERS for character in value)
    ):
        raise ValueError("%s must be a lowercase SHA-256" % label)
    return value


def _require_relative_path(value: str, label: str) -> str:
    _require_text(value, label)
    parts = value.split("/")
    if value.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise ValueError("%s must be a canonical relative path" % label)
    return value


def _canonical_json_value(raw: bytes, label: str) -> Any:
    if not isinstance(raw, bytes):
        raise ValueError("%s must be canonical JSON bytes" % label)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("%s must be canonical JSON bytes" % label) from exc
    if canonical_json_bytes(value) != raw:
        raise ValueError("%s must be canonical JSON bytes" % label)
    return value


def _require_uuid4(value: str, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("%s must be a canonical UUID4" % label) from exc
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("%s must be a canonical UUID4" % label)
    return value


def _tuple_row(row: Any) -> Optional[Tuple[Any, ...]]:
    return None if row is None else tuple(row)


@dataclass(frozen=True)
class ImportedItem:
    item_id: str

    def __post_init__(self) -> None:
        _require_uuid4(self.item_id, "item_id")


@dataclass(frozen=True)
class ImportedObservation:
    observation_key: str
    observation_id: str
    path: str
    kind: str
    payload_json: bytes

    def __post_init__(self) -> None:
        _require_text(self.observation_key, "observation_key")
        _require_text(self.observation_id, "observation_id")
        _require_relative_path(self.path, "observation path")
        _require_text(self.kind, "observation kind")
        _canonical_json_value(self.payload_json, "observation payload_json")


@dataclass(frozen=True)
class ImportedObservationLink:
    link_id: str
    observation_id: str
    item_id: str
    provenance_json: bytes

    def __post_init__(self) -> None:
        _require_text(self.link_id, "link_id")
        _require_text(self.observation_id, "observation_id")
        _require_uuid4(self.item_id, "item_id")
        _canonical_json_value(self.provenance_json, "link provenance_json")


@dataclass(frozen=True)
class ImportedClassificationCandidate:
    candidate_id: str
    item_id: str
    axis: str
    candidate_value: Optional[str]
    provider_id: str
    confidence: str
    uncertainty: Optional[str]
    context_freshness: str
    evidence_json: bytes

    def __post_init__(self) -> None:
        _require_text(self.candidate_id, "candidate_id")
        _require_uuid4(self.item_id, "item_id")
        if self.axis not in _CANDIDATE_AXES:
            raise ValueError("unsupported classification axis")
        if self.candidate_value is not None:
            _require_text(self.candidate_value, "candidate_value")
        _require_text(self.provider_id, "provider_id")
        if self.confidence not in _CONFIDENCE:
            raise ValueError("unsupported confidence")
        if self.uncertainty is not None:
            _require_text(self.uncertainty, "uncertainty")
        if self.context_freshness not in _FRESHNESS:
            raise ValueError("unsupported context_freshness")
        _canonical_json_value(self.evidence_json, "candidate evidence_json")


@dataclass(frozen=True)
class ImportedPlacementTargetCandidate:
    target_candidate_id: str
    item_id: str
    snapshot_id: str
    registry_rule_id: Optional[str]
    registry_rule_sha256: Optional[str]
    target_path: Optional[str]
    rename_delta_json: bytes
    uncertainty: Optional[str]
    payload_json: bytes

    def __post_init__(self) -> None:
        _require_text(self.target_candidate_id, "target_candidate_id")
        _require_uuid4(self.item_id, "item_id")
        _require_text(self.snapshot_id, "snapshot_id")
        if self.registry_rule_id is not None:
            _require_text(self.registry_rule_id, "registry_rule_id")
        if self.registry_rule_sha256 is not None:
            _require_hash(self.registry_rule_sha256, "registry_rule_sha256")
        if (self.registry_rule_id is None) != (self.registry_rule_sha256 is None):
            raise ValueError("target registry rule id/hash must appear together")
        if self.target_path is not None:
            _require_relative_path(self.target_path, "target_path")
        if self.uncertainty is not None:
            _require_text(self.uncertainty, "target uncertainty")
        rename_delta = _canonical_json_value(
            self.rename_delta_json,
            "target rename_delta_json",
        )
        payload = _canonical_json_value(self.payload_json, "target payload_json")
        expected_payload_fields = {
            "evidence_ids",
            "input_sha256",
            "matched_rule_id",
            "matched_rule_sha256",
            "rename_delta",
            "resolver_version",
            "schema_version",
            "status",
            "target_path",
            "uncertainty",
        }
        if (
            not isinstance(rename_delta, dict)
            or set(rename_delta) != {"from", "to"}
            or not isinstance(rename_delta["from"], str)
            or not rename_delta["from"]
            or (
                rename_delta["to"] is not None
                and not isinstance(rename_delta["to"], str)
            )
            or not isinstance(payload, dict)
            or set(payload) != expected_payload_fields
            or payload["schema_version"] != 1
            or payload["status"] not in ("blocked", "resolved")
            or payload["matched_rule_id"] != self.registry_rule_id
            or payload["matched_rule_sha256"] != self.registry_rule_sha256
            or payload["target_path"] != self.target_path
            or payload["rename_delta"] != rename_delta
            or payload["uncertainty"] != self.uncertainty
        ):
            raise ValueError("target payload binding is invalid")
        _require_hash(payload["input_sha256"], "target input_sha256")
        _require_text(payload["resolver_version"], "target resolver_version")
        evidence_ids = payload["evidence_ids"]
        if (
            not isinstance(evidence_ids, list)
            or evidence_ids != sorted(set(evidence_ids))
            or any(not isinstance(value, str) or not value for value in evidence_ids)
        ):
            raise ValueError("target payload evidence binding is invalid")
        if payload["status"] == "blocked":
            if (
                self.target_path is not None
                or self.registry_rule_id is not None
                or self.uncertainty is None
                or rename_delta["to"] is not None
            ):
                raise ValueError("blocked target payload binding is invalid")
        elif (
            self.target_path is None
            or self.registry_rule_id is None
            or self.uncertainty is not None
            or rename_delta["to"] is None
        ):
            raise ValueError("resolved target payload binding is invalid")


@dataclass(frozen=True)
class RunImportPlan:
    items: Tuple[ImportedItem, ...]
    observations: Tuple[ImportedObservation, ...]
    links: Tuple[ImportedObservationLink, ...]
    classification_candidates: Tuple[ImportedClassificationCandidate, ...]
    placement_target_candidates: Tuple[ImportedPlacementTargetCandidate, ...] = ()

    def __post_init__(self) -> None:
        for label, values, expected_type in (
            ("items", self.items, ImportedItem),
            ("observations", self.observations, ImportedObservation),
            ("links", self.links, ImportedObservationLink),
            (
                "classification_candidates",
                self.classification_candidates,
                ImportedClassificationCandidate,
            ),
            (
                "placement_target_candidates",
                self.placement_target_candidates,
                ImportedPlacementTargetCandidate,
            ),
        ):
            if not isinstance(values, tuple) or any(
                not isinstance(value, expected_type) for value in values
            ):
                raise ValueError("%s must be a tuple of import records" % label)
        row_count = sum(
            len(values)
            for values in (
                self.items,
                self.observations,
                self.links,
                self.classification_candidates,
                self.placement_target_candidates,
            )
        )
        if row_count == 0 or row_count > _MAX_IMPORT_ROWS:
            raise ValueError("import plan row bound is invalid")
        item_ids = {item.item_id for item in self.items}
        observation_ids = {
            observation.observation_id for observation in self.observations
        }
        if len(item_ids) != len(self.items):
            raise ValueError("duplicate imported item_id")
        if len(observation_ids) != len(self.observations):
            raise ValueError("duplicate imported observation_id")
        if len({item.observation_key for item in self.observations}) != len(
            self.observations
        ):
            raise ValueError("duplicate imported observation_key")
        if len({link.link_id for link in self.links}) != len(self.links):
            raise ValueError("duplicate imported link_id")
        if len(
            {candidate.candidate_id for candidate in self.classification_candidates}
        ) != len(self.classification_candidates):
            raise ValueError("duplicate imported candidate_id")
        if len(
            {
                candidate.target_candidate_id
                for candidate in self.placement_target_candidates
            }
        ) != len(self.placement_target_candidates):
            raise ValueError("duplicate imported target_candidate_id")
        if any(
            link.item_id not in item_ids or link.observation_id not in observation_ids
            for link in self.links
        ):
            raise ValueError("imported link references an unknown record")
        if any(
            candidate.item_id not in item_ids
            for candidate in self.classification_candidates
        ):
            raise ValueError("imported candidate references an unknown item")
        if any(
            candidate.item_id not in item_ids
            for candidate in self.placement_target_candidates
        ):
            raise ValueError("imported target references an unknown item")
        if len(self.canonical_bytes()) > _MAX_IMPORT_BYTES:
            raise ValueError("import plan byte bound is invalid")

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "classification_candidates": [
                    {
                        "axis": candidate.axis,
                        "candidate_id": candidate.candidate_id,
                        "candidate_value": candidate.candidate_value,
                        "confidence": candidate.confidence,
                        "context_freshness": candidate.context_freshness,
                        "evidence": _canonical_json_value(
                            candidate.evidence_json,
                            "candidate evidence_json",
                        ),
                        "item_id": candidate.item_id,
                        "provider_id": candidate.provider_id,
                        "uncertainty": candidate.uncertainty,
                    }
                    for candidate in sorted(
                        self.classification_candidates,
                        key=lambda value: value.candidate_id,
                    )
                ],
                "items": [
                    {"item_id": item.item_id}
                    for item in sorted(self.items, key=lambda value: value.item_id)
                ],
                "links": [
                    {
                        "item_id": link.item_id,
                        "link_id": link.link_id,
                        "observation_id": link.observation_id,
                        "provenance": _canonical_json_value(
                            link.provenance_json,
                            "link provenance_json",
                        ),
                    }
                    for link in sorted(self.links, key=lambda value: value.link_id)
                ],
                "observations": [
                    {
                        "kind": observation.kind,
                        "observation_id": observation.observation_id,
                        "observation_key": observation.observation_key,
                        "path": observation.path,
                        "payload": _canonical_json_value(
                            observation.payload_json,
                            "observation payload_json",
                        ),
                    }
                    for observation in sorted(
                        self.observations,
                        key=lambda value: value.observation_key,
                    )
                ],
                "placement_target_candidates": [
                    {
                        "item_id": candidate.item_id,
                        "payload": _canonical_json_value(
                            candidate.payload_json,
                            "target payload_json",
                        ),
                        "registry_rule_id": candidate.registry_rule_id,
                        "registry_rule_sha256": candidate.registry_rule_sha256,
                        "rename_delta": _canonical_json_value(
                            candidate.rename_delta_json,
                            "target rename_delta_json",
                        ),
                        "snapshot_id": candidate.snapshot_id,
                        "target_candidate_id": candidate.target_candidate_id,
                        "target_path": candidate.target_path,
                        "uncertainty": candidate.uncertainty,
                    }
                    for candidate in sorted(
                        self.placement_target_candidates,
                        key=lambda value: value.target_candidate_id,
                    )
                ],
                "schema_version": 1,
            }
        )

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes())

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> "RunImportPlan":
        value = _canonical_json_value(raw, "import plan")
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError("unsupported import plan")
        try:
            return cls(
                items=tuple(
                    ImportedItem(item_id=item["item_id"])
                    for item in value["items"]
                ),
                observations=tuple(
                    ImportedObservation(
                        observation_key=item["observation_key"],
                        observation_id=item["observation_id"],
                        path=item["path"],
                        kind=item["kind"],
                        payload_json=canonical_json_bytes(item["payload"]),
                    )
                    for item in value["observations"]
                ),
                links=tuple(
                    ImportedObservationLink(
                        link_id=item["link_id"],
                        observation_id=item["observation_id"],
                        item_id=item["item_id"],
                        provenance_json=canonical_json_bytes(item["provenance"]),
                    )
                    for item in value["links"]
                ),
                classification_candidates=tuple(
                    ImportedClassificationCandidate(
                        candidate_id=item["candidate_id"],
                        item_id=item["item_id"],
                        axis=item["axis"],
                        candidate_value=item["candidate_value"],
                        provider_id=item["provider_id"],
                        confidence=item["confidence"],
                        uncertainty=item["uncertainty"],
                        context_freshness=item["context_freshness"],
                        evidence_json=canonical_json_bytes(item["evidence"]),
                    )
                    for item in value["classification_candidates"]
                ),
                placement_target_candidates=tuple(
                    ImportedPlacementTargetCandidate(
                        target_candidate_id=item["target_candidate_id"],
                        item_id=item["item_id"],
                        snapshot_id=item["snapshot_id"],
                        registry_rule_id=item["registry_rule_id"],
                        registry_rule_sha256=item["registry_rule_sha256"],
                        target_path=item["target_path"],
                        rename_delta_json=canonical_json_bytes(
                            item["rename_delta"]
                        ),
                        uncertainty=item["uncertainty"],
                        payload_json=canonical_json_bytes(item["payload"]),
                    )
                    for item in value.get("placement_target_candidates", [])
                ),
            )
        except (KeyError, TypeError) as exc:
            raise ValueError("import plan shape is invalid") from exc


@dataclass(frozen=True)
class RootRunRequest:
    run_id: str
    run_sha256: str
    run_package_path: str
    manifest_sha256: str
    policy: admission.ApprovedPolicyRef
    campaign_id: str
    binding_id: str
    integration_id: str
    submission_id: str
    snapshot_id: str
    campaign_path: str
    binding_path: str
    snapshot_path: str
    import_plan: RunImportPlan
    opened_by: str
    snapshot_payload_json: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("run_id", self.run_id),
            ("campaign_id", self.campaign_id),
            ("binding_id", self.binding_id),
            ("integration_id", self.integration_id),
            ("submission_id", self.submission_id),
            ("snapshot_id", self.snapshot_id),
            ("opened_by", self.opened_by),
        ):
            _require_text(value, label)
        _require_hash(self.run_sha256, "run_sha256")
        _require_hash(self.manifest_sha256, "manifest_sha256")
        for label, value in (
            ("run_package_path", self.run_package_path),
            ("campaign_path", self.campaign_path),
            ("binding_path", self.binding_path),
            ("snapshot_path", self.snapshot_path),
        ):
            _require_relative_path(value, label)
        if not isinstance(self.policy, admission.ApprovedPolicyRef):
            raise ValueError("policy must be ApprovedPolicyRef")
        if not isinstance(self.import_plan, RunImportPlan):
            raise ValueError("import_plan must be RunImportPlan")
        if any(
            candidate.snapshot_id != self.snapshot_id
            for candidate in self.import_plan.placement_target_candidates
        ):
            raise ValueError("target candidate snapshot binding is invalid")
        snapshot = _canonical_json_value(
            self.snapshot_payload_json,
            "snapshot_payload_json",
        )
        snapshot_schema_version = (
            snapshot.get("schema_version")
            if isinstance(snapshot, dict)
            else None
        )
        analysis_contexts = (
            snapshot.get("analysis_contexts")
            if isinstance(snapshot, dict)
            else None
        )
        context_ids = (
            [row.get("context_id") for row in analysis_contexts]
            if type(analysis_contexts) is list
            and all(
                type(row) is dict
                and type(row.get("context_id")) is str
                for row in analysis_contexts
            )
            else None
        )
        if (
            not isinstance(snapshot, dict)
            or snapshot_schema_version not in (1, 2)
            or (
                snapshot_schema_version == 1
                and "analysis_contexts" in snapshot
            )
            or (
                snapshot_schema_version == 2
                and (
                    not context_ids
                    or context_ids != sorted(context_ids)
                    or len(context_ids) != len(set(context_ids))
                )
            )
            or snapshot.get("kind") != "campaign-genesis-review"
            or snapshot.get("campaign_id") != self.campaign_id
            or snapshot.get("snapshot_id") != self.snapshot_id
            or snapshot.get("root_run_id") != self.run_id
            or snapshot.get("import_payload_sha256") != self.import_plan.sha256
            or snapshot.get("structural_approval_ready") is not False
            or snapshot.get("decisions") != []
            or snapshot.get("version") != 1
        ):
            raise ValueError("root review snapshot payload binding is invalid")
        if len(self.snapshot_payload_json) > _MAX_IMPORT_BYTES:
            raise ValueError("root review snapshot payload exceeds byte bound")

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "binding_id": self.binding_id,
                "binding_path": self.binding_path,
                "campaign_id": self.campaign_id,
                "campaign_path": self.campaign_path,
                "import_plan": _canonical_json_value(
                    self.import_plan.canonical_bytes(),
                    "import plan",
                ),
                "integration_id": self.integration_id,
                "manifest_sha256": self.manifest_sha256,
                "opened_by": self.opened_by,
                "policy": _policy_payload(self.policy),
                "run_id": self.run_id,
                "run_package_path": self.run_package_path,
                "run_sha256": self.run_sha256,
                "schema_version": 1,
                "snapshot_id": self.snapshot_id,
                "snapshot_payload": _canonical_json_value(
                    self.snapshot_payload_json,
                    "snapshot payload",
                ),
                "snapshot_path": self.snapshot_path,
                "submission_id": self.submission_id,
            }
        )

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> "RootRunRequest":
        value = _canonical_json_value(raw, "root run request")
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError("unsupported root run request")
        try:
            policy = value["policy"]
            return cls(
                run_id=value["run_id"],
                run_sha256=value["run_sha256"],
                run_package_path=value["run_package_path"],
                manifest_sha256=value["manifest_sha256"],
                policy=admission.ApprovedPolicyRef(
                    raw_hash=policy["raw_hash"],
                    full_hash=policy["full_hash"],
                    writer_control_hash=policy["writer_control_hash"],
                    foundation_hash=policy["foundation_hash"],
                    generation=policy["generation"],
                    source_kind=policy["source_kind"],
                    source_run_id=policy["source_run_id"],
                    guard_epoch=policy["guard_epoch"],
                ),
                campaign_id=value["campaign_id"],
                binding_id=value["binding_id"],
                integration_id=value["integration_id"],
                submission_id=value["submission_id"],
                snapshot_id=value["snapshot_id"],
                snapshot_payload_json=canonical_json_bytes(
                    value["snapshot_payload"]
                ),
                campaign_path=value["campaign_path"],
                binding_path=value["binding_path"],
                snapshot_path=value["snapshot_path"],
                import_plan=RunImportPlan.from_canonical_bytes(
                    canonical_json_bytes(value["import_plan"])
                ),
                opened_by=value["opened_by"],
            )
        except (KeyError, TypeError) as exc:
            raise ValueError("root run request shape is invalid") from exc


@dataclass(frozen=True)
class RootIntegrationDraft:
    campaign_id: str
    binding_id: str
    integration_id: str
    submission_id: str
    snapshot_id: str
    snapshot_path: str
    snapshot_payload_json: bytes


@dataclass(frozen=True)
class RootIntegrationPlan:
    final_path: str
    snapshot_payload_json: bytes
    snapshot_payload_sha256: str
    package_sha256: str
    plan_json: bytes
    sealed_payload: Optional[Any] = None


@dataclass(frozen=True)
class RootIntegrationPublishResult:
    final_path: str
    package_sha256: str


@dataclass(frozen=True)
class CampaignPublicationDraft:
    campaign_id: str
    binding_id: str
    campaign_path: str
    binding_path: str
    campaign_bytes: bytes
    binding_bytes: bytes


@dataclass(frozen=True)
class CampaignPublicationPlan:
    campaign_path: str
    campaign_bytes: bytes
    campaign_sha256: str
    binding_path: str
    binding_bytes: bytes
    binding_sha256: str


@dataclass(frozen=True)
class PreparedRootPublication:
    """Exact root publication plans prepared outside writer lifetime locks."""

    request_json: bytes
    integration_plan: RootIntegrationPlan
    campaign_plan: CampaignPublicationPlan

    def __post_init__(self) -> None:
        if type(self.request_json) is not bytes:
            raise TypeError("request_json must be bytes")
        if not isinstance(self.integration_plan, RootIntegrationPlan):
            raise TypeError("integration_plan must be RootIntegrationPlan")
        if not isinstance(self.campaign_plan, CampaignPublicationPlan):
            raise TypeError("campaign_plan must be CampaignPublicationPlan")


@dataclass(frozen=True)
class CampaignPublishResult:
    campaign_path: str
    campaign_sha256: str
    binding_path: str
    binding_sha256: str


@dataclass(frozen=True)
class CampaignOpenResult:
    campaign_id: str
    binding_id: str
    integration_id: str
    snapshot_id: str
    status: str
    snapshot_payload_json: bytes
    resumed: bool


def _policy_payload(policy: admission.ApprovedPolicyRef) -> Dict[str, Any]:
    return {
        "foundation_hash": policy.foundation_hash,
        "full_hash": policy.full_hash,
        "generation": policy.generation,
        "guard_epoch": policy.guard_epoch,
        "raw_hash": policy.raw_hash,
        "source_kind": policy.source_kind,
        "source_run_id": policy.source_run_id,
        "writer_control_hash": policy.writer_control_hash,
    }


def _root_integration_draft(request: RootRunRequest) -> RootIntegrationDraft:
    return RootIntegrationDraft(
        campaign_id=request.campaign_id,
        binding_id=request.binding_id,
        integration_id=request.integration_id,
        submission_id=request.submission_id,
        snapshot_id=request.snapshot_id,
        snapshot_path=request.snapshot_path,
        snapshot_payload_json=request.snapshot_payload_json,
    )


def _campaign_publication_draft(
    request: RootRunRequest,
    integration_plan: RootIntegrationPlan,
) -> CampaignPublicationDraft:
    campaign_bytes = canonical_json_bytes(
        {
            "campaign_id": request.campaign_id,
            "kind": "curation-campaign",
            "opened_by": request.opened_by,
            "policy": _policy_payload(request.policy),
            "preallocated": {
                "binding_id": request.binding_id,
                "integration_id": request.integration_id,
                "snapshot_final_sha256": integration_plan.package_sha256,
                "snapshot_id": request.snapshot_id,
                "snapshot_path": request.snapshot_path,
                "snapshot_payload_sha256": integration_plan.snapshot_payload_sha256,
                "submission_id": request.submission_id,
            },
            "review_revision": 0,
            "root_run_id": request.run_id,
            "root_run_sha256": request.run_sha256,
            "schema_version": 1,
            "status": "OPENING",
        }
    )
    binding_bytes = canonical_json_bytes(
        {
            "binding_id": request.binding_id,
            "binding_kind": "ROOT",
            "campaign_id": request.campaign_id,
            "expected_review_revision": 0,
            "import_payload_sha256": request.import_plan.sha256,
            "integration_id": request.integration_id,
            "kind": "campaign-run-binding",
            "policy": _policy_payload(request.policy),
            "run_id": request.run_id,
            "run_sha256": request.run_sha256,
            "schema_version": 1,
            "snapshot_id": request.snapshot_id,
            "state": "PREPARED",
        }
    )
    return CampaignPublicationDraft(
        campaign_id=request.campaign_id,
        binding_id=request.binding_id,
        campaign_path=request.campaign_path,
        binding_path=request.binding_path,
        campaign_bytes=campaign_bytes,
        binding_bytes=binding_bytes,
    )


def _validate_root_integration_plan(
    draft: RootIntegrationDraft,
    plan: RootIntegrationPlan,
) -> None:
    if not isinstance(plan, RootIntegrationPlan):
        raise CampaignLedgerError("integration publisher returned an invalid plan")
    try:
        _require_relative_path(plan.final_path, "integration final_path")
        _require_hash(plan.snapshot_payload_sha256, "snapshot_payload_sha256")
        _require_hash(plan.package_sha256, "package_sha256")
        plan_value = _canonical_json_value(plan.plan_json, "integration plan_json")
    except ValueError as exc:
        raise CampaignLedgerError(str(exc)) from exc
    if (
        plan.final_path != draft.snapshot_path
        or plan.snapshot_payload_json != draft.snapshot_payload_json
        or plan.snapshot_payload_sha256
        != sha256_bytes(draft.snapshot_payload_json)
        or not isinstance(plan_value, dict)
        or plan_value.get("final_path") != plan.final_path
        or plan_value.get("package_sha256") != plan.package_sha256
        or plan_value.get("snapshot_payload_sha256")
        != plan.snapshot_payload_sha256
    ):
        raise CampaignLedgerError("integration plan does not bind the exact draft")


def _validate_campaign_publication_plan(
    draft: CampaignPublicationDraft,
    plan: CampaignPublicationPlan,
) -> None:
    if not isinstance(plan, CampaignPublicationPlan):
        raise CampaignLedgerError("campaign publisher returned an invalid plan")
    if (
        plan.campaign_path != draft.campaign_path
        or plan.binding_path != draft.binding_path
        or plan.campaign_bytes != draft.campaign_bytes
        or plan.binding_bytes != draft.binding_bytes
        or plan.campaign_sha256 != sha256_bytes(draft.campaign_bytes)
        or plan.binding_sha256 != sha256_bytes(draft.binding_bytes)
    ):
        raise CampaignLedgerError("campaign plan does not bind the exact draft")


def prepare_root_publication(
    request: RootRunRequest,
    *,
    campaign_publisher: Any,
    integration_publisher: Any,
) -> PreparedRootPublication:
    """Plan one exact root publication without acquiring writer guards."""

    if not isinstance(request, RootRunRequest):
        raise TypeError("request must be RootRunRequest")
    for label, publisher in (
        ("campaign_publisher", campaign_publisher),
        ("integration_publisher", integration_publisher),
    ):
        if not callable(getattr(publisher, "plan", None)) or not callable(
            getattr(publisher, "publish", None)
        ):
            raise TypeError("%s must provide plan() and publish()" % label)
    integration_draft = _root_integration_draft(request)
    integration_plan = integration_publisher.plan(integration_draft)
    _validate_root_integration_plan(integration_draft, integration_plan)
    campaign_draft = _campaign_publication_draft(request, integration_plan)
    campaign_plan = campaign_publisher.plan(campaign_draft)
    _validate_campaign_publication_plan(campaign_draft, campaign_plan)
    return PreparedRootPublication(
        request_json=request.canonical_bytes(),
        integration_plan=integration_plan,
        campaign_plan=campaign_plan,
    )


@contextmanager
def _immediate_transaction(
    connection: sqlite3.Connection,
    *,
    before_commit: Optional[Callable[[], None]] = None,
):
    if connection.in_transaction:
        raise CampaignLedgerError("campaign writer does not own the transaction")
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
        if before_commit is not None:
            before_commit()
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


class CampaignRunBinder:
    """Bind and integrate one sealed root run into a new campaign."""

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        placement_shared: Callable[[], ContextManager[Any]],
        ledger_exclusive: Callable[[], ContextManager[Any]],
        current_policy: Callable[[], admission.ApprovedPolicyRef],
        campaign_publisher: Any,
        integration_publisher: Any,
    ) -> None:
        self._connection = connection
        self._placement_shared = placement_shared
        self._ledger_exclusive = ledger_exclusive
        self._current_policy = current_policy
        self._campaign_publisher = campaign_publisher
        self._integration_publisher = integration_publisher

    def prepare_root_publication(
        self,
        request: RootRunRequest,
    ) -> PreparedRootPublication:
        """Prepare exact plans while this binder holds no writer guards."""

        return prepare_root_publication(
            request,
            campaign_publisher=self._campaign_publisher,
            integration_publisher=self._integration_publisher,
        )

    def _require_prepared_publication(
        self,
        request: RootRunRequest,
        prepared: PreparedRootPublication,
    ) -> None:
        if type(prepared) is not PreparedRootPublication:
            raise TypeError("prepared must be PreparedRootPublication")
        if prepared.request_json != request.canonical_bytes():
            raise CampaignLedgerError(
                "prepared root publication changed canonical request"
            )
        integration_draft = _root_integration_draft(request)
        _validate_root_integration_plan(
            integration_draft,
            prepared.integration_plan,
        )
        campaign_draft = _campaign_publication_draft(
            request,
            prepared.integration_plan,
        )
        _validate_campaign_publication_plan(
            campaign_draft,
            prepared.campaign_plan,
        )

    def _open_root_run_locked(
        self,
        request: RootRunRequest,
        prepared: PreparedRootPublication,
        *,
        schema_verified: bool = False,
    ) -> CampaignOpenResult:
        if not isinstance(request, RootRunRequest):
            raise TypeError("request must be RootRunRequest")
        if not schema_verified:
            ledger_schema.verify_v2_schema(self._connection)
        self._require_prepared_publication(request, prepared)
        self._require_current_policy(request.policy)
        snapshot_payload = request.snapshot_payload_json
        integration_plan = prepared.integration_plan
        campaign_plan = prepared.campaign_plan
        resumed, integrated = self._reserve_root(
            request,
            campaign_plan,
            integration_plan,
        )
        if integrated:
            self._verify_integrated_import(request)
            return self._result(request, snapshot_payload, resumed=True)

        binding_state = self._binding_state(request.binding_id)
        if binding_state == "PREPARED":
            publication = self._campaign_publisher.publish(campaign_plan)
            self._validate_campaign_publication(campaign_plan, publication)
            self._require_current_policy(request.policy)
            self._publish_binding_and_prepare_integration(
                request,
                campaign_plan,
                integration_plan,
            )
        elif binding_state != "PUBLISHED":
            raise CampaignLedgerError("root binding is blocked")

        self._reserve_genesis_submission(
            request,
            snapshot_payload,
            integration_plan,
        )
        if self._integration_state(request.integration_id) == "INTEGRATED":
            self._verify_integrated_import(request)
            return self._result(request, snapshot_payload, resumed=True)

        try:
            integration_result = self._integration_publisher.publish(
                integration_plan
            )
            self._validate_integration_publication(
                integration_plan,
                integration_result,
            )
            self._require_current_policy(request.policy)
            self._commit_root_integration(
                request,
                snapshot_payload,
                integration_plan,
            )
        except _CampaignPolicyDriftError:
            raise
        except CampaignLedgerError:
            self._block_integration(request)
            raise
        except sqlite3.Error as exc:
            self._block_integration(request)
            raise CampaignLedgerError(
                "root integration transaction failed"
            ) from exc
        return self._result(request, snapshot_payload, resumed=resumed)

    def open_prepared_root_run(
        self,
        request: RootRunRequest,
        prepared: PreparedRootPublication,
    ) -> CampaignOpenResult:
        """Apply one exact pre-rendered root plan under writer guards."""

        with self._placement_shared():
            with self._ledger_exclusive():
                return self._open_root_run_locked(request, prepared)

    def open_root_run(self, request: RootRunRequest) -> CampaignOpenResult:
        """Compatibility entrypoint that plans before its own writer guards."""

        prepared = self.prepare_root_publication(request)
        return self.open_prepared_root_run(request, prepared)

    def _stored_root_request_locked(self, run_id: str) -> RootRunRequest:
        row = _tuple_row(self._connection.execute(
            "SELECT request_json, request_sha256 FROM campaign_run_bindings "
            "WHERE run_id = ?",
            (run_id,),
        ).fetchone())
        if row is None:
            raise CampaignLedgerError("root run has no stored reservation")
        request_json = bytes(row[0])
        if sha256_bytes(request_json) != row[1]:
            raise CampaignLedgerError("stored root request hash mismatch")
        try:
            request = RootRunRequest.from_canonical_bytes(request_json)
        except ValueError as exc:
            raise CampaignLedgerError(str(exc)) from exc
        if request.run_id != run_id:
            raise CampaignLedgerError("stored root request run mismatch")
        return request

    def resume_prepared_root_run(
        self,
        run_id: str,
        prepared: PreparedRootPublication,
    ) -> CampaignOpenResult:
        """Resume the stored canonical request with an exact pre-rendered plan."""

        try:
            _require_text(run_id, "run_id")
        except ValueError as exc:
            raise CampaignLedgerError(str(exc)) from exc
        with self._placement_shared():
            with self._ledger_exclusive():
                ledger_schema.verify_v2_schema(self._connection)
                request = self._stored_root_request_locked(run_id)
                return self._open_root_run_locked(
                    request,
                    prepared,
                    schema_verified=True,
                )

    def resume_root_run(self, run_id: str) -> CampaignOpenResult:
        """Compatibility resume that plans only after releasing its read guards."""

        try:
            _require_text(run_id, "run_id")
        except ValueError as exc:
            raise CampaignLedgerError(str(exc)) from exc
        with self._placement_shared():
            with self._ledger_exclusive():
                ledger_schema.verify_v2_schema(self._connection)
                request = self._stored_root_request_locked(run_id)
        prepared = self.prepare_root_publication(request)
        return self.resume_prepared_root_run(run_id, prepared)

    @staticmethod
    def _validate_campaign_publication(
        plan: CampaignPublicationPlan,
        result: CampaignPublishResult,
    ) -> None:
        if not isinstance(result, CampaignPublishResult) or (
            result.campaign_path,
            result.campaign_sha256,
            result.binding_path,
            result.binding_sha256,
        ) != (
            plan.campaign_path,
            plan.campaign_sha256,
            plan.binding_path,
            plan.binding_sha256,
        ):
            raise CampaignLedgerError("campaign publication readback mismatch")

    @staticmethod
    def _validate_integration_publication(
        plan: RootIntegrationPlan,
        result: RootIntegrationPublishResult,
    ) -> None:
        if not isinstance(result, RootIntegrationPublishResult) or (
            result.final_path,
            result.package_sha256,
        ) != (plan.final_path, plan.package_sha256):
            raise CampaignLedgerError("integration publication readback mismatch")

    def _require_current_policy(
        self,
        expected: admission.ApprovedPolicyRef,
    ) -> None:
        observed = self._current_policy()
        if observed != expected:
            raise _CampaignPolicyDriftError("current policy authority drifted")
        self._require_ledger_policy_state(expected)

    def _require_ledger_policy_state(
        self,
        expected: admission.ApprovedPolicyRef,
    ) -> None:
        head = _tuple_row(self._connection.execute(
            "SELECT generation, full_hash, writer_control_hash, foundation_hash, "
            "source_kind, source_run_id, guard_epoch FROM policy_head WHERE id = 1"
        ).fetchone())
        if head != (
            expected.generation,
            expected.full_hash,
            expected.writer_control_hash,
            expected.foundation_hash,
            expected.source_kind,
            expected.source_run_id,
            expected.guard_epoch,
        ):
            raise _CampaignPolicyDriftError(
                "ledger policy head does not match the run"
            )
        if self._connection.execute(
            "SELECT count(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
        ).fetchone()[0]:
            raise _CampaignPolicyDriftError(
                "open policy guard episode blocks root binding"
            )
        lane = _tuple_row(self._connection.execute(
            "SELECT state FROM policy_mutation_lane WHERE id = 1"
        ).fetchone())
        if lane is not None and lane != ("IDLE",):
            raise _CampaignPolicyDriftError(
                "policy mutation lane blocks root binding"
            )

    @contextmanager
    def _authority_transaction(
        self,
        expected_policy: admission.ApprovedPolicyRef,
    ):
        with _immediate_transaction(
            self._connection,
            before_commit=lambda: self._require_current_policy(expected_policy),
        ):
            self._require_current_policy(expected_policy)
            yield

    def _reserve_root(
        self,
        request: RootRunRequest,
        campaign_plan: CampaignPublicationPlan,
        integration_plan: RootIntegrationPlan,
    ) -> Tuple[bool, bool]:
        existing_binding = _tuple_row(self._connection.execute(
            "SELECT binding_id FROM campaign_run_bindings WHERE run_id = ?",
            (request.run_id,),
        ).fetchone())
        if existing_binding is not None:
            self._validate_existing_root(
                request,
                campaign_plan,
                integration_plan,
            )
            state = self._integration_state(request.integration_id, allow_missing=True)
            return True, state == "INTEGRATED"

        with self._authority_transaction(request.policy):
            existing_run = _tuple_row(self._connection.execute(
                "SELECT run_sha256, package_path, manifest_sha256, policy_raw_hash, "
                "policy_generation, policy_full_hash, policy_writer_control_hash, "
                "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
                "policy_guard_epoch, parent_run_id, state FROM inventory_runs "
                "WHERE run_id = ?",
                (request.run_id,),
            ).fetchone())
            expected_run = (
                request.run_sha256,
                request.run_package_path,
                request.manifest_sha256,
                request.policy.raw_hash,
                request.policy.generation,
                request.policy.full_hash,
                request.policy.writer_control_hash,
                request.policy.foundation_hash,
                request.policy.source_kind,
                request.policy.source_run_id,
                request.policy.guard_epoch,
                None,
                "OPENED",
            )
            if existing_run is None:
                self._connection.execute(
                    "INSERT INTO inventory_runs ("
                    "run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
                    "policy_generation, policy_full_hash, policy_writer_control_hash, "
                    "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
                    "policy_guard_epoch, parent_run_id, state"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'OPENED')",
                    (
                        request.run_id,
                        request.run_sha256,
                        request.run_package_path,
                        request.manifest_sha256,
                        request.policy.raw_hash,
                        request.policy.generation,
                        request.policy.full_hash,
                        request.policy.writer_control_hash,
                        request.policy.foundation_hash,
                        request.policy.source_kind,
                        request.policy.source_run_id,
                        request.policy.guard_epoch,
                    ),
                )
            elif existing_run != expected_run:
                raise CampaignLedgerError("root inventory run identity collision")
            self._connection.execute(
                "INSERT INTO campaigns ("
                "campaign_id, root_run_id, root_run_sha256, status, current_snapshot_id, "
                "current_snapshot_sha256, review_revision, active_integration_id, "
                "opened_by, payload_json, campaign_path, campaign_sha256"
                ") VALUES (?, ?, ?, 'OPENING', NULL, NULL, 0, NULL, ?, ?, ?, ?)",
                (
                    request.campaign_id,
                    request.run_id,
                    request.run_sha256,
                    request.opened_by,
                    campaign_plan.campaign_bytes,
                    campaign_plan.campaign_path,
                    campaign_plan.campaign_sha256,
                ),
            )
            self._connection.execute(
                "INSERT INTO campaign_run_bindings ("
                "binding_id, campaign_id, run_id, run_sha256, binding_kind, "
                "parent_binding_id, authorization_id, expected_snapshot_id, "
                "expected_snapshot_sha256, expected_review_revision, payload_json, "
                "payload_sha256, request_json, request_sha256, integration_plan_json, "
                "integration_plan_sha256, final_path, final_sha256, state"
                ") VALUES (?, ?, ?, ?, 'ROOT', NULL, NULL, NULL, NULL, 0, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                (
                    request.binding_id,
                    request.campaign_id,
                    request.run_id,
                    request.run_sha256,
                    campaign_plan.binding_bytes,
                    campaign_plan.binding_sha256,
                    request.canonical_bytes(),
                    sha256_bytes(request.canonical_bytes()),
                    integration_plan.plan_json,
                    sha256_bytes(integration_plan.plan_json),
                    campaign_plan.binding_path,
                    campaign_plan.binding_sha256,
                ),
            )
        return False, False

    def _validate_existing_root(
        self,
        request: RootRunRequest,
        campaign_plan: CampaignPublicationPlan,
        integration_plan: RootIntegrationPlan,
    ) -> None:
        binding = _tuple_row(self._connection.execute(
            "SELECT binding_id, campaign_id, run_sha256, binding_kind, payload_json, "
            "payload_sha256, request_json, request_sha256, integration_plan_json, "
            "integration_plan_sha256, final_path, final_sha256, state "
            "FROM campaign_run_bindings WHERE run_id = ?",
            (request.run_id,),
        ).fetchone())
        if binding is None or binding[:-1] != (
            request.binding_id,
            request.campaign_id,
            request.run_sha256,
            "ROOT",
            campaign_plan.binding_bytes,
            campaign_plan.binding_sha256,
            request.canonical_bytes(),
            sha256_bytes(request.canonical_bytes()),
            integration_plan.plan_json,
            sha256_bytes(integration_plan.plan_json),
            campaign_plan.binding_path,
            campaign_plan.binding_sha256,
        ):
            raise CampaignLedgerError("root run is already bound to another campaign")
        campaign = _tuple_row(self._connection.execute(
            "SELECT root_run_id, root_run_sha256, opened_by, payload_json, "
            "campaign_path, campaign_sha256 FROM campaigns WHERE campaign_id = ?",
            (request.campaign_id,),
        ).fetchone())
        if campaign != (
            request.run_id,
            request.run_sha256,
            request.opened_by,
            campaign_plan.campaign_bytes,
            campaign_plan.campaign_path,
            campaign_plan.campaign_sha256,
        ):
            raise CampaignLedgerError("stored campaign reservation does not match")
        integration = _tuple_row(self._connection.execute(
            "SELECT integration_id, payload_json, imported_payload_sha256, "
            "submission_id, snapshot_id, snapshot_path, snapshot_payload_sha256, "
            "snapshot_final_sha256 FROM run_integrations WHERE binding_id = ?",
            (request.binding_id,),
        ).fetchone())
        if integration is not None and integration != (
            request.integration_id,
            request.import_plan.canonical_bytes(),
            request.import_plan.sha256,
            request.submission_id,
            request.snapshot_id,
            integration_plan.final_path,
            integration_plan.snapshot_payload_sha256,
            integration_plan.package_sha256,
        ):
            raise CampaignLedgerError("stored root integration does not match")

    def _publish_binding_and_prepare_integration(
        self,
        request: RootRunRequest,
        campaign_plan: CampaignPublicationPlan,
        integration_plan: RootIntegrationPlan,
    ) -> None:
        with self._authority_transaction(request.policy):
            campaign = _tuple_row(self._connection.execute(
                "SELECT status, current_snapshot_id, current_snapshot_sha256, "
                "review_revision, active_integration_id, campaign_sha256 "
                "FROM campaigns WHERE campaign_id = ?",
                (request.campaign_id,),
            ).fetchone())
            if campaign not in (
                ("OPENING", None, None, 0, None, campaign_plan.campaign_sha256),
                (
                    "OPENING",
                    None,
                    None,
                    0,
                    request.integration_id,
                    campaign_plan.campaign_sha256,
                ),
            ):
                raise CampaignLedgerError("campaign opening CAS failed")
            binding = _tuple_row(self._connection.execute(
                "SELECT state, final_sha256 FROM campaign_run_bindings "
                "WHERE binding_id = ?",
                (request.binding_id,),
            ).fetchone())
            if binding == ("PUBLISHED", campaign_plan.binding_sha256):
                return
            if binding != ("PREPARED", campaign_plan.binding_sha256):
                raise CampaignLedgerError("root binding publication CAS failed")
            updated = self._connection.execute(
                "UPDATE campaign_run_bindings SET state = 'PUBLISHED' "
                "WHERE binding_id = ? AND state = 'PREPARED'",
                (request.binding_id,),
            ).rowcount
            if updated != 1:
                raise CampaignLedgerError("root binding publication CAS failed")
            self._connection.execute(
                "INSERT INTO run_integrations ("
                "integration_id, campaign_id, binding_id, expected_snapshot_id, "
                "expected_snapshot_sha256, expected_review_revision, payload_json, "
                "payload_sha256, imported_payload_sha256, submission_id, snapshot_id, "
                "snapshot_path, snapshot_payload_sha256, snapshot_final_sha256, state"
                ") VALUES (?, ?, ?, NULL, NULL, 0, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                (
                    request.integration_id,
                    request.campaign_id,
                    request.binding_id,
                    request.import_plan.canonical_bytes(),
                    request.import_plan.sha256,
                    request.import_plan.sha256,
                    request.submission_id,
                    request.snapshot_id,
                    integration_plan.final_path,
                    integration_plan.snapshot_payload_sha256,
                    integration_plan.package_sha256,
                ),
            )
            updated = self._connection.execute(
                "UPDATE campaigns SET active_integration_id = ? "
                "WHERE campaign_id = ? AND status = 'OPENING' "
                "AND current_snapshot_id IS NULL AND review_revision = 0 "
                "AND active_integration_id IS NULL",
                (request.integration_id, request.campaign_id),
            ).rowcount
            if updated != 1:
                raise CampaignLedgerError("campaign integration reservation CAS failed")

    def _reserve_genesis_submission(
        self,
        request: RootRunRequest,
        snapshot_payload: bytes,
        integration_plan: RootIntegrationPlan,
    ) -> None:
        if self._integration_state(request.integration_id) == "INTEGRATED":
            return
        expected_submission = (
            request.campaign_id,
            request.snapshot_id,
            snapshot_payload,
            integration_plan.snapshot_payload_sha256,
            integration_plan.final_path,
            integration_plan.package_sha256,
            "PREPARED",
        )
        submission = _tuple_row(self._connection.execute(
            "SELECT campaign_id, snapshot_id, payload_json, payload_sha256, final_path, "
            "final_sha256, state FROM review_submissions WHERE submission_id = ?",
            (request.submission_id,),
        ).fetchone())
        snapshot = _tuple_row(self._connection.execute(
            "SELECT campaign_id, version, payload_sha256, final_path, final_sha256, "
            "state, structural_approval_ready FROM review_snapshots WHERE snapshot_id = ?",
            (request.snapshot_id,),
        ).fetchone())
        if submission is not None or snapshot is not None:
            if submission != expected_submission or snapshot != (
                request.campaign_id,
                1,
                integration_plan.snapshot_payload_sha256,
                integration_plan.final_path,
                integration_plan.package_sha256,
                "PREPARED",
                0,
            ):
                raise CampaignLedgerError("stored genesis submission does not match")
            return
        with self._authority_transaction(request.policy):
            integration = _tuple_row(self._connection.execute(
                "SELECT state FROM run_integrations WHERE integration_id = ? "
                "AND campaign_id = ? AND binding_id = ?",
                (
                    request.integration_id,
                    request.campaign_id,
                    request.binding_id,
                ),
            ).fetchone())
            campaign = _tuple_row(self._connection.execute(
                "SELECT status, current_snapshot_id, review_revision, active_integration_id "
                "FROM campaigns WHERE campaign_id = ?",
                (request.campaign_id,),
            ).fetchone())
            if integration != ("PREPARED",) or campaign != (
                "OPENING",
                None,
                0,
                request.integration_id,
            ):
                raise CampaignLedgerError("genesis submission reservation CAS failed")
            request_hash = sha256_bytes(request.import_plan.canonical_bytes())
            self._connection.execute(
                "INSERT INTO review_submissions ("
                "submission_id, lineage_kind, campaign_id, batch_id, request_hash, "
                "snapshot_id, base_snapshot_id, base_snapshot_sha256, payload_json, "
                "payload_sha256, final_path, final_sha256, state"
                ") VALUES (?, 'CAMPAIGN', ?, NULL, ?, ?, NULL, NULL, ?, ?, ?, ?, 'PREPARED')",
                (
                    request.submission_id,
                    request.campaign_id,
                    request_hash,
                    request.snapshot_id,
                    snapshot_payload,
                    integration_plan.snapshot_payload_sha256,
                    integration_plan.final_path,
                    integration_plan.package_sha256,
                ),
            )
            self._connection.execute(
                "INSERT INTO review_snapshots ("
                "snapshot_id, lineage_kind, campaign_id, batch_id, version, "
                "parent_snapshot_id, parent_snapshot_sha256, payload_sha256, final_path, "
                "final_sha256, state, structural_approval_ready"
                ") VALUES (?, 'CAMPAIGN', ?, NULL, 1, NULL, NULL, ?, ?, ?, 'PREPARED', 0)",
                (
                    request.snapshot_id,
                    request.campaign_id,
                    integration_plan.snapshot_payload_sha256,
                    integration_plan.final_path,
                    integration_plan.package_sha256,
                ),
            )

    def _commit_root_integration(
        self,
        request: RootRunRequest,
        snapshot_payload: bytes,
        integration_plan: RootIntegrationPlan,
    ) -> None:
        with self._authority_transaction(request.policy):
            campaign = _tuple_row(self._connection.execute(
                "SELECT status, current_snapshot_id, current_snapshot_sha256, "
                "review_revision, active_integration_id FROM campaigns WHERE campaign_id = ?",
                (request.campaign_id,),
            ).fetchone())
            if campaign == (
                "READY",
                request.snapshot_id,
                integration_plan.snapshot_payload_sha256,
                1,
                None,
            ) and self._integration_state(request.integration_id) == "INTEGRATED":
                return
            if campaign != ("OPENING", None, None, 0, request.integration_id):
                raise CampaignLedgerError("campaign genesis final CAS failed")
            if self._binding_state(request.binding_id) != "PUBLISHED":
                raise CampaignLedgerError("root binding is not published")
            if self._integration_state(request.integration_id) != "PREPARED":
                raise CampaignLedgerError("root integration is not prepared")
            submission = _tuple_row(self._connection.execute(
                "SELECT state, payload_json, final_sha256 FROM review_submissions "
                "WHERE submission_id = ?",
                (request.submission_id,),
            ).fetchone())
            snapshot = _tuple_row(self._connection.execute(
                "SELECT state, payload_sha256, final_sha256, structural_approval_ready "
                "FROM review_snapshots WHERE snapshot_id = ?",
                (request.snapshot_id,),
            ).fetchone())
            if submission != (
                "PREPARED",
                snapshot_payload,
                integration_plan.package_sha256,
            ) or snapshot != (
                "PREPARED",
                integration_plan.snapshot_payload_sha256,
                integration_plan.package_sha256,
                0,
            ):
                raise CampaignLedgerError("genesis snapshot final CAS failed")
            self._insert_import_rows(request)
            if self._connection.execute(
                "UPDATE review_submissions SET state = 'COMMITTED' "
                "WHERE submission_id = ? AND state = 'PREPARED'",
                (request.submission_id,),
            ).rowcount != 1:
                raise CampaignLedgerError("genesis submission final CAS failed")
            if self._connection.execute(
                "UPDATE review_snapshots SET state = 'PUBLISHED' "
                "WHERE snapshot_id = ? AND state = 'PREPARED'",
                (request.snapshot_id,),
            ).rowcount != 1:
                raise CampaignLedgerError("genesis snapshot final CAS failed")
            if self._connection.execute(
                "UPDATE run_integrations SET state = 'INTEGRATED' "
                "WHERE integration_id = ? AND state = 'PREPARED'",
                (request.integration_id,),
            ).rowcount != 1:
                raise CampaignLedgerError("root integration final CAS failed")
            if self._connection.execute(
                "UPDATE campaigns SET status = 'READY', current_snapshot_id = ?, "
                "current_snapshot_sha256 = ?, review_revision = 1, "
                "active_integration_id = NULL WHERE campaign_id = ? "
                "AND status = 'OPENING' AND current_snapshot_id IS NULL "
                "AND review_revision = 0 AND active_integration_id = ?",
                (
                    request.snapshot_id,
                    integration_plan.snapshot_payload_sha256,
                    request.campaign_id,
                    request.integration_id,
                ),
            ).rowcount != 1:
                raise CampaignLedgerError("campaign genesis final CAS failed")

    def _insert_import_rows(self, request: RootRunRequest) -> None:
        for item in request.import_plan.items:
            self._connection.execute(
                "INSERT INTO items (item_id, first_seen_run_id, state) "
                "VALUES (?, ?, 'TENTATIVE')",
                (item.item_id, request.run_id),
            )
        for observation in request.import_plan.observations:
            self._connection.execute(
                "INSERT INTO observations ("
                "observation_key, run_id, observation_id, path, kind, payload_json, payload_sha256"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    observation.observation_key,
                    request.run_id,
                    observation.observation_id,
                    observation.path,
                    observation.kind,
                    observation.payload_json,
                    sha256_bytes(observation.payload_json),
                ),
            )
        for link in request.import_plan.links:
            self._connection.execute(
                "INSERT INTO observation_item_links ("
                "link_id, run_id, observation_id, item_id, link_generation, is_current, "
                "provenance_json, provenance_sha256"
                ") VALUES (?, ?, ?, ?, 1, 1, ?, ?)",
                (
                    link.link_id,
                    request.run_id,
                    link.observation_id,
                    link.item_id,
                    link.provenance_json,
                    sha256_bytes(link.provenance_json),
                ),
            )
        for candidate in request.import_plan.classification_candidates:
            self._connection.execute(
                "INSERT INTO classification_candidates ("
                "candidate_id, item_id, axis, candidate_value, provider_id, confidence, "
                "uncertainty, context_freshness, evidence_json, evidence_sha256, state"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'TENTATIVE')",
                (
                    candidate.candidate_id,
                    candidate.item_id,
                    candidate.axis,
                    candidate.candidate_value,
                    candidate.provider_id,
                    candidate.confidence,
                    candidate.uncertainty,
                    candidate.context_freshness,
                    candidate.evidence_json,
                    sha256_bytes(candidate.evidence_json),
                ),
            )
        for candidate in request.import_plan.placement_target_candidates:
            self._connection.execute(
                "INSERT INTO placement_target_candidates ("
                "target_candidate_id, item_id, snapshot_id, registry_rule_id, "
                "registry_rule_sha256, target_path, rename_delta_json, uncertainty, "
                "payload_sha256, state"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'TENTATIVE')",
                (
                    candidate.target_candidate_id,
                    candidate.item_id,
                    candidate.snapshot_id,
                    candidate.registry_rule_id,
                    candidate.registry_rule_sha256,
                    candidate.target_path,
                    candidate.rename_delta_json,
                    candidate.uncertainty,
                    sha256_bytes(candidate.payload_json),
                ),
            )

    def _verify_integrated_import(self, request: RootRunRequest) -> None:
        integration = _tuple_row(self._connection.execute(
            "SELECT state, imported_payload_sha256, payload_json FROM run_integrations "
            "WHERE integration_id = ?",
            (request.integration_id,),
        ).fetchone())
        if integration != (
            "INTEGRATED",
            request.import_plan.sha256,
            request.import_plan.canonical_bytes(),
        ):
            raise CampaignLedgerError("integrated import identity mismatch")
        expected_counts = (
            len(request.import_plan.items),
            len(request.import_plan.observations),
            len(request.import_plan.links),
            len(request.import_plan.classification_candidates),
            len(request.import_plan.placement_target_candidates),
        )
        observed_counts = (
            self._connection.execute(
                "SELECT count(*) FROM items WHERE first_seen_run_id = ?",
                (request.run_id,),
            ).fetchone()[0],
            self._connection.execute(
                "SELECT count(*) FROM observations WHERE run_id = ?",
                (request.run_id,),
            ).fetchone()[0],
            self._connection.execute(
                "SELECT count(*) FROM observation_item_links WHERE run_id = ?",
                (request.run_id,),
            ).fetchone()[0],
            self._connection.execute(
                "SELECT count(*) FROM classification_candidates "
                "WHERE item_id IN (SELECT item_id FROM items WHERE first_seen_run_id = ?)",
                (request.run_id,),
            ).fetchone()[0],
            self._connection.execute(
                "SELECT count(*) FROM placement_target_candidates "
                "WHERE item_id IN (SELECT item_id FROM items WHERE first_seen_run_id = ?)",
                (request.run_id,),
            ).fetchone()[0],
        )
        if observed_counts != expected_counts:
            raise CampaignLedgerError("integrated import row count mismatch")
        observed_items = [
            tuple(row)
            for row in self._connection.execute(
                "SELECT item_id, state FROM items WHERE first_seen_run_id = ? "
                "ORDER BY item_id",
                (request.run_id,),
            ).fetchall()
        ]
        expected_items = [
            (item.item_id, "TENTATIVE")
            for item in sorted(
                request.import_plan.items,
                key=lambda value: value.item_id,
            )
        ]
        observed_observations = [
            tuple(row)
            for row in self._connection.execute(
                "SELECT observation_key, observation_id, path, kind, payload_json, "
                "payload_sha256 FROM observations WHERE run_id = ? "
                "ORDER BY observation_key",
                (request.run_id,),
            ).fetchall()
        ]
        expected_observations = [
            (
                observation.observation_key,
                observation.observation_id,
                observation.path,
                observation.kind,
                observation.payload_json,
                sha256_bytes(observation.payload_json),
            )
            for observation in sorted(
                request.import_plan.observations,
                key=lambda value: value.observation_key,
            )
        ]
        observed_links = [
            tuple(row)
            for row in self._connection.execute(
                "SELECT link_id, observation_id, item_id, link_generation, is_current, "
                "provenance_json, provenance_sha256 FROM observation_item_links "
                "WHERE run_id = ? ORDER BY link_id",
                (request.run_id,),
            ).fetchall()
        ]
        expected_links = [
            (
                link.link_id,
                link.observation_id,
                link.item_id,
                1,
                1,
                link.provenance_json,
                sha256_bytes(link.provenance_json),
            )
            for link in sorted(
                request.import_plan.links,
                key=lambda value: value.link_id,
            )
        ]
        observed_candidates = [
            tuple(row)
            for row in self._connection.execute(
                "SELECT candidate_id, item_id, axis, candidate_value, provider_id, "
                "confidence, uncertainty, context_freshness, evidence_json, "
                "evidence_sha256, state FROM classification_candidates "
                "WHERE item_id IN ("
                "SELECT item_id FROM items WHERE first_seen_run_id = ?"
                ") ORDER BY candidate_id",
                (request.run_id,),
            ).fetchall()
        ]
        expected_candidates = [
            (
                candidate.candidate_id,
                candidate.item_id,
                candidate.axis,
                candidate.candidate_value,
                candidate.provider_id,
                candidate.confidence,
                candidate.uncertainty,
                candidate.context_freshness,
                candidate.evidence_json,
                sha256_bytes(candidate.evidence_json),
                "TENTATIVE",
            )
            for candidate in sorted(
                request.import_plan.classification_candidates,
                key=lambda value: value.candidate_id,
            )
        ]
        observed_targets = [
            tuple(row)
            for row in self._connection.execute(
                "SELECT target_candidate_id, item_id, snapshot_id, registry_rule_id, "
                "registry_rule_sha256, target_path, rename_delta_json, uncertainty, "
                "payload_sha256, state FROM placement_target_candidates "
                "WHERE item_id IN ("
                "SELECT item_id FROM items WHERE first_seen_run_id = ?"
                ") ORDER BY target_candidate_id",
                (request.run_id,),
            ).fetchall()
        ]
        expected_targets = [
            (
                candidate.target_candidate_id,
                candidate.item_id,
                candidate.snapshot_id,
                candidate.registry_rule_id,
                candidate.registry_rule_sha256,
                candidate.target_path,
                candidate.rename_delta_json,
                candidate.uncertainty,
                sha256_bytes(candidate.payload_json),
                "TENTATIVE",
            )
            for candidate in sorted(
                request.import_plan.placement_target_candidates,
                key=lambda value: value.target_candidate_id,
            )
        ]
        if (
            observed_items != expected_items
            or observed_observations != expected_observations
            or observed_links != expected_links
            or observed_candidates != expected_candidates
            or observed_targets != expected_targets
        ):
            raise CampaignLedgerError("integrated import data mismatch")

    def _block_integration(self, request: RootRunRequest) -> None:
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")
        with self._authority_transaction(request.policy):
            self._connection.execute(
                "UPDATE review_submissions SET state = 'BLOCKED' "
                "WHERE submission_id = ? AND state = 'PREPARED'",
                (request.submission_id,),
            )
            self._connection.execute(
                "UPDATE review_snapshots SET state = 'BLOCKED' "
                "WHERE snapshot_id = ? AND state = 'PREPARED'",
                (request.snapshot_id,),
            )
            self._connection.execute(
                "UPDATE run_integrations SET state = 'BLOCKED' "
                "WHERE integration_id = ? AND state = 'PREPARED'",
                (request.integration_id,),
            )
            self._connection.execute(
                "UPDATE campaigns SET status = 'BLOCKED', active_integration_id = NULL "
                "WHERE campaign_id = ? AND status = 'OPENING' "
                "AND active_integration_id = ?",
                (request.campaign_id, request.integration_id),
            )

    def _binding_state(self, binding_id: str) -> str:
        row = _tuple_row(self._connection.execute(
            "SELECT state FROM campaign_run_bindings WHERE binding_id = ?",
            (binding_id,),
        ).fetchone())
        if row is None:
            raise CampaignLedgerError("root binding is missing")
        return str(row[0])

    def _integration_state(
        self,
        integration_id: str,
        *,
        allow_missing: bool = False,
    ) -> Optional[str]:
        row = _tuple_row(self._connection.execute(
            "SELECT state FROM run_integrations WHERE integration_id = ?",
            (integration_id,),
        ).fetchone())
        if row is None:
            if allow_missing:
                return None
            raise CampaignLedgerError("root integration is missing")
        return str(row[0])

    @staticmethod
    def _result(
        request: RootRunRequest,
        snapshot_payload: bytes,
        *,
        resumed: bool,
    ) -> CampaignOpenResult:
        return CampaignOpenResult(
            campaign_id=request.campaign_id,
            binding_id=request.binding_id,
            integration_id=request.integration_id,
            snapshot_id=request.snapshot_id,
            status="READY",
            snapshot_payload_json=snapshot_payload,
            resumed=resumed,
        )


__all__ = [
    "CampaignLedgerError",
    "CampaignOpenResult",
    "CampaignPublicationDraft",
    "CampaignPublicationPlan",
    "CampaignPublishResult",
    "CampaignRunBinder",
    "ImportedClassificationCandidate",
    "ImportedItem",
    "ImportedObservation",
    "ImportedObservationLink",
    "ImportedPlacementTargetCandidate",
    "PreparedRootPublication",
    "RootIntegrationDraft",
    "RootIntegrationPlan",
    "RootIntegrationPublishResult",
    "RootRunRequest",
    "RunImportPlan",
    "prepare_root_publication",
]
