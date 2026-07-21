"""Pure structured-deferral preview, trigger, and evidence compilers.

Read-only previews never mutate a deferral.  ``evaluate`` only returns a
deterministic ledger intent; persistence and publication remain the caller's
responsibility.
"""

from __future__ import annotations

import datetime
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TRIGGERS = frozenset(("date", "workstream-resume", "evidence", "manual-reopen"))
_RESTRICTED_SCOPES = frozenset(
    ("private-reviewable", "opaque", "evidence", "protected", "coverage-only")
)
_SAFE_METADATA_KEYS = frozenset(
    ("kind", "size", "mtime_ns", "label", "source_id", "media_type")
)
_SECRET_KEY_FRAGMENT = re.compile(
    r"(?:password|passwd|secret|token|credential|api[-_]?key)", re.IGNORECASE
)


class DeferralValidationError(ValueError):
    """A deferral trigger or evidence attachment is incomplete or unsafe."""


@dataclass(frozen=True)
class DeferralRecord:
    deferral_id: str
    item_id: str
    version: int
    state: str
    trigger_kind: str
    review_date: Optional[str] = None
    timezone: Optional[str] = None
    workstream_id: Optional[str] = None
    captured_lifecycle: Optional[str] = None
    captured_policy_hash: Optional[str] = None


@dataclass(frozen=True)
class PublishedEvidence:
    event_id: str
    event_sha256: str
    deferral_id: str
    deferral_version: int
    state: str


@dataclass(frozen=True)
class ManualReopenEvidence:
    deferral_id: str
    deferral_version: int
    actor: str
    reason: str


@dataclass(frozen=True)
class TriggerPreview:
    deferral_id: str
    deferral_version: int
    trigger_kind: str
    inbox_state: str
    triggered: bool
    trigger_evidence: Tuple[str, ...]
    trigger_evidence_hash: str


@dataclass(frozen=True)
class TriggerEvaluation:
    idempotency_key: Tuple[str, str, str]
    event: Dict[str, Any]
    projection: Dict[str, Any]
    approval_created: bool
    corpus_effect_created: bool


@dataclass(frozen=True)
class EvidenceAttachmentInput:
    event_id: str
    deferral_id: str
    deferral_version: int
    actor: str
    scope_class: str
    allowed_metadata: Tuple[Tuple[str, Any], ...]
    source_ref: Optional[str] = None
    content_sha256: Optional[str] = None
    opaque_source_id: Optional[str] = None
    actor_attestation: Optional[str] = None
    raw_body: Optional[str] = None


@dataclass(frozen=True)
class CompiledEvidenceAttachment:
    payload: Dict[str, Any]
    idempotency_key: str


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise DeferralValidationError("%s is invalid" % label)
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise DeferralValidationError("%s is invalid" % label)
    return value


def _text(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or len(value.encode("utf-8")) > 16 * 1024
        or any(ord(character) < 0x20 for character in value)
    ):
        raise DeferralValidationError("%s is required" % label)
    return value


def _validate_record(record: DeferralRecord) -> None:
    if type(record) is not DeferralRecord:
        raise TypeError("record must be DeferralRecord")
    _identifier(record.deferral_id, "deferral id")
    _identifier(record.item_id, "item id")
    if type(record.version) is not int or record.version < 1:
        raise DeferralValidationError("deferral version is invalid")
    if record.state != "waiting":
        raise DeferralValidationError("deferral is not current and waiting")
    if record.trigger_kind not in _TRIGGERS:
        raise DeferralValidationError("deferral trigger kind is invalid")
    if record.trigger_kind == "date":
        if type(record.review_date) is not str:
            raise DeferralValidationError("date trigger review date is required")
        try:
            datetime.date.fromisoformat(record.review_date)
        except ValueError as exc:
            raise DeferralValidationError("date trigger review date is invalid") from exc
        if type(record.timezone) is not str or not record.timezone:
            raise DeferralValidationError("date trigger timezone is required")
        try:
            ZoneInfo(record.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise DeferralValidationError("date trigger timezone is invalid") from exc
        if any(
            value is not None
            for value in (
                record.workstream_id,
                record.captured_lifecycle,
                record.captured_policy_hash,
            )
        ):
            raise DeferralValidationError("date trigger fields are inconsistent")
    elif record.trigger_kind == "workstream-resume":
        _identifier(record.workstream_id, "workstream id")
        if record.captured_lifecycle not in ("paused", "completed"):
            raise DeferralValidationError(
                "captured workstream lifecycle must be paused or completed"
            )
        _hash(record.captured_policy_hash, "captured policy hash")
        if record.review_date is not None or record.timezone is not None:
            raise DeferralValidationError(
                "workstream resume trigger fields are inconsistent"
            )
    elif any(
        value is not None
        for value in (
            record.review_date,
            record.timezone,
            record.workstream_id,
            record.captured_lifecycle,
            record.captured_policy_hash,
        )
    ):
        raise DeferralValidationError("deferral trigger fields are inconsistent")


def _aware_clock(value: Any) -> datetime.datetime:
    if not isinstance(value, datetime.datetime) or value.tzinfo is None:
        raise DeferralValidationError("current clock must be timezone-aware")
    if value.utcoffset() is None:
        raise DeferralValidationError("current clock must be timezone-aware")
    return value


def _preview(
    record: DeferralRecord,
    *,
    inbox_state: str,
    triggered: bool,
    evidence: Tuple[str, ...],
) -> TriggerPreview:
    digest = sha256_bytes(
        canonical_json_bytes(
            {
                "deferral_id": record.deferral_id,
                "deferral_version": record.version,
                "evidence": list(evidence),
                "trigger_kind": record.trigger_kind,
            }
        )
    )
    return TriggerPreview(
        deferral_id=record.deferral_id,
        deferral_version=record.version,
        trigger_kind=record.trigger_kind,
        inbox_state=inbox_state,
        triggered=triggered,
        trigger_evidence=evidence,
        trigger_evidence_hash=digest,
    )


class DeferralTriggerEvaluator:
    """Compute deterministic waiting/due state and explicit trigger intents."""

    def preview(
        self,
        record: DeferralRecord,
        *,
        now: datetime.datetime,
        current_workstream_lifecycle: Optional[str] = None,
        current_policy_hash: Optional[str] = None,
        published_evidence: Optional[PublishedEvidence] = None,
        manual_reopen: Optional[ManualReopenEvidence] = None,
    ) -> TriggerPreview:
        _validate_record(record)
        clock = _aware_clock(now)
        if record.trigger_kind == "date":
            if any(
                value is not None
                for value in (
                    current_workstream_lifecycle,
                    current_policy_hash,
                    published_evidence,
                    manual_reopen,
                )
            ):
                raise DeferralValidationError("date preview received unrelated evidence")
            local_date = clock.astimezone(ZoneInfo(record.timezone)).date()
            review_date = datetime.date.fromisoformat(record.review_date)
            evidence = (record.review_date, record.timezone)
            return _preview(
                record,
                inbox_state="due" if local_date >= review_date else "scheduled-later",
                triggered=local_date >= review_date,
                evidence=evidence,
            )

        if record.trigger_kind == "workstream-resume":
            if published_evidence is not None or manual_reopen is not None:
                raise DeferralValidationError(
                    "workstream resume preview received unrelated evidence"
                )
            if current_workstream_lifecycle not in ("active", "paused", "completed"):
                raise DeferralValidationError("current workstream lifecycle is invalid")
            policy_hash = _hash(current_policy_hash, "current policy hash")
            evidence = (
                record.workstream_id,
                record.captured_lifecycle,
                "active",
                policy_hash,
            )
            resumed = current_workstream_lifecycle == "active"
            return _preview(
                record,
                inbox_state="due" if resumed else "waiting-workstream-resume",
                triggered=resumed,
                evidence=evidence,
            )

        if record.trigger_kind == "evidence":
            if any(
                value is not None
                for value in (
                    current_workstream_lifecycle,
                    current_policy_hash,
                    manual_reopen,
                )
            ):
                raise DeferralValidationError("evidence preview received unrelated input")
            if published_evidence is None:
                return _preview(
                    record,
                    inbox_state="waiting-evidence",
                    triggered=False,
                    evidence=("no-published-evidence",),
                )
            if type(published_evidence) is not PublishedEvidence:
                raise DeferralValidationError("published evidence is invalid")
            _identifier(published_evidence.event_id, "evidence event id")
            _hash(published_evidence.event_sha256, "evidence event hash")
            if published_evidence.deferral_id != record.deferral_id:
                raise DeferralValidationError("evidence deferral identity is stale")
            if published_evidence.deferral_version != record.version:
                raise DeferralValidationError("evidence deferral version is stale")
            if published_evidence.state != "PUBLISHED":
                raise DeferralValidationError("evidence event is not PUBLISHED")
            return _preview(
                record,
                inbox_state="due",
                triggered=True,
                evidence=(published_evidence.event_id, published_evidence.event_sha256),
            )

        if any(
            value is not None
            for value in (
                current_workstream_lifecycle,
                current_policy_hash,
                published_evidence,
            )
        ):
            raise DeferralValidationError("manual reopen received unrelated evidence")
        if manual_reopen is None:
            return _preview(
                record,
                inbox_state="waiting-manual-reopen",
                triggered=False,
                evidence=("manual-reopen-required",),
            )
        if type(manual_reopen) is not ManualReopenEvidence:
            raise DeferralValidationError("manual reopen evidence is invalid")
        if manual_reopen.deferral_id != record.deferral_id:
            raise DeferralValidationError("manual reopen deferral identity is stale")
        if manual_reopen.deferral_version != record.version:
            raise DeferralValidationError("manual reopen deferral version is stale")
        actor = _text(manual_reopen.actor, "manual reopen actor")
        reason = _text(manual_reopen.reason, "manual reopen reason")
        return _preview(
            record,
            inbox_state="due",
            triggered=True,
            evidence=(actor, reason),
        )

    def evaluate(
        self,
        record: DeferralRecord,
        preview: TriggerPreview,
        *,
        actor: str,
    ) -> TriggerEvaluation:
        _validate_record(record)
        if type(preview) is not TriggerPreview:
            raise TypeError("preview must be TriggerPreview")
        reviewer = _text(actor, "evaluation actor")
        if (
            preview.deferral_id != record.deferral_id
            or preview.deferral_version != record.version
            or preview.trigger_kind != record.trigger_kind
        ):
            raise DeferralValidationError("trigger preview identity is stale")
        if not preview.triggered or preview.inbox_state != "due":
            raise DeferralValidationError("deferral trigger is not due")
        expected = _preview(
            record,
            inbox_state=preview.inbox_state,
            triggered=preview.triggered,
            evidence=preview.trigger_evidence,
        )
        if expected != preview:
            raise DeferralValidationError("trigger preview evidence hash is invalid")
        key = (
            record.deferral_id,
            record.trigger_kind,
            preview.trigger_evidence_hash,
        )
        event_id = "deferral-trigger-%s" % sha256_bytes(
            canonical_json_bytes(list(key))
        )[:24]
        return TriggerEvaluation(
            idempotency_key=key,
            event={
                "actor": reviewer,
                "deferral_id": record.deferral_id,
                "deferral_version": record.version,
                "event_id": event_id,
                "trigger_evidence": list(preview.trigger_evidence),
                "trigger_evidence_hash": preview.trigger_evidence_hash,
                "trigger_kind": record.trigger_kind,
            },
            projection={
                "item_id": record.item_id,
                "primary_state": "review-ready",
                "projection_generation_delta": 1,
                "source_trigger_event_id": event_id,
            },
            approval_created=False,
            corpus_effect_created=False,
        )


def _safe_source_ref(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or value.endswith("/")
        or posixpath.normpath(value) != value
        or value in (".", "..")
        or value.startswith("../")
        or "//" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise DeferralValidationError("evidence source reference is unsafe")
    return value


def _metadata(entries: Tuple[Tuple[str, Any], ...]) -> Dict[str, Any]:
    if type(entries) is not tuple:
        raise DeferralValidationError("allowed metadata must be a tuple")
    output: Dict[str, Any] = {}
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 2:
            raise DeferralValidationError("allowed metadata entry is invalid")
        key, value = entry
        if (
            type(key) is not str
            or key not in _SAFE_METADATA_KEYS
            or _SECRET_KEY_FRAGMENT.search(key)
            or key in output
        ):
            raise DeferralValidationError("allowed metadata key is unsafe")
        if type(value) not in (str, int, bool) or (
            type(value) is str
            and (
                len(value.encode("utf-8")) > 4096
                or any(ord(character) < 0x20 for character in value)
            )
        ):
            raise DeferralValidationError("allowed metadata value is unsafe")
        output[key] = value
    canonical_json_bytes(output)
    return output


class DeferralEvidenceCompiler:
    """Compile scope-safe evidence metadata without publishing it."""

    def compile(
        self,
        request: EvidenceAttachmentInput,
    ) -> CompiledEvidenceAttachment:
        if type(request) is not EvidenceAttachmentInput:
            raise TypeError("request must be EvidenceAttachmentInput")
        event_id = _identifier(request.event_id, "evidence event id")
        deferral_id = _identifier(request.deferral_id, "deferral id")
        if type(request.deferral_version) is not int or request.deferral_version < 1:
            raise DeferralValidationError("deferral version is invalid")
        actor = _text(request.actor, "evidence actor")
        if type(request.scope_class) is not str or not request.scope_class:
            raise DeferralValidationError("evidence scope class is invalid")
        if request.raw_body is not None:
            raise DeferralValidationError("raw evidence body is forbidden")
        metadata = _metadata(request.allowed_metadata)
        restricted = request.scope_class in _RESTRICTED_SCOPES
        payload: Dict[str, Any] = {
            "actor": actor,
            "allowed_metadata": metadata,
            "deferral_id": deferral_id,
            "deferral_version": request.deferral_version,
            "event_id": event_id,
            "schema_version": 1,
            "scope_class": request.scope_class,
        }
        if restricted:
            if request.content_sha256 is not None or request.source_ref is not None:
                raise DeferralValidationError(
                    "restricted evidence cannot include source bytes or content hash"
                )
            opaque_source_id = _identifier(
                request.opaque_source_id, "opaque evidence source id"
            )
            attestation = _text(
                request.actor_attestation, "restricted evidence actor attestation"
            )
            payload.update(
                {
                    "actor_attestation": attestation,
                    "opaque_source_id": opaque_source_id,
                }
            )
            identity = {
                "actor_attestation": attestation,
                "allowed_metadata": metadata,
                "deferral_id": deferral_id,
                "deferral_version": request.deferral_version,
                "opaque_source_id": opaque_source_id,
                "scope_class": request.scope_class,
            }
        else:
            source_ref = _safe_source_ref(request.source_ref)
            content_hash = _hash(request.content_sha256, "evidence content hash")
            if request.opaque_source_id is not None or request.actor_attestation is not None:
                raise DeferralValidationError(
                    "eligible evidence cannot include opaque attestation fields"
                )
            payload.update(
                {"content_sha256": content_hash, "source_ref": source_ref}
            )
            identity = {
                "allowed_metadata": metadata,
                "content_sha256": content_hash,
                "deferral_id": deferral_id,
                "deferral_version": request.deferral_version,
                "scope_class": request.scope_class,
                "source_ref": source_ref,
            }
        return CompiledEvidenceAttachment(
            payload=payload,
            idempotency_key=sha256_bytes(canonical_json_bytes(identity)),
        )


__all__ = [
    "CompiledEvidenceAttachment",
    "DeferralEvidenceCompiler",
    "DeferralRecord",
    "DeferralTriggerEvaluator",
    "DeferralValidationError",
    "EvidenceAttachmentInput",
    "ManualReopenEvidence",
    "PublishedEvidence",
    "TriggerEvaluation",
    "TriggerPreview",
]
