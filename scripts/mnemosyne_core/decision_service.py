"""Pure compiler for nonmovement curation decisions.

The compiler validates one exact review choice and returns canonical event and
projection payloads.  It deliberately has no filesystem or SQLite dependency;
the partial-publish-safe submission service owns persistence in a later layer.
"""

from __future__ import annotations

import datetime as _datetime
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_ACTIONS = frozenset(
    ("keep", "link", "defer", "exclude", "correction", "proposal-reject")
)
_WORKSTREAM_RELATIONS = frozenset(("primary", "related", "shared"))
_DOCUMENT_RELATIONS = frozenset(("reference", "derived", "evidence"))
_DOCUMENT_DIRECTIONS = frozenset(
    ("canonical-to-related", "related-to-canonical")
)
_TRIGGERS = frozenset(("date", "workstream-resume", "evidence", "manual-reopen"))
_CORRECTION_FIELDS = frozenset(
    (
        "primary_workstream",
        "related_workstreams",
        "shared",
        "document_role",
        "authority",
        "document_lifecycle",
        "recommended_action",
        "target_path",
    )
)


class DecisionValidationError(ValueError):
    """A proposed nonmovement decision is not safe or fully explained."""


@dataclass(frozen=True)
class WorkstreamRelationInput:
    workstream_id: str
    relation_kind: str
    evidence: str
    provenance: str


@dataclass(frozen=True)
class DocumentRelationInput:
    canonical_item_id: str
    related_item_id: str
    relation_kind: str
    direction: str
    evidence: str
    provenance: str


@dataclass(frozen=True)
class DeferralInput:
    reason: str
    required_evidence: str
    trigger_kind: str
    review_date: Optional[str] = None
    timezone: Optional[str] = None
    workstream_id: Optional[str] = None
    captured_lifecycle: Optional[str] = None
    captured_policy_hash: Optional[str] = None
    owner: Optional[str] = None


@dataclass(frozen=True)
class UnassignedInput:
    reason: str
    assignment_condition: str


@dataclass(frozen=True)
class ItemDecisionInput:
    unit_id: str
    member_item_ids: Tuple[str, ...]
    selected_item_ids: Tuple[str, ...]
    action: str
    reason: Optional[str] = None
    corrections: Tuple[Tuple[str, Any], ...] = ()
    workstream_relations: Tuple[WorkstreamRelationInput, ...] = ()
    document_relations: Tuple[DocumentRelationInput, ...] = ()
    deferral: Optional[DeferralInput] = None
    unassigned: Optional[UnassignedInput] = None


@dataclass(frozen=True)
class DecisionRequest:
    campaign_id: str
    batch_id: str
    base_snapshot_id: str
    base_snapshot_sha256: str
    expected_review_revision: int
    expected_execution_generation: int
    submission_id: str
    next_snapshot_id: str
    actor: str
    decided_at_utc: str
    decisions: Tuple[ItemDecisionInput, ...]


@dataclass(frozen=True)
class CompiledDecisionSet:
    events: Tuple[Dict[str, Any], ...]
    projections: Tuple[Dict[str, Any], ...]
    workstream_relations: Tuple[Dict[str, Any], ...]
    document_relation_events: Tuple[Dict[str, Any], ...]
    deferrals: Tuple[Dict[str, Any], ...]
    unassigned_exceptions: Tuple[Dict[str, Any], ...]


@dataclass(frozen=True)
class ReopenDecisionRequest:
    campaign_id: str
    batch_id: str
    base_snapshot_id: str
    base_snapshot_sha256: str
    expected_review_revision: int
    expected_execution_generation: int
    submission_id: str
    next_snapshot_id: str
    item_id: str
    current_decision_event_id: str
    current_projection_generation: int
    actor: str
    reason: str
    reopened_at_utc: str
    selected_relation_kind: Optional[str] = None
    selected_relation_id: Optional[str] = None


@dataclass(frozen=True)
class CompiledReopen:
    event: Dict[str, Any]
    projection: Dict[str, Any]
    supersessions: Tuple[Dict[str, str], ...]
    named_output_frontier_stale: bool
    membership_reuse_allowed: bool


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise DecisionValidationError("%s is invalid" % label)
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise DecisionValidationError("%s is invalid" % label)
    return value


def _text(value: Any, label: str, *, optional: bool = False) -> Optional[str]:
    if value is None and optional:
        return None
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or len(value.encode("utf-8")) > 16 * 1024
        or any(ord(character) < 0x20 for character in value)
    ):
        raise DecisionValidationError("%s is required" % label)
    return value


def _utc_timestamp(value: Any) -> str:
    text = _text(value, "decided_at_utc")
    if not text.endswith("Z"):
        raise DecisionValidationError("decided_at_utc must use UTC Z notation")
    try:
        parsed = _datetime.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise DecisionValidationError("decided_at_utc is invalid") from exc
    if parsed.utcoffset() != _datetime.timedelta(0):
        raise DecisionValidationError("decided_at_utc must be UTC")
    return text


def _stable_id(prefix: str, payload: Dict[str, Any]) -> str:
    return "%s-%s" % (prefix, sha256_bytes(canonical_json_bytes(payload))[:24])


def _validate_request(request: DecisionRequest) -> None:
    if type(request) is not DecisionRequest:
        raise TypeError("request must be DecisionRequest")
    for value, label in (
        (request.campaign_id, "campaign id"),
        (request.batch_id, "batch id"),
        (request.base_snapshot_id, "base snapshot id"),
        (request.submission_id, "submission id"),
        (request.next_snapshot_id, "next snapshot id"),
    ):
        _identifier(value, label)
    _hash(request.base_snapshot_sha256, "base snapshot hash")
    if (
        type(request.expected_review_revision) is not int
        or request.expected_review_revision < 1
    ):
        raise DecisionValidationError("expected review revision is invalid")
    if (
        type(request.expected_execution_generation) is not int
        or request.expected_execution_generation < 0
    ):
        raise DecisionValidationError("expected execution generation is invalid")
    _text(request.actor, "actor")
    _utc_timestamp(request.decided_at_utc)
    if not request.decisions:
        raise DecisionValidationError("at least one decision is required")


def _validate_membership(decision: ItemDecisionInput) -> Tuple[str, ...]:
    _identifier(decision.unit_id, "review unit id")
    if not decision.member_item_ids:
        raise DecisionValidationError("review unit membership is required")
    members = tuple(
        _identifier(value, "member item id") for value in decision.member_item_ids
    )
    selected = tuple(
        _identifier(value, "selected item id") for value in decision.selected_item_ids
    )
    if tuple(sorted(set(members))) != members:
        raise DecisionValidationError("member item ids must be unique and sorted")
    if tuple(sorted(set(selected))) != selected:
        raise DecisionValidationError("selected item ids must be unique and sorted")
    if selected != members:
        raise DecisionValidationError(
            "partial folder decision is forbidden; explode the review unit first"
        )
    return members


def _validate_workstream_relation(
    relation: WorkstreamRelationInput,
) -> None:
    if type(relation) is not WorkstreamRelationInput:
        raise DecisionValidationError("workstream relation is invalid")
    _identifier(relation.workstream_id, "workstream id")
    if relation.relation_kind not in _WORKSTREAM_RELATIONS:
        raise DecisionValidationError("workstream relation kind is invalid")
    _text(relation.evidence, "workstream relation evidence")
    _text(relation.provenance, "workstream relation provenance")


def _validate_document_relation(
    relation: DocumentRelationInput,
    item_id: str,
) -> None:
    if type(relation) is not DocumentRelationInput:
        raise DecisionValidationError("document relation is invalid")
    _identifier(relation.canonical_item_id, "canonical item id")
    _identifier(relation.related_item_id, "related item id")
    if relation.canonical_item_id == relation.related_item_id:
        raise DecisionValidationError("document relation endpoints must differ")
    if item_id not in (relation.canonical_item_id, relation.related_item_id):
        raise DecisionValidationError("document relation does not include the decided item")
    if relation.relation_kind not in _DOCUMENT_RELATIONS:
        raise DecisionValidationError("document relation kind is invalid")
    if relation.direction not in _DOCUMENT_DIRECTIONS:
        raise DecisionValidationError("document relation direction is invalid")
    if (
        relation.direction == "canonical-to-related"
        and item_id != relation.canonical_item_id
    ) or (
        relation.direction == "related-to-canonical"
        and item_id != relation.related_item_id
    ):
        raise DecisionValidationError("document relation direction does not match item")
    _text(relation.evidence, "document relation evidence")
    _text(relation.provenance, "document relation provenance")


def _deferral_payload(value: DeferralInput) -> Dict[str, Any]:
    if type(value) is not DeferralInput:
        raise DecisionValidationError("defer requires structured deferral input")
    reason = _text(value.reason, "defer reason")
    required = _text(value.required_evidence, "defer required evidence")
    if value.trigger_kind not in _TRIGGERS:
        raise DecisionValidationError("defer revisit trigger is invalid")
    owner = _text(value.owner, "defer owner", optional=True)
    review_date = value.review_date
    timezone = value.timezone
    workstream_id = value.workstream_id
    captured_lifecycle = value.captured_lifecycle
    captured_policy_hash = value.captured_policy_hash
    if value.trigger_kind == "date":
        if type(review_date) is not str:
            raise DecisionValidationError("date trigger review date is required")
        try:
            _datetime.date.fromisoformat(review_date)
        except ValueError as exc:
            raise DecisionValidationError("date trigger review date is invalid") from exc
        if type(timezone) is not str or not timezone:
            raise DecisionValidationError("date trigger timezone is required")
        try:
            ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise DecisionValidationError("date trigger timezone is invalid") from exc
        if any(
            value is not None
            for value in (workstream_id, captured_lifecycle, captured_policy_hash)
        ):
            raise DecisionValidationError("date trigger fields are inconsistent")
    elif value.trigger_kind == "workstream-resume":
        _identifier(workstream_id, "defer workstream id")
        if captured_lifecycle not in ("paused", "completed"):
            raise DecisionValidationError(
                "workstream resume captured lifecycle must be non-active"
            )
        _hash(captured_policy_hash, "defer captured policy hash")
        if review_date is not None or timezone is not None:
            raise DecisionValidationError("workstream resume trigger fields are inconsistent")
    else:
        if any(
            value is not None
            for value in (
                review_date,
                timezone,
                workstream_id,
                captured_lifecycle,
                captured_policy_hash,
            )
        ):
            raise DecisionValidationError("defer trigger fields are inconsistent")
    return {
        "captured_lifecycle": captured_lifecycle,
        "captured_policy_hash": captured_policy_hash,
        "owner": owner,
        "reason": reason,
        "required_evidence": required,
        "review_date": review_date,
        "timezone": timezone,
        "trigger_kind": value.trigger_kind,
        "workstream_id": workstream_id,
    }


def _corrections(value: Tuple[Tuple[str, Any], ...]) -> Dict[str, Any]:
    if type(value) is not tuple:
        raise DecisionValidationError("corrections must be a tuple")
    output: Dict[str, Any] = {}
    for entry in value:
        if type(entry) is not tuple or len(entry) != 2:
            raise DecisionValidationError("correction entry is invalid")
        field, changed = entry
        if field not in _CORRECTION_FIELDS or field in output:
            raise DecisionValidationError("correction field is invalid or duplicated")
        if type(changed) not in (str, bool) or (type(changed) is str and not changed):
            raise DecisionValidationError("correction value is invalid")
        output[field] = changed
    canonical_json_bytes(output)
    return output


class DecisionService:
    """Validate and deterministically compile nonmovement review actions."""

    def compile(self, request: DecisionRequest) -> CompiledDecisionSet:
        _validate_request(request)
        events = []
        projections = []
        workstream_relations = []
        document_relation_events = []
        deferrals = []
        unassigned_exceptions = []
        seen_items = set()

        for decision_index, decision in enumerate(request.decisions):
            if type(decision) is not ItemDecisionInput:
                raise DecisionValidationError("item decision is invalid")
            members = _validate_membership(decision)
            if decision.action not in _ACTIONS:
                raise DecisionValidationError("decision action is invalid")
            corrections = _corrections(decision.corrections)
            reason = decision.reason
            if decision.action != "defer":
                reason = _text(reason, "%s reason" % decision.action)
            elif reason is not None:
                raise DecisionValidationError("defer reason belongs in structured deferral")

            if decision.action == "link" and not (
                decision.workstream_relations or decision.document_relations
            ):
                raise DecisionValidationError("link requires a confirmed relation")
            if decision.action not in ("link", "correction") and (
                decision.workstream_relations or decision.document_relations
            ):
                raise DecisionValidationError(
                    "relations require a link or correction action"
                )
            if decision.action == "defer":
                deferral_payload = _deferral_payload(decision.deferral)
            else:
                if decision.deferral is not None:
                    raise DecisionValidationError("structured deferral requires defer action")
                deferral_payload = None
            if decision.action == "correction":
                if not (
                    corrections
                    or decision.unassigned is not None
                    or decision.workstream_relations
                    or decision.document_relations
                ):
                    raise DecisionValidationError("correction requires a changed field")
            elif corrections or decision.unassigned is not None:
                raise DecisionValidationError("correction payload requires correction action")

            primary_count = sum(
                relation.relation_kind == "primary"
                for relation in decision.workstream_relations
            )
            if primary_count > 1:
                raise DecisionValidationError(
                    "an item cannot have multiple current primary workstreams"
                )
            workstream_keys = set()
            for relation in decision.workstream_relations:
                _validate_workstream_relation(relation)
                key = (relation.workstream_id, relation.relation_kind)
                if key in workstream_keys:
                    raise DecisionValidationError("workstream relation is duplicated")
                workstream_keys.add(key)
            if len(members) != 1 and decision.document_relations:
                raise DecisionValidationError(
                    "document relation decisions require an exploded single-item unit"
                )
            document_keys = set()
            for relation in decision.document_relations:
                _validate_document_relation(relation, members[0])
                key = (
                    relation.canonical_item_id,
                    relation.related_item_id,
                    relation.relation_kind,
                )
                if key in document_keys:
                    raise DecisionValidationError("document relation is duplicated")
                document_keys.add(key)

            unassigned_payload = None
            if decision.unassigned is not None:
                if type(decision.unassigned) is not UnassignedInput:
                    raise DecisionValidationError("unassigned input is invalid")
                unassigned_payload = {
                    "assignment_condition": _text(
                        decision.unassigned.assignment_condition,
                        "unassigned assignment condition",
                    ),
                    "reason": _text(
                        decision.unassigned.reason,
                        "unassigned reason",
                    ),
                }

            for member_index, item_id in enumerate(members):
                if item_id in seen_items:
                    raise DecisionValidationError("item decision is duplicated")
                seen_items.add(item_id)
                event_seed = {
                    "action": decision.action,
                    "decision_index": decision_index,
                    "item_id": item_id,
                    "member_index": member_index,
                    "submission_id": request.submission_id,
                }
                event_id = _stable_id("decision", event_seed)
                event = {
                    "action": decision.action,
                    "actor": request.actor,
                    "base_snapshot_id": request.base_snapshot_id,
                    "batch_id": request.batch_id,
                    "campaign_id": request.campaign_id,
                    "corrections": corrections,
                    "decided_at_utc": request.decided_at_utc,
                    "event_id": event_id,
                    "item_id": item_id,
                    "next_snapshot_id": request.next_snapshot_id,
                    "reason": reason,
                    "submission_id": request.submission_id,
                    "unit_id": decision.unit_id,
                }
                events.append(event)

                primary_state = {
                    "keep": "keep",
                    "link": "linked",
                    "defer": "deferred",
                    "exclude": "excluded",
                    "correction": "review-ready",
                    "proposal-reject": "review-ready",
                }[decision.action]
                projections.append(
                    {
                        "correction_required": decision.action == "proposal-reject",
                        "item_id": item_id,
                        "primary_state": primary_state,
                        "projection_generation_delta": 1,
                        "source_decision_event_id": event_id,
                        "unassigned": unassigned_payload is not None,
                    }
                )

                for relation_index, relation in enumerate(
                    decision.workstream_relations
                ):
                    relation_id = _stable_id(
                        "workstream-relation",
                        {
                            "event_id": event_id,
                            "index": relation_index,
                            "item_id": item_id,
                            "kind": relation.relation_kind,
                            "workstream_id": relation.workstream_id,
                        },
                    )
                    workstream_relations.append(
                        {
                            "evidence": relation.evidence,
                            "item_id": item_id,
                            "provenance": relation.provenance,
                            "relation_id": relation_id,
                            "relation_kind": relation.relation_kind,
                            "source_decision_event_id": event_id,
                            "state": "current",
                            "workstream_id": relation.workstream_id,
                        }
                    )

                for relation_index, relation in enumerate(
                    decision.document_relations
                ):
                    relation_id = _stable_id(
                        "document-relation",
                        {
                            "canonical_item_id": relation.canonical_item_id,
                            "event_id": event_id,
                            "index": relation_index,
                            "kind": relation.relation_kind,
                            "related_item_id": relation.related_item_id,
                        },
                    )
                    document_relation_events.append(
                        {
                            "canonical_item_id": relation.canonical_item_id,
                            "direction": relation.direction,
                            "event_id": _stable_id(
                                "document-relation-event",
                                {"decision_event_id": event_id, "relation_id": relation_id},
                            ),
                            "evidence": relation.evidence,
                            "provenance": relation.provenance,
                            "related_item_id": relation.related_item_id,
                            "relation_id": relation_id,
                            "relation_kind": relation.relation_kind,
                            "source_decision_event_id": event_id,
                            "state": "current",
                        }
                    )

                if deferral_payload is not None:
                    deferral_id = _stable_id(
                        "deferral", {"event_id": event_id, "item_id": item_id}
                    )
                    row = dict(deferral_payload)
                    row.update(
                        {
                            "deferral_id": deferral_id,
                            "item_id": item_id,
                            "source_decision_event_id": event_id,
                            "state": "waiting",
                            "version": 1,
                        }
                    )
                    deferrals.append(row)

                if unassigned_payload is not None:
                    row = dict(unassigned_payload)
                    row.update(
                        {
                            "exception_id": _stable_id(
                                "unassigned", {"event_id": event_id, "item_id": item_id}
                            ),
                            "item_id": item_id,
                            "source_decision_event_id": event_id,
                            "state": "current",
                        }
                    )
                    unassigned_exceptions.append(row)

        return CompiledDecisionSet(
            events=tuple(events),
            projections=tuple(projections),
            workstream_relations=tuple(workstream_relations),
            document_relation_events=tuple(document_relation_events),
            deferrals=tuple(deferrals),
            unassigned_exceptions=tuple(unassigned_exceptions),
        )

    def compile_reopen(self, request: ReopenDecisionRequest) -> CompiledReopen:
        """Compile a stale-safe reopen intent without mutating its current row."""

        if type(request) is not ReopenDecisionRequest:
            raise TypeError("request must be ReopenDecisionRequest")
        for value, label in (
            (request.campaign_id, "campaign id"),
            (request.batch_id, "batch id"),
            (request.base_snapshot_id, "base snapshot id"),
            (request.submission_id, "submission id"),
            (request.next_snapshot_id, "next snapshot id"),
            (request.item_id, "item id"),
            (request.current_decision_event_id, "current decision event id"),
        ):
            _identifier(value, label)
        _hash(request.base_snapshot_sha256, "base snapshot hash")
        if (
            type(request.expected_review_revision) is not int
            or request.expected_review_revision < 1
        ):
            raise DecisionValidationError("expected review revision is invalid")
        if (
            type(request.expected_execution_generation) is not int
            or request.expected_execution_generation < 0
        ):
            raise DecisionValidationError("expected execution generation is invalid")
        if (
            type(request.current_projection_generation) is not int
            or request.current_projection_generation < 1
        ):
            raise DecisionValidationError("current projection generation is invalid")
        _text(request.actor, "actor")
        reason = _text(request.reason, "reopen reason")
        reopened_at = _utc_timestamp(request.reopened_at_utc)
        if (request.selected_relation_kind is None) != (
            request.selected_relation_id is None
        ):
            raise DecisionValidationError("selected relation identity is incomplete")
        if request.selected_relation_kind is not None:
            if request.selected_relation_kind not in (
                "workstream-relation",
                "document-relation",
            ):
                raise DecisionValidationError("selected relation kind is invalid")
            _identifier(request.selected_relation_id, "selected relation id")

        event_seed = {
            "current_decision_event_id": request.current_decision_event_id,
            "item_id": request.item_id,
            "selected_relation_id": request.selected_relation_id,
            "submission_id": request.submission_id,
        }
        event_id = _stable_id("decision", event_seed)
        event = {
            "action": "reopen",
            "actor": request.actor,
            "base_snapshot_id": request.base_snapshot_id,
            "batch_id": request.batch_id,
            "campaign_id": request.campaign_id,
            "current_decision_event_id": request.current_decision_event_id,
            "current_projection_generation": request.current_projection_generation,
            "event_id": event_id,
            "item_id": request.item_id,
            "next_snapshot_id": request.next_snapshot_id,
            "reason": reason,
            "reopened_at_utc": reopened_at,
            "selected_relation_id": request.selected_relation_id,
            "selected_relation_kind": request.selected_relation_kind,
            "submission_id": request.submission_id,
        }
        projection = {
            "correction_required": False,
            "item_id": request.item_id,
            "primary_state": "review-ready",
            "projection_generation": request.current_projection_generation + 1,
            "source_decision_event_id": event_id,
            "unassigned": False,
        }
        supersessions = [
            {
                "kind": "decision-projection",
                "subject_id": request.current_decision_event_id,
            }
        ]
        if request.selected_relation_kind is not None:
            supersessions.append(
                {
                    "kind": request.selected_relation_kind,
                    "subject_id": request.selected_relation_id,
                }
            )
        return CompiledReopen(
            event=event,
            projection=projection,
            supersessions=tuple(supersessions),
            named_output_frontier_stale=True,
            membership_reuse_allowed=False,
        )


__all__ = [
    "CompiledDecisionSet",
    "CompiledReopen",
    "DecisionRequest",
    "DecisionService",
    "DecisionValidationError",
    "DeferralInput",
    "DocumentRelationInput",
    "ItemDecisionInput",
    "ReopenDecisionRequest",
    "UnassignedInput",
    "WorkstreamRelationInput",
]
