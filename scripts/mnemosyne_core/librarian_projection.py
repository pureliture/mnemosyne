"""Safe Librarian immutable record projection helpers."""

from __future__ import annotations

from collections.abc import Callable

from . import artifact_contract, librarian_contract
from .canonical_json import canonical_json_bytes


EFFECT_PREFIXES = (
    "safe-librarian-proposal-",
    "safe-librarian-decision-",
    "safe-librarian-intent-",
    "safe-librarian-result-",
)
READ_LIMIT = 16_385

_EVIDENCE_KEYS = frozenset(("proposals", "decisions", "intents", "results"))
_RecordEntry = tuple[artifact_contract.SealedArtifactRef, dict[str, object]]
_RawRecordEntry = tuple[artifact_contract.SealedArtifactRef, bytes]


def _matches_scope(record: dict[str, object], scope_path: str) -> bool:
    return any(
        path == scope_path or path.startswith(scope_path + "/")
        for path in (
            record["source_relative_path"],
            record["target_relative_path"],
        )
    )


def _proposal_id_from_effect_id(effect_id: object, prefix: str) -> str:
    if type(effect_id) is not str or not effect_id.startswith(prefix):
        raise TypeError("Safe Librarian record evidence is invalid")
    return "p-" + effect_id.removeprefix(prefix)


def _proposal_id_from_proposal_record(record: dict[str, object]) -> str:
    return record["proposal_id"]


def _proposal_id_from_decision_record(record: dict[str, object]) -> str:
    return record["effect_summary"]["proposal_id"]


def _proposal_id_from_embedded_proposal(record: dict[str, object]) -> str:
    proposal_reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
        canonical_json_bytes(record["proposal"])
    )
    return proposal_reference.canonical_path.rsplit("/", 1)[-1][:-5]


def _append_partitioned_record(
    evidence: dict[str, list[_RawRecordEntry]],
    *,
    key: str,
    expected_schema: artifact_contract.SchemaIdentity,
    expected_path: str,
    reference: object,
    artifact_bytes: object,
) -> None:
    if (
        type(reference) is not artifact_contract.SealedArtifactRef
        or reference.schema != expected_schema
        or reference.canonical_path != expected_path
        or type(artifact_bytes) is not bytes
    ):
        raise TypeError("Safe Librarian record evidence is invalid")
    evidence[key].append((reference, artifact_bytes))


def partition_finalized_records(
    records: object,
) -> dict[str, tuple[_RawRecordEntry, ...]]:
    evidence: dict[str, list[_RawRecordEntry]] = {
        "proposals": [],
        "decisions": [],
        "intents": [],
        "results": [],
    }
    for effect_id, reference, artifact_bytes in records:
        if type(effect_id) is not str:
            raise TypeError("Safe Librarian record evidence is invalid")
        if effect_id.startswith("safe-librarian-proposal-"):
            proposal_id = _proposal_id_from_effect_id(
                effect_id,
                "safe-librarian-proposal-",
            )
            _append_partitioned_record(
                evidence,
                key="proposals",
                expected_schema=librarian_contract.PROPOSAL_SCHEMA,
                expected_path=librarian_contract.proposal_artifact_path(proposal_id),
                reference=reference,
                artifact_bytes=artifact_bytes,
            )
        elif effect_id.startswith("safe-librarian-decision-"):
            proposal_id = _proposal_id_from_effect_id(
                effect_id,
                "safe-librarian-decision-",
            )
            _append_partitioned_record(
                evidence,
                key="decisions",
                expected_schema=librarian_contract.DECISION_SCHEMA,
                expected_path=librarian_contract.decision_artifact_path(proposal_id),
                reference=reference,
                artifact_bytes=artifact_bytes,
            )
        elif effect_id.startswith("safe-librarian-intent-"):
            proposal_id = _proposal_id_from_effect_id(
                effect_id,
                "safe-librarian-intent-",
            )
            _append_partitioned_record(
                evidence,
                key="intents",
                expected_schema=librarian_contract.INTENT_SCHEMA,
                expected_path=librarian_contract.intent_artifact_path(proposal_id),
                reference=reference,
                artifact_bytes=artifact_bytes,
            )
        elif effect_id.startswith("safe-librarian-result-"):
            proposal_id = _proposal_id_from_effect_id(
                effect_id,
                "safe-librarian-result-",
            )
            _append_partitioned_record(
                evidence,
                key="results",
                expected_schema=librarian_contract.RESULT_SCHEMA,
                expected_path=librarian_contract.result_artifact_path(proposal_id),
                reference=reference,
                artifact_bytes=artifact_bytes,
            )
        else:
            raise TypeError("Safe Librarian record evidence is invalid")
    return {key: tuple(value) for key, value in evidence.items()}


def _index_record_evidence(
    entries: object,
    *,
    decode_record: Callable[[object], dict[str, object]],
    proposal_id_from_record: Callable[[dict[str, object]], str],
    schema: artifact_contract.SchemaIdentity,
    artifact_path: Callable[[str], str],
    invalid_message: str,
) -> dict[str, _RecordEntry]:
    records: dict[str, _RecordEntry] = {}
    for reference, record_bytes in entries:
        record = decode_record(record_bytes)
        proposal_id = proposal_id_from_record(record)
        if (
            type(reference) is not artifact_contract.SealedArtifactRef
            or reference.schema != schema
            or reference.canonical_path != artifact_path(proposal_id)
            or proposal_id in records
        ):
            raise TypeError(invalid_message)
        records[proposal_id] = (reference, record)
    return records


def _index_all_evidence(
    evidence: object,
) -> tuple[
    dict[str, _RecordEntry],
    dict[str, _RecordEntry],
    dict[str, _RecordEntry],
    dict[str, _RecordEntry],
]:
    if type(evidence) is not dict or set(evidence) != _EVIDENCE_KEYS:
        raise TypeError("Safe Librarian record evidence is invalid")
    proposals = _index_record_evidence(
        evidence["proposals"],
        decode_record=librarian_contract.decode_proposal_record,
        proposal_id_from_record=_proposal_id_from_proposal_record,
        schema=librarian_contract.PROPOSAL_SCHEMA,
        artifact_path=librarian_contract.proposal_artifact_path,
        invalid_message="Safe Librarian proposal evidence is invalid",
    )
    decisions = _index_record_evidence(
        evidence["decisions"],
        decode_record=librarian_contract.decode_decision_record,
        proposal_id_from_record=_proposal_id_from_decision_record,
        schema=librarian_contract.DECISION_SCHEMA,
        artifact_path=librarian_contract.decision_artifact_path,
        invalid_message="Safe Librarian decision evidence is invalid",
    )
    if not set(decisions).issubset(proposals):
        raise TypeError("Safe Librarian decision has no proposal")
    intents = _index_record_evidence(
        evidence["intents"],
        decode_record=librarian_contract.decode_intent_record,
        proposal_id_from_record=_proposal_id_from_embedded_proposal,
        schema=librarian_contract.INTENT_SCHEMA,
        artifact_path=librarian_contract.intent_artifact_path,
        invalid_message="Safe Librarian intent evidence is invalid",
    )
    results = _index_record_evidence(
        evidence["results"],
        decode_record=librarian_contract.decode_result_record,
        proposal_id_from_record=_proposal_id_from_embedded_proposal,
        schema=librarian_contract.RESULT_SCHEMA,
        artifact_path=librarian_contract.result_artifact_path,
        invalid_message="Safe Librarian result evidence is invalid",
    )
    if not set(intents).issubset(proposals) or not set(results).issubset(proposals):
        raise TypeError("Safe Librarian placement evidence has no proposal")
    return proposals, decisions, intents, results


def _project_one_record(
    *,
    proposal_id: str,
    proposal_reference: artifact_contract.SealedArtifactRef,
    proposal: dict[str, object],
    decision_entry: _RecordEntry | None,
    intent_entry: _RecordEntry | None,
    result_entry: _RecordEntry | None,
) -> dict[str, object]:
    decision_reference = None
    decision = None
    if decision_entry is not None:
        decision_reference, decision = decision_entry
        if decision["proposal"] != proposal_reference.canonical_value:
            raise TypeError("Safe Librarian decision proposal is invalid")
    intent_reference = None
    intent = None
    if intent_entry is not None:
        intent_reference, intent = intent_entry
        if (
            decision_reference is None
            or intent["proposal"] != proposal_reference.canonical_value
            or intent["decision"] != decision_reference.canonical_value
        ):
            raise TypeError("Safe Librarian intent chain is invalid")
    result_reference = None
    placement_result = None
    if result_entry is not None:
        result_reference, placement_result = result_entry
        if placement_result["proposal"] != proposal_reference.canonical_value:
            raise TypeError("Safe Librarian result proposal is invalid")
        expected_intent = (
            None if intent_reference is None else intent_reference.canonical_value
        )
        if placement_result["intent"] != expected_intent:
            raise TypeError("Safe Librarian result intent is invalid")
    if decision is None:
        status = "PENDING"
    elif decision["decision"] == "REJECTED":
        if intent is not None or placement_result is not None:
            raise TypeError("Rejected Safe Librarian proposal has placement evidence")
        status = "REJECTED"
    elif placement_result is not None:
        status = placement_result["status"]
    elif intent is not None:
        status = "RECOVERY_REQUIRED"
    else:
        status = "APPROVED_PENDING_APPLY"
    return {
        "proposal_id": proposal_id,
        "status": status,
        "proposal": proposal_reference.canonical_value,
        "decision": (
            None if decision_reference is None else decision_reference.canonical_value
        ),
        "intent": (
            None if intent_reference is None else intent_reference.canonical_value
        ),
        "placement_result": (
            None if result_reference is None else result_reference.canonical_value
        ),
        "placement_reason_code": (
            None if placement_result is None else placement_result["reason_code"]
        ),
        "source_relative_path": proposal["source_relative_path"],
        "target_relative_path": proposal["target_relative_path"],
        "destination_kind": proposal["destination_kind"],
        "destination_id": proposal["destination_id"],
        "reason": proposal["reason"],
        "created_at": proposal["created_at"],
        "proposal_actor": proposal["actor"],
        "decision_id": None if decision is None else decision["decision_id"],
        "decision_value": None if decision is None else decision["decision"],
        "decided_at": None if decision is None else decision["decided_at"],
        "decision_actor": None if decision is None else decision["actor"],
        "decision_reason": None if decision is None else decision["decision_reason"],
    }


def project_record_page(
    evidence: object,
    *,
    scope_path: str,
    view: str,
    offset: int,
    maximum: int,
) -> dict[str, object]:
    proposals, decisions, intents, results = _index_all_evidence(evidence)
    records = []
    for proposal_id in sorted(proposals):
        proposal_reference, proposal = proposals[proposal_id]
        if not _matches_scope(proposal, scope_path):
            continue
        decision_entry = decisions.get(proposal_id)
        if view == "pending" and decision_entry is not None:
            continue
        records.append(
            _project_one_record(
                proposal_id=proposal_id,
                proposal_reference=proposal_reference,
                proposal=proposal,
                decision_entry=decision_entry,
                intent_entry=intents.get(proposal_id),
                result_entry=results.get(proposal_id),
            )
        )
    page = records[offset : offset + maximum]
    truncated = offset + len(page) < len(records)
    return {
        "schema_version": 1,
        "view": view,
        "scope": {"relative_path": scope_path},
        "offset": offset,
        "returned": len(page),
        "next_offset": offset + len(page) if truncated else None,
        "truncated": truncated,
        "records": page,
    }


__all__ = [
    "EFFECT_PREFIXES",
    "READ_LIMIT",
    "partition_finalized_records",
    "project_record_page",
]
