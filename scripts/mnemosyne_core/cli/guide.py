"""TTY-only human request drafting for the public Curation surface."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .. import (
    activation_contract,
    artifact_contract,
    librarian_contract,
    navigation_draft,
    operation_contract,
)
from ..canonical_json import canonical_json_bytes
from ..operation_contract import codec as operation_codec
from . import context_activation
from .canonical_file import CanonicalFileError, read_owner_only_file
from .request_builder import (
    build_activation_request,
    build_decision_request,
    build_placement_request,
    build_proposal_request,
    build_view_request,
)


def _fields_present(*values: object) -> bool:
    return any(value is not None for value in values)


def _load_fresh_activation_audit(*, audit_file: object, root: object) -> dict[str, object]:
    audit_raw = read_owner_only_file(
        audit_file,
        label="fresh Curation audit",
        max_bytes=operation_contract.MAX_OPERATION_REQUEST_BYTES,
    )
    try:
        outcome = json.loads(audit_raw.decode("utf-8"))
        request_sha256 = outcome.get("request_sha256")
        if (
            type(outcome) is not dict
            or set(outcome) != {"outcome_kind", "request_sha256", "result"}
            or outcome["outcome_kind"] != "completed"
            or type(request_sha256) is not str
            or len(request_sha256) != 64
            or any(character not in "0123456789abcdef" for character in request_sha256)
            or canonical_json_bytes(outcome) != audit_raw
        ):
            raise ValueError("fresh Curation audit is invalid")
        return activation_contract.require_fresh_audit_result(
            outcome["result"],
            root=root,
        )
    except (AttributeError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("fresh Curation audit is invalid") from exc


def _load_completed_artifact(
    *,
    request_file: object,
    outcome_file: object,
    operation_kind: str,
    schema: artifact_contract.SchemaIdentity,
    artifact_path,
) -> tuple[
    operation_contract.OperationRequest,
    artifact_contract.SealedArtifactRef,
]:
    request_raw = read_owner_only_file(
        request_file,
        label="prior Curation request",
        max_bytes=operation_contract.MAX_OPERATION_REQUEST_BYTES,
    )
    outcome_raw = read_owner_only_file(
        outcome_file,
        label="prior Curation outcome",
        max_bytes=operation_contract.MAX_OPERATION_REQUEST_BYTES,
    )
    request = operation_codec.decode_operation_request(request_raw)
    try:
        outcome = json.loads(outcome_raw.decode("utf-8"))
        if (
            type(outcome) is not dict
            or set(outcome)
            != {"outcome_kind", "request_sha256", "result_artifact"}
            or outcome["outcome_kind"] != "completed"
            or outcome["request_sha256"] != request.sha256
            or canonical_json_bytes(outcome) != outcome_raw
            or request.operation_kind != operation_kind
        ):
            raise ValueError("prior Curation result is invalid")
        reference = artifact_contract.SealedArtifactRef.from_canonical_bytes(
            canonical_json_bytes(outcome["result_artifact"])
        )
        proposal_id = librarian_contract.require_proposal_id(
            request.scope["proposal_id"]
        )
        if (
            reference.schema != schema
            or reference.canonical_path != artifact_path(proposal_id)
            or reference.media_type != "application/json"
        ):
            raise ValueError("prior Curation artifact is invalid")
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("prior Curation result is invalid") from exc
    return request, reference


def guide_request(
    *,
    root: object,
    actor: object,
    draft: object,
    view: object,
    max_items: object,
    offset: object,
    workstream_ref: object = None,
    relative_path: object = None,
    source_relative_path: object = None,
    target_relative_path: object = None,
    destination_kind: object = None,
    destination_id: object = None,
    reason: object = None,
    max_entries: object = None,
    max_depth: object = None,
    max_hint_bytes: object = None,
    max_total_bytes: object = None,
    proposal_request_file: object = None,
    proposal_outcome_file: object = None,
    decision: object = None,
    decision_reason: object = None,
    decision_request_file: object = None,
    decision_outcome_file: object = None,
    audit_file: object = None,
    expected_plan_sha256: object = None,
    stdin_isatty: bool,
    stdout_isatty: bool,
    navigation_review_package: object = None,
    navigation_proposed_document_file: object = None,
    navigation_source_map_file: object = None,
    navigation_output_directory: object = None,
) -> tuple[int, str, bool]:
    """Produce a reviewable request draft; this adapter never executes it."""

    if not stdin_isatty or not stdout_isatty:
        return 2, "curation guide requires an interactive TTY\n", True
    navigation_fields = (
        navigation_review_package,
        navigation_proposed_document_file,
        navigation_source_map_file,
        navigation_output_directory,
    )
    try:
        if draft == "activation":
            if (
                view != "scope"
                or offset != 0
                or audit_file is None
                or _fields_present(
                    max_items,
                    workstream_ref,
                    relative_path,
                    source_relative_path,
                    target_relative_path,
                    destination_kind,
                    destination_id,
                    reason,
                    max_entries,
                    max_depth,
                    max_hint_bytes,
                    max_total_bytes,
                    proposal_request_file,
                    proposal_outcome_file,
                    decision,
                    decision_reason,
                    decision_request_file,
                    decision_outcome_file,
                    expected_plan_sha256,
                    *navigation_fields,
                )
            ):
                raise ValueError("activation draft fields are invalid")
            audit_result = _load_fresh_activation_audit(
                audit_file=audit_file,
                root=root,
            )
            request = build_activation_request(
                root=root,
                actor=actor,
                activation_id="act-" + uuid.uuid4().hex,
                audit_result=audit_result,
            )
            effect_text = (
                f"exact root: {request.root}\n"
                f"activation id: {request.scope['activation_id']}\n"
                "writable namespace: _registry/curation/**\n"
                "corpus effect: none — no document will move.\n"
            )
        elif draft == "context-activation":
            if (
                view != "scope"
                or offset != 0
                or navigation_review_package is None
                or expected_plan_sha256 is None
                or decision != "APPROVE_ALL"
                or _fields_present(
                    max_items,
                    workstream_ref,
                    relative_path,
                    source_relative_path,
                    target_relative_path,
                    destination_kind,
                    destination_id,
                    reason,
                    max_entries,
                    max_depth,
                    max_hint_bytes,
                    max_total_bytes,
                    proposal_request_file,
                    proposal_outcome_file,
                    decision_reason,
                    decision_request_file,
                    decision_outcome_file,
                    audit_file,
                    navigation_proposed_document_file,
                    navigation_source_map_file,
                    navigation_output_directory,
                )
            ):
                raise ValueError("Context activation draft fields are invalid")
            request, effect_paths = context_activation.build_context_activation_draft(
                root=root,
                actor=actor,
                review_package_directory=navigation_review_package,
                expected_plan_sha256=expected_plan_sha256,
                decision=decision,
            )
            effects = "".join(
                f"sealed effect: {source} -> {target}\n"
                for source, target in effect_paths
            )
            effect_text = (
                "This Context activation will move only the sealed effect(s) "
                "when dispatched.\n"
                f"sealed effect count: {len(effect_paths)}\n"
                f"{effects}"
            )
        elif draft == "navigation":
            if (
                view != "scope"
                or offset != 0
                or any(value is None for value in navigation_fields)
                or _fields_present(
                    max_items,
                    workstream_ref,
                    relative_path,
                    source_relative_path,
                    target_relative_path,
                    destination_kind,
                    destination_id,
                    reason,
                    max_entries,
                    max_depth,
                    max_hint_bytes,
                    max_total_bytes,
                    proposal_request_file,
                    proposal_outcome_file,
                    decision,
                    decision_reason,
                    decision_request_file,
                    decision_outcome_file,
                    audit_file,
                    expected_plan_sha256,
                )
            ):
                raise ValueError("navigation draft fields are invalid")
            root_path = Path(root)
            parent_package = Path(navigation_review_package)
            output_directory = Path(navigation_output_directory)
            proposed_file = Path(navigation_proposed_document_file)
            source_map_file = Path(navigation_source_map_file)
            resolved_root = root_path.resolve()
            for path in (parent_package, output_directory, proposed_file, source_map_file):
                resolved = path.resolve()
                if resolved == resolved_root or resolved_root in resolved.parents:
                    raise ValueError("navigation draft artifacts must stay outside root")
            proposed_document = read_owner_only_file(
                str(proposed_file),
                label="proposed navigation document",
                max_bytes=8 * 1024 * 1024,
            )
            source_map = read_owner_only_file(
                str(source_map_file),
                label="navigation source map",
                max_bytes=1024 * 1024,
            )
            navigation_draft.require_empty_navigation_review_directory(
                output_directory
            )
            payload, semantic = navigation_draft.compile_navigation_review(
                root=root_path,
                parent_review_directory=parent_package,
                proposed_document=proposed_document,
                source_map=source_map,
                rendered_at=datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                renderer_id="mnemosyne-navigation-guide",
            )
            hashes = navigation_draft.write_navigation_review(
                output_directory,
                payload,
                root=root_path,
            )
            return (
                0,
                "Navigation entry-document draft created. 적용되지 않았습니다.\n"
                f"review package: {output_directory}\n"
                f"parent_plan_sha256: {semantic['parent_plan_sha256']}\n"
                f"output_content_sha256: {semantic['output']['content_sha256']}\n"
                f"review_markdown_sha256: {hashes.markdown_sha256}\n"
                "source documents: unchanged\n"
                "dispatch request: none\n",
                False,
            )
        elif draft == "proposal":
            if (
                offset != 0
                or _fields_present(
                    max_items,
                    workstream_ref,
                    relative_path,
                    max_hint_bytes,
                    proposal_request_file,
                    proposal_outcome_file,
                    decision,
                    decision_reason,
                    decision_request_file,
                    decision_outcome_file,
                    audit_file,
                    expected_plan_sha256,
                    *navigation_fields,
                )
            ):
                raise ValueError("proposal draft fields are invalid")
            request = build_proposal_request(
                root=root,
                actor=actor,
                proposal_id="p-" + uuid.uuid4().hex,
                source_relative_path=source_relative_path,
                target_relative_path=target_relative_path,
                destination_kind=destination_kind,
                destination_id=destination_id,
                reason=reason,
                max_entries=4096 if max_entries is None else max_entries,
                max_depth=16 if max_depth is None else max_depth,
                max_total_bytes=(
                    256 * 1024 * 1024
                    if max_total_bytes is None
                    else max_total_bytes
                ),
            )
            effect_text = (
                "The source remains unchanged; it has not been moved.\n"
            )
        elif draft == "decision":
            if (
                offset != 0
                or _fields_present(
                    max_items,
                    workstream_ref,
                    relative_path,
                    source_relative_path,
                    target_relative_path,
                    destination_kind,
                    destination_id,
                    reason,
                    max_entries,
                    max_depth,
                    max_hint_bytes,
                    max_total_bytes,
                    decision_request_file,
                    decision_outcome_file,
                    audit_file,
                    expected_plan_sha256,
                    *navigation_fields,
                )
            ):
                raise ValueError("decision draft fields are invalid")
            proposal_request, proposal_reference = _load_completed_artifact(
                request_file=proposal_request_file,
                outcome_file=proposal_outcome_file,
                operation_kind="librarian.proposal",
                schema=librarian_contract.PROPOSAL_SCHEMA,
                artifact_path=librarian_contract.proposal_artifact_path,
            )
            request = build_decision_request(
                root=root,
                actor=actor,
                proposal_request=proposal_request,
                proposal_reference=proposal_reference,
                decision_id="d-" + uuid.uuid4().hex,
                decision=decision,
                decision_reason=decision_reason,
            )
            if decision == "REJECTED":
                effect_text = (
                    "This records a rejection. The source will not move.\n"
                )
            else:
                effect_text = (
                    "This records approval only. The source has not moved yet.\n"
                )
        elif draft == "placement":
            if (
                offset != 0
                or _fields_present(
                    max_items,
                    workstream_ref,
                    relative_path,
                    source_relative_path,
                    target_relative_path,
                    destination_kind,
                    destination_id,
                    reason,
                    max_entries,
                    max_depth,
                    max_hint_bytes,
                    max_total_bytes,
                    decision,
                    decision_reason,
                    audit_file,
                    expected_plan_sha256,
                    *navigation_fields,
                )
            ):
                raise ValueError("placement draft fields are invalid")
            proposal_request, proposal_reference = _load_completed_artifact(
                request_file=proposal_request_file,
                outcome_file=proposal_outcome_file,
                operation_kind="librarian.proposal",
                schema=librarian_contract.PROPOSAL_SCHEMA,
                artifact_path=librarian_contract.proposal_artifact_path,
            )
            decision_request, decision_reference = _load_completed_artifact(
                request_file=decision_request_file,
                outcome_file=decision_outcome_file,
                operation_kind="librarian.decision",
                schema=librarian_contract.DECISION_SCHEMA,
                artifact_path=librarian_contract.decision_artifact_path,
            )
            request = build_placement_request(
                root=root,
                actor=actor,
                proposal_request=proposal_request,
                proposal_reference=proposal_reference,
                decision_request=decision_request,
                decision_reference=decision_reference,
            )
            effect_text = (
                "This placement will move exactly "
                f"{request.scope['source_relative_path']} -> "
                f"{request.scope['target_relative_path']} when dispatched.\n"
            )
        elif draft == "inspect":
            if _fields_present(
                source_relative_path,
                target_relative_path,
                destination_kind,
                destination_id,
                reason,
                max_entries,
                max_total_bytes,
                proposal_request_file,
                proposal_outcome_file,
                decision,
                decision_reason,
                decision_request_file,
                decision_outcome_file,
                audit_file,
                expected_plan_sha256,
                *navigation_fields,
            ):
                raise ValueError("inspect draft fields are invalid")
            request = build_view_request(
                view=view,
                root=root,
                actor=actor,
                max_items=max_items,
                offset=offset,
                workstream_ref=workstream_ref,
                relative_path=relative_path,
                max_depth=max_depth,
                max_hint_bytes=max_hint_bytes,
            )
            effect_text = ""
        else:
            raise ValueError("guide draft kind is invalid")
    except (
        CanonicalFileError,
        navigation_draft.NavigationDraftError,
        TypeError,
        ValueError,
    ):
        return 2, "guide request fields are invalid; correct them and retry\n", True
    request_text = request.canonical_bytes.decode("utf-8")
    return (
        0,
        "This is a request draft. It has not been executed.\n"
        f"{effect_text}"
        f"operation: {request.operation_kind}\n"
        f"request_sha256: {request.sha256}\n"
        "Run the exact request separately through `curation dispatch`.\n"
        + request_text,
        False,
    )


__all__ = ["guide_request"]
