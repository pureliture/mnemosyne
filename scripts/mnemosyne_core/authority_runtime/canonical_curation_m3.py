"""Irreversible M3 transformation transaction with exact cleanup recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Callable

from .. import canonical_curation as stage_a
from .. import canonical_curation_m3 as domain
from .. import canonical_curation_m3_review as review
from .. import operation_contract, safety
from ..canonical_json import canonical_json_bytes, sha256_bytes
from . import AuthorityRuntimeError, CanonicalCurationFence
from . import _durable_snapshot
from . import canonical_curation as stage_a_runtime


_CONTROL_PARTS = ("_registry", "curation", "canonical-curation-v2")
_TRANSACTION_PARTS = _CONTROL_PARTS + ("transactions",)
_STAGING_PARTS = _CONTROL_PARTS + ("staging",)
_PLAN_DIRECTORY = re.compile(r"p-([0-9a-f]{64})\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EFFECTS = 64
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_TRANSACTIONS = 256
_MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_INTENT_SCHEMA = "mnemosyne-canonical-curation-intent-v2"
_PHASE_SCHEMA = "mnemosyne-canonical-curation-phase-v2"
_RESULT_SCHEMA = "mnemosyne-canonical-curation-result-v2"


class CurationCleanupRequired(AuthorityRuntimeError):
    """A committed M3 Plan may only resume its exact cleanup manifest."""

    def __init__(self, message: str, *, plan_sha256: str) -> None:
        super().__init__(message)
        self.plan_sha256 = plan_sha256
        self.reason_code = "CURATION_CLEANUP_RECOVERY_REQUIRED"


def _run_checkpoint(_point: str) -> None:
    """Private deterministic fault-injection seam used only by tests."""


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if type(value) in {tuple, list}:
        return [_plain(item) for item in value]
    return value


def _fields(value: object, expected: set[str], label: str) -> dict[str, object]:
    plain = _plain(value)
    if type(plain) is not dict or set(plain) != expected:
        raise ValueError("%s shape is invalid" % label)
    return plain


def _decode_output(value: object) -> domain.CompleteOutput:
    payload = _fields(
        value,
        {"content", "content_sha256", "document_role", "output_id", "output_path"},
        "complete output",
    )
    return domain.CompleteOutput(**payload)


def _decode_mapping(value: object) -> domain.SourceOutputMapping:
    payload = _fields(
        value,
        {
            "disposition",
            "mapping_id",
            "output_id",
            "output_sections",
            "source_observation_id",
            "source_sections",
        },
        "source-output mapping",
    )
    if type(payload["source_sections"]) is not list or type(payload["output_sections"]) is not list:
        raise ValueError("source-output mapping sections are invalid")
    return domain.SourceOutputMapping(
        mapping_id=payload["mapping_id"],
        source_observation_id=payload["source_observation_id"],
        source_sections=tuple(payload["source_sections"]),
        output_id=payload["output_id"],
        output_sections=tuple(payload["output_sections"]),
        disposition=payload["disposition"],
    )


def _decode_disappearing(value: object) -> domain.DisappearingContent:
    payload = _fields(
        value,
        {"classification", "reason", "source_observation_id", "source_sections"},
        "disappearing content",
    )
    if type(payload["source_sections"]) is not list:
        raise ValueError("disappearing content sections are invalid")
    return domain.DisappearingContent(
        source_observation_id=payload["source_observation_id"],
        source_sections=tuple(payload["source_sections"]),
        reason=payload["reason"],
        classification=payload["classification"],
    )


def _decode_effect(value: object) -> domain.TransformationEffect:
    payload = _fields(
        value,
        {
            "action",
            "dependency_effect_ids",
            "disappearing_content",
            "effect_id",
            "input_observation_ids",
            "irreversible",
            "outputs",
            "review_status",
            "risk_codes",
            "source_output_mappings",
        },
        "transformation effect",
    )
    for name in (
        "dependency_effect_ids",
        "disappearing_content",
        "input_observation_ids",
        "outputs",
        "risk_codes",
        "source_output_mappings",
    ):
        if type(payload[name]) is not list:
            raise ValueError("transformation effect collection is invalid: %s" % name)
    return domain.TransformationEffect(
        effect_id=payload["effect_id"],
        action=payload["action"],
        input_observation_ids=tuple(payload["input_observation_ids"]),
        outputs=tuple(_decode_output(item) for item in payload["outputs"]),
        source_output_mappings=tuple(
            _decode_mapping(item) for item in payload["source_output_mappings"]
        ),
        disappearing_content=tuple(
            _decode_disappearing(item) for item in payload["disappearing_content"]
        ),
        risk_codes=tuple(payload["risk_codes"]),
        review_status=payload["review_status"],
        irreversible=payload["irreversible"],
        dependency_effect_ids=tuple(payload["dependency_effect_ids"]),
    )


def decode_plan(value: object) -> domain.TransformationPlan:
    """Strictly reconstruct one canonical M3 Plan from request JSON."""

    payload = _fields(
        value,
        {
            "captured_lifecycle",
            "coverage",
            "cutoff_required",
            "effects",
            "final_paths",
            "findings",
            "irreversible_consequence",
            "out_of_scope_paths",
            "output_manifest_sha256",
            "parent_plan_sha256",
            "policy_sha256",
            "primary_workstream_id",
            "project_home",
            "project_identity",
            "root_identity",
            "schema",
            "source_observation_sha256",
            "source_observations",
            "spec_sha256",
            "spine",
            "unchanged_paths",
        },
        "M3 Curation Plan",
    )
    for name in (
        "effects",
        "final_paths",
        "findings",
        "out_of_scope_paths",
        "project_identity",
        "root_identity",
        "source_observations",
        "spine",
        "unchanged_paths",
    ):
        if type(payload[name]) is not list:
            raise ValueError("M3 Curation Plan collection is invalid: %s" % name)
    if type(payload["coverage"]) is not dict:
        raise ValueError("M3 Curation Plan coverage is invalid")
    plan = domain.TransformationPlan(
        primary_workstream_id=payload["primary_workstream_id"],
        captured_lifecycle=payload["captured_lifecycle"],
        project_home=payload["project_home"],
        project_identity=tuple(payload["project_identity"]),
        root_identity=tuple(payload["root_identity"]),
        policy_sha256=payload["policy_sha256"],
        source_observations=tuple(
            stage_a_runtime._decode_observation(item)
            for item in payload["source_observations"]
        ),
        effects=tuple(_decode_effect(item) for item in payload["effects"]),
        spine=tuple(stage_a_runtime._decode_spine(item) for item in payload["spine"]),
        findings=tuple(
            stage_a_runtime._decode_finding(item) for item in payload["findings"]
        ),
        unchanged_paths=tuple(payload["unchanged_paths"]),
        out_of_scope_paths=tuple(payload["out_of_scope_paths"]),
        final_paths=tuple(payload["final_paths"]),
        coverage=tuple(sorted(payload["coverage"].items())),
        parent_plan_sha256=payload["parent_plan_sha256"],
        schema=payload["schema"],
        spec_sha256=payload["spec_sha256"],
        cutoff_required=payload["cutoff_required"],
        irreversible_consequence=payload["irreversible_consequence"],
    )
    if plan.canonical_value != payload:
        raise ValueError("M3 Curation Plan is not canonical")
    return plan


def _validate_decision(
    value: object,
    plan: domain.TransformationPlan,
) -> tuple[dict[str, object], str]:
    decision = _fields(
        value,
        {
            "action",
            "approved_plan_sha256",
            "displayed_plan_sha256",
            "irreversible_acknowledgement",
            "output_manifest_sha256",
            "reason",
            "review_package_hashes",
            "selected_effect_ids",
            "source_observation_sha256",
        },
        "M3 Curation decision",
    )
    hashes = decision["review_package_hashes"]
    selected = decision["selected_effect_ids"]
    expected_membership = [effect.effect_id for effect in plan.effects]
    expected_displayed = (
        plan.sha256 if decision["action"] == "APPROVE_ALL" else plan.parent_plan_sha256
    )
    if (
        decision["action"] not in {"APPROVE_ALL", "APPROVE_SELECTED"}
        or type(selected) is not list
        or selected != expected_membership
        or not selected
        or decision["approved_plan_sha256"] != plan.sha256
        or decision["displayed_plan_sha256"] != expected_displayed
        or decision["irreversible_acknowledgement"]
        != domain.IRREVERSIBLE_CONSEQUENCE_KO
        or decision["output_manifest_sha256"] != plan.output_manifest_sha256
        or decision["source_observation_sha256"] != plan.source_observation_sha256
        or type(hashes) is not dict
        or set(hashes)
        != {"html_sha256", "markdown_sha256", "meta_sha256", "semantic_sha256"}
        or any(type(item) is not str or _HASH.fullmatch(item) is None for item in hashes.values())
        or (decision["reason"] is not None and type(decision["reason"]) is not str)
    ):
        raise ValueError("M3 decision does not approve the exact Plan and consequence")
    return decision, sha256_bytes(canonical_json_bytes(decision))


def _review_package_path(value: object) -> Path:
    return stage_a_runtime._review_package_path(value)


def _require_review_package_binding(
    *,
    root: Path,
    plan: domain.TransformationPlan,
    decision: dict[str, object],
    directory: Path,
) -> None:
    try:
        directory.relative_to(root)
    except ValueError:
        pass
    else:
        raise CanonicalCurationFence(
            "M3 Review Package overlaps the authority root",
            reason_code="STALE",
        )
    try:
        hashes, displayed_value = review.validate_review_directory_with_plan(
            directory,
            expected_plan_sha256=decision["displayed_plan_sha256"],
        )
    except (TypeError, ValueError, OSError) as exc:
        raise CanonicalCurationFence(
            "sealed M3 Review Package is unavailable or changed",
            reason_code="STALE",
        ) from exc
    actual = {
        "html_sha256": hashes.html_sha256,
        "markdown_sha256": hashes.markdown_sha256,
        "meta_sha256": hashes.meta_sha256,
        "semantic_sha256": hashes.semantic_sha256,
    }
    if actual != decision["review_package_hashes"]:
        raise CanonicalCurationFence(
            "sealed M3 Review Package does not match the approval",
            reason_code="STALE",
        )
    try:
        displayed = decode_plan(displayed_value)
        expected = (
            displayed
            if decision["action"] == "APPROVE_ALL"
            else displayed.subset(tuple(decision["selected_effect_ids"]))
        )
    except (TypeError, ValueError, stage_a.CanonicalCurationError) as exc:
        raise CanonicalCurationFence(
            "sealed M3 Review Package cannot reconstruct the approved Plan",
            reason_code="STALE",
        ) from exc
    if expected.canonical_value != plan.canonical_value:
        raise CanonicalCurationFence(
            "approved M3 Plan is not the exact displayed selection",
            reason_code="STALE",
        )


def _validated_request(
    request: object,
) -> tuple[domain.TransformationPlan, dict[str, object], str]:
    if type(request) is not operation_contract.OperationRequest:
        raise ValueError("M3 Curation Plan apply request is invalid")
    if (
        request.operation_kind != "curation.plan_apply"
        or request.action is not operation_contract.LifecycleAction.APPLY
        or request.claim_mode is not operation_contract.ClaimMode.CURRENT
        or request.requested_authority is not operation_contract.AuthorityMode.WRITE
        or set(request.scope) != {"plan_sha256", "workstream_id"}
        or set(request.bounds) != {"max_effects", "max_total_bytes"}
        or set(request.payload) != {"decision", "plan", "review_package_directory"}
        or request.approval_artifact is not None
        or request.prerequisite_artifacts
    ):
        raise ValueError("M3 Curation Plan apply request is invalid")
    bounds = request.bounds
    payload = request.payload
    scope = request.scope
    max_effects = bounds["max_effects"]
    max_total_bytes = bounds["max_total_bytes"]
    if (
        type(max_effects) is not int
        or not 1 <= max_effects <= _MAX_EFFECTS
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _MAX_TOTAL_BYTES
    ):
        raise ValueError("M3 Curation Plan apply bounds are invalid")
    plan = decode_plan(payload["plan"])
    _review_package_path(payload["review_package_directory"])
    decision, decision_sha256 = _validate_decision(payload["decision"], plan)
    input_bytes = sum(item.size for item in plan.source_observations)
    output_bytes = sum(
        len(output.content_bytes) for effect in plan.effects for output in effect.outputs
    )
    if (
        scope["plan_sha256"] != plan.sha256
        or scope["workstream_id"] != plan.primary_workstream_id
        or len(plan.effects) > max_effects
        or input_bytes > max_total_bytes
        or output_bytes > max_total_bytes
    ):
        raise ValueError("M3 Curation Plan apply scope or bounds mismatch")
    return plan, decision, decision_sha256


def validate_plan_apply_request(request: object) -> None:
    _validated_request(request)


def decode_admitted_input(
    value: object,
) -> tuple[domain.TransformationPlan, dict[str, object], str, int, Path]:
    if not isinstance(value, Mapping):
        raise ValueError("M3 admitted input is invalid")
    plain = _plain(value)
    if (
        type(plain) is not dict
        or set(plain)
        != {
            "action",
            "approval_artifact",
            "bounds",
            "operation_kind",
            "payload",
            "prerequisite_artifacts",
            "scope",
        }
        or plain["operation_kind"] != "curation.plan_apply"
        or plain["action"] is not operation_contract.LifecycleAction.APPLY
        or plain["approval_artifact"] is not None
        or plain["prerequisite_artifacts"] != []
        or set(plain["payload"])
        != {"decision", "plan", "review_package_directory"}
        or set(plain["bounds"]) != {"max_effects", "max_total_bytes"}
        or set(plain["scope"]) != {"plan_sha256", "workstream_id"}
    ):
        raise ValueError("M3 admitted input is invalid")
    bounds = plain["bounds"]
    payload = plain["payload"]
    scope = plain["scope"]
    plan = decode_plan(payload["plan"])
    decision, decision_sha256 = _validate_decision(payload["decision"], plan)
    max_effects = bounds["max_effects"]
    max_total_bytes = bounds["max_total_bytes"]
    input_bytes = sum(item.size for item in plan.source_observations)
    output_bytes = sum(
        len(output.content_bytes) for effect in plan.effects for output in effect.outputs
    )
    if (
        type(max_effects) is not int
        or not 1 <= max_effects <= _MAX_EFFECTS
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _MAX_TOTAL_BYTES
        or len(plan.effects) > max_effects
        or input_bytes > max_total_bytes
        or output_bytes > max_total_bytes
        or scope["plan_sha256"] != plan.sha256
        or scope["workstream_id"] != plan.primary_workstream_id
    ):
        raise ValueError("M3 admitted input scope or bounds mismatch")
    return (
        plan,
        decision,
        decision_sha256,
        max_total_bytes,
        _review_package_path(payload["review_package_directory"]),
    )


def _transaction_path(anchor: _durable_snapshot._RootAnchor, plan_sha256: str):
    return anchor.joinpath(*_TRANSACTION_PARTS, "p-" + plan_sha256)


def _staging_path(anchor: _durable_snapshot._RootAnchor, plan_sha256: str):
    return anchor.joinpath(*_STAGING_PARTS, "p-" + plan_sha256)


def _source_stage_path(
    anchor: _durable_snapshot._RootAnchor,
    plan_sha256: str,
    observation_id: str,
):
    return _staging_path(anchor, plan_sha256).joinpath(
        "sources",
        observation_id + ".stage",
    )


def _output_stage_path(
    anchor: _durable_snapshot._RootAnchor,
    plan_sha256: str,
    output_id: str,
):
    return _staging_path(anchor, plan_sha256).joinpath(
        "outputs",
        output_id + ".stage",
    )


def _list_optional(anchor: _durable_snapshot._RootAnchor, path) -> tuple[str, ...]:
    try:
        descriptor = anchor._open_directory(path.parts, create=False)
    except FileNotFoundError:
        return ()
    else:
        os.close(descriptor)
    return anchor.list_directory(path)


def _directory_exists(anchor: _durable_snapshot._RootAnchor, path) -> bool:
    try:
        descriptor = anchor._open_directory(path.parts, create=False)
    except FileNotFoundError:
        return False
    os.close(descriptor)
    return True


def _ensure_layout(anchor: _durable_snapshot._RootAnchor) -> None:
    for parts in (_CONTROL_PARTS, _TRANSACTION_PARTS, _STAGING_PARTS):
        descriptor = anchor._open_directory(parts, create=True)
        os.close(descriptor)


def _read_record(anchor: _durable_snapshot._RootAnchor, path, *, label: str):
    raw = anchor.read_bytes(path)
    if raw is None:
        return None
    if len(raw) > _MAX_JOURNAL_BYTES:
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 Curation transaction record is oversized"
        )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 Curation transaction record is invalid"
        ) from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise stage_a_runtime.CurationRecoveryRequired("%s is not canonical" % label)
    return raw, value


def _publish_exact(anchor: _durable_snapshot._RootAnchor, path, raw: bytes, *, label: str) -> None:
    existing = anchor.read_bytes(path)
    if existing is not None:
        if existing != raw:
            raise stage_a_runtime.CurationRecoveryRequired("%s differs" % label)
        return
    anchor.publish_bytes(path, raw, label=label)


def _intent_value(
    plan: domain.TransformationPlan,
    *,
    request_sha256: str,
    decision_sha256: str,
) -> dict[str, object]:
    observations = {item.observation_id: item for item in plan.source_observations}
    return {
        "decision_sha256": decision_sha256,
        "effects": [
            {
                "action": effect.action,
                "effect_id": effect.effect_id,
                "outputs": [
                    {
                        "content_sha256": output.content_sha256,
                        "output_id": output.output_id,
                        "output_path": output.output_path,
                        "size": len(output.content_bytes),
                    }
                    for output in effect.outputs
                ],
                "sources": [
                    {
                        "content_sha256": observations[item].content_sha256,
                        "device": observations[item].device,
                        "inode": observations[item].inode,
                        "link_count": observations[item].link_count,
                        "mode": observations[item].mode,
                        "modified_time_ns": observations[item].modified_time_ns,
                        "observation_id": item,
                        "owner": observations[item].owner,
                        "size": observations[item].size,
                        "source_path": observations[item].relative_path,
                    }
                    for item in effect.input_observation_ids
                ],
            }
            for effect in plan.effects
        ],
        "output_manifest_sha256": plan.output_manifest_sha256,
        "plan_sha256": plan.sha256,
        "request_sha256": request_sha256,
        "schema": _INTENT_SCHEMA,
        "source_observation_sha256": plan.source_observation_sha256,
        "status": "PREPARED",
        "workstream_id": plan.primary_workstream_id,
    }


def _phase_value(
    plan: domain.TransformationPlan,
    *,
    request_sha256: str,
    decision_sha256: str,
    phase: str,
) -> dict[str, object]:
    return {
        "decision_sha256": decision_sha256,
        "output_manifest_sha256": plan.output_manifest_sha256,
        "phase": phase,
        "plan_sha256": plan.sha256,
        "request_sha256": request_sha256,
        "schema": _PHASE_SCHEMA,
        "source_observation_sha256": plan.source_observation_sha256,
        "workstream_id": plan.primary_workstream_id,
    }


def _result_value(
    plan: domain.TransformationPlan,
    *,
    request_sha256: str,
    decision_sha256: str,
    status: str,
    reason_code: str | None,
) -> dict[str, object]:
    finalized = status == "FINALIZED"
    rolled_back = status == "ROLLED_BACK"
    return {
        "cleanup": {
            "staging_empty": finalized or rolled_back,
            "superseded_originals_absent": finalized,
        },
        "cutoff_state": "CLEANUP_VERIFIED" if finalized else "NOT_COMMITTED",
        "decision_sha256": decision_sha256,
        "effect_count": len(plan.effects),
        "effects": [
            {
                "action": effect.action,
                "effect_id": effect.effect_id,
                "outputs": [
                    {
                        "content_sha256": output.content_sha256,
                        "output_id": output.output_id,
                        "output_path": output.output_path,
                    }
                    for output in effect.outputs
                ],
                "source_paths": [
                    next(
                        item.relative_path
                        for item in plan.source_observations
                        if item.observation_id == observation_id
                    )
                    for observation_id in effect.input_observation_ids
                ],
            }
            for effect in plan.effects
        ],
        "equality": {
            "effect_membership_complete": finalized or rolled_back,
            "outputs_match": finalized,
            "sources_restored": rolled_back,
        },
        "output_manifest_sha256": plan.output_manifest_sha256,
        "plan_sha256": plan.sha256,
        "reason_code": reason_code,
        "request_sha256": request_sha256,
        "schema": _RESULT_SCHEMA,
        "status": status,
        "workstream_id": plan.primary_workstream_id,
    }


def _target_parent_identity(
    root: Path,
    output: domain.CompleteOutput,
    allowed_source_paths: set[str],
) -> tuple[int, int]:
    path = root.joinpath(*output.output_path.split("/"))
    descriptor = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=stage_a_runtime._TransactionError,
    )
    try:
        info = os.fstat(descriptor)
        try:
            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return info.st_dev, info.st_ino
        if output.output_path not in allowed_source_paths:
            raise CanonicalCurationFence(
                "M3 Curation target already exists",
                reason_code="TARGET_CONFLICT",
            )
        return info.st_dev, info.st_ino
    finally:
        os.close(descriptor)


def _output_matches(state: dict[str, object] | None, output: domain.CompleteOutput) -> bool:
    return state is not None and all(
        state.get(name) == value
        for name, value in {
            "content_sha256": output.content_sha256,
            "link_count": 1,
            "size": len(output.content_bytes),
        }.items()
    ) and state["mode"] & 0o077 == 0


def _rename_generated(
    source: Path,
    target: Path,
    state: dict[str, object],
    *,
    target_parent_identity: tuple[int, int],
) -> None:
    expected = {
        "source": (state["parent"]["device"], state["parent"]["inode"]),
        "target": target_parent_identity,
    }

    def require_parent(_path: Path, descriptor: int, label: str) -> None:
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) != expected[label]:
            raise stage_a_runtime._TransactionError(
                "M3 Curation output parent identity changed"
            )

    safety.rename_path_no_replace(
        source,
        target,
        collision_error="M3 Curation output target already exists",
        require_directory=False,
        expected_source_identity=(state["device"], state["inode"], stat.S_IFREG),
        create_target_parent=False,
        error_type=stage_a_runtime._TransactionError,
        before_directory_identity_check=require_parent,
    )


def _unlink_exact(
    anchor: _durable_snapshot._RootAnchor,
    relative_path: str,
    *,
    content_sha256: str,
    max_total_bytes: int,
) -> None:
    state = stage_a_runtime._regular_state(
        anchor,
        relative_path,
        max_bytes=max_total_bytes,
    )
    if state is None:
        return
    if state["content_sha256"] != content_sha256 or state["link_count"] != 1:
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 cleanup member differs from the exact manifest"
        )
    parts = tuple(relative_path.split("/"))
    parent_fd = anchor._open_directory(parts[:-1], create=False)
    try:
        current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (state["device"], state["inode"]):
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 cleanup member identity changed"
            )
        os.unlink(parts[-1], dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _remove_empty_directory(anchor: _durable_snapshot._RootAnchor, path) -> None:
    if _list_optional(anchor, path):
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 Curation staging directory is not empty"
        )
    try:
        parent_fd = anchor._open_directory(path.parts[:-1], create=False)
    except FileNotFoundError:
        return
    try:
        try:
            os.rmdir(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            return
    finally:
        os.close(parent_fd)


def _remove_staging_tree(
    anchor: _durable_snapshot._RootAnchor,
    plan_sha256: str,
) -> None:
    stage = _staging_path(anchor, plan_sha256)
    _remove_empty_directory(anchor, stage.joinpath("sources"))
    _remove_empty_directory(anchor, stage.joinpath("outputs"))
    _remove_empty_directory(anchor, stage)


def _rollback(
    anchor: _durable_snapshot._RootAnchor,
    root: Path,
    plan: domain.TransformationPlan,
    *,
    max_total_bytes: int,
) -> None:
    for effect in reversed(plan.effects):
        for output in reversed(effect.outputs):
            stage_path = _output_stage_path(anchor, plan.sha256, output.output_id)
            stage_relative = "/".join(stage_path.parts)
            stage_state = stage_a_runtime._regular_state(
                anchor,
                stage_relative,
                max_bytes=max_total_bytes,
            )
            final_state = stage_a_runtime._regular_state(
                anchor,
                output.output_path,
                max_bytes=max_total_bytes,
            )
            present = [stage_state is not None, final_state is not None]
            if sum(present) > 1:
                raise stage_a_runtime.CurationRecoveryRequired(
                    "M3 rollback output membership is ambiguous"
                )
            if stage_state is not None:
                _unlink_exact(
                    anchor,
                    stage_relative,
                    content_sha256=output.content_sha256,
                    max_total_bytes=max_total_bytes,
                )
            elif final_state is not None:
                _unlink_exact(
                    anchor,
                    output.output_path,
                    content_sha256=output.content_sha256,
                    max_total_bytes=max_total_bytes,
                )

    for observation in reversed(plan.source_observations):
        stage_path = _source_stage_path(
            anchor,
            plan.sha256,
            observation.observation_id,
        )
        stage_relative = "/".join(stage_path.parts)
        source = stage_a_runtime._regular_state(
            anchor,
            observation.relative_path,
            max_bytes=max_total_bytes,
        )
        staged = stage_a_runtime._regular_state(
            anchor,
            stage_relative,
            max_bytes=max_total_bytes,
        )
        if sum((source is not None, staged is not None)) != 1:
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 rollback source membership is ambiguous"
            )
        if source is not None:
            if not stage_a_runtime._matches_source(source, observation):
                raise stage_a_runtime.CurationRecoveryRequired(
                    "M3 rollback source differs"
                )
            continue
        if not stage_a_runtime._matches_relocated(staged, observation):
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 rollback staged source differs"
            )
        destination = root.joinpath(*observation.relative_path.split("/"))
        destination_fd = safety.open_verified_directory(
            destination.parent,
            require_owner_only=True,
            error_type=stage_a_runtime._TransactionError,
        )
        try:
            parent = os.fstat(destination_fd)
            target_parent = (parent.st_dev, parent.st_ino)
        finally:
            os.close(destination_fd)
        stage_a_runtime._rename(
            stage_path.display_path,
            destination,
            observation,
            source_parent_identity=(
                staged["parent"]["device"],
                staged["parent"]["inode"],
            ),
            target_parent_identity=target_parent,
        )
    _remove_staging_tree(anchor, plan.sha256)
    for observation in plan.source_observations:
        if not stage_a_runtime._matches_source(
            stage_a_runtime._regular_state(
                anchor,
                observation.relative_path,
                max_bytes=max_total_bytes,
            ),
            observation,
        ):
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 rollback equality is unproven"
            )
    for effect in plan.effects:
        for output in effect.outputs:
            if stage_a_runtime._regular_state(
                anchor,
                output.output_path,
                max_bytes=max_total_bytes,
            ) is not None and output.output_path not in {
                item.relative_path for item in plan.source_observations
            }:
                raise stage_a_runtime.CurationRecoveryRequired(
                    "M3 rollback output remains"
                )


def _verify_published(
    anchor: _durable_snapshot._RootAnchor,
    plan: domain.TransformationPlan,
    *,
    max_total_bytes: int,
) -> None:
    for effect in plan.effects:
        for output in effect.outputs:
            if not _output_matches(
                stage_a_runtime._regular_state(
                    anchor,
                    output.output_path,
                    max_bytes=max_total_bytes,
                ),
                output,
            ):
                raise stage_a_runtime.CurationRecoveryRequired(
                    "M3 published output equality is unproven"
                )
    for observation in plan.source_observations:
        staged = _source_stage_path(anchor, plan.sha256, observation.observation_id)
        if not stage_a_runtime._matches_relocated(
            stage_a_runtime._regular_state(
                anchor,
                "/".join(staged.parts),
                max_bytes=max_total_bytes,
            ),
            observation,
        ):
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 superseded source staging is incomplete"
            )


def _cleanup_committed(
    anchor: _durable_snapshot._RootAnchor,
    plan: domain.TransformationPlan,
    *,
    max_total_bytes: int,
) -> None:
    observations = {item.observation_id: item for item in plan.source_observations}
    for effect in plan.effects:
        for observation_id in effect.input_observation_ids:
            observation = observations[observation_id]
            stage = _source_stage_path(anchor, plan.sha256, observation_id)
            _unlink_exact(
                anchor,
                "/".join(stage.parts),
                content_sha256=observation.content_sha256,
                max_total_bytes=max_total_bytes,
            )
            _run_checkpoint("after-cleanup:" + observation_id)
    _remove_staging_tree(anchor, plan.sha256)
    _run_checkpoint("after-cleanup-verified")


def _verify_committed_generation(
    anchor: _durable_snapshot._RootAnchor,
    plan: domain.TransformationPlan,
    *,
    max_total_bytes: int,
) -> None:
    outputs_by_path = {
        output.output_path: output
        for effect in plan.effects
        for output in effect.outputs
    }
    for effect in plan.effects:
        for output in effect.outputs:
            if not _output_matches(
                stage_a_runtime._regular_state(
                    anchor,
                    output.output_path,
                    max_bytes=max_total_bytes,
                ),
                output,
            ):
                raise CurationCleanupRequired(
                    "M3 committed output differs from the approved bytes",
                    plan_sha256=plan.sha256,
                )
            output_stage = _output_stage_path(anchor, plan.sha256, output.output_id)
            if stage_a_runtime._regular_state(
                anchor,
                "/".join(output_stage.parts),
                max_bytes=max_total_bytes,
            ) is not None:
                raise CurationCleanupRequired(
                    "M3 committed output staging is ambiguous",
                    plan_sha256=plan.sha256,
                )
    for observation in plan.source_observations:
        source_stage = _source_stage_path(
            anchor,
            plan.sha256,
            observation.observation_id,
        )
        staged = stage_a_runtime._regular_state(
            anchor,
            "/".join(source_stage.parts),
            max_bytes=max_total_bytes,
        )
        if staged is not None and not stage_a_runtime._matches_relocated(
            staged,
            observation,
        ):
            raise CurationCleanupRequired(
                "M3 committed cleanup source differs from the manifest",
                plan_sha256=plan.sha256,
            )
        source_state = stage_a_runtime._regular_state(
            anchor,
            observation.relative_path,
            max_bytes=max_total_bytes,
        )
        replacement = outputs_by_path.get(observation.relative_path)
        if replacement is None:
            if source_state is not None:
                raise CurationCleanupRequired(
                    "M3 committed original reappeared",
                    plan_sha256=plan.sha256,
                )
        elif (
            not _output_matches(source_state, replacement)
            or source_state["inode"] == observation.inode
        ):
            raise CurationCleanupRequired(
                "M3 committed in-place replacement is invalid",
                plan_sha256=plan.sha256,
            )


def _verify_final(
    anchor: _durable_snapshot._RootAnchor,
    plan: domain.TransformationPlan,
    *,
    max_total_bytes: int,
) -> None:
    outputs_by_path = {
        output.output_path: output
        for effect in plan.effects
        for output in effect.outputs
    }
    for path, output in outputs_by_path.items():
        if not _output_matches(
            stage_a_runtime._regular_state(anchor, path, max_bytes=max_total_bytes),
            output,
        ):
            raise CurationCleanupRequired(
                "M3 final output equality is unproven",
                plan_sha256=plan.sha256,
            )
    for observation in plan.source_observations:
        state = stage_a_runtime._regular_state(
            anchor,
            observation.relative_path,
            max_bytes=max_total_bytes,
        )
        replacement = outputs_by_path.get(observation.relative_path)
        if replacement is None:
            if state is not None:
                raise CurationCleanupRequired(
                    "M3 superseded original still exists",
                    plan_sha256=plan.sha256,
                )
        elif not _output_matches(state, replacement) or state["inode"] == observation.inode:
            raise CurationCleanupRequired(
                "M3 in-place output did not replace the original",
                plan_sha256=plan.sha256,
            )
    if _directory_exists(anchor, _staging_path(anchor, plan.sha256)):
        raise CurationCleanupRequired(
            "M3 staging namespace was not removed",
            plan_sha256=plan.sha256,
        )
    for path in plan.unchanged_paths:
        if stage_a_runtime._regular_state(anchor, path, max_bytes=max_total_bytes) is None:
            raise CurationCleanupRequired(
                "M3 final path set is incomplete",
                plan_sha256=plan.sha256,
            )


def _validate_result_record(
    value: dict[str, object],
    plan: domain.TransformationPlan,
    *,
    request_sha256: str,
    decision_sha256: str,
) -> None:
    expected = _result_value(
        plan,
        request_sha256=request_sha256,
        decision_sha256=decision_sha256,
        status=value.get("status") if type(value.get("status")) is str else "INVALID",
        reason_code=value.get("reason_code"),
    )
    if value != expected or value["status"] not in {"FINALIZED", "ROLLED_BACK"}:
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 terminal result is invalid"
        )


def _terminal_replay(
    anchor: _durable_snapshot._RootAnchor,
    plan: domain.TransformationPlan,
    result: dict[str, object],
    *,
    request_sha256: str,
    decision_sha256: str,
    max_total_bytes: int,
) -> dict[str, object]:
    _validate_result_record(
        result,
        plan,
        request_sha256=request_sha256,
        decision_sha256=decision_sha256,
    )
    if result["status"] == "FINALIZED":
        _verify_final(anchor, plan, max_total_bytes=max_total_bytes)
        return result
    _rollback(anchor, anchor.display_path(()), plan, max_total_bytes=max_total_bytes)
    raise CanonicalCurationFence(
        "M3 Curation Plan was already rolled back",
        reason_code="ROLLED_BACK",
    )


def _control_records(
    anchor: _durable_snapshot._RootAnchor,
) -> tuple[tuple[str, dict[str, object], dict[str, object] | None, bool], ...]:
    control = anchor.joinpath(*_CONTROL_PARTS)
    members = _list_optional(anchor, control)
    if not set(members) <= {"staging", "transactions"}:
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 Curation control member is unknown"
        )
    transactions = _list_optional(anchor, anchor.joinpath(*_TRANSACTION_PARTS))
    staging = _list_optional(anchor, anchor.joinpath(*_STAGING_PARTS))
    if len(transactions) > _MAX_TRANSACTIONS or len(staging) > _MAX_TRANSACTIONS:
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 Curation control capacity is exceeded"
        )
    if any(_PLAN_DIRECTORY.fullmatch(name) is None for name in (*transactions, *staging)):
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 Curation control member is invalid"
        )
    if not set(staging) <= set(transactions):
        raise stage_a_runtime.CurationRecoveryRequired(
            "M3 Curation staging has no transaction"
        )
    records = []
    for name in transactions:
        transaction = anchor.joinpath(*_TRANSACTION_PARTS, name)
        entries = set(_list_optional(anchor, transaction))
        allowed = {
            "committed-cleanup.json",
            "intent.json",
            "published-verified.json",
            "recovery-required.json",
            "result.json",
        }
        if not entries <= allowed:
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 Curation transaction membership is unsafe"
            )
        intent = _read_record(anchor, transaction / "intent.json", label="M3 intent")
        result = _read_record(anchor, transaction / "result.json", label="M3 result")
        committed = _read_record(
            anchor,
            transaction / "committed-cleanup.json",
            label="M3 cutoff marker",
        )
        if intent is None:
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 Curation transaction intent is missing"
            )
        intent_value = intent[1]
        if (
            set(intent_value)
            != {
                "decision_sha256",
                "effects",
                "output_manifest_sha256",
                "plan_sha256",
                "request_sha256",
                "schema",
                "source_observation_sha256",
                "status",
                "workstream_id",
            }
            or intent_value.get("schema") != _INTENT_SCHEMA
            or intent_value.get("status") != "PREPARED"
            or type(intent_value.get("effects")) is not list
            or not intent_value["effects"]
            or any(
                type(intent_value.get(field)) is not str
                or _HASH.fullmatch(intent_value[field]) is None
                for field in (
                    "decision_sha256",
                    "output_manifest_sha256",
                    "plan_sha256",
                    "request_sha256",
                    "source_observation_sha256",
                )
            )
        ):
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 Curation transaction intent contract is invalid"
            )
        published = _read_record(
            anchor,
            transaction / "published-verified.json",
            label="M3 published marker",
        )
        recovery = _read_record(
            anchor,
            transaction / "recovery-required.json",
            label="M3 recovery marker",
        )
        for record, expected_phase in (
            (published, "PUBLISHED_VERIFIED"),
            (committed, "COMMITTED_CLEANUP"),
            (recovery, "RECOVERY_REQUIRED"),
        ):
            if record is None:
                continue
            value = record[1]
            if (
                set(value)
                != {
                    "decision_sha256",
                    "output_manifest_sha256",
                    "phase",
                    "plan_sha256",
                    "request_sha256",
                    "schema",
                    "source_observation_sha256",
                    "workstream_id",
                }
                or value.get("schema") != _PHASE_SCHEMA
                or value.get("phase") != expected_phase
                or any(
                    value.get(field) != intent_value.get(field)
                    for field in (
                        "decision_sha256",
                        "output_manifest_sha256",
                        "plan_sha256",
                        "request_sha256",
                        "source_observation_sha256",
                        "workstream_id",
                    )
                )
            ):
                raise stage_a_runtime.CurationRecoveryRequired(
                    "M3 Curation phase marker is invalid"
                )
        if committed is not None and published is None:
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 cutoff marker has no published verification"
            )
        if recovery is not None and committed is None:
            raise stage_a_runtime.CurationRecoveryRequired(
                "M3 recovery marker has no cutoff"
            )
        if result is not None:
            result_value = result[1]
            if (
                result_value.get("schema") != _RESULT_SCHEMA
                or result_value.get("status") not in {"FINALIZED", "ROLLED_BACK"}
                or any(
                    result_value.get(field) != intent_value.get(field)
                    for field in (
                        "decision_sha256",
                        "output_manifest_sha256",
                        "plan_sha256",
                        "request_sha256",
                        "workstream_id",
                    )
                )
                or (committed is not None and result_value["status"] != "FINALIZED")
            ):
                raise stage_a_runtime.CurationRecoveryRequired(
                    "M3 Curation terminal result contract is invalid"
                )
        if name in staging and result is not None:
            raise stage_a_runtime.CurationRecoveryRequired(
                "terminal M3 Curation transaction retains staging"
            )
        records.append((name, intent_value, None if result is None else result[1], committed is not None))
    return tuple(records)


def workstream_mutation_status(root: Path, workstream_id: str) -> str | None:
    if type(workstream_id) is not str or re.fullmatch(r"[a-z][a-z0-9-]{1,95}", workstream_id) is None:
        raise ValueError("M3 Curation Workstream id is invalid")
    root_identity = stage_a_runtime._root_mode_identity(Path(root))[:2]
    anchor = _durable_snapshot._RootAnchor.open(Path(root), expected_identity=root_identity)
    try:
        try:
            for _name, intent, result, committed in _control_records(anchor):
                if intent.get("workstream_id") != workstream_id:
                    continue
                if result is None:
                    return "RECOVERY_REQUIRED" if committed else "MUTATION_IN_PROGRESS"
            return None
        except (AuthorityRuntimeError, OSError, ValueError):
            return "RECOVERY_REQUIRED"
    finally:
        anchor.close()


def _other_active_transaction_check(
    anchor: _durable_snapshot._RootAnchor,
    plan: domain.TransformationPlan,
) -> None:
    earlier_status = stage_a_runtime._workstream_mutation_status_v1(
        anchor.display_path(()),
        plan.primary_workstream_id,
    )
    if earlier_status == "RECOVERY_REQUIRED":
        raise stage_a_runtime.CurationRecoveryRequired(
            "a Stage-A Plan requires recovery"
        )
    if earlier_status == "MUTATION_IN_PROGRESS":
        raise CanonicalCurationFence(
            "a Stage-A Plan is mutating this Workstream",
            reason_code="PLAN_CONFLICT",
        )
    for name, intent, result, committed in _control_records(anchor):
        if name == "p-" + plan.sha256:
            continue
        if intent.get("workstream_id") != plan.primary_workstream_id:
            continue
        if result is None:
            if committed:
                raise CurationCleanupRequired(
                    "another M3 Plan requires exact cleanup",
                    plan_sha256=intent.get("plan_sha256", plan.sha256),
                )
            raise CanonicalCurationFence(
                "another M3 Plan is mutating this Workstream",
                reason_code="PLAN_CONFLICT",
            )


def apply_plan(
    *,
    root: Path,
    root_identity: tuple[int, int],
    compiled_policy: object,
    plan: domain.TransformationPlan,
    decision: dict[str, object],
    review_package_directory: Path,
    request_sha256: str,
    decision_sha256: str,
    max_total_bytes: int,
    revalidate: Callable[[], None],
) -> dict[str, object]:
    """Apply or resume one exact M3 Plan while the caller owns the writer gate."""

    _require_review_package_binding(
        root=root,
        plan=plan,
        decision=decision,
        directory=review_package_directory,
    )
    stage_a_runtime._require_current_authority(root, compiled_policy, plan)
    anchor = _durable_snapshot._RootAnchor.open(root, expected_identity=root_identity)
    intent_value = _intent_value(
        plan,
        request_sha256=request_sha256,
        decision_sha256=decision_sha256,
    )
    intent_raw = canonical_json_bytes(intent_value)
    transaction = _transaction_path(anchor, plan.sha256)
    intent_path = transaction / "intent.json"
    result_path = transaction / "result.json"
    cutoff_path = transaction / "committed-cleanup.json"
    try:
        _ensure_layout(anchor)
        _other_active_transaction_check(anchor, plan)
        existing_intent = _read_record(anchor, intent_path, label="M3 intent")
        existing_result = _read_record(anchor, result_path, label="M3 result")
        committed = _read_record(anchor, cutoff_path, label="M3 cutoff marker")
        if existing_result is not None:
            if existing_intent is None or existing_intent[0] != intent_raw:
                raise CanonicalCurationFence(
                    "terminal M3 Plan belongs to another request",
                    reason_code="PLAN_CONFLICT",
                )
            return _terminal_replay(
                anchor,
                plan,
                existing_result[1],
                request_sha256=request_sha256,
                decision_sha256=decision_sha256,
                max_total_bytes=max_total_bytes,
            )
        if existing_intent is not None:
            if existing_intent[0] != intent_raw:
                raise CanonicalCurationFence(
                    "incomplete M3 Plan belongs to another request",
                    reason_code="PLAN_CONFLICT",
                )
            if committed is not None:
                expected_cutoff = canonical_json_bytes(
                    _phase_value(
                        plan,
                        request_sha256=request_sha256,
                        decision_sha256=decision_sha256,
                        phase="COMMITTED_CLEANUP",
                    )
                )
                if committed[0] != expected_cutoff:
                    raise CurationCleanupRequired(
                        "M3 cutoff marker is not bound to the exact request",
                        plan_sha256=plan.sha256,
                    )
                try:
                    _verify_committed_generation(
                        anchor,
                        plan,
                        max_total_bytes=max_total_bytes,
                    )
                    _cleanup_committed(anchor, plan, max_total_bytes=max_total_bytes)
                    _verify_final(anchor, plan, max_total_bytes=max_total_bytes)
                    finalized = _result_value(
                        plan,
                        request_sha256=request_sha256,
                        decision_sha256=decision_sha256,
                        status="FINALIZED",
                        reason_code=None,
                    )
                    _publish_exact(
                        anchor,
                        result_path,
                        canonical_json_bytes(finalized),
                        label="M3 final result",
                    )
                    return finalized
                except Exception as exc:
                    raise CurationCleanupRequired(
                        "M3 committed cleanup remains incomplete",
                        plan_sha256=plan.sha256,
                    ) from exc
            _rollback(anchor, root, plan, max_total_bytes=max_total_bytes)
            rolled_back = _result_value(
                plan,
                request_sha256=request_sha256,
                decision_sha256=decision_sha256,
                status="ROLLED_BACK",
                reason_code="ROLLED_BACK",
            )
            _publish_exact(
                anchor,
                result_path,
                canonical_json_bytes(rolled_back),
                label="M3 rollback result",
            )
            raise CanonicalCurationFence(
                "interrupted M3 Plan was rolled back",
                reason_code="ROLLED_BACK",
            )

        try:
            revalidate()
        except AuthorityRuntimeError as exc:
            raise CanonicalCurationFence(
                "M3 Plan policy or lifecycle changed",
                reason_code="STALE",
            ) from exc
        source_snapshots = {
            observation.observation_id: stage_a_runtime._observation_snapshot(
                root,
                compiled_policy,
                observation,
                max_total_bytes=max_total_bytes,
            )
            for observation in plan.source_observations
        }
        source_paths = {item.relative_path for item in plan.source_observations}
        target_parents = {
            output.output_id: _target_parent_identity(root, output, source_paths)
            for effect in plan.effects
            for output in effect.outputs
        }
        _publish_exact(anchor, intent_path, intent_raw, label="M3 transaction intent")
        committed_cleanup = False
        try:
            _run_checkpoint("after-prepared")
            stage = _staging_path(anchor, plan.sha256)
            sources_fd = anchor._open_directory(stage.parts + ("sources",), create=True)
            outputs_fd = anchor._open_directory(stage.parts + ("outputs",), create=True)
            try:
                source_parent = os.fstat(sources_fd)
                source_parent_identity = (source_parent.st_dev, source_parent.st_ino)
            finally:
                os.close(sources_fd)
                os.close(outputs_fd)
            if _list_optional(anchor, stage.joinpath("sources")) or _list_optional(
                anchor,
                stage.joinpath("outputs"),
            ):
                raise stage_a_runtime.CurationRecoveryRequired(
                    "new M3 staging is not empty"
                )

            for observation in plan.source_observations:
                try:
                    revalidate()
                except AuthorityRuntimeError as exc:
                    raise CanonicalCurationFence(
                        "M3 Plan policy or lifecycle changed",
                        reason_code="STALE",
                    ) from exc
                stage_file = _source_stage_path(
                    anchor,
                    plan.sha256,
                    observation.observation_id,
                )
                _run_checkpoint("before-stage:" + observation.observation_id)
                stage_a_runtime._rename(
                    root.joinpath(*observation.relative_path.split("/")),
                    stage_file.display_path,
                    observation,
                    source_parent_identity=(
                        source_snapshots[observation.observation_id]["parent"]["device"],
                        source_snapshots[observation.observation_id]["parent"]["inode"],
                    ),
                    target_parent_identity=source_parent_identity,
                )
                if not stage_a_runtime._matches_relocated(
                    stage_a_runtime._regular_state(
                        anchor,
                        "/".join(stage_file.parts),
                        max_bytes=max_total_bytes,
                    ),
                    observation,
                ):
                    raise stage_a_runtime.CurationRecoveryRequired(
                        "M3 staged source readback differs"
                    )
                _run_checkpoint("after-stage:" + observation.observation_id)

            for effect in plan.effects:
                for output in effect.outputs:
                    output_stage = _output_stage_path(
                        anchor,
                        plan.sha256,
                        output.output_id,
                    )
                    _run_checkpoint("before-output-stage:" + output.output_id)
                    _publish_exact(
                        anchor,
                        output_stage,
                        output.content_bytes,
                        label="M3 complete output staging",
                    )
                    if not _output_matches(
                        stage_a_runtime._regular_state(
                            anchor,
                            "/".join(output_stage.parts),
                            max_bytes=max_total_bytes,
                        ),
                        output,
                    ):
                        raise stage_a_runtime.CurationRecoveryRequired(
                            "M3 complete output staging differs"
                        )
                    _run_checkpoint("after-output-stage:" + output.output_id)

            for effect in plan.effects:
                for output in effect.outputs:
                    output_stage = _output_stage_path(
                        anchor,
                        plan.sha256,
                        output.output_id,
                    )
                    stage_state = stage_a_runtime._regular_state(
                        anchor,
                        "/".join(output_stage.parts),
                        max_bytes=max_total_bytes,
                    )
                    _run_checkpoint("before-output-publish:" + output.output_id)
                    _rename_generated(
                        output_stage.display_path,
                        root.joinpath(*output.output_path.split("/")),
                        stage_state,
                        target_parent_identity=target_parents[output.output_id],
                    )
                    _run_checkpoint("after-output-publish:" + output.output_id)

            _verify_published(anchor, plan, max_total_bytes=max_total_bytes)
            _publish_exact(
                anchor,
                transaction / "published-verified.json",
                canonical_json_bytes(
                    _phase_value(
                        plan,
                        request_sha256=request_sha256,
                        decision_sha256=decision_sha256,
                        phase="PUBLISHED_VERIFIED",
                    )
                ),
                label="M3 published verification marker",
            )
            _run_checkpoint("after-published-verified")
            _require_review_package_binding(
                root=root,
                plan=plan,
                decision=decision,
                directory=review_package_directory,
            )
            stage_a_runtime._require_current_authority(root, compiled_policy, plan)
            _verify_published(anchor, plan, max_total_bytes=max_total_bytes)
            _publish_exact(
                anchor,
                cutoff_path,
                canonical_json_bytes(
                    _phase_value(
                        plan,
                        request_sha256=request_sha256,
                        decision_sha256=decision_sha256,
                        phase="COMMITTED_CLEANUP",
                    )
                ),
                label="M3 irreversible cutoff marker",
            )
            committed_cleanup = True
            _run_checkpoint("after-cutoff-committed")
            _cleanup_committed(anchor, plan, max_total_bytes=max_total_bytes)
            _verify_final(anchor, plan, max_total_bytes=max_total_bytes)
            finalized = _result_value(
                plan,
                request_sha256=request_sha256,
                decision_sha256=decision_sha256,
                status="FINALIZED",
                reason_code=None,
            )
            _publish_exact(
                anchor,
                result_path,
                canonical_json_bytes(finalized),
                label="M3 final result",
            )
            return finalized
        except Exception as exc:
            if committed_cleanup or anchor.read_bytes(cutoff_path) is not None:
                marker = transaction / "recovery-required.json"
                try:
                    _publish_exact(
                        anchor,
                        marker,
                        canonical_json_bytes(
                            _phase_value(
                                plan,
                                request_sha256=request_sha256,
                                decision_sha256=decision_sha256,
                                phase="RECOVERY_REQUIRED",
                            )
                        ),
                        label="M3 cleanup recovery marker",
                    )
                except Exception:
                    pass
                raise CurationCleanupRequired(
                    "M3 irreversible cleanup requires exact resume",
                    plan_sha256=plan.sha256,
                ) from exc
            try:
                _rollback(anchor, root, plan, max_total_bytes=max_total_bytes)
                rolled_back = _result_value(
                    plan,
                    request_sha256=request_sha256,
                    decision_sha256=decision_sha256,
                    status="ROLLED_BACK",
                    reason_code=(
                        exc.reason_code
                        if isinstance(exc, CanonicalCurationFence)
                        else "ROLLED_BACK"
                    ),
                )
                _publish_exact(
                    anchor,
                    result_path,
                    canonical_json_bytes(rolled_back),
                    label="M3 rollback result",
                )
            except Exception as rollback_error:
                raise stage_a_runtime.CurationRecoveryRequired(
                    "M3 rollback equality is unproven"
                ) from rollback_error
            if isinstance(exc, CanonicalCurationFence):
                raise
            raise CanonicalCurationFence(
                "M3 Plan failed and was rolled back",
                reason_code="ROLLED_BACK",
            ) from exc
    finally:
        anchor.close()


def validate_plan_apply_result(outcome: object) -> None:
    result = outcome.result if type(outcome) is operation_contract.OperationOutcome else None
    if type(result) is not dict or result.get("schema") != _RESULT_SCHEMA:
        raise ValueError("M3 Curation Plan apply result is invalid")
    if (
        type(outcome) is not operation_contract.OperationOutcome
        or outcome.outcome_kind != "completed"
        or result.get("status") != "FINALIZED"
        or result.get("reason_code") is not None
        or result.get("cutoff_state") != "CLEANUP_VERIFIED"
        or result.get("cleanup")
        != {"staging_empty": True, "superseded_originals_absent": True}
        or result.get("equality")
        != {
            "effect_membership_complete": True,
            "outputs_match": True,
            "sources_restored": False,
        }
        or type(result.get("effects")) is not list
        or result.get("effect_count") != len(result["effects"])
        or any(
            type(result.get(name)) is not str or _HASH.fullmatch(result[name]) is None
            for name in (
                "decision_sha256",
                "output_manifest_sha256",
                "plan_sha256",
                "request_sha256",
            )
        )
    ):
        raise ValueError("M3 Curation Plan apply result is invalid")


__all__ = [
    "CurationCleanupRequired",
    "apply_plan",
    "decode_admitted_input",
    "decode_plan",
    "validate_plan_apply_request",
    "validate_plan_apply_result",
    "workstream_mutation_status",
]
