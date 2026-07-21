"""Strict canonical bytes codec for private D1a operation requests."""

from __future__ import annotations

import json

from .. import artifact_contract
from ..canonical_json import canonical_json_bytes
from . import (  # pyright: ignore[reportAttributeAccessIssue]
    AuthorityMode,
    ClaimMode,
    LifecycleAction,
    OperationRequest,
)


_REQUEST_FIELDS = {
    "schema_version",
    "operation_kind",
    "action",
    "claim_mode",
    "root",
    "actor",
    "requested_authority",
    "payload",
    "bounds",
    "scope",
    "approval_artifact",
    "prerequisite_artifacts",
}


def encode_operation_request(request: OperationRequest) -> bytes:
    if type(request) is not OperationRequest:
        raise TypeError("operation request is invalid")
    return request.canonical_bytes


def _decode_artifact_reference(
    value: object,
    label: str,
) -> artifact_contract.SealedArtifactRef:
    if type(value) is not dict:
        raise ValueError(f"canonical operation request {label} is invalid")
    try:
        return artifact_contract.SealedArtifactRef.from_canonical_bytes(
            canonical_json_bytes(value)
        )
    except ValueError as exc:
        raise ValueError(
            f"canonical operation request {label} sealed reference is invalid"
        ) from exc


def decode_operation_request(raw: bytes) -> OperationRequest:
    """Decode one exact canonical request including sealed artifact evidence."""

    if type(raw) is not bytes:
        raise ValueError("canonical operation request bytes are invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("canonical operation request is invalid") from exc
    if type(value) is not dict or set(value) != _REQUEST_FIELDS:
        raise ValueError("canonical operation request shape is invalid")
    approval_artifact = value["approval_artifact"]
    if approval_artifact is not None:
        approval_artifact = _decode_artifact_reference(
            approval_artifact,
            "approval artifact",
        )
    prerequisite_values = value["prerequisite_artifacts"]
    if type(prerequisite_values) is not list or len(prerequisite_values) > 1024:
        raise ValueError(
            "canonical operation request prerequisite artifacts are invalid"
        )
    prerequisite_artifacts = tuple(
        _decode_artifact_reference(item, "prerequisite artifact")
        for item in prerequisite_values
    )
    try:
        request = OperationRequest(
            schema_version=value["schema_version"],
            operation_kind=value["operation_kind"],
            action=LifecycleAction(value["action"]),
            claim_mode=ClaimMode(value["claim_mode"]),
            root=value["root"],
            actor=value["actor"],
            requested_authority=AuthorityMode(value["requested_authority"]),
            payload=value["payload"],
            bounds=value["bounds"],
            scope=value["scope"],
            approval_artifact=approval_artifact,
            prerequisite_artifacts=prerequisite_artifacts,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("canonical operation request is invalid") from exc
    if request.canonical_bytes != raw:
        raise ValueError("canonical operation request is required")
    return request
