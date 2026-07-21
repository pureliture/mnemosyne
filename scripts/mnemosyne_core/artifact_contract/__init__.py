"""Private sealed-artifact contract values for the D1a foundation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ..canonical_json import canonical_json_bytes, sha256_bytes


_ARTIFACT_KIND = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*")
_CANONICAL_PATH_PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_canonical_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
    ):
        raise ValueError("artifact canonical path is invalid")
    parts = value.split("/")
    if any(_CANONICAL_PATH_PART.fullmatch(part) is None for part in parts):
        raise ValueError("artifact canonical path is invalid")
    return value


def _freeze_json(value: object, label: str) -> object:
    if value is None or type(value) in (bool, int, float, str):
        return value
    if type(value) is list:
        return tuple(_freeze_json(item, label) for item in value)
    if type(value) is dict:
        frozen = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise ValueError(f"{label} contains an invalid key")
            frozen[key] = _freeze_json(item, label)
        return MappingProxyType(frozen)
    raise ValueError(f"{label} must contain JSON values")


def _thaw_json(value: object) -> object:
    if isinstance(value, MappingProxyType):
        return {key: _thaw_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True)
class SchemaIdentity:
    kind: str
    version: int
    schema_sha256: str

    def __post_init__(self) -> None:
        if type(self.kind) is not str or _ARTIFACT_KIND.fullmatch(self.kind) is None:
            raise ValueError("artifact schema kind is invalid")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("artifact schema version is invalid")
        _require_sha256(self.schema_sha256, "artifact schema hash")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "version": self.version,
            "schema_sha256": self.schema_sha256,
        }


@dataclass(frozen=True)
class SealedArtifactRef:
    schema: SchemaIdentity
    canonical_path: str
    artifact_sha256: str
    manifest_sha256: str
    producer_operation_sha256: str
    byte_length: int
    media_type: str

    def __post_init__(self) -> None:
        if type(self.schema) is not SchemaIdentity:
            raise ValueError("artifact schema identity is invalid")
        _require_canonical_path(self.canonical_path)
        _require_sha256(self.artifact_sha256, "artifact hash")
        _require_sha256(self.manifest_sha256, "artifact manifest hash")
        _require_sha256(
            self.producer_operation_sha256,
            "artifact producer operation identity",
        )
        if type(self.byte_length) is not int or self.byte_length < 0:
            raise ValueError("artifact byte length is invalid")
        if type(self.media_type) is not str or _MEDIA_TYPE.fullmatch(self.media_type) is None:
            raise ValueError("artifact media type is invalid")

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "schema": self.schema.canonical_value,
            "canonical_path": self.canonical_path,
            "artifact_sha256": self.artifact_sha256,
            "manifest_sha256": self.manifest_sha256,
            "producer_operation_sha256": self.producer_operation_sha256,
            "byte_length": self.byte_length,
            "media_type": self.media_type,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_value)

    def verify_bytes(self, artifact_bytes: bytes) -> "SealedArtifactRef":
        if type(artifact_bytes) is not bytes:
            raise ValueError("artifact bytes are invalid")
        if len(artifact_bytes) != self.byte_length:
            raise ValueError("artifact byte length does not match its sealed reference")
        if sha256_bytes(artifact_bytes) != self.artifact_sha256:
            raise ValueError("artifact hash does not match its sealed reference")
        return self

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> "SealedArtifactRef":
        if type(raw) is not bytes:
            raise ValueError("canonical sealed reference bytes are invalid")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("canonical sealed reference is invalid") from exc
        if type(value) is not dict or set(value) != {
            "schema",
            "canonical_path",
            "artifact_sha256",
            "manifest_sha256",
            "producer_operation_sha256",
            "byte_length",
            "media_type",
        }:
            raise ValueError("canonical sealed reference shape is invalid")
        schema_value = value["schema"]
        if type(schema_value) is not dict or set(schema_value) != {
            "kind",
            "version",
            "schema_sha256",
        }:
            raise ValueError("canonical sealed reference schema is invalid")
        reference = cls(
            schema=SchemaIdentity(
                kind=schema_value["kind"],
                version=schema_value["version"],
                schema_sha256=schema_value["schema_sha256"],
            ),
            canonical_path=value["canonical_path"],
            artifact_sha256=value["artifact_sha256"],
            manifest_sha256=value["manifest_sha256"],
            producer_operation_sha256=value["producer_operation_sha256"],
            byte_length=value["byte_length"],
            media_type=value["media_type"],
        )
        if reference.canonical_bytes != raw:
            raise ValueError("canonical sealed reference is required")
        return reference


@dataclass(frozen=True)
class ArtifactManifest:
    schema: SchemaIdentity
    artifact_refs: tuple[SealedArtifactRef, ...]
    metadata: dict[str, Any]

    def __post_init__(self) -> None:
        if type(self.schema) is not SchemaIdentity:
            raise ValueError("manifest schema identity is invalid")
        if (
            type(self.artifact_refs) is not tuple
            or not self.artifact_refs
            or any(type(reference) is not SealedArtifactRef for reference in self.artifact_refs)
            or any(reference.schema != self.schema for reference in self.artifact_refs)
            or len(self.artifact_refs) > 1024
            or len({reference.artifact_sha256 for reference in self.artifact_refs})
            != len(self.artifact_refs)
            or len({reference.canonical_path for reference in self.artifact_refs})
            != len(self.artifact_refs)
        ):
            raise ValueError("manifest artifact references are invalid")
        if type(self.metadata) is not dict:
            raise ValueError("manifest metadata must be a plain object")
        frozen = _freeze_json(self.metadata, "manifest metadata")
        if not isinstance(frozen, MappingProxyType):
            raise AssertionError("manifest metadata must freeze to a mapping")
        object.__setattr__(self, "metadata", frozen)

    @property
    def canonical_value(self) -> dict[str, object]:
        return {
            "schema": self.schema.canonical_value,
            "artifact_refs": [
                reference.canonical_value for reference in self.artifact_refs
            ],
            "metadata": _thaw_json(self.metadata),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_value)

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes)

    @property
    def member_hashes(self) -> MappingProxyType:
        return MappingProxyType(
            {
                reference.canonical_path: reference.artifact_sha256
                for reference in self.artifact_refs
            }
        )


__all__ = ["SchemaIdentity", "SealedArtifactRef", "ArtifactManifest"]
