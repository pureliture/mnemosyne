"""Adaptive folder-first review units and immutable explode snapshots."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Sequence, Tuple

from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ACTIONS = frozenset(("keep", "link", "move", "archive", "defer", "exclude"))
_RISKS = frozenset(("low", "medium", "high", "blocked"))
_FREEZE = frozenset(("active", "frozen", "override"))


class ReviewUnitError(ValueError):
    """Review-unit membership would be ambiguous or unsafe."""


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ReviewUnitError("%s is invalid" % label)
    return value


def _path(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ReviewUnitError("review item path must be raw-relative")
    if posixpath.normpath(value) != value or value in (".", "..") or value.startswith("../"):
        raise ReviewUnitError("review item path must be canonical")
    if any(ord(character) < 0x20 for character in value):
        raise ReviewUnitError("review item path contains control characters")
    return value


@dataclass(frozen=True)
class ReviewItem:
    item_id: str
    path: str
    size: int
    scope_class: str
    scope_rule_id: str
    primary_workstream: str
    related_workstreams: Tuple[str, ...]
    shared: bool
    document_role: str
    authority: str
    document_lifecycle: str
    sensitivity: str
    access_domain: str
    recommended_action: str
    risk_band: str
    freeze_state: str
    reference_complete: bool
    negative_flags: Tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.item_id, "item id")
        object.__setattr__(self, "path", _path(self.path))
        if type(self.size) is not int or self.size < 0:
            raise ReviewUnitError("item size must be non-negative")
        for label, value in (
            ("scope class", self.scope_class),
            ("scope rule id", self.scope_rule_id),
            ("primary workstream", self.primary_workstream),
            ("document role", self.document_role),
            ("authority", self.authority),
            ("document lifecycle", self.document_lifecycle),
            ("sensitivity", self.sensitivity),
            ("access domain", self.access_domain),
        ):
            _identifier(value, label)
        if type(self.related_workstreams) is not tuple or tuple(
            sorted(set(self.related_workstreams))
        ) != self.related_workstreams:
            raise ReviewUnitError("related workstreams must be unique and sorted")
        for workstream in self.related_workstreams:
            _identifier(workstream, "related workstream")
        if type(self.shared) is not bool:
            raise ReviewUnitError("shared must be boolean")
        if self.recommended_action not in _ACTIONS:
            raise ReviewUnitError("recommended action is invalid")
        if self.risk_band not in _RISKS:
            raise ReviewUnitError("risk band is invalid")
        if self.freeze_state not in _FREEZE:
            raise ReviewUnitError("freeze state is invalid")
        if type(self.reference_complete) is not bool:
            raise ReviewUnitError("reference_complete must be boolean")
        if type(self.negative_flags) is not tuple or tuple(
            sorted(set(self.negative_flags))
        ) != self.negative_flags:
            raise ReviewUnitError("negative flags must be unique and sorted")
        for flag in self.negative_flags:
            _identifier(flag, "negative flag")

    def homogeneity_key(self) -> Tuple[object, ...]:
        return (
            self.scope_class,
            self.scope_rule_id,
            self.primary_workstream,
            self.related_workstreams,
            self.shared,
            self.document_role,
            self.authority,
            self.document_lifecycle,
            self.sensitivity,
            self.access_domain,
            self.recommended_action,
            self.risk_band,
            self.freeze_state,
            self.reference_complete,
        )

    def manifest_row(self) -> dict:
        return {
            "homogeneity": list(self.homogeneity_key()),
            "item_id": self.item_id,
            "path": self.path,
            "size": self.size,
        }

    def to_dict(self) -> dict:
        return {
            "access_domain": self.access_domain,
            "authority": self.authority,
            "document_lifecycle": self.document_lifecycle,
            "document_role": self.document_role,
            "freeze_state": self.freeze_state,
            "item_id": self.item_id,
            "negative_flags": list(self.negative_flags),
            "path": self.path,
            "primary_workstream": self.primary_workstream,
            "recommended_action": self.recommended_action,
            "reference_complete": self.reference_complete,
            "related_workstreams": list(self.related_workstreams),
            "risk_band": self.risk_band,
            "scope_class": self.scope_class,
            "scope_rule_id": self.scope_rule_id,
            "sensitivity": self.sensitivity,
            "shared": self.shared,
            "size": self.size,
        }


@dataclass(frozen=True)
class ReviewUnit:
    unit_id: str
    kind: str
    path: str
    member_item_ids: Tuple[str, ...]
    underlying_file_count: int
    total_bytes: int
    descendant_manifest_sha256: str
    homogeneity_key: Tuple[object, ...]
    explode_reasons: Tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "descendant_manifest_sha256": self.descendant_manifest_sha256,
            "explode_reasons": list(self.explode_reasons),
            "homogeneity_key": list(self.homogeneity_key),
            "kind": self.kind,
            "member_item_ids": list(self.member_item_ids),
            "path": self.path,
            "total_bytes": self.total_bytes,
            "underlying_file_count": self.underlying_file_count,
            "unit_id": self.unit_id,
        }


@dataclass(frozen=True)
class ReviewUnitSet:
    builder_version: str
    items: Tuple[ReviewItem, ...]
    units: Tuple[ReviewUnit, ...]


def _unit_id(
    builder_version: str,
    kind: str,
    path: str,
    members: Tuple[ReviewItem, ...],
) -> str:
    return "unit-%s" % sha256_bytes(
        canonical_json_bytes(
            {
                "builder_version": builder_version,
                "kind": kind,
                "member_item_ids": [item.item_id for item in members],
                "path": path,
            }
        )
    )[:24]


def _make_unit(
    builder_version: str,
    kind: str,
    path: str,
    members: Tuple[ReviewItem, ...],
) -> ReviewUnit:
    ordered = tuple(sorted(members, key=lambda value: (value.path, value.item_id)))
    manifest = canonical_json_bytes(
        [item.manifest_row() for item in ordered]
    )
    reasons = tuple(
        sorted({flag for item in ordered for flag in item.negative_flags})
    )
    return ReviewUnit(
        unit_id=_unit_id(builder_version, kind, path, ordered),
        kind=kind,
        path=path,
        member_item_ids=tuple(item.item_id for item in ordered),
        underlying_file_count=len(ordered),
        total_bytes=sum(item.size for item in ordered),
        descendant_manifest_sha256=sha256_bytes(manifest),
        homogeneity_key=ordered[0].homogeneity_key(),
        explode_reasons=reasons,
    )


class ReviewUnitBuilder:
    def __init__(self, builder_version: str) -> None:
        self.builder_version = _identifier(builder_version, "builder version")

    def build(self, items: Sequence[ReviewItem]) -> ReviewUnitSet:
        if not isinstance(items, (tuple, list)):
            raise TypeError("items must be a sequence")
        ordered = tuple(sorted(items, key=lambda value: (value.path, value.item_id)))
        if not ordered:
            raise ReviewUnitError("at least one review item is required")
        if any(type(item) is not ReviewItem for item in ordered):
            raise TypeError("items must contain ReviewItem values")
        if len({item.item_id for item in ordered}) != len(ordered):
            raise ReviewUnitError("review item ids must be unique")
        if len({item.path for item in ordered}) != len(ordered):
            raise ReviewUnitError("review item paths must be unique")

        units = []

        def emit(folder: str, descendants: Tuple[ReviewItem, ...]) -> None:
            direct = tuple(
                item for item in descendants if posixpath.dirname(item.path) == folder
            )
            child_names = sorted(
                {
                    item.path[len(folder) + 1 :].split("/", 1)[0]
                    if folder
                    else item.path.split("/", 1)[0]
                    for item in descendants
                    if posixpath.dirname(item.path) != folder
                }
            )
            if not direct and len(child_names) == 1:
                child = posixpath.join(folder, child_names[0]) if folder else child_names[0]
                emit(child, descendants)
                return
            homogeneous = len({item.homogeneity_key() for item in descendants}) == 1
            forced = any(item.negative_flags for item in descendants)
            if folder and len(descendants) > 1 and homogeneous and not forced:
                units.append(
                    _make_unit(self.builder_version, "folder", folder, descendants)
                )
                return
            for current in direct:
                units.append(
                    _make_unit(self.builder_version, "file", current.path, (current,))
                )
            for child_name in child_names:
                child = posixpath.join(folder, child_name) if folder else child_name
                prefix = child + "/"
                child_items = tuple(
                    item for item in descendants if item.path.startswith(prefix)
                )
                emit(child, child_items)

        emit("", ordered)
        result_units = tuple(sorted(units, key=lambda value: (value.path, value.kind)))
        memberships = [item_id for unit in result_units for item_id in unit.member_item_ids]
        if sorted(memberships) != sorted(item.item_id for item in ordered):
            raise ReviewUnitError("review unit membership is incomplete")
        if len(memberships) != len(set(memberships)):
            raise ReviewUnitError("review unit membership overlaps")
        return ReviewUnitSet(self.builder_version, ordered, result_units)


__all__ = [
    "ReviewItem",
    "ReviewUnit",
    "ReviewUnitBuilder",
    "ReviewUnitError",
    "ReviewUnitSet",
]
