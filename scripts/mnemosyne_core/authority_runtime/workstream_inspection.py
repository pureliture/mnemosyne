"""Authority-bound resolution and physical identity for Workstream inspection."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .. import inventory, safety
from . import (
    AuthorityRuntimeError,
    WorkstreamInspectionEvidence,
    WorkstreamInspectionFence,
    WorkstreamProjectIdentity,
)
from . import auxiliary_index


_SUPPORTED_LIFECYCLES = frozenset(("active", "paused", "completed"))
_FROZEN_LIFECYCLES = frozenset(("paused", "completed"))
_MAX_DRIFT_FINDINGS = 8
_MAX_EXCLUDED_REASON_ROWS = 8
_VALID_FROZEN_DIRECTORY_TRAVERSALS = frozenset(
    ("directory-count-only", "not-entered")
)
_FROZEN_ERROR_CODES = frozenset(
    (
        "directory-count-entry-error",
        "directory-list-failed",
        "directory-open-failed",
        "directory-race",
        "max-depth",
        "max-direct-entries",
        "max-entries",
        "mount-boundary",
    )
)
_UNREADABLE_DIRECTORY_ERRORS = frozenset(
    (
        "directory-count-entry-error",
        "directory-list-failed",
        "directory-open-failed",
    )
)
_DRIFT_REASON_CODES = frozenset(
    (
        "AUXILIARY_MISSING",
        "AUXILIARY_MALFORMED",
        "AUXILIARY_AMBIGUOUS",
        "AUXILIARY_LIMIT_EXCEEDED",
        "AUXILIARY_ID_MISMATCH",
        "AUXILIARY_ROOT_MISMATCH",
        "AUXILIARY_FRESHNESS_MISSING",
        "AUXILIARY_UNSAFE",
    )
)


@dataclass(frozen=True)
class ResolvedWorkstream:
    canonical_id: str
    lifecycle: str
    project_home: Path


def _fence(message: str, reason_code: str) -> WorkstreamInspectionFence:
    return WorkstreamInspectionFence(message, reason_code=reason_code)


def _scope_unsafe(message: str) -> WorkstreamInspectionFence:
    return _fence(message, "SCOPE_UNSAFE")


def _require_public_text(value: object, label: str, *, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise _scope_unsafe("Frozen %s is unsafe" % label)
    return value


def _require_public_relative_path(value: object, label: str) -> str:
    path = _require_public_text(value, label, maximum=4096)
    components = path.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise _scope_unsafe("Frozen %s is unsafe" % label)
    return path


def _require_non_negative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise _scope_unsafe("Frozen %s is invalid" % label)
    return value


def _validated_frozen_bounds(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != {
        "max_items",
        "max_depth",
        "max_hint_bytes",
    }:
        raise _scope_unsafe("Frozen bounds are invalid")
    bounds = {
        "max_items": value["max_items"],
        "max_depth": value["max_depth"],
        "max_hint_bytes": value["max_hint_bytes"],
    }
    if (
        type(bounds["max_items"]) is not int
        or not 1 <= bounds["max_items"] <= 4096
        or type(bounds["max_depth"]) is not int
        or not 0 <= bounds["max_depth"] <= 16
        or type(bounds["max_hint_bytes"]) is not int
        or not 0 <= bounds["max_hint_bytes"] <= 1024 * 1024
    ):
        raise _scope_unsafe("Frozen bounds are invalid")
    return bounds


def _validated_drift(value: object) -> tuple[list[dict[str, object]], int, bool]:
    if not isinstance(value, Mapping) or set(value) != {
        "findings",
        "metadata_bytes_used",
        "truncated",
    }:
        raise _scope_unsafe("Frozen drift evidence is invalid")
    findings = value["findings"]
    metadata_bytes_used = value["metadata_bytes_used"]
    truncated = value["truncated"]
    if (
        type(findings) is not tuple
        or type(metadata_bytes_used) is not int
        or not 0 <= metadata_bytes_used <= 8192
        or type(truncated) is not bool
    ):
        raise _scope_unsafe("Frozen drift evidence is invalid")
    projected = []
    for finding in findings[:_MAX_DRIFT_FINDINGS]:
        if not isinstance(finding, Mapping) or set(finding) != {
            "source_id",
            "field",
            "reason_code",
            "authority_value",
            "observed_value",
            "requires_manual_review",
        }:
            raise _scope_unsafe("Frozen drift finding is invalid")
        source_id = _require_public_text(finding["source_id"], "drift source")
        field = _require_public_text(finding["field"], "drift field")
        reason_code = finding["reason_code"]
        authority_value = finding["authority_value"]
        observed_value = finding["observed_value"]
        if (
            reason_code not in _DRIFT_REASON_CODES
            or finding["requires_manual_review"] is not True
            or (
                authority_value is not None
                and type(authority_value) is not str
            )
            or (
                observed_value is not None
                and type(observed_value) is not str
            )
        ):
            raise _scope_unsafe("Frozen drift finding is invalid")
        if authority_value is not None:
            authority_value = _require_public_text(
                authority_value,
                "drift authority value",
            )
        if observed_value is not None:
            observed_value = _require_public_text(
                observed_value,
                "drift observed value",
            )
        projected.append(
            {
                "source_id": source_id,
                "field": field,
                "reason_code": reason_code,
                "authority_value": authority_value,
                "observed_value": observed_value,
                "requires_manual_review": True,
            }
        )
    return (
        projected,
        metadata_bytes_used,
        truncated or len(findings) > _MAX_DRIFT_FINDINGS,
    )


def _public_local_directory_path(display_path: object) -> str | None:
    if display_path == ".":
        return ""
    try:
        return _require_public_relative_path(display_path, "directory path")
    except WorkstreamInspectionFence:
        return None


def _increment_reason_count(counts: dict[str, int], reason_code: str) -> None:
    counts[reason_code] = counts.get(reason_code, 0) + 1


def _validated_frozen_errors(value: object) -> list[str]:
    if type(value) is not tuple or any(
        type(code) is not str or code not in _FROZEN_ERROR_CODES
        for code in value
    ):
        raise _scope_unsafe("Frozen inventory errors are unsafe")
    return sorted(set(value))


def build_frozen_scope_result(
    inventory_result: inventory.InventoryResult,
    evidence: WorkstreamInspectionEvidence,
    request_bounds: object,
    drift_evidence: object,
) -> dict[str, object]:
    """Project count-only observations through the frozen public allowlist."""

    if type(inventory_result) is not inventory.InventoryResult:
        raise _scope_unsafe("Frozen inventory result is invalid")
    if (
        type(evidence) is not WorkstreamInspectionEvidence
        or evidence.captured_lifecycle not in _FROZEN_LIFECYCLES
        or not evidence.canonical_id
        or type(evidence.project_home_relative) is not tuple
        or not evidence.project_home_relative
    ):
        raise _scope_unsafe("Frozen Workstream evidence is invalid")
    canonical_id = _require_public_text(evidence.canonical_id, "Workstream id")
    project_home = _require_public_relative_path(
        "/".join(evidence.project_home_relative),
        "project home",
    )
    bounds = _validated_frozen_bounds(request_bounds)
    drift, metadata_bytes_used, auxiliary_truncated = _validated_drift(drift_evidence)
    observations = inventory_result.observations
    if len(observations) > bounds["max_items"]:
        raise _fence("Frozen result exceeds item bound", "SCOPE_LIMIT_EXCEEDED")

    directories = []
    excluded_counts: dict[str, int] = {}
    seen_paths = set()
    file_count = 0
    other_count = 0
    unreadable_count = 0
    unsafe_count = 0
    unknown_descendant_count = 0
    max_depth_reached = 0
    traversal_truncated = False
    for observation in observations:
        if (
            type(observation) is not inventory.Observation
            or observation.run_id != inventory_result.run_id
            or observation.physical_kind != "directory"
            or observation.content_inspected
            or observation.reference_projection is not None
            or observation.classification_projection is not None
            or observation.fingerprint_kind == "sha256"
            or (
                observation.fingerprint_value is not None
                and observation.fingerprint_kind != "direct-entry-manifest"
            )
            or observation.scope_class != "coverage-only"
            or observation.scope_rule_id != "paused-completed"
        ):
            raise _scope_unsafe("Frozen inventory observation is unsafe")
        direct_files = _require_non_negative_int(
            observation.direct_file_count,
            "direct file count",
        )
        direct_other = _require_non_negative_int(
            observation.direct_other_count,
            "direct other count",
        )
        descendant_unknown = _require_non_negative_int(
            observation.descendant_unknown,
            "descendant unknown count",
        )

        file_count += direct_files
        other_count += direct_other
        unknown_descendant_count += descendant_unknown
        errors = _validated_frozen_errors(observation.errors)
        for code in errors:
            _increment_reason_count(excluded_counts, code)
        if any(code.startswith("max-") for code in errors):
            traversal_truncated = True
        if any(code in _UNREADABLE_DIRECTORY_ERRORS for code in errors):
            unreadable_count += 1

        local_path = _public_local_directory_path(observation.display_path)
        if observation.kind != "directory" or local_path is None:
            unsafe_count += 1
            _increment_reason_count(excluded_counts, "unsafe-directory")
            continue
        if observation.traversal not in _VALID_FROZEN_DIRECTORY_TRAVERSALS:
            raise _scope_unsafe("Frozen directory traversal is unsafe")
        public_path = project_home if not local_path else project_home + "/" + local_path
        if public_path in seen_paths:
            raise _scope_unsafe("Frozen directory paths are ambiguous")
        seen_paths.add(public_path)
        depth = 0 if not local_path else local_path.count("/") + 1
        if depth > bounds["max_depth"]:
            raise _scope_unsafe("Frozen directory depth exceeds its bound")
        if observation.traversal == "directory-count-only":
            max_depth_reached = max(max_depth_reached, depth)
        directories.append(
            {
                "path": public_path,
                "direct_file_count": direct_files,
                "direct_other_count": direct_other,
                "descendant_unknown_count": descendant_unknown,
                "errors": errors,
            }
        )

    directories.sort(key=lambda item: item["path"])
    excluded_items = sorted(excluded_counts.items())
    excluded_truncated = len(excluded_items) > _MAX_EXCLUDED_REASON_ROWS
    excluded = [
        {"reason_code": reason_code, "count": count}
        for reason_code, count in excluded_items[:_MAX_EXCLUDED_REASON_ROWS]
    ]
    returned = len(directories) + len(excluded) + len(drift)
    if returned > bounds["max_items"] + _MAX_EXCLUDED_REASON_ROWS + _MAX_DRIFT_FINDINGS:
        raise _fence("Frozen result cannot be represented", "SCOPE_LIMIT_EXCEEDED")
    return {
        "schema_version": 2,
        "view": "scope",
        "inspection_mode": "frozen-coverage",
        "workstream": {
            "id": canonical_id,
            "lifecycle": evidence.captured_lifecycle,
            "project_home": project_home,
            "identity_status": "verified",
        },
        "bounds": bounds,
        "current_scope": {"status": "verified"},
        "usage": {
            "items_used": len(observations),
            "max_depth_reached": max_depth_reached,
            "metadata_bytes_used": metadata_bytes_used,
            "drift_returned": len(drift),
        },
        "frozen_coverage": {
            "directories": directories,
            "directory_count": len(directories),
            "file_count": file_count,
            "other_count": other_count,
            "unreadable_count": unreadable_count,
            "unsafe_count": unsafe_count,
            "unknown_descendant_count": unknown_descendant_count,
            "hint_bytes_used": 0,
        },
        "excluded": excluded,
        "drift": drift,
        "candidates": [],
        "returned": returned,
        "truncated": (
            traversal_truncated or auxiliary_truncated or excluded_truncated
        ),
    }


def _require_reference(value: object) -> str:
    if type(value) is not str or not value:
        raise _fence("Workstream reference is invalid", "WORKSTREAM_NOT_FOUND")
    return value


def resolve_workstream_for_inspection(
    compiled_policy: object,
    workstream_ref: object,
) -> ResolvedWorkstream:
    """Resolve one exact case-folded id or alias without path interpretation."""

    reference_key = _require_reference(workstream_ref).casefold()
    matches = []
    for workstream in getattr(compiled_policy, "workstreams", ()):
        identifier = getattr(workstream, "id", None)
        aliases = getattr(workstream, "aliases", ())
        if type(identifier) is not str or not isinstance(aliases, tuple):
            continue
        tokens = (identifier,) + aliases
        if any(type(token) is str and token.casefold() == reference_key for token in tokens):
            matches.append(workstream)
    if not matches:
        raise _fence("Workstream was not found", "WORKSTREAM_NOT_FOUND")
    if len(matches) != 1:
        raise _fence("Workstream reference is ambiguous", "WORKSTREAM_AMBIGUOUS")
    selected = matches[0]
    identifier = getattr(selected, "id", None)
    lifecycle = getattr(selected, "lifecycle", None)
    project_home = getattr(selected, "project_home", None)
    if type(identifier) is not str or not identifier:
        raise _fence("Workstream evidence is ambiguous", "WORKSTREAM_AMBIGUOUS")
    if lifecycle not in _SUPPORTED_LIFECYCLES:
        raise _fence(
            "Workstream lifecycle is unsupported",
            "WORKSTREAM_LIFECYCLE_UNSUPPORTED",
        )
    if type(project_home) is not str or not project_home:
        raise _fence("Workstream home is unsafe", "WORKSTREAM_HOME_UNSAFE")
    return ResolvedWorkstream(
        canonical_id=identifier,
        lifecycle=lifecycle,
        project_home=Path(project_home),
    )


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _relative_components(root: Path, project_home: Path) -> tuple[str, ...]:
    if (
        not root.is_absolute()
        or not project_home.is_absolute()
        or any(component in {"", ".", ".."} for component in project_home.parts[1:])
    ):
        raise _fence("Workstream home is unsafe", "WORKSTREAM_HOME_UNSAFE")
    try:
        relative = project_home.relative_to(root)
    except ValueError as exc:
        raise _fence("Workstream home is unsafe", "WORKSTREAM_HOME_UNSAFE") from exc
    components = relative.parts
    if not components or any(component in {"", ".", ".."} for component in components):
        raise _fence("Workstream home is unsafe", "WORKSTREAM_HOME_UNSAFE")
    return components


def _open_project_home(
    root: Path,
    components: tuple[str, ...],
) -> tuple[int, WorkstreamProjectIdentity]:
    current: int | None = None
    flags = _directory_flags()
    try:
        current = os.open(root, flags)
        root_info = os.fstat(current)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) & 0o022
        ):
            raise _fence("Workstream root is unsafe", "WORKSTREAM_HOME_UNSAFE")
        root_device = root_info.st_dev
        for component in components:
            try:
                lexical = os.stat(component, dir_fd=current, follow_symlinks=False)
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError as exc:
                raise _fence(
                    "Workstream home is missing",
                    "WORKSTREAM_HOME_MISSING",
                ) from exc
            except OSError as exc:
                raise _fence("Workstream home is unsafe", "WORKSTREAM_HOME_UNSAFE") from exc
            try:
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(lexical.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or (lexical.st_dev, lexical.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or opened.st_dev != root_device
                    or opened.st_uid != os.getuid()
                    or stat.S_IMODE(opened.st_mode) & 0o022
                ):
                    raise _fence(
                        "Workstream home is unsafe",
                        "WORKSTREAM_HOME_UNSAFE",
                    )
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        info = os.fstat(current)
        return current, WorkstreamProjectIdentity(
            device=info.st_dev,
            inode=info.st_ino,
            mode=stat.S_IMODE(info.st_mode),
            uid=info.st_uid,
        )
    except WorkstreamInspectionFence:
        if current is not None:
            os.close(current)
        raise
    except OSError as exc:
        if current is not None:
            os.close(current)
        raise _fence("Workstream home is unsafe", "WORKSTREAM_HOME_UNSAFE") from exc


def capture_inspection_evidence(
    root: Path,
    resolved: ResolvedWorkstream,
) -> WorkstreamInspectionEvidence:
    """Capture one immutable Workstream row and verified project directory identity."""

    if not isinstance(root, Path) or type(resolved) is not ResolvedWorkstream:
        raise TypeError("Workstream inspection evidence input is invalid")
    components = _relative_components(root, resolved.project_home)
    descriptor, identity = _open_project_home(root, components)
    os.close(descriptor)
    return WorkstreamInspectionEvidence(
        canonical_id=resolved.canonical_id,
        captured_lifecycle=resolved.lifecycle,
        project_home_relative=components,
        project_identity=identity,
    )


def revalidate_inspection_evidence(
    compiled_policy: object,
    root: Path,
    workstream_ref: object,
    evidence: WorkstreamInspectionEvidence,
) -> None:
    """Re-resolve the sealed reference and prove the same project directory remains."""

    if type(evidence) is not WorkstreamInspectionEvidence:
        raise TypeError("Workstream inspection evidence is invalid")
    try:
        resolved = resolve_workstream_for_inspection(compiled_policy, workstream_ref)
    except WorkstreamInspectionFence as exc:
        raise _fence("Workstream policy changed", "POLICY_CHANGED") from exc
    try:
        components = _relative_components(root, resolved.project_home)
    except WorkstreamInspectionFence as exc:
        raise _fence("Workstream policy changed", "POLICY_CHANGED") from exc
    if (
        resolved.canonical_id != evidence.canonical_id
        or resolved.lifecycle != evidence.captured_lifecycle
        or components != evidence.project_home_relative
    ):
        raise _fence("Workstream policy changed", "POLICY_CHANGED")
    try:
        descriptor, observed_identity = _open_project_home(root, components)
    except WorkstreamInspectionFence as exc:
        raise _fence("Workstream home changed", "WORKSTREAM_HOME_CHANGED") from exc
    os.close(descriptor)
    if observed_identity != evidence.project_identity:
        raise _fence("Workstream home changed", "WORKSTREAM_HOME_CHANGED")


def _open_frozen_project_at(
    raw_root_fd: int,
    evidence: WorkstreamInspectionEvidence,
) -> int:
    """Reopen the captured project home below one retained verified root fd."""

    current: int | None = None
    flags = _directory_flags()
    try:
        root_info = os.fstat(raw_root_fd)
        root_device = int(root_info.st_dev)
        current = os.dup(raw_root_fd)
        for component in evidence.project_home_relative:
            try:
                lexical = os.stat(component, dir_fd=current, follow_symlinks=False)
                child = os.open(component, flags, dir_fd=current)
            except OSError as exc:
                raise _fence(
                    "Workstream home changed",
                    "WORKSTREAM_HOME_CHANGED",
                ) from exc
            try:
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(lexical.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or (lexical.st_dev, lexical.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or opened.st_dev != root_device
                    or opened.st_uid != os.getuid()
                    or stat.S_IMODE(opened.st_mode) & 0o022
                ):
                    raise _fence(
                        "Workstream home changed",
                        "WORKSTREAM_HOME_CHANGED",
                    )
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        info = os.fstat(current)
        observed = WorkstreamProjectIdentity(
            device=info.st_dev,
            inode=info.st_ino,
            mode=stat.S_IMODE(info.st_mode),
            uid=info.st_uid,
        )
        if observed != evidence.project_identity:
            raise _fence("Workstream home changed", "WORKSTREAM_HOME_CHANGED")
        result = current
        current = None
        return result
    except WorkstreamInspectionFence:
        raise
    except OSError as exc:
        raise _fence("Workstream home changed", "WORKSTREAM_HOME_CHANGED") from exc
    finally:
        if current is not None:
            os.close(current)


def _missing_auxiliary_inspection(
    raw_root_fd: int,
    root: Path,
    evidence: WorkstreamInspectionEvidence,
) -> auxiliary_index.AuxiliaryInspection:
    try:
        token = auxiliary_index.derive_snapshot_token(evidence.canonical_id)
        with auxiliary_index.open_snapshot_capability(raw_root_fd, token) as capability:
            return auxiliary_index.inspect_snapshot(
                capability,
                expected_workstream_id=evidence.canonical_id,
                expected_project_home=root.joinpath(*evidence.project_home_relative),
                raw_root=root,
            )
    except auxiliary_index.AuxiliaryIndexError as exc:
        return auxiliary_index.inspection_from_error(exc)


def inspect_frozen_scope(
    *,
    root: Path,
    root_identity: tuple[int, int],
    evidence: WorkstreamInspectionEvidence,
    bounds: object,
) -> dict[str, object]:
    """Produce one in-memory paused/completed exact-root coverage result."""

    if (
        not isinstance(root, Path)
        or type(root_identity) is not tuple
        or len(root_identity) != 2
        or type(evidence) is not WorkstreamInspectionEvidence
        or evidence.captured_lifecycle not in _FROZEN_LIFECYCLES
        or not isinstance(bounds, Mapping)
    ):
        raise _scope_unsafe("Frozen inspection input is invalid")
    projected_bounds = _validated_frozen_bounds(bounds)
    try:
        raw_root_fd = safety.open_verified_directory(
            root,
            require_owner_only=True,
            error_type=AuthorityRuntimeError,
        )
    except AuthorityRuntimeError as exc:
        raise _fence("authority root changed", "RAW_ROOT_CHANGED") from exc
    project_fd: int | None = None
    try:
        raw_info = os.fstat(raw_root_fd)
        if (raw_info.st_dev, raw_info.st_ino) != root_identity:
            raise _fence("authority root changed", "RAW_ROOT_CHANGED")
        project_fd = _open_frozen_project_at(raw_root_fd, evidence)
        decision = inventory.ScopeDecision(
            rule_id="paused-completed",
            scope_class="coverage-only",
            traversal="directory-count-only",
            lifecycle=evidence.captured_lifecycle,
            content_inspection="none",
        )
        traversal_bounds = inventory.TraversalBounds(
            max_entries=projected_bounds["max_items"],
            max_direct_entries=projected_bounds["max_items"],
            max_depth=projected_bounds["max_depth"],
            max_file_bytes=0,
            max_content_bytes=0,
        )
        try:
            inventory_result = inventory.scan_directory_count_only(
                "frozen-workstream-inspection",
                project_fd,
                decision,
                traversal_bounds,
            )
        except (inventory.InventoryError, OSError) as exc:
            raise _scope_unsafe("Frozen traversal is unsafe") from exc
        auxiliary = _missing_auxiliary_inspection(raw_root_fd, root, evidence)
        result = build_frozen_scope_result(
            inventory_result,
            evidence,
            projected_bounds,
            auxiliary.to_evidence(),
        )
        project_info = os.fstat(project_fd)
        if WorkstreamProjectIdentity(
            device=project_info.st_dev,
            inode=project_info.st_ino,
            mode=stat.S_IMODE(project_info.st_mode),
            uid=project_info.st_uid,
        ) != evidence.project_identity:
            raise _fence("Workstream home changed", "WORKSTREAM_HOME_CHANGED")
        raw_after = os.fstat(raw_root_fd)
        if (raw_after.st_dev, raw_after.st_ino) != root_identity:
            raise _fence("authority root changed", "RAW_ROOT_CHANGED")
        return result
    finally:
        if project_fd is not None:
            os.close(project_fd)
        os.close(raw_root_fd)


__all__ = [
    "ResolvedWorkstream",
    "build_frozen_scope_result",
    "capture_inspection_evidence",
    "inspect_frozen_scope",
    "resolve_workstream_for_inspection",
    "revalidate_inspection_evidence",
]
