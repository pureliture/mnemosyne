"""Bounded read-only Workstream inspection and Stage-A Review Package workflow."""

from __future__ import annotations

import os
import stat
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional

from . import (
    canonical_curation,
    canonical_curation_review,
    context_assembly,
    policy,
    review_package,
    safety,
)
from .canonical_json import canonical_json_bytes, sha256_bytes
from .authority_runtime import (
    canonical_curation as curation_transaction,
    librarian,
    librarian_snapshot,
    workstream_inspection,
)


_MAX_REGISTRY_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_ROLE_DIRECTORY_PATTERNS = {
    "current_state": (("status",), ("current-state",)),
    "decisions": (("decisions",), ("decision",), ("adr",), ("adrs",)),
    "work_results": (("work",), ("results",), ("outputs",)),
    "references": (
        ("references",),
        ("reference",),
        ("research",),
        ("docs", "research"),
    ),
}
_EXPLICIT_DOCUMENT_ROLE_TOKENS = {
    "overview": ("overview", "소개", "개요"),
    "decisions": ("decision", "adr", "결정"),
    "current_state": ("status", "current", "next", "상태", "다음"),
    "references": (
        "reference",
        "source",
        "evidence",
        "research",
        "참고",
        "근거",
        "리서치",
        "조사",
        "레퍼런스",
    ),
}
_HUMAN_DOCUMENT_SUFFIXES = {".adoc", ".markdown", ".md", ".okf", ".rst", ".txt"}
_CONTEXT_NONBLOCKING_LOCAL_REASONS = frozenset(
    {
        "CONTENT_OPAQUE",
        "GENERATED",
        "POLICY_EXCLUDED",
        "SOURCE_CHANGED",
        "WORKSTREAM_INACTIVE",
    }
)
_CONTEXT_UNSAFE_LOCAL_REASONS = frozenset({"SCOPE_UNSAFE", "SOURCE_UNSUPPORTED"})


@dataclass(frozen=True)
class _ContextInspectionRow:
    """One already-classified scan row consumed by the private context adapter."""

    relative_path: str
    reason_code: str

    def __post_init__(self) -> None:
        try:
            context_assembly._require_relative_path(
                self.relative_path,
                "context inspection path",
            )
        except context_assembly.ContextAssemblyError as exc:
            raise context_assembly.ContextAssemblyError(
                "context inspection row is invalid"
            ) from exc
        if (
            type(self.reason_code) is not str
            or not self.reason_code
            or len(self.reason_code) > 128
        ):
            raise context_assembly.ContextAssemblyError(
                "context inspection reason is invalid"
            )


@dataclass(frozen=True)
class _TargetResolution:
    target_path: Optional[str] = None
    ambiguous_directories: tuple[str, ...] = ()


@dataclass(frozen=True)
class _CurationCandidate:
    row: dict[str, object]
    classification: str
    classification_evidence: tuple[str, ...]
    role: str
    move_eligible: bool
    ambiguous_roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ContextInspectionEvidence:
    """Frozen inspection facts; this adapter never scans or classifies paths."""

    observations: tuple[canonical_curation.SourceObservation, ...]
    internal_uncertain: tuple[_ContextInspectionRow, ...]
    internal_excluded: tuple[_ContextInspectionRow, ...]
    external_uncertain: tuple[_ContextInspectionRow, ...]
    external_excluded: tuple[_ContextInspectionRow, ...]
    internal_truncated: bool = False
    external_truncated: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.observations) is not tuple
            or any(
                not isinstance(item, canonical_curation.SourceObservation)
                for item in self.observations
            )
        ):
            raise context_assembly.ContextAssemblyError(
                "context inspection observations are invalid"
            )
        for rows in (
            self.internal_uncertain,
            self.internal_excluded,
            self.external_uncertain,
            self.external_excluded,
        ):
            if type(rows) is not tuple or any(
                not isinstance(item, _ContextInspectionRow) for item in rows
            ):
                raise context_assembly.ContextAssemblyError(
                    "context inspection rows are invalid"
                )
        if (
            type(self.internal_truncated) is not bool
            or type(self.external_truncated) is not bool
        ):
            raise context_assembly.ContextAssemblyError(
                "context inspection truncation is invalid"
            )


@dataclass(frozen=True)
class _ContextAssemblyInput:
    """Exact, deterministic arguments for ``build_context_assembly``."""

    local_observations: tuple[context_assembly.ContextLocalObservation, ...]
    local_gaps: tuple[context_assembly.ContextGap, ...]
    excluded_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.local_observations) is not tuple
            or any(
                not isinstance(item, context_assembly.ContextLocalObservation)
                for item in self.local_observations
            )
            or type(self.local_gaps) is not tuple
            or any(
                not isinstance(item, context_assembly.ContextGap)
                for item in self.local_gaps
            )
            or type(self.excluded_paths) is not tuple
        ):
            raise context_assembly.ContextAssemblyError(
                "context assembly input is invalid"
            )
        for path in self.excluded_paths:
            context_assembly._require_relative_path(path, "context excluded path")


@dataclass(frozen=True)
class _CapturedContextCuration:
    """Immutable read-only capture shared by inspect and Context activation."""

    assembly: context_assembly.ContextAssembly
    complete_context: context_assembly.CompleteContextAssembly | None
    context_plan: canonical_curation.ContextBoundCurationPlan | None
    workstream_id: str
    project_home: str
    root_identity: tuple[int, int, int, int]
    project_identity: tuple[int, int, int, int]
    registry_sha256: str
    workstream_ref: str
    inspection_evidence: object
    observed_effects: tuple[tuple[canonical_curation.PlanEffect, dict[str, object]], ...]
    observed_unchanged: tuple[
        tuple[canonical_curation.SourceObservation, dict[str, object]], ...
    ]
    scans: tuple[tuple[str, int, int, int, dict[str, object]], ...]
    context_input: _ContextAssemblyInput
    observations: tuple[canonical_curation.SourceObservation, ...]
    effects: tuple[canonical_curation.PlanEffect, ...]
    plan: canonical_curation.CurationPlan | None


class WorkstreamCurationError(RuntimeError):
    """The read-only planning workflow stopped instead of guessing."""

    _NEXT_SAFE_ACTION = {
        "COVERAGE_INCOMPLETE": "narrow-scope",
        "INVALID_REQUEST": "correct-request",
        "MUTATION_IN_PROGRESS": "inspect-transaction",
        "POLICY_CHANGED": "inspect-policy",
        "RECOVERY_REQUIRED": "inspect-recovery",
        "REVIEW_NOT_READY": "inspect-workstream",
        "STALE": "inspect-workstream",
        "WORKSTREAM_FROZEN": "reopen-workstream",
        "WORKSTREAM_HOME_UNSAFE": "inspect-workstream",
        "WORKSTREAM_NOT_FOUND": "choose-workstream",
        "WORKSTREAM_AMBIGUOUS": "inspect-policy",
    }

    def __init__(self, message: str, *, reason_code: str) -> None:
        if reason_code not in self._NEXT_SAFE_ACTION:
            raise ValueError("Workstream curation reason code is invalid")
        super().__init__(message)
        self.reason_code = reason_code
        self.next_safe_action = self._NEXT_SAFE_ACTION[reason_code]


class _BoundaryError(RuntimeError):
    pass


def _require_readable_workstream(root: Path, workstream_id: str) -> None:
    try:
        status = curation_transaction.workstream_mutation_status(
            root,
            workstream_id,
        )
    except Exception as exc:
        raise WorkstreamCurationError(
            "Curation transaction state is unavailable",
            reason_code="RECOVERY_REQUIRED",
        ) from exc
    if status is not None:
        raise WorkstreamCurationError(
            "Workstream has an unfinished Curation transaction",
            reason_code=status,
        )


def _blocked_from_inspection(exc: Exception) -> WorkstreamCurationError:
    reason_code = getattr(exc, "reason_code", "WORKSTREAM_HOME_UNSAFE")
    if reason_code not in WorkstreamCurationError._NEXT_SAFE_ACTION:
        reason_code = "WORKSTREAM_HOME_UNSAFE"
    return WorkstreamCurationError(str(exc), reason_code=reason_code)


def _validated_bounds(
    max_items: object,
    max_depth: object,
    max_hint_bytes: object,
) -> tuple[int, int, int]:
    if (
        type(max_items) is not int
        or not 1 <= max_items <= 4096
        or type(max_depth) is not int
        or not 0 <= max_depth <= 16
        or type(max_hint_bytes) is not int
        or not 0 <= max_hint_bytes <= 1024 * 1024
    ):
        raise WorkstreamCurationError(
            "inspection bounds are invalid",
            reason_code="INVALID_REQUEST",
        )
    return max_items, max_depth, max_hint_bytes


def _root_identity(root: Path) -> tuple[int, int, int, int]:
    try:
        descriptor = safety.open_verified_directory(
            root,
            require_owner_only=True,
            error_type=_BoundaryError,
        )
    except WorkstreamCurationError:
        raise
    except Exception as exc:
        raise WorkstreamCurationError(
            "raw root is unsafe",
            reason_code="WORKSTREAM_HOME_UNSAFE",
        ) from exc
    try:
        info = os.fstat(descriptor)
        safety.require_same_directory_identity(
            root,
            descriptor,
            "raw root",
            error_type=_BoundaryError,
        )
        return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid)
    finally:
        os.close(descriptor)


def _read_compiled_policy(root: Path) -> tuple[object, str]:
    registry_directory = root / "_registry"
    registry_path = registry_directory / "placement-map.yml"
    try:
        directory_fd = safety.open_verified_directory(
            registry_directory,
            require_owner_only=True,
            error_type=_BoundaryError,
        )
    except Exception as exc:
        if isinstance(exc, WorkstreamCurationError):
            raise
        raise WorkstreamCurationError(
            "placement registry directory is unsafe",
            reason_code="POLICY_CHANGED",
        ) from exc
    try:
        try:
            info, raw = safety.read_regular_file_at(
                directory_fd,
                registry_path.name,
                registry_path,
                label="placement registry",
                expected_mode=None,
                error_type=_BoundaryError,
            )
        except Exception as exc:
            if isinstance(exc, WorkstreamCurationError):
                raise
            raise WorkstreamCurationError(
                "placement registry is unavailable",
                reason_code="POLICY_CHANGED",
            ) from exc
        if (
            info.st_uid != os.getuid()
            or info.st_nlink != 1
            or len(raw) > _MAX_REGISTRY_BYTES
        ):
            raise WorkstreamCurationError(
                "placement registry identity is unsafe",
                reason_code="POLICY_CHANGED",
            )
        safety.require_same_directory_identity(
            registry_directory,
            directory_fd,
            "placement registry",
            error_type=_BoundaryError,
        )
    finally:
        os.close(directory_fd)
    try:
        parsed = policy.parse_strict_yaml(raw)
        effective = (
            raw
            if "curation" in parsed
            else policy.build_additive_curation_postimage(raw, str(root))
        )
        compiled = policy.compile_policy(effective, str(root))
    except (TypeError, ValueError) as exc:
        raise WorkstreamCurationError(
            "placement registry cannot be compiled",
            reason_code="POLICY_CHANGED",
        ) from exc
    return compiled, sha256_bytes(raw)


def read_current_policy_sha256(root: Path) -> str:
    """Return the policy hash stored in canonical Curation Plans."""

    compiled_policy, _source_sha256 = _read_compiled_policy(Path(root))
    return compiled_policy.full_hash


def _relative_to_root(root: Path, value: object, label: str) -> str:
    if type(value) is not str:
        raise WorkstreamCurationError(
            "%s is invalid" % label,
            reason_code="POLICY_CHANGED",
        )
    try:
        relative = Path(value).relative_to(root).as_posix()
    except ValueError as exc:
        raise WorkstreamCurationError(
            "%s is outside the raw root" % label,
            reason_code="POLICY_CHANGED",
        ) from exc
    if not relative or any(part in {"", ".", ".."} for part in relative.split("/")):
        raise WorkstreamCurationError(
            "%s is invalid" % label,
            reason_code="POLICY_CHANGED",
        )
    return relative


def _scan_scope(
    *,
    root: Path,
    compiled_policy: object,
    relative_path: str,
    max_items: int,
    max_depth: int,
    max_hint_bytes: int,
) -> dict[str, object]:
    try:
        return librarian.inspect_scope(
            root=root,
            compiled_policy=compiled_policy,
            relative_path=relative_path,
            max_items=max_items,
            max_depth=max_depth,
            max_hint_bytes=max_hint_bytes,
        )
    except Exception as exc:
        raise WorkstreamCurationError(
            "bounded inspection failed",
            reason_code="WORKSTREAM_HOME_UNSAFE",
        ) from exc


def _route_tokens(resolved: object, compiled_policy: object) -> tuple[str, ...]:
    canonical_id = getattr(resolved, "canonical_id", "")
    values = [canonical_id]
    for workstream in getattr(compiled_policy, "workstreams", ()):
        if getattr(workstream, "id", None) == getattr(resolved, "canonical_id", None):
            values.extend(getattr(workstream, "aliases", ()))
    folded = [value.casefold() for value in values if type(value) is str and value]
    return tuple(dict.fromkeys(folded))


def _external_classification(
    row: Mapping[str, object],
    route_tokens: tuple[str, ...],
) -> Optional[tuple[str, tuple[str, ...]]]:
    relative_path = row.get("relative_path")
    hint = row.get("hint")
    if type(relative_path) is not str:
        return None
    path_folded = relative_path.casefold()
    hint_folded = hint.casefold() if type(hint) is str else ""
    matched = tuple(
        token for token in route_tokens if token in path_folded or token in hint_folded
    )
    if not matched:
        return None
    exact = route_tokens[0] in path_folded or route_tokens[0] in hint_folded
    evidence = tuple(
        sorted(
            {
                "path-token" if any(token in path_folded for token in matched) else "heading-token",
                "allowlisted-inbox",
            }
        )
    )
    return ("EXACT" if exact else "SUPPORTED", evidence)


def _explicit_document_roles(relative_path: str, hint: object) -> tuple[str, ...]:
    folded = unicodedata.normalize(
        "NFC",
        relative_path + " " + (hint if type(hint) is str else ""),
    ).casefold()
    return tuple(
        role
        for role, tokens in _EXPLICIT_DOCUMENT_ROLE_TOKENS.items()
        if any(token in folded for token in tokens)
    )


def _document_role(relative_path: str, hint: object, *, external: bool) -> str:
    if external:
        return "references"
    explicit_roles = _explicit_document_roles(relative_path, hint)
    if explicit_roles:
        return explicit_roles[0]
    name = Path(relative_path).name.casefold()
    if name in {"readme.md", "index.md"}:
        return "overview"
    return "work_results"


def _document_profile(
    *,
    project_home: str,
    relative_path: str,
    hint: object,
    external: bool,
) -> Optional[tuple[str, str, bool, tuple[str, ...]]]:
    path = Path(relative_path)
    if external:
        if path.suffix.casefold() not in _HUMAN_DOCUMENT_SUFFIXES:
            return None
        return (
            _document_role(relative_path, hint, external=True),
            "artifact-family:external-document",
            True,
            (),
        )
    try:
        project_parts = path.relative_to(project_home).parts
    except ValueError:
        return None
    if any(part == "__pycache__" or part.endswith("-out") for part in project_parts[:-1]):
        return None
    if path.suffix.casefold() not in _HUMAN_DOCUMENT_SUFFIXES:
        return None
    if len(project_parts) >= 2 and project_parts[:2] == ("docs", "research"):
        return "references", "artifact-family:reference-library", False, ()
    if project_parts and project_parts[0] == "meetings":
        return "work_results", "artifact-family:meeting-source", False, ()
    family = (
        "artifact-family:canonical-navigation-candidate"
        if len(project_parts) == 1
        else "artifact-family:human-document"
    )
    explicit_roles = _explicit_document_roles(relative_path, hint)
    ambiguous_roles = (
        explicit_roles
        if len(project_parts) == 1 and len(explicit_roles) > 1
        else ()
    )
    return (
        _document_role(relative_path, hint, external=False),
        family,
        len(project_parts) == 1,
        ambiguous_roles,
    )


def _context_group_for_internal_path(project_home: str, relative_path: str) -> str:
    """Map a known internal path to an existing Context Assembly local group."""

    try:
        project_parts = Path(relative_path).relative_to(project_home).parts
    except ValueError as exc:
        raise context_assembly.ContextAssemblyError(
            "internal context path is outside the project home"
        ) from exc
    if len(project_parts) == 1:
        return "PROJECT_ROOT"
    if project_parts[0] == "meetings":
        return "MEETING"
    if len(project_parts) >= 2 and project_parts[:2] == ("docs", "research"):
        return "REFERENCE_LIBRARY"
    return "OTHER_NESTED"


def _dedupe_context_rows(
    rows: tuple[_ContextInspectionRow, ...],
) -> tuple[_ContextInspectionRow, ...]:
    return tuple(
        sorted(
            set(rows),
            key=lambda item: (item.relative_path, item.reason_code),
        )
    )


def _context_inspection_rows(
    result: Mapping[str, object],
    key: str,
) -> tuple[_ContextInspectionRow, ...]:
    """Project only existing scan rows into the frozen Context adapter input."""

    values = result.get(key)
    if type(values) is not list:
        raise context_assembly.ContextAssemblyError(
            "context inspection result is invalid"
        )
    rows = []
    for value in values:
        if type(value) is not dict:
            continue
        relative_path = value.get("relative_path")
        reason_code = value.get("reason_code")
        if type(relative_path) is not str or type(reason_code) is not str:
            continue
        rows.append(_ContextInspectionRow(relative_path, reason_code))
    return _dedupe_context_rows(tuple(rows))


def _compiled_workstream_for_id(compiled_policy: object, workstream_id: str) -> object:
    """Return the exact compiled policy row, never the lossy resolver projection."""

    for candidate in getattr(compiled_policy, "workstreams", ()):
        if getattr(candidate, "id", None) == workstream_id:
            return candidate
    raise WorkstreamCurationError(
        "resolved Workstream is absent from the compiled policy",
        reason_code="POLICY_CHANGED",
    )


def _context_workstream_row(
    *,
    root: Path,
    compiled_policy: object,
    workstream_id: str,
) -> policy.CompiledWorkstream:
    """Bind the exact compiled row to Context's root-relative authority form."""

    compiled = _compiled_workstream_for_id(compiled_policy, workstream_id)
    if not isinstance(compiled, policy.CompiledWorkstream):
        raise WorkstreamCurationError(
            "compiled Workstream row is invalid",
            reason_code="POLICY_CHANGED",
        )
    return replace(
        compiled,
        project_home=_relative_to_root(root, compiled.project_home, "project home"),
    )


def _public_context_value(assembly: context_assembly.ContextAssembly) -> dict[str, object]:
    """Expose the bounded canonical Context and compact status before review."""

    return {
        "assembly": assembly.canonical_value,
        "assembly_sha256": assembly.sha256,
        "coverage_sha256": assembly.coverage_sha256,
        "excluded_count": len(assembly.coverage.excluded_paths),
        "gap_count": len(assembly.gaps),
        "gap_paths": list(assembly.coverage.gap_paths[:8]),
        "outcome": assembly.outcome,
        "source_count": len(assembly.sources),
    }


def _context_input_from_inspection_evidence(
    *,
    project_home: str,
    evidence: _ContextInspectionEvidence,
    source_groups: Mapping[str, str],
) -> _ContextAssemblyInput:
    """Translate frozen scan evidence without rescanning or reclassifying it.

    The caller owns eligibility and ownership decisions.  This private seam only
    binds exact observations to the approved Context Assembly groups and makes
    scan uncertainty visible to the assembly builder.
    """

    context_assembly._require_relative_path(project_home, "project home")
    if not isinstance(evidence, _ContextInspectionEvidence) or not isinstance(
        source_groups, Mapping
    ):
        raise context_assembly.ContextAssemblyError(
            "context inspection adapter input is invalid"
        )

    observations_by_id: dict[str, canonical_curation.SourceObservation] = {}
    for observation in evidence.observations:
        previous = observations_by_id.get(observation.observation_id)
        if previous is not None and previous != observation:
            raise context_assembly.ContextAssemblyError(
                "duplicate inspection observation is inconsistent"
            )
        observations_by_id[observation.observation_id] = observation
    observed_ids = frozenset(observations_by_id)
    if (
        any(type(source_id) is not str or type(group) is not str for source_id, group in source_groups.items())
        or frozenset(source_groups) != observed_ids
    ):
        raise context_assembly.ContextAssemblyError(
            "context source groups must cover exactly the observations"
        )

    local_observations = tuple(
        sorted(
            (
                context_assembly.ContextLocalObservation(
                    observation=observation,
                    group=source_groups[observation_id],
                )
                for observation_id, observation in observations_by_id.items()
            ),
            key=lambda item: (
                item.observation.relative_path,
                item.observation.observation_id,
            ),
        )
    )

    gaps: list[context_assembly.ContextGap] = []
    excluded_paths: set[str] = set()
    for row in _dedupe_context_rows(
        (*evidence.internal_uncertain, *evidence.internal_excluded)
    ):
        if row.reason_code in _CONTEXT_UNSAFE_LOCAL_REASONS:
            raise context_assembly.ContextAssemblyError(
                "local inspection contains an unsafe scan result",
                reason_code="CONTEXT_BLOCKED_UNSAFE",
            )
        if row.reason_code not in _CONTEXT_NONBLOCKING_LOCAL_REASONS:
            raise context_assembly.ContextAssemblyError(
                "local inspection reason is not understood"
            )
        profile = _document_profile(
            project_home=project_home,
            relative_path=row.relative_path,
            hint=None,
            external=False,
        )
        if row.reason_code == "SOURCE_CHANGED" and profile is not None:
            gaps.append(
                context_assembly.ContextGap(
                    gap_id="gap-inspection-source-changed:%s"
                    % sha256_bytes(row.relative_path.encode("utf-8")),
                    kind="UNREADABLE",
                    group=_context_group_for_internal_path(
                        project_home,
                        row.relative_path,
                    ),
                    reason_code="SOURCE_CHANGED",
                    relative_path=row.relative_path,
                )
            )
        else:
            excluded_paths.add(row.relative_path)

    # Inbox rows have no established ownership in this adapter.  Their scan
    # uncertainty is visible in coverage but cannot lower this Workstream's
    # completeness until an earlier caller has bound them to an observation.
    excluded_paths.update(
        row.relative_path
        for row in _dedupe_context_rows(
            (*evidence.external_uncertain, *evidence.external_excluded)
        )
    )
    if evidence.internal_truncated:
        gaps.append(
            context_assembly.ContextGap(
                gap_id="gap-inspection-truncated:%s"
                % sha256_bytes(project_home.encode("utf-8")),
                kind="TRUNCATED",
                group="PROJECT_ROOT",
                reason_code="INSPECTION_TRUNCATED",
                relative_path=project_home,
            )
        )
    if evidence.external_truncated:
        gaps.append(
            context_assembly.ContextGap(
                gap_id="gap-inspection-external-truncated:%s"
                % sha256_bytes(project_home.encode("utf-8")),
                kind="TRUNCATED",
                group="ALLOWLISTED_EXTERNAL_LOCAL",
                reason_code="INSPECTION_TRUNCATED",
            )
        )
    return _ContextAssemblyInput(
        local_observations=local_observations,
        local_gaps=tuple(
            sorted(
                set(gaps),
                key=lambda item: (
                    item.relative_path or "",
                    item.reason_code,
                    item.gap_id,
                ),
            )
        ),
        excluded_paths=tuple(sorted(excluded_paths)),
    )


def _resolve_target_path(
    project_home: str,
    role: str,
    source_path: str,
    available_directories: frozenset[str],
) -> _TargetResolution:
    if role == "overview":
        return _TargetResolution()
    patterns = _ROLE_DIRECTORY_PATTERNS[role]
    matching_directories: list[str] = []
    for directory in available_directories:
        try:
            relative_parts = tuple(
                part.casefold()
                for part in Path(directory).relative_to(project_home).parts
            )
        except ValueError:
            continue
        if _ignored_role_directory(relative_parts):
            continue
        if _matches_role_directory_pattern(relative_parts, patterns):
            matching_directories.append(directory)
    matching_directories.sort()
    if not matching_directories:
        return _TargetResolution()
    if len(matching_directories) > 1:
        return _TargetResolution(
            ambiguous_directories=tuple(matching_directories),
        )
    return _TargetResolution(
        target_path="%s/%s"
        % (matching_directories[0], Path(source_path).name),
    )


def _ignored_role_directory(relative_parts: tuple[str, ...]) -> bool:
    return any(
        part.startswith(".") or part == "__pycache__" or part.endswith("-out")
        for part in relative_parts
    )


def _matches_role_directory_pattern(
    relative_parts: tuple[str, ...],
    patterns: tuple[tuple[str, ...], ...],
) -> bool:
    return relative_parts in patterns or (
        relative_parts and (relative_parts[-1],) in patterns
    )


def _proposal_id(source_path: str, target_path: str) -> str:
    digest = sha256_bytes(
        canonical_json_bytes({"source": source_path, "target": target_path})
    )
    return "p-" + digest[:32]


def _observe_effect(
    *,
    root: Path,
    compiled_policy: object,
    source_path: str,
    target_path: str,
) -> dict[str, object]:
    destination_kind, destination_id = librarian_snapshot.resolve_destination_owner(
        root,
        compiled_policy,
        target_path,
    )
    return librarian_snapshot.observe_proposal(
        root,
        compiled_policy,
        {
            "proposal_id": _proposal_id(source_path, target_path),
            "source_relative_path": source_path,
            "target_relative_path": target_path,
        },
        {
            "max_entries": 1,
            "max_depth": 0,
            "max_total_bytes": _MAX_SOURCE_BYTES,
        },
        {
            "destination_kind": destination_kind,
            "destination_id": destination_id,
            "reason": "Stage A common-spine path alignment",
        },
    )


def _observe_source(
    *,
    root: Path,
    compiled_policy: object,
    source_path: str,
) -> dict[str, object]:
    return librarian_snapshot.observe_regular_file(
        root,
        compiled_policy,
        source_path,
        max_total_bytes=_MAX_SOURCE_BYTES,
    )


def _observe_unchanged_candidate(
    *,
    root: Path,
    compiled_policy: object,
    workstream_id: str,
    project_home: str,
    row: Mapping[str, object],
    role: str,
    classification: str,
    classification_evidence: tuple[str, ...],
) -> tuple[canonical_curation.SourceObservation, dict[str, object]]:
    source_path = row["relative_path"]
    source_snapshot = _observe_source(
        root=root,
        compiled_policy=compiled_policy,
        source_path=source_path,
    )
    observation = _observation_from_snapshot(
        source_snapshot=source_snapshot,
        workstream_id=workstream_id,
        project_home=project_home,
        role=role,
        classification=classification,
        evidence=classification_evidence,
        summary=row.get("hint") or Path(source_path).name,
    )
    return observation, source_snapshot


def _observation_from_snapshot(
    *,
    source_snapshot: Mapping[str, object],
    workstream_id: str,
    project_home: str,
    role: str,
    classification: str,
    evidence: tuple[str, ...],
    summary: str,
) -> canonical_curation.SourceObservation:
    snapshot_hash = source_snapshot.get("snapshot_sha256")
    relative_path = source_snapshot.get("relative_path")
    if type(snapshot_hash) is not str or type(relative_path) is not str:
        raise WorkstreamCurationError(
            "source observation is incomplete",
            reason_code="STALE",
        )
    is_internal = relative_path.startswith(project_home + "/")
    return canonical_curation.SourceObservation(
        observation_id="obs-" + snapshot_hash[:24],
        relative_path=relative_path,
        owner_kind="workstream" if is_internal else "unassigned",
        owner_id=workstream_id if is_internal else "unassigned",
        lifecycle="active" if is_internal else "unassigned",
        document_role=role,
        classification=classification,
        classification_evidence=evidence,
        content_summary=summary,
        device=source_snapshot["device"],
        inode=source_snapshot["inode"],
        owner=source_snapshot["owner"],
        mode=source_snapshot["mode"],
        link_count=source_snapshot["link_count"],
        size=source_snapshot["size"],
        modified_time_ns=source_snapshot["modified_time_ns"],
        content_sha256=source_snapshot["content_sha256"],
        snapshot_sha256=snapshot_hash,
    )


def _effect_for(
    observation: canonical_curation.SourceObservation,
    target_path: str,
) -> canonical_curation.PlanEffect:
    action = (
        "rename"
        if Path(observation.relative_path).parent == Path(target_path).parent
        else "move"
    )
    digest = sha256_bytes(
        canonical_json_bytes(
            {
                "action": action,
                "observation_id": observation.observation_id,
                "target": target_path,
            }
        )
    )
    return canonical_curation.PlanEffect(
        effect_id="effect-" + digest[:24],
        action=action,
        input_observation_id=observation.observation_id,
        source_path=observation.relative_path,
        output_path=target_path,
        expected_output_sha256=observation.content_sha256,
        risk_codes=("PATH_ONLY_CHANGE",),
    )


def _finding(
    relative_path: str,
    finding_kind: str,
    evidence: tuple[str, ...],
) -> canonical_curation.CurationFinding:
    digest = sha256_bytes(
        canonical_json_bytes(
            {
                "evidence": list(evidence),
                "kind": finding_kind,
                "path": relative_path,
            }
        )
    )
    return canonical_curation.CurationFinding(
        finding_id="finding-" + digest[:24],
        finding_kind=finding_kind,
        relative_path=relative_path,
        evidence=evidence,
    )


def _file_rows(result: Mapping[str, object], key: str) -> list[dict[str, object]]:
    values = result.get(key)
    if type(values) is not list:
        raise WorkstreamCurationError(
            "inspection result is invalid",
            reason_code="REVIEW_NOT_READY",
        )
    return [
        value
        for value in values
        if type(value) is dict and value.get("entry_type") == "file"
    ]


def _directory_paths(result: Mapping[str, object], key: str) -> frozenset[str]:
    values = result.get(key)
    if type(values) is not list:
        raise WorkstreamCurationError(
            "inspection result is invalid",
            reason_code="REVIEW_NOT_READY",
        )
    return frozenset(
        value["relative_path"]
        for value in values
        if type(value) is dict
        and value.get("entry_type") == "directory"
        and type(value.get("relative_path")) is str
    )


def _spine(
    internal_rows: list[tuple[dict[str, object], str]],
    effects: tuple[canonical_curation.PlanEffect, ...],
    observations: tuple[canonical_curation.SourceObservation, ...],
) -> tuple[canonical_curation.SpineEntry, ...]:
    current_by_role: dict[str, dict[str, object]] = {}
    for row, role in sorted(
        internal_rows,
        key=lambda value: value[0]["relative_path"],
    ):
        current_by_role.setdefault(role, row)
    role_by_observation_id = {
        observation.observation_id: observation.document_role
        for observation in observations
    }
    proposed_by_role = {
        role_by_observation_id[effect.input_observation_id]: effect.output_path
        for effect in effects
    }
    entries = []
    for role in canonical_curation.COMMON_SPINE_ROLES:
        current = current_by_role.get(role)
        proposed_path = proposed_by_role.get(role)
        current_path = None if current is None else current["relative_path"]
        current_heading = None if current is None else current.get("hint")
        if proposed_path is not None:
            status = "PROPOSED"
        elif current_path is not None:
            proposed_path = current_path
            status = "PRESENT"
        else:
            status = "MISSING"
        entries.append(
            canonical_curation.SpineEntry(
                role=role,
                current_path=current_path,
                current_heading=current_heading,
                proposed_path=proposed_path,
                proposed_heading=current_heading,
                status=status,
            )
        )
    return tuple(entries)


def _revalidate(
    *,
    root: Path,
    root_identity: tuple[int, int, int, int],
    registry_sha256: str,
    workstream_ref: str,
    evidence: object,
    observations: list[tuple[canonical_curation.PlanEffect, dict[str, object]]],
    unchanged_observations: list[
        tuple[canonical_curation.SourceObservation, dict[str, object]]
    ],
    scans: list[tuple[str, int, int, int, dict[str, object]]],
) -> object:
    current_policy, current_registry_sha256 = _read_compiled_policy(root)
    if current_registry_sha256 != registry_sha256 or _root_identity(root) != root_identity:
        raise WorkstreamCurationError(
            "root or policy changed during inspection",
            reason_code="STALE",
        )
    try:
        workstream_inspection.revalidate_inspection_evidence(
            current_policy,
            root,
            workstream_ref,
            evidence,
        )
    except Exception as exc:
        raise WorkstreamCurationError(
            "Workstream changed during inspection",
            reason_code="STALE",
        ) from exc
    _require_readable_workstream(
        root,
        getattr(evidence, "canonical_id"),
    )
    for relative_path, max_items, max_depth, max_hint_bytes, expected in scans:
        actual = _scan_scope(
            root=root,
            compiled_policy=current_policy,
            relative_path=relative_path,
            max_items=max_items,
            max_depth=max_depth,
            max_hint_bytes=max_hint_bytes,
        )
        if actual != expected:
            raise WorkstreamCurationError(
                "inspection evidence changed during review rendering",
                reason_code="STALE",
            )
    for effect, expected in observations:
        try:
            actual = _observe_effect(
                root=root,
                compiled_policy=current_policy,
                source_path=effect.source_path,
                target_path=effect.output_path,
            )
        except Exception as exc:
            raise WorkstreamCurationError(
                "source or target changed during inspection",
                reason_code="STALE",
            ) from exc
        if actual != expected:
            raise WorkstreamCurationError(
                "source or target changed during inspection",
                reason_code="STALE",
            )
    for observation, expected in unchanged_observations:
        try:
            actual = _observe_source(
                root=root,
                compiled_policy=current_policy,
                source_path=observation.relative_path,
            )
        except Exception as exc:
            raise WorkstreamCurationError(
                "unchanged source changed during inspection",
                reason_code="STALE",
            ) from exc
        if actual != expected:
            raise WorkstreamCurationError(
                "unchanged source changed during inspection",
                reason_code="STALE",
            )
    return current_policy


def _revalidate_context_assembly(
    *,
    root: Path,
    compiled_policy: object,
    workstream_id: str,
    root_identity: tuple[int, int, int, int],
    project_identity: tuple[int, int, int, int],
    context_input: _ContextAssemblyInput,
    expected: context_assembly.ContextAssembly,
) -> None:
    """Rebuild the bounded read-only context and require exact semantic identity."""

    try:
        current = context_assembly.build_context_assembly(
            root=root,
            compiled_workstream=_context_workstream_row(
                root=root,
                compiled_policy=compiled_policy,
                workstream_id=workstream_id,
            ),
            policy_sha256=getattr(compiled_policy, "full_hash"),
            root_identity=root_identity,
            project_identity=project_identity,
            local_observations=context_input.local_observations,
            local_gaps=context_input.local_gaps,
            excluded_paths=context_input.excluded_paths,
            bounds=expected.bounds,
        )
    except Exception as exc:
        raise WorkstreamCurationError(
            "Context changed during Review Package sealing",
            reason_code="STALE",
        ) from exc
    if current.canonical_bytes != expected.canonical_bytes:
        raise WorkstreamCurationError(
            "Context changed during Review Package sealing",
            reason_code="STALE",
        )


def _capture_context_curation(
    *,
    root: Path,
    compiled_policy: object,
    registry_sha256: str,
    workstream_ref: str,
    max_items: int,
    max_depth: int,
    max_hint_bytes: int,
) -> _CapturedContextCuration:
    """Capture one current Context-bound Plan without writing an artifact."""

    max_items, max_depth, max_hint_bytes = _validated_bounds(
        max_items,
        max_depth,
        max_hint_bytes,
    )
    if type(workstream_ref) is not str or not workstream_ref:
        raise WorkstreamCurationError(
            "Workstream reference is invalid",
            reason_code="INVALID_REQUEST",
        )
    root = Path(root)
    if not root.is_absolute():
        raise WorkstreamCurationError("root is invalid", reason_code="INVALID_REQUEST")
    captured_root_identity = _root_identity(root)
    try:
        resolved = workstream_inspection.resolve_workstream_for_inspection(
            compiled_policy,
            workstream_ref,
        )
        evidence = workstream_inspection.capture_inspection_evidence(root, resolved)
    except Exception as exc:
        raise _blocked_from_inspection(exc) from exc
    if getattr(resolved, "lifecycle", None) != "active":
        raise WorkstreamCurationError(
            "paused or completed Workstream content is frozen",
            reason_code="WORKSTREAM_FROZEN",
        )
    _require_readable_workstream(root, resolved.canonical_id)
    project_home = "/".join(evidence.project_home_relative)
    internal_result = _scan_scope(
        root=root,
        compiled_policy=compiled_policy,
        relative_path=project_home,
        max_items=max_items,
        max_depth=max_depth,
        max_hint_bytes=max_hint_bytes,
    )
    remaining_items = max_items - int(internal_result.get("returned", 0))
    inbox = _relative_to_root(
        root,
        getattr(compiled_policy.registry_anchors, "inbox", None),
        "inbox anchor",
    )
    inbox_exists = (root / inbox).exists()
    if inbox_exists:
        if remaining_items < 1:
            external_result = {
                "organized": [],
                "candidates": [],
                "excluded": [],
                "uncertain": [],
                "returned": 0,
                "truncated": True,
            }
        else:
            external_result = _scan_scope(
                root=root,
                compiled_policy=compiled_policy,
                relative_path=inbox,
                max_items=remaining_items,
                max_depth=max_depth,
                max_hint_bytes=max_hint_bytes,
            )
    else:
        external_result = {
            "organized": [],
            "candidates": [],
            "excluded": [],
            "uncertain": [],
            "returned": 0,
            "truncated": False,
        }
    scans = [
        (project_home, max_items, max_depth, max_hint_bytes, internal_result),
    ]
    if inbox_exists and remaining_items >= 1:
        scans.append(
            (inbox, remaining_items, max_depth, max_hint_bytes, external_result)
        )
    internal_rows = _file_rows(internal_result, "organized")
    available_directories = _directory_paths(internal_result, "organized")
    external_rows = _file_rows(external_result, "candidates")
    route_tokens = _route_tokens(resolved, compiled_policy)
    observations: list[canonical_curation.SourceObservation] = []
    effects: list[canonical_curation.PlanEffect] = []
    observed_effects: list[tuple[canonical_curation.PlanEffect, dict[str, object]]] = []
    observed_unchanged: list[
        tuple[canonical_curation.SourceObservation, dict[str, object]]
    ] = []
    findings: list[canonical_curation.CurationFinding] = []
    unchanged_paths: list[str] = []
    out_of_scope_paths: list[str] = []

    candidates: list[_CurationCandidate] = []
    spine_rows: list[tuple[dict[str, object], str]] = []
    for row in internal_rows:
        profile = _document_profile(
            project_home=project_home,
            relative_path=row["relative_path"],
            hint=row.get("hint"),
            external=False,
        )
        if profile is None:
            out_of_scope_paths.append(row["relative_path"])
            continue
        role, family_evidence, move_eligible, ambiguous_roles = profile
        spine_rows.append((row, role))
        candidates.append(
            _CurationCandidate(
                row=row,
                classification="EXACT",
                classification_evidence=("active-project-home", family_evidence),
                role=role,
                move_eligible=move_eligible,
                ambiguous_roles=ambiguous_roles,
            )
        )
    for row in external_rows:
        classification = _external_classification(row, route_tokens)
        if classification is None:
            out_of_scope_paths.append(row["relative_path"])
            continue
        profile = _document_profile(
            project_home=project_home,
            relative_path=row["relative_path"],
            hint=row.get("hint"),
            external=True,
        )
        if profile is None:
            out_of_scope_paths.append(row["relative_path"])
            continue
        role, family_evidence, move_eligible, ambiguous_roles = profile
        candidates.append(
            _CurationCandidate(
                row=row,
                classification=classification[0],
                classification_evidence=(*classification[1], family_evidence),
                role=role,
                move_eligible=move_eligible,
                ambiguous_roles=ambiguous_roles,
            )
        )

    for candidate in candidates:
        row = candidate.row
        source_path = row["relative_path"]
        target_resolution = (
            _resolve_target_path(
                project_home,
                candidate.role,
                source_path,
                available_directories,
            )
            if candidate.move_eligible and not candidate.ambiguous_roles
            else _TargetResolution()
        )
        target_path = target_resolution.target_path
        if target_path is None or target_path.casefold() == source_path.casefold():
            try:
                observation, source_snapshot = _observe_unchanged_candidate(
                    root=root,
                    compiled_policy=compiled_policy,
                    workstream_id=resolved.canonical_id,
                    project_home=project_home,
                    row=row,
                    role=candidate.role,
                    classification=candidate.classification,
                    classification_evidence=candidate.classification_evidence,
                )
            except Exception as exc:
                raise WorkstreamCurationError(
                    "unchanged source cannot be observed exactly",
                    reason_code="REVIEW_NOT_READY",
                ) from exc
            observations.append(observation)
            observed_unchanged.append((observation, source_snapshot))
            unchanged_paths.append(source_path)
            if candidate.ambiguous_roles:
                findings.append(
                    _finding(
                        source_path,
                        "ROLE_AMBIGUOUS",
                        tuple(
                            "explicit-role:%s" % item
                            for item in candidate.ambiguous_roles
                        ),
                    )
                )
            elif target_resolution.ambiguous_directories:
                findings.append(
                    _finding(
                        source_path,
                        "TARGET_AMBIGUOUS",
                        (
                            "document-role:%s" % candidate.role,
                            *(
                                "candidate:%s" % directory
                                for directory in target_resolution.ambiguous_directories
                            ),
                        ),
                    )
                )
            continue
        try:
            observed = _observe_effect(
                root=root,
                compiled_policy=compiled_policy,
                source_path=source_path,
                target_path=target_path,
            )
        except Exception as exc:
            reason_code = getattr(exc, "reason_code", "EFFECT_NOT_IMPLEMENTED")
            try:
                observation, source_snapshot = _observe_unchanged_candidate(
                    root=root,
                    compiled_policy=compiled_policy,
                    workstream_id=resolved.canonical_id,
                    project_home=project_home,
                    row=row,
                    role=candidate.role,
                    classification=candidate.classification,
                    classification_evidence=candidate.classification_evidence,
                )
            except Exception as source_error:
                raise WorkstreamCurationError(
                    "blocked source cannot be observed exactly",
                    reason_code="REVIEW_NOT_READY",
                ) from source_error
            observations.append(observation)
            observed_unchanged.append((observation, source_snapshot))
            unchanged_paths.append(source_path)
            findings.append(
                _finding(
                    source_path,
                    "PATH_EFFECT_BLOCKED",
                    (reason_code,),
                )
            )
            continue
        summary = row.get("hint") or Path(source_path).name
        observation = _observation_from_snapshot(
            source_snapshot=observed["source_snapshot"],
            workstream_id=resolved.canonical_id,
            project_home=project_home,
            role=candidate.role,
            classification=candidate.classification,
            evidence=candidate.classification_evidence,
            summary=summary,
        )
        effect = _effect_for(observation, target_path)
        observations.append(observation)
        effects.append(effect)
        observed_effects.append((effect, observed))

    for result in (internal_result, external_result):
        for key in ("excluded", "uncertain"):
            values = result.get(key, [])
            if type(values) is list:
                out_of_scope_paths.extend(
                    value["relative_path"]
                    for value in values
                    if type(value) is dict and type(value.get("relative_path")) is str
                )
    observations_tuple = tuple(sorted(observations, key=lambda value: value.observation_id))
    effects_tuple = tuple(sorted(effects, key=lambda value: value.effect_id))
    root_info = captured_root_identity
    project_info = evidence.project_identity
    coverage = tuple(
        sorted(
            {
                "bounds": {
                    "max_depth": max_depth,
                    "max_hint_bytes": max_hint_bytes,
                    "max_items": max_items,
                    "max_source_bytes": _MAX_SOURCE_BYTES,
                },
                "excluded_count": len(set(out_of_scope_paths)),
                "external_candidates": len(external_rows),
                "inspected_files": len(internal_rows) + len(external_rows),
                "internal_files": len(internal_rows),
                "truncated": False,
                "unreadable_count": sum(
                    len(result.get("uncertain", []))
                    for result in (internal_result, external_result)
                ),
            }.items()
        )
    )
    # The Context builder receives the already-observed source set and the
    # scan results captured above.  It never starts a second inspection pass.
    context_evidence = _ContextInspectionEvidence(
        observations=observations_tuple,
        internal_uncertain=_context_inspection_rows(internal_result, "uncertain"),
        internal_excluded=_context_inspection_rows(internal_result, "excluded"),
        external_uncertain=_context_inspection_rows(external_result, "uncertain"),
        external_excluded=_context_inspection_rows(external_result, "excluded"),
        internal_truncated=internal_result.get("truncated") is True,
        external_truncated=external_result.get("truncated") is True,
    )
    source_groups = {
        observation.observation_id: (
            _context_group_for_internal_path(project_home, observation.relative_path)
            if observation.relative_path.startswith(project_home + "/")
            else "ALLOWLISTED_EXTERNAL_LOCAL"
        )
        for observation in observations_tuple
    }
    try:
        context_input = _context_input_from_inspection_evidence(
            project_home=project_home,
            evidence=context_evidence,
            source_groups=source_groups,
        )
        assembly = context_assembly.build_context_assembly(
            root=root,
            compiled_workstream=_context_workstream_row(
                root=root,
                compiled_policy=compiled_policy,
                workstream_id=resolved.canonical_id,
            ),
            policy_sha256=compiled_policy.full_hash,
            root_identity=root_info,
            project_identity=(
                project_info.device,
                project_info.inode,
                project_info.mode,
                project_info.uid,
            ),
            local_observations=context_input.local_observations,
            local_gaps=context_input.local_gaps,
            excluded_paths=context_input.excluded_paths,
            bounds=context_assembly.ContextAssemblyBounds(),
        )
    except context_assembly.ContextAssemblyError as exc:
        if exc.reason_code == "CONTEXT_STALE":
            raise WorkstreamCurationError(
                "Context changed during inspection",
                reason_code="STALE",
            ) from exc
        if exc.reason_code == "CONTEXT_BLOCKED_UNSAFE":
            raise WorkstreamCurationError(
                "Context boundary is unsafe",
                reason_code="WORKSTREAM_HOME_UNSAFE",
            ) from exc
        raise WorkstreamCurationError(
            "Context cannot be assembled safely",
            reason_code="REVIEW_NOT_READY",
        ) from exc

    if assembly.outcome != context_assembly.COMPLETE:
        return _CapturedContextCuration(
            assembly=assembly,
            complete_context=None,
            context_plan=None,
            workstream_id=resolved.canonical_id,
            project_home=project_home,
            root_identity=root_info,
            project_identity=(
                project_info.device,
                project_info.inode,
                project_info.mode,
                project_info.uid,
            ),
            registry_sha256=registry_sha256,
            workstream_ref=workstream_ref,
            inspection_evidence=evidence,
            observed_effects=tuple(observed_effects),
            observed_unchanged=tuple(observed_unchanged),
            scans=tuple(scans),
            context_input=context_input,
            observations=observations_tuple,
            effects=effects_tuple,
            plan=None,
        )

    plan = canonical_curation.CurationPlan(
        primary_workstream_id=resolved.canonical_id,
        captured_lifecycle=resolved.lifecycle,
        project_home=project_home,
        project_identity=(
            project_info.device,
            project_info.inode,
            project_info.mode,
            project_info.uid,
        ),
        root_identity=root_info,
        policy_sha256=compiled_policy.full_hash,
        source_observations=observations_tuple,
        effects=effects_tuple,
        spine=_spine(spine_rows, effects_tuple, observations_tuple),
        findings=tuple(sorted(findings, key=lambda value: value.finding_id)),
        unchanged_paths=tuple(sorted(set(unchanged_paths))),
        out_of_scope_paths=tuple(sorted(set(out_of_scope_paths))),
        coverage=coverage,
    )
    try:
        complete_context = assembly.require_complete(
            expected_workstream=assembly.workstream,
            expected_policy_sha256=compiled_policy.full_hash,
            expected_root_identity=root_info,
            expected_project_identity=(
                project_info.device,
                project_info.inode,
                project_info.mode,
                project_info.uid,
            ),
            expected_assembly_sha256=assembly.sha256,
            expected_coverage_sha256=assembly.coverage_sha256,
        )
        context_bound_plan = canonical_curation.compile_curation_plan(
            plan,
            context_assembly=complete_context,
        )
    except (
        canonical_curation.CanonicalCurationError,
        context_assembly.ContextAssemblyError,
    ) as exc:
        raise WorkstreamCurationError(
            "Context-bound Plan cannot be sealed",
            reason_code="STALE",
        ) from exc
    return _CapturedContextCuration(
        assembly=assembly,
        complete_context=complete_context,
        context_plan=context_bound_plan,
        workstream_id=resolved.canonical_id,
        project_home=project_home,
        root_identity=root_info,
        project_identity=(
            project_info.device,
            project_info.inode,
            project_info.mode,
            project_info.uid,
        ),
        registry_sha256=registry_sha256,
        workstream_ref=workstream_ref,
        inspection_evidence=evidence,
        observed_effects=tuple(observed_effects),
        observed_unchanged=tuple(observed_unchanged),
        scans=tuple(scans),
        context_input=context_input,
        observations=observations_tuple,
        effects=effects_tuple,
        plan=plan,
    )


def _revalidate_captured_context(
    *,
    root: Path,
    captured: _CapturedContextCuration,
) -> None:
    """Recheck one capture before its inspect-only Review seal."""

    current_policy = _revalidate(
        root=root,
        root_identity=captured.root_identity,
        registry_sha256=captured.registry_sha256,
        workstream_ref=captured.workstream_ref,
        evidence=captured.inspection_evidence,
        observations=list(captured.observed_effects),
        unchanged_observations=list(captured.observed_unchanged),
        scans=list(captured.scans),
    )
    _revalidate_context_assembly(
        root=root,
        compiled_policy=current_policy,
        workstream_id=captured.workstream_id,
        root_identity=captured.root_identity,
        project_identity=captured.project_identity,
        context_input=captured.context_input,
        expected=captured.assembly,
    )


def inspect_workstream(
    *,
    root: Path,
    workstream_ref: str,
    review_package_directory: Path,
    max_items: int,
    max_depth: int,
    max_hint_bytes: int,
    actor: str,
) -> dict[str, object]:
    """Inspect through the shared capture seam, then write one sealed V3 Review."""

    max_items, max_depth, max_hint_bytes = _validated_bounds(
        max_items,
        max_depth,
        max_hint_bytes,
    )
    if type(actor) is not str or not actor or len(actor) > 128:
        raise WorkstreamCurationError("actor is invalid", reason_code="INVALID_REQUEST")
    if type(workstream_ref) is not str or not workstream_ref:
        raise WorkstreamCurationError(
            "Workstream reference is invalid",
            reason_code="INVALID_REQUEST",
        )
    root = Path(root)
    package_directory = Path(review_package_directory)
    if not root.is_absolute() or not package_directory.is_absolute():
        raise WorkstreamCurationError(
            "root and review package paths must be absolute",
            reason_code="INVALID_REQUEST",
        )
    if package_directory == root or root in package_directory.parents:
        raise WorkstreamCurationError(
            "review package must stay outside the temporary raw root",
            reason_code="INVALID_REQUEST",
        )
    try:
        review_package.require_empty_review_directory(package_directory)
    except (TypeError, review_package.ReviewPackageError) as exc:
        raise WorkstreamCurationError(
            "review package directory must be a fresh owner-only directory",
            reason_code="INVALID_REQUEST",
        ) from exc
    _root_identity(root)
    compiled_policy, registry_sha256 = _read_compiled_policy(root)
    captured = _capture_context_curation(
        root=root,
        compiled_policy=compiled_policy,
        registry_sha256=registry_sha256,
        workstream_ref=workstream_ref,
        max_items=max_items,
        max_depth=max_depth,
        max_hint_bytes=max_hint_bytes,
    )
    if captured.complete_context is None or captured.context_plan is None:
        _revalidate_captured_context(root=root, captured=captured)
        return {
            "outcome_kind": "completed",
            "result": {
                "canonical_source_read_only": True,
                "context": _public_context_value(captured.assembly),
                "not_modified": ["canonical-corpus", "curation-control"],
                "view": "workstream",
                "workstream": {
                    "id": captured.workstream_id,
                    "lifecycle": "active",
                    "project_home": captured.project_home,
                },
            },
        }
    if captured.plan is None:
        raise AssertionError("complete Context capture has no legacy Plan")
    payload = canonical_curation_review.compile_context_bound_review(
        captured.context_plan,
        context_assembly=captured.complete_context,
        rendered_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        renderer_id="mnemosyne-curation-v3",
    )
    try:
        hashes = canonical_curation_review.write_context_bound_review_package(
            package_directory,
            payload,
            before_final_seal=lambda: _revalidate_captured_context(
                root=root,
                captured=captured,
            ),
        )
    except WorkstreamCurationError:
        try:
            review_package.discard_unsealed_review_package(package_directory, payload)
        except review_package.ReviewPackageError as cleanup_error:
            raise WorkstreamCurationError(
                "stale Review Package cleanup could not be proven",
                reason_code="REVIEW_NOT_READY",
            ) from cleanup_error
        raise
    try:
        _revalidate_captured_context(root=root, captured=captured)
    except WorkstreamCurationError:
        try:
            review_package.discard_unsealed_review_package(package_directory, payload)
        except review_package.ReviewPackageError as cleanup_error:
            raise WorkstreamCurationError(
                "stale Review Package cleanup could not be proven",
                reason_code="REVIEW_NOT_READY",
            ) from cleanup_error
        raise
    return {
        "outcome_kind": "completed",
        "result": {
            "canonical_source_read_only": True,
            "not_modified": ["canonical-corpus", "curation-control"],
            "plan": {
                "effects": [
                    {
                        "action": effect.action,
                        "id": effect.effect_id,
                        "output_sha256": effect.expected_output_sha256,
                        "source": effect.source_path,
                        "source_sha256": next(
                            observation.content_sha256
                            for observation in captured.observations
                            if observation.observation_id == effect.input_observation_id
                        ),
                        "target": effect.output_path,
                    }
                    for effect in captured.effects
                ],
                "findings": [
                    {
                        "evidence": list(finding.evidence),
                        "id": finding.finding_id,
                        "kind": finding.finding_kind,
                        "path": finding.relative_path,
                        "status": finding.status,
                    }
                    for finding in captured.plan.findings
                ],
                "schema": captured.context_plan.schema,
                "sha256": captured.context_plan.sha256,
                "source_observation_sha256": captured.plan.source_observation_sha256,
            },
            "context": _public_context_value(captured.assembly),
            "review_package": {
                "directory": str(package_directory),
                "html_sha256": hashes.html_sha256,
                "markdown_sha256": hashes.markdown_sha256,
                "meta_sha256": hashes.meta_sha256,
                "semantic_sha256": hashes.semantic_sha256,
            },
            "view": "workstream",
            "workstream": {
                "id": captured.workstream_id,
                "lifecycle": "active",
                "project_home": captured.project_home,
            },
        },
    }


__all__ = [
    "WorkstreamCurationError",
    "inspect_workstream",
    "read_current_policy_sha256",
]
