"""Source-preserving, draft-only Workstream entry-document review packages."""

from __future__ import annotations

import html
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from . import (
    canonical_curation,
    canonical_curation_review,
    context_assembly,
    policy,
    review_package,
    safety,
    workstream_curation,
)
from .canonical_json import canonical_json_bytes, sha256_bytes


INPUT_SCHEMA = "mnemosyne-navigation-draft-input-v1"
SEMANTIC_SCHEMA = "mnemosyne-navigation-draft-semantic-v1"
REVIEW_KIND = "mnemosyne-navigation-draft"
CONTEXT_BOUND_INPUT_SCHEMA = "mnemosyne-context-bound-navigation-draft-input-v2"
CONTEXT_BOUND_SEMANTIC_SCHEMA = "mnemosyne-context-bound-navigation-draft-semantic-v2"
CONTEXT_BOUND_REVIEW_KIND = "mnemosyne-context-bound-navigation-draft"
CORPUS_CONSEQUENCE = "DRAFT_ONLY_NO_CORPUS_WRITE"
_SOURCE_CONSEQUENCE_TEMPLATE_KO = (
    "이 초안은 원문 {source_count}개를 모두 그대로 둡니다. "
    "제안 README도 ~/raw에 쓰지 않았으며, 승인이나 적용 요청을 만들지 않습니다."
)
_CANDIDATE_EVIDENCE = "artifact-family:canonical-navigation-candidate"
_SEMANTIC_START = b"<!-- mnemosyne-navigation-semantic:start -->\n"
_SEMANTIC_END = b"<!-- mnemosyne-navigation-semantic:end -->\n"
_RENDERED_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RENDERER_ID = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
_MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
_MAX_MAPPING_BYTES = 1024 * 1024
_CONTEXT_BOUND_SEMANTIC_START = b"<!-- mnemosyne-context-bound-navigation-semantic:start -->\n"
_CONTEXT_BOUND_SEMANTIC_END = b"<!-- mnemosyne-context-bound-navigation-semantic:end -->\n"


class NavigationDraftError(ValueError):
    """A navigation draft is incomplete, stale, or outside its safe boundary."""


def _source_consequence(source_count: int) -> str:
    return _SOURCE_CONSEQUENCE_TEMPLATE_KO.format(source_count=source_count)


def _require_text(value: object, label: str, *, maximum: int) -> str:
    if type(value) is not str or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise NavigationDraftError(f"{label} is invalid")
    if any(ord(character) < 0x20 and character not in "\n\r\t" for character in value):
        raise NavigationDraftError(f"{label} contains control characters")
    return value


def _canonical_absolute_path(value: object, label: str) -> Path:
    try:
        path = Path(value)
    except TypeError as exc:
        raise NavigationDraftError(f"{label} is invalid") from exc
    if not path.is_absolute() or str(path) != os.path.abspath(path):
        raise NavigationDraftError(f"{label} must be an absolute canonical path")
    return path


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
    )


def _require_directory_identity(path: Path, expected: object, label: str) -> None:
    if (
        type(expected) is not list
        or len(expected) != 4
        or any(type(value) is not int for value in expected)
    ):
        raise NavigationDraftError(f"{label} identity is invalid")
    try:
        info = path.lstat()
    except OSError as exc:
        raise NavigationDraftError(f"{label} cannot be inspected") from exc
    if not stat.S_ISDIR(info.st_mode) or _identity(info) != tuple(expected):
        raise NavigationDraftError(f"{label} changed after inspection")


def _read_exact_source(root: Path, observation: Mapping[str, object]) -> bytes:
    relative_path = observation.get("relative_path")
    if type(relative_path) is not str:
        raise NavigationDraftError("source path is invalid")
    try:
        canonical_curation._require_relative_path(relative_path, "source path")
        lexical = safety.require_no_symlink_components(
            relative_path,
            root,
            "navigation source",
            error_type=NavigationDraftError,
        )
        parent_fd = safety.open_verified_directory(
            lexical.parent,
            require_owner_only=False,
            error_type=NavigationDraftError,
        )
    except (OSError, canonical_curation.CanonicalCurationError) as exc:
        raise NavigationDraftError("source path is unsafe") from exc
    descriptor = None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lexical.name, flags, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_DOCUMENT_BYTES
        ):
            raise NavigationDraftError("source is not a bounded regular file")
        raw = safety.read_open_file_bytes(descriptor)
        after = os.fstat(descriptor)
        expected = {
            "device": before.st_dev,
            "inode": before.st_ino,
            "owner": before.st_uid,
            "mode": stat.S_IMODE(before.st_mode),
            "link_count": before.st_nlink,
            "size": before.st_size,
            "modified_time_ns": before.st_mtime_ns,
            "content_sha256": sha256_bytes(raw),
        }
        if (
            len(raw) != before.st_size
            or (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            or any(observation.get(name) != value for name, value in expected.items())
        ):
            raise NavigationDraftError("source changed after inspection")
        safety.require_same_directory_identity(
            lexical.parent,
            parent_fd,
            "navigation source parent",
            error_type=NavigationDraftError,
        )
        return raw
    except OSError as exc:
        raise NavigationDraftError("source cannot be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _parse_input(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or len(raw) > _MAX_MAPPING_BYTES:
        raise NavigationDraftError("source map is invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NavigationDraftError("source map is invalid") from exc
    fields = {
        "mappings",
        "output_path",
        "output_role",
        "parent_plan_sha256",
        "review_notes",
        "schema",
        "spine",
        "workstream_id",
    }
    if type(value) is not dict or set(value) != fields or canonical_json_bytes(value) != raw:
        raise NavigationDraftError("source map contract is invalid")
    if value["schema"] != INPUT_SCHEMA:
        raise NavigationDraftError("source map schema is invalid")
    return value


def _headings(content: str) -> set[str]:
    return {
        match.group(1).strip().rstrip("#").rstrip()
        for match in re.finditer(r"^#{1,6}[ \t]+(.+?)\s*$", content, re.MULTILINE)
    }


@dataclass(frozen=True)
class _ContextSourceObservation:
    """Private attribute adapter accepted by the no-follow Context reader."""

    observation_id: str
    relative_path: str
    device: int
    inode: int
    owner: int
    mode: int
    link_count: int
    size: int
    modified_time_ns: int
    content_sha256: str
    snapshot_sha256: str


def _context_observation(source: context_assembly.ContextSource) -> _ContextSourceObservation:
    if (
        source.mode != "CURRENT_LOCAL"
        or source.observation_id is None
        or source.relative_path is None
        or source.identity is None
        or source.content_sha256 is None
        or source.snapshot_sha256 is None
    ):
        raise NavigationDraftError("current local Context source is invalid")
    return _ContextSourceObservation(
        observation_id=source.observation_id,
        relative_path=source.relative_path,
        device=source.identity[0],
        inode=source.identity[1],
        owner=source.identity[2],
        mode=source.identity[3],
        link_count=source.identity[4],
        size=source.identity[5],
        modified_time_ns=source.identity[6],
        content_sha256=source.content_sha256,
        snapshot_sha256=source.snapshot_sha256,
    )


def _reread_context_source(
    root: Path,
    source: context_assembly.ContextSource,
    bounds: context_assembly.ContextAssemblyBounds,
) -> context_assembly.ContextSource:
    """Treat the parent Context as a claim and reopen the actual local bytes."""

    try:
        reread = context_assembly.read_current_local_source(
            root,
            _context_observation(source),
            group=source.group,
            bounds=bounds,
        )
    except context_assembly.ContextAssemblyError as exc:
        raise NavigationDraftError("current local Context source is stale") from exc
    if reread.canonical_value != source.canonical_value:
        raise NavigationDraftError("current local Context projection changed")
    return reread


def _parse_context_bound_input(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or len(raw) > _MAX_MAPPING_BYTES:
        raise NavigationDraftError("context-bound source map is invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NavigationDraftError("context-bound source map is invalid") from exc
    fields = {
        "context_assembly_sha256",
        "context_coverage_sha256",
        "mappings",
        "output_path",
        "output_role",
        "parent_plan_sha256",
        "review_notes",
        "schema",
        "spine",
        "workstream_id",
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or canonical_json_bytes(value) != raw
        or value.get("schema") != CONTEXT_BOUND_INPUT_SCHEMA
    ):
        raise NavigationDraftError("context-bound source map contract is invalid")
    for name in ("context_assembly_sha256", "context_coverage_sha256", "parent_plan_sha256"):
        if type(value[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", value[name]):
            raise NavigationDraftError("context-bound source map hash is invalid")
    return value


def _context_bound_parent(
    directory: Path,
) -> tuple[canonical_curation.ContextBoundCurationPlan, context_assembly.ContextAssembly, review_package.ReviewPackageHashes]:
    """Accept only the separate V3 reader; V2 review bytes are never upgraded."""

    try:
        hashes, plan_value, assembly = canonical_curation_review.validate_context_bound_review_directory(directory)
        plan = canonical_curation.decode_context_bound_plan(plan_value)
    except (ValueError, canonical_curation.CanonicalCurationError, canonical_curation_review.CurationReviewError) as exc:
        raise NavigationDraftError("parent must be a sealed context-bound Review V3") from exc
    if (
        plan.context_binding.outcome != context_assembly.COMPLETE
        or plan.context_binding.assembly_sha256 != assembly.sha256
        or plan.context_binding.coverage_sha256 != assembly.coverage_sha256
    ):
        raise NavigationDraftError("parent Context binding is stale")
    return plan, assembly, hashes


def _review_hashes_value(
    hashes: review_package.ReviewPackageHashes,
) -> dict[str, str]:
    return {
        "html_sha256": hashes.html_sha256,
        "markdown_sha256": hashes.markdown_sha256,
        "meta_sha256": hashes.meta_sha256,
        "semantic_sha256": hashes.semantic_sha256,
    }


def _require_parent_review_hashes(value: object) -> dict[str, str]:
    fields = {
        "html_sha256",
        "markdown_sha256",
        "meta_sha256",
        "semantic_sha256",
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or any(
            type(value[name]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", value[name]) is None
            for name in fields
        )
    ):
        raise NavigationDraftError("parent Review hashes are invalid")
    return value


def _context_counts(assembly: context_assembly.ContextAssembly, root_count: int) -> dict[str, int]:
    return {
        "root_navigation": root_count,
        "full_current_local": sum(source.mode == "CURRENT_LOCAL" for source in assembly.sources),
        "historical_hint": sum(source.mode == "HISTORICAL_HINT" for source in assembly.sources),
        "unverified_external": sum(source.mode == "UNVERIFIED_EXTERNAL" for source in assembly.sources),
    }


def _meta_hashes_valid(meta: Mapping[str, object], fields: set[str]) -> bool:
    return all(
        type(meta[name]) is str and re.fullmatch(r"[0-9a-f]{64}", meta[name])
        for name in fields
    )


def _context_bound_meta(semantic: Mapping[str, object], rendered_at: str, renderer_id: str, *, markdown: bytes, rendered_html: bytes, semantic_json: bytes) -> dict[str, object]:
    return {
        "context_assembly_sha256": semantic["context_assembly_sha256"],
        "context_coverage_sha256": semantic["context_coverage_sha256"],
        "context_counts": semantic["context_counts"],
        "html_sha256": sha256_bytes(rendered_html),
        "locale": "ko-KR",
        "markdown_sha256": sha256_bytes(markdown),
        "parent_plan_sha256": semantic["parent_plan_sha256"],
        "rendered_at": rendered_at,
        "renderer_id": renderer_id,
        "review_kind": CONTEXT_BOUND_REVIEW_KIND,
        "schema_version": 2,
        "semantic_schema": CONTEXT_BOUND_SEMANTIC_SCHEMA,
        "semantic_sha256": sha256_bytes(semantic_json),
    }


def _context_bound_mappings(
    mapping_input: Mapping[str, object],
    plan: canonical_curation.ContextBoundCurationPlan,
    assembly: context_assembly.ContextAssembly,
    root: Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]], tuple[str, ...]]:
    """Validate root exact-once mappings and optional nested Context citations."""

    project_home = plan.project_home
    source_by_observation = {
        source.observation_id: source
        for source in assembly.sources
        if source.mode == "CURRENT_LOCAL" and source.observation_id is not None
    }
    root_candidates = {
        observation.observation_id: observation
        for observation in plan.source_observations
        if (
            _CANDIDATE_EVIDENCE in observation.classification_evidence
            and Path(observation.relative_path).parent.as_posix() == project_home
        )
    }
    if not root_candidates:
        raise NavigationDraftError("root navigation source membership is empty")
    mappings = mapping_input.get("mappings")
    if type(mappings) is not list or not mappings:
        raise NavigationDraftError("context-bound source mappings are empty")
    normalized: list[dict[str, object]] = []
    mapped_ids: list[str] = []
    source_views: dict[str, dict[str, object]] = {}
    output_headings = _headings(mapping_input.get("_proposed_text", ""))
    for value in mappings:
        if type(value) is not dict or set(value) != {"output_sections", "source_observation_id", "source_sections"}:
            raise NavigationDraftError("context-bound source mapping is invalid")
        source_id = value["source_observation_id"]
        source_sections = value["source_sections"]
        output_sections = value["output_sections"]
        if (
            type(source_id) is not str
            or source_id not in source_by_observation
            or type(source_sections) is not list
            or not source_sections
            or type(output_sections) is not list
            or not output_sections
            or any(type(item) is not str or not item.strip() for item in source_sections + output_sections)
        ):
            raise NavigationDraftError("context-bound source mapping sections are invalid")
        reread = _reread_context_source(root, source_by_observation[source_id], assembly.bounds)
        projection = reread.content_projection
        assert projection is not None
        if any(
            section not in set(projection.headings) | {projection.title}
            for section in source_sections
        ):
            raise NavigationDraftError("mapped Context source section is missing")
        if any(section not in output_headings for section in output_sections):
            raise NavigationDraftError("mapped output section is missing")
        mapped_ids.append(source_id)
        source_views[source_id] = reread.canonical_value
        normalized.append(
            {
                "output_sections": output_sections,
                "source_observation_id": source_id,
                "source_path": reread.relative_path,
                "source_sections": source_sections,
            }
        )
    if len(mapped_ids) != len(set(mapped_ids)) or not set(root_candidates).issubset(mapped_ids):
        raise NavigationDraftError("every root navigation source must be mapped exactly once")
    return (
        sorted(normalized, key=lambda item: item["source_observation_id"]),
        [source_views[key] for key in sorted(source_views)],
        tuple(sorted(root_candidates)),
    )


def _revalidate_historical_context_source(
    root: Path, source: context_assembly.ContextSource
) -> None:
    if (
        source.mode != "HISTORICAL_HINT"
        or source.relative_path is None
        or source.identity is None
        or source.content_sha256 is None
    ):
        raise NavigationDraftError("historical Context source is invalid")
    try:
        _read_exact_source(
            root,
            {
                "relative_path": source.relative_path,
                "device": source.identity[0],
                "inode": source.identity[1],
                "owner": source.identity[2],
                "mode": source.identity[3],
                "link_count": source.identity[4],
                "size": source.identity[5],
                "modified_time_ns": source.identity[6],
                "content_sha256": source.content_sha256,
            },
        )
    except NavigationDraftError as exc:
        raise NavigationDraftError("historical Context source is stale") from exc


def _revalidate_assembly_sources(
    root: Path, assembly: context_assembly.ContextAssembly
) -> None:
    for source in assembly.sources:
        if source.mode == "CURRENT_LOCAL":
            _reread_context_source(root, source, assembly.bounds)
        elif source.mode == "HISTORICAL_HINT":
            _revalidate_historical_context_source(root, source)


def _revalidate_assembly_membership(
    root: Path,
    assembly: context_assembly.ContextAssembly,
) -> None:
    """Rebuild the sealed Context so memory membership cannot drift unnoticed."""

    try:
        current_policy_sha256 = workstream_curation.read_current_policy_sha256(root)
        if current_policy_sha256 != assembly.policy_sha256:
            raise NavigationDraftError("Workstream policy changed before package seal")
        compiled_workstream = policy.CompiledWorkstream(
            id=assembly.workstream.id,
            lifecycle=assembly.workstream.lifecycle,
            project_home=assembly.workstream.project_home,
            aliases=assembly.workstream.aliases,
            memory_workspace=assembly.workstream.memory_workspace,
        )
        current_memory = context_assembly.read_memory_context(
            root,
            assembly.workstream,
            bounds=assembly.bounds,
        )
        memory_exclusions = set(current_memory.excluded_paths)
        local_exclusions = tuple(
            path
            for path in assembly.coverage.excluded_paths
            if path not in memory_exclusions
        )
        current_local = tuple(
            context_assembly.ContextLocalObservation(
                observation=_context_observation(source),
                group=source.group,
            )
            for source in assembly.sources
            if source.mode == "CURRENT_LOCAL"
        )
        rebuilt = context_assembly.build_context_assembly(
            root=root,
            compiled_workstream=compiled_workstream,
            policy_sha256=current_policy_sha256,
            root_identity=assembly.root_identity,
            project_identity=assembly.project_identity,
            local_observations=current_local,
            local_gaps=(),
            excluded_paths=local_exclusions,
            bounds=assembly.bounds,
        )
    except NavigationDraftError:
        raise
    except (OSError, ValueError, context_assembly.ContextAssemblyError) as exc:
        raise NavigationDraftError("sealed Context membership is stale") from exc
    if rebuilt.canonical_bytes != assembly.canonical_bytes:
        raise NavigationDraftError("sealed Context membership is stale")


def _context_bound_semantic(
    *,
    root: Path,
    parent_review_directory: Path,
    proposed_document: bytes,
    source_map: bytes,
) -> dict[str, object]:
    if type(proposed_document) is not bytes or not proposed_document or len(proposed_document) > _MAX_DOCUMENT_BYTES:
        raise NavigationDraftError("proposed document bytes are invalid")
    try:
        proposed_text = proposed_document.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NavigationDraftError("proposed document must be UTF-8") from exc
    mapping_input = _parse_context_bound_input(source_map)
    plan, assembly, parent_hashes = _context_bound_parent(parent_review_directory)
    if (
        mapping_input["parent_plan_sha256"] != plan.sha256
        or mapping_input["context_assembly_sha256"] != assembly.sha256
        or mapping_input["context_coverage_sha256"] != assembly.coverage_sha256
        or mapping_input["workstream_id"] != plan.primary_workstream_id
        or plan.captured_lifecycle != "active"
    ):
        raise NavigationDraftError("context-bound navigation input is bound to another parent")
    root_path = _canonical_absolute_path(root, "root")
    project_path = safety.require_no_symlink_components(plan.project_home, root_path, "project home", error_type=NavigationDraftError)
    _require_directory_identity(root_path, list(plan.root_identity), "root")
    _require_directory_identity(project_path, list(plan.project_identity), "project home")
    augmented = dict(mapping_input)
    augmented["_proposed_text"] = proposed_text
    _revalidate_assembly_sources(root_path, assembly)
    mappings, mapped_sources, root_ids = _context_bound_mappings(augmented, plan, assembly, root_path)
    if mapping_input["output_path"] != f"{plan.project_home}/README.md" or mapping_input["output_role"] != "overview":
        raise NavigationDraftError("navigation output must be the Workstream README")
    spine = mapping_input["spine"]
    if (
        type(spine) is not list
        or len(spine) != len(canonical_curation.COMMON_SPINE_ROLES)
        or [value.get("role") if type(value) is dict else None for value in spine] != list(canonical_curation.COMMON_SPINE_ROLES)
        or any(type(value) is not dict or set(value) != {"output_section", "role"} or value["output_section"] not in _headings(proposed_text) for value in spine)
    ):
        raise NavigationDraftError("common spine mapping is incomplete")
    notes = mapping_input["review_notes"]
    if type(notes) is not list or any(type(note) is not str or not note.strip() or len(note.encode("utf-8")) > 1024 for note in notes):
        raise NavigationDraftError("review notes are invalid")
    return {
        "boundary": {"project_home": plan.project_home, "project_identity": list(plan.project_identity), "root_identity": list(plan.root_identity)},
        "context_assembly": assembly.canonical_value,
        "context_assembly_sha256": assembly.sha256,
        "context_counts": _context_counts(assembly, len(root_ids)),
        "context_coverage_sha256": assembly.coverage_sha256,
        "context_sources": [source.canonical_value for source in assembly.sources],
        "corpus_consequence": CORPUS_CONSEQUENCE,
        "draft_only": True,
        "mapped_context_sources": mapped_sources,
        "output": {"content": proposed_text, "content_sha256": sha256_bytes(proposed_document), "document_role": "overview", "output_path": mapping_input["output_path"]},
        "parent_plan_sha256": plan.sha256,
        "parent_review_hashes": _review_hashes_value(parent_hashes),
        "policy_sha256": plan.policy_sha256,
        "review_notes": notes,
        "root_navigation_source_ids": list(root_ids),
        "schema": CONTEXT_BOUND_SEMANTIC_SCHEMA,
        "source_mappings": mappings,
        "spine": spine,
        "workstream_id": plan.primary_workstream_id,
    }


def _context_bound_markdown(semantic: dict[str, object], semantic_json: bytes) -> bytes:
    counts = semantic["context_counts"]
    output = semantic["output"]
    lines = [
        "# Workstream 진입 문서 초안 검토", "", "상태: **초안 — 적용되지 않음**", "",
        "## Context coverage", "",
        "- navigation source count: %d" % counts["root_navigation"],
        "- full current-local context source count: %d" % counts["full_current_local"],
        "- historical hint count: %d" % counts["historical_hint"],
        "- unverified external reference count: %d" % counts["unverified_external"],
        "- Context Assembly SHA-256: `%s`" % semantic["context_assembly_sha256"],
        "- Context Coverage SHA-256: `%s`" % semantic["context_coverage_sha256"], "",
        "## 제안 entry document 전체", "", output["content"], "",
        "## 원문 → entry document 출처표", "", "| 원문 | 원문 section | entry document section |", "| --- | --- | --- |",
    ]
    for mapping in semantic["source_mappings"]:
        lines.append("| `%s` | %s | %s |" % (mapping["source_path"], _table_text(mapping["source_sections"]), _table_text(mapping["output_sections"])))
    lines.extend(("", "## 재검증한 Context source", ""))
    for source in semantic["mapped_context_sources"]:
        projection = source["content_projection"]
        lines.extend(("### `%s`" % source["relative_path"], "", "```text", projection["excerpt"], "```", ""))
    lines.extend(("## 기술 부록", "", _CONTEXT_BOUND_SEMANTIC_START.decode().rstrip("\n"), semantic_json.decode().rstrip("\n"), _CONTEXT_BOUND_SEMANTIC_END.decode().rstrip("\n"), ""))
    return "\n".join(lines).encode("utf-8")


def _context_bound_html(semantic: dict[str, object], semantic_json: bytes, markdown_sha256: str) -> bytes:
    counts = semantic["context_counts"]
    output = semantic["output"]
    rows = "".join("<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (html.escape(mapping["source_path"]), html.escape(", ".join(mapping["source_sections"])), html.escape(", ".join(mapping["output_sections"]))) for mapping in semantic["source_mappings"])
    evidence = "".join("<section><h3><code>%s</code></h3><pre><code>%s</code></pre></section>" % (html.escape(source["relative_path"]), html.escape(source["content_projection"]["excerpt"])) for source in semantic["mapped_context_sources"])
    return ("<!doctype html><html lang=\"ko-KR\"><head><meta charset=\"utf-8\"><meta name=\"mnemosyne-markdown-sha256\" content=\"%s\"><title>Workstream 진입 문서 초안 검토</title></head><body><main id=\"main-content\"><h1>Workstream 진입 문서 초안 검토</h1><h2>Context coverage</h2><ul><li>navigation source count: %d</li><li>full current-local context source count: %d</li><li>historical hint count: %d</li><li>unverified external reference count: %d</li></ul><h2>제안 entry document 전체</h2><pre>%s</pre><h2>원문 → entry document 출처표</h2><table><tbody>%s</tbody></table><h2>재검증한 Context source</h2>%s<details><summary>canonical semantic JSON 열기</summary><pre><code>%s</code></pre></details></main></body></html>" % (markdown_sha256, counts["root_navigation"], counts["full_current_local"], counts["historical_hint"], counts["unverified_external"], html.escape(output["content"]), rows, evidence, html.escape(semantic_json.decode()))).encode("utf-8")


def compile_context_bound_navigation_review(
    *, root: Path, parent_review_directory: Path, proposed_document: bytes, source_map: bytes, rendered_at: str, renderer_id: str,
) -> tuple[review_package.ReviewPackagePayload, dict[str, object]]:
    if type(rendered_at) is not str or _RENDERED_AT.fullmatch(rendered_at) is None or type(renderer_id) is not str or _RENDERER_ID.fullmatch(renderer_id) is None:
        raise NavigationDraftError("renderer metadata is invalid")
    semantic = _context_bound_semantic(root=_canonical_absolute_path(root, "root"), parent_review_directory=_canonical_absolute_path(parent_review_directory, "parent Review Package"), proposed_document=proposed_document, source_map=source_map)
    semantic_json = canonical_json_bytes(semantic)
    markdown = _context_bound_markdown(semantic, semantic_json)
    rendered_html = _context_bound_html(semantic, semantic_json, sha256_bytes(markdown))
    meta = _context_bound_meta(
        semantic,
        rendered_at,
        renderer_id,
        markdown=markdown,
        rendered_html=rendered_html,
        semantic_json=semantic_json,
    )
    payload = review_package.ReviewPackagePayload(
        markdown,
        rendered_html,
        canonical_json_bytes(meta),
        semantic_json,
    )
    validate_context_bound_navigation_review(payload)
    return payload, semantic


def _context_bound_semantic_from_markdown(markdown: bytes) -> bytes:
    if markdown.count(_CONTEXT_BOUND_SEMANTIC_START) != 1 or markdown.count(_CONTEXT_BOUND_SEMANTIC_END) != 1:
        raise NavigationDraftError("context-bound navigation semantic appendix is missing")
    start = markdown.index(_CONTEXT_BOUND_SEMANTIC_START) + len(_CONTEXT_BOUND_SEMANTIC_START)
    end = markdown.index(_CONTEXT_BOUND_SEMANTIC_END, start)
    value = markdown[start:end]
    return value if value.endswith(b"\n") else value + b"\n"


def validate_context_bound_navigation_review(payload: review_package.ReviewPackagePayload) -> review_package.ReviewPackageHashes:
    if type(payload) is not review_package.ReviewPackagePayload:
        raise TypeError("payload must be ReviewPackagePayload")
    try:
        meta = json.loads(payload.meta_json.decode("utf-8"))
        semantic = json.loads(payload.semantic_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NavigationDraftError("context-bound navigation JSON is invalid") from exc
    meta_fields = {"context_assembly_sha256", "context_coverage_sha256", "context_counts", "html_sha256", "locale", "markdown_sha256", "parent_plan_sha256", "rendered_at", "renderer_id", "review_kind", "schema_version", "semantic_schema", "semantic_sha256"}
    meta_hash_fields = {
        "context_assembly_sha256",
        "context_coverage_sha256",
        "html_sha256",
        "markdown_sha256",
        "parent_plan_sha256",
        "semantic_sha256",
    }
    meta_contract_valid = (
        type(meta) is dict
        and set(meta) == meta_fields
        and canonical_json_bytes(meta) == payload.meta_json
        and _meta_hashes_valid(meta, meta_hash_fields)
        and meta["review_kind"] == CONTEXT_BOUND_REVIEW_KIND
        and meta["schema_version"] == 2
        and meta["semantic_schema"] == CONTEXT_BOUND_SEMANTIC_SCHEMA
        and meta["locale"] == "ko-KR"
        and sha256_bytes(payload.markdown) == meta["markdown_sha256"]
        and sha256_bytes(payload.html) == meta["html_sha256"]
        and sha256_bytes(payload.semantic_json) == meta["semantic_sha256"]
    )
    semantic_contract_valid = (
        type(semantic) is dict
        and canonical_json_bytes(semantic) == payload.semantic_json
        and _context_bound_semantic_from_markdown(payload.markdown)
        == payload.semantic_json
        and semantic.get("schema") == CONTEXT_BOUND_SEMANTIC_SCHEMA
        and semantic.get("draft_only") is True
        and semantic.get("context_assembly_sha256")
        == meta.get("context_assembly_sha256")
        and semantic.get("context_coverage_sha256")
        == meta.get("context_coverage_sha256")
        and semantic.get("context_counts") == meta.get("context_counts")
        and semantic.get("parent_plan_sha256") == meta.get("parent_plan_sha256")
    )
    if not meta_contract_valid or not semantic_contract_valid:
        raise NavigationDraftError("context-bound navigation review seal is invalid")
    counts = semantic.get("context_counts")
    sources = semantic.get("context_sources")
    mappings = semantic.get("source_mappings")
    root_ids = semantic.get("root_navigation_source_ids")
    _require_parent_review_hashes(semantic.get("parent_review_hashes"))
    if (
        type(counts) is not dict or set(counts) != {"root_navigation", "full_current_local", "historical_hint", "unverified_external"}
        or any(type(value) is not int or value < 0 for value in counts.values())
        or type(sources) is not list or type(mappings) is not list or not mappings
        or type(root_ids) is not list or not root_ids or any(type(value) is not str for value in root_ids)
        or len(root_ids) != len(set(root_ids)) or counts["root_navigation"] != len(root_ids)
        or counts["full_current_local"] != sum(source.get("mode") == "CURRENT_LOCAL" for source in sources if type(source) is dict)
        or counts["historical_hint"] != sum(source.get("mode") == "HISTORICAL_HINT" for source in sources if type(source) is dict)
        or counts["unverified_external"] != sum(source.get("mode") == "UNVERIFIED_EXTERNAL" for source in sources if type(source) is dict)
    ):
        raise NavigationDraftError("context-bound navigation coverage is invalid")
    try:
        assembly = context_assembly.decode_context_assembly(semantic.get("context_assembly"))
    except (TypeError, ValueError, context_assembly.ContextAssemblyError) as exc:
        raise NavigationDraftError("context-bound navigation Context Assembly is invalid") from exc
    mapping_ids = [mapping.get("source_observation_id") for mapping in mappings if type(mapping) is dict]
    if (
        assembly.canonical_value != semantic["context_assembly"]
        or assembly.sha256 != semantic["context_assembly_sha256"]
        or assembly.coverage_sha256 != semantic["context_coverage_sha256"]
        or [source.canonical_value for source in assembly.sources] != sources
        or len(mapping_ids) != len(set(mapping_ids))
        or not set(root_ids).issubset(mapping_ids)
    ):
        raise NavigationDraftError("context-bound navigation source membership is invalid")
    return review_package.ReviewPackageHashes(sha256_bytes(payload.markdown), sha256_bytes(payload.html), sha256_bytes(payload.meta_json), sha256_bytes(payload.semantic_json), sha256_bytes(canonical_json_bytes(sources)))


def _revalidate_context_bound_navigation_boundary(root: Path, semantic: Mapping[str, object]) -> None:
    boundary = semantic.get("boundary")
    if type(boundary) is not dict or set(boundary) != {"project_home", "project_identity", "root_identity"}:
        raise NavigationDraftError("context-bound navigation boundary is invalid")
    project_home = boundary["project_home"]
    if type(project_home) is not str:
        raise NavigationDraftError("context-bound navigation project home is invalid")
    root_path = _canonical_absolute_path(root, "root")
    project_path = safety.require_no_symlink_components(project_home, root_path, "project home", error_type=NavigationDraftError)
    _require_directory_identity(root_path, boundary["root_identity"], "root")
    _require_directory_identity(project_path, boundary["project_identity"], "project home")
    try:
        assembly = context_assembly.decode_context_assembly(semantic.get("context_assembly"))
    except (TypeError, ValueError, context_assembly.ContextAssemblyError) as exc:
        raise NavigationDraftError("sealed Context Assembly is invalid") from exc
    if assembly.sha256 != semantic.get("context_assembly_sha256") or assembly.coverage_sha256 != semantic.get("context_coverage_sha256"):
        raise NavigationDraftError("sealed Context Assembly hash is stale")
    _revalidate_assembly_membership(root_path, assembly)


def write_context_bound_navigation_review(
    directory: Path,
    payload: review_package.ReviewPackagePayload,
    *,
    root: Path,
    parent_review_directory: Path,
) -> review_package.ReviewPackageHashes:
    try:
        semantic = json.loads(payload.semantic_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NavigationDraftError("context-bound navigation semantic JSON is invalid") from exc
    if type(semantic) is not dict:
        raise NavigationDraftError("context-bound navigation semantic contract is invalid")
    expected_parent_hashes = _require_parent_review_hashes(
        semantic.get("parent_review_hashes")
    )
    parent_plan, parent_assembly, parent_hashes = _context_bound_parent(
        _canonical_absolute_path(parent_review_directory, "parent Review Package")
    )
    if (
        parent_plan.sha256 != semantic.get("parent_plan_sha256")
        or parent_assembly.sha256 != semantic.get("context_assembly_sha256")
        or parent_assembly.coverage_sha256 != semantic.get("context_coverage_sha256")
        or _review_hashes_value(parent_hashes) != expected_parent_hashes
    ):
        raise NavigationDraftError("parent context-bound Review changed before package seal")
    def revalidate_before_final_seal() -> None:
        _revalidate_context_bound_navigation_boundary(root, semantic)
        current_plan, current_assembly, current_hashes = _context_bound_parent(
            _canonical_absolute_path(
                parent_review_directory,
                "parent Review Package",
            )
        )
        if (
            current_plan.sha256 != semantic.get("parent_plan_sha256")
            or current_assembly.sha256 != semantic.get("context_assembly_sha256")
            or current_assembly.coverage_sha256
            != semantic.get("context_coverage_sha256")
            or _review_hashes_value(current_hashes) != expected_parent_hashes
        ):
            raise NavigationDraftError(
                "parent context-bound Review changed before package seal"
            )

    revalidate_before_final_seal()
    try:
        hashes = review_package.write_validated_review_package(
            directory,
            payload,
            validate=validate_context_bound_navigation_review,
            before_final_seal=revalidate_before_final_seal,
        )
    except NavigationDraftError:
        try:
            review_package.discard_unsealed_review_package(directory, payload)
        except review_package.ReviewPackageError as cleanup_error:
            raise NavigationDraftError(
                "stale context-bound navigation cleanup cannot be proven"
            ) from cleanup_error
        raise
    except review_package.ReviewPackageError as exc:
        raise NavigationDraftError("context-bound navigation Review Package cannot be written") from exc
    try:
        revalidate_before_final_seal()
    except NavigationDraftError:
        try:
            review_package.discard_unsealed_review_package(directory, payload)
        except review_package.ReviewPackageError as cleanup_error:
            raise NavigationDraftError("stale context-bound navigation cleanup cannot be proven") from cleanup_error
        raise
    return hashes


def _validated_semantic(
    *,
    root: Path,
    parent_review_directory: Path,
    proposed_document: bytes,
    source_map: bytes,
) -> dict[str, object]:
    if type(proposed_document) is not bytes or not proposed_document or len(proposed_document) > _MAX_DOCUMENT_BYTES:
        raise NavigationDraftError("proposed document bytes are invalid")
    try:
        proposed_text = proposed_document.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NavigationDraftError("proposed document must be UTF-8") from exc
    _require_text(proposed_text, "proposed document", maximum=_MAX_DOCUMENT_BYTES)
    mapping_input = _parse_input(source_map)
    try:
        parent_hashes, plan = canonical_curation_review.validate_review_directory_with_plan(
            parent_review_directory
        )
    except (canonical_curation_review.CurationReviewError, review_package.ReviewPackageError) as exc:
        raise NavigationDraftError("parent Review Package is invalid") from exc
    parent_plan_sha256 = sha256_bytes(canonical_json_bytes(plan))
    if mapping_input["parent_plan_sha256"] != parent_plan_sha256:
        raise NavigationDraftError("source map is bound to a different parent Plan")
    if (
        mapping_input["workstream_id"] != plan.get("primary_workstream_id")
        or plan.get("captured_lifecycle") != "active"
        or type(plan.get("project_home")) is not str
    ):
        raise NavigationDraftError("Workstream identity is invalid")
    root_path = _canonical_absolute_path(root, "root")
    project_home = plan["project_home"]
    try:
        canonical_curation._require_relative_path(project_home, "project home")
    except canonical_curation.CanonicalCurationError as exc:
        raise NavigationDraftError("project home is invalid") from exc
    project_path = safety.require_no_symlink_components(
        project_home,
        root_path,
        "project home",
        error_type=NavigationDraftError,
    )
    _require_directory_identity(root_path, plan.get("root_identity"), "root")
    _require_directory_identity(project_path, plan.get("project_identity"), "project home")
    try:
        current_policy_sha256 = workstream_curation.read_current_policy_sha256(
            root_path
        )
    except workstream_curation.WorkstreamCurationError as exc:
        raise NavigationDraftError("current Workstream policy cannot be verified") from exc
    if current_policy_sha256 != plan.get("policy_sha256"):
        raise NavigationDraftError("Workstream policy changed after inspection")

    observations = plan.get("source_observations")
    if type(observations) is not list:
        raise NavigationDraftError("parent source observations are invalid")
    candidates = []
    source_headings: dict[str, set[str]] = {}
    for observation in observations:
        if type(observation) is not dict:
            raise NavigationDraftError("parent source observation is invalid")
        evidence = observation.get("classification_evidence")
        relative_path = observation.get("relative_path")
        if (
            type(evidence) is list
            and _CANDIDATE_EVIDENCE in evidence
            and type(relative_path) is str
            and Path(relative_path).parent.as_posix() == project_home
        ):
            raw = _read_exact_source(root_path, observation)
            try:
                source_headings[observation["observation_id"]] = _headings(
                    raw.decode("utf-8")
                )
            except UnicodeDecodeError as exc:
                raise NavigationDraftError("navigation source must be UTF-8") from exc
            candidates.append(observation)
    if not candidates:
        raise NavigationDraftError("navigation source membership is empty")

    output_path = mapping_input["output_path"]
    if output_path != f"{project_home}/README.md" or mapping_input["output_role"] != "overview":
        raise NavigationDraftError("navigation output must be the Workstream README")
    mappings = mapping_input["mappings"]
    if type(mappings) is not list or not mappings:
        raise NavigationDraftError("source mappings are empty")
    candidate_by_id = {item["observation_id"]: item for item in candidates}
    normalized_mappings = []
    for value in mappings:
        if type(value) is not dict or set(value) != {
            "output_sections",
            "source_observation_id",
            "source_sections",
        }:
            raise NavigationDraftError("source mapping is invalid")
        source_id = value["source_observation_id"]
        if source_id not in candidate_by_id:
            raise NavigationDraftError("source mapping is outside the approved membership")
        source_sections = value["source_sections"]
        output_sections = value["output_sections"]
        if (
            type(source_sections) is not list
            or not source_sections
            or type(output_sections) is not list
            or not output_sections
            or any(type(item) is not str or not item.strip() for item in source_sections + output_sections)
        ):
            raise NavigationDraftError("source mapping sections are invalid")
        if any(
            section not in source_headings[source_id]
            for section in source_sections
        ):
            raise NavigationDraftError("mapped source section is missing")
        normalized_mappings.append(
            {
                "output_sections": output_sections,
                "source_observation_id": source_id,
                "source_path": candidate_by_id[source_id]["relative_path"],
                "source_sections": source_sections,
            }
        )
    source_ids = [value["source_observation_id"] for value in normalized_mappings]
    if len(source_ids) != len(set(source_ids)) or set(source_ids) != set(candidate_by_id):
        raise NavigationDraftError("every approved source must be mapped exactly once")

    headings = _headings(proposed_text)
    spine = mapping_input["spine"]
    if type(spine) is not list or len(spine) != len(canonical_curation.COMMON_SPINE_ROLES):
        raise NavigationDraftError("common spine mapping is incomplete")
    if [value.get("role") if type(value) is dict else None for value in spine] != list(
        canonical_curation.COMMON_SPINE_ROLES
    ):
        raise NavigationDraftError("common spine roles are invalid")
    for value in spine:
        if set(value) != {"output_section", "role"} or value["output_section"] not in headings:
            raise NavigationDraftError("common spine output section is missing")
    for value in normalized_mappings:
        if any(section not in headings for section in value["output_sections"]):
            raise NavigationDraftError("mapped output section is missing")

    notes = mapping_input["review_notes"]
    if type(notes) is not list or any(
        type(note) is not str or not note.strip() or len(note.encode("utf-8")) > 1024
        for note in notes
    ):
        raise NavigationDraftError("review notes are invalid")
    selected_observations = sorted(candidates, key=lambda item: item["observation_id"])
    source_snapshot_sha256 = sha256_bytes(canonical_json_bytes(selected_observations))
    return {
        "boundary": {
            "project_home": project_home,
            "project_identity": plan.get("project_identity"),
            "root_identity": plan.get("root_identity"),
        },
        "corpus_consequence": CORPUS_CONSEQUENCE,
        "draft_only": True,
        "output": {
            "content": proposed_text,
            "content_sha256": sha256_bytes(proposed_document),
            "document_role": "overview",
            "output_path": output_path,
        },
        "parent_plan_sha256": parent_plan_sha256,
        "parent_review_hashes": {
            "html_sha256": parent_hashes.html_sha256,
            "markdown_sha256": parent_hashes.markdown_sha256,
            "meta_sha256": parent_hashes.meta_sha256,
            "semantic_sha256": parent_hashes.semantic_sha256,
        },
        "policy_sha256": plan.get("policy_sha256"),
        "review_notes": notes,
        "schema": SEMANTIC_SCHEMA,
        "source_consequence": _source_consequence(len(selected_observations)),
        "source_mappings": sorted(
            normalized_mappings,
            key=lambda item: item["source_observation_id"],
        ),
        "source_observation_sha256": source_snapshot_sha256,
        "source_observations": selected_observations,
        "spine": spine,
        "workstream_id": mapping_input["workstream_id"],
    }


def _table_text(values: list[str]) -> str:
    return "<br>".join(value.replace("|", "\\|") for value in values)


def _markdown(semantic: dict[str, object], semantic_json: bytes) -> bytes:
    output = semantic["output"]
    lines = [
        "# Workstream 진입 문서 초안 검토",
        "",
        "상태: **초안 — 적용되지 않음**",
        "",
        f"- Corpus consequence: `{CORPUS_CONSEQUENCE}`",
        f"- Workstream: `{semantic['workstream_id']}`",
        f"- Parent Plan SHA-256: `{semantic['parent_plan_sha256']}`",
        f"- 제안 경로: `{output['output_path']}`",
        "- 실행 요청: 없음",
        "",
        "## 원문과 적용 결과",
        "",
        semantic["source_consequence"],
        "",
        "## 제안 entry document 전체",
        "",
        output["content"],
        "",
        f"SHA-256: `{output['content_sha256']}`",
        "",
        "## 원문 → entry document 출처표",
        "",
        "| 원문 | 원문 section | entry document section |",
        "| --- | --- | --- |",
    ]
    for mapping in semantic["source_mappings"]:
        lines.append(
            "| `%s` | %s | %s |"
            % (
                mapping["source_path"],
                _table_text(mapping["source_sections"]),
                _table_text(mapping["output_sections"]),
            )
        )
    lines.extend(("", "## 공통 탐색 뼈대", ""))
    for item in semantic["spine"]:
        lines.append(f"- `{item['role']}` → `{item['output_section']}`")
    lines.extend(("", "## 검토 메모", ""))
    if semantic["review_notes"]:
        lines.extend(f"- {note}" for note in semantic["review_notes"])
    else:
        lines.append("- 없음")
    lines.extend(
        (
            "",
            "## 기술 부록",
            "",
            _SEMANTIC_START.decode().rstrip("\n"),
            semantic_json.decode().rstrip("\n"),
            _SEMANTIC_END.decode().rstrip("\n"),
            "",
        )
    )
    return "\n".join(lines).encode("utf-8")


def _html(semantic: dict[str, object], semantic_json: bytes, markdown_sha256: str) -> bytes:
    output = semantic["output"]
    rows = "".join(
        "<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>"
        % (
            html.escape(mapping["source_path"]),
            "<br>".join(html.escape(value) for value in mapping["source_sections"]),
            "<br>".join(html.escape(value) for value in mapping["output_sections"]),
        )
        for mapping in semantic["source_mappings"]
    )
    body = (
        '<!doctype html><html lang="ko-KR"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta name="mnemosyne-markdown-sha256" content="{markdown_sha256}">'
        "<title>Workstream 진입 문서 초안 검토</title></head><body>"
        '<main id="main-content"><h1>Workstream 진입 문서 초안 검토</h1>'
        f"<p><strong>초안 — 적용되지 않음</strong> <code>{CORPUS_CONSEQUENCE}</code></p>"
        f"<p>{html.escape(semantic['source_consequence'])}</p>"
        "<h2>제안 entry document 전체</h2>"
        f"<pre>{html.escape(output['content'])}</pre>"
        "<h2>원문 → entry document 출처표</h2>"
        "<table><thead><tr><th>원문</th><th>원문 section</th><th>entry document section</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "<details><summary>canonical semantic JSON 열기</summary>"
        f"<pre><code>{html.escape(semantic_json.decode())}</code></pre></details>"
        "</main></body></html>"
    )
    return body.encode("utf-8")


def compile_navigation_review(
    *,
    root: Path,
    parent_review_directory: Path,
    proposed_document: bytes,
    source_map: bytes,
    rendered_at: str,
    renderer_id: str,
) -> tuple[review_package.ReviewPackagePayload, dict[str, object]]:
    if type(rendered_at) is not str or _RENDERED_AT.fullmatch(rendered_at) is None:
        raise NavigationDraftError("rendered_at is invalid")
    if type(renderer_id) is not str or _RENDERER_ID.fullmatch(renderer_id) is None:
        raise NavigationDraftError("renderer_id is invalid")
    semantic = _validated_semantic(
        root=_canonical_absolute_path(root, "root"),
        parent_review_directory=_canonical_absolute_path(
            parent_review_directory,
            "parent Review Package",
        ),
        proposed_document=proposed_document,
        source_map=source_map,
    )
    semantic_json = canonical_json_bytes(semantic)
    markdown = _markdown(semantic, semantic_json)
    rendered_html = _html(semantic, semantic_json, sha256_bytes(markdown))
    meta_json = canonical_json_bytes(
        {
            "html_sha256": sha256_bytes(rendered_html),
            "locale": "ko-KR",
            "markdown_sha256": sha256_bytes(markdown),
            "output_content_sha256": semantic["output"]["content_sha256"],
            "parent_plan_sha256": semantic["parent_plan_sha256"],
            "rendered_at": rendered_at,
            "renderer_id": renderer_id,
            "review_kind": REVIEW_KIND,
            "schema_version": 1,
            "semantic_schema": SEMANTIC_SCHEMA,
            "semantic_sha256": sha256_bytes(semantic_json),
            "source_snapshot_sha256": semantic["source_observation_sha256"],
        }
    )
    payload = review_package.ReviewPackagePayload(
        markdown=markdown,
        html=rendered_html,
        meta_json=meta_json,
        semantic_json=semantic_json,
    )
    validate_navigation_review(payload)
    return payload, semantic


def _semantic_from_markdown(markdown: bytes) -> bytes:
    if markdown.count(_SEMANTIC_START) != 1 or markdown.count(_SEMANTIC_END) != 1:
        raise NavigationDraftError("navigation semantic appendix is missing")
    start = markdown.index(_SEMANTIC_START) + len(_SEMANTIC_START)
    end = markdown.index(_SEMANTIC_END, start)
    value = markdown[start:end]
    return value if value.endswith(b"\n") else value + b"\n"


def validate_navigation_review(
    payload: review_package.ReviewPackagePayload,
) -> review_package.ReviewPackageHashes:
    if type(payload) is not review_package.ReviewPackagePayload:
        raise TypeError("payload must be ReviewPackagePayload")
    try:
        meta = json.loads(payload.meta_json)
        semantic = json.loads(payload.semantic_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NavigationDraftError("navigation review JSON is invalid") from exc
    meta_fields = {
        "html_sha256",
        "locale",
        "markdown_sha256",
        "output_content_sha256",
        "parent_plan_sha256",
        "rendered_at",
        "renderer_id",
        "review_kind",
        "schema_version",
        "semantic_schema",
        "semantic_sha256",
        "source_snapshot_sha256",
    }
    if (
        type(meta) is not dict
        or set(meta) != meta_fields
        or canonical_json_bytes(meta) != payload.meta_json
        or meta["review_kind"] != REVIEW_KIND
        or meta["semantic_schema"] != SEMANTIC_SCHEMA
        or meta["schema_version"] != 1
        or meta["locale"] != "ko-KR"
        or sha256_bytes(payload.markdown) != meta["markdown_sha256"]
        or sha256_bytes(payload.html) != meta["html_sha256"]
        or sha256_bytes(payload.semantic_json) != meta["semantic_sha256"]
        or _semantic_from_markdown(payload.markdown) != payload.semantic_json
    ):
        raise NavigationDraftError("navigation review seal is invalid")
    if (
        type(semantic) is not dict
        or canonical_json_bytes(semantic) != payload.semantic_json
        or semantic.get("schema") != SEMANTIC_SCHEMA
        or semantic.get("draft_only") is not True
        or semantic.get("corpus_consequence") != CORPUS_CONSEQUENCE
    ):
        raise NavigationDraftError("navigation review semantic contract is invalid")
    output = semantic.get("output")
    boundary = semantic.get("boundary")
    observations = semantic.get("source_observations")
    mappings = semantic.get("source_mappings")
    if (
        type(output) is not dict
        or type(boundary) is not dict
        or set(boundary) != {"project_home", "project_identity", "root_identity"}
        or type(output.get("content")) is not str
        or sha256_bytes(output["content"].encode("utf-8")) != output.get("content_sha256")
        or type(observations) is not list
        or not observations
        or type(mappings) is not list
        or not mappings
        or semantic.get("source_consequence") != _source_consequence(len(observations))
    ):
        raise NavigationDraftError("navigation review content is invalid")
    observation_ids = {value.get("observation_id") for value in observations if type(value) is dict}
    mapping_ids = {value.get("source_observation_id") for value in mappings if type(value) is dict}
    if (
        len(observation_ids) != len(observations)
        or observation_ids != mapping_ids
        or output["content"].encode("utf-8") not in payload.markdown
        or html.escape(output["content"]).encode("utf-8") not in payload.html
        or html.escape(payload.semantic_json.decode()).encode("utf-8") not in payload.html
        or meta["output_content_sha256"] != output["content_sha256"]
        or meta["parent_plan_sha256"] != semantic.get("parent_plan_sha256")
        or meta["source_snapshot_sha256"] != semantic.get("source_observation_sha256")
    ):
        raise NavigationDraftError("navigation review mapping or output seal is invalid")
    return review_package.ReviewPackageHashes(
        markdown_sha256=sha256_bytes(payload.markdown),
        html_sha256=sha256_bytes(payload.html),
        meta_sha256=sha256_bytes(payload.meta_json),
        semantic_sha256=sha256_bytes(payload.semantic_json),
        source_snapshot_sha256=semantic["source_observation_sha256"],
    )


def _revalidate_navigation_boundary(
    root: Path,
    semantic: Mapping[str, object],
) -> None:
    root_path = _canonical_absolute_path(root, "root")
    boundary = semantic.get("boundary")
    observations = semantic.get("source_observations")
    if type(boundary) is not dict or type(observations) is not list:
        raise NavigationDraftError("navigation boundary is invalid")
    project_home = boundary.get("project_home")
    if type(project_home) is not str:
        raise NavigationDraftError("project home is invalid")
    project_path = safety.require_no_symlink_components(
        project_home,
        root_path,
        "project home",
        error_type=NavigationDraftError,
    )
    _require_directory_identity(root_path, boundary.get("root_identity"), "root")
    _require_directory_identity(
        project_path,
        boundary.get("project_identity"),
        "project home",
    )
    try:
        current_policy_sha256 = workstream_curation.read_current_policy_sha256(
            root_path
        )
    except workstream_curation.WorkstreamCurationError as exc:
        raise NavigationDraftError("current Workstream policy cannot be verified") from exc
    if current_policy_sha256 != semantic.get("policy_sha256"):
        raise NavigationDraftError("Workstream policy changed before package seal")
    for observation in observations:
        if type(observation) is not dict:
            raise NavigationDraftError("source observation is invalid")
        _read_exact_source(root_path, observation)


def write_navigation_review(
    directory: Path,
    payload: review_package.ReviewPackagePayload,
    *,
    root: Path,
) -> review_package.ReviewPackageHashes:
    try:
        semantic = json.loads(payload.semantic_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NavigationDraftError("navigation review semantic JSON is invalid") from exc
    if type(semantic) is not dict:
        raise NavigationDraftError("navigation review semantic contract is invalid")
    _revalidate_navigation_boundary(root, semantic)
    try:
        hashes = review_package.write_validated_review_package(
            directory,
            payload,
            validate=validate_navigation_review,
        )
    except review_package.ReviewPackageError as exc:
        raise NavigationDraftError(
            "navigation Review Package cannot be written"
        ) from exc
    try:
        _revalidate_navigation_boundary(root, semantic)
    except NavigationDraftError:
        try:
            review_package.discard_unsealed_review_package(directory, payload)
        except review_package.ReviewPackageError as cleanup_error:
            raise NavigationDraftError(
                "stale navigation Review Package cleanup cannot be proven"
            ) from cleanup_error
        raise
    return hashes


def require_empty_navigation_review_directory(directory: Path) -> None:
    """Require a fresh destination without exposing package storage to the CLI."""

    try:
        review_package.require_empty_review_directory(directory)
    except review_package.ReviewPackageError as exc:
        raise NavigationDraftError(
            "navigation Review Package destination is not fresh"
        ) from exc


__all__ = [
    "CONTEXT_BOUND_INPUT_SCHEMA",
    "CONTEXT_BOUND_REVIEW_KIND",
    "CONTEXT_BOUND_SEMANTIC_SCHEMA",
    "CORPUS_CONSEQUENCE",
    "INPUT_SCHEMA",
    "NavigationDraftError",
    "SEMANTIC_SCHEMA",
    "compile_navigation_review",
    "compile_context_bound_navigation_review",
    "require_empty_navigation_review_directory",
    "validate_navigation_review",
    "validate_context_bound_navigation_review",
    "write_navigation_review",
    "write_context_bound_navigation_review",
]
