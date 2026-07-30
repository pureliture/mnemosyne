"""Typed, sealed approval-review data for workspace-sync Plans."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


APPROVAL_REVIEW_SCHEMA = "mnemosyne-workspace-sync-approval-review-v1"
WORKSPACE_SYNC_PLAN_V2_SCHEMA = "mnemosyne-workspace-sync-plan-v2"


_APPROVAL_REVIEW_KEYS = {
    "schema",
    "overview",
    "current_state_groups",
    "history_groups",
    "exclusions",
    "references",
}
_PLAN_V2_KEYS = {
    "schema",
    "schema_version",
    "created_at",
    "root",
    "workspace",
    "workstream",
    "workstream_status",
    "title",
    "summary",
    "claim_mode",
    "sanitization_policy_sha256",
    "bases",
    "effects",
    "approval_review",
}
_GROUP_KEYS = {"title", "items"}
_REFERENCE_KEYS = {"ref", "role"}


def _require_single_line_text(value: object, field: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\n" in value
        or "\r" in value
        or "\x00" in value
    ):
        raise ValueError(f"{field} must be a non-empty single-line string")
    return value


def _require_exact_keys(value: object, expected: set[str], field: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"{field} shape is invalid")
    return value


def _validate_groups(value: object, field: str) -> list[dict[str, Any]]:
    if type(value) is not list or not value:
        raise ValueError(f"{field} must contain at least one group")
    seen_titles: set[str] = set()
    groups: list[dict[str, Any]] = []
    for index, raw_group in enumerate(value):
        group = _require_exact_keys(raw_group, _GROUP_KEYS, f"{field}[{index}]")
        title = _require_single_line_text(group["title"], f"{field}[{index}].title")
        items = group["items"]
        if type(items) is not list or not items:
            raise ValueError(f"{field}[{index}].items must not be empty")
        if title in seen_titles:
            raise ValueError(f"{field} titles must be unique")
        seen_titles.add(title)
        seen_items: set[str] = set()
        for item_index, item in enumerate(items):
            text = _require_single_line_text(
                item,
                f"{field}[{index}].items[{item_index}]",
            )
            if text in seen_items:
                raise ValueError(f"{field}[{index}] items must be unique")
            seen_items.add(text)
        groups.append(group)
    return groups


def _validate_references(value: object) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise ValueError("references must be a list")
    seen_refs: set[str] = set()
    references: list[dict[str, Any]] = []
    for index, raw_reference in enumerate(value):
        reference = _require_exact_keys(raw_reference, _REFERENCE_KEYS, f"references[{index}]")
        ref = _require_single_line_text(reference["ref"], f"references[{index}].ref")
        _require_single_line_text(reference["role"], f"references[{index}].role")
        if ref in seen_refs:
            raise ValueError("references must not repeat a ref")
        seen_refs.add(ref)
        references.append(reference)
    return references


def validate_approval_review(value: object) -> dict[str, Any]:
    """Validate the approval data that is sealed inside a v2 workspace-sync Plan."""
    review = _require_exact_keys(value, _APPROVAL_REVIEW_KEYS, "approval_review")
    if review["schema"] != APPROVAL_REVIEW_SCHEMA:
        raise ValueError("approval_review schema is invalid")
    _require_single_line_text(review["overview"], "approval_review.overview")
    _validate_groups(review["current_state_groups"], "approval_review.current_state_groups")
    _validate_groups(review["history_groups"], "approval_review.history_groups")
    exclusions = review["exclusions"]
    if type(exclusions) is not list or not exclusions:
        raise ValueError("approval_review.exclusions must not be empty")
    seen_exclusions: set[str] = set()
    for index, exclusion in enumerate(exclusions):
        text = _require_single_line_text(exclusion, f"approval_review.exclusions[{index}]")
        if text in seen_exclusions:
            raise ValueError("approval_review.exclusions must be unique")
        seen_exclusions.add(text)
    _validate_references(review["references"])
    return review


def approval_review_text_values(value: object) -> list[str]:
    """Return all renderable text after validating *value*."""
    review = validate_approval_review(value)
    values = [review["overview"]]
    for group_key in ("current_state_groups", "history_groups"):
        for group in review[group_key]:
            values.append(group["title"])
            values.extend(group["items"])
    values.extend(review["exclusions"])
    for reference in review["references"]:
        values.extend((reference["ref"], reference["role"]))
    return values


def validate_workspace_sync_plan_v2(value: object) -> dict[str, Any]:
    """Validate only the v2 semantic fields needed by approval rendering/apply."""
    plan = _require_exact_keys(value, _PLAN_V2_KEYS, "workspace sync Plan")
    if (
        plan["schema"] != WORKSPACE_SYNC_PLAN_V2_SCHEMA
        or plan["schema_version"] != 2
        or plan["claim_mode"] != "HISTORICAL"
        or type(plan["workstream_status"]) is not str
        or plan["workstream_status"] not in {"new", "existing"}
    ):
        raise ValueError("workspace sync Plan v2 metadata is invalid")
    for field in ("created_at", "root", "workspace", "workstream", "title", "summary"):
        _require_single_line_text(plan[field], f"workspace sync Plan.{field}")
    if (
        type(plan["sanitization_policy_sha256"]) is not str
        or type(plan["bases"]) is not dict
        or type(plan["effects"]) is not list
        or len(plan["effects"]) != 2
    ):
        raise ValueError("workspace sync Plan v2 effects are invalid")
    validate_approval_review(plan["approval_review"])
    return plan


def _split_snapshot_frontmatter(text: str) -> tuple[list[str], str]:
    if not text.startswith("---\n"):
        raise ValueError("snapshot missing YAML frontmatter")
    end = text.find("\n---", 4)
    if end == -1:
        raise ValueError("snapshot frontmatter is not closed")
    frontmatter = text[4:end].strip("\n").splitlines()
    body = text[end + len("\n---") :]
    if body.startswith("\n"):
        body = body[1:]
    return frontmatter, body


def _source_refs_end(lines: list[str], start: int) -> int:
    index = start + 1
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if not line.startswith(" ") and not line.startswith("-") and ":" in line:
            break
        index += 1
    return index


def _upsert_snapshot_workstream(body: str, workstream: str, title: str, summary: str) -> str:
    lines = body.splitlines()
    entry_id = f"- id: {workstream}"
    latest_update = " ".join(f"{title}: {summary}".split())
    summary_line = " ".join(summary.split())
    replacement_fields = {
        "latest_update": f"  latest_update: {json.dumps(latest_update, ensure_ascii=False)}",
        "summary": f"  summary: {json.dumps(summary_line, ensure_ascii=False)}",
    }
    try:
        section_start = lines.index("## Workstreams")
    except ValueError:
        if lines and lines[-1]:
            lines.append("")
        lines.extend(
            (
                "## Workstreams",
                "",
                entry_id,
                "  status: active",
                replacement_fields["latest_update"],
                replacement_fields["summary"],
            )
        )
        return "\n".join(lines) + "\n"
    section_end = next(
        (index for index in range(section_start + 1, len(lines)) if lines[index].startswith("## ")),
        len(lines),
    )
    try:
        entry_start = lines.index(entry_id, section_start + 1, section_end)
    except ValueError:
        lines[section_end:section_end] = (
            entry_id,
            "  status: active",
            replacement_fields["latest_update"],
            replacement_fields["summary"],
            "",
        )
        return "\n".join(lines) + "\n"
    entry_end = next(
        (
            index
            for index in range(entry_start + 1, section_end)
            if lines[index].startswith("- id:")
        ),
        section_end,
    )
    seen: set[str] = set()
    for index in range(entry_start + 1, entry_end):
        field = lines[index].strip().partition(":")[0]
        if field in replacement_fields:
            lines[index] = replacement_fields[field]
            seen.add(field)
    for field in ("latest_update", "summary"):
        if field not in seen:
            lines.insert(entry_end, replacement_fields[field])
            entry_end += 1
    return "\n".join(lines) + "\n"


def _upsert_snapshot_current_state(
    body: str,
    workstream: str,
    current_state_groups: list[dict[str, Any]],
) -> str:
    lines = body.splitlines()
    entry_id = f"- id: {workstream}"
    try:
        section_start = lines.index("## Workstreams")
        section_end = next(
            (
                index
                for index in range(section_start + 1, len(lines))
                if lines[index].startswith("## ")
            ),
            len(lines),
        )
        entry_start = lines.index(entry_id, section_start + 1, section_end)
    except ValueError as exc:
        raise ValueError("workstream entry is unavailable for current-state update") from exc
    entry_end = next(
        (
            index
            for index in range(entry_start + 1, section_end)
            if lines[index].startswith("- id:")
        ),
        section_end,
    )
    current_state_start = next(
        (
            index
            for index in range(entry_start + 1, entry_end)
            if lines[index] == "  current_state:"
        ),
        None,
    )
    if current_state_start is None:
        insertion = entry_end
        while insertion > entry_start and not lines[insertion - 1]:
            insertion -= 1
    else:
        insertion = current_state_start
        current_state_end = next(
            (
                index
                for index in range(current_state_start + 1, entry_end)
                if lines[index].startswith("  ") and not lines[index].startswith("    ")
            ),
            entry_end,
        )
        del lines[current_state_start:current_state_end]
    current_state_lines = ["  current_state:"]
    for group in current_state_groups:
        for item in group["items"]:
            detail = f"{group['title']}: {item}"
            current_state_lines.append(f"    - {json.dumps(detail, ensure_ascii=False)}")
    lines[insertion:insertion] = current_state_lines
    return "\n".join(lines) + "\n"


def _slugify_title(title: str) -> str:
    normalized = "".join(
        character.lower() if character.isascii() and character.isalnum() else "-"
        for character in title
    ).strip("-")
    while "--" in normalized:
        normalized = normalized.replace("--", "-")
    return normalized or "memory-sync"


def _timestamp_for_filename(created_at: str) -> str:
    return created_at.replace("-", "").replace(":", "")


def workspace_root_from_registry(registry_text: str, workspace: str) -> str:
    """Read the workspace root with the same bounded registry grammar as planning."""
    in_workspaces = False
    current_slug: str | None = None
    workspaces: dict[str, dict[str, str]] = {}
    for raw_line in registry_text.splitlines():
        line_without_comment = raw_line.split("#", 1)[0].rstrip()
        if not line_without_comment.strip():
            continue
        indent = len(line_without_comment) - len(line_without_comment.lstrip(" "))
        line = line_without_comment.strip()
        if indent == 0:
            in_workspaces = line == "workspaces:"
            current_slug = None
            continue
        if not in_workspaces:
            continue
        if indent == 2 and line.endswith(":"):
            current_slug = line[:-1]
            workspaces[current_slug] = {}
            continue
        if indent == 4 and current_slug and ":" in line:
            key, value = line.split(":", 1)
            workspaces[current_slug][key.strip()] = value.strip().strip("\"'")
    return workspaces.get(workspace, {}).get("root", "")


def derive_workspace_sync_effects(
    *,
    root: str,
    workspace: str,
    workspace_root: str,
    workstream: str,
    created_at: str,
    title: str,
    summary: str,
    approval_review: object,
    snapshot_text: str,
) -> dict[str, str]:
    """Derive the only snapshot/history effects permitted by a sealed review."""
    review = validate_approval_review(approval_review)
    frontmatter, body = _split_snapshot_frontmatter(snapshot_text)
    workstream_status = (
        "existing" if f"- id: {workstream}" in body.splitlines() else "new"
    )
    slug = _slugify_title(title)
    refs = [
        f"memory-sync: {slug}",
        *(reference["ref"] for reference in review["references"]),
    ]
    existing_refs = {
        line.strip()[2:].strip()
        for line in frontmatter
        if line.strip().startswith("- ")
    }
    refs_to_add = [ref for ref in refs if ref not in existing_refs]
    updated_frontmatter: list[str] = []
    updated_at_seen = False
    source_refs_index: int | None = None
    for line in frontmatter:
        if line.startswith("updated_at:"):
            updated_frontmatter.append(f"updated_at: {created_at}")
            updated_at_seen = True
        else:
            if line == "source_refs:" and source_refs_index is None:
                source_refs_index = len(updated_frontmatter)
            updated_frontmatter.append(line)
    if not updated_at_seen:
        insert_at = source_refs_index if source_refs_index is not None else len(updated_frontmatter)
        updated_frontmatter.insert(insert_at, f"updated_at: {created_at}")
        if source_refs_index is not None:
            source_refs_index += 1
    if source_refs_index is None:
        updated_frontmatter.append("source_refs:")
        source_refs_index = len(updated_frontmatter) - 1
    insert_at = _source_refs_end(updated_frontmatter, source_refs_index)
    for ref in refs_to_add:
        updated_frontmatter.insert(insert_at, f"- {ref}")
        insert_at += 1
    snapshot_body = _upsert_snapshot_workstream(body, workstream, title, summary)
    snapshot_body = _upsert_snapshot_current_state(
        snapshot_body,
        workstream,
        review["current_state_groups"],
    )
    snapshot_final_text = "---\n" + "\n".join(updated_frontmatter) + "\n---\n" + snapshot_body
    approval_sections: list[str] = ["## 최신 상태에 반영한 내용", ""]
    for group in review["current_state_groups"]:
        approval_sections.extend((f"### {group['title']}", ""))
        approval_sections.extend(f"- {item}" for item in group["items"])
        approval_sections.append("")
    approval_sections.extend(("## 기록으로 남긴 내용", ""))
    for group in review["history_groups"]:
        approval_sections.extend((f"### {group['title']}", ""))
        approval_sections.extend(f"- {item}" for item in group["items"])
        approval_sections.append("")
    approval_sections.extend(("## 이번 기록에 포함하지 않은 내용", ""))
    approval_sections.extend(f"- {exclusion}" for exclusion in review["exclusions"])
    approval_sections.append("")
    source_refs = "\n".join(f"- {ref}" for ref in refs)
    rendered_approval_sections = "\n".join(approval_sections)
    history_final_text = f"""---
schema_version: 1
event_type: snapshot-update
workspace: {workspace}
workspace_root: {workspace_root}
workstream: {workstream}
created_at: {created_at}
source_refs:
{source_refs}
raw_log_policy: no raw command output, raw logs, raw file bodies, full environment dumps, credentials, token values, email values, secret-like values, and credential-like values were not persisted
transcript_policy: summary only; raw transcript content was not persisted
redaction_policy: sanitized summary and explicit source_refs only
---

# {title}

{summary}

{rendered_approval_sections}
## Boundary

This sync mutated only files under `{Path(root) / "memory" / workspace}`. It did not mutate Jira, Confluence, GitHub, repository source files, runtime state, deployments, graphify output, worktrees, or external services. It does not store raw logs, credentials, tokens, private keys, email values, exact endpoints, raw command output, raw transcript content, or full private bodies.
"""
    history_path = (
        f"memory/{workspace}/history/"
        f"{_timestamp_for_filename(created_at)}-{slug}.md"
    )
    return {
        "workstream_status": workstream_status,
        "history_path": history_path,
        "snapshot_final_text": snapshot_final_text,
        "history_final_text": history_final_text,
    }


def _inline_code(value: str) -> str:
    return value.replace("\\", "\\\\").replace("`", "\\`")


def _render_groups(lines: list[str], groups: list[dict[str, Any]]) -> None:
    for group in groups:
        lines.extend((f"### {group['title']}", ""))
        lines.extend(f"- {item}" for item in group["items"])
        lines.append("")


def render_workspace_sync_approval_card(value: object) -> str:
    """Render one stable Korean approval card from the exact sealed v2 Plan."""
    plan = validate_workspace_sync_plan_v2(value)
    review = validate_approval_review(plan["approval_review"])
    workstream_status = "기존" if plan["workstream_status"] == "existing" else "신규"
    exclusion_summary = review["exclusions"][0]
    if len(review["exclusions"]) > 1:
        exclusion_summary += f" 외 {len(review['exclusions']) - 1}건"

    lines = [
        f"# 승인 요청 — {plan['workspace']}",
        "",
        "## 한눈에 보기",
        f"> **{review['overview']}**",
        ">",
        f"> - **이번 동기화:** {plan['title']}",
        f"> - **저장할 요약:** {plan['summary']}",
        f"> - **기록 시각:** {plan['created_at']}",
        "> - **적용 결과:** 최신 상태 1개 갱신 · 기록 1건 추가",
        f"> - **저장 제외:** {exclusion_summary}",
        "",
        "---",
        "",
        "## 최신 상태에 반영할 내용",
        "",
        f"- **대상 workstream:** `{_inline_code(plan['workstream'])}` ({workstream_status})",
        "",
    ]
    _render_groups(lines, review["current_state_groups"])
    lines.extend(("## 기록으로 남길 내용", ""))
    _render_groups(lines, review["history_groups"])
    lines.extend(("## 이번 기록에 포함하지 않는 내용", ""))
    lines.extend(f"- {exclusion}" for exclusion in review["exclusions"])
    lines.extend(("", "## 참고 자료", ""))
    if review["references"]:
        lines.extend(
            f"- `{_inline_code(reference['ref'])}` — {reference['role']}"
            for reference in review["references"]
        )
    else:
        lines.append("- 별도로 대조한 참고 자료 없음")
    lines.extend(
        (
            "",
            "## 그 밖의 변경",
            "",
            "- 최신 상태(snapshot) 1개를 갱신합니다.",
            "- 기록(history) 1건을 추가합니다.",
            "- 승인 전에는 raw memory를 변경하지 않습니다.",
            "",
            "이 내용 그대로 적용할까요?",
        )
    )
    return "\n".join(lines) + "\n"
