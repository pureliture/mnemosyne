"""Plan-bound Review Package V2 compiler and independent fidelity validator."""

from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Optional

from . import canonical_curation, context_assembly
from .canonical_curation import CurationPlan
from .canonical_json import canonical_json_bytes, sha256_bytes
from . import review_package


SEMANTIC_SCHEMA = "mnemosyne-curation-review-semantic-v2"
REVIEW_KIND = "workstream-canonical-curation"
DECISION_ACTIONS_KO = ("전체 승인", "선택 승인", "거절", "보류")
REQUIRED_CATEGORIES = (
    "workstream_identity",
    "coverage",
    "structure",
    "item_identity",
    "classification",
    "rationale",
    "relations",
    "content_consequence",
    "uncertainty",
    "untouched_proof",
    "seal",
)
_CATEGORY_LABELS = {
    "workstream_identity": "Workstream 신원",
    "coverage": "조사 범위",
    "structure": "현재 구조와 제안 구조",
    "item_identity": "이동 항목",
    "classification": "문서 분류",
    "rationale": "변경 이유",
    "relations": "다른 Workstream과의 관계",
    "content_consequence": "내용에 생기는 결과",
    "uncertainty": "불확실성과 사람 판단",
    "untouched_proof": "건드리지 않는 항목",
    "seal": "봉인 정보",
}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RENDERED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_SEMANTIC_START = b"<!-- MNEMOSYNE-CURATION-SEMANTIC-V2 -->\n```json\n"
_SEMANTIC_END = b"```\n<!-- /MNEMOSYNE-CURATION-SEMANTIC-V2 -->\n"

CONTEXT_BOUND_SEMANTIC_SCHEMA = "mnemosyne-context-bound-curation-review-semantic-v3"
CONTEXT_BOUND_REVIEW_KIND = "workstream-context-bound-curation"
CONTEXT_BOUND_REQUIRED_CATEGORIES = REQUIRED_CATEGORIES + (
    "context_summary",
    "current_local_evidence",
)
_CONTEXT_BOUND_SEMANTIC_START = (
    b"<!-- MNEMOSYNE-CONTEXT-BOUND-CURATION-SEMANTIC-V3 -->\n```json\n"
)
_CONTEXT_BOUND_SEMANTIC_END = (
    b"```\n<!-- /MNEMOSYNE-CONTEXT-BOUND-CURATION-SEMANTIC-V3 -->\n"
)


class CurationReviewError(ValueError):
    """Review V2 bytes are incomplete, inconsistent or unsafe."""


def _semantic_for_plan(plan: CurationPlan) -> dict[str, object]:
    plan_value = plan.canonical_value
    effects = plan_value["effects"]
    observations = plan_value["source_observations"]
    findings = plan_value["findings"]
    categories = {
        "workstream_identity": {
            "id": plan.primary_workstream_id,
            "lifecycle": plan.captured_lifecycle,
            "policy_sha256": plan.policy_sha256,
            "project_home": plan.project_home,
            "project_identity": list(plan.project_identity),
            "root_identity": list(plan.root_identity),
        },
        "coverage": dict(plan.coverage),
        "structure": {
            "common_spine": plan_value["spine"],
            "current_paths": sorted(
                set(plan_value["unchanged_paths"])
                | {effect["source_path"] for effect in effects}
            ),
            "proposed_paths": sorted(
                set(plan_value["unchanged_paths"])
                | {effect["output_path"] for effect in effects}
            ),
        },
        "item_identity": {"effects": effects},
        "classification": {"source_observations": observations},
        "rationale": {
            "effects": [
                {
                    "effect_id": effect["effect_id"],
                    "human_readability": "논리적 common spine 역할 아래에서 찾기 쉬워집니다.",
                    "llm_retrievability": "Workstream과 문서 역할이 경로에서 명확해집니다.",
                    "reason": "내용은 유지하고 canonical path만 정돈합니다.",
                }
                for effect in effects
            ]
        },
        "relations": {
            "relation_change": "NONE_STAGE_A",
            "note": "다른 Workstream source를 흡수하거나 relation/projection을 쓰지 않습니다.",
        },
        "content_consequence": {
            "effects": [
                {
                    "action": effect["action"],
                    "effect_id": effect["effect_id"],
                    "old_path": effect["source_path"],
                    "new_path": effect["output_path"],
                    "retained_sha256": effect["expected_output_sha256"],
                    "bytes_changed": False,
                    "irreversible": False,
                }
                for effect in effects
            ]
        },
        "uncertainty": {
            "findings": findings,
            "human_decision_required": True,
            "status": "REVIEW_REQUIRED" if not findings else "BLOCKED_FINDINGS_PRESENT",
        },
        "untouched_proof": {
            "out_of_scope_paths": plan_value["out_of_scope_paths"],
            "unchanged_paths": plan_value["unchanged_paths"],
            "unselected_effects_are_not_writable": True,
        },
        "seal": {
            "cutoff_required": plan.cutoff_required,
            "effect_count": len(plan.effects),
            "irreversible_consequence": plan.irreversible_consequence,
            "plan_schema": plan.schema,
            "plan_sha256": plan.sha256,
            "source_observation_sha256": plan.source_observation_sha256,
            "spec_sha256": plan.spec_sha256,
        },
    }
    return {
        "categories": categories,
        "decision_actions": list(DECISION_ACTIONS_KO),
        "plan": plan_value,
        "plan_sha256": plan.sha256,
        "schema": SEMANTIC_SCHEMA,
        "source_observation_sha256": plan.source_observation_sha256,
    }


def _markdown_for_semantic(semantic: dict[str, object]) -> bytes:
    plan = semantic["plan"]
    categories = semantic["categories"]
    has_blocked_findings = bool(plan["findings"])
    lines = [
        "# Workstream 문서 정리 검토",
        "",
        (
            "상태: **검토 필요 — 차단 Finding 있음**"
            if has_blocked_findings
            else "상태: **검토 준비됨**"
        ),
        "",
        "이 문서는 원문 내용을 바꾸지 않고 경로만 정돈하는 Stage A Plan입니다.",
        "원본과 기존 Curation 통제 상태는 이 조사에서 수정하지 않았습니다.",
        "",
    ]
    if has_blocked_findings:
        lines.extend(
            (
                "차단된 Finding은 승인 대상이 아닙니다. 보강된 새 Plan이 나오기 전까지 그대로 둡니다.",
                "",
            )
        )
    lines.extend(("## 선택할 행동", ""))
    for index, action in enumerate(DECISION_ACTIONS_KO, 1):
        lines.append("%d. %s" % (index, action))
    lines.extend(
        (
            "",
            "선택을 실행하려면 이 문서에 표시된 exact Plan과 effect membership을 다시 지정해야 합니다.",
            "",
            "## 한눈에 보기",
            "",
            "- Workstream: `%s`" % plan["primary_workstream_id"],
            "- 현재 상태: `%s`" % plan["captured_lifecycle"],
            "- 이동/이름변경: %d건" % len(plan["effects"]),
            "- Plan SHA-256: `%s`" % semantic["plan_sha256"],
            "",
            "| Effect | 행동 | 현재 경로 | 제안 경로 | 내용 SHA-256 | 상태 |",
            "| --- | --- | --- | --- | --- | --- |",
        )
    )
    for effect in plan["effects"]:
        lines.append(
            "| `%s` | %s | `%s` | `%s` | `%s` | 검토 필요 |"
            % (
                effect["effect_id"],
                effect["action"],
                effect["source_path"],
                effect["output_path"],
                effect["expected_output_sha256"],
            )
        )
    for category in REQUIRED_CATEGORIES:
        lines.extend(
            (
                "",
                "## %s `category:%s`" % (_CATEGORY_LABELS[category], category),
                "",
                "```json",
                canonical_json_bytes(categories[category]).decode("utf-8").rstrip("\n"),
                "```",
            )
        )
    semantic_json = canonical_json_bytes(semantic)
    lines.extend(
        (
            "",
            "## 기술 부록",
            "",
            "아래 canonical JSON은 Markdown과 HTML이 같은 Plan을 보여 주는지 검증하는 공개 부록입니다.",
            "",
            _SEMANTIC_START.decode("ascii").rstrip("\n"),
            semantic_json.decode("utf-8").rstrip("\n"),
            _SEMANTIC_END.decode("ascii").rstrip("\n"),
            "",
        )
    )
    return "\n".join(lines).encode("utf-8")


def _html_for_semantic(
    semantic: dict[str, object],
    semantic_json: bytes,
    markdown_sha256: str,
) -> bytes:
    plan = semantic["plan"]
    categories = semantic["categories"]
    has_blocked_findings = bool(plan["findings"])
    status = (
        "검토 필요 — 차단 Finding 있음"
        if has_blocked_findings
        else "검토 준비됨"
    )
    parts = [
        '<!doctype html><html lang="ko-KR"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="mnemosyne-markdown-sha256" content="%s">'
        % markdown_sha256,
        '<title>Workstream 문서 정리 검토</title></head><body>',
        '<a href="#main-content">본문으로 건너뛰기</a>',
        '<main id="main-content" data-plan-sha256="%s">' % semantic["plan_sha256"],
        '<h1>Workstream 문서 정리 검토</h1>',
        '<p><strong>상태: %s</strong></p>' % html.escape(status),
        '<p>원문 내용을 바꾸지 않고 경로만 정돈하는 Stage A Plan입니다.</p>',
    ]
    if has_blocked_findings:
        parts.append(
            '<p>차단된 Finding은 승인 대상이 아닙니다. '
            '보강된 새 Plan이 나오기 전까지 그대로 둡니다.</p>'
        )
    parts.append('<h2>선택할 행동</h2><ol id="decision-actions">')
    for action in DECISION_ACTIONS_KO:
        parts.append(
            '<li data-decision-action="%s">%s</li>'
            % (html.escape(action, quote=True), html.escape(action))
        )
    parts.extend(
        (
            "</ol>",
            "<p>선택을 실행하려면 표시된 exact Plan과 effect membership을 다시 지정해야 합니다.</p>",
            "<h2>한눈에 보기</h2>",
            "<ul><li>Workstream: <code>%s</code></li>"
            "<li>현재 상태: <code>%s</code></li>"
            "<li>이동/이름변경: %d건</li>"
            "<li>Plan SHA-256: <code>%s</code></li></ul>"
            % (
                html.escape(plan["primary_workstream_id"]),
                html.escape(plan["captured_lifecycle"]),
                len(plan["effects"]),
                semantic["plan_sha256"],
            ),
            '<table><caption>이동 및 이름변경 effect</caption><thead><tr>'
            '<th scope="col">Effect</th><th scope="col">행동</th>'
            '<th scope="col">현재 경로</th><th scope="col">제안 경로</th>'
            '<th scope="col">내용 SHA-256</th><th scope="col">상태</th>'
            "</tr></thead><tbody>",
        )
    )
    for effect in plan["effects"]:
        parts.append(
            "<tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td>"
            "<td><code>%s</code></td><td><code>%s</code></td><td>검토 필요</td></tr>"
            % (
                html.escape(effect["effect_id"]),
                html.escape(effect["action"]),
                html.escape(effect["source_path"]),
                html.escape(effect["output_path"]),
                effect["expected_output_sha256"],
            )
        )
    parts.append("</tbody></table>")
    for category in REQUIRED_CATEGORIES:
        category_json = canonical_json_bytes(categories[category]).decode("utf-8")
        parts.extend(
            (
                '<section data-category="%s">' % category,
                "<h2>%s</h2>" % html.escape(_CATEGORY_LABELS[category]),
                "<pre><code>%s</code></pre>" % html.escape(category_json),
                "</section>",
            )
        )
    parts.extend(
        (
            "<h2>기술 부록</h2>",
            "<details><summary>canonical semantic JSON 열기</summary>",
            '<pre><code data-curation-semantic="v2">%s</code></pre>'
            % html.escape(semantic_json.decode("utf-8")),
            "</details></main></body></html>",
        )
    )
    return "".join(parts).encode("utf-8")


def compile_review(
    plan: CurationPlan,
    *,
    rendered_at: str,
    renderer_id: str,
) -> review_package.ReviewPackagePayload:
    """Compile one complete immutable Plan into three Review Package bytes."""

    if type(plan) is not CurationPlan:
        raise TypeError("plan must be CurationPlan")
    if type(rendered_at) is not str or _RENDERED_AT.fullmatch(rendered_at) is None:
        raise CurationReviewError("rendered_at must be canonical UTC seconds")
    if (
        type(renderer_id) is not str
        or not re.fullmatch(r"[a-z][a-z0-9._-]{1,63}", renderer_id)
    ):
        raise CurationReviewError("renderer_id is invalid")
    semantic = _semantic_for_plan(plan)
    semantic_json = canonical_json_bytes(semantic)
    markdown = _markdown_for_semantic(semantic)
    markdown_sha256 = sha256_bytes(markdown)
    rendered_html = _html_for_semantic(semantic, semantic_json, markdown_sha256)
    meta_json = canonical_json_bytes(
        {
            "effect_count": len(plan.effects),
            "html_sha256": sha256_bytes(rendered_html),
            "locale": "ko-KR",
            "markdown_sha256": markdown_sha256,
            "plan_schema": plan.schema,
            "plan_sha256": plan.sha256,
            "rendered_at": rendered_at,
            "renderer_id": renderer_id,
            "review_kind": REVIEW_KIND,
            "schema_version": 2,
            "semantic_schema": SEMANTIC_SCHEMA,
            "semantic_sha256": sha256_bytes(semantic_json),
            "source_observation_sha256": plan.source_observation_sha256,
            "spec_sha256": plan.spec_sha256,
        }
    )
    payload = review_package.ReviewPackagePayload(
        markdown=markdown,
        html=rendered_html,
        meta_json=meta_json,
        semantic_json=semantic_json,
    )
    validate_review_payload(payload)
    return payload


def _extract_semantic_from_markdown(markdown: bytes) -> bytes:
    if markdown.count(_SEMANTIC_START) != 1 or markdown.count(_SEMANTIC_END) != 1:
        raise CurationReviewError("review Markdown semantic appendix is missing")
    start = markdown.index(_SEMANTIC_START) + len(_SEMANTIC_START)
    end = markdown.index(_SEMANTIC_END, start)
    encoded = markdown[start:end]
    if not encoded.endswith(b"\n"):
        encoded += b"\n"
    return encoded


class _ReviewHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.categories: list[str] = []
        self.actions: list[str] = []
        self.errors: list[str] = []
        self.plan_sha256: Optional[str] = None
        self.markdown_sha256: Optional[str] = None
        self.semantic_parts: list[str] = []
        self._semantic_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        values = dict(attrs)
        if len(values) != len(attrs):
            self.errors.append("duplicate attribute")
        if tag in {"script", "iframe", "object", "embed"}:
            self.errors.append("executable or embedded content")
        for name in ("href", "src"):
            target = values.get(name)
            if target and re.match(r"^(?:https?:)?//", target, re.IGNORECASE):
                self.errors.append("external dependency")
        if tag == "section" and values.get("data-category") is not None:
            self.categories.append(values["data-category"] or "")
        if tag == "li" and values.get("data-decision-action") is not None:
            self.actions.append(values["data-decision-action"] or "")
        if tag == "main":
            self.plan_sha256 = values.get("data-plan-sha256")
        if tag == "meta" and values.get("name") == "mnemosyne-markdown-sha256":
            self.markdown_sha256 = values.get("content")
        if tag == "code" and values.get("data-curation-semantic") == "v2":
            self._semantic_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "code" and self._semantic_depth:
            self._semantic_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._semantic_depth:
            self.semantic_parts.append(data)


def _parse_meta(meta_json: bytes) -> dict[str, object]:
    expected_fields = {
        "effect_count",
        "html_sha256",
        "locale",
        "markdown_sha256",
        "plan_schema",
        "plan_sha256",
        "rendered_at",
        "renderer_id",
        "review_kind",
        "schema_version",
        "semantic_schema",
        "semantic_sha256",
        "source_observation_sha256",
        "spec_sha256",
    }
    try:
        value = json.loads(meta_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationReviewError("review meta JSON is invalid") from exc
    if (
        type(value) is not dict
        or set(value) != expected_fields
        or canonical_json_bytes(value) != meta_json
        or value["schema_version"] != 2
        or value["review_kind"] != REVIEW_KIND
        or value["semantic_schema"] != SEMANTIC_SCHEMA
        or value["locale"] != "ko-KR"
        or type(value["effect_count"]) is not int
        or value["effect_count"] < 0
        or type(value["rendered_at"]) is not str
        or _RENDERED_AT.fullmatch(value["rendered_at"]) is None
    ):
        raise CurationReviewError("review meta contract is invalid")
    for key in (
        "html_sha256",
        "markdown_sha256",
        "plan_sha256",
        "semantic_sha256",
        "source_observation_sha256",
        "spec_sha256",
    ):
        if type(value[key]) is not str or _HASH.fullmatch(value[key]) is None:
            raise CurationReviewError("review meta hash is invalid: %s" % key)
    return value


def validate_review_payload(
    payload: review_package.ReviewPackagePayload,
) -> review_package.ReviewPackageHashes:
    """Independently prove Markdown, HTML, semantic JSON and meta fidelity."""

    if type(payload) is not review_package.ReviewPackagePayload:
        raise TypeError("payload must be ReviewPackagePayload")
    meta = _parse_meta(payload.meta_json)
    if sha256_bytes(payload.markdown) != meta["markdown_sha256"]:
        raise CurationReviewError("review Markdown hash mismatch")
    if sha256_bytes(payload.html) != meta["html_sha256"]:
        raise CurationReviewError("review HTML hash mismatch")
    semantic_json = _extract_semantic_from_markdown(payload.markdown)
    if semantic_json != payload.semantic_json:
        raise CurationReviewError("review semantic manifest differs from Markdown")
    try:
        semantic = json.loads(semantic_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationReviewError("review semantic JSON is invalid") from exc
    if canonical_json_bytes(semantic) != semantic_json:
        raise CurationReviewError("review semantic JSON is not canonical")
    if (
        type(semantic) is not dict
        or set(semantic) != {
            "categories",
            "decision_actions",
            "plan",
            "plan_sha256",
            "schema",
            "source_observation_sha256",
        }
        or semantic["schema"] != SEMANTIC_SCHEMA
        or semantic["decision_actions"] != list(DECISION_ACTIONS_KO)
        or sha256_bytes(semantic_json) != meta["semantic_sha256"]
        or semantic["plan_sha256"] != meta["plan_sha256"]
        or semantic["source_observation_sha256"]
        != meta["source_observation_sha256"]
    ):
        raise CurationReviewError("review semantic contract is invalid")
    categories = semantic["categories"]
    if (
        type(categories) is not dict
        or tuple(categories) != tuple(sorted(REQUIRED_CATEGORIES))
        or set(categories) != set(REQUIRED_CATEGORIES)
        or any(type(categories[key]) is not dict or not categories[key] for key in REQUIRED_CATEGORIES)
    ):
        raise CurationReviewError("review category coverage is incomplete")
    plan = semantic["plan"]
    if (
        type(plan) is not dict
        or sha256_bytes(canonical_json_bytes(plan)) != semantic["plan_sha256"]
        or plan.get("source_observation_sha256")
        != semantic["source_observation_sha256"]
        or sha256_bytes(canonical_json_bytes(plan.get("source_observations")))
        != semantic["source_observation_sha256"]
        or plan.get("schema") != meta["plan_schema"]
        or plan.get("spec_sha256") != meta["spec_sha256"]
        or type(plan.get("effects")) is not list
        or len(plan["effects"]) != meta["effect_count"]
    ):
        raise CurationReviewError("review Plan binding is invalid")
    observations = {
        value.get("observation_id"): value
        for value in plan["source_observations"]
        if type(value) is dict
    }
    if len(observations) != len(plan["source_observations"]):
        raise CurationReviewError("review source observations are invalid")
    for effect in plan["effects"]:
        if type(effect) is not dict or set(effect) != {
            "action",
            "dependency_effect_ids",
            "effect_id",
            "expected_output_sha256",
            "input_observation_id",
            "output_path",
            "review_status",
            "risk_codes",
            "source_path",
        }:
            raise CurationReviewError("review effect is invalid")
        observation = observations.get(effect["input_observation_id"])
        if (
            effect["action"] not in {"move", "rename"}
            or type(effect["risk_codes"]) is not list
            or not effect["risk_codes"]
            or type(observation) is not dict
            or observation.get("relative_path") != effect["source_path"]
            or observation.get("content_sha256") != effect["expected_output_sha256"]
        ):
            raise CurationReviewError("review effect evidence is incomplete")
        for visible in (
            effect["effect_id"],
            effect["source_path"],
            effect["output_path"],
            effect["expected_output_sha256"],
        ):
            if visible.encode("utf-8") not in payload.markdown:
                raise CurationReviewError("review Markdown effect coverage is incomplete")
            if html.escape(visible).encode("utf-8") not in payload.html:
                raise CurationReviewError("review HTML effect coverage is incomplete")
    markdown_categories = tuple(
        re.findall(rb"`category:([a-z_]+)`", payload.markdown)
    )
    if tuple(value.decode("ascii") for value in markdown_categories) != REQUIRED_CATEGORIES:
        raise CurationReviewError("review Markdown category coverage is incomplete")
    parser = _ReviewHTMLParser()
    try:
        parser.feed(payload.html.decode("utf-8"))
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise CurationReviewError("review HTML is invalid") from exc
    if (
        parser.errors
        or tuple(parser.categories) != REQUIRED_CATEGORIES
        or tuple(parser.actions) != DECISION_ACTIONS_KO
        or parser.plan_sha256 != semantic["plan_sha256"]
        or parser.markdown_sha256 != meta["markdown_sha256"]
        or "".join(parser.semantic_parts).encode("utf-8") != semantic_json
        or b'<html lang="ko-KR">' not in payload.html
        or b'<main id="main-content"' not in payload.html
        or b"<details><summary>" not in payload.html
    ):
        raise CurationReviewError("review HTML fidelity or accessibility is incomplete")
    return review_package.ReviewPackageHashes(
        markdown_sha256=sha256_bytes(payload.markdown),
        html_sha256=sha256_bytes(payload.html),
        meta_sha256=sha256_bytes(payload.meta_json),
        semantic_sha256=sha256_bytes(semantic_json),
        source_snapshot_sha256=semantic["source_observation_sha256"],
    )


def write_review_package(
    directory: Path,
    payload: review_package.ReviewPackagePayload,
) -> review_package.ReviewPackageHashes:
    return review_package.write_validated_review_package(
        directory,
        payload,
        validate=validate_review_payload,
    )


def validate_review_directory(
    directory: Path,
    *,
    expected_plan_sha256: Optional[str] = None,
) -> review_package.ReviewPackageHashes:
    """Reread and validate a sealed V2 directory without rewriting it."""

    hashes, _plan = validate_review_directory_with_plan(
        directory,
        expected_plan_sha256=expected_plan_sha256,
    )
    return hashes


def validate_review_directory_with_plan(
    directory: Path,
    *,
    expected_plan_sha256: Optional[str] = None,
) -> tuple[review_package.ReviewPackageHashes, dict[str, object]]:
    """Validate one sealed directory and return its exact displayed Plan value."""

    if (
        expected_plan_sha256 is not None
        and (
            type(expected_plan_sha256) is not str
            or _HASH.fullmatch(expected_plan_sha256) is None
        )
    ):
        raise CurationReviewError("expected Plan hash is invalid")
    try:
        payload = review_package.read_review_package_payload(
            directory,
            derive_semantic=_extract_semantic_from_markdown,
        )
    except (TypeError, review_package.ReviewPackageError) as exc:
        raise CurationReviewError("sealed Review Package cannot be read") from exc
    hashes = validate_review_payload(payload)
    meta = _parse_meta(payload.meta_json)
    if (
        expected_plan_sha256 is not None
        and meta["plan_sha256"] != expected_plan_sha256
    ):
        raise CurationReviewError("sealed Review Package Plan hash mismatch")
    try:
        semantic = json.loads(payload.semantic_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationReviewError("sealed Review Package semantic JSON is invalid") from exc
    plan = semantic.get("plan") if type(semantic) is dict else None
    if type(plan) is not dict:
        raise CurationReviewError("sealed Review Package displayed Plan is invalid")
    return hashes, plan


__all__ = [
    "CurationReviewError",
    "DECISION_ACTIONS_KO",
    "REQUIRED_CATEGORIES",
    "compile_review",
    "validate_review_directory",
    "validate_review_directory_with_plan",
    "validate_review_payload",
    "write_review_package",
]


# Context-bound Review Package V3 deliberately has separate entry points from
# V2.  A V3 package makes the full context assembly visible exactly once in its
# semantic value and renders only carefully-derived local evidence around it.


def _require_context_bound_decoders() -> tuple[object, object]:
    assembly_decoder = getattr(context_assembly, "decode_context_assembly", None)
    plan_decoder = getattr(canonical_curation, "decode_context_bound_plan", None)
    if not callable(assembly_decoder) or not callable(plan_decoder):
        raise CurationReviewError("context-bound strict decoders are unavailable")
    return assembly_decoder, plan_decoder


def _current_local_evidence(
    assembly: context_assembly.ContextAssembly,
) -> list[dict[str, object]]:
    evidence = []
    for source in sorted(assembly.sources, key=lambda item: item.source_id):
        if source.mode != "CURRENT_LOCAL":
            continue
        projection = source.content_projection
        if projection is None:
            raise CurationReviewError("current local Context evidence is invalid")
        evidence.append(
            {
                "content_sha256": source.content_sha256,
                "excerpt": projection.excerpt,
                "excerpt_truncated": projection.excerpt_truncated,
                "headings": list(projection.headings),
                "headings_truncated": projection.headings_truncated,
                "identity": list(source.identity or ()),
                "observation_id": source.observation_id,
                "relative_path": source.relative_path,
                "snapshot_sha256": source.snapshot_sha256,
                "source_id": source.source_id,
                "title": projection.title,
            }
        )
    return evidence


def _context_summary(assembly: context_assembly.ContextAssembly) -> dict[str, object]:
    coverage = assembly.coverage.canonical_value
    claim_mode_counts: dict[str, int] = {}
    for claim in assembly.claims:
        claim_mode_counts[claim.mode] = claim_mode_counts.get(claim.mode, 0) + 1
    reference_ids = sorted(
        {
            reference_id
            for source in assembly.sources
            for reference_id in source.reference_source_ids
        }
        | {
            source.source_id
            for source in assembly.sources
            if source.mode == "UNVERIFIED_EXTERNAL"
        }
    )
    return {
        "claim_mode_counts": claim_mode_counts,
        "counts": {
            "current_local": sum(
                source.mode == "CURRENT_LOCAL" for source in assembly.sources
            ),
            "historical_hint": sum(
                source.mode == "HISTORICAL_HINT" for source in assembly.sources
            ),
            "unverified_external": sum(
                source.mode == "UNVERIFIED_EXTERNAL" for source in assembly.sources
            ),
        },
        "excluded_paths": coverage["excluded_paths"],
        "gap_paths": coverage["gap_paths"],
        "gaps": [
            gap.canonical_value
            for gap in sorted(assembly.gaps, key=lambda item: item.gap_id)
        ],
        "historical_sources": [
            source.canonical_value
            for source in sorted(assembly.sources, key=lambda item: item.source_id)
            if source.mode == "HISTORICAL_HINT"
        ],
        "outcome": assembly.outcome,
        "privacy_safe_reference_ids": reference_ids,
        "source_group_counts": coverage["source_group_counts"],
        "unverified_external_sources": [
            source.canonical_value
            for source in sorted(assembly.sources, key=lambda item: item.source_id)
            if source.mode == "UNVERIFIED_EXTERNAL"
        ],
    }


def _verified_context_bound_review_inputs(
    plan: canonical_curation.ContextBoundCurationPlan,
    complete: context_assembly.CompleteContextAssembly,
) -> tuple[context_assembly.ContextAssembly, list[dict[str, object]]]:
    if type(plan) is not canonical_curation.ContextBoundCurationPlan:
        raise TypeError("plan must be ContextBoundCurationPlan")
    if not isinstance(complete, context_assembly.CompleteContextAssembly):
        raise TypeError("complete_context_assembly must be CompleteContextAssembly")

    assembly = complete.assembly
    if any(source.mode == "CURRENT_EXTERNAL" for source in assembly.sources):
        raise CurationReviewError("current external Context sources are unsupported")
    assembly_sha256 = sha256_bytes(canonical_json_bytes(assembly.canonical_value))
    coverage_sha256 = sha256_bytes(canonical_json_bytes(assembly.coverage.canonical_value))
    if (
        complete.assembly_sha256 != assembly_sha256
        or complete.coverage_sha256 != coverage_sha256
        or plan.context_binding.assembly_sha256 != assembly_sha256
        or plan.context_binding.coverage_sha256 != coverage_sha256
        or plan.context_binding.outcome != context_assembly.COMPLETE
    ):
        raise CurationReviewError("Context Assembly binding is stale")
    if (
        plan.primary_workstream_id != assembly.workstream.id
        or plan.captured_lifecycle != assembly.workstream.lifecycle
        or plan.project_home != assembly.workstream.project_home
        or plan.policy_sha256 != assembly.policy_sha256
        or plan.root_identity != assembly.root_identity
        or plan.project_identity != assembly.project_identity
    ):
        raise CurationReviewError("Plan authority differs from Context Assembly")
    coverage = dict(plan.coverage)
    if (
        len(coverage) != len(plan.coverage)
        or coverage.get("context_outcome") != context_assembly.COMPLETE
        or coverage.get("context_assembly_sha256") != assembly_sha256
        or coverage.get("context_coverage_sha256") != coverage_sha256
    ):
        raise CurationReviewError("Plan Context coverage binding is invalid")

    expected = {
        source.observation_id: source
        for source in assembly.sources
        if source.mode == "CURRENT_LOCAL"
    }
    observations = {
        observation.observation_id: observation for observation in plan.source_observations
    }
    if set(expected) != set(observations):
        raise CurationReviewError("Plan current local membership differs from Context")
    for observation_id, source in expected.items():
        observation = observations[observation_id]
        actual_identity = (
            observation.device,
            observation.inode,
            observation.owner,
            observation.mode,
            observation.link_count,
            observation.size,
            observation.modified_time_ns,
        )
        if (
            source.source_id != source.observation_id
            or source.relative_path != observation.relative_path
            or source.identity != actual_identity
            or source.content_sha256 != observation.content_sha256
            or source.snapshot_sha256 != observation.snapshot_sha256
        ):
            raise CurationReviewError("Plan current local evidence differs from Context")

    assembly_decoder, plan_decoder = _require_context_bound_decoders()
    try:
        decoded_assembly = assembly_decoder(json.loads(assembly.canonical_bytes))
        decoded_plan = plan_decoder(json.loads(plan.canonical_bytes))
    except (TypeError, ValueError) as exc:
        raise CurationReviewError("Context-bound strict decode failed") from exc
    if (
        not isinstance(decoded_assembly, context_assembly.ContextAssembly)
        or type(decoded_plan) is not canonical_curation.ContextBoundCurationPlan
        or decoded_assembly.canonical_bytes != assembly.canonical_bytes
        or decoded_plan.canonical_bytes != plan.canonical_bytes
    ):
        raise CurationReviewError("Context-bound strict decode changed the authority")
    return assembly, _current_local_evidence(assembly)


def _context_bound_semantic(
    plan: canonical_curation.ContextBoundCurationPlan,
    assembly: context_assembly.ContextAssembly,
    evidence: list[dict[str, object]],
) -> dict[str, object]:
    plan_value = plan.canonical_value
    categories = {
        "workstream_identity": {
            "id": plan.primary_workstream_id,
            "lifecycle": plan.captured_lifecycle,
            "policy_sha256": plan.policy_sha256,
            "project_home": plan.project_home,
            "project_identity": list(plan.project_identity),
            "root_identity": list(plan.root_identity),
        },
        "coverage": dict(plan.coverage),
        "structure": {
            "common_spine": plan_value["spine"],
            "current_paths": sorted(
                set(plan_value["unchanged_paths"])
                | {effect["source_path"] for effect in plan_value["effects"]}
            ),
            "proposed_paths": sorted(
                set(plan_value["unchanged_paths"])
                | {effect["output_path"] for effect in plan_value["effects"]}
            ),
        },
        "item_identity": {"effects": plan_value["effects"]},
        "classification": {"source_observations": plan_value["source_observations"]},
        "rationale": {
            "effects": [
                {
                    "effect_id": effect["effect_id"],
                    "human_readability": "논리적 common spine 역할 아래에서 찾기 쉬워집니다.",
                    "llm_retrievability": "Workstream과 문서 역할이 경로에서 명확해집니다.",
                    "reason": "내용은 유지하고 canonical path만 정돈합니다.",
                }
                for effect in plan_value["effects"]
            ]
        },
        "relations": {
            "relation_change": "NONE_STAGE_A",
            "note": "다른 Workstream source를 흡수하거나 relation/projection을 쓰지 않습니다.",
        },
        "content_consequence": {
            "effects": [
                {
                    "action": effect["action"],
                    "effect_id": effect["effect_id"],
                    "old_path": effect["source_path"],
                    "new_path": effect["output_path"],
                    "retained_sha256": effect["expected_output_sha256"],
                    "bytes_changed": False,
                    "irreversible": False,
                }
                for effect in plan_value["effects"]
            ]
        },
        "uncertainty": {
            "findings": plan_value["findings"],
            "human_decision_required": True,
            "status": "REVIEW_REQUIRED" if not plan_value["findings"] else "BLOCKED_FINDINGS_PRESENT",
        },
        "untouched_proof": {
            "out_of_scope_paths": plan_value["out_of_scope_paths"],
            "unchanged_paths": plan_value["unchanged_paths"],
            "unselected_effects_are_not_writable": True,
        },
        "seal": {
            "context_assembly_sha256": plan.context_binding.assembly_sha256,
            "context_coverage_sha256": plan.context_binding.coverage_sha256,
            "plan_schema": plan.schema,
            "plan_sha256": plan.sha256,
            "source_observation_sha256": plan.plan.source_observation_sha256,
            "spec_sha256": plan_value["spec_sha256"],
        },
        "context_summary": _context_summary(assembly),
        "current_local_evidence": {"sources": evidence},
    }
    return {
        "categories": categories,
        "context_assembly": assembly.canonical_value,
        "context_assembly_sha256": assembly.sha256,
        "context_coverage_sha256": assembly.coverage_sha256,
        "context_assembly_outcome": assembly.outcome,
        "current_local_evidence": evidence,
        "decision_actions": list(DECISION_ACTIONS_KO),
        "plan": plan_value,
        "plan_sha256": plan.sha256,
        "schema": CONTEXT_BOUND_SEMANTIC_SCHEMA,
        "source_observation_sha256": plan.plan.source_observation_sha256,
    }


def _context_bound_markdown(semantic: dict[str, object]) -> bytes:
    plan = semantic["plan"]
    categories = semantic["categories"]
    summary = categories["context_summary"]
    has_blocked_findings = bool(plan["findings"])
    lines = [
        "# Workstream 문서 정리 검토",
        "",
        (
            "상태: **검토 필요 — 차단 Finding 있음**"
            if has_blocked_findings
            else "상태: **검토 준비됨**"
        ),
        "",
        "이 문서는 이동 Plan과, 그 Plan을 만들 때 확인한 현재 문맥을 함께 보여 줍니다.",
        "문서 이동은 이 검토만으로 실행되지 않습니다.",
        "",
    ]
    if has_blocked_findings:
        lines.extend(
            (
                "차단된 Finding은 승인 대상이 아닙니다. 보강된 새 Plan이 나오기 전까지 그대로 둡니다.",
                "",
            )
        )
    lines.extend(("## 선택할 행동", ""))
    for index, action in enumerate(DECISION_ACTIONS_KO, 1):
        lines.append("%d. %s" % (index, action))
    lines.extend(
        (
            "",
            "## 한눈에 보기",
            "",
            "- Workstream: `%s`" % plan["primary_workstream_id"],
            "- 현재 상태: `%s`" % plan["captured_lifecycle"],
            "- 이동/이름변경: %d건" % len(plan["effects"]),
            "- 현재 로컬 문서: %d건" % summary["counts"]["current_local"],
            "- 역사적 힌트: %d건" % summary["counts"]["historical_hint"],
            "- 미검증 외부 참조: %d건" % summary["counts"]["unverified_external"],
            "- Plan SHA-256: `%s`" % semantic["plan_sha256"],
            "- Context Assembly SHA-256: `%s`" % semantic["context_assembly_sha256"],
            "",
            "## Current Local Evidence",
            "",
        )
    )
    for source in semantic["current_local_evidence"]:
        lines.extend(
            (
                "### `%s` — `%s`" % (source["source_id"], source["relative_path"]),
                "",
                "- observation: `%s`" % source["observation_id"],
                "- identity: `%s`" % source["identity"],
                "- content SHA-256: `%s`" % source["content_sha256"],
                "- snapshot SHA-256: `%s`" % source["snapshot_sha256"],
                "- title: %s" % source["title"],
                "- headings: %s" % ", ".join(source["headings"]),
                "",
                "```text",
                source["excerpt"],
                "```",
                "",
            )
        )
    for category in CONTEXT_BOUND_REQUIRED_CATEGORIES:
        lines.extend(
            (
                "## %s `category:%s`" % (_CATEGORY_LABELS.get(category, category), category),
                "",
                "```json",
                canonical_json_bytes(categories[category]).decode("utf-8").rstrip("\n"),
                "```",
                "",
            )
        )
    semantic_json = canonical_json_bytes(semantic)
    lines.extend(
        (
            "## 기술 부록",
            "",
            _CONTEXT_BOUND_SEMANTIC_START.decode("ascii").rstrip("\n"),
            semantic_json.decode("utf-8").rstrip("\n"),
            _CONTEXT_BOUND_SEMANTIC_END.decode("ascii").rstrip("\n"),
            "",
        )
    )
    return "\n".join(lines).encode("utf-8")


def _context_bound_html(
    semantic: dict[str, object], semantic_json: bytes, markdown_sha256: str
) -> bytes:
    plan = semantic["plan"]
    summary = semantic["categories"]["context_summary"]
    has_blocked_findings = bool(plan["findings"])
    review_status = (
        "상태: 검토 필요 — 차단 Finding 있음"
        if has_blocked_findings
        else "상태: 검토 준비됨"
    )
    parts = [
        '<!doctype html><html lang="ko-KR"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="mnemosyne-markdown-sha256" content="%s">' % markdown_sha256,
        '<title>Workstream 문서 정리 검토</title></head><body>',
        '<a href="#main-content">본문으로 건너뛰기</a>',
        '<main id="main-content" data-plan-sha256="%s">' % semantic["plan_sha256"],
        '<h1>Workstream 문서 정리 검토</h1>',
        '<p><strong>%s</strong></p>' % html.escape(review_status),
        '<p>이 문서는 이동 Plan과, 그 Plan을 만들 때 확인한 현재 문맥을 함께 보여 줍니다.</p>',
    ]
    if has_blocked_findings:
        parts.append(
            '<p>차단된 Finding은 승인 대상이 아닙니다. 보강된 새 Plan이 나오기 전까지 그대로 둡니다.</p>'
        )
    parts.append('<h2>선택할 행동</h2><ol id="decision-actions">')
    for action in DECISION_ACTIONS_KO:
        parts.append('<li data-decision-action="%s">%s</li>' % (html.escape(action, quote=True), html.escape(action)))
    parts.extend(
        (
            "</ol><h2>한눈에 보기</h2>",
            "<ul><li>Workstream: <code>%s</code></li>"
            "<li>이동/이름변경: %d건</li><li>현재 로컬 문서: %d건</li>"
            "<li>역사적 힌트: %d건</li><li>미검증 외부 참조: %d건</li></ul>"
            % (
                html.escape(plan["primary_workstream_id"]),
                len(plan["effects"]),
                summary["counts"]["current_local"],
                summary["counts"]["historical_hint"],
                summary["counts"]["unverified_external"],
            ),
            "<h2>Current Local Evidence</h2>",
        )
    )
    for source in semantic["current_local_evidence"]:
        parts.extend(
            (
                "<section><h3><code>%s</code> — <code>%s</code></h3>"
                % (html.escape(source["source_id"]), html.escape(source["relative_path"])),
                "<dl><dt>observation</dt><dd><code>%s</code></dd>"
                "<dt>identity</dt><dd><code>%s</code></dd>"
                "<dt>content SHA-256</dt><dd><code>%s</code></dd>"
                "<dt>snapshot SHA-256</dt><dd><code>%s</code></dd>"
                "<dt>title</dt><dd>%s</dd><dt>headings</dt><dd>%s</dd></dl>"
                % (
                    html.escape(source["observation_id"]), html.escape(str(source["identity"])),
                    source["content_sha256"], source["snapshot_sha256"], html.escape(source["title"]),
                    html.escape(", ".join(source["headings"])),
                ),
                "<pre><code>%s</code></pre></section>" % html.escape(source["excerpt"]),
            )
        )
    for category in CONTEXT_BOUND_REQUIRED_CATEGORIES:
        category_json = canonical_json_bytes(semantic["categories"][category]).decode("utf-8")
        parts.extend(
            (
                '<section data-category="%s">' % category,
                "<h2>%s</h2>" % html.escape(_CATEGORY_LABELS.get(category, category)),
                "<pre><code>%s</code></pre>" % html.escape(category_json),
                "</section>",
            )
        )
    parts.extend(
        (
            "<h2>기술 부록</h2><details><summary>canonical semantic JSON 열기</summary>",
            '<pre><code data-curation-semantic="context-v3">%s</code></pre>' % html.escape(semantic_json.decode("utf-8")),
            "</details></main></body></html>",
        )
    )
    return "".join(parts).encode("utf-8")


def compile_context_bound_review(
    plan: canonical_curation.ContextBoundCurationPlan,
    *,
    context_assembly: context_assembly.CompleteContextAssembly,
    rendered_at: str,
    renderer_id: str,
) -> review_package.ReviewPackagePayload:
    """Compile one complete Context Assembly and its exact bound Plan as V3."""
    if type(rendered_at) is not str or _RENDERED_AT.fullmatch(rendered_at) is None:
        raise CurationReviewError("rendered_at must be canonical UTC seconds")
    if type(renderer_id) is not str or not re.fullmatch(r"[a-z][a-z0-9._-]{1,63}", renderer_id):
        raise CurationReviewError("renderer_id is invalid")
    assembly, evidence = _verified_context_bound_review_inputs(plan, context_assembly)
    semantic = _context_bound_semantic(plan, assembly, evidence)
    semantic_json = canonical_json_bytes(semantic)
    markdown = _context_bound_markdown(semantic)
    markdown_sha256 = sha256_bytes(markdown)
    rendered_html = _context_bound_html(semantic, semantic_json, markdown_sha256)
    meta_json = canonical_json_bytes(
        {
            "context_assembly_sha256": assembly.sha256,
            "context_assembly_outcome": assembly.outcome,
            "context_coverage_sha256": assembly.coverage_sha256,
            "context_summary": _context_summary(assembly),
            "current_local_count": len(evidence),
            "effect_count": len(plan.effects),
            "html_sha256": sha256_bytes(rendered_html),
            "locale": "ko-KR",
            "markdown_sha256": markdown_sha256,
            "plan_schema": plan.schema,
            "plan_sha256": plan.sha256,
            "rendered_at": rendered_at,
            "renderer_id": renderer_id,
            "review_kind": CONTEXT_BOUND_REVIEW_KIND,
            "schema_version": 3,
            "sealed": True,
            "semantic_schema": CONTEXT_BOUND_SEMANTIC_SCHEMA,
            "semantic_sha256": sha256_bytes(semantic_json),
            "source_observation_sha256": plan.plan.source_observation_sha256,
            "spec_sha256": plan.canonical_value["spec_sha256"],
        }
    )
    payload = review_package.ReviewPackagePayload(markdown, rendered_html, meta_json, semantic_json)
    validate_context_bound_review_payload(payload)
    return payload


def _extract_context_bound_semantic_from_markdown(markdown: bytes) -> bytes:
    if (
        markdown.count(_CONTEXT_BOUND_SEMANTIC_START) != 1
        or markdown.count(_CONTEXT_BOUND_SEMANTIC_END) != 1
    ):
        raise CurationReviewError("context-bound Review Markdown semantic appendix is missing")
    start = markdown.index(_CONTEXT_BOUND_SEMANTIC_START) + len(_CONTEXT_BOUND_SEMANTIC_START)
    end = markdown.index(_CONTEXT_BOUND_SEMANTIC_END, start)
    value = markdown[start:end]
    return value if value.endswith(b"\n") else value + b"\n"


class _ContextBoundReviewHTMLParser(_ReviewHTMLParser):
    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        super().handle_starttag(tag, attrs)
        values = dict(attrs)
        if tag == "code" and values.get("data-curation-semantic") == "context-v3":
            self._semantic_depth += 1


def _parse_context_bound_review_meta(meta_json: bytes) -> dict[str, object]:
    fields = {
        "context_assembly_sha256",
        "context_assembly_outcome",
        "context_coverage_sha256",
        "context_summary",
        "current_local_count",
        "effect_count",
        "html_sha256",
        "locale",
        "markdown_sha256",
        "plan_schema",
        "plan_sha256",
        "rendered_at",
        "renderer_id",
        "review_kind",
        "schema_version",
        "sealed",
        "semantic_schema",
        "semantic_sha256",
        "source_observation_sha256",
        "spec_sha256",
    }
    try:
        value = json.loads(meta_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationReviewError("context-bound review meta JSON is invalid") from exc
    if (
        type(value) is not dict
        or set(value) != fields
        or canonical_json_bytes(value) != meta_json
        or value["schema_version"] != 3
        or value["review_kind"] != CONTEXT_BOUND_REVIEW_KIND
        or value["semantic_schema"] != CONTEXT_BOUND_SEMANTIC_SCHEMA
        or value["locale"] != "ko-KR"
        or value["context_assembly_outcome"] != context_assembly.COMPLETE
        or value["sealed"] is not True
        or type(value["context_summary"]) is not dict
        or type(value["effect_count"]) is not int
        or value["effect_count"] < 0
        or type(value["current_local_count"]) is not int
        or value["current_local_count"] < 0
        or type(value["rendered_at"]) is not str
        or _RENDERED_AT.fullmatch(value["rendered_at"]) is None
        or type(value["renderer_id"]) is not str
        or re.fullmatch(r"[a-z][a-z0-9._-]{1,63}", value["renderer_id"]) is None
    ):
        raise CurationReviewError("context-bound review meta contract is invalid")
    for key in (
        "context_assembly_sha256",
        "context_coverage_sha256",
        "html_sha256",
        "markdown_sha256",
        "plan_sha256",
        "semantic_sha256",
        "source_observation_sha256",
        "spec_sha256",
    ):
        if type(value[key]) is not str or _HASH.fullmatch(value[key]) is None:
            raise CurationReviewError("context-bound review meta hash is invalid: %s" % key)
    return value


def _decode_context_bound_semantic(
    semantic: dict[str, object], meta: dict[str, object]
) -> tuple[canonical_curation.ContextBoundCurationPlan, context_assembly.ContextAssembly]:
    if (
        type(semantic) is not dict
        or set(semantic) != {
            "categories",
            "context_assembly",
            "context_assembly_sha256",
            "context_assembly_outcome",
            "context_coverage_sha256",
            "current_local_evidence",
            "decision_actions",
            "plan",
            "plan_sha256",
            "schema",
            "source_observation_sha256",
        }
        or semantic["schema"] != CONTEXT_BOUND_SEMANTIC_SCHEMA
        or semantic["decision_actions"] != list(DECISION_ACTIONS_KO)
        or semantic["plan_sha256"] != meta["plan_sha256"]
        or semantic["context_assembly_sha256"] != meta["context_assembly_sha256"]
        or semantic["context_assembly_outcome"] != meta["context_assembly_outcome"]
        or semantic["context_coverage_sha256"] != meta["context_coverage_sha256"]
        or semantic["source_observation_sha256"] != meta["source_observation_sha256"]
    ):
        raise CurationReviewError("context-bound review semantic contract is invalid")
    categories = semantic["categories"]
    if (
        type(categories) is not dict
        or set(categories) != set(CONTEXT_BOUND_REQUIRED_CATEGORIES)
        or any(type(categories[key]) is not dict or not categories[key] for key in CONTEXT_BOUND_REQUIRED_CATEGORIES)
    ):
        raise CurationReviewError("context-bound review category coverage is incomplete")
    assembly_decoder, plan_decoder = _require_context_bound_decoders()
    try:
        decoded_assembly = assembly_decoder(semantic["context_assembly"])
        decoded_plan = plan_decoder(semantic["plan"])
    except (TypeError, ValueError) as exc:
        raise CurationReviewError("context-bound review strict decode failed") from exc
    if (
        not isinstance(decoded_assembly, context_assembly.ContextAssembly)
        or type(decoded_plan) is not canonical_curation.ContextBoundCurationPlan
        or decoded_assembly.canonical_value != semantic["context_assembly"]
        or decoded_plan.canonical_value != semantic["plan"]
        or decoded_assembly.sha256 != semantic["context_assembly_sha256"]
        or decoded_assembly.coverage_sha256 != semantic["context_coverage_sha256"]
        or decoded_plan.sha256 != semantic["plan_sha256"]
        or decoded_plan.plan.source_observation_sha256 != semantic["source_observation_sha256"]
        or decoded_plan.schema != meta["plan_schema"]
        or decoded_plan.canonical_value["spec_sha256"] != meta["spec_sha256"]
    ):
        raise CurationReviewError("context-bound review authority binding is invalid")
    complete = decoded_assembly.require_complete(
        expected_workstream=decoded_assembly.workstream,
        expected_policy_sha256=decoded_assembly.policy_sha256,
        expected_root_identity=decoded_assembly.root_identity,
        expected_project_identity=decoded_assembly.project_identity,
        expected_assembly_sha256=decoded_assembly.sha256,
        expected_coverage_sha256=decoded_assembly.coverage_sha256,
    )
    _assembly, evidence = _verified_context_bound_review_inputs(decoded_plan, complete)
    if semantic["current_local_evidence"] != evidence:
        raise CurationReviewError("context-bound current local evidence differs from Context")
    if categories["current_local_evidence"] != {"sources": evidence}:
        raise CurationReviewError("context-bound category evidence differs from Context")
    if categories["context_summary"] != _context_summary(decoded_assembly):
        raise CurationReviewError("context-bound category summary differs from Context")
    if meta["context_summary"] != categories["context_summary"]:
        raise CurationReviewError("context-bound meta summary differs from Context")
    if semantic["context_assembly_outcome"] != decoded_assembly.outcome:
        raise CurationReviewError("context-bound assembly outcome differs from Context")
    return decoded_plan, decoded_assembly


def validate_context_bound_review_payload(
    payload: review_package.ReviewPackagePayload,
) -> review_package.ReviewPackageHashes:
    """Independently validate only Context-bound Review Package V3 bytes."""
    if type(payload) is not review_package.ReviewPackagePayload:
        raise TypeError("payload must be ReviewPackagePayload")
    meta = _parse_context_bound_review_meta(payload.meta_json)
    if (
        sha256_bytes(payload.markdown) != meta["markdown_sha256"]
        or sha256_bytes(payload.html) != meta["html_sha256"]
    ):
        raise CurationReviewError("context-bound review artifact hash mismatch")
    semantic_json = _extract_context_bound_semantic_from_markdown(payload.markdown)
    if semantic_json != payload.semantic_json:
        raise CurationReviewError("context-bound semantic differs from Markdown")
    try:
        semantic = json.loads(semantic_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationReviewError("context-bound review semantic JSON is invalid") from exc
    if (
        canonical_json_bytes(semantic) != semantic_json
        or sha256_bytes(semantic_json) != meta["semantic_sha256"]
    ):
        raise CurationReviewError("context-bound review semantic JSON is not canonical")
    plan, assembly = _decode_context_bound_semantic(semantic, meta)
    if assembly.outcome != context_assembly.COMPLETE:
        raise CurationReviewError("context-bound Review requires complete Context")
    if len(semantic["current_local_evidence"]) != meta["current_local_count"]:
        raise CurationReviewError("context-bound current local count is invalid")
    if len(plan.effects) != meta["effect_count"]:
        raise CurationReviewError("context-bound effect count is invalid")
    markdown_categories = tuple(
        value.decode("ascii")
        for value in re.findall(rb"`category:([a-z_]+)`", payload.markdown)
    )
    parser = _ContextBoundReviewHTMLParser()
    try:
        parser.feed(payload.html.decode("utf-8"))
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise CurationReviewError("context-bound review HTML is invalid") from exc
    if (
        markdown_categories != CONTEXT_BOUND_REQUIRED_CATEGORIES
        or parser.errors
        or tuple(parser.categories) != CONTEXT_BOUND_REQUIRED_CATEGORIES
        or tuple(parser.actions) != DECISION_ACTIONS_KO
        or parser.plan_sha256 != plan.sha256
        or parser.markdown_sha256 != meta["markdown_sha256"]
        or "".join(parser.semantic_parts).encode("utf-8") != semantic_json
        or b'<html lang="ko-KR">' not in payload.html
        or b'<main id="main-content"' not in payload.html
        or b"<details><summary>" not in payload.html
    ):
        raise CurationReviewError("context-bound review HTML fidelity is incomplete")
    for source in semantic["current_local_evidence"]:
        for visible in (
            source["source_id"], source["relative_path"], source["content_sha256"],
            source["snapshot_sha256"], source["title"], source["excerpt"],
        ):
            if visible.encode("utf-8") not in payload.markdown:
                raise CurationReviewError("current local evidence is missing from Markdown")
            if html.escape(visible).encode("utf-8") not in payload.html:
                raise CurationReviewError("current local evidence is missing from HTML")
    return review_package.ReviewPackageHashes(
        markdown_sha256=sha256_bytes(payload.markdown),
        html_sha256=sha256_bytes(payload.html),
        meta_sha256=sha256_bytes(payload.meta_json),
        semantic_sha256=sha256_bytes(semantic_json),
        source_snapshot_sha256=plan.plan.source_observation_sha256,
    )


def write_context_bound_review_package(
    directory: Path,
    payload: review_package.ReviewPackagePayload,
    *,
    before_final_seal: Optional[Callable[[], None]] = None,
) -> review_package.ReviewPackageHashes:
    """Write only a V3 payload through the shared three-file sealed store."""
    return review_package.write_validated_review_package(
        directory,
        payload,
        validate=validate_context_bound_review_payload,
        before_final_seal=before_final_seal,
    )


def validate_context_bound_review_directory(
    directory: Path,
    *,
    expected_plan_sha256: Optional[str] = None,
) -> tuple[
    review_package.ReviewPackageHashes,
    dict[str, object],
    context_assembly.ContextAssembly,
]:
    """Reread a sealed V3 package and return its exact Plan and Context."""
    if (
        expected_plan_sha256 is not None
        and (type(expected_plan_sha256) is not str or _HASH.fullmatch(expected_plan_sha256) is None)
    ):
        raise CurationReviewError("expected Plan hash is invalid")
    try:
        payload = review_package.read_review_package_payload(
            directory,
            derive_semantic=_extract_context_bound_semantic_from_markdown,
        )
    except (TypeError, review_package.ReviewPackageError) as exc:
        raise CurationReviewError("sealed context-bound Review Package cannot be read") from exc
    hashes = validate_context_bound_review_payload(payload)
    meta = _parse_context_bound_review_meta(payload.meta_json)
    if expected_plan_sha256 is not None and meta["plan_sha256"] != expected_plan_sha256:
        raise CurationReviewError("sealed context-bound Review Package Plan hash mismatch")
    try:
        semantic = json.loads(payload.semantic_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationReviewError("sealed context-bound review semantic JSON is invalid") from exc
    _plan, assembly = _decode_context_bound_semantic(semantic, meta)
    return hashes, semantic["plan"], assembly


__all__ += [
    "CONTEXT_BOUND_REVIEW_KIND",
    "CONTEXT_BOUND_REQUIRED_CATEGORIES",
    "CONTEXT_BOUND_SEMANTIC_SCHEMA",
    "compile_context_bound_review",
    "validate_context_bound_review_directory",
    "validate_context_bound_review_payload",
    "write_context_bound_review_package",
]
