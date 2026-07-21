"""Review Package compiler and fidelity validator for irreversible M3 Plans."""

from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

from . import canonical_curation_m3 as domain
from . import review_package
from .canonical_json import canonical_json_bytes, sha256_bytes


SEMANTIC_SCHEMA = "mnemosyne-curation-review-semantic-v3"
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
    "item_identity": "변환 항목",
    "classification": "문서 분류",
    "rationale": "변경 이유와 원본 연결",
    "relations": "다른 Workstream과의 관계",
    "content_consequence": "완성 결과와 사라지는 내용",
    "uncertainty": "불확실성과 사람 판단",
    "untouched_proof": "건드리지 않는 항목",
    "seal": "봉인과 복구 불가 경계",
}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RENDERED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
_SEMANTIC_START = b"<!-- MNEMOSYNE-CURATION-SEMANTIC-V3 -->\n```json\n"
_SEMANTIC_END = b"```\n<!-- /MNEMOSYNE-CURATION-SEMANTIC-V3 -->\n"


class CurationReviewError(ValueError):
    """The M3 Review Package is incomplete, inconsistent or unsafe."""


def _semantic_for_plan(plan: domain.TransformationPlan) -> dict[str, object]:
    plan_value = plan.canonical_value
    effects = plan_value["effects"]
    observations = plan_value["source_observations"]
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
                | {item["relative_path"] for item in observations}
            ),
            "proposed_final_paths": plan_value["final_paths"],
        },
        "item_identity": {"effects": effects},
        "classification": {"source_observations": observations},
        "rationale": {
            "effects": [
                {
                    "action": effect["action"],
                    "effect_id": effect["effect_id"],
                    "source_output_mappings": effect["source_output_mappings"],
                }
                for effect in effects
            ],
            "meaning_preservation_claim": "HUMAN_REVIEW_REQUIRED",
        },
        "relations": {
            "relation_change": "NONE_M3",
            "note": "M4 projection 또는 relation writer는 이 Plan에 포함되지 않습니다.",
        },
        "content_consequence": {
            "effects": [
                {
                    "action": effect["action"],
                    "disappearing_content": effect["disappearing_content"],
                    "effect_id": effect["effect_id"],
                    "input_observation_ids": effect["input_observation_ids"],
                    "irreversible": effect["irreversible"],
                    "outputs": effect["outputs"],
                    "source_output_mappings": effect["source_output_mappings"],
                }
                for effect in effects
            ],
            "irreversible_consequence": plan.irreversible_consequence,
            "superseded_source_paths": sorted(
                item["relative_path"] for item in observations
            ),
        },
        "uncertainty": {
            "findings": plan_value["findings"],
            "human_decision_required": True,
            "status": (
                "BLOCKED_FINDINGS_PRESENT"
                if plan.findings
                else "REVIEW_REQUIRED"
            ),
        },
        "untouched_proof": {
            "out_of_scope_paths": plan_value["out_of_scope_paths"],
            "unchanged_paths": plan_value["unchanged_paths"],
            "unselected_effects_are_not_writable": True,
        },
        "seal": {
            "cutoff_required": True,
            "effect_count": len(plan.effects),
            "irreversible_consequence": plan.irreversible_consequence,
            "output_manifest_sha256": plan.output_manifest_sha256,
            "plan_schema": plan.schema,
            "plan_sha256": plan.sha256,
            "source_observation_sha256": plan.source_observation_sha256,
            "spec_sha256": plan.spec_sha256,
        },
    }
    return {
        "categories": categories,
        "decision_actions": list(DECISION_ACTIONS_KO),
        "output_manifest_sha256": plan.output_manifest_sha256,
        "plan": plan_value,
        "plan_sha256": plan.sha256,
        "schema": SEMANTIC_SCHEMA,
        "source_observation_sha256": plan.source_observation_sha256,
    }


def _markdown_for_semantic(semantic: dict[str, object]) -> bytes:
    plan = semantic["plan"]
    categories = semantic["categories"]
    blocked = bool(plan["findings"])
    lines = [
        "# Workstream 문서 변환 검토",
        "",
        "상태: **%s**"
        % ("검토 불가 — 차단 Finding 있음" if blocked else "검토 필요"),
        "",
        "아래 결과물 전체와 원본→결과 연결을 검토한 뒤에만 승인할 수 있습니다.",
        "",
        "## 선택할 행동",
        "",
    ]
    lines.extend("%d. %s" % (index, action) for index, action in enumerate(DECISION_ACTIONS_KO, 1))
    lines.extend(
        (
            "",
            "## 복구 불가 결과",
            "",
            plan["irreversible_consequence"],
            "",
            "## 완성 결과물 전체",
            "",
        )
    )
    for effect in plan["effects"]:
        lines.extend(("### Effect `%s`" % effect["effect_id"], ""))
        for output in effect["outputs"]:
            lines.extend(
                (
                    "#### Output `%s` — `%s`"
                    % (output["output_id"], output["output_path"]),
                    "",
                    output["content"],
                    "",
                    "SHA-256: `%s`" % output["content_sha256"],
                    "",
                )
            )
    for category in REQUIRED_CATEGORIES:
        lines.extend(
            (
                "## %s `category:%s`" % (_CATEGORY_LABELS[category], category),
                "",
                "```json",
                canonical_json_bytes(categories[category]).decode().rstrip("\n"),
                "```",
                "",
            )
        )
    semantic_json = canonical_json_bytes(semantic)
    lines.extend(
        (
            "## 기술 부록",
            "",
            _SEMANTIC_START.decode().rstrip("\n"),
            semantic_json.decode().rstrip("\n"),
            _SEMANTIC_END.decode().rstrip("\n"),
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
    blocked = bool(plan["findings"])
    parts = [
        '<!doctype html><html lang="ko-KR"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="mnemosyne-markdown-sha256" content="%s">'
        % markdown_sha256,
        "<title>Workstream 문서 변환 검토</title></head><body>",
        '<a href="#main-content">본문으로 건너뛰기</a>',
        '<main id="main-content" data-plan-sha256="%s">' % semantic["plan_sha256"],
        "<h1>Workstream 문서 변환 검토</h1>",
        "<p><strong>상태: %s</strong></p>"
        % ("검토 불가 — 차단 Finding 있음" if blocked else "검토 필요"),
        "<h2>선택할 행동</h2><ol id=\"decision-actions\">",
    ]
    for action in DECISION_ACTIONS_KO:
        parts.append(
            '<li data-decision-action="%s">%s</li>'
            % (html.escape(action, quote=True), html.escape(action))
        )
    parts.extend(
        (
            "</ol>",
            "<h2>복구 불가 결과</h2><p>%s</p>"
            % html.escape(plan["irreversible_consequence"]),
            "<h2>완성 결과물 전체</h2>",
        )
    )
    for effect in plan["effects"]:
        parts.append("<section><h3>Effect <code>%s</code></h3>" % html.escape(effect["effect_id"]))
        for output in effect["outputs"]:
            parts.extend(
                (
                    "<h4>Output <code>%s</code> — <code>%s</code></h4>"
                    % (html.escape(output["output_id"]), html.escape(output["output_path"])),
                    "<pre><code>%s</code></pre>" % html.escape(output["content"]),
                    "<p>SHA-256: <code>%s</code></p>" % output["content_sha256"],
                )
            )
        parts.append("</section>")
    for category in REQUIRED_CATEGORIES:
        parts.extend(
            (
                '<section data-category="%s">' % category,
                "<h2>%s</h2>" % html.escape(_CATEGORY_LABELS[category]),
                "<pre><code>%s</code></pre>"
                % html.escape(canonical_json_bytes(semantic["categories"][category]).decode()),
                "</section>",
            )
        )
    parts.extend(
        (
            "<h2>기술 부록</h2>",
            "<details><summary>canonical semantic JSON 열기</summary>",
            '<pre><code data-curation-semantic="m3">%s</code></pre>'
            % html.escape(semantic_json.decode()),
            "</details></main></body></html>",
        )
    )
    return "".join(parts).encode("utf-8")


def compile_review(
    plan: domain.TransformationPlan,
    *,
    rendered_at: str,
    renderer_id: str,
) -> review_package.ReviewPackagePayload:
    if type(plan) is not domain.TransformationPlan:
        raise TypeError("plan must be TransformationPlan")
    if type(rendered_at) is not str or _RENDERED_AT.fullmatch(rendered_at) is None:
        raise CurationReviewError("rendered_at must be canonical UTC seconds")
    if type(renderer_id) is not str or not re.fullmatch(r"[a-z][a-z0-9._-]{1,63}", renderer_id):
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
            "output_manifest_sha256": plan.output_manifest_sha256,
            "plan_schema": plan.schema,
            "plan_sha256": plan.sha256,
            "rendered_at": rendered_at,
            "renderer_id": renderer_id,
            "review_kind": REVIEW_KIND,
            "schema_version": 3,
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
    semantic = markdown[start:end]
    return semantic if semantic.endswith(b"\n") else semantic + b"\n"


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
        if tag == "code" and values.get("data-curation-semantic") == "m3":
            self._semantic_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "code" and self._semantic_depth:
            self._semantic_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._semantic_depth:
            self.semantic_parts.append(data)


def _parse_meta(meta_json: bytes) -> dict[str, object]:
    fields = {
        "effect_count",
        "html_sha256",
        "locale",
        "markdown_sha256",
        "output_manifest_sha256",
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
        value = json.loads(meta_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationReviewError("review meta JSON is invalid") from exc
    if (
        type(value) is not dict
        or set(value) != fields
        or canonical_json_bytes(value) != meta_json
        or value["schema_version"] != 3
        or value["review_kind"] != REVIEW_KIND
        or value["semantic_schema"] != SEMANTIC_SCHEMA
        or value["locale"] != "ko-KR"
        or type(value["effect_count"]) is not int
        or value["effect_count"] < 1
        or type(value["rendered_at"]) is not str
        or _RENDERED_AT.fullmatch(value["rendered_at"]) is None
    ):
        raise CurationReviewError("review meta contract is invalid")
    for key in (
        "html_sha256",
        "markdown_sha256",
        "output_manifest_sha256",
        "plan_sha256",
        "semantic_sha256",
        "source_observation_sha256",
        "spec_sha256",
    ):
        if type(value[key]) is not str or _HASH.fullmatch(value[key]) is None:
            raise CurationReviewError("review meta hash is invalid: %s" % key)
    return value


def _validate_plan_outputs(plan: dict[str, object]) -> None:
    effects = plan.get("effects")
    observations = plan.get("source_observations")
    if type(effects) is not list or not effects or type(observations) is not list:
        raise CurationReviewError("review transformation membership is invalid")
    observation_ids = {
        item.get("observation_id") for item in observations if type(item) is dict
    }
    if len(observation_ids) != len(observations):
        raise CurationReviewError("review source observations are invalid")
    effect_fields = {
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
    }
    output_fields = {
        "content",
        "content_sha256",
        "document_role",
        "output_id",
        "output_path",
    }
    all_outputs = []
    for effect in effects:
        if type(effect) is not dict or set(effect) != effect_fields:
            raise CurationReviewError("review transformation effect is invalid")
        inputs = effect["input_observation_ids"]
        outputs = effect["outputs"]
        mappings = effect["source_output_mappings"]
        input_ids = set(inputs) if type(inputs) is list else set()
        if (
            effect["action"] not in domain.TRANSFORMATION_ACTIONS
            or effect["irreversible"] is not True
            or type(inputs) is not list
            or not inputs
            or not input_ids <= observation_ids
            or type(outputs) is not list
            or not outputs
            or type(mappings) is not list
            or not mappings
        ):
            raise CurationReviewError("review transformation evidence is incomplete")
        output_ids = set()
        for output in outputs:
            if type(output) is not dict or set(output) != output_fields:
                raise CurationReviewError("complete output contract is invalid")
            content = output["content"]
            if (
                type(content) is not str
                or type(output["content_sha256"]) is not str
                or sha256_bytes(content.encode("utf-8")) != output["content_sha256"]
            ):
                raise CurationReviewError("complete output bytes do not match the seal")
            output_ids.add(output["output_id"])
            all_outputs.append(output)
        mapped_sources = {
            mapping.get("source_observation_id")
            for mapping in mappings
            if type(mapping) is dict
        }
        mapped_outputs = {
            mapping.get("output_id") for mapping in mappings if type(mapping) is dict
        }
        if mapped_sources != input_ids or mapped_outputs != output_ids:
            raise CurationReviewError("complete output source mapping is incomplete")
    expected_manifest = sha256_bytes(canonical_json_bytes(all_outputs))
    if plan.get("output_manifest_sha256") != expected_manifest:
        raise CurationReviewError("complete output manifest hash mismatch")


def validate_review_payload(
    payload: review_package.ReviewPackagePayload,
) -> review_package.ReviewPackageHashes:
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
        semantic = json.loads(semantic_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurationReviewError("review semantic JSON is invalid") from exc
    if canonical_json_bytes(semantic) != semantic_json:
        raise CurationReviewError("review semantic JSON is not canonical")
    if (
        type(semantic) is not dict
        or set(semantic) != {
            "categories",
            "decision_actions",
            "output_manifest_sha256",
            "plan",
            "plan_sha256",
            "schema",
            "source_observation_sha256",
        }
        or semantic["schema"] != SEMANTIC_SCHEMA
        or semantic["decision_actions"] != list(DECISION_ACTIONS_KO)
        or sha256_bytes(semantic_json) != meta["semantic_sha256"]
        or semantic["output_manifest_sha256"] != meta["output_manifest_sha256"]
        or semantic["plan_sha256"] != meta["plan_sha256"]
        or semantic["source_observation_sha256"]
        != meta["source_observation_sha256"]
    ):
        raise CurationReviewError("review semantic contract is invalid")
    categories = semantic["categories"]
    if (
        type(categories) is not dict
        or set(categories) != set(REQUIRED_CATEGORIES)
        or any(type(categories[key]) is not dict or not categories[key] for key in REQUIRED_CATEGORIES)
    ):
        raise CurationReviewError("review category coverage is incomplete")
    plan = semantic["plan"]
    if type(plan) is not dict:
        raise CurationReviewError("review Plan binding is invalid")
    _validate_plan_outputs(plan)
    if (
        sha256_bytes(canonical_json_bytes(plan)) != semantic["plan_sha256"]
        or plan.get("schema") != meta["plan_schema"]
        or plan.get("spec_sha256") != meta["spec_sha256"]
        or plan.get("source_observation_sha256")
        != semantic["source_observation_sha256"]
        or sha256_bytes(canonical_json_bytes(plan.get("source_observations")))
        != semantic["source_observation_sha256"]
        or plan.get("cutoff_required") is not True
        or plan.get("irreversible_consequence")
        != domain.IRREVERSIBLE_CONSEQUENCE_KO
    ):
        raise CurationReviewError("review Plan binding is invalid")
    if plan["output_manifest_sha256"] != semantic["output_manifest_sha256"]:
        raise CurationReviewError("complete output manifest binding is invalid")
    for effect in plan["effects"]:
        for output in effect["outputs"]:
            if output["content"].encode() not in payload.markdown:
                raise CurationReviewError("complete output is missing from Markdown")
            if html.escape(output["content"]).encode() not in payload.html:
                raise CurationReviewError("complete output is missing from HTML")
    if domain.IRREVERSIBLE_CONSEQUENCE_KO.encode() not in payload.markdown:
        raise CurationReviewError("irreversible consequence is missing from Markdown")
    markdown_categories = tuple(
        value.decode() for value in re.findall(rb"`category:([a-z_]+)`", payload.markdown)
    )
    parser = _ReviewHTMLParser()
    try:
        parser.feed(payload.html.decode())
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise CurationReviewError("review HTML is invalid") from exc
    if (
        markdown_categories != REQUIRED_CATEGORIES
        or parser.errors
        or tuple(parser.categories) != REQUIRED_CATEGORIES
        or tuple(parser.actions) != DECISION_ACTIONS_KO
        or parser.plan_sha256 != semantic["plan_sha256"]
        or parser.markdown_sha256 != meta["markdown_sha256"]
        or "".join(parser.semantic_parts).encode() != semantic_json
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
    if expected_plan_sha256 is not None and meta["plan_sha256"] != expected_plan_sha256:
        raise CurationReviewError("sealed Review Package Plan hash mismatch")
    try:
        semantic = json.loads(payload.semantic_json)
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
