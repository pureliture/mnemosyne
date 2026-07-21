"""Markdown-first review compiler and read-only fidelity validation for M2."""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEADING = re.compile(r"^(#{1,6}) (.+) \{#([a-z0-9][a-z0-9-]{0,63})\}$")
_NOTICE = re.compile(r"^> \[notice:([A-Za-z0-9._:-]+)\] (.+)$")
_WARNING = re.compile(r"^- \[warning:([A-Za-z0-9._:-]+)\] (.+)$")
_ACTIONS = frozenset(("keep", "link", "move", "archive", "defer", "exclude"))
_RISKS = frozenset(("low", "medium", "high", "blocked"))
_FRESHNESS = frozenset(("fresh", "stale", "unknown"))
_KINDS = frozenset(("run-overview", "batch-preview"))
_SOURCE_KINDS = frozenset(("inventory-run", "campaign-snapshot", "batch-snapshot"))
_NOTICE_COPY = {
    "non-authoritative": "이 문서는 검토용입니다. 파일 이동·보관 승인이나 machine state SoT가 아닙니다.",
}
_WARNING_COPY = {
    "m2-no-structural-authority": "이 스냅샷은 검토용이며 파일 이동·보관 승인이 아닙니다.",
    "private-metadata-only": "콘텐츠 미노출 — private-reviewable 정책",
    "opaque-content-unopened": "내용을 열지 않음 — opaque evidence 범위",
    "reference-incomplete": "참조 안전성 검사가 완전하지 않습니다.",
    "lifecycle-frozen": "중지·완료 Workstream의 freeze가 적용됩니다.",
    "competing-candidate": "서로 경쟁하는 분류 후보가 있습니다.",
    "inventory-error": "inventory 오류를 먼저 해결해야 합니다.",
}
_EFFECT_COPY = {
    "none": "없음",
    "plan-unavailable-m2": "계획 미완료 — M2에서는 구조적 효과 권한을 만들지 않습니다.",
}
_BIDI_CONTROLS = frozenset(
    tuple(range(0x202A, 0x202F))
    + tuple(range(0x2066, 0x206A))
    + (0x200E, 0x200F, 0x061C)
)


class ReviewCompileError(ValueError):
    """A review model or sealed artifact violates the M2 contract."""


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ReviewCompileError("%s is invalid" % label)
    return value


def _hash(value: str, label: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise ReviewCompileError("%s is invalid" % label)
    return value


def _display_escape(value: str) -> str:
    if not isinstance(value, str):
        raise ReviewCompileError("review display value must be text")
    output = []
    for character in value:
        codepoint = ord(character)
        if (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or codepoint in _BIDI_CONTROLS
            or character in "\\|`<>#"
        ):
            output.append("\\u%04X" % codepoint)
        else:
            output.append(character)
    return "".join(output)


def _tuple_of_ids(values: Tuple[str, ...], label: str) -> Tuple[str, ...]:
    if type(values) is not tuple or tuple(sorted(set(values))) != values:
        raise ReviewCompileError("%s must be unique and sorted" % label)
    for value in values:
        _identifier(value, label)
    return values


@dataclass(frozen=True)
class CoverageSummary:
    folders_total: int
    folders_traversed: int
    folders_excluded: int
    folders_error: int
    files_total: int
    files_inspected: int
    files_metadata_only: int
    files_excluded: int
    files_error: int

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if type(value) is not int or value < 0:
                raise ReviewCompileError("%s must be non-negative" % name)


@dataclass(frozen=True)
class ReviewBounds:
    review_items: int
    underlying_files: int
    total_bytes: int
    leaf_folders: int
    effect_count: int

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if type(value) is not int or value < 0:
                raise ReviewCompileError("%s must be non-negative" % name)


@dataclass(frozen=True)
class WorkstreamSummary:
    workstream_id: str
    lifecycle: str
    review_items: int
    blocked: int
    errors: int

    def __post_init__(self) -> None:
        _identifier(self.workstream_id, "workstream id")
        _identifier(self.lifecycle, "workstream lifecycle")
        for name in ("review_items", "blocked", "errors"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ReviewCompileError("workstream count must be non-negative")


@dataclass(frozen=True)
class ReviewRow:
    unit_id: str
    unit_kind: str
    canonical_path: str
    display_path: str
    underlying_file_count: int
    primary_workstream: str
    related_workstreams: Tuple[str, ...]
    shared: bool
    document_role: str
    authority: str
    document_lifecycle: str
    scope_class: str
    sensitivity: str
    access_domain: str
    recommended_action: str
    target_path: Optional[str]
    risk_band: str
    context_freshness: str
    evidence_providers: Tuple[str, ...]
    warning_codes: Tuple[str, ...]
    effect_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.unit_id, "unit id")
        if self.unit_kind not in ("folder", "file"):
            raise ReviewCompileError("unit kind is invalid")
        if not isinstance(self.canonical_path, str) or not self.canonical_path:
            raise ReviewCompileError("canonical path is required")
        if not isinstance(self.display_path, str) or not self.display_path:
            raise ReviewCompileError("display path is required")
        if type(self.underlying_file_count) is not int or self.underlying_file_count < 1:
            raise ReviewCompileError("underlying file count must be positive")
        for label, value in (
            ("primary workstream", self.primary_workstream),
            ("document role", self.document_role),
            ("authority", self.authority),
            ("document lifecycle", self.document_lifecycle),
            ("scope class", self.scope_class),
            ("sensitivity", self.sensitivity),
            ("access domain", self.access_domain),
        ):
            _identifier(value, label)
        _tuple_of_ids(self.related_workstreams, "related workstream")
        if type(self.shared) is not bool:
            raise ReviewCompileError("shared must be boolean")
        if self.recommended_action not in _ACTIONS:
            raise ReviewCompileError("recommended action is invalid")
        if self.target_path is not None and not isinstance(self.target_path, str):
            raise ReviewCompileError("target path is invalid")
        if self.risk_band not in _RISKS:
            raise ReviewCompileError("risk band is invalid")
        if self.context_freshness not in _FRESHNESS:
            raise ReviewCompileError("context freshness is invalid")
        _tuple_of_ids(self.evidence_providers, "evidence provider")
        _tuple_of_ids(self.warning_codes, "warning code")
        _tuple_of_ids(self.effect_codes, "effect code")
        unknown_warnings = set(self.warning_codes) - set(_WARNING_COPY)
        unknown_effects = set(self.effect_codes) - set(_EFFECT_COPY)
        if unknown_warnings or unknown_effects:
            raise ReviewCompileError("review row uses unsupported display code")
        if (
            self.scope_class == "private-reviewable"
            or self.sensitivity == "private"
        ) and "private-metadata-only" not in self.warning_codes:
            raise ReviewCompileError(
                "private-reviewable row requires private-metadata-only warning"
            )
        if self.scope_class in (
            "opaque-private-evidence",
            "evidence",
            "memory",
            "protected",
            "never-touch",
        ) and "opaque-content-unopened" not in self.warning_codes:
            raise ReviewCompileError(
                "%s row requires opaque-content-unopened warning"
                % self.scope_class
            )
        private_or_opaque = (
            self.sensitivity == "private"
            or self.scope_class
            in (
                "private-reviewable",
                "opaque-private-evidence",
                "evidence",
                "memory",
                "protected",
                "never-touch",
            )
        )
        if private_or_opaque and (
            self.recommended_action in ("move", "archive")
            or self.target_path is not None
            or self.risk_band != "blocked"
            or any(
                provider
                in (
                    "safe-content-token",
                    "ephemeral-private-projection",
                    "exact-duplicate",
                )
                for provider in self.evidence_providers
            )
        ):
            raise ReviewCompileError(
                "private or opaque row cannot be movement-ready or persist content evidence"
            )


@dataclass(frozen=True)
class ReviewDocument:
    review_kind: str
    source_kind: str
    source_id: str
    source_snapshot_sha256: str
    rendered_at: str
    campaign_id: Optional[str]
    batch_id: Optional[str]
    snapshot_id: Optional[str]
    snapshot_version: Optional[int]
    policy_binding: str
    coverage: CoverageSummary
    bounds: Optional[ReviewBounds]
    workstreams: Tuple[WorkstreamSummary, ...]
    items: Tuple[ReviewRow, ...]
    warning_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        if self.review_kind not in _KINDS:
            raise ReviewCompileError("review kind is invalid")
        if self.source_kind not in _SOURCE_KINDS:
            raise ReviewCompileError("review source kind is invalid")
        if self.review_kind == "batch-preview" and self.source_kind != "batch-snapshot":
            raise ReviewCompileError("batch preview source must be batch-snapshot")
        if self.review_kind == "run-overview" and self.source_kind not in (
            "inventory-run",
            "campaign-snapshot",
        ):
            raise ReviewCompileError(
                "run overview source must be inventory-run or campaign-snapshot"
            )
        _identifier(self.source_id, "review source id")
        _hash(self.source_snapshot_sha256, "source snapshot hash")
        if _TIME.fullmatch(self.rendered_at) is None:
            raise ReviewCompileError("rendered_at must be canonical UTC seconds")
        for label, value in (
            ("campaign id", self.campaign_id),
            ("batch id", self.batch_id),
            ("snapshot id", self.snapshot_id),
        ):
            if value is not None:
                _identifier(value, label)
        if self.review_kind == "batch-preview":
            if None in (self.campaign_id, self.batch_id, self.snapshot_id):
                raise ReviewCompileError("batch preview identity is incomplete")
            if type(self.snapshot_version) is not int or self.snapshot_version < 1:
                raise ReviewCompileError("batch snapshot version is invalid")
            if self.bounds is None:
                raise ReviewCompileError("batch preview bounds are required")
        if not isinstance(self.policy_binding, str) or not self.policy_binding:
            raise ReviewCompileError("policy binding is required")
        if type(self.coverage) is not CoverageSummary:
            raise TypeError("coverage must be CoverageSummary")
        if self.bounds is not None and type(self.bounds) is not ReviewBounds:
            raise TypeError("bounds must be ReviewBounds")
        if type(self.workstreams) is not tuple or any(
            type(row) is not WorkstreamSummary for row in self.workstreams
        ):
            raise TypeError("workstreams must be immutable WorkstreamSummary values")
        if tuple(sorted(self.workstreams, key=lambda row: row.workstream_id)) != self.workstreams:
            raise ReviewCompileError("workstream summaries must be sorted")
        if type(self.items) is not tuple or any(type(row) is not ReviewRow for row in self.items):
            raise TypeError("items must be immutable ReviewRow values")
        if tuple(sorted(self.items, key=lambda row: row.unit_id)) != self.items:
            raise ReviewCompileError("review rows must be sorted by unit id")
        if len({row.unit_id for row in self.items}) != len(self.items):
            raise ReviewCompileError("review unit ids must be unique")
        if self.bounds is not None:
            if self.bounds.review_items != len(self.items):
                raise ReviewCompileError(
                    "review item bound does not match exact membership"
                )
            if self.bounds.underlying_files != sum(
                row.underlying_file_count for row in self.items
            ):
                raise ReviewCompileError(
                    "underlying file bound does not match exact membership"
                )
        _tuple_of_ids(self.warning_codes, "warning code")
        if set(self.warning_codes) - set(_WARNING_COPY):
            raise ReviewCompileError("review document uses unsupported warning code")


@dataclass(frozen=True)
class ReviewArtifacts:
    markdown: bytes
    html: bytes
    meta_json: bytes
    semantic_json: bytes


def _markdown_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> List[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(_display_escape(value) for value in row) + " |")
    return lines


def _materialize_markdown(document: ReviewDocument, renderer_id: str) -> bytes:
    lines = [
        "# Mnemosyne 문서 정리 검토 {#review}",
        "",
        "> [notice:non-authoritative] 이 문서는 검토용입니다. 파일 이동·보관 승인이나 machine state SoT가 아닙니다.",
        "",
        "## 검토본 식별 {#identity}",
    ]
    identity_rows = [
        ("Review kind", document.review_kind),
        ("Source kind", document.source_kind),
        ("Source ID", document.source_id),
        ("Source snapshot SHA-256", document.source_snapshot_sha256),
        ("Rendered at", document.rendered_at),
        ("Renderer ID", renderer_id),
        ("Policy binding", document.policy_binding),
        ("Structural approval ready", "false"),
    ]
    for label, value in (
        ("Campaign ID", document.campaign_id),
        ("Batch ID", document.batch_id),
        ("Snapshot ID", document.snapshot_id),
        (
            "Snapshot version",
            None if document.snapshot_version is None else str(document.snapshot_version),
        ),
    ):
        if value is not None:
            identity_rows.append((label, value))
    lines.extend(_markdown_table(("필드", "값"), identity_rows))
    lines.extend(("", "## Coverage {#coverage}"))
    coverage = document.coverage
    lines.extend(
        _markdown_table(
            ("Denominator", "Total", "Reviewed", "Metadata only", "Excluded", "Error"),
            (
                (
                    "folders",
                    str(coverage.folders_total),
                    str(coverage.folders_traversed),
                    "0",
                    str(coverage.folders_excluded),
                    str(coverage.folders_error),
                ),
                (
                    "files",
                    str(coverage.files_total),
                    str(coverage.files_inspected),
                    str(coverage.files_metadata_only),
                    str(coverage.files_excluded),
                    str(coverage.files_error),
                ),
            ),
        )
    )
    lines.extend(("", "## Workstream 현황 {#workstreams}"))
    lines.extend(
        _markdown_table(
            ("Workstream", "Lifecycle", "Review items", "Blocked", "Errors"),
            tuple(
                (
                    row.workstream_id,
                    row.lifecycle,
                    str(row.review_items),
                    str(row.blocked),
                    str(row.errors),
                )
                for row in document.workstreams
            ),
        )
    )
    if document.bounds is not None:
        lines.extend(("", "## Bounded scope {#bounds}"))
        bounds = document.bounds
        lines.extend(
            _markdown_table(
                ("Review items", "Underlying files", "Total bytes", "Leaf folders", "Effects"),
                ((str(bounds.review_items), str(bounds.underlying_files), str(bounds.total_bytes), str(bounds.leaf_folders), str(bounds.effect_count)),),
            )
        )
    lines.extend(("", "## 검토 항목 {#items}"))
    item_rows = []
    for row in document.items:
        warning_text = ",".join(row.warning_codes) or "none"
        effect_text = ",".join(row.effect_codes) or "none"
        item_rows.append(
            (
                row.unit_id,
                row.unit_kind,
                row.display_path,
                str(row.underlying_file_count),
                row.primary_workstream,
                ",".join(row.related_workstreams) or "none",
                "true" if row.shared else "false",
                row.document_role,
                row.authority,
                row.document_lifecycle,
                row.scope_class,
                row.recommended_action,
                row.target_path or "none",
                row.risk_band,
                row.context_freshness,
                ",".join(row.evidence_providers) or "none",
                warning_text,
                effect_text,
            )
        )
    lines.extend(
        _markdown_table(
            (
                "ID",
                "Unit",
                "Path",
                "Files",
                "Primary",
                "Related",
                "Shared",
                "Role",
                "Authority",
                "Lifecycle",
                "Scope",
                "Action",
                "Target",
                "Risk",
                "Freshness",
                "Evidence",
                "Warnings",
                "Effects",
            ),
            item_rows,
        )
    )
    lines.extend(("", "## 경고 {#warnings}"))
    warning_codes = tuple(
        sorted(
            set(document.warning_codes).union(
                *(set(row.warning_codes) for row in document.items)
            )
        )
    )
    if warning_codes:
        for code in warning_codes:
            lines.append("- [warning:%s] %s" % (code, _WARNING_COPY[code]))
    else:
        lines.append("- [warning:none] 추가 경고 없음")
    lines.extend(("", "## 다음 단계 {#next-step}"))
    lines.append(
        "Effect plan과 별도 승인이 준비되기 전에는 source corpus를 변경할 수 없습니다."
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _table_cells(line: str) -> List[str]:
    return [cell.strip() for cell in line.strip()[1:-1].split("|")]


def _parse_markdown(markdown: bytes) -> Tuple[List[dict], dict]:
    try:
        text = markdown.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReviewCompileError("review Markdown is not UTF-8") from exc
    lines = text.splitlines()
    blocks = []
    headings = []
    notices = []
    warnings = []
    items = []
    identity = {}
    code_blocks = 0
    current_section = None
    index = 0
    while index < len(lines):
        line = lines[index]
        heading = _HEADING.fullmatch(line)
        if heading:
            level = len(heading.group(1))
            row = {"type": "heading", "level": level, "text": heading.group(2), "id": heading.group(3)}
            blocks.append(row)
            headings.append({"level": level, "text": heading.group(2), "id": heading.group(3)})
            current_section = heading.group(3)
            index += 1
            continue
        notice = _NOTICE.fullmatch(line)
        if notice:
            notice_code = notice.group(1)
            notice_text = notice.group(2)
            if _NOTICE_COPY.get(notice_code) != notice_text:
                raise ReviewCompileError(
                    "review approval notice golden copy contract is unsupported"
                )
            blocks.append({"type": "notice", "code": notice.group(1), "text": notice.group(2)})
            notices.append({"code": notice_code, "text": notice_text})
            index += 1
            continue
        warning = _WARNING.fullmatch(line)
        if warning:
            warning_code = warning.group(1)
            warning_text = warning.group(2)
            expected_warning = (
                "추가 경고 없음"
                if warning_code == "none"
                else _WARNING_COPY.get(warning_code)
            )
            if expected_warning != warning_text:
                raise ReviewCompileError("review warning contract is unsupported")
            blocks.append({"type": "warning", "code": warning.group(1), "text": warning.group(2)})
            warnings.append({"code": warning_code, "text": warning_text})
            index += 1
            continue
        if line.startswith("```"):
            code_blocks += 1
        if line.startswith("|") and index + 1 < len(lines) and lines[index + 1].startswith("|"):
            headers = _table_cells(line)
            separator = _table_cells(lines[index + 1])
            if len(headers) == len(separator) and all(set(cell) <= {"-", ":"} for cell in separator):
                rows = []
                index += 2
                while index < len(lines) and lines[index].startswith("|"):
                    cells = _table_cells(lines[index])
                    if len(cells) != len(headers):
                        raise ReviewCompileError("review Markdown table width changed")
                    rows.append(cells)
                    index += 1
                block = {"type": "table", "section": current_section, "headers": headers, "rows": rows}
                blocks.append(block)
                if current_section == "items":
                    lookup = {header: offset for offset, header in enumerate(headers)}
                    required = ("ID", "Action", "Effects", "Warnings")
                    if any(name not in lookup for name in required):
                        raise ReviewCompileError("review item table contract is incomplete")
                    for cells in rows:
                        items.append(
                            {
                                "id": cells[lookup["ID"]],
                                "action": cells[lookup["Action"]],
                                "effects": cells[lookup["Effects"]],
                                "warnings": cells[lookup["Warnings"]],
                            }
                        )
                elif current_section == "identity":
                    if headers != ["필드", "값"]:
                        raise ReviewCompileError(
                            "review identity table contract is invalid"
                        )
                    for cells in rows:
                        if cells[0] in identity:
                            raise ReviewCompileError(
                                "review identity field is duplicated"
                            )
                        identity[cells[0]] = cells[1]
                continue
        if line:
            blocks.append({"type": "paragraph", "text": line})
        index += 1
    expected_notices = [
        {
            "code": "non-authoritative",
            "text": _NOTICE_COPY["non-authoritative"],
        }
    ]
    if notices != expected_notices:
        raise ReviewCompileError(
            "review approval notice cardinality contract is unsupported"
        )
    semantic = {
        "schema": "mnemosyne-review-semantic-v1",
        "headings": headings,
        "notices": notices,
        "warnings": warnings,
        "items": items,
        "identity": identity,
        "code_block_count": code_blocks // 2,
    }
    return blocks, semantic


def semantic_json_from_markdown(markdown: bytes) -> bytes:
    """Return the canonical semantic manifest for exact Markdown bytes."""

    _blocks, semantic = _parse_markdown(markdown)
    return canonical_json_bytes(semantic)


def _html_from_markdown(markdown: bytes, markdown_sha256: str) -> Tuple[bytes, bytes]:
    blocks, semantic = _parse_markdown(markdown)
    semantic_json = canonical_json_bytes(semantic)
    title = semantic["headings"][0]["text"] if semantic["headings"] else "Mnemosyne review"
    output = [
        "<!doctype html>",
        '<html lang="ko-KR">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="mnemosyne-markdown-sha256" content="%s">' % markdown_sha256,
        "<title>%s</title>" % html.escape(title),
        "<style>body{font-family:system-ui,sans-serif;line-height:1.5;margin:0 auto;max-width:110rem;padding:1rem}a.skip{position:absolute;left:-9999px}a.skip:focus{left:1rem;top:1rem;background:#fff;color:#111;padding:.5rem;outline:3px solid #005fcc}table{border-collapse:collapse;width:100%;margin-block:1rem}th,td{border:1px solid #777;padding:.35rem;text-align:left;vertical-align:top}th{background:#eee;color:#111}.warning{border-left:.4rem solid #9b5b00;padding:.5rem}.notice{border:2px solid #005fcc;padding:.5rem}:focus-visible{outline:3px solid #005fcc;outline-offset:2px}</style>",
        "</head>",
        "<body>",
        '<a class="skip" href="#main-content">본문으로 건너뛰기</a>',
        '<label for="review-filter">항목 필터</label>',
        '<input id="review-filter" type="search" aria-describedby="filter-help">',
        '<span id="filter-help">브라우저 찾기와 함께 사용할 수 있습니다.</span>',
        '<main id="main-content">',
    ]
    section_title = "검토 표"
    for block in blocks:
        kind = block["type"]
        if kind == "heading":
            section_title = block["text"]
            output.append(
                '<h{level} id="{id}" data-section-id="{id}">{text}</h{level}>'.format(
                    level=block["level"],
                    id=html.escape(block["id"], quote=True),
                    text=html.escape(block["text"]),
                )
            )
        elif kind == "notice":
            output.append(
                '<aside class="notice" data-notice="%s" data-notice-text="%s">%s</aside>'
                % (
                    html.escape(block["code"], quote=True),
                    html.escape(block["text"], quote=True),
                    html.escape(block["text"]),
                )
            )
        elif kind == "warning":
            output.append(
                '<p class="warning" data-warning-id="%s" data-warning-text="%s"><strong>경고:</strong> %s</p>'
                % (
                    html.escape(block["code"], quote=True),
                    html.escape(block["text"], quote=True),
                    html.escape(block["text"]),
                )
            )
        elif kind == "paragraph":
            output.append("<p>%s</p>" % html.escape(block["text"]))
        elif kind == "table":
            output.append(
                '<table data-section="%s"><caption>%s</caption><thead><tr>'
                % (html.escape(block["section"] or "", quote=True), html.escape(section_title))
            )
            output.extend('<th scope="col">%s</th>' % html.escape(cell) for cell in block["headers"])
            output.append("</tr></thead><tbody>")
            lookup = {header: offset for offset, header in enumerate(block["headers"])}
            for row in block["rows"]:
                attributes = ""
                if block["section"] == "items":
                    attributes = (
                        ' data-item-id="%s" data-action="%s" data-effect="%s" data-warning="%s"'
                        % tuple(
                            html.escape(row[lookup[name]], quote=True)
                            for name in ("ID", "Action", "Effects", "Warnings")
                        )
                    )
                output.append("<tr%s>" % attributes)
                for offset, cell in enumerate(row):
                    tag = "th" if offset == 0 else "td"
                    scope = ' scope="row"' if tag == "th" else ""
                    output.append("<%s%s>%s</%s>" % (tag, scope, html.escape(cell), tag))
                output.append("</tr>")
            output.append("</tbody></table>")
    output.extend(("</main>", "</body>", "</html>", ""))
    return "\n".join(output).encode("utf-8"), semantic_json


class ReviewCompiler:
    def __init__(self, renderer_id: str) -> None:
        self.renderer_id = _identifier(renderer_id, "renderer id")

    def compile(self, document: ReviewDocument) -> ReviewArtifacts:
        if type(document) is not ReviewDocument:
            raise TypeError("document must be ReviewDocument")
        markdown = _materialize_markdown(document, self.renderer_id)
        markdown_sha256 = sha256_bytes(markdown)
        rendered_html, semantic_json = _html_from_markdown(markdown, markdown_sha256)
        semantic = json.loads(semantic_json.decode("utf-8"))
        identity = semantic["identity"]
        meta = canonical_json_bytes(
            {
                "html_sha256": sha256_bytes(rendered_html),
                "locale": "ko-KR",
                "markdown_sha256": markdown_sha256,
                "rendered_at": identity["Rendered at"],
                "renderer_id": identity["Renderer ID"],
                "review_kind": identity["Review kind"],
                "schema_version": 1,
                "semantic_schema": "mnemosyne-review-semantic-v1",
                "semantic_sha256": sha256_bytes(semantic_json),
                "source_id": identity["Source ID"],
                "source_kind": identity["Source kind"],
                "source_snapshot_sha256": identity["Source snapshot SHA-256"],
            }
        )
        return ReviewArtifacts(markdown, rendered_html, meta, semantic_json)


class _ReviewHTMLSemantics(HTMLParser):
    def __init__(self) -> None:
        HTMLParser.__init__(self, convert_charrefs=True)
        self.headings = []
        self.notices = []
        self.warnings = []
        self.items = []
        self.code_block_count = 0
        self.ids = set()
        self.errors = []
        self._heading = None
        self._in_pre = False
        self.table_count = 0
        self.caption_count = 0
        self.column_header_count = 0
        self.filter_label_count = 0
        self.filter_input_count = 0
        self.filter_help_count = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = {name: value for name, value in attrs}
        if len(values) != len(attrs):
            self.errors.append("duplicate HTML attribute")
        element_id = values.get("id")
        if element_id is not None:
            if element_id in self.ids:
                self.errors.append("duplicate DOM id")
            self.ids.add(element_id)
        if "hidden" in values or "display:none" in (values.get("style") or "").replace(" ", "").lower():
            self.errors.append("hidden review content")
        tabindex = values.get("tabindex")
        if tabindex is not None:
            try:
                if int(tabindex) > 0:
                    self.errors.append("positive tabindex")
            except ValueError:
                self.errors.append("invalid tabindex")
        for attribute in ("src", "href"):
            target = values.get(attribute)
            if target and re.match(r"^(?:https?:)?//", target, re.IGNORECASE):
                self.errors.append("external dependency")
        if tag in ("script", "iframe", "object", "embed"):
            self.errors.append("executable or embedded content")
        if tag == "label" and values.get("for") == "review-filter":
            self.filter_label_count += 1
        if tag == "input" and values.get("id") == "review-filter":
            if (
                values.get("type") != "search"
                or values.get("aria-describedby") != "filter-help"
            ):
                self.errors.append("accessibility contract: filter input")
            self.filter_input_count += 1
        if tag == "span" and values.get("id") == "filter-help":
            self.filter_help_count += 1
        if tag == "table":
            self.table_count += 1
        if tag == "caption":
            self.caption_count += 1
        if tag == "th":
            if values.get("scope") not in ("col", "row"):
                self.errors.append("accessibility contract: table header scope")
            elif values.get("scope") == "col":
                self.column_header_count += 1
        if re.fullmatch(r"h[1-6]", tag) and values.get("data-section-id"):
            self._heading = {
                "level": int(tag[1]),
                "id": values["data-section-id"],
                "text": "",
            }
        notice = values.get("data-notice")
        if notice is not None:
            notice_text = values.get("data-notice-text")
            if _NOTICE_COPY.get(notice) != notice_text:
                self.errors.append("notice contract")
            self.notices.append({"code": notice, "text": notice_text})
        elif tag == "aside" and "notice" in (values.get("class") or "").split():
            self.errors.append("notice contract")
        warning = values.get("data-warning-id")
        if warning is not None:
            warning_text = values.get("data-warning-text")
            expected_warning = (
                "추가 경고 없음"
                if warning == "none"
                else _WARNING_COPY.get(warning)
            )
            if expected_warning != warning_text:
                self.errors.append("warning contract")
            self.warnings.append({"code": warning, "text": warning_text})
        elif tag == "p" and "warning" in (values.get("class") or "").split():
            self.errors.append("warning contract")
        item_id = values.get("data-item-id")
        if item_id is not None:
            self.items.append(
                {
                    "id": item_id,
                    "action": values.get("data-action"),
                    "effects": values.get("data-effect"),
                    "warnings": values.get("data-warning"),
                }
            )
        if tag == "pre":
            self._in_pre = True
        elif tag == "code" and self._in_pre:
            self.code_block_count += 1

    def handle_endtag(self, tag: str) -> None:
        if re.fullmatch(r"h[1-6]", tag) and self._heading is not None:
            self.headings.append(self._heading)
            self._heading = None
        if tag == "pre":
            self._in_pre = False

    def handle_data(self, data: str) -> None:
        if self._heading is not None:
            self._heading["text"] += data

    def semantic(self) -> dict:
        return {
            "headings": self.headings,
            "notices": self.notices,
            "warnings": self.warnings,
            "items": self.items,
            "code_block_count": self.code_block_count,
        }


def validate_review_artifacts(artifacts: ReviewArtifacts) -> bool:
    if type(artifacts) is not ReviewArtifacts:
        raise TypeError("artifacts must be ReviewArtifacts")
    try:
        meta = json.loads(artifacts.meta_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewCompileError("review meta JSON is invalid") from exc
    if sha256_bytes(artifacts.markdown) != meta.get("markdown_sha256"):
        raise ReviewCompileError("review Markdown hash mismatch")
    if sha256_bytes(artifacts.html) != meta.get("html_sha256"):
        raise ReviewCompileError("review HTML hash mismatch")
    _blocks, semantic = _parse_markdown(artifacts.markdown)
    semantic_json = canonical_json_bytes(semantic)
    if semantic_json != artifacts.semantic_json:
        raise ReviewCompileError("review semantic manifest mismatch")
    if sha256_bytes(semantic_json) != meta.get("semantic_sha256"):
        raise ReviewCompileError("review semantic hash mismatch")
    identity = semantic.get("identity", {})
    identity_meta = {
        "Review kind": "review_kind",
        "Source kind": "source_kind",
        "Source ID": "source_id",
        "Source snapshot SHA-256": "source_snapshot_sha256",
        "Rendered at": "rendered_at",
        "Renderer ID": "renderer_id",
    }
    if any(identity.get(label) != meta.get(field) for label, field in identity_meta.items()):
        raise ReviewCompileError("review meta identity mismatch")
    embedded = (
        'name="mnemosyne-markdown-sha256" content="%s"'
        % meta["markdown_sha256"]
    ).encode("ascii")
    if embedded not in artifacts.html:
        raise ReviewCompileError("review HTML Markdown binding mismatch")
    html_semantics = _ReviewHTMLSemantics()
    try:
        html_semantics.feed(artifacts.html.decode("utf-8"))
        html_semantics.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReviewCompileError("review HTML is invalid") from exc
    if html_semantics.errors:
        raise ReviewCompileError(
            "review HTML safety contract failed: %s"
            % ", ".join(html_semantics.errors)
        )
    if (
        html_semantics.filter_label_count != 1
        or html_semantics.filter_input_count != 1
        or html_semantics.filter_help_count != 1
        or html_semantics.table_count < 1
        or html_semantics.caption_count != html_semantics.table_count
        or html_semantics.column_header_count < 1
    ):
        raise ReviewCompileError("review HTML accessibility contract failed")
    markdown_comparable = {
        key: semantic[key]
        for key in ("headings", "notices", "warnings", "items", "code_block_count")
    }
    if html_semantics.semantic() != markdown_comparable:
        raise ReviewCompileError("review Markdown and HTML semantic coverage differs")
    for required in (
        b'<html lang="ko-KR">',
        b'<main id="main-content">',
        b'<a class="skip" href="#main-content">',
    ):
        if required not in artifacts.html:
            raise ReviewCompileError("review HTML accessibility contract failed")
    return True


__all__ = [
    "CoverageSummary",
    "ReviewArtifacts",
    "ReviewBounds",
    "ReviewCompileError",
    "ReviewCompiler",
    "ReviewDocument",
    "ReviewRow",
    "WorkstreamSummary",
    "sha256_bytes",
    "semantic_json_from_markdown",
    "validate_review_artifacts",
]
