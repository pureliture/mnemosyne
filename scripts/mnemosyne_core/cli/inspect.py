"""Read-only request construction and presentation for fixed inspect views."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path

from .. import operation_contract, workstream_curation
from ..canonical_json import canonical_json_bytes, sha256_bytes
from .request_builder import build_view_request


_SCOPE_REASON_TEXT = {
    "CONTENT_OPAQUE": "내용을 안전하게 분류할 수 없음",
    "SOURCE_UNSUPPORTED": "안전하게 다룰 수 없는 파일 형식",
    "WORKSTREAM_INACTIVE": "중지되었거나 완료된 Workstream",
}

_FROZEN_DRIFT_TEXT = {
    "AUXILIARY_MISSING": "보조 스냅샷 메타데이터가 없습니다.",
    "AUXILIARY_MALFORMED": "보조 스냅샷 메타데이터 형식을 확인해야 합니다.",
    "AUXILIARY_AMBIGUOUS": "보조 스냅샷 메타데이터에 서로 다른 주장이 있습니다.",
    "AUXILIARY_LIMIT_EXCEEDED": "보조 스냅샷 메타데이터가 검사 한도를 넘었습니다.",
    "AUXILIARY_ID_MISMATCH": "보조 스냅샷의 Workstream 식별자가 현재 기준과 다릅니다.",
    "AUXILIARY_ROOT_MISMATCH": "보조 스냅샷의 프로젝트 위치가 현재 기준과 다릅니다.",
    "AUXILIARY_FRESHNESS_MISSING": "보조 스냅샷의 최신 시점을 확인할 수 없습니다.",
    "AUXILIARY_UNSAFE": "보조 스냅샷을 안전하게 읽을 수 없습니다.",
}


def _blocked_invalid_request() -> bytes:
    return operation_contract.OperationOutcome.blocked(
        sha256_bytes(b""),
        reason_code="INVALID_REQUEST",
        next_safe_action="correct-request",
    ).canonical_bytes


def _exit_code(raw: bytes) -> int:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 2
    if type(value) is dict and value.get("outcome_kind") in {
        "completed",
        "completed_current",
    }:
        return 0
    return 2


def _scope_human_text(result: Mapping) -> str | None:
    if result.get("inspection_mode") == "frozen-coverage":
        workstream = result.get("workstream")
        coverage = result.get("frozen_coverage")
        drift = result.get("drift")
        if (
            not isinstance(workstream, Mapping)
            or not isinstance(coverage, Mapping)
            or not isinstance(drift, list)
            or type(workstream.get("id")) is not str
            or workstream.get("lifecycle") not in {"paused", "completed"}
            or type(workstream.get("project_home")) is not str
            or any(
                type(coverage.get(key)) is not int
                for key in (
                    "directory_count",
                    "file_count",
                    "unreadable_count",
                    "unsafe_count",
                )
            )
        ):
            return None
        lifecycle = "중지됨" if workstream["lifecycle"] == "paused" else "완료됨"
        lines = [
            f"Workstream: {workstream['id']} ({lifecycle})",
            f"현재 프로젝트: {workstream['project_home']}",
            f"디렉터리: {coverage['directory_count']}개",
            f"파일: {coverage['file_count']}개",
            (
                "읽을 수 없음/안전 문제: "
                f"{coverage['unreadable_count']}개/{coverage['unsafe_count']}개"
            ),
            f"사람 확인 필요: {len(drift)}건",
        ]
        for finding in drift:
            if not isinstance(finding, Mapping):
                return None
            reason_code = finding.get("reason_code")
            if reason_code not in _FROZEN_DRIFT_TEXT:
                return None
            lines.append("- " + _FROZEN_DRIFT_TEXT[reason_code])
        if result.get("truncated") is True:
            lines.append("검사 한도에 맞춰 일부 집계만 표시했습니다.")
        lines.extend(
            (
                "파일 내용은 읽지 않았습니다.",
                "이동 후보를 만들지 않았습니다.",
            )
        )
        return "\n".join(lines) + "\n"
    scope = result.get("scope")
    if not isinstance(scope, Mapping) or type(scope.get("relative_path")) is not str:
        return None
    groups = (
        ("organized", "정리된 항목"),
        ("candidates", "제안 후보"),
        ("excluded", "제외"),
        ("uncertain", "확인 필요"),
    )
    lines = [f"검사 범위: {scope['relative_path']}"]
    for key, label in groups:
        items = result.get(key)
        if not isinstance(items, list):
            return None
        lines.append(f"{label}: {len(items)}건")
        for item in items:
            if not isinstance(item, Mapping):
                return None
            relative_path = item.get("relative_path")
            if type(relative_path) is not str:
                return None
            detail = None
            if key == "organized":
                destination_kind = item.get("destination_kind")
                destination_id = item.get("destination_id")
                if type(destination_kind) is str and type(destination_id) is str:
                    detail = f"{destination_kind}: {destination_id}"
            elif key == "candidates":
                hint = item.get("hint")
                if type(hint) is str:
                    detail = hint
            else:
                reason_code = item.get("reason_code")
                if type(reason_code) is str:
                    detail = _SCOPE_REASON_TEXT.get(
                        reason_code,
                        "안전한 다음 단계를 사람이 확인해야 함",
                    )
            lines.append(
                f"- {relative_path}" if detail is None else f"- {relative_path} | {detail}"
            )
    if result.get("truncated") is True:
        lines.append("일부 결과만 표시했습니다. 범위를 좁혀 다시 검사하세요.")
    return "\n".join(lines) + "\n"


def _human_text(view: str, raw: bytes) -> str:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return f"{view}: 결과를 해석할 수 없습니다. --json으로 다시 확인하세요.\n"
    if type(value) is not dict:
        return f"{view}: 결과 형식이 올바르지 않습니다. --json으로 다시 확인하세요.\n"
    outcome_kind = value.get("outcome_kind")
    if outcome_kind not in {"completed", "completed_current"}:
        return (
            f"{view}: 실행할 수 없습니다 "
            f"({value.get('reason_code', 'UNKNOWN')}). 다음: "
            f"{value.get('next_safe_action', 'inspect')}\n"
        )
    result = value.get("result")
    if isinstance(result, Mapping) and result.get("view") == "capabilities":
        summary = result.get("summary")
        return f"capabilities: {summary}\n"
    if isinstance(result, Mapping) and result.get("view") == "audit":
        return (
            f"audit: {result.get('activation_state')}, "
            f"blocking_total={result.get('blocking_total')}\n"
        )
    if isinstance(result, Mapping) and result.get("view") == "scope":
        rendered = _scope_human_text(result)
        if rendered is None:
            return f"{view}: 결과 형식이 올바르지 않습니다. --json으로 다시 확인하세요.\n"
        return rendered
    if isinstance(result, Mapping) and result.get("view") == "workstream":
        workstream = result.get("workstream")
        context = result.get("context")
        plan = result.get("plan")
        package = result.get("review_package")
        if (
            isinstance(workstream, Mapping)
            and isinstance(context, Mapping)
            and context.get("outcome") == "INCOMPLETE"
            and plan is None
            and package is None
        ):
            source_count = context.get("source_count")
            gap_count = context.get("gap_count")
            gap_paths = context.get("gap_paths")
            if (
                type(source_count) is not int
                or type(gap_count) is not int
                or not isinstance(gap_paths, list)
                or any(type(path) is not str for path in gap_paths)
            ):
                return f"{view}: 결과 형식이 올바르지 않습니다. --json으로 다시 확인하세요.\n"
            lines = [
                f"Workstream: {workstream.get('id')} ({workstream.get('lifecycle')})",
                "문맥 확인: 아직 완성되지 않았습니다.",
                f"확인한 소스: {source_count}건 | 확인이 필요한 빈칸: {gap_count}건",
            ]
            if gap_paths:
                lines.append("먼저 확인할 경로:")
                lines.extend("- " + path for path in gap_paths[:5])
            lines.extend(
                (
                    "문서 이동 Plan과 검토 패키지는 만들지 않았습니다.",
                    "빈칸을 해결한 뒤 다시 검사하세요.",
                )
            )
            return "\n".join(lines) + "\n"
        if not all(isinstance(value, Mapping) for value in (workstream, plan, package)):
            return f"{view}: 결과 형식이 올바르지 않습니다. --json으로 다시 확인하세요.\n"
        effects = plan.get("effects")
        if type(effects) is not list:
            return f"{view}: 결과 형식이 올바르지 않습니다. --json으로 다시 확인하세요.\n"
        return (
            f"Workstream: {workstream.get('id')} ({workstream.get('lifecycle')})\n"
            f"경로 이동/이름변경: {len(effects)}건\n"
            f"검토 패키지: {package.get('directory')}\n"
            "원문과 Curation 통제 상태는 변경하지 않았습니다.\n"
        )
    if isinstance(result, Mapping) and result.get("view") in {"pending", "history"}:
        records = result.get("records")
        if not isinstance(records, list):
            return f"{view}: 결과 형식이 올바르지 않습니다. --json으로 다시 확인하세요.\n"
        lines = [f"{view}: {len(records)}건"]
        for record in records:
            if not isinstance(record, Mapping):
                return (
                    f"{view}: 결과 형식이 올바르지 않습니다. "
                    "--json으로 다시 확인하세요.\n"
                )
            lines.append(
                f"{record.get('proposal_id')} | {record.get('status')} | "
                f"{record.get('source_relative_path')} -> "
                f"{record.get('target_relative_path')}"
            )
        if result.get("truncated"):
            lines.append(f"다음 offset: {result.get('next_offset')}")
        return "\n".join(lines) + "\n"
    return f"{view}: 완료\n"


def inspect_view(
    *,
    view: object,
    root: object,
    actor: object,
    max_items: object,
    offset: object,
    workstream_ref: object = None,
    relative_path: object = None,
    max_depth: object = None,
    max_hint_bytes: object = None,
    review_package: object = None,
    as_json: bool,
    execute_request_bytes: Callable[[bytes], bytes],
) -> tuple[int, bytes | str]:
    """Execute exactly one fixed read-only catalog request and render it."""

    if view == "workstream":
        if (
            type(workstream_ref) is not str
            or not workstream_ref
            or type(review_package) is not str
            or not review_package
            or relative_path is not None
            or offset != 0
        ):
            raw = _blocked_invalid_request()
            return 2, raw if as_json else _human_text(str(view), raw)
        try:
            outcome = workstream_curation.inspect_workstream(
                root=Path(root).expanduser(),
                workstream_ref=workstream_ref,
                review_package_directory=Path(review_package).expanduser(),
                max_items=256 if max_items is None else max_items,
                max_depth=8 if max_depth is None else max_depth,
                max_hint_bytes=(
                    1024 * 1024 if max_hint_bytes is None else max_hint_bytes
                ),
                actor=actor,
            )
            raw = canonical_json_bytes(outcome)
        except workstream_curation.WorkstreamCurationError as exc:
            raw = canonical_json_bytes(
                {
                    "next_safe_action": exc.next_safe_action,
                    "outcome_kind": "blocked",
                    "reason_code": exc.reason_code,
                }
            )
        except Exception:
            raw = canonical_json_bytes(
                {
                    "next_safe_action": "inspect-workstream",
                    "outcome_kind": "blocked",
                    "reason_code": "REVIEW_NOT_READY",
                }
            )
        return _exit_code(raw), raw if as_json else _human_text(str(view), raw)

    if review_package is not None:
        raw = _blocked_invalid_request()
        return 2, raw if as_json else _human_text(str(view), raw)

    try:
        request = build_view_request(
            view=view,
            root=root,
            actor=actor,
            max_items=max_items,
            offset=offset,
            workstream_ref=workstream_ref,
            relative_path=relative_path,
            max_depth=max_depth,
            max_hint_bytes=max_hint_bytes,
        )
    except (TypeError, ValueError):
        raw = _blocked_invalid_request()
        return 2, raw if as_json else _human_text(str(view), raw)
    try:
        raw = execute_request_bytes(request.canonical_bytes)
    except Exception:
        raw = operation_contract.OperationOutcome.blocked(
            request.sha256,
            reason_code="EXECUTION_UNAVAILABLE",
            next_safe_action="inspect",
        ).canonical_bytes
    if type(raw) is not bytes:
        raw = operation_contract.OperationOutcome.blocked(
            request.sha256,
            reason_code="EXECUTION_UNAVAILABLE",
            next_safe_action="inspect",
        ).canonical_bytes
    return _exit_code(raw), raw if as_json else _human_text(str(view), raw)


__all__ = ["build_view_request", "inspect_view"]
