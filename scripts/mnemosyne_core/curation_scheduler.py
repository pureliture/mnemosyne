"""Scheduler-neutral inspection result and two thin session adapters."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional

from .canonical_json import canonical_json_bytes, sha256_bytes
from .workstream_curation import WorkstreamCurationError, inspect_workstream


_SHA256 = re.compile(r"[0-9a-f]{64}")
_STATUSES = {"PENDING_DELIVERY", "QUIET", "REVIEW_READY"}
_PACKAGE_HASH_KEYS = (
    "html_sha256",
    "markdown_sha256",
    "meta_sha256",
    "semantic_sha256",
)


class ScheduledInspectionError(RuntimeError):
    """A scheduler result could not be represented without guessing."""


@dataclass(frozen=True)
class ScheduledInspectionRequest:
    root: Path
    workstream_ref: str
    review_package_directory: Path
    max_items: int
    max_depth: int
    max_hint_bytes: int
    actor: str

    def __post_init__(self) -> None:
        root = Path(self.root)
        package = Path(self.review_package_directory)
        if not root.is_absolute() or not package.is_absolute():
            raise ValueError("scheduled inspection paths must be absolute")
        if type(self.workstream_ref) is not str or not self.workstream_ref:
            raise ValueError("scheduled inspection Workstream is invalid")
        if type(self.actor) is not str or not self.actor or len(self.actor) > 128:
            raise ValueError("scheduled inspection actor is invalid")
        if (
            type(self.max_items) is not int
            or not 1 <= self.max_items <= 4096
            or type(self.max_depth) is not int
            or not 0 <= self.max_depth <= 16
            or type(self.max_hint_bytes) is not int
            or not 0 <= self.max_hint_bytes <= 1024 * 1024
        ):
            raise ValueError("scheduled inspection bounds are invalid")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "review_package_directory", package)


@dataclass(frozen=True)
class ScheduledInspectionResult:
    status: str
    action_kind: str
    workstream_id: str
    idempotency_key: str
    brief: str
    question: Optional[str]
    plan_sha256: Optional[str]
    source_observation_sha256: Optional[str]
    review_package_directory: Optional[str]
    review_package_hashes: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ValueError("scheduled inspection status is invalid")
        if type(self.idempotency_key) is not str or not self.idempotency_key:
            raise ValueError("scheduled inspection idempotency key is invalid")
        if self.status == "QUIET" and self.question is not None:
            raise ValueError("quiet inspection cannot ask a question")


@dataclass(frozen=True)
class SessionDeliveryResult:
    status: str
    runtime: str
    idempotency_key: str
    session_id: Optional[str]
    created: bool


def _require_sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ScheduledInspectionError(f"{label} identity is invalid")
    return value


def _blocked_result(
    request: ScheduledInspectionRequest,
    exc: WorkstreamCurationError,
) -> ScheduledInspectionResult:
    reason_code = exc.reason_code
    identity = sha256_bytes(
        canonical_json_bytes(
            {
                "reason_code": reason_code,
                "workstream_ref": request.workstream_ref,
            }
        )
    )
    return ScheduledInspectionResult(
        status="REVIEW_READY",
        action_kind="INSPECTION_BLOCKED",
        workstream_id=request.workstream_ref,
        idempotency_key=f"mnemosyne-review:{identity}",
        brief=(
            f"{request.workstream_ref} Workstream 검사가 중지되었습니다.\n"
            f"이유: {reason_code}\n"
            f"다음 안전한 행동: {exc.next_safe_action}"
        ),
        question="표시된 상태를 확인한 뒤 이 Workstream을 다시 검사할까요?",
        plan_sha256=None,
        source_observation_sha256=None,
        review_package_directory=None,
        review_package_hashes=(),
    )


def _require_inspection_result(value: object) -> tuple[dict[str, object], dict[str, object]]:
    if type(value) is not dict or value.get("outcome_kind") != "completed":
        raise ScheduledInspectionError("inspection did not return a completed result")
    result = value.get("result")
    if type(result) is not dict:
        raise ScheduledInspectionError("inspection result is invalid")
    plan = result.get("plan")
    package = result.get("review_package")
    workstream = result.get("workstream")
    if type(plan) is not dict or type(package) is not dict or type(workstream) is not dict:
        raise ScheduledInspectionError("inspection result is incomplete")
    return result, plan


def _effect_rows(effects: list[object]) -> list[str]:
    rows: list[str] = []
    for index, effect in enumerate(effects, 1):
        if type(effect) is not dict:
            raise ScheduledInspectionError("Plan effect is invalid")
        action = effect.get("action")
        source = effect.get("source")
        target = effect.get("target")
        if not all(type(value) is str and value for value in (action, source, target)):
            raise ScheduledInspectionError("Plan effect summary is incomplete")
        rows.append(f"{index}. {action}: {source} -> {target}")
    return rows


def _finding_rows(findings: list[object]) -> list[str]:
    rows: list[str] = []
    for index, finding in enumerate(findings, 1):
        if type(finding) is not dict:
            raise ScheduledInspectionError("Plan finding is invalid")
        kind = finding.get("kind")
        path = finding.get("path")
        if not all(type(value) is str and value for value in (kind, path)):
            raise ScheduledInspectionError("Plan finding summary is incomplete")
        rows.append(f"판단 {index}. {kind}: {path}")
    return rows


def run_scheduled_inspection(
    request: ScheduledInspectionRequest,
    *,
    inspector: Callable[..., dict[str, object]] = inspect_workstream,
) -> ScheduledInspectionResult:
    """Run the existing current-source inspection behind one concrete contract."""

    if type(request) is not ScheduledInspectionRequest:
        raise TypeError("scheduled inspection request is invalid")
    try:
        raw = inspector(
            root=request.root,
            workstream_ref=request.workstream_ref,
            review_package_directory=request.review_package_directory,
            max_items=request.max_items,
            max_depth=request.max_depth,
            max_hint_bytes=request.max_hint_bytes,
            actor=request.actor,
        )
    except WorkstreamCurationError as exc:
        return _blocked_result(request, exc)
    result, plan = _require_inspection_result(raw)
    plan_sha256 = _require_sha(plan.get("sha256"), "Plan")
    source_sha256 = _require_sha(
        plan.get("source_observation_sha256"),
        "source observation",
    )
    effects = plan.get("effects")
    findings = plan.get("findings")
    package = result["review_package"]
    workstream = result["workstream"]
    if (
        type(effects) is not list
        or type(findings) is not list
        or type(package.get("directory")) is not str
        or not package["directory"]
        or type(workstream.get("id")) is not str
        or not workstream["id"]
    ):
        raise ScheduledInspectionError("inspection membership is invalid")
    package_hashes = tuple(
        (key, _require_sha(package.get(key), key)) for key in _PACKAGE_HASH_KEYS
    )
    idempotency_key = f"mnemosyne-review:{plan_sha256}"
    if not effects and not findings:
        return ScheduledInspectionResult(
            status="QUIET",
            action_kind="NO_ACTIONABLE_CHANGE",
            workstream_id=workstream["id"],
            idempotency_key=idempotency_key,
            brief=f"{workstream['id']} Workstream에 승인할 변경이 없습니다.",
            question=None,
            plan_sha256=plan_sha256,
            source_observation_sha256=source_sha256,
            review_package_directory=package["directory"],
            review_package_hashes=package_hashes,
        )
    summary_rows = _effect_rows(effects) + _finding_rows(findings)
    brief = (
        f"{workstream['id']} Workstream 정리안이 준비되었습니다.\n"
        + "\n".join(summary_rows)
        + f"\n전체 근거: {package['directory']}"
    )
    if effects:
        action_kind = "PLAN_REVIEW"
        question = "이 Curation Plan을 승인, 일부 승인, 거절, 보류 중 어떻게 처리할까요?"
    else:
        action_kind = "FINDING_REVIEW"
        question = "판단이 필요한 항목을 어떻게 처리할까요?"
    return ScheduledInspectionResult(
        status="REVIEW_READY",
        action_kind=action_kind,
        workstream_id=workstream["id"],
        idempotency_key=idempotency_key,
        brief=brief,
        question=question,
        plan_sha256=plan_sha256,
        source_observation_sha256=source_sha256,
        review_package_directory=package["directory"],
        review_package_hashes=package_hashes,
    )


def _delivery_payload(result: ScheduledInspectionResult) -> dict[str, object]:
    return {
        "action_kind": result.action_kind,
        "brief": result.brief,
        "idempotency_key": result.idempotency_key,
        "plan_sha256": result.plan_sha256,
        "question": result.question,
        "review_package_directory": result.review_package_directory,
        "review_package_hashes": dict(result.review_package_hashes),
        "source_observation_sha256": result.source_observation_sha256,
        "workstream_id": result.workstream_id,
    }


def _pending_delivery_result(
    result: ScheduledInspectionResult,
    *,
    runtime: str,
) -> SessionDeliveryResult:
    return SessionDeliveryResult(
        status="PENDING_DELIVERY",
        runtime=runtime,
        idempotency_key=result.idempotency_key,
        session_id=None,
        created=False,
    )


def _deliver(
    result: ScheduledInspectionResult,
    *,
    runtime: str,
    create_or_get_session: Optional[
        Callable[[str, dict[str, object]], Mapping[str, object]]
    ],
) -> SessionDeliveryResult:
    if type(result) is not ScheduledInspectionResult:
        raise TypeError("scheduled inspection result is invalid")
    if result.status != "REVIEW_READY":
        return SessionDeliveryResult(
            status=result.status,
            runtime=runtime,
            idempotency_key=result.idempotency_key,
            session_id=None,
            created=False,
        )
    if create_or_get_session is None:
        return _pending_delivery_result(result, runtime=runtime)
    try:
        delivered = create_or_get_session(
            result.idempotency_key,
            _delivery_payload(result),
        )
    except Exception:
        return _pending_delivery_result(result, runtime=runtime)
    if (
        type(delivered) is not dict
        or delivered.get("continuable") is not True
        or type(delivered.get("created")) is not bool
        or type(delivered.get("session_id")) is not str
        or not delivered["session_id"]
    ):
        return _pending_delivery_result(result, runtime=runtime)
    return SessionDeliveryResult(
        status="REVIEW_READY",
        runtime=runtime,
        idempotency_key=result.idempotency_key,
        session_id=delivered["session_id"],
        created=delivered["created"],
    )


def deliver_to_codex(
    result: ScheduledInspectionResult,
    *,
    create_or_get_session: Optional[
        Callable[[str, dict[str, object]], Mapping[str, object]]
    ],
) -> SessionDeliveryResult:
    return _deliver(
        result,
        runtime="codex",
        create_or_get_session=create_or_get_session,
    )


def deliver_to_hermes(
    result: ScheduledInspectionResult,
    *,
    create_or_get_session: Optional[
        Callable[[str, dict[str, object]], Mapping[str, object]]
    ],
) -> SessionDeliveryResult:
    return _deliver(
        result,
        runtime="hermes",
        create_or_get_session=create_or_get_session,
    )


__all__ = [
    "ScheduledInspectionError",
    "ScheduledInspectionRequest",
    "ScheduledInspectionResult",
    "SessionDeliveryResult",
    "deliver_to_codex",
    "deliver_to_hermes",
    "run_scheduled_inspection",
]
