"""Non-authoritative copy-on-write review draft checkouts.

The trusted loader owns sealed snapshot/package verification.  This module
binds that exact immutable snapshot to an owner-only draft checkout and only
accepts edits made through the visible, typed marker rows appended to the
ReviewCompiler Markdown.  It never writes the ledger or source corpus.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Tuple

from . import safety
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_MARKER_PREFIX = "- [mnemosyne-draft-field-v1] "
_DECISIONS = frozenset(
    (
        "pending",
        "accept-recommendation",
        "keep",
        "link",
        "defer",
        "exclude",
        "proposal-reject",
        "correction",
    )
)
_ACTIONS = frozenset(("keep", "link", "move", "archive", "defer", "exclude"))
_AUTHORITIES = frozenset(
    ("canonical", "reference", "derived", "evidence", "ephemeral", "unknown")
)
_LIFECYCLES = frozenset(("current", "draft", "superseded", "archival", "unknown"))
_CORRECTION_FIELDS = (
    "primary_workstream",
    "related_workstreams",
    "shared",
    "document_role",
    "authority",
    "document_lifecycle",
    "recommended_action",
    "target_path",
)
_MARKER_FIELDS = ("decision",) + tuple(
    "correction.%s" % field for field in _CORRECTION_FIELDS
)
_DEFAULT_VALUES = {field: "unchanged" for field in _MARKER_FIELDS}
_DEFAULT_VALUES["decision"] = "pending"
_DRAFT_NOTICE = (
    "이 파일은 비권위 검토 초안입니다. marker value만 편집할 수 있으며 "
    "승인이나 파일 변경 권한을 만들지 않습니다."
)
_MANIFEST_KEYS = frozenset(
    (
        "allowed_marker_fields",
        "approval_ready",
        "authority",
        "base_review_markdown_sha256",
        "base_snapshot_id",
        "base_snapshot_sha256",
        "draft_id",
        "item_ids",
        "kind",
        "owner_actor",
        "review_draft_template_sha256",
        "schema_version",
    )
)
_MAX_DRAFT_FILE_BYTES = {
    "draft.json": 256 * 1024,
    "review.draft.md": 64 * 1024 * 1024,
}


class ReviewDraftError(Exception):
    """Base error for review draft checkout and validation."""


class ReviewDraftValidationError(ReviewDraftError, ValueError):
    """Draft bytes, markers, identities, or filesystem evidence are invalid."""


class ReviewDraftConflict(ReviewDraftError):
    """A preallocated identity or existing path is bound to different bytes."""


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ReviewDraftValidationError("%s is invalid" % label)
    return value


def _hash(value: str, label: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise ReviewDraftValidationError("%s is invalid" % label)
    return value


def _actor(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ReviewDraftValidationError("actor is invalid")
    return value


def _canonical_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ReviewDraftValidationError("%s must be raw-relative" % label)
    if (
        posixpath.normpath(value) != value
        or value in (".", "..")
        or value.startswith("../")
        or value.endswith("/")
        or any(ord(character) < 0x20 for character in value)
        or any(character in value for character in "<>`")
    ):
        raise ReviewDraftValidationError("%s must be canonical and display-safe" % label)
    return value


def _display_escape(value: str) -> str:
    output = []
    for character in value:
        codepoint = ord(character)
        if (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or 0x202A <= codepoint <= 0x202E
            or 0x2066 <= codepoint <= 0x2069
            or codepoint in (0x200E, 0x200F, 0x061C)
            or character in "\\|`<>#"
        ):
            output.append("\\u%04X" % codepoint)
        else:
            output.append(character)
    return "".join(output)


@dataclass(frozen=True)
class TrustedReviewSnapshot:
    snapshot_id: str
    snapshot_sha256: str
    snapshot_bytes: bytes
    review_markdown: bytes
    review_markdown_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.snapshot_id, "snapshot id")
        _hash(self.snapshot_sha256, "snapshot hash")
        _hash(self.review_markdown_sha256, "review Markdown hash")
        if type(self.snapshot_bytes) is not bytes:
            raise ReviewDraftValidationError("snapshot bytes must be immutable bytes")
        if type(self.review_markdown) is not bytes:
            raise ReviewDraftValidationError("review Markdown must be immutable bytes")


@dataclass(frozen=True)
class ReviewDraftRequest:
    draft_id: str
    base_snapshot_id: str
    base_snapshot_sha256: str
    actor: str

    def __post_init__(self) -> None:
        _identifier(self.draft_id, "draft id")
        _identifier(self.base_snapshot_id, "base snapshot id")
        _hash(self.base_snapshot_sha256, "base snapshot hash")
        _actor(self.actor)


@dataclass(frozen=True)
class DraftItemEdit:
    unit_id: str
    decision: str
    corrections: Tuple[Tuple[str, object], ...]


@dataclass(frozen=True)
class ReviewDraft:
    path: Path
    draft_id: str
    base_snapshot_id: str
    base_snapshot_sha256: str
    actor: str
    authority: bool
    approval_ready: bool
    template_markdown_sha256: str
    current_markdown_sha256: str
    edits: Tuple[DraftItemEdit, ...]


def _markdown_cells(line: str) -> Tuple[str, ...]:
    if not line.startswith("|") or not line.endswith("|"):
        raise ReviewDraftValidationError("review Markdown table is invalid")
    return tuple(cell.strip() for cell in line[1:-1].split("|"))


def _table_after_heading(lines: Tuple[str, ...], heading: str) -> Tuple[Tuple[str, ...], ...]:
    positions = [index for index, line in enumerate(lines) if line == heading]
    if len(positions) != 1:
        raise ReviewDraftValidationError("review Markdown section identity is invalid")
    index = positions[0] + 1
    if index < len(lines) and lines[index] == "":
        index += 1
    if index + 1 >= len(lines):
        raise ReviewDraftValidationError("review Markdown table is incomplete")
    header = _markdown_cells(lines[index])
    separator = _markdown_cells(lines[index + 1])
    if len(header) != len(separator) or any(value != "---" for value in separator):
        raise ReviewDraftValidationError("review Markdown table header is invalid")
    rows = []
    index += 2
    while index < len(lines) and lines[index] != "":
        cells = _markdown_cells(lines[index])
        if len(cells) != len(header):
            raise ReviewDraftValidationError("review Markdown row width is invalid")
        rows.append(cells)
        index += 1
    return (header,) + tuple(rows)


def _snapshot_membership(snapshot: TrustedReviewSnapshot) -> Tuple[str, ...]:
    if sha256_bytes(snapshot.snapshot_bytes) != snapshot.snapshot_sha256:
        raise ReviewDraftConflict("trusted loader snapshot hash mismatch")
    try:
        payload = json.loads(snapshot.snapshot_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewDraftValidationError("trusted snapshot JSON is invalid") from exc
    if canonical_json_bytes(payload) != snapshot.snapshot_bytes:
        raise ReviewDraftValidationError("trusted snapshot JSON is not canonical")
    if payload.get("snapshot_id") != snapshot.snapshot_id:
        raise ReviewDraftConflict("trusted loader snapshot identity mismatch")
    if payload.get("authority") not in (None, False):
        raise ReviewDraftValidationError("trusted snapshot claims authority")
    if payload.get("approval_ready") is not False:
        raise ReviewDraftValidationError("trusted snapshot is approval-ready")
    if payload.get("structural_approval_ready") is not False:
        raise ReviewDraftValidationError("trusted snapshot has structural authority")
    units = payload.get("units")
    if not isinstance(units, list) or not units:
        raise ReviewDraftValidationError("trusted snapshot membership is missing")
    item_ids = []
    for unit in units:
        if not isinstance(unit, dict):
            raise ReviewDraftValidationError("trusted snapshot unit is invalid")
        item_ids.append(_identifier(unit.get("unit_id"), "review unit id"))
    if tuple(sorted(set(item_ids))) != tuple(item_ids):
        raise ReviewDraftValidationError("trusted snapshot membership is not unique and sorted")
    return tuple(item_ids)


def _validate_review_markdown(
    snapshot: TrustedReviewSnapshot,
    item_ids: Tuple[str, ...],
) -> None:
    if sha256_bytes(snapshot.review_markdown) != snapshot.review_markdown_sha256:
        raise ReviewDraftConflict("trusted loader review Markdown hash mismatch")
    try:
        text = snapshot.review_markdown.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReviewDraftValidationError("review Markdown is not UTF-8") from exc
    if not text.endswith("\n"):
        raise ReviewDraftValidationError("review Markdown is not newline-terminated")
    if "<" in text:
        raise ReviewDraftValidationError("review Markdown contains raw HTML")
    lines = tuple(text.splitlines())
    identity_table = _table_after_heading(lines, "## 검토본 식별 {#identity}")
    if identity_table[0] != ("필드", "값"):
        raise ReviewDraftValidationError("review Markdown identity header is invalid")
    identity = {}
    for row in identity_table[1:]:
        if row[0] in identity:
            raise ReviewDraftValidationError("review Markdown identity is duplicated")
        identity[row[0]] = row[1]
    if (
        identity.get("Snapshot ID") != snapshot.snapshot_id
        or identity.get("Source snapshot SHA-256") != snapshot.snapshot_sha256
        or identity.get("Structural approval ready") != "false"
    ):
        raise ReviewDraftConflict("review Markdown base identity mismatch")
    item_table = _table_after_heading(lines, "## 검토 항목 {#items}")
    if not item_table[0] or item_table[0][0] != "ID":
        raise ReviewDraftValidationError("review Markdown item header is invalid")
    markdown_ids = tuple(row[0] for row in item_table[1:])
    if markdown_ids != item_ids:
        raise ReviewDraftValidationError("review Markdown membership mismatch")


def _load_trusted_snapshot(
    request: ReviewDraftRequest,
    snapshot_loader: Callable[[str, str], TrustedReviewSnapshot],
) -> Tuple[TrustedReviewSnapshot, Tuple[str, ...]]:
    if not callable(snapshot_loader):
        raise TypeError("snapshot_loader must be callable")
    snapshot = snapshot_loader(
        request.base_snapshot_id,
        request.base_snapshot_sha256,
    )
    if type(snapshot) is not TrustedReviewSnapshot:
        raise ReviewDraftConflict("trusted loader returned an invalid value")
    if (
        snapshot.snapshot_id != request.base_snapshot_id
        or snapshot.snapshot_sha256 != request.base_snapshot_sha256
    ):
        raise ReviewDraftConflict("trusted loader returned another base identity")
    item_ids = _snapshot_membership(snapshot)
    _validate_review_markdown(snapshot, item_ids)
    return snapshot, item_ids


def _marker_line(unit_id: str, field: str, value: str) -> str:
    encoded = canonical_json_bytes(
        {"field": field, "unit_id": unit_id, "value": value}
    ).decode("utf-8").rstrip("\n")
    return _MARKER_PREFIX + encoded


def _render_draft_markdown(
    snapshot: TrustedReviewSnapshot,
    request: ReviewDraftRequest,
    item_ids: Tuple[str, ...],
    values: Dict[Tuple[str, str], str],
) -> bytes:
    base = snapshot.review_markdown.decode("utf-8")
    lines = [
        "",
        "## 편집 가능한 검토 초안 {#draft-edits}",
        "",
        "> [draft-notice:non-authoritative] %s" % _DRAFT_NOTICE,
        "",
        "- Draft ID: `%s`" % request.draft_id,
        "- Base snapshot ID: `%s`" % request.base_snapshot_id,
        "- Base snapshot SHA-256: `%s`" % request.base_snapshot_sha256,
        "- Owner actor: `%s`" % _display_escape(request.actor),
        "- Authority: `false`",
        "- Approval ready: `false`",
        "",
        "아래 marker의 `value`만 수정할 수 있습니다.",
    ]
    for unit_id in item_ids:
        lines.extend(("", "### Draft item `%s` {#draft-item-%s}" % (unit_id, unit_id)))
        for field in _MARKER_FIELDS:
            lines.append(_marker_line(unit_id, field, values[(unit_id, field)]))
    return (base + "\n".join(lines) + "\n").encode("utf-8")


def _default_values(item_ids: Tuple[str, ...]) -> Dict[Tuple[str, str], str]:
    return {
        (unit_id, field): _DEFAULT_VALUES[field]
        for unit_id in item_ids
        for field in _MARKER_FIELDS
    }


def _validate_marker_value(field: str, value: object) -> str:
    if not isinstance(value, str):
        raise ReviewDraftValidationError("draft marker value must be text")
    if any(ord(character) < 0x20 for character in value) or any(
        character in value for character in "<>`"
    ):
        raise ReviewDraftValidationError("draft marker contains raw HTML or controls")
    if field == "decision":
        if value not in _DECISIONS:
            raise ReviewDraftValidationError("draft decision is invalid")
        return value
    correction = field.split(".", 1)[1]
    if value == "unchanged":
        return value
    if correction in ("primary_workstream", "document_role"):
        return _identifier(value, correction)
    if correction == "authority":
        if value not in _AUTHORITIES:
            raise ReviewDraftValidationError("draft authority correction is invalid")
        return value
    if correction == "document_lifecycle":
        if value not in _LIFECYCLES:
            raise ReviewDraftValidationError("draft lifecycle correction is invalid")
        return value
    if correction == "recommended_action":
        if value not in _ACTIONS:
            raise ReviewDraftValidationError("draft action correction is invalid")
        return value
    if correction == "shared":
        if value not in ("true", "false"):
            raise ReviewDraftValidationError("draft shared correction is invalid")
        return value
    if correction == "related_workstreams":
        if value == "none":
            return value
        related = tuple(value.split(","))
        if tuple(sorted(set(related))) != related:
            raise ReviewDraftValidationError("related Workstream correction is not sorted")
        for workstream in related:
            _identifier(workstream, "related Workstream")
        return value
    if correction == "target_path":
        if value == "none":
            return value
        return _canonical_path(value, "target path correction")
    raise ReviewDraftValidationError("draft correction field is unsupported")


def _parse_draft_markdown(
    encoded: bytes,
    *,
    snapshot: TrustedReviewSnapshot,
    request: ReviewDraftRequest,
    item_ids: Tuple[str, ...],
) -> Tuple[DraftItemEdit, ...]:
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReviewDraftValidationError("review draft is not UTF-8") from exc
    if "<" in text:
        raise ReviewDraftValidationError("review draft contains raw HTML")
    observed = {}
    for line in text.splitlines():
        if not line.startswith(_MARKER_PREFIX):
            continue
        raw = line[len(_MARKER_PREFIX) :]
        try:
            marker = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ReviewDraftValidationError("draft marker JSON is invalid") from exc
        if (
            not isinstance(marker, dict)
            or set(marker) != {"field", "unit_id", "value"}
            or canonical_json_bytes(marker).decode("utf-8").rstrip("\n") != raw
        ):
            raise ReviewDraftValidationError("draft marker is not canonical")
        unit_id = marker["unit_id"]
        field = marker["field"]
        if unit_id not in item_ids or field not in _MARKER_FIELDS:
            raise ReviewDraftValidationError("draft marker membership is invalid")
        key = (unit_id, field)
        if key in observed:
            raise ReviewDraftValidationError("draft marker membership is duplicated")
        observed[key] = _validate_marker_value(field, marker["value"])
    expected_keys = {
        (unit_id, field) for unit_id in item_ids for field in _MARKER_FIELDS
    }
    if set(observed) != expected_keys:
        raise ReviewDraftValidationError("draft marker membership is incomplete")
    for unit_id in item_ids:
        changed = [
            field
            for field in _CORRECTION_FIELDS
            if observed[(unit_id, "correction.%s" % field)] != "unchanged"
        ]
        decision = observed[(unit_id, "decision")]
        if changed and decision != "correction":
            raise ReviewDraftValidationError(
                "draft corrections require the correction decision"
            )
        if decision == "correction" and not changed:
            raise ReviewDraftValidationError(
                "correction decision requires at least one correction"
            )
    expected = _render_draft_markdown(snapshot, request, item_ids, observed)
    if expected != encoded:
        raise ReviewDraftValidationError("review draft contains non-marker changes")
    edits = []
    for unit_id in item_ids:
        corrections = []
        for field in _CORRECTION_FIELDS:
            value = observed[(unit_id, "correction.%s" % field)]
            if value == "unchanged":
                continue
            typed: object = value
            if field == "related_workstreams":
                typed = () if value == "none" else tuple(value.split(","))
            elif field == "shared":
                typed = value == "true"
            elif field == "target_path" and value == "none":
                typed = None
            corrections.append((field, typed))
        edits.append(
            DraftItemEdit(
                unit_id=unit_id,
                decision=observed[(unit_id, "decision")],
                corrections=tuple(corrections),
            )
        )
    return tuple(edits)


def _manifest_bytes(
    request: ReviewDraftRequest,
    snapshot: TrustedReviewSnapshot,
    item_ids: Tuple[str, ...],
    template_sha256: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "allowed_marker_fields": list(_MARKER_FIELDS),
            "approval_ready": False,
            "authority": False,
            "base_review_markdown_sha256": snapshot.review_markdown_sha256,
            "base_snapshot_id": request.base_snapshot_id,
            "base_snapshot_sha256": request.base_snapshot_sha256,
            "draft_id": request.draft_id,
            "item_ids": list(item_ids),
            "kind": "mnemosyne-review-draft-v1",
            "owner_actor": request.actor,
            "review_draft_template_sha256": template_sha256,
            "schema_version": 1,
        }
    )


def _require_absolute_root(path: Path) -> Path:
    value = Path(path)
    if not value.is_absolute() or any(part in (".", "..") for part in value.parts):
        raise ReviewDraftValidationError("drafts root must be canonical and absolute")
    return value


def _require_directory(path: Path, label: str) -> Tuple[str, ...]:
    try:
        directory_fd = safety.open_verified_directory(
            path,
            require_owner_only=True,
            error_type=ReviewDraftValidationError,
        )
    except ReviewDraftValidationError as exc:
        raise ReviewDraftValidationError(
            "%s directory identity is invalid" % label
        ) from exc
    try:
        opened = os.fstat(directory_fd)
        lexical = path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
            or (opened.st_dev, opened.st_ino)
            != (lexical.st_dev, lexical.st_ino)
        ):
            raise ReviewDraftValidationError(
                "%s directory identity is invalid" % label
            )
        return tuple(sorted(os.listdir(directory_fd)))
    except OSError as exc:
        raise ReviewDraftValidationError(
            "%s directory cannot be listed" % label
        ) from exc
    finally:
        os.close(directory_fd)


def _safe_regular_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1
    )


def _stable_file_identity(info: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_regular(path: Path, label: str) -> bytes:
    limit = _MAX_DRAFT_FILE_BYTES[label]
    try:
        lexical_before = path.lstat()
    except OSError as exc:
        raise ReviewDraftValidationError("%s identity is unreadable" % label) from exc
    if not _safe_regular_file(lexical_before):
        raise ReviewDraftValidationError("%s identity is invalid" % label)
    if lexical_before.st_size > limit:
        raise ReviewDraftValidationError("%s exceeds size limit" % label)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
        try:
            opened_before = os.fstat(descriptor)
            if (
                not _safe_regular_file(opened_before)
                or _stable_file_identity(opened_before)
                != _stable_file_identity(lexical_before)
            ):
                raise ReviewDraftValidationError("%s identity changed" % label)
            chunks = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, limit - total + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise ReviewDraftValidationError(
                        "%s exceeds size limit" % label
                    )
            opened_after = os.fstat(descriptor)
            try:
                lexical_after = path.lstat()
            except OSError as exc:
                raise ReviewDraftValidationError(
                    "%s changed while read" % label
                ) from exc
            if (
                not _safe_regular_file(opened_after)
                or not _safe_regular_file(lexical_after)
                or _stable_file_identity(opened_before)
                != _stable_file_identity(opened_after)
                or _stable_file_identity(opened_after)
                != _stable_file_identity(lexical_after)
                or total != opened_after.st_size
            ):
                raise ReviewDraftValidationError("%s changed while read" % label)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ReviewDraftValidationError("%s cannot be opened no-follow" % label) from exc
    return b"".join(chunks)


def _publish_file(path: Path, encoded: bytes, label: str) -> None:
    safety.publish_bytes_atomic_no_replace(
        path,
        encoded,
        label=label,
        mode=0o600,
        create_parent=False,
        collision_error="%s already exists" % label,
        final_identity_error="%s final identity mismatch" % label,
        parent_error="%s parent is invalid" % label,
        error_type=ReviewDraftConflict,
        after_fd_readback=lambda _path, _fd, _directory_fd: None,
    )


def _preflight_package(
    path: Path,
    expected: Dict[str, bytes],
    *,
    final: bool,
) -> Tuple[str, ...]:
    names = _require_directory(path, "review draft" if final else "review draft staging")
    allowed = set(expected)
    if not set(names).issubset(allowed) or (final and set(names) != allowed):
        raise ReviewDraftValidationError("review draft package members are invalid")
    for name in names:
        if _read_regular(path / name, name) != expected[name]:
            raise ReviewDraftConflict("review draft path contains different bytes")
    return names


def _require_staging_absent_beside_final(staging_path: Path) -> None:
    if os.path.lexists(staging_path):
        raise ReviewDraftConflict(
            "conflicting review draft staging exists beside final package"
        )


def _publish_checkout(
    drafts_root: Path,
    request: ReviewDraftRequest,
    manifest: bytes,
    markdown: bytes,
) -> Path:
    final_path = drafts_root / request.draft_id
    staging_path = drafts_root / (".incomplete-%s" % request.draft_id)
    expected = {"draft.json": manifest, "review.draft.md": markdown}
    try:
        final_path.lstat()
    except FileNotFoundError:
        pass
    else:
        _preflight_package(final_path, expected, final=True)
        _require_staging_absent_beside_final(staging_path)
        return final_path
    root_fd = safety.open_or_create_verified_directory(
        drafts_root,
        error_type=ReviewDraftValidationError,
    )
    os.close(root_fd)
    try:
        staging_path.lstat()
    except FileNotFoundError:
        safety.create_verified_directory_no_replace(
            staging_path,
            label="review draft staging",
            collision_error="review draft staging already exists",
            mode=0o700,
            error_type=ReviewDraftConflict,
        )
    existing = _preflight_package(staging_path, expected, final=False)
    for name in ("draft.json", "review.draft.md"):
        if name not in existing:
            _publish_file(staging_path / name, expected[name], name)
    _preflight_package(staging_path, expected, final=True)
    try:
        safety.rename_path_no_replace(
            staging_path,
            final_path,
            collision_error="review draft final path already exists",
            require_directory=True,
            error_type=ReviewDraftConflict,
        )
    except ReviewDraftConflict:
        try:
            final_path.lstat()
        except OSError:
            raise
        _preflight_package(final_path, expected, final=True)
        _require_staging_absent_beside_final(staging_path)
    _preflight_package(final_path, expected, final=True)
    return final_path


def _parse_manifest(
    encoded: bytes,
    request: ReviewDraftRequest,
    snapshot: TrustedReviewSnapshot,
    item_ids: Tuple[str, ...],
) -> dict:
    try:
        manifest = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewDraftValidationError("draft.json is invalid") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != _MANIFEST_KEYS
        or canonical_json_bytes(manifest) != encoded
    ):
        raise ReviewDraftValidationError("draft.json is not canonical")
    expected_identity = (
        request.draft_id,
        request.base_snapshot_id,
        request.base_snapshot_sha256,
        request.actor,
    )
    observed_identity = (
        manifest.get("draft_id"),
        manifest.get("base_snapshot_id"),
        manifest.get("base_snapshot_sha256"),
        manifest.get("owner_actor"),
    )
    if observed_identity != expected_identity:
        raise ReviewDraftConflict("review draft identity was manipulated")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("kind") != "mnemosyne-review-draft-v1"
        or manifest.get("authority") is not False
        or manifest.get("approval_ready") is not False
        or manifest.get("allowed_marker_fields") != list(_MARKER_FIELDS)
        or manifest.get("item_ids") != list(item_ids)
        or manifest.get("base_review_markdown_sha256")
        != snapshot.review_markdown_sha256
    ):
        raise ReviewDraftValidationError("draft.json contract is invalid")
    _hash(manifest.get("review_draft_template_sha256"), "draft template hash")
    return manifest


def _validate_directory(
    path: Path,
    request: ReviewDraftRequest,
    snapshot: TrustedReviewSnapshot,
    item_ids: Tuple[str, ...],
) -> ReviewDraft:
    names = _require_directory(path, "review draft")
    if names != ("draft.json", "review.draft.md"):
        raise ReviewDraftValidationError("review draft package members are invalid")
    manifest_bytes = _read_regular(path / "draft.json", "draft.json")
    markdown = _read_regular(path / "review.draft.md", "review.draft.md")
    manifest = _parse_manifest(manifest_bytes, request, snapshot, item_ids)
    defaults = _default_values(item_ids)
    template = _render_draft_markdown(snapshot, request, item_ids, defaults)
    template_sha256 = sha256_bytes(template)
    if manifest["review_draft_template_sha256"] != template_sha256:
        raise ReviewDraftConflict("review draft template identity mismatch")
    edits = _parse_draft_markdown(
        markdown,
        snapshot=snapshot,
        request=request,
        item_ids=item_ids,
    )
    return ReviewDraft(
        path=path,
        draft_id=request.draft_id,
        base_snapshot_id=request.base_snapshot_id,
        base_snapshot_sha256=request.base_snapshot_sha256,
        actor=request.actor,
        authority=False,
        approval_ready=False,
        template_markdown_sha256=template_sha256,
        current_markdown_sha256=sha256_bytes(markdown),
        edits=edits,
    )


def checkout_review(
    request: ReviewDraftRequest,
    *,
    drafts_root: Path,
    snapshot_loader: Callable[[str, str], TrustedReviewSnapshot],
) -> ReviewDraft:
    """Create or exactly replay a non-authoritative draft checkout."""
    if type(request) is not ReviewDraftRequest:
        raise TypeError("request must be ReviewDraftRequest")
    root = _require_absolute_root(Path(drafts_root))
    snapshot, item_ids = _load_trusted_snapshot(request, snapshot_loader)
    template = _render_draft_markdown(
        snapshot,
        request,
        item_ids,
        _default_values(item_ids),
    )
    manifest = _manifest_bytes(
        request,
        snapshot,
        item_ids,
        sha256_bytes(template),
    )
    path = _publish_checkout(root, request, manifest, template)
    return _validate_directory(path, request, snapshot, item_ids)


def validate_review_draft(
    request: ReviewDraftRequest,
    *,
    drafts_root: Path,
    snapshot_loader: Callable[[str, str], TrustedReviewSnapshot],
) -> ReviewDraft:
    """Load and fully validate an existing edited draft without writing.

    This is the sole public existing-draft reader.  Keeping one name avoids a
    second alias whose behavior and safety contract could drift independently.
    """
    if type(request) is not ReviewDraftRequest:
        raise TypeError("request must be ReviewDraftRequest")
    root = _require_absolute_root(Path(drafts_root))
    snapshot, item_ids = _load_trusted_snapshot(request, snapshot_loader)
    return _validate_directory(
        root / request.draft_id,
        request,
        snapshot,
        item_ids,
    )
__all__ = [
    "DraftItemEdit",
    "ReviewDraft",
    "ReviewDraftConflict",
    "ReviewDraftError",
    "ReviewDraftRequest",
    "ReviewDraftValidationError",
    "TrustedReviewSnapshot",
    "checkout_review",
    "validate_review_draft",
]
