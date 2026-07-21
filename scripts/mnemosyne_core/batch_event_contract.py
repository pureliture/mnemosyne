"""Pure persisted-envelope contract for sealed batch events."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_CLOSE_KEYS = frozenset(
    (
        "actor",
        "batch_id",
        "event_id",
        "event_kind",
        "expected_execution_generation",
        "expected_review_revision",
        "expected_snapshot_id",
        "expected_snapshot_sha256",
        "membership_release",
        "membership_release_sha256",
        "schema_version",
        "terminal_batch_status",
    )
)
_SPLIT_KEYS = frozenset(
    (
        "actor",
        "batch_id",
        "child_batch_id",
        "child_snapshot_id",
        "child_snapshot_sha256",
        "child_submission_id",
        "event_id",
        "event_kind",
        "expected_execution_generation",
        "expected_review_revision",
        "expected_snapshot_id",
        "expected_snapshot_sha256",
        "parent_next_snapshot_id",
        "parent_next_snapshot_sha256",
        "parent_submission_id",
        "remainder_memberships",
        "remainder_unit_ids",
        "schema_version",
        "selected_memberships",
        "selected_unit_ids",
    )
)
_SUPPORTED_KINDS = frozenset(("CLOSE_REVIEW", "ABANDON", "SPLIT"))


class BatchEventContractError(ValueError):
    """A persisted batch event cannot be trusted as a sealed envelope."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ValidatedBatchEvent:
    event_id: str
    batch_id: str
    event_kind: str
    state: str
    payload: Dict[str, Any]
    membership_release: Tuple[Dict[str, str], ...]


def _storage_error() -> BatchEventContractError:
    return BatchEventContractError("batch-event-storage-invalid")


def _envelope_error() -> BatchEventContractError:
    return BatchEventContractError("batch-event-envelope-mismatch")


def _identifier(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise _storage_error()
    return value


def campaign_event_root(control_root: Path, campaign_id: Any) -> Path:
    root = Path(control_root)
    if not root.is_absolute() or any(part in (".", "..") for part in root.parts):
        raise _storage_error()
    return root / "campaigns" / _identifier(campaign_id) / "batch-events"


def campaign_snapshot_root(control_root: Path, campaign_id: Any) -> Path:
    root = Path(control_root)
    if not root.is_absolute() or any(part in (".", "..") for part in root.parts):
        raise _storage_error()
    return root / "campaigns" / _identifier(campaign_id) / "snapshots"


def split_child_request_hash(parent_batch_id: Any, child_batch_id: Any) -> str:
    parent = _identifier(parent_batch_id)
    child = _identifier(child_batch_id)
    if parent == child:
        raise _envelope_error()
    return sha256_bytes(
        canonical_json_bytes(
            {
                "child_batch_id": child,
                "kind": "split-child-genesis",
                "parent_batch_id": parent,
            }
        )
    )


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise _storage_error()
    return value


def _counter(value: Any, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or value < minimum:
        raise _storage_error()
    return value


def _text(value: Any, *, limit: int = 16 * 1024) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise _envelope_error()
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise _envelope_error() from exc
    if len(encoded) > limit or any(ord(character) < 0x20 for character in value):
        raise _envelope_error()
    return value


def validate_actor(value: Any) -> str:
    return _text(value)


def _canonical_value(raw: Any, digest: Any, *, max_bytes: int) -> Any:
    if (
        type(raw) is not bytes
        or len(raw) > max_bytes
        or type(digest) is not str
        or _HASH.fullmatch(digest) is None
        or sha256_bytes(raw) != digest
    ):
        raise _storage_error()
    try:
        value = json.loads(raw.decode("utf-8"))
        if canonical_json_bytes(value) != raw:
            raise _envelope_error()
        return value
    except BatchEventContractError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise _envelope_error() from exc


def _release_entry(value: Any) -> Dict[str, str]:
    if type(value) is not dict or set(value) != {
        "item_id",
        "membership_id",
        "path",
        "unit_id",
    }:
        raise _envelope_error()
    item_id = _identifier(value["item_id"])
    membership_id = _identifier(value["membership_id"])
    unit_id = _identifier(value["unit_id"])
    path = _text(value["path"], limit=4096)
    if (
        "\\" in path
        or path.startswith("/")
        or path.endswith("/")
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise _envelope_error()
    return {
        "item_id": item_id,
        "membership_id": membership_id,
        "path": path,
        "unit_id": unit_id,
    }


def _release_list(value: Any) -> Tuple[Dict[str, str], ...]:
    if type(value) is not list or not value:
        raise _envelope_error()
    rows = tuple(_release_entry(entry) for entry in value)
    membership_ids = tuple(row["membership_id"] for row in rows)
    if membership_ids != tuple(sorted(set(membership_ids))):
        raise _envelope_error()
    identities = {
        (row["item_id"], row["membership_id"], row["path"], row["unit_id"])
        for row in rows
    }
    if len(identities) != len(rows):
        raise _envelope_error()
    return rows


def _split_memberships(
    value: Any,
    expected_units: Tuple[str, ...],
) -> Tuple[Dict[str, str], ...]:
    if type(value) is not list or not value:
        raise _envelope_error()
    rows = []
    for entry in value:
        if type(entry) is not dict or set(entry) != {
            "item_id",
            "membership_id",
            "path",
            "status",
            "unit_id",
        }:
            raise _envelope_error()
        if entry["status"] != "OPEN":
            raise _envelope_error()
        rows.append(
            _release_entry(
                {
                    "item_id": entry["item_id"],
                    "membership_id": entry["membership_id"],
                    "path": entry["path"],
                    "unit_id": entry["unit_id"],
                }
            )
        )
    membership_ids = tuple(row["membership_id"] for row in rows)
    if membership_ids != tuple(sorted(set(membership_ids))):
        raise _envelope_error()
    if frozenset(row["unit_id"] for row in rows) != frozenset(expected_units):
        raise _envelope_error()
    return tuple(rows)


def _unit_ids(value: Any) -> Tuple[str, ...]:
    if type(value) is not list or not value:
        raise _envelope_error()
    values = tuple(_identifier(entry) for entry in value)
    if values != tuple(sorted(set(values))):
        raise _envelope_error()
    return values


def _require_null(record: Mapping[str, Any], fields: Tuple[str, ...]) -> None:
    if any(record.get(field) is not None for field in fields):
        raise _envelope_error()


def validate_batch_event(
    record: Mapping[str, Any],
    *,
    max_blob_bytes: int,
) -> ValidatedBatchEvent:
    """Validate one stored event without consulting mutable post-state."""

    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    if type(max_blob_bytes) is not int or max_blob_bytes < 0:
        raise TypeError("max_blob_bytes must be a nonnegative integer")
    event_id = _identifier(record.get("batch_event_id"))
    batch_id = _identifier(record.get("batch_id"))
    kind = record.get("event_kind")
    if type(kind) is not str:
        raise _storage_error()
    if kind not in _SUPPORTED_KINDS:
        raise BatchEventContractError("unsupported-batch-event-kind")
    expected_snapshot_id = _identifier(record.get("expected_snapshot_id"))
    expected_snapshot_hash = _hash(record.get("expected_snapshot_sha256"))
    expected_revision = _counter(
        record.get("expected_review_revision"),
        positive=True,
    )
    expected_generation = _counter(
        record.get("expected_execution_generation")
    )
    membership_release = _release_list(
        _canonical_value(
            record.get("membership_release_json"),
            record.get("membership_release_sha256"),
            max_bytes=max_blob_bytes,
        )
    )
    payload = _canonical_value(
        record.get("payload_json"),
        record.get("payload_sha256"),
        max_bytes=max_blob_bytes,
    )
    if type(payload) is not dict:
        raise _envelope_error()
    if record.get("final_sha256") != record.get("payload_sha256"):
        raise _envelope_error()
    state = record.get("state")
    if state not in ("PREPARED", "PUBLISHED", "BLOCKED"):
        raise _storage_error()

    payload_revision = payload.get("expected_review_revision")
    payload_generation = payload.get("expected_execution_generation")
    common = (
        type(payload.get("schema_version")) is int
        and payload.get("schema_version") == 1
        and payload.get("event_id") == event_id
        and payload.get("batch_id") == batch_id
        and payload.get("event_kind") == kind
        and payload.get("expected_snapshot_id") == expected_snapshot_id
        and payload.get("expected_snapshot_sha256") == expected_snapshot_hash
        and type(payload_revision) is int
        and payload_revision == expected_revision
        and type(payload_generation) is int
        and payload_generation == expected_generation
    )
    if not common:
        raise _envelope_error()
    validate_actor(payload.get("actor"))

    if kind in ("CLOSE_REVIEW", "ABANDON"):
        terminal = "CLOSED_REVIEW" if kind == "CLOSE_REVIEW" else "ABANDONED"
        if (
            set(payload) != _CLOSE_KEYS
            or record.get("expected_batch_status") != "OPEN"
            or record.get("terminal_batch_status") != terminal
            or payload.get("terminal_batch_status") != terminal
            or payload.get("membership_release_sha256")
            != record.get("membership_release_sha256")
            or payload.get("membership_release") != list(membership_release)
        ):
            raise _envelope_error()
        _require_null(
            record,
            (
                "child_batch_id",
                "child_snapshot_id",
                "child_snapshot_sha256",
                "source_execution_id",
                "source_approval_id",
                "result_path",
                "result_sha256",
            ),
        )
    else:
        if (
            set(payload) != _SPLIT_KEYS
            or record.get("expected_batch_status") != "OPEN"
            or record.get("terminal_batch_status") is not None
        ):
            raise _envelope_error()
        child_batch_id = _identifier(payload.get("child_batch_id"))
        child_snapshot_id = _identifier(payload.get("child_snapshot_id"))
        child_snapshot_hash = _hash(payload.get("child_snapshot_sha256"))
        for field in (
            "child_submission_id",
            "parent_next_snapshot_id",
            "parent_submission_id",
        ):
            _identifier(payload.get(field))
        _hash(payload.get("parent_next_snapshot_sha256"))
        if (
            child_batch_id == batch_id
            or len(
                {
                    expected_snapshot_id,
                    child_snapshot_id,
                    payload.get("parent_next_snapshot_id"),
                }
            )
            != 3
            or payload.get("child_submission_id")
            == payload.get("parent_submission_id")
            or record.get("child_batch_id") != child_batch_id
            or record.get("child_snapshot_id") != child_snapshot_id
            or record.get("child_snapshot_sha256") != child_snapshot_hash
        ):
            raise _envelope_error()
        _require_null(
            record,
            (
                "source_execution_id",
                "source_approval_id",
                "result_path",
                "result_sha256",
            ),
        )
        selected_units = _unit_ids(payload.get("selected_unit_ids"))
        remainder_units = _unit_ids(payload.get("remainder_unit_ids"))
        if set(selected_units) & set(remainder_units):
            raise _envelope_error()
        selected = _split_memberships(
            payload.get("selected_memberships"),
            selected_units,
        )
        remainder = _split_memberships(
            payload.get("remainder_memberships"),
            remainder_units,
        )
        combined = tuple(
            sorted(selected + remainder, key=lambda row: row["membership_id"])
        )
        if combined != membership_release:
            raise _envelope_error()

    return ValidatedBatchEvent(
        event_id=event_id,
        batch_id=batch_id,
        event_kind=kind,
        state=state,
        payload=payload,
        membership_release=membership_release,
    )


__all__ = [
    "BatchEventContractError",
    "ValidatedBatchEvent",
    "campaign_event_root",
    "campaign_snapshot_root",
    "split_child_request_hash",
    "validate_actor",
    "validate_batch_event",
]
