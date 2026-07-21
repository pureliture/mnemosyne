"""Bounded noninteractive transport for canonical operation request bytes."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import BinaryIO

from .. import operation_contract
from ..canonical_json import sha256_bytes
from .canonical_file import CanonicalFileError, read_owner_only_file


MAX_REQUEST_BYTES = operation_contract.MAX_OPERATION_REQUEST_BYTES


class RequestSourceError(CanonicalFileError):
    """A request source failed before canonical request bytes existed."""


def _source_blocked() -> bytes:
    return operation_contract.OperationOutcome.blocked(
        sha256_bytes(b""),
        reason_code="UNSAFE_REQUEST_SOURCE",
        next_safe_action="correct-request-source",
    ).canonical_bytes


def _execution_blocked(raw: bytes) -> bytes:
    return operation_contract.OperationOutcome.blocked(
        sha256_bytes(raw),
        reason_code="EXECUTION_UNAVAILABLE",
        next_safe_action="inspect",
    ).canonical_bytes


def _read_request_file(value: object) -> bytes:
    return read_owner_only_file(
        value,
        label="operation request",
        max_bytes=MAX_REQUEST_BYTES,
        error_type=RequestSourceError,
    )


def _read_stdin(stdin: object) -> bytes:
    isatty = getattr(stdin, "isatty", None)
    if not callable(isatty) or isatty():
        raise RequestSourceError("dispatch stdin must be a noninteractive byte stream")
    stream = getattr(stdin, "buffer", stdin)
    read = getattr(stream, "read", None)
    if not callable(read):
        raise RequestSourceError("dispatch stdin is not readable")
    raw = read(MAX_REQUEST_BYTES + 1)
    if type(raw) is not bytes or len(raw) > MAX_REQUEST_BYTES:
        raise RequestSourceError("dispatch stdin exceeds the byte bound")
    return raw


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


def dispatch_request(
    *,
    request_file: object,
    stdin: BinaryIO,
    execute_request_bytes: Callable[[bytes], bytes],
) -> tuple[int, bytes]:
    """Read exactly one bounded source and preserve the core outcome bytes."""

    try:
        raw = _read_stdin(stdin) if request_file is None else _read_request_file(request_file)
    except RequestSourceError:
        return 2, _source_blocked()
    try:
        result = execute_request_bytes(raw)
    except Exception:
        return 2, _execution_blocked(raw)
    if type(result) is not bytes:
        return 2, _execution_blocked(raw)
    return _exit_code(result), result


__all__ = ["dispatch_request"]
