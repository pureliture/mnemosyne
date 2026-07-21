"""Canonical JSON encoding and hashing used by sealed Mnemosyne artifacts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["canonical_json_bytes", "sha256_bytes"]


def canonical_json_bytes(value: Any) -> bytes:
    """Encode *value* as stable UTF-8 JSON terminated by one newline."""
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest of *value*."""
    return hashlib.sha256(value).hexdigest()
