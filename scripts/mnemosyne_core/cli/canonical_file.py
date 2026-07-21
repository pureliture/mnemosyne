"""Anchored owner-only reads for canonical Curation exchange files."""

from __future__ import annotations

import os
from pathlib import Path

from .. import safety


class CanonicalFileError(ValueError):
    """A canonical exchange file failed before its bytes were trusted."""


def read_owner_only_file(
    value: object,
    *,
    label: str,
    max_bytes: int,
    error_type: type[ValueError] = CanonicalFileError,
) -> bytes:
    """Read one absolute 0600 regular file without following links."""

    if type(value) is not str:
        raise error_type(f"{label} path is invalid")
    path = Path(value)
    if (
        not path.is_absolute()
        or path.name in {"", ".", ".."}
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise error_type(f"{label} path is not canonical")
    try:
        directory_fd = safety.open_verified_directory(
            path.parent,
            require_owner_only=True,
            error_type=error_type,
        )
    except (OSError, ValueError) as exc:
        raise error_type(f"{label} parent is unsafe") from exc
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label=label,
            expected_mode=0o600,
            max_bytes=max_bytes,
            error_type=error_type,
        )
        if info.st_nlink != 1:
            raise error_type(f"{label} link count is invalid")
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            f"{label} parent",
            error_type=error_type,
        )
        return raw
    except (OSError, ValueError) as exc:
        raise error_type(f"{label} is unsafe") from exc
    finally:
        os.close(directory_fd)


__all__ = ["CanonicalFileError", "read_owner_only_file"]
