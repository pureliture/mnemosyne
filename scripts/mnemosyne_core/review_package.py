"""Crash-aware persistence boundary for compiled M2 review artifacts.

This module accepts only :class:`ReviewArtifacts`; source document bodies never
cross this boundary.  A package is written into an already-created, dedicated,
owner-controlled staging subdirectory (for example ``batch/review/``).  The
directory may contain only the three review artifacts; batch snapshot files
belong in its parent.  Artifact names are fixed and publishing is no-replace.
The semantic manifest is always derived from the exact stored Markdown bytes
and is deliberately not persisted.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from . import review_compiler
from .canonical_json import canonical_json_bytes, sha256_bytes
from .safety import (
    open_verified_directory,
    read_open_file_bytes,
    require_same_directory_identity,
)


REVIEW_PACKAGE_FILENAMES = (
    "review.md",
    "review.html",
    "review.meta.json",
)

_ARTIFACT_BYTES = {
    "review.html": "html",
    "review.md": "markdown",
    "review.meta.json": "meta_json",
}
_META_FIELDS = frozenset(
    (
        "html_sha256",
        "locale",
        "markdown_sha256",
        "rendered_at",
        "renderer_id",
        "review_kind",
        "schema_version",
        "semantic_schema",
        "semantic_sha256",
        "source_id",
        "source_kind",
        "source_snapshot_sha256",
    )
)
_HASH = re.compile(r"^[0-9a-f]{64}$")
_MAX_ARTIFACT_BYTES = {
    "review.md": 64 * 1024 * 1024,
    "review.html": 128 * 1024 * 1024,
    "review.meta.json": 256 * 1024,
}


class ReviewPackageError(ValueError):
    """A review package cannot be safely written or verified."""


@dataclass(frozen=True)
class ReviewPackageHashes:
    markdown_sha256: str
    html_sha256: str
    meta_sha256: str
    semantic_sha256: str
    source_snapshot_sha256: str


@dataclass(frozen=True)
class ReviewPackagePayload:
    """Schema-neutral bytes accepted by the shared three-file store."""

    markdown: bytes
    html: bytes
    meta_json: bytes
    semantic_json: bytes


def _package_path(directory: Path) -> Path:
    try:
        path = Path(directory)
    except TypeError as exc:
        raise TypeError("review package directory must be path-like") from exc
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ReviewPackageError(
            "review package directory must be an absolute canonical path"
        )
    return path


def _open_flags(read_write: bool) -> int:
    flags = os.O_RDWR if read_write else os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _identity(info: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _require_safe_regular(
    info: os.stat_result,
    *,
    name: str,
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_nlink != 1
    ):
        raise ReviewPackageError(
            "%s must be an owner-only regular file with one link" % name
        )


def _read_regular_file_at(directory_fd: int, name: str) -> bytes:
    try:
        lexical_before = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise ReviewPackageError("review package artifact is missing: %s" % name) from exc
    except OSError as exc:
        raise ReviewPackageError("cannot inspect review package artifact: %s" % name) from exc
    _require_safe_regular(lexical_before, name=name)
    if lexical_before.st_size > _MAX_ARTIFACT_BYTES[name]:
        raise ReviewPackageError("review package artifact exceeds size limit: %s" % name)
    descriptor = None
    try:
        descriptor = os.open(name, _open_flags(False), dir_fd=directory_fd)
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        opened_before = os.fstat(descriptor)
        _require_safe_regular(opened_before, name=name)
        if (opened_before.st_dev, opened_before.st_ino) != (
            lexical_before.st_dev,
            lexical_before.st_ino,
        ):
            raise ReviewPackageError("review package artifact identity changed: %s" % name)
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks = []
        total = 0
        limit = _MAX_ARTIFACT_BYTES[name]
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ReviewPackageError(
                    "review package artifact exceeds size limit: %s" % name
                )
        encoded = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        lexical_after = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            _identity(opened_after) != _identity(opened_before)
            or (lexical_after.st_dev, lexical_after.st_ino)
            != (opened_before.st_dev, opened_before.st_ino)
            or len(encoded) != opened_after.st_size
        ):
            raise ReviewPackageError("review package artifact changed while read: %s" % name)
        return encoded
    except ReviewPackageError:
        raise
    except OSError as exc:
        raise ReviewPackageError("cannot read review package artifact: %s" % name) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _create_artifact_no_replace(
    directory_fd: int,
    name: str,
    encoded: bytes,
) -> None:
    flags = _open_flags(True) | os.O_CREAT | os.O_EXCL
    descriptor = None
    created = False
    try:
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
            created = True
        except FileExistsError:
            existing = _read_regular_file_at(directory_fd, name)
            if existing != encoded:
                raise ReviewPackageError("existing %s bytes differ" % name)
            return
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        _require_safe_regular(opened, name=name)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise ReviewPackageError("review package write made no progress: %s" % name)
            offset += written
        os.fsync(descriptor)
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        final = os.fstat(descriptor)
        if (
            (lexical.st_dev, lexical.st_ino) != (final.st_dev, final.st_ino)
            or read_open_file_bytes(descriptor) != encoded
        ):
            raise ReviewPackageError("review package write readback mismatch: %s" % name)
        os.fsync(directory_fd)
    except ReviewPackageError:
        raise
    except OSError as exc:
        action = "create" if not created else "write"
        raise ReviewPackageError("cannot %s review package artifact: %s" % (action, name)) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_private_meta_temp(directory_fd: int, encoded: bytes) -> str:
    """Write one fsynced, private candidate meta file beside its final name.

    A dot-prefixed temporary name is intentionally *not* part of the package
    contract.  Therefore a reader that observes it rejects the directory as
    unsealed rather than treating an in-progress write as a review package.
    """

    name = ".review.meta.json.seal-%s" % secrets.token_hex(16)
    flags = _open_flags(True) | os.O_CREAT | os.O_EXCL
    descriptor = None
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        _require_safe_regular(opened, name="review.meta.json temporary")
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise ReviewPackageError("review meta temporary write made no progress")
            offset += written
        os.fsync(descriptor)
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        final = os.fstat(descriptor)
        if (
            (lexical.st_dev, lexical.st_ino) != (final.st_dev, final.st_ino)
            or read_open_file_bytes(descriptor) != encoded
        ):
            raise ReviewPackageError("review meta temporary readback mismatch")
        os.fsync(directory_fd)
        return name
    except ReviewPackageError:
        raise
    except OSError as exc:
        raise ReviewPackageError("cannot write review meta temporary") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _publish_final_meta_no_replace(directory_fd: int, encoded: bytes) -> None:
    """Expose ``review.meta.json`` only as the final no-replace commit.

    A same-directory hard link gives the final name no-replace atomic publish
    semantics on macOS/APFS.  The temporary link is removed before the final
    artifact is accepted: a crash before that cleanup leaves an unexpected
    entry (and a link count above one), which all readers reject fail-closed.
    """

    temporary_name = _write_private_meta_temp(directory_fd, encoded)
    published = False
    try:
        try:
            os.link(
                temporary_name,
                "review.meta.json",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            published = True
        except FileExistsError:
            if _read_regular_file_at(directory_fd, "review.meta.json") != encoded:
                raise ReviewPackageError("existing review.meta.json bytes differ")
        except (AttributeError, NotImplementedError) as exc:
            raise ReviewPackageError(
                "no-replace review meta publish primitive is unavailable"
            ) from exc
        os.unlink(temporary_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        if _read_regular_file_at(directory_fd, "review.meta.json") != encoded:
            raise ReviewPackageError("review meta final readback differs")
    except ReviewPackageError:
        if not published:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except OSError:
                pass
        raise
    except OSError as exc:
        if not published:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except OSError:
                pass
        raise ReviewPackageError("cannot publish review meta final seal") from exc


def _parse_canonical_meta(meta_json: bytes) -> dict:
    try:
        meta = json.loads(meta_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewPackageError("review meta JSON is invalid") from exc
    if type(meta) is not dict or set(meta) != _META_FIELDS:
        raise ReviewPackageError("review meta fields are invalid")
    if canonical_json_bytes(meta) != meta_json:
        raise ReviewPackageError("review meta JSON is not canonical")
    for name in (
        "html_sha256",
        "markdown_sha256",
        "semantic_sha256",
        "source_snapshot_sha256",
    ):
        if type(meta[name]) is not str or _HASH.fullmatch(meta[name]) is None:
            raise ReviewPackageError("review meta hash is invalid: %s" % name)
    if (
        type(meta["schema_version"]) is not int
        or meta["schema_version"] != 1
        or meta["locale"] != "ko-KR"
        or meta["semantic_schema"] != "mnemosyne-review-semantic-v1"
    ):
        raise ReviewPackageError("review meta schema contract is invalid")
    return meta


def _derive_artifacts(
    markdown: bytes,
    rendered_html: bytes,
    meta_json: bytes,
) -> review_compiler.ReviewArtifacts:
    try:
        semantic_json = review_compiler.semantic_json_from_markdown(markdown)
    except review_compiler.ReviewCompileError as exc:
        raise ReviewPackageError("review Markdown semantic contract is invalid") from exc
    return review_compiler.ReviewArtifacts(
        markdown=markdown,
        html=rendered_html,
        meta_json=meta_json,
        semantic_json=semantic_json,
    )


def _validate_bytes(
    markdown: bytes,
    rendered_html: bytes,
    meta_json: bytes,
    *,
    expected_source_snapshot_sha256: Optional[str],
) -> ReviewPackageHashes:
    meta = _parse_canonical_meta(meta_json)
    if expected_source_snapshot_sha256 is not None:
        if (
            type(expected_source_snapshot_sha256) is not str
            or _HASH.fullmatch(expected_source_snapshot_sha256) is None
        ):
            raise ReviewPackageError("expected source snapshot hash is invalid")
        if meta["source_snapshot_sha256"] != expected_source_snapshot_sha256:
            raise ReviewPackageError("review source snapshot hash mismatch")
    artifacts = _derive_artifacts(markdown, rendered_html, meta_json)
    try:
        review_compiler.validate_review_artifacts(artifacts)
    except review_compiler.ReviewCompileError as exc:
        raise ReviewPackageError("review artifact fidelity validation failed: %s" % exc) from exc
    return ReviewPackageHashes(
        markdown_sha256=sha256_bytes(markdown),
        html_sha256=sha256_bytes(rendered_html),
        meta_sha256=sha256_bytes(meta_json),
        semantic_sha256=sha256_bytes(artifacts.semantic_json),
        source_snapshot_sha256=meta["source_snapshot_sha256"],
    )


def _artifact_mapping(
    artifacts: review_compiler.ReviewArtifacts,
) -> Dict[str, bytes]:
    if type(artifacts) is not review_compiler.ReviewArtifacts:
        raise TypeError("artifacts must be ReviewArtifacts")
    values = {
        name: getattr(artifacts, attribute)
        for name, attribute in _ARTIFACT_BYTES.items()
    }
    if any(type(value) is not bytes for value in values.values()):
        raise TypeError("ReviewArtifacts values must be bytes")
    if type(artifacts.semantic_json) is not bytes:
        raise TypeError("ReviewArtifacts semantic manifest must be bytes")
    for name, value in values.items():
        if len(value) > _MAX_ARTIFACT_BYTES[name]:
            raise ReviewPackageError(
                "review package artifact exceeds size limit: %s" % name
            )
    return values


def _directory_entries(directory_fd: int) -> Tuple[str, ...]:
    try:
        entries = tuple(sorted(os.listdir(directory_fd)))
    except OSError as exc:
        raise ReviewPackageError("cannot list review package directory") from exc
    unexpected = tuple(name for name in entries if name not in _ARTIFACT_BYTES)
    if unexpected:
        raise ReviewPackageError(
            "unexpected review package entry: %s" % unexpected[0]
        )
    return entries


def require_empty_review_directory(directory: Path) -> None:
    """Require a fresh owner-only directory before a new Plan is rendered."""

    path = _package_path(directory)
    directory_fd = open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ReviewPackageError,
    )
    try:
        require_same_directory_identity(
            path,
            directory_fd,
            "review package",
            error_type=ReviewPackageError,
        )
        if _directory_entries(directory_fd):
            raise ReviewPackageError("new review package directory is not empty")
    finally:
        os.close(directory_fd)


def discard_unsealed_review_package(
    directory: Path,
    payload: ReviewPackagePayload,
) -> None:
    """Remove only exact body-only or fully written bytes from a failed seal."""

    values = _payload_mapping(payload)
    path = _package_path(directory)
    directory_fd = open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ReviewPackageError,
    )
    try:
        require_same_directory_identity(
            path,
            directory_fd,
            "unsealed review package",
            error_type=ReviewPackageError,
        )
        entries = _directory_entries(directory_fd)
        body_entries = ("review.html", "review.md")
        sealed_entries = tuple(sorted(REVIEW_PACKAGE_FILENAMES))
        if entries not in {body_entries, sealed_entries}:
            raise ReviewPackageError("unsealed review package artifact set changed")
        for name in entries:
            if _read_regular_file_at(directory_fd, name) != values[name]:
                raise ReviewPackageError("unsealed review package bytes changed: %s" % name)
        for name in entries:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            _require_safe_regular(current, name=name)
            os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        if _directory_entries(directory_fd):
            raise ReviewPackageError("unsealed review package cleanup is incomplete")
        require_same_directory_identity(
            path,
            directory_fd,
            "unsealed review package",
            error_type=ReviewPackageError,
        )
    except ReviewPackageError:
        raise
    except OSError as exc:
        raise ReviewPackageError("cannot discard unsealed review package") from exc
    finally:
        os.close(directory_fd)


def _payload_mapping(payload: ReviewPackagePayload) -> Dict[str, bytes]:
    if type(payload) is not ReviewPackagePayload:
        raise TypeError("payload must be ReviewPackagePayload")
    values = {
        "review.md": payload.markdown,
        "review.html": payload.html,
        "review.meta.json": payload.meta_json,
    }
    if any(type(value) is not bytes for value in (*values.values(), payload.semantic_json)):
        raise TypeError("review package payload values must be bytes")
    for name, value in values.items():
        if len(value) > _MAX_ARTIFACT_BYTES[name]:
            raise ReviewPackageError(
                "review package artifact exceeds size limit: %s" % name
            )
    return values


def write_validated_review_package(
    directory: Path,
    payload: ReviewPackagePayload,
    *,
    validate: Callable[[ReviewPackagePayload], ReviewPackageHashes],
    before_final_seal: Callable[[], None] | None = None,
) -> ReviewPackageHashes:
    """Persist one schema-validated payload through the shared sealed store.

    Schema-specific compilers and validators remain outside this module.  The
    physical package contract stays one owner-only, no-replace, three-file
    implementation for both V1 and V2.
    """

    if not callable(validate):
        raise TypeError("review package validator must be callable")
    if before_final_seal is not None and not callable(before_final_seal):
        raise TypeError("review package before-final-seal hook must be callable")
    values = _payload_mapping(payload)
    expected_hashes = validate(payload)
    if type(expected_hashes) is not ReviewPackageHashes:
        raise TypeError("review package validator returned an invalid result")
    path = _package_path(directory)
    directory_fd = open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ReviewPackageError,
    )
    try:
        require_same_directory_identity(
            path,
            directory_fd,
            "review package",
            error_type=ReviewPackageError,
        )
        existing_names = _directory_entries(directory_fd)
        for name in existing_names:
            if _read_regular_file_at(directory_fd, name) != values[name]:
                raise ReviewPackageError("existing %s bytes differ" % name)
        if "review.meta.json" in existing_names:
            if existing_names != tuple(sorted(REVIEW_PACKAGE_FILENAMES)):
                raise ReviewPackageError("review package artifact set is incomplete")
        else:
            for name in ("review.md", "review.html"):
                if name not in existing_names:
                    _create_artifact_no_replace(directory_fd, name, values[name])
            if _directory_entries(directory_fd) != ("review.html", "review.md"):
                raise ReviewPackageError("review package body artifact set is incomplete")
            body_readback = {
                name: _read_regular_file_at(directory_fd, name)
                for name in ("review.md", "review.html")
            }
            if any(
                body_readback[name] != values[name]
                for name in ("review.md", "review.html")
            ):
                raise ReviewPackageError("review package body readback differs")
            os.fsync(directory_fd)
            require_same_directory_identity(
                path,
                directory_fd,
                "review package",
                error_type=ReviewPackageError,
            )
            if before_final_seal is not None:
                before_final_seal()
            require_same_directory_identity(
                path,
                directory_fd,
                "review package",
                error_type=ReviewPackageError,
            )
            if _directory_entries(directory_fd) != ("review.html", "review.md"):
                raise ReviewPackageError("review package body artifact set changed before seal")
            for name in ("review.md", "review.html"):
                if _read_regular_file_at(directory_fd, name) != values[name]:
                    raise ReviewPackageError("review package body bytes changed before seal")
            _publish_final_meta_no_replace(directory_fd, values["review.meta.json"])
        if _directory_entries(directory_fd) != tuple(sorted(REVIEW_PACKAGE_FILENAMES)):
            raise ReviewPackageError("review package artifact set is incomplete")
        readback = {
            name: _read_regular_file_at(directory_fd, name)
            for name in REVIEW_PACKAGE_FILENAMES
        }
        if any(readback[name] != values[name] for name in REVIEW_PACKAGE_FILENAMES):
            raise ReviewPackageError("review package final readback differs")
        os.fsync(directory_fd)
        require_same_directory_identity(
            path,
            directory_fd,
            "review package",
            error_type=ReviewPackageError,
        )
        final_hashes = validate(
            ReviewPackagePayload(
                markdown=readback["review.md"],
                html=readback["review.html"],
                meta_json=readback["review.meta.json"],
                semantic_json=payload.semantic_json,
            )
        )
        if final_hashes != expected_hashes:
            raise ReviewPackageError("review package final hash set differs")
        return final_hashes
    except ReviewPackageError:
        raise
    except OSError as exc:
        raise ReviewPackageError("cannot finalize review package") from exc
    finally:
        os.close(directory_fd)


def read_review_package_payload(
    directory: Path,
    *,
    derive_semantic: Callable[[bytes], bytes],
) -> ReviewPackagePayload:
    """Read the exact sealed three-file set without selecting a schema."""

    if not callable(derive_semantic):
        raise TypeError("semantic derivation must be callable")
    path = _package_path(directory)
    directory_fd = open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ReviewPackageError,
    )
    try:
        require_same_directory_identity(
            path,
            directory_fd,
            "review package",
            error_type=ReviewPackageError,
        )
        entries = _directory_entries(directory_fd)
        missing = tuple(
            name for name in REVIEW_PACKAGE_FILENAMES if name not in entries
        )
        if missing:
            raise ReviewPackageError(
                "review package artifact is missing: %s" % missing[0]
            )
        encoded = {
            name: _read_regular_file_at(directory_fd, name)
            for name in REVIEW_PACKAGE_FILENAMES
        }
        require_same_directory_identity(
            path,
            directory_fd,
            "review package",
            error_type=ReviewPackageError,
        )
        semantic_json = derive_semantic(encoded["review.md"])
        if type(semantic_json) is not bytes:
            raise TypeError("semantic derivation returned invalid bytes")
        return ReviewPackagePayload(
            markdown=encoded["review.md"],
            html=encoded["review.html"],
            meta_json=encoded["review.meta.json"],
            semantic_json=semantic_json,
        )
    finally:
        os.close(directory_fd)


def write_review_package(
    directory: Path,
    artifacts: review_compiler.ReviewArtifacts,
) -> ReviewPackageHashes:
    """Persist exact compiler outputs into an existing dedicated subdirectory.

    An exact retry is idempotent: existing identical artifacts are read and
    accepted without replacement.  Any different existing bytes fail closed.
    """

    values = _artifact_mapping(artifacts)
    derived = _derive_artifacts(
        values["review.md"],
        values["review.html"],
        values["review.meta.json"],
    )
    if artifacts.semantic_json != derived.semantic_json:
        raise ReviewPackageError(
            "input review semantic manifest differs from exact Markdown"
        )
    try:
        review_compiler.validate_review_artifacts(artifacts)
    except review_compiler.ReviewCompileError as exc:
        raise ReviewPackageError(
            "input ReviewArtifacts fidelity validation failed: %s" % exc
        ) from exc
    payload = ReviewPackagePayload(
        markdown=values["review.md"],
        html=values["review.html"],
        meta_json=values["review.meta.json"],
        semantic_json=artifacts.semantic_json,
    )

    def validate_v1(candidate: ReviewPackagePayload) -> ReviewPackageHashes:
        return _validate_bytes(
            candidate.markdown,
            candidate.html,
            candidate.meta_json,
            expected_source_snapshot_sha256=None,
        )

    return write_validated_review_package(
        directory,
        payload,
        validate=validate_v1,
    )


def validate_review_directory(
    directory: Path,
    *,
    expected_source_snapshot_sha256: Optional[str] = None,
) -> ReviewPackageHashes:
    """Validate a sealed review directory without rewriting or rerendering it."""

    path = _package_path(directory)
    directory_fd = open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ReviewPackageError,
    )
    try:
        require_same_directory_identity(
            path,
            directory_fd,
            "review package",
            error_type=ReviewPackageError,
        )
        entries = _directory_entries(directory_fd)
        missing = tuple(
            name for name in REVIEW_PACKAGE_FILENAMES if name not in entries
        )
        if missing:
            raise ReviewPackageError(
                "review package artifact is missing: %s" % missing[0]
            )
        encoded = {
            name: _read_regular_file_at(directory_fd, name)
            for name in REVIEW_PACKAGE_FILENAMES
        }
        require_same_directory_identity(
            path,
            directory_fd,
            "review package",
            error_type=ReviewPackageError,
        )
        return _validate_bytes(
            encoded["review.md"],
            encoded["review.html"],
            encoded["review.meta.json"],
            expected_source_snapshot_sha256=expected_source_snapshot_sha256,
        )
    finally:
        os.close(directory_fd)


__all__ = [
    "REVIEW_PACKAGE_FILENAMES",
    "ReviewPackageError",
    "ReviewPackageHashes",
    "ReviewPackagePayload",
    "discard_unsealed_review_package",
    "read_review_package_payload",
    "require_empty_review_directory",
    "validate_review_directory",
    "write_review_package",
    "write_validated_review_package",
]
