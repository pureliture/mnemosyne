"""Small source-bound writer for allowlisted Curation projections."""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import safety
from .canonical_json import canonical_json_bytes, sha256_bytes


_SCHEMA = "mnemosyne.curation-projection.v1"
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_WORKSTREAM_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_PROJECTION_FILES = {
    "curation_memory": "curation-memory.json",
    "draft_plan": "draft-plan.json",
    "freshness_state": "freshness-state.json",
    "inventory": "inventory.json",
    "okf": "navigation.okf.json",
    "relation_map": "relation-map.json",
}
_PROJECTION_PARTS = (
    "_registry",
    "curation",
    "projections",
    "v1",
    "workstreams",
)


class ProjectionRefreshError(RuntimeError):
    """The previous projection remains the last admitted current result."""


@dataclass(frozen=True)
class ProjectionRefreshRequest:
    root: Path
    workstream_id: str
    projection_kind: str
    source_observation_sha256: str
    output: bytes
    media_type: str
    actor: str

    def __post_init__(self) -> None:
        root = Path(self.root)
        if not root.is_absolute():
            raise ValueError("projection root must be absolute")
        if (
            type(self.workstream_id) is not str
            or _WORKSTREAM_ID.fullmatch(self.workstream_id) is None
        ):
            raise ValueError("projection Workstream id is invalid")
        if self.projection_kind not in _PROJECTION_FILES:
            raise ValueError("projection kind is not allowlisted")
        if (
            type(self.source_observation_sha256) is not str
            or _SHA256.fullmatch(self.source_observation_sha256) is None
        ):
            raise ValueError("projection source observation identity is invalid")
        if type(self.output) is not bytes or len(self.output) > _MAX_OUTPUT_BYTES:
            raise ValueError("projection output is invalid")
        try:
            self.output.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("projection output must be UTF-8") from exc
        if (
            type(self.media_type) is not str
            or not self.media_type
            or len(self.media_type) > 128
            or any(character.isspace() for character in self.media_type)
        ):
            raise ValueError("projection media type is invalid")
        if type(self.actor) is not str or not self.actor or len(self.actor) > 128:
            raise ValueError("projection actor is invalid")
        object.__setattr__(self, "root", root)


@dataclass(frozen=True)
class ProjectionRefreshResult:
    status: str
    changed: bool
    relative_path: str
    source_observation_sha256: str
    output_sha256: str
    envelope_sha256: str


def _directory_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _regular_flags() -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _require_private_directory(fd: int, label: str) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ProjectionRefreshError(f"{label} is not an owner-only directory")


def _open_or_create_child(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ProjectionRefreshError("projection namespace cannot be created") from exc
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise ProjectionRefreshError("projection namespace is unsafe") from exc
    try:
        _require_private_directory(descriptor, "projection namespace")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_projection_directory(root: Path, workstream_id: str) -> int:
    try:
        descriptor = safety.open_verified_directory(
            root,
            require_owner_only=True,
            error_type=ProjectionRefreshError,
        )
    except ProjectionRefreshError:
        raise
    except Exception as exc:
        raise ProjectionRefreshError("projection root is unsafe") from exc
    try:
        for part in (*_PROJECTION_PARTS, workstream_id):
            child = _open_or_create_child(descriptor, part)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_existing(directory_fd: int, name: str) -> tuple[dict[str, object], bytes] | None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProjectionRefreshError("existing projection cannot be observed") from exc
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            name,
            Path(name),
            label="Curation projection",
            expected_mode=0o600,
            error_type=ProjectionRefreshError,
        )
    except ProjectionRefreshError:
        raise
    except OSError as exc:
        if exc.errno == getattr(os, "ENOENT", 2):
            return None
        raise ProjectionRefreshError("existing projection cannot be read") from exc
    if info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ProjectionRefreshError("existing projection identity is unsafe")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectionRefreshError("existing projection is malformed") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise ProjectionRefreshError("existing projection is not canonical")
    return value, raw


def _require_existing_envelope(
    value: dict[str, object],
    *,
    kind: str,
    workstream_id: str,
) -> tuple[str, str, str]:
    output = value.get("output")
    receipt = value.get("receipt")
    if (
        value.get("schema") != _SCHEMA
        or value.get("projection_kind") != kind
        or value.get("workstream_id") != workstream_id
        or _SHA256.fullmatch(str(value.get("source_observation_sha256"))) is None
        or type(output) is not dict
        or type(receipt) is not dict
        or receipt.get("status") != "CURRENT"
        or type(output.get("text")) is not str
        or _SHA256.fullmatch(str(output.get("content_sha256"))) is None
        or sha256_bytes(output["text"].encode("utf-8")) != output["content_sha256"]
        or receipt.get("output_sha256") != output["content_sha256"]
    ):
        raise ProjectionRefreshError("existing projection envelope is invalid")
    return (
        value["source_observation_sha256"],
        output["content_sha256"],
        str(output.get("media_type")),
    )


def _acquire_writer(directory_fd: int) -> int:
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(".writer.lock", flags, 0o600, dir_fd=directory_fd)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ProjectionRefreshError("projection writer lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as exc:
        raise ProjectionRefreshError("projection writer is busy") from exc
    except ProjectionRefreshError:
        raise
    except OSError as exc:
        raise ProjectionRefreshError("projection writer lock is unavailable") from exc


def _publish_replace(
    directory_fd: int,
    name: str,
    encoded: bytes,
    *,
    checkpoint: Optional[Callable[[str], None]],
) -> None:
    temporary_name = f".tmp-{secrets.token_hex(16)}"
    descriptor: int | None = None
    replaced = False
    try:
        descriptor = os.open(temporary_name, _regular_flags(), 0o600, dir_fd=directory_fd)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise ProjectionRefreshError("projection temporary write stopped")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or safety.read_open_file_bytes(descriptor) != encoded
        ):
            raise ProjectionRefreshError("projection temporary readback failed")
        if checkpoint is not None:
            checkpoint("before_atomic_replace")
        os.replace(
            temporary_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        replaced = True
        os.fsync(directory_fd)
        final_info, final_raw = safety.read_regular_file_at(
            directory_fd,
            name,
            Path(name),
            label="Curation projection",
            expected_mode=0o600,
            error_type=ProjectionRefreshError,
        )
        if (
            final_info.st_uid != os.getuid()
            or final_info.st_nlink != 1
            or final_raw != encoded
        ):
            raise ProjectionRefreshError("projection final readback failed")
    except ProjectionRefreshError:
        raise
    except Exception as exc:
        raise ProjectionRefreshError("projection refresh did not complete") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not replaced:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def refresh_projection(
    request: ProjectionRefreshRequest,
    *,
    refreshed_at: str | None = None,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> ProjectionRefreshResult:
    """Atomically replace one allowlisted projection envelope."""

    if type(request) is not ProjectionRefreshRequest:
        raise TypeError("projection refresh request is invalid")
    timestamp = refreshed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if type(timestamp) is not str or _TIMESTAMP.fullmatch(timestamp) is None:
        raise ValueError("projection refresh time is invalid")
    filename = _PROJECTION_FILES[request.projection_kind]
    relative_path = "/".join(
        (*_PROJECTION_PARTS, request.workstream_id, filename)
    )
    output_sha256 = sha256_bytes(request.output)
    directory_fd = _open_projection_directory(request.root, request.workstream_id)
    writer_fd: int | None = None
    try:
        writer_fd = _acquire_writer(directory_fd)
        existing = _read_existing(directory_fd, filename)
        previous_source: str | None = None
        if existing is not None:
            previous_source, previous_output, previous_media_type = _require_existing_envelope(
                existing[0],
                kind=request.projection_kind,
                workstream_id=request.workstream_id,
            )
            if (
                previous_source == request.source_observation_sha256
                and previous_output == output_sha256
                and previous_media_type == request.media_type
            ):
                return ProjectionRefreshResult(
                    status="CURRENT",
                    changed=False,
                    relative_path=relative_path,
                    source_observation_sha256=previous_source,
                    output_sha256=previous_output,
                    envelope_sha256=sha256_bytes(existing[1]),
                )
        envelope = {
            "output": {
                "content_sha256": output_sha256,
                "media_type": request.media_type,
                "text": request.output.decode("utf-8"),
            },
            "previous_source_observation_sha256": previous_source,
            "projection_kind": request.projection_kind,
            "receipt": {
                "actor": request.actor,
                "output_sha256": output_sha256,
                "refreshed_at": timestamp,
                "status": "CURRENT",
            },
            "schema": _SCHEMA,
            "source_observation_sha256": request.source_observation_sha256,
            "workstream_id": request.workstream_id,
        }
        encoded = canonical_json_bytes(envelope)
        _publish_replace(
            directory_fd,
            filename,
            encoded,
            checkpoint=checkpoint,
        )
        return ProjectionRefreshResult(
            status="CURRENT",
            changed=True,
            relative_path=relative_path,
            source_observation_sha256=request.source_observation_sha256,
            output_sha256=output_sha256,
            envelope_sha256=sha256_bytes(encoded),
        )
    finally:
        if writer_fd is not None:
            os.close(writer_fd)
        os.close(directory_fd)


__all__ = [
    "ProjectionRefreshError",
    "ProjectionRefreshRequest",
    "ProjectionRefreshResult",
    "refresh_projection",
]
