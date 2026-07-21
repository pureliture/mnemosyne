"""Exact, bounded auxiliary snapshot evidence for frozen Workstream inspection."""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Iterator

from .. import policy


MAX_FRONTMATTER_BYTES = 8192
_CAPABILITY_ISSUER = object()
_ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_KNOWN_ENVELOPE_KEYS = frozenset(
    (
        "schema_version",
        "workspace",
        "updated_at",
        "source_refs",
        "raw_log_policy",
        "transcript_policy",
        "redaction_policy",
    )
)


class AuxiliaryIndexError(ValueError):
    """A non-authoritative snapshot path could not be inspected safely."""

    _REASONS = frozenset(("AUXILIARY_MISSING", "AUXILIARY_UNSAFE"))

    def __init__(self, message: str, *, reason_code: str) -> None:
        if type(message) is not str or not message or reason_code not in self._REASONS:
            raise ValueError("auxiliary index error is invalid")
        super().__init__(message)
        self.reason_code = reason_code
        self.blocks_authority = False


@dataclass(frozen=True)
class AuxiliarySnapshotToken:
    value: str


@dataclass(frozen=True)
class AuxiliarySnapshotIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    link_count: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "AuxiliarySnapshotIdentity":
        return cls(
            device=int(value.st_dev),
            inode=int(value.st_ino),
            mode=stat.S_IMODE(value.st_mode),
            uid=int(value.st_uid),
            link_count=int(value.st_nlink),
            size=int(value.st_size),
            mtime_ns=int(
                getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))
            ),
            ctime_ns=int(
                getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000))
            ),
        )


class AuxiliarySnapshotCapability:
    """One module-issued, one-shot descriptor capability."""

    __slots__ = ("_active", "_file_descriptor", "identity")

    def __init__(
        self,
        issuer: object,
        file_descriptor: int,
        identity: AuxiliarySnapshotIdentity,
    ) -> None:
        if (
            issuer is not _CAPABILITY_ISSUER
            or type(file_descriptor) is not int
            or type(identity) is not AuxiliarySnapshotIdentity
        ):
            raise TypeError("auxiliary snapshot capability is private")
        self._file_descriptor = file_descriptor
        self.identity = identity
        self._active = True

    @property
    def file_descriptor(self) -> int:
        if not self._active:
            raise ValueError("auxiliary snapshot capability is closed")
        return self._file_descriptor

    def _deactivate(self) -> None:
        self._active = False


@dataclass(frozen=True)
class AuxiliaryFinding:
    source_id: str
    field: str
    reason_code: str
    authority_value: str | None
    observed_value: str | None
    requires_manual_review: bool = True

    def to_mapping(self) -> MappingProxyType:
        return MappingProxyType(
            {
                "source_id": self.source_id,
                "field": self.field,
                "reason_code": self.reason_code,
                "authority_value": self.authority_value,
                "observed_value": self.observed_value,
                "requires_manual_review": self.requires_manual_review,
            }
        )


@dataclass(frozen=True)
class AuxiliaryInspection:
    findings: tuple[AuxiliaryFinding, ...]
    metadata_bytes_used: int
    truncated: bool

    def to_evidence(self) -> MappingProxyType:
        return MappingProxyType(
            {
                "findings": tuple(finding.to_mapping() for finding in self.findings),
                "metadata_bytes_used": self.metadata_bytes_used,
                "truncated": self.truncated,
            }
        )


def _unsafe(message: str) -> AuxiliaryIndexError:
    return AuxiliaryIndexError(message, reason_code="AUXILIARY_UNSAFE")


def _missing(message: str) -> AuxiliaryIndexError:
    return AuxiliaryIndexError(message, reason_code="AUXILIARY_MISSING")


def derive_snapshot_token(canonical_id: object) -> AuxiliarySnapshotToken:
    """Derive one literal filesystem segment without decoding or normalization."""

    if (
        type(canonical_id) is not str
        or not canonical_id
        or canonical_id in (".", "..")
        or "/" in canonical_id
        or "\\" in canonical_id
        or _ENCODED_SEPARATOR.search(canonical_id)
        or any(unicodedata.category(character) == "Cc" for character in canonical_id)
    ):
        raise _unsafe("canonical Workstream id cannot select auxiliary evidence")
    try:
        encoded = os.fsencode(canonical_id)
    except (TypeError, UnicodeEncodeError) as exc:
        raise _unsafe("canonical Workstream id cannot select auxiliary evidence") from exc
    if not encoded or len(encoded) > 255:
        raise _unsafe("canonical Workstream id cannot select auxiliary evidence")
    return AuxiliarySnapshotToken(canonical_id)


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _unsafe("no-follow directory opening is unavailable")
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | os.O_NOFOLLOW
    )


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _unsafe("no-follow file opening is unavailable")
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | os.O_NOFOLLOW
    )


def _full_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_uid),
        int(value.st_nlink),
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))),
        int(getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000))),
    )


def _same_opened_object(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        int(first.st_dev),
        int(first.st_ino),
        stat.S_IFMT(first.st_mode),
    ) == (
        int(second.st_dev),
        int(second.st_ino),
        stat.S_IFMT(second.st_mode),
    )


def _validate_directory(value: os.stat_result, root_device: int) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_dev != root_device
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) & 0o022
    ):
        raise _unsafe("auxiliary snapshot directory is unsafe")


def _validate_file(value: os.stat_result, root_device: int) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_dev != root_device
        or value.st_uid != os.getuid()
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) & 0o022
    ):
        raise _unsafe("auxiliary snapshot file is unsafe")


@contextmanager
def open_snapshot_capability(
    raw_root_fd: int,
    token: AuxiliarySnapshotToken,
) -> Iterator[AuxiliarySnapshotCapability]:
    """Open only ``_index/memory/<token>/snapshot.md`` below a retained root fd."""

    if type(token) is not AuxiliarySnapshotToken:
        raise _unsafe("auxiliary snapshot token is invalid")
    if type(raw_root_fd) is not int:
        raise _unsafe("auxiliary raw-root descriptor is invalid")

    owned_descriptors: list[int] = []
    lexical_checks: list[tuple[int, str, tuple[int, ...]]] = []
    capability: AuxiliarySnapshotCapability | None = None
    try:
        try:
            root_info = os.fstat(raw_root_fd)
            _validate_directory(root_info, int(root_info.st_dev))
            current = os.dup(raw_root_fd)
        except OSError as exc:
            raise _unsafe("auxiliary raw-root descriptor is unavailable") from exc
        owned_descriptors.append(current)
        root_device = int(root_info.st_dev)

        for component in ("_index", "memory", token.value):
            try:
                lexical = os.stat(component, dir_fd=current, follow_symlinks=False)
                child = os.open(component, _directory_flags(), dir_fd=current)
            except FileNotFoundError as exc:
                raise _missing("auxiliary snapshot is missing") from exc
            except OSError as exc:
                raise _unsafe("auxiliary snapshot directory is unsafe") from exc
            owned_descriptors.append(child)
            opened = os.fstat(child)
            if not _same_opened_object(lexical, opened):
                raise _unsafe("auxiliary snapshot directory identity changed")
            _validate_directory(opened, root_device)
            lexical_checks.append((current, component, _full_identity(lexical)))
            current = child

        try:
            lexical_file = os.stat(
                "snapshot.md",
                dir_fd=current,
                follow_symlinks=False,
            )
            opened_file_fd = os.open(
                "snapshot.md",
                _file_flags(),
                dir_fd=current,
            )
        except FileNotFoundError as exc:
            raise _missing("auxiliary snapshot is missing") from exc
        except OSError as exc:
            raise _unsafe("auxiliary snapshot file is unsafe") from exc
        owned_descriptors.append(opened_file_fd)
        opened_file = os.fstat(opened_file_fd)
        if not _same_opened_object(lexical_file, opened_file):
            raise _unsafe("auxiliary snapshot file identity changed")
        _validate_file(opened_file, root_device)
        lexical_checks.append((current, "snapshot.md", _full_identity(lexical_file)))
        identity = AuxiliarySnapshotIdentity.from_stat(opened_file)
        try:
            capability_fd = os.dup(opened_file_fd)
        except OSError as exc:
            raise _unsafe("auxiliary snapshot capability is unavailable") from exc
        capability = AuxiliarySnapshotCapability(
            _CAPABILITY_ISSUER,
            capability_fd,
            identity,
        )
        try:
            yield capability
            if AuxiliarySnapshotIdentity.from_stat(
                os.fstat(capability.file_descriptor)
            ) != identity:
                raise _unsafe("auxiliary snapshot identity changed")
            for parent_fd, name, expected in lexical_checks:
                try:
                    observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except OSError as exc:
                    raise _unsafe("auxiliary snapshot identity changed") from exc
                if _full_identity(observed) != expected:
                    raise _unsafe("auxiliary snapshot identity changed")
        finally:
            capability._deactivate()
            try:
                os.close(capability_fd)
            except OSError:
                pass
    finally:
        for descriptor in reversed(owned_descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _finding(
    reason_code: str,
    field: str,
    authority_value: str | None,
    observed_value: str | None,
) -> AuxiliaryFinding:
    return AuxiliaryFinding(
        source_id="auxiliary-snapshot",
        field=field,
        reason_code=reason_code,
        authority_value=authority_value,
        observed_value=observed_value,
    )


def _single_finding_inspection(
    reason_code: str,
    field: str,
    metadata_bytes_used: int,
    *,
    truncated: bool = False,
) -> AuxiliaryInspection:
    return AuxiliaryInspection(
        (_finding(reason_code, field, None, None),),
        metadata_bytes_used,
        truncated,
    )


def _read_frontmatter(file_descriptor: int) -> tuple[bytes | None, int, str | None]:
    consumed = bytearray()
    line = bytearray()
    first_line = True
    while len(consumed) < MAX_FRONTMATTER_BYTES:
        try:
            chunk = os.read(file_descriptor, 1)
        except OSError:
            return None, len(consumed), "AUXILIARY_UNSAFE"
        if not chunk:
            return None, len(consumed), "AUXILIARY_MALFORMED"
        consumed.extend(chunk)
        line.extend(chunk)
        if chunk != b"\n":
            continue
        if first_line:
            if bytes(line) != b"---\n":
                return None, len(consumed), "AUXILIARY_MALFORMED"
            first_line = False
            line.clear()
            continue
        if bytes(line) == b"---\n":
            return bytes(consumed[4:-4]), len(consumed), None
        line.clear()
    return None, MAX_FRONTMATTER_BYTES, "AUXILIARY_LIMIT_EXCEEDED"


def _valid_timestamp(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _malformed(metadata_bytes_used: int) -> AuxiliaryInspection:
    return _single_finding_inspection(
        "AUXILIARY_MALFORMED",
        "frontmatter",
        metadata_bytes_used,
    )


def _validate_envelope(value: object) -> Mapping[str, object] | None:
    if (
        not isinstance(value, Mapping)
        or not set(value) <= _KNOWN_ENVELOPE_KEYS
        or set(("schema_version", "workspace")) - set(value)
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["workspace"], Mapping)
        or set(value["workspace"]) != {"slug", "root"}
        or type(value["workspace"]["slug"]) is not str
        or not value["workspace"]["slug"]
        or type(value["workspace"]["root"]) is not str
        or not value["workspace"]["root"]
    ):
        return None
    if "updated_at" in value and type(value["updated_at"]) is not str:
        return None
    if "source_refs" in value and (
        type(value["source_refs"]) is not list
        or any(type(item) is not str for item in value["source_refs"])
    ):
        return None
    for key in ("raw_log_policy", "transcript_policy", "redaction_policy"):
        if key in value and type(value[key]) is not str:
            return None
    return value


def _safe_observed_id(value: str) -> str | None:
    if (
        len(value) > 512
        or "/" in value
        or "\\" in value
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        return None
    return value


def _safe_observed_root(value: str, raw_root: Path) -> str | None:
    if (
        len(value) > 4096
        or "\\" in value
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        return None
    candidate = Path(value)
    if (
        not candidate.is_absolute()
        or any(component in ("", ".", "..") for component in candidate.parts[1:])
        or str(candidate) != value
    ):
        return None
    try:
        relative = candidate.relative_to(raw_root)
    except ValueError:
        return None
    if not relative.parts:
        return None
    return relative.as_posix()


def inspect_snapshot(
    capability: AuxiliarySnapshotCapability,
    *,
    expected_workstream_id: str,
    expected_project_home: Path,
    raw_root: Path,
) -> AuxiliaryInspection:
    """Read only delimiter-bounded YAML from an exact snapshot capability."""

    if type(capability) is not AuxiliarySnapshotCapability or not capability._active:
        raise TypeError("exact auxiliary snapshot capability is required")
    if (
        type(expected_workstream_id) is not str
        or not expected_workstream_id
        or not isinstance(expected_project_home, Path)
        or not expected_project_home.is_absolute()
        or not isinstance(raw_root, Path)
        or not raw_root.is_absolute()
    ):
        raise TypeError("auxiliary authority comparison is invalid")
    try:
        expected_relative = expected_project_home.relative_to(raw_root)
    except ValueError as exc:
        raise TypeError("auxiliary authority comparison is invalid") from exc
    if (
        not expected_relative.parts
        or any(component in ("", ".", "..") for component in expected_relative.parts)
    ):
        raise TypeError("auxiliary authority comparison is invalid")
    expected_relative_text = expected_relative.as_posix()

    descriptor = capability.file_descriptor
    try:
        before = AuxiliarySnapshotIdentity.from_stat(os.fstat(descriptor))
        if before != capability.identity:
            raise OSError("identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        return _single_finding_inspection("AUXILIARY_UNSAFE", "snapshot", 0)
    frontmatter, consumed, read_error = _read_frontmatter(descriptor)
    try:
        after = AuxiliarySnapshotIdentity.from_stat(os.fstat(descriptor))
    except OSError:
        after = None
    if after != before or read_error == "AUXILIARY_UNSAFE":
        return _single_finding_inspection("AUXILIARY_UNSAFE", "snapshot", consumed)
    if read_error == "AUXILIARY_LIMIT_EXCEEDED":
        return _single_finding_inspection(
            "AUXILIARY_LIMIT_EXCEEDED",
            "frontmatter",
            consumed,
            truncated=True,
        )
    if read_error is not None or frontmatter is None:
        return _malformed(consumed)

    try:
        parsed = policy.parse_strict_yaml(frontmatter)
    except policy.StrictYAMLDuplicateKeyError:
        return _single_finding_inspection(
            "AUXILIARY_AMBIGUOUS",
            "frontmatter",
            consumed,
        )
    except policy.StrictYAMLError:
        return _malformed(consumed)
    envelope = _validate_envelope(parsed)
    if envelope is None:
        return _malformed(consumed)

    workspace = envelope["workspace"]
    observed_id = workspace["slug"]
    observed_root = workspace["root"]
    findings = []
    if observed_id != expected_workstream_id:
        findings.append(
            _finding(
                "AUXILIARY_ID_MISMATCH",
                "workspace.slug",
                expected_workstream_id,
                _safe_observed_id(observed_id),
            )
        )
    if observed_root != str(expected_project_home):
        findings.append(
            _finding(
                "AUXILIARY_ROOT_MISMATCH",
                "workspace.root",
                expected_relative_text,
                _safe_observed_root(observed_root, raw_root),
            )
        )
    if not _valid_timestamp(envelope.get("updated_at")):
        findings.append(
            _finding(
                "AUXILIARY_FRESHNESS_MISSING",
                "updated_at",
                expected_relative_text,
                None,
            )
        )
    return AuxiliaryInspection(tuple(findings), consumed, False)


def inspection_from_error(error: AuxiliaryIndexError) -> AuxiliaryInspection:
    """Normalize a token/open error into non-authoritative drift evidence."""

    if type(error) is not AuxiliaryIndexError:
        raise TypeError("auxiliary index error is invalid")
    return _single_finding_inspection(error.reason_code, "snapshot", 0)


__all__ = [
    "MAX_FRONTMATTER_BYTES",
    "AuxiliaryFinding",
    "AuxiliaryIndexError",
    "AuxiliaryInspection",
    "AuxiliarySnapshotCapability",
    "AuxiliarySnapshotIdentity",
    "AuxiliarySnapshotToken",
    "derive_snapshot_token",
    "inspect_snapshot",
    "inspection_from_error",
    "open_snapshot_capability",
]
