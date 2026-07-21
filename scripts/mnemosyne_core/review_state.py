"""Read-only, ledger-bound loading of sealed Mnemosyne review snapshots.

The filesystem reader accepts one absolute final snapshot directory and binds
every lexical object to owner-controlled, no-follow identities.  The head
loaders accept identifiers only: their filesystem path and expected hashes are
obtained from an exact supported ledger inside one read transaction.
"""

from __future__ import annotations

import fcntl
import json
import os
import posixpath
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from . import (
    batch_service,
    control,
    ledger_schema,
    m3_schema,
    review_compiler,
    review_context,
    review_package,
    safety,
)
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_MEMBERS = ("manifest.json", "review", "snapshot.json")
_REVIEW_MEMBERS = ("review.html", "review.md", "review.meta.json")
_MANIFEST_MEMBER_PATHS = (
    "review/review.html",
    "review/review.md",
    "review/review.meta.json",
    "snapshot.json",
)
_BATCH_UNIT_FIELDS = frozenset(
    (
        "access_domain",
        "analysis_provenance",
        "authority",
        "canonical_conflict",
        "canonical_path",
        "context_freshness",
        "display_path",
        "document_lifecycle",
        "document_role",
        "effect_count",
        "effect_codes",
        "evidence_providers",
        "file_count",
        "lifecycle_class",
        "member_item_ids",
        "member_paths",
        "override_class",
        "primary_workstream",
        "recommended_action",
        "reference_complete",
        "relation_conflict",
        "related_workstreams",
        "risk_band",
        "scope_rule_id",
        "scope_class",
        "sensitivity",
        "shared",
        "target_path",
        "target_proven",
        "total_bytes",
        "unit_id",
        "unit_kind",
        "underlying_file_count",
        "warning_codes",
    )
)
_TUPLE_FIELDS = (
    "effect_codes",
    "evidence_providers",
    "member_item_ids",
    "member_paths",
    "related_workstreams",
    "warning_codes",
)


class ReviewStateError(Exception):
    """A sealed review snapshot or its current ledger binding is invalid."""


@dataclass(frozen=True)
class ReviewStateBounds:
    """Explicit resource bounds for one sealed snapshot read."""

    max_snapshot_bytes: int = 64 * 1024 * 1024
    max_manifest_bytes: int = 1024 * 1024
    max_review_markdown_bytes: int = 64 * 1024 * 1024
    max_review_html_bytes: int = 128 * 1024 * 1024
    max_review_meta_bytes: int = 256 * 1024
    max_units: int = 10000
    max_selected_units: int = 1000
    max_member_items: int = 1000000
    max_total_bytes: int = 1024 * 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if type(value) is not int or value <= 0:
                raise ReviewStateError("%s must be a positive integer" % name)


@dataclass(frozen=True)
class SealedReviewSnapshot:
    """Typed readback of one fully verified immutable review package."""

    snapshot_id: str
    final_path: Path
    snapshot_payload: bytes
    payload: Dict[str, Any]
    schema_version: int
    analysis_contexts_json: bytes
    snapshot_sha256: str
    manifest_payload: bytes
    review_markdown: bytes
    package_sha256: str
    sealed_identity_sha256: str
    review_hashes: review_package.ReviewPackageHashes
    review_kind: str
    source_kind: str
    source_id: str
    units: Tuple[batch_service.BatchUnit, ...]


@dataclass(frozen=True)
class CampaignReviewHead:
    campaign_id: str
    current_snapshot_id: str
    current_snapshot_sha256: str
    review_revision: int
    snapshot: SealedReviewSnapshot
    units: Tuple[batch_service.BatchUnit, ...]


@dataclass(frozen=True)
class BatchReviewHead:
    batch_id: str
    campaign_id: str
    current_snapshot_id: str
    current_snapshot_sha256: str
    review_revision: int
    execution_generation: int
    snapshot: SealedReviewSnapshot
    units: Tuple[batch_service.BatchUnit, ...]


def _after_file_read(_path: Path, _descriptor: int, _directory_fd: int) -> None:
    """Observational test seam; mandatory post-read checks always follow it."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ReviewStateError("%s is invalid" % label)
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ReviewStateError("%s is invalid" % label)
    return value


def _absolute_path(value: Any, label: str) -> Path:
    try:
        path = Path(value)
    except TypeError as exc:
        raise TypeError("%s must be path-like" % label) from exc
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ReviewStateError("%s must be a canonical absolute path" % label)
    return path


def _directory_identity(info: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_ctime_ns,
    )


def _file_identity(info: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _require_exact_directory(info: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ReviewStateError("%s must be an owner-only mode 0700 directory" % label)


def _open_exact_directory(path: Path, label: str) -> int:
    descriptor = safety.open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ReviewStateError,
    )
    try:
        _require_exact_directory(os.fstat(descriptor), label)
        safety.require_same_directory_identity(
            path,
            descriptor,
            label,
            error_type=ReviewStateError,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_child_directory(
    parent_fd: int,
    parent_path: Path,
    name: str,
    label: str,
) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lexical = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ReviewStateError("%s is unreadable" % label) from exc
    try:
        opened = os.fstat(descriptor)
        _require_exact_directory(opened, label)
        if _directory_identity(opened) != _directory_identity(lexical):
            raise ReviewStateError("%s directory identity changed" % label)
        safety.require_same_directory_identity(
            parent_path / name,
            descriptor,
            label,
            error_type=ReviewStateError,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _entries(directory_fd: int, expected: Tuple[str, ...], label: str) -> None:
    try:
        observed = tuple(sorted(os.listdir(directory_fd)))
    except OSError as exc:
        raise ReviewStateError("cannot list %s" % label) from exc
    if observed != tuple(sorted(expected)):
        raise ReviewStateError("%s member set is invalid" % label)


def _require_regular(info: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise ReviewStateError(
            "%s must be an owner-only mode 0600 regular file with one link" % label
        )


def _read_bounded_file(
    directory_fd: int,
    path: Path,
    *,
    label: str,
    limit: int,
) -> bytes:
    name = path.name
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: Optional[int] = None
    try:
        lexical_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _require_regular(lexical_before, label)
        if lexical_before.st_size > limit:
            raise ReviewStateError("%s exceeds its byte bound" % label)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        opened_before = os.fstat(descriptor)
        _require_regular(opened_before, label)
        if _file_identity(opened_before) != _file_identity(lexical_before):
            raise ReviewStateError("%s identity changed before read" % label)
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ReviewStateError("%s exceeds its byte bound" % label)
        encoded = b"".join(chunks)
        _after_file_read(path, descriptor, directory_fd)
        opened_after = os.fstat(descriptor)
        lexical_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _file_identity(opened_after) != _file_identity(opened_before)
            or _file_identity(lexical_after) != _file_identity(opened_before)
            or len(encoded) != opened_after.st_size
        ):
            raise ReviewStateError("%s changed while read" % label)
        return encoded
    except ReviewStateError:
        raise
    except OSError as exc:
        raise ReviewStateError("cannot safely read %s" % label) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _canonical_object(encoded: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewStateError("%s is not valid JSON" % label) from exc
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise ReviewStateError("%s is not canonical JSON" % label) from exc
    if type(value) is not dict or canonical != encoded:
        raise ReviewStateError("%s is not a canonical JSON object" % label)
    return value


def _manifest_hashes(
    manifest_payload: bytes,
    *,
    expected_snapshot_id: str,
) -> Dict[str, str]:
    manifest = _canonical_object(manifest_payload, "snapshot manifest")
    if set(manifest) != {"kind", "members", "schema_version", "snapshot_id"}:
        raise ReviewStateError("snapshot manifest fields are invalid")
    if (
        manifest["kind"] != "MNEMOSYNE_REVIEW_SNAPSHOT"
        or manifest["schema_version"] != 1
        or manifest["snapshot_id"] != expected_snapshot_id
        or type(manifest["members"]) is not list
        or len(manifest["members"]) != len(_MANIFEST_MEMBER_PATHS)
    ):
        raise ReviewStateError("snapshot manifest contract is invalid")
    hashes: Dict[str, str] = {}
    for expected_path, member in zip(_MANIFEST_MEMBER_PATHS, manifest["members"]):
        if (
            type(member) is not dict
            or set(member) != {"path", "sha256"}
            or member.get("path") != expected_path
        ):
            raise ReviewStateError("snapshot manifest member is invalid")
        hashes[expected_path] = _sha256(member.get("sha256"), "manifest member hash")
    return hashes


def _batch_unit(value: Any) -> batch_service.BatchUnit:
    if type(value) is not dict or set(value) != _BATCH_UNIT_FIELDS:
        raise ReviewStateError("snapshot batch unit fields are invalid")
    for name in _TUPLE_FIELDS:
        if type(value[name]) is not list:
            raise ReviewStateError("snapshot batch unit %s must be a list" % name)
    if (
        type(value["underlying_file_count"]) is not int
        or value["underlying_file_count"] != value["file_count"]
    ):
        raise ReviewStateError("snapshot unit file counts do not match")
    values = dict(value)
    values["path"] = values.pop("canonical_path")
    values["analysis_provenance_json"] = canonical_json_bytes(
        values.pop("analysis_provenance")
    )
    values.pop("underlying_file_count")
    for name in _TUPLE_FIELDS:
        values[name] = tuple(values[name])
    try:
        return batch_service.BatchUnit(**values)
    except (batch_service.BatchValidationError, TypeError, ValueError) as exc:
        raise ReviewStateError("snapshot batch unit is invalid") from exc


def _paths_overlap(left: str, right: str) -> bool:
    return (
        left == right
        or left.startswith(right + "/")
        or right.startswith(left + "/")
    )


def _snapshot_units(
    payload: Dict[str, Any],
    bounds: ReviewStateBounds,
) -> Tuple[batch_service.BatchUnit, ...]:
    values = payload.get("units")
    if type(values) is not list:
        raise ReviewStateError("snapshot units must be a list")
    if len(values) > bounds.max_units:
        raise ReviewStateError("snapshot unit bound exceeded")
    units = tuple(_batch_unit(value) for value in values)
    unit_ids = tuple(unit.unit_id for unit in units)
    if unit_ids != tuple(sorted(unit_ids)) or len(set(unit_ids)) != len(unit_ids):
        raise ReviewStateError("snapshot unit ids are duplicated or not canonical")
    member_ids = tuple(item for unit in units for item in unit.member_item_ids)
    member_paths = tuple(path for unit in units for path in unit.member_paths)
    if len(member_ids) > bounds.max_member_items:
        raise ReviewStateError("snapshot member bound exceeded")
    if len(member_ids) != len(set(member_ids)):
        raise ReviewStateError("snapshot member item ids overlap")
    if len(member_paths) != len(set(member_paths)):
        raise ReviewStateError("snapshot member paths overlap")
    if sum(unit.total_bytes for unit in units) > bounds.max_total_bytes:
        raise ReviewStateError("snapshot total byte bound exceeded")
    for index, left in enumerate(units):
        for right in units[index + 1 :]:
            if _paths_overlap(left.path, right.path):
                raise ReviewStateError("snapshot unit resource paths overlap")
    return units


def read_sealed_review_snapshot(
    final_dir: Path,
    *,
    expected_snapshot_id: str,
    expected_snapshot_sha256: str,
    expected_package_sha256: str,
    bounds: ReviewStateBounds = ReviewStateBounds(),
) -> SealedReviewSnapshot:
    """Read one exact sealed review snapshot without following links."""

    final_path = _absolute_path(final_dir, "review snapshot final directory")
    identity = _identifier(expected_snapshot_id, "expected snapshot id")
    expected_snapshot_hash = _sha256(
        expected_snapshot_sha256,
        "expected snapshot hash",
    )
    expected_package_hash = _sha256(
        expected_package_sha256,
        "expected package hash",
    )
    if type(bounds) is not ReviewStateBounds:
        raise TypeError("bounds must be ReviewStateBounds")

    final_fd = _open_exact_directory(final_path, "review snapshot")
    review_fd: Optional[int] = None
    try:
        final_directory_identity = _directory_identity(os.fstat(final_fd))
        _entries(final_fd, _TOP_LEVEL_MEMBERS, "review snapshot")
        review_fd = _open_child_directory(
            final_fd,
            final_path,
            "review",
            "review package",
        )
        review_directory_identity = _directory_identity(os.fstat(review_fd))
        _entries(review_fd, _REVIEW_MEMBERS, "review package")
        limits = {
            "review.html": bounds.max_review_html_bytes,
            "review.md": bounds.max_review_markdown_bytes,
            "review.meta.json": bounds.max_review_meta_bytes,
        }
        first_review = {
            name: _read_bounded_file(
                review_fd,
                final_path / "review" / name,
                label=name,
                limit=limits[name],
            )
            for name in _REVIEW_MEMBERS
        }
        snapshot_payload = _read_bounded_file(
            final_fd,
            final_path / "snapshot.json",
            label="snapshot payload",
            limit=bounds.max_snapshot_bytes,
        )
        manifest_payload = _read_bounded_file(
            final_fd,
            final_path / "manifest.json",
            label="snapshot manifest",
            limit=bounds.max_manifest_bytes,
        )
        if sha256_bytes(snapshot_payload) != expected_snapshot_hash:
            raise ReviewStateError("snapshot payload hash does not match expected head")
        if sha256_bytes(manifest_payload) != expected_package_hash:
            raise ReviewStateError("snapshot package hash does not match expected head")
        manifest_hashes = _manifest_hashes(
            manifest_payload,
            expected_snapshot_id=identity,
        )
        actual_member_hashes = {
            "review/review.html": sha256_bytes(first_review["review.html"]),
            "review/review.md": sha256_bytes(first_review["review.md"]),
            "review/review.meta.json": sha256_bytes(first_review["review.meta.json"]),
            "snapshot.json": sha256_bytes(snapshot_payload),
        }
        if manifest_hashes != actual_member_hashes:
            raise ReviewStateError("snapshot manifest member hashes do not match")
        try:
            review_hashes = review_package.validate_review_directory(
                final_path / "review",
                expected_source_snapshot_sha256=expected_snapshot_hash,
            )
        except review_package.ReviewPackageError as exc:
            raise ReviewStateError("review package fidelity validation failed") from exc
        if (
            review_hashes.html_sha256 != manifest_hashes["review/review.html"]
            or review_hashes.markdown_sha256 != manifest_hashes["review/review.md"]
            or review_hashes.meta_sha256 != manifest_hashes["review/review.meta.json"]
            or review_hashes.source_snapshot_sha256 != expected_snapshot_hash
        ):
            raise ReviewStateError("review package hashes do not match manifest")

        _entries(final_fd, _TOP_LEVEL_MEMBERS, "review snapshot")
        _entries(review_fd, _REVIEW_MEMBERS, "review package")
        second_review = {
            name: _read_bounded_file(
                review_fd,
                final_path / "review" / name,
                label=name,
                limit=limits[name],
            )
            for name in _REVIEW_MEMBERS
        }
        second_snapshot = _read_bounded_file(
            final_fd,
            final_path / "snapshot.json",
            label="snapshot payload",
            limit=bounds.max_snapshot_bytes,
        )
        second_manifest = _read_bounded_file(
            final_fd,
            final_path / "manifest.json",
            label="snapshot manifest",
            limit=bounds.max_manifest_bytes,
        )
        if (
            second_review != first_review
            or second_snapshot != snapshot_payload
            or second_manifest != manifest_payload
        ):
            raise ReviewStateError("review snapshot changed during validation")
        safety.require_same_directory_identity(
            final_path / "review",
            review_fd,
            "review package",
            error_type=ReviewStateError,
        )
        safety.require_same_directory_identity(
            final_path,
            final_fd,
            "review snapshot",
            error_type=ReviewStateError,
        )
        _require_exact_directory(os.fstat(review_fd), "review package")
        _require_exact_directory(os.fstat(final_fd), "review snapshot")
        if (
            _directory_identity(os.fstat(review_fd)) != review_directory_identity
            or _directory_identity(os.fstat(final_fd)) != final_directory_identity
        ):
            raise ReviewStateError("review snapshot directory changed during validation")
    finally:
        if review_fd is not None:
            os.close(review_fd)
        os.close(final_fd)

    payload = _canonical_object(snapshot_payload, "snapshot payload")
    schema_version = payload.get("schema_version")
    if (
        schema_version not in (1, 2)
        or payload.get("snapshot_id") != identity
        or (schema_version == 1 and "analysis_contexts" in payload)
        or (schema_version == 2 and "analysis_contexts" not in payload)
    ):
        raise ReviewStateError("snapshot payload identity contract is invalid")
    if schema_version == 1:
        analysis_contexts_json = canonical_json_bytes([])
        analysis_context_bundle = None
    else:
        try:
            analysis_context_bundle = (
                review_context.AnalysisContextBundle.from_canonical_bytes(
                    canonical_json_bytes(payload["analysis_contexts"])
                )
            )
            analysis_contexts_json = analysis_context_bundle.canonical_bytes
        except review_context.ReviewContextError as exc:
            raise ReviewStateError(
                "snapshot analysis contexts are invalid"
            ) from exc
    meta = _canonical_object(first_review["review.meta.json"], "review meta")
    if (
        meta.get("source_snapshot_sha256") != expected_snapshot_hash
        or meta.get("source_id") != identity
        or type(meta.get("review_kind")) is not str
        or type(meta.get("source_kind")) is not str
    ):
        raise ReviewStateError("review meta is not bound to snapshot identity")
    units = _snapshot_units(payload, bounds)
    if analysis_context_bundle is not None:
        try:
            if units:
                analysis_context_bundle.require_exact_unit_bindings(units)
            elif "batch_id" in payload:
                raise review_context.ReviewContextError(
                    "batch analysis units are missing"
                )
        except review_context.ReviewContextError as exc:
            raise ReviewStateError(
                "snapshot analysis context binding is invalid"
            ) from exc
    if schema_version == 2 and meta["review_kind"] == "run-overview":
        try:
            review_context.parse_campaign_review_snapshot(snapshot_payload)
        except review_context.ReviewContextError as exc:
            raise ReviewStateError(
                "campaign review workstream context is invalid"
            ) from exc
    try:
        semantic = json.loads(
            review_compiler.semantic_json_from_markdown(
                first_review["review.md"]
            ).decode("utf-8")
        )
    except (review_compiler.ReviewCompileError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewStateError("review semantic manifest is invalid") from exc
    semantic_items = semantic.get("items")
    expected_semantic_items = [
        {
            "action": unit.recommended_action,
            "effects": ",".join(unit.effect_codes) or "none",
            "id": unit.unit_id,
            "warnings": ",".join(unit.warning_codes) or "none",
        }
        for unit in units
    ]
    if semantic_items != expected_semantic_items:
        raise ReviewStateError("review items do not match sealed snapshot units")
    sealed_identity = sha256_bytes(
        canonical_json_bytes(
            {
                "manifest_sha256": expected_package_hash,
                "snapshot_sha256": expected_snapshot_hash,
            }
        )
    )
    return SealedReviewSnapshot(
        snapshot_id=identity,
        final_path=final_path,
        snapshot_payload=snapshot_payload,
        payload=payload,
        schema_version=schema_version,
        analysis_contexts_json=analysis_contexts_json,
        snapshot_sha256=expected_snapshot_hash,
        manifest_payload=manifest_payload,
        review_markdown=first_review["review.md"],
        package_sha256=expected_package_hash,
        sealed_identity_sha256=sealed_identity,
        review_hashes=review_hashes,
        review_kind=meta["review_kind"],
        source_kind=meta["source_kind"],
        source_id=meta["source_id"],
        units=units,
    )


def _row_tuple(row: Any) -> Optional[Tuple[Any, ...]]:
    return None if row is None else tuple(row)


class _HeadLoader:
    def __init__(
        self,
        connection: sqlite3.Connection,
        raw_root: Path,
        *,
        bounds: ReviewStateBounds = ReviewStateBounds(),
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if type(bounds) is not ReviewStateBounds:
            raise TypeError("bounds must be ReviewStateBounds")
        self.connection = connection
        self.raw_root = _absolute_path(raw_root, "raw root")
        self.bounds = bounds
        root_fd = safety.open_verified_directory(
            self.raw_root,
            require_owner_only=True,
            error_type=ReviewStateError,
        )
        try:
            info = os.fstat(root_fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise ReviewStateError("raw root is not owner-controlled")
            self._raw_root_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(root_fd)

    def _require_root_identity(self) -> None:
        descriptor = safety.open_verified_directory(
            self.raw_root,
            require_owner_only=True,
            error_type=ReviewStateError,
        )
        try:
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != self._raw_root_identity:
                raise ReviewStateError("raw root identity changed")
        finally:
            os.close(descriptor)

    def _begin(self) -> None:
        if self.connection.in_transaction:
            raise ReviewStateError("head loader requires transaction ownership")
        try:
            self.connection.execute("BEGIN")
            migrations = [
                tuple(row)
                for row in self.connection.execute(
                    "SELECT version, schema_sha256 "
                    "FROM schema_migrations ORDER BY version"
                ).fetchall()
            ]
            if migrations == [
                (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256),
                (
                    ledger_schema.LEDGER_SCHEMA_VERSION,
                    ledger_schema.LEDGER_SCHEMA_SHA256,
                ),
                (m3_schema.M3_SCHEMA_VERSION, m3_schema.M3_SCHEMA_SHA256),
            ]:
                m3_schema.verify_v3_schema(self.connection)
            else:
                ledger_schema.verify_v2_schema(self.connection)
        except (ledger_schema.LedgerSchemaError, m3_schema.M3SchemaError) as exc:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise ReviewStateError(
                "exact version-2 or version-3 ledger schema is required"
            ) from exc
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _rollback(self) -> None:
        if self.connection.in_transaction:
            self.connection.execute("ROLLBACK")

    def _commit(self) -> None:
        self.connection.execute("COMMIT")

    def _ledger_final_path(self, value: Any) -> Path:
        if type(value) is not str or not value or any(ord(character) < 0x20 for character in value):
            raise ReviewStateError("ledger snapshot final path is invalid")
        candidate_value = Path(value)
        if candidate_value.is_absolute():
            if str(candidate_value) != value or any(
                part in (".", "..") for part in candidate_value.parts
            ):
                raise ReviewStateError("ledger snapshot final path is not canonical")
            candidate = candidate_value
        else:
            if (
                posixpath.normpath(value) != value
                or value in (".", "..")
                or value.startswith("../")
                or value.startswith("/")
                or value.endswith("/")
                or "//" in value
            ):
                raise ReviewStateError("ledger snapshot final path is not canonical")
            candidate = self.raw_root / Path(value)
        try:
            relative = candidate.relative_to(self.raw_root)
        except ValueError as exc:
            raise ReviewStateError("ledger snapshot final path escapes raw root") from exc
        if not relative.parts:
            raise ReviewStateError("ledger snapshot final path cannot equal raw root")
        return candidate

    def _snapshot_row(self, snapshot_id: str) -> Tuple[Any, ...]:
        row = _row_tuple(
            self.connection.execute(
                "SELECT lineage_kind, campaign_id, batch_id, version, payload_sha256, "
                "final_path, final_sha256, state, structural_approval_ready "
                "FROM review_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
        )
        if row is None:
            raise ReviewStateError("current review snapshot row is missing")
        return row

    def _sealed_from_row(
        self,
        *,
        snapshot_id: str,
        snapshot_sha256: str,
        lineage_kind: str,
        campaign_id: str,
        batch_id: Optional[str],
        review_revision: int,
    ) -> SealedReviewSnapshot:
        row = self._snapshot_row(snapshot_id)
        (
            row_lineage,
            row_campaign,
            row_batch,
            version,
            payload_sha256,
            final_path_value,
            final_sha256,
            state,
            structural_approval_ready,
        ) = row
        if (
            row_lineage != lineage_kind
            or row_campaign != campaign_id
            or row_batch != batch_id
            or type(version) is not int
            or version < 1
            or version != review_revision
            or payload_sha256 != snapshot_sha256
            or state != "PUBLISHED"
            or type(structural_approval_ready) is not int
            or structural_approval_ready not in (0, 1)
        ):
            raise ReviewStateError("current review snapshot head ledger binding is invalid")
        _sha256(payload_sha256, "ledger snapshot payload hash")
        package_hash = _sha256(final_sha256, "ledger snapshot package hash")
        final_path = self._ledger_final_path(final_path_value)
        if final_path.name != snapshot_id:
            raise ReviewStateError("ledger snapshot final path does not match snapshot id")
        expected_path = (
            self.raw_root
            / "campaigns"
            / campaign_id
            / "snapshots"
            / snapshot_id
        )
        if final_path != expected_path:
            raise ReviewStateError(
                "ledger snapshot path is outside canonical campaign namespace"
            )
        self._require_root_identity()
        sealed = read_sealed_review_snapshot(
            final_path,
            expected_snapshot_id=snapshot_id,
            expected_snapshot_sha256=payload_sha256,
            expected_package_sha256=package_hash,
            bounds=self.bounds,
        )
        self._require_root_identity()
        payload = sealed.payload
        if (
            payload.get("campaign_id") != campaign_id
            or payload.get("snapshot_id") != snapshot_id
            or payload.get("schema_version") not in (1, 2)
            or type(payload.get("structural_approval_ready")) is not bool
            or payload.get("structural_approval_ready") != bool(structural_approval_ready)
        ):
            raise ReviewStateError("sealed snapshot payload does not match ledger binding")
        if lineage_kind == "CAMPAIGN":
            if (
                payload.get("version") != version
                or payload.get("batch_id") is not None
                or sealed.review_kind != "run-overview"
                or sealed.source_kind != "campaign-snapshot"
            ):
                raise ReviewStateError("campaign snapshot payload binding is invalid")
        else:
            if (
                payload.get("batch_id") != batch_id
                or payload.get("batch_version") != version
                or sealed.review_kind != "batch-preview"
                or sealed.source_kind != "batch-snapshot"
            ):
                raise ReviewStateError("batch snapshot payload binding is invalid")
        return sealed

    def _requested_unit_ids(self, unit_ids: Tuple[str, ...]) -> Tuple[str, ...]:
        if type(unit_ids) is not tuple or not unit_ids:
            raise ReviewStateError("requested unit ids must be a non-empty tuple")
        if len(unit_ids) > self.bounds.max_selected_units:
            raise ReviewStateError("requested unit bound exceeded")
        for unit_id in unit_ids:
            _identifier(unit_id, "requested unit id")
        if len(set(unit_ids)) != len(unit_ids):
            raise ReviewStateError("requested unit ids must be unique")
        return unit_ids

    def _subset(
        self,
        snapshot: SealedReviewSnapshot,
        unit_ids: Tuple[str, ...],
    ) -> Tuple[batch_service.BatchUnit, ...]:
        requested = self._requested_unit_ids(unit_ids)
        by_id = {unit.unit_id: unit for unit in snapshot.units}
        unknown = tuple(unit_id for unit_id in requested if unit_id not in by_id)
        if unknown:
            raise ReviewStateError("requested unit is not in current sealed snapshot")
        return tuple(by_id[unit_id] for unit_id in requested)


class CampaignHeadLoader(_HeadLoader):
    """Load selected units from the current READY campaign head."""

    def load(
        self,
        campaign_id: str,
        unit_ids: Tuple[str, ...],
    ) -> CampaignReviewHead:
        identity = _identifier(campaign_id, "campaign id")
        requested_unit_ids = self._requested_unit_ids(unit_ids)
        self._begin()
        try:
            row = _row_tuple(
                self.connection.execute(
                    "SELECT status, current_snapshot_id, current_snapshot_sha256, "
                    "review_revision FROM campaigns WHERE campaign_id = ?",
                    (identity,),
                ).fetchone()
            )
            if row is None:
                raise ReviewStateError("campaign does not exist")
            status, snapshot_id, snapshot_sha256, review_revision = row
            if (
                status != "READY"
                or type(review_revision) is not int
                or review_revision < 1
            ):
                raise ReviewStateError("campaign is not a current READY head")
            current_id = _identifier(snapshot_id, "campaign head snapshot id")
            current_hash = _sha256(snapshot_sha256, "campaign head snapshot hash")
            sealed = self._sealed_from_row(
                snapshot_id=current_id,
                snapshot_sha256=current_hash,
                lineage_kind="CAMPAIGN",
                campaign_id=identity,
                batch_id=None,
                review_revision=review_revision,
            )
            units = self._subset(sealed, requested_unit_ids)
            result = CampaignReviewHead(
                campaign_id=identity,
                current_snapshot_id=current_id,
                current_snapshot_sha256=current_hash,
                review_revision=review_revision,
                snapshot=sealed,
                units=units,
            )
            self._commit()
            return result
        except BaseException:
            self._rollback()
            raise

    load_head = load


class ReviewSnapshotLoader(_HeadLoader):
    """Load any ledger-published snapshot by id without requiring current-head status."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        control_root: Path,
        *,
        bounds: ReviewStateBounds = ReviewStateBounds(),
    ) -> None:
        super().__init__(connection, control_root, bounds=bounds)

    def load(self, snapshot_id: str) -> SealedReviewSnapshot:
        identity = _identifier(snapshot_id, "snapshot id")
        self._begin()
        try:
            row = self._snapshot_row(identity)
            lineage_kind, campaign_id, batch_id, version = row[:4]
            if lineage_kind not in ("CAMPAIGN", "BATCH"):
                raise ReviewStateError("review snapshot lineage is invalid")
            campaign_identity = _identifier(
                campaign_id,
                "review snapshot campaign id",
            )
            if type(version) is not int or version < 1:
                raise ReviewStateError("review snapshot version is invalid")
            if lineage_kind == "CAMPAIGN":
                if batch_id is not None:
                    raise ReviewStateError("campaign snapshot batch binding is invalid")
                batch_identity = None
            else:
                batch_identity = _identifier(
                    batch_id,
                    "review snapshot batch id",
                )
            sealed = self._sealed_from_row(
                snapshot_id=identity,
                snapshot_sha256=_sha256(row[4], "ledger snapshot payload hash"),
                lineage_kind=lineage_kind,
                campaign_id=campaign_identity,
                batch_id=batch_identity,
                review_revision=version,
            )
            self._commit()
            return sealed
        except BaseException:
            self._rollback()
            raise


class BatchHeadLoader(_HeadLoader):
    """Load selected units from the current OPEN batch head for explode."""

    def load(
        self,
        batch_id: str,
        unit_ids: Tuple[str, ...],
    ) -> BatchReviewHead:
        identity = _identifier(batch_id, "batch id")
        requested_unit_ids = self._requested_unit_ids(unit_ids)
        self._begin()
        try:
            row = _row_tuple(
                self.connection.execute(
                    "SELECT campaign_id, status, current_snapshot_id, "
                    "current_snapshot_sha256, review_revision, execution_generation "
                    "FROM review_batches WHERE batch_id = ?",
                    (identity,),
                ).fetchone()
            )
            if row is None:
                raise ReviewStateError("batch does not exist")
            (
                campaign_id,
                status,
                snapshot_id,
                snapshot_sha256,
                review_revision,
                execution_generation,
            ) = row
            if (
                status != "OPEN"
                or type(review_revision) is not int
                or review_revision < 1
                or type(execution_generation) is not int
                or execution_generation < 0
            ):
                raise ReviewStateError("batch is not a current OPEN head")
            campaign_identity = _identifier(campaign_id, "batch campaign id")
            current_id = _identifier(snapshot_id, "batch head snapshot id")
            current_hash = _sha256(snapshot_sha256, "batch head snapshot hash")
            sealed = self._sealed_from_row(
                snapshot_id=current_id,
                snapshot_sha256=current_hash,
                lineage_kind="BATCH",
                campaign_id=campaign_identity,
                batch_id=identity,
                review_revision=review_revision,
            )
            units = self._subset(sealed, requested_unit_ids)
            result = BatchReviewHead(
                batch_id=identity,
                campaign_id=campaign_identity,
                current_snapshot_id=current_id,
                current_snapshot_sha256=current_hash,
                review_revision=review_revision,
                execution_generation=execution_generation,
                snapshot=sealed,
                units=units,
            )
            self._commit()
            return result
        except BaseException:
            self._rollback()
            raise

    load_head = load


__all__ = [
    "BatchHeadLoader",
    "BatchReviewHead",
    "CampaignHeadLoader",
    "CampaignReviewHead",
    "ReviewStateBounds",
    "ReviewStateError",
    "ReviewSnapshotLoader",
    "SealedReviewSnapshot",
    "read_sealed_review_snapshot",
]
