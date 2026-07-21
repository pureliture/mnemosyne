"""Framework-neutral immutable snapshot and review-package publisher."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from . import review_compiler, review_package, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ReviewSnapshotError(ValueError):
    """A review snapshot cannot be planned, published, or verified safely."""


@dataclass(frozen=True)
class ReviewSnapshotPlan:
    snapshot_id: str
    staging_path: Path
    final_path: Path
    snapshot_payload: bytes
    snapshot_sha256: str
    review_artifacts: review_compiler.ReviewArtifacts
    manifest_bytes: bytes
    package_sha256: str
    sealed_identity_sha256: str


@dataclass(frozen=True)
class ReviewSnapshotResult:
    snapshot_id: str
    final_path: Path
    snapshot_sha256: str
    package_sha256: str
    sealed_identity_sha256: str
    resumed: bool


def _snapshot_id(value: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ReviewSnapshotError("snapshot id is invalid")
    return value


def _canonical_snapshot_payload(snapshot_id: str, payload: bytes) -> bytes:
    if type(payload) is not bytes:
        raise TypeError("snapshot_payload must be bytes")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewSnapshotError("snapshot payload is not canonical JSON") from exc
    if type(decoded) is not dict or canonical_json_bytes(decoded) != payload:
        raise ReviewSnapshotError("snapshot payload is not canonical JSON")
    if decoded.get("snapshot_id") != snapshot_id:
        raise ReviewSnapshotError("snapshot payload id does not match plan")
    return payload


def _expected_manifest(
    snapshot_id: str,
    snapshot_payload: bytes,
    artifacts: review_compiler.ReviewArtifacts,
) -> bytes:
    members = [
        {
            "path": "review/review.html",
            "sha256": sha256_bytes(artifacts.html),
        },
        {
            "path": "review/review.md",
            "sha256": sha256_bytes(artifacts.markdown),
        },
        {
            "path": "review/review.meta.json",
            "sha256": sha256_bytes(artifacts.meta_json),
        },
        {
            "path": "snapshot.json",
            "sha256": sha256_bytes(snapshot_payload),
        },
    ]
    return canonical_json_bytes(
        {
            "kind": "MNEMOSYNE_REVIEW_SNAPSHOT",
            "members": members,
            "schema_version": 1,
            "snapshot_id": snapshot_id,
        }
    )


def _open_owner_directory(path: Path, label: str) -> int:
    descriptor = safety.open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ReviewSnapshotError,
    )
    opened = os.fstat(descriptor)
    if (
        opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise ReviewSnapshotError("%s directory must be owner-only mode 0700" % label)
    return descriptor


def _ensure_directory(path: Path, label: str) -> None:
    if not os.path.lexists(path):
        safety.create_verified_directory_no_replace(
            path,
            label=label,
            collision_error="%s already exists" % label,
            mode=0o700,
            error_type=ReviewSnapshotError,
        )
    descriptor = _open_owner_directory(path, label)
    os.close(descriptor)


def _read_exact_file(path: Path, label: str) -> bytes:
    directory_fd = _open_owner_directory(path.parent, "%s parent" % label)
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label=label,
            expected_mode=0o600,
            error_type=ReviewSnapshotError,
        )
        if info.st_nlink != 1:
            raise ReviewSnapshotError("%s link count is invalid" % label)
        return raw
    finally:
        os.close(directory_fd)


def _ensure_file(path: Path, encoded: bytes, label: str) -> None:
    if os.path.lexists(path):
        if _read_exact_file(path, label) != encoded:
            raise ReviewSnapshotError("%s bytes differ from the sealed plan" % label)
        return
    safety.publish_bytes_atomic_no_replace(
        path,
        encoded,
        label=label,
        mode=0o600,
        create_parent=False,
        collision_error="%s already exists" % label,
        final_identity_error="%s identity is invalid" % label,
        parent_error="%s parent is invalid" % label,
        error_type=ReviewSnapshotError,
        after_fd_readback=lambda _path, _fd, _directory_fd: None,
    )


def _require_entries(path: Path, allowed: tuple, *, complete: bool) -> None:
    descriptor = _open_owner_directory(path, "review snapshot")
    try:
        observed = tuple(sorted(os.listdir(descriptor)))
    finally:
        os.close(descriptor)
    unexpected = tuple(name for name in observed if name not in allowed)
    if unexpected:
        raise ReviewSnapshotError(
            "unexpected review snapshot member: %s" % unexpected[0]
        )
    if complete and observed != tuple(sorted(allowed)):
        raise ReviewSnapshotError("review snapshot member set is incomplete")


class ReviewSnapshotPublisher:
    """Plan exact bytes, then publish and verify one immutable package."""

    def __init__(self, snapshot_root: Path, *, renderer_id: str) -> None:
        root = Path(snapshot_root)
        if not root.is_absolute() or any(part in (".", "..") for part in root.parts):
            raise ReviewSnapshotError(
                "snapshot root must be a canonical absolute path"
            )
        self.snapshot_root = root
        self.compiler = review_compiler.ReviewCompiler(renderer_id)

    def plan(
        self,
        *,
        snapshot_id: str,
        snapshot_payload: bytes,
        review_document: review_compiler.ReviewDocument,
    ) -> ReviewSnapshotPlan:
        identity = _snapshot_id(snapshot_id)
        encoded_snapshot = _canonical_snapshot_payload(identity, snapshot_payload)
        if type(review_document) is not review_compiler.ReviewDocument:
            raise TypeError("review_document must be ReviewDocument")
        snapshot_sha256 = sha256_bytes(encoded_snapshot)
        if review_document.source_id != identity:
            raise ReviewSnapshotError(
                "review source id does not match snapshot payload"
            )
        if review_document.source_snapshot_sha256 != snapshot_sha256:
            raise ReviewSnapshotError(
                "review source snapshot hash does not match snapshot payload"
            )
        if (
            review_document.snapshot_id is not None
            and review_document.snapshot_id != identity
        ):
            raise ReviewSnapshotError(
                "review snapshot id does not match snapshot payload"
            )
        artifacts = self.compiler.compile(review_document)
        try:
            meta = json.loads(artifacts.meta_json.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReviewSnapshotError("review meta is invalid") from exc
        if meta.get("source_snapshot_sha256") != snapshot_sha256:
            raise ReviewSnapshotError(
                "review meta source snapshot hash does not match snapshot payload"
            )
        manifest = _expected_manifest(identity, encoded_snapshot, artifacts)
        package_sha256 = sha256_bytes(manifest)
        sealed_identity_sha256 = sha256_bytes(
            canonical_json_bytes(
                {
                    "manifest_sha256": package_sha256,
                    "snapshot_sha256": snapshot_sha256,
                }
            )
        )
        return ReviewSnapshotPlan(
            snapshot_id=identity,
            staging_path=self.snapshot_root / (".incomplete-%s" % identity),
            final_path=self.snapshot_root / identity,
            snapshot_payload=encoded_snapshot,
            snapshot_sha256=snapshot_sha256,
            review_artifacts=artifacts,
            manifest_bytes=manifest,
            package_sha256=package_sha256,
            sealed_identity_sha256=sealed_identity_sha256,
        )

    def _validate_plan(self, plan: ReviewSnapshotPlan) -> None:
        if type(plan) is not ReviewSnapshotPlan:
            raise TypeError("plan must be ReviewSnapshotPlan")
        _snapshot_id(plan.snapshot_id)
        if (
            plan.staging_path
            != self.snapshot_root / (".incomplete-%s" % plan.snapshot_id)
            or plan.final_path != self.snapshot_root / plan.snapshot_id
        ):
            raise ReviewSnapshotError("plan paths do not match publisher root")
        _canonical_snapshot_payload(plan.snapshot_id, plan.snapshot_payload)
        if sha256_bytes(plan.snapshot_payload) != plan.snapshot_sha256:
            raise ReviewSnapshotError("plan snapshot hash is invalid")
        if type(plan.review_artifacts) is not review_compiler.ReviewArtifacts:
            raise ReviewSnapshotError("plan review artifact type is invalid")
        try:
            review_compiler.validate_review_artifacts(plan.review_artifacts)
            meta = json.loads(plan.review_artifacts.meta_json.decode("utf-8"))
        except (
            review_compiler.ReviewCompileError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise ReviewSnapshotError("plan review artifacts are invalid") from exc
        if meta.get("source_snapshot_sha256") != plan.snapshot_sha256:
            raise ReviewSnapshotError("plan review meta is not bound to snapshot")
        if meta.get("source_id") != plan.snapshot_id:
            raise ReviewSnapshotError(
                "plan review source id is not bound to snapshot"
            )
        expected_manifest = _expected_manifest(
            plan.snapshot_id,
            plan.snapshot_payload,
            plan.review_artifacts,
        )
        if plan.manifest_bytes != expected_manifest:
            raise ReviewSnapshotError("plan manifest bytes are invalid")
        if sha256_bytes(plan.manifest_bytes) != plan.package_sha256:
            raise ReviewSnapshotError("plan package hash is invalid")
        expected_identity = sha256_bytes(
            canonical_json_bytes(
                {
                    "manifest_sha256": plan.package_sha256,
                    "snapshot_sha256": plan.snapshot_sha256,
                }
            )
        )
        if plan.sealed_identity_sha256 != expected_identity:
            raise ReviewSnapshotError("plan sealed identity is invalid")

    def _verify_package(self, path: Path, plan: ReviewSnapshotPlan) -> None:
        _require_entries(
            path,
            ("manifest.json", "review", "snapshot.json"),
            complete=True,
        )
        review_fd = _open_owner_directory(path / "review", "review package")
        os.close(review_fd)
        if (
            _read_exact_file(path / "snapshot.json", "snapshot payload")
            != plan.snapshot_payload
        ):
            raise ReviewSnapshotError("snapshot payload readback mismatch")
        if (
            _read_exact_file(path / "manifest.json", "snapshot manifest")
            != plan.manifest_bytes
        ):
            raise ReviewSnapshotError("snapshot manifest readback mismatch")
        try:
            hashes = review_package.validate_review_directory(
                path / "review",
                expected_source_snapshot_sha256=plan.snapshot_sha256,
            )
        except review_package.ReviewPackageError as exc:
            raise ReviewSnapshotError(
                "review package fidelity or identity validation failed"
            ) from exc
        expected_review_hashes = (
            sha256_bytes(plan.review_artifacts.markdown),
            sha256_bytes(plan.review_artifacts.html),
            sha256_bytes(plan.review_artifacts.meta_json),
        )
        if (
            hashes.markdown_sha256,
            hashes.html_sha256,
            hashes.meta_sha256,
        ) != expected_review_hashes:
            raise ReviewSnapshotError("review package readback mismatch")

    def publish(self, plan: ReviewSnapshotPlan) -> ReviewSnapshotResult:
        self._validate_plan(plan)
        if os.path.lexists(plan.final_path):
            root_fd = _open_owner_directory(self.snapshot_root, "snapshot root")
            os.close(root_fd)
            if os.path.lexists(plan.staging_path):
                _require_entries(
                    plan.staging_path,
                    ("manifest.json", "review", "snapshot.json"),
                    complete=False,
                )
                raise ReviewSnapshotError(
                    "conflicting snapshot staging exists beside final package"
                )
            self._verify_package(plan.final_path, plan)
            return ReviewSnapshotResult(
                snapshot_id=plan.snapshot_id,
                final_path=plan.final_path,
                snapshot_sha256=plan.snapshot_sha256,
                package_sha256=plan.package_sha256,
                sealed_identity_sha256=plan.sealed_identity_sha256,
                resumed=True,
            )

        root_fd = safety.open_or_create_verified_directory(
            self.snapshot_root,
            mode=0o700,
            error_type=ReviewSnapshotError,
        )
        os.close(root_fd)
        root_fd = _open_owner_directory(self.snapshot_root, "snapshot root")
        os.close(root_fd)
        resumed = os.path.lexists(plan.staging_path)
        _ensure_directory(plan.staging_path, "snapshot staging")
        _require_entries(
            plan.staging_path,
            ("manifest.json", "review", "snapshot.json"),
            complete=False,
        )
        _ensure_file(
            plan.staging_path / "snapshot.json",
            plan.snapshot_payload,
            "snapshot payload",
        )
        _ensure_directory(plan.staging_path / "review", "review package")
        try:
            review_package.write_review_package(
                plan.staging_path / "review",
                plan.review_artifacts,
            )
        except review_package.ReviewPackageError as exc:
            raise ReviewSnapshotError(
                "review package publication failed"
            ) from exc
        _ensure_file(
            plan.staging_path / "manifest.json",
            plan.manifest_bytes,
            "snapshot manifest",
        )
        self._verify_package(plan.staging_path, plan)
        staging_fd = _open_owner_directory(plan.staging_path, "snapshot staging")
        try:
            os.fsync(staging_fd)
        finally:
            os.close(staging_fd)
        try:
            safety.rename_path_no_replace(
                plan.staging_path,
                plan.final_path,
                collision_error="snapshot final path already exists",
                require_directory=True,
                error_type=ReviewSnapshotError,
            )
        except ReviewSnapshotError:
            if not os.path.lexists(plan.final_path):
                raise
            self._verify_package(plan.final_path, plan)
            if os.path.lexists(plan.staging_path):
                raise ReviewSnapshotError(
                    "conflicting snapshot staging exists beside final package"
                )
        self._verify_package(plan.final_path, plan)
        return ReviewSnapshotResult(
            snapshot_id=plan.snapshot_id,
            final_path=plan.final_path,
            snapshot_sha256=plan.snapshot_sha256,
            package_sha256=plan.package_sha256,
            sealed_identity_sha256=plan.sealed_identity_sha256,
            resumed=resumed,
        )


__all__ = [
    "ReviewSnapshotError",
    "ReviewSnapshotPlan",
    "ReviewSnapshotPublisher",
    "ReviewSnapshotResult",
]
