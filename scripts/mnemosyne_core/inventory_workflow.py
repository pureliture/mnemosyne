"""M1 read-only corpus inventory orchestration.

The workflow composes the independently verified admission, traversal, and
sealed-run primitives.  It writes only below the policy-owned inventory runs
root and never claims that a freshly sealed run is openable or approval-ready.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import admission, inventory, safety


EXPECTED_ARTIFACTS = ("coverage.json", "observations.jsonl")
MAX_REGISTRY_BYTES = 4 * 1024 * 1024
_POLICY_RECHECK_EVENTS = frozenset(
    ("terminal-before-rename", "terminal-rename-directory-check")
)


class InventoryWorkflowError(RuntimeError):
    """The workflow cannot safely start, resume, or publish the inventory."""


class InventoryPolicyDriftError(InventoryWorkflowError):
    """The placement registry changed while the admitted run was active."""


@dataclass(frozen=True)
class InventoryWorkflowReport:
    operation: str
    request_sha256: str
    scope_hash: str
    approved_policy: admission.ApprovedPolicyRef
    terminal: inventory.InventoryTerminal
    openable: bool = False
    approval_ready: bool = False

    def __post_init__(self) -> None:
        if self.operation not in ("start", "resume"):
            raise ValueError("unsupported inventory workflow operation")
        if (
            not isinstance(self.request_sha256, str)
            or len(self.request_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.request_sha256)
        ):
            raise ValueError("workflow request hash is invalid")
        if (
            not isinstance(self.scope_hash, str)
            or len(self.scope_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.scope_hash)
        ):
            raise ValueError("workflow scope hash is invalid")
        if not isinstance(self.approved_policy, admission.ApprovedPolicyRef):
            raise TypeError("workflow approved policy is invalid")
        if not isinstance(self.terminal, inventory.InventoryTerminal):
            raise TypeError("workflow terminal is invalid")
        if (
            self.openable is not False
            or self.approval_ready is not False
            or self.terminal.openable is not False
            or self.terminal.approval_ready is not False
        ):
            raise ValueError("M1 inventory is not openable or approval-ready")


def _canonical_bounds(
    bounds: Optional[inventory.TraversalBounds],
) -> inventory.TraversalBounds:
    if bounds is None:
        return inventory.TraversalBounds()
    if type(bounds) is not inventory.TraversalBounds:
        raise TypeError("bounds must be TraversalBounds")
    return bounds


def _bounds_mapping(bounds: inventory.TraversalBounds) -> Dict[str, int]:
    return {
        "max_entries": bounds.max_entries,
        "max_direct_entries": bounds.max_direct_entries,
        "max_depth": bounds.max_depth,
        "max_file_bytes": bounds.max_file_bytes,
        "max_content_bytes": bounds.max_content_bytes,
    }


def derive_inventory_run_request(
    admitted: admission.InventoryAdmission,
    run_id: str,
    bounds: Optional[inventory.TraversalBounds] = None,
) -> inventory.InventoryRunRequest:
    """Derive the one canonical request accepted by the full M1 workflow."""

    if type(admitted) is not admission.InventoryAdmission:
        raise TypeError("admitted must be InventoryAdmission")
    canonical_bounds = _canonical_bounds(bounds)
    approved = admitted.approved_policy
    policy_authority = {
        "raw_hash": approved.raw_hash,
        "full_hash": approved.full_hash,
        "writer_control_hash": approved.writer_control_hash,
        "foundation_hash": approved.foundation_hash,
        "generation": approved.generation,
        "source_kind": approved.source_kind,
        "source_run_id": approved.source_run_id,
        "guard_epoch": approved.guard_epoch,
    }
    scope = {
        "raw_root": admitted.scope.raw_root,
        "scope_hash": admitted.scope.scope_hash,
        "scope_json_b64": base64.b64encode(admitted.scope.scope_json).decode("ascii"),
    }
    return inventory.InventoryRunRequest.create(
        run_id=run_id,
        policy_authority=policy_authority,
        scope=scope,
        bounds=_bounds_mapping(canonical_bounds),
        expected_artifacts=EXPECTED_ARTIFACTS,
    )


def _canonical_root(root: Path) -> Path:
    candidate = Path(root)
    if not candidate.is_absolute() or any(part in (".", "..") for part in candidate.parts):
        raise InventoryWorkflowError("raw root is not a canonical absolute path")
    return candidate


def _ensure_runs_root(
    root: Path,
    compiled: Any,
    *,
    create: bool,
) -> Path:
    expected = root / "_registry" / "curation-runs"
    foundation = getattr(compiled, "foundation", None)
    if foundation is None or foundation.runs_root != str(expected):
        raise InventoryWorkflowError("compiled policy runs root is not canonical")

    parent = expected.parent
    parent_fd = safety.open_verified_directory(
        parent,
        require_owner_only=True,
        error_type=InventoryWorkflowError,
    )
    try:
        try:
            current = os.stat(expected.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if not create:
                raise InventoryWorkflowError("inventory runs root does not exist")
            try:
                os.mkdir(expected.name, 0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise InventoryWorkflowError("cannot create inventory runs root") from exc
        else:
            if not stat.S_ISDIR(current.st_mode):
                raise InventoryWorkflowError("inventory runs root is not a directory")

        descriptor = safety.open_verified_directory(
            expected,
            require_owner_only=True,
            error_type=InventoryWorkflowError,
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise InventoryWorkflowError("inventory runs root must be owner 0700")
            lexical = os.stat(expected.name, dir_fd=parent_fd, follow_symlinks=False)
            if (lexical.st_dev, lexical.st_ino) != (info.st_dev, info.st_ino):
                raise InventoryWorkflowError("inventory runs root identity changed")
            safety.require_same_directory_identity(
                expected,
                descriptor,
                "inventory runs root",
                error_type=InventoryWorkflowError,
            )
        finally:
            os.close(descriptor)
        safety.require_same_directory_identity(
            parent,
            parent_fd,
            "inventory runs parent",
            error_type=InventoryWorkflowError,
        )
        return expected
    finally:
        os.close(parent_fd)


def _verify_registry_raw_hash(root: Path, expected_raw_hash: str) -> None:
    path = root / "_registry" / "placement-map.yml"
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=InventoryPolicyDriftError,
    )
    try:
        info, raw = safety.read_regular_file_at(
            parent_fd,
            path.name,
            path,
            label="inventory policy registry",
            expected_mode=None,
            error_type=InventoryPolicyDriftError,
        )
        if (
            info.st_uid != os.getuid()
            or info.st_nlink != 1
            or len(raw) > MAX_REGISTRY_BYTES
            or hashlib.sha256(raw).hexdigest() != expected_raw_hash
        ):
            raise InventoryPolicyDriftError("inventory policy registry changed")
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            "inventory policy registry",
            error_type=InventoryPolicyDriftError,
        )
    finally:
        os.close(parent_fd)


def _workflow_report(
    operation: str,
    request: inventory.InventoryRunRequest,
    admitted: admission.InventoryAdmission,
    terminal: inventory.InventoryTerminal,
) -> InventoryWorkflowReport:
    return InventoryWorkflowReport(
        operation=operation,
        request_sha256=request.sha256,
        scope_hash=admitted.scope.scope_hash,
        approved_policy=admitted.approved_policy,
        terminal=terminal,
    )


def _run_inventory(
    root: Path,
    *,
    bootstrap_id: str,
    run_id: str,
    bounds: Optional[inventory.TraversalBounds],
    resume: bool,
) -> InventoryWorkflowReport:
    canonical = _canonical_root(root)
    canonical_bounds = _canonical_bounds(bounds)
    admitted = admission.admit_inventory(canonical, bootstrap_id=bootstrap_id)
    request = derive_inventory_run_request(admitted, run_id, canonical_bounds)
    detected_drift = {"error": None}

    def verify_current_policy() -> None:
        try:
            _verify_registry_raw_hash(canonical, admitted.approved_policy.raw_hash)
        except InventoryPolicyDriftError as exc:
            detected_drift["error"] = exc
            raise

    def store_checkpoint(event: str, _details: Mapping[str, Any]) -> None:
        # The outer equality lease already owns placement SH -> ledger SH.
        # Recheck exact registry bytes directly; never recursively acquire locks.
        if event in _POLICY_RECHECK_EVENTS:
            verify_current_policy()

    try:
        with admission.policy_equality_guard(
            canonical,
            bootstrap_id=bootstrap_id,
            approved_policy=admitted.approved_policy,
        ) as lease:
            if lease.approved_policy != admitted.approved_policy:
                raise InventoryWorkflowError("inventory policy lease changed")
            runs_root = _ensure_runs_root(
                canonical,
                lease.compiled_policy,
                create=not resume,
            )
            verify_current_policy()
            store = inventory.InventoryRunStore(
                runs_root,
                fault_checkpoint=store_checkpoint,
            )
            operation = "resume" if resume else "start"
            current = store.resume(request) if resume else store.start(request)
            if isinstance(current, inventory.InventoryTerminal):
                return _workflow_report(operation, request, admitted, current)
            if not isinstance(current, inventory.InventoryRunSession):
                raise InventoryWorkflowError("inventory store returned an invalid state")

            with current as session:
                verify_current_policy()
                engine = inventory.InventoryEngine(
                    canonical,
                    admitted.scope.to_scope_map(),
                    canonical_bounds,
                )
                try:
                    result = engine.scan(run_id)
                except inventory.InventoryError as exc:
                    verify_current_policy()
                    terminal = session.fail(
                        "inventory-scan-failed",
                        {"error_type": type(exc).__name__},
                    )
                    return _workflow_report(operation, request, admitted, terminal)
                verify_current_policy()
                terminal = session.publish_result(result)
                verify_current_policy()
                return _workflow_report(operation, request, admitted, terminal)
    except admission.InventoryAdmissionError as exc:
        if detected_drift["error"] is not None:
            raise detected_drift["error"] from exc
        raise


def start_inventory(
    root: Path,
    *,
    bootstrap_id: str,
    run_id: str,
    bounds: Optional[inventory.TraversalBounds] = None,
) -> InventoryWorkflowReport:
    """Start one new full inventory run under current policy authority."""

    return _run_inventory(
        root,
        bootstrap_id=bootstrap_id,
        run_id=run_id,
        bounds=bounds,
        resume=False,
    )


def resume_inventory(
    root: Path,
    *,
    bootstrap_id: str,
    run_id: str,
    bounds: Optional[inventory.TraversalBounds] = None,
) -> InventoryWorkflowReport:
    """Resume exact staging or read back an exact terminal inventory run."""

    return _run_inventory(
        root,
        bootstrap_id=bootstrap_id,
        run_id=run_id,
        bounds=bounds,
        resume=True,
    )


__all__ = [
    "EXPECTED_ARTIFACTS",
    "InventoryPolicyDriftError",
    "InventoryWorkflowError",
    "InventoryWorkflowReport",
    "derive_inventory_run_request",
    "resume_inventory",
    "start_inventory",
]
