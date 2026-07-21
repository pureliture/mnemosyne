"""Read-only inventory admission and typed policy-to-scope projection.

This module creates no policy authority of its own.  It admits only a current,
terminal ledger policy whose exact registry bytes remain stable while the
verified placement and ledger locks are held shared.  The resulting immutable
reference can be rechecked with :func:`policy_equality_guard` for the lifetime
of one bounded content read.

Only the strict :mod:`mnemosyne_core.policy` compiler parses registry YAML.
Scope projection consumes its typed anchors and the fixed inventory safety
matrix; it never reparses policy JSON or YAML.
"""

from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Sequence, Tuple

from . import control, inventory, policy, policy_authority, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


MAX_REGISTRY_BYTES = 4 * 1024 * 1024
SCOPE_PROJECTION_VERSION = "inventory-scope-v1"
_HASH_CHARACTERS = frozenset("0123456789abcdef")
_SOURCE_KINDS = frozenset(("INITIAL", "EDIT", "RECONCILE", "CUTOVER"))


class InventoryAdmissionError(RuntimeError):
    """Current filesystem/ledger state cannot mint inventory authority."""


class _StableRegistryMismatch(InventoryAdmissionError):
    """A no-follow postcheck captured stable bytes different from the lease."""

    def __init__(self, current_info: os.stat_result, current_raw: bytes) -> None:
        super().__init__("registry changed during admission")
        self.current_info = current_info
        self.current_raw = current_raw


class _PolicyDriftCandidate(Exception):
    """Stable registry bytes may be an external mismatch needing a guard event."""

    def __init__(
        self,
        cause: InventoryAdmissionError,
        *,
        observed_raw: bytes,
        observed_identity: Dict[str, Any],
        head_generation: int,
        head_full_hash: str,
        guard_epoch: int,
    ) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.observed_raw = observed_raw
        self.observed_identity = observed_identity
        self.head_generation = head_generation
        self.head_full_hash = head_full_hash
        self.guard_epoch = guard_epoch


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HASH_CHARACTERS for character in value)
    )


@dataclass(frozen=True)
class ApprovedPolicyRef:
    """Exact normal-policy authority, including raw and normalized identity."""

    raw_hash: str
    full_hash: str
    writer_control_hash: str
    foundation_hash: str
    generation: int
    source_kind: str
    source_run_id: str
    guard_epoch: int

    def __post_init__(self) -> None:
        for label, value in (
            ("raw_hash", self.raw_hash),
            ("full_hash", self.full_hash),
            ("writer_control_hash", self.writer_control_hash),
            ("foundation_hash", self.foundation_hash),
        ):
            if not _is_hash(value):
                raise ValueError("%s must be a lowercase SHA-256" % label)
        if (
            not isinstance(self.generation, int)
            or isinstance(self.generation, bool)
            or self.generation < 1
        ):
            raise ValueError("generation must be a positive integer")
        if self.source_kind not in _SOURCE_KINDS:
            raise ValueError("unsupported source_kind")
        if (
            not isinstance(self.source_run_id, str)
            or not self.source_run_id
            or self.source_run_id != self.source_run_id.strip()
            or any(ord(character) < 0x20 for character in self.source_run_id)
        ):
            raise ValueError("source_run_id is invalid")
        if (
            not isinstance(self.guard_epoch, int)
            or isinstance(self.guard_epoch, bool)
            or self.guard_epoch < 0
        ):
            raise ValueError("guard_epoch must be a non-negative integer")


@dataclass(frozen=True)
class InventoryScopeBinding:
    components: Tuple[bytes, ...]
    decision: inventory.ScopeDecision

    def __post_init__(self) -> None:
        if not self.components:
            raise ValueError("scope binding cannot target the raw root")
        # The inventory encoder is the canonical byte-component validator.
        inventory.canonical_raw_path(self.components)


@dataclass(frozen=True)
class InventoryScopeProjection:
    """Immutable effective scope map derived from typed policy anchors."""

    raw_root: str
    default: inventory.ScopeDecision
    bindings: Tuple[InventoryScopeBinding, ...]
    never_touch: Tuple[Tuple[bytes, ...], ...]
    scope_json: bytes
    scope_hash: str

    def __post_init__(self) -> None:
        if not _is_hash(self.scope_hash) or sha256_bytes(self.scope_json) != self.scope_hash:
            raise ValueError("scope projection hash is invalid")
        if tuple(
            sorted(
                self.bindings,
                key=lambda item: (
                    -len(item.components),
                    inventory.canonical_raw_path(item.components),
                ),
            )
        ) != self.bindings:
            raise ValueError("scope bindings are not in canonical order")

    def to_scope_map(self) -> inventory.ScopeMap:
        return inventory.ScopeMap.create(
            default=self.default,
            bindings=tuple(
                (binding.components, binding.decision) for binding in self.bindings
            ),
            never_touch=self.never_touch,
        )


@dataclass(frozen=True)
class InventoryAdmission:
    approved_policy: ApprovedPolicyRef
    scope: InventoryScopeProjection
    scope_hash: str

    def __post_init__(self) -> None:
        if self.scope_hash != self.scope.scope_hash:
            raise ValueError("admission scope hash changed")


@dataclass(frozen=True)
class PolicyReadLease:
    """Short-lived equality proof held under both shared coordination locks."""

    approved_policy: ApprovedPolicyRef
    compiled_policy: policy.CompiledPolicy


@dataclass
class _RegistryObservation:
    path: Path
    parent_fd: int
    info: os.stat_result
    raw: bytes

    def guard_identity(
        self,
        root: Path,
        compiled: Optional[policy.CompiledPolicy],
        *,
        raw: Optional[bytes] = None,
        info: Optional[os.stat_result] = None,
    ) -> Dict[str, Any]:
        observed_raw = self.raw if raw is None else raw
        observed_info = self.info if info is None else info
        return {
            "path": str(root / "_registry" / "placement-map.yml"),
            "raw_sha256": sha256_bytes(observed_raw),
            "normalized_full_hash": (
                compiled.full_hash if compiled is not None else None
            ),
            "compile_status": "VALID" if compiled is not None else "INVALID",
            "bytes": len(observed_raw),
            "device": observed_info.st_dev,
            "inode": observed_info.st_ino,
            "mode": "%04o" % stat.S_IMODE(observed_info.st_mode),
            "uid": observed_info.st_uid,
            "nlink": observed_info.st_nlink,
        }

    def verify_unchanged(self) -> None:
        try:
            current, raw = safety.read_regular_file_at(
                self.parent_fd,
                self.path.name,
                self.path,
                label="placement registry",
                expected_mode=None,
                error_type=InventoryAdmissionError,
            )
            safety.require_same_directory_identity(
                self.path.parent,
                self.parent_fd,
                "placement registry",
                error_type=InventoryAdmissionError,
            )
        except InventoryAdmissionError as exc:
            raise InventoryAdmissionError("registry changed during admission") from exc
        if (
            (current.st_dev, current.st_ino) != (self.info.st_dev, self.info.st_ino)
            or current.st_uid != self.info.st_uid
            or current.st_nlink != self.info.st_nlink
            or stat.S_IMODE(current.st_mode) != stat.S_IMODE(self.info.st_mode)
            or raw != self.raw
        ):
            raise _StableRegistryMismatch(current, raw)

    def close(self) -> None:
        os.close(self.parent_fd)


def _canonical_root(root: Path) -> Path:
    candidate = Path(root)
    if not candidate.is_absolute() or any(part in (".", "..") for part in candidate.parts):
        raise InventoryAdmissionError("raw root is not a canonical absolute path")
    descriptor = safety.open_verified_directory(
        candidate,
        require_owner_only=True,
        error_type=InventoryAdmissionError,
    )
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise InventoryAdmissionError("raw root is not owner-controlled")
    finally:
        os.close(descriptor)
    return candidate


def _open_shared_lock(path: Path, label: str) -> int:
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=InventoryAdmissionError,
    )
    descriptor: Optional[int] = None
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lexical = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise InventoryAdmissionError("%s identity is invalid" % label)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InventoryAdmissionError("%s is busy" % label) from exc
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            label,
            error_type=InventoryAdmissionError,
        )
        return descriptor
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent_fd)


@contextmanager
def _shared_control_locks(root: Path) -> Iterator[None]:
    placement_fd = _open_shared_lock(
        root / "_registry" / "placement-map.lock",
        "placement policy lock",
    )
    ledger_fd: Optional[int] = None
    try:
        ledger_fd = _open_shared_lock(
            root / "_registry" / "curation" / "ledger.lock",
            "curation ledger lock",
        )
        yield
    finally:
        if ledger_fd is not None:
            os.close(ledger_fd)
        os.close(placement_fd)


def _open_registry(root: Path) -> _RegistryObservation:
    path = root / "_registry" / "placement-map.yml"
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=InventoryAdmissionError,
    )
    try:
        info, raw = safety.read_regular_file_at(
            parent_fd,
            path.name,
            path,
            label="placement registry",
            expected_mode=None,
            error_type=InventoryAdmissionError,
        )
        if info.st_uid != os.getuid() or info.st_nlink != 1:
            raise InventoryAdmissionError("placement registry ownership is invalid")
        if len(raw) > MAX_REGISTRY_BYTES:
            raise InventoryAdmissionError("placement registry exceeds admission bound")
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            "placement registry",
            error_type=InventoryAdmissionError,
        )
        return _RegistryObservation(path, parent_fd, info, raw)
    except Exception:
        os.close(parent_fd)
        raise


def _connect_readonly_ledger(root: Path) -> Tuple[sqlite3.Connection, Tuple[int, int]]:
    path = root / "_registry" / "curation" / "ledger.sqlite3"
    parent_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=InventoryAdmissionError,
    )
    try:
        info, database_raw = safety.read_regular_file_at(
            parent_fd,
            path.name,
            path,
            label="curation ledger",
            expected_mode=0o600,
            error_type=InventoryAdmissionError,
        )
        if info.st_nlink != 1:
            raise InventoryAdmissionError("curation ledger link count is invalid")
        if (
            len(database_raw) < 100
            or database_raw[:16] != b"SQLite format 3\x00"
            or database_raw[18:20] != b"\x02\x02"
        ):
            raise InventoryAdmissionError("curation ledger header is not terminal WAL mode")
        try:
            wal_info = os.stat(
                path.name + "-wal",
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            wal_info = None
        except OSError as exc:
            raise InventoryAdmissionError("curation ledger WAL state is unreadable") from exc
        if wal_info is not None and (
            not stat.S_ISREG(wal_info.st_mode)
            or wal_info.st_uid != os.getuid()
            or wal_info.st_size != 0
        ):
            raise InventoryAdmissionError(
                "curation ledger has pending WAL state; immutable read is unsafe"
            )
        identity = (info.st_dev, info.st_ino)
        safety.require_same_directory_identity(
            path.parent,
            parent_fd,
            "curation ledger",
            error_type=InventoryAdmissionError,
        )
    finally:
        os.close(parent_fd)

    try:
        connection = sqlite3.connect(
            path.as_uri() + "?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        raise InventoryAdmissionError("cannot open curation ledger read-only") from exc
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = %d" % control.BUSY_TIMEOUT_MS)
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise InventoryAdmissionError("curation ledger integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise InventoryAdmissionError("curation ledger foreign-key check failed")
        migration = connection.execute(
            "SELECT schema_sha256 FROM schema_migrations WHERE version = ?",
            (control.CONTROL_SCHEMA_VERSION,),
        ).fetchone()
        if migration is None or migration[0] != control.CONTROL_SCHEMA_SHA256:
            raise InventoryAdmissionError("curation ledger schema identity changed")
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            raise InventoryAdmissionError("curation ledger identity changed while opening")
        connection.execute("BEGIN")
        return connection, identity
    except Exception:
        connection.close()
        raise


def _verify_ledger_identity(root: Path, identity: Tuple[int, int]) -> None:
    path = root / "_registry" / "curation" / "ledger.sqlite3"
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise InventoryAdmissionError("curation ledger identity changed") from exc
    if (current.st_dev, current.st_ino) != identity:
        raise InventoryAdmissionError("curation ledger identity changed")


def _require_lane_and_guard_clear(connection: sqlite3.Connection) -> None:
    lane = connection.execute(
        "SELECT generation, state, owner_kind, owner_proposal_id, owner_approval_id, "
        "owner_run_id, owner_process_id FROM policy_mutation_lane WHERE id = 1"
    ).fetchone()
    if lane is None or lane["state"] != "IDLE" or any(
        lane[field] is not None
        for field in (
            "owner_kind",
            "owner_proposal_id",
            "owner_approval_id",
            "owner_run_id",
            "owner_process_id",
        )
    ):
        raise InventoryAdmissionError("policy mutation lane is not IDLE")
    if connection.execute(
        "SELECT COUNT(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
    ).fetchone()[0]:
        raise InventoryAdmissionError("open policy guard episode blocks inventory")
    if connection.execute(
        "SELECT COUNT(*) FROM policy_guard_events WHERE state != 'COMPLETE'"
    ).fetchone()[0]:
        raise InventoryAdmissionError("nonterminal policy guard event blocks inventory")


def _read_unbound_head(connection: sqlite3.Connection) -> sqlite3.Row:
    head = connection.execute(
        "SELECT generation, full_hash, writer_control_hash, foundation_hash, "
        "source_kind, source_run_id, guard_epoch FROM policy_head WHERE id = 1"
    ).fetchone()
    if head is None:
        raise InventoryAdmissionError("policy head is missing")
    if (
        not isinstance(head["generation"], int)
        or head["generation"] < 1
        or not _is_hash(head["full_hash"])
        or not _is_hash(head["writer_control_hash"])
        or not _is_hash(head["foundation_hash"])
        or head["source_kind"] not in _SOURCE_KINDS
        or not isinstance(head["source_run_id"], str)
        or not head["source_run_id"]
        or not isinstance(head["guard_epoch"], int)
        or head["guard_epoch"] < 0
    ):
        raise InventoryAdmissionError("policy head fields are invalid")
    return head


def _read_head(
    connection: sqlite3.Connection,
    compiled: policy.CompiledPolicy,
) -> sqlite3.Row:
    head = _read_unbound_head(connection)
    if (
        head["full_hash"] != compiled.full_hash
        or head["writer_control_hash"] != compiled.writer_hash
        or head["foundation_hash"] != compiled.foundation_hash
    ):
        raise InventoryAdmissionError("policy head does not match current registry")
    return head


def _verify_terminal_source(
    connection: sqlite3.Connection,
    root: Path,
    bootstrap_id: str,
    registry_raw: bytes,
    compiled: policy.CompiledPolicy,
    head: sqlite3.Row,
) -> None:
    try:
        policy_authority.verify_current_policy_binding_locked(
            connection,
            root,
            registry_raw,
            compiled,
            head,
            expected_initial_bootstrap_id=bootstrap_id,
        )
    except policy_authority.PolicyAuthorityError as exc:
        if "run membership changed" in str(exc):
            raise InventoryAdmissionError("source run membership changed") from exc
        if "result" in str(exc):
            raise InventoryAdmissionError("source result authority changed") from exc
        raise InventoryAdmissionError(
            "%s terminal source is not exact" % head["source_kind"]
        ) from exc


def _decision_dict(value: inventory.ScopeDecision) -> Dict[str, Any]:
    return {
        "rule_id": value.rule_id,
        "scope_class": value.scope_class,
        "traversal": value.traversal,
        "lifecycle": value.lifecycle,
        "content_inspection": value.content_inspection,
        "excluded_reason": value.excluded_reason,
    }


def _fallback() -> inventory.ScopeDecision:
    return inventory.ScopeDecision(
        "fallback-unassigned",
        "unassigned-intake",
        "metadata-only",
        "unassigned",
        "none",
    )


def _active() -> inventory.ScopeDecision:
    return inventory.ScopeDecision(
        "active-workstream-content",
        "eligible",
        "full",
        "active",
        "bounded-text",
    )


def _frozen(lifecycle: str) -> inventory.ScopeDecision:
    return inventory.ScopeDecision(
        "paused-completed",
        "coverage-only",
        "directory-count-only",
        lifecycle,
        "none",
    )


def _opaque(scope_class: str = "opaque-private-evidence") -> inventory.ScopeDecision:
    return inventory.ScopeDecision(
        "opaque-evidence",
        scope_class,
        "metadata-only",
        "any",
        "none",
    )


def _private() -> inventory.ScopeDecision:
    return inventory.ScopeDecision(
        "private-reviewable",
        "private-reviewable",
        "metadata-only",
        "any",
        "none",
    )


def _control() -> inventory.ScopeDecision:
    return inventory.ScopeDecision(
        "control", "control", "not-entered", "protected", "none", "control"
    )


def _relative_components(path: str, raw_root: str, label: str) -> Tuple[bytes, ...]:
    if path == raw_root or not path.startswith(raw_root + "/"):
        raise InventoryAdmissionError("%s is not below the raw root" % label)
    relative = path[len(raw_root) + 1 :]
    components = tuple(component.encode("utf-8") for component in relative.split("/"))
    try:
        inventory.canonical_raw_path(components)
    except (TypeError, ValueError) as exc:
        raise InventoryAdmissionError("%s cannot be represented as inventory scope" % label) from exc
    return components


def _scope_rank(value: inventory.ScopeDecision) -> int:
    if value.scope_class == "never-touch":
        return 120
    if value.scope_class == "control":
        return 110
    if value.scope_class in ("opaque-private-evidence", "memory", "mirror"):
        return 100
    if value.rule_id == "paused-completed":
        return 90
    # Physical private targets may never be widened by an active Workstream.
    if value.scope_class == "private-reviewable":
        return 80
    if value.rule_id == "active-workstream-content":
        return 60
    return 10


def _category_decision(category_id: str, components: Sequence[bytes]) -> inventory.ScopeDecision:
    lowered = category_id.casefold()
    first = components[0].lower() if components else b""
    if lowered == "memory" or first == b"memory":
        return _opaque("memory")
    if "mirror" in lowered or first == b"mirrors":
        return _opaque("mirror")
    if "private" in lowered or first == b"private":
        return _private()
    if (
        "evidence" in lowered
        or "audit" in lowered
        or first == b"evidence"
        or first.endswith(b"-cleanup-audit")
    ):
        return _opaque()
    return _fallback()


def _lifecycle_decision(lifecycle: str) -> inventory.ScopeDecision:
    if lifecycle == "active":
        return _active()
    if lifecycle in ("paused", "completed"):
        return _frozen(lifecycle)
    raise InventoryAdmissionError("compiled Workstream lifecycle is unsupported")


def _add_candidate(
    candidates: Dict[Tuple[bytes, ...], inventory.ScopeDecision],
    components: Tuple[bytes, ...],
    decision: inventory.ScopeDecision,
) -> None:
    current = candidates.get(components)
    if current is None or (
        _scope_rank(decision),
        canonical_json_bytes(_decision_dict(decision)),
    ) > (
        _scope_rank(current),
        canonical_json_bytes(_decision_dict(current)),
    ):
        candidates[components] = decision


def compile_inventory_scope(
    compiled: policy.CompiledPolicy,
    raw_root: str,
) -> InventoryScopeProjection:
    """Compile only typed policy anchors into the effective inventory matrix."""

    if not isinstance(compiled, policy.CompiledPolicy):
        raise TypeError("compiled must be CompiledPolicy")
    if compiled.registry_anchors.registry_root != raw_root + "/_registry":
        raise InventoryAdmissionError("compiled policy belongs to another raw root")

    candidates: Dict[Tuple[bytes, ...], inventory.ScopeDecision] = {}
    fixed = (
        ((b"_registry",), _control()),
        ((b"AGENTS.md",), _control()),
        ((b"CLAUDE.md",), _control()),
        ((b"_projects.md",), _control()),
        ((b"memory",), _opaque("memory")),
        ((b"mirrors",), _opaque("mirror")),
        ((b"private",), _private()),
        ((b"evidence",), _opaque()),
        ((b"_index", b"memory"), _frozen("completed")),
    )
    for components, decision in fixed:
        _add_candidate(candidates, components, decision)

    _add_candidate(
        candidates,
        _relative_components(
            compiled.registry_anchors.memory_workspaces,
            raw_root,
            "memory workspace registry",
        ),
        _control(),
    )
    _add_candidate(
        candidates,
        _relative_components(
            compiled.registry_anchors.inbox,
            raw_root,
            "inbox anchor",
        ),
        _fallback(),
    )

    for category in compiled.categories:
        components = _relative_components(
            category.target,
            raw_root,
            "category target %s" % category.id,
        )
        _add_candidate(
            candidates,
            components,
            _category_decision(category.id, components),
        )

    workstream_by_id = {value.id: value for value in compiled.workstreams}
    for workstream in compiled.workstreams:
        _add_candidate(
            candidates,
            _relative_components(
                workstream.project_home,
                raw_root,
                "Workstream project_home %s" % workstream.id,
            ),
            _lifecycle_decision(workstream.lifecycle),
        )

    for archive in compiled.archive_roots:
        workstream = workstream_by_id.get(archive.workstream_id)
        if workstream is None:
            raise InventoryAdmissionError("compiled archive root lost its Workstream")
        if archive.sensitivity == "opaque":
            decision = _opaque()
        elif archive.sensitivity == "private":
            decision = _private()
        else:
            decision = _lifecycle_decision(workstream.lifecycle)
        _add_candidate(
            candidates,
            _relative_components(
                archive.root,
                raw_root,
                "archive root %s" % archive.workstream_id,
            ),
            decision,
        )

    # Remove a more-permissive descendant that would otherwise win longest-
    # prefix resolution over a physically more-restrictive ancestor.
    effective: Dict[Tuple[bytes, ...], inventory.ScopeDecision] = {}
    for components, decision in sorted(
        candidates.items(),
        key=lambda item: (len(item[0]), inventory.canonical_raw_path(item[0])),
    ):
        ancestors = [
            (prefix, ancestor)
            for prefix, ancestor in effective.items()
            if len(prefix) < len(components) and components[: len(prefix)] == prefix
        ]
        strongest = max(
            ancestors,
            key=lambda item: (
                _scope_rank(item[1]),
                -len(item[0]),
                inventory.canonical_raw_path(item[0]),
            ),
            default=None,
        )
        if strongest is not None and _scope_rank(strongest[1]) > _scope_rank(decision):
            continue
        effective[components] = decision

    never_touch = tuple(
        tuple(component.encode("utf-8") for component in prefix.components)
        for prefix in compiled.never_touch
    )
    scope_map = inventory.ScopeMap.create(
        default=_fallback(),
        bindings=tuple(effective.items()),
        never_touch=never_touch,
    )
    bindings = tuple(
        InventoryScopeBinding(components, decision)
        for components, decision in scope_map.bindings
    )
    projection_value = {
        "version": SCOPE_PROJECTION_VERSION,
        "raw_root": raw_root,
        "default": _decision_dict(scope_map.default),
        "bindings": [
            {
                "path": inventory.canonical_raw_path(binding.components),
                "decision": _decision_dict(binding.decision),
            }
            for binding in bindings
        ],
        "never_touch": [
            inventory.canonical_raw_path(prefix) for prefix in scope_map.never_touch
        ],
    }
    scope_json = canonical_json_bytes(projection_value)
    return InventoryScopeProjection(
        raw_root=raw_root,
        default=scope_map.default,
        bindings=bindings,
        never_touch=scope_map.never_touch,
        scope_json=scope_json,
        scope_hash=sha256_bytes(scope_json),
    )


def _authority_ref(
    compiled: policy.CompiledPolicy,
    head: sqlite3.Row,
) -> ApprovedPolicyRef:
    return ApprovedPolicyRef(
        raw_hash=compiled.raw_hash,
        full_hash=compiled.full_hash,
        writer_control_hash=compiled.writer_hash,
        foundation_hash=compiled.foundation_hash,
        generation=head["generation"],
        source_kind=head["source_kind"],
        source_run_id=head["source_run_id"],
        guard_epoch=head["guard_epoch"],
    )


def _drift_candidate(
    cause: BaseException,
    *,
    observation: _RegistryObservation,
    root: Path,
    compiled: Optional[policy.CompiledPolicy],
    head: sqlite3.Row,
) -> _PolicyDriftCandidate:
    if isinstance(cause, InventoryAdmissionError):
        error = cause
    elif isinstance(cause, policy.PolicyError):
        error = InventoryAdmissionError("current registry policy is invalid")
        error.__cause__ = cause
    elif isinstance(cause, policy_authority.PolicyAuthorityError):
        error = InventoryAdmissionError("terminal policy authority is invalid")
        error.__cause__ = cause
    else:
        error = InventoryAdmissionError("policy admission validation failed")
        error.__cause__ = cause
    observed_raw = observation.raw
    observed_info = observation.info
    observed_compiled = compiled
    if isinstance(cause, _StableRegistryMismatch):
        observed_raw = cause.current_raw
        observed_info = cause.current_info
        try:
            observed_compiled = policy.compile_policy(observed_raw, str(root))
        except policy.PolicyError:
            observed_compiled = None
    return _PolicyDriftCandidate(
        error,
        observed_raw=observed_raw,
        observed_identity=observation.guard_identity(
            root,
            observed_compiled,
            raw=observed_raw,
            info=observed_info,
        ),
        head_generation=head["generation"],
        head_full_hash=head["full_hash"],
        guard_epoch=head["guard_epoch"],
    )


def _raise_after_durable_drift_observation(
    root: Path,
    candidate: _PolicyDriftCandidate,
    *,
    observed_by: str,
) -> None:
    """Record a mismatch after shared locks are gone, then fail admission."""
    first_error: Optional[BaseException] = None
    try:
        result = policy_authority.observe_policy_drift_from_stable_observation(
            root,
            observed_by=observed_by,
            observed_raw=candidate.observed_raw,
            observed_identity=candidate.observed_identity,
            expected_head_generation=candidate.head_generation,
            expected_head_full_hash=candidate.head_full_hash,
            expected_guard_epoch=candidate.guard_epoch,
        )
    except policy_authority.PolicyAuthorityError as exc:
        first_error = exc
        # The initially read bytes can be the approved A while a later
        # no-follow postcheck detects current B.  A fresh GuardService probe is
        # safe here because it derives the head/source/mismatch under its own
        # locks and cannot adopt policy authority.
        try:
            result = policy_authority.observe_policy_drift(
                root,
                observed_by=observed_by,
            )
        except policy_authority.PolicyAuthorityError as final_error:
            if first_error is not None:
                final_error.__context__ = first_error
            raise candidate.cause from final_error
    raise InventoryAdmissionError(
        "%s; policy drift guard recorded: episode_id=%s, event_id=%s, "
        "guard_epoch=%s"
        % (
            candidate.cause,
            result.get("episode_id"),
            result.get("event_id"),
            result.get("guard_epoch"),
        )
    ) from candidate.cause


def admit_inventory(root: Path, *, bootstrap_id: str) -> InventoryAdmission:
    """Admit a terminal current policy and return its immutable scope projection."""

    canonical = _canonical_root(root)
    if not isinstance(bootstrap_id, str) or not bootstrap_id:
        raise InventoryAdmissionError("bootstrap_id is required")
    try:
        with _shared_control_locks(canonical):
            try:
                control.verify_complete_bootstrap(
                    canonical,
                    bootstrap_id=bootstrap_id,
                )
            except control.ControlBootstrapError as exc:
                raise InventoryAdmissionError(
                    "control bootstrap is not structurally COMPLETE"
                ) from exc

            observation = _open_registry(canonical)
            connection: Optional[sqlite3.Connection] = None
            try:
                connection, ledger_identity = _connect_readonly_ledger(canonical)
                _require_lane_and_guard_clear(connection)
                head = _read_unbound_head(connection)
                compiled: Optional[policy.CompiledPolicy] = None
                try:
                    compiled = policy.compile_policy(
                        observation.raw,
                        str(canonical),
                    )
                    if (
                        head["full_hash"] != compiled.full_hash
                        or head["writer_control_hash"] != compiled.writer_hash
                        or head["foundation_hash"] != compiled.foundation_hash
                    ):
                        raise InventoryAdmissionError(
                            "policy head does not match current registry"
                        )
                    _verify_terminal_source(
                        connection,
                        canonical,
                        bootstrap_id,
                        observation.raw,
                        compiled,
                        head,
                    )
                except (
                    InventoryAdmissionError,
                    policy.PolicyError,
                    policy_authority.PolicyAuthorityError,
                ) as exc:
                    raise _drift_candidate(
                        exc,
                        observation=observation,
                        root=canonical,
                        compiled=compiled,
                        head=head,
                    ) from exc
                scope = compile_inventory_scope(compiled, str(canonical))
                approved = _authority_ref(compiled, head)
                try:
                    observation.verify_unchanged()
                except _StableRegistryMismatch as exc:
                    raise _drift_candidate(
                        exc,
                        observation=observation,
                        root=canonical,
                        compiled=compiled,
                        head=head,
                    ) from exc
                _verify_ledger_identity(canonical, ledger_identity)
                return InventoryAdmission(approved, scope, scope.scope_hash)
            finally:
                if connection is not None:
                    connection.close()
                observation.close()
    except _PolicyDriftCandidate as candidate:
        _raise_after_durable_drift_observation(
            canonical,
            candidate,
            observed_by="inventory-admission",
        )
        raise AssertionError("drift observation helper must raise")


def _verify_binding_only(
    connection: sqlite3.Connection,
    root: Path,
    bootstrap_id: str,
    registry_raw: bytes,
    compiled: policy.CompiledPolicy,
    approved_policy: ApprovedPolicyRef,
) -> sqlite3.Row:
    _require_lane_and_guard_clear(connection)
    head = _read_head(connection, compiled)
    _verify_terminal_source(
        connection,
        root,
        bootstrap_id,
        registry_raw,
        compiled,
        head,
    )
    observed = _authority_ref(compiled, head)
    if observed != approved_policy:
        raise InventoryAdmissionError("approved policy binding is stale")
    return head


@contextmanager
def policy_equality_guard(
    root: Path,
    *,
    bootstrap_id: str,
    approved_policy: ApprovedPolicyRef,
) -> Iterator[PolicyReadLease]:
    """Hold exact current policy equality through one bounded content read."""

    if not isinstance(approved_policy, ApprovedPolicyRef):
        raise TypeError("approved_policy must be ApprovedPolicyRef")
    canonical = _canonical_root(root)
    try:
        with _shared_control_locks(canonical):
            try:
                control.verify_complete_bootstrap(
                    canonical,
                    bootstrap_id=bootstrap_id,
                )
            except control.ControlBootstrapError as exc:
                raise InventoryAdmissionError(
                    "control bootstrap is not structurally COMPLETE"
                ) from exc
            observation = _open_registry(canonical)
            try:
                connection, ledger_identity = _connect_readonly_ledger(canonical)
                try:
                    _require_lane_and_guard_clear(connection)
                    head = _read_unbound_head(connection)
                    compiled: Optional[policy.CompiledPolicy] = None
                    try:
                        compiled = policy.compile_policy(
                            observation.raw,
                            str(canonical),
                        )
                        head = _verify_binding_only(
                            connection,
                            canonical,
                            bootstrap_id,
                            observation.raw,
                            compiled,
                            approved_policy,
                        )
                    except (
                        InventoryAdmissionError,
                        policy.PolicyError,
                        policy_authority.PolicyAuthorityError,
                    ) as exc:
                        raise _drift_candidate(
                            exc,
                            observation=observation,
                            root=canonical,
                            compiled=compiled,
                            head=head,
                        ) from exc
                finally:
                    connection.close()
                try:
                    # Do not let an external lock-bypassing edit race the first
                    # content open after the initial equality query.
                    observation.verify_unchanged()
                except _StableRegistryMismatch as exc:
                    raise _drift_candidate(
                        exc,
                        observation=observation,
                        root=canonical,
                        compiled=compiled,
                        head=head,
                    ) from exc
                try:
                    yield PolicyReadLease(approved_policy, compiled)
                finally:
                    try:
                        observation.verify_unchanged()
                    except _StableRegistryMismatch as exc:
                        raise _drift_candidate(
                            exc,
                            observation=observation,
                            root=canonical,
                            compiled=compiled,
                            head=head,
                        ) from exc

                    # Use a fresh read transaction after the caller's content
                    # read so a non-cooperating SQLite writer cannot hide
                    # behind our original read snapshot.  This runs even if
                    # the reader raises.
                    final_connection, final_identity = _connect_readonly_ledger(
                        canonical
                    )
                    try:
                        try:
                            _verify_binding_only(
                                final_connection,
                                canonical,
                                bootstrap_id,
                                observation.raw,
                                compiled,
                                approved_policy,
                            )
                        except (
                            InventoryAdmissionError,
                            policy_authority.PolicyAuthorityError,
                        ) as exc:
                            raise _drift_candidate(
                                exc,
                                observation=observation,
                                root=canonical,
                                compiled=compiled,
                                head=head,
                            ) from exc
                    finally:
                        final_connection.close()
                    if final_identity != ledger_identity:
                        raise InventoryAdmissionError(
                            "curation ledger identity changed"
                        )
                    _verify_ledger_identity(canonical, ledger_identity)
            finally:
                observation.close()
    except _PolicyDriftCandidate as candidate:
        _raise_after_durable_drift_observation(
            canonical,
            candidate,
            observed_by="inventory-policy-equality-guard",
        )
        raise AssertionError("drift observation helper must raise")


__all__ = [
    "ApprovedPolicyRef",
    "InventoryAdmission",
    "InventoryAdmissionError",
    "InventoryScopeBinding",
    "InventoryScopeProjection",
    "PolicyReadLease",
    "SCOPE_PROJECTION_VERSION",
    "admit_inventory",
    "compile_inventory_scope",
    "policy_equality_guard",
]
