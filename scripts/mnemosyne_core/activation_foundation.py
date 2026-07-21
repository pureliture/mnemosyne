"""Pure policy material and exact SQLite genesis for Safe Librarian activation."""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from . import control, ledger_schema, policy
from .canonical_json import canonical_json_bytes, sha256_bytes


INITIAL_POLICY_MODE = "safe-librarian-initial-curation-v1"
ACTIVATION_V2_SOURCE_ID = "safe-librarian-activation-v2"
_ACTIVATION_ID = re.compile(r"act-[0-9a-f]{32}")
_HASH = re.compile(r"[0-9a-f]{64}")


class ActivationFoundationError(ValueError):
    """Fresh genesis input or exact readback is not safe to accept."""


class ExplicitCurationPolicyError(ValueError):
    """The base registry already owns an explicit Curation policy."""


@dataclass(frozen=True)
class InitialPolicyIdentity:
    """Exact base, overlay, effective source, and compiled policy hashes."""

    mode: str
    registry_input_sha256: str
    overlay_sha256: str
    effective_policy_source_sha256: str
    full_hash: str
    writer_control_hash: str
    foundation_hash: str

    def as_dict(self) -> dict[str, str]:
        return {
            "mode": self.mode,
            "registry_input_sha256": self.registry_input_sha256,
            "overlay_sha256": self.overlay_sha256,
            "effective_policy_source_sha256": self.effective_policy_source_sha256,
            "full_hash": self.full_hash,
            "writer_control_hash": self.writer_control_hash,
            "foundation_hash": self.foundation_hash,
        }


@dataclass(frozen=True)
class _InitialPolicyMaterial:
    """Immutable source bytes and compiled identity for an in-memory overlay."""

    raw_root: str
    registry_bytes: bytes
    overlay_bytes: bytes
    effective_policy_bytes: bytes
    normalized_policy_json: bytes
    identity: InitialPolicyIdentity


@dataclass(frozen=True)
class ActivationFoundationPlan:
    """Closed input plan for one fresh activation genesis."""

    activation_id: str
    raw_root: str
    registry_bytes: bytes
    overlay_bytes: bytes
    effective_policy_bytes: bytes
    initial_policy: InitialPolicyIdentity
    compiled_policy: policy.CompiledPolicy
    snapshot_id: str


@dataclass(frozen=True)
class ActivationFoundationReadback:
    """Exact logical state read from a fresh activation ledger."""

    activation_id: str
    initial_snapshot_id: str
    schema_migrations: tuple[tuple[int, str, str], ...]
    policy_snapshot: tuple[object, ...]
    policy_head: tuple[object, ...]
    policy_mutation_lane: tuple[object, ...]
    empty_table_counts: tuple[tuple[str, int], ...]
    policy_identity: InitialPolicyIdentity

    @property
    def canonical_value(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "kind": "SAFE_LIBRARIAN_ACTIVATION_FOUNDATION_READBACK",
            "activation_id": self.activation_id,
            "initial_snapshot_id": self.initial_snapshot_id,
            "schema_identity": {
                "control": {
                    "version": control.CONTROL_SCHEMA_VERSION,
                    "sha256": control.CONTROL_SCHEMA_SHA256,
                    "applied_by": self.activation_id,
                },
                "ledger": {
                    "version": ledger_schema.LEDGER_SCHEMA_VERSION,
                    "sha256": ledger_schema.LEDGER_SCHEMA_SHA256,
                    "applied_by": ACTIVATION_V2_SOURCE_ID,
                },
            },
            "schema_migrations": [list(row) for row in self.schema_migrations],
            "initial_policy": {
                "identity": self.policy_identity.as_dict(),
                "snapshot": list(self.policy_snapshot),
                "head": list(self.policy_head),
                "mutation_lane": list(self.policy_mutation_lane),
            },
            "empty_table_counts": dict(self.empty_table_counts),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.canonical_value)

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.canonical_bytes)

    @property
    def logical_readback_sha256(self) -> str:
        """Compatibility spelling for receipt builders."""

        return self.sha256


def _build_initial_policy_material(
    registry_bytes: bytes,
    raw_root: str,
) -> _InitialPolicyMaterial:
    """Build the canonical additive curation policy without writing it."""

    if not isinstance(registry_bytes, bytes):
        raise TypeError("registry_bytes must be bytes")
    registry = policy.parse_strict_yaml(registry_bytes)
    if "curation" in registry:
        raise ExplicitCurationPolicyError(
            "registry already has an explicit curation section"
        )
    overlay = policy.build_initial_curation_block(raw_root)
    effective_source = policy.build_additive_curation_postimage(
        registry_bytes,
        raw_root,
    )
    compiled = policy.compile_policy(effective_source, raw_root)
    identity = InitialPolicyIdentity(
        mode=INITIAL_POLICY_MODE,
        registry_input_sha256=sha256_bytes(registry_bytes),
        overlay_sha256=sha256_bytes(overlay),
        effective_policy_source_sha256=sha256_bytes(effective_source),
        full_hash=compiled.full_hash,
        writer_control_hash=compiled.writer_hash,
        foundation_hash=compiled.foundation_hash,
    )
    return _InitialPolicyMaterial(
        raw_root=raw_root,
        registry_bytes=registry_bytes,
        overlay_bytes=overlay,
        effective_policy_bytes=effective_source,
        normalized_policy_json=compiled.full_json,
        identity=identity,
    )


def build_activation_foundation(
    registry_bytes: bytes,
    raw_root: str,
    activation_id: str,
) -> ActivationFoundationPlan:
    """Build the complete immutable input plan for a fresh genesis."""

    activation_id = _require_activation_id(activation_id)
    material = _build_initial_policy_material(registry_bytes, raw_root)
    compiled = policy.compile_policy(material.effective_policy_bytes, raw_root)
    return ActivationFoundationPlan(
        activation_id=activation_id,
        raw_root=raw_root,
        registry_bytes=material.registry_bytes,
        overlay_bytes=material.overlay_bytes,
        effective_policy_bytes=material.effective_policy_bytes,
        initial_policy=material.identity,
        compiled_policy=compiled,
        snapshot_id=initial_snapshot_id(material.identity.full_hash),
    )


def compile_initial_policy(
    registry_bytes: bytes,
    raw_root: str,
) -> InitialPolicyIdentity:
    """Compile the canonical additive curation policy without writing it."""

    return _build_initial_policy_material(registry_bytes, raw_root).identity


def initial_snapshot_id(full_hash: str) -> str:
    """Derive the only allowed generation-one snapshot identifier."""

    if not isinstance(full_hash, str) or _HASH.fullmatch(full_hash) is None:
        raise ActivationFoundationError("full_hash is invalid")
    return "policy-00000001-" + full_hash[:24]


def _require_activation_id(activation_id: str) -> str:
    if (
        not isinstance(activation_id, str)
        or _ACTIVATION_ID.fullmatch(activation_id) is None
    ):
        raise ActivationFoundationError("activation_id is invalid")
    return activation_id


def _material_from_plan(plan: ActivationFoundationPlan) -> _InitialPolicyMaterial:
    return _InitialPolicyMaterial(
        raw_root=plan.raw_root,
        registry_bytes=plan.registry_bytes,
        overlay_bytes=plan.overlay_bytes,
        effective_policy_bytes=plan.effective_policy_bytes,
        normalized_policy_json=plan.compiled_policy.full_json,
        identity=plan.initial_policy,
    )


def _require_plan(plan: ActivationFoundationPlan) -> ActivationFoundationPlan:
    if not isinstance(plan, ActivationFoundationPlan):
        raise ActivationFoundationError("activation foundation plan is invalid")
    try:
        expected = build_activation_foundation(
            plan.registry_bytes,
            plan.raw_root,
            plan.activation_id,
        )
    except (
        ExplicitCurationPolicyError,
        policy.PolicyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ActivationFoundationError(
            "activation foundation plan is invalid"
        ) from exc
    if plan != expected:
        raise ActivationFoundationError(
            "activation foundation plan identity is invalid"
        )
    return plan


def _require_connection(connection: sqlite3.Connection) -> sqlite3.Connection:
    if not isinstance(connection, sqlite3.Connection):
        raise ActivationFoundationError("SQLite connection is required")
    return connection


def _require_database_modes(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
        raise ActivationFoundationError("SQLite foreign keys are disabled")
    if connection.execute("PRAGMA synchronous").fetchone() != (2,):
        raise ActivationFoundationError("SQLite synchronous mode is not FULL")
    journal_row = connection.execute("PRAGMA journal_mode").fetchone()
    if journal_row is None or str(journal_row[0]).upper() != "DELETE":
        raise ActivationFoundationError("SQLite journal mode is not DELETE")


def _query_exact_rows(
    connection: sqlite3.Connection,
    *,
    activation_id: str,
    policy_material: _InitialPolicyMaterial,
) -> ActivationFoundationReadback:
    try:
        ledger_schema.verify_v2_schema(connection)
    except ledger_schema.LedgerSchemaError as exc:
        raise ActivationFoundationError(str(exc)) from exc

    identity = policy_material.identity
    snapshot_id = initial_snapshot_id(identity.full_hash)
    migrations = tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT version, schema_sha256, applied_by_bootstrap_id "
            "FROM schema_migrations ORDER BY version"
        ).fetchall()
    )
    expected_migrations = (
        (
            control.CONTROL_SCHEMA_VERSION,
            control.CONTROL_SCHEMA_SHA256,
            activation_id,
        ),
        (
            ledger_schema.LEDGER_SCHEMA_VERSION,
            ledger_schema.LEDGER_SCHEMA_SHA256,
            ACTIVATION_V2_SOURCE_ID,
        ),
    )
    if migrations != expected_migrations:
        raise ActivationFoundationError("activation schema binding is invalid")

    snapshots = connection.execute(
        "SELECT snapshot_id, full_hash, writer_control_hash, foundation_hash, "
        "normalized_policy_json, source_kind, source_run_id, source_state "
        "FROM policy_snapshots"
    ).fetchall()
    expected_snapshot = (
        snapshot_id,
        identity.full_hash,
        identity.writer_control_hash,
        identity.foundation_hash,
        policy_material.normalized_policy_json,
        "INITIAL",
        activation_id,
        "TERMINAL",
    )
    if [tuple(row) for row in snapshots] != [expected_snapshot]:
        raise ActivationFoundationError("initial policy snapshot is invalid")

    heads = connection.execute(
        "SELECT id, generation, full_hash, writer_control_hash, foundation_hash, "
        "source_kind, source_run_id, guard_epoch FROM policy_head"
    ).fetchall()
    expected_head = (
        1,
        1,
        identity.full_hash,
        identity.writer_control_hash,
        identity.foundation_hash,
        "INITIAL",
        activation_id,
        0,
    )
    if [tuple(row) for row in heads] != [expected_head]:
        raise ActivationFoundationError("initial policy head is invalid")

    lanes = connection.execute(
        "SELECT id, generation, state, owner_kind, owner_proposal_id, "
        "owner_approval_id, owner_run_id, owner_process_id "
        "FROM policy_mutation_lane"
    ).fetchall()
    expected_lane = (1, 0, "IDLE", None, None, None, None, None)
    if [tuple(row) for row in lanes] != [expected_lane]:
        raise ActivationFoundationError("initial policy mutation lane is invalid")

    populated_tables = {
        "schema_migrations",
        "policy_snapshots",
        "policy_head",
        "policy_mutation_lane",
    }
    empty_counts = tuple(
        (
            table,
            int(connection.execute('SELECT COUNT(*) FROM "%s"' % table).fetchone()[0]),
        )
        for table in sorted(
            set(control.CONTROL_SCHEMA_TABLES + ledger_schema.LEDGER_SCHEMA_TABLES)
            - populated_tables
        )
    )
    if any(count != 0 for _table, count in empty_counts):
        raise ActivationFoundationError("non-foundation ledger rows are present")

    return ActivationFoundationReadback(
        activation_id=activation_id,
        initial_snapshot_id=snapshot_id,
        schema_migrations=migrations,
        policy_snapshot=(
            snapshot_id,
            identity.full_hash,
            identity.writer_control_hash,
            identity.foundation_hash,
            sha256_bytes(policy_material.normalized_policy_json),
            "INITIAL",
            activation_id,
            "TERMINAL",
        ),
        policy_head=expected_head,
        policy_mutation_lane=expected_lane,
        empty_table_counts=empty_counts,
        policy_identity=identity,
    )


def _verify_activation_connection(
    connection: sqlite3.Connection,
    plan: ActivationFoundationPlan,
) -> ActivationFoundationReadback:
    """Read and verify the exact activation ledger without changing it."""

    connection = _require_connection(connection)
    policy_material = _material_from_plan(plan)
    try:
        _require_database_modes(connection)
        return _query_exact_rows(
            connection,
            activation_id=plan.activation_id,
            policy_material=policy_material,
        )
    except ActivationFoundationError:
        raise
    except sqlite3.Error as exc:
        raise ActivationFoundationError("activation ledger is unreadable") from exc


def _initialize_activation_connection(
    connection: sqlite3.Connection,
    plan: ActivationFoundationPlan,
) -> ActivationFoundationReadback:
    """Create one exact v1+v2 genesis in one ``BEGIN IMMEDIATE`` transaction."""

    connection = _require_connection(connection)
    activation_id = plan.activation_id
    policy_material = _material_from_plan(plan)
    if connection.in_transaction:
        raise ActivationFoundationError("genesis requires transaction ownership")

    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        journal_row = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        if journal_row is None or str(journal_row[0]).upper() != "DELETE":
            raise ActivationFoundationError("SQLite journal mode cannot be DELETE")
        existing_objects = connection.execute(
            "SELECT type, name FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        if existing_objects:
            raise ActivationFoundationError("activation ledger is not empty")

        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in control.CONTROL_SCHEMA_STATEMENTS:
                connection.execute(statement)
            for statement in control.CONTROL_SCHEMA_INDEX_STATEMENTS:
                connection.execute(statement)
            for statement in control.CONTROL_SCHEMA_TRIGGER_STATEMENTS:
                connection.execute(statement)
            for statement in ledger_schema.LEDGER_SCHEMA_STATEMENTS:
                connection.execute(statement)
            for statement in ledger_schema.LEDGER_SCHEMA_INDEX_STATEMENTS:
                connection.execute(statement)
            for statement in ledger_schema.LEDGER_SCHEMA_TRIGGER_STATEMENTS:
                connection.execute(statement)

            identity = policy_material.identity
            connection.executemany(
                "INSERT INTO schema_migrations "
                "(version, schema_sha256, applied_by_bootstrap_id) VALUES (?, ?, ?)",
                (
                    (
                        control.CONTROL_SCHEMA_VERSION,
                        control.CONTROL_SCHEMA_SHA256,
                        activation_id,
                    ),
                    (
                        ledger_schema.LEDGER_SCHEMA_VERSION,
                        ledger_schema.LEDGER_SCHEMA_SHA256,
                        ACTIVATION_V2_SOURCE_ID,
                    ),
                ),
            )
            connection.execute(
                "INSERT INTO policy_snapshots "
                "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                "normalized_policy_json, source_kind, source_run_id, source_state) "
                "VALUES (?, ?, ?, ?, ?, 'INITIAL', ?, 'TERMINAL')",
                (
                    initial_snapshot_id(identity.full_hash),
                    identity.full_hash,
                    identity.writer_control_hash,
                    identity.foundation_hash,
                    policy_material.normalized_policy_json,
                    activation_id,
                ),
            )
            connection.execute(
                "INSERT INTO policy_head "
                "(id, generation, full_hash, writer_control_hash, foundation_hash, "
                "source_kind, source_run_id, guard_epoch) "
                "VALUES (1, 1, ?, ?, ?, 'INITIAL', ?, 0)",
                (
                    identity.full_hash,
                    identity.writer_control_hash,
                    identity.foundation_hash,
                    activation_id,
                ),
            )
            connection.execute(
                "INSERT INTO policy_mutation_lane "
                "(id, generation, state, owner_kind, owner_proposal_id, "
                "owner_approval_id, owner_run_id, owner_process_id) "
                "VALUES (1, 0, 'IDLE', NULL, NULL, NULL, NULL, NULL)"
            )
            _require_database_modes(connection)
            readback = _query_exact_rows(
                connection,
                activation_id=activation_id,
                policy_material=policy_material,
            )
            connection.execute("COMMIT")
            return readback
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    except ActivationFoundationError:
        raise
    except sqlite3.Error as exc:
        raise ActivationFoundationError("activation genesis failed") from exc


def _require_ledger_file(
    path: str | os.PathLike[str],
    *,
    require_empty: bool,
) -> tuple[str, os.stat_result]:
    try:
        value = os.fspath(path)
    except TypeError as exc:
        raise ActivationFoundationError("ledger path is invalid") from exc
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or not os.path.isabs(value)
        or value.startswith("//")
        or os.path.normpath(value) != value
    ):
        raise ActivationFoundationError("ledger path must be canonical and absolute")
    try:
        info = os.lstat(value)
    except OSError as exc:
        raise ActivationFoundationError("ledger file is unavailable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ActivationFoundationError("ledger file must be regular")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ActivationFoundationError("ledger file mode must be 0600")
    if info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ActivationFoundationError("ledger file identity is unsafe")
    if require_empty and info.st_size != 0:
        raise ActivationFoundationError("ledger file must be empty")
    return value, info


def _require_same_ledger_file(path: str, expected: os.stat_result) -> None:
    _value, observed = _require_ledger_file(path, require_empty=False)
    if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
        raise ActivationFoundationError("ledger file identity changed")


def _connect_existing_ledger(path: str, *, mode: str) -> sqlite3.Connection:
    uri = "file:%s?mode=%s" % (quote(path, safe="/"), mode)
    try:
        return sqlite3.connect(uri, uri=True, isolation_level=None)
    except sqlite3.Error as exc:
        raise ActivationFoundationError("ledger file cannot be opened") from exc


def initialize_activation_ledger(
    path: str | os.PathLike[str],
    plan: ActivationFoundationPlan,
) -> ActivationFoundationReadback:
    """Initialize a caller-precreated, empty, exact ``0600`` ledger file.

    The caller owns anchored parent-directory access.  This function never
    creates the path and rejects a symlink, hard link, wrong owner, or changed
    final-component identity.
    """

    plan = _require_plan(plan)
    exact_path, before = _require_ledger_file(path, require_empty=True)
    connection = _connect_existing_ledger(exact_path, mode="rw")
    try:
        _require_same_ledger_file(exact_path, before)
        readback = _initialize_activation_connection(connection, plan)
    finally:
        connection.close()
    _require_same_ledger_file(exact_path, before)
    if os.path.lexists(exact_path + "-journal"):
        raise ActivationFoundationError("SQLite journal remains after genesis")
    return readback


def verify_activation_ledger(
    connection_or_path: sqlite3.Connection | str | os.PathLike[str],
    plan: ActivationFoundationPlan,
) -> ActivationFoundationReadback:
    """Verify exact genesis through an existing connection or read-only path."""

    plan = _require_plan(plan)
    if isinstance(connection_or_path, sqlite3.Connection):
        return _verify_activation_connection(connection_or_path, plan)

    exact_path, before = _require_ledger_file(
        connection_or_path,
        require_empty=False,
    )
    connection = _connect_existing_ledger(exact_path, mode="ro")
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        _require_same_ledger_file(exact_path, before)
        return _verify_activation_connection(connection, plan)
    finally:
        connection.close()
        _require_same_ledger_file(exact_path, before)


__all__ = [
    "ACTIVATION_V2_SOURCE_ID",
    "INITIAL_POLICY_MODE",
    "ActivationFoundationError",
    "ActivationFoundationPlan",
    "ActivationFoundationReadback",
    "ExplicitCurationPolicyError",
    "InitialPolicyIdentity",
    "build_activation_foundation",
    "compile_initial_policy",
    "initialize_activation_ledger",
    "initial_snapshot_id",
    "verify_activation_ledger",
]
