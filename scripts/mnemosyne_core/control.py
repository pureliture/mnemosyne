"""Crash-safe control-ledger bootstrap primitives for Mnemosyne curation.

The compatibility facade is intentionally not imported here.  This module owns
its filesystem observations and accepts only values (actors and exact preview
bindings) from callers.  A control-root rename whose effect cannot be safely
compensated propagates ``ManualRecoveryRequired`` unchanged so the facade can
publish its guarded manual-recovery blocker without claiming no effect.
"""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from .canonical_json import canonical_json_bytes, sha256_bytes
from . import safety


CONTROL_SCHEMA_VERSION = 1
BUSY_TIMEOUT_MS = 5_000
STAGING_JOURNAL_MODE = "DELETE"
TERMINAL_JOURNAL_MODE = "WAL"
BOOTSTRAP_PREFIX = ".incomplete-curation-bootstrap-"

CONTROL_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY CHECK (version > 0),
        schema_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(schema_sha256) = 64 AND schema_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        applied_by_bootstrap_id TEXT NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE control_bootstraps (
        bootstrap_id TEXT PRIMARY KEY,
        preview_id TEXT NOT NULL UNIQUE,
        preview_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(preview_sha256) = 64 AND preview_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
requested_by TEXT NOT NULL CHECK (
length(trim(requested_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')) > 0
AND requested_by = trim(requested_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')
),
approved_by TEXT NOT NULL CHECK (
length(trim(approved_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')) > 0
AND approved_by = trim(approved_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')
),
        manifest_path TEXT NOT NULL UNIQUE,
        manifest_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        schema_version INTEGER NOT NULL,
        schema_sha256 TEXT NOT NULL CHECK (
            length(schema_sha256) = 64 AND schema_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        registry_path TEXT NOT NULL,
        registry_sha256 TEXT NOT NULL CHECK (
            length(registry_sha256) = 64 AND registry_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        registry_device INTEGER NOT NULL,
        registry_inode INTEGER NOT NULL,
        placement_lock_path TEXT NOT NULL,
        placement_lock_sha256 TEXT NOT NULL CHECK (
            length(placement_lock_sha256) = 64
            AND placement_lock_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        placement_lock_device INTEGER NOT NULL,
        placement_lock_inode INTEGER NOT NULL,
        completed_migration_id TEXT NOT NULL,
        completed_result_path TEXT NOT NULL,
        completed_result_sha256 TEXT NOT NULL CHECK (
            length(completed_result_sha256) = 64
            AND completed_result_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        staging_path TEXT NOT NULL UNIQUE,
        final_path TEXT NOT NULL UNIQUE,
        ledger_path TEXT NOT NULL UNIQUE,
        ledger_device INTEGER NOT NULL,
        ledger_inode INTEGER NOT NULL,
        ledger_lock_path TEXT NOT NULL UNIQUE,
        ledger_lock_device INTEGER NOT NULL,
        ledger_lock_inode INTEGER NOT NULL,
        staging_journal_mode TEXT NOT NULL CHECK (staging_journal_mode = 'DELETE'),
        terminal_journal_mode TEXT NOT NULL CHECK (terminal_journal_mode = 'WAL'),
        wal_checkpoint_status TEXT CHECK (
            wal_checkpoint_status IS NULL OR wal_checkpoint_status = 'FULL'
        ),
        logical_readback_sha256 TEXT CHECK (
            logical_readback_sha256 IS NULL OR (
                length(logical_readback_sha256) = 64
                AND logical_readback_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        state TEXT NOT NULL CHECK (
            state IN ('PREPARED', 'FILES_PUBLISHED', 'WAL_READY', 'COMPLETE', 'BLOCKED')
        ),
        CHECK (
            (
                state IN ('PREPARED', 'FILES_PUBLISHED')
                AND wal_checkpoint_status IS NULL
                AND logical_readback_sha256 IS NULL
            )
            OR (
                state IN ('WAL_READY', 'COMPLETE')
                AND wal_checkpoint_status IS NOT NULL
                AND wal_checkpoint_status = 'FULL'
                AND logical_readback_sha256 IS NOT NULL
            )
            OR state = 'BLOCKED'
        )
    )
    """,
    """
    CREATE TABLE policy_snapshots (
        snapshot_id TEXT PRIMARY KEY,
        full_hash TEXT NOT NULL CHECK (
            length(full_hash) = 64 AND full_hash NOT GLOB '*[^0-9a-f]*'
        ),
        writer_control_hash TEXT NOT NULL CHECK (
            length(writer_control_hash) = 64
            AND writer_control_hash NOT GLOB '*[^0-9a-f]*'
        ),
        foundation_hash TEXT NOT NULL CHECK (
            length(foundation_hash) = 64 AND foundation_hash NOT GLOB '*[^0-9a-f]*'
        ),
        normalized_policy_json BLOB NOT NULL,
        source_kind TEXT NOT NULL CHECK (source_kind IN ('INITIAL', 'EDIT', 'RECONCILE', 'CUTOVER')),
        source_run_id TEXT NOT NULL UNIQUE,
        source_state TEXT NOT NULL CHECK (source_state = 'TERMINAL'),
        UNIQUE (full_hash, source_kind, source_run_id)
    )
    """,
    """
    CREATE TABLE policy_head (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        generation INTEGER NOT NULL CHECK (generation > 0),
        full_hash TEXT NOT NULL CHECK (
            length(full_hash) = 64 AND full_hash NOT GLOB '*[^0-9a-f]*'
        ),
        writer_control_hash TEXT NOT NULL CHECK (
            length(writer_control_hash) = 64
            AND writer_control_hash NOT GLOB '*[^0-9a-f]*'
        ),
        foundation_hash TEXT NOT NULL CHECK (
            length(foundation_hash) = 64 AND foundation_hash NOT GLOB '*[^0-9a-f]*'
        ),
        source_kind TEXT NOT NULL CHECK (source_kind IN ('INITIAL', 'EDIT', 'RECONCILE', 'CUTOVER')),
        source_run_id TEXT NOT NULL UNIQUE,
        guard_epoch INTEGER NOT NULL CHECK (guard_epoch >= 0),
        FOREIGN KEY (full_hash, source_kind, source_run_id)
            REFERENCES policy_snapshots(full_hash, source_kind, source_run_id)
    )
    """,
    """
    CREATE TABLE policy_guard_episodes (
        episode_id TEXT PRIMARY KEY,
        head_generation INTEGER NOT NULL CHECK (head_generation > 0),
        head_full_hash TEXT NOT NULL CHECK (
            length(head_full_hash) = 64 AND head_full_hash NOT GLOB '*[^0-9a-f]*'
        ),
        guard_epoch_before INTEGER NOT NULL CHECK (guard_epoch_before >= 0),
        guard_epoch_after INTEGER NOT NULL CHECK (guard_epoch_after = guard_epoch_before + 1),
        first_event_id TEXT NOT NULL UNIQUE,
        current_observed_identity_json BLOB NOT NULL,
        root_execution_id TEXT,
        status TEXT NOT NULL CHECK (
            status IN ('OPEN', 'CLEARED_EQUALITY', 'CLEARED_RECONCILED')
        )
    )
    """,
    """
    CREATE TABLE policy_guard_events (
        event_id TEXT PRIMARY KEY,
        episode_id TEXT NOT NULL REFERENCES policy_guard_episodes(episode_id),
        kind TEXT NOT NULL CHECK (
            kind IN ('FIRST_DRIFT', 'OBSERVATION', 'DRIFT_CLEARED_EQUALITY', 'DRIFT_CLEARED_RECONCILED')
        ),
        head_generation INTEGER NOT NULL CHECK (head_generation > 0),
        guard_epoch INTEGER NOT NULL CHECK (guard_epoch >= 0),
        observation_path TEXT NOT NULL,
        observation_sha256 TEXT NOT NULL CHECK (
            length(observation_sha256) = 64
            AND observation_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        result_path TEXT NOT NULL,
        result_sha256 TEXT CHECK (
            result_sha256 IS NULL OR (
                length(result_sha256) = 64 AND result_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        state TEXT NOT NULL CHECK (state IN ('GUARD_BUMPED', 'PREPARED', 'COMPLETE', 'BLOCKED'))
    )
    """,
    """
    CREATE TABLE policy_mutation_lane (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        generation INTEGER NOT NULL CHECK (generation >= 0),
        state TEXT NOT NULL CHECK (state IN ('IDLE', 'RESERVED', 'ACTIVE', 'BLOCKED_RECOVERY')),
        owner_kind TEXT,
        owner_proposal_id TEXT,
        owner_approval_id TEXT,
        owner_run_id TEXT,
        owner_process_id TEXT,
        CHECK (
            (state = 'IDLE' AND owner_kind IS NULL AND owner_proposal_id IS NULL
             AND owner_approval_id IS NULL AND owner_run_id IS NULL AND owner_process_id IS NULL)
            OR (
                state = 'RESERVED'
                AND owner_kind IS NOT NULL
                AND owner_proposal_id IS NOT NULL
                AND owner_approval_id IS NOT NULL
                AND length(trim(owner_kind)) > 0
                AND length(trim(owner_proposal_id)) > 0
                AND length(trim(owner_approval_id)) > 0
                AND owner_run_id IS NULL
                AND owner_process_id IS NULL
            )
            OR (
                state IN ('ACTIVE', 'BLOCKED_RECOVERY')
                AND owner_kind IS NOT NULL
                AND owner_proposal_id IS NOT NULL
                AND owner_approval_id IS NOT NULL
                AND owner_run_id IS NOT NULL
                AND owner_process_id IS NOT NULL
                AND length(trim(owner_kind)) > 0
                AND length(trim(owner_proposal_id)) > 0
                AND length(trim(owner_approval_id)) > 0
                AND length(trim(owner_run_id)) > 0
                AND length(trim(owner_process_id)) > 0
            )
        )
    )
    """,
    """
    CREATE TABLE policy_bootstrap_proposals (
        proposal_id TEXT PRIMARY KEY,
        proposal_generation INTEGER NOT NULL CHECK (proposal_generation > 0),
        base_hash TEXT NOT NULL CHECK (
            length(base_hash) = 64 AND base_hash NOT GLOB '*[^0-9a-f]*'
        ),
        semantic_hash TEXT NOT NULL CHECK (
            length(semantic_hash) = 64 AND semantic_hash NOT GLOB '*[^0-9a-f]*'
        ),
        expected_post_hash TEXT NOT NULL CHECK (
            length(expected_post_hash) = 64
            AND expected_post_hash NOT GLOB '*[^0-9a-f]*'
        ),
        payload_json BLOB NOT NULL,
        proposal_path TEXT NOT NULL UNIQUE,
        proposal_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(proposal_sha256) = 64 AND proposal_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
requested_by TEXT NOT NULL CHECK (
length(trim(requested_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')) > 0
AND requested_by = trim(requested_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')
),
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'PUBLISHED', 'BLOCKED')),
        UNIQUE (base_hash, semantic_hash, proposal_generation)
    )
    """,
    """
    CREATE TABLE policy_bootstrap_approvals (
        approval_id TEXT PRIMARY KEY,
        proposal_id TEXT NOT NULL REFERENCES policy_bootstrap_proposals(proposal_id),
        attempt INTEGER NOT NULL CHECK (attempt > 0),
approved_by TEXT NOT NULL CHECK (
length(trim(approved_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')) > 0
AND approved_by = trim(approved_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')
),
        export_path TEXT NOT NULL UNIQUE,
        export_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(export_sha256) = 64 AND export_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (
            state IN ('PREPARED', 'PUBLISHED', 'CLAIMED', 'CONSUMED', 'CANCELLED',
                      'BLOCKED', 'COMPENSATED_NONREUSABLE')
        ),
        UNIQUE (proposal_id, attempt)
    )
    """,
    """
    CREATE TABLE policy_bootstrap_runs (
        run_id TEXT PRIMARY KEY,
        approval_id TEXT NOT NULL UNIQUE REFERENCES policy_bootstrap_approvals(approval_id),
        process_instance_id TEXT NOT NULL UNIQUE,
executed_by TEXT NOT NULL CHECK (
length(trim(executed_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')) > 0
AND executed_by = trim(executed_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')
),
        result_path TEXT NOT NULL UNIQUE,
        result_sha256 TEXT CHECK (
            result_sha256 IS NULL OR (
                length(result_sha256) = 64 AND result_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        expected_post_hash TEXT NOT NULL CHECK (
            length(expected_post_hash) = 64
            AND expected_post_hash NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (
            state IN ('CLAIMED', 'POLICY_PUBLISHED', 'ACTIVE', 'COMPENSATED', 'BLOCKED_RECOVERY')
        )
    )
    """,
    """
    CREATE TABLE policy_change_proposals (
        proposal_id TEXT PRIMARY KEY,
        mode TEXT NOT NULL CHECK (mode IN ('EDIT', 'RECONCILE')),
        base_generation INTEGER NOT NULL CHECK (base_generation > 0),
        base_hash TEXT NOT NULL CHECK (
            length(base_hash) = 64 AND base_hash NOT GLOB '*[^0-9a-f]*'
        ),
        semantic_hash TEXT NOT NULL CHECK (
            length(semantic_hash) = 64 AND semantic_hash NOT GLOB '*[^0-9a-f]*'
        ),
        proposal_generation INTEGER NOT NULL CHECK (proposal_generation > 0),
        payload_json BLOB NOT NULL,
        proposal_path TEXT NOT NULL UNIQUE,
        proposal_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(proposal_sha256) = 64 AND proposal_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
requested_by TEXT NOT NULL CHECK (
length(trim(requested_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')) > 0
AND requested_by = trim(requested_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')
),
        state TEXT NOT NULL CHECK (state IN ('PREPARED', 'PUBLISHED', 'BLOCKED')),
        UNIQUE (mode, base_generation, semantic_hash, proposal_generation)
    )
    """,
    """
    CREATE TABLE policy_change_approvals (
        approval_id TEXT PRIMARY KEY,
        proposal_id TEXT NOT NULL REFERENCES policy_change_proposals(proposal_id),
        mode TEXT NOT NULL CHECK (mode IN ('EDIT', 'RECONCILE')),
        attempt INTEGER NOT NULL CHECK (attempt > 0),
approved_by TEXT NOT NULL CHECK (
length(trim(approved_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')) > 0
AND approved_by = trim(approved_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')
),
        export_path TEXT NOT NULL UNIQUE,
        export_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(export_sha256) = 64 AND export_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (
            state IN ('PREPARED', 'PUBLISHED', 'CLAIMED', 'CONSUMED', 'CANCELLED',
                      'BLOCKED', 'COMPENSATED_NONREUSABLE')
        ),
        UNIQUE (proposal_id, attempt)
    )
    """,
    """
    CREATE TABLE policy_change_runs (
        run_id TEXT PRIMARY KEY,
        approval_id TEXT NOT NULL UNIQUE REFERENCES policy_change_approvals(approval_id),
        mode TEXT NOT NULL CHECK (mode IN ('EDIT', 'RECONCILE')),
        process_instance_id TEXT NOT NULL UNIQUE,
executed_by TEXT NOT NULL CHECK (
length(trim(executed_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')) > 0
AND executed_by = trim(executed_by, char(9) || char(10) || char(11) || char(12) || char(13) || ' ')
),
        result_path TEXT NOT NULL UNIQUE,
        result_sha256 TEXT CHECK (
            result_sha256 IS NULL OR (
                length(result_sha256) = 64 AND result_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
        state TEXT NOT NULL CHECK (
            state IN ('CLAIMED', 'POLICY_PUBLISHED', 'NO_YAML_WRITE_VERIFIED',
                      'ACTIVE', 'COMPENSATED', 'BLOCKED_RECOVERY')
        )
    )
    """,
)
CONTROL_SCHEMA_TABLES = tuple(
    statement.split("CREATE TABLE ", 1)[1].split(" ", 1)[0].strip()
    for statement in CONTROL_SCHEMA_STATEMENTS
)
CONTROL_SCHEMA_INDEX_STATEMENTS = (
    """
    CREATE UNIQUE INDEX policy_guard_one_open_per_head
    ON policy_guard_episodes (head_generation, head_full_hash)
    WHERE status = 'OPEN'
    """,
    """
    CREATE UNIQUE INDEX policy_guard_one_nonterminal_event_per_episode
    ON policy_guard_events (episode_id)
    WHERE state IN ('GUARD_BUMPED', 'PREPARED')
    """,
    """
    CREATE UNIQUE INDEX policy_bootstrap_one_nonterminal_approval
    ON policy_bootstrap_approvals (proposal_id)
    WHERE state IN ('PREPARED', 'PUBLISHED', 'CLAIMED')
    """,
    """
    CREATE UNIQUE INDEX policy_change_one_nonterminal_approval
    ON policy_change_approvals (proposal_id)
    WHERE state IN ('PREPARED', 'PUBLISHED', 'CLAIMED')
    """,
)
CONTROL_SCHEMA_INDEXES = tuple(
    statement.split("CREATE UNIQUE INDEX ", 1)[1].split()[0].strip()
    for statement in CONTROL_SCHEMA_INDEX_STATEMENTS
)
CONTROL_SCHEMA_TRIGGER_STATEMENTS = (
    """
    CREATE TRIGGER policy_snapshots_immutable_update
    BEFORE UPDATE ON policy_snapshots
    BEGIN SELECT RAISE(ABORT, 'immutable policy_snapshots'); END
    """,
    """
    CREATE TRIGGER policy_snapshots_immutable_delete
    BEFORE DELETE ON policy_snapshots
    BEGIN SELECT RAISE(ABORT, 'immutable policy_snapshots'); END
    """,
    """
    CREATE TRIGGER policy_bootstrap_proposals_immutable_update
    BEFORE UPDATE ON policy_bootstrap_proposals
    WHEN NEW.proposal_id IS NOT OLD.proposal_id
      OR NEW.proposal_generation IS NOT OLD.proposal_generation
      OR NEW.base_hash IS NOT OLD.base_hash
      OR NEW.semantic_hash IS NOT OLD.semantic_hash
      OR NEW.expected_post_hash IS NOT OLD.expected_post_hash
      OR NEW.payload_json IS NOT OLD.payload_json
      OR NEW.proposal_path IS NOT OLD.proposal_path
      OR NEW.proposal_sha256 IS NOT OLD.proposal_sha256
      OR NEW.requested_by IS NOT OLD.requested_by
      OR NOT (
          NEW.state = OLD.state
          OR (OLD.state = 'PREPARED' AND NEW.state IN ('PUBLISHED', 'BLOCKED'))
      )
    BEGIN SELECT RAISE(ABORT, 'immutable policy_bootstrap_proposals'); END
    """,
    """
    CREATE TRIGGER policy_bootstrap_proposals_immutable_delete
    BEFORE DELETE ON policy_bootstrap_proposals
    BEGIN SELECT RAISE(ABORT, 'immutable policy_bootstrap_proposals'); END
    """,
    """
    CREATE TRIGGER policy_change_proposals_immutable_update
    BEFORE UPDATE ON policy_change_proposals
    WHEN NEW.proposal_id IS NOT OLD.proposal_id
      OR NEW.mode IS NOT OLD.mode
      OR NEW.base_generation IS NOT OLD.base_generation
      OR NEW.base_hash IS NOT OLD.base_hash
      OR NEW.semantic_hash IS NOT OLD.semantic_hash
      OR NEW.proposal_generation IS NOT OLD.proposal_generation
      OR NEW.payload_json IS NOT OLD.payload_json
      OR NEW.proposal_path IS NOT OLD.proposal_path
      OR NEW.proposal_sha256 IS NOT OLD.proposal_sha256
      OR NEW.requested_by IS NOT OLD.requested_by
      OR NOT (
          NEW.state = OLD.state
          OR (OLD.state = 'PREPARED' AND NEW.state IN ('PUBLISHED', 'BLOCKED'))
      )
    BEGIN SELECT RAISE(ABORT, 'immutable policy_change_proposals'); END
    """,
    """
    CREATE TRIGGER policy_change_proposals_immutable_delete
    BEFORE DELETE ON policy_change_proposals
    BEGIN SELECT RAISE(ABORT, 'immutable policy_change_proposals'); END
    """,
)
CONTROL_SCHEMA_TRIGGERS = tuple(
    statement.split("CREATE TRIGGER ", 1)[1].split()[0].strip()
    for statement in CONTROL_SCHEMA_TRIGGER_STATEMENTS
)
CONTROL_SCHEMA_SHA256 = sha256_bytes(
    canonical_json_bytes(
        {
            "schema_version": CONTROL_SCHEMA_VERSION,
            "statements": [
                " ".join(statement.split())
                for statement in (
                    CONTROL_SCHEMA_STATEMENTS
                    + CONTROL_SCHEMA_INDEX_STATEMENTS
                    + CONTROL_SCHEMA_TRIGGER_STATEMENTS
                )
            ],
        }
    )
)


class ControlBootstrapError(Exception):
    """A bootstrap precondition or exact-readback check failed."""


ManualRecoveryRequired = safety.ManualRecoveryRequired


def _acquire_flock(descriptor: int, operation: int, label: str) -> None:
    try:
        fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise ControlBootstrapError("%s is busy" % label) from exc


def _require_actor(actor: str, label: str) -> str:
    if not isinstance(actor, str) or not actor.strip() or actor != actor.strip():
        raise ControlBootstrapError("%s is required" % label)
    if any(ord(character) < 0x20 for character in actor):
        raise ControlBootstrapError("%s contains control characters" % label)
    return actor


def _require_canonical_root(root: Path) -> Path:
    path = Path(root)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ControlBootstrapError("raw root is not a canonical absolute path")
    descriptor = safety.open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ControlBootstrapError,
    )
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ControlBootstrapError("raw root is not owner-controlled")
    finally:
        os.close(descriptor)
    return path


def _read_verified_regular_file(
    path: Path,
    *,
    label: str,
    expected_mode: Optional[int],
) -> Tuple[os.stat_result, bytes]:
    try:
        directory_fd = safety.open_verified_directory(
            path.parent,
            require_owner_only=True,
            error_type=ControlBootstrapError,
        )
    except ControlBootstrapError as exc:
        raise ControlBootstrapError("%s parent is unsafe" % label) from exc
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label=label,
            expected_mode=expected_mode,
            error_type=ControlBootstrapError,
        )
        if info.st_nlink != 1:
            raise ControlBootstrapError("%s link count is invalid" % label)
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=ControlBootstrapError,
        )
        return info, raw
    finally:
        os.close(directory_fd)


def _file_identity(path: Path, info: os.stat_result, raw: bytes) -> Dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_bytes(raw),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": "%04o" % stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "nlink": info.st_nlink,
    }


def _parse_canonical_json(raw: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlBootstrapError("%s is not canonical JSON" % label) from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ControlBootstrapError("%s is not canonical JSON" % label)
    return value


def _verified_bootstrap_inputs(
    root: Path,
    completed_result_path: Path,
    *,
    existing_bootstrap_id: Optional[str] = None,
) -> Dict[str, Any]:
    registry_directory = root / "_registry"
    registry_fd = safety.open_verified_directory(
        registry_directory,
        require_owner_only=True,
        error_type=ControlBootstrapError,
    )
    try:
        registry_info, registry_raw = safety.read_regular_file_at(
            registry_fd,
            "placement-map.yml",
            registry_directory / "placement-map.yml",
            label="placement registry",
            expected_mode=None,
            error_type=ControlBootstrapError,
        )
        if registry_info.st_nlink != 1:
            raise ControlBootstrapError("placement registry link count is invalid")
        names = os.listdir(registry_fd)
        if "curation" in names and existing_bootstrap_id is None:
            raise ControlBootstrapError("curation control root already exists")
        partials = sorted(name for name in names if name.startswith(BOOTSTRAP_PREFIX))
        allowed_partial = (
            BOOTSTRAP_PREFIX + existing_bootstrap_id
            if existing_bootstrap_id is not None
            else None
        )
        unexpected_partials = [name for name in partials if name != allowed_partial]
        if unexpected_partials:
            raise ControlBootstrapError(
                "incomplete control bootstrap requires explicit resume: %s"
                % unexpected_partials[0]
            )
        safety.require_same_directory_identity(
            registry_directory,
            registry_fd,
            "registry",
            error_type=ControlBootstrapError,
        )
    finally:
        os.close(registry_fd)

    expected_completed_parent = (
        registry_directory / "lock-migrations" / "completed"
    )
    completed_result_path = Path(completed_result_path)
    if (
        completed_result_path.name != "result.json"
        or completed_result_path.parent.parent != expected_completed_parent
    ):
        raise ControlBootstrapError("completed lock migration result path is not canonical")
    completed_info, completed_raw = _read_verified_regular_file(
        completed_result_path,
        label="completed lock migration result",
        expected_mode=0o600,
    )
    completed = _parse_canonical_json(completed_raw, "completed lock migration result")
    migration_id = completed_result_path.parent.name
    if (
        completed.get("schema_version") != 1
        or completed.get("kind") != "LOCK_MIGRATION_RESULT"
        or completed.get("status") != "COMPLETE"
        or completed.get("migration_id") != migration_id
        or completed.get("registry_sha256") != sha256_bytes(registry_raw)
    ):
        raise ControlBootstrapError("completed lock migration binding is invalid")
    paths = completed.get("paths")
    if not isinstance(paths, dict):
        raise ControlBootstrapError("completed lock migration paths are invalid")
    active_marker = registry_directory / "lock-migrations" / "active"
    placement_lock = registry_directory / "placement-map.lock"
    if (
        paths.get("active_marker") != str(active_marker)
        or paths.get("completed_result") != str(completed_result_path)
        or paths.get("placement_lock") != str(placement_lock)
        or os.path.lexists(active_marker)
    ):
        raise ControlBootstrapError("completed lock migration path binding is invalid")

    lock_info, lock_raw = _read_verified_regular_file(
        placement_lock,
        label="placement policy lock",
        expected_mode=0o600,
    )
    lock_payload = _parse_canonical_json(lock_raw, "placement policy lock")
    recorded_lock = completed.get("placement_lock")
    if (
        not isinstance(recorded_lock, dict)
        or recorded_lock.get("path") != str(placement_lock)
        or recorded_lock.get("sha256") != sha256_bytes(lock_raw)
        or recorded_lock.get("mode") != "0600"
        or recorded_lock.get("uid") != os.getuid()
        or recorded_lock.get("nlink") != 1
        or lock_payload.get("kind") != "PLACEMENT_COORDINATION_LOCK"
        or lock_payload.get("migration_id") != migration_id
        or completed.get("placement_lock_protocol_version")
        != lock_payload.get("placement_lock_protocol_version")
    ):
        raise ControlBootstrapError("completed placement lock binding is invalid")

    return {
        "registry": _file_identity(
            registry_directory / "placement-map.yml",
            registry_info,
            registry_raw,
        ),
        "placement_lock": _file_identity(placement_lock, lock_info, lock_raw),
        "completed_lock_migration": {
            "id": migration_id,
            "result": _file_identity(
                completed_result_path,
                completed_info,
                completed_raw,
            ),
            "placement_lock_protocol_version": completed.get(
                "placement_lock_protocol_version"
            ),
        },
    }


def _preview_bootstrap_state(
    root: Path,
    *,
    requested_by: str,
    completed_result_path: Path,
    existing_bootstrap_id: Optional[str],
) -> Dict[str, Any]:
    canonical_root = _require_canonical_root(root)
    actor = _require_actor(requested_by, "requested_by")
    inputs = _verified_bootstrap_inputs(
        canonical_root,
        completed_result_path,
        existing_bootstrap_id=existing_bootstrap_id,
    )
    seed = {
        "schema_version": 1,
        "kind": "CONTROL_BOOTSTRAP_INPUT",
        "root": str(canonical_root),
        "requested_by": actor,
        "registry": inputs["registry"],
        "placement_lock": inputs["placement_lock"],
        "completed_lock_migration": inputs["completed_lock_migration"],
        "control_schema": {
            "version": CONTROL_SCHEMA_VERSION,
            "sha256": CONTROL_SCHEMA_SHA256,
            "tables": list(CONTROL_SCHEMA_TABLES),
            "indexes": list(CONTROL_SCHEMA_INDEXES),
            "triggers": list(CONTROL_SCHEMA_TRIGGERS),
        },
    }
    bootstrap_id = "curboot-" + sha256_bytes(canonical_json_bytes(seed))[:24]
    staging = canonical_root / "_registry" / (BOOTSTRAP_PREFIX + bootstrap_id)
    final = canonical_root / "_registry" / "curation"
    preview = {
        "schema_version": 1,
        "kind": "CONTROL_BOOTSTRAP_PREVIEW",
        "approval_ready": True,
        "preview_id": bootstrap_id,
        "bootstrap_id": bootstrap_id,
        "requested_by": actor,
        "raw_root": str(canonical_root),
        "registry": inputs["registry"],
        "placement_lock": inputs["placement_lock"],
        "completed_lock_migration": inputs["completed_lock_migration"],
        "control_schema": seed["control_schema"],
        "settings": {
            "foreign_keys": True,
            "synchronous": "FULL",
            "busy_timeout_ms": BUSY_TIMEOUT_MS,
            "staging_journal_mode": STAGING_JOURNAL_MODE,
            "terminal_journal_mode": TERMINAL_JOURNAL_MODE,
        },
        "modes": {
            "directory": "0700",
            "ledger": "0600",
            "ledger_lock": "0600",
            "manifest": "0600",
        },
        "paths": {
            "staging": str(staging),
            "final": str(final),
            "staging_ledger": str(staging / "ledger.sqlite3"),
            "final_ledger": str(final / "ledger.sqlite3"),
            "staging_ledger_lock": str(staging / "ledger.lock"),
            "final_ledger_lock": str(final / "ledger.lock"),
            "staging_manifest": str(
                staging / "bootstrap-state" / bootstrap_id / "manifest.json"
            ),
            "final_manifest": str(
                final / "bootstrap-state" / bootstrap_id / "manifest.json"
            ),
        },
    }
    if existing_bootstrap_id is not None and bootstrap_id != existing_bootstrap_id:
        raise ControlBootstrapError("control bootstrap id no longer matches current inputs")
    return preview


def preview_bootstrap_state(
    root: Path,
    *,
    requested_by: str,
    completed_result_path: Path,
) -> Dict[str, Any]:
    """Return an exact deterministic bootstrap preview without writing state."""
    return _preview_bootstrap_state(
        root,
        requested_by=requested_by,
        completed_result_path=completed_result_path,
        existing_bootstrap_id=None,
    )


def bootstrap_preview_sha256(preview: Dict[str, Any]) -> str:
    """Hash one canonical preview for apply-time exact binding."""
    return sha256_bytes(canonical_json_bytes(preview))


def _checkpoint(
    callback: Optional[Callable[[str], None]],
    name: str,
) -> None:
    if callback is not None:
        callback(name)


def _open_and_lock_regular_file(
    path: Path,
    *,
    label: str,
    operation: int,
    expected_identity: Optional[Dict[str, Any]] = None,
) -> int:
    directory_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=ControlBootstrapError,
    )
    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        lexical = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        _acquire_flock(descriptor, operation, label)
        opened = os.fstat(descriptor)
        final = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        raw = safety.read_open_file_bytes(descriptor)
        identity = _file_identity(path, opened, raw)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
            or (opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino)
            or (expected_identity is not None and identity != expected_identity)
        ):
            raise ControlBootstrapError("%s identity is invalid" % label)
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=ControlBootstrapError,
        )
        return descriptor
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(directory_fd)


def _create_and_lock_file(path: Path, *, label: str) -> Tuple[int, os.stat_result]:
    directory_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=ControlBootstrapError,
    )
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
        _acquire_flock(descriptor, fcntl.LOCK_EX, label)
        os.fsync(descriptor)
        os.fsync(directory_fd)
        opened = os.fstat(descriptor)
        lexical = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise ControlBootstrapError("%s identity is invalid" % label)
        return descriptor, opened
    except FileExistsError as exc:
        raise ControlBootstrapError("refusing to overwrite %s" % label) from exc
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(directory_fd)


def _create_empty_regular_file(path: Path, *, label: str) -> os.stat_result:
    descriptor, info = _create_and_lock_file(path, label=label)
    os.close(descriptor)
    return info


def _create_directory(path: Path, *, label: str) -> os.stat_result:
    safety.create_verified_directory_no_replace(
        path,
        label=label,
        collision_error="refusing to overwrite %s" % label,
        mode=0o700,
        error_type=ControlBootstrapError,
    )
    descriptor = safety.open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ControlBootstrapError,
    )
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ControlBootstrapError("%s identity is invalid" % label)
        return info
    finally:
        os.close(descriptor)


def _publish_manifest(path: Path, manifest_bytes: bytes) -> os.stat_result:
    return safety.publish_bytes_atomic_no_replace(
        path,
        manifest_bytes,
        label="control bootstrap manifest",
        mode=0o600,
        create_parent=False,
        collision_error="refusing to overwrite control bootstrap manifest",
        final_identity_error="control bootstrap manifest identity changed",
        parent_error="control bootstrap manifest parent is unsafe",
        error_type=ControlBootstrapError,
        after_fd_readback=lambda _path, _fd, _parent_fd: None,
    )


def _manifest_for_preview(
    preview: Dict[str, Any],
    preview_sha256: str,
    approved_by: str,
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "CONTROL_BOOTSTRAP_MANIFEST",
        "bootstrap_id": preview["bootstrap_id"],
        "preview_id": preview["preview_id"],
        "preview_sha256": preview_sha256,
        "requested_by": preview["requested_by"],
        "approved_by": approved_by,
        "raw_root": preview["raw_root"],
        "registry": preview["registry"],
        "placement_lock": preview["placement_lock"],
        "completed_lock_migration": preview["completed_lock_migration"],
        "control_schema": preview["control_schema"],
        "settings": preview["settings"],
        "modes": preview["modes"],
        "paths": preview["paths"],
    }


def _verified_regular_info(
    path: Path,
    *,
    label: str,
    expected_mode: int,
) -> os.stat_result:
    directory_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=ControlBootstrapError,
    )
    try:
        opened = _verified_regular_info_at(
            directory_fd,
            path.name,
            label=label,
            expected_mode=expected_mode,
        )
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=ControlBootstrapError,
        )
        return opened
    finally:
        os.close(directory_fd)


def _verified_regular_info_at(
    directory_fd: int,
    name: str,
    *,
    label: str,
    expected_mode: int,
) -> os.stat_result:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        lexical = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        final = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
            or (opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino)
        ):
            raise ControlBootstrapError("%s identity is invalid" % label)
        return opened
    except OSError as exc:
        raise ControlBootstrapError("%s identity is invalid" % label) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_sqlite_artifacts_before_open(
    path: Path,
) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    directory_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=ControlBootstrapError,
    )
    try:
        parent_info = os.fstat(directory_fd)
        ledger_info = _verified_regular_info_at(
            directory_fd,
            path.name,
            label="control ledger",
            expected_mode=0o600,
        )
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar_name = path.name + suffix
            try:
                os.stat(sidecar_name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ControlBootstrapError(
                    "SQLite sidecar is unsafe: %s" % (path.parent / sidecar_name)
                ) from exc
            try:
                _verified_regular_info_at(
                    directory_fd,
                    sidecar_name,
                    label="SQLite sidecar",
                    expected_mode=0o600,
                )
            except ControlBootstrapError as exc:
                raise ControlBootstrapError(
                    "SQLite sidecar is unsafe: %s" % (path.parent / sidecar_name)
                ) from exc
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            "control ledger parent",
            error_type=ControlBootstrapError,
        )
        return (
            (parent_info.st_dev, parent_info.st_ino),
            (ledger_info.st_dev, ledger_info.st_ino),
        )
    finally:
        os.close(directory_fd)


def _connect_database(path: Path) -> sqlite3.Connection:
    """Open after pathname identity checks, within the sqlite3 stdlib limit.

    Python's sqlite3 API accepts only a pathname and neither supports an
    fd-bound open nor exposes SQLite's opened descriptor.  Comparing the
    verified parent and ledger identities immediately before and after connect
    narrows that pathname race.  An adversarial swap-and-restore completed
    wholly inside sqlite3.connect remains a documented stdlib boundary.
    """
    parent_identity, ledger_identity = _verify_sqlite_artifacts_before_open(path)
    connection = None
    try:
        connection = sqlite3.connect(
            str(path),
            timeout=BUSY_TIMEOUT_MS / 1000.0,
            isolation_level=None,
        )
        post_parent_identity, post_ledger_identity = (
            _verify_sqlite_artifacts_before_open(path)
        )
        if post_parent_identity != parent_identity:
            raise ControlBootstrapError(
                "control ledger parent identity changed during open"
            )
        if post_ledger_identity != ledger_identity:
            raise ControlBootstrapError("control ledger identity changed during open")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = %d" % BUSY_TIMEOUT_MS)
        return connection
    except ControlBootstrapError:
        if connection is not None:
            connection.close()
        raise
    except sqlite3.Error as exc:
        if connection is not None:
            connection.close()
        raise ControlBootstrapError("control ledger is corrupt") from exc


def _normalized_sql(value: str) -> str:
    return " ".join(value.strip().rstrip(";").split())


def _verify_schema(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        "SELECT name, sql FROM sqlite_master "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    observed = {name: sql for name, sql in rows}
    if set(observed) != set(CONTROL_SCHEMA_TABLES):
        raise ControlBootstrapError("control schema table set is invalid")
    for name, statement in zip(CONTROL_SCHEMA_TABLES, CONTROL_SCHEMA_STATEMENTS):
        if _normalized_sql(observed[name]) != _normalized_sql(statement):
            raise ControlBootstrapError("control schema definition is invalid: %s" % name)
    index_rows = connection.execute(
        "SELECT name, sql FROM sqlite_master "
        "WHERE type = 'index' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    observed_indexes = {name: sql for name, sql in index_rows}
    if set(observed_indexes) != set(CONTROL_SCHEMA_INDEXES):
        raise ControlBootstrapError("control schema index set is invalid")
    for name, statement in zip(
        CONTROL_SCHEMA_INDEXES,
        CONTROL_SCHEMA_INDEX_STATEMENTS,
    ):
        if _normalized_sql(observed_indexes[name]) != _normalized_sql(statement):
            raise ControlBootstrapError("control schema index is invalid: %s" % name)
    trigger_rows = connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name"
    ).fetchall()
    observed_triggers = {name: sql for name, sql in trigger_rows}
    if set(observed_triggers) != set(CONTROL_SCHEMA_TRIGGERS):
        raise ControlBootstrapError("control schema trigger set is invalid")
    for name, statement in zip(
        CONTROL_SCHEMA_TRIGGERS,
        CONTROL_SCHEMA_TRIGGER_STATEMENTS,
    ):
        if _normalized_sql(observed_triggers[name]) != _normalized_sql(statement):
            raise ControlBootstrapError("control schema trigger is invalid: %s" % name)
    migration = [
        tuple(row)
        for row in connection.execute(
        "SELECT version, schema_sha256 FROM schema_migrations"
        ).fetchall()
    ]
    if migration != [(CONTROL_SCHEMA_VERSION, CONTROL_SCHEMA_SHA256)]:
        raise ControlBootstrapError("control schema migration binding is invalid")


def _verify_database_health(
    connection: sqlite3.Connection,
    *,
    expected_journal_mode: str,
) -> None:
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise ControlBootstrapError("SQLite foreign keys are disabled")
    if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
        raise ControlBootstrapError("SQLite synchronous mode is not FULL")
    if connection.execute("PRAGMA busy_timeout").fetchone()[0] != BUSY_TIMEOUT_MS:
        raise ControlBootstrapError("SQLite busy timeout is invalid")
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    if str(journal_mode).upper() != expected_journal_mode:
        raise ControlBootstrapError("SQLite journal mode is invalid")
    integrity = [
        tuple(row) for row in connection.execute("PRAGMA integrity_check").fetchall()
    ]
    if integrity != [("ok",)]:
        raise ControlBootstrapError("SQLite integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise ControlBootstrapError("SQLite foreign key check failed")
    _verify_schema(connection)


def _safe_file_info(path: Path, *, label: str, expected_mode: int) -> os.stat_result:
    return _verified_regular_info(
        path,
        label=label,
        expected_mode=expected_mode,
    )


def _fsync_file_if_present(path: Path, *, label: str) -> None:
    if not os.path.lexists(path):
        return
    info = _verified_regular_info(
        path,
        label=label,
        expected_mode=0o600,
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ControlBootstrapError("%s identity changed before sync" % label)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path, *, label: str) -> None:
    descriptor = safety.open_verified_directory(
        path,
        require_owner_only=True,
        error_type=ControlBootstrapError,
    )
    try:
        os.fsync(descriptor)
        safety.require_same_directory_identity(
            path,
            descriptor,
            label,
            error_type=ControlBootstrapError,
        )
    finally:
        os.close(descriptor)


def _initialize_database(
    path: Path,
    *,
    preview: Dict[str, Any],
    preview_sha256: str,
    approved_by: str,
    manifest_sha256: str,
    ledger_lock_info: os.stat_result,
    allow_existing: bool = False,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> os.stat_result:
    if os.path.lexists(path):
        if not allow_existing:
            raise ControlBootstrapError("refusing to overwrite control ledger")
        _safe_file_info(path, label="control ledger", expected_mode=0o600)
    else:
        _create_empty_regular_file(path, label="control ledger")
        _checkpoint(checkpoint, "ledger-file-created")
    connection = _connect_database(path)
    try:
        mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
        if str(mode).upper() != STAGING_JOURNAL_MODE:
            raise ControlBootstrapError("cannot establish DELETE staging journal")
        existing_tables = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        if existing_tables:
            if not allow_existing:
                raise ControlBootstrapError("control ledger unexpectedly contains schema")
            _verify_database_health(
                connection,
                expected_journal_mode=STAGING_JOURNAL_MODE,
            )
            return _safe_file_info(
                path,
                label="control ledger",
                expected_mode=0o600,
            )
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in CONTROL_SCHEMA_STATEMENTS:
                connection.execute(statement)
            for statement in CONTROL_SCHEMA_INDEX_STATEMENTS:
                connection.execute(statement)
            for statement in CONTROL_SCHEMA_TRIGGER_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations "
                "(version, schema_sha256, applied_by_bootstrap_id) VALUES (?, ?, ?)",
                (
                    CONTROL_SCHEMA_VERSION,
                    CONTROL_SCHEMA_SHA256,
                    preview["bootstrap_id"],
                ),
            )
            ledger_info = os.stat(path, follow_symlinks=False)
            connection.execute(
                "INSERT INTO control_bootstraps ("
                "bootstrap_id, preview_id, preview_sha256, requested_by, approved_by, "
                "manifest_path, manifest_sha256, schema_version, schema_sha256, "
                "registry_path, registry_sha256, registry_device, registry_inode, "
                "placement_lock_path, placement_lock_sha256, placement_lock_device, "
                "placement_lock_inode, completed_migration_id, completed_result_path, "
                "completed_result_sha256, staging_path, final_path, ledger_path, "
                "ledger_device, ledger_inode, ledger_lock_path, ledger_lock_device, "
                "ledger_lock_inode, staging_journal_mode, terminal_journal_mode, state"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                (
                    preview["bootstrap_id"],
                    preview["preview_id"],
                    preview_sha256,
                    preview["requested_by"],
                    approved_by,
                    preview["paths"]["final_manifest"],
                    manifest_sha256,
                    CONTROL_SCHEMA_VERSION,
                    CONTROL_SCHEMA_SHA256,
                    preview["registry"]["path"],
                    preview["registry"]["sha256"],
                    preview["registry"]["device"],
                    preview["registry"]["inode"],
                    preview["placement_lock"]["path"],
                    preview["placement_lock"]["sha256"],
                    preview["placement_lock"]["device"],
                    preview["placement_lock"]["inode"],
                    preview["completed_lock_migration"]["id"],
                    preview["completed_lock_migration"]["result"]["path"],
                    preview["completed_lock_migration"]["result"]["sha256"],
                    preview["paths"]["staging"],
                    preview["paths"]["final"],
                    preview["paths"]["final_ledger"],
                    ledger_info.st_dev,
                    ledger_info.st_ino,
                    preview["paths"]["final_ledger_lock"],
                    ledger_lock_info.st_dev,
                    ledger_lock_info.st_ino,
                    STAGING_JOURNAL_MODE,
                    TERMINAL_JOURNAL_MODE,
                ),
            )
            connection.execute(
                "INSERT INTO policy_mutation_lane "
                "(id, generation, state) VALUES (1, 0, 'IDLE')"
            )
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        _verify_database_health(
            connection,
            expected_journal_mode=STAGING_JOURNAL_MODE,
        )
    finally:
        connection.close()
    ledger_info = _safe_file_info(path, label="control ledger", expected_mode=0o600)
    _fsync_file_if_present(path, label="control ledger")
    return ledger_info


_CONTROL_EVIDENCE_COLUMNS = (
    "bootstrap_id",
    "preview_id",
    "preview_sha256",
    "requested_by",
    "approved_by",
    "manifest_path",
    "manifest_sha256",
    "schema_version",
    "schema_sha256",
    "registry_path",
    "registry_sha256",
    "registry_device",
    "registry_inode",
    "placement_lock_path",
    "placement_lock_sha256",
    "placement_lock_device",
    "placement_lock_inode",
    "completed_migration_id",
    "completed_result_path",
    "completed_result_sha256",
    "staging_path",
    "final_path",
    "ledger_path",
    "ledger_device",
    "ledger_inode",
    "ledger_lock_path",
    "ledger_lock_device",
    "ledger_lock_inode",
    "staging_journal_mode",
    "terminal_journal_mode",
)


def _logical_readback_payload(
    connection: sqlite3.Connection,
    bootstrap_id: str,
) -> Dict[str, Any]:
    row = connection.execute(
        "SELECT %s FROM control_bootstraps WHERE bootstrap_id = ?"
        % ", ".join(_CONTROL_EVIDENCE_COLUMNS),
        (bootstrap_id,),
    ).fetchone()
    if row is None:
        raise ControlBootstrapError("control bootstrap row is missing")
    migrations = connection.execute(
        "SELECT version, schema_sha256, applied_by_bootstrap_id "
        "FROM schema_migrations WHERE version = ?",
        (CONTROL_SCHEMA_VERSION,),
    ).fetchall()
    return {
        "schema_version": 1,
        "kind": "CONTROL_LEDGER_LOGICAL_READBACK",
        "control_bootstrap": dict(zip(_CONTROL_EVIDENCE_COLUMNS, row)),
        "schema_migrations": [list(item) for item in migrations],
        "initial_policy_mutation_lane": [[1, 0, "IDLE", None, None, None, None, None]],
        "initial_policy_head_count": 0,
        "schema_sha256": CONTROL_SCHEMA_SHA256,
    }


def _logical_readback_sha256(
    connection: sqlite3.Connection,
    bootstrap_id: str,
) -> str:
    return sha256_bytes(
        canonical_json_bytes(_logical_readback_payload(connection, bootstrap_id))
    )


def _require_state(
    connection: sqlite3.Connection,
    bootstrap_id: str,
    expected: str,
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM control_bootstraps WHERE bootstrap_id = ?",
        (bootstrap_id,),
    ).fetchone()
    if row is None or row["state"] != expected:
        raise ControlBootstrapError(
            "control bootstrap state is not %s" % expected
        )
    return row


def _checkpoint_wal(connection: sqlite3.Connection) -> None:
    checkpoint = connection.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
    if checkpoint is None or checkpoint[0] != 0:
        raise ControlBootstrapError("SQLite WAL checkpoint is busy")


def _sync_database_artifacts(ledger_path: Path) -> None:
    _fsync_file_if_present(ledger_path, label="control ledger")
    _fsync_file_if_present(Path(str(ledger_path) + "-wal"), label="control ledger WAL")
    _fsync_file_if_present(Path(str(ledger_path) + "-shm"), label="control ledger SHM")
    _fsync_directory(ledger_path.parent, label="curation control root")


def _advance_files_published(ledger_path: Path, bootstrap_id: str) -> None:
    connection = _connect_database(ledger_path)
    connection.row_factory = sqlite3.Row
    try:
        _verify_database_health(
            connection,
            expected_journal_mode=STAGING_JOURNAL_MODE,
        )
        _require_state(connection, bootstrap_id, "PREPARED")
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "UPDATE control_bootstraps SET state = 'FILES_PUBLISHED' "
            "WHERE bootstrap_id = ? AND state = 'PREPARED'",
            (bootstrap_id,),
        )
        if cursor.rowcount != 1:
            connection.execute("ROLLBACK")
            raise ControlBootstrapError("FILES_PUBLISHED compare-and-swap failed")
        connection.execute("COMMIT")
    finally:
        connection.close()
    _sync_database_artifacts(ledger_path)


def _advance_wal_ready(
    ledger_path: Path,
    bootstrap_id: str,
    *,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> None:
    connection = _connect_database(ledger_path)
    connection.row_factory = sqlite3.Row
    try:
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).upper() != TERMINAL_JOURNAL_MODE:
            raise ControlBootstrapError("cannot establish terminal WAL mode")
        _verify_database_health(
            connection,
            expected_journal_mode=TERMINAL_JOURNAL_MODE,
        )
        _sync_database_artifacts(ledger_path)
        _checkpoint(checkpoint, "wal-mode-enabled")
        _require_state(connection, bootstrap_id, "FILES_PUBLISHED")
        initial_lane = [
            tuple(row)
            for row in connection.execute(
                "SELECT id, generation, state, owner_kind, owner_proposal_id, "
                "owner_approval_id, owner_run_id, owner_process_id "
                "FROM policy_mutation_lane"
            ).fetchall()
        ]
        if initial_lane != [(1, 0, "IDLE", None, None, None, None, None)]:
            raise ControlBootstrapError("initial policy mutation lane is invalid")
        if connection.execute("SELECT COUNT(*) FROM policy_head").fetchone()[0] != 0:
            raise ControlBootstrapError("initial policy head must be absent")
        _checkpoint_wal(connection)
        _sync_database_artifacts(ledger_path)
        logical_sha256 = _logical_readback_sha256(connection, bootstrap_id)
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "UPDATE control_bootstraps SET state = 'WAL_READY', "
            "wal_checkpoint_status = 'FULL', logical_readback_sha256 = ? "
            "WHERE bootstrap_id = ? AND state = 'FILES_PUBLISHED'",
            (logical_sha256, bootstrap_id),
        )
        if cursor.rowcount != 1:
            connection.execute("ROLLBACK")
            raise ControlBootstrapError("WAL_READY compare-and-swap failed")
        connection.execute("COMMIT")
        _checkpoint_wal(connection)
        _sync_database_artifacts(ledger_path)
        row = _require_state(connection, bootstrap_id, "WAL_READY")
        if (
            row["logical_readback_sha256"] != logical_sha256
            or _logical_readback_sha256(connection, bootstrap_id) != logical_sha256
        ):
            raise ControlBootstrapError("logical ledger readback changed at WAL_READY")
    finally:
        connection.close()


def _identity_from_row(row: sqlite3.Row, prefix: str) -> Dict[str, Any]:
    return {
        "path": row[prefix + "_path"],
        "sha256": row[prefix + "_sha256"],
        "device": row[prefix + "_device"],
        "inode": row[prefix + "_inode"],
        "mode": "0600" if prefix == "placement_lock" else None,
        "uid": os.getuid(),
        "nlink": 1,
    }


def _verify_expected_file_identity(
    expected: Dict[str, Any],
    *,
    label: str,
    expected_mode: Optional[int],
) -> None:
    path = Path(expected["path"])
    info, raw = _read_verified_regular_file(
        path,
        label=label,
        expected_mode=expected_mode,
    )
    observed = _file_identity(path, info, raw)
    comparable = {
        key: value for key, value in expected.items() if value is not None
    }
    if any(observed.get(key) != value for key, value in comparable.items()):
        raise ControlBootstrapError("%s identity changed" % label)


def _advance_complete(ledger_path: Path, bootstrap_id: str) -> None:
    connection = _connect_database(ledger_path)
    connection.row_factory = sqlite3.Row
    try:
        _verify_database_health(
            connection,
            expected_journal_mode=TERMINAL_JOURNAL_MODE,
        )
        row = _require_state(connection, bootstrap_id, "WAL_READY")
        if (
            row["wal_checkpoint_status"] != "FULL"
            or row["logical_readback_sha256"] is None
        ):
            raise ControlBootstrapError("WAL_READY evidence is incomplete")
        try:
            _verify_manifest_for_row(row, bootstrap_id)
        except ControlBootstrapError as exc:
            raise ControlBootstrapError(
                "control bootstrap manifest changed before COMPLETE"
            ) from exc
        _verify_expected_file_identity(
            {
                "path": row["registry_path"],
                "sha256": row["registry_sha256"],
                "device": row["registry_device"],
                "inode": row["registry_inode"],
                "uid": os.getuid(),
                "nlink": 1,
            },
            label="placement registry",
            expected_mode=None,
        )
        _verify_expected_file_identity(
            _identity_from_row(row, "placement_lock"),
            label="placement policy lock",
            expected_mode=0o600,
        )
        logical_sha256 = _logical_readback_sha256(connection, bootstrap_id)
        if row["logical_readback_sha256"] != logical_sha256:
            raise ControlBootstrapError("logical ledger readback is invalid")
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "UPDATE control_bootstraps SET state = 'COMPLETE' "
            "WHERE bootstrap_id = ? AND state = 'WAL_READY' "
            "AND logical_readback_sha256 = ?",
            (bootstrap_id, logical_sha256),
        )
        if cursor.rowcount != 1:
            connection.execute("ROLLBACK")
            raise ControlBootstrapError("COMPLETE compare-and-swap failed")
        connection.execute("COMMIT")
        _checkpoint_wal(connection)
        _sync_database_artifacts(ledger_path)
        completed = _require_state(connection, bootstrap_id, "COMPLETE")
        if (
            completed["logical_readback_sha256"] != logical_sha256
            or _logical_readback_sha256(connection, bootstrap_id) != logical_sha256
        ):
            raise ControlBootstrapError("logical ledger readback changed at COMPLETE")
    finally:
        connection.close()


def _read_manifest(path: Path) -> Tuple[Dict[str, Any], str]:
    _info, raw = _read_verified_regular_file(
        path,
        label="control bootstrap manifest",
        expected_mode=0o600,
    )
    manifest = _parse_canonical_json(raw, "control bootstrap manifest")
    if manifest.get("kind") != "CONTROL_BOOTSTRAP_MANIFEST":
        raise ControlBootstrapError("control bootstrap manifest binding is invalid")
    return manifest, sha256_bytes(raw)


def _verify_manifest_for_row(
    row: sqlite3.Row,
    bootstrap_id: str,
) -> Dict[str, Any]:
    manifest, manifest_sha256 = _read_manifest(Path(row["manifest_path"]))
    expected_schema = {
        "version": CONTROL_SCHEMA_VERSION,
        "sha256": CONTROL_SCHEMA_SHA256,
        "tables": list(CONTROL_SCHEMA_TABLES),
        "indexes": list(CONTROL_SCHEMA_INDEXES),
        "triggers": list(CONTROL_SCHEMA_TRIGGERS),
    }
    paths = manifest.get("paths")
    if (
        manifest_sha256 != row["manifest_sha256"]
        or manifest.get("schema_version") != 1
        or manifest.get("kind") != "CONTROL_BOOTSTRAP_MANIFEST"
        or manifest.get("bootstrap_id") != bootstrap_id
        or manifest.get("preview_id") != row["preview_id"]
        or manifest.get("preview_sha256") != row["preview_sha256"]
        or manifest.get("requested_by") != row["requested_by"]
        or manifest.get("approved_by") != row["approved_by"]
        or manifest.get("control_schema") != expected_schema
        or not isinstance(paths, dict)
        or paths.get("staging") != row["staging_path"]
        or paths.get("final") != row["final_path"]
        or paths.get("final_ledger") != row["ledger_path"]
        or paths.get("final_ledger_lock") != row["ledger_lock_path"]
        or paths.get("final_manifest") != row["manifest_path"]
    ):
        raise ControlBootstrapError("control bootstrap manifest binding changed")
    return manifest


def _result_from_connection(
    connection: sqlite3.Connection,
    bootstrap_id: str,
) -> Dict[str, Any]:
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        "SELECT * FROM control_bootstraps WHERE bootstrap_id = ?",
        (bootstrap_id,),
    ).fetchone()
    if row is None:
        raise ControlBootstrapError("control bootstrap row is missing")
    return {
        "schema_version": 1,
        "kind": "CONTROL_BOOTSTRAP_RESULT",
        "bootstrap_id": row["bootstrap_id"],
        "preview_id": row["preview_id"],
        "preview_sha256": row["preview_sha256"],
        "manifest_sha256": row["manifest_sha256"],
        "schema_sha256": row["schema_sha256"],
        "logical_readback_sha256": row["logical_readback_sha256"],
        "journal_mode": row["terminal_journal_mode"],
        "state": row["state"],
        "paths": {
            "final": row["final_path"],
            "ledger": row["ledger_path"],
            "ledger_lock": row["ledger_lock_path"],
            "manifest": row["manifest_path"],
        },
    }


def _read_result(ledger_path: Path, bootstrap_id: str) -> Dict[str, Any]:
    connection = _connect_database(ledger_path)
    try:
        return _result_from_connection(connection, bootstrap_id)
    finally:
        connection.close()


def apply_bootstrap_state(
    root: Path,
    *,
    requested_by: str,
    approved_by: str,
    preview_id: str,
    preview_sha256: str,
    completed_result_path: Path,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Apply one exact preview, propagating ManualRecoveryRequired on rename."""
    actor = _require_actor(approved_by, "approved_by")
    preview = preview_bootstrap_state(
        root,
        requested_by=requested_by,
        completed_result_path=completed_result_path,
    )
    actual_preview_sha256 = bootstrap_preview_sha256(preview)
    if preview_id != preview["preview_id"] or preview_sha256 != actual_preview_sha256:
        raise ControlBootstrapError("bootstrap preview binding changed")

    placement_fd = _open_and_lock_regular_file(
        Path(preview["placement_lock"]["path"]),
        label="placement policy lock",
        operation=fcntl.LOCK_SH,
        expected_identity=preview["placement_lock"],
    )
    ledger_lock_fd = None
    try:
        _checkpoint(checkpoint, "placement-lock-acquired")
        locked_preview = preview_bootstrap_state(
            root,
            requested_by=requested_by,
            completed_result_path=completed_result_path,
        )
        if (
            locked_preview != preview
            or bootstrap_preview_sha256(locked_preview) != preview_sha256
        ):
            raise ControlBootstrapError("bootstrap inputs changed under placement lock")

        staging = Path(preview["paths"]["staging"])
        final = Path(preview["paths"]["final"])
        _create_directory(staging, label="control bootstrap staging directory")
        _checkpoint(checkpoint, "staging-created")
        staging_identity = safety.source_identity(
            os.stat(staging, follow_symlinks=False)
        )
        ledger_lock_fd, ledger_lock_info = _create_and_lock_file(
            Path(preview["paths"]["staging_ledger_lock"]),
            label="control ledger lock",
        )
        _checkpoint(checkpoint, "ledger-lock-acquired")

        bootstrap_state = staging / "bootstrap-state"
        manifest_directory = bootstrap_state / preview["bootstrap_id"]
        _create_directory(bootstrap_state, label="bootstrap-state directory")
        _create_directory(manifest_directory, label="bootstrap manifest directory")
        manifest = _manifest_for_preview(preview, preview_sha256, actor)
        manifest_bytes = canonical_json_bytes(manifest)
        manifest_sha256 = sha256_bytes(manifest_bytes)
        _publish_manifest(Path(preview["paths"]["staging_manifest"]), manifest_bytes)
        _fsync_directory(manifest_directory, label="bootstrap manifest directory")
        _fsync_directory(bootstrap_state, label="bootstrap-state directory")
        _fsync_directory(staging, label="control bootstrap staging directory")
        _checkpoint(checkpoint, "manifest-published")

        ledger_info = _initialize_database(
            Path(preview["paths"]["staging_ledger"]),
            preview=preview,
            preview_sha256=preview_sha256,
            approved_by=actor,
            manifest_sha256=manifest_sha256,
            ledger_lock_info=ledger_lock_info,
            checkpoint=checkpoint,
        )
        if (
            ledger_info.st_dev == 0
            or ledger_info.st_ino == 0
            or ledger_lock_info.st_nlink != 1
        ):
            raise ControlBootstrapError("control ledger identity is invalid")
        _fsync_directory(manifest_directory, label="bootstrap manifest directory")
        _fsync_directory(bootstrap_state, label="bootstrap-state directory")
        _fsync_directory(staging, label="control bootstrap staging directory")
        _checkpoint(checkpoint, "prepared")

        safety.rename_path_no_replace(
            staging,
            final,
            collision_error="refusing to overwrite curation control root",
            require_directory=True,
            expected_source_identity=staging_identity,
            error_type=ControlBootstrapError,
        )
        _checkpoint(checkpoint, "final-directory-published")
        _advance_files_published(
            Path(preview["paths"]["final_ledger"]),
            preview["bootstrap_id"],
        )
        _checkpoint(checkpoint, "files-published")
        _advance_wal_ready(
            Path(preview["paths"]["final_ledger"]),
            preview["bootstrap_id"],
            checkpoint=checkpoint,
        )
        _checkpoint(checkpoint, "wal-ready")
        _advance_complete(
            Path(preview["paths"]["final_ledger"]),
            preview["bootstrap_id"],
        )
        _checkpoint(checkpoint, "complete")
        return _read_result(
            Path(preview["paths"]["final_ledger"]),
            preview["bootstrap_id"],
        )
    finally:
        if ledger_lock_fd is not None:
            os.close(ledger_lock_fd)
        os.close(placement_fd)


def _require_bootstrap_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("curboot-")
        or len(value) != len("curboot-") + 24
        or any(character not in "0123456789abcdef" for character in value[8:])
    ):
        raise ControlBootstrapError("bootstrap_id is invalid")
    return value


def _resume_database_state(
    ledger_path: Path,
    *,
    bootstrap_id: str,
    manifest_sha256: str,
    ledger_lock_info: os.stat_result,
    preview: Dict[str, Any],
    preview_sha256: str,
    approved_by: str,
) -> str:
    ledger_info = _safe_file_info(
        ledger_path,
        label="control ledger",
        expected_mode=0o600,
    )
    connection = _connect_database(ledger_path)
    connection.row_factory = sqlite3.Row
    try:
        journal_mode = str(
            connection.execute("PRAGMA journal_mode").fetchone()[0]
        ).upper()
        expected_mode = (
            TERMINAL_JOURNAL_MODE
            if journal_mode == TERMINAL_JOURNAL_MODE
            else STAGING_JOURNAL_MODE
        )
        _verify_database_health(
            connection,
            expected_journal_mode=expected_mode,
        )
        row = connection.execute(
            "SELECT * FROM control_bootstraps WHERE bootstrap_id = ?",
            (bootstrap_id,),
        ).fetchone()
        if row is None:
            raise ControlBootstrapError("control bootstrap row is missing")
        expected_values = {
            "preview_id": preview["preview_id"],
            "preview_sha256": preview_sha256,
            "requested_by": preview["requested_by"],
            "approved_by": approved_by,
            "manifest_path": preview["paths"]["final_manifest"],
            "schema_version": CONTROL_SCHEMA_VERSION,
            "schema_sha256": CONTROL_SCHEMA_SHA256,
            "registry_path": preview["registry"]["path"],
            "registry_sha256": preview["registry"]["sha256"],
            "registry_device": preview["registry"]["device"],
            "registry_inode": preview["registry"]["inode"],
            "placement_lock_path": preview["placement_lock"]["path"],
            "placement_lock_sha256": preview["placement_lock"]["sha256"],
            "placement_lock_device": preview["placement_lock"]["device"],
            "placement_lock_inode": preview["placement_lock"]["inode"],
            "completed_migration_id": preview["completed_lock_migration"]["id"],
            "completed_result_path": preview["completed_lock_migration"]["result"]["path"],
            "completed_result_sha256": preview["completed_lock_migration"]["result"]["sha256"],
            "staging_path": preview["paths"]["staging"],
            "final_path": preview["paths"]["final"],
            "ledger_path": preview["paths"]["final_ledger"],
            "ledger_lock_path": preview["paths"]["final_ledger_lock"],
            "staging_journal_mode": STAGING_JOURNAL_MODE,
            "terminal_journal_mode": TERMINAL_JOURNAL_MODE,
        }
        if (
            row["manifest_sha256"] != manifest_sha256
            or any(row[key] != value for key, value in expected_values.items())
            or (ledger_info.st_dev, ledger_info.st_ino)
            != (row["ledger_device"], row["ledger_inode"])
            or (ledger_lock_info.st_dev, ledger_lock_info.st_ino)
            != (row["ledger_lock_device"], row["ledger_lock_inode"])
        ):
            raise ControlBootstrapError("control bootstrap resume identity changed")
        state = row["state"]
        if state == "PREPARED" and journal_mode != STAGING_JOURNAL_MODE:
            raise ControlBootstrapError("partial control bootstrap journal mode is invalid")
        if state == "FILES_PUBLISHED" and journal_mode not in {
            STAGING_JOURNAL_MODE,
            TERMINAL_JOURNAL_MODE,
        }:
            raise ControlBootstrapError("published control bootstrap journal mode is invalid")
        if state in {"WAL_READY", "COMPLETE"} and journal_mode != TERMINAL_JOURNAL_MODE:
            raise ControlBootstrapError("terminal control bootstrap journal mode is invalid")
        if state == "BLOCKED":
            raise ControlBootstrapError("control bootstrap is blocked")
        return str(state)
    finally:
        connection.close()


def _peek_final_database_state(
    ledger_path: Path,
    *,
    bootstrap_id: str,
    manifest_sha256: str,
    ledger_lock_info: os.stat_result,
) -> str:
    ledger_info = _safe_file_info(
        ledger_path,
        label="control ledger",
        expected_mode=0o600,
    )
    connection = _connect_database(ledger_path)
    connection.row_factory = sqlite3.Row
    try:
        journal_mode = str(
            connection.execute("PRAGMA journal_mode").fetchone()[0]
        ).upper()
        expected_mode = (
            TERMINAL_JOURNAL_MODE
            if journal_mode == TERMINAL_JOURNAL_MODE
            else STAGING_JOURNAL_MODE
        )
        _verify_database_health(connection, expected_journal_mode=expected_mode)
        row = connection.execute(
            "SELECT * FROM control_bootstraps WHERE bootstrap_id = ?",
            (bootstrap_id,),
        ).fetchone()
        if row is None:
            raise ControlBootstrapError("control bootstrap row is missing")
        if (
            row["manifest_sha256"] != manifest_sha256
            or (ledger_info.st_dev, ledger_info.st_ino)
            != (row["ledger_device"], row["ledger_inode"])
            or (ledger_lock_info.st_dev, ledger_lock_info.st_ino)
            != (row["ledger_lock_device"], row["ledger_lock_inode"])
        ):
            raise ControlBootstrapError("control bootstrap final identity changed")
        state = str(row["state"])
        if state == "COMPLETE":
            if journal_mode != TERMINAL_JOURNAL_MODE:
                raise ControlBootstrapError("terminal control bootstrap journal mode is invalid")
            _verify_manifest_for_row(row, bootstrap_id)
            if row["logical_readback_sha256"] != _logical_readback_sha256(
                connection,
                bootstrap_id,
            ):
                raise ControlBootstrapError("logical ledger readback is invalid")
        return state
    finally:
        connection.close()


def resume_bootstrap_state(
    root: Path,
    *,
    bootstrap_id: str,
    resumed_by: str,
    completed_result_path: Path,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Resume only missing transitions from one exact sealed bootstrap."""
    canonical_root = _require_canonical_root(root)
    identifier = _require_bootstrap_id(bootstrap_id)
    _require_actor(resumed_by, "resumed_by")
    placement_path = canonical_root / "_registry" / "placement-map.lock"
    placement_fd = _open_and_lock_regular_file(
        placement_path,
        label="placement policy lock",
        operation=fcntl.LOCK_SH,
    )
    ledger_lock_fd = None
    try:
        _checkpoint(checkpoint, "placement-lock-acquired")
        staging = canonical_root / "_registry" / (BOOTSTRAP_PREFIX + identifier)
        final = canonical_root / "_registry" / "curation"
        staging_exists = os.path.lexists(staging)
        final_exists = os.path.lexists(final)
        if staging_exists == final_exists:
            if staging_exists:
                raise ControlBootstrapError(
                    "staging and final control roots both exist; refusing repair"
                )
            raise ControlBootstrapError("control bootstrap state is missing")
        current_root = final if final_exists else staging
        current_root_fd = safety.open_verified_directory(
            current_root,
            require_owner_only=True,
            error_type=ControlBootstrapError,
        )
        try:
            current_root_info = os.fstat(current_root_fd)
            if stat.S_IMODE(current_root_info.st_mode) != 0o700:
                raise ControlBootstrapError("control bootstrap directory mode is invalid")
        finally:
            os.close(current_root_fd)

        current_manifest_path = (
            current_root / "bootstrap-state" / identifier / "manifest.json"
        )
        if not os.path.lexists(current_manifest_path):
            raise ControlBootstrapError(
                "manual blocker: control bootstrap manifest was not durably published"
            )
        try:
            manifest, manifest_sha256 = _read_manifest(current_manifest_path)
        except ControlBootstrapError as exc:
            raise ControlBootstrapError(
                "manual blocker: control bootstrap manifest is unsafe or corrupt"
            ) from exc
        if (
            manifest.get("bootstrap_id") != identifier
            or manifest.get("raw_root") != str(canonical_root)
            or manifest.get("completed_lock_migration", {})
            .get("result", {})
            .get("path")
            != str(Path(completed_result_path))
        ):
            raise ControlBootstrapError("control bootstrap manifest binding is invalid")
        requested_by = manifest.get("requested_by")
        approved_by = manifest.get("approved_by")
        _require_actor(requested_by, "manifest requested_by")
        _require_actor(approved_by, "manifest approved_by")

        current_lock_path = current_root / "ledger.lock"
        if not os.path.lexists(current_lock_path):
            raise ControlBootstrapError(
                "manual blocker: sealed manifest exists without ledger lock"
            )
        ledger_lock_fd = _open_and_lock_regular_file(
            current_lock_path,
            label="control ledger lock",
            operation=fcntl.LOCK_EX,
        )
        if safety.read_open_file_bytes(ledger_lock_fd) != b"":
            raise ControlBootstrapError("control ledger lock content is invalid")
        _checkpoint(checkpoint, "ledger-lock-acquired")
        current_ledger_path = current_root / "ledger.sqlite3"
        state = None
        if current_root == final:
            state = _peek_final_database_state(
                current_ledger_path,
                bootstrap_id=identifier,
                manifest_sha256=manifest_sha256,
                ledger_lock_info=os.fstat(ledger_lock_fd),
            )

        if state != "COMPLETE":
            preview = _preview_bootstrap_state(
                canonical_root,
                requested_by=requested_by,
                completed_result_path=completed_result_path,
                existing_bootstrap_id=identifier,
            )
            preview_sha256 = bootstrap_preview_sha256(preview)
            expected_manifest = _manifest_for_preview(
                preview,
                preview_sha256,
                approved_by,
            )
            if manifest != expected_manifest:
                raise ControlBootstrapError(
                    "control bootstrap manifest no longer matches inputs"
                )
            if current_root == staging:
                _initialize_database(
                    current_ledger_path,
                    preview=preview,
                    preview_sha256=preview_sha256,
                    approved_by=approved_by,
                    manifest_sha256=manifest_sha256,
                    ledger_lock_info=os.fstat(ledger_lock_fd),
                    allow_existing=True,
                    checkpoint=checkpoint,
                )
                _fsync_directory(staging, label="control bootstrap staging directory")
            state = _resume_database_state(
                current_ledger_path,
                bootstrap_id=identifier,
                manifest_sha256=manifest_sha256,
                ledger_lock_info=os.fstat(ledger_lock_fd),
                preview=preview,
                preview_sha256=preview_sha256,
                approved_by=approved_by,
            )

        if current_root == staging:
            if state != "PREPARED":
                raise ControlBootstrapError("staging control bootstrap state is invalid")
            staging_identity = safety.source_identity(
                os.stat(staging, follow_symlinks=False)
            )
            safety.rename_path_no_replace(
                staging,
                final,
                collision_error="refusing to overwrite curation control root",
                require_directory=True,
                expected_source_identity=staging_identity,
                error_type=ControlBootstrapError,
            )
            _checkpoint(checkpoint, "final-directory-published")
            current_ledger_path = final / "ledger.sqlite3"
            _advance_files_published(current_ledger_path, identifier)
            state = "FILES_PUBLISHED"
            _checkpoint(checkpoint, "files-published")
        elif state == "PREPARED":
            _advance_files_published(current_ledger_path, identifier)
            state = "FILES_PUBLISHED"
            _checkpoint(checkpoint, "files-published")

        if state == "FILES_PUBLISHED":
            _advance_wal_ready(
                current_ledger_path,
                identifier,
                checkpoint=checkpoint,
            )
            state = "WAL_READY"
            _checkpoint(checkpoint, "wal-ready")
        if state == "WAL_READY":
            _advance_complete(current_ledger_path, identifier)
            state = "COMPLETE"
            _checkpoint(checkpoint, "complete")
        if state != "COMPLETE":
            raise ControlBootstrapError("control bootstrap cannot be resumed")
    finally:
        if ledger_lock_fd is not None:
            os.close(ledger_lock_fd)
        os.close(placement_fd)
    return verify_complete_bootstrap(
        canonical_root,
        bootstrap_id=identifier,
    )


def _verify_complete_bootstrap(
    root: Path,
    *,
    bootstrap_id: str,
    require_registry_preimage: bool,
) -> Dict[str, Any]:
    """Verify structural authority, optionally binding the INITIAL preimage."""
    canonical_root = _require_canonical_root(root)
    placement_path = canonical_root / "_registry" / "placement-map.lock"
    placement_fd = _open_and_lock_regular_file(
        placement_path,
        label="placement policy lock",
        operation=fcntl.LOCK_SH,
    )
    ledger_lock_fd = None
    try:
        final = canonical_root / "_registry" / "curation"
        final_fd = safety.open_verified_directory(
            final,
            require_owner_only=True,
            error_type=ControlBootstrapError,
        )
        try:
            final_info = os.fstat(final_fd)
            if stat.S_IMODE(final_info.st_mode) != 0o700:
                raise ControlBootstrapError("curation control root mode is invalid")
        finally:
            os.close(final_fd)
        ledger_lock = final / "ledger.lock"
        ledger_lock_fd = _open_and_lock_regular_file(
            ledger_lock,
            label="control ledger lock",
            operation=fcntl.LOCK_SH,
        )
        if safety.read_open_file_bytes(ledger_lock_fd) != b"":
            raise ControlBootstrapError("control ledger lock content is invalid")
        ledger = final / "ledger.sqlite3"
        _safe_file_info(ledger, label="control ledger", expected_mode=0o600)
        connection = _connect_database(ledger)
        connection.row_factory = sqlite3.Row
        try:
            _verify_database_health(
                connection,
                expected_journal_mode=TERMINAL_JOURNAL_MODE,
            )
            row = _require_state(connection, bootstrap_id, "COMPLETE")
            if (
                row["wal_checkpoint_status"] != "FULL"
                or row["logical_readback_sha256"] is None
            ):
                raise ControlBootstrapError(
                    "completed control bootstrap WAL evidence is invalid"
                )
            if row["final_path"] != str(final) or row["ledger_path"] != str(ledger):
                raise ControlBootstrapError("control bootstrap path binding is invalid")
            manifest = _verify_manifest_for_row(row, bootstrap_id)
            completed_result_identity = (
                manifest.get("completed_lock_migration", {}).get("result")
            )
            if not isinstance(completed_result_identity, dict):
                raise ControlBootstrapError(
                    "completed lock migration result binding is invalid"
                )
            _verify_expected_file_identity(
                completed_result_identity,
                label="completed lock migration result",
                expected_mode=0o600,
            )
            lock_info = os.fstat(ledger_lock_fd)
            ledger_info = os.stat(ledger, follow_symlinks=False)
            placement_info = os.fstat(placement_fd)
            if (
                (lock_info.st_dev, lock_info.st_ino)
                != (row["ledger_lock_device"], row["ledger_lock_inode"])
                or (ledger_info.st_dev, ledger_info.st_ino)
                != (row["ledger_device"], row["ledger_inode"])
                or (placement_info.st_dev, placement_info.st_ino)
                != (row["placement_lock_device"], row["placement_lock_inode"])
            ):
                raise ControlBootstrapError("control bootstrap file identity changed")
            if os.path.lexists(row["staging_path"]):
                raise ControlBootstrapError(
                    "completed control bootstrap has an incomplete staging collision"
                )
            if require_registry_preimage:
                try:
                    _verify_expected_file_identity(
                        {
                            "path": row["registry_path"],
                            "sha256": row["registry_sha256"],
                            "device": row["registry_device"],
                            "inode": row["registry_inode"],
                            "uid": os.getuid(),
                            "nlink": 1,
                        },
                        label="placement registry",
                        expected_mode=None,
                    )
                except ControlBootstrapError as exc:
                    raise ControlBootstrapError(
                        "placement registry preimage changed"
                    ) from exc
            _verify_expected_file_identity(
                {
                    "path": row["placement_lock_path"],
                    "sha256": row["placement_lock_sha256"],
                    "device": row["placement_lock_device"],
                    "inode": row["placement_lock_inode"],
                    "mode": "0600",
                    "uid": os.getuid(),
                    "nlink": 1,
                },
                label="placement policy lock",
                expected_mode=0o600,
            )
            logical_sha256 = _logical_readback_sha256(connection, bootstrap_id)
            if row["logical_readback_sha256"] != logical_sha256:
                raise ControlBootstrapError("logical ledger readback is invalid")
            return _result_from_connection(connection, bootstrap_id)
        finally:
            connection.close()
    finally:
        if ledger_lock_fd is not None:
            os.close(ledger_lock_fd)
        os.close(placement_fd)


def verify_complete_bootstrap(
    root: Path,
    *,
    bootstrap_id: str,
) -> Dict[str, Any]:
    """Verify structural COMPLETE independent of later approved policy bytes."""
    return _verify_complete_bootstrap(
        root,
        bootstrap_id=bootstrap_id,
        require_registry_preimage=False,
    )


def verify_bootstrap_registry_preimage(
    root: Path,
    *,
    bootstrap_id: str,
) -> Dict[str, Any]:
    """Verify the original registry preimage immediately before INITIAL publish."""
    return _verify_complete_bootstrap(
        root,
        bootstrap_id=bootstrap_id,
        require_registry_preimage=True,
    )


__all__ = [
    "BUSY_TIMEOUT_MS",
    "CONTROL_SCHEMA_SHA256",
    "CONTROL_SCHEMA_INDEXES",
    "CONTROL_SCHEMA_INDEX_STATEMENTS",
    "CONTROL_SCHEMA_STATEMENTS",
    "CONTROL_SCHEMA_TABLES",
    "CONTROL_SCHEMA_TRIGGERS",
    "CONTROL_SCHEMA_TRIGGER_STATEMENTS",
    "CONTROL_SCHEMA_VERSION",
    "ControlBootstrapError",
    "ManualRecoveryRequired",
    "apply_bootstrap_state",
    "bootstrap_preview_sha256",
    "preview_bootstrap_state",
    "resume_bootstrap_state",
    "verify_complete_bootstrap",
    "verify_bootstrap_registry_preimage",
]
