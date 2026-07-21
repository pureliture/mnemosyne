"""Post-INITIAL policy authority transitions for Mnemosyne curation.

The module owns policy drift invalidation and the EDIT/RECONCILE authority
families.  It deliberately has no CLI dependency and never touches corpus
content.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from . import activation_foundation, policy, policy_state
from .canonical_json import canonical_json_bytes, sha256_bytes


class PolicyAuthorityError(Exception):
    """A policy authority precondition or immutable binding failed."""


class PolicyChangeRecoveryRequired(PolicyAuthorityError):
    """A claimed EDIT/RECONCILE attempt needs separately approved recovery."""

    def __init__(
        self,
        message: str,
        *,
        mode: str,
        phase: str,
        run_id: str,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.mode = mode
        self.phase = phase
        self.run_id = run_id
        self.cause = cause


POLICY_AUTHORITY_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ActivationInitialPolicySource:
    """Typed immutable source for the Safe Librarian activation INITIAL head."""

    plan: activation_foundation.ActivationFoundationPlan
    receipt_path: Path
    receipt_sha256: str


def _checkpoint(callback: Optional[Callable[[str], None]], point: str) -> None:
    if callback is not None:
        callback(point)


def _require_actor(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PolicyAuthorityError("%s is required" % label)
    if any(ord(character) < 0x20 for character in value):
        raise PolicyAuthorityError("%s contains control characters" % label)
    return value


def _required_sealed_mode(value: Optional[str]) -> Optional[str]:
    if value is not None and value not in {"EDIT", "RECONCILE"}:
        raise PolicyAuthorityError("required_sealed_mode is invalid")
    return value


def _canonical_root(root: Path) -> Path:
    try:
        return policy_state._canonical_root(root)
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def _registry_observation(root: Path) -> Tuple[bytes, Dict[str, Any]]:
    try:
        info, raw, identity = policy_state._registry_identity(root)
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc
    compiled_hash: Optional[str]
    try:
        compiled_hash = policy.compile_policy(raw, str(root)).full_hash
        compile_status = "VALID"
    except policy.PolicyError:
        compiled_hash = None
        compile_status = "INVALID"
    return raw, {
        "path": identity["path"],
        "raw_sha256": identity["raw_sha256"],
        "normalized_full_hash": compiled_hash,
        "compile_status": compile_status,
        "bytes": len(raw),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": "%04o" % stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "nlink": info.st_nlink,
    }


def _snapshot_for_head(
    connection: sqlite3.Connection,
    head: sqlite3.Row,
) -> sqlite3.Row:
    snapshot = connection.execute(
        "SELECT * FROM policy_snapshots "
        "WHERE full_hash = ? AND source_kind = ? AND source_run_id = ?",
        (head["full_hash"], head["source_kind"], head["source_run_id"]),
    ).fetchone()
    if (
        snapshot is None
        or snapshot["source_kind"] != head["source_kind"]
        or snapshot["source_run_id"] != head["source_run_id"]
        or snapshot["source_state"] != "TERMINAL"
    ):
        raise PolicyAuthorityError("policy head source is not terminal")
    return snapshot


def _head_row(connection: sqlite3.Connection) -> sqlite3.Row:
    head = connection.execute("SELECT * FROM policy_head WHERE id = 1").fetchone()
    if head is None:
        raise PolicyAuthorityError("policy head is missing")
    _snapshot_for_head(connection, head)
    return head


def _require_idle_lane(connection: sqlite3.Connection) -> None:
    lane = connection.execute(
        "SELECT state, owner_kind, owner_proposal_id, owner_approval_id, "
        "owner_run_id, owner_process_id FROM policy_mutation_lane WHERE id = 1"
    ).fetchone()
    if lane is None or tuple(lane) != ("IDLE", None, None, None, None, None):
        raise PolicyAuthorityError("policy mutation lane is not IDLE")


def _guard_paths(root: Path, event_id: str) -> Tuple[Path, Path]:
    directory = root / "_registry" / "curation" / "policy-guard" / "events" / event_id
    return directory / "observation.json", directory / "result.json"


def _observation_payload(
    event: sqlite3.Row,
    episode: sqlite3.Row,
    identity: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": event["kind"],
        "event_id": event["event_id"],
        "episode_id": episode["episode_id"],
        "head_generation": event["head_generation"],
        "head_full_hash": episode["head_full_hash"],
        "head": {
            "generation": event["head_generation"],
            "full_hash": episode["head_full_hash"],
            "guard_epoch": event["guard_epoch"],
        },
        "observation": identity,
    }


def _read_canonical_artifact(path: Path, label: str) -> Tuple[bytes, Dict[str, Any]]:
    try:
        _, raw = policy_state._read_regular(path, label=label, expected_mode=0o600)
        value = json.loads(raw)
    except (policy_state.PolicyStateError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyAuthorityError("%s is invalid" % label) from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise PolicyAuthorityError("%s is not canonical" % label)
    return raw, value


def _publish_or_verify(path: Path, raw: bytes, label: str) -> None:
    try:
        policy_state._publish_or_verify(path, raw, label=label)
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def _finish_guard_event(
    root: Path,
    connection: sqlite3.Connection,
    event_id: str,
    *,
    checkpoint: Optional[Callable[[str], None]],
) -> Dict[str, Any]:
    event = connection.execute(
        "SELECT * FROM policy_guard_events WHERE event_id = ?", (event_id,)
    ).fetchone()
    if event is None:
        raise PolicyAuthorityError("policy guard event is missing")
    episode = connection.execute(
        "SELECT * FROM policy_guard_episodes WHERE episode_id = ?",
        (event["episode_id"],),
    ).fetchone()
    if episode is None:
        raise PolicyAuthorityError("policy guard episode is missing")
    observation_path = Path(event["observation_path"])
    result_path = Path(event["result_path"])
    if os.path.lexists(observation_path):
        observation_bytes, observation = _read_canonical_artifact(
            observation_path,
            "policy guard observation",
        )
        if (
            observation.get("event_id") != event_id
            or observation.get("episode_id") != episode["episode_id"]
        ):
            raise PolicyAuthorityError("stored policy guard observation identity changed")
    else:
        identity = json.loads(bytes(episode["current_observed_identity_json"]))
        observation = _observation_payload(event, episode, identity)
        observation_bytes = canonical_json_bytes(observation)
    if sha256_bytes(observation_bytes) != event["observation_sha256"]:
        raise PolicyAuthorityError("stored policy guard observation binding changed")
    _publish_or_verify(observation_path, observation_bytes, "policy guard observation")
    _checkpoint(checkpoint, "guard-observation-published")

    if event["result_sha256"] is None:
        _, final_identity = _registry_observation(root)
        result = {
            "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
            "kind": "POLICY_GUARD_EVENT_RESULT",
            "status": "COMPLETE",
            "event_id": event_id,
            "episode_id": episode["episode_id"],
            "event_kind": event["kind"],
            "observation_sha256": event["observation_sha256"],
            "final_observation": final_identity,
        }
        result_bytes = canonical_json_bytes(result)
        result_sha256 = sha256_bytes(result_bytes)
        try:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE policy_guard_events SET result_sha256 = ? WHERE event_id = ? "
                "AND state IN ('GUARD_BUMPED', 'PREPARED') AND result_sha256 IS NULL",
                (result_sha256, event_id),
            ).rowcount
            if updated != 1:
                raise PolicyAuthorityError("policy guard result prepare CAS failed")
            connection.execute(
                "UPDATE policy_guard_episodes SET current_observed_identity_json = ? "
                "WHERE episode_id = ? AND status = 'OPEN'",
                (canonical_json_bytes(final_identity), episode["episode_id"]),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
    else:
        _, observation_value = _read_canonical_artifact(
            observation_path, "policy guard observation"
        )
        current_episode = connection.execute(
            "SELECT current_observed_identity_json FROM policy_guard_episodes "
            "WHERE episode_id = ?",
            (episode["episode_id"],),
        ).fetchone()
        final_identity = json.loads(bytes(current_episode[0]))
        result = {
            "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
            "kind": "POLICY_GUARD_EVENT_RESULT",
            "status": "COMPLETE",
            "event_id": event_id,
            "episode_id": episode["episode_id"],
            "event_kind": event["kind"],
            "observation_sha256": sha256_bytes(canonical_json_bytes(observation_value)),
            "final_observation": final_identity,
        }
        result_bytes = canonical_json_bytes(result)
        result_sha256 = sha256_bytes(result_bytes)
        if result_sha256 != event["result_sha256"]:
            raise PolicyAuthorityError("stored policy guard result binding changed")
    _checkpoint(checkpoint, "guard-result-prepared")
    _publish_or_verify(result_path, result_bytes, "policy guard result")
    _checkpoint(checkpoint, "guard-result-published")
    try:
        connection.execute("BEGIN IMMEDIATE")
        updated = connection.execute(
            "UPDATE policy_guard_events SET state = 'COMPLETE' WHERE event_id = ? "
            "AND state IN ('GUARD_BUMPED', 'PREPARED') AND result_sha256 = ?",
            (event_id, result_sha256),
        ).rowcount
        if updated == 0:
            state = connection.execute(
                "SELECT state FROM policy_guard_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if state is None or state[0] != "COMPLETE":
                raise PolicyAuthorityError("policy guard completion CAS failed")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    return {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": event["kind"],
        "event_id": event_id,
        "episode_id": episode["episode_id"],
        "guard_epoch": event["guard_epoch"],
        "observation_path": str(observation_path),
        "observation_sha256": event["observation_sha256"],
        "result_path": str(result_path),
        "result_sha256": result_sha256,
        "state": "COMPLETE",
    }


def _observe_policy_drift(
    root: Path,
    *,
    observed_by: str,
    checkpoint: Optional[Callable[[str], None]] = None,
    captured_raw: Optional[bytes] = None,
    captured_identity: Optional[Dict[str, Any]] = None,
    expected_head: Optional[Tuple[int, str, int]] = None,
) -> Dict[str, Any]:
    """Persist one external mismatch observation before normal authority can exist."""
    canonical = _canonical_root(root)
    _require_actor(observed_by, "observed_by")
    try:
        locked = policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_SH,
            ledger_operation=fcntl.LOCK_EX,
            query_only=False,
            checkpoint=checkpoint,
        )
        with locked as connection:
            head = _head_row(connection)
            _require_idle_lane(connection)
            if captured_raw is None:
                current_raw, identity = _registry_observation(canonical)
            else:
                if not isinstance(captured_raw, bytes) or not isinstance(
                    captured_identity, dict
                ):
                    raise PolicyAuthorityError(
                        "stable policy observation raw and identity are required"
                    )
                if expected_head is None or tuple(expected_head) != (
                    head["generation"],
                    head["full_hash"],
                    head["guard_epoch"],
                ):
                    raise PolicyAuthorityError(
                        "stable policy observation head binding changed"
                    )
                try:
                    captured_compiled = policy.compile_policy(
                        captured_raw,
                        str(canonical),
                    )
                    normalized_full_hash: Optional[str] = captured_compiled.full_hash
                    compile_status = "VALID"
                except policy.PolicyError:
                    normalized_full_hash = None
                    compile_status = "INVALID"
                identity = dict(captured_identity)
                expected_identity = {
                    "path": str(canonical / "_registry" / "placement-map.yml"),
                    "raw_sha256": sha256_bytes(captured_raw),
                    "normalized_full_hash": normalized_full_hash,
                    "compile_status": compile_status,
                    "bytes": len(captured_raw),
                }
                if (
                    set(identity)
                    != {
                        "path",
                        "raw_sha256",
                        "normalized_full_hash",
                        "compile_status",
                        "bytes",
                        "device",
                        "inode",
                        "mode",
                        "uid",
                        "nlink",
                    }
                    or any(
                        identity.get(key) != value
                        for key, value in expected_identity.items()
                    )
                    or not isinstance(identity.get("device"), int)
                    or not isinstance(identity.get("inode"), int)
                    or not isinstance(identity.get("mode"), str)
                    or len(identity["mode"]) != 4
                    or any(character not in "01234567" for character in identity["mode"])
                    or identity.get("uid") != os.getuid()
                    or identity.get("nlink") != 1
                ):
                    raise PolicyAuthorityError(
                        "stable policy observation identity is invalid"
                    )
                current_raw = captured_raw
            approved_raw = verify_policy_head_source_locked(
                connection,
                canonical,
                head,
            )["raw"]
            if current_raw == approved_raw:
                raise PolicyAuthorityError("current registry matches policy head")
            nonterminal = connection.execute(
                "SELECT event_id FROM policy_guard_events "
                "WHERE state IN ('GUARD_BUMPED', 'PREPARED')"
            ).fetchone()
            if nonterminal is not None:
                return _finish_guard_event(
                    canonical,
                    connection,
                    nonterminal["event_id"],
                    checkpoint=checkpoint,
                )
            episode = connection.execute(
                "SELECT * FROM policy_guard_episodes WHERE status = 'OPEN'"
            ).fetchone()
            seed = {
                "head_generation": head["generation"],
                "head_full_hash": head["full_hash"],
                "guard_epoch": head["guard_epoch"],
                "observed_raw_sha256": identity["raw_sha256"],
            }
            digest = sha256_bytes(canonical_json_bytes(seed))
            if episode is None:
                episode_id = "pgepisode-" + digest[:24]
                event_id = "pgevent-" + digest[:24]
                event_kind = "FIRST_DRIFT"
                event_state = "GUARD_BUMPED"
                guard_epoch = head["guard_epoch"] + 1
            else:
                if (
                    episode["head_generation"] != head["generation"]
                    or episode["head_full_hash"] != head["full_hash"]
                    or episode["guard_epoch_after"] != head["guard_epoch"]
                ):
                    raise PolicyAuthorityError("open policy guard episode does not match head")
                episode_id = episode["episode_id"]
                event_id = "pgevent-" + sha256_bytes(
                    canonical_json_bytes(
                        {
                            "episode_id": episode_id,
                            "observed_raw_sha256": identity["raw_sha256"],
                            "prior_events": connection.execute(
                                "SELECT COUNT(*) FROM policy_guard_events WHERE episode_id = ?",
                                (episode_id,),
                            ).fetchone()[0],
                        }
                    )
                )[:24]
                event_kind = "OBSERVATION"
                event_state = "PREPARED"
                guard_epoch = head["guard_epoch"]
            observation_path, result_path = _guard_paths(canonical, event_id)
            synthetic_event = {
                "event_id": event_id,
                "kind": event_kind,
                "head_generation": head["generation"],
                "guard_epoch": guard_epoch,
            }
            synthetic_episode = {
                "episode_id": episode_id,
                "head_full_hash": head["full_hash"],
            }
            observation_bytes = canonical_json_bytes(
                _observation_payload(synthetic_event, synthetic_episode, identity)  # type: ignore[arg-type]
            )
            observation_sha256 = sha256_bytes(observation_bytes)
            try:
                connection.execute("BEGIN IMMEDIATE")
                if episode is None:
                    if connection.execute(
                        "UPDATE policy_head SET guard_epoch = ? WHERE id = 1 "
                        "AND generation = ? AND full_hash = ? AND guard_epoch = ?",
                        (
                            guard_epoch,
                            head["generation"],
                            head["full_hash"],
                            head["guard_epoch"],
                        ),
                    ).rowcount != 1:
                        raise PolicyAuthorityError("policy guard epoch bump CAS failed")
                    connection.execute(
                        "INSERT INTO policy_guard_episodes "
                        "(episode_id, head_generation, head_full_hash, guard_epoch_before, "
                        "guard_epoch_after, first_event_id, current_observed_identity_json, "
                        "root_execution_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'OPEN')",
                        (
                            episode_id,
                            head["generation"],
                            head["full_hash"],
                            head["guard_epoch"],
                            guard_epoch,
                            event_id,
                            canonical_json_bytes(identity),
                        ),
                    )
                else:
                    connection.execute(
                        "UPDATE policy_guard_episodes SET current_observed_identity_json = ? "
                        "WHERE episode_id = ? AND status = 'OPEN'",
                        (canonical_json_bytes(identity), episode_id),
                    )
                connection.execute(
                    "INSERT INTO policy_guard_events "
                    "(event_id, episode_id, kind, head_generation, guard_epoch, "
                    "observation_path, observation_sha256, result_path, result_sha256, state) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                    (
                        event_id,
                        episode_id,
                        event_kind,
                        head["generation"],
                        guard_epoch,
                        str(observation_path),
                        observation_sha256,
                        str(result_path),
                        event_state,
                    ),
                )
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            _checkpoint(checkpoint, "guard-bumped" if event_kind == "FIRST_DRIFT" else "guard-observation-prepared")
            return _finish_guard_event(
                canonical,
                connection,
                event_id,
                checkpoint=checkpoint,
            )
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def observe_policy_drift(
    root: Path,
    *,
    observed_by: str,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Observe the current registry under GuardService locks."""
    return _observe_policy_drift(
        root,
        observed_by=observed_by,
        checkpoint=checkpoint,
    )


def observe_policy_drift_from_stable_observation(
    root: Path,
    *,
    observed_by: str,
    observed_raw: bytes,
    observed_identity: Dict[str, Any],
    expected_head_generation: int,
    expected_head_full_hash: str,
    expected_guard_epoch: int,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Invalidate one exact admission-captured mismatch despite later ABA."""
    return _observe_policy_drift(
        root,
        observed_by=observed_by,
        checkpoint=checkpoint,
        captured_raw=observed_raw,
        captured_identity=observed_identity,
        expected_head=(
            expected_head_generation,
            expected_head_full_hash,
            expected_guard_epoch,
        ),
    )


def resume_policy_guard_event(
    root: Path,
    *,
    event_id: str,
    resumed_by: str,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    canonical = _canonical_root(root)
    _require_actor(resumed_by, "resumed_by")
    try:
        with policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_SH,
            ledger_operation=fcntl.LOCK_EX,
            query_only=False,
            checkpoint=checkpoint,
        ) as connection:
            return _finish_guard_event(
                canonical,
                connection,
                event_id,
                checkpoint=checkpoint,
            )
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def _require_no_active_policy_execution(connection: sqlite3.Connection) -> None:
    bootstrap_count = connection.execute(
        "SELECT COUNT(*) FROM policy_bootstrap_runs "
        "WHERE state IN ('CLAIMED', 'POLICY_PUBLISHED', 'BLOCKED_RECOVERY')"
    ).fetchone()[0]
    change_count = connection.execute(
        "SELECT COUNT(*) FROM policy_change_runs "
        "WHERE state IN ('CLAIMED', 'POLICY_PUBLISHED', 'NO_YAML_WRITE_VERIFIED', "
        "'BLOCKED_RECOVERY')"
    ).fetchone()[0]
    if bootstrap_count or change_count:
        raise PolicyAuthorityError("active policy execution blocks drift closure")


def _require_no_open_guard(connection: sqlite3.Connection) -> None:
    if connection.execute(
        "SELECT COUNT(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
    ).fetchone()[0]:
        raise PolicyAuthorityError("open policy guard episode blocks normal policy mutation")
    if connection.execute(
        "SELECT COUNT(*) FROM policy_guard_events "
        "WHERE state IN ('GUARD_BUMPED', 'PREPARED')"
    ).fetchone()[0]:
        raise PolicyAuthorityError("nonterminal policy guard event blocks normal policy mutation")


def _curation_removed(raw: bytes) -> bytes:
    lines = raw.splitlines(True)
    start: Optional[int] = None
    end = len(raw)
    offset = 0
    for line in lines:
        stripped = line.lstrip()
        is_top_level = line == stripped and bool(stripped.strip()) and not stripped.startswith(b"#")
        if is_top_level and stripped.startswith(b"curation:"):
            if start is not None:
                raise PolicyAuthorityError("registry has duplicate curation sections")
            start = offset
        elif start is not None and is_top_level:
            end = offset
            break
        offset += len(line)
    if start is None:
        raise PolicyAuthorityError("registry curation section is missing")
    return raw[:start] + raw[end:]


def _validate_edit_postimage(
    root: Path,
    base_raw: bytes,
    post_raw: bytes,
    base_compiled: policy.CompiledPolicy,
    post_compiled: policy.CompiledPolicy,
) -> None:
    if post_compiled.full_hash == base_compiled.full_hash:
        raise PolicyAuthorityError("policy EDIT cannot create a no-op generation")
    if post_compiled.writer_hash != base_compiled.writer_hash:
        raise PolicyAuthorityError("policy EDIT cannot change writer-control")
    if post_compiled.foundation_hash != base_compiled.foundation_hash:
        raise PolicyAuthorityError("policy EDIT cannot change curation foundation")
    try:
        base = policy.parse_strict_yaml(base_raw)
        post = policy.parse_strict_yaml(post_raw)
    except policy.PolicyError as exc:
        raise PolicyAuthorityError("policy EDIT postimage is not strict YAML") from exc
    if list(base) != list(post):
        raise PolicyAuthorityError("policy EDIT cannot reorder or replace registry sections")
    for key in base:
        if key != "curation" and base[key] != post[key]:
            raise PolicyAuthorityError("policy EDIT cannot change non-curation field: %s" % key)
    if _curation_removed(base_raw) != _curation_removed(post_raw):
        raise PolicyAuthorityError("policy EDIT must preserve all non-curation bytes")
    base_curation = base.get("curation")
    post_curation = post.get("curation")
    if not isinstance(base_curation, dict) or not isinstance(post_curation, dict):
        raise PolicyAuthorityError("policy EDIT requires curation mappings")
    if list(base_curation) != list(post_curation):
        raise PolicyAuthorityError("policy EDIT cannot reorder curation fields")
    mutable = {"scope_rules", "archive_roots"}
    for key in base_curation:
        if key not in mutable and base_curation[key] != post_curation[key]:
            raise PolicyAuthorityError("policy EDIT cannot change curation field: %s" % key)


def _change_paths(
    root: Path,
    proposal_id: str,
    run_id: str,
    approval_id: str,
) -> Dict[str, str]:
    namespace = root / "_registry" / "curation" / "policy-changes"
    staging = namespace / "runs" / (".incomplete-" + run_id)
    final = namespace / "runs" / run_id
    return {
        "proposal": str(namespace / "proposals" / proposal_id / "proposal.json"),
        "approval": str(namespace / "approvals" / (approval_id + ".json")),
        "run_staging": str(staging),
        "run_final": str(final),
        "plan_staging": str(staging / "plan.json"),
        "plan_final": str(final / "plan.json"),
        "policy_preimage": str(staging / "policy-preimage"),
        "policy_parking": str(staging / "policy-parking"),
        "policy_postimage": str(staging / "policy-postimage"),
        "result_staging": str(staging / "result.json"),
        "result_final": str(final / "result.json"),
    }


def policy_change_preview_sha256(preview: Dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(preview))


def preview_policy_change(
    root: Path,
    *,
    requested_by: str,
    postimage: bytes,
) -> Dict[str, Any]:
    """Return a write-free EDIT preview for curation-owned non-writer fields."""
    canonical = _canonical_root(root)
    actor = _require_actor(requested_by, "requested_by")
    if not isinstance(postimage, bytes):
        raise PolicyAuthorityError("postimage must be bytes")
    try:
        with policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_SH,
            ledger_operation=fcntl.LOCK_SH,
            query_only=True,
        ) as connection:
            head = _head_row(connection)
            _require_idle_lane(connection)
            _require_no_active_policy_execution(connection)
            _require_no_open_guard(connection)
            base_raw, base_identity = _registry_observation(canonical)
            try:
                base_compiled = policy.compile_policy(base_raw, str(canonical))
                post_compiled = policy.compile_policy(postimage, str(canonical))
            except policy.PolicyError as exc:
                raise PolicyAuthorityError("policy EDIT input does not compile") from exc
            if (
                base_compiled.full_hash != head["full_hash"]
                or base_compiled.writer_hash != head["writer_control_hash"]
                or base_compiled.foundation_hash != head["foundation_hash"]
            ):
                raise PolicyAuthorityError("policy EDIT base does not match current head")
            verify_current_policy_binding_locked(
                connection,
                canonical,
                base_raw,
                base_compiled,
                head,
            )
            _validate_edit_postimage(
                canonical,
                base_raw,
                postimage,
                base_compiled,
                post_compiled,
            )
            semantic = {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "mode": "EDIT",
                "requested_by": actor,
                "base_generation": head["generation"],
                "base_full_hash": head["full_hash"],
                "base_guard_epoch": head["guard_epoch"],
                "base_raw_sha256": sha256_bytes(base_raw),
                "post_raw_sha256": sha256_bytes(postimage),
                "post_full_hash": post_compiled.full_hash,
            }
            semantic_hash = sha256_bytes(canonical_json_bytes(semantic))
            proposal_id = "polchg-" + semantic_hash[:24]
            run_id = "polchgrun-" + sha256_bytes(
                canonical_json_bytes(
                    {"proposal_id": proposal_id, "post_full_hash": post_compiled.full_hash}
                )
            )[:24]
            approval_id = "polchgappr-" + sha256_bytes(
                canonical_json_bytes({"proposal_id": proposal_id, "attempt": 1})
            )[:24]
            paths = _change_paths(canonical, proposal_id, run_id, approval_id)
            return {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "kind": "POLICY_CHANGE_PREVIEW",
                "mode": "EDIT",
                "preview_id": "polchgprev-" + semantic_hash[:24],
                "proposal_id": proposal_id,
                "proposal_generation": head["generation"] + 1,
                "run_id": run_id,
                "approval_id": approval_id,
                "semantic_hash": semantic_hash,
                "requested_by": actor,
                "base": {
                    "generation": head["generation"],
                    "normalized_full_hash": head["full_hash"],
                    "raw_sha256": sha256_bytes(base_raw),
                    "guard_epoch": head["guard_epoch"],
                    "source_kind": head["source_kind"],
                    "source_run_id": head["source_run_id"],
                    "identity": base_identity,
                },
                "postimage": {
                    "raw_sha256": sha256_bytes(postimage),
                    "normalized_full_hash": post_compiled.full_hash,
                    "writer_control_hash": post_compiled.writer_hash,
                    "foundation_hash": post_compiled.foundation_hash,
                },
                "paths": paths,
                "sealed_bytes": {
                    "base_b64": base64.b64encode(base_raw).decode("ascii"),
                    "postimage_b64": base64.b64encode(postimage).decode("ascii"),
                    "normalized_full_json_b64": base64.b64encode(
                        post_compiled.full_json
                    ).decode("ascii"),
                },
                "approval_ready": True,
            }
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def _normalized_policy_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _head_raw_policy(
    connection: sqlite3.Connection,
    head: sqlite3.Row,
    root: Path,
) -> bytes:
    if head["source_kind"] == "INITIAL":
        row = connection.execute(
            "SELECT p.payload_json, p.expected_post_hash FROM policy_bootstrap_runs r "
            "JOIN policy_bootstrap_approvals a ON a.approval_id = r.approval_id "
            "JOIN policy_bootstrap_proposals p ON p.proposal_id = a.proposal_id "
            "WHERE r.run_id = ? AND r.state = 'ACTIVE' AND a.state = 'CONSUMED'",
            (head["source_run_id"],),
        ).fetchone()
        sealed_key = "postimage_b64"
        expected_hash = row["expected_post_hash"] if row is not None else None
    elif head["source_kind"] in {"EDIT", "RECONCILE"}:
        row = connection.execute(
            "SELECT p.payload_json FROM policy_change_runs r "
            "JOIN policy_change_approvals a ON a.approval_id = r.approval_id "
            "JOIN policy_change_proposals p ON p.proposal_id = a.proposal_id "
            "WHERE r.run_id = ? AND r.state = 'ACTIVE' AND a.state = 'CONSUMED'",
            (head["source_run_id"],),
        ).fetchone()
        sealed_key = "postimage_b64"
        expected_hash = None
    else:
        raise PolicyAuthorityError("policy head raw source kind is unsupported")
    if row is None:
        raise PolicyAuthorityError("policy head raw source binding is missing")
    try:
        payload = json.loads(bytes(row["payload_json"]))
        encoded = payload["sealed_bytes"][sealed_key]
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (KeyError, TypeError, UnicodeEncodeError, ValueError, json.JSONDecodeError) as exc:
        raise PolicyAuthorityError("policy head raw source bytes are invalid") from exc
    if expected_hash is not None and sha256_bytes(raw) != expected_hash:
        raise PolicyAuthorityError("policy head raw source hash changed")
    try:
        compiled = policy.compile_policy(raw, str(root))
    except policy.PolicyError as exc:
        raise PolicyAuthorityError("policy head raw source no longer compiles") from exc
    if compiled.full_hash != head["full_hash"]:
        raise PolicyAuthorityError("policy head raw source no longer matches head")
    return raw


def _mask_reconcile_owned_values(raw: bytes) -> bytes:
    lines = raw.splitlines(True)
    output = []
    in_workstreams = False
    for line in lines:
        stripped = line.lstrip()
        is_top_level = line == stripped and bool(stripped.strip()) and not stripped.startswith(b"#")
        if is_top_level:
            in_workstreams = stripped.startswith(b"workstreams:")
        if in_workstreams and (
            line.startswith(b"    lifecycle:") or line.startswith(b"    project_home:")
        ):
            newline = b"\n" if line.endswith(b"\n") else b""
            key = line.split(b":", 1)[0]
            output.append(key + b": <external-owned>" + newline)
        else:
            output.append(line)
    return b"".join(output)


def _validate_reconcile_diff(
    base: Dict[str, Any],
    observed: Dict[str, Any],
    base_raw: bytes,
    observed_raw: bytes,
) -> None:
    if _mask_reconcile_owned_values(base_raw) != _mask_reconcile_owned_values(observed_raw):
        raise PolicyAuthorityError(
            "policy RECONCILE found raw drift outside lifecycle/project_home"
        )
    if list(base) != list(observed):
        raise PolicyAuthorityError("policy RECONCILE cannot reorder registry sections")
    for key in base:
        if key != "workstreams" and base[key] != observed[key]:
            raise PolicyAuthorityError(
                "policy RECONCILE found forbidden drift in field: %s" % key
            )
    base_workstreams = base.get("workstreams")
    observed_workstreams = observed.get("workstreams")
    if not isinstance(base_workstreams, list) or not isinstance(observed_workstreams, list):
        raise PolicyAuthorityError("policy RECONCILE requires Workstream lists")
    if len(base_workstreams) != len(observed_workstreams):
        raise PolicyAuthorityError("policy RECONCILE cannot add or remove Workstreams")
    changed = False
    for index, (prior, current) in enumerate(zip(base_workstreams, observed_workstreams)):
        if not isinstance(prior, dict) or not isinstance(current, dict):
            raise PolicyAuthorityError("policy RECONCILE Workstream entry is invalid")
        if list(prior) != list(current):
            raise PolicyAuthorityError("policy RECONCILE cannot reorder Workstream fields")
        for key in prior:
            if key in {"lifecycle", "project_home"}:
                if prior[key] != current[key]:
                    changed = True
            elif prior[key] != current[key]:
                raise PolicyAuthorityError(
                    "policy RECONCILE cannot change Workstream %s at index %d"
                    % (key, index)
                )
    if not changed:
        raise PolicyAuthorityError("policy RECONCILE cannot create a no-op generation")


def _require_reconcile_episode(
    connection: sqlite3.Connection,
    head: sqlite3.Row,
    current_identity: Dict[str, Any],
) -> sqlite3.Row:
    episodes = connection.execute(
        "SELECT * FROM policy_guard_episodes WHERE status = 'OPEN'"
    ).fetchall()
    if len(episodes) != 1:
        raise PolicyAuthorityError("policy RECONCILE requires exactly one OPEN guard episode")
    episode = episodes[0]
    if (
        episode["head_generation"] != head["generation"]
        or episode["head_full_hash"] != head["full_hash"]
        or episode["guard_epoch_after"] != head["guard_epoch"]
    ):
        raise PolicyAuthorityError("policy RECONCILE guard episode does not match head")
    if connection.execute(
        "SELECT COUNT(*) FROM policy_guard_events WHERE episode_id = ? "
        "AND state IN ('GUARD_BUMPED', 'PREPARED')",
        (episode["episode_id"],),
    ).fetchone()[0]:
        raise PolicyAuthorityError("policy RECONCILE guard episode has a nonterminal event")
    stored_identity = json.loads(bytes(episode["current_observed_identity_json"]))
    if stored_identity.get("raw_sha256") != current_identity["raw_sha256"]:
        raise PolicyAuthorityError("policy RECONCILE requires a fresh guard observation")
    return episode


def preview_policy_reconcile(
    root: Path,
    *,
    requested_by: str,
    external_actor: str,
    external_workflow: str,
) -> Dict[str, Any]:
    """Seal a proven external Workstream lifecycle/project_home adoption preview."""
    canonical = _canonical_root(root)
    requester = _require_actor(requested_by, "requested_by")
    actor = _require_actor(external_actor, "external_actor")
    workflow = _require_actor(external_workflow, "external_workflow")
    try:
        with policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_SH,
            ledger_operation=fcntl.LOCK_SH,
            query_only=True,
        ) as connection:
            head = _head_row(connection)
            _require_idle_lane(connection)
            _require_no_active_policy_execution(connection)
            current_raw, current_identity = _registry_observation(canonical)
            try:
                current_compiled = policy.compile_policy(current_raw, str(canonical))
                current_object = policy.parse_strict_yaml(current_raw)
            except policy.PolicyError as exc:
                raise PolicyAuthorityError("policy RECONCILE observed registry is invalid") from exc
            if current_compiled.full_hash == head["full_hash"]:
                raise PolicyAuthorityError("policy RECONCILE cannot create a no-op generation")
            if current_compiled.writer_hash != head["writer_control_hash"]:
                raise PolicyAuthorityError("policy RECONCILE cannot adopt writer-control drift")
            if current_compiled.foundation_hash != head["foundation_hash"]:
                raise PolicyAuthorityError("policy RECONCILE cannot adopt foundation drift")
            verified_source = verify_policy_head_source_locked(
                connection,
                canonical,
                head,
            )
            base_raw = verified_source["raw"]
            try:
                base_object = policy.parse_strict_yaml(base_raw)
            except policy.PolicyError as exc:
                raise PolicyAuthorityError("policy head raw source is invalid") from exc
            try:
                snapshot_object = json.loads(
                    bytes(verified_source["snapshot"]["normalized_policy_json"])
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PolicyAuthorityError("policy head snapshot is invalid") from exc
            if _normalized_policy_json(base_object) != _normalized_policy_json(snapshot_object):
                raise PolicyAuthorityError("policy head raw source differs from immutable snapshot")
            _validate_reconcile_diff(
                base_object,
                current_object,
                base_raw,
                current_raw,
            )
            episode = _require_reconcile_episode(connection, head, current_identity)
            semantic = {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "mode": "RECONCILE",
                "requested_by": requester,
                "external_actor": actor,
                "external_workflow": workflow,
                "base_generation": head["generation"],
                "base_full_hash": head["full_hash"],
                "guard_epoch": head["guard_epoch"],
                "episode_id": episode["episode_id"],
                "observed_raw_sha256": sha256_bytes(current_raw),
                "observed_full_hash": current_compiled.full_hash,
            }
            semantic_hash = sha256_bytes(canonical_json_bytes(semantic))
            proposal_id = "polchg-" + semantic_hash[:24]
            run_id = "polchgrun-" + sha256_bytes(
                canonical_json_bytes(
                    {"proposal_id": proposal_id, "post_full_hash": current_compiled.full_hash}
                )
            )[:24]
            approval_id = "polchgappr-" + sha256_bytes(
                canonical_json_bytes({"proposal_id": proposal_id, "attempt": 1})
            )[:24]
            paths = _change_paths(canonical, proposal_id, run_id, approval_id)
            clear_seed = {
                "episode_id": episode["episode_id"],
                "proposal_id": proposal_id,
                "run_id": run_id,
                "kind": "DRIFT_CLEARED_RECONCILED",
            }
            clear_event_id = "pgevent-" + sha256_bytes(
                canonical_json_bytes(clear_seed)
            )[:24]
            clear_observation, clear_result = _guard_paths(canonical, clear_event_id)
            paths["clear_event_observation"] = str(clear_observation)
            paths["clear_event_result"] = str(clear_result)
            return {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "kind": "POLICY_CHANGE_PREVIEW",
                "mode": "RECONCILE",
                "preview_id": "polchgprev-" + semantic_hash[:24],
                "proposal_id": proposal_id,
                "proposal_generation": head["generation"] + 1,
                "run_id": run_id,
                "approval_id": approval_id,
                "semantic_hash": semantic_hash,
                "requested_by": requester,
                "base": {
                    "generation": head["generation"],
                    "normalized_full_hash": head["full_hash"],
                    "guard_epoch": head["guard_epoch"],
                    "source_kind": head["source_kind"],
                    "source_run_id": head["source_run_id"],
                },
                "postimage": {
                    "raw_sha256": sha256_bytes(current_raw),
                    "normalized_full_hash": current_compiled.full_hash,
                    "writer_control_hash": current_compiled.writer_hash,
                    "foundation_hash": current_compiled.foundation_hash,
                    "identity": current_identity,
                },
                "guard_episode": {
                    "episode_id": episode["episode_id"],
                    "first_event_id": episode["first_event_id"],
                    "head_generation": episode["head_generation"],
                    "head_full_hash": episode["head_full_hash"],
                    "guard_epoch": episode["guard_epoch_after"],
                    "clear_event_id": clear_event_id,
                },
                "external_provenance": {
                    "actor": actor,
                    "workflow": workflow,
                },
                "paths": paths,
                "sealed_bytes": {
                    "base_normalized_json_b64": base64.b64encode(
                        _normalized_policy_json(base_object)
                    ).decode("ascii"),
                    "base_raw_b64": base64.b64encode(base_raw).decode("ascii"),
                    "postimage_b64": base64.b64encode(current_raw).decode("ascii"),
                    "normalized_full_json_b64": base64.b64encode(
                        current_compiled.full_json
                    ).decode("ascii"),
                },
                "approval_ready": True,
            }
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def _proposal_payload(preview: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "POLICY_CHANGE_PROPOSAL",
        "mode": preview["mode"],
        "proposal_id": preview["proposal_id"],
        "proposal_generation": preview["proposal_generation"],
        "preview_id": preview["preview_id"],
        "preview_sha256": policy_change_preview_sha256(preview),
        "semantic_hash": preview["semantic_hash"],
        "requested_by": preview["requested_by"],
        "run_id": preview["run_id"],
        "approval_id": preview["approval_id"],
        "base": preview["base"],
        "postimage": preview["postimage"],
        "paths": preview["paths"],
        "sealed_bytes": preview["sealed_bytes"],
        "authority": "NONE_UNTIL_APPROVAL_AND_APPLY",
    }
    if preview["mode"] == "RECONCILE":
        payload["guard_episode"] = preview["guard_episode"]
        payload["external_provenance"] = preview["external_provenance"]
    return payload


def _publish_change_proposal_locked(
    connection: sqlite3.Connection,
    preview: Dict[str, Any],
    *,
    checkpoint: Optional[Callable[[str], None]],
) -> Dict[str, Any]:
    payload = _proposal_payload(preview)
    payload_bytes = canonical_json_bytes(payload)
    proposal_sha256 = sha256_bytes(payload_bytes)
    proposal_path = Path(preview["paths"]["proposal"])
    expected = (
        preview["proposal_id"],
        preview["mode"],
        preview["base"]["generation"],
        preview["base"]["normalized_full_hash"],
        preview["semantic_hash"],
        preview["proposal_generation"],
        payload_bytes,
        str(proposal_path),
        proposal_sha256,
        preview["requested_by"],
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT proposal_id, mode, base_generation, base_hash, semantic_hash, "
            "proposal_generation, payload_json, proposal_path, proposal_sha256, "
            "requested_by, state FROM policy_change_proposals WHERE proposal_id = ?",
            (preview["proposal_id"],),
        ).fetchone()
        if existing is None:
            connection.execute(
                "INSERT INTO policy_change_proposals "
                "(proposal_id, mode, base_generation, base_hash, semantic_hash, "
                "proposal_generation, payload_json, proposal_path, proposal_sha256, "
                "requested_by, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                expected,
            )
        elif tuple(existing[:10]) != expected or existing["state"] not in {
            "PREPARED",
            "PUBLISHED",
        }:
            raise PolicyAuthorityError("existing policy change proposal differs")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    _checkpoint(checkpoint, "proposal-prepared")
    _publish_or_verify(proposal_path, payload_bytes, "policy change proposal")
    _checkpoint(checkpoint, "proposal-artifact-published")
    try:
        connection.execute("BEGIN IMMEDIATE")
        updated = connection.execute(
            "UPDATE policy_change_proposals SET state = 'PUBLISHED' "
            "WHERE proposal_id = ? AND state = 'PREPARED'",
            (preview["proposal_id"],),
        ).rowcount
        if updated == 0:
            state = connection.execute(
                "SELECT state FROM policy_change_proposals WHERE proposal_id = ?",
                (preview["proposal_id"],),
            ).fetchone()
            if state is None or state[0] != "PUBLISHED":
                raise PolicyAuthorityError("policy change proposal publish CAS failed")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    _checkpoint(checkpoint, "proposal-published")
    return {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "POLICY_CHANGE_PROPOSAL",
        "mode": preview["mode"],
        "proposal_id": preview["proposal_id"],
        "proposal_sha256": proposal_sha256,
        "proposal_path": str(proposal_path),
        "run_id": preview["run_id"],
        "approval_id": preview["approval_id"],
        "payload": payload,
        "state": "PUBLISHED",
    }


def publish_policy_change_proposal(
    root: Path,
    *,
    preview: Dict[str, Any],
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    canonical = _canonical_root(root)
    if not isinstance(preview, dict) or preview.get("mode") not in {"EDIT", "RECONCILE"}:
        raise PolicyAuthorityError("policy change preview is required")
    if preview["mode"] == "EDIT":
        recomputed = preview_policy_change(
            canonical,
            requested_by=preview.get("requested_by"),
            postimage=base64.b64decode(preview["sealed_bytes"]["postimage_b64"]),
        )
    else:
        provenance = preview.get("external_provenance", {})
        recomputed = preview_policy_reconcile(
            canonical,
            requested_by=preview.get("requested_by"),
            external_actor=provenance.get("actor"),
            external_workflow=provenance.get("workflow"),
        )
    if recomputed != preview:
        raise PolicyAuthorityError("policy change preview binding changed")
    try:
        with policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_SH,
            ledger_operation=fcntl.LOCK_EX,
            query_only=False,
            checkpoint=checkpoint,
        ) as connection:
            head = _head_row(connection)
            _require_idle_lane(connection)
            current_raw, current_identity = _registry_observation(canonical)
            base = preview.get("base", {})
            postimage = preview.get("postimage", {})
            if (
                head["generation"] != base.get("generation")
                or head["full_hash"] != base.get("normalized_full_hash")
                or head["guard_epoch"] != base.get("guard_epoch")
            ):
                raise PolicyAuthorityError(
                    "policy change preview head changed before publication"
                )
            if preview["mode"] == "EDIT":
                _require_no_open_guard(connection)
                if (
                    sha256_bytes(current_raw) != base.get("raw_sha256")
                    or current_identity["normalized_full_hash"] != head["full_hash"]
                ):
                    raise PolicyAuthorityError(
                        "policy EDIT preview base changed before publication"
                    )
                try:
                    current_compiled = policy.compile_policy(
                        current_raw,
                        str(canonical),
                    )
                except policy.PolicyError as exc:
                    raise PolicyAuthorityError(
                        "policy EDIT publication base is invalid"
                    ) from exc
                verify_current_policy_binding_locked(
                    connection,
                    canonical,
                    current_raw,
                    current_compiled,
                    head,
                )
            else:
                episode = _require_reconcile_episode(
                    connection,
                    head,
                    current_identity,
                )
                guard = preview.get("guard_episode", {})
                if (
                    sha256_bytes(current_raw) != postimage.get("raw_sha256")
                    or current_identity["normalized_full_hash"]
                    != postimage.get("normalized_full_hash")
                    or guard.get("episode_id") != episode["episode_id"]
                    or guard.get("guard_epoch") != episode["guard_epoch_after"]
                ):
                    raise PolicyAuthorityError(
                        "policy RECONCILE preview changed before publication"
                    )
                verify_policy_head_source_locked(
                    connection,
                    canonical,
                    head,
                )
            return _publish_change_proposal_locked(
                connection,
                preview,
                checkpoint=checkpoint,
            )
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def _load_change_proposal(
    connection: sqlite3.Connection,
    proposal_id: str,
    proposal_sha256: Optional[str] = None,
) -> Tuple[sqlite3.Row, Dict[str, Any]]:
    row = connection.execute(
        "SELECT * FROM policy_change_proposals WHERE proposal_id = ?", (proposal_id,)
    ).fetchone()
    if row is None or row["state"] != "PUBLISHED":
        raise PolicyAuthorityError("policy change proposal is not PUBLISHED")
    raw, payload = _read_canonical_artifact(
        Path(row["proposal_path"]), "policy change proposal"
    )
    if (
        sha256_bytes(raw) != row["proposal_sha256"]
        or (proposal_sha256 is not None and proposal_sha256 != row["proposal_sha256"])
        or canonical_json_bytes(payload) != bytes(row["payload_json"])
        or payload.get("proposal_id") != proposal_id
        or payload.get("mode") != row["mode"]
    ):
        raise PolicyAuthorityError("policy change proposal binding changed")
    return row, payload


def approve_policy_change(
    root: Path,
    *,
    proposal_id: str,
    proposal_sha256: str,
    approved_by: str,
    required_sealed_mode: Optional[str] = None,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    canonical = _canonical_root(root)
    actor = _require_actor(approved_by, "approved_by")
    required_mode = _required_sealed_mode(required_sealed_mode)
    try:
        with policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_SH,
            ledger_operation=fcntl.LOCK_EX,
            query_only=False,
            checkpoint=checkpoint,
        ) as connection:
            proposal, payload = _load_change_proposal(
                connection, proposal_id, proposal_sha256
            )
            mode = proposal["mode"]
            if mode not in {"EDIT", "RECONCILE"}:
                raise PolicyAuthorityError("unsupported policy change mode")
            if required_mode is not None and mode != required_mode:
                raise PolicyAuthorityError(
                    "sealed policy change mode does not match required mode"
                )
            head = _head_row(connection)
            _require_no_active_policy_execution(connection)
            current_raw, identity = _registry_observation(canonical)
            if mode == "EDIT":
                _require_no_open_guard(connection)
                if (
                    head["generation"] != proposal["base_generation"]
                    or head["full_hash"] != proposal["base_hash"]
                    or identity["normalized_full_hash"] != head["full_hash"]
                    or sha256_bytes(current_raw) != payload["base"]["raw_sha256"]
                    or head["guard_epoch"] != payload["base"]["guard_epoch"]
                ):
                    raise PolicyAuthorityError("policy change approval base changed")
                try:
                    current_compiled = policy.compile_policy(
                        current_raw,
                        str(canonical),
                    )
                except policy.PolicyError as exc:
                    raise PolicyAuthorityError(
                        "policy change approval base is invalid"
                    ) from exc
                verify_current_policy_binding_locked(
                    connection,
                    canonical,
                    current_raw,
                    current_compiled,
                    head,
                )
                owner_kind = "POLICY_EDIT"
            else:
                episode = _require_reconcile_episode(connection, head, identity)
                guard = payload.get("guard_episode", {})
                if (
                    head["generation"] != proposal["base_generation"]
                    or head["full_hash"] != proposal["base_hash"]
                    or head["guard_epoch"] != payload["base"]["guard_epoch"]
                    or identity["normalized_full_hash"]
                    != payload["postimage"]["normalized_full_hash"]
                    or sha256_bytes(current_raw) != payload["postimage"]["raw_sha256"]
                    or guard.get("episode_id") != episode["episode_id"]
                    or guard.get("guard_epoch") != episode["guard_epoch_after"]
                    or guard.get("first_event_id") != episode["first_event_id"]
                ):
                    raise PolicyAuthorityError("policy RECONCILE approval binding changed")
                verify_policy_head_source_locked(
                    connection,
                    canonical,
                    head,
                )
                owner_kind = "POLICY_RECONCILE"
            approval_id = payload["approval_id"]
            export_path = Path(payload["paths"]["approval"])
            approval_payload = {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "kind": "POLICY_CHANGE_APPROVAL",
                "mode": mode,
                "approval_id": approval_id,
                "proposal_id": proposal_id,
                "proposal_sha256": proposal_sha256,
                "attempt": 1,
                "approved_by": actor,
                "run_id": payload["run_id"],
                "base": payload["base"],
                "postimage": payload["postimage"],
                "paths": payload["paths"],
            }
            if mode == "RECONCILE":
                approval_payload["guard_episode"] = payload["guard_episode"]
                approval_payload["external_provenance"] = payload[
                    "external_provenance"
                ]
            export_bytes = canonical_json_bytes(approval_payload)
            export_sha256 = sha256_bytes(export_bytes)
            existing = connection.execute(
                "SELECT * FROM policy_change_approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if existing is None:
                _require_idle_lane(connection)
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "INSERT INTO policy_change_approvals "
                        "(approval_id, proposal_id, mode, attempt, approved_by, export_path, "
                        "export_sha256, state) VALUES (?, ?, ?, 1, ?, ?, ?, 'PREPARED')",
                        (
                            approval_id,
                            proposal_id,
                            mode,
                            actor,
                            str(export_path),
                            export_sha256,
                        ),
                    )
                    lane = connection.execute(
                        "SELECT generation FROM policy_mutation_lane "
                        "WHERE id = 1 AND state = 'IDLE'"
                    ).fetchone()
                    if lane is None or connection.execute(
                        "UPDATE policy_mutation_lane SET generation = ?, state = 'RESERVED', "
                        "owner_kind = ?, owner_proposal_id = ?, owner_approval_id = ? "
                        "WHERE id = 1 AND generation = ? AND state = 'IDLE'",
                        (lane[0] + 1, owner_kind, proposal_id, approval_id, lane[0]),
                    ).rowcount != 1:
                        raise PolicyAuthorityError(
                            "policy %s lane reservation failed" % mode
                        )
                    connection.commit()
                except Exception:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
            else:
                expected_existing = (
                    approval_id,
                    proposal_id,
                    mode,
                    1,
                    actor,
                    str(export_path),
                    export_sha256,
                )
                if tuple(existing[:7]) != expected_existing or existing["state"] not in {
                    "PREPARED",
                    "PUBLISHED",
                }:
                    raise PolicyAuthorityError(
                        "existing policy change approval differs"
                    )
                lane = connection.execute(
                    "SELECT state, owner_kind, owner_proposal_id, owner_approval_id, "
                    "owner_run_id, owner_process_id FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()
                if lane is None or tuple(lane) != (
                    "RESERVED",
                    owner_kind,
                    proposal_id,
                    approval_id,
                    None,
                    None,
                ):
                    raise PolicyAuthorityError(
                        "existing policy change approval lane differs"
                    )
                if connection.execute(
                    "SELECT COUNT(*) FROM policy_change_runs WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()[0]:
                    raise PolicyAuthorityError(
                        "existing policy change approval already has a run"
                    )
            _checkpoint(checkpoint, "approval-prepared")
            _publish_or_verify(export_path, export_bytes, "policy change approval")
            _checkpoint(checkpoint, "approval-artifact-published")
            try:
                connection.execute("BEGIN IMMEDIATE")
                updated = connection.execute(
                    "UPDATE policy_change_approvals SET state = 'PUBLISHED' "
                    "WHERE approval_id = ? AND state = 'PREPARED'",
                    (approval_id,),
                ).rowcount
                if updated == 0:
                    state = connection.execute(
                        "SELECT state FROM policy_change_approvals WHERE approval_id = ?",
                        (approval_id,),
                    ).fetchone()
                    if state is None or state[0] != "PUBLISHED":
                        raise PolicyAuthorityError(
                            "policy change approval publish CAS failed"
                        )
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            _checkpoint(checkpoint, "approval-published")
            return {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "kind": "POLICY_CHANGE_APPROVAL",
                "mode": mode,
                "approval_id": approval_id,
                "export_path": str(export_path),
                "export_sha256": export_sha256,
                "proposal_id": proposal_id,
                "run_id": payload["run_id"],
                "payload": approval_payload,
                "state": "PUBLISHED",
            }
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def _load_change_approval(
    connection: sqlite3.Connection,
    approval_id: str,
    approval_sha256: str,
) -> Tuple[sqlite3.Row, Dict[str, Any]]:
    row = connection.execute(
        "SELECT * FROM policy_change_approvals WHERE approval_id = ?", (approval_id,)
    ).fetchone()
    if row is None or row["state"] != "PUBLISHED":
        raise PolicyAuthorityError("policy change approval is not PUBLISHED")
    raw, payload = _read_canonical_artifact(
        Path(row["export_path"]), "policy change approval"
    )
    if (
        sha256_bytes(raw) != row["export_sha256"]
        or approval_sha256 != row["export_sha256"]
        or payload.get("approval_id") != approval_id
        or payload.get("proposal_id") != row["proposal_id"]
        or payload.get("mode") != row["mode"]
        or payload.get("approved_by") != row["approved_by"]
    ):
        raise PolicyAuthorityError("policy change approval binding changed")
    return row, payload


def _decode_sealed(value: Any, expected_hash: str, label: str) -> bytes:
    if not isinstance(value, str):
        raise PolicyAuthorityError("%s sealed bytes are missing" % label)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise PolicyAuthorityError("%s sealed bytes are invalid" % label) from exc
    if sha256_bytes(raw) != expected_hash:
        raise PolicyAuthorityError("%s sealed bytes changed" % label)
    return raw


def _decode_exact_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise PolicyAuthorityError("%s sealed bytes are missing" % label)
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise PolicyAuthorityError("%s sealed bytes are invalid" % label) from exc


def _verify_terminal_change_run_locked(
    connection: sqlite3.Connection,
    root: Path,
    run_id: str,
) -> Dict[str, Any]:
    """Verify one immutable EDIT/RECONCILE receipt without acquiring locks."""
    run = connection.execute(
        "SELECT * FROM policy_change_runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if (
        run is None
        or run["state"] != "ACTIVE"
        or run["mode"] not in {"EDIT", "RECONCILE"}
        or not isinstance(run["result_sha256"], str)
        or len(run["result_sha256"]) != 64
    ):
        raise PolicyAuthorityError("terminal policy change run is invalid")
    mode = run["mode"]
    approval = connection.execute(
        "SELECT * FROM policy_change_approvals WHERE approval_id = ?",
        (run["approval_id"],),
    ).fetchone()
    if (
        approval is None
        or approval["state"] != "CONSUMED"
        or approval["mode"] != mode
        or approval["attempt"] != 1
    ):
        raise PolicyAuthorityError("terminal policy change approval is invalid")
    proposal = connection.execute(
        "SELECT * FROM policy_change_proposals WHERE proposal_id = ?",
        (approval["proposal_id"],),
    ).fetchone()
    if (
        proposal is None
        or proposal["state"] != "PUBLISHED"
        or proposal["mode"] != mode
        or proposal["proposal_generation"] != proposal["base_generation"] + 1
    ):
        raise PolicyAuthorityError("terminal policy change proposal is invalid")

    proposal_raw, proposal_payload = _read_canonical_artifact(
        Path(proposal["proposal_path"]),
        "terminal policy change proposal",
    )
    if (
        sha256_bytes(proposal_raw) != proposal["proposal_sha256"]
        or proposal_raw != bytes(proposal["payload_json"])
        or proposal_payload.get("schema_version") != POLICY_AUTHORITY_SCHEMA_VERSION
        or proposal_payload.get("kind") != "POLICY_CHANGE_PROPOSAL"
        or proposal_payload.get("mode") != mode
        or proposal_payload.get("proposal_id") != proposal["proposal_id"]
        or proposal_payload.get("proposal_generation")
        != proposal["proposal_generation"]
        or proposal_payload.get("semantic_hash") != proposal["semantic_hash"]
        or proposal_payload.get("requested_by") != proposal["requested_by"]
        or proposal_payload.get("run_id") != run_id
        or proposal_payload.get("approval_id") != approval["approval_id"]
        or proposal_payload.get("authority") != "NONE_UNTIL_APPROVAL_AND_APPLY"
    ):
        raise PolicyAuthorityError("terminal policy change proposal binding changed")
    expected_proposal_keys = {
        "schema_version",
        "kind",
        "mode",
        "proposal_id",
        "proposal_generation",
        "preview_id",
        "preview_sha256",
        "semantic_hash",
        "requested_by",
        "run_id",
        "approval_id",
        "base",
        "postimage",
        "paths",
        "sealed_bytes",
        "authority",
    }
    if mode == "RECONCILE":
        expected_proposal_keys.update({"guard_episode", "external_provenance"})
    if set(proposal_payload) != expected_proposal_keys:
        raise PolicyAuthorityError("terminal policy change proposal shape changed")
    base = proposal_payload.get("base")
    postimage = proposal_payload.get("postimage")
    paths = proposal_payload.get("paths")
    sealed = proposal_payload.get("sealed_bytes")
    if not all(isinstance(value, dict) for value in (base, postimage, paths, sealed)):
        raise PolicyAuthorityError("terminal policy change proposal payload is invalid")
    if (
        base.get("generation") != proposal["base_generation"]
        or base.get("normalized_full_hash") != proposal["base_hash"]
    ):
        raise PolicyAuthorityError("terminal policy change proposal base changed")
    expected_paths = _change_paths(
        root,
        proposal["proposal_id"],
        run_id,
        approval["approval_id"],
    )
    if mode == "RECONCILE":
        guard = proposal_payload.get("guard_episode")
        if not isinstance(guard, dict):
            raise PolicyAuthorityError("terminal RECONCILE guard binding is missing")
        clear_event_id = guard.get("clear_event_id")
        if not isinstance(clear_event_id, str) or not clear_event_id:
            raise PolicyAuthorityError("terminal RECONCILE clear event is invalid")
        clear_observation, clear_result = _guard_paths(root, clear_event_id)
        expected_paths["clear_event_observation"] = str(clear_observation)
        expected_paths["clear_event_result"] = str(clear_result)
    if paths != expected_paths or proposal["proposal_path"] != paths["proposal"]:
        raise PolicyAuthorityError("terminal policy change paths changed")
    if run["result_path"] != paths["result_final"]:
        raise PolicyAuthorityError("terminal policy change result path changed")
    if os.path.lexists(Path(paths["run_staging"])):
        raise PolicyAuthorityError("terminal policy change has a staging collision")

    post_raw = _decode_sealed(
        sealed.get("postimage_b64"),
        postimage.get("raw_sha256"),
        "terminal policy change postimage",
    )
    try:
        post_compiled = policy.compile_policy(post_raw, str(root))
    except policy.PolicyError as exc:
        raise PolicyAuthorityError("terminal policy change postimage is invalid") from exc
    normalized_raw = _decode_exact_base64(
        sealed.get("normalized_full_json_b64"),
        "terminal policy normalized projection",
    )
    if (
        normalized_raw != post_compiled.full_json
        or postimage.get("normalized_full_hash") != post_compiled.full_hash
        or postimage.get("writer_control_hash") != post_compiled.writer_hash
        or postimage.get("foundation_hash") != post_compiled.foundation_hash
    ):
        raise PolicyAuthorityError("terminal policy change postimage projection changed")
    if mode == "EDIT":
        base_raw = _decode_sealed(
            sealed.get("base_b64"),
            base.get("raw_sha256"),
            "terminal EDIT preimage",
        )
    else:
        base_raw = _decode_exact_base64(
            sealed.get("base_raw_b64"),
            "terminal RECONCILE preimage",
        )
    try:
        base_compiled = policy.compile_policy(base_raw, str(root))
    except policy.PolicyError as exc:
        raise PolicyAuthorityError("terminal policy change preimage is invalid") from exc
    if base_compiled.full_hash != proposal["base_hash"]:
        raise PolicyAuthorityError("terminal policy change preimage binding changed")
    if mode == "RECONCILE" and _decode_exact_base64(
        sealed.get("base_normalized_json_b64"),
        "terminal RECONCILE base projection",
    ) != base_compiled.full_json:
        raise PolicyAuthorityError("terminal RECONCILE base projection changed")

    approval_raw, approval_payload = _read_canonical_artifact(
        Path(approval["export_path"]),
        "consumed terminal policy change approval",
    )
    expected_approval = {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "POLICY_CHANGE_APPROVAL",
        "mode": mode,
        "approval_id": approval["approval_id"],
        "proposal_id": proposal["proposal_id"],
        "proposal_sha256": proposal["proposal_sha256"],
        "attempt": 1,
        "approved_by": approval["approved_by"],
        "run_id": run_id,
        "base": base,
        "postimage": postimage,
        "paths": paths,
    }
    if mode == "RECONCILE":
        expected_approval["guard_episode"] = proposal_payload["guard_episode"]
        expected_approval["external_provenance"] = proposal_payload[
            "external_provenance"
        ]
    if (
        sha256_bytes(approval_raw) != approval["export_sha256"]
        or approval_payload != expected_approval
    ):
        raise PolicyAuthorityError("consumed policy change approval binding changed")

    snapshots = connection.execute(
        "SELECT * FROM policy_snapshots WHERE source_run_id = ?",
        (run_id,),
    ).fetchall()
    if len(snapshots) != 1:
        raise PolicyAuthorityError("terminal policy change snapshot is missing")
    snapshot = snapshots[0]
    expected_snapshot_id = "policy-%08d-%s" % (
        proposal["proposal_generation"],
        post_compiled.full_hash[:24],
    )
    if (
        snapshot["snapshot_id"] != expected_snapshot_id
        or snapshot["full_hash"] != post_compiled.full_hash
        or snapshot["writer_control_hash"] != post_compiled.writer_hash
        or snapshot["foundation_hash"] != post_compiled.foundation_hash
        or bytes(snapshot["normalized_policy_json"]) != post_compiled.full_json
        or snapshot["source_kind"] != mode
        or snapshot["source_run_id"] != run_id
        or snapshot["source_state"] != "TERMINAL"
    ):
        raise PolicyAuthorityError("terminal policy change snapshot binding changed")

    result_raw, result = _read_canonical_artifact(
        Path(run["result_path"]),
        "terminal policy change result",
    )
    run_final = Path(paths["run_final"])
    result_paths = {
        "registry": str(root / "_registry" / "placement-map.yml"),
        "run": str(run_final),
        "result": paths["result_final"],
        "plan": paths["plan_final"],
    }
    if mode == "EDIT":
        result_paths.update(
            {
                "policy_preimage": str(run_final / "policy-preimage"),
                "policy_parking": str(run_final / "policy-parking"),
                "policy_postimage": str(run_final / "policy-postimage"),
            }
        )
    else:
        result_paths.update(
            {
                "clear_event_observation": paths["clear_event_observation"],
                "clear_event_result": paths["clear_event_result"],
            }
        )
    expected_result = {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "POLICY_CHANGE_RESULT",
        "status": "COMPLETE",
        "source_kind": mode,
        "generation": proposal["proposal_generation"],
        "guard_epoch": base["guard_epoch"],
        "proposal_id": proposal["proposal_id"],
        "proposal_sha256": proposal["proposal_sha256"],
        "approval_id": approval["approval_id"],
        "approval_sha256": approval["export_sha256"],
        "run_id": run_id,
        "process_instance_id": run["process_instance_id"],
        "requested_by": proposal["requested_by"],
        "approved_by": approval["approved_by"],
        "executed_by": run["executed_by"],
        "raw_hash": post_compiled.raw_hash,
        "normalized_full_hash": post_compiled.full_hash,
        "writer_control_hash": post_compiled.writer_hash,
        "foundation_hash": post_compiled.foundation_hash,
        "policy_snapshot_id": snapshot["snapshot_id"],
        "paths": result_paths,
    }
    if mode == "RECONCILE":
        guard = proposal_payload["guard_episode"]
        expected_result.update(
            {
                "external_provenance": proposal_payload["external_provenance"],
                "guard_episode_id": guard["episode_id"],
                "clear_event_id": guard["clear_event_id"],
                "yaml_write_effects": 0,
            }
        )
    if sha256_bytes(result_raw) != run["result_sha256"] or result != expected_result:
        raise PolicyAuthorityError("terminal policy change result binding changed")

    expected_plan = {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "POLICY_CHANGE_PLAN",
        "mode": mode,
        "proposal_id": proposal["proposal_id"],
        "proposal_sha256": proposal["proposal_sha256"],
        "approval_id": approval["approval_id"],
        "approval_sha256": approval["export_sha256"],
        "run_id": run_id,
        "process_instance_id": run["process_instance_id"],
        "executed_by": run["executed_by"],
        "base": base,
        "postimage": postimage,
        "paths": paths,
    }
    if mode == "RECONCILE":
        expected_plan.update(
            {
                "guard_episode": proposal_payload["guard_episode"],
                "external_provenance": proposal_payload["external_provenance"],
                "yaml_write_effects": 0,
            }
        )
    plan_bytes = canonical_json_bytes(expected_plan)
    expected_members = {
        "plan.json": (sha256_bytes(plan_bytes), 0o600),
        "result.json": (run["result_sha256"], 0o600),
    }
    if mode == "EDIT":
        base_identity = base.get("identity")
        mode_text = (
            base_identity.get("mode") if isinstance(base_identity, dict) else None
        )
        if (
            not isinstance(mode_text, str)
            or len(mode_text) != 4
            or any(character not in "01234567" for character in mode_text)
        ):
            raise PolicyAuthorityError("terminal EDIT preimage mode is invalid")
        expected_members.update(
            {
                "policy-preimage": (sha256_bytes(base_raw), 0o600),
                "policy-parking": (sha256_bytes(base_raw), int(mode_text, 8)),
                "policy-postimage": (sha256_bytes(post_raw), 0o600),
            }
        )
    try:
        members = policy_state.verify_sealed_run_directory(
            run_final,
            expected_members,
            source_kind=mode,
        )
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc
    if members["plan.json"] != plan_bytes or members["result.json"] != result_raw:
        raise PolicyAuthorityError("terminal policy change sealed members changed")
    if mode == "EDIT" and (
        members["policy-preimage"] != base_raw
        or members["policy-parking"] != base_raw
        or members["policy-postimage"] != post_raw
    ):
        raise PolicyAuthorityError("terminal EDIT policy evidence changed")

    if mode == "RECONCILE":
        guard = proposal_payload["guard_episode"]
        episode = connection.execute(
            "SELECT * FROM policy_guard_episodes WHERE episode_id = ?",
            (guard["episode_id"],),
        ).fetchone()
        clear_event = connection.execute(
            "SELECT * FROM policy_guard_events WHERE event_id = ?",
            (guard["clear_event_id"],),
        ).fetchone()
        expected_clear_event_id = "pgevent-" + sha256_bytes(
            canonical_json_bytes(
                {
                    "episode_id": guard["episode_id"],
                    "proposal_id": proposal["proposal_id"],
                    "run_id": run_id,
                    "kind": "DRIFT_CLEARED_RECONCILED",
                }
            )
        )[:24]
        if (
            guard.get("head_generation") != base["generation"]
            or guard.get("head_full_hash") != base["normalized_full_hash"]
            or guard.get("guard_epoch") != base["guard_epoch"]
            or guard.get("clear_event_id") != expected_clear_event_id
            or episode is None
            or episode["status"] != "CLEARED_RECONCILED"
            or episode["head_generation"] != base["generation"]
            or episode["head_full_hash"] != base["normalized_full_hash"]
            or episode["guard_epoch_after"] != base["guard_epoch"]
            or episode["first_event_id"] != guard.get("first_event_id")
            or bytes(episode["current_observed_identity_json"])
            != canonical_json_bytes(postimage["identity"])
            or clear_event is None
            or clear_event["episode_id"] != episode["episode_id"]
            or clear_event["kind"] != "DRIFT_CLEARED_RECONCILED"
            or clear_event["state"] != "COMPLETE"
            or clear_event["head_generation"] != base["generation"]
            or clear_event["guard_epoch"] != base["guard_epoch"]
            or clear_event["observation_path"] != paths["clear_event_observation"]
            or clear_event["result_path"] != paths["clear_event_result"]
        ):
            raise PolicyAuthorityError("terminal RECONCILE guard binding changed")
        clear_observation_raw, clear_observation = _read_canonical_artifact(
            Path(clear_event["observation_path"]),
            "terminal RECONCILE clear observation",
        )
        expected_clear_observation = {
            "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
            "kind": "DRIFT_CLEARED_RECONCILED",
            "event_id": clear_event["event_id"],
            "episode_id": episode["episode_id"],
            "head": {
                "generation": base["generation"],
                "full_hash": base["normalized_full_hash"],
                "guard_epoch": base["guard_epoch"],
            },
            "proposal_id": proposal["proposal_id"],
            "approval_id": approval["approval_id"],
            "run_id": run_id,
            "observed_policy": postimage["identity"],
            "external_provenance": proposal_payload["external_provenance"],
        }
        clear_result_raw, clear_result = _read_canonical_artifact(
            Path(clear_event["result_path"]),
            "terminal RECONCILE clear result",
        )
        expected_clear_result = {
            "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
            "kind": "POLICY_GUARD_EVENT_RESULT",
            "status": "COMPLETE",
            "event_id": clear_event["event_id"],
            "episode_id": episode["episode_id"],
            "event_kind": "DRIFT_CLEARED_RECONCILED",
            "observation_sha256": sha256_bytes(clear_observation_raw),
            "adopted_normalized_full_hash": post_compiled.full_hash,
        }
        if (
            clear_observation != expected_clear_observation
            or sha256_bytes(clear_observation_raw) != clear_event["observation_sha256"]
            or clear_result != expected_clear_result
            or sha256_bytes(clear_result_raw) != clear_event["result_sha256"]
        ):
            raise PolicyAuthorityError("terminal RECONCILE clear artifacts changed")

    return {
        "mode": mode,
        "run": run,
        "approval": approval,
        "proposal": proposal,
        "snapshot": snapshot,
        "raw": post_raw,
        "compiled": post_compiled,
        "result": result,
        "result_path": run["result_path"],
        "result_sha256": run["result_sha256"],
    }


def verify_terminal_policy_source_locked(
    connection: sqlite3.Connection,
    root: Path,
    registry_raw: bytes,
    compiled: policy.CompiledPolicy,
    head: sqlite3.Row,
    snapshot: sqlite3.Row,
) -> Dict[str, Any]:
    """Verify the current EDIT/RECONCILE source under caller-held SH locks."""
    if head["source_kind"] not in {"EDIT", "RECONCILE"}:
        raise PolicyAuthorityError("terminal source is not EDIT or RECONCILE")
    verified = _verify_terminal_change_run_locked(
        connection,
        root,
        head["source_run_id"],
    )
    verified_snapshot = verified["snapshot"]
    result = verified["result"]
    if (
        registry_raw != verified["raw"]
        or compiled.raw_hash != sha256_bytes(registry_raw)
        or compiled.full_json != verified["compiled"].full_json
        or compiled.full_hash != verified["compiled"].full_hash
        or compiled.writer_hash != verified["compiled"].writer_hash
        or compiled.foundation_hash != verified["compiled"].foundation_hash
        or head["generation"] != result["generation"]
        or head["full_hash"] != compiled.full_hash
        or head["writer_control_hash"] != compiled.writer_hash
        or head["foundation_hash"] != compiled.foundation_hash
        or head["source_kind"] != verified["mode"]
        or head["source_run_id"] != verified["run"]["run_id"]
        or head["guard_epoch"] < result["guard_epoch"]
    ):
        raise PolicyAuthorityError("current terminal policy source binding changed")
    snapshot_fields = (
        "snapshot_id",
        "full_hash",
        "writer_control_hash",
        "foundation_hash",
        "normalized_policy_json",
        "source_kind",
        "source_run_id",
        "source_state",
    )
    if any(snapshot[field] != verified_snapshot[field] for field in snapshot_fields):
        raise PolicyAuthorityError("current terminal policy snapshot changed")
    return {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "VERIFIED_TERMINAL_POLICY_SOURCE",
        "approved_policy_ref": {
            "generation": head["generation"],
            "full_hash": head["full_hash"],
            "source_kind": head["source_kind"],
            "source_run_id": head["source_run_id"],
        },
        "guard_epoch": head["guard_epoch"],
        "raw_hash": compiled.raw_hash,
        "writer_control_hash": compiled.writer_hash,
        "foundation_hash": compiled.foundation_hash,
        "source_result": {
            "path": verified["result_path"],
            "sha256": verified["result_sha256"],
        },
        "result": result,
    }


def _verify_activation_initial_policy_source_locked(
    connection: sqlite3.Connection,
    root: Path,
    head: sqlite3.Row,
    snapshot: sqlite3.Row,
    source: ActivationInitialPolicySource,
) -> Dict[str, Any]:
    """Verify the one direct-V2 activation source without legacy bootstrap rows."""

    if type(source) is not ActivationInitialPolicySource:
        raise PolicyAuthorityError("activation INITIAL source is invalid")
    plan = source.plan
    if type(plan) is not activation_foundation.ActivationFoundationPlan:
        raise PolicyAuthorityError("activation INITIAL source is invalid")
    try:
        rebuilt = activation_foundation.build_activation_foundation(
            plan.registry_bytes,
            plan.raw_root,
            plan.activation_id,
        )
    except (TypeError, ValueError) as exc:
        raise PolicyAuthorityError("activation INITIAL source is invalid") from exc
    expected_receipt_path = root / "_registry" / "curation" / "activation" / "v1" / "receipt.json"
    if (
        rebuilt != plan
        or plan.raw_root != str(root)
        or source.receipt_path != expected_receipt_path
        or not isinstance(source.receipt_sha256, str)
        or len(source.receipt_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source.receipt_sha256)
    ):
        raise PolicyAuthorityError("activation INITIAL source is invalid")

    identity = plan.initial_policy
    expected_head = (
        1,
        1,
        identity.full_hash,
        identity.writer_control_hash,
        identity.foundation_hash,
        "INITIAL",
        plan.activation_id,
        0,
    )
    head_fields = (
        "id",
        "generation",
        "full_hash",
        "writer_control_hash",
        "foundation_hash",
        "source_kind",
        "source_run_id",
        "guard_epoch",
    )
    expected_snapshot = (
        plan.snapshot_id,
        identity.full_hash,
        identity.writer_control_hash,
        identity.foundation_hash,
        plan.compiled_policy.full_json,
        "INITIAL",
        plan.activation_id,
        "TERMINAL",
    )
    snapshot_fields = (
        "snapshot_id",
        "full_hash",
        "writer_control_hash",
        "foundation_hash",
        "normalized_policy_json",
        "source_kind",
        "source_run_id",
        "source_state",
    )
    if (
        tuple(head[field] for field in head_fields) != expected_head
        or tuple(snapshot[field] for field in snapshot_fields) != expected_snapshot
    ):
        raise PolicyAuthorityError("activation INITIAL policy binding changed")

    result = {
        "generation": 1,
        "guard_epoch": 0,
        "source_kind": "INITIAL",
        "source_run_id": plan.activation_id,
    }
    return {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "VERIFIED_TERMINAL_POLICY_SOURCE",
        "approved_policy_ref": {
            "generation": 1,
            "full_hash": identity.full_hash,
            "source_kind": "INITIAL",
            "source_run_id": plan.activation_id,
        },
        "guard_epoch": 0,
        "raw_hash": plan.compiled_policy.raw_hash,
        "writer_control_hash": identity.writer_control_hash,
        "foundation_hash": identity.foundation_hash,
        "source_result": {
            "path": str(source.receipt_path),
            "sha256": source.receipt_sha256,
        },
        "raw": plan.effective_policy_bytes,
        "compiled": plan.compiled_policy,
        "snapshot": snapshot,
        "result": result,
    }


def verify_policy_head_source_locked(
    connection: sqlite3.Connection,
    root: Path,
    head: sqlite3.Row,
    *,
    expected_initial_bootstrap_id: Optional[str] = None,
    activation_initial_source: Optional[ActivationInitialPolicySource] = None,
) -> Dict[str, Any]:
    """Verify the immutable terminal source selected by the current head."""
    snapshot = _snapshot_for_head(connection, head)
    if head["source_kind"] == "INITIAL":
        if activation_initial_source is not None:
            if expected_initial_bootstrap_id is not None:
                raise PolicyAuthorityError("INITIAL source variants cannot co-present")
            return _verify_activation_initial_policy_source_locked(
                connection,
                root,
                head,
                snapshot,
                activation_initial_source,
            )
        try:
            initial = policy_state.verify_initial_policy_source_locked(
                connection,
                root,
                head,
                expected_bootstrap_id=expected_initial_bootstrap_id,
            )
        except policy_state.PolicyStateError as exc:
            raise PolicyAuthorityError(str(exc)) from exc
        result = initial["result"]
        if head["guard_epoch"] < result["guard_epoch"]:
            raise PolicyAuthorityError("current INITIAL guard epoch is invalid")
        return {
            "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
            "kind": "VERIFIED_TERMINAL_POLICY_SOURCE",
            "approved_policy_ref": {
                "generation": head["generation"],
                "full_hash": head["full_hash"],
                "source_kind": head["source_kind"],
                "source_run_id": head["source_run_id"],
            },
            "guard_epoch": head["guard_epoch"],
            "raw_hash": initial["compiled"].raw_hash,
            "writer_control_hash": initial["compiled"].writer_hash,
            "foundation_hash": initial["compiled"].foundation_hash,
            "source_result": {
                "path": initial["result_path"],
                "sha256": initial["result_sha256"],
            },
            "raw": initial["raw"],
            "compiled": initial["compiled"],
            "snapshot": initial["snapshot"],
            "result": result,
        }
    if head["source_kind"] not in {"EDIT", "RECONCILE"}:
        raise PolicyAuthorityError(
            "terminal source contract is unavailable for %s" % head["source_kind"]
        )
    approved_raw = _head_raw_policy(connection, head, root)
    try:
        approved_compiled = policy.compile_policy(approved_raw, str(root))
    except policy.PolicyError as exc:
        raise PolicyAuthorityError("policy head raw source no longer compiles") from exc
    verified = verify_terminal_policy_source_locked(
        connection,
        root,
        approved_raw,
        approved_compiled,
        head,
        snapshot,
    )
    verified["raw"] = approved_raw
    verified["compiled"] = approved_compiled
    verified["snapshot"] = snapshot
    return verified


def verify_current_policy_binding_locked(
    connection: sqlite3.Connection,
    root: Path,
    registry_raw: bytes,
    compiled: policy.CompiledPolicy,
    head: sqlite3.Row,
    *,
    expected_initial_bootstrap_id: Optional[str] = None,
    activation_initial_source: Optional[ActivationInitialPolicySource] = None,
) -> Dict[str, Any]:
    """Bind live registry bytes to one exact immutable terminal head source."""
    verified = verify_policy_head_source_locked(
        connection,
        root,
        head,
        expected_initial_bootstrap_id=expected_initial_bootstrap_id,
        activation_initial_source=activation_initial_source,
    )
    source_compiled = verified["compiled"]
    expected_registry_raw = (
        activation_initial_source.plan.registry_bytes
        if activation_initial_source is not None
        else verified["raw"]
    )
    if (
        registry_raw != expected_registry_raw
        or (
            activation_initial_source is None
            and compiled.raw_hash != sha256_bytes(registry_raw)
        )
        or compiled.full_json != source_compiled.full_json
        or compiled.full_hash != source_compiled.full_hash
        or compiled.writer_hash != source_compiled.writer_hash
        or compiled.foundation_hash != source_compiled.foundation_hash
        or head["full_hash"] != compiled.full_hash
        or head["writer_control_hash"] != compiled.writer_hash
        or head["foundation_hash"] != compiled.foundation_hash
    ):
        raise PolicyAuthorityError(
            "current registry does not match exact terminal policy source"
        )
    return verified


def _terminal_policy_change_retry_locked(
    connection: sqlite3.Connection,
    root: Path,
    *,
    approval_id: str,
    approval_sha256: str,
    executed_by: str,
    process_instance_id: str,
    required_sealed_mode: Optional[str],
) -> Optional[Dict[str, Any]]:
    approval = connection.execute(
        "SELECT * FROM policy_change_approvals WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    if approval is None or approval["state"] != "CONSUMED":
        return None
    if (
        required_sealed_mode is not None
        and approval["mode"] != required_sealed_mode
    ):
        raise PolicyAuthorityError(
            "sealed policy change mode does not match required mode"
        )
    run = connection.execute(
        "SELECT * FROM policy_change_runs WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    if (
        approval["export_sha256"] != approval_sha256
        or run is None
        or run["state"] != "ACTIVE"
        or run["executed_by"] != executed_by
        or run["process_instance_id"] != process_instance_id
    ):
        raise PolicyAuthorityError("terminal policy change retry binding changed")
    verified = _verify_terminal_change_run_locked(connection, root, run["run_id"])
    head = _head_row(connection)
    result = verified["result"]
    if head["generation"] < result["generation"]:
        raise PolicyAuthorityError("terminal policy change retry is ahead of policy head")
    if head["generation"] == result["generation"] and (
        head["source_kind"] != result["source_kind"]
        or head["source_run_id"] != result["run_id"]
        or head["full_hash"] != result["normalized_full_hash"]
    ):
        raise PolicyAuthorityError("terminal policy change retry head binding changed")
    return result


def _mark_policy_change_blocked(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    approval_id: str,
    process_instance_id: str,
    clear_event_id: Optional[str] = None,
) -> None:
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE policy_change_runs SET state = 'BLOCKED_RECOVERY' "
            "WHERE run_id = ? AND process_instance_id = ? "
            "AND state IN ('CLAIMED', 'POLICY_PUBLISHED', 'NO_YAML_WRITE_VERIFIED')",
            (run_id, process_instance_id),
        )
        connection.execute(
            "UPDATE policy_change_approvals SET state = 'BLOCKED' "
            "WHERE approval_id = ? AND state = 'CLAIMED'",
            (approval_id,),
        )
        connection.execute(
            "UPDATE policy_mutation_lane SET state = 'BLOCKED_RECOVERY' "
            "WHERE id = 1 AND state = 'ACTIVE' AND owner_approval_id = ? "
            "AND owner_run_id = ? AND owner_process_id = ?",
            (approval_id, run_id, process_instance_id),
        )
        if clear_event_id is not None:
            connection.execute(
                "UPDATE policy_guard_events SET state = 'BLOCKED' "
                "WHERE event_id = ? AND state = 'PREPARED'",
                (clear_event_id,),
            )
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def _apply_policy_reconcile_locked(
    canonical: Path,
    connection: sqlite3.Connection,
    *,
    approval: sqlite3.Row,
    approval_payload: Dict[str, Any],
    proposal: sqlite3.Row,
    proposal_payload: Dict[str, Any],
    approval_id: str,
    approval_sha256: str,
    executed_by: str,
    process_instance_id: str,
    checkpoint: Optional[Callable[[str], None]],
) -> Dict[str, Any]:
    if (
        approval_payload.get("run_id") != proposal_payload.get("run_id")
        or approval_payload.get("base") != proposal_payload.get("base")
        or approval_payload.get("postimage") != proposal_payload.get("postimage")
        or approval_payload.get("paths") != proposal_payload.get("paths")
        or approval_payload.get("guard_episode")
        != proposal_payload.get("guard_episode")
        or approval_payload.get("external_provenance")
        != proposal_payload.get("external_provenance")
    ):
        raise PolicyAuthorityError("policy RECONCILE approval/proposal binding changed")
    head = _head_row(connection)
    _require_no_active_policy_execution(connection)
    current_raw, current_identity = _registry_observation(canonical)
    episode = _require_reconcile_episode(connection, head, current_identity)
    guard = proposal_payload.get("guard_episode", {})
    if (
        head["generation"] != proposal["base_generation"]
        or head["full_hash"] != proposal["base_hash"]
        or head["guard_epoch"] != proposal_payload["base"]["guard_epoch"]
        or current_identity["normalized_full_hash"]
        != proposal_payload["postimage"]["normalized_full_hash"]
        or sha256_bytes(current_raw) != proposal_payload["postimage"]["raw_sha256"]
        or guard.get("episode_id") != episode["episode_id"]
        or guard.get("guard_epoch") != episode["guard_epoch_after"]
        or guard.get("first_event_id") != episode["first_event_id"]
    ):
        raise PolicyAuthorityError("policy RECONCILE claim binding changed")
    verify_policy_head_source_locked(
        connection,
        canonical,
        head,
    )
    observed_raw = _decode_sealed(
        proposal_payload["sealed_bytes"]["postimage_b64"],
        proposal_payload["postimage"]["raw_sha256"],
        "RECONCILE observed registry",
    )
    if observed_raw != current_raw:
        raise PolicyAuthorityError("policy RECONCILE observed bytes changed")
    try:
        observed_compiled = policy.compile_policy(observed_raw, str(canonical))
        observed_object = policy.parse_strict_yaml(observed_raw)
    except policy.PolicyError as exc:
        raise PolicyAuthorityError("policy RECONCILE observed bytes no longer compile") from exc
    base_raw = _decode_sealed(
        proposal_payload["sealed_bytes"]["base_raw_b64"],
        sha256_bytes(
            base64.b64decode(
                proposal_payload["sealed_bytes"]["base_raw_b64"].encode("ascii"),
                validate=True,
            )
        ),
        "RECONCILE base registry",
    )
    try:
        base_compiled = policy.compile_policy(base_raw, str(canonical))
        base_object = policy.parse_strict_yaml(base_raw)
    except policy.PolicyError as exc:
        raise PolicyAuthorityError("policy RECONCILE base bytes no longer compile") from exc
    if base_compiled.full_hash != head["full_hash"]:
        raise PolicyAuthorityError("policy RECONCILE base bytes differ from head")
    _validate_reconcile_diff(base_object, observed_object, base_raw, observed_raw)
    if (
        observed_compiled.full_hash
        != proposal_payload["postimage"]["normalized_full_hash"]
        or observed_compiled.writer_hash
        != proposal_payload["postimage"]["writer_control_hash"]
        or observed_compiled.foundation_hash
        != proposal_payload["postimage"]["foundation_hash"]
    ):
        raise PolicyAuthorityError("policy RECONCILE postimage projection changed")

    run_id = proposal_payload["run_id"]
    paths = proposal_payload["paths"]
    run_staging = Path(paths["run_staging"])
    run_final = Path(paths["run_final"])
    if os.path.lexists(run_staging) or os.path.lexists(run_final):
        raise PolicyAuthorityError("policy RECONCILE run path already exists")
    clear_event_id = guard["clear_event_id"]
    clear_observation_path = Path(paths["clear_event_observation"])
    clear_result_path = Path(paths["clear_event_result"])
    clear_observation = {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "DRIFT_CLEARED_RECONCILED",
        "event_id": clear_event_id,
        "episode_id": episode["episode_id"],
        "head": {
            "generation": head["generation"],
            "full_hash": head["full_hash"],
            "guard_epoch": head["guard_epoch"],
        },
        "proposal_id": proposal["proposal_id"],
        "approval_id": approval_id,
        "run_id": run_id,
        "observed_policy": current_identity,
        "external_provenance": proposal_payload["external_provenance"],
    }
    clear_observation_bytes = canonical_json_bytes(clear_observation)
    clear_observation_sha256 = sha256_bytes(clear_observation_bytes)
    clear_result = {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "POLICY_GUARD_EVENT_RESULT",
        "status": "COMPLETE",
        "event_id": clear_event_id,
        "episode_id": episode["episode_id"],
        "event_kind": "DRIFT_CLEARED_RECONCILED",
        "observation_sha256": clear_observation_sha256,
        "adopted_normalized_full_hash": observed_compiled.full_hash,
    }
    clear_result_bytes = canonical_json_bytes(clear_result)
    clear_result_sha256 = sha256_bytes(clear_result_bytes)
    plan = {
        "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
        "kind": "POLICY_CHANGE_PLAN",
        "mode": "RECONCILE",
        "proposal_id": proposal["proposal_id"],
        "proposal_sha256": proposal["proposal_sha256"],
        "approval_id": approval_id,
        "approval_sha256": approval_sha256,
        "run_id": run_id,
        "process_instance_id": process_instance_id,
        "executed_by": executed_by,
        "base": proposal_payload["base"],
        "postimage": proposal_payload["postimage"],
        "guard_episode": guard,
        "external_provenance": proposal_payload["external_provenance"],
        "paths": paths,
        "yaml_write_effects": 0,
    }
    plan_bytes = canonical_json_bytes(plan)
    try:
        connection.execute("BEGIN IMMEDIATE")
        lane = connection.execute(
            "SELECT * FROM policy_mutation_lane WHERE id = 1"
        ).fetchone()
        if (
            lane is None
            or lane["state"] != "RESERVED"
            or lane["owner_kind"] != "POLICY_RECONCILE"
            or lane["owner_proposal_id"] != proposal["proposal_id"]
            or lane["owner_approval_id"] != approval_id
        ):
            raise PolicyAuthorityError("policy RECONCILE lane reservation changed")
        connection.execute(
            "INSERT INTO policy_change_runs "
            "(run_id, approval_id, mode, process_instance_id, executed_by, result_path, "
            "result_sha256, state) VALUES (?, ?, 'RECONCILE', ?, ?, ?, NULL, 'CLAIMED')",
            (
                run_id,
                approval_id,
                process_instance_id,
                executed_by,
                paths["result_final"],
            ),
        )
        if connection.execute(
            "UPDATE policy_change_approvals SET state = 'CLAIMED' "
            "WHERE approval_id = ? AND state = 'PUBLISHED'",
            (approval_id,),
        ).rowcount != 1:
            raise PolicyAuthorityError("policy RECONCILE approval claim failed")
        if connection.execute(
            "UPDATE policy_mutation_lane SET generation = ?, state = 'ACTIVE', "
            "owner_run_id = ?, owner_process_id = ? WHERE id = 1 AND generation = ? "
            "AND state = 'RESERVED' AND owner_kind = 'POLICY_RECONCILE' "
            "AND owner_proposal_id = ? AND owner_approval_id = ?",
            (
                lane["generation"] + 1,
                run_id,
                process_instance_id,
                lane["generation"],
                proposal["proposal_id"],
                approval_id,
            ),
        ).rowcount != 1:
            raise PolicyAuthorityError("policy RECONCILE lane claim failed")
        connection.execute(
            "INSERT INTO policy_guard_events "
            "(event_id, episode_id, kind, head_generation, guard_epoch, observation_path, "
            "observation_sha256, result_path, result_sha256, state) "
            "VALUES (?, ?, 'DRIFT_CLEARED_RECONCILED', ?, ?, ?, ?, ?, ?, 'PREPARED')",
            (
                clear_event_id,
                episode["episode_id"],
                head["generation"],
                head["guard_epoch"],
                str(clear_observation_path),
                clear_observation_sha256,
                str(clear_result_path),
                clear_result_sha256,
            ),
        )
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    phase = "CLAIMED"
    try:
        _checkpoint(checkpoint, "claimed")
        policy_state.safety.create_verified_directory_no_replace(
            run_staging,
            label="policy RECONCILE run staging",
            collision_error="refusing to overwrite policy RECONCILE run staging",
            mode=0o700,
            error_type=PolicyAuthorityError,
        )
        _publish_or_verify(Path(paths["plan_staging"]), plan_bytes, "policy RECONCILE plan")
        _, verified_identity = _registry_observation(canonical)
        current_info = os.stat(
            canonical / "_registry" / "placement-map.yml",
            follow_symlinks=False,
        )
        if (
            verified_identity != current_identity
            or (current_info.st_dev, current_info.st_ino)
            != (current_identity["device"], current_identity["inode"])
        ):
            raise PolicyAuthorityError("policy RECONCILE registry changed before no-write proof")
        try:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "UPDATE policy_change_runs SET state = 'NO_YAML_WRITE_VERIFIED' "
                "WHERE run_id = ? AND state = 'CLAIMED'",
                (run_id,),
            ).rowcount != 1:
                raise PolicyAuthorityError("policy RECONCILE no-write CAS failed")
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        phase = "NO_YAML_WRITE_VERIFIED"
        _checkpoint(checkpoint, "no-yaml-write-verified")
        generation = head["generation"] + 1
        snapshot_id = "policy-%08d-%s" % (generation, observed_compiled.full_hash[:24])
        result = {
            "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
            "kind": "POLICY_CHANGE_RESULT",
            "status": "COMPLETE",
            "source_kind": "RECONCILE",
            "generation": generation,
            "guard_epoch": head["guard_epoch"],
            "proposal_id": proposal["proposal_id"],
            "proposal_sha256": proposal["proposal_sha256"],
            "approval_id": approval_id,
            "approval_sha256": approval_sha256,
            "run_id": run_id,
            "process_instance_id": process_instance_id,
            "requested_by": proposal["requested_by"],
            "approved_by": approval["approved_by"],
            "executed_by": executed_by,
            "external_provenance": proposal_payload["external_provenance"],
            "guard_episode_id": episode["episode_id"],
            "clear_event_id": clear_event_id,
            "raw_hash": sha256_bytes(observed_raw),
            "normalized_full_hash": observed_compiled.full_hash,
            "writer_control_hash": observed_compiled.writer_hash,
            "foundation_hash": observed_compiled.foundation_hash,
            "policy_snapshot_id": snapshot_id,
            "yaml_write_effects": 0,
            "paths": {
                "registry": str(canonical / "_registry" / "placement-map.yml"),
                "run": str(run_final),
                "result": paths["result_final"],
                "plan": paths["plan_final"],
                "clear_event_observation": str(clear_observation_path),
                "clear_event_result": str(clear_result_path),
            },
        }
        result_bytes = canonical_json_bytes(result)
        result_sha256 = sha256_bytes(result_bytes)
        _publish_or_verify(
            clear_observation_path,
            clear_observation_bytes,
            "policy RECONCILE clear event",
        )
        _publish_or_verify(
            clear_result_path,
            clear_result_bytes,
            "policy RECONCILE clear event result",
        )
        _publish_or_verify(
            Path(paths["result_staging"]),
            result_bytes,
            "policy RECONCILE result",
        )
        run_identity = policy_state.safety.source_identity(
            os.stat(run_staging, follow_symlinks=False)
        )
        policy_state.safety.rename_path_no_replace(
            run_staging,
            run_final,
            collision_error="refusing to overwrite policy RECONCILE final run",
            require_directory=True,
            expected_source_identity=run_identity,
            error_type=PolicyAuthorityError,
        )
        phase = "RESULT_PUBLISHED"
        _checkpoint(checkpoint, "result-published")
        policy_state.verify_sealed_run_directory(
            run_final,
            {
                "plan.json": (sha256_bytes(plan_bytes), 0o600),
                "result.json": (result_sha256, 0o600),
            },
            source_kind="RECONCILE",
        )
        _, final_identity = _registry_observation(canonical)
        final_info = os.stat(
            canonical / "_registry" / "placement-map.yml",
            follow_symlinks=False,
        )
        if (
            final_identity != current_identity
            or (final_info.st_dev, final_info.st_ino)
            != (current_identity["device"], current_identity["inode"])
        ):
            raise PolicyAuthorityError("policy RECONCILE registry changed before final CAS")
        try:
            connection.execute("BEGIN IMMEDIATE")
            current_head = _head_row(connection)
            active_lane = connection.execute(
                "SELECT * FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
            current_episode = connection.execute(
                "SELECT * FROM policy_guard_episodes WHERE episode_id = ?",
                (episode["episode_id"],),
            ).fetchone()
            clear_row = connection.execute(
                "SELECT * FROM policy_guard_events WHERE event_id = ?",
                (clear_event_id,),
            ).fetchone()
            if (
                current_head["generation"] != head["generation"]
                or current_head["full_hash"] != head["full_hash"]
                or current_head["guard_epoch"] != head["guard_epoch"]
                or active_lane is None
                or active_lane["state"] != "ACTIVE"
                or active_lane["owner_kind"] != "POLICY_RECONCILE"
                or active_lane["owner_proposal_id"] != proposal["proposal_id"]
                or active_lane["owner_approval_id"] != approval_id
                or active_lane["owner_run_id"] != run_id
                or active_lane["owner_process_id"] != process_instance_id
                or current_episode is None
                or current_episode["status"] != "OPEN"
                or current_episode["guard_epoch_after"] != head["guard_epoch"]
                or clear_row is None
                or clear_row["state"] != "PREPARED"
                or clear_row["observation_sha256"] != clear_observation_sha256
                or clear_row["result_sha256"] != clear_result_sha256
            ):
                raise PolicyAuthorityError("policy RECONCILE final binding changed")
            verify_policy_head_source_locked(
                connection,
                canonical,
                current_head,
            )
            connection.execute(
                "INSERT INTO policy_snapshots "
                "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                "normalized_policy_json, source_kind, source_run_id, source_state) "
                "VALUES (?, ?, ?, ?, ?, 'RECONCILE', ?, 'TERMINAL')",
                (
                    snapshot_id,
                    observed_compiled.full_hash,
                    observed_compiled.writer_hash,
                    observed_compiled.foundation_hash,
                    observed_compiled.full_json,
                    run_id,
                ),
            )
            if connection.execute(
                "UPDATE policy_head SET generation = ?, full_hash = ?, "
                "writer_control_hash = ?, foundation_hash = ?, source_kind = 'RECONCILE', "
                "source_run_id = ? WHERE id = 1 AND generation = ? AND full_hash = ? "
                "AND guard_epoch = ?",
                (
                    generation,
                    observed_compiled.full_hash,
                    observed_compiled.writer_hash,
                    observed_compiled.foundation_hash,
                    run_id,
                    head["generation"],
                    head["full_hash"],
                    head["guard_epoch"],
                ),
            ).rowcount != 1:
                raise PolicyAuthorityError("policy RECONCILE head CAS failed")
            if connection.execute(
                "UPDATE policy_change_runs SET state = 'ACTIVE', result_sha256 = ? "
                "WHERE run_id = ? AND state = 'NO_YAML_WRITE_VERIFIED'",
                (result_sha256, run_id),
            ).rowcount != 1:
                raise PolicyAuthorityError("policy RECONCILE run final CAS failed")
            if connection.execute(
                "UPDATE policy_change_approvals SET state = 'CONSUMED' "
                "WHERE approval_id = ? AND state = 'CLAIMED'",
                (approval_id,),
            ).rowcount != 1:
                raise PolicyAuthorityError("policy RECONCILE approval consume CAS failed")
            if connection.execute(
                "UPDATE policy_guard_episodes SET status = 'CLEARED_RECONCILED', "
                "current_observed_identity_json = ? WHERE episode_id = ? AND status = 'OPEN' "
                "AND head_generation = ? AND head_full_hash = ? AND guard_epoch_after = ?",
                (
                    canonical_json_bytes(final_identity),
                    episode["episode_id"],
                    head["generation"],
                    head["full_hash"],
                    head["guard_epoch"],
                ),
            ).rowcount != 1:
                raise PolicyAuthorityError("policy RECONCILE episode close CAS failed")
            if connection.execute(
                "UPDATE policy_guard_events SET state = 'COMPLETE' "
                "WHERE event_id = ? AND state = 'PREPARED'",
                (clear_event_id,),
            ).rowcount != 1:
                raise PolicyAuthorityError("policy RECONCILE clear-event CAS failed")
            if connection.execute(
                "UPDATE policy_mutation_lane SET generation = ?, state = 'IDLE', "
                "owner_kind = NULL, owner_proposal_id = NULL, owner_approval_id = NULL, "
                "owner_run_id = NULL, owner_process_id = NULL WHERE id = 1 "
                "AND generation = ? AND state = 'ACTIVE' "
                "AND owner_kind = 'POLICY_RECONCILE' AND owner_proposal_id = ? "
                "AND owner_approval_id = ? AND owner_run_id = ? AND owner_process_id = ?",
                (
                    active_lane["generation"] + 1,
                    active_lane["generation"],
                    proposal["proposal_id"],
                    approval_id,
                    run_id,
                    process_instance_id,
                ),
            ).rowcount != 1:
                raise PolicyAuthorityError("policy RECONCILE lane release CAS failed")
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        phase = "COMPLETE"
    except Exception as exc:
        _mark_policy_change_blocked(
            connection,
            run_id=run_id,
            approval_id=approval_id,
            process_instance_id=process_instance_id,
            clear_event_id=clear_event_id,
        )
        raise PolicyChangeRecoveryRequired(
            "claimed policy RECONCILE requires separately approved recovery",
            mode="RECONCILE",
            phase=phase,
            run_id=run_id,
            cause=exc,
        ) from exc
    _checkpoint(checkpoint, "complete")
    return result


def apply_policy_change(
    root: Path,
    *,
    approval_id: str,
    approval_sha256: str,
    executed_by: str,
    process_instance_id: str,
    required_sealed_mode: Optional[str] = None,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Claim and execute the mode sealed into one policy-change approval."""
    canonical = _canonical_root(root)
    actor = _require_actor(executed_by, "executed_by")
    process_id = _require_actor(process_instance_id, "process_instance_id")
    required_mode = _required_sealed_mode(required_sealed_mode)
    try:
        with policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_EX,
            ledger_operation=fcntl.LOCK_EX,
            query_only=False,
            checkpoint=checkpoint,
        ) as connection:
            terminal = _terminal_policy_change_retry_locked(
                connection,
                canonical,
                approval_id=approval_id,
                approval_sha256=approval_sha256,
                executed_by=actor,
                process_instance_id=process_id,
                required_sealed_mode=required_mode,
            )
            if terminal is not None:
                return terminal
            approval, approval_payload = _load_change_approval(
                connection, approval_id, approval_sha256
            )
            if required_mode is not None and approval["mode"] != required_mode:
                raise PolicyAuthorityError(
                    "sealed policy change mode does not match required mode"
                )
            proposal, proposal_payload = _load_change_proposal(
                connection,
                approval["proposal_id"],
                approval_payload["proposal_sha256"],
            )
            mode = proposal["mode"]
            if mode == "RECONCILE":
                return _apply_policy_reconcile_locked(
                    canonical,
                    connection,
                    approval=approval,
                    approval_payload=approval_payload,
                    proposal=proposal,
                    proposal_payload=proposal_payload,
                    approval_id=approval_id,
                    approval_sha256=approval_sha256,
                    executed_by=actor,
                    process_instance_id=process_id,
                    checkpoint=checkpoint,
                )
            if mode != "EDIT":
                raise PolicyAuthorityError("unsupported policy change mode")
            if (
                approval_payload.get("run_id") != proposal_payload.get("run_id")
                or approval_payload.get("base") != proposal_payload.get("base")
                or approval_payload.get("postimage") != proposal_payload.get("postimage")
                or approval_payload.get("paths") != proposal_payload.get("paths")
            ):
                raise PolicyAuthorityError("policy change approval/proposal binding changed")
            head = _head_row(connection)
            _require_no_active_policy_execution(connection)
            _require_no_open_guard(connection)
            base_raw, base_identity = _registry_observation(canonical)
            if (
                head["generation"] != proposal["base_generation"]
                or head["full_hash"] != proposal["base_hash"]
                or head["guard_epoch"] != proposal_payload["base"]["guard_epoch"]
                or base_identity["normalized_full_hash"] != head["full_hash"]
                or sha256_bytes(base_raw) != proposal_payload["base"]["raw_sha256"]
            ):
                raise PolicyAuthorityError("policy change claim base changed")
            post_raw = _decode_sealed(
                proposal_payload["sealed_bytes"]["postimage_b64"],
                proposal_payload["postimage"]["raw_sha256"],
                "policy postimage",
            )
            sealed_base = _decode_sealed(
                proposal_payload["sealed_bytes"]["base_b64"],
                proposal_payload["base"]["raw_sha256"],
                "policy preimage",
            )
            if sealed_base != base_raw:
                raise PolicyAuthorityError("policy change sealed base differs from registry")
            try:
                base_compiled = policy.compile_policy(base_raw, str(canonical))
                post_compiled = policy.compile_policy(post_raw, str(canonical))
            except policy.PolicyError as exc:
                raise PolicyAuthorityError("sealed policy change no longer compiles") from exc
            verify_current_policy_binding_locked(
                connection,
                canonical,
                base_raw,
                base_compiled,
                head,
            )
            _validate_edit_postimage(
                canonical,
                base_raw,
                post_raw,
                base_compiled,
                post_compiled,
            )
            if (
                post_compiled.full_hash
                != proposal_payload["postimage"]["normalized_full_hash"]
                or post_compiled.writer_hash
                != proposal_payload["postimage"]["writer_control_hash"]
                or post_compiled.foundation_hash
                != proposal_payload["postimage"]["foundation_hash"]
            ):
                raise PolicyAuthorityError("sealed policy change postimage binding changed")
            run_id = proposal_payload["run_id"]
            paths = proposal_payload["paths"]
            run_staging = Path(paths["run_staging"])
            run_final = Path(paths["run_final"])
            if os.path.lexists(run_staging) or os.path.lexists(run_final):
                raise PolicyAuthorityError("policy change run path already exists")
            plan = {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "kind": "POLICY_CHANGE_PLAN",
                "mode": mode,
                "proposal_id": proposal["proposal_id"],
                "proposal_sha256": proposal["proposal_sha256"],
                "approval_id": approval_id,
                "approval_sha256": approval_sha256,
                "run_id": run_id,
                "process_instance_id": process_id,
                "executed_by": actor,
                "base": proposal_payload["base"],
                "postimage": proposal_payload["postimage"],
                "paths": paths,
            }
            plan_bytes = canonical_json_bytes(plan)
            try:
                connection.execute("BEGIN IMMEDIATE")
                lane = connection.execute(
                    "SELECT * FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()
                if (
                    lane is None
                    or lane["state"] != "RESERVED"
                    or lane["owner_kind"] != "POLICY_EDIT"
                    or lane["owner_proposal_id"] != proposal["proposal_id"]
                    or lane["owner_approval_id"] != approval_id
                ):
                    raise PolicyAuthorityError("policy EDIT lane reservation changed")
                connection.execute(
                    "INSERT INTO policy_change_runs "
                    "(run_id, approval_id, mode, process_instance_id, executed_by, "
                    "result_path, result_sha256, state) "
                    "VALUES (?, ?, 'EDIT', ?, ?, ?, NULL, 'CLAIMED')",
                    (run_id, approval_id, process_id, actor, paths["result_final"]),
                )
                if connection.execute(
                    "UPDATE policy_change_approvals SET state = 'CLAIMED' "
                    "WHERE approval_id = ? AND state = 'PUBLISHED'",
                    (approval_id,),
                ).rowcount != 1:
                    raise PolicyAuthorityError("policy EDIT approval claim failed")
                if connection.execute(
                    "UPDATE policy_mutation_lane SET generation = ?, state = 'ACTIVE', "
                    "owner_run_id = ?, owner_process_id = ? WHERE id = 1 AND generation = ? "
                    "AND state = 'RESERVED' AND owner_kind = 'POLICY_EDIT' "
                    "AND owner_proposal_id = ? AND owner_approval_id = ?",
                    (
                        lane["generation"] + 1,
                        run_id,
                        process_id,
                        lane["generation"],
                        proposal["proposal_id"],
                        approval_id,
                    ),
                ).rowcount != 1:
                    raise PolicyAuthorityError("policy EDIT lane claim failed")
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            phase = "CLAIMED"
            try:
                _checkpoint(checkpoint, "claimed")
                policy_state.safety.create_verified_directory_no_replace(
                    run_staging,
                    label="policy change run staging",
                    collision_error="refusing to overwrite policy change run staging",
                    mode=0o700,
                    error_type=PolicyAuthorityError,
                )
                _publish_or_verify(Path(paths["plan_staging"]), plan_bytes, "policy change plan")
                _publish_or_verify(
                    Path(paths["policy_preimage"]), base_raw, "policy change preimage"
                )
                post_info = policy_state._publish_or_verify(
                    Path(paths["policy_postimage"]),
                    post_raw,
                    label="policy change postimage",
                )
                _checkpoint(checkpoint, "plan-published")
                registry_path = canonical / "_registry" / "placement-map.yml"
                registry_info = os.stat(registry_path, follow_symlinks=False)
                policy_state.safety.rename_path_no_replace(
                    registry_path,
                    Path(paths["policy_parking"]),
                    collision_error="refusing to overwrite policy change parking",
                    require_directory=False,
                    expected_source_identity=policy_state.safety.source_identity(registry_info),
                    error_type=PolicyAuthorityError,
                )
                phase = "POLICY_PARKED"
                _, parked = policy_state._read_regular(
                    Path(paths["policy_parking"]),
                    label="policy change parking",
                    expected_mode=stat.S_IMODE(registry_info.st_mode),
                )
                if parked != base_raw:
                    raise PolicyAuthorityError("policy change parked preimage changed")
                _checkpoint(checkpoint, "policy-parked")
                policy_state.safety.rename_path_no_replace(
                    Path(paths["policy_postimage"]),
                    registry_path,
                    collision_error="refusing to overwrite policy change registry",
                    require_directory=False,
                    expected_source_identity=policy_state.safety.source_identity(post_info),
                    error_type=PolicyAuthorityError,
                )
                _, published = policy_state._read_regular(
                    registry_path,
                    label="published policy change registry",
                    expected_mode=0o600,
                )
                if published != post_raw:
                    raise PolicyAuthorityError("published policy change readback changed")
                _publish_or_verify(
                    Path(paths["policy_postimage"]), post_raw, "policy change postimage evidence"
                )
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    if connection.execute(
                        "UPDATE policy_change_runs SET state = 'POLICY_PUBLISHED' "
                        "WHERE run_id = ? AND state = 'CLAIMED'",
                        (run_id,),
                    ).rowcount != 1:
                        raise PolicyAuthorityError("policy EDIT published-state CAS failed")
                    connection.commit()
                except Exception:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
                phase = "POLICY_PUBLISHED"
                _checkpoint(checkpoint, "policy-published")
                generation = head["generation"] + 1
                snapshot_id = "policy-%08d-%s" % (generation, post_compiled.full_hash[:24])
                result = {
                    "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                    "kind": "POLICY_CHANGE_RESULT",
                    "status": "COMPLETE",
                    "source_kind": "EDIT",
                    "generation": generation,
                    "guard_epoch": head["guard_epoch"],
                    "proposal_id": proposal["proposal_id"],
                    "proposal_sha256": proposal["proposal_sha256"],
                    "approval_id": approval_id,
                    "approval_sha256": approval_sha256,
                    "run_id": run_id,
                    "process_instance_id": process_id,
                    "requested_by": proposal["requested_by"],
                    "approved_by": approval["approved_by"],
                    "executed_by": actor,
                    "raw_hash": sha256_bytes(post_raw),
                    "normalized_full_hash": post_compiled.full_hash,
                    "writer_control_hash": post_compiled.writer_hash,
                    "foundation_hash": post_compiled.foundation_hash,
                    "policy_snapshot_id": snapshot_id,
                    "paths": {
                        "registry": str(registry_path),
                        "run": str(run_final),
                        "result": paths["result_final"],
                        "plan": paths["plan_final"],
                        "policy_preimage": str(run_final / "policy-preimage"),
                        "policy_parking": str(run_final / "policy-parking"),
                        "policy_postimage": str(run_final / "policy-postimage"),
                    },
                }
                result_bytes = canonical_json_bytes(result)
                result_sha256 = sha256_bytes(result_bytes)
                _publish_or_verify(
                    Path(paths["result_staging"]), result_bytes, "policy change result"
                )
                run_identity = policy_state.safety.source_identity(
                    os.stat(run_staging, follow_symlinks=False)
                )
                policy_state.safety.rename_path_no_replace(
                    run_staging,
                    run_final,
                    collision_error="refusing to overwrite policy change final run",
                    require_directory=True,
                    expected_source_identity=run_identity,
                    error_type=PolicyAuthorityError,
                )
                phase = "RESULT_PUBLISHED"
                _checkpoint(checkpoint, "result-published")
                expected_members = {
                    "plan.json": (sha256_bytes(plan_bytes), 0o600),
                    "policy-preimage": (sha256_bytes(base_raw), 0o600),
                    "policy-parking": (
                        sha256_bytes(base_raw),
                        stat.S_IMODE(registry_info.st_mode),
                    ),
                    "policy-postimage": (sha256_bytes(post_raw), 0o600),
                    "result.json": (result_sha256, 0o600),
                }
                policy_state.verify_sealed_run_directory(
                    run_final,
                    expected_members,
                    source_kind="EDIT",
                )
                _, final_raw, _ = policy_state._registry_identity(canonical)
                final_compiled = policy.compile_policy(final_raw, str(canonical))
                if final_raw != post_raw or final_compiled != post_compiled:
                    raise PolicyAuthorityError("policy EDIT changed before final CAS")
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    current_head = _head_row(connection)
                    lane = connection.execute(
                        "SELECT * FROM policy_mutation_lane WHERE id = 1"
                    ).fetchone()
                    if (
                        current_head["generation"] != head["generation"]
                        or current_head["full_hash"] != head["full_hash"]
                        or current_head["guard_epoch"] != head["guard_epoch"]
                        or lane is None
                        or lane["state"] != "ACTIVE"
                        or lane["owner_kind"] != "POLICY_EDIT"
                        or lane["owner_proposal_id"] != proposal["proposal_id"]
                        or lane["owner_approval_id"] != approval_id
                        or lane["owner_run_id"] != run_id
                        or lane["owner_process_id"] != process_id
                    ):
                        raise PolicyAuthorityError("policy EDIT final authority binding changed")
                    verify_policy_head_source_locked(
                        connection,
                        canonical,
                        current_head,
                    )
                    _require_no_open_guard(connection)
                    connection.execute(
                        "INSERT INTO policy_snapshots "
                        "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                        "normalized_policy_json, source_kind, source_run_id, source_state) "
                        "VALUES (?, ?, ?, ?, ?, 'EDIT', ?, 'TERMINAL')",
                        (
                            snapshot_id,
                            post_compiled.full_hash,
                            post_compiled.writer_hash,
                            post_compiled.foundation_hash,
                            post_compiled.full_json,
                            run_id,
                        ),
                    )
                    if connection.execute(
                        "UPDATE policy_head SET generation = ?, full_hash = ?, "
                        "writer_control_hash = ?, foundation_hash = ?, source_kind = 'EDIT', "
                        "source_run_id = ? WHERE id = 1 AND generation = ? AND full_hash = ? "
                        "AND guard_epoch = ?",
                        (
                            generation,
                            post_compiled.full_hash,
                            post_compiled.writer_hash,
                            post_compiled.foundation_hash,
                            run_id,
                            head["generation"],
                            head["full_hash"],
                            head["guard_epoch"],
                        ),
                    ).rowcount != 1:
                        raise PolicyAuthorityError("policy EDIT head CAS failed")
                    if connection.execute(
                        "UPDATE policy_change_runs SET state = 'ACTIVE', result_sha256 = ? "
                        "WHERE run_id = ? AND state = 'POLICY_PUBLISHED'",
                        (result_sha256, run_id),
                    ).rowcount != 1:
                        raise PolicyAuthorityError("policy EDIT run final CAS failed")
                    if connection.execute(
                        "UPDATE policy_change_approvals SET state = 'CONSUMED' "
                        "WHERE approval_id = ? AND state = 'CLAIMED'",
                        (approval_id,),
                    ).rowcount != 1:
                        raise PolicyAuthorityError("policy EDIT approval consume CAS failed")
                    if connection.execute(
                        "UPDATE policy_mutation_lane SET generation = ?, state = 'IDLE', "
                        "owner_kind = NULL, owner_proposal_id = NULL, owner_approval_id = NULL, "
                        "owner_run_id = NULL, owner_process_id = NULL WHERE id = 1 "
                        "AND generation = ? AND state = 'ACTIVE' AND owner_kind = 'POLICY_EDIT' "
                        "AND owner_proposal_id = ? AND owner_approval_id = ? "
                        "AND owner_run_id = ? AND owner_process_id = ?",
                        (
                            lane["generation"] + 1,
                            lane["generation"],
                            proposal["proposal_id"],
                            approval_id,
                            run_id,
                            process_id,
                        ),
                    ).rowcount != 1:
                        raise PolicyAuthorityError("policy EDIT lane release CAS failed")
                    connection.commit()
                except Exception:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
                phase = "COMPLETE"
            except Exception as exc:
                _mark_policy_change_blocked(
                    connection,
                    run_id=run_id,
                    approval_id=approval_id,
                    process_instance_id=process_id,
                )
                raise PolicyChangeRecoveryRequired(
                    "claimed policy EDIT requires separately approved recovery",
                    mode=mode,
                    phase=phase,
                    run_id=run_id,
                    cause=exc,
                ) from exc
            _checkpoint(checkpoint, "complete")
            return result
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def verify_normal_policy_authority(root: Path) -> Dict[str, Any]:
    """Return the current normal binding only when no drift authority is open."""
    canonical = _canonical_root(root)
    try:
        with policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_SH,
            ledger_operation=fcntl.LOCK_SH,
            query_only=True,
        ) as connection:
            head = _head_row(connection)
            _require_idle_lane(connection)
            if connection.execute(
                "SELECT COUNT(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
            ).fetchone()[0]:
                raise PolicyAuthorityError("open policy guard episode blocks normal authority")
            if connection.execute(
                "SELECT COUNT(*) FROM policy_guard_events "
                "WHERE state IN ('GUARD_BUMPED', 'PREPARED')"
            ).fetchone()[0]:
                raise PolicyAuthorityError("nonterminal policy guard event blocks normal authority")
            _require_no_active_policy_execution(connection)
            raw, identity = _registry_observation(canonical)
            try:
                compiled = policy.compile_policy(raw, str(canonical))
            except policy.PolicyError as exc:
                raise PolicyAuthorityError("current registry is not valid policy") from exc
            verified = verify_current_policy_binding_locked(
                connection,
                canonical,
                raw,
                compiled,
                head,
            )
            return {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "kind": "NORMAL_POLICY_AUTHORITY",
                "approved_policy_ref": verified["approved_policy_ref"],
                "guard_epoch": verified["guard_epoch"],
                "raw_hash": verified["raw_hash"],
                "writer_control_hash": verified["writer_control_hash"],
                "foundation_hash": verified["foundation_hash"],
                "source_result": verified["source_result"],
            }
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


def clear_policy_drift_equality(
    root: Path,
    *,
    episode_id: str,
    expected_head_generation: int,
    expected_head_full_hash: str,
    expected_guard_epoch: int,
    cleared_by: str,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Close one exact OPEN episode after the original policy equality returns."""
    canonical = _canonical_root(root)
    _require_actor(cleared_by, "cleared_by")
    try:
        with policy_state._locked_ledger(
            canonical,
            placement_operation=fcntl.LOCK_SH,
            ledger_operation=fcntl.LOCK_EX,
            query_only=False,
            checkpoint=checkpoint,
        ) as connection:
            head = _head_row(connection)
            if (
                head["generation"] != expected_head_generation
                or head["full_hash"] != expected_head_full_hash
                or head["guard_epoch"] != expected_guard_epoch
            ):
                raise PolicyAuthorityError("equality clear policy head binding changed")
            _require_idle_lane(connection)
            _require_no_active_policy_execution(connection)
            episode = connection.execute(
                "SELECT * FROM policy_guard_episodes WHERE episode_id = ?",
                (episode_id,),
            ).fetchone()
            if (
                episode is None
                or episode["status"] not in {"OPEN", "CLEARED_EQUALITY"}
                or episode["head_generation"] != expected_head_generation
                or episode["head_full_hash"] != expected_head_full_hash
                or episode["guard_epoch_after"] != expected_guard_epoch
            ):
                raise PolicyAuthorityError("equality clear episode binding changed")
            current_raw, identity = _registry_observation(canonical)
            try:
                current_compiled = policy.compile_policy(
                    current_raw,
                    str(canonical),
                )
            except policy.PolicyError as exc:
                raise PolicyAuthorityError(
                    "equality clear current policy is invalid"
                ) from exc
            approved_source = verify_policy_head_source_locked(
                connection,
                canonical,
                head,
            )
            if current_raw != approved_source["raw"]:
                raise PolicyAuthorityError(
                    "equality clear requires the exact approved raw policy"
                )
            verify_current_policy_binding_locked(
                connection,
                canonical,
                current_raw,
                current_compiled,
                head,
            )
            existing = connection.execute(
                "SELECT * FROM policy_guard_events WHERE episode_id = ? "
                "AND kind = 'DRIFT_CLEARED_EQUALITY'",
                (episode_id,),
            ).fetchone()
            if existing is None:
                digest = sha256_bytes(
                    canonical_json_bytes(
                        {
                            "episode_id": episode_id,
                            "head_generation": expected_head_generation,
                            "head_full_hash": expected_head_full_hash,
                            "guard_epoch": expected_guard_epoch,
                            "kind": "DRIFT_CLEARED_EQUALITY",
                        }
                    )
                )
                event_id = "pgevent-" + digest[:24]
                observation_path, result_path = _guard_paths(canonical, event_id)
                synthetic_event = {
                    "event_id": event_id,
                    "kind": "DRIFT_CLEARED_EQUALITY",
                    "head_generation": expected_head_generation,
                    "guard_epoch": expected_guard_epoch,
                }
                synthetic_episode = {
                    "episode_id": episode_id,
                    "head_full_hash": expected_head_full_hash,
                }
                observation_sha256 = sha256_bytes(
                    canonical_json_bytes(
                        _observation_payload(  # type: ignore[arg-type]
                            synthetic_event,
                            synthetic_episode,
                            identity,
                        )
                    )
                )
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "UPDATE policy_guard_episodes SET current_observed_identity_json = ? "
                        "WHERE episode_id = ? AND status = 'OPEN'",
                        (canonical_json_bytes(identity), episode_id),
                    )
                    connection.execute(
                        "INSERT INTO policy_guard_events "
                        "(event_id, episode_id, kind, head_generation, guard_epoch, "
                        "observation_path, observation_sha256, result_path, result_sha256, state) "
                        "VALUES (?, ?, 'DRIFT_CLEARED_EQUALITY', ?, ?, ?, ?, ?, NULL, 'PREPARED')",
                        (
                            event_id,
                            episode_id,
                            expected_head_generation,
                            expected_guard_epoch,
                            str(observation_path),
                            observation_sha256,
                            str(result_path),
                        ),
                    )
                    connection.commit()
                except Exception:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
            else:
                event_id = existing["event_id"]
            _checkpoint(checkpoint, "equality-clear-prepared")
            completed = _finish_guard_event(
                canonical,
                connection,
                event_id,
                checkpoint=checkpoint,
            )
            final_raw, final_identity = _registry_observation(canonical)
            try:
                final_compiled = policy.compile_policy(
                    final_raw,
                    str(canonical),
                )
            except policy.PolicyError as exc:
                raise PolicyAuthorityError(
                    "registry changed before equality clear final CAS"
                ) from exc
            verify_current_policy_binding_locked(
                connection,
                canonical,
                final_raw,
                final_compiled,
                head,
            )
            try:
                connection.execute("BEGIN IMMEDIATE")
                current_head = _head_row(connection)
                verify_current_policy_binding_locked(
                    connection,
                    canonical,
                    final_raw,
                    final_compiled,
                    current_head,
                )
                if connection.execute(
                    "UPDATE policy_guard_episodes SET status = 'CLEARED_EQUALITY', "
                    "current_observed_identity_json = ? WHERE episode_id = ? AND status = 'OPEN' "
                    "AND head_generation = ? AND head_full_hash = ? AND guard_epoch_after = ?",
                    (
                        canonical_json_bytes(final_identity),
                        episode_id,
                        expected_head_generation,
                        expected_head_full_hash,
                        expected_guard_epoch,
                    ),
                ).rowcount == 0:
                    state = connection.execute(
                        "SELECT status FROM policy_guard_episodes WHERE episode_id = ?",
                        (episode_id,),
                    ).fetchone()
                    if state is None or state[0] != "CLEARED_EQUALITY":
                        raise PolicyAuthorityError("equality clear final CAS failed")
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            _checkpoint(checkpoint, "equality-cleared")
            return {
                "schema_version": POLICY_AUTHORITY_SCHEMA_VERSION,
                "kind": "DRIFT_CLEARED_EQUALITY",
                "episode_id": episode_id,
                "event_id": event_id,
                "head_generation": expected_head_generation,
                "head_full_hash": expected_head_full_hash,
                "guard_epoch": expected_guard_epoch,
                "result_path": completed["result_path"],
                "result_sha256": completed["result_sha256"],
                "state": "CLEARED_EQUALITY",
            }
    except policy_state.PolicyStateError as exc:
        raise PolicyAuthorityError(str(exc)) from exc


__all__ = [
    "ActivationInitialPolicySource",
    "PolicyAuthorityError",
    "PolicyChangeRecoveryRequired",
    "apply_policy_change",
    "approve_policy_change",
    "clear_policy_drift_equality",
    "observe_policy_drift",
    "observe_policy_drift_from_stable_observation",
    "policy_change_preview_sha256",
    "preview_policy_change",
    "preview_policy_reconcile",
    "publish_policy_change_proposal",
    "resume_policy_guard_event",
    "verify_current_policy_binding_locked",
    "verify_normal_policy_authority",
    "verify_policy_head_source_locked",
    "verify_terminal_policy_source_locked",
]
