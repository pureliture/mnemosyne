"""Initial policy-bootstrap state machine for Mnemosyne curation.

This module owns only the G0L ``INITIAL`` transition from a verified control
bootstrap and a registry without a curation section to generation-one policy
authority.  It never writes corpus content and it never enables the curation
movement writer.  Recovery execution is deliberately not implemented here:
once a claimed filesystem effect cannot be completed in the same invocation,
the exact lane and run are left ``BLOCKED_RECOVERY`` for a separately approved
recovery workflow.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from . import control, policy, safety
from .canonical_json import canonical_json_bytes, sha256_bytes


POLICY_BOOTSTRAP_SCHEMA_VERSION = 1
MAX_REGISTRY_BYTES = 4 * 1024 * 1024
INITIAL_OWNER_KIND = "INITIAL"
INITIAL_SOURCE_KIND = "INITIAL"
TERMINAL_RUN_STATE = "ACTIVE"


class PolicyStateError(Exception):
    """An exact policy-state precondition or readback failed."""


class PolicyBootstrapRecoveryRequired(PolicyStateError):
    """A claimed INITIAL attempt needs separately approved recovery."""

    def __init__(
        self,
        message: str,
        *,
        phase: str,
        run_id: str,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.phase = phase
        self.run_id = run_id
        self.cause = cause


class PolicyBootstrapPublicationIncomplete(PolicyStateError):
    """A RESERVED approval publication must be retried with exact inputs."""

    def __init__(
        self,
        message: str,
        *,
        proposal_id: str,
        approval_id: str,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.phase = "APPROVAL_PUBLICATION"
        self.proposal_id = proposal_id
        self.approval_id = approval_id
        self.cause = cause


def _checkpoint(callback: Optional[Callable[[str], None]], point: str) -> None:
    if callback is not None:
        callback(point)


def _require_actor(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PolicyStateError("%s is required" % label)
    if any(ord(character) < 0x20 for character in value):
        raise PolicyStateError("%s contains control characters" % label)
    return value


def _require_identifier(value: str, prefix: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or len(value) != len(prefix) + 24
        or any(character not in "0123456789abcdef" for character in value[len(prefix) :])
    ):
        raise PolicyStateError("%s is invalid" % label)
    return value


def _verify_control_complete(root: Path, bootstrap_id: str) -> Dict[str, Any]:
    try:
        return control.verify_complete_bootstrap(root, bootstrap_id=bootstrap_id)
    except control.ControlBootstrapError as exc:
        raise PolicyStateError("control bootstrap COMPLETE verification failed") from exc


def _verify_control_preimage(root: Path, bootstrap_id: str) -> Dict[str, Any]:
    try:
        return control.verify_bootstrap_registry_preimage(
            root, bootstrap_id=bootstrap_id
        )
    except control.ControlBootstrapError as exc:
        raise PolicyStateError("INITIAL registry preimage verification failed") from exc


def _canonical_root(root: Path) -> Path:
    path = Path(root)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise PolicyStateError("raw root is not a canonical absolute path")
    descriptor = safety.open_verified_directory(
        path,
        require_owner_only=True,
        error_type=PolicyStateError,
    )
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise PolicyStateError("raw root is not owner-controlled")
    finally:
        os.close(descriptor)
    return path


def _read_regular(path: Path, *, label: str, expected_mode: Optional[int]) -> Tuple[os.stat_result, bytes]:
    directory_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=PolicyStateError,
    )
    try:
        info, raw = safety.read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label=label,
            expected_mode=expected_mode,
            error_type=PolicyStateError,
        )
        if info.st_uid != os.getuid() or info.st_nlink != 1:
            raise PolicyStateError("%s ownership or link count is invalid" % label)
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=PolicyStateError,
        )
        return info, raw
    finally:
        os.close(directory_fd)


def verify_sealed_run_directory(
    run_path: Path,
    expected_members: Dict[str, Tuple[str, int]],
    *,
    source_kind: str = "INITIAL",
) -> Dict[str, bytes]:
    """Verify one exact, no-follow terminal run membership snapshot."""
    if source_kind not in {"INITIAL", "EDIT", "RECONCILE"}:
        raise PolicyStateError("sealed run source kind is invalid")
    sealed_label = "sealed %s run" % source_kind
    expected_names = set(expected_members)
    run_fd = safety.open_verified_directory(
        run_path,
        require_owner_only=True,
        error_type=PolicyStateError,
    )
    try:
        opened = os.fstat(run_fd)
        if (
            opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise PolicyStateError("%s ownership or mode is invalid" % sealed_label)
        try:
            initial_names = os.listdir(run_fd)
        except OSError as exc:
            raise PolicyStateError("%s cannot be listed" % sealed_label) from exc
        if len(initial_names) != len(expected_names) or set(initial_names) != expected_names:
            raise PolicyStateError("%s membership changed" % sealed_label)

        readback: Dict[str, bytes] = {}
        member_identities: Dict[str, Tuple[int, ...]] = {}
        for name in sorted(expected_names):
            expected_hash, expected_mode = expected_members[name]
            if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                raise PolicyStateError("%s member hash is invalid" % sealed_label)
            member_path = run_path / name
            info, raw = safety.read_regular_file_at(
                run_fd,
                name,
                member_path,
                label="%s member %s" % (sealed_label, name),
                expected_mode=expected_mode,
                error_type=PolicyStateError,
            )
            if info.st_uid != os.getuid() or info.st_nlink != 1:
                raise PolicyStateError(
                    "%s member ownership or link count is invalid" % sealed_label
                )
            if sha256_bytes(raw) != expected_hash:
                raise PolicyStateError("%s member hash changed" % sealed_label)
            readback[name] = raw
            member_identities[name] = (
                info.st_dev,
                info.st_ino,
                stat.S_IFMT(info.st_mode),
                stat.S_IMODE(info.st_mode),
                info.st_uid,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
            )

        safety.require_same_directory_identity(
            run_path,
            run_fd,
            sealed_label,
            error_type=PolicyStateError,
        )
        try:
            final_names = os.listdir(run_fd)
        except OSError as exc:
            raise PolicyStateError("%s cannot be relisted" % sealed_label) from exc
        final = os.fstat(run_fd)
        if (
            len(final_names) != len(expected_names)
            or set(final_names) != expected_names
            or (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise PolicyStateError("%s membership changed" % sealed_label)
        for name in sorted(expected_names):
            try:
                current = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
            except OSError as exc:
                raise PolicyStateError(
                    "%s member changed during verification" % sealed_label
                ) from exc
            current_identity = (
                current.st_dev,
                current.st_ino,
                stat.S_IFMT(current.st_mode),
                stat.S_IMODE(current.st_mode),
                current.st_uid,
                current.st_nlink,
                current.st_size,
                current.st_mtime_ns,
            )
            if current_identity != member_identities[name]:
                raise PolicyStateError(
                    "%s member changed during verification" % sealed_label
                )
        return readback
    finally:
        os.close(run_fd)


def _verify_sealed_run_directory(
    run_path: Path,
    expected_members: Dict[str, Tuple[str, int]],
    *,
    source_kind: str = "INITIAL",
) -> Dict[str, bytes]:
    """Compatibility alias for the shared sealed-run verifier."""
    return verify_sealed_run_directory(
        run_path,
        expected_members,
        source_kind=source_kind,
    )


def _registry_identity(root: Path) -> Tuple[os.stat_result, bytes, Dict[str, Any]]:
    path = root / "_registry" / "placement-map.yml"
    info, raw = _read_regular(path, label="placement registry", expected_mode=None)
    if len(raw) > MAX_REGISTRY_BYTES:
        raise PolicyStateError("placement registry exceeds the bootstrap bound")
    return info, raw, {
        "path": str(path),
        "raw_sha256": sha256_bytes(raw),
        "bytes": len(raw),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": "%04o" % stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "nlink": info.st_nlink,
    }


def _parse_canonical_object(raw: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyStateError("%s is not canonical JSON" % label) from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise PolicyStateError("%s is not canonical JSON" % label)
    return value


def _decode_bound_bytes(value: Any, label: str, expected_hash: str) -> bytes:
    if not isinstance(value, str):
        raise PolicyStateError("%s bytes are missing" % label)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise PolicyStateError("%s bytes are invalid" % label) from exc
    if sha256_bytes(raw) != expected_hash:
        raise PolicyStateError("%s bytes do not match their sealed hash" % label)
    return raw


def _after_exact_readback(expected: bytes) -> Callable[[Path, int, int], None]:
    def verify(path: Path, descriptor: int, _directory_fd: int) -> None:
        if safety.read_open_file_bytes(descriptor) != expected:
            raise PolicyStateError("published artifact readback changed: %s" % path)

    return verify


def _publish_or_verify(path: Path, raw: bytes, *, label: str) -> os.stat_result:
    if os.path.lexists(path):
        info, observed = _read_regular(path, label=label, expected_mode=0o600)
        if observed != raw:
            raise PolicyStateError("%s collision differs from sealed bytes" % label)
        return info
    return safety.publish_bytes_atomic_no_replace(
        path,
        raw,
        label=label,
        mode=0o600,
        create_parent=True,
        collision_error="refusing to overwrite %s" % label,
        final_identity_error="%s final identity is invalid" % label,
        parent_error="%s parent is unsafe" % label,
        error_type=PolicyStateError,
        after_fd_readback=_after_exact_readback(raw),
    )


def _open_lock(path: Path, *, operation: int, label: str) -> int:
    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = safety.open_verified_directory(
        path.parent,
        require_owner_only=True,
        error_type=PolicyStateError,
    )
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        lexical = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise PolicyStateError("%s identity is invalid" % label)
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise PolicyStateError("%s is busy" % label) from exc
        safety.require_same_directory_identity(
            path.parent,
            directory_fd,
            label,
            error_type=PolicyStateError,
        )
        return descriptor
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(directory_fd)


def _connect_ledger(root: Path, *, query_only: bool) -> Tuple[sqlite3.Connection, Tuple[int, int]]:
    ledger_path = root / "_registry" / "curation" / "ledger.sqlite3"
    info, _ = _read_regular(ledger_path, label="curation ledger", expected_mode=0o600)
    identity = (info.st_dev, info.st_ino)
    connection = sqlite3.connect(str(ledger_path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA busy_timeout = %d" % control.BUSY_TIMEOUT_MS)
        connection.execute("PRAGMA foreign_keys = ON")
        if query_only:
            connection.execute("PRAGMA query_only = ON")
        if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).upper() != "WAL":
            raise PolicyStateError("curation ledger is not in terminal WAL mode")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise PolicyStateError("curation ledger integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise PolicyStateError("curation ledger foreign-key check failed")
        migration = connection.execute(
            "SELECT schema_sha256 FROM schema_migrations WHERE version = ?",
            (control.CONTROL_SCHEMA_VERSION,),
        ).fetchone()
        if migration is None or migration[0] != control.CONTROL_SCHEMA_SHA256:
            raise PolicyStateError("curation ledger schema identity changed")
        current = os.stat(ledger_path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            raise PolicyStateError("curation ledger identity changed while opening")
        return connection, identity
    except Exception:
        connection.close()
        raise


@contextmanager
def _locked_ledger(
    root: Path,
    *,
    placement_operation: int,
    ledger_operation: int,
    query_only: bool,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Iterator[sqlite3.Connection]:
    placement_fd = _open_lock(
        root / "_registry" / "placement-map.lock",
        operation=placement_operation,
        label="placement policy lock",
    )
    ledger_fd: Optional[int] = None
    connection: Optional[sqlite3.Connection] = None
    try:
        _checkpoint(checkpoint, "placement-lock-acquired")
        ledger_fd = _open_lock(
            root / "_registry" / "curation" / "ledger.lock",
            operation=ledger_operation,
            label="curation ledger lock",
        )
        _checkpoint(checkpoint, "ledger-lock-acquired")
        connection, ledger_identity = _connect_ledger(root, query_only=query_only)
        yield connection
        current = os.stat(
            root / "_registry" / "curation" / "ledger.sqlite3",
            follow_symlinks=False,
        )
        if (current.st_dev, current.st_ino) != ledger_identity:
            raise PolicyStateError("curation ledger identity changed under lock")
    finally:
        if connection is not None:
            connection.close()
        if ledger_fd is not None:
            os.close(ledger_fd)
        os.close(placement_fd)


def _begin(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")


def _rollback(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        connection.rollback()


def _require_pre_head_idle(connection: sqlite3.Connection) -> sqlite3.Row:
    if connection.execute("SELECT COUNT(*) FROM policy_head").fetchone()[0] != 0:
        raise PolicyStateError("INITIAL bootstrap requires the no-head sentinel")
    if connection.execute(
        "SELECT COUNT(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
    ).fetchone()[0] != 0:
        raise PolicyStateError("INITIAL bootstrap cannot own a policy guard episode")
    lane = connection.execute(
        "SELECT * FROM policy_mutation_lane WHERE id = 1"
    ).fetchone()
    if lane is None or lane["state"] != "IDLE":
        raise PolicyStateError("policy mutation lane is not IDLE")
    if connection.execute(
        "SELECT COUNT(*) FROM policy_bootstrap_runs "
        "WHERE state IN ('CLAIMED', 'POLICY_PUBLISHED', 'BLOCKED_RECOVERY')"
    ).fetchone()[0] != 0:
        raise PolicyStateError("another INITIAL execution is unresolved")
    if connection.execute(
        "SELECT COUNT(*) FROM policy_change_runs "
        "WHERE state IN ('CLAIMED', 'POLICY_PUBLISHED', 'NO_YAML_WRITE_VERIFIED', "
        "'BLOCKED_RECOVERY')"
    ).fetchone()[0] != 0:
        raise PolicyStateError("another policy execution is unresolved")
    return lane


def _preview_from_current(
    root: Path,
    *,
    bootstrap_id: str,
    requested_by: str,
) -> Dict[str, Any]:
    info, registry_raw, registry_identity = _registry_identity(root)
    try:
        postimage = policy.build_additive_curation_postimage(registry_raw, str(root))
        compiled = policy.compile_policy(postimage, str(root))
    except policy.PolicyError as exc:
        raise PolicyStateError("registry is not eligible for additive INITIAL policy bootstrap") from exc
    if len(postimage) > MAX_REGISTRY_BYTES:
        raise PolicyStateError("placement registry postimage exceeds the bootstrap bound")
    if (
        compiled.writer_control.movement_writer != "legacy"
        or compiled.writer_control.structural_apply != "disabled"
        or compiled.writer_control.writer_epoch != "legacy-v1"
    ):
        raise PolicyStateError("INITIAL policy bootstrap would activate a writer")

    semantic = {
        "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
        "kind": "POLICY_BOOTSTRAP_SEMANTIC_BINDING",
        "raw_root": str(root),
        "bootstrap_id": bootstrap_id,
        "requested_by": requested_by,
        "base": registry_identity,
        "postimage": {
            "raw_sha256": sha256_bytes(postimage),
            "bytes": len(postimage),
            "normalized_full_sha256": compiled.full_hash,
            "writer_control_sha256": compiled.writer_hash,
            "foundation_sha256": compiled.foundation_hash,
        },
        "bounds": {
            "max_registry_bytes": MAX_REGISTRY_BYTES,
            "base_bytes": len(registry_raw),
            "postimage_bytes": len(postimage),
        },
    }
    semantic_hash = sha256_bytes(canonical_json_bytes(semantic))
    preview_id = "polprev-" + semantic_hash[:24]
    proposal_id = "polboot-" + semantic_hash[:24]
    run_id = "polrun-" + sha256_bytes(
        canonical_json_bytes({"proposal_id": proposal_id, "expected_post": compiled.raw_hash})
    )[:24]
    paths = _expected_paths(root, proposal_id, run_id)
    return {
        "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
        "kind": "POLICY_BOOTSTRAP_PREVIEW",
        "preview_id": preview_id,
        "proposal_id": proposal_id,
        "run_id": run_id,
        "semantic_hash": semantic_hash,
        "requested_by": requested_by,
        "raw_root": str(root),
        "bootstrap_id": bootstrap_id,
        "base": registry_identity,
        "postimage": {
            "raw_sha256": sha256_bytes(postimage),
            "bytes": len(postimage),
            "normalized_full_sha256": compiled.full_hash,
            "writer_control_sha256": compiled.writer_hash,
            "foundation_sha256": compiled.foundation_hash,
        },
        "writer_control": {
            "movement_writer": compiled.writer_control.movement_writer,
            "structural_apply": compiled.writer_control.structural_apply,
            "writer_epoch": compiled.writer_control.writer_epoch,
        },
        "foundation": {
            "profile_version": compiled.foundation.profile_version,
            "state_root": compiled.foundation.state_root,
            "runs_root": compiled.foundation.runs_root,
        },
        "bounds": semantic["bounds"],
        "paths": paths,
        "sealed_bytes": {
            "base_b64": base64.b64encode(registry_raw).decode("ascii"),
            "postimage_b64": base64.b64encode(postimage).decode("ascii"),
            "normalized_full_json_b64": base64.b64encode(compiled.full_json).decode("ascii"),
        },
        "approval_ready": True,
    }


def _expected_paths(root: Path, proposal_id: str, run_id: str) -> Dict[str, str]:
    namespace = root / "_registry" / "curation" / "policy-bootstrap"
    run_staging = namespace / "runs" / (".incomplete-" + run_id)
    run_final = namespace / "runs" / run_id
    return {
        "proposal": str(namespace / "proposals" / proposal_id / "proposal.json"),
        "run_staging": str(run_staging),
        "run_final": str(run_final),
        "plan_staging": str(run_staging / "plan.json"),
        "plan_final": str(run_final / "plan.json"),
        "policy_staging": str(run_staging / "policy-staging"),
        "policy_parking": str(run_staging / "policy-parking"),
        "policy_preimage": str(run_staging / "policy-preimage"),
        "policy_quarantine": str(run_staging / "policy-quarantine"),
        "result_staging": str(run_staging / "result.json"),
        "result_final": str(run_final / "result.json"),
    }


def preview_sha256(preview: Dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(preview))


def preview_policy_bootstrap(
    root: Path,
    *,
    bootstrap_id: str,
    requested_by: str,
) -> Dict[str, Any]:
    """Return an exact, deterministic, write-free INITIAL preview."""
    canonical = _canonical_root(root)
    _require_identifier(bootstrap_id, "curboot-", "bootstrap_id")
    actor = _require_actor(requested_by, "requested_by")
    _verify_control_complete(canonical, bootstrap_id)
    _verify_control_preimage(canonical, bootstrap_id)
    with _locked_ledger(
        canonical,
        placement_operation=fcntl.LOCK_SH,
        ledger_operation=fcntl.LOCK_SH,
        query_only=True,
    ) as connection:
        _require_pre_head_idle(connection)
        return _preview_from_current(
            canonical,
            bootstrap_id=bootstrap_id,
            requested_by=actor,
        )


def _proposal_payload(preview: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
        "kind": "POLICY_BOOTSTRAP_PROPOSAL",
        "proposal_id": preview["proposal_id"],
        "proposal_generation": 1,
        "preview_id": preview["preview_id"],
        "preview_sha256": preview_sha256(preview),
        "semantic_hash": preview["semantic_hash"],
        "requested_by": preview["requested_by"],
        "raw_root": preview["raw_root"],
        "bootstrap_id": preview["bootstrap_id"],
        "run_id": preview["run_id"],
        "base": preview["base"],
        "postimage": preview["postimage"],
        "writer_control": preview["writer_control"],
        "foundation": preview["foundation"],
        "bounds": preview["bounds"],
        "paths": preview["paths"],
        "sealed_bytes": preview["sealed_bytes"],
        "authority": "NONE_UNTIL_APPROVAL_AND_APPLY",
    }


def publish_policy_bootstrap_proposal(
    root: Path,
    *,
    bootstrap_id: str,
    preview: Dict[str, Any],
) -> Dict[str, Any]:
    """Seal one exact preview as a non-authoritative proposal."""
    canonical = _canonical_root(root)
    _require_identifier(bootstrap_id, "curboot-", "bootstrap_id")
    if not isinstance(preview, dict):
        raise PolicyStateError("preview is required")
    requested_by = _require_actor(preview.get("requested_by"), "requested_by")
    _verify_control_complete(canonical, bootstrap_id)
    _verify_control_preimage(canonical, bootstrap_id)
    with _locked_ledger(
        canonical,
        placement_operation=fcntl.LOCK_SH,
        ledger_operation=fcntl.LOCK_EX,
        query_only=False,
    ) as connection:
        _require_pre_head_idle(connection)
        recomputed = _preview_from_current(
            canonical,
            bootstrap_id=bootstrap_id,
            requested_by=requested_by,
        )
        if preview != recomputed:
            raise PolicyStateError("policy bootstrap preview binding changed")
        payload = _proposal_payload(preview)
        payload_bytes = canonical_json_bytes(payload)
        proposal_sha256 = sha256_bytes(payload_bytes)
        proposal_id = _require_identifier(
            preview["proposal_id"], "polboot-", "proposal_id"
        )
        proposal_path = Path(preview["paths"]["proposal"])
        expected = (
            proposal_id,
            1,
            preview["base"]["raw_sha256"],
            preview["semantic_hash"],
            preview["postimage"]["raw_sha256"],
            payload_bytes,
            str(proposal_path),
            proposal_sha256,
            requested_by,
        )
        try:
            _begin(connection)
            existing = connection.execute(
                "SELECT proposal_id, proposal_generation, base_hash, semantic_hash, "
                "expected_post_hash, payload_json, proposal_path, proposal_sha256, "
                "requested_by, state FROM policy_bootstrap_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO policy_bootstrap_proposals "
                    "(proposal_id, proposal_generation, base_hash, semantic_hash, "
                    "expected_post_hash, payload_json, proposal_path, proposal_sha256, "
                    "requested_by, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED')",
                    expected,
                )
            elif tuple(existing[:9]) != expected or existing["state"] not in {
                "PREPARED",
                "PUBLISHED",
            }:
                raise PolicyStateError("existing proposal does not match sealed preview")
            connection.commit()
        except Exception:
            _rollback(connection)
            raise

        _publish_or_verify(proposal_path, payload_bytes, label="policy bootstrap proposal")
        try:
            _begin(connection)
            updated = connection.execute(
                "UPDATE policy_bootstrap_proposals SET state = 'PUBLISHED' "
                "WHERE proposal_id = ? AND state = 'PREPARED'",
                (proposal_id,),
            ).rowcount
            if updated == 0:
                state = connection.execute(
                    "SELECT state FROM policy_bootstrap_proposals WHERE proposal_id = ?",
                    (proposal_id,),
                ).fetchone()
                if state is None or state[0] != "PUBLISHED":
                    raise PolicyStateError("proposal publication CAS failed")
            connection.commit()
        except Exception:
            _rollback(connection)
            raise
        return {
            "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
            "kind": "POLICY_BOOTSTRAP_PROPOSAL",
            "proposal_id": proposal_id,
            "proposal_sha256": proposal_sha256,
            "preview_sha256": payload["preview_sha256"],
            "semantic_hash": preview["semantic_hash"],
            "run_id": preview["run_id"],
            "paths": preview["paths"],
            "payload": payload,
            "state": "PUBLISHED",
        }


def _load_proposal(
    connection: sqlite3.Connection,
    proposal_id: str,
    root: Path,
) -> Tuple[sqlite3.Row, Dict[str, Any]]:
    row = connection.execute(
        "SELECT * FROM policy_bootstrap_proposals WHERE proposal_id = ?",
        (proposal_id,),
    ).fetchone()
    if row is None or row["state"] != "PUBLISHED":
        raise PolicyStateError("policy bootstrap proposal is not PUBLISHED")
    raw = bytes(row["payload_json"])
    payload = _parse_canonical_object(raw, "policy bootstrap proposal payload")
    run_id = payload.get("run_id")
    _require_identifier(run_id, "polrun-", "proposal run_id")
    expected_paths = _expected_paths(root, proposal_id, run_id)
    if (
        payload.get("schema_version") != POLICY_BOOTSTRAP_SCHEMA_VERSION
        or payload.get("kind") != "POLICY_BOOTSTRAP_PROPOSAL"
        or payload.get("proposal_id") != proposal_id
        or payload.get("proposal_generation") != 1
        or payload.get("raw_root") != str(root)
        or sha256_bytes(raw) != row["proposal_sha256"]
        or payload.get("base", {}).get("raw_sha256") != row["base_hash"]
        or payload.get("postimage", {}).get("raw_sha256") != row["expected_post_hash"]
        or payload.get("semantic_hash") != row["semantic_hash"]
        or payload.get("paths") != expected_paths
        or row["proposal_path"] != expected_paths["proposal"]
        or payload.get("authority") != "NONE_UNTIL_APPROVAL_AND_APPLY"
        or payload.get("writer_control")
        != {
            "movement_writer": "legacy",
            "structural_apply": "disabled",
            "writer_epoch": "legacy-v1",
        }
    ):
        raise PolicyStateError("policy bootstrap proposal row binding is invalid")
    path = Path(row["proposal_path"])
    _, artifact = _read_regular(
        path,
        label="policy bootstrap proposal",
        expected_mode=0o600,
    )
    if artifact != raw:
        raise PolicyStateError("policy bootstrap proposal artifact changed")
    return row, payload


def approve_policy_bootstrap(
    root: Path,
    *,
    bootstrap_id: str,
    proposal_id: str,
    proposal_sha256: str,
    approved_by: str,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Reserve the INITIAL lane and publish one exact approval export."""
    canonical = _canonical_root(root)
    _require_identifier(bootstrap_id, "curboot-", "bootstrap_id")
    identifier = _require_identifier(proposal_id, "polboot-", "proposal_id")
    actor = _require_actor(approved_by, "approved_by")
    _verify_control_complete(canonical, bootstrap_id)
    _verify_control_preimage(canonical, bootstrap_id)
    with _locked_ledger(
        canonical,
        placement_operation=fcntl.LOCK_SH,
        ledger_operation=fcntl.LOCK_EX,
        query_only=False,
    ) as connection:
        row, proposal_payload = _load_proposal(connection, identifier, canonical)
        if row["proposal_sha256"] != proposal_sha256:
            raise PolicyStateError("proposal approval binding changed")
        _, current, current_identity = _registry_identity(canonical)
        if (
            current_identity["raw_sha256"] != row["base_hash"]
            or current != _decode_bound_bytes(
                proposal_payload["sealed_bytes"]["base_b64"],
                "proposal base",
                row["base_hash"],
            )
        ):
            raise PolicyStateError("registry base changed before approval")
        approval_seed = canonical_json_bytes(
            {
                "proposal_id": identifier,
                "proposal_sha256": proposal_sha256,
                "approved_by": actor,
                "attempt": 1,
            }
        )
        approval_id = "polappr-" + sha256_bytes(approval_seed)[:24]
        namespace = canonical / "_registry" / "curation" / "policy-bootstrap"
        export_path = namespace / "approvals" / approval_id / "approval.json"
        approval_payload = {
            "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
            "kind": "POLICY_BOOTSTRAP_APPROVAL",
            "approval_id": approval_id,
            "attempt": 1,
            "proposal_id": identifier,
            "proposal_path": row["proposal_path"],
            "proposal_sha256": proposal_sha256,
            "base_raw_sha256": row["base_hash"],
            "expected_post_raw_sha256": row["expected_post_hash"],
            "run_id": proposal_payload["run_id"],
            "approved_by": actor,
            "export_path": str(export_path),
            "state": "APPROVED_FOR_CLAIM",
        }
        approval_bytes = canonical_json_bytes(approval_payload)
        export_sha256 = sha256_bytes(approval_bytes)

        try:
            _begin(connection)
            existing = connection.execute(
                "SELECT * FROM policy_bootstrap_approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if existing is None:
                lane = _require_pre_head_idle(connection)
                connection.execute(
                    "INSERT INTO policy_bootstrap_approvals "
                    "(approval_id, proposal_id, attempt, approved_by, export_path, "
                    "export_sha256, state) VALUES (?, ?, 1, ?, ?, ?, 'PREPARED')",
                    (approval_id, identifier, actor, str(export_path), export_sha256),
                )
                updated = connection.execute(
                    "UPDATE policy_mutation_lane SET generation = ?, state = 'RESERVED', "
                    "owner_kind = 'INITIAL', owner_proposal_id = ?, owner_approval_id = ? "
                    "WHERE id = 1 AND generation = ? AND state = 'IDLE'",
                    (lane["generation"] + 1, identifier, approval_id, lane["generation"]),
                ).rowcount
                if updated != 1:
                    raise PolicyStateError("policy lane reservation CAS failed")
            else:
                expected_existing = (
                    identifier,
                    1,
                    actor,
                    str(export_path),
                    export_sha256,
                )
                if tuple(
                    existing[key]
                    for key in (
                        "proposal_id",
                        "attempt",
                        "approved_by",
                        "export_path",
                        "export_sha256",
                    )
                ) != expected_existing or existing["state"] not in {"PREPARED", "PUBLISHED"}:
                    raise PolicyStateError("existing approval does not match exact request")
                lane = connection.execute(
                    "SELECT * FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()
                if (
                    lane["state"] != "RESERVED"
                    or lane["owner_kind"] != "INITIAL"
                    or lane["owner_proposal_id"] != identifier
                    or lane["owner_approval_id"] != approval_id
                ):
                    raise PolicyStateError("approval publication lane binding changed")
            connection.commit()
        except Exception:
            _rollback(connection)
            raise

        try:
            _checkpoint(checkpoint, "approval-prepared")
            _publish_or_verify(
                export_path,
                approval_bytes,
                label="policy bootstrap approval",
            )
            _checkpoint(checkpoint, "approval-export-published")
            _begin(connection)
            updated = connection.execute(
                "UPDATE policy_bootstrap_approvals SET state = 'PUBLISHED' "
                "WHERE approval_id = ? AND state = 'PREPARED'",
                (approval_id,),
            ).rowcount
            if updated == 0:
                current_state = connection.execute(
                    "SELECT state FROM policy_bootstrap_approvals WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
                if current_state is None or current_state[0] != "PUBLISHED":
                    raise PolicyStateError("approval publication CAS failed")
            lane = connection.execute(
                "SELECT state, owner_approval_id FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
            if lane is None or tuple(lane) != ("RESERVED", approval_id):
                raise PolicyStateError("approval lane changed before publication")
            connection.commit()
        except Exception as exc:
            _rollback(connection)
            raise PolicyBootstrapPublicationIncomplete(
                "INITIAL approval publication is incomplete; retry exact approval inputs",
                proposal_id=identifier,
                approval_id=approval_id,
                cause=exc,
            ) from exc
        return {
            "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
            "kind": "POLICY_BOOTSTRAP_APPROVAL",
            "approval_id": approval_id,
            "proposal_id": identifier,
            "export_path": str(export_path),
            "export_sha256": export_sha256,
            "payload": approval_payload,
            "state": "PUBLISHED",
        }


def _load_approval(
    connection: sqlite3.Connection,
    approval_id: str,
    approval_sha256: str,
) -> Tuple[sqlite3.Row, Dict[str, Any]]:
    row = connection.execute(
        "SELECT * FROM policy_bootstrap_approvals WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    if row is None or row["state"] != "PUBLISHED":
        raise PolicyStateError("policy bootstrap approval is not PUBLISHED")
    if row["export_sha256"] != approval_sha256:
        raise PolicyStateError("policy bootstrap approval hash changed")
    _, raw = _read_regular(
        Path(row["export_path"]),
        label="policy bootstrap approval",
        expected_mode=0o600,
    )
    if sha256_bytes(raw) != approval_sha256:
        raise PolicyStateError("policy bootstrap approval artifact changed")
    payload = _parse_canonical_object(raw, "policy bootstrap approval")
    if (
        payload.get("approval_id") != approval_id
        or payload.get("proposal_id") != row["proposal_id"]
        or payload.get("approved_by") != row["approved_by"]
        or payload.get("export_path") != row["export_path"]
    ):
        raise PolicyStateError("policy bootstrap approval binding is invalid")
    return row, payload


def _mark_blocked(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    approval_id: str,
    process_instance_id: str,
) -> None:
    try:
        _rollback(connection)
        _begin(connection)
        connection.execute(
            "UPDATE policy_bootstrap_runs SET state = 'BLOCKED_RECOVERY' "
            "WHERE run_id = ? AND state IN ('CLAIMED', 'POLICY_PUBLISHED')",
            (run_id,),
        )
        connection.execute(
            "UPDATE policy_mutation_lane SET state = 'BLOCKED_RECOVERY' "
            "WHERE id = 1 AND state = 'ACTIVE' AND owner_kind = 'INITIAL' "
            "AND owner_approval_id = ? AND owner_run_id = ? AND owner_process_id = ?",
            (approval_id, run_id, process_instance_id),
        )
        connection.commit()
    except Exception:
        _rollback(connection)


def _run_plan(
    proposal: Dict[str, Any],
    approval: Dict[str, Any],
    *,
    executed_by: str,
    process_instance_id: str,
) -> Dict[str, Any]:
    return {
        "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
        "kind": "POLICY_BOOTSTRAP_PLAN",
        "source_kind": "INITIAL",
        "proposal_id": proposal["proposal_id"],
        "proposal_sha256": approval["proposal_sha256"],
        "approval_id": approval["approval_id"],
        "approval_sha256": None,
        "run_id": proposal["run_id"],
        "process_instance_id": process_instance_id,
        "requested_by": proposal["requested_by"],
        "approved_by": approval["approved_by"],
        "executed_by": executed_by,
        "base": proposal["base"],
        "postimage": proposal["postimage"],
        "paths": proposal["paths"],
        "effect": "ADDITIVE_REGISTRY_POLICY_BOOTSTRAP",
    }


def apply_policy_bootstrap(
    root: Path,
    *,
    bootstrap_id: str,
    approval_id: str,
    approval_sha256: str,
    executed_by: str,
    process_instance_id: str,
    checkpoint: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Claim and publish the exact writer-disabled INITIAL policy."""
    canonical = _canonical_root(root)
    _require_identifier(bootstrap_id, "curboot-", "bootstrap_id")
    identifier = _require_identifier(approval_id, "polappr-", "approval_id")
    actor = _require_actor(executed_by, "executed_by")
    process_id = _require_actor(process_instance_id, "process_instance_id")

    # Historical preimage authority exists only immediately before INITIAL
    # publication.  The structural COMPLETE verifier remains valid afterwards.
    _verify_control_complete(canonical, bootstrap_id)
    preimage_error: Optional[PolicyStateError] = None
    try:
        _verify_control_preimage(canonical, bootstrap_id)
    except PolicyStateError as exc:
        preimage_error = exc

    # An exact retry after the terminal CAS is readback, not a second effect.
    # This probe also keeps the historical preimage verifier scoped to the
    # one INITIAL publication: after success the registry inode is expected to
    # differ from the control-bootstrap preimage.
    if preimage_error is not None:
        try:
            authority = verify_initial_policy_authority(
                canonical,
                bootstrap_id=bootstrap_id,
            )
        except PolicyStateError:
            authority = None
        if authority is not None:
            _, existing_raw = _read_regular(
                Path(authority["result_path"]),
                label="existing terminal INITIAL result",
                expected_mode=0o600,
            )
            existing = _parse_canonical_object(
                existing_raw,
                "existing terminal INITIAL result",
            )
            if (
                existing.get("approval_id") != identifier
                or existing.get("approval_sha256") != approval_sha256
                or existing.get("executed_by") != actor
                or existing.get("process_instance_id") != process_id
            ):
                raise PolicyStateError(
                    "generation-one policy already belongs to a different INITIAL request"
                )
            return existing

    with _locked_ledger(
        canonical,
        placement_operation=fcntl.LOCK_EX,
        ledger_operation=fcntl.LOCK_EX,
        query_only=False,
        checkpoint=checkpoint,
    ) as connection:
        approval_probe = connection.execute(
            "SELECT * FROM policy_bootstrap_approvals WHERE approval_id = ?",
            (identifier,),
        ).fetchone()
        if approval_probe is None:
            raise PolicyStateError("policy bootstrap approval is missing")
        if approval_probe["state"] in {"CLAIMED", "BLOCKED"}:
            run_probe = connection.execute(
                "SELECT * FROM policy_bootstrap_runs WHERE approval_id = ?",
                (identifier,),
            ).fetchone()
            if run_probe is None or run_probe["state"] not in {
                "CLAIMED",
                "POLICY_PUBLISHED",
                "BLOCKED_RECOVERY",
            }:
                raise PolicyStateError("claimed INITIAL recovery state is ambiguous")
            raise PolicyBootstrapRecoveryRequired(
                "existing claimed INITIAL policy bootstrap requires separately approved recovery",
                phase=run_probe["state"],
                run_id=run_probe["run_id"],
            )
        if approval_probe["state"] == "PREPARED":
            raise PolicyBootstrapPublicationIncomplete(
                "INITIAL approval export is not PUBLISHED",
                proposal_id=approval_probe["proposal_id"],
                approval_id=identifier,
            )
        if approval_probe["state"] != "PUBLISHED":
            raise PolicyStateError(
                "policy bootstrap approval is not claimable: %s"
                % approval_probe["state"]
            )
        if preimage_error is not None:
            raise preimage_error
        approval_row, approval_payload = _load_approval(
            connection, identifier, approval_sha256
        )
        proposal_row, proposal_payload = _load_proposal(
            connection, approval_row["proposal_id"], canonical
        )
        if (
            approval_payload.get("proposal_sha256") != proposal_row["proposal_sha256"]
            or approval_payload.get("run_id") != proposal_payload.get("run_id")
            or proposal_payload.get("bootstrap_id") != bootstrap_id
        ):
            raise PolicyStateError("approval/proposal INITIAL binding is invalid")
        run_id = _require_identifier(proposal_payload["run_id"], "polrun-", "run_id")
        base_raw = _decode_bound_bytes(
            proposal_payload["sealed_bytes"]["base_b64"],
            "proposal base",
            proposal_row["base_hash"],
        )
        post_raw = _decode_bound_bytes(
            proposal_payload["sealed_bytes"]["postimage_b64"],
            "proposal postimage",
            proposal_row["expected_post_hash"],
        )
        normalized_json = _decode_bound_bytes(
            proposal_payload["sealed_bytes"]["normalized_full_json_b64"],
            "normalized policy",
            proposal_payload["postimage"]["normalized_full_sha256"],
        )
        compiled = policy.compile_policy(post_raw, str(canonical))
        if (
            compiled.full_json != normalized_json
            or compiled.full_hash != proposal_payload["postimage"]["normalized_full_sha256"]
            or compiled.writer_hash != proposal_payload["postimage"]["writer_control_sha256"]
            or compiled.foundation_hash != proposal_payload["postimage"]["foundation_sha256"]
            or compiled.writer_control.movement_writer != "legacy"
            or compiled.writer_control.structural_apply != "disabled"
            or compiled.writer_control.writer_epoch != "legacy-v1"
        ):
            raise PolicyStateError("sealed INITIAL postimage no longer compiles exactly")
        registry_info, current_raw, current_identity = _registry_identity(canonical)
        if (
            current_raw != base_raw
            or current_identity["raw_sha256"] != proposal_row["base_hash"]
            or any(
                current_identity[key] != proposal_payload["base"][key]
                for key in ("device", "inode", "uid", "nlink")
            )
        ):
            raise PolicyStateError("registry base changed before INITIAL claim")

        plan = _run_plan(
            proposal_payload,
            approval_payload,
            executed_by=actor,
            process_instance_id=process_id,
        )
        plan["approval_sha256"] = approval_sha256
        plan_bytes = canonical_json_bytes(plan)
        paths = proposal_payload["paths"]
        run_staging = Path(paths["run_staging"])
        run_final = Path(paths["run_final"])
        if os.path.lexists(run_staging) or os.path.lexists(run_final):
            raise PolicyStateError("policy bootstrap run path already exists before claim")

        try:
            _begin(connection)
            lane = connection.execute(
                "SELECT * FROM policy_mutation_lane WHERE id = 1"
            ).fetchone()
            if (
                lane is None
                or lane["state"] != "RESERVED"
                or lane["owner_kind"] != "INITIAL"
                or lane["owner_proposal_id"] != proposal_row["proposal_id"]
                or lane["owner_approval_id"] != identifier
                or lane["owner_run_id"] is not None
                or lane["owner_process_id"] is not None
            ):
                raise PolicyStateError("INITIAL lane reservation changed")
            if connection.execute("SELECT COUNT(*) FROM policy_head").fetchone()[0] != 0:
                raise PolicyStateError("INITIAL claim requires the no-head sentinel")
            if connection.execute(
                "SELECT COUNT(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
            ).fetchone()[0] != 0:
                raise PolicyStateError("INITIAL claim cannot own a guard episode")
            connection.execute(
                "INSERT INTO policy_bootstrap_runs "
                "(run_id, approval_id, process_instance_id, executed_by, result_path, "
                "result_sha256, expected_post_hash, state) VALUES (?, ?, ?, ?, ?, NULL, ?, 'CLAIMED')",
                (
                    run_id,
                    identifier,
                    process_id,
                    actor,
                    paths["result_final"],
                    proposal_row["expected_post_hash"],
                ),
            )
            if connection.execute(
                "UPDATE policy_bootstrap_approvals SET state = 'CLAIMED' "
                "WHERE approval_id = ? AND state = 'PUBLISHED'",
                (identifier,),
            ).rowcount != 1:
                raise PolicyStateError("approval claim CAS failed")
            if connection.execute(
                "UPDATE policy_mutation_lane SET generation = ?, state = 'ACTIVE', "
                "owner_run_id = ?, owner_process_id = ? WHERE id = 1 AND generation = ? "
                "AND state = 'RESERVED' AND owner_kind = 'INITIAL' "
                "AND owner_proposal_id = ? AND owner_approval_id = ?",
                (
                    lane["generation"] + 1,
                    run_id,
                    process_id,
                    lane["generation"],
                    proposal_row["proposal_id"],
                    identifier,
                ),
            ).rowcount != 1:
                raise PolicyStateError("INITIAL lane claim CAS failed")
            connection.commit()
        except Exception:
            _rollback(connection)
            raise
        phase = "CLAIMED"

        try:
            _checkpoint(checkpoint, "claimed")
            safety.create_verified_directory_no_replace(
                run_staging,
                label="policy bootstrap run staging",
                collision_error="refusing to overwrite policy bootstrap run staging",
                mode=0o700,
                error_type=PolicyStateError,
            )
            _publish_or_verify(Path(paths["plan_staging"]), plan_bytes, label="policy bootstrap plan")
            _publish_or_verify(
                Path(paths["policy_preimage"]),
                base_raw,
                label="policy bootstrap preimage",
            )
            staging_info = _publish_or_verify(
                Path(paths["policy_staging"]),
                post_raw,
                label="policy bootstrap staging policy",
            )
            quarantine_bytes = canonical_json_bytes(
                {
                    "schema_version": 1,
                    "kind": "POLICY_BOOTSTRAP_QUARANTINE",
                    "state": "UNUSED",
                    "run_id": run_id,
                }
            )
            _publish_or_verify(
                Path(paths["policy_quarantine"]),
                quarantine_bytes,
                label="policy bootstrap quarantine sentinel",
            )
            _checkpoint(checkpoint, "plan-published")

            registry_path = canonical / "_registry" / "placement-map.yml"
            safety.rename_path_no_replace(
                registry_path,
                Path(paths["policy_parking"]),
                collision_error="refusing to overwrite policy bootstrap parking",
                require_directory=False,
                expected_source_identity=safety.source_identity(registry_info),
                error_type=PolicyStateError,
            )
            phase = "POLICY_PARKED"
            _, parked = _read_regular(
                Path(paths["policy_parking"]),
                label="policy bootstrap parking",
                expected_mode=stat.S_IMODE(registry_info.st_mode),
            )
            if parked != base_raw:
                raise PolicyStateError("parked registry preimage changed")
            _checkpoint(checkpoint, "policy-parked")

            safety.rename_path_no_replace(
                Path(paths["policy_staging"]),
                registry_path,
                collision_error="refusing to overwrite placement registry postimage",
                require_directory=False,
                expected_source_identity=safety.source_identity(staging_info),
                error_type=PolicyStateError,
            )
            _, published = _read_regular(
                registry_path,
                label="published placement registry",
                expected_mode=0o600,
            )
            if published != post_raw:
                raise PolicyStateError("published INITIAL policy readback changed")
            # Keep the exact postimage in the sealed run after the effect file
            # itself has moved into the registry namespace.
            _publish_or_verify(
                Path(paths["policy_staging"]),
                post_raw,
                label="policy bootstrap staging evidence",
            )
            try:
                _begin(connection)
                if connection.execute(
                    "UPDATE policy_bootstrap_runs SET state = 'POLICY_PUBLISHED' "
                    "WHERE run_id = ? AND state = 'CLAIMED'",
                    (run_id,),
                ).rowcount != 1:
                    raise PolicyStateError("policy-published run CAS failed")
                connection.commit()
            except Exception:
                _rollback(connection)
                raise
            phase = "POLICY_PUBLISHED"
            _checkpoint(checkpoint, "policy-published")

            snapshot_id = "policy-00000001-" + compiled.full_hash[:24]
            result = {
                "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
                "kind": "POLICY_BOOTSTRAP_RESULT",
                "status": "COMPLETE",
                "source_kind": "INITIAL",
                "generation": 1,
                "guard_epoch": 0,
                "bootstrap_id": bootstrap_id,
                "proposal_id": proposal_row["proposal_id"],
                "proposal_sha256": proposal_row["proposal_sha256"],
                "approval_id": identifier,
                "approval_sha256": approval_sha256,
                "run_id": run_id,
                "process_instance_id": process_id,
                "requested_by": proposal_payload["requested_by"],
                "approved_by": approval_row["approved_by"],
                "executed_by": actor,
                "raw_hash": sha256_bytes(post_raw),
                "normalized_full_hash": compiled.full_hash,
                "writer_control_hash": compiled.writer_hash,
                "foundation_hash": compiled.foundation_hash,
                "policy_snapshot_id": snapshot_id,
                "artifacts": {
                    "plan_sha256": sha256_bytes(plan_bytes),
                    "policy_staging_sha256": sha256_bytes(post_raw),
                    "policy_parking_sha256": sha256_bytes(base_raw),
                    "policy_preimage_sha256": sha256_bytes(base_raw),
                    "policy_quarantine_sha256": sha256_bytes(quarantine_bytes),
                },
                "writer_control": {
                    "movement_writer": compiled.writer_control.movement_writer,
                    "structural_apply": compiled.writer_control.structural_apply,
                    "writer_epoch": compiled.writer_control.writer_epoch,
                },
                "paths": {
                    "registry": str(registry_path),
                    "run": str(run_final),
                    "result": paths["result_final"],
                    "plan": paths["plan_final"],
                    "policy_staging": str(run_final / "policy-staging"),
                    "policy_parking": str(run_final / "policy-parking"),
                    "policy_preimage": str(run_final / "policy-preimage"),
                    "policy_quarantine": str(run_final / "policy-quarantine"),
                },
            }
            result_bytes = canonical_json_bytes(result)
            result_sha256 = sha256_bytes(result_bytes)
            _publish_or_verify(
                Path(paths["result_staging"]),
                result_bytes,
                label="policy bootstrap result",
            )
            run_identity = safety.source_identity(os.stat(run_staging, follow_symlinks=False))
            safety.rename_path_no_replace(
                run_staging,
                run_final,
                collision_error="refusing to overwrite policy bootstrap final run",
                require_directory=True,
                expected_source_identity=run_identity,
                error_type=PolicyStateError,
            )
            phase = "RESULT_PUBLISHED"
            _, final_result = _read_regular(
                Path(paths["result_final"]),
                label="policy bootstrap final result",
                expected_mode=0o600,
            )
            if final_result != result_bytes:
                raise PolicyStateError("policy bootstrap final result readback changed")
            sealed_expected_members = {
                "plan.json": (sha256_bytes(plan_bytes), 0o600),
                "policy-staging": (sha256_bytes(post_raw), 0o600),
                "policy-parking": (
                    sha256_bytes(base_raw),
                    stat.S_IMODE(registry_info.st_mode),
                ),
                "policy-preimage": (sha256_bytes(base_raw), 0o600),
                "policy-quarantine": (
                    sha256_bytes(quarantine_bytes),
                    0o600,
                ),
                "result.json": (result_sha256, 0o600),
            }
            _checkpoint(checkpoint, "result-published")

            _, final_registry, _ = _registry_identity(canonical)
            final_compiled = policy.compile_policy(final_registry, str(canonical))
            if final_registry != post_raw or final_compiled != compiled:
                raise PolicyStateError("INITIAL policy changed before final authority CAS")
            try:
                _begin(connection)
                verify_sealed_run_directory(
                    run_final,
                    sealed_expected_members,
                    source_kind="INITIAL",
                )
                lane = connection.execute(
                    "SELECT * FROM policy_mutation_lane WHERE id = 1"
                ).fetchone()
                if (
                    lane is None
                    or lane["state"] != "ACTIVE"
                    or lane["owner_kind"] != "INITIAL"
                    or lane["owner_proposal_id"] != proposal_row["proposal_id"]
                    or lane["owner_approval_id"] != identifier
                    or lane["owner_run_id"] != run_id
                    or lane["owner_process_id"] != process_id
                ):
                    raise PolicyStateError("INITIAL active lane binding changed")
                if connection.execute("SELECT COUNT(*) FROM policy_head").fetchone()[0] != 0:
                    raise PolicyStateError("INITIAL final CAS lost no-head sentinel")
                if connection.execute(
                    "SELECT COUNT(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
                ).fetchone()[0] != 0:
                    raise PolicyStateError("INITIAL final CAS found an open guard episode")
                connection.execute(
                    "INSERT INTO policy_snapshots "
                    "(snapshot_id, full_hash, writer_control_hash, foundation_hash, "
                    "normalized_policy_json, source_kind, source_run_id, source_state) "
                    "VALUES (?, ?, ?, ?, ?, 'INITIAL', ?, 'TERMINAL')",
                    (
                        snapshot_id,
                        compiled.full_hash,
                        compiled.writer_hash,
                        compiled.foundation_hash,
                        compiled.full_json,
                        run_id,
                    ),
                )
                connection.execute(
                    "INSERT INTO policy_head "
                    "(id, generation, full_hash, writer_control_hash, foundation_hash, "
                    "source_kind, source_run_id, guard_epoch) "
                    "VALUES (1, 1, ?, ?, ?, 'INITIAL', ?, 0)",
                    (
                        compiled.full_hash,
                        compiled.writer_hash,
                        compiled.foundation_hash,
                        run_id,
                    ),
                )
                if connection.execute(
                    "UPDATE policy_bootstrap_runs SET state = 'ACTIVE', result_sha256 = ? "
                    "WHERE run_id = ? AND approval_id = ? AND process_instance_id = ? "
                    "AND expected_post_hash = ? AND state = 'POLICY_PUBLISHED'",
                    (
                        result_sha256,
                        run_id,
                        identifier,
                        process_id,
                        sha256_bytes(post_raw),
                    ),
                ).rowcount != 1:
                    raise PolicyStateError("INITIAL run final CAS failed")
                if connection.execute(
                    "UPDATE policy_bootstrap_approvals SET state = 'CONSUMED' "
                    "WHERE approval_id = ? AND state = 'CLAIMED'",
                    (identifier,),
                ).rowcount != 1:
                    raise PolicyStateError("INITIAL approval consume CAS failed")
                if connection.execute(
                    "UPDATE policy_mutation_lane SET generation = ?, state = 'IDLE', "
                    "owner_kind = NULL, owner_proposal_id = NULL, owner_approval_id = NULL, "
                    "owner_run_id = NULL, owner_process_id = NULL "
                    "WHERE id = 1 AND generation = ? AND state = 'ACTIVE' "
                    "AND owner_kind = 'INITIAL' AND owner_proposal_id = ? "
                    "AND owner_approval_id = ? AND owner_run_id = ? AND owner_process_id = ?",
                    (
                        lane["generation"] + 1,
                        lane["generation"],
                        proposal_row["proposal_id"],
                        identifier,
                        run_id,
                        process_id,
                    ),
                ).rowcount != 1:
                    raise PolicyStateError("INITIAL lane release CAS failed")
                connection.commit()
            except Exception:
                _rollback(connection)
                raise
            phase = "COMPLETE"
        except Exception as exc:
            _mark_blocked(
                connection,
                run_id=run_id,
                approval_id=identifier,
                process_instance_id=process_id,
            )
            raise PolicyBootstrapRecoveryRequired(
                "claimed INITIAL policy bootstrap requires separately approved recovery",
                phase=phase,
                run_id=run_id,
                cause=exc,
            ) from exc

        _checkpoint(checkpoint, "complete")
        return result


def verify_initial_policy_source_locked(
    connection: sqlite3.Connection,
    root: Path,
    head: sqlite3.Row,
    *,
    expected_bootstrap_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify one exact INITIAL terminal source under caller-held locks."""
    canonical = Path(root)
    if (
        head is None
        or head["generation"] != 1
        or head["source_kind"] != "INITIAL"
        or head["guard_epoch"] < 0
    ):
        raise PolicyStateError("generation-one INITIAL policy head is invalid")
    run = connection.execute(
        "SELECT * FROM policy_bootstrap_runs WHERE run_id = ?",
        (head["source_run_id"],),
    ).fetchone()
    if (
        run is None
        or run["state"] != TERMINAL_RUN_STATE
        or not isinstance(run["result_sha256"], str)
        or len(run["result_sha256"]) != 64
    ):
        raise PolicyStateError("INITIAL source run is not terminal")
    approval = connection.execute(
        "SELECT * FROM policy_bootstrap_approvals WHERE approval_id = ?",
        (run["approval_id"],),
    ).fetchone()
    if (
        approval is None
        or approval["state"] != "CONSUMED"
        or approval["attempt"] != 1
    ):
        raise PolicyStateError("INITIAL approval is not consumed")
    proposal, proposal_payload = _load_proposal(
        connection,
        approval["proposal_id"],
        canonical,
    )
    bootstrap_id = _require_identifier(
        proposal_payload.get("bootstrap_id"),
        "curboot-",
        "terminal INITIAL bootstrap_id",
    )
    if expected_bootstrap_id is not None and bootstrap_id != expected_bootstrap_id:
        raise PolicyStateError("INITIAL bootstrap authority binding changed")
    if (
        proposal_payload.get("run_id") != run["run_id"]
        or proposal_payload.get("proposal_generation") != 1
        or proposal_payload.get("raw_root") != str(canonical)
    ):
        raise PolicyStateError("INITIAL proposal source run binding is invalid")
    expected_proposal_keys = {
        "schema_version",
        "kind",
        "proposal_id",
        "proposal_generation",
        "preview_id",
        "preview_sha256",
        "semantic_hash",
        "requested_by",
        "raw_root",
        "bootstrap_id",
        "run_id",
        "base",
        "postimage",
        "writer_control",
        "foundation",
        "bounds",
        "paths",
        "sealed_bytes",
        "authority",
    }
    if set(proposal_payload) != expected_proposal_keys:
        raise PolicyStateError("terminal INITIAL proposal shape changed")

    sealed = proposal_payload.get("sealed_bytes")
    if not isinstance(sealed, dict):
        raise PolicyStateError("terminal INITIAL sealed bytes are missing")
    sealed_base = _decode_bound_bytes(
        sealed.get("base_b64"),
        "terminal proposal base",
        proposal["base_hash"],
    )
    sealed_post = _decode_bound_bytes(
        sealed.get("postimage_b64"),
        "terminal proposal postimage",
        proposal["expected_post_hash"],
    )
    try:
        compiled = policy.compile_policy(sealed_post, str(canonical))
    except policy.PolicyError as exc:
        raise PolicyStateError("terminal INITIAL postimage is invalid") from exc
    normalized = _decode_bound_bytes(
        sealed.get("normalized_full_json_b64"),
        "terminal INITIAL normalized policy",
        compiled.full_hash,
    )
    postimage = proposal_payload.get("postimage")
    writer_control = proposal_payload.get("writer_control")
    foundation = proposal_payload.get("foundation")
    bounds = proposal_payload.get("bounds")
    if (
        normalized != compiled.full_json
        or postimage
        != {
            "raw_sha256": compiled.raw_hash,
            "bytes": len(sealed_post),
            "normalized_full_sha256": compiled.full_hash,
            "writer_control_sha256": compiled.writer_hash,
            "foundation_sha256": compiled.foundation_hash,
        }
        or writer_control
        != {
            "movement_writer": compiled.writer_control.movement_writer,
            "structural_apply": compiled.writer_control.structural_apply,
            "writer_epoch": compiled.writer_control.writer_epoch,
        }
        or foundation
        != {
            "profile_version": compiled.foundation.profile_version,
            "state_root": compiled.foundation.state_root,
            "runs_root": compiled.foundation.runs_root,
        }
        or bounds
        != {
            "max_registry_bytes": MAX_REGISTRY_BYTES,
            "base_bytes": len(sealed_base),
            "postimage_bytes": len(sealed_post),
        }
    ):
        raise PolicyStateError("terminal INITIAL proposal projection changed")
    snapshot = connection.execute(
        "SELECT * FROM policy_snapshots WHERE full_hash = ? AND source_kind = ? "
        "AND source_run_id = ?",
        (head["full_hash"], head["source_kind"], head["source_run_id"]),
    ).fetchone()
    if (
        snapshot is None
        or snapshot["snapshot_id"]
        != "policy-00000001-" + compiled.full_hash[:24]
        or snapshot["full_hash"] != compiled.full_hash
        or snapshot["writer_control_hash"] != compiled.writer_hash
        or snapshot["foundation_hash"] != compiled.foundation_hash
        or bytes(snapshot["normalized_policy_json"]) != compiled.full_json
        or snapshot["source_kind"] != "INITIAL"
        or snapshot["source_run_id"] != run["run_id"]
        or snapshot["source_state"] != "TERMINAL"
        or head["full_hash"] != compiled.full_hash
        or head["writer_control_hash"] != compiled.writer_hash
        or head["foundation_hash"] != compiled.foundation_hash
    ):
        raise PolicyStateError("immutable INITIAL policy snapshot is invalid")

    _, approval_raw = _read_regular(
        Path(approval["export_path"]),
        label="consumed INITIAL approval",
        expected_mode=0o600,
    )
    approval_payload = _parse_canonical_object(
        approval_raw,
        "consumed INITIAL approval",
    )
    expected_approval = {
        "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
        "kind": "POLICY_BOOTSTRAP_APPROVAL",
        "approval_id": approval["approval_id"],
        "attempt": 1,
        "proposal_id": proposal["proposal_id"],
        "proposal_path": proposal["proposal_path"],
        "proposal_sha256": proposal["proposal_sha256"],
        "base_raw_sha256": proposal["base_hash"],
        "expected_post_raw_sha256": proposal["expected_post_hash"],
        "run_id": run["run_id"],
        "approved_by": approval["approved_by"],
        "export_path": approval["export_path"],
        "state": "APPROVED_FOR_CLAIM",
    }
    if (
        sha256_bytes(approval_raw) != approval["export_sha256"]
        or approval_payload != expected_approval
    ):
        raise PolicyStateError("consumed INITIAL approval binding changed")

    paths = proposal_payload["paths"]
    run_final = Path(paths["run_final"])
    run_staging = Path(paths["run_staging"])
    if (
        paths != _expected_paths(canonical, proposal["proposal_id"], run["run_id"])
        or str(run_final / "result.json") != run["result_path"]
        or os.path.lexists(run_staging)
    ):
        raise PolicyStateError("terminal INITIAL run path binding changed")
    expected_plan = _run_plan(
        proposal_payload,
        approval_payload,
        executed_by=run["executed_by"],
        process_instance_id=run["process_instance_id"],
    )
    expected_plan["approval_sha256"] = approval["export_sha256"]
    plan_raw = canonical_json_bytes(expected_plan)
    quarantine_raw = canonical_json_bytes(
        {
            "schema_version": 1,
            "kind": "POLICY_BOOTSTRAP_QUARANTINE",
            "state": "UNUSED",
            "run_id": run["run_id"],
        }
    )
    result_paths = {
        "registry": str(canonical / "_registry" / "placement-map.yml"),
        "run": str(run_final),
        "result": paths["result_final"],
        "plan": paths["plan_final"],
        "policy_staging": str(run_final / "policy-staging"),
        "policy_parking": str(run_final / "policy-parking"),
        "policy_preimage": str(run_final / "policy-preimage"),
        "policy_quarantine": str(run_final / "policy-quarantine"),
    }
    artifacts = {
        "plan_sha256": sha256_bytes(plan_raw),
        "policy_staging_sha256": sha256_bytes(sealed_post),
        "policy_parking_sha256": sha256_bytes(sealed_base),
        "policy_preimage_sha256": sha256_bytes(sealed_base),
        "policy_quarantine_sha256": sha256_bytes(quarantine_raw),
    }
    _, result_raw = _read_regular(
        Path(run["result_path"]),
        label="terminal INITIAL result",
        expected_mode=0o600,
    )
    result = _parse_canonical_object(result_raw, "terminal INITIAL result")
    expected_result = {
        "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
        "kind": "POLICY_BOOTSTRAP_RESULT",
        "status": "COMPLETE",
        "source_kind": "INITIAL",
        "generation": 1,
        "guard_epoch": 0,
        "bootstrap_id": bootstrap_id,
        "proposal_id": proposal["proposal_id"],
        "proposal_sha256": proposal["proposal_sha256"],
        "approval_id": approval["approval_id"],
        "approval_sha256": approval["export_sha256"],
        "run_id": run["run_id"],
        "process_instance_id": run["process_instance_id"],
        "requested_by": proposal["requested_by"],
        "approved_by": approval["approved_by"],
        "executed_by": run["executed_by"],
        "raw_hash": compiled.raw_hash,
        "normalized_full_hash": compiled.full_hash,
        "writer_control_hash": compiled.writer_hash,
        "foundation_hash": compiled.foundation_hash,
        "policy_snapshot_id": snapshot["snapshot_id"],
        "artifacts": artifacts,
        "writer_control": writer_control,
        "paths": result_paths,
    }
    if (
        result != expected_result
        or sha256_bytes(result_raw) != run["result_sha256"]
        or run["expected_post_hash"] != compiled.raw_hash
    ):
        raise PolicyStateError("terminal INITIAL result binding is invalid")
    base_mode = proposal_payload.get("base", {}).get("mode")
    if (
        not isinstance(base_mode, str)
        or len(base_mode) != 4
        or any(character not in "01234567" for character in base_mode)
    ):
        raise PolicyStateError("terminal INITIAL base mode is invalid")
    sealed_members = verify_sealed_run_directory(
        run_final,
        {
            "plan.json": (artifacts["plan_sha256"], 0o600),
            "policy-staging": (artifacts["policy_staging_sha256"], 0o600),
            "policy-parking": (artifacts["policy_parking_sha256"], int(base_mode, 8)),
            "policy-preimage": (artifacts["policy_preimage_sha256"], 0o600),
            "policy-quarantine": (
                artifacts["policy_quarantine_sha256"],
                0o600,
            ),
            "result.json": (run["result_sha256"], 0o600),
        },
        source_kind="INITIAL",
    )
    if (
        sealed_members["plan.json"] != plan_raw
        or sealed_members["policy-staging"] != sealed_post
        or sealed_members["policy-parking"] != sealed_base
        or sealed_members["policy-preimage"] != sealed_base
        or sealed_members["policy-quarantine"] != quarantine_raw
        or sealed_members["result.json"] != result_raw
    ):
        raise PolicyStateError("terminal INITIAL sealed evidence changed")
    return {
        "mode": "INITIAL",
        "run": run,
        "approval": approval,
        "proposal": proposal,
        "snapshot": snapshot,
        "raw": sealed_post,
        "compiled": compiled,
        "result": result,
        "result_path": run["result_path"],
        "result_sha256": run["result_sha256"],
        "bootstrap_id": bootstrap_id,
    }


def verify_initial_policy_authority(
    root: Path,
    *,
    bootstrap_id: str,
) -> Dict[str, Any]:
    """Verify G0L as control COMPLETE plus exact terminal INITIAL authority."""
    canonical = _canonical_root(root)
    _require_identifier(bootstrap_id, "curboot-", "bootstrap_id")
    control_result = _verify_control_complete(canonical, bootstrap_id)
    with _locked_ledger(
        canonical,
        placement_operation=fcntl.LOCK_SH,
        ledger_operation=fcntl.LOCK_SH,
        query_only=True,
    ) as connection:
        _, registry_raw, _ = _registry_identity(canonical)
        try:
            compiled = policy.compile_policy(registry_raw, str(canonical))
        except policy.PolicyError as exc:
            raise PolicyStateError("current registry is not a valid approved policy") from exc
        head = connection.execute("SELECT * FROM policy_head WHERE id = 1").fetchone()
        verified = verify_initial_policy_source_locked(
            connection,
            canonical,
            head,
            expected_bootstrap_id=bootstrap_id,
        )
        if registry_raw != verified["raw"] or compiled != verified["compiled"]:
            raise PolicyStateError("current registry does not match INITIAL authority")
        lane = connection.execute(
            "SELECT * FROM policy_mutation_lane WHERE id = 1"
        ).fetchone()
        if (
            lane is None
            or lane["state"] != "IDLE"
            or any(
                lane[key] is not None
                for key in (
                    "owner_kind",
                    "owner_proposal_id",
                    "owner_approval_id",
                    "owner_run_id",
                    "owner_process_id",
                )
            )
        ):
            raise PolicyStateError("policy mutation lane is not terminal IDLE")
        if connection.execute(
            "SELECT COUNT(*) FROM policy_guard_episodes WHERE status = 'OPEN'"
        ).fetchone()[0] != 0:
            raise PolicyStateError("open policy guard episode blocks INITIAL authority")
        return {
            "schema_version": POLICY_BOOTSTRAP_SCHEMA_VERSION,
            "kind": "G0L_INITIAL_POLICY_AUTHORITY",
            "state": "COMPLETE",
            "control_bootstrap": {
                "bootstrap_id": bootstrap_id,
                "state": control_result["state"],
            },
            "approved_policy_ref": {
                "generation": head["generation"],
                "full_hash": head["full_hash"],
                "source_kind": head["source_kind"],
                "source_run_id": head["source_run_id"],
            },
            "guard_epoch": head["guard_epoch"],
            "raw_hash": sha256_bytes(registry_raw),
            "writer_control_hash": compiled.writer_hash,
            "foundation_hash": compiled.foundation_hash,
            "result_path": verified["result_path"],
            "result_sha256": verified["result_sha256"],
        }


__all__ = [
    "INITIAL_OWNER_KIND",
    "INITIAL_SOURCE_KIND",
    "MAX_REGISTRY_BYTES",
    "POLICY_BOOTSTRAP_SCHEMA_VERSION",
    "PolicyBootstrapPublicationIncomplete",
    "PolicyBootstrapRecoveryRequired",
    "PolicyStateError",
    "apply_policy_bootstrap",
    "approve_policy_bootstrap",
    "preview_policy_bootstrap",
    "preview_sha256",
    "publish_policy_bootstrap_proposal",
    "verify_initial_policy_source_locked",
    "verify_sealed_run_directory",
    "verify_initial_policy_authority",
]
