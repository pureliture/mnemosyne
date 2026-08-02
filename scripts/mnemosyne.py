#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import fnmatch
import hashlib
import importlib.machinery
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import types
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


RUNTIME_MODULE_CLOSURE = (
    ("mnemosyne_core", "__init__.py", True),
    ("mnemosyne_core.canonical_json", "canonical_json.py", False),
    ("mnemosyne_core.safety", "safety.py", False),
    ("mnemosyne_core.policy", "policy.py", False),
    ("mnemosyne_core.context_assembly", "context_assembly.py", False),
    (
        "mnemosyne_core.operation_contract",
        "operation_contract/__init__.py",
        True,
    ),
    (
        "mnemosyne_core.operation_contract.codec",
        "operation_contract/codec.py",
        False,
    ),
    (
        "mnemosyne_core.artifact_contract",
        "artifact_contract/__init__.py",
        True,
    ),
    (
        "mnemosyne_core.artifact_contract.compatibility",
        "artifact_contract/compatibility.py",
        False,
    ),
    ("mnemosyne_core.librarian_contract", "librarian_contract.py", False),
    ("mnemosyne_core.librarian_projection", "librarian_projection.py", False),
    (
        "mnemosyne_core.operation_control",
        "operation_control/__init__.py",
        True,
    ),
    (
        "mnemosyne_core.operation_control.catalog",
        "operation_control/catalog.py",
        False,
    ),
    (
        "mnemosyne_core.workspace_sync_review",
        "workspace_sync_review.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime",
        "authority_runtime/__init__.py",
        True,
    ),
    ("mnemosyne_core.control", "control.py", False),
    ("mnemosyne_core.ledger_schema", "ledger_schema.py", False),
    (
        "mnemosyne_core.activation_foundation",
        "activation_foundation.py",
        False,
    ),
    ("mnemosyne_core.activation_contract", "activation_contract.py", False),
    ("mnemosyne_core.activation_markers", "activation_markers.py", False),
    ("mnemosyne_core.inventory", "inventory.py", False),
    ("mnemosyne_core.policy_state", "policy_state.py", False),
    ("mnemosyne_core.policy_authority", "policy_authority.py", False),
    ("mnemosyne_core.admission", "admission.py", False),
    ("mnemosyne_core.inventory_workflow", "inventory_workflow.py", False),
    ("mnemosyne_core.classification", "classification.py", False),
    ("mnemosyne_core.routing_risk", "routing_risk.py", False),
    ("mnemosyne_core.references", "references.py", False),
    ("mnemosyne_core.review_units", "review_units.py", False),
    ("mnemosyne_core.review_compiler", "review_compiler.py", False),
    ("mnemosyne_core.review_package", "review_package.py", False),
    ("mnemosyne_core.canonical_curation", "canonical_curation.py", False),
    (
        "mnemosyne_core.canonical_curation_review",
        "canonical_curation_review.py",
        False,
    ),
    ("mnemosyne_core.canonical_curation_m3", "canonical_curation_m3.py", False),
    (
        "mnemosyne_core.canonical_curation_m3_review",
        "canonical_curation_m3_review.py",
        False,
    ),
    ("mnemosyne_core.projection_refresh", "projection_refresh.py", False),
    ("mnemosyne_core.review_snapshot", "review_snapshot.py", False),
    ("mnemosyne_core.review_context", "review_context.py", False),
    ("mnemosyne_core.review_draft", "review_draft.py", False),
    ("mnemosyne_core.campaign_ledger", "campaign_ledger.py", False),
    ("mnemosyne_core.batch_event_contract", "batch_event_contract.py", False),
    ("mnemosyne_core.m3_schema", "m3_schema.py", False),
    ("mnemosyne_core.ledger_runtime", "ledger_runtime.py", False),
    ("mnemosyne_core.curation_audit", "curation_audit.py", False),
    (
        "mnemosyne_core.authority_runtime.activation",
        "authority_runtime/activation.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime._durable_snapshot",
        "authority_runtime/_durable_snapshot.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime.durable",
        "authority_runtime/durable.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime.librarian",
        "authority_runtime/librarian.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime.librarian_snapshot",
        "authority_runtime/librarian_snapshot.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime.canonical_curation",
        "authority_runtime/canonical_curation.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime.canonical_curation_m3",
        "authority_runtime/canonical_curation_m3.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime.auxiliary_index",
        "authority_runtime/auxiliary_index.py",
        False,
    ),
    (
        "mnemosyne_core.authority_runtime.workstream_inspection",
        "authority_runtime/workstream_inspection.py",
        False,
    ),
    ("mnemosyne_core.workstream_curation", "workstream_curation.py", False),
    ("mnemosyne_core.navigation_draft", "navigation_draft.py", False),
    ("mnemosyne_core.curation_scheduler", "curation_scheduler.py", False),
    (
        "mnemosyne_core.authority_runtime.session",
        "authority_runtime/session.py",
        False,
    ),
    ("mnemosyne_core.schema_migration", "schema_migration.py", False),
    ("mnemosyne_core.decision_service", "decision_service.py", False),
    ("mnemosyne_core.deferral_service", "deferral_service.py", False),
    ("mnemosyne_core.legacy_import", "legacy_import.py", False),
    ("mnemosyne_core.batch_service", "batch_service.py", False),
    ("mnemosyne_core.run_review", "run_review.py", False),
    ("mnemosyne_core.m2_publishers", "m2_publishers.py", False),
    ("mnemosyne_core.review_state", "review_state.py", False),
    ("mnemosyne_core.explode_service", "explode_service.py", False),
    ("mnemosyne_core.m2_workflow", "m2_workflow.py", False),
    ("mnemosyne_core.m3_schema_migration", "m3_schema_migration.py", False),
    ("mnemosyne_core.batch_event_service", "batch_event_service.py", False),
    ("mnemosyne_core.split_batch_service", "split_batch_service.py", False),
    ("mnemosyne_core.m4_workflow", "m4_workflow.py", False),
    ("mnemosyne_core.progress_query", "progress_query.py", False),
    ("mnemosyne_core.curation_inspect_query", "curation_inspect_query.py", False),
    ("mnemosyne_core.review_submission", "review_submission.py", False),
    ("mnemosyne_core.deferral_store", "deferral_store.py", False),
    ("mnemosyne_core.m3_workflow", "m3_workflow.py", False),
    ("mnemosyne_core.curation_contract", "curation_contract.py", False),
    ("mnemosyne_core.curation_inspect", "curation_inspect.py", False),
    (
        "mnemosyne_core.inspect_audit_operation",
        "inspect_audit_operation.py",
        False,
    ),
    (
        "mnemosyne_core.librarian_inspection",
        "librarian_inspection.py",
        False,
    ),
    ("mnemosyne_core.librarian_records", "librarian_records.py", False),
    ("mnemosyne_core.librarian_placement", "librarian_placement.py", False),
    (
        "mnemosyne_core.operation_control.composition",
        "operation_control/composition.py",
        False,
    ),
    (
        "mnemosyne_core.operation_control.execution",
        "operation_control/execution.py",
        False,
    ),
    ("mnemosyne_core.cli", "cli/__init__.py", True),
    ("mnemosyne_core.cli.canonical_file", "cli/canonical_file.py", False),
    ("mnemosyne_core.cli.dispatch", "cli/dispatch.py", False),
    (
        "mnemosyne_core.cli.request_builder",
        "cli/request_builder.py",
        False,
    ),
    (
        "mnemosyne_core.cli.context_activation",
        "cli/context_activation.py",
        False,
    ),
    ("mnemosyne_core.cli.inspect", "cli/inspect.py", False),
    ("mnemosyne_core.cli.guide", "cli/guide.py", False),
    ("mnemosyne_core.raw_memory_query", "raw_memory_query.py", False),
)


def _bootstrap_read_core_source(core_directory_fd: int, core_root: Path, name: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    path = core_root / name
    try:
        lexical = os.stat(name, dir_fd=core_directory_fd, follow_symlinks=False)
        fd = os.open(name, flags, dir_fd=core_directory_fd)
    except OSError as exc:
        raise RuntimeError("core source is unavailable") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise RuntimeError("core source is unsafe")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        final = os.stat(name, dir_fd=core_directory_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
            raise RuntimeError("core source changed during bootstrap")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _bootstrap_module_shell(
    name: str,
    path: Path,
    package: str,
    *,
    is_package: bool,
) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__cached__ = None
    module.__package__ = name if is_package else package
    module.__loader__ = None
    module.__spec__ = importlib.machinery.ModuleSpec(
        name,
        loader=None,
        origin=str(path),
        is_package=is_package,
    )
    if is_package:
        module.__path__ = []
        module.__spec__.submodule_search_locations = []
    sys.modules[name] = module
    return module


class _VerifiedCoreImportGuard:
    def __init__(self, package_name: str, allowed_names: tuple[str, ...]) -> None:
        self._prefix = package_name + "."
        self._allowed = frozenset(allowed_names)

    def find_spec(self, fullname: str, _path=None, _target=None):
        if fullname.startswith(self._prefix) and fullname not in self._allowed:
            raise ImportError("core import is outside the verified closure")
        return None


def _load_mnemosyne_core_from_source(
) -> tuple[dict[str, types.ModuleType], dict[str, str]]:
    core_root = Path(__file__).resolve().parent / "mnemosyne_core"
    names = tuple(module_name for module_name, _relative_path, _is_package in RUNTIME_MODULE_CLOSURE)
    if any(name in sys.modules for name in names):
        raise RuntimeError("core modules were loaded before verified bootstrap")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        core_directory_fd = os.open(core_root, flags)
    except OSError as exc:
        raise RuntimeError("core directory is unavailable") from exc
    try:
        core_info = os.fstat(core_directory_fd)
        if (
            not stat.S_ISDIR(core_info.st_mode)
            or core_info.st_uid != os.getuid()
            or stat.S_IMODE(core_info.st_mode) & 0o022
        ):
            raise RuntimeError("core directory is unsafe")
        sources = {
            relative_path: _bootstrap_read_core_source(
                core_directory_fd,
                core_root,
                relative_path,
            )
            for _module_name, relative_path, _is_package in RUNTIME_MODULE_CLOSURE
        }
    finally:
        os.close(core_directory_fd)

    source_manifest = types.MappingProxyType(
        {
            module_name: types.MappingProxyType(
                {
                    "relative_path": relative_path,
                    "sha256": hashlib.sha256(sources[relative_path]).hexdigest(),
                }
            )
            for module_name, relative_path, _is_package in RUNTIME_MODULE_CLOSURE
        }
    )

    package_name, package_relative_path, package_is_package = RUNTIME_MODULE_CLOSURE[0]
    if not package_is_package or "." in package_name:
        raise RuntimeError("core package contract is invalid")
    package = types.ModuleType(package_name)
    package.__file__ = str(core_root / package_relative_path)
    package.__cached__ = None
    package.__package__ = package_name
    package.__loader__ = None
    package.__path__ = []
    package.__spec__ = importlib.machinery.ModuleSpec(
        package_name,
        loader=None,
        origin=package.__file__,
        is_package=True,
    )
    package.__spec__.submodule_search_locations = []
    package._verified_source_manifest = source_manifest
    sys.modules[package_name] = package
    modules = {package_name: package}
    try:
        for module_name, relative_path, is_package in RUNTIME_MODULE_CLOSURE[1:]:
            parent_name, separator, child_name = module_name.rpartition(".")
            parent = modules.get(parent_name)
            if (
                not separator
                or not module_name.startswith(package_name + ".")
                or parent is None
                or not hasattr(parent, "__path__")
            ):
                raise RuntimeError("core module contract is invalid")
            module = _bootstrap_module_shell(
                module_name,
                core_root / relative_path,
                parent_name,
                is_package=is_package,
            )
            modules[module_name] = module
            setattr(parent, child_name, module)
        guard = _VerifiedCoreImportGuard(package_name, names)
        sys.meta_path.insert(0, guard)
        try:
            for module_name, relative_path, _is_package in RUNTIME_MODULE_CLOSURE[1:]:
                module = modules[module_name]
                exec(
                    compile(
                        sources[relative_path],
                        module.__file__,
                        "exec",
                        dont_inherit=True,
                    ),
                    module.__dict__,
                )
            exec(
                compile(
                    sources[package_relative_path],
                    package.__file__,
                    "exec",
                    dont_inherit=True,
                ),
                package.__dict__,
            )
        finally:
            sys.meta_path.remove(guard)
    except Exception:
        for name in reversed(names):
            sys.modules.pop(name, None)
        raise
    source_hashes = {
        module_name: source_manifest[module_name]["sha256"]
        for module_name, _relative_path, _is_package in RUNTIME_MODULE_CLOSURE
    }
    return modules, source_hashes


def _bootstrap_core_package() -> types.ModuleType:
    return next(
        _BOOTSTRAP_CORE_MODULES[name]
        for name, _relative_path, is_package in RUNTIME_MODULE_CLOSURE
        if is_package
    )


def _bootstrap_core_module_by_path(relative_path: str) -> types.ModuleType:
    return next(
        _BOOTSTRAP_CORE_MODULES[name]
        for name, module_path, _is_package in RUNTIME_MODULE_CLOSURE
        if module_path == relative_path
    )


try:
    _BOOTSTRAP_CORE_MODULES, _BOOTSTRAP_CORE_SOURCE_HASHES = (
        _load_mnemosyne_core_from_source()
    )
except Exception:
    print("error: verified Mnemosyne core could not be loaded", file=sys.stderr)
    raise SystemExit(2)

_mnemosyne_core = _bootstrap_core_package()
_canonical_json_core = _bootstrap_core_module_by_path("canonical_json.py")
_safety_core = _bootstrap_core_module_by_path("safety.py")
_raw_memory_query_core = _bootstrap_core_module_by_path("raw_memory_query.py")
_policy_core = _bootstrap_core_module_by_path("policy.py")
_control_core = _bootstrap_core_module_by_path("control.py")
_workspace_sync_review_core = _bootstrap_core_module_by_path("workspace_sync_review.py")
_inventory_core = _bootstrap_core_module_by_path("inventory.py")
_policy_state_core = _bootstrap_core_module_by_path("policy_state.py")
_policy_authority_core = _bootstrap_core_module_by_path("policy_authority.py")
_admission_core = _bootstrap_core_module_by_path("admission.py")
_inventory_workflow_core = _bootstrap_core_module_by_path("inventory_workflow.py")
_m2_workflow_core = _bootstrap_core_module_by_path("m2_workflow.py")
_m3_workflow_core = _bootstrap_core_module_by_path("m3_workflow.py")
_m4_workflow_core = _bootstrap_core_module_by_path("m4_workflow.py")
_schema_migration_core = _bootstrap_core_module_by_path("schema_migration.py")
_cli_dispatch_core = _bootstrap_core_module_by_path("cli/dispatch.py")
_cli_inspect_core = _bootstrap_core_module_by_path("cli/inspect.py")
_cli_guide_core = _bootstrap_core_module_by_path("cli/guide.py")


def _function_closure_state(function: types.FunctionType) -> tuple[tuple[int, str], ...]:
    if function.__closure__ is None:
        return ()
    return tuple(
        (id(cell), repr(cell.cell_contents))
        for cell in function.__closure__
    )


def _function_execution_state(function: types.FunctionType) -> dict[str, Any]:
    return {
        "code": function.__code__,
        "defaults": repr(function.__defaults__),
        "kwdefaults": repr(function.__kwdefaults__),
        "closure": _function_closure_state(function),
        "attributes": repr(function.__dict__),
    }


def _class_execution_state(class_value: type) -> dict[str, Any]:
    state: dict[str, Any] = {}
    for name, value in vars(class_value).items():
        if isinstance(value, types.FunctionType):
            functions = (("function", value, _function_execution_state(value)),)
            kind = "function"
        elif isinstance(value, (staticmethod, classmethod)):
            function = value.__func__
            functions = (("function", function, _function_execution_state(function)),)
            kind = type(value).__name__
        elif isinstance(value, property):
            functions = tuple(
                (slot, function, _function_execution_state(function))
                for slot, function in (
                    ("fget", value.fget),
                    ("fset", value.fset),
                    ("fdel", value.fdel),
                )
                if function is not None
            )
            kind = "property"
        else:
            continue
        state[name] = (kind, value, functions)
    return state


def _snapshot_core_module(
    module: types.ModuleType,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    dict[str, Any],
    dict[str, str],
    dict[str, dict[str, Any]],
]:
    functions = {
        name: value
        for name, value in vars(module).items()
        if isinstance(value, types.FunctionType) and value.__module__ == module.__name__
    }
    bindings = {
        name: value
        for name, value in vars(module).items()
        if (not name.startswith("__") or name == "__all__") and name not in functions
    }
    shapes = {
        name: repr(value)
        for name, value in bindings.items()
        if isinstance(value, (dict, list, set))
    }
    function_states = {
        name: _function_execution_state(function)
        for name, function in functions.items()
    }
    class_states = {
        name: _class_execution_state(value)
        for name, value in bindings.items()
        if isinstance(value, type) and value.__module__ == module.__name__
    }
    return functions, function_states, bindings, shapes, class_states


_BOOTSTRAP_CORE_FUNCTIONS: dict[str, dict[str, Any]] = {}
_BOOTSTRAP_CORE_FUNCTION_STATES: dict[str, dict[str, dict[str, Any]]] = {}
_BOOTSTRAP_CORE_BINDINGS: dict[str, dict[str, Any]] = {}
_BOOTSTRAP_CORE_BINDING_SHAPES: dict[str, dict[str, str]] = {}
_BOOTSTRAP_CORE_CLASS_STATES: dict[str, dict[str, dict[str, Any]]] = {}
for _module_name, _relative_path, _is_package in RUNTIME_MODULE_CLOSURE:
    _core_module = _BOOTSTRAP_CORE_MODULES[_module_name]
    _functions, _function_states, _bindings, _shapes, _class_states = (
        _snapshot_core_module(_core_module)
    )
    _BOOTSTRAP_CORE_FUNCTIONS[_core_module.__name__] = _functions
    _BOOTSTRAP_CORE_FUNCTION_STATES[_core_module.__name__] = _function_states
    _BOOTSTRAP_CORE_BINDINGS[_core_module.__name__] = _bindings
    _BOOTSTRAP_CORE_BINDING_SHAPES[_core_module.__name__] = _shapes
    _BOOTSTRAP_CORE_CLASS_STATES[_core_module.__name__] = _class_states


DEFAULT_ROOT = Path.home() / "raw"
MNEMOSYNE_COMPATIBILITY_VERSION = "document-curation-m0-v2"
# The source-controlled shell launcher has to resolve its own symlink before it
# can select a Python >= 3.10 interpreter.  It is intentionally accepted only
# when its complete, versioned byte sequence and its sibling canonical writer
# both match; generic multi-line shell launchers remain rejected.
MNEMOSYNE_CONTROL_LAUNCHER_V1_SHA256 = (
    "f7fe43eb4582ac476da1cfabd2f94b6a2dd89fafb7d8a8419067b8f1a7912140"
)
MNEMOSYNE_CONTROL_LAUNCHER_KIND = "mnemosyne-control-v1"
DIRECT_EXEC_LAUNCHER_KIND = "direct-exec-v1"
PLACEMENT_LOCK_PROTOCOL_VERSION = "placement-lock-v1"
MAX_WORKSPACE_SYNC_PLAN_BYTES = 8 * 1024 * 1024
LOCK_MIGRATION_ID_RE = re.compile(r"lockmig-\d{8}T\d{6}Z-[0-9a-f]{12}")
INTERNAL_SKIP_DIRS = {".git", "__pycache__", "_registry"}
UNSAFE_CONTENT_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{8,}"),
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
    re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
    re.compile(r"https?://[^\s]+"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"),
]


class MnemosyneError(Exception):
    pass


ManualRecoveryRequired = _safety_core.ManualRecoveryRequired


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    if value in {"true", "false"}:
        return value == "true"
    if value.isdigit():
        return int(value)
    if value[0:1] in {'"', "'"}:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value.strip("\"'")
    return value


def yaml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def parse_flat_yaml_text(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = parse_scalar(value)
    return data


def load_flat_yaml(path: Path) -> dict[str, Any]:
    return parse_flat_yaml_text(path.read_text(encoding="utf-8"))


def write_flat_yaml(path: Path, data: dict[str, Any]) -> None:
    lines = [f"{key}: {yaml_value(value)}" for key, value in data.items()]
    if path.parent.name == "pending":
        label = "pending proposal"
    elif path.parent.name == "decisions":
        label = "decision"
    else:
        label = "control YAML"
    publish_control_file_no_replace(
        path,
        ("\n".join(lines) + "\n").encode("utf-8"),
        label=label,
    )


def inspect_registry_entry(root: Path) -> tuple[bool, bytes | None]:
    registry_directory = root / "_registry"
    path = registry_path(root)
    if not os.path.lexists(registry_directory):
        return False, None
    try:
        registry_fd = open_verified_directory(registry_directory, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError(f"registry directory is unsafe: {registry_directory}") from exc
    try:
        try:
            lexical_info = os.stat(path.name, dir_fd=registry_fd, follow_symlinks=False)
        except FileNotFoundError:
            require_same_directory_identity(registry_directory, registry_fd, "registry")
            return False, None
        except OSError as exc:
            raise MnemosyneError(f"cannot inspect registry: {path}") from exc
        if not stat.S_ISREG(lexical_info.st_mode):
            raise MnemosyneError(f"registry entry is unsafe: {path}")
        info, raw = read_regular_file_at(
            registry_fd,
            path.name,
            path,
            label="registry",
            expected_mode=None,
        )
        if info.st_nlink != 1:
            raise MnemosyneError(f"registry link count is invalid: {path}")
        require_same_directory_identity(registry_directory, registry_fd, "registry")
        return True, raw
    finally:
        os.close(registry_fd)


def read_registry_bytes_verified(root: Path) -> bytes:
    exists, raw = inspect_registry_entry(root)
    if not exists or raw is None:
        raise MnemosyneError(f"registry missing: {registry_path(root)}")
    return raw


def load_registry(path: Path) -> dict[str, Any]:
    root = path.parent.parent
    if path != registry_path(root):
        raise MnemosyneError(f"registry path is not canonical: {path}")
    raw = read_registry_bytes_verified(root)
    try:
        registry_text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MnemosyneError(f"registry is not UTF-8: {path}") from exc

    data: dict[str, Any] = {"never_touch": [], "categories": []}
    section: str | None = None
    current_category: dict[str, Any] | None = None
    current_list_key: str | None = None

    for raw_line in registry_text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        if indent == 0:
            current_category = None
            current_list_key = None
            if line.endswith(":"):
                section = line[:-1].strip()
                if section in {"never_touch", "categories"}:
                    data.setdefault(section, [])
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                data[key.strip()] = parse_scalar(value)
                section = None
            continue

        if section == "never_touch" and line.startswith("- "):
            data["never_touch"].append(parse_scalar(line[2:]))
            continue

        if section != "categories":
            continue

        if indent == 2 and line.startswith("- "):
            current_category = {}
            data["categories"].append(current_category)
            current_list_key = None
            rest = line[2:].strip()
            if rest and ":" in rest:
                key, value = rest.split(":", 1)
                current_category[key.strip()] = parse_scalar(value)
            continue

        if current_category is None:
            continue

        if indent == 4:
            if line.endswith(":"):
                current_list_key = line[:-1].strip()
                current_category[current_list_key] = []
            elif ":" in line:
                key, value = line.split(":", 1)
                current_category[key.strip()] = parse_scalar(value)
                current_list_key = None
            continue

        if indent == 6 and current_list_key and line.startswith("- "):
            current_category[current_list_key].append(parse_scalar(line[2:]))

    return data


def default_registry_text(root: Path) -> str:
    root = root.resolve()
    return f"""# Mnemosyne placement registry.
# Machine-control metadata lives here, not in content files.
schema_version: 1
root: {root}
registry_root: {root / "_registry"}
inbox: {root / "inbox"}
decision_policy: propose-approve-apply
graphify_update: explicit-request-only
memory_workspaces: {root / "memory" / "workspaces.yml"}

never_touch:
  - worktrees/
  - graphify-out/
  - .agents/
  - .claude/
  - .codex/
  - .gemini/
  - .harnesskit/

categories:
  - id: memory
    target: {root / "memory"}
    description: Workspace memory snapshots, history, and policy summaries.
    patterns:
      - memory/**
      - "*memory*"
      - "snapshot.md"
  - id: projects
    target: {root / "projects"}
    description: Project-specific source references, planning notes, and handoffs.
    patterns:
      - projects/**
      - "*project*"
      - "*handoff*"
      - "*plan*"
  - id: artifacts
    target: {root / "artifacts"}
    description: Generated or reviewable artifacts that are not registry control files.
    patterns:
      - artifacts/**
      - "*.html"
      - "*.svg"
      - "*.png"
      - "*.jpg"
      - "*.jpeg"
      - "*.json"
  - id: reports
    target: {root / "reports"}
    description: Audits, reviews, summaries, and report-style outputs.
    patterns:
      - reports/**
      - "*audit*"
      - "*report*"
      - "*review*"
  - id: docs
    target: {root / "docs"}
    description: General human-readable notes and docs without a more specific project home.
    patterns:
      - docs/**
      - "*.md"
      - "*.txt"
  - id: agents
    target: {root / "agents"}
    description: Agent specs, skills, and agent-local implementation files.
    patterns:
      - agents/**
      - "SKILL.md"
      - "*agent*"
  - id: tooling
    target: {root / "tooling"}
    description: Local helper scripts and tool wrappers.
    patterns:
      - tooling/**
      - "*.py"
      - "*.sh"
  - id: private
    target: {root / "private"}
    description: Private, redacted, or access-controlled notes that are safe to store locally.
    patterns:
      - private/**
      - "*private*"
      - "*redacted*"
  - id: mirrors
    target: {root / "mirrors"}
    description: Mirrored external content kept as read-only reference material.
    patterns:
      - mirrors/**
      - "*mirror*"
  - id: inbox_review
    target: {root / "inbox" / "review"}
    description: Fallback holding area for items that need manual classification.
    patterns:
      - inbox/**
"""


def registry_path(root: Path) -> Path:
    return root / "_registry" / "placement-map.yml"


def pending_dir(root: Path) -> Path:
    return root / "_registry" / "pending"


def decisions_dir(root: Path) -> Path:
    return root / "_registry" / "decisions"


def lock_migrations_dir(root: Path) -> Path:
    return root / "_registry" / "lock-migrations"


def manual_recovery_dir(root: Path) -> Path:
    return lock_migrations_dir(root) / "manual-recovery"


def placement_lock_path(root: Path) -> Path:
    return root / "_registry" / "placement-map.lock"


def require_no_active_lock_migration(root: Path) -> None:
    if os.path.lexists(lock_migrations_dir(root) / "active"):
        raise MnemosyneError(
            "lock migration is active; legacy placement writes are blocked"
        )


def require_no_manual_recovery_blockers(root: Path) -> None:
    directory = manual_recovery_dir(root)
    if not os.path.lexists(directory):
        return
    try:
        directory_fd = open_verified_directory(directory, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError("manual recovery blocker directory is not verified") from exc
    try:
        before_token = directory_mutation_token(os.fstat(directory_fd))
        entries = sorted(os.listdir(directory_fd))
        require_same_directory_identity(directory, directory_fd, "manual recovery blocker")
        after_token = directory_mutation_token(os.fstat(directory_fd))
        if entries:
            raise MnemosyneError(
                "unresolved manual recovery blocker prevents placement writes"
            )
        if before_token != after_token:
            raise MnemosyneError(
                "manual recovery blocker directory changed during inspection"
            )
    except OSError as exc:
        raise MnemosyneError("cannot inspect manual recovery blockers") from exc
    finally:
        os.close(directory_fd)


_MANUAL_RECOVERY_GUARD_FACTORY_TOKEN = object()


class ManualRecoveryGuard:
    def __init__(
        self,
        root: Path,
        root_fd: int,
        factory_token: object | None = None,
    ) -> None:
        if factory_token is not _MANUAL_RECOVERY_GUARD_FACTORY_TOKEN:
            raise MnemosyneError(
                "manual recovery guard must be created by manual_recovery_guard"
            )
        self.root = root
        self._root_fd = root_fd
        self._active = True
        self._published_blocker = False

    def require_active(self) -> None:
        if not self._active:
            raise MnemosyneError("manual recovery coordination guard is no longer active")
        require_same_directory_identity(
            self.root,
            self._root_fd,
            "manual recovery coordination",
        )

    def checkpoint(self) -> None:
        self.require_active()
        require_no_manual_recovery_blockers(self.root)

    def mark_blocker_published(self) -> None:
        self.require_active()
        self._published_blocker = True

    @property
    def published_blocker(self) -> bool:
        return self._published_blocker

    def close(self) -> None:
        self._active = False


@contextmanager
def manual_recovery_guard(root: Path) -> Iterator[ManualRecoveryGuard]:
    root = root.resolve()
    root_fd = open_verified_directory(root, require_owner_only=True)
    locked = False
    guard = ManualRecoveryGuard(
        root,
        root_fd,
        _MANUAL_RECOVERY_GUARD_FACTORY_TOKEN,
    )
    try:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX)
            locked = True
        except OSError as exc:
            raise MnemosyneError("cannot acquire manual recovery coordination guard") from exc
        guard.checkpoint()
        yield guard
        if guard.published_blocker:
            guard.require_active()
        else:
            guard.checkpoint()
    finally:
        guard.close()
        try:
            if locked:
                fcntl.flock(root_fd, fcntl.LOCK_UN)
        finally:
            os.close(root_fd)


class LegacyWriterAuthority:
    def __init__(self, guard: ManualRecoveryGuard, checkpoint: Any) -> None:
        self.recovery_guard = guard
        self._checkpoint = checkpoint

    def __call__(self) -> None:
        self.recovery_guard.checkpoint()
        self._checkpoint()


def process_start_identity(pid: int) -> str:
    if sys.platform == "darwin":
        class ProcBsdInfo(ctypes.Structure):
            _fields_ = [
                ("pbi_flags", ctypes.c_uint32),
                ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32),
                ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32),
                ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32),
                ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32),
                ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32),
                ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16),
                ("pbi_name", ctypes.c_char * 32),
                ("pbi_nfiles", ctypes.c_uint32),
                ("pbi_pgid", ctypes.c_uint32),
                ("pbi_pjobc", ctypes.c_uint32),
                ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32),
                ("pbi_nice", ctypes.c_int32),
                ("pbi_start_tvsec", ctypes.c_uint64),
                ("pbi_start_tvusec", ctypes.c_uint64),
            ]

        try:
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            proc_pidinfo = libproc.proc_pidinfo
            proc_pidinfo.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            proc_pidinfo.restype = ctypes.c_int
            info = ProcBsdInfo()
            size = ctypes.sizeof(info)
            returned = proc_pidinfo(pid, 3, 0, ctypes.byref(info), size)
        except (AttributeError, OSError) as exc:
            raise MnemosyneError(f"cannot determine process start identity for pid {pid}") from exc
        if returned != size or info.pbi_pid != pid or info.pbi_start_tvsec == 0:
            raise MnemosyneError(f"cannot determine process start identity for pid {pid}")
        return f"darwin:{info.pbi_start_tvsec}.{info.pbi_start_tvusec:06d}"

    if sys.platform.startswith("linux"):
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            after_name = stat_text[stat_text.rindex(")") + 2 :].split()
            start_ticks = after_name[19]
        except (OSError, ValueError, IndexError) as exc:
            raise MnemosyneError(f"cannot determine process start identity for pid {pid}") from exc
        return f"linux:{start_ticks}"

    try:
        result = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MnemosyneError(f"cannot determine process start identity for pid {pid}") from exc
    identity = " ".join(result.stdout.split())
    if result.returncode != 0 or not identity:
        raise MnemosyneError(f"cannot determine process start identity for pid {pid}")
    return identity


def probe_process_identity(pid: int, expected_start_identity: str) -> dict[str, Any]:
    if pid <= 0:
        return {
            "status": "dead",
            "reason": "invalid-pid",
            "pid": pid,
            "expected_start_identity": expected_start_identity,
            "observed_start_identity": None,
        }
    try:
        observed = process_start_identity(pid)
    except MnemosyneError:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            status = "dead"
            reason = "pid-absent"
        except (PermissionError, OSError):
            status = "ambiguous"
            reason = "start-identity-unavailable"
        else:
            status = "ambiguous"
            reason = "start-identity-unavailable"
        return {
            "status": status,
            "reason": reason,
            "pid": pid,
            "expected_start_identity": expected_start_identity,
            "observed_start_identity": None,
        }

    if observed == expected_start_identity:
        status = "alive"
        reason = "identity-match"
    else:
        status = "dead"
        reason = "pid-reused"
    return {
        "status": status,
        "reason": reason,
        "pid": pid,
        "expected_start_identity": expected_start_identity,
        "observed_start_identity": observed,
    }


def canonical_json_bytes(value: Any) -> bytes:
    return _canonical_json_core.canonical_json_bytes(value)


def sha256_bytes(value: bytes) -> str:
    return _canonical_json_core.sha256_bytes(value)


def validate_lock_migration_id(value: str) -> str:
    if not LOCK_MIGRATION_ID_RE.fullmatch(value):
        raise MnemosyneError("invalid lock migration id")
    return value


def yaml_directory_manifest(path: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    try:
        directory_fd = open_verified_directory(path, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError(f"manifest directory is unsafe: {path}") from exc
    try:
        try:
            names = sorted(name for name in os.listdir(directory_fd) if name.endswith(".yml"))
        except OSError as exc:
            raise MnemosyneError(f"cannot list manifest directory: {path}") from exc
        for name in names:
            child = path / name
            info, raw = read_regular_file_at(
                directory_fd,
                name,
                child,
                label="manifest entry",
                expected_mode=None,
            )
            if info.st_nlink != 1:
                raise MnemosyneError(f"manifest entry link count is invalid: {child}")
            entries.append({"name": name, "size": len(raw), "sha256": sha256_bytes(raw)})
        require_same_directory_identity(path, directory_fd, "manifest")
    finally:
        os.close(directory_fd)
    return {"entries": entries, "root_sha256": sha256_bytes(canonical_json_bytes(entries))}


def registry_has_curation_section(registry_bytes: bytes) -> bool:
    text = registry_bytes.decode("utf-8")
    return any(re.fullmatch(r"curation\s*:\s*(?:#.*)?", line) for line in text.splitlines())


def require_lock_migration_ledger_absent(root: Path) -> None:
    curation_directory = root / "_registry" / "curation"
    if not os.path.lexists(curation_directory):
        return
    try:
        curation_fd = open_verified_directory(curation_directory, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError("lock migration requires ledger to be absent") from exc
    try:
        try:
            os.stat("ledger.sqlite3", dir_fd=curation_fd, follow_symlinks=False)
        except FileNotFoundError:
            require_same_directory_identity(curation_directory, curation_fd, "curation")
            return
        except OSError as exc:
            raise MnemosyneError("lock migration requires ledger to be absent") from exc
        raise MnemosyneError("lock migration requires ledger to be absent")
    finally:
        os.close(curation_fd)


def open_or_create_verified_directory(path: Path, *, mode: int = 0o700) -> int:
    return _safety_core.open_or_create_verified_directory(
        path,
        mode=mode,
        error_type=MnemosyneError,
    )


def create_verified_directory_no_replace(
    path: Path,
    *,
    label: str,
    collision_error: str,
    mode: int = 0o700,
) -> None:
    _safety_core.create_verified_directory_no_replace(
        path,
        label=label,
        collision_error=collision_error,
        mode=mode,
        error_type=MnemosyneError,
        before_directory_identity_check=safety_before_directory_identity_check,
    )


def safety_before_directory_identity_check(_path: Path, _fd: int, _label: str) -> None:
    """Observational fault seam before mandatory core identity verification."""


def sealed_artifact_after_fd_readback(_path: Path, _fd: int, _directory_fd: int) -> None:
    """Fault-injection seam after atomic publish and before final readback."""


def publish_bytes_atomic_no_replace(
    path: Path,
    encoded: bytes,
    *,
    label: str,
    mode: int,
    create_parent: bool,
    collision_error: str,
    final_identity_error: str,
    parent_error: str,
) -> os.stat_result:
    return _safety_core.publish_bytes_atomic_no_replace(
        path,
        encoded,
        label=label,
        mode=mode,
        create_parent=create_parent,
        collision_error=collision_error,
        final_identity_error=final_identity_error,
        parent_error=parent_error,
        error_type=MnemosyneError,
        after_fd_readback=sealed_artifact_after_fd_readback,
        before_directory_identity_check=safety_before_directory_identity_check,
    )


def publish_control_file_no_replace(
    path: Path,
    encoded: bytes,
    *,
    label: str,
    mode: int = 0o600,
) -> tuple[int, int]:
    info = publish_bytes_atomic_no_replace(
        path,
        encoded,
        label=label,
        mode=mode,
        create_parent=False,
        collision_error=f"refusing to overwrite {label}: {path}",
        final_identity_error=f"{label} final identity changed: {path}",
        parent_error=f"cannot open verified {label} parent: {path.parent}",
    )
    return info.st_dev, info.st_ino


def publish_json_no_replace(path: Path, value: Any, *, mode: int = 0o600) -> str:
    encoded = canonical_json_bytes(value)
    publish_bytes_atomic_no_replace(
        path,
        encoded,
        label="sealed artifact",
        mode=mode,
        create_parent=True,
        collision_error=f"refusing to overwrite sealed artifact: {path}",
        final_identity_error=f"sealed artifact final identity changed: {path}",
        parent_error=f"cannot open verified artifact parent: {path.parent}",
    )
    return sha256_bytes(encoded)


def open_verified_directory(path: Path, *, require_owner_only: bool = False) -> int:
    """Open an absolute directory one no-follow component at a time."""
    return _safety_core.open_verified_directory(
        path,
        require_owner_only=require_owner_only,
        error_type=MnemosyneError,
    )


def verified_directory_present(path: Path, *, label: str) -> bool:
    return _safety_core.verified_directory_present(
        path,
        label=label,
        error_type=MnemosyneError,
        before_directory_identity_check=safety_before_directory_identity_check,
    )


def read_open_file_bytes(fd: int) -> bytes:
    return _safety_core.read_open_file_bytes(fd)


def validate_open_placement_lock(
    fd: int,
    path: Path,
    expected_sha256: str | None,
) -> os.stat_result:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
    ):
        raise MnemosyneError(f"placement lock identity is invalid: {path}")
    if (
        expected_sha256 is not None
        and sha256_bytes(read_open_file_bytes(fd)) != expected_sha256
    ):
        raise MnemosyneError(f"placement lock readback mismatch: {path}")
    return info


def open_placement_lock_verified(root: Path, expected_sha256: str | None) -> int:
    registry = root / "_registry"
    try:
        registry_fd = open_verified_directory(registry, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError(f"cannot open verified registry directory: {registry}") from exc
    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock_path = placement_lock_path(root)
    try:
        lock_fd = os.open("placement-map.lock", flags, dir_fd=registry_fd)
        lexical_info = os.stat(
            "placement-map.lock",
            dir_fd=registry_fd,
            follow_symlinks=False,
        )
        opened_info = validate_open_placement_lock(lock_fd, lock_path, expected_sha256)
        if (opened_info.st_dev, opened_info.st_ino) != (
            lexical_info.st_dev,
            lexical_info.st_ino,
        ):
            raise MnemosyneError(
                f"placement lock identity changed while opening: {lock_path}"
            )
        return lock_fd
    except MnemosyneError:
        if "lock_fd" in locals():
            os.close(lock_fd)
        raise
    except OSError as exc:
        if "lock_fd" in locals():
            os.close(lock_fd)
        raise MnemosyneError(f"cannot open placement lock: {lock_path}") from exc
    finally:
        os.close(registry_fd)


def publish_placement_lock_no_replace(root: Path, value: Any) -> str:
    encoded = canonical_json_bytes(value)
    lock_path = placement_lock_path(root)
    publish_bytes_atomic_no_replace(
        lock_path,
        encoded,
        label="placement lock",
        mode=0o600,
        create_parent=False,
        collision_error=f"refusing to overwrite placement lock: {lock_path}",
        final_identity_error=(
            f"placement lock identity changed during publish: {lock_path}"
        ),
        parent_error=f"cannot open verified registry directory: {lock_path.parent}",
    )
    validate_placement_lock(lock_path, sha256_bytes(encoded))
    return sha256_bytes(encoded)


def read_owner_only_manifest(path: Path) -> tuple[bytes, dict[str, Any], os.stat_result]:
    if not path.is_absolute():
        raise MnemosyneError("installed entrypoint manifest path must be absolute")
    try:
        lexical_info = os.lstat(path)
    except OSError as exc:
        raise MnemosyneError(f"installed entrypoint manifest is unreadable: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(lexical_info.st_mode)
        or stat.S_IMODE(lexical_info.st_mode) != 0o600
        or lexical_info.st_uid != os.getuid()
        or lexical_info.st_nlink != 1
    ):
        raise MnemosyneError(
            "installed entrypoint manifest must be owner-only mode 0600 regular file"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise MnemosyneError(f"installed entrypoint manifest is unreadable: {path}") from exc
    try:
        opened_info = os.fstat(fd)
        if (opened_info.st_dev, opened_info.st_ino) != (
            lexical_info.st_dev,
            lexical_info.st_ino,
        ):
            raise MnemosyneError(
                "installed entrypoint manifest identity changed while opening"
            )
        raw = read_open_file_bytes(fd)
    finally:
        os.close(fd)
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MnemosyneError("installed entrypoint manifest is invalid JSON") from exc
    if raw != canonical_json_bytes(manifest):
        raise MnemosyneError("installed entrypoint manifest is not canonical JSON")
    return raw, manifest, opened_info


def entrypoint_candidate_name(name: str) -> bool:
    return name in {"mnemosyne", "mnemosyne.py"} or name.startswith(
        ("mnemosyne-", "mnemosyne.")
    )


def executable_looks_like_legacy_writer_at(
    directory_fd: int,
    name: str,
    path: Path,
) -> bool:
    try:
        lexical_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    if (
        not stat.S_ISREG(lexical_info.st_mode)
        or not stat.S_IMODE(lexical_info.st_mode) & 0o111
    ):
        return False
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise MnemosyneError(f"cannot inspect executable entrypoint candidate: {path}") from exc
    try:
        opened_info = os.fstat(fd)
        if (
            not stat.S_ISREG(opened_info.st_mode)
            or not stat.S_IMODE(opened_info.st_mode) & 0o111
            or (opened_info.st_dev, opened_info.st_ino)
            != (lexical_info.st_dev, lexical_info.st_ino)
        ):
            raise MnemosyneError(f"executable entrypoint candidate identity is unsafe: {path}")
        raw = os.read(fd, 1024 * 1024)
        final_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (final_info.st_dev, final_info.st_ino) != (opened_info.st_dev, opened_info.st_ino):
            raise MnemosyneError(f"executable entrypoint candidate identity changed: {path}")
    finally:
        os.close(fd)
    lowered = raw.lower()
    return b"mnemosyne" in lowered and any(
        marker in lowered
        for marker in [b"placement-map.yml", b"propose-place", b"lock-migrations"]
    )


def symlink_target_looks_like_legacy_writer_at(
    directory_fd: int,
    name: str,
    alias_path: Path,
) -> bool:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    if not stat.S_ISLNK(before.st_mode):
        return False
    try:
        link_value = os.readlink(name, dir_fd=directory_fd)
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise MnemosyneError(f"cannot inspect symlink entrypoint candidate: {alias_path}") from exc
    if (
        before.st_uid != os.getuid()
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise MnemosyneError(f"symlink entrypoint candidate identity is unsafe: {alias_path}")
    raw_target = Path(link_value)
    target = raw_target if raw_target.is_absolute() else alias_path.parent / raw_target
    lexical_target = Path(os.path.abspath(target))
    try:
        target_parent_fd = open_verified_directory(lexical_target.parent)
    except MnemosyneError as exc:
        raise MnemosyneError(f"symlink entrypoint target is unsafe: {alias_path}") from exc
    try:
        return executable_looks_like_legacy_writer_at(
            target_parent_fd,
            lexical_target.name,
            lexical_target,
        )
    finally:
        os.close(target_parent_fd)


def regular_file_evidence(
    path: Path,
    expected_sha256: str,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    if not path.is_absolute():
        raise MnemosyneError(f"{label} path must be absolute: {path}")
    try:
        opened_info, raw = read_verified_regular_file(
            path,
            label=label,
            expected_mode=None,
        )
    except MnemosyneError as exc:
        raise MnemosyneError(f"{label} identity is unsafe: {path}") from exc
    if opened_info.st_nlink != 1:
        raise MnemosyneError(f"{label} identity is unsafe: {path}")
    actual_sha256 = sha256_bytes(raw)
    if actual_sha256 != expected_sha256:
        raise MnemosyneError(f"{label} hash mismatch: {path}")
    return (
        {
            "path": str(path),
            "sha256": actual_sha256,
            "device": opened_info.st_dev,
            "inode": opened_info.st_ino,
            "uid": opened_info.st_uid,
            "mode": f"{stat.S_IMODE(opened_info.st_mode):04o}",
            "nlink": opened_info.st_nlink,
            "lexical_kind": "regular",
        },
        raw,
    )


def durable_entrypoint_file_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Remove read-episode inode data from durable installation authority."""
    ephemeral_keys = {"device", "inode", "link_device", "link_inode"}
    return {key: value for key, value in evidence.items() if key not in ephemeral_keys}


def writer_symlink_alias_evidence(
    alias_path: Path,
    canonical_path: Path,
    canonical: dict[str, Any],
) -> dict[str, Any]:
    if not alias_path.is_absolute():
        raise MnemosyneError(f"writer alias path must be absolute: {alias_path}")
    try:
        parent_fd = open_verified_directory(alias_path.parent, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError(f"writer alias parent is unsafe: {alias_path.parent}") from exc
    try:
        try:
            before = os.stat(alias_path.name, dir_fd=parent_fd, follow_symlinks=False)
            link_value = os.readlink(alias_path.name, dir_fd=parent_fd)
            after = os.stat(alias_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise MnemosyneError(f"writer alias is unreadable: {alias_path}") from exc
        if (
            not stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.getuid()
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise MnemosyneError(f"writer alias identity is unsafe: {alias_path}")
        raw_target = Path(link_value)
        target = raw_target if raw_target.is_absolute() else alias_path.parent / raw_target
        lexical_target = Path(os.path.abspath(target))
        if lexical_target != canonical_path:
            raise MnemosyneError(f"writer alias target mismatch: {alias_path}")
        require_same_directory_identity(alias_path.parent, parent_fd, "writer alias")
        return {
            "path": str(alias_path),
            "sha256": canonical["sha256"],
            "device": canonical["device"],
            "inode": canonical["inode"],
            "uid": before.st_uid,
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "nlink": before.st_nlink,
            "lexical_kind": "symlink",
            "link_device": before.st_dev,
            "link_inode": before.st_ino,
            "link_target": link_value,
        }
    finally:
        os.close(parent_fd)


def launcher_symlink_alias_evidence(
    alias_path: Path,
    launcher_path: Path,
    launcher: dict[str, Any],
) -> dict[str, Any]:
    if not alias_path.is_absolute():
        raise MnemosyneError(f"launcher alias path must be absolute: {alias_path}")
    try:
        parent_fd = open_verified_directory(alias_path.parent, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError(f"launcher alias parent is unsafe: {alias_path.parent}") from exc
    try:
        try:
            before = os.stat(alias_path.name, dir_fd=parent_fd, follow_symlinks=False)
            link_value = os.readlink(alias_path.name, dir_fd=parent_fd)
            after = os.stat(alias_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise MnemosyneError(f"launcher alias is unreadable: {alias_path}") from exc
        if (
            not stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.getuid()
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise MnemosyneError(f"launcher alias identity is unsafe: {alias_path}")
        raw_target = Path(link_value)
        target = raw_target if raw_target.is_absolute() else alias_path.parent / raw_target
        lexical_target = Path(os.path.abspath(target))
        if lexical_target != launcher_path:
            raise MnemosyneError(f"launcher alias target mismatch: {alias_path}")
        require_same_directory_identity(alias_path.parent, parent_fd, "launcher alias")
        return {
            "path": str(alias_path),
            "sha256": launcher["sha256"],
            "device": launcher["device"],
            "inode": launcher["inode"],
            "uid": before.st_uid,
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "nlink": before.st_nlink,
            "lexical_kind": "symlink",
            "link_device": before.st_dev,
            "link_inode": before.st_ino,
            "link_target": link_value,
        }
    finally:
        os.close(parent_fd)


def launcher_bytes_match_delegate(
    raw: bytes,
    delegate: str,
    direct_writer_paths: set[str],
    instruction_surface_paths: set[str],
    launcher_path: Path,
    launcher_kind: str | None,
) -> bool:
    canonical_path = Path(__file__).resolve()
    if (
        launcher_kind == MNEMOSYNE_CONTROL_LAUNCHER_KIND
        and launcher_path.resolve() == canonical_path.parent / "mnemosyne-control"
        and delegate == str(canonical_path)
        and sha256_bytes(raw) == MNEMOSYNE_CONTROL_LAUNCHER_V1_SHA256
    ):
        return True
    if launcher_kind not in {None, DIRECT_EXEC_LAUNCHER_KIND}:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    if len(lines) != 1 or lines[0].startswith("#"):
        return False
    try:
        tokens = shlex.split(lines[0], posix=True)
    except ValueError:
        return False
    if len(tokens) < 3 or tokens[0] != "exec" or tokens[-1] != "$@":
        return False
    if delegate in direct_writer_paths:
        if tokens == ["exec", delegate, "$@"]:
            return True
        return (
            len(tokens) == 4
            and Path(tokens[1]).name in {"python", "python3"}
            and tokens[2] == delegate
        )
    if delegate in instruction_surface_paths:
        delegate_path = Path(delegate)
        if tuple(delegate_path.parts[-4:]) != (".hermes", "skills", "mnemosyne", "SKILL.md"):
            return False
        command = tokens[1:-1]
        if len(command) != 3 or Path(command[0]).name != "hermes":
            return False
        return command[1:] in (["-p", "mnemosyne"], ["--profile", "mnemosyne"])
    return False


def canonical_source_scripts_alias_root(alias_path: Path, source_root: Path) -> Path:
    """Accept only a direct, owner-controlled alias of the canonical scripts root."""
    try:
        parent_fd = open_verified_directory(alias_path.parent, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError(
            f"authoritative source scripts alias parent is unsafe: {alias_path.parent}"
        ) from exc
    try:
        try:
            before = os.stat(alias_path.name, dir_fd=parent_fd, follow_symlinks=False)
            link_value = os.readlink(alias_path.name, dir_fd=parent_fd)
            after = os.stat(alias_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise MnemosyneError(
                f"authoritative source scripts alias is unreadable: {alias_path}"
            ) from exc
        if (
            not stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.getuid()
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise MnemosyneError(
                f"authoritative source scripts alias identity is unsafe: {alias_path}"
            )
        raw_target = Path(link_value)
        target = raw_target if raw_target.is_absolute() else alias_path.parent / raw_target
        if Path(os.path.abspath(target)) != source_root:
            raise MnemosyneError(
                f"authoritative source scripts alias target is invalid: {alias_path}"
            )
        require_same_directory_identity(alias_path.parent, parent_fd, "source scripts alias")
        return source_root
    finally:
        os.close(parent_fd)


def authoritative_entrypoint_discovery_roots(home_root: Path | None = None) -> list[Path]:
    home = Path.home() if home_root is None else home_root
    source_root = Path(__file__).resolve().parent
    candidates = [
        (source_root, False),
        (home / ".local" / "bin", False),
        (home / ".hermes" / "skills" / "mnemosyne" / "scripts", True),
        (home / ".codex" / "skills" / "mnemosyne" / "scripts", True),
        (home / ".claude" / "skills" / "mnemosyne" / "scripts", True),
    ]
    roots: list[Path] = []
    for candidate, can_alias_source in candidates:
        if not os.path.lexists(candidate):
            continue
        if candidate.is_symlink():
            if not can_alias_source:
                raise MnemosyneError(
                    f"authoritative entrypoint discovery root is symlinked: {candidate}"
                )
            candidate = canonical_source_scripts_alias_root(candidate, source_root)
        if candidate not in roots:
            roots.append(candidate)
    return roots


def authoritative_entrypoint_instruction_surfaces(home_root: Path | None = None) -> list[Path]:
    home = Path.home() if home_root is None else home_root
    candidates = [
        home / ".codex" / "skills" / "mnemosyne" / "SKILL.md",
        home / ".hermes" / "skills" / "mnemosyne" / "SKILL.md",
        home / ".claude" / "skills" / "mnemosyne" / "SKILL.md",
    ]
    return [path for path in candidates if os.path.lexists(path)]


def read_runtime_source_bytes(path: Path) -> bytes:
    """Read a runtime source file without trusting the extracted safety module."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lexical = os.lstat(path)
        fd = os.open(path, flags)
    except OSError as exc:
        raise MnemosyneError(f"installed runtime module source is unreadable: {path}") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise MnemosyneError(f"installed runtime module source is unsafe: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        final = os.lstat(path)
        if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
            raise MnemosyneError(f"installed runtime module source changed during read: {path}")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _function_matches_snapshot(
    function: types.FunctionType,
    expected_function: types.FunctionType,
    expected_state: dict[str, Any],
) -> bool:
    return (
        function is expected_function
        and function.__code__ is expected_state["code"]
        and repr(function.__defaults__) == expected_state["defaults"]
        and repr(function.__kwdefaults__) == expected_state["kwdefaults"]
        and _function_closure_state(function) == expected_state["closure"]
        and repr(function.__dict__) == expected_state["attributes"]
    )


def verify_loaded_runtime_module_code(module: Any, path: Path) -> None:
    """Verify the source-only bootstrap objects and globals remain unchanged."""
    raw = read_runtime_source_bytes(path)
    if hashlib.sha256(raw).hexdigest() != _BOOTSTRAP_CORE_SOURCE_HASHES[module.__name__]:
        raise MnemosyneError(f"installed runtime module code does not match verified source: {path}")
    if (
        module.__file__ != str(path)
        or module.__cached__ is not None
        or module.__loader__ is not None
        or module.__spec__ is None
        or module.__spec__.origin != str(path)
    ):
        raise MnemosyneError(f"installed runtime module loader provenance is invalid: {path}")

    expected_functions = _BOOTSTRAP_CORE_FUNCTIONS[module.__name__]
    current_functions = {
        name: value
        for name, value in vars(module).items()
        if isinstance(value, types.FunctionType) and value.__module__ == module.__name__
    }
    if set(current_functions) != set(expected_functions) or any(
        current_functions[name] is not expected for name, expected in expected_functions.items()
    ):
        raise MnemosyneError(f"installed runtime module code does not match verified source: {path}")
    expected_function_states = _BOOTSTRAP_CORE_FUNCTION_STATES[module.__name__]
    for name, current in current_functions.items():
        expected_state = expected_function_states[name]
        if not _function_matches_snapshot(
            current,
            expected_functions[name],
            expected_state,
        ):
            raise MnemosyneError(
                f"installed runtime module function state does not match verified source: {path}"
            )

    expected_bindings = _BOOTSTRAP_CORE_BINDINGS[module.__name__]
    current_bindings = {
        name: value
        for name, value in vars(module).items()
        if (not name.startswith("__") or name == "__all__") and name not in current_functions
    }
    if set(current_bindings) != set(expected_bindings):
        raise MnemosyneError(f"installed runtime module globals do not match verified source: {path}")
    for name, expected in expected_bindings.items():
        if current_bindings[name] is not expected:
            raise MnemosyneError(
                f"installed runtime module globals do not match verified source: {path}"
            )
        expected_shape = _BOOTSTRAP_CORE_BINDING_SHAPES[module.__name__].get(name)
        if expected_shape is not None and repr(current_bindings[name]) != expected_shape:
            raise MnemosyneError(
                f"installed runtime module globals do not match verified source: {path}"
            )

    expected_classes = _BOOTSTRAP_CORE_CLASS_STATES[module.__name__]
    current_classes = {
        name: value
        for name, value in current_bindings.items()
        if isinstance(value, type) and value.__module__ == module.__name__
    }
    if set(current_classes) != set(expected_classes):
        raise MnemosyneError(
            f"installed runtime module class state does not match verified source: {path}"
        )
    for class_name, class_value in current_classes.items():
        current_state = _class_execution_state(class_value)
        expected_state = expected_classes[class_name]
        if set(current_state) != set(expected_state):
            raise MnemosyneError(
                f"installed runtime module class state does not match verified source: {path}"
            )
        for member_name, (kind, member, functions) in current_state.items():
            expected_kind, expected_member, expected_functions = expected_state[
                member_name
            ]
            if (
                kind != expected_kind
                or member is not expected_member
                or tuple(label for label, _function, _state in functions)
                != tuple(
                    label for label, _function, _state in expected_functions
                )
                or len(functions) != len(expected_functions)
                or any(
                    not _function_matches_snapshot(
                        current_function,
                        expected_function,
                        expected_function_state,
                    )
                    for (
                        _label,
                        current_function,
                        _current_function_state,
                    ), (
                        _expected_label,
                        expected_function,
                        expected_function_state,
                    ) in zip(functions, expected_functions)
                )
            ):
                raise MnemosyneError(
                    f"installed runtime module class state does not match verified source: {path}"
                )


def authoritative_runtime_module_paths() -> list[Path]:
    """Return the exact shared-module closure executed by this entrypoint."""
    package_name = next(
        module_name
        for module_name, _relative_path, is_package in RUNTIME_MODULE_CLOSURE
        if is_package
    )
    expected_names = {
        module_name for module_name, _relative_path, _is_package in RUNTIME_MODULE_CLOSURE
    }
    loaded_names = {
        name
        for name in sys.modules
        if name == package_name or name.startswith(package_name + ".")
    }
    if loaded_names != expected_names:
        raise MnemosyneError("installed runtime module closure contains unexpected loaded modules")
    module_paths: list[tuple[Any, Path]] = []
    for module_name, _relative_path, _is_package in RUNTIME_MODULE_CLOSURE:
        module = _BOOTSTRAP_CORE_MODULES[module_name]
        module_file = getattr(module, "__file__", None)
        if not module_file:
            raise MnemosyneError("installed runtime module has no source path")
        module_paths.append((module, Path(module_file).resolve()))
    paths = [path for _module, path in module_paths]
    if len(paths) != len(set(paths)):
        raise MnemosyneError("installed runtime module closure contains duplicate paths")
    paths = sorted(paths, key=lambda path: str(path))
    package_root = Path(__file__).resolve().parent / "mnemosyne_core"
    expected_paths = sorted(
        [package_root / relative_path for _name, relative_path, _package in RUNTIME_MODULE_CLOSURE],
        key=lambda path: str(path),
    )
    if paths != expected_paths:
        raise MnemosyneError("installed runtime module closure is outside the canonical writer layout")
    by_name = {module.__name__: (module, path) for module, path in module_paths}
    for module_name, _relative_path, _is_package in RUNTIME_MODULE_CLOSURE:
        module, path = by_name[module_name]
        verify_loaded_runtime_module_code(module, path)
    return paths


def verify_installed_entrypoint_manifest(
    manifest_path: Path,
) -> tuple[dict[str, Any], str, dict[str, Any], str, list[dict[str, Any]]]:
    raw, manifest, _manifest_info = read_owner_only_manifest(manifest_path)
    manifest_schema_version = manifest.get("schema_version")
    expected_keys = {
        "schema_version",
        "kind",
        "compatibility_version",
        "declared_by",
        "coverage_complete",
        "canonical_writer",
        "writer_aliases",
        "instruction_surfaces",
        "launchers",
        "discovery_roots",
        "retired_paths",
        "runtime_modules",
    }
    if manifest_schema_version == 3:
        expected_keys.add("launcher_aliases")
    if set(manifest) != expected_keys:
        raise MnemosyneError("installed entrypoint manifest shape is invalid")
    if (
        manifest_schema_version not in {2, 3}
        or manifest.get("kind") != "MNEMOSYNE_INSTALLED_ENTRYPOINTS"
        or manifest.get("compatibility_version") != MNEMOSYNE_COMPATIBILITY_VERSION
        or manifest.get("coverage_complete") is not True
        or not isinstance(manifest.get("declared_by"), str)
        or not manifest["declared_by"]
    ):
        raise MnemosyneError("installed entrypoint manifest contract is invalid")
    collection_keys = [
        "writer_aliases",
        "instruction_surfaces",
        "launchers",
        "discovery_roots",
        "retired_paths",
        "runtime_modules",
    ]
    if manifest_schema_version == 3:
        collection_keys.append("launcher_aliases")
    if not all(isinstance(manifest.get(key), list) for key in collection_keys):
        raise MnemosyneError("installed entrypoint manifest collections are invalid")

    runtime_contracts = manifest["runtime_modules"]
    if not all(
        isinstance(item, dict) and set(item) == {"path", "sha256"}
        for item in runtime_contracts
    ):
        raise MnemosyneError("installed runtime module contract is invalid")
    expected_runtime_paths = [str(path) for path in authoritative_runtime_module_paths()]
    declared_runtime_paths = [str(item["path"]) for item in runtime_contracts]
    if (
        declared_runtime_paths != sorted(declared_runtime_paths)
        or len(declared_runtime_paths) != len(set(declared_runtime_paths))
        or declared_runtime_paths != expected_runtime_paths
    ):
        raise MnemosyneError("installed runtime module closure is invalid")
    runtime_modules: list[dict[str, Any]] = []
    for item in runtime_contracts:
        runtime_module, _runtime_raw = regular_file_evidence(
            Path(str(item["path"])),
            str(item["sha256"]),
            "runtime module",
        )
        runtime_modules.append(runtime_module)

    canonical_contract = manifest.get("canonical_writer")
    if not isinstance(canonical_contract, dict) or set(canonical_contract) != {"path", "sha256"}:
        raise MnemosyneError("installed entrypoint canonical writer contract is invalid")
    canonical_path = Path(str(canonical_contract["path"]))
    canonical, canonical_raw = regular_file_evidence(
        canonical_path,
        str(canonical_contract["sha256"]),
        "canonical writer",
    )
    running_path = Path(__file__).resolve()
    running_info, running_raw = read_verified_regular_file(
        running_path,
        label="running canonical writer",
        expected_mode=None,
    )
    if (
        (canonical["device"], canonical["inode"]) != (running_info.st_dev, running_info.st_ino)
        or canonical_raw != running_raw
        or canonical["sha256"] != sha256_bytes(running_raw)
        or MNEMOSYNE_COMPATIBILITY_VERSION.encode("utf-8") not in running_raw
    ):
        raise MnemosyneError("installed canonical writer is not the running M0-compatible entrypoint")

    blockers: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    alias_paths: set[str] = set()
    for item in manifest["writer_aliases"]:
        if not isinstance(item, dict) or set(item) != {"path", "must_resolve_to"}:
            raise MnemosyneError("installed entrypoint alias contract is invalid")
        alias_path = Path(str(item["path"]))
        if str(item["must_resolve_to"]) != str(canonical_path):
            raise MnemosyneError("installed entrypoint alias target contract is invalid")
        try:
            alias = writer_symlink_alias_evidence(
                alias_path,
                canonical_path,
                canonical,
            )
        except MnemosyneError:
            blockers.append({"kind": "ENTRYPOINT_NOT_CANONICAL", "path": str(alias_path)})
            continue
        aliases.append(alias)
        alias_paths.add(str(alias_path))

    instruction_surfaces: list[dict[str, Any]] = []
    instruction_surface_paths: set[str] = set()
    for item in manifest["instruction_surfaces"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "required_writer_path"}:
            raise MnemosyneError("installed instruction surface contract is invalid")
        surface_path = Path(str(item["path"]))
        surface, surface_raw = regular_file_evidence(
            surface_path,
            str(item["sha256"]),
            "instruction surface",
        )
        try:
            surface_text = surface_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MnemosyneError(f"instruction surface is not UTF-8: {surface_path}") from exc
        references = sorted(set(re.findall(r"/[A-Za-z0-9_./-]*/mnemosyne\.py", surface_text)))
        if str(item["required_writer_path"]) != str(canonical_path) or references != [str(canonical_path)]:
            blockers.append({"kind": "ENTRYPOINT_TARGET_MISMATCH", "path": str(surface_path)})
        else:
            instruction_surface_paths.add(str(surface_path))
        instruction_surfaces.append(surface)
    authoritative_instruction_paths = sorted(
        {str(path) for path in authoritative_entrypoint_instruction_surfaces()}
    )
    for required_surface in authoritative_instruction_paths:
        if required_surface not in instruction_surface_paths:
            blockers.append({"kind": "INSTALL_SURFACE_NOT_COVERED", "path": required_surface})

    launchers: list[dict[str, Any]] = []
    launcher_paths: set[str] = set()
    launchers_by_path: dict[str, dict[str, Any]] = {}
    for item in manifest["launchers"]:
        expected_launcher_keys = {"path", "sha256", "delegates_to"}
        if manifest_schema_version == 3:
            expected_launcher_keys.add("kind")
        if not isinstance(item, dict) or set(item) != expected_launcher_keys:
            raise MnemosyneError("installed launcher contract is invalid")
        launcher_kind = item.get("kind")
        if manifest_schema_version == 3 and launcher_kind not in {
            MNEMOSYNE_CONTROL_LAUNCHER_KIND,
            DIRECT_EXEC_LAUNCHER_KIND,
        }:
            raise MnemosyneError("installed launcher kind is invalid")
        launcher_path = Path(str(item["path"]))
        if not isinstance(item["delegates_to"], str) or not item["delegates_to"]:
            raise MnemosyneError("installed launcher delegate contract is invalid")
        launcher, launcher_raw = regular_file_evidence(
            launcher_path,
            str(item["sha256"]),
            "launcher",
        )
        delegate = str(item["delegates_to"])
        if (
            sha256_bytes(launcher_raw) != launcher["sha256"]
            or not launcher_bytes_match_delegate(
                launcher_raw,
                delegate,
                {str(canonical_path), *alias_paths},
                instruction_surface_paths,
                launcher_path,
                launcher_kind,
            )
        ):
            blockers.append({"kind": "LAUNCHER_DELEGATE_MISMATCH", "path": str(launcher_path)})
        if manifest_schema_version == 3:
            launcher["kind"] = launcher_kind
        launchers.append(launcher)
        launcher_paths.add(str(launcher_path))
        launchers_by_path[str(launcher_path)] = launcher

    launcher_aliases: list[dict[str, Any]] = []
    launcher_alias_paths: set[str] = set()
    for item in manifest.get("launcher_aliases", []):
        if not isinstance(item, dict) or set(item) != {"path", "must_resolve_to"}:
            raise MnemosyneError("installed launcher alias contract is invalid")
        alias_path = Path(str(item["path"]))
        target_path = str(item["must_resolve_to"])
        launcher = launchers_by_path.get(target_path)
        if launcher is None:
            raise MnemosyneError("installed launcher alias target contract is invalid")
        if str(alias_path) in launcher_alias_paths:
            raise MnemosyneError("installed launcher alias path is duplicated")
        try:
            launcher_alias = launcher_symlink_alias_evidence(
                alias_path,
                Path(target_path),
                launcher,
            )
        except MnemosyneError:
            blockers.append({"kind": "LAUNCHER_ALIAS_NOT_CANONICAL", "path": str(alias_path)})
            continue
        launcher_aliases.append(launcher_alias)
        launcher_alias_paths.add(str(alias_path))

    declared_discovery_roots = [str(Path(str(value))) for value in manifest["discovery_roots"]]
    authoritative_roots = sorted({str(path) for path in authoritative_entrypoint_discovery_roots()})
    for required_root in authoritative_roots:
        if required_root not in declared_discovery_roots:
            blockers.append({"kind": "INSTALL_SURFACE_NOT_COVERED", "path": required_root})
    discovery_roots: list[str] = []
    allowed_paths = {
        str(canonical_path),
        *alias_paths,
        *launcher_paths,
        *launcher_alias_paths,
    }
    required_parents = {str(canonical_path.parent)} | {
        str(Path(path).parent)
        for path in alias_paths | launcher_paths | launcher_alias_paths
    }
    for root_value in sorted(set(declared_discovery_roots) | set(authoritative_roots)):
        root_path = Path(str(root_value))
        if not root_path.is_absolute():
            raise MnemosyneError("installed entrypoint discovery root must be absolute")
        try:
            root_fd = open_verified_directory(root_path, require_owner_only=True)
        except MnemosyneError as exc:
            raise MnemosyneError(f"installed entrypoint discovery root is invalid: {root_path}") from exc
        try:
            for name in sorted(os.listdir(root_fd)):
                candidate = str(root_path / name)
                if candidate in allowed_paths:
                    continue
                if entrypoint_candidate_name(name) or executable_looks_like_legacy_writer_at(
                    root_fd,
                    name,
                    root_path / name,
                ) or symlink_target_looks_like_legacy_writer_at(
                    root_fd,
                    name,
                    root_path / name,
                ):
                    blockers.append({"kind": "UNREGISTERED_ENTRYPOINT", "path": candidate})
        finally:
            os.close(root_fd)
        discovery_roots.append(str(root_path))
    if not required_parents.issubset(set(discovery_roots)):
        raise MnemosyneError("installed entrypoint discovery roots do not cover declared launch surfaces")

    retired_paths: list[str] = []
    for retired_value in manifest["retired_paths"]:
        retired_path = Path(str(retired_value))
        if not retired_path.is_absolute():
            raise MnemosyneError("retired entrypoint path must be absolute")
        retired_paths.append(str(retired_path))
        if os.path.lexists(retired_path):
            blockers.append({"kind": "RETIRED_ENTRYPOINT_PRESENT", "path": str(retired_path)})

    blockers.sort(key=lambda item: (str(item.get("kind")), str(item.get("path"))))
    evidence = {
        "schema_version": manifest_schema_version,
        "kind": "MNEMOSYNE_INSTALLED_ENTRYPOINT_EVIDENCE",
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256_bytes(raw),
        "canonical_writer": durable_entrypoint_file_evidence(canonical),
        "writer_aliases": [durable_entrypoint_file_evidence(item) for item in aliases],
        "instruction_surfaces": [
            durable_entrypoint_file_evidence(item) for item in instruction_surfaces
        ],
        "launchers": [durable_entrypoint_file_evidence(item) for item in launchers],
        "discovery_roots": discovery_roots,
        "authoritative_discovery_roots": authoritative_roots,
        "authoritative_instruction_surfaces": authoritative_instruction_paths,
        "retired_paths": retired_paths,
        "runtime_modules": [
            durable_entrypoint_file_evidence(item) for item in runtime_modules
        ],
        "observed_at": utc_now(),
    }
    if manifest_schema_version == 3:
        evidence["launcher_aliases"] = [
            durable_entrypoint_file_evidence(item) for item in launcher_aliases
        ]
    evidence_sha256 = sha256_bytes(canonical_json_bytes({key: value for key, value in evidence.items() if key != "observed_at"}))
    return manifest, sha256_bytes(raw), evidence, evidence_sha256, blockers


def verify_proposal_entrypoint_evidence(proposal: dict[str, Any]) -> None:
    if proposal.get("placement_lock_protocol_version") != PLACEMENT_LOCK_PROTOCOL_VERSION:
        raise MnemosyneError("lock migration proposal protocol is incompatible")
    contract = proposal.get("entrypoint_manifest")
    if not isinstance(contract, dict) or set(contract) != {"path", "sha256"}:
        raise MnemosyneError("lock migration proposal entrypoint manifest binding is invalid")
    proposal_evidence = proposal.get("entrypoint_evidence")
    if not isinstance(proposal_evidence, dict):
        raise MnemosyneError("lock migration proposal entrypoint evidence is missing")
    proposal_canonical_writer = proposal_evidence.get("canonical_writer")
    if not isinstance(proposal_canonical_writer, dict):
        raise MnemosyneError("lock migration proposal entrypoint binding is invalid")
    expected_entrypoint = {
        "path": proposal_canonical_writer.get("path"),
        "compatibility_version": MNEMOSYNE_COMPATIBILITY_VERSION,
        "sha256": proposal_canonical_writer.get("sha256"),
    }
    if proposal.get("entrypoint") != expected_entrypoint:
        raise MnemosyneError("lock migration proposal entrypoint binding is invalid")
    _manifest, manifest_sha256, evidence, evidence_sha256, blockers = verify_installed_entrypoint_manifest(
        Path(str(contract["path"]))
    )
    if manifest_sha256 != contract["sha256"]:
        raise MnemosyneError("installed entrypoint manifest changed after lock migration preview")
    comparable_evidence = {key: value for key, value in evidence.items() if key != "observed_at"}
    comparable_proposal = {key: value for key, value in proposal_evidence.items() if key != "observed_at"}
    if comparable_evidence != comparable_proposal or evidence_sha256 != proposal.get("entrypoint_evidence_sha256"):
        raise MnemosyneError("installed entrypoint evidence changed after lock migration preview")
    if blockers:
        raise MnemosyneError("installed entrypoint manifest is no longer approval-ready")


def verify_current_entrypoint_compatibility(proposal: dict[str, Any]) -> None:
    if proposal.get("placement_lock_protocol_version") != PLACEMENT_LOCK_PROTOCOL_VERSION:
        raise MnemosyneError("completed lock migration protocol is incompatible")
    contract = proposal.get("entrypoint_manifest")
    entrypoint = proposal.get("entrypoint")
    proposal_evidence = proposal.get("entrypoint_evidence")
    if (
        not isinstance(contract, dict)
        or set(contract) != {"path", "sha256"}
        or not isinstance(entrypoint, dict)
        or set(entrypoint) != {"path", "compatibility_version", "sha256"}
        or not isinstance(proposal_evidence, dict)
        or not isinstance(proposal_evidence.get("canonical_writer"), dict)
        or entrypoint.get("path")
        != proposal_evidence["canonical_writer"].get("path")
        or entrypoint.get("sha256")
        != proposal_evidence["canonical_writer"].get("sha256")
    ):
        raise MnemosyneError("completed lock migration entrypoint binding is invalid")
    _manifest, _manifest_sha256, current_evidence, _evidence_sha256, blockers = (
        verify_installed_entrypoint_manifest(Path(str(contract["path"])))
    )
    current_writer = current_evidence.get("canonical_writer")
    if (
        not isinstance(current_writer, dict)
        or current_writer.get("path") != entrypoint.get("path")
        or blockers
    ):
        raise MnemosyneError("current entrypoint is not placement-lock compatible")


def scan_legacy_leases(root: Path, migration_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lease_directory = lock_migrations_dir(root) / "legacy-leases"
    leases: list[dict[str, Any]] = []
    cleanup_effects: list[dict[str, Any]] = []
    if not os.path.lexists(lease_directory):
        return leases, cleanup_effects
    try:
        lease_directory_fd = open_verified_directory(lease_directory, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError("cannot open verified legacy lease directory") from exc
    try:
        for lease_name in sorted(os.listdir(lease_directory_fd)):
            lease_path = lease_directory / lease_name
            try:
                lexical_info = os.stat(
                    lease_name,
                    dir_fd=lease_directory_fd,
                    follow_symlinks=False,
                )
            except OSError:
                leases.append(
                    {"path": str(lease_path), "status": "ambiguous", "reason": "lease-stat-failed"}
                )
                continue
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                lease_fd = os.open(lease_name, flags, dir_fd=lease_directory_fd)
            except OSError:
                leases.append(
                    {"path": str(lease_path), "status": "ambiguous", "reason": "non-regular-lease"}
                )
                continue
            try:
                opened_info = os.fstat(lease_fd)
                if (
                    not stat.S_ISREG(opened_info.st_mode)
                    or opened_info.st_uid != os.getuid()
                    or stat.S_IMODE(opened_info.st_mode) != 0o600
                    or (opened_info.st_dev, opened_info.st_ino)
                    != (lexical_info.st_dev, lexical_info.st_ino)
                ):
                    leases.append(
                        {"path": str(lease_path), "status": "ambiguous", "reason": "non-regular-lease"}
                    )
                    continue
                if opened_info.st_nlink != 1:
                    leases.append(
                        {
                            "path": str(lease_path),
                            "status": "ambiguous",
                            "reason": "unsafe-link-count",
                        }
                    )
                    continue
                raw = read_open_file_bytes(lease_fd)
            finally:
                os.close(lease_fd)
            try:
                payload = json.loads(raw)
                pid = int(payload["pid"])
                expected_identity = str(payload["process_start_identity"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                leases.append(
                    {
                        "path": str(lease_path),
                        "sha256": sha256_bytes(raw),
                        "device": opened_info.st_dev,
                        "inode": opened_info.st_ino,
                        "status": "ambiguous",
                        "reason": "invalid-lease-payload",
                    }
                )
                continue
            probe = probe_process_identity(pid, expected_identity)
            lease = {
                "path": str(lease_path),
                "sha256": sha256_bytes(raw),
                "device": opened_info.st_dev,
                "inode": opened_info.st_ino,
                "pid": pid,
                "process_start_identity": expected_identity,
                "command": payload.get("command"),
                "registry_sha256": payload.get("registry_sha256"),
                "status": probe["status"],
                "reason": probe["reason"],
                "observed_start_identity": probe["observed_start_identity"],
            }
            leases.append(lease)
            if probe["status"] == "dead":
                cleanup_effects.append(
                    {
                        "kind": "QUARANTINE_STALE_LEASE",
                        "source": str(lease_path),
                        "source_sha256": sha256_bytes(raw),
                        "source_device": opened_info.st_dev,
                        "source_inode": opened_info.st_ino,
                        "target": str(
                            lock_migrations_dir(root)
                            / "quarantined-leases"
                            / migration_id
                            / lease_name
                        ),
                    }
                )
    finally:
        os.close(lease_directory_fd)
    return leases, cleanup_effects


OPERATION_REPORT_KEYS = (
    "mode",
    "registry_updates",
    "content_placement_writes",
    "memory_updates",
    "not_modified",
    "needs_review",
)


def operation_report(
    *,
    mode: str,
    registry_updates: list[Any] | None = None,
    content_placement_writes: list[Any] | None = None,
    memory_updates: list[Any] | None = None,
    not_modified: list[Any] | None = None,
    needs_review: list[Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(mode, str) or not mode:
        raise MnemosyneError("operation report mode is required")
    values = {
        "registry_updates": registry_updates,
        "content_placement_writes": content_placement_writes,
        "memory_updates": memory_updates,
        "not_modified": not_modified,
        "needs_review": needs_review,
    }
    for key, value in values.items():
        if value is not None and not isinstance(value, list):
            raise MnemosyneError("operation report %s must be a list" % key)
    return {
        "mode": mode,
        "registry_updates": list(registry_updates or []),
        "content_placement_writes": list(content_placement_writes or []),
        "memory_updates": list(memory_updates or []),
        "not_modified": list(not_modified or []),
        "needs_review": list(needs_review or []),
    }


def render_operation_report(report: dict[str, Any], *, as_json: bool) -> None:
    if set(report) != set(OPERATION_REPORT_KEYS):
        raise MnemosyneError("operation report must contain exactly six stable keys")
    if not isinstance(report["mode"], str) or not report["mode"]:
        raise MnemosyneError("operation report mode is invalid")
    for key in OPERATION_REPORT_KEYS[1:]:
        if not isinstance(report[key], list):
            raise MnemosyneError("operation report %s must be a list" % key)
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    titles = [
        ("모드", "mode"),
        ("레지스트리 변경", "registry_updates"),
        ("콘텐츠·배치 변경", "content_placement_writes"),
        ("메모리 변경", "memory_updates"),
        ("변경하지 않음", "not_modified"),
        ("검토 필요", "needs_review"),
    ]
    for title, key in titles:
        print(f"{title}: {json.dumps(report[key], ensure_ascii=False, sort_keys=True)}")


def lock_migration_checkpoint(_name: str, _root: Path, _migration_id: str) -> None:
    """Fault-injection seam for crash/resume tests."""


def checked_lock_migration_checkpoint(name: str, root: Path, migration_id: str) -> None:
    lock_migration_checkpoint(name, root, migration_id)
    require_no_manual_recovery_blockers(root)


def lock_migration_before_final_run_publish(_source: Path, _target: Path) -> None:
    """Fault-injection seam immediately after the legacy target precheck."""


def lock_migration_before_completed_marker_publish(_active: Path, _completed: Path) -> None:
    """Fault-injection seam before active-to-completed marker publication."""


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def source_identity(info: os.stat_result) -> tuple[int, int, int]:
    return _safety_core.source_identity(info)


def persist_manual_recovery_blocker(
    guard: ManualRecoveryGuard,
    recovery: ManualRecoveryRequired,
    *,
    kind: str = "LEGACY_RENAME_MANUAL_RECOVERY",
) -> tuple[Path, str]:
    if not isinstance(guard, ManualRecoveryGuard):
        raise MnemosyneError("manual recovery blocker publication requires an active guard")
    guard.require_active()
    root = guard.root
    marker_id = (
        "rename-"
        + utc_now().replace("-", "").replace(":", "")
        + "-"
        + uuid.uuid4().hex[:12]
    )
    marker_path = manual_recovery_dir(root) / f"{marker_id}.json"
    payload = {
        "schema_version": 1,
        "kind": kind,
        "status": "OPEN",
        "detected_at": utc_now(),
        "source": str(recovery.source),
        "target": str(recovery.target),
        "reason": recovery.reason,
        "expected_source_identity": list(recovery.expected_source_identity),
        "observed_target_identity": (
            list(recovery.observed_target_identity)
            if recovery.observed_target_identity is not None
            else None
        ),
    }
    digest = publish_json_no_replace(marker_path, payload)
    marker_info, marker_bytes = read_verified_regular_file(
        marker_path,
        label="manual recovery blocker",
    )
    if (
        marker_info.st_nlink != 1
        or marker_bytes != canonical_json_bytes(payload)
        or sha256_bytes(marker_bytes) != digest
    ):
        raise MnemosyneError("manual recovery blocker readback mismatch")
    guard.mark_blocker_published()
    return marker_path, digest


def rename_path_no_replace(
    source: Path,
    target: Path,
    *,
    collision_error: str,
    recovery_guard: ManualRecoveryGuard,
    require_directory: bool | None = None,
    expected_source_identity: tuple[int, int, int] | None = None,
) -> None:
    if not isinstance(recovery_guard, ManualRecoveryGuard):
        raise MnemosyneError("rename requires an active manual recovery guard")
    recovery_guard.checkpoint()
    try:
        _safety_core.rename_path_no_replace(
            source,
            target,
            collision_error=collision_error,
            require_directory=require_directory,
            expected_source_identity=expected_source_identity,
            error_type=MnemosyneError,
            before_directory_identity_check=safety_before_directory_identity_check,
        )
    except ManualRecoveryRequired as exc:
        marker_path, marker_sha256 = persist_manual_recovery_blocker(
            recovery_guard,
            exc,
        )
        raise MnemosyneError(
            f"{exc}; blocker: {marker_path}; blocker_sha256: {marker_sha256}"
        ) from exc
    recovery_guard.checkpoint()


def rename_directory_no_replace(
    source: Path,
    target: Path,
    *,
    recovery_guard: ManualRecoveryGuard,
) -> None:
    rename_path_no_replace(
        source,
        target,
        collision_error=f"refusing to overwrite lock migration run: {target}",
        require_directory=True,
        recovery_guard=recovery_guard,
    )


def read_regular_file_at(
    directory_fd: int,
    name: str,
    path: Path,
    *,
    label: str,
    expected_mode: int | None = 0o600,
) -> tuple[os.stat_result, bytes]:
    return _safety_core.read_regular_file_at(
        directory_fd,
        name,
        path,
        label=label,
        expected_mode=expected_mode,
        error_type=MnemosyneError,
    )


def read_flat_yaml_at(
    directory_fd: int,
    name: str,
    path: Path,
    *,
    label: str,
) -> tuple[os.stat_result, dict[str, Any]]:
    info, raw = read_regular_file_at(
        directory_fd,
        name,
        path,
        label=label,
        expected_mode=None,
    )
    if info.st_nlink != 1:
        raise MnemosyneError(f"{label} link count is invalid: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MnemosyneError(f"{label} is not UTF-8: {path}") from exc
    return info, parse_flat_yaml_text(text)


def read_verified_regular_file(
    path: Path,
    *,
    label: str,
    expected_mode: int | None = 0o600,
) -> tuple[os.stat_result, bytes]:
    try:
        directory_fd = open_verified_directory(path.parent, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError(f"cannot open verified {label} parent") from exc
    try:
        info, raw = read_regular_file_at(
            directory_fd,
            path.name,
            path,
            label=label,
            expected_mode=expected_mode,
        )
        require_same_directory_identity(path.parent, directory_fd, label)
        return info, raw
    finally:
        os.close(directory_fd)


def move_regular_file_no_replace(
    source: Path,
    target: Path,
    expected_sha256: str,
    *,
    expected_device: int,
    expected_inode: int,
) -> None:
    _safety_core.move_regular_file_no_replace(
        source,
        target,
        expected_sha256,
        expected_device=expected_device,
        expected_inode=expected_inode,
        error_type=MnemosyneError,
        before_directory_identity_check=safety_before_directory_identity_check,
    )


def ensure_completed_marker_link(
    active_marker: Path,
    completed_marker: Path,
    expected_sha256: str,
) -> tuple[int, int]:
    try:
        active_parent_fd = open_verified_directory(active_marker.parent, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError("cannot open verified active marker parent") from exc
    try:
        completed_parent_fd = open_verified_directory(
            completed_marker.parent,
            require_owner_only=True,
        )
    except MnemosyneError as exc:
        os.close(active_parent_fd)
        raise MnemosyneError("cannot open verified completed marker parent") from exc
    try:
        active_info, active_bytes = read_regular_file_at(
            active_parent_fd,
            active_marker.name,
            active_marker,
            label="active lock migration marker",
        )
        if sha256_bytes(active_bytes) != expected_sha256:
            raise MnemosyneError("active lock migration marker readback mismatch")
        try:
            os.stat(
                completed_marker.name,
                dir_fd=completed_parent_fd,
                follow_symlinks=False,
            )
            completed_exists = True
        except FileNotFoundError:
            completed_exists = False
        if not completed_exists:
            try:
                os.link(
                    active_marker.name,
                    completed_marker.name,
                    src_dir_fd=active_parent_fd,
                    dst_dir_fd=completed_parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise MnemosyneError(
                    f"refusing to overwrite completed marker: {completed_marker}"
                ) from exc
            except OSError as exc:
                raise MnemosyneError("cannot publish completed lock migration marker") from exc
            os.fsync(completed_parent_fd)
        completed_info, completed_bytes = read_regular_file_at(
            completed_parent_fd,
            completed_marker.name,
            completed_marker,
            label="completed lock migration marker",
        )
        if (
            completed_bytes != active_bytes
            or (completed_info.st_dev, completed_info.st_ino)
            != (active_info.st_dev, active_info.st_ino)
        ):
            raise MnemosyneError("completed marker does not match active marker identity")
        require_same_directory_identity(
            active_marker.parent,
            active_parent_fd,
            "active marker",
        )
        require_same_directory_identity(
            completed_marker.parent,
            completed_parent_fd,
            "completed marker",
        )
        return active_info.st_dev, active_info.st_ino
    finally:
        os.close(completed_parent_fd)
        os.close(active_parent_fd)


def unlink_active_marker_if_same(
    active_marker: Path,
    completed_marker: Path,
    expected_identity: tuple[int, int],
    expected_sha256: str,
) -> None:
    try:
        active_parent_fd = open_verified_directory(active_marker.parent, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError("cannot open verified active marker parent") from exc
    try:
        completed_parent_fd = open_verified_directory(
            completed_marker.parent,
            require_owner_only=True,
        )
    except MnemosyneError as exc:
        os.close(active_parent_fd)
        raise MnemosyneError("cannot open verified completed marker parent") from exc
    try:
        active_info, active_bytes = read_regular_file_at(
            active_parent_fd,
            active_marker.name,
            active_marker,
            label="active lock migration marker",
        )
        completed_info, completed_bytes = read_regular_file_at(
            completed_parent_fd,
            completed_marker.name,
            completed_marker,
            label="completed lock migration marker",
        )
        if (
            (active_info.st_dev, active_info.st_ino) != expected_identity
            or (completed_info.st_dev, completed_info.st_ino) != expected_identity
            or active_bytes != completed_bytes
            or sha256_bytes(active_bytes) != expected_sha256
        ):
            raise MnemosyneError("completed lock migration marker identity changed before completion")
        require_same_directory_identity(active_marker.parent, active_parent_fd, "active marker")
        require_same_directory_identity(completed_marker.parent, completed_parent_fd, "completed marker")
        os.unlink(active_marker.name, dir_fd=active_parent_fd)
        os.fsync(active_parent_fd)
        require_same_directory_identity(active_marker.parent, active_parent_fd, "active marker")
        require_same_directory_identity(completed_marker.parent, completed_parent_fd, "completed marker")
        final_completed = os.stat(
            completed_marker.name,
            dir_fd=completed_parent_fd,
            follow_symlinks=False,
        )
        if (
            (final_completed.st_dev, final_completed.st_ino) != expected_identity
            or final_completed.st_nlink != 1
        ):
            raise MnemosyneError("completed lock migration marker final identity is invalid")
    finally:
        os.close(completed_parent_fd)
        os.close(active_parent_fd)


def apply_approved_stale_lease_cleanup(
    root: Path,
    proposal: dict[str, Any],
) -> list[dict[str, Any]]:
    effects = {str(effect["source"]): effect for effect in proposal["cleanup_effects"]}
    approved_sources = {str(lease["path"]) for lease in proposal["leases"]}
    lease_directory = lock_migrations_dir(root) / "legacy-leases"
    if not approved_sources and not effects and not os.path.lexists(lease_directory):
        return []
    try:
        lease_directory_fd = open_verified_directory(lease_directory, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError("cannot open verified legacy lease directory") from exc
    try:
        current_sources = {str(lease_directory / name) for name in os.listdir(lease_directory_fd)}
        unbound = sorted(current_sources - approved_sources)
        if unbound:
            raise MnemosyneError(f"unapproved legacy writer lease appeared: {unbound[0]}")

        quarantined: list[dict[str, Any]] = []
        for lease in proposal["leases"]:
            source = Path(str(lease["path"]))
            if source.parent != lease_directory or lease.get("status") != "dead" or str(source) not in effects:
                raise MnemosyneError(f"legacy writer lease is not approved for quarantine: {source}")
            effect = effects[str(source)]
            target = Path(str(effect["target"]))
            expected_target = (
                lock_migrations_dir(root)
                / "quarantined-leases"
                / str(proposal["migration_id"])
                / source.name
            )
            if target != expected_target:
                raise MnemosyneError(f"stale lease quarantine target binding mismatch: {target}")
            expected_sha256 = str(effect["source_sha256"])
            expected_device = int(effect["source_device"])
            expected_inode = int(effect["source_inode"])
            try:
                target_directory_fd = open_or_create_verified_directory(target.parent)
            except MnemosyneError as exc:
                raise MnemosyneError("cannot open verified quarantine parent") from exc
            try:
                try:
                    os.stat(source.name, dir_fd=lease_directory_fd, follow_symlinks=False)
                    source_exists = True
                except FileNotFoundError:
                    source_exists = False
                try:
                    os.stat(target.name, dir_fd=target_directory_fd, follow_symlinks=False)
                    target_exists = True
                except FileNotFoundError:
                    target_exists = False

                if source_exists:
                    source_info, source_bytes = read_regular_file_at(
                        lease_directory_fd,
                        source.name,
                        source,
                        label="approved stale lease",
                    )
                    if (
                        sha256_bytes(source_bytes) != expected_sha256
                        or (source_info.st_dev, source_info.st_ino)
                        != (expected_device, expected_inode)
                    ):
                        raise MnemosyneError(f"approved stale lease changed: {source}")
                    try:
                        payload = json.loads(source_bytes)
                        fresh_probe = probe_process_identity(
                            int(payload["pid"]),
                            str(payload["process_start_identity"]),
                        )
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise MnemosyneError(f"approved stale lease payload changed: {source}") from exc
                    if fresh_probe["status"] != "dead":
                        raise MnemosyneError(f"approved stale lease is no longer confirmed dead: {source}")

                if target_exists:
                    target_info, target_bytes = read_regular_file_at(
                        target_directory_fd,
                        target.name,
                        target,
                        label="quarantined lease",
                    )
                    if (
                        sha256_bytes(target_bytes) != expected_sha256
                        or (target_info.st_dev, target_info.st_ino)
                        != (expected_device, expected_inode)
                    ):
                        raise MnemosyneError(f"quarantined lease readback mismatch: {target}")

                if source_exists and target_exists:
                    if (source_info.st_dev, source_info.st_ino) != (
                        target_info.st_dev,
                        target_info.st_ino,
                    ) or source_info.st_nlink != 2 or target_info.st_nlink != 2:
                        raise MnemosyneError(f"stale lease quarantine collision: {target}")
                    current_source = os.stat(
                        source.name,
                        dir_fd=lease_directory_fd,
                        follow_symlinks=False,
                    )
                    if (current_source.st_dev, current_source.st_ino) != (
                        source_info.st_dev,
                        source_info.st_ino,
                    ):
                        raise MnemosyneError(f"approved stale lease changed before removal: {source}")
                    os.unlink(source.name, dir_fd=lease_directory_fd)
                    os.fsync(lease_directory_fd)
                elif source_exists:
                    if source_info.st_nlink != 1:
                        raise MnemosyneError(f"approved stale lease has unsafe link count: {source}")
                    move_regular_file_no_replace(
                        source,
                        target,
                        expected_sha256,
                        expected_device=expected_device,
                        expected_inode=expected_inode,
                    )
                elif not target_exists:
                    raise MnemosyneError(
                        f"approved stale lease and quarantine target are both missing: {source}"
                    )
                elif target_info.st_nlink != 1:
                    raise MnemosyneError(f"quarantined lease has unsafe link count: {target}")
                final_target_info, final_target_bytes = read_regular_file_at(
                    target_directory_fd,
                    target.name,
                    target,
                    label="quarantined lease",
                )
                if (
                    sha256_bytes(final_target_bytes) != expected_sha256
                    or (final_target_info.st_dev, final_target_info.st_ino)
                    != (expected_device, expected_inode)
                    or final_target_info.st_nlink != 1
                ):
                    raise MnemosyneError(f"quarantined lease readback mismatch: {target}")
                require_same_directory_identity(target.parent, target_directory_fd, "quarantine")
            finally:
                os.close(target_directory_fd)

            quarantined.append(
                {
                    "source": str(source),
                    "target": str(target),
                    "sha256": expected_sha256,
                    "device": final_target_info.st_dev,
                    "inode": final_target_info.st_ino,
                }
            )
        require_same_directory_identity(lease_directory, lease_directory_fd, "legacy lease")
        return quarantined
    finally:
        os.close(lease_directory_fd)


def validate_placement_lock(path: Path, expected_sha256: str) -> os.stat_result:
    root = path.parent.parent
    if path != placement_lock_path(root):
        raise MnemosyneError(f"placement lock path is not canonical: {path}")
    lock_fd = open_placement_lock_verified(root, expected_sha256)
    try:
        return os.fstat(lock_fd)
    finally:
        os.close(lock_fd)


def verify_quarantined_leases(
    proposal: dict[str, Any],
    quarantined: Any,
) -> list[dict[str, Any]]:
    cleanup_effects = proposal.get("cleanup_effects", [])
    if not isinstance(cleanup_effects, list):
        raise MnemosyneError("completed lock migration quarantine binding mismatch")
    expected: list[dict[str, Any]] = []
    seen_sources: set[str] = set()
    for effect in cleanup_effects:
        if not isinstance(effect, dict) or effect.get("kind") != "QUARANTINE_STALE_LEASE":
            raise MnemosyneError("completed lock migration quarantine binding mismatch")
        source = str(effect.get("source", ""))
        if not source or source in seen_sources:
            raise MnemosyneError("completed lock migration quarantine binding mismatch")
        seen_sources.add(source)
        target = Path(str(effect.get("target", "")))
        expected_device = int(effect.get("source_device", -1))
        expected_inode = int(effect.get("source_inode", -1))
        expected_sha256 = str(effect.get("source_sha256", ""))
        expected.append(
            {
                "source": source,
                "target": str(target),
                "sha256": expected_sha256,
                "device": expected_device,
                "inode": expected_inode,
            }
        )
    if quarantined != expected:
        raise MnemosyneError("completed lock migration quarantine binding mismatch")
    for item in expected:
        target = Path(item["target"])
        expected_device = item["device"]
        expected_inode = item["inode"]
        expected_sha256 = item["sha256"]
        try:
            quarantine_info, quarantine_bytes = read_verified_regular_file(
                target,
                label="quarantined lease",
            )
        except MnemosyneError as exc:
            raise MnemosyneError("quarantined lease identity changed after migration") from exc
        if (
            sha256_bytes(quarantine_bytes) != expected_sha256
            or (quarantine_info.st_dev, quarantine_info.st_ino)
            != (expected_device, expected_inode)
            or quarantine_info.st_nlink != 1
        ):
            raise MnemosyneError("quarantined lease identity changed after migration")
    return expected


def verify_completed_lock_migration(
    root: Path,
    proposal: dict[str, Any],
    proposal_sha256: str,
    paths: dict[str, Path],
    *,
    require_current_registry_state: bool = True,
    require_current_queue_state: bool = True,
) -> dict[str, Any]:
    require_no_manual_recovery_blockers(root)
    if os.path.lexists(paths["active_marker"]):
        raise MnemosyneError("completed lock migration still has active marker")
    verify_current_entrypoint_compatibility(proposal)
    try:
        run_fd = open_verified_directory(paths["final_run"], require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError("completed lock migration evidence is incomplete or unsafe") from exc
    try:
        plan_info, plan_bytes = read_regular_file_at(
            run_fd,
            "plan.json",
            paths["final_run"] / "plan.json",
            label="completed lock migration plan",
        )
        result_info, result_bytes = read_regular_file_at(
            run_fd,
            "result.json",
            paths["final_run"] / "result.json",
            label="completed lock migration result",
        )
        if plan_info.st_nlink != 1 or result_info.st_nlink != 1:
            raise MnemosyneError("completed lock migration run evidence link count is invalid")
        require_same_directory_identity(paths["final_run"], run_fd, "completed run")
    except MnemosyneError as exc:
        raise MnemosyneError("completed lock migration evidence is incomplete or unsafe") from exc
    finally:
        os.close(run_fd)

    if paths["completed_result"].parent != paths["completed_marker"].parent:
        raise MnemosyneError("completed lock migration evidence parent binding mismatch")
    try:
        completed_fd = open_verified_directory(
            paths["completed_result"].parent,
            require_owner_only=True,
        )
    except MnemosyneError as exc:
        raise MnemosyneError("completed lock migration evidence is incomplete or unsafe") from exc
    try:
        completed_result_info, completed_result_bytes = read_regular_file_at(
            completed_fd,
            paths["completed_result"].name,
            paths["completed_result"],
            label="completed lock migration result copy",
        )
        marker_info, marker_bytes = read_regular_file_at(
            completed_fd,
            paths["completed_marker"].name,
            paths["completed_marker"],
            label="completed lock migration marker",
        )
        if completed_result_info.st_nlink != 1 or marker_info.st_nlink != 1:
            raise MnemosyneError("completed lock migration completion evidence link count is invalid")
        require_same_directory_identity(
            paths["completed_result"].parent,
            completed_fd,
            "completed evidence",
        )
    except MnemosyneError as exc:
        raise MnemosyneError("completed lock migration evidence is incomplete or unsafe") from exc
    finally:
        os.close(completed_fd)

    try:
        lock_fd = open_placement_lock_verified(root, None)
        try:
            lock_bytes = read_open_file_bytes(lock_fd)
        finally:
            os.close(lock_fd)
        plan = json.loads(plan_bytes)
        result = json.loads(result_bytes)
        marker = json.loads(marker_bytes)
        lock_payload = json.loads(lock_bytes)
    except (MnemosyneError, json.JSONDecodeError) as exc:
        raise MnemosyneError("cannot read completed lock migration evidence") from exc
    for raw, value, label in [
        (plan_bytes, plan, "plan"),
        (result_bytes, result, "result"),
        (marker_bytes, marker, "marker"),
        (lock_bytes, lock_payload, "placement lock"),
    ]:
        if raw != canonical_json_bytes(value):
            raise MnemosyneError(f"completed lock migration {label} is not canonical")
    if completed_result_bytes != result_bytes:
        raise MnemosyneError("completed result does not match final run result")
    plan_sha256 = sha256_bytes(plan_bytes)
    lock_sha256 = sha256_bytes(lock_bytes)
    expected_actor = proposal.get("requested_by")
    if not isinstance(expected_actor, str) or not expected_actor:
        raise MnemosyneError("completed lock migration proposal actor is invalid")
    expected_plan = lock_migration_plan_contract(
        lock_migrations_dir(root) / "proposals" / proposal["migration_id"] / "proposal.json",
        proposal,
        proposal_sha256,
        expected_actor,
        expected_actor,
    )
    if plan != expected_plan:
        raise MnemosyneError("completed lock migration plan binding mismatch")
    expected_marker = {
        "schema_version": 1,
        "kind": "LOCK_MIGRATION_ACTIVE",
        "migration_id": proposal["migration_id"],
        "proposal_sha256": proposal_sha256,
        "plan_sha256": plan_sha256,
        "started_at": plan.get("created_at"),
    }
    if marker != expected_marker or sha256_bytes(marker_bytes) != result.get("active_marker_sha256"):
        raise MnemosyneError("completed lock migration marker binding mismatch")
    expected_lock_payload = {
        "schema_version": 1,
        "kind": "PLACEMENT_COORDINATION_LOCK",
        "migration_id": proposal["migration_id"],
        "proposal_sha256": proposal_sha256,
        "placement_lock_protocol_version": proposal.get(
            "placement_lock_protocol_version"
        ),
        "compatibility_version": proposal.get("entrypoint", {}).get(
            "compatibility_version"
        ),
        "entrypoint_manifest_sha256": proposal.get("entrypoint_manifest", {}).get("sha256"),
        "entrypoint_evidence_sha256": proposal.get("entrypoint_evidence_sha256"),
    }
    if (
        lock_payload != expected_lock_payload
        or result.get("placement_lock", {}).get("sha256") != lock_sha256
    ):
        raise MnemosyneError("completed placement lock binding mismatch")
    lock_info = validate_placement_lock(paths["placement_lock"], lock_sha256)
    quarantined = result.get("quarantined_leases")
    expected_quarantined = verify_quarantined_leases(proposal, quarantined)
    expected_result = {
        "schema_version": 1,
        "kind": "LOCK_MIGRATION_RESULT",
        "status": "COMPLETE",
        "migration_id": proposal["migration_id"],
        "proposal_sha256": proposal_sha256,
        "plan_sha256": plan_sha256,
        "active_marker_sha256": sha256_bytes(marker_bytes),
        "approved_by": plan.get("approved_by"),
        "executed_by": plan.get("executed_by"),
        "placement_lock_protocol_version": proposal.get(
            "placement_lock_protocol_version"
        ),
        "entrypoint": proposal["entrypoint"],
        "entrypoint_manifest": proposal.get("entrypoint_manifest"),
        "entrypoint_evidence_sha256": proposal.get("entrypoint_evidence_sha256"),
        "registry_sha256": proposal["registry_sha256"],
        "pending_manifest": proposal["pending_manifest"],
        "history_manifest": proposal["history_manifest"],
        "placement_lock": {
            "path": str(paths["placement_lock"]),
            "sha256": lock_sha256,
            "mode": "0600",
            "uid": lock_info.st_uid,
            "nlink": lock_info.st_nlink,
        },
        "quarantined_leases": expected_quarantined,
        "paths": proposal["paths"],
        "completed_at": marker["started_at"],
    }
    if result != expected_result:
        raise MnemosyneError("completed lock migration result binding mismatch")
    if (
        require_current_registry_state
        and sha256_bytes(read_registry_bytes_verified(root)) != result.get("registry_sha256")
    ):
        raise MnemosyneError("registry drifted after completed lock migration")
    if require_current_queue_state:
        if yaml_directory_manifest(pending_dir(root)) != result.get("pending_manifest"):
            raise MnemosyneError("pending queue drifted after completed lock migration")
        if yaml_directory_manifest(decisions_dir(root)) != result.get("history_manifest"):
            raise MnemosyneError("decision history drifted after completed lock migration")
    require_no_manual_recovery_blockers(root)
    return result


def legacy_writer_after_shared_lock_acquire(_root: Path, _lock_path: Path, _lock_fd: int) -> None:
    """Narrow test seam after completed migration verification and shared lock acquisition."""


def acquire_shared_flock_nonblocking(lock_fd: int) -> None:
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
            raise MnemosyneError("placement lock is busy") from exc
        raise MnemosyneError("cannot acquire placement shared lock") from exc


def require_current_placement_lock_identity(
    root: Path,
    expected_sha256: str,
    opened_info: os.stat_result,
) -> None:
    current_fd = open_placement_lock_verified(root, expected_sha256)
    try:
        current_info = os.fstat(current_fd)
        if (current_info.st_dev, current_info.st_ino) != (
            opened_info.st_dev,
            opened_info.st_ino,
        ):
            raise MnemosyneError("placement lock identity changed during verification")
    finally:
        os.close(current_fd)


def directory_mutation_token(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mtime_ns


@contextmanager
def verified_shared_placement_lock(root: Path) -> Iterator[Any]:
    require_no_manual_recovery_blockers(root)
    require_no_active_lock_migration(root)
    lock_path = placement_lock_path(root)
    lock_fd = open_placement_lock_verified(root, None)
    registry_directory = root / "_registry"
    registry_fd: int | None = None
    try:
        registry_fd = open_verified_directory(registry_directory, require_owner_only=True)
        registry_token = directory_mutation_token(os.fstat(registry_fd))
        opened_info = os.fstat(lock_fd)
        acquire_shared_flock_nonblocking(lock_fd)
        require_no_manual_recovery_blockers(root)
        require_no_active_lock_migration(root)
        lock_bytes = read_open_file_bytes(lock_fd)
        try:
            lock_payload = json.loads(lock_bytes)
        except json.JSONDecodeError as exc:
            raise MnemosyneError("placement lock payload is invalid") from exc
        if lock_bytes != canonical_json_bytes(lock_payload):
            raise MnemosyneError("placement lock payload is not canonical")
        migration_id = str(lock_payload.get("migration_id", ""))
        proposal_sha256 = str(lock_payload.get("proposal_sha256", ""))
        if (
            lock_payload.get("kind") != "PLACEMENT_COORDINATION_LOCK"
            or lock_payload.get("placement_lock_protocol_version")
            != PLACEMENT_LOCK_PROTOCOL_VERSION
            or not isinstance(lock_payload.get("compatibility_version"), str)
            or not lock_payload.get("compatibility_version")
            or not migration_id
            or not proposal_sha256
        ):
            raise MnemosyneError("placement lock payload binding is invalid")
        validate_lock_migration_id(migration_id)
        proposal_path = lock_migrations_dir(root) / "proposals" / migration_id / "proposal.json"
        try:
            proposal_info, proposal_bytes = read_verified_regular_file(
                proposal_path,
                label="completed lock migration proposal",
            )
            if proposal_info.st_nlink != 1:
                raise MnemosyneError("completed lock migration proposal link count is invalid")
            proposal = json.loads(proposal_bytes)
        except json.JSONDecodeError as exc:
            raise MnemosyneError("completed lock migration proposal is unreadable") from exc
        if sha256_bytes(proposal_bytes) != proposal_sha256 or proposal.get("migration_id") != migration_id:
            raise MnemosyneError("completed lock migration proposal binding mismatch")
        migration_root = lock_migrations_dir(root)
        paths = {
            "active_marker": migration_root / "active",
            "placement_lock": lock_path,
            "incomplete_run": migration_root / "runs" / f".incomplete-{migration_id}",
            "final_run": migration_root / "runs" / migration_id,
            "completed_result": migration_root / "completed" / migration_id / "result.json",
            "completed_marker": migration_root / "completed" / migration_id / "marker.json",
        }
        if any(proposal.get("paths", {}).get(name) != str(path) for name, path in paths.items()):
            raise MnemosyneError("completed lock migration path binding mismatch")
        verify_completed_lock_migration(
            root,
            proposal,
            proposal_sha256,
            paths,
            require_current_registry_state=False,
            require_current_queue_state=False,
        )
        lock_sha256 = sha256_bytes(lock_bytes)

        def checkpoint() -> None:
            require_no_manual_recovery_blockers(root)
            require_no_active_lock_migration(root)
            require_current_placement_lock_identity(root, lock_sha256, opened_info)
            require_same_directory_identity(registry_directory, registry_fd, "registry")
            if directory_mutation_token(os.fstat(registry_fd)) != registry_token:
                raise MnemosyneError("registry directory changed during placement write")

        checkpoint()
        legacy_writer_after_shared_lock_acquire(root, lock_path, lock_fd)
        checkpoint()
        yield checkpoint
        checkpoint()
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
            if registry_fd is not None:
                os.close(registry_fd)


def legacy_writer_after_lease_create(_root: Path, _lease_path: Path) -> None:
    """Narrow interleaving seam used by deterministic lock-migration tests."""


def legacy_approve_before_target_publish(_source: Path, _target: Path) -> None:
    """Fault-injection seam after the legacy target precheck."""


def require_same_lease_identity_at(
    lease_directory_fd: int,
    lease_name: str,
    lease_path: Path,
    lease_stat: os.stat_result,
) -> None:
    try:
        current = os.stat(lease_name, dir_fd=lease_directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise MnemosyneError(f"legacy writer lease identity changed: {lease_path}") from exc
    if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
        lease_stat.st_dev,
        lease_stat.st_ino,
    ):
        raise MnemosyneError(f"legacy writer lease identity changed: {lease_path}")


def require_same_directory_identity(path: Path, opened_fd: int, label: str) -> None:
    _safety_core.require_same_directory_identity(
        path,
        opened_fd,
        label,
        error_type=MnemosyneError,
        before_directory_identity_check=safety_before_directory_identity_check,
    )


@contextmanager
def _legacy_writer_lease_without_recovery_guard(
    root: Path,
    command: str,
) -> Iterator[Any]:
    require_no_manual_recovery_blockers(root)
    require_no_active_lock_migration(root)
    if os.path.lexists(placement_lock_path(root)):
        with verified_shared_placement_lock(root) as checkpoint:
            yield checkpoint
        return
    registry = registry_path(root)
    registry_bytes = read_registry_bytes_verified(root)
    completed_root = lock_migrations_dir(root) / "completed"
    completed_state_present = False
    if os.path.lexists(completed_root):
        try:
            completed_root_fd = open_verified_directory(completed_root, require_owner_only=True)
        except MnemosyneError:
            completed_state_present = True
        else:
            try:
                completed_state_present = bool(os.listdir(completed_root_fd))
                require_same_directory_identity(completed_root, completed_root_fd, "completed migration")
            except (MnemosyneError, OSError):
                completed_state_present = True
            finally:
                os.close(completed_root_fd)
    if (
        completed_state_present
        or registry_has_curation_section(registry_bytes)
        or os.path.lexists(root / "_registry" / "curation" / "ledger.sqlite3")
    ):
        raise MnemosyneError(
            "completed lock migration requires placement lock; lockless fallback is forbidden"
        )

    pid = os.getpid()
    start_identity = process_start_identity(pid)
    start_digest = hashlib.sha256(f"{pid}\0{start_identity}".encode("utf-8")).hexdigest()[:20]
    lease_id = f"{pid}-{start_digest}"
    lease_directory = lock_migrations_dir(root) / "legacy-leases"
    try:
        lease_directory_fd = open_or_create_verified_directory(lease_directory)
    except MnemosyneError as exc:
        raise MnemosyneError("cannot open verified legacy lease directory") from exc
    lease_path = lease_directory / lease_id
    payload = {
        "schema_version": 1,
        "pid": pid,
        "process_start_identity": start_identity,
        "command": command,
        "registry_sha256": hashlib.sha256(registry_bytes).hexdigest(),
    }
    encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(lease_id, flags, 0o600, dir_fd=lease_directory_fd)
    except FileExistsError as exc:
        os.close(lease_directory_fd)
        raise MnemosyneError(f"legacy writer lease already exists: {lease_path.name}") from exc
    except OSError as exc:
        os.close(lease_directory_fd)
        raise MnemosyneError(f"cannot create legacy writer lease: {lease_path}") from exc

    lease_stat: os.stat_result | None = None
    try:
        try:
            lease_stat = os.fstat(fd)
        except OSError as exc:
            raise MnemosyneError(
                f"cannot inspect new legacy writer lease: {lease_path}"
            ) from exc
        offset = 0
        while offset < len(encoded):
            written = os.write(fd, encoded[offset:])
            if written <= 0:
                raise MnemosyneError(f"legacy writer lease write made no progress: {lease_path}")
            offset += written
        os.fsync(fd)
        os.fsync(lease_directory_fd)
        legacy_writer_after_lease_create(root, lease_path)
        require_no_manual_recovery_blockers(root)
        require_same_directory_identity(lease_directory, lease_directory_fd, "legacy lease")
        require_same_lease_identity_at(lease_directory_fd, lease_id, lease_path, lease_stat)
        require_no_active_lock_migration(root)
        if os.path.lexists(placement_lock_path(root)):
            raise MnemosyneError("placement lock changed during legacy writer lease; retry required")
        require_same_directory_identity(lease_directory, lease_directory_fd, "legacy lease")
        require_same_lease_identity_at(lease_directory_fd, lease_id, lease_path, lease_stat)
        def checkpoint() -> None:
            require_no_manual_recovery_blockers(root)
            require_same_directory_identity(lease_directory, lease_directory_fd, "legacy lease")
            require_same_lease_identity_at(lease_directory_fd, lease_id, lease_path, lease_stat)
            require_no_active_lock_migration(root)
            if os.path.lexists(placement_lock_path(root)):
                raise MnemosyneError("placement lock changed during legacy writer lease; retry required")

        yield checkpoint
        checkpoint()
    finally:
        try:
            if lease_stat is not None:
                require_same_directory_identity(lease_directory, lease_directory_fd, "legacy lease")
                require_same_lease_identity_at(lease_directory_fd, lease_id, lease_path, lease_stat)
                os.unlink(lease_id, dir_fd=lease_directory_fd)
                os.fsync(lease_directory_fd)
                require_same_directory_identity(lease_directory, lease_directory_fd, "legacy lease")
        finally:
            os.close(fd)
            os.close(lease_directory_fd)


@contextmanager
def legacy_writer_lease(root: Path, command: str) -> Iterator[LegacyWriterAuthority]:
    with manual_recovery_guard(root) as guard:
        with _legacy_writer_lease_without_recovery_guard(root, command) as checkpoint:
            authority = LegacyWriterAuthority(guard, checkpoint)
            authority()
            yield authority
            authority()


def resolve_under_root(value: str | Path, root: Path, *, must_exist: bool = False) -> Path:
    return _safety_core.resolve_under_root(
        value,
        root,
        must_exist=must_exist,
        error_type=MnemosyneError,
    )


def require_no_symlink_components(value: str | Path, root: Path, label: str) -> Path:
    return _safety_core.require_no_symlink_components(
        value,
        root,
        label,
        error_type=MnemosyneError,
    )


def relative_posix(path: Path, root: Path) -> str:
    return _safety_core.relative_posix(path, root)


def violates_never_touch(path: Path, root: Path, rules: list[str]) -> str | None:
    return _safety_core.violates_never_touch(path, root, rules)


def require_safe_path(path: Path, root: Path, registry: dict[str, Any], label: str) -> None:
    _safety_core.require_safe_path(
        path,
        root,
        registry,
        label,
        error_type=MnemosyneError,
    )


def require_movable_path(path: Path, root: Path, label: str) -> None:
    _safety_core.require_movable_path(
        path,
        root,
        label,
        error_type=MnemosyneError,
    )


def require_safe_tree(path: Path, root: Path, registry: dict[str, Any], label: str) -> None:
    _safety_core.require_safe_tree(
        path,
        root,
        registry,
        label,
        error_type=MnemosyneError,
    )


def safe_tree_identity_manifest(path: Path, label: str) -> tuple[tuple[str, int, int, int], ...]:
    return _safety_core.safe_tree_identity_manifest(
        path,
        label,
        error_type=MnemosyneError,
    )


def category_for_source(source: Path, root: Path, registry: dict[str, Any]) -> dict[str, Any]:
    rel = relative_posix(source, root)
    name = source.name
    fallback: dict[str, Any] | None = None
    for category in registry.get("categories", []):
        if category.get("id") == "inbox_review":
            fallback = category
        for pattern in category.get("patterns", []):
            pattern = str(pattern)
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
                return category
    if fallback:
        return fallback
    raise MnemosyneError(f"no matching category for: {source}")


def matches_any_category(path: Path, root: Path, registry: dict[str, Any]) -> bool:
    rel = relative_posix(path, root)
    name = path.name
    for category in registry.get("categories", []):
        target = Path(str(category.get("target", ""))).resolve()
        if path.resolve(strict=False) == target or target in path.resolve(strict=False).parents:
            return True
        for pattern in category.get("patterns", []):
            pattern = str(pattern)
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
                return True
    return False


def make_id(prefix: str, source: Path, target: Path) -> str:
    now = utc_now().replace("-", "").replace(":", "")
    digest = hashlib.sha256(f"{source}|{target}|{now}".encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{now}-{digest}"


def validate_proposal_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", value):
        raise MnemosyneError("invalid proposal id")
    return value


def find_pending(root: Path, proposal_id: str) -> Path:
    proposal_id = validate_proposal_id(proposal_id)
    exact = pending_dir(root) / f"{proposal_id}.yml"
    if exact.exists():
        return exact
    matches = sorted(pending_dir(root).glob(f"{proposal_id}*.yml"))
    if len(matches) == 1:
        return matches[0]
    if matches:
        raise MnemosyneError(f"ambiguous proposal id: {proposal_id}")
    raise MnemosyneError(f"pending proposal not found: {proposal_id}")


def open_pending_proposal(
    root: Path,
    proposal_id: str,
) -> tuple[int, Path, os.stat_result, dict[str, Any]]:
    proposal_id = validate_proposal_id(proposal_id)
    directory = pending_dir(root)
    try:
        directory_fd = open_verified_directory(directory, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError(f"cannot open verified pending proposal parent: {directory}") from exc
    try:
        names = sorted(
            name
            for name in os.listdir(directory_fd)
            if name.endswith(".yml") and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*\.yml", name)
        )
        exact_name = f"{proposal_id}.yml"
        if exact_name in names:
            name = exact_name
        else:
            matches = [candidate for candidate in names if candidate.startswith(proposal_id)]
            if len(matches) == 1:
                name = matches[0]
            elif matches:
                raise MnemosyneError(f"ambiguous proposal id: {proposal_id}")
            else:
                raise MnemosyneError(f"pending proposal not found: {proposal_id}")
        path = directory / name
        info, proposal = read_flat_yaml_at(
            directory_fd,
            name,
            path,
            label="pending proposal",
        )
        require_same_directory_identity(directory, directory_fd, "pending proposal")
        return directory_fd, path, info, proposal
    except Exception:
        os.close(directory_fd)
        raise


def remove_pending_proposal_if_same(
    root: Path,
    directory_fd: int,
    path: Path,
    expected: os.stat_result,
) -> None:
    directory = pending_dir(root)
    require_same_directory_identity(directory, directory_fd, "pending proposal")
    try:
        current = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise MnemosyneError("pending proposal identity changed before removal") from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise MnemosyneError("pending proposal identity changed before removal")
    os.unlink(path.name, dir_fd=directory_fd)
    os.fsync(directory_fd)
    require_same_directory_identity(directory, directory_fd, "pending proposal")
    try:
        os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise MnemosyneError("pending proposal removal readback mismatch")


def iter_yaml_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    return sorted(path.glob("*.yml"))


def validate_workspace_slug(slug: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", slug):
        raise MnemosyneError(f"invalid workspace slug: {slug}")


def slugify_title(title: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", title.lower()).strip("-")
    return slug or "memory-sync"


def timestamp_for_filename(created_at: str) -> str:
    return created_at.replace("-", "").replace(":", "")


def memory_root(root: Path) -> Path:
    return root / "memory"


def canonical_plan_path(path: Path) -> Path:
    """Resolve only the parent so the plan leaf stays subject to O_NOFOLLOW."""
    try:
        absolute_path = Path(os.path.abspath(path.expanduser()))
        return absolute_path.parent.resolve(strict=False) / absolute_path.name
    except (OSError, RuntimeError) as exc:
        raise MnemosyneError("plan output path is invalid") from exc


def require_plan_outside_memory_root(root: Path, plan_path: Path) -> Path:
    try:
        resolved_memory_root = memory_root(root).resolve(strict=False)
        resolved_plan_path = canonical_plan_path(plan_path)
    except (OSError, RuntimeError) as exc:
        raise MnemosyneError("plan output path is invalid") from exc
    if (
        resolved_plan_path == resolved_memory_root
        or resolved_memory_root in resolved_plan_path.parents
    ):
        raise MnemosyneError("plan output must be outside raw memory")
    return resolved_plan_path


def workspace_memory_dir(root: Path, workspace: str) -> Path:
    base = memory_root(root).resolve(strict=False)
    path = (memory_root(root) / workspace).resolve(strict=False)
    if path != base and base not in path.parents:
        raise MnemosyneError(f"workspace memory path outside memory root: {path}")
    return path


def load_workspaces(root: Path) -> dict[str, dict[str, str]]:
    path = memory_root(root) / "workspaces.yml"
    if not path.exists():
        raise MnemosyneError(f"workspace registry missing: {path}")

    workspaces: dict[str, dict[str, str]] = {}
    in_workspaces = False
    current_slug: str | None = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line_without_comment = raw_line.split("#", 1)[0].rstrip()
        if not line_without_comment.strip():
            continue
        indent = len(line_without_comment) - len(line_without_comment.lstrip(" "))
        line = line_without_comment.strip()

        if indent == 0:
            in_workspaces = line == "workspaces:"
            current_slug = None
            continue

        if not in_workspaces:
            continue

        if indent == 2 and line.endswith(":"):
            current_slug = line[:-1]
            workspaces[current_slug] = {}
            continue

        if indent == 4 and current_slug and ":" in line:
            key, value = line.split(":", 1)
            workspaces[current_slug][key.strip()] = value.strip().strip("\"'")

    return workspaces


def check_safe_content(values: list[str]) -> None:
    for value in values:
        for pattern in UNSAFE_CONTENT_PATTERNS:
            if pattern.search(value):
                raise MnemosyneError("unsafe content detected; refusing memory-sync write")


def redact_unsafe_output(text: str) -> str:
    redacted = text
    for pattern in UNSAFE_CONTENT_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def split_frontmatter(text: str) -> tuple[list[str], str]:
    if not text.startswith("---\n"):
        raise MnemosyneError("snapshot missing YAML frontmatter")
    end = text.find("\n---", 4)
    if end == -1:
        raise MnemosyneError("snapshot frontmatter is not closed")
    frontmatter = text[4:end].strip("\n").splitlines()
    body = text[end + len("\n---") :]
    if body.startswith("\n"):
        body = body[1:]
    return frontmatter, body


def find_source_refs_end(lines: list[str], start: int) -> int:
    index = start + 1
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if not line.startswith(" ") and not line.startswith("-") and ":" in line:
            break
        index += 1
    return index


def upsert_snapshot_workstream(body: str, workstream: str, title: str, summary: str) -> str:
    lines = body.splitlines()
    entry_id = f"- id: {workstream}"
    latest_update = " ".join(f"{title}: {summary}".split())
    summary_line = " ".join(summary.split())
    replacement_fields = {
        "latest_update": f"  latest_update: {json.dumps(latest_update, ensure_ascii=False)}",
        "summary": f"  summary: {json.dumps(summary_line, ensure_ascii=False)}",
    }

    try:
        section_start = lines.index("## Workstreams")
    except ValueError:
        if lines and lines[-1]:
            lines.append("")
        lines.extend(
            [
                "## Workstreams",
                "",
                entry_id,
                "  status: active",
                replacement_fields["latest_update"],
                replacement_fields["summary"],
            ]
        )
        return "\n".join(lines) + "\n"

    section_end = next(
        (index for index in range(section_start + 1, len(lines)) if lines[index].startswith("## ")),
        len(lines),
    )
    try:
        entry_start = lines.index(entry_id, section_start + 1, section_end)
    except ValueError:
        insertion = [
            entry_id,
            "  status: active",
            replacement_fields["latest_update"],
            replacement_fields["summary"],
            "",
        ]
        lines[section_end:section_end] = insertion
        return "\n".join(lines) + "\n"

    entry_end = next(
        (
            index
            for index in range(entry_start + 1, section_end)
            if lines[index].startswith("- id:")
        ),
        section_end,
    )
    seen: set[str] = set()
    for index in range(entry_start + 1, entry_end):
        field = lines[index].strip().partition(":")[0]
        if field in replacement_fields:
            lines[index] = replacement_fields[field]
            seen.add(field)
    for field in ("latest_update", "summary"):
        if field not in seen:
            lines.insert(entry_end, replacement_fields[field])
            entry_end += 1
    return "\n".join(lines) + "\n"


def snapshot_workstream_status(text: str, workstream: str) -> str:
    _, body = split_frontmatter(text)
    entry_id = f"- id: {workstream}"
    return "existing" if entry_id in body.splitlines() else "new"


def render_snapshot_current_state_lines(
    current_state_groups: list[dict[str, Any]],
) -> list[str]:
    lines = ["  current_state:"]
    for group in current_state_groups:
        for item in group["items"]:
            detail = f"{group['title']}: {item}"
            lines.append(f"    - {json.dumps(detail, ensure_ascii=False)}")
    return lines


def upsert_snapshot_workstream_current_state(
    body: str,
    workstream: str,
    current_state_groups: list[dict[str, Any]],
) -> str:
    lines = body.splitlines()
    entry_id = f"- id: {workstream}"
    try:
        section_start = lines.index("## Workstreams")
        section_end = next(
            (
                index
                for index in range(section_start + 1, len(lines))
                if lines[index].startswith("## ")
            ),
            len(lines),
        )
        entry_start = lines.index(entry_id, section_start + 1, section_end)
    except ValueError as exc:
        raise MnemosyneError("workstream entry is unavailable for current-state update") from exc
    entry_end = next(
        (
            index
            for index in range(entry_start + 1, section_end)
            if lines[index].startswith("- id:")
        ),
        section_end,
    )
    current_state_start = next(
        (
            index
            for index in range(entry_start + 1, entry_end)
            if lines[index] == "  current_state:"
        ),
        None,
    )
    if current_state_start is None:
        insertion = entry_end
        while insertion > entry_start and not lines[insertion - 1]:
            insertion -= 1
    else:
        insertion = current_state_start
        current_state_end = next(
            (
                index
                for index in range(current_state_start + 1, entry_end)
                if lines[index].startswith("  ") and not lines[index].startswith("    ")
            ),
            entry_end,
        )
        del lines[current_state_start:current_state_end]
    lines[insertion:insertion] = render_snapshot_current_state_lines(current_state_groups)
    return "\n".join(lines) + "\n"


def build_updated_snapshot(
    text: str,
    created_at: str,
    refs: list[str],
    workstream: str,
    title: str,
    summary: str,
    current_state_groups: list[dict[str, Any]] | None = None,
) -> tuple[str, list[str]]:
    frontmatter, body = split_frontmatter(text)
    existing_refs = {line.strip()[2:].strip() for line in frontmatter if line.strip().startswith("- ")}
    refs_to_add = [ref for ref in refs if ref not in existing_refs]

    updated_lines: list[str] = []
    updated_at_seen = False
    source_refs_index: int | None = None
    for line in frontmatter:
        if line.startswith("updated_at:"):
            updated_lines.append(f"updated_at: {created_at}")
            updated_at_seen = True
        else:
            if line == "source_refs:" and source_refs_index is None:
                source_refs_index = len(updated_lines)
            updated_lines.append(line)

    if not updated_at_seen:
        insert_at = source_refs_index if source_refs_index is not None else len(updated_lines)
        updated_lines.insert(insert_at, f"updated_at: {created_at}")
        if source_refs_index is not None:
            source_refs_index += 1

    if source_refs_index is None:
        updated_lines.append("source_refs:")
        source_refs_index = len(updated_lines) - 1

    insert_at = find_source_refs_end(updated_lines, source_refs_index)
    for ref in refs_to_add:
        updated_lines.insert(insert_at, f"- {ref}")
        insert_at += 1

    body = upsert_snapshot_workstream(body, workstream, title, summary)
    if current_state_groups is not None:
        body = upsert_snapshot_workstream_current_state(
            body,
            workstream,
            current_state_groups,
        )
    updated = "---\n" + "\n".join(updated_lines) + "\n---\n" + body
    return updated, refs_to_add


def _require_plan_parent_identity(path: Path, parent_fd: int) -> None:
    try:
        opened = os.fstat(parent_fd)
        observed = os.stat(path.parent, follow_symlinks=False)
    except OSError as exc:
        raise MnemosyneError("plan output parent changed or is unavailable") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
    ):
        raise MnemosyneError("plan output parent changed or is unsafe")


def _open_verified_plan_parent(path: Path) -> int:
    if (
        not path.is_absolute()
        or not path.name
        or path.name in {".", ".."}
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise MnemosyneError("plan output path is invalid")
    try:
        parent_fd = open_verified_directory(path.parent, require_owner_only=True)
    except MnemosyneError as exc:
        raise MnemosyneError("plan output parent changed or is unsafe") from exc
    try:
        _require_plan_parent_identity(path, parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    return parent_fd


def write_owner_only_plan(
    path: Path,
    plan_bytes: bytes,
    *,
    parent_fd: int | None = None,
) -> None:
    owns_parent_fd = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_verified_plan_parent(path)
    try:
        _require_plan_parent_identity(path, parent_fd)

        def require_parent_identity(*_unused: object) -> None:
            _require_plan_parent_identity(path, parent_fd)

        _safety_core.publish_bytes_atomic_no_replace_at(
            parent_fd,
            path.name,
            path,
            plan_bytes,
            label="workspace sync Plan",
            mode=0o600,
            collision_error=f"plan already exists: {path}",
            final_identity_error=f"new plan file identity changed: {path}",
            error_type=MnemosyneError,
            after_fd_readback=require_parent_identity,
            after_file_fsync=require_parent_identity,
            after_file_readback=require_parent_identity,
            after_directory_fsync=require_parent_identity,
        )
    finally:
        if owns_parent_fd:
            os.close(parent_fd)


def read_owner_only_plan(path: Path) -> bytes:
    try:
        path = canonical_plan_path(path)
    except MnemosyneError as exc:
        raise MnemosyneError(f"cannot resolve approved plan: {path}") from exc
    parent_fd = _open_verified_plan_parent(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path.name, flags, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise MnemosyneError(f"cannot open approved plan: {path}") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            raise MnemosyneError("approved plan file is unsafe")
        chunks = []
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise MnemosyneError("approved plan changed while reading")
        _require_plan_parent_identity(path, parent_fd)
        return b"".join(chunks)
    finally:
        os.close(fd)
        os.close(parent_fd)


def read_owner_only_approval_review(path: Path) -> dict[str, Any]:
    try:
        review_bytes = read_owner_only_plan(path)
    except MnemosyneError as exc:
        raise MnemosyneError(str(exc).replace("approved plan", "approval review")) from exc
    if len(review_bytes) > 8 * 1024 * 1024:
        raise MnemosyneError("approval review is too large")
    try:
        review = json.loads(review_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MnemosyneError("approval review is invalid") from exc
    try:
        validated = _workspace_sync_review_core.validate_approval_review(review)
    except ValueError as exc:
        raise MnemosyneError("approval review is invalid") from exc
    check_safe_content(_workspace_sync_review_core.approval_review_text_values(validated))
    return validated


def render_workspace_sync_approval_card(args: argparse.Namespace) -> int:
    plan_path = Path(args.render_approval_card).expanduser()
    plan_bytes = read_owner_only_plan(plan_path)
    try:
        plan = json.loads(plan_bytes.decode("utf-8"))
        validated = _workspace_sync_review_core.validate_workspace_sync_plan_v2(plan)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise MnemosyneError("approved plan cannot render an approval card") from exc
    review = validated["approval_review"]
    check_safe_content(
        [
            validated["workspace"],
            validated["workstream"],
            validated["title"],
            validated["summary"],
        ]
        + _workspace_sync_review_core.approval_review_text_values(review)
    )
    print(_workspace_sync_review_core.render_workspace_sync_approval_card(validated), end="")
    return 0


def build_workspace_sync_apply_request(
    *,
    root: Path,
    actor: str,
    plan_text: str,
    plan_bytes: bytes,
    plan_sha256: str,
    workstream: str,
) -> Any:
    contract = _mnemosyne_core.operation_contract
    return contract.OperationRequest(
        schema_version=1,
        operation_kind="memory.workspace_sync",
        action=contract.LifecycleAction.APPLY,
        claim_mode=contract.ClaimMode.HISTORICAL,
        root=str(root),
        actor=actor,
        requested_authority=contract.AuthorityMode.WRITE,
        payload={"plan_text": plan_text},
        scope={
            "plan_sha256": plan_sha256,
            "workstream_id": workstream,
        },
        bounds={"max_total_bytes": max(1, len(plan_bytes))},
    )


def apply_workspace_sync_plan(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    plan_path = Path(args.apply_plan).expanduser()
    plan_bytes = read_owner_only_plan(plan_path)
    expected_sha256 = args.expected_plan_sha256
    if (
        type(expected_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or sha256_bytes(plan_bytes) != expected_sha256
    ):
        raise MnemosyneError("approved plan identity does not match")
    try:
        plan_text = plan_bytes.decode("utf-8")
        plan = json.loads(plan_text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MnemosyneError("approved plan is invalid") from exc
    workstream = plan.get("workstream")
    if type(workstream) is not str or not workstream:
        raise MnemosyneError("approved plan workstream is invalid")
    request = build_workspace_sync_apply_request(
        root=root,
        actor=args.actor,
        plan_text=plan_text,
        plan_bytes=plan_bytes,
        plan_sha256=expected_sha256,
        workstream=workstream,
    )
    outcome = json.loads(_mnemosyne_core.execute_request_bytes(request.canonical_bytes))
    if outcome.get("outcome_kind") != "completed":
        reason = outcome.get("reason_code", "ADMISSION_DENIED")
        next_action = outcome.get("next_safe_action", "inspect")
        raise MnemosyneError(f"memory-sync blocked: {reason}; next: {next_action}")
    result = outcome.get("result", {})
    print("outcome: completed")
    print(f"claim_mode: {result.get('claim_mode')}")
    print(f"history: {root / result['history_path']}")
    print(f"snapshot: {root / result['snapshot_path']}")
    print(f"receipt: {root / result['receipt_path']}")
    return 0


def build_history_content(
    *,
    root: Path,
    workspace: str,
    workspace_root: str,
    workstream: str,
    created_at: str,
    title: str,
    summary: str,
    refs: list[str],
    approval_review: dict[str, Any] | None = None,
) -> str:
    source_refs = "\n".join(f"- {ref}" for ref in refs)
    approval_sections: list[str] = []
    if approval_review is not None:
        approval_sections.extend(("## 최신 상태에 반영한 내용", ""))
        for group in approval_review["current_state_groups"]:
            approval_sections.extend((f"### {group['title']}", ""))
            approval_sections.extend(f"- {item}" for item in group["items"])
            approval_sections.append("")
        approval_sections.extend(("## 기록으로 남긴 내용", ""))
        for group in approval_review["history_groups"]:
            approval_sections.extend((f"### {group['title']}", ""))
            approval_sections.extend(f"- {item}" for item in group["items"])
            approval_sections.append("")
        approval_sections.extend(("## 이번 기록에 포함하지 않은 내용", ""))
        approval_sections.extend(f"- {exclusion}" for exclusion in approval_review["exclusions"])
        approval_sections.append("")
    rendered_approval_sections = "\n".join(approval_sections)
    return f"""---
schema_version: 1
event_type: snapshot-update
workspace: {workspace}
workspace_root: {workspace_root}
workstream: {workstream}
created_at: {created_at}
source_refs:
{source_refs}
raw_log_policy: no raw command output, raw logs, raw file bodies, full environment dumps, credentials, token values, email values, secret-like values, and credential-like values were not persisted
transcript_policy: summary only; raw transcript content was not persisted
redaction_policy: sanitized summary and explicit source_refs only
---

# {title}

{summary}

{rendered_approval_sections}
## Boundary

This sync mutated only files under `{root / "memory" / workspace}`. It did not mutate Jira, Confluence, GitHub, repository source files, runtime state, deployments, graphify output, worktrees, or external services. It does not store raw logs, credentials, tokens, private keys, email values, exact endpoints, raw command output, raw transcript content, or full private bodies.
"""


def command_memory_sync(args: argparse.Namespace) -> int:
    if getattr(args, "render_approval_card", None):
        return render_workspace_sync_approval_card(args)
    if getattr(args, "apply_plan", None):
        return apply_workspace_sync_plan(args)
    if getattr(args, "apply", False):
        raise MnemosyneError("direct --apply was removed; create and approve a Plan")
    if not getattr(args, "plan_out", None):
        raise MnemosyneError(
            "memory-sync requires --plan-out, --render-approval-card, or --apply-plan"
        )
    if not all(type(value) is str and value for value in (args.workspace, args.title, args.summary)):
        raise MnemosyneError("Plan creation requires workspace, title, and summary")
    root = Path(args.root).expanduser().resolve()
    validate_workspace_slug(args.workspace)
    check_safe_content([args.workspace, args.title, args.summary, args.workstream or "", *args.ref])

    workspaces = load_workspaces(root)
    if args.workspace not in workspaces and not args.allow_unknown:
        raise MnemosyneError(f"unknown workspace: {args.workspace}")

    workspace_root = workspaces.get(args.workspace, {}).get("root", "")
    workspace_dir = workspace_memory_dir(root, args.workspace)
    snapshot_path = workspace_dir / "snapshot.md"
    if not snapshot_path.exists():
        raise MnemosyneError(f"snapshot missing: {snapshot_path}")

    approval_review_path = getattr(args, "approval_review", None)
    if type(approval_review_path) is not str or not approval_review_path:
        raise MnemosyneError("Plan creation requires --approval-review")
    approval_review = read_owner_only_approval_review(Path(approval_review_path).expanduser())
    review_refs = {reference["ref"] for reference in approval_review["references"]}
    if len(set(args.ref)) != len(args.ref) or review_refs != set(args.ref):
        raise MnemosyneError("approval review references must exactly match --ref")

    created_at = utc_now()
    workstream = args.workstream or args.workspace

    if args.plan_out:
        plan_path = require_plan_outside_memory_root(
            root,
            Path(args.plan_out).expanduser(),
        )
        registry_path = memory_root(root) / "workspaces.yml"
        snapshot_bytes = snapshot_path.read_bytes()
        snapshot_text = snapshot_bytes.decode("utf-8")
        derived_effects = _workspace_sync_review_core.derive_workspace_sync_effects(
            root=root,
            workspace=args.workspace,
            workspace_root=workspace_root,
            workstream=workstream,
            created_at=created_at,
            title=args.title,
            summary=args.summary,
            approval_review=approval_review,
            snapshot_text=snapshot_text,
        )
        workstream_status = derived_effects["workstream_status"]
        history_path = root / derived_effects["history_path"]
        updated_snapshot = derived_effects["snapshot_final_text"]
        history_content = derived_effects["history_final_text"]
        plan = {
            "schema": _workspace_sync_review_core.WORKSPACE_SYNC_PLAN_V2_SCHEMA,
            "schema_version": 2,
            "created_at": created_at,
            "root": str(root),
            "workspace": args.workspace,
            "workstream": workstream,
            "workstream_status": workstream_status,
            "title": args.title,
            "summary": args.summary,
            "claim_mode": "HISTORICAL",
            "sanitization_policy_sha256": sha256_bytes(
                "\n".join(pattern.pattern for pattern in UNSAFE_CONTENT_PATTERNS).encode("utf-8")
            ),
            "bases": {
                "memory/workspaces.yml": sha256_bytes(registry_path.read_bytes()),
                str(snapshot_path.relative_to(root)): sha256_bytes(snapshot_bytes),
            },
            "effects": [
                {
                    "path": str(history_path.relative_to(root)),
                    "base_sha256": None,
                    "final_text": history_content,
                    "final_sha256": sha256_bytes(history_content.encode("utf-8")),
                },
                {
                    "path": str(snapshot_path.relative_to(root)),
                    "base_sha256": sha256_bytes(snapshot_bytes),
                    "final_text": updated_snapshot,
                    "final_sha256": sha256_bytes(updated_snapshot.encode("utf-8")),
                },
            ],
            "approval_review": approval_review,
        }
        try:
            _workspace_sync_review_core.validate_workspace_sync_plan_v2(plan)
        except ValueError as exc:
            raise MnemosyneError("workspace sync Plan is invalid") from exc
        plan_bytes = canonical_json_bytes(plan) + b"\n"
        if len(plan_bytes) > MAX_WORKSPACE_SYNC_PLAN_BYTES:
            raise MnemosyneError("workspace sync Plan is too large")
        plan_sha256 = sha256_bytes(plan_bytes)
        request = build_workspace_sync_apply_request(
            root=root,
            actor=args.actor,
            plan_text=plan_bytes.decode("utf-8"),
            plan_bytes=plan_bytes,
            plan_sha256=plan_sha256,
            workstream=workstream,
        )
        if (
            len(request.canonical_bytes)
            > _mnemosyne_core.operation_contract.MAX_OPERATION_REQUEST_BYTES
        ):
            raise MnemosyneError(
                "workspace sync Plan exceeds operation request transport limit"
            )
        write_owner_only_plan(plan_path, plan_bytes)
        print("mode: memory-sync plan")
        print(f"workspace: {args.workspace}")
        print(f"history: {history_path}")
        print(f"snapshot: {snapshot_path}")
        print(f"plan: {plan_path}")
        print(f"plan_sha256: {plan_sha256}")
        print("writes: none")
        return 0

    raise AssertionError("workspace sync Plan mode returned unexpectedly")


def extract_heading(text: str, fallback: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or fallback
    return fallback


def extract_updated_at(snapshot_text: str) -> str:
    try:
        frontmatter, _ = split_frontmatter(snapshot_text)
    except MnemosyneError:
        frontmatter = snapshot_text.splitlines()[:50]
    for line in frontmatter:
        if line.startswith("updated_at:"):
            return line.split(":", 1)[1].strip()
    return ""


def truncate_text(text: str, limit: int) -> tuple[str, bool]:
    if limit <= 0:
        return "", bool(text)
    if len(text) <= limit:
        return text, False
    marker = "\n[truncated]\n"
    if limit <= len(marker):
        return text[:limit], True
    return text[: limit - len(marker)] + marker, True


def question_tokens(question: str | None) -> set[str]:
    if not question:
        return set()
    return {token for token in re.findall(r"[A-Za-z0-9가-힣_.-]+", question.lower()) if len(token) > 1}


def relevance_score(path: Path, text: str, tokens: set[str]) -> int:
    if not tokens:
        return 0
    haystack = f"{path.name}\n{text}".lower()
    return sum(haystack.count(token) for token in tokens)


def read_history_entries(workspace_dir: Path, *, count: int, question: str | None, excerpt_chars: int) -> list[dict[str, str]]:
    history_dir = workspace_dir / "history"
    if not history_dir.exists():
        return []

    tokens = question_tokens(question)
    candidates: list[tuple[int, str, Path, str]] = []
    for path in sorted(history_dir.glob("*.md"), reverse=True):
        text = path.read_text(encoding="utf-8", errors="replace")
        score = relevance_score(path, text, tokens)
        candidates.append((score, path.name, path, text))

    if tokens:
        candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)

    entries: list[dict[str, str]] = []
    for _, _, path, text in candidates[: max(0, count)]:
        excerpt, _ = truncate_text(redact_unsafe_output(text.strip()), excerpt_chars)
        entries.append(
            {
                "path": str(path),
                "title": extract_heading(text, path.stem),
                "excerpt": excerpt,
            }
        )
    return entries


def run_graphify_context(root: Path, question: str | None, workspace: str, max_chars: int) -> str:
    graph_path = root / "graphify-out" / "graph.json"
    if not graph_path.exists():
        return "graphify not available: graphify-out/graph.json missing"
    query = question or f"{workspace} workspace context"
    try:
        result = subprocess.run(
            ["graphify", "query", query, "--budget", "1500"],
            cwd=str(root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"graphify error: {exc}"
    output = result.stdout.strip()
    if result.returncode != 0:
        output = f"graphify exited {result.returncode}: {output}"
    excerpt, _ = truncate_text(redact_unsafe_output(output), max_chars)
    return excerpt


def build_context_package(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser().resolve()
    validate_workspace_slug(args.workspace)
    workspaces = load_workspaces(root)
    if args.workspace not in workspaces and not args.allow_unknown:
        raise MnemosyneError(f"unknown workspace: {args.workspace}")

    workspace_dir = workspace_memory_dir(root, args.workspace)
    snapshot_path = workspace_dir / "snapshot.md"
    if not snapshot_path.exists():
        raise MnemosyneError(f"snapshot missing: {snapshot_path}")

    snapshot_text = snapshot_path.read_text(encoding="utf-8", errors="replace")
    snapshot_budget = max(400, int(args.max_chars * 0.45))
    history_budget = max(250, int(args.max_chars * 0.18))
    snapshot_excerpt, snapshot_truncated = truncate_text(redact_unsafe_output(snapshot_text.strip()), snapshot_budget)
    history_entries = read_history_entries(
        workspace_dir,
        count=args.history,
        question=args.question,
        excerpt_chars=history_budget,
    )
    graphify_output = None
    if args.with_graphify:
        graphify_output = run_graphify_context(root, args.question, args.workspace, max(500, int(args.max_chars * 0.20)))

    return {
        "mode": "context",
        "workspace": args.workspace,
        "workspace_root": workspaces.get(args.workspace, {}).get("root", ""),
        "snapshot_path": str(snapshot_path),
        "updated_at": extract_updated_at(snapshot_text),
        "question": args.question or "",
        "snapshot_excerpt": snapshot_excerpt,
        "history": history_entries,
        "graphify": graphify_output,
        "truncated": snapshot_truncated,
        "char_count": 0,
    }


def render_context_package(package: dict[str, Any], max_chars: int) -> str:
    lines = [
        "mode: context",
        f"workspace: {package['workspace']}",
        f"workspace_root: {package['workspace_root']}",
        f"snapshot: {package['snapshot_path']}",
        f"updated_at: {package['updated_at']}",
        f"question: {package['question'] or '(none)'}",
        "writes: none",
        "",
        "## Snapshot",
        str(package["snapshot_excerpt"]),
        "",
        f"## Recent history ({len(package['history'])})",
    ]
    for entry in package["history"]:
        lines.extend(["", f"### {entry['title']}", f"path: {entry['path']}", entry["excerpt"]])
    if package["graphify"] is not None:
        lines.extend(["", "## Graphify", str(package["graphify"])])
    lines.extend(
        [
            "",
            "## Safety",
            "- sources are memory snapshot/history only unless --with-graphify is set",
            "- command is read-only",
            "- excerpts are capped by --max-chars",
        ]
    )
    text = "\n".join(lines) + "\n"
    text, truncated = truncate_text(text, max_chars)
    if truncated and not text.endswith("[truncated]\n"):
        text = text.rstrip() + "\n[truncated]\n"
    return text


def render_context_json(package: dict[str, Any], max_chars: int) -> str:
    for _ in range(20):
        payload = ""
        for _ in range(5):
            payload = json.dumps(package, ensure_ascii=False, indent=2)
            if package.get("char_count") == len(payload):
                break
            package["char_count"] = len(payload)
        if len(payload) <= max_chars:
            return payload

        package["truncated"] = True
        history = package.get("history", [])
        reducible_history = [entry for entry in history if entry.get("excerpt")]
        if reducible_history:
            for entry in reducible_history:
                entry["excerpt"], _ = truncate_text(entry["excerpt"], max(0, len(entry["excerpt"]) // 2))
            continue
        if package.get("snapshot_excerpt"):
            package["snapshot_excerpt"], _ = truncate_text(package["snapshot_excerpt"], max(0, len(package["snapshot_excerpt"]) // 2))
            continue
        if package.get("graphify"):
            package["graphify"], _ = truncate_text(str(package["graphify"]), max(0, len(str(package["graphify"])) // 2))
            continue
        if history:
            package["history"] = history[: max(0, len(history) // 2)]
            continue
        break

    payload = json.dumps(package, ensure_ascii=False, indent=2)
    if len(payload) > max_chars:
        raise MnemosyneError("--max-chars too small for JSON envelope")
    return payload


def command_context(args: argparse.Namespace) -> int:
    args.history = getattr(args, "history", 5)
    args.max_chars = getattr(args, "max_chars", 12000)
    if not args.workspace:
        raise MnemosyneError("--workspace is required")
    if args.history < 0:
        raise MnemosyneError("--history must be >= 0")
    if args.max_chars < 500:
        raise MnemosyneError("--max-chars must be >= 500")

    package = build_context_package(args)
    if args.json:
        print(render_context_json(package, args.max_chars))
        return 0

    output = render_context_package(package, args.max_chars)
    print(output, end="")
    return 0


def _render_query_json(payload: dict[str, Any], *, max_chars: int | None = None) -> str:
    """Render one query envelope, shrinking only bounded excerpts when needed."""
    rendered_payload = json.loads(json.dumps(payload, ensure_ascii=False))
    rendered_payload["truncated"] = False
    for _ in range(32):
        rendered = json.dumps(rendered_payload, ensure_ascii=False, indent=2)
        if max_chars is None or len(rendered) <= max_chars:
            return rendered + "\n"

        rendered_payload["truncated"] = True
        history = rendered_payload.get("history", [])
        reducible = [
            entry
            for entry in history
            if isinstance(entry, dict) and isinstance(entry.get("excerpt"), str) and entry["excerpt"]
        ]
        if reducible:
            for entry in reducible:
                excerpt = entry["excerpt"]
                entry["excerpt"], _ = truncate_text(excerpt, len(excerpt) // 2)
            continue
        snapshot = rendered_payload.get("snapshot_excerpt")
        if isinstance(snapshot, str) and snapshot:
            rendered_payload["snapshot_excerpt"], _ = truncate_text(
                snapshot, len(snapshot) // 2
            )
            continue
        if isinstance(history, list) and history:
            rendered_payload["history"] = history[:-1]
            continue
        break
    raise MnemosyneError("--max-chars is too small for the query result envelope")


def command_collect_sync_history(args: argparse.Namespace) -> int:
    try:
        result = _raw_memory_query_core.collect_sync_history(
            Path(args.root),
            start_date=args.from_date,
            end_date=args.to_date,
        )
    except _raw_memory_query_core.RawMemoryQueryError as exc:
        raise MnemosyneError(str(exc)) from exc
    payload = result.as_dict()
    if args.json:
        print(_render_query_json(payload), end="")
        return 0

    lines = [
        "mode: collect-sync-history",
        f"status: {payload['status']}",
        f"range: {args.from_date}..{args.to_date}",
        "writes: none",
        "",
        "## Items",
    ]
    for item in payload["items"]:
        source_refs = ", ".join(item["source_refs"]) or "(history path only)"
        workstream = item.get("workstream") or "(none)"
        lines.extend(
            (
                f"- {item['recorded_at']} · {item['workspace']} / {workstream}",
                f"  item: {item['item']}",
                f"  sources: {source_refs}",
                f"  history: {item['history_path']}",
            )
        )
    if payload["issues"]:
        lines.extend(("", "## Read issues"))
        lines.extend(
            f"- {issue['path']}: {issue['detail']}" for issue in payload["issues"]
        )
    print("\n".join(lines))
    return 0


def command_lookup_project_context(args: argparse.Namespace) -> int:
    args.history = getattr(args, "history", 8)
    args.max_chars = getattr(args, "max_chars", 24000)
    if args.max_chars < 500:
        raise MnemosyneError("--max-chars must be >= 500")
    try:
        result = _raw_memory_query_core.lookup_project_context(
            Path(args.root),
            project_root=Path(args.project_root),
            question=args.question or "",
            task_context=args.task_context or "",
            snapshot_char_limit=args.snapshot_chars,
            history_limit=args.history,
            history_excerpt_char_limit=args.history_excerpt_chars,
        )
    except _raw_memory_query_core.RawMemoryQueryError as exc:
        raise MnemosyneError(str(exc)) from exc
    payload = result.as_dict()
    if args.json:
        print(_render_query_json(payload, max_chars=args.max_chars), end="")
        return 0

    lines = [
        "mode: lookup-project-context",
        f"status: {payload['status']}",
        f"workspace: {payload['workspace'] or '(none)'}",
        f"candidates: {', '.join(payload['candidates']) or '(none)'}",
        "writes: none",
    ]
    if payload["snapshot_path"]:
        lines.extend(
            (
                "",
                "## Snapshot",
                f"path: {payload['snapshot_path']}",
                payload["snapshot_excerpt"] or "",
            )
        )
    if payload["history"]:
        lines.extend(("", "## Relevant history"))
        for entry in payload["history"]:
            lines.extend(
                (
                    "",
                    f"path: {entry['history_path']}",
                    f"recorded_at: {entry['recorded_at'] or '(unknown)'}",
                    entry["excerpt"],
                )
            )
    if payload["issues"]:
        lines.extend(("", "## Read issues"))
        lines.extend(
            f"- {issue['path']}: {issue['detail']}" for issue in payload["issues"]
        )
    rendered, _truncated = truncate_text("\n".join(lines) + "\n", args.max_chars)
    print(rendered, end="")
    return 0


def ensure_verified_directory(path: Path) -> None:
    directory_fd = open_or_create_verified_directory(path)
    os.close(directory_fd)


def require_bootstrap_registry_creation_allowed(root: Path) -> None:
    registry_directory = root / "_registry"
    coordination_paths = [
        registry_directory / "placement-map.lock",
        registry_directory / "lock-migrations",
        registry_directory / "curation",
    ]
    if any(os.path.lexists(path) for path in coordination_paths):
        raise MnemosyneError("bootstrap cannot create registry after coordination state exists")


def execute_bootstrap(root: Path, *, registry_exists: bool) -> int:
    ensure_verified_directory(root / "_registry")
    ensure_verified_directory(pending_dir(root))
    ensure_verified_directory(decisions_dir(root))
    ensure_verified_directory(root / "inbox")

    reg_path = registry_path(root)
    if not registry_exists:
        require_bootstrap_registry_creation_allowed(root)
        publish_control_file_no_replace(
            reg_path,
            default_registry_text(root).encode("utf-8"),
            label="registry",
            mode=0o644,
        )
        registry_action = "created"
    else:
        read_registry_bytes_verified(root)
        registry_action = "exists"

    print(f"bootstrap {registry_action}: {reg_path}")
    print(f"pending: {pending_dir(root)}")
    print(f"decisions: {decisions_dir(root)}")
    print(f"inbox: {root / 'inbox'}")
    return 0


# Private compatibility owners retained only for D2 migration evidence.  D1b
# exposes none of them through the launcher or an Operation Control binding.
def _legacy_bootstrap(args: argparse.Namespace) -> int:
    root = resolve_under_root(args.root, Path(args.root).expanduser().resolve())
    registry_exists, _registry_bytes = inspect_registry_entry(root)
    if registry_exists:
        with legacy_writer_lease(root, "bootstrap") as checkpoint:
            checkpoint()
            return execute_bootstrap(root, registry_exists=True)
    with manual_recovery_guard(root) as guard:
        guard.checkpoint()
        require_no_active_lock_migration(root)
        require_bootstrap_registry_creation_allowed(root)
        return execute_bootstrap(root, registry_exists=False)


def derive_target(args: argparse.Namespace, source: Path, root: Path, registry: dict[str, Any]) -> tuple[Path, str, str]:
    if args.target:
        require_no_symlink_components(args.target, root, "target")
        target = resolve_under_root(args.target, root)
        category = "manual"
        reason = args.reason or "Manual target supplied by operator."
        if target.exists() and target.is_dir():
            target = target / source.name
        elif str(args.target).endswith(("/", os.sep)):
            target = target / source.name
        return target, category, reason

    category_data = category_for_source(source, root, registry)
    raw_target = Path(str(category_data["target"])) / source.name
    require_no_symlink_components(raw_target, root, "target")
    target = resolve_under_root(raw_target, root)
    reason = args.reason or f"Matched placement category: {category_data.get('id')}"
    return target, str(category_data.get("id", "unknown")), reason


def _legacy_propose_place(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with legacy_writer_lease(root, "propose-place") as checkpoint:
        registry = load_registry(registry_path(root))
        require_no_symlink_components(args.source, root, "source")
        source = resolve_under_root(args.source, root, must_exist=True)
        require_safe_tree(source, root, registry, "source")
        target, category, reason = derive_target(args, source, root, registry)
        require_safe_tree(target, root, registry, "target")
        if source == target:
            raise MnemosyneError(f"target equals source: {target}")
        if source.is_dir() and source in target.parents:
            raise MnemosyneError("target cannot be inside source directory")

        proposal_id = make_id("place", source, target)
        proposal = {
            "id": proposal_id,
            "status": "pending",
            "created_at": utc_now(),
            "actor": args.actor,
            "source": str(source),
            "target": str(target),
            "category": category,
            "reason": reason,
        }
        path = pending_dir(root) / f"{proposal_id}.yml"
        if os.path.lexists(path):
            raise MnemosyneError(f"proposal already exists: {path}")
        checkpoint()
        write_flat_yaml(path, proposal)
        try:
            published_info, published_bytes = read_verified_regular_file(
                path,
                label="pending proposal",
            )
            published = parse_flat_yaml_text(published_bytes.decode("utf-8"))
        except (MnemosyneError, UnicodeDecodeError) as exc:
            raise MnemosyneError("pending proposal readback mismatch") from exc
        if published_info.st_nlink != 1 or published != proposal:
            raise MnemosyneError("pending proposal readback mismatch")
        checkpoint()
        print(f"created proposal {proposal_id}")
    return 0


def _legacy_list_pending(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    proposals = [load_flat_yaml(path) for path in iter_yaml_files(pending_dir(root))]
    proposals = [proposal for proposal in proposals if proposal.get("status") == "pending"]

    if args.json:
        print(json.dumps(proposals, ensure_ascii=False, indent=2))
        return 0

    print("pending proposals")
    if not proposals:
        print("(none)")
        return 0
    for proposal in proposals:
        print(
            f"{proposal.get('id')} | {proposal.get('created_at')} | "
            f"{proposal.get('source')} -> {proposal.get('target')} | {proposal.get('reason')}"
        )
    return 0


def write_decision(root: Path, proposal: dict[str, Any], decision: str, actor: str) -> Path:
    decision_id = make_id(decision, Path(str(proposal["source"])), Path(str(proposal["target"])))
    record = {
        "id": decision_id,
        "proposal_id": proposal["id"],
        "decision": decision,
        "decided_at": utc_now(),
        "actor": actor,
        "source": proposal["source"],
        "target": proposal["target"],
        "category": proposal.get("category", ""),
        "reason": proposal.get("reason", ""),
        "proposal_created_at": proposal.get("created_at", ""),
    }
    path = decisions_dir(root) / f"{decision_id}.yml"
    write_flat_yaml(path, record)
    return path


def verify_decision_readback(
    path: Path,
    proposal: dict[str, Any],
    decision: str,
    actor: str,
) -> None:
    try:
        info, raw = read_verified_regular_file(path, label="decision")
        record = parse_flat_yaml_text(raw.decode("utf-8"))
    except (MnemosyneError, UnicodeDecodeError) as exc:
        raise MnemosyneError("decision readback mismatch") from exc
    expected_fields = {
        "proposal_id": proposal["id"],
        "decision": decision,
        "actor": actor,
        "source": proposal["source"],
        "target": proposal["target"],
        "category": proposal.get("category", ""),
        "reason": proposal.get("reason", ""),
        "proposal_created_at": proposal.get("created_at", ""),
    }
    if (
        info.st_nlink != 1
        or set(record) != set(expected_fields) | {"id", "decided_at"}
        or any(record.get(key) != value for key, value in expected_fields.items())
        or not str(record.get("id", "")).startswith(f"{decision}-")
        or not record.get("decided_at")
    ):
        raise MnemosyneError("decision readback mismatch")


def _legacy_approve(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with legacy_writer_lease(root, "approve") as checkpoint:
        registry = load_registry(registry_path(root))
        pending_fd, path, pending_info, proposal = open_pending_proposal(root, args.proposal_id)
        try:
            if proposal.get("status") != "pending":
                raise MnemosyneError(f"proposal is not pending: {args.proposal_id}")

            require_no_symlink_components(str(proposal["source"]), root, "source")
            require_no_symlink_components(str(proposal["target"]), root, "target")
            source = resolve_under_root(str(proposal["source"]), root, must_exist=True)
            target = resolve_under_root(str(proposal["target"]), root)
            try:
                expected_source_identity = source_identity(os.lstat(source))
            except OSError as exc:
                raise MnemosyneError(f"source is missing: {source}") from exc
            require_safe_tree(source, root, registry, "source")
            try:
                validated_source_identity = source_identity(os.lstat(source))
            except OSError as exc:
                raise MnemosyneError(f"source identity changed during validation: {source}") from exc
            if validated_source_identity != expected_source_identity:
                raise MnemosyneError(f"source identity changed during validation: {source}")
            expected_tree_identity = safe_tree_identity_manifest(source, "source")
            require_safe_tree(target, root, registry, "target")
            if target.exists():
                raise MnemosyneError(f"target already exists: {target}")

            legacy_approve_before_target_publish(source, target)
            checkpoint()
            require_safe_tree(source, root, registry, "source")
            if safe_tree_identity_manifest(source, "source") != expected_tree_identity:
                raise MnemosyneError(f"source tree identity changed before publish: {source}")
            rename_path_no_replace(
                source,
                target,
                collision_error=f"target already exists: {target}",
                expected_source_identity=expected_source_identity,
                recovery_guard=checkpoint.recovery_guard,
            )
            checkpoint()
            require_safe_tree(target, root, registry, "target")
            if safe_tree_identity_manifest(target, "target") != expected_tree_identity:
                raise MnemosyneError(f"source tree identity changed after publish: {target}")
            decision_path = write_decision(root, proposal, "approved", args.actor)
            verify_decision_readback(decision_path, proposal, "approved", args.actor)
            checkpoint()
            remove_pending_proposal_if_same(root, pending_fd, path, pending_info)
            checkpoint()
            print(f"approved {proposal['id']} -> {target}")
        finally:
            os.close(pending_fd)
    return 0


def _legacy_reject(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with legacy_writer_lease(root, "reject") as checkpoint:
        pending_fd, path, pending_info, proposal = open_pending_proposal(root, args.proposal_id)
        try:
            if proposal.get("status") != "pending":
                raise MnemosyneError(f"proposal is not pending: {args.proposal_id}")
            checkpoint()
            decision_path = write_decision(root, proposal, "rejected", args.actor)
            verify_decision_readback(decision_path, proposal, "rejected", args.actor)
            checkpoint()
            remove_pending_proposal_if_same(root, pending_fd, path, pending_info)
            checkpoint()
            print(f"rejected {proposal['id']}")
        finally:
            os.close(pending_fd)
    return 0


def _legacy_list_history(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    records = [load_flat_yaml(path) for path in iter_yaml_files(decisions_dir(root))]
    records.sort(key=lambda item: str(item.get("decided_at", "")), reverse=True)
    if args.limit:
        records = records[: args.limit]

    if args.json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
        return 0

    print("decision history")
    if not records:
        print("(none)")
        return 0
    for record in records:
        print(
            f"{record.get('decision')} | {record.get('decided_at')} | "
            f"{record.get('proposal_id')} | {record.get('source')} -> {record.get('target')}"
        )
    return 0


def path_depth(path: Path, base: Path) -> int:
    if path.resolve(strict=False) == base.resolve(strict=False):
        return 0
    return len(path.resolve(strict=False).relative_to(base.resolve(strict=False)).parts)


def iter_audit_files(scope: Path, root: Path, registry: dict[str, Any], max_depth: int) -> list[Path]:
    files: list[Path] = []
    scope = scope.resolve(strict=True)
    for current, dirs, filenames in os.walk(scope):
        current_path = Path(current)
        depth = path_depth(current_path, scope)
        kept_dirs = []
        for dirname in dirs:
            child = current_path / dirname
            if dirname in INTERNAL_SKIP_DIRS:
                continue
            if violates_never_touch(child, root, list(registry.get("never_touch", []))):
                continue
            if depth + 1 > max_depth:
                continue
            kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        if depth > max_depth:
            continue
        for filename in filenames:
            child = current_path / filename
            if violates_never_touch(child, root, list(registry.get("never_touch", []))):
                continue
            files.append(child)
    return files


def _legacy_audit(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    reg_path = registry_path(root)
    issues: list[str] = []
    orphan_candidates: list[str] = []

    try:
        registry = load_registry(reg_path)
    except MnemosyneError as exc:
        registry = {"never_touch": [], "categories": []}
        issues.append(str(exc))

    for required in [root / "_registry", pending_dir(root), decisions_dir(root), root / "inbox"]:
        if not required.exists():
            issues.append(f"missing scaffold: {required}")

    for proposal_path in iter_yaml_files(pending_dir(root)):
        proposal = load_flat_yaml(proposal_path)
        source = resolve_under_root(str(proposal.get("source", "")), root)
        target = resolve_under_root(str(proposal.get("target", "")), root)
        if proposal.get("status") != "pending":
            issues.append(f"non-pending file in pending queue: {proposal_path.name}")
        if not source.exists():
            issues.append(f"pending source missing: {proposal.get('id')}")
        if target.exists():
            issues.append(f"pending target already exists: {proposal.get('id')}")
        source_rule = violates_never_touch(source, root, list(registry.get("never_touch", [])))
        target_rule = violates_never_touch(target, root, list(registry.get("never_touch", [])))
        if source_rule or target_rule:
            issues.append(f"pending proposal touches never-touch: {proposal.get('id')}")

    scope = resolve_under_root(args.scope or root, root, must_exist=True)
    for file_path in iter_audit_files(scope, root, registry, args.max_depth):
        if not matches_any_category(file_path, root, registry):
            orphan_candidates.append(str(file_path))
        if len(orphan_candidates) >= args.limit:
            break

    print("mode: audit")
    print("writes: none")
    print(f"root: {root}")
    print(f"registry: {reg_path}")
    print(f"pending_count: {len(iter_yaml_files(pending_dir(root)))}")
    print(f"decision_count: {len(iter_yaml_files(decisions_dir(root)))}")
    print("issues:")
    if issues:
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("  - none")
    print("orphan_candidates:")
    if orphan_candidates:
        for candidate in orphan_candidates:
            print(f"  - {candidate}")
    else:
        print("  - none")
    return 0


def _legacy_preview_lock_migration(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        return _command_preview_lock_migration(args, root, recovery_guard)


def _command_preview_lock_migration(
    args: argparse.Namespace,
    root: Path,
    recovery_guard: ManualRecoveryGuard,
) -> int:
    recovery_guard.checkpoint()
    if not args.entrypoint_manifest:
        raise MnemosyneError("lock migration preview requires an installed entrypoint manifest")
    manifest_path = Path(args.entrypoint_manifest).expanduser()
    (
        _entrypoint_manifest,
        entrypoint_manifest_sha256,
        entrypoint_evidence,
        entrypoint_evidence_sha256,
        entrypoint_blockers,
    ) = verify_installed_entrypoint_manifest(manifest_path)
    registry = registry_path(root)
    registry_bytes = read_registry_bytes_verified(root)
    if registry_has_curation_section(registry_bytes):
        raise MnemosyneError("lock migration preview requires registry without curation section")
    require_lock_migration_ledger_absent(root)
    require_no_active_lock_migration(root)
    if os.path.lexists(placement_lock_path(root)):
        raise MnemosyneError("lock migration preview requires placement lock to be absent")

    migration_id = f"lockmig-{utc_now().replace('-', '').replace(':', '')}-{uuid.uuid4().hex[:12]}"
    leases, cleanup_effects = scan_legacy_leases(root, migration_id)
    blockers = [
        {
            "kind": "LEASE_NOT_QUIESCENT",
            "path": lease["path"],
            "status": lease["status"],
            "reason": lease["reason"],
        }
        for lease in leases
        if lease["status"] in {"alive", "ambiguous"}
    ] + entrypoint_blockers
    canonical_writer = entrypoint_evidence["canonical_writer"]
    migration_root = lock_migrations_dir(root)
    proposal_directory = migration_root / "proposals" / migration_id
    paths = {
        "active_marker": str(migration_root / "active"),
        "placement_lock": str(placement_lock_path(root)),
        "incomplete_run": str(migration_root / "runs" / f".incomplete-{migration_id}"),
        "final_run": str(migration_root / "runs" / migration_id),
        "completed_result": str(migration_root / "completed" / migration_id / "result.json"),
        "completed_marker": str(migration_root / "completed" / migration_id / "marker.json"),
    }
    proposal = {
        "schema_version": 1,
        "kind": "LOCK_MIGRATION",
        "placement_lock_protocol_version": PLACEMENT_LOCK_PROTOCOL_VERSION,
        "migration_id": migration_id,
        "created_at": utc_now(),
        "requested_by": args.requested_by,
        "approval_ready": not blockers,
        "blockers": blockers,
        "entrypoint": {
            "path": canonical_writer["path"],
            "compatibility_version": MNEMOSYNE_COMPATIBILITY_VERSION,
            "sha256": canonical_writer["sha256"],
        },
        "entrypoint_manifest": {
            "path": str(manifest_path),
            "sha256": entrypoint_manifest_sha256,
        },
        "entrypoint_evidence": entrypoint_evidence,
        "entrypoint_evidence_sha256": entrypoint_evidence_sha256,
        "registry_path": str(registry),
        "registry_sha256": sha256_bytes(registry_bytes),
        "pending_manifest": yaml_directory_manifest(pending_dir(root)),
        "history_manifest": yaml_directory_manifest(decisions_dir(root)),
        "leases": leases,
        "cleanup_effects": cleanup_effects,
        "paths": paths,
        "preconditions": {
            "curation_section_absent": True,
            "ledger_absent": True,
            "placement_lock_absent": True,
            "active_marker_absent": True,
        },
    }

    create_verified_directory_no_replace(
        proposal_directory,
        label="proposal",
        collision_error=f"lock migration proposal already exists: {proposal_directory}",
    )
    proposal_path = proposal_directory / "proposal.json"
    proposal_sha256 = publish_json_no_replace(proposal_path, proposal)
    report = {
        "mode": "preview-lock-migration",
        "registry_updates": [
            {
                "kind": "sealed-proposal",
                "migration_id": migration_id,
                "path": str(proposal_path),
                "sha256": proposal_sha256,
            }
        ],
        "content_placement_writes": [],
        "memory_updates": [],
        "not_modified": [
            str(registry),
            str(pending_dir(root)),
            str(decisions_dir(root)),
            "raw corpus",
            str(placement_lock_path(root)),
        ],
        "needs_review": [
            {
                "kind": "lock-migration-proposal",
                "migration_id": migration_id,
                "proposal_sha256": proposal_sha256,
                "approval_ready": not blockers,
                "blockers": blockers,
            }
        ],
    }
    render_operation_report(report, as_json=args.json)
    return 0


def lock_migration_plan_contract(
    proposal_path: Path,
    proposal: dict[str, Any],
    proposal_sha256: str,
    approved_by: str,
    executed_by: str,
) -> dict[str, Any]:
    created_at = proposal.get("created_at")
    if not isinstance(created_at, str) or not created_at:
        raise MnemosyneError("lock migration proposal timestamp is invalid")
    return {
        "schema_version": 1,
        "kind": "LOCK_MIGRATION_PLAN",
        "migration_id": proposal["migration_id"],
        "proposal_path": str(proposal_path),
        "proposal_sha256": proposal_sha256,
        "approved_by": approved_by,
        "executed_by": executed_by,
        "maintenance_window_confirmed": True,
        "created_at": created_at,
        "cleanup_effects": proposal["cleanup_effects"],
        "paths": proposal["paths"],
    }


def _legacy_apply_lock_migration(args: argparse.Namespace) -> int:
    is_resume = bool(getattr(args, "resume", False))
    if not is_resume and not args.maintenance_window_confirmed:
        raise MnemosyneError("lock migration requires explicit maintenance-window confirmation")
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        return _command_apply_lock_migration(
            args,
            root,
            recovery_guard,
            is_resume=is_resume,
        )


def _command_apply_lock_migration(
    args: argparse.Namespace,
    root: Path,
    recovery_guard: ManualRecoveryGuard,
    *,
    is_resume: bool,
) -> int:
    recovery_guard.checkpoint()
    migration_root = lock_migrations_dir(root)
    proposal_id = validate_lock_migration_id(str(args.proposal_id))
    proposal_path = migration_root / "proposals" / proposal_id / "proposal.json"
    try:
        proposal_info, proposal_bytes = read_verified_regular_file(
            proposal_path,
            label="lock migration proposal",
        )
        if proposal_info.st_nlink != 1:
            raise MnemosyneError("lock migration proposal link count is invalid")
        proposal = json.loads(proposal_bytes)
    except json.JSONDecodeError as exc:
        raise MnemosyneError(f"cannot load lock migration proposal: {proposal_path}") from exc
    actual_proposal_sha256 = sha256_bytes(proposal_bytes)
    if actual_proposal_sha256 != args.proposal_sha256:
        raise MnemosyneError("lock migration proposal hash mismatch")
    if proposal.get("kind") != "LOCK_MIGRATION" or proposal.get("migration_id") != proposal_id:
        raise MnemosyneError("lock migration proposal identity mismatch")
    if not proposal.get("approval_ready") or proposal.get("blockers"):
        raise MnemosyneError("lock migration proposal is not approval-ready")
    expected_actor = proposal.get("requested_by")
    if not isinstance(expected_actor, str) or not expected_actor:
        raise MnemosyneError("lock migration proposal actor is invalid")
    supplied_approved_by = getattr(args, "approved_by", None)
    supplied_executed_by = getattr(args, "executed_by", None)
    if (
        supplied_approved_by is not None
        and supplied_approved_by != expected_actor
    ) or (
        supplied_executed_by is not None
        and supplied_executed_by != expected_actor
    ):
        raise MnemosyneError("lock migration actors must match proposal requested_by")

    paths = proposal.get("paths", {})
    expected_paths = {
        "active_marker": migration_root / "active",
        "placement_lock": placement_lock_path(root),
        "incomplete_run": migration_root / "runs" / f".incomplete-{proposal_id}",
        "final_run": migration_root / "runs" / proposal_id,
        "completed_result": migration_root / "completed" / proposal_id / "result.json",
        "completed_marker": migration_root / "completed" / proposal_id / "marker.json",
    }
    if any(paths.get(name) != str(path) for name, path in expected_paths.items()):
        raise MnemosyneError("lock migration proposal path binding mismatch")
    if (
        is_resume
        and not os.path.lexists(expected_paths["active_marker"])
        and os.path.lexists(expected_paths["completed_marker"])
    ):
        verify_completed_lock_migration(root, proposal, actual_proposal_sha256, expected_paths)
        report = {
            "mode": "resume-lock-migration",
            "registry_updates": [],
            "content_placement_writes": [],
            "memory_updates": [],
            "not_modified": [
                str(registry_path(root)),
                str(pending_dir(root)),
                str(decisions_dir(root)),
                "raw corpus",
                str(expected_paths["placement_lock"]),
                str(expected_paths["final_run"]),
                str(expected_paths["completed_result"]),
                str(expected_paths["completed_marker"]),
            ],
            "needs_review": [],
        }
        render_operation_report(report, as_json=args.json)
        return 0
    require_lock_migration_ledger_absent(root)
    if sha256_bytes(read_registry_bytes_verified(root)) != proposal["registry_sha256"]:
        raise MnemosyneError("registry changed after lock migration preview")
    verify_proposal_entrypoint_evidence(proposal)
    incomplete_run = expected_paths["incomplete_run"]
    final_run = expected_paths["final_run"]
    if is_resume:
        active_present = os.path.lexists(expected_paths["active_marker"])
        if active_present:
            try:
                active_lexical = os.lstat(expected_paths["active_marker"])
            except OSError as exc:
                raise MnemosyneError("cannot inspect lock migration active marker") from exc
            if not stat.S_ISREG(active_lexical.st_mode):
                raise MnemosyneError("lock migration active marker is not a regular file")
        incomplete_present = verified_directory_present(
            incomplete_run,
            label="lock migration run",
        )
        final_present = verified_directory_present(
            final_run,
            label="lock migration run",
        )
        if incomplete_present == final_present:
            raise MnemosyneError("lock migration resume requires exactly one run directory")
        if not active_present and final_present:
            raise MnemosyneError("lock migration final run cannot precede active marker")
        run_directory = final_run if final_present else incomplete_run
        plan_path = run_directory / "plan.json"
        if not os.path.lexists(plan_path):
            if (
                active_present
                or final_present
                or os.path.lexists(expected_paths["placement_lock"])
                or os.path.lexists(expected_paths["completed_marker"])
                or os.path.lexists(expected_paths["completed_result"])
            ):
                raise MnemosyneError("missing lock migration plan has later-stage artifacts")
            recovery_plan = lock_migration_plan_contract(
                proposal_path,
                proposal,
                actual_proposal_sha256,
                expected_actor,
                expected_actor,
            )
            publish_json_no_replace(plan_path, recovery_plan)
            checked_lock_migration_checkpoint("plan-published", root, args.proposal_id)
        try:
            plan_info, plan_bytes = read_verified_regular_file(
                plan_path,
                label="lock migration resume plan",
            )
            if plan_info.st_nlink != 1:
                raise MnemosyneError("lock migration resume plan link count is invalid")
            plan = json.loads(plan_bytes)
        except json.JSONDecodeError as exc:
            raise MnemosyneError("cannot read lock migration resume plan") from exc
        plan_sha256 = sha256_bytes(plan_bytes)
        expected_plan = lock_migration_plan_contract(
            proposal_path,
            proposal,
            actual_proposal_sha256,
            expected_actor,
            expected_actor,
        )
        if plan != expected_plan:
            raise MnemosyneError("stored lock migration plan does not match proposal")
        approved_by = str(plan["approved_by"])
        executed_by = str(plan["executed_by"])
        if active_present:
            try:
                _active_info, active_bytes = read_verified_regular_file(
                    expected_paths["active_marker"],
                    label="active lock migration marker",
                )
                active_marker = json.loads(active_bytes)
            except json.JSONDecodeError as exc:
                raise MnemosyneError("cannot read lock migration active marker") from exc
            active_sha256 = sha256_bytes(active_bytes)
            expected_active_marker = {
                "schema_version": 1,
                "kind": "LOCK_MIGRATION_ACTIVE",
                "migration_id": args.proposal_id,
                "proposal_sha256": actual_proposal_sha256,
                "plan_sha256": plan_sha256,
                "started_at": plan.get("created_at"),
            }
            if (
                active_marker != expected_active_marker
                or active_bytes != canonical_json_bytes(active_marker)
            ):
                raise MnemosyneError("active lock migration marker does not match stored plan")
        else:
            if os.path.lexists(expected_paths["placement_lock"]) or os.path.lexists(
                expected_paths["completed_marker"]
            ):
                raise MnemosyneError("pre-marker lock migration resume found later-stage artifacts")
            if sha256_bytes(read_registry_bytes_verified(root)) != proposal["registry_sha256"]:
                raise MnemosyneError("registry changed before lock migration marker resume")
            if yaml_directory_manifest(pending_dir(root)) != proposal["pending_manifest"]:
                raise MnemosyneError("pending queue changed before lock migration marker resume")
            if yaml_directory_manifest(decisions_dir(root)) != proposal["history_manifest"]:
                raise MnemosyneError("decision history changed before lock migration marker resume")
            active_marker = {
                "schema_version": 1,
                "kind": "LOCK_MIGRATION_ACTIVE",
                "migration_id": args.proposal_id,
                "proposal_sha256": actual_proposal_sha256,
                "plan_sha256": plan_sha256,
                "started_at": plan["created_at"],
            }
            require_no_manual_recovery_blockers(root)
            active_sha256 = publish_json_no_replace(expected_paths["active_marker"], active_marker)
            checked_lock_migration_checkpoint("active-marker-published", root, args.proposal_id)
    else:
        if os.path.lexists(expected_paths["active_marker"]):
            raise MnemosyneError("another lock migration is active")
        if os.path.lexists(expected_paths["placement_lock"]):
            raise MnemosyneError("placement lock already exists")
        if os.path.lexists(incomplete_run) or os.path.lexists(final_run):
            raise MnemosyneError("lock migration run path already exists; use resume")
        approved_by = expected_actor
        executed_by = expected_actor
        require_no_manual_recovery_blockers(root)
        plan = lock_migration_plan_contract(
            proposal_path,
            proposal,
            actual_proposal_sha256,
            approved_by,
            executed_by,
        )
        create_verified_directory_no_replace(
            incomplete_run,
            label="run",
            collision_error="lock migration run path already exists; use resume",
        )
        run_directory = incomplete_run
        plan_sha256 = publish_json_no_replace(incomplete_run / "plan.json", plan)
        checked_lock_migration_checkpoint("plan-published", root, args.proposal_id)
        active_marker = {
            "schema_version": 1,
            "kind": "LOCK_MIGRATION_ACTIVE",
            "migration_id": args.proposal_id,
            "proposal_sha256": actual_proposal_sha256,
            "plan_sha256": plan_sha256,
            "started_at": plan["created_at"],
        }
        require_no_manual_recovery_blockers(root)
        active_sha256 = publish_json_no_replace(expected_paths["active_marker"], active_marker)
        checked_lock_migration_checkpoint("active-marker-published", root, args.proposal_id)

    require_no_manual_recovery_blockers(root)
    registry = registry_path(root)
    registry_bytes = read_registry_bytes_verified(root)
    if sha256_bytes(registry_bytes) != proposal["registry_sha256"]:
        raise MnemosyneError("registry changed after lock migration preview")
    if yaml_directory_manifest(pending_dir(root)) != proposal["pending_manifest"]:
        raise MnemosyneError("pending queue changed after lock migration preview")
    if yaml_directory_manifest(decisions_dir(root)) != proposal["history_manifest"]:
        raise MnemosyneError("decision history changed after lock migration preview")
    verify_proposal_entrypoint_evidence(proposal)
    require_lock_migration_ledger_absent(root)

    require_no_manual_recovery_blockers(root)
    quarantined = apply_approved_stale_lease_cleanup(root, proposal)
    checked_lock_migration_checkpoint("stale-leases-quarantined", root, args.proposal_id)
    verify_quarantined_leases(proposal, quarantined)
    verify_proposal_entrypoint_evidence(proposal)

    lock_payload = {
        "schema_version": 1,
        "kind": "PLACEMENT_COORDINATION_LOCK",
        "migration_id": args.proposal_id,
        "proposal_sha256": actual_proposal_sha256,
        "placement_lock_protocol_version": proposal["placement_lock_protocol_version"],
        "compatibility_version": proposal["entrypoint"]["compatibility_version"],
        "entrypoint_manifest_sha256": proposal["entrypoint_manifest"]["sha256"],
        "entrypoint_evidence_sha256": proposal["entrypoint_evidence_sha256"],
    }
    require_lock_migration_ledger_absent(root)
    expected_lock_sha256 = sha256_bytes(canonical_json_bytes(lock_payload))
    require_no_manual_recovery_blockers(root)
    if os.path.lexists(expected_paths["placement_lock"]):
        lock_sha256 = expected_lock_sha256
    else:
        lock_sha256 = publish_placement_lock_no_replace(root, lock_payload)
    require_no_manual_recovery_blockers(root)
    if lock_sha256 != expected_lock_sha256:
        raise MnemosyneError("placement lock canonical hash mismatch")
    validate_placement_lock(expected_paths["placement_lock"], lock_sha256)
    lock_fd = open_placement_lock_verified(root, lock_sha256)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        require_no_manual_recovery_blockers(root)
        checked_lock_migration_checkpoint("placement-lock-published", root, args.proposal_id)
        lock_info = validate_open_placement_lock(
            lock_fd,
            expected_paths["placement_lock"],
            lock_sha256,
        )
        completed_at = active_marker.get("started_at")
        if not isinstance(completed_at, str) or not completed_at:
            raise MnemosyneError("active lock migration marker timestamp is invalid")
        result_contract = {
            "schema_version": 1,
            "kind": "LOCK_MIGRATION_RESULT",
            "status": "COMPLETE",
            "migration_id": args.proposal_id,
            "proposal_sha256": actual_proposal_sha256,
            "plan_sha256": plan_sha256,
            "active_marker_sha256": active_sha256,
            "approved_by": approved_by,
            "executed_by": executed_by,
            "placement_lock_protocol_version": proposal[
                "placement_lock_protocol_version"
            ],
            "entrypoint": proposal["entrypoint"],
            "entrypoint_manifest": proposal["entrypoint_manifest"],
            "entrypoint_evidence_sha256": proposal["entrypoint_evidence_sha256"],
            "registry_sha256": proposal["registry_sha256"],
            "pending_manifest": proposal["pending_manifest"],
            "history_manifest": proposal["history_manifest"],
            "placement_lock": {
                "path": str(expected_paths["placement_lock"]),
                "sha256": lock_sha256,
                "mode": "0600",
                "uid": lock_info.st_uid,
                "nlink": lock_info.st_nlink,
            },
            "quarantined_leases": quarantined,
            "paths": paths,
            "completed_at": completed_at,
        }
        incomplete_result = run_directory / "result.json"
        require_no_manual_recovery_blockers(root)
        if os.path.lexists(incomplete_result):
            try:
                result_info, result_bytes = read_verified_regular_file(
                    incomplete_result,
                    label="existing lock migration result",
                )
                if result_info.st_nlink != 1:
                    raise MnemosyneError("existing lock migration result link count is invalid")
                result = json.loads(result_bytes)
            except json.JSONDecodeError as exc:
                raise MnemosyneError("cannot read existing lock migration result") from exc
            if result_bytes != canonical_json_bytes(result):
                raise MnemosyneError("existing lock migration result is not canonical")
            if result != result_contract:
                raise MnemosyneError("existing lock migration result binding mismatch")
            result_sha256 = sha256_bytes(result_bytes)
        else:
            result = result_contract
            result_sha256 = publish_json_no_replace(incomplete_result, result)
        checked_lock_migration_checkpoint("result-published", root, args.proposal_id)
        if run_directory == incomplete_run:
            if os.path.lexists(final_run):
                raise MnemosyneError(f"refusing to overwrite lock migration run: {final_run}")
            lock_migration_before_final_run_publish(incomplete_run, final_run)
            require_no_manual_recovery_blockers(root)
            rename_directory_no_replace(
                incomplete_run,
                final_run,
                recovery_guard=recovery_guard,
            )
        final_result_info, final_result_bytes = read_verified_regular_file(
            final_run / "result.json",
            label="final lock migration result",
        )
        if final_result_info.st_nlink != 1 or sha256_bytes(final_result_bytes) != result_sha256:
            raise MnemosyneError("final lock migration run readback mismatch")
        checked_lock_migration_checkpoint("final-run-published", root, args.proposal_id)
        if os.path.lexists(expected_paths["completed_result"]):
            completed_result_info, completed_result_bytes = read_verified_regular_file(
                expected_paths["completed_result"],
                label="existing completed result",
            )
            if completed_result_info.st_nlink != 1:
                raise MnemosyneError("existing completed result link count is invalid")
            if completed_result_bytes != canonical_json_bytes(result):
                raise MnemosyneError("existing completed result does not match final run")
            completed_result_sha256 = sha256_bytes(completed_result_bytes)
        else:
            completed_result_sha256 = publish_json_no_replace(expected_paths["completed_result"], result)
        if completed_result_sha256 != result_sha256:
            raise MnemosyneError("completed result hash mismatch")
        checked_lock_migration_checkpoint("completed-result-published", root, args.proposal_id)
        verify_quarantined_leases(proposal, quarantined)
        require_lock_migration_ledger_absent(root)
        completed_marker = expected_paths["completed_marker"]
        lock_migration_before_completed_marker_publish(
            expected_paths["active_marker"],
            completed_marker,
        )
        require_no_manual_recovery_blockers(root)
        verify_proposal_entrypoint_evidence(proposal)
        require_lock_migration_ledger_absent(root)
        require_no_manual_recovery_blockers(root)
        active_identity = ensure_completed_marker_link(
            expected_paths["active_marker"],
            completed_marker,
            active_sha256,
        )
        checked_lock_migration_checkpoint("completed-marker-linked", root, args.proposal_id)
        verify_quarantined_leases(proposal, quarantined)
        verify_proposal_entrypoint_evidence(proposal)
        require_lock_migration_ledger_absent(root)
        require_no_manual_recovery_blockers(root)
        unlink_active_marker_if_same(
            expected_paths["active_marker"],
            completed_marker,
            active_identity,
            active_sha256,
        )
        checked_lock_migration_checkpoint("completion-marker-published", root, args.proposal_id)
        verify_completed_lock_migration(
            root,
            proposal,
            actual_proposal_sha256,
            expected_paths,
        )
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)

    require_no_manual_recovery_blockers(root)
    report = {
        "mode": "resume-lock-migration" if is_resume else "apply-lock-migration",
        "registry_updates": [
            {"kind": "placement-lock", "path": str(expected_paths["placement_lock"]), "sha256": lock_sha256},
            {"kind": "sealed-run", "path": str(expected_paths["final_run"])},
            {
                "kind": "completed-result",
                "path": str(expected_paths["completed_result"]),
                "sha256": result_sha256,
            },
            {"kind": "completed-marker", "path": str(expected_paths["completed_marker"])},
        ],
        "content_placement_writes": [],
        "memory_updates": [],
        "not_modified": [str(registry), str(pending_dir(root)), str(decisions_dir(root)), "raw corpus"],
        "needs_review": [],
    }
    render_operation_report(report, as_json=args.json)
    return 0


def resolve_completed_lock_migration_result(
    root: Path,
    *,
    require_current_registry_state: bool = True,
) -> Path:
    """Return the fully verified M0 completion result that authorizes M1."""
    require_no_manual_recovery_blockers(root)
    require_no_active_lock_migration(root)
    lock_fd = open_placement_lock_verified(root, None)
    try:
        acquire_shared_flock_nonblocking(lock_fd)
        lock_bytes = read_open_file_bytes(lock_fd)
        try:
            lock_payload = json.loads(lock_bytes)
        except json.JSONDecodeError as exc:
            raise MnemosyneError("completed placement lock payload is invalid") from exc
        if lock_bytes != canonical_json_bytes(lock_payload):
            raise MnemosyneError("completed placement lock payload is not canonical")
        migration_id = validate_lock_migration_id(
            str(lock_payload.get("migration_id", ""))
        )
        proposal_sha256 = str(lock_payload.get("proposal_sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", proposal_sha256):
            raise MnemosyneError("completed placement lock proposal hash is invalid")
        migration_root = lock_migrations_dir(root)
        proposal_path = (
            migration_root / "proposals" / migration_id / "proposal.json"
        )
        proposal_info, proposal_bytes = read_verified_regular_file(
            proposal_path,
            label="completed lock migration proposal",
        )
        if proposal_info.st_nlink != 1:
            raise MnemosyneError(
                "completed lock migration proposal link count is invalid"
            )
        try:
            proposal = json.loads(proposal_bytes)
        except json.JSONDecodeError as exc:
            raise MnemosyneError(
                "completed lock migration proposal is invalid"
            ) from exc
        if (
            proposal_bytes != canonical_json_bytes(proposal)
            or sha256_bytes(proposal_bytes) != proposal_sha256
            or proposal.get("migration_id") != migration_id
        ):
            raise MnemosyneError(
                "completed lock migration proposal binding mismatch"
            )
        paths = {
            "active_marker": migration_root / "active",
            "placement_lock": placement_lock_path(root),
            "incomplete_run": migration_root
            / "runs"
            / f".incomplete-{migration_id}",
            "final_run": migration_root / "runs" / migration_id,
            "completed_result": migration_root
            / "completed"
            / migration_id
            / "result.json",
            "completed_marker": migration_root
            / "completed"
            / migration_id
            / "marker.json",
        }
        if any(
            proposal.get("paths", {}).get(name) != str(path)
            for name, path in paths.items()
        ):
            raise MnemosyneError(
                "completed lock migration path binding mismatch"
            )
        verify_completed_lock_migration(
            root,
            proposal,
            proposal_sha256,
            paths,
            require_current_registry_state=require_current_registry_state,
            require_current_queue_state=False,
        )
        return paths["completed_result"]
    finally:
        os.close(lock_fd)


def _run_control_bootstrap_call(
    recovery_guard: ManualRecoveryGuard,
    callback: Any,
) -> dict[str, Any]:
    try:
        result = callback()
    except _control_core.ManualRecoveryRequired as exc:
        marker_path, marker_sha256 = persist_manual_recovery_blocker(
            recovery_guard,
            exc,
            kind="CONTROL_BOOTSTRAP_RENAME_MANUAL_RECOVERY",
        )
        raise MnemosyneError(
            f"{exc}; blocker: {marker_path}; blocker_sha256: {marker_sha256}"
        ) from exc
    except _control_core.ControlBootstrapError as exc:
        raise MnemosyneError(str(exc)) from exc
    recovery_guard.checkpoint()
    if not isinstance(result, dict):
        raise MnemosyneError("control bootstrap returned an invalid result")
    return result


def _control_bootstrap_preview_report(
    root: Path,
    preview: dict[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    preview_hash = _control_core.bootstrap_preview_sha256(preview)
    return operation_report(
        mode=mode,
        not_modified=[
            str(registry_path(root)),
            str(placement_lock_path(root)),
            str(root / "_registry" / "curation"),
            "raw corpus",
        ],
        needs_review=[
            {
                "kind": "control-bootstrap-preview",
                "preview_id": preview["preview_id"],
                "preview_sha256": preview_hash,
                "approval_ready": preview["approval_ready"],
                "paths": preview["paths"],
                "control_schema": preview["control_schema"],
            }
        ],
    )


def _control_bootstrap_result_report(
    root: Path,
    result: dict[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    paths = result.get("paths")
    if not isinstance(paths, dict):
        raise MnemosyneError("control bootstrap result paths are invalid")
    return operation_report(
        mode=mode,
        registry_updates=[
            {
                "kind": "curation-control-root",
                "bootstrap_id": result.get("bootstrap_id"),
                "state": result.get("state"),
                "paths": paths,
                "schema_sha256": result.get("schema_sha256"),
                "logical_readback_sha256": result.get(
                    "logical_readback_sha256"
                ),
            }
        ],
        not_modified=[
            str(registry_path(root)),
            str(pending_dir(root)),
            str(decisions_dir(root)),
            "raw corpus",
        ],
    )


def command_preview_bootstrap_state(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        completed_result = resolve_completed_lock_migration_result(root)
        recovery_guard.checkpoint()
        preview = _run_control_bootstrap_call(
            recovery_guard,
            lambda: _control_core.preview_bootstrap_state(
                root,
                requested_by=args.requested_by,
                completed_result_path=completed_result,
            ),
        )
        report = _control_bootstrap_preview_report(
            root,
            preview,
            mode="preview-bootstrap-state",
        )
        render_operation_report(report, as_json=args.json)
    return 0


def command_bootstrap_state(args: argparse.Namespace) -> int:
    if not args.apply:
        return command_preview_bootstrap_state(args)
    missing = [
        name
        for name in ("preview_id", "preview_hash", "approved_by")
        if not getattr(args, name, None)
    ]
    if missing:
        raise MnemosyneError(
            "bootstrap-state --apply requires --%s"
            % ", --".join(name.replace("_", "-") for name in missing)
        )
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        completed_result = resolve_completed_lock_migration_result(root)
        recovery_guard.checkpoint()
        result = _run_control_bootstrap_call(
            recovery_guard,
            lambda: _control_core.apply_bootstrap_state(
                root,
                requested_by=args.requested_by,
                approved_by=args.approved_by,
                preview_id=args.preview_id,
                preview_sha256=args.preview_hash,
                completed_result_path=completed_result,
            ),
        )
        report = _control_bootstrap_result_report(
            root,
            result,
            mode="bootstrap-state",
        )
        render_operation_report(report, as_json=args.json)
    return 0


def command_resume_bootstrap_state(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        completed_result = resolve_completed_lock_migration_result(
            root,
            require_current_registry_state=False,
        )
        recovery_guard.checkpoint()
        result = _run_control_bootstrap_call(
            recovery_guard,
            lambda: _control_core.resume_bootstrap_state(
                root,
                bootstrap_id=args.bootstrap_id,
                resumed_by=args.resumed_by,
                completed_result_path=completed_result,
            ),
        )
        report = _control_bootstrap_result_report(
            root,
            result,
            mode="resume-bootstrap-state",
        )
        render_operation_report(report, as_json=args.json)
    return 0


def _run_policy_state_call(
    recovery_guard: ManualRecoveryGuard,
    callback: Any,
) -> dict[str, Any]:
    try:
        result = callback()
    except _policy_state_core.PolicyBootstrapRecoveryRequired as exc:
        cause = exc.cause
        if isinstance(cause, ManualRecoveryRequired):
            marker_path, marker_sha256 = persist_manual_recovery_blocker(
                recovery_guard,
                cause,
                kind="POLICY_BOOTSTRAP_RENAME_MANUAL_RECOVERY",
            )
            raise MnemosyneError(
                f"{exc}; phase: {exc.phase}; run_id: {exc.run_id}; "
                f"blocker: {marker_path}; blocker_sha256: {marker_sha256}"
            ) from exc
        raise MnemosyneError(
            f"{exc}; phase: {exc.phase}; run_id: {exc.run_id}"
        ) from exc
    except _policy_state_core.PolicyBootstrapPublicationIncomplete as exc:
        raise MnemosyneError(
            f"{exc}; phase: {exc.phase}; proposal_id: {exc.proposal_id}; "
            f"approval_id: {exc.approval_id}"
        ) from exc
    except ManualRecoveryRequired as exc:
        marker_path, marker_sha256 = persist_manual_recovery_blocker(
            recovery_guard,
            exc,
            kind="POLICY_BOOTSTRAP_RENAME_MANUAL_RECOVERY",
        )
        raise MnemosyneError(
            f"{exc}; blocker: {marker_path}; blocker_sha256: {marker_sha256}"
        ) from exc
    except _policy_state_core.PolicyStateError as exc:
        raise MnemosyneError(str(exc)) from exc
    recovery_guard.checkpoint()
    if not isinstance(result, dict):
        raise MnemosyneError("policy state service returned an invalid result")
    return result


def _policy_cli_process_instance_id(
    root: Path,
    *,
    bootstrap_id: str,
    approval_id: str,
    approval_sha256: str,
    executed_by: str,
) -> str:
    binding = canonical_json_bytes(
        {
            "kind": "POLICY_BOOTSTRAP_CLI_PROCESS_BINDING",
            "raw_root": str(root),
            "bootstrap_id": bootstrap_id,
            "approval_id": approval_id,
            "approval_sha256": approval_sha256,
            "executed_by": executed_by,
        }
    )
    return "policy-cli-" + sha256_bytes(binding)[:24]


def _policy_proposal_report(
    root: Path,
    preview: dict[str, Any],
    proposal: dict[str, Any],
) -> dict[str, Any]:
    return operation_report(
        mode="preview-policy-bootstrap",
        registry_updates=[
            {
                "kind": "initial-policy-proposal",
                "proposal_id": proposal.get("proposal_id"),
                "proposal_sha256": proposal.get("proposal_sha256"),
                "preview_sha256": proposal.get("preview_sha256"),
                "run_id": proposal.get("run_id"),
                "state": proposal.get("state"),
                "paths": proposal.get("paths"),
            }
        ],
        not_modified=[
            str(registry_path(root)),
            "raw corpus",
            "movement writer",
        ],
        needs_review=[
            {
                "kind": "initial-policy-bootstrap",
                "proposal_id": proposal.get("proposal_id"),
                "proposal_sha256": proposal.get("proposal_sha256"),
                "expected_post_raw_sha256": preview.get("postimage", {}).get(
                    "raw_sha256"
                ),
                "writer_control": preview.get("writer_control"),
                "approval_ready": preview.get("approval_ready"),
            }
        ],
    )


def command_preview_policy_bootstrap(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        preview = _run_policy_state_call(
            recovery_guard,
            lambda: _policy_state_core.preview_policy_bootstrap(
                root,
                bootstrap_id=args.bootstrap_id,
                requested_by=args.requested_by,
            ),
        )
        proposal = _run_policy_state_call(
            recovery_guard,
            lambda: _policy_state_core.publish_policy_bootstrap_proposal(
                root,
                bootstrap_id=args.bootstrap_id,
                preview=preview,
            ),
        )
        render_operation_report(
            _policy_proposal_report(root, preview, proposal),
            as_json=args.json,
        )
    return 0


def command_approve_policy_bootstrap(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        approval = _run_policy_state_call(
            recovery_guard,
            lambda: _policy_state_core.approve_policy_bootstrap(
                root,
                bootstrap_id=args.bootstrap_id,
                proposal_id=args.proposal_id,
                proposal_sha256=args.proposal_sha256,
                approved_by=args.approved_by,
            ),
        )
        approval_sha256 = approval.get("export_sha256") or approval.get(
            "approval_sha256"
        )
        report = operation_report(
            mode="approve-policy-bootstrap",
            registry_updates=[
                {
                    "kind": "initial-policy-approval",
                    "proposal_id": approval.get("proposal_id"),
                    "approval_id": approval.get("approval_id"),
                    "approval_sha256": approval_sha256,
                    "run_id": approval.get("run_id")
                    or approval.get("payload", {}).get("run_id"),
                    "state": approval.get("state"),
                    "export_path": approval.get("export_path"),
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
            ],
            needs_review=[
                {
                    "kind": "initial-policy-apply-binding",
                    "approval_id": approval.get("approval_id"),
                    "approval_sha256": approval_sha256,
                }
            ],
        )
        render_operation_report(report, as_json=args.json)
    return 0


def command_apply_policy_bootstrap(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    process_instance_id = _policy_cli_process_instance_id(
        root,
        bootstrap_id=args.bootstrap_id,
        approval_id=args.approval_id,
        approval_sha256=args.approval_sha256,
        executed_by=args.executed_by,
    )
    with manual_recovery_guard(root) as recovery_guard:
        result = _run_policy_state_call(
            recovery_guard,
            lambda: _policy_state_core.apply_policy_bootstrap(
                root,
                bootstrap_id=args.bootstrap_id,
                approval_id=args.approval_id,
                approval_sha256=args.approval_sha256,
                executed_by=args.executed_by,
                process_instance_id=process_instance_id,
            ),
        )
        report = operation_report(
            mode="apply-policy-bootstrap",
            registry_updates=[
                {
                    "kind": "initial-approved-policy",
                    "status": result.get("status"),
                    "generation": result.get("generation"),
                    "guard_epoch": result.get("guard_epoch"),
                    "proposal_id": result.get("proposal_id"),
                    "approval_id": result.get("approval_id"),
                    "run_id": result.get("run_id"),
                    "raw_hash": result.get("raw_hash"),
                    "normalized_full_hash": result.get(
                        "normalized_full_hash"
                    ),
                    "writer_control_hash": result.get("writer_control_hash"),
                    "foundation_hash": result.get("foundation_hash"),
                    "paths": result.get("paths"),
                }
            ],
            not_modified=["raw corpus", "movement writer"],
        )
        render_operation_report(report, as_json=args.json)
    return 0


MAX_POLICY_POSTIMAGE_BYTES = 4 * 1024 * 1024


def _run_policy_authority_call(
    recovery_guard: ManualRecoveryGuard,
    callback: Any,
) -> dict[str, Any]:
    try:
        result = callback()
    except _policy_authority_core.PolicyChangeRecoveryRequired as exc:
        cause = exc.cause
        if isinstance(cause, ManualRecoveryRequired):
            marker_path, marker_sha256 = persist_manual_recovery_blocker(
                recovery_guard,
                cause,
                kind="POLICY_CHANGE_RENAME_MANUAL_RECOVERY",
            )
            raise MnemosyneError(
                f"{exc}; mode: {exc.mode}; phase: {exc.phase}; "
                f"run_id: {exc.run_id}; blocker: {marker_path}; "
                f"blocker_sha256: {marker_sha256}"
            ) from exc
        raise MnemosyneError(
            f"{exc}; mode: {exc.mode}; phase: {exc.phase}; "
            f"run_id: {exc.run_id}"
        ) from exc
    except ManualRecoveryRequired as exc:
        marker_path, marker_sha256 = persist_manual_recovery_blocker(
            recovery_guard,
            exc,
            kind="POLICY_CHANGE_RENAME_MANUAL_RECOVERY",
        )
        raise MnemosyneError(
            f"{exc}; blocker: {marker_path}; blocker_sha256: {marker_sha256}"
        ) from exc
    except _policy_authority_core.PolicyAuthorityError as exc:
        raise MnemosyneError(str(exc)) from exc
    recovery_guard.checkpoint()
    if not isinstance(result, dict):
        raise MnemosyneError("policy authority service returned an invalid result")
    return result


def _policy_change_cli_process_instance_id(
    root: Path,
    *,
    approval_id: str,
    approval_sha256: str,
    executed_by: str,
    required_sealed_mode: str,
) -> str:
    binding = canonical_json_bytes(
        {
            "kind": "POLICY_CHANGE_CLI_PROCESS_BINDING",
            "raw_root": str(root),
            "approval_id": approval_id,
            "approval_sha256": approval_sha256,
            "executed_by": executed_by,
            "required_sealed_mode": required_sealed_mode,
        }
    )
    return "policy-change-cli-" + sha256_bytes(binding)[:24]


def _read_policy_postimage_file(value: str) -> bytes:
    path = Path(value).expanduser()
    if (
        not path.is_absolute()
        or any(component in (".", "..") for component in path.parts)
        or not path.name
    ):
        raise MnemosyneError("policy postimage path must be canonical and absolute")
    _info, raw = read_verified_regular_file(
        path,
        label="policy postimage input",
        expected_mode=None,
    )
    if len(raw) > MAX_POLICY_POSTIMAGE_BYTES:
        raise MnemosyneError("policy postimage input exceeds the size limit")
    return raw


def _policy_guard_operation_report(
    root: Path,
    result: dict[str, Any],
    *,
    mode: str,
    episode_open: bool,
) -> dict[str, Any]:
    needs_review = []
    if episode_open:
        needs_review.append(
            {
                "kind": "policy-drift-episode",
                "episode_id": result.get("episode_id"),
                "event_id": result.get("event_id"),
                "guard_epoch": result.get("guard_epoch"),
                "state": result.get("state"),
                "normal_authority_blocked": True,
            }
        )
    return operation_report(
        mode=mode,
        registry_updates=[
            {
                "kind": result.get("kind"),
                "episode_id": result.get("episode_id"),
                "event_id": result.get("event_id"),
                "guard_epoch": result.get("guard_epoch"),
                "head_generation": result.get("head_generation"),
                "head_full_hash": result.get("head_full_hash"),
                "observation_path": result.get("observation_path"),
                "observation_sha256": result.get("observation_sha256"),
                "result_path": result.get("result_path"),
                "result_sha256": result.get("result_sha256"),
                "state": result.get("state"),
            }
        ],
        not_modified=[
            str(registry_path(root)),
            "raw corpus",
            "movement writer",
            "navigation/OKF/Graphify/memory",
        ],
        needs_review=needs_review,
    )


def command_record_policy_drift(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        result = _run_policy_authority_call(
            recovery_guard,
            lambda: _policy_authority_core.observe_policy_drift(
                root,
                observed_by=args.observed_by,
            ),
        )
        render_operation_report(
            _policy_guard_operation_report(
                root,
                result,
                mode="record-policy-drift",
                episode_open=True,
            ),
            as_json=args.json,
        )
    return 0


def command_resume_policy_guard_event(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        result = _run_policy_authority_call(
            recovery_guard,
            lambda: _policy_authority_core.resume_policy_guard_event(
                root,
                event_id=args.event_id,
                resumed_by=args.resumed_by,
            ),
        )
        render_operation_report(
            _policy_guard_operation_report(
                root,
                result,
                mode="resume-policy-guard-event",
                episode_open=True,
            ),
            as_json=args.json,
        )
    return 0


def command_clear_policy_drift(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        result = _run_policy_authority_call(
            recovery_guard,
            lambda: _policy_authority_core.clear_policy_drift_equality(
                root,
                episode_id=args.episode_id,
                expected_head_generation=args.expected_head_generation,
                expected_head_full_hash=args.expected_head_full_hash,
                expected_guard_epoch=args.expected_guard_epoch,
                cleared_by=args.cleared_by,
            ),
        )
        render_operation_report(
            _policy_guard_operation_report(
                root,
                result,
                mode="clear-policy-drift",
                episode_open=False,
            ),
            as_json=args.json,
        )
    return 0


def _policy_change_proposal_report(
    root: Path,
    preview: dict[str, Any],
    proposal: dict[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    return operation_report(
        mode=mode,
        registry_updates=[
            {
                "kind": "policy-change-proposal",
                "sealed_mode": proposal.get("mode"),
                "proposal_id": proposal.get("proposal_id"),
                "proposal_sha256": proposal.get("proposal_sha256"),
                "proposal_path": proposal.get("proposal_path"),
                "run_id": proposal.get("run_id"),
                "approval_id": proposal.get("approval_id"),
                "state": proposal.get("state"),
            }
        ],
        not_modified=[
            str(registry_path(root)),
            "raw corpus",
            "movement writer",
            "navigation/OKF/Graphify/memory",
        ],
        needs_review=[
            {
                "kind": "policy-change-approval",
                "sealed_mode": preview.get("mode"),
                "proposal_id": proposal.get("proposal_id"),
                "proposal_sha256": proposal.get("proposal_sha256"),
                "base": preview.get("base"),
                "postimage": preview.get("postimage"),
                "guard_episode": preview.get("guard_episode"),
                "external_provenance": preview.get("external_provenance"),
                "approval_ready": preview.get("approval_ready"),
            }
        ],
    )


def _preview_policy_authority_change(
    args: argparse.Namespace,
    *,
    required_sealed_mode: str,
) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        if required_sealed_mode == "EDIT":
            postimage = _read_policy_postimage_file(args.postimage_file)
            preview = _run_policy_authority_call(
                recovery_guard,
                lambda: _policy_authority_core.preview_policy_change(
                    root,
                    requested_by=args.requested_by,
                    postimage=postimage,
                ),
            )
            report_mode = "preview-policy-change"
        else:
            preview = _run_policy_authority_call(
                recovery_guard,
                lambda: _policy_authority_core.preview_policy_reconcile(
                    root,
                    requested_by=args.requested_by,
                    external_actor=args.external_actor,
                    external_workflow=args.external_workflow,
                ),
            )
            report_mode = "preview-policy-reconcile"
        if preview.get("mode") != required_sealed_mode:
            raise MnemosyneError("policy preview returned the wrong sealed mode")
        proposal = _run_policy_authority_call(
            recovery_guard,
            lambda: _policy_authority_core.publish_policy_change_proposal(
                root,
                preview=preview,
            ),
        )
        if proposal.get("mode") != required_sealed_mode:
            raise MnemosyneError("policy proposal returned the wrong sealed mode")
        render_operation_report(
            _policy_change_proposal_report(
                root,
                preview,
                proposal,
                mode=report_mode,
            ),
            as_json=args.json,
        )
    return 0


def command_preview_policy_change(args: argparse.Namespace) -> int:
    return _preview_policy_authority_change(args, required_sealed_mode="EDIT")


def command_preview_policy_reconcile(args: argparse.Namespace) -> int:
    return _preview_policy_authority_change(
        args,
        required_sealed_mode="RECONCILE",
    )


def _approve_policy_authority_change(
    args: argparse.Namespace,
    *,
    required_sealed_mode: str,
    report_mode: str,
) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        approval = _run_policy_authority_call(
            recovery_guard,
            lambda: _policy_authority_core.approve_policy_change(
                root,
                proposal_id=args.proposal_id,
                proposal_sha256=args.proposal_sha256,
                approved_by=args.approved_by,
                required_sealed_mode=required_sealed_mode,
            ),
        )
        if approval.get("mode") != required_sealed_mode:
            raise MnemosyneError("policy approval returned the wrong sealed mode")
        report = operation_report(
            mode=report_mode,
            registry_updates=[
                {
                    "kind": "policy-change-approval",
                    "sealed_mode": approval.get("mode"),
                    "proposal_id": approval.get("proposal_id"),
                    "approval_id": approval.get("approval_id"),
                    "approval_sha256": approval.get("export_sha256"),
                    "export_path": approval.get("export_path"),
                    "run_id": approval.get("run_id"),
                    "state": approval.get("state"),
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
                "navigation/OKF/Graphify/memory",
            ],
            needs_review=[
                {
                    "kind": "policy-change-apply-binding",
                    "sealed_mode": approval.get("mode"),
                    "approval_id": approval.get("approval_id"),
                    "approval_sha256": approval.get("export_sha256"),
                }
            ],
        )
        render_operation_report(report, as_json=args.json)
    return 0


def command_approve_policy_change(args: argparse.Namespace) -> int:
    return _approve_policy_authority_change(
        args,
        required_sealed_mode="EDIT",
        report_mode="approve-policy-change",
    )


def command_approve_policy_reconcile(args: argparse.Namespace) -> int:
    return _approve_policy_authority_change(
        args,
        required_sealed_mode="RECONCILE",
        report_mode="approve-policy-reconcile",
    )


def _apply_policy_authority_change(
    args: argparse.Namespace,
    *,
    required_sealed_mode: str,
    report_mode: str,
) -> int:
    root = Path(args.root).expanduser().resolve()
    process_instance_id = _policy_change_cli_process_instance_id(
        root,
        approval_id=args.approval_id,
        approval_sha256=args.approval_sha256,
        executed_by=args.executed_by,
        required_sealed_mode=required_sealed_mode,
    )
    with manual_recovery_guard(root) as recovery_guard:
        result = _run_policy_authority_call(
            recovery_guard,
            lambda: _policy_authority_core.apply_policy_change(
                root,
                approval_id=args.approval_id,
                approval_sha256=args.approval_sha256,
                executed_by=args.executed_by,
                process_instance_id=process_instance_id,
                required_sealed_mode=required_sealed_mode,
            ),
        )
        if result.get("source_kind") != required_sealed_mode:
            raise MnemosyneError("policy result returned the wrong sealed mode")
        no_yaml_write = required_sealed_mode == "RECONCILE"
        not_modified = [
            "raw corpus",
            "movement writer",
            "navigation/OKF/Graphify/memory",
        ]
        if no_yaml_write:
            not_modified.insert(0, str(registry_path(root)))
        report = operation_report(
            mode=report_mode,
            registry_updates=[
                {
                    "kind": "approved-policy-generation",
                    "sealed_mode": result.get("source_kind"),
                    "status": result.get("status"),
                    "generation": result.get("generation"),
                    "guard_epoch": result.get("guard_epoch"),
                    "proposal_id": result.get("proposal_id"),
                    "approval_id": result.get("approval_id"),
                    "run_id": result.get("run_id"),
                    "raw_hash": result.get("raw_hash"),
                    "normalized_full_hash": result.get(
                        "normalized_full_hash"
                    ),
                    "writer_control_hash": result.get("writer_control_hash"),
                    "foundation_hash": result.get("foundation_hash"),
                    "yaml_write_effects": result.get("yaml_write_effects"),
                    "paths": result.get("paths"),
                }
            ],
            not_modified=not_modified,
        )
        render_operation_report(report, as_json=args.json)
    return 0


def command_apply_policy_change(args: argparse.Namespace) -> int:
    return _apply_policy_authority_change(
        args,
        required_sealed_mode="EDIT",
        report_mode="apply-policy-change",
    )


def command_apply_policy_reconcile(args: argparse.Namespace) -> int:
    return _apply_policy_authority_change(
        args,
        required_sealed_mode="RECONCILE",
        report_mode="apply-policy-reconcile",
    )


def _generated_inventory_run_id() -> str:
    timestamp = utc_now().replace("-", "").replace(":", "")
    return "inventory-%s-%s" % (timestamp, uuid.uuid4().hex[:12])


def _run_inventory_workflow_call(
    recovery_guard: ManualRecoveryGuard,
    callback: Any,
) -> Any:
    try:
        result = callback()
    except ManualRecoveryRequired as exc:
        marker_path, marker_sha256 = persist_manual_recovery_blocker(
            recovery_guard,
            exc,
            kind="INVENTORY_RUN_RENAME_MANUAL_RECOVERY",
        )
        raise MnemosyneError(
            f"{exc}; blocker: {marker_path}; blocker_sha256: {marker_sha256}"
        ) from exc
    except (
        _inventory_workflow_core.InventoryWorkflowError,
        _admission_core.InventoryAdmissionError,
        _inventory_core.InventoryError,
    ) as exc:
        raise MnemosyneError(str(exc)) from exc
    recovery_guard.checkpoint()
    if not isinstance(
        result,
        _inventory_workflow_core.InventoryWorkflowReport,
    ):
        raise MnemosyneError("inventory workflow returned an invalid report")
    return result


def _inventory_operation_report(
    root: Path,
    workflow_report: Any,
    *,
    mode: str,
) -> dict[str, Any]:
    terminal = workflow_report.terminal
    approved = workflow_report.approved_policy
    review_kind = (
        "inventory-run-review"
        if terminal.state == "complete"
        else "inventory-run-failure"
    )
    return operation_report(
        mode=mode,
        registry_updates=[
            {
                "kind": "sealed-inventory-run",
                "run_id": terminal.run_id,
                "state": terminal.state,
                "path": terminal.path,
                "package_sha256": terminal.package_sha256,
                "request_sha256": workflow_report.request_sha256,
                "scope_hash": workflow_report.scope_hash,
                "approved_policy": {
                    "raw_hash": approved.raw_hash,
                    "full_hash": approved.full_hash,
                    "generation": approved.generation,
                    "source_kind": approved.source_kind,
                    "source_run_id": approved.source_run_id,
                    "guard_epoch": approved.guard_epoch,
                },
            }
        ],
        not_modified=[
            str(registry_path(root)),
            "raw corpus",
            "policy head",
            "movement writer",
        ],
        needs_review=[
            {
                "kind": review_kind,
                "run_id": terminal.run_id,
                "state": terminal.state,
                "path": terminal.path,
                "package_sha256": terminal.package_sha256,
                "openable": workflow_report.openable,
                "approval_ready": workflow_report.approval_ready,
            }
        ],
    )


def command_inventory(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    run_id = args.run_id or _generated_inventory_run_id()
    with manual_recovery_guard(root) as recovery_guard:
        workflow_report = _run_inventory_workflow_call(
            recovery_guard,
            lambda: _inventory_workflow_core.start_inventory(
                root,
                bootstrap_id=args.bootstrap_id,
                run_id=run_id,
            ),
        )
        render_operation_report(
            _inventory_operation_report(
                root,
                workflow_report,
                mode="inventory",
            ),
            as_json=args.json,
        )
    return 0


def command_resume_inventory(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    with manual_recovery_guard(root) as recovery_guard:
        workflow_report = _run_inventory_workflow_call(
            recovery_guard,
            lambda: _inventory_workflow_core.resume_inventory(
                root,
                bootstrap_id=args.bootstrap_id,
                run_id=args.run_id,
            ),
        )
        render_operation_report(
            _inventory_operation_report(
                root,
                workflow_report,
                mode="resume-inventory",
            ),
            as_json=args.json,
        )
    return 0


def command_preview_m2_migration(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        plan = _schema_migration_core.preview_m2_migration(
            root,
            plan_id=args.plan_id,
            requested_by=args.requested_by,
        )
    except _schema_migration_core.SchemaMigrationError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="preview-m2-migration",
            not_modified=[
                "ledger",
                str(registry_path(root)),
                "raw corpus",
                "schema-migration approval/backup/result artifacts",
                "navigation/OKF/Graphify/memory",
            ],
            needs_review=[plan],
        ),
        as_json=args.json,
    )
    return 0


def command_approve_m2_migration(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        approval = _schema_migration_core.approve_m2_migration(
            root,
            plan_id=args.plan_id,
            expected_plan_sha256=args.plan_sha256,
            requested_by=args.requested_by,
            approved_by=args.approved_by,
        )
    except _schema_migration_core.SchemaMigrationError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="approve-m2-migration",
            registry_updates=[approval],
            not_modified=[
                "ledger schema",
                str(registry_path(root)),
                "raw corpus",
                "schema-migration backup/result artifacts",
                "navigation/OKF/Graphify/memory",
            ],
            needs_review=[
                {
                    "kind": "approved-m2-schema-migration",
                    "approval_id": approval["approval_id"],
                    "approval_sha256": approval["approval_sha256"],
                    "plan_id": approval["plan_id"],
                    "plan_sha256": approval["plan_sha256"],
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def command_apply_m2_migration(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        result = _schema_migration_core.apply_m2_migration(
            root,
            plan_id=args.plan_id,
            expected_plan_sha256=args.plan_sha256,
            requested_by=args.requested_by,
            approval_id=args.approval_id,
            approval_sha256=args.approval_sha256,
            executed_by=args.executed_by,
        )
    except _schema_migration_core.SchemaMigrationError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="apply-m2-migration",
            registry_updates=[result],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
                "navigation/OKF/Graphify/memory",
                "structural approval authority",
            ],
            needs_review=[
                {
                    "kind": "completed-m2-schema-migration",
                    "plan_id": result["plan_id"],
                    "backup_path": result["backup_path"],
                    "result_path": result["result_path"],
                    "result_sha256": result["result_sha256"],
                    "status": result["status"],
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def command_open_run(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m2_workflow_core.open_root_run(
            root,
            run_id=args.run_id,
            opened_by=args.opened_by,
            rendered_at=args.rendered_at or utc_now(),
            campaign_id=args.campaign_id,
        )
    except _m2_workflow_core.M2WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="open-run",
            registry_updates=[
                {
                    "kind": "curation-campaign-root-review",
                    "campaign_id": report.campaign_id,
                    "binding_id": report.binding_id,
                    "integration_id": report.integration_id,
                    "snapshot_id": report.snapshot_id,
                    "status": report.status,
                    "snapshot_path": report.snapshot_path,
                    "snapshot_payload_sha256": (
                        report.snapshot_payload_sha256
                    ),
                    "resumed": report.resumed,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
                "navigation/OKF/Graphify/memory",
                "structural approval authority",
            ],
            needs_review=[
                {
                    "kind": "run-overview",
                    "campaign_id": report.campaign_id,
                    "snapshot_id": report.snapshot_id,
                    "review_directory": report.review_directory,
                    "structural_approval_ready": False,
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def command_open_batch(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m2_workflow_core.open_batch(
            root,
            campaign_id=args.campaign_id,
            unit_ids=tuple(args.unit_id),
            batch_id=args.batch_id,
            snapshot_id=args.snapshot_id,
            submission_id=args.submission_id,
            actor=args.actor,
            max_items=args.max_items,
            max_files=args.max_files,
            max_bytes=args.max_bytes,
            max_effects=args.max_effects,
        )
    except _m2_workflow_core.M2WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="open-batch",
            registry_updates=[
                {
                    "kind": "bounded-review-batch",
                    "campaign_id": report.campaign_id,
                    "batch_id": report.batch_id,
                    "snapshot_id": report.snapshot_id,
                    "status": report.status,
                    "snapshot_state": report.snapshot_state,
                    "snapshot_version": report.snapshot_version,
                    "review_revision": report.review_revision,
                    "snapshot_sha256": report.snapshot_sha256,
                    "package_sha256": report.package_sha256,
                    "final_path": report.final_path,
                    "resumed": report.resumed,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
                "navigation/OKF/Graphify/memory",
                "structural approval authority",
            ],
            needs_review=[
                {
                    "kind": "batch-preview",
                    "batch_id": report.batch_id,
                    "snapshot_id": report.snapshot_id,
                    "review_directory": report.review_directory,
                    "structural_approval_ready": (
                        report.structural_approval_ready
                    ),
                    "structural_blocker": report.structural_blocker,
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def command_validate_review(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m2_workflow_core.validate_review(
            root,
            snapshot_id=args.snapshot_id,
        )
    except _m2_workflow_core.M2WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="validate-review",
            not_modified=[
                "ledger",
                str(registry_path(root)),
                "raw corpus",
                "review package",
                "navigation/OKF/Graphify/memory",
            ],
            needs_review=[
                {
                    "kind": "validated-review",
                    "snapshot_id": report.snapshot_id,
                    "review_kind": report.review_kind,
                    "source_kind": report.source_kind,
                    "source_id": report.source_id,
                    "unit_count": report.unit_count,
                    "final_path": report.final_path,
                    "review_directory": report.review_directory,
                    "snapshot_sha256": report.snapshot_sha256,
                    "package_sha256": report.package_sha256,
                    "sealed_identity_sha256": (
                        report.sealed_identity_sha256
                    ),
                    "structural_approval_ready": (
                        report.structural_approval_ready
                    ),
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def command_checkout_review(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m2_workflow_core.checkout_review(
            root,
            snapshot_id=args.snapshot_id,
            snapshot_sha256=args.snapshot_sha256,
            draft_id=args.draft_id,
            actor=args.actor,
        )
    except _m2_workflow_core.M2WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="checkout-review",
            registry_updates=[
                {
                    "kind": "non-authoritative-review-draft",
                    "draft_id": report.draft_id,
                    "base_snapshot_id": report.base_snapshot_id,
                    "base_snapshot_sha256": report.base_snapshot_sha256,
                    "actor": report.actor,
                    "final_path": report.final_path,
                    "draft_markdown_path": report.draft_markdown_path,
                    "template_markdown_sha256": (
                        report.template_markdown_sha256
                    ),
                    "current_markdown_sha256": (
                        report.current_markdown_sha256
                    ),
                    "authority": report.authority,
                    "approval_ready": report.approval_ready,
                }
            ],
            not_modified=[
                "ledger",
                str(registry_path(root)),
                "sealed review package",
                "raw corpus",
                "movement writer",
                "navigation/OKF/Graphify/memory",
                "structural approval authority",
            ],
            needs_review=[
                {
                    "kind": "editable-review-draft",
                    "draft_id": report.draft_id,
                    "review_draft_path": report.draft_markdown_path,
                    "allowed_scope": "typed marker values only",
                    "submit_required_for_sealed_state": True,
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def command_explode_review_unit(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m2_workflow_core.explode_review_unit(
            root,
            batch_id=args.batch_id,
            snapshot_id=args.snapshot_id,
            snapshot_sha256=args.snapshot_sha256,
            folder_unit_id=args.folder_unit_id,
            next_snapshot_id=args.next_snapshot_id,
            submission_id=args.submission_id,
            actor=args.actor,
        )
    except _m2_workflow_core.M2WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="explode-review-unit",
            registry_updates=[
                {
                    "kind": "copy-on-write-exploded-review-snapshot",
                    "batch_id": report.batch_id,
                    "parent_snapshot_id": report.parent_snapshot_id,
                    "parent_snapshot_sha256": report.parent_snapshot_sha256,
                    "snapshot_id": report.snapshot_id,
                    "snapshot_version": report.snapshot_version,
                    "review_revision": report.review_revision,
                    "execution_generation": report.execution_generation,
                    "status": report.status,
                    "snapshot_state": report.snapshot_state,
                    "snapshot_sha256": report.snapshot_sha256,
                    "package_sha256": report.package_sha256,
                    "final_path": report.final_path,
                    "structural_approval_ready": (
                        report.structural_approval_ready
                    ),
                    "structural_blocker": report.structural_blocker,
                    "resumed": report.resumed,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "previous sealed snapshot",
                "movement writer",
                "navigation/OKF/Graphify/memory",
                "structural approval authority",
            ],
            needs_review=[
                {
                    "kind": "exploded-batch-preview",
                    "batch_id": report.batch_id,
                    "snapshot_id": report.snapshot_id,
                    "review_directory": report.review_directory,
                    "structural_approval_ready": (
                        report.structural_approval_ready
                    ),
                    "structural_blocker": report.structural_blocker,
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def command_split_review_batch(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m4_workflow_core.split_review_batch(
            root,
            event_id=args.event_id,
            batch_id=args.batch_id,
            expected_snapshot_id=args.snapshot_id,
            expected_snapshot_sha256=args.snapshot_sha256,
            expected_review_revision=args.expected_review_revision,
            expected_execution_generation=args.expected_execution_generation,
            selected_unit_ids=tuple(args.unit_id),
            child_batch_id=args.child_batch_id,
            child_snapshot_id=args.child_snapshot_id,
            child_snapshot_sha256=args.child_snapshot_sha256,
            child_submission_id=args.child_submission_id,
            parent_next_snapshot_id=args.parent_next_snapshot_id,
            parent_next_snapshot_sha256=args.parent_next_snapshot_sha256,
            parent_submission_id=args.parent_submission_id,
            actor=args.actor,
        )
    except _m4_workflow_core.M4WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="split-review-batch",
            registry_updates=[
                {
                    "kind": "split-batch-event",
                    "batch_id": report.batch_id,
                    "event_id": report.event_id,
                    "state": report.state,
                    "resumed": report.resumed,
                    "child_batch_id": report.child_batch_id,
                    "parent_snapshot_id": report.parent_snapshot_id,
                    "child_snapshot_id": report.child_snapshot_id,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
                "navigation/OKF/Graphify/memory",
                "structural approval authority",
            ],
            needs_review=[
                {
                    "kind": "split-batch-published",
                    "batch_id": report.batch_id,
                    "child_batch_id": report.child_batch_id,
                    "event_id": report.event_id,
                    "note": "selected memberships moved to child batch; parent head advanced",
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def _render_m3_submission_report(
    args: argparse.Namespace,
    report: object,
    *,
    mode: str,
) -> None:
    render_operation_report(
        operation_report(
            mode=mode,
            registry_updates=[
                {
                    "kind": "review-decision-submission",
                    "batch_id": report.batch_id,
                    "snapshot_id": report.snapshot_id,
                    "submission_id": report.submission_id,
                    "submission_state": report.submission_state,
                    "review_revision": report.review_revision,
                    "execution_generation": report.execution_generation,
                    "snapshot_sha256": report.snapshot_sha256,
                    "package_sha256": report.package_sha256,
                    "final_path": report.final_path,
                    "resumed": report.resumed,
                }
            ],
            not_modified=[
                str(registry_path(Path(args.root).expanduser().resolve())),
                "raw corpus",
                "movement writer",
                "navigation/OKF/Graphify/memory",
                "structural approval authority",
            ],
            needs_review=[
                {
                    "kind": "batch-review-snapshot",
                    "batch_id": report.batch_id,
                    "snapshot_id": report.snapshot_id,
                    "review_directory": report.review_directory,
                    "structural_approval_ready": report.structural_approval_ready,
                }
            ],
        ),
        as_json=args.json,
    )


def command_decide(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.decide(
            root,
            campaign_id=args.campaign_id,
            batch_id=args.batch_id,
            base_snapshot_id=args.base_snapshot_id,
            base_snapshot_sha256=args.base_snapshot_sha256,
            expected_review_revision=args.expected_review_revision,
            expected_execution_generation=args.expected_execution_generation,
            submission_id=args.submission_id,
            next_snapshot_id=args.next_snapshot_id,
            actor=args.actor,
            unit_id=args.unit_id,
            member_item_ids=tuple(args.member_item_id),
            action=args.action,
            reason=args.reason,
            decided_at_utc=args.decided_at,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    _render_m3_submission_report(args, report, mode="decide")
    return 0


def command_submit_review(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.submit_review(
            root,
            draft_id=args.draft_id,
            submission_id=args.submission_id,
            next_snapshot_id=args.next_snapshot_id,
            actor=args.actor,
            reason=args.reason,
            decided_at_utc=args.decided_at,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    _render_m3_submission_report(args, report, mode="submit-review")
    return 0


def command_reopen_decision(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.reopen_decision(
            root,
            campaign_id=args.campaign_id,
            batch_id=args.batch_id,
            base_snapshot_id=args.base_snapshot_id,
            base_snapshot_sha256=args.base_snapshot_sha256,
            expected_review_revision=args.expected_review_revision,
            expected_execution_generation=args.expected_execution_generation,
            submission_id=args.submission_id,
            next_snapshot_id=args.next_snapshot_id,
            item_id=args.item_id,
            current_decision_event_id=args.current_decision_event_id,
            current_projection_generation=args.current_projection_generation,
            actor=args.actor,
            reason=args.reason,
            reopened_at_utc=args.reopened_at,
            selected_relation_kind=args.selected_relation_kind,
            selected_relation_id=args.selected_relation_id,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    _render_m3_submission_report(args, report, mode="reopen-decision")
    return 0


def _add_batch_terminal_cli_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--expected-snapshot-id", required=True)
    parser.add_argument("--expected-snapshot-sha256", required=True)
    parser.add_argument("--expected-review-revision", type=int, required=True)
    parser.add_argument(
        "--expected-execution-generation",
        type=int,
        required=True,
    )
    parser.add_argument("--actor", required=True)
    parser.add_argument("--root", default=str(DEFAULT_ROOT))
    parser.add_argument("--json", action="store_true")


def command_preview_legacy_history_import(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.preview_legacy_history_import(
            root,
            preview_id=args.preview_id,
            requested_by=args.requested_by,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="preview-legacy-history-import",
            registry_updates=[
                {
                    "kind": "legacy-import-preview",
                    "preview_id": report.preview_id,
                    "preview_sha256": report.preview_sha256,
                    "entry_count": report.entry_count,
                    "pending_count": report.pending_count,
                    "collision_count": report.collision_count,
                    "preview": report.preview,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "exact curation ledger",
                "movement writer",
            ],
            needs_review=[
                {
                    "kind": "legacy-import-preview",
                    "preview_id": report.preview_id,
                    "preview_sha256": report.preview_sha256,
                    "pending_count": report.pending_count,
                    "collision_count": report.collision_count,
                }
            ],
        ),
        as_json=args.json,
    )
    return 0


def command_import_legacy_history(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.import_legacy_history(
            root,
            import_run_id=args.import_run_id,
            preview_file=Path(args.preview_file),
            actor=args.actor,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="import-legacy-history",
            registry_updates=[
                {
                    "kind": "legacy-import-result",
                    "import_run_id": report.import_run_id,
                    "preview_sha256": report.preview_sha256,
                    "state": report.state,
                    "entry_count": report.entry_count,
                    "result_path": report.result_path,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
            ],
            needs_review=[],
        ),
        as_json=args.json,
    )
    return 0


def command_progress(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.query_progress(
            root,
            workstream_id=args.workstream_id,
            item_id=args.item_id,
            deferred_state=args.deferred,
            history=args.history,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="progress",
            registry_updates=[
                {
                    "kind": "progress-view",
                    "view": report.view,
                    "payload": report.payload,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "exact curation ledger",
                "movement writer",
            ],
            needs_review=[],
        ),
        as_json=args.json,
    )
    return 0


def _command_batch_terminal(args: argparse.Namespace, *, mode: str) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        if mode == "close-review-batch":
            report = _m3_workflow_core.close_review_batch(
                root,
                event_id=args.event_id,
                batch_id=args.batch_id,
                expected_snapshot_id=args.expected_snapshot_id,
                expected_snapshot_sha256=args.expected_snapshot_sha256,
                expected_review_revision=args.expected_review_revision,
                expected_execution_generation=args.expected_execution_generation,
                actor=args.actor,
            )
        else:
            report = _m3_workflow_core.abandon_review_batch(
                root,
                event_id=args.event_id,
                batch_id=args.batch_id,
                expected_snapshot_id=args.expected_snapshot_id,
                expected_snapshot_sha256=args.expected_snapshot_sha256,
                expected_review_revision=args.expected_review_revision,
                expected_execution_generation=args.expected_execution_generation,
                actor=args.actor,
            )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode=mode,
            registry_updates=[
                {
                    "kind": "batch-terminal-event",
                    "event_id": report.event_id,
                    "event_state": report.event_state,
                    "event_sha256": report.event_sha256,
                    "batch_id": report.batch_id,
                    "batch_status": report.batch_status,
                    "released_memberships": report.released_memberships,
                    "final_path": report.final_path,
                    "resumed": report.resumed,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
                "navigation/OKF/Graphify/memory",
            ],
            needs_review=[],
        ),
        as_json=args.json,
    )
    return 0


def command_close_review_batch(args: argparse.Namespace) -> int:
    return _command_batch_terminal(args, mode="close-review-batch")


def command_abandon_review_batch(args: argparse.Namespace) -> int:
    return _command_batch_terminal(args, mode="abandon-review-batch")


def command_resume_batch_event(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.resume_batch_event(
            root,
            event_id=args.event_id,
            resumed_by=args.resumed_by,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="resume-batch-event",
            registry_updates=[
                {
                    "kind": "batch-terminal-event",
                    "event_id": report.event_id,
                    "event_state": report.event_state,
                    "event_sha256": report.event_sha256,
                    "batch_id": report.batch_id,
                    "batch_status": report.batch_status,
                    "released_memberships": report.released_memberships,
                    "final_path": report.final_path,
                    "resumed": report.resumed,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
            ],
            needs_review=[],
        ),
        as_json=args.json,
    )
    return 0


def command_resume_legacy_history_import(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.resume_legacy_history_import(
            root,
            import_run_id=args.import_run_id,
            resumed_by=args.resumed_by,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="resume-legacy-history-import",
            registry_updates=[
                {
                    "kind": "legacy-import-result",
                    "import_run_id": report.import_run_id,
                    "preview_sha256": report.preview_sha256,
                    "state": report.state,
                    "entry_count": report.entry_count,
                    "result_path": report.result_path,
                    "resumed": True,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
            ],
            needs_review=[],
        ),
        as_json=args.json,
    )
    return 0


def command_resume_review_submission(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.resume_review_submission(
            root,
            submission_id=args.submission_id,
            actor=args.actor,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    _render_m3_submission_report(args, report, mode="resume-review-submission")
    return 0


def _render_progress_view_report(
    args: argparse.Namespace,
    report: _m3_workflow_core.ProgressViewReport,
    *,
    mode: str,
) -> None:
    render_operation_report(
        operation_report(
            mode=mode,
            registry_updates=[
                {
                    "kind": "progress-view",
                    "view": report.view,
                    "payload": report.payload,
                }
            ],
            not_modified=[
                str(registry_path(Path(args.root).expanduser().resolve())),
                "raw corpus",
                "exact curation ledger",
                "movement writer",
            ],
            needs_review=[],
        ),
        as_json=args.json,
    )


def command_list_deferred(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.list_deferred(
            root,
            state=args.state,
            workstream_id=args.workstream_id,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    _render_progress_view_report(args, report, mode="list-deferred")
    return 0


def _legacy_curation_history(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.query_item_history(
            root,
            item_id=args.item_id,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    _render_progress_view_report(args, report, mode="history")
    return 0


def command_attach_deferral_evidence(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.attach_deferral_evidence(
            root,
            event_id=args.event_id,
            deferral_id=args.deferral_id,
            deferral_version=args.deferral_version,
            actor=args.actor,
            scope_class=args.scope_class,
            allowed_metadata=tuple(args.metadata or ()),
            source_ref=args.source_ref,
            content_sha256=args.content_sha256,
            opaque_source_id=args.opaque_source_id,
            actor_attestation=args.actor_attestation,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="attach-deferral-evidence",
            registry_updates=[
                {
                    "kind": "deferral-evidence",
                    "event_id": report.event_id,
                    "deferral_id": report.deferral_id,
                    "deferral_version": report.deferral_version,
                    "state": report.state,
                    "final_path": report.final_path,
                    "final_sha256": report.final_sha256,
                    "resumed": report.resumed,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
            ],
            needs_review=[],
        ),
        as_json=args.json,
    )
    return 0


def command_evaluate_deferrals(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    try:
        report = _m3_workflow_core.evaluate_deferral_trigger(
            root,
            deferral_id=args.deferral_id,
            expected_version=args.expected_version,
            actor=args.actor,
            evidence_event_id=args.evidence_event_id,
            manual_reason=args.manual_reason,
        )
    except _m3_workflow_core.M3WorkflowError as exc:
        raise MnemosyneError(str(exc)) from exc
    render_operation_report(
        operation_report(
            mode="evaluate-deferrals",
            registry_updates=[
                {
                    "kind": "deferral-trigger",
                    "trigger_event_id": report.trigger_event_id,
                    "deferral_id": report.deferral_id,
                    "deferral_version": report.deferral_version,
                    "trigger_kind": report.trigger_kind,
                    "projection_generation": report.projection_generation,
                    "repeated": report.repeated,
                }
            ],
            not_modified=[
                str(registry_path(root)),
                "raw corpus",
                "movement writer",
            ],
            needs_review=[],
        ),
        as_json=args.json,
    )
    return 0


def _write_machine_result(raw: bytes) -> None:
    stream = getattr(sys.stdout, "buffer", None)
    if stream is not None:
        stream.write(raw)
        stream.flush()
        return
    sys.stdout.write(raw.decode("utf-8"))
    sys.stdout.flush()


def command_curation_dispatch(args: argparse.Namespace) -> int:
    exit_code, raw = _cli_dispatch_core.dispatch_request(
        request_file=args.request_file,
        stdin=sys.stdin,
        execute_request_bytes=_mnemosyne_core.execute_request_bytes,
    )
    _write_machine_result(raw)
    return exit_code


def command_curation_inspect(args: argparse.Namespace) -> int:
    exit_code, rendered = _cli_inspect_core.inspect_view(
        view=args.view,
        root=args.root,
        actor=args.actor,
        max_items=args.max_items,
        offset=args.offset,
        workstream_ref=args.workstream,
        relative_path=args.relative_path,
        max_depth=args.max_depth,
        max_hint_bytes=args.max_hint_bytes,
        review_package=args.review_package,
        as_json=args.json,
        execute_request_bytes=_mnemosyne_core.execute_request_bytes,
    )
    if args.json:
        _write_machine_result(rendered)
    else:
        sys.stdout.write(rendered)
        sys.stdout.flush()
    return exit_code


def command_curation_guide(args: argparse.Namespace) -> int:
    exit_code, rendered, is_error = _cli_guide_core.guide_request(
        root=args.root,
        actor=args.actor,
        draft=args.draft,
        view=args.view,
        max_items=args.max_items,
        offset=args.offset,
        workstream_ref=args.workstream,
        relative_path=args.relative_path,
        source_relative_path=args.source_relative_path,
        target_relative_path=args.target_relative_path,
        destination_kind=args.destination_kind,
        destination_id=args.destination_id,
        reason=args.reason,
        max_entries=args.max_entries,
        max_depth=args.max_depth,
        max_hint_bytes=args.max_hint_bytes,
        max_total_bytes=args.max_total_bytes,
        proposal_request_file=args.proposal_request_file,
        proposal_outcome_file=args.proposal_outcome_file,
        decision=args.decision,
        decision_reason=args.decision_reason,
        decision_request_file=args.decision_request_file,
        decision_outcome_file=args.decision_outcome_file,
        audit_file=args.audit_file,
        expected_plan_sha256=args.expected_plan_sha256,
        navigation_review_package=args.review_package,
        navigation_proposed_document_file=args.proposed_document_file,
        navigation_source_map_file=args.source_map_file,
        navigation_output_directory=args.output_directory,
        stdin_isatty=sys.stdin.isatty(),
        stdout_isatty=sys.stdout.isatty(),
    )
    stream = sys.stderr if is_error else sys.stdout
    stream.write(rendered)
    stream.flush()
    return exit_code


class _CurationSurfaceParser(argparse.ArgumentParser):
    """Give removed Curation commands one generic, non-dispatching migration hint."""

    def error(self, message: str) -> None:
        if "invalid choice" in message:
            if self.prog.endswith(" curation"):
                prefix = "unsupported curation command"
            else:
                prefix = "unsupported command"
            self.exit(
                2,
                f"error: {prefix}; use `curation guide`, `curation dispatch`, "
                "or `curation inspect`.\n",
            )
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _CurationSurfaceParser(
        description="Mnemosyne Document Curation and Workspace Context CLI"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_CurationSurfaceParser,
    )

    memory_sync = subparsers.add_parser("memory-sync")
    memory_sync.add_argument("--workspace")
    memory_sync.add_argument("--title")
    memory_sync.add_argument("--summary")
    memory_sync.add_argument("--ref", action="append", default=[])
    memory_sync.add_argument("--workstream")
    memory_sync.add_argument("--approval-review")
    memory_sync_mode = memory_sync.add_mutually_exclusive_group(required=True)
    memory_sync_mode.add_argument("--plan-out")
    memory_sync_mode.add_argument("--render-approval-card")
    memory_sync_mode.add_argument("--apply-plan")
    memory_sync.add_argument("--expected-plan-sha256")
    memory_sync.add_argument("--actor", default="local-operator")
    memory_sync.add_argument("--allow-unknown", action="store_true")
    memory_sync.add_argument("--root", default=str(DEFAULT_ROOT))
    memory_sync.set_defaults(func=command_memory_sync)

    context = subparsers.add_parser("context")
    context.add_argument("--workspace")
    context.add_argument("--question")
    context.add_argument("--history", type=int, default=argparse.SUPPRESS)
    context.add_argument("--max-chars", type=int, default=argparse.SUPPRESS)
    context.add_argument("--with-graphify", action="store_true")
    context.add_argument("--json", action="store_true")
    context.add_argument("--allow-unknown", action="store_true")
    context.add_argument("--root", default=str(DEFAULT_ROOT))
    context.set_defaults(func=command_context)

    context_queries = context.add_subparsers(dest="context_query")

    collect_sync_history = context_queries.add_parser("collect-sync-history")
    collect_sync_history.add_argument("--from-date", required=True)
    collect_sync_history.add_argument("--to-date", required=True)
    collect_sync_history.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS
    )
    collect_sync_history.add_argument("--root", default=argparse.SUPPRESS)
    collect_sync_history.set_defaults(func=command_collect_sync_history)

    lookup_project_context = context_queries.add_parser("lookup-project-context")
    lookup_project_context.add_argument("--project-root", required=True)
    lookup_project_context.add_argument("--question", default=argparse.SUPPRESS)
    lookup_project_context.add_argument("--task-context")
    lookup_project_context.add_argument("--snapshot-chars", type=int, default=12000)
    lookup_project_context.add_argument(
        "--history", type=int, default=argparse.SUPPRESS
    )
    lookup_project_context.add_argument(
        "--history-excerpt-chars", type=int, default=2000
    )
    lookup_project_context.add_argument(
        "--max-chars", type=int, default=argparse.SUPPRESS
    )
    lookup_project_context.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS
    )
    lookup_project_context.add_argument("--root", default=argparse.SUPPRESS)
    lookup_project_context.set_defaults(func=command_lookup_project_context)

    curation = subparsers.add_parser("curation")
    curation_commands = curation.add_subparsers(dest="curation_command", required=True)
    guide = curation_commands.add_parser("guide")
    guide.add_argument("--root", default=str(DEFAULT_ROOT))
    guide.add_argument("--actor", default="local-operator")
    guide.add_argument(
        "--draft",
        choices=(
            "activation",
            "context-activation",
            "inspect",
            "navigation",
            "proposal",
            "decision",
            "placement",
        ),
        default="inspect",
    )
    guide.add_argument(
        "--view",
        choices=("scope", "pending", "history"),
        default="scope",
    )
    guide.add_argument("--max-items", type=int)
    guide.add_argument("--offset", type=int, default=0)
    guide.add_argument("--workstream")
    guide.add_argument("--relative-path")
    guide.add_argument("--source-relative-path")
    guide.add_argument("--target-relative-path")
    guide.add_argument(
        "--destination-kind",
        choices=("workstream", "manual_category"),
    )
    guide.add_argument("--destination-id")
    guide.add_argument("--reason")
    guide.add_argument("--max-entries", type=int)
    guide.add_argument("--max-depth", type=int)
    guide.add_argument("--max-hint-bytes", type=int)
    guide.add_argument("--max-total-bytes", type=int)
    guide.add_argument("--proposal-request-file")
    guide.add_argument("--proposal-outcome-file")
    guide.add_argument(
        "--decision",
        choices=("APPROVED", "REJECTED", "APPROVE_ALL"),
    )
    guide.add_argument("--decision-reason")
    guide.add_argument("--decision-request-file")
    guide.add_argument("--decision-outcome-file")
    guide.add_argument("--audit-file")
    guide.add_argument("--review-package")
    guide.add_argument("--expected-plan-sha256")
    guide.add_argument("--proposed-document-file")
    guide.add_argument("--source-map-file")
    guide.add_argument("--output-directory")
    guide.set_defaults(func=command_curation_guide)

    dispatch = curation_commands.add_parser("dispatch")
    dispatch.add_argument("--request-file")
    dispatch.set_defaults(func=command_curation_dispatch)

    inspect = curation_commands.add_parser("inspect")
    inspect.add_argument(
        "view",
        choices=("audit", "scope", "pending", "history", "workstream"),
    )
    inspect.add_argument("--root", default=str(DEFAULT_ROOT))
    inspect.add_argument("--actor", default="local-operator")
    inspect.add_argument("--max-items", type=int)
    inspect.add_argument("--offset", type=int, default=0)
    inspect.add_argument("--workstream")
    inspect.add_argument("--relative-path")
    inspect.add_argument("--max-depth", type=int)
    inspect.add_argument("--max-hint-bytes", type=int)
    inspect.add_argument("--review-package")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(func=command_curation_inspect)

    return parser




def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except MnemosyneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
