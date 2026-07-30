import argparse
import ast
import contextlib
import hashlib
import inspect
import io
import json
import os
import py_compile
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

# Discovery may import pure core-module test files before this facade test.
# Remove only those test-owned imports so the production verified bootstrap
# still proves that it, rather than Python's normal importer, loads the closure.
for _loaded_name in tuple(sys.modules):
    if _loaded_name == "mnemosyne_core" or _loaded_name.startswith(
        "mnemosyne_core."
    ):
        sys.modules.pop(_loaded_name, None)
sys.modules.pop("mnemosyne", None)

import mnemosyne  # noqa: E402


class MnemosyneCliTest(unittest.TestCase):
    def test_runtime_core_package_disables_filesystem_import_fallback(self):
        self.assertEqual(mnemosyne._mnemosyne_core.__path__, [])

    def test_context_assembly_is_inside_verified_runtime_module_closure(self):
        self.assertIn(
            "mnemosyne_core.context_assembly",
            mnemosyne._BOOTSTRAP_CORE_MODULES,
        )
        self.assertEqual(
            mnemosyne._BOOTSTRAP_CORE_MODULES[
                "mnemosyne_core.context_assembly"
            ].__file__,
            str(
                Path(mnemosyne.__file__).resolve().parent
                / "mnemosyne_core"
                / "context_assembly.py"
            ),
        )

    def test_runtime_module_closure_is_dependency_topological(self):
        positions = {
            module_name: index
            for index, (module_name, _path, _is_package) in enumerate(
                mnemosyne.RUNTIME_MODULE_CLOSURE
            )
        }
        core_root = Path(mnemosyne.__file__).resolve().parent / "mnemosyne_core"

        for module_name, relative_path, is_package in mnemosyne.RUNTIME_MODULE_CLOSURE:
            if is_package:
                continue
            tree = ast.parse((core_root / relative_path).read_text(encoding="utf-8"))
            dependencies = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 1:
                    if node.module:
                        dependencies.add("mnemosyne_core." + node.module.split(".")[0])
                    else:
                        dependencies.update(
                            "mnemosyne_core." + alias.name.split(".")[0]
                            for alias in node.names
                        )
                elif isinstance(node, ast.Import):
                    dependencies.update(
                        alias.name
                        for alias in node.names
                        if alias.name.startswith("mnemosyne_core.")
                    )
            for dependency in dependencies.intersection(positions):
                self.assertLess(
                    positions[dependency],
                    positions[module_name],
                    "%s must load before %s" % (dependency, module_name),
                )

    def test_runtime_module_closure_binds_only_verified_module_objects(self):
        verified = mnemosyne._BOOTSTRAP_CORE_MODULES

        for module_name, module in verified.items():
            self.assertIs(sys.modules[module_name], module)
            self.assertIsNone(module.__loader__, module_name)
            self.assertIsNone(module.__cached__, module_name)
            for binding_name, value in vars(module).items():
                if isinstance(value, types.ModuleType) and value.__name__ in verified:
                    self.assertIs(
                        value,
                        verified[value.__name__],
                        "%s.%s" % (module_name, binding_name),
                    )
                if isinstance(value, (types.FunctionType, type)):
                    source_module_name = getattr(value, "__module__", None)
                    if source_module_name in verified:
                        canonical = getattr(
                            verified[source_module_name],
                            getattr(value, "__name__", ""),
                            None,
                        )
                        self.assertIs(
                            value,
                            canonical,
                            "%s.%s" % (module_name, binding_name),
                        )

    def test_canonical_facade_delegates_to_loaded_core_module(self):
        with mock.patch.object(
            mnemosyne._canonical_json_core,
            "canonical_json_bytes",
            return_value=b"core-json\n",
        ) as encode:
            self.assertEqual(mnemosyne.canonical_json_bytes({"b": 1}), b"core-json\n")
        encode.assert_called_once_with({"b": 1})

        with mock.patch.object(
            mnemosyne._canonical_json_core,
            "sha256_bytes",
            return_value="core-digest",
        ) as digest:
            self.assertEqual(mnemosyne.sha256_bytes(b"payload"), "core-digest")
        digest.assert_called_once_with(b"payload")

    def test_safety_core_exposes_observation_seams_not_replaceable_safety_operations(self):
        forbidden = {
            "open_or_create_directory",
            "open_directory",
            "rename_entry",
            "require_same_directory_identity",
        }
        for name in (
            "create_verified_directory_no_replace",
            "publish_bytes_atomic_no_replace",
            "verified_directory_present",
            "rename_path_no_replace",
            "move_regular_file_no_replace",
        ):
            parameters = inspect.signature(getattr(mnemosyne._safety_core, name)).parameters
            self.assertTrue(forbidden.isdisjoint(parameters), name)
            self.assertIn("before_directory_identity_check", parameters, name)
        rename_parameters = inspect.signature(
            mnemosyne._safety_core.rename_path_no_replace
        ).parameters
        self.assertNotIn("manual_recovery_error_type", rename_parameters)
        self.assertIs(
            mnemosyne.ManualRecoveryRequired,
            mnemosyne._safety_core.ManualRecoveryRequired,
        )
        self.assertIs(
            inspect.signature(mnemosyne.rename_path_no_replace)
            .parameters["recovery_guard"]
            .default,
            inspect.Parameter.empty,
        )
        self.assertNotIn(
            "recovery_root",
            inspect.signature(mnemosyne.rename_path_no_replace).parameters,
        )
        self.assertEqual(
            list(inspect.signature(mnemosyne.persist_manual_recovery_blocker).parameters)[0],
            "guard",
        )

    def test_manual_recovery_guard_token_cannot_be_constructed_outside_factory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            root_fd = os.open(root, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "must be created by manual_recovery_guard",
                ):
                    mnemosyne.ManualRecoveryGuard(root, root_fd)
            finally:
                os.close(root_fd)

    def test_runtime_module_closure_rejects_noncanonical_import_layout(self):
        with mock.patch.object(
            mnemosyne._safety_core,
            "__file__",
            "/private/tmp/untrusted/mnemosyne_core/safety.py",
        ):
            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "outside the canonical writer layout",
            ):
                mnemosyne.authoritative_runtime_module_paths()

    def test_runtime_module_closure_rejects_loaded_function_divergence(self):
        def forged_require_safe_tree(*_args, **_kwargs):
            return None

        with mock.patch.object(
            mnemosyne._safety_core,
            "require_safe_tree",
            forged_require_safe_tree,
        ):
            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "runtime module code does not match verified source",
            ):
                mnemosyne.authoritative_runtime_module_paths()

    def test_runtime_module_closure_rejects_in_place_code_swap(self):
        target = mnemosyne._safety_core.require_safe_tree
        original_code = target.__code__

        def forged_require_safe_tree(*_args, **_kwargs):
            return None

        target.__code__ = forged_require_safe_tree.__code__
        try:
            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "runtime module function state does not match verified source",
            ):
                mnemosyne.authoritative_runtime_module_paths()
        finally:
            target.__code__ = original_code

    def test_runtime_module_closure_rejects_in_place_kwdefault_mutation(self):
        target = mnemosyne._safety_core.open_or_create_verified_directory
        original_kwdefaults = dict(target.__kwdefaults__ or {})
        self.assertIn("mode", original_kwdefaults)
        target.__kwdefaults__["mode"] = 0o777
        try:
            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "runtime module function state does not match verified source",
            ):
                mnemosyne.authoritative_runtime_module_paths()
        finally:
            target.__kwdefaults__.clear()
            target.__kwdefaults__.update(original_kwdefaults)

    def test_runtime_module_closure_rejects_class_method_divergence(self):
        contract = mnemosyne._BOOTSTRAP_CORE_MODULES[
            "mnemosyne_core.curation_contract"
        ]
        targets = (
            (contract.HarnessRequest, "__post_init__"),
            (contract.HarnessResult, "__post_init__"),
            (contract.CapabilityDescriptor, "__post_init__"),
            (contract._FrozenDict, "_immutable"),
            (contract._FrozenList, "_immutable"),
        )

        def forged_method(*_args, **_kwargs):
            return None

        for owner, name in targets:
            with self.subTest(owner=owner.__name__, method=name):
                with mock.patch.object(owner, name, forged_method):
                    with self.assertRaisesRegex(
                        mnemosyne.MnemosyneError,
                        "runtime module class state does not match verified source",
                    ):
                        mnemosyne.authoritative_runtime_module_paths()

    def test_runtime_module_closure_rejects_loaded_global_dependency_divergence(self):
        forged_hashlib = mock.Mock()
        forged_hashlib.sha256.return_value.hexdigest.return_value = "forged"
        with mock.patch.object(
            mnemosyne._canonical_json_core,
            "hashlib",
            forged_hashlib,
        ):
            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "runtime module globals do not match verified source",
            ):
                mnemosyne.authoritative_runtime_module_paths()

    def test_runtime_module_closure_rejects_unexpected_loaded_local_module(self):
        module_name = "mnemosyne_core.unexpected"
        unexpected = type(mnemosyne._safety_core)(module_name)
        unexpected.__file__ = str(
            Path(mnemosyne.__file__).resolve().parent / "mnemosyne_core" / "unexpected.py"
        )
        with mock.patch.dict(sys.modules, {module_name: unexpected}):
            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "unexpected loaded modules",
            ):
                mnemosyne.authoritative_runtime_module_paths()

    def test_runtime_module_bootstrap_ignores_timestamp_pyc_source_divergence(self):
        with tempfile.TemporaryDirectory() as tmp:
            install_root = Path(tmp).resolve() / "install"
            package_root = install_root / "mnemosyne_core"
            package_root.mkdir(parents=True, mode=0o700)
            source_root = Path(mnemosyne.__file__).resolve().parent
            (install_root / "mnemosyne.py").write_bytes((source_root / "mnemosyne.py").read_bytes())
            for _module_name, name, _is_package in mnemosyne.RUNTIME_MODULE_CLOSURE:
                target = package_root / name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes((source_root / "mnemosyne_core" / name).read_bytes())

            safety_path = package_root / "safety.py"
            approved_source = safety_path.read_text(encoding="utf-8")
            timestamp = int(safety_path.stat().st_mtime) - 10
            override = "\n\ndef require_safe_tree(*_args, **_kwargs):\n    return None\n"
            padding = "\n#" + (" " * (len(override.encode("utf-8")) - 3)) + "\n"
            self.assertEqual(len(padding.encode("utf-8")), len(override.encode("utf-8")))
            malicious_source = approved_source + override
            verified_source = approved_source + padding
            self.assertEqual(
                len(malicious_source.encode("utf-8")),
                len(verified_source.encode("utf-8")),
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(install_root)
            env["PYTHONPYCACHEPREFIX"] = str(Path(tmp).resolve() / "pycache")
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            cache_probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import importlib.util; "
                    f"print(importlib.util.cache_from_source({str(safety_path)!r}))",
                ],
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            cache_path = Path(cache_probe.stdout.strip())
            cache_path.parent.mkdir(parents=True, mode=0o700)
            safety_path.write_text(malicious_source, encoding="utf-8")
            os.utime(safety_path, (timestamp, timestamp))
            py_compile.compile(
                str(safety_path),
                cfile=str(cache_path),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
            )
            safety_path.write_text(verified_source, encoding="utf-8")
            os.utime(safety_path, (timestamp, timestamp))

            probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import mnemosyne\n"
                    "mnemosyne.authoritative_runtime_module_paths()\n"
                    "if mnemosyne._safety_core.require_safe_tree.__code__.co_argcount != 4:\n"
                    "    raise SystemExit(9)\n"
                    "print('source-only')\n",
                ],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(probe.returncode, 0, probe.stderr + probe.stdout)
            self.assertEqual(probe.stdout, "source-only\n")

    def test_runtime_module_bootstrap_failure_has_stable_cli_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            install_root = Path(tmp).resolve() / "install"
            install_root.mkdir(parents=True, mode=0o700)
            source = Path(mnemosyne.__file__).resolve()
            (install_root / "mnemosyne.py").write_bytes(source.read_bytes())
            env = dict(os.environ)
            env["PYTHONPATH"] = str(install_root)
            env["PYTHONPYCACHEPREFIX"] = str(Path(tmp).resolve() / "pycache")

            probe = subprocess.run(
                [sys.executable, "-c", "import mnemosyne"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(probe.returncode, 2)
            self.assertEqual(probe.stdout, "")
            self.assertEqual(
                probe.stderr,
                "error: verified Mnemosyne core could not be loaded\n",
            )

    def test_runtime_module_bootstrap_rejects_import_outside_verified_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            install_root = Path(tmp).resolve() / "install"
            package_root = install_root / "mnemosyne_core"
            package_root.mkdir(parents=True, mode=0o700)
            source_root = Path(mnemosyne.__file__).resolve().parent
            (install_root / "mnemosyne.py").write_bytes(
                (source_root / "mnemosyne.py").read_bytes()
            )
            for _module_name, name, _is_package in mnemosyne.RUNTIME_MODULE_CLOSURE:
                target = package_root / name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(
                    (source_root / "mnemosyne_core" / name).read_bytes()
                )
            canonical = package_root / "canonical_json.py"
            canonical.write_text(
                canonical.read_text(encoding="utf-8")
                + "\nfrom . import unexpected_core_dependency\n",
                encoding="utf-8",
            )
            (package_root / "unexpected_core_dependency.py").write_text(
                "UNVERIFIED = True\n",
                encoding="utf-8",
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(install_root)
            env["PYTHONDONTWRITEBYTECODE"] = "1"

            probe = subprocess.run(
                [sys.executable, "-c", "import mnemosyne"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(probe.returncode, 2)
            self.assertEqual(probe.stdout, "")
            self.assertEqual(
                probe.stderr,
                "error: verified Mnemosyne core could not be loaded\n",
            )

    def run_cli(self, *args):
        args = list(args)
        if args[:2] == ["curation", "preview-lock-migration"] and "--entrypoint-manifest" not in args:
            root = Path(args[args.index("--root") + 1]).resolve()
            manifest = self.write_entrypoint_manifest(root)
            args.extend(["--entrypoint-manifest", str(manifest)])
        return self.run_cli_exact(*args)

    def legacy_command_args(self, args):
        """Map historical test vectors to direct command-function arguments."""
        command, *tokens = args
        options: dict[str, object] = {}
        positionals: list[str] = []
        boolean_options = {
            "--apply",
            "--dry-run",
            "--allow-unknown",
            "--json",
            "--maintenance-window-confirmed",
            "--with-graphify",
        }
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in boolean_options:
                options[token] = True
            elif token.startswith("--"):
                index += 1
                value = tokens[index]
                if token == "--ref":
                    options.setdefault(token, []).append(value)
                else:
                    options[token] = value
            else:
                positionals.append(token)
            index += 1

        def namespace(func, **values):
            return argparse.Namespace(func=func, **values)

        root = options.get("--root")
        if command == "bootstrap":
            return namespace(mnemosyne._legacy_bootstrap, root=root)
        if command == "propose-place":
            return namespace(
                mnemosyne._legacy_propose_place,
                source=positionals[0],
                target=options.get("--target"),
                reason=options.get("--reason"),
                actor=options.get("--actor", "operator"),
                root=root,
            )
        if command == "list-pending":
            return namespace(
                mnemosyne._legacy_list_pending,
                root=root,
                json=bool(options.get("--json")),
            )
        if command in {"approve", "reject"}:
            return namespace(
                mnemosyne._legacy_approve
                if command == "approve"
                else mnemosyne._legacy_reject,
                proposal_id=positionals[0],
                actor=options.get("--actor", "operator"),
                root=root,
            )
        if command == "audit":
            return namespace(
                mnemosyne._legacy_audit,
                root=root,
                scope=options.get("--scope"),
                max_depth=int(options.get("--max-depth", 2)),
                limit=int(options.get("--limit", 50)),
            )
        if command == "memory-sync":
            return namespace(
                mnemosyne.command_memory_sync,
                workspace=options.get("--workspace"),
                title=options.get("--title"),
                summary=options.get("--summary"),
                ref=options.get("--ref", []),
                workstream=options.get("--workstream"),
                approval_review=options.get("--approval-review"),
                plan_out=options.get("--plan-out"),
                apply_plan=options.get("--apply-plan"),
                render_approval_card=options.get("--render-approval-card"),
                expected_plan_sha256=options.get("--expected-plan-sha256"),
                actor=options.get("--actor", "local-operator"),
                apply=bool(options.get("--apply")),
                dry_run=bool(options.get("--dry-run")),
                allow_unknown=bool(options.get("--allow-unknown")),
                root=root,
            )
        if command == "context":
            return namespace(
                mnemosyne.command_context,
                workspace=options.get("--workspace"),
                question=options.get("--question"),
                history=int(options.get("--history", 5)),
                max_chars=int(options.get("--max-chars", 12000)),
                with_graphify=bool(options.get("--with-graphify")),
                json=bool(options.get("--json")),
                allow_unknown=bool(options.get("--allow-unknown")),
                root=root,
            )
        if command == "curation":
            operation = positionals.pop(0)
            if operation == "preview-lock-migration":
                return namespace(
                    mnemosyne._legacy_preview_lock_migration,
                    requested_by=options.get("--requested-by"),
                    entrypoint_manifest=options.get("--entrypoint-manifest"),
                    root=root,
                    json=bool(options.get("--json")),
                )
            return namespace(
                mnemosyne._legacy_apply_lock_migration,
                proposal_id=options.get("--proposal-id"),
                proposal_sha256=options.get("--proposal-sha256"),
                approved_by=options.get("--approved-by"),
                executed_by=options.get("--resumed-by"),
                maintenance_window_confirmed=bool(
                    options.get("--maintenance-window-confirmed")
                ),
                root=root,
                json=bool(options.get("--json")),
                resume=operation == "resume-lock-migration",
            )
        self.fail(f"unmapped direct test command: {command}")

    def run_cli_exact(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        authoritative_roots = getattr(
            self,
            "authoritative_entrypoint_roots",
            [Path(mnemosyne.__file__).resolve().parent],
        )
        authoritative_instructions = getattr(self, "authoritative_entrypoint_instructions", [])
        authoritative_runtime_modules = getattr(
            self,
            "authoritative_runtime_modules",
            mnemosyne.authoritative_runtime_module_paths(),
        )
        authoritative_runtime_modules = sorted(
            (path.resolve() for path in authoritative_runtime_modules),
            key=str,
        )
        with mock.patch.object(
            mnemosyne,
            "authoritative_entrypoint_discovery_roots",
            return_value=authoritative_roots,
        ), mock.patch.object(
            mnemosyne,
            "authoritative_entrypoint_instruction_surfaces",
            return_value=authoritative_instructions,
        ), mock.patch.object(
            mnemosyne,
            "authoritative_runtime_module_paths",
            return_value=authoritative_runtime_modules,
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            command_args = self.legacy_command_args(list(args))
            try:
                code = command_args.func(command_args)
            except mnemosyne.MnemosyneError as exc:
                print(f"error: {exc}", file=sys.stderr)
                code = 2
        return code, stdout.getvalue(), stderr.getvalue()

    def canonical_entrypoint_path(self) -> Path:
        module_file = mnemosyne.__file__
        if not isinstance(module_file, str):
            raise AssertionError("mnemosyne module has no source path")
        return Path(module_file).resolve()

    def write_entrypoint_manifest(
        self,
        root: Path,
        *,
        discovery_roots=None,
        retired_paths=None,
    ) -> Path:
        entrypoint = self.canonical_entrypoint_path()
        control_launcher = entrypoint.parent / "mnemosyne-control"
        runtime_modules = getattr(
            self,
            "authoritative_runtime_modules",
            mnemosyne.authoritative_runtime_module_paths(),
        )
        manifest = {
            "schema_version": 3,
            "kind": "MNEMOSYNE_INSTALLED_ENTRYPOINTS",
            "compatibility_version": mnemosyne.MNEMOSYNE_COMPATIBILITY_VERSION,
            "declared_by": "test-installer",
            "coverage_complete": True,
            "canonical_writer": {
                "path": str(entrypoint),
                "sha256": hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
            },
            "writer_aliases": [],
            "instruction_surfaces": [],
            "launchers": [
                {
                    "kind": "mnemosyne-control-v1",
                    "path": str(control_launcher),
                    "sha256": hashlib.sha256(control_launcher.read_bytes()).hexdigest(),
                    "delegates_to": str(entrypoint),
                }
            ],
            "launcher_aliases": [],
            "discovery_roots": [
                str(path.resolve()) for path in (discovery_roots or [entrypoint.parent])
            ],
            "retired_paths": [str(path.resolve()) for path in (retired_paths or [])],
            "runtime_modules": [
                {
                    "path": str(path.resolve()),
                    "sha256": hashlib.sha256(path.resolve().read_bytes()).hexdigest(),
                }
                for path in sorted(runtime_modules, key=lambda value: str(value.resolve()))
            ],
        }
        path = root / "_registry" / "lock-migrations" / "installed-entrypoints.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def use_copied_runtime_modules(self, root: Path) -> list[Path]:
        runtime_root = root / "installed-runtime"
        runtime_root.mkdir(mode=0o700)
        runtime_paths: list[Path] = []
        for index, source in enumerate(mnemosyne.authoritative_runtime_module_paths()):
            target = runtime_root / f"{index}-{source.name}"
            target.write_bytes(source.read_bytes())
            target.chmod(0o600)
            runtime_paths.append(target.resolve())
        self.authoritative_runtime_modules = runtime_paths
        return runtime_paths

    def manual_recovery_record(self, root: Path):
        return mnemosyne.ManualRecoveryRequired(
            "test manual recovery blocker",
            source=root / "inbox" / "blocked-source.md",
            target=root / "docs" / "blocked-target.md",
            reason="test-open-blocker",
            expected_source_identity=(1, 2, 3),
            observed_target_identity=None,
        )

    def publish_manual_recovery_blocker(self, root: Path) -> Path:
        recovery = self.manual_recovery_record(root)
        marker = (
            mnemosyne.manual_recovery_dir(root)
            / f"test-open-{mnemosyne.uuid.uuid4().hex}.json"
        )
        payload = {
            "schema_version": 1,
            "kind": "LEGACY_RENAME_MANUAL_RECOVERY",
            "status": "OPEN",
            "detected_at": mnemosyne.utc_now(),
            "source": str(recovery.source),
            "target": str(recovery.target),
            "reason": recovery.reason,
            "expected_source_identity": list(recovery.expected_source_identity),
            "observed_target_identity": None,
        }
        mnemosyne.publish_json_no_replace(marker, payload)
        return marker

    def start_guarded_blocker_publisher(self, root: Path):
        started = threading.Event()
        acquired = threading.Event()
        published = threading.Event()
        markers: list[Path] = []
        errors: list[BaseException] = []

        def publish() -> None:
            started.set()
            try:
                with mnemosyne.manual_recovery_guard(root) as guard:
                    acquired.set()
                    marker, _digest = mnemosyne.persist_manual_recovery_blocker(
                        guard,
                        self.manual_recovery_record(root),
                    )
                    markers.append(marker)
                    published.set()
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=publish, daemon=True)
        thread.start()
        return thread, started, acquired, published, markers, errors

    def write_memory_workspace(self, root: Path, workspace: str = "example-service"):
        memory_root = root / "memory"
        workspace_dir = memory_root / workspace
        workspace_dir.mkdir(parents=True)
        (memory_root / "workspaces.yml").write_text(
            "\n".join(
                [
                    "schema_version: 1",
                    "workspaces:",
                    f"  {workspace}:",
                    f"    root: {root / 'projects' / workspace}",
                    "    confirmed_at: 2026-07-09T00:00:00Z",
                    "    confirmation: test",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        snapshot = workspace_dir / "snapshot.md"
        snapshot.write_text(
            "\n".join(
                [
                    "---",
                    "schema_version: 1",
                    "workspace:",
                    f"  slug: {workspace}",
                    f"  root: {root / 'projects' / workspace}",
                    "updated_at: 2026-01-01T00:00:00Z",
                    "source_refs:",
                    "- existing-ref: keep-me",
                    "raw_log_policy: no raw command output",
                    "transcript_policy: summarized_only",
                    "redaction_policy: no credentials",
                    "---",
                    "",
                    f"# {workspace} Workspace Snapshot",
                    "",
                    "Existing body stays.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return snapshot

    def write_memory_sync_approval_review(
        self,
        root: Path,
        *,
        name: str = "approval-review.json",
    ) -> Path:
        review = {
            "schema": "mnemosyne-workspace-sync-approval-review-v1",
            "overview": "현재 확인된 구현과 CI 사실, 사용자 결정, 아직 실행으로 확인하지 않은 부분을 나눠 기록합니다.",
            "current_state_groups": [
                {
                    "title": "현재 저장소와 CI에서 확인된 사실",
                    "items": ["현재 source와 CI 확인은 실제 runtime 성공을 뜻하지 않습니다."],
                },
                {
                    "title": "사용자가 정한 운영 방향",
                    "items": ["승인된 workstream 경계 안에서만 최신 상태를 갱신합니다."],
                },
                {
                    "title": "아직 실제 실행으로 확인하지 않은 것",
                    "items": ["최신 revision의 runtime receipt와 readback은 이번 기록으로 단정하지 않습니다."],
                },
            ],
            "history_groups": [
                {
                    "title": "기존 기록에서 이어 가거나 바로잡는 내용",
                    "items": ["이번 대조 범위와 이전 기록의 차이를 history에 남깁니다."],
                }
            ],
            "exclusions": ["원본 명령 출력, 전체 문서 본문, credential과 endpoint"],
            "references": [
                {
                    "ref": "public-pr: example-service#123",
                    "role": "현재 구현과 CI를 대조한 자료",
                }
            ],
        }
        path = root / name
        path.write_text(
            json.dumps(review, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def write_history(self, root: Path, workspace: str, name: str, title: str, body: str):
        history_dir = root / "memory" / workspace / "history"
        history_dir.mkdir(parents=True, exist_ok=True)
        path = history_dir / name
        path.write_text(
            "\n".join(
                [
                    "---",
                    "schema_version: 1",
                    f"workspace: {workspace}",
                    "created_at: 2026-07-09T00:00:00Z",
                    "---",
                    "",
                    f"# {title}",
                    "",
                    body,
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return path

    def test_process_start_identity_is_stable_for_current_pid(self):
        first = mnemosyne.process_start_identity(os.getpid())
        second = mnemosyne.process_start_identity(os.getpid())

        self.assertTrue(first)
        self.assertEqual(first, second)

    def test_process_identity_probe_distinguishes_alive_dead_and_pid_reuse(self):
        pid = os.getpid()
        identity = mnemosyne.process_start_identity(pid)

        alive = mnemosyne.probe_process_identity(pid, identity)
        reused = mnemosyne.probe_process_identity(pid, identity + "-different")
        absent = mnemosyne.probe_process_identity(99_999_999, "missing")

        self.assertEqual(alive["status"], "alive")
        self.assertEqual(alive["observed_start_identity"], identity)
        self.assertEqual(reused["status"], "dead")
        self.assertEqual(reused["reason"], "pid-reused")
        self.assertEqual(absent["status"], "dead")
        self.assertEqual(absent["reason"], "pid-absent")

    def test_process_identity_probe_is_ambiguous_when_live_pid_cannot_be_inspected(self):
        with mock.patch.object(
            mnemosyne,
            "process_start_identity",
            side_effect=mnemosyne.MnemosyneError("probe denied"),
        ), mock.patch.object(mnemosyne.os, "kill", side_effect=PermissionError("denied")):
            probe = mnemosyne.probe_process_identity(1234, "expected")

        self.assertEqual(probe["status"], "ambiguous")
        self.assertEqual(probe["reason"], "start-identity-unavailable")

    def test_shared_placement_lock_fails_fast_under_exclusive_contention(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "placement-map.lock"
            lock_path.write_text("", encoding="utf-8")
            first = os.open(lock_path, os.O_RDWR)
            second = os.open(lock_path, os.O_RDWR)
            try:
                mnemosyne.fcntl.flock(first, mnemosyne.fcntl.LOCK_EX | mnemosyne.fcntl.LOCK_NB)
                with self.assertRaisesRegex(mnemosyne.MnemosyneError, "placement lock is busy"):
                    mnemosyne.acquire_shared_flock_nonblocking(second)
            finally:
                os.close(second)
                os.close(first)

    def test_shared_placement_lock_closes_lock_fd_if_registry_open_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock_path = root / "placement-map.lock"
            lock_path.write_bytes(b"")
            lock_fd = os.open(lock_path, os.O_RDWR)
            with mock.patch.object(
                mnemosyne,
                "require_no_active_lock_migration",
            ), mock.patch.object(
                mnemosyne,
                "open_placement_lock_verified",
                return_value=lock_fd,
            ), mock.patch.object(
                mnemosyne,
                "open_verified_directory",
                side_effect=mnemosyne.MnemosyneError("registry unavailable"),
            ):
                with self.assertRaisesRegex(mnemosyne.MnemosyneError, "registry unavailable"):
                    with mnemosyne.verified_shared_placement_lock(root):
                        self.fail("context should not yield")
            with self.assertRaises(OSError):
                os.fstat(lock_fd)

    def test_placement_lock_publish_rejects_symlinked_registry_parent(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside)
            (root / "_registry").symlink_to(outside_root, target_is_directory=True)
            payload = {
                "schema_version": 1,
                "kind": "PLACEMENT_COORDINATION_LOCK",
                "migration_id": "lockmig-test",
                "proposal_sha256": "a" * 64,
                "compatibility_version": mnemosyne.MNEMOSYNE_COMPATIBILITY_VERSION,
            }

            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "verified registry directory",
            ):
                mnemosyne.publish_placement_lock_no_replace(root, payload)

            self.assertFalse((outside_root / "placement-map.lock").exists())

    def test_sealed_json_publish_rejects_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside)
            (root / "sealed").symlink_to(outside_root, target_is_directory=True)

            with self.assertRaisesRegex(mnemosyne.MnemosyneError, "verified artifact parent"):
                mnemosyne.publish_json_no_replace(root / "sealed" / "artifact.json", {"safe": True})

            self.assertFalse((outside_root / "artifact.json").exists())

    def test_sealed_json_publish_rechecks_final_name_after_fd_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp).resolve() / "sealed" / "artifact.json"
            replacement = b'{"replacement":true}\n'

            def replace_named_artifact(path: Path, _fd: int, _directory_fd: int) -> None:
                path.unlink()
                path.write_bytes(replacement)
                path.chmod(0o600)

            with mock.patch.object(
                mnemosyne,
                "sealed_artifact_after_fd_readback",
                replace_named_artifact,
            ):
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "sealed artifact final identity changed",
                ):
                    mnemosyne.publish_json_no_replace(target, {"safe": True})

            self.assertEqual(target.read_bytes(), replacement)

    def test_sealed_json_partial_write_never_exposes_final_and_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp).resolve() / "sealed" / "artifact.json"
            value = {"safe": True, "payload": "x" * 128}
            real_write = os.write
            write_calls = 0

            def partial_then_crash(fd: int, data: bytes) -> int:
                nonlocal write_calls
                write_calls += 1
                if write_calls == 1:
                    return real_write(fd, data[: max(1, len(data) // 2)])
                raise OSError("injected write crash")

            with mock.patch.object(mnemosyne.os, "write", partial_then_crash):
                with self.assertRaises(mnemosyne.MnemosyneError):
                    mnemosyne.publish_json_no_replace(target, value)

            self.assertFalse(os.path.lexists(target))
            staging = list(target.parent.glob(f".{target.name}.incomplete-*"))
            self.assertEqual(len(staging), 1)

            digest = mnemosyne.publish_json_no_replace(target, value)

            expected = mnemosyne.canonical_json_bytes(value)
            self.assertEqual(target.read_bytes(), expected)
            self.assertEqual(digest, hashlib.sha256(expected).hexdigest())
            self.assertFalse(staging[0].exists())

    def test_bootstrap_creates_registry_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code, stdout, stderr = self.run_cli("bootstrap", "--root", str(root))

            resolved_root = root.resolve()
            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertEqual(
                stdout,
                "\n".join(
                    [
                        f"bootstrap created: {resolved_root / '_registry' / 'placement-map.yml'}",
                        f"pending: {resolved_root / '_registry' / 'pending'}",
                        f"decisions: {resolved_root / '_registry' / 'decisions'}",
                        f"inbox: {resolved_root / 'inbox'}",
                        "",
                    ]
                ),
            )
            self.assertTrue((root / "_registry" / "placement-map.yml").is_file())
            self.assertTrue((root / "_registry" / "pending").is_dir())
            self.assertTrue((root / "_registry" / "decisions").is_dir())
            self.assertTrue((root / "inbox").is_dir())

    def test_bootstrap_retries_partial_registry_staging_without_exposing_final(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_write = os.write
            write_calls = 0

            def partial_then_crash(fd: int, data: bytes) -> int:
                nonlocal write_calls
                write_calls += 1
                if write_calls == 1:
                    return real_write(fd, data[: max(1, len(data) // 2)])
                raise OSError("injected registry write crash")

            with mock.patch.object(mnemosyne.os, "write", partial_then_crash):
                code, stdout, stderr = self.run_cli("bootstrap", "--root", str(root))

            registry = root / "_registry" / "placement-map.yml"
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertFalse(os.path.lexists(registry))
            self.assertEqual(
                len(list(registry.parent.glob(f".{registry.name}.incomplete-*"))),
                1,
            )

            code, stdout, stderr = self.run_cli("bootstrap", "--root", str(root))

            self.assertEqual(code, 0, stderr)
            self.assertTrue(registry.is_file())
            self.assertIn("bootstrap created", stdout)

    def test_existing_registry_bootstrap_stops_during_lock_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            inbox = root / "inbox"
            inbox.rmdir()
            marker = root / "_registry" / "lock-migrations" / "active"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("{}\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli("bootstrap", "--root", str(root))

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: lock migration is active; legacy placement writes are blocked\n",
            )
            self.assertFalse(inbox.exists())

    def test_bootstrap_rejects_dangling_registry_symlink_without_outside_write(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_target = Path(outside) / "missing-placement-map.yml"
            registry_directory = root / "_registry"
            registry_directory.mkdir()
            registry = registry_directory / "placement-map.yml"
            registry.symlink_to(outside_target)

            code, stdout, stderr = self.run_cli("bootstrap", "--root", str(root))

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("registry", stderr)
            self.assertTrue(registry.is_symlink())
            self.assertFalse(outside_target.exists())
            self.assertFalse((root / "inbox").exists())

    def test_bootstrap_never_recreates_registry_after_completed_lock_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            registry = root / "_registry" / "placement-map.yml"
            registry.unlink()
            placement_lock = Path(proposal["paths"]["placement_lock"])
            completed_marker = Path(proposal["paths"]["completed_marker"])
            before = (placement_lock.read_bytes(), completed_marker.read_bytes())

            code, stdout, stderr = self.run_cli("bootstrap", "--root", str(root))

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("coordination state", stderr)
            self.assertFalse(registry.exists())
            self.assertEqual(before, (placement_lock.read_bytes(), completed_marker.read_bytes()))

    def test_propose_list_and_reject_leave_source_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "note.md"
            source.write_text("hello\n", encoding="utf-8")
            target = root / "docs" / "note.md"

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--reason",
                "manual test",
                "--actor",
                "tester",
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            self.assertEqual(stdout, f"created proposal {proposal_id}\n")
            self.assertTrue(source.exists())
            self.assertEqual(len(list((root / "_registry" / "pending").glob("*.yml"))), 1)

            code, pending, stderr = self.run_cli("list-pending", "--root", str(root))
            proposal = mnemosyne.load_flat_yaml(root / "_registry" / "pending" / f"{proposal_id}.yml")
            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertEqual(
                pending,
                "\n".join(
                    [
                        "pending proposals",
                        f"{proposal_id} | {proposal['created_at']} | {proposal['source']} -> {proposal['target']} | manual test",
                        "",
                    ]
                ),
            )

            code, stdout, stderr = self.run_cli("reject", proposal_id, "--actor", "tester", "--root", str(root))
            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertEqual(stdout, f"rejected {proposal_id}\n")
            self.assertTrue(source.exists())
            self.assertFalse(target.exists())
            self.assertEqual(len(list((root / "_registry" / "pending").glob("*.yml"))), 0)
            self.assertEqual(len(list((root / "_registry" / "decisions").glob("*.yml"))), 1)

    def test_approve_moves_file_and_writes_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "meeting.md"
            source.write_text("notes\n", encoding="utf-8")
            target = root / "projects" / "example-project" / "meeting.md"

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--reason",
                "project meeting",
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]

            code, stdout, stderr = self.run_cli("approve", proposal_id, "--actor", "tester", "--root", str(root))

            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertEqual(stdout, f"approved {proposal_id} -> {target.resolve()}\n")
            self.assertFalse(source.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "notes\n")
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])
            decisions = list((root / "_registry" / "decisions").glob("*.yml"))
            self.assertEqual(len(decisions), 1)
            decision = mnemosyne.load_flat_yaml(decisions[0])
            self.assertEqual(decision["proposal_id"], proposal_id)
            self.assertEqual(decision["decision"], "approved")
            self.assertEqual(decision["source"], str(source.resolve(strict=False)))
            self.assertEqual(decision["target"], str(target.resolve()))

    def test_approve_refuses_target_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "duplicate.md"
            target = root / "docs" / "duplicate.md"
            target.parent.mkdir(parents=True)
            source.write_text("new\n", encoding="utf-8")
            target.write_text("old\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]

            code, _, stderr = self.run_cli("approve", proposal_id, "--root", str(root))

            self.assertEqual(code, 2)
            self.assertIn("target already exists", stderr)
            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")

    def test_approve_never_replaces_target_created_after_precheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "racing-target.md"
            target = root / "docs" / source.name
            source.write_text("source\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]

            def create_competitor(_source: Path, publish_target: Path) -> None:
                publish_target.parent.mkdir(parents=True, exist_ok=True)
                publish_target.write_text("competitor\n", encoding="utf-8")

            with mock.patch.object(
                mnemosyne,
                "legacy_approve_before_target_publish",
                create_competitor,
            ):
                code, stdout, stderr = self.run_cli(
                    "approve",
                    proposal_id,
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, f"error: target already exists: {target.resolve()}\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "competitor\n")
            self.assertEqual(source.read_text(encoding="utf-8"), "source\n")
            self.assertTrue((root / "_registry" / "pending" / f"{proposal_id}.yml").is_file())

    def test_approve_rejects_source_replaced_after_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "racing-source.md"
            target = root / "docs" / source.name
            displaced = root / "inbox" / "racing-source.original"
            source.write_text("original\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place", str(source), "--target", str(target),
                "--root", str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]

            def replace_source(publish_source: Path, _target: Path) -> None:
                publish_source.rename(displaced)
                publish_source.write_text("replacement\n", encoding="utf-8")

            with mock.patch.object(
                mnemosyne,
                "legacy_approve_before_target_publish",
                replace_source,
            ):
                code, stdout, stderr = self.run_cli(
                    "approve", proposal_id, "--actor", "tester", "--root", str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("source tree identity changed", stderr)
            self.assertEqual(source.read_text(encoding="utf-8"), "replacement\n")
            self.assertEqual(displaced.read_text(encoding="utf-8"), "original\n")
            self.assertFalse(target.exists())
            self.assertTrue((root / "_registry" / "pending" / f"{proposal_id}.yml").is_file())
            self.assertEqual(list((root / "_registry" / "decisions").glob("*.yml")), [])

    def test_approve_rejects_directory_descendant_replaced_after_validation(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "source-tree"
            source.mkdir()
            child = source / "child.md"
            child.write_text("original child\n", encoding="utf-8")
            outside_file = Path(outside) / "outside.md"
            outside_file.write_text("outside must stay outside\n", encoding="utf-8")
            target = root / "docs" / source.name
            code, stdout, stderr = self.run_cli(
                "propose-place", str(source), "--target", str(target),
                "--root", str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]

            def replace_descendant(publish_source: Path, _target: Path) -> None:
                replaced_child = publish_source / "child.md"
                replaced_child.unlink()
                replaced_child.symlink_to(outside_file)

            with mock.patch.object(
                mnemosyne,
                "legacy_approve_before_target_publish",
                replace_descendant,
            ):
                code, stdout, stderr = self.run_cli(
                    "approve", proposal_id, "--actor", "tester", "--root", str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("source has a symlink descendant", stderr)
            self.assertTrue(source.is_dir())
            self.assertTrue(child.is_symlink())
            self.assertFalse(target.exists())
            self.assertTrue((root / "_registry" / "pending" / f"{proposal_id}.yml").is_file())
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "outside must stay outside\n")

    def test_approve_rejects_target_parent_identity_swap_before_rename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "parent-swap.md"
            target = root / "docs" / source.name
            displaced_parent = root / "docs-displaced"
            source.write_text("stay at source\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place", str(source), "--target", str(target),
                "--root", str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            swapped = False

            def swap_before_identity_check(path: Path, _fd: int, _label: str) -> None:
                nonlocal swapped
                if path == target.parent.resolve(strict=False) and not swapped:
                    swapped = True
                    path.rename(displaced_parent)
                    path.mkdir(mode=0o700)

            with mock.patch.object(
                mnemosyne,
                "safety_before_directory_identity_check",
                swap_before_identity_check,
            ):
                code, stdout, stderr = self.run_cli(
                    "approve", proposal_id, "--actor", "tester", "--root", str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("target directory identity changed", stderr)
            self.assertTrue(source.is_file())
            self.assertFalse(target.exists())
            self.assertFalse((displaced_parent / source.name).exists())
            self.assertTrue((root / "_registry" / "pending" / f"{proposal_id}.yml").is_file())

    def test_rename_compensates_target_parent_rename_out_between_check_and_effect(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp).resolve()
            outside_root = Path(outside).resolve()
            source_parent = root / "source"
            target_parent = root / "target"
            source_parent.mkdir(mode=0o700)
            target_parent.mkdir(mode=0o700)
            source = source_parent / "item.md"
            target = target_parent / source.name
            source.write_text("must return to source\n", encoding="utf-8")
            displaced_parent = outside_root / "displaced-target"
            original_rename = mnemosyne._safety_core.rename_entry_no_replace_at
            swapped = False

            def rename_after_parent_swap(*args, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    target_parent.rename(displaced_parent)
                    target_parent.mkdir(mode=0o700)
                return original_rename(*args, **kwargs)

            with mock.patch.object(
                mnemosyne._safety_core,
                "rename_entry_no_replace_at",
                side_effect=rename_after_parent_swap,
            ), mnemosyne.manual_recovery_guard(root) as recovery_guard:
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "target directory identity changed",
                ):
                    mnemosyne.rename_path_no_replace(
                        source,
                        target,
                        collision_error="target exists",
                        require_directory=False,
                        recovery_guard=recovery_guard,
                    )

            self.assertTrue(swapped)
            self.assertEqual(source.read_text(encoding="utf-8"), "must return to source\n")
            self.assertFalse(target.exists())
            self.assertFalse((displaced_parent / source.name).exists())

    def test_rename_reports_manual_recovery_if_compensation_source_is_recreated(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp).resolve()
            outside_root = Path(outside).resolve()
            source_parent = root / "source"
            target_parent = root / "target"
            source_parent.mkdir(mode=0o700)
            target_parent.mkdir(mode=0o700)
            source = source_parent / "item.md"
            target = target_parent / source.name
            source.write_text("original\n", encoding="utf-8")
            displaced_parent = outside_root / "displaced-target"
            original_rename = mnemosyne._safety_core.rename_entry_no_replace_at
            swapped = False

            def block_compensation_after_parent_swap(*args, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    target_parent.rename(displaced_parent)
                    target_parent.mkdir(mode=0o700)
                    result = original_rename(*args, **kwargs)
                    source.write_text("competitor\n", encoding="utf-8")
                    return result
                return original_rename(*args, **kwargs)

            with mock.patch.object(
                mnemosyne._safety_core,
                "rename_entry_no_replace_at",
                side_effect=block_compensation_after_parent_swap,
            ), mnemosyne.manual_recovery_guard(root) as recovery_guard:
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "rename effect requires manual recovery",
                ):
                    mnemosyne.rename_path_no_replace(
                        source,
                        target,
                        collision_error="target exists",
                        require_directory=False,
                        recovery_guard=recovery_guard,
                    )

            self.assertEqual(source.read_text(encoding="utf-8"), "competitor\n")
            self.assertEqual(
                (displaced_parent / source.name).read_text(encoding="utf-8"),
                "original\n",
            )

    def test_rename_compensation_refuses_replaced_target_without_moving_competitor(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp).resolve()
            outside_root = Path(outside).resolve()
            source_parent = root / "source"
            target_parent = root / "target"
            source_parent.mkdir(mode=0o700)
            target_parent.mkdir(mode=0o700)
            source = source_parent / "item.md"
            target = target_parent / source.name
            source.write_text("original\n", encoding="utf-8")
            displaced_parent = outside_root / "displaced-target"
            parked_original = displaced_parent / "parked-original.md"
            original_rename = mnemosyne._safety_core.rename_entry_no_replace_at
            runtime_modules = mnemosyne.authoritative_runtime_module_paths()
            swapped = False

            def replace_target_after_forward_rename(*args, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    target_parent.rename(displaced_parent)
                    target_parent.mkdir(mode=0o700)
                    result = original_rename(*args, **kwargs)
                    (displaced_parent / source.name).rename(parked_original)
                    (displaced_parent / source.name).write_text(
                        "competitor\n",
                        encoding="utf-8",
                    )
                    return result
                return original_rename(*args, **kwargs)

            with mock.patch.object(
                mnemosyne._safety_core,
                "rename_entry_no_replace_at",
                side_effect=replace_target_after_forward_rename,
            ), mock.patch.object(
                mnemosyne,
                "authoritative_runtime_module_paths",
                return_value=runtime_modules,
            ), mnemosyne.manual_recovery_guard(root) as recovery_guard:
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "rename effect requires manual recovery",
                ):
                    mnemosyne.rename_path_no_replace(
                        source,
                        target,
                        collision_error="target exists",
                        require_directory=False,
                        recovery_guard=recovery_guard,
                    )

            self.assertFalse(source.exists())
            self.assertEqual(parked_original.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(
                (displaced_parent / source.name).read_text(encoding="utf-8"),
                "competitor\n",
            )

    def test_rename_compensation_undoes_target_replacement_during_reverse_rename(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp).resolve()
            outside_root = Path(outside).resolve()
            source_parent = root / "source"
            target_parent = root / "target"
            source_parent.mkdir(mode=0o700)
            target_parent.mkdir(mode=0o700)
            source = source_parent / "item.md"
            target = target_parent / source.name
            source.write_text("original\n", encoding="utf-8")
            displaced_parent = outside_root / "displaced-target"
            parked_original = displaced_parent / "parked-original.md"
            original_rename = mnemosyne._safety_core.rename_entry_no_replace_at
            calls = 0

            def replace_target_during_reverse_rename(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    target_parent.rename(displaced_parent)
                    target_parent.mkdir(mode=0o700)
                    return original_rename(*args, **kwargs)
                if calls == 2:
                    (displaced_parent / source.name).rename(parked_original)
                    (displaced_parent / source.name).write_text(
                        "competitor\n",
                        encoding="utf-8",
                    )
                return original_rename(*args, **kwargs)

            with mock.patch.object(
                mnemosyne._safety_core,
                "rename_entry_no_replace_at",
                side_effect=replace_target_during_reverse_rename,
            ), mnemosyne.manual_recovery_guard(root) as recovery_guard:
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "rename effect requires manual recovery",
                ):
                    mnemosyne.rename_path_no_replace(
                        source,
                        target,
                        collision_error="target exists",
                        require_directory=False,
                        recovery_guard=recovery_guard,
                    )

            self.assertEqual(calls, 4)
            self.assertFalse(source.exists())
            self.assertEqual(parked_original.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(
                (displaced_parent / source.name).read_text(encoding="utf-8"),
                "competitor\n",
            )

    def test_approve_persists_manual_recovery_blocker_and_blocks_next_writer(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp).resolve()
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "manual-recovery.md"
            target = root / "docs" / source.name
            source.write_text("original\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            displaced_parent = outside_root / "displaced-docs"
            parked_original = displaced_parent / "parked-original.md"
            original_rename = mnemosyne._safety_core.rename_entry_no_replace_at
            runtime_modules = mnemosyne.authoritative_runtime_module_paths()
            swapped = False

            def replace_target_after_forward_rename(*args, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    target.parent.rename(displaced_parent)
                    target.parent.mkdir(mode=0o700)
                    result = original_rename(*args, **kwargs)
                    (displaced_parent / source.name).rename(parked_original)
                    (displaced_parent / source.name).write_text(
                        "competitor\n",
                        encoding="utf-8",
                    )
                    return result
                return original_rename(*args, **kwargs)

            with mock.patch.object(
                mnemosyne._safety_core,
                "rename_entry_no_replace_at",
                side_effect=replace_target_after_forward_rename,
            ), mock.patch.object(
                mnemosyne,
                "authoritative_runtime_module_paths",
                return_value=runtime_modules,
            ):
                code, stdout, stderr = self.run_cli(
                    "approve",
                    proposal_id,
                    "--actor",
                    "tester",
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("rename effect requires manual recovery", stderr)
            blocker_directory = (
                root / "_registry" / "lock-migrations" / "manual-recovery"
            )
            blockers = list(blocker_directory.glob("*.json"))
            self.assertEqual(len(blockers), 1)
            blocker_bytes = blockers[0].read_bytes()
            blocker = json.loads(blocker_bytes)
            self.assertEqual(stat.S_IMODE(blockers[0].stat().st_mode), 0o600)
            self.assertEqual(blocker_bytes, mnemosyne.canonical_json_bytes(blocker))
            self.assertEqual(blocker["kind"], "LEGACY_RENAME_MANUAL_RECOVERY")
            self.assertEqual(blocker["status"], "OPEN")
            self.assertEqual(blocker["source"], str(source))
            self.assertEqual(blocker["target"], str(target))
            self.assertEqual(blocker["reason"], "compensation-target-identity-mismatch")

            next_source = root / "inbox" / "must-be-blocked.md"
            next_source.write_text("blocked\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(next_source),
                "--target",
                str(root / "docs" / next_source.name),
                "--root",
                str(root),
            )
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("unresolved manual recovery blocker", stderr)
            self.assertEqual(
                list((root / "_registry" / "pending").glob("*.yml")),
                [root / "_registry" / "pending" / f"{proposal_id}.yml"],
            )

            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("unresolved manual recovery blocker", stderr)

    def test_verified_directory_create_rejects_parent_identity_swap_before_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "runs" / "run-1"
            target.parent.mkdir(mode=0o700)
            displaced_parent = root / "runs-displaced"
            swapped = False

            def swap_before_identity_check(path: Path, _fd: int, _label: str) -> None:
                nonlocal swapped
                if path == target.parent and not swapped:
                    swapped = True
                    path.rename(displaced_parent)
                    path.mkdir(mode=0o700)

            with mock.patch.object(
                mnemosyne,
                "safety_before_directory_identity_check",
                swap_before_identity_check,
            ):
                with self.assertRaisesRegex(
                    mnemosyne.MnemosyneError,
                    "run directory identity changed",
                ):
                    mnemosyne.create_verified_directory_no_replace(
                        target,
                        label="run",
                        collision_error="run exists",
                    )

            self.assertTrue(swapped)
            self.assertFalse(target.exists())
            self.assertFalse((displaced_parent / target.name).exists())

    def test_approve_rejects_remove_restore_placement_lock_aba_before_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            source = root / "inbox" / "work-aba.md"
            target = root / "docs" / source.name
            source.write_text("must remain\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place", str(source), "--target", str(target),
                "--root", str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            lock_path = root / "_registry" / "placement-map.lock"
            displaced_lock = lock_path.with_name("placement-map.lock.displaced")
            held_fds: list[int] = []
            original_verify = mnemosyne.verify_decision_readback

            def replace_lock(_source: Path, _target: Path) -> None:
                lock_path.rename(displaced_lock)
                lock_path.write_bytes(displaced_lock.read_bytes())
                lock_path.chmod(0o600)
                replacement_fd = os.open(lock_path, os.O_RDWR)
                mnemosyne.fcntl.flock(
                    replacement_fd,
                    mnemosyne.fcntl.LOCK_EX | mnemosyne.fcntl.LOCK_NB,
                )
                held_fds.append(replacement_fd)

            def restore_lock(*args, **kwargs) -> None:
                original_verify(*args, **kwargs)
                for held_fd in held_fds:
                    os.close(held_fd)
                held_fds.clear()
                lock_path.unlink()
                displaced_lock.rename(lock_path)

            try:
                with mock.patch.object(
                    mnemosyne,
                    "legacy_approve_before_target_publish",
                    replace_lock,
                ), mock.patch.object(
                    mnemosyne,
                    "verify_decision_readback",
                    restore_lock,
                ):
                    code, stdout, stderr = self.run_cli(
                        "approve", proposal_id, "--actor", "tester", "--root", str(root),
                    )
            finally:
                for held_fd in held_fds:
                    os.close(held_fd)
                if displaced_lock.exists():
                    if lock_path.exists():
                        lock_path.unlink()
                    displaced_lock.rename(lock_path)

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("placement lock identity changed", stderr)
            self.assertTrue(source.is_file())
            self.assertFalse(target.exists())
            self.assertTrue((root / "_registry" / "pending" / f"{proposal_id}.yml").is_file())

    def test_legacy_approve_fails_closed_when_lock_migration_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "blocked.md"
            target = root / "docs" / "blocked.md"
            source.write_text("keep me\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            pending = root / "_registry" / "pending" / f"{proposal_id}.yml"
            marker = root / "_registry" / "lock-migrations" / "active"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("{}\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli(
                "approve",
                proposal_id,
                "--actor",
                "tester",
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: lock migration is active; legacy placement writes are blocked\n",
            )
            self.assertEqual(source.read_text(encoding="utf-8"), "keep me\n")
            self.assertFalse(target.exists())
            self.assertTrue(pending.is_file())
            self.assertEqual(list((root / "_registry" / "decisions").glob("*.yml")), [])

    def test_legacy_propose_fails_closed_when_lock_migration_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "blocked-proposal.md"
            source.write_text("keep me\n", encoding="utf-8")
            marker = root / "_registry" / "lock-migrations" / "active"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("{}\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: lock migration is active; legacy placement writes are blocked\n",
            )
            self.assertEqual(source.read_text(encoding="utf-8"), "keep me\n")
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_legacy_reject_fails_closed_when_lock_migration_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "blocked-reject.md"
            source.write_text("keep me\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            pending = root / "_registry" / "pending" / f"{proposal_id}.yml"
            marker = root / "_registry" / "lock-migrations" / "active"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("{}\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli(
                "reject",
                proposal_id,
                "--actor",
                "tester",
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: lock migration is active; legacy placement writes are blocked\n",
            )
            self.assertTrue(pending.is_file())
            self.assertEqual(source.read_text(encoding="utf-8"), "keep me\n")
            self.assertEqual(list((root / "_registry" / "decisions").glob("*.yml")), [])

    def test_legacy_approve_rechecks_marker_after_writer_lease_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "lease-race.md"
            target = root / "docs" / "lease-race.md"
            source.write_text("keep me\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            pending = root / "_registry" / "pending" / f"{proposal_id}.yml"

            def publish_marker_after_lease(lease_root: Path, _lease_path: Path) -> None:
                marker = lease_root / "_registry" / "lock-migrations" / "active"
                marker.write_text("{}\n", encoding="utf-8")

            with mock.patch.object(
                mnemosyne,
                "legacy_writer_after_lease_create",
                publish_marker_after_lease,
                create=True,
            ):
                code, stdout, stderr = self.run_cli(
                    "approve",
                    proposal_id,
                    "--actor",
                    "tester",
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: lock migration is active; legacy placement writes are blocked\n",
            )
            self.assertEqual(source.read_text(encoding="utf-8"), "keep me\n")
            self.assertFalse(target.exists())
            self.assertTrue(pending.is_file())
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            self.assertTrue(lease_dir.is_dir())
            self.assertEqual(list(lease_dir.iterdir()), [])
            self.assertEqual(list((root / "_registry" / "decisions").glob("*.yml")), [])

    def test_legacy_writer_checkpoint_rejects_late_manual_recovery_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))

            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "unresolved manual recovery blocker",
            ):
                with mnemosyne.legacy_writer_lease(root, "test-writer") as checkpoint:
                    blocker = self.publish_manual_recovery_blocker(root)
                    self.assertTrue(blocker.is_file())
                    checkpoint()

            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            self.assertTrue(lease_dir.is_dir())
            self.assertEqual(list(lease_dir.iterdir()), [])

    def test_manual_recovery_gate_serializes_guarded_blocker_with_both_legacy_writer_modes(self):
        for completed_migration in (False, True):
            with self.subTest(completed_migration=completed_migration), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                self.run_cli("bootstrap", "--root", str(root))
                if completed_migration:
                    code, stdout, stderr = self.run_cli(
                        "curation",
                        "preview-lock-migration",
                        "--requested-by",
                        "tester",
                        "--root",
                        str(root),
                        "--json",
                    )
                    self.assertEqual(code, 0, stderr)
                    preview = json.loads(stdout)["registry_updates"][0]
                    migration = json.loads(
                        Path(preview["path"]).read_text(encoding="utf-8")
                    )
                    code, _stdout, stderr = self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        migration["migration_id"],
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )
                    self.assertEqual(code, 0, stderr)

                source = root / "inbox" / "serialized-rename.md"
                target = root / "docs" / source.name
                source.write_text("serialized\n", encoding="utf-8")
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(target),
                    "--root",
                    str(root),
                )
                self.assertEqual(code, 0, stderr)
                proposal_id = stdout.strip().splitlines()[-1].split()[-1]
                publisher_state = []

                def start_publisher(_source: Path, _target: Path) -> None:
                    state = self.start_guarded_blocker_publisher(root)
                    publisher_state.append(state)
                    _thread, started, acquired, _published, _markers, _errors = state
                    self.assertTrue(started.wait(1))
                    self.assertFalse(acquired.wait(0.05))

                with mock.patch.object(
                    mnemosyne,
                    "legacy_approve_before_target_publish",
                    start_publisher,
                ):
                    code, stdout, stderr = self.run_cli(
                        "approve",
                        proposal_id,
                        "--actor",
                        "tester",
                        "--root",
                        str(root),
                    )

                self.assertEqual(code, 0, stderr)
                self.assertTrue(stdout.startswith("approved "))
                self.assertEqual(len(publisher_state), 1)
                thread, _started, acquired, published, markers, errors = publisher_state[0]
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertTrue(acquired.is_set())
                self.assertTrue(published.is_set())
                self.assertEqual(len(markers), 1)
                self.assertTrue(markers[0].is_file())
                self.assertFalse(source.exists())
                self.assertTrue(target.is_file())
                self.assertEqual(
                    len(list((root / "_registry" / "decisions").glob("*.yml"))),
                    1,
                )

    def test_manual_recovery_gate_serializes_guarded_blocker_with_lock_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            publisher_state = []

            def start_publisher(
                name: str,
                _checkpoint_root: Path,
                _migration_id: str,
            ) -> None:
                if name != "active-marker-published":
                    return
                state = self.start_guarded_blocker_publisher(root)
                publisher_state.append(state)
                _thread, started, acquired, _published, _markers, _errors = state
                self.assertTrue(started.wait(1))
                self.assertFalse(acquired.wait(0.05))

            with mock.patch.object(
                mnemosyne,
                "lock_migration_checkpoint",
                start_publisher,
            ):
                code, stdout, stderr = self.run_cli_exact(
                    "curation",
                    "apply-lock-migration",
                    "--proposal-id",
                    proposal["migration_id"],
                    "--proposal-sha256",
                    preview["sha256"],
                    "--approved-by",
                    "tester",
                    "--maintenance-window-confirmed",
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["mode"], "apply-lock-migration")
            self.assertEqual(len(publisher_state), 1)
            thread, _started, acquired, published, markers, errors = publisher_state[0]
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertTrue(acquired.is_set())
            self.assertTrue(published.is_set())
            self.assertEqual(len(markers), 1)
            self.assertTrue(markers[0].is_file())
            self.assertFalse(Path(proposal["paths"]["active_marker"]).exists())
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())

    def test_legacy_propose_holds_owner_only_writer_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "leased-proposal.md"
            target = root / "docs" / source.name
            source.write_text("proposal\n", encoding="utf-8")
            registry = root / "_registry" / "placement-map.yml"
            observed: list[tuple[Path, dict]] = []

            def inspect_lease(lease_root: Path, lease_path: Path) -> None:
                self.assertEqual(lease_root, root.resolve())
                self.assertEqual(stat.S_IMODE(lease_path.stat().st_mode), 0o600)
                payload = json.loads(lease_path.read_text(encoding="utf-8"))
                self.assertEqual(payload["schema_version"], 1)
                self.assertEqual(payload["pid"], os.getpid())
                self.assertTrue(payload["process_start_identity"])
                self.assertEqual(payload["command"], "propose-place")
                self.assertEqual(
                    payload["registry_sha256"],
                    hashlib.sha256(registry.read_bytes()).hexdigest(),
                )
                observed.append((lease_path, payload))

            with mock.patch.object(mnemosyne, "legacy_writer_after_lease_create", inspect_lease):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(target),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(len(observed), 1)
            lease_path, _payload = observed[0]
            self.assertFalse(lease_path.exists())
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            self.assertTrue((root / "_registry" / "pending" / f"{proposal_id}.yml").is_file())

    def test_legacy_writer_blocks_dangling_active_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            migration_root = root / "_registry" / "lock-migrations"
            migration_root.mkdir(parents=True)
            (migration_root / "active").symlink_to(migration_root / "missing-marker")
            source = root / "inbox" / "dangling-active.md"
            source.write_text("stay\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: lock migration is active; legacy placement writes are blocked\n",
            )
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_legacy_writer_rejects_symlinked_lease_directory_before_creating_lease(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            migration_root = root / "_registry" / "lock-migrations"
            migration_root.mkdir(parents=True)
            (migration_root / "legacy-leases").symlink_to(outside_root, target_is_directory=True)
            source = root / "inbox" / "symlinked-lease.md"
            source.write_text("stay\n", encoding="utf-8")
            observed = []

            def observe_outside_lease(_root: Path, _lease_path: Path) -> None:
                observed.extend(outside_root.iterdir())

            with mock.patch.object(
                mnemosyne,
                "legacy_writer_after_lease_create",
                observe_outside_lease,
            ):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(root / "docs" / source.name),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: cannot open verified legacy lease directory\n",
            )
            self.assertEqual(observed, [])
            self.assertEqual(list(outside_root.iterdir()), [])
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_legacy_writer_rejects_migration_root_swap_before_yield(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "hidden-lease.md"
            source.write_text("stay\n", encoding="utf-8")
            migration_root = root / "_registry" / "lock-migrations"
            hidden_root = root / "_registry" / "lock-migrations-hidden"
            original_check = mnemosyne.require_no_active_lock_migration
            checks = 0

            def swap_on_second_check(check_root: Path) -> None:
                nonlocal checks
                checks += 1
                if checks == 2:
                    migration_root.rename(hidden_root)
                    migration_root.mkdir(mode=0o700)
                original_check(check_root)

            with mock.patch.object(
                mnemosyne,
                "require_no_active_lock_migration",
                side_effect=swap_on_second_check,
            ):
                code, stdout, stderr = self.run_cli_exact(
                    "propose-place",
                    str(source),
                    "--target",
                    str(root / "docs" / source.name),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("legacy lease directory identity changed", stderr)
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])
            hidden_leases = hidden_root / "legacy-leases"
            self.assertTrue(hidden_leases.is_dir())
            self.assertEqual(len(list(hidden_leases.iterdir())), 1)

    def test_legacy_propose_detects_pending_readback_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "tampered-proposal.md"
            source.write_text("proposal\n", encoding="utf-8")
            original_write = mnemosyne.write_flat_yaml

            def corrupt_pending(path: Path, data: dict) -> None:
                original_write(path, data)
                if path.parent.name == "pending":
                    with path.open("a", encoding="utf-8") as handle:
                        handle.write('reason: "tampered"\n')

            with mock.patch.object(mnemosyne, "write_flat_yaml", corrupt_pending):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(root / "docs" / source.name),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "error: pending proposal readback mismatch\n")
            self.assertTrue(source.is_file())

    def test_legacy_reject_holds_writer_lease_until_decision_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "leased-reject.md"
            source.write_text("reject\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            pending = root / "_registry" / "pending" / f"{proposal_id}.yml"
            observed: list[Path] = []

            def inspect_lease(_lease_root: Path, lease_path: Path) -> None:
                payload = json.loads(lease_path.read_text(encoding="utf-8"))
                self.assertEqual(payload["command"], "reject")
                self.assertTrue(pending.is_file())
                observed.append(lease_path)

            with mock.patch.object(mnemosyne, "legacy_writer_after_lease_create", inspect_lease):
                code, stdout, stderr = self.run_cli(
                    "reject",
                    proposal_id,
                    "--actor",
                    "tester",
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(stdout, f"rejected {proposal_id}\n")
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].exists())
            self.assertFalse(pending.exists())
            decisions = list((root / "_registry" / "decisions").glob("*.yml"))
            self.assertEqual(len(decisions), 1)
            self.assertEqual(mnemosyne.load_flat_yaml(decisions[0])["decision"], "rejected")

    def test_legacy_reject_keeps_pending_when_decision_readback_mismatches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "tampered-decision.md"
            source.write_text("reject\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            pending = root / "_registry" / "pending" / f"{proposal_id}.yml"
            original_write_decision = mnemosyne.write_decision

            def corrupt_decision(*args, **kwargs):
                decision_path = original_write_decision(*args, **kwargs)
                with decision_path.open("a", encoding="utf-8") as handle:
                    handle.write('decision: "tampered"\n')
                return decision_path

            with mock.patch.object(mnemosyne, "write_decision", corrupt_decision):
                code, stdout, stderr = self.run_cli(
                    "reject",
                    proposal_id,
                    "--actor",
                    "tester",
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "error: decision readback mismatch\n")
            self.assertTrue(pending.is_file())
            self.assertTrue(source.is_file())

    def test_legacy_propose_stops_if_placement_lock_appears_after_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "lock-race.md"
            source.write_text("keep me\n", encoding="utf-8")

            def publish_lock_after_lease(lease_root: Path, _lease_path: Path) -> None:
                lock_path = lease_root / "_registry" / "placement-map.lock"
                lock_path.write_text("", encoding="utf-8")
                lock_path.chmod(0o600)

            with mock.patch.object(
                mnemosyne,
                "legacy_writer_after_lease_create",
                publish_lock_after_lease,
            ):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(root / "docs" / source.name),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: placement lock changed during legacy writer lease; retry required\n",
            )
            self.assertEqual(source.read_text(encoding="utf-8"), "keep me\n")
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_legacy_propose_never_writes_through_symlinked_pending_directory(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            pending = root / "_registry" / "pending"
            original_pending = root / "_registry" / "pending-original"
            pending.rename(original_pending)
            pending.symlink_to(outside_root, target_is_directory=True)
            source = root / "inbox" / "pending-parent.md"
            source.write_text("stay\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli_exact(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("verified pending proposal parent", stderr)
            self.assertEqual(list(outside_root.iterdir()), [])
            self.assertEqual(list(original_pending.iterdir()), [])

    def test_legacy_reject_never_writes_through_symlinked_decision_directory(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "decision-parent.md"
            source.write_text("stay\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            pending_path = root / "_registry" / "pending" / f"{proposal_id}.yml"
            decisions = root / "_registry" / "decisions"
            original_decisions = root / "_registry" / "decisions-original"
            decisions.rename(original_decisions)
            decisions.symlink_to(outside_root, target_is_directory=True)

            code, stdout, stderr = self.run_cli_exact(
                "reject",
                proposal_id,
                "--actor",
                "tester",
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("verified decision parent", stderr)
            self.assertTrue(pending_path.is_file())
            self.assertEqual(list(outside_root.iterdir()), [])

    def test_legacy_reject_never_deletes_replaced_pending_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "pending-swap.md"
            source.write_text("stay\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            pending_path = root / "_registry" / "pending" / f"{proposal_id}.yml"
            displaced = pending_path.with_suffix(".original")
            original_verify = mnemosyne.verify_decision_readback

            def replace_after_decision(path: Path, proposal: dict, decision: str, actor: str) -> None:
                original_verify(path, proposal, decision, actor)
                pending_path.rename(displaced)
                pending_path.write_text("competitor: keep\n", encoding="utf-8")

            with mock.patch.object(
                mnemosyne,
                "verify_decision_readback",
                side_effect=replace_after_decision,
            ):
                code, stdout, stderr = self.run_cli_exact(
                    "reject",
                    proposal_id,
                    "--actor",
                    "tester",
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("pending proposal identity changed", stderr)
            self.assertEqual(pending_path.read_text(encoding="utf-8"), "competitor: keep\n")
            self.assertTrue(displaced.is_file())

    def test_legacy_reject_refuses_decision_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "decision-collision.md"
            source.write_text("stay\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            pending_path = root / "_registry" / "pending" / f"{proposal_id}.yml"
            collision = root / "_registry" / "decisions" / "rejected-fixed.yml"
            collision.write_text("competitor: keep\n", encoding="utf-8")

            with mock.patch.object(mnemosyne, "make_id", return_value="rejected-fixed"):
                code, stdout, stderr = self.run_cli_exact(
                    "reject",
                    proposal_id,
                    "--actor",
                    "tester",
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("refusing to overwrite decision", stderr)
            self.assertEqual(collision.read_text(encoding="utf-8"), "competitor: keep\n")
            self.assertTrue(pending_path.is_file())

    def test_legacy_reject_rejects_invalid_proposal_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))

            code, stdout, stderr = self.run_cli_exact(
                "reject",
                "../outside",
                "--actor",
                "tester",
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "error: invalid proposal id\n")
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            self.assertEqual(list(lease_dir.iterdir()), [])

    def test_legacy_writer_never_deletes_or_writes_through_replaced_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "replaced-lease.md"
            source.write_text("keep me\n", encoding="utf-8")
            replaced: list[Path] = []

            def replace_lease(_lease_root: Path, lease_path: Path) -> None:
                lease_path.unlink()
                lease_path.write_text("replacement\n", encoding="utf-8")
                replaced.append(lease_path)

            with mock.patch.object(mnemosyne, "legacy_writer_after_lease_create", replace_lease):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(root / "docs" / source.name),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(len(replaced), 1)
            self.assertEqual(
                stderr,
                f"error: legacy writer lease identity changed: {replaced[0]}\n",
            )
            self.assertEqual(replaced[0].read_text(encoding="utf-8"), "replacement\n")
            self.assertEqual(source.read_text(encoding="utf-8"), "keep me\n")
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_legacy_writer_closes_uninspectable_new_lease_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "uninspectable-lease.md"
            source.write_text("keep me\n", encoding="utf-8")
            original_open = mnemosyne.os.open
            original_fstat = mnemosyne.os.fstat
            lease_fd: list[int] = []

            def capture_new_lease(path, flags, *args, **kwargs):
                fd = original_open(path, flags, *args, **kwargs)
                if (
                    isinstance(path, str)
                    and path.startswith(f"{os.getpid()}-")
                    and flags & os.O_EXCL
                ):
                    lease_fd.append(fd)
                return fd

            def fail_new_lease_fstat(fd):
                if lease_fd and fd == lease_fd[0]:
                    raise OSError("injected lease fstat failure")
                return original_fstat(fd)

            with mock.patch.object(
                mnemosyne.os,
                "open",
                side_effect=capture_new_lease,
            ), mock.patch.object(
                mnemosyne.os,
                "fstat",
                side_effect=fail_new_lease_fstat,
            ):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(root / "docs" / source.name),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("cannot inspect new legacy writer lease", stderr)
            self.assertEqual(len(lease_fd), 1)
            with self.assertRaises(OSError):
                original_fstat(lease_fd[0])
            self.assertEqual(source.read_text(encoding="utf-8"), "keep me\n")
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])
            self.assertEqual(
                len(list((root / "_registry" / "lock-migrations" / "legacy-leases").iterdir())),
                1,
            )

    def test_preview_lock_migration_requires_installed_entrypoint_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: lock migration preview requires an installed entrypoint manifest\n",
            )

    def test_preview_lock_migration_requires_exact_runtime_module_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            manifest_path = self.write_entrypoint_manifest(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["runtime_modules"] = manifest["runtime_modules"][:-1]
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: installed runtime module closure is invalid\n",
            )

    def test_preview_lock_migration_rejects_symlinked_registry(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            registry = root / "_registry" / "placement-map.yml"
            outside_registry = Path(outside) / "placement-map.yml"
            outside_registry.write_bytes(registry.read_bytes())
            registry.unlink()
            registry.symlink_to(outside_registry)

            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("registry", stderr)
            proposal_root = root / "_registry" / "lock-migrations" / "proposals"
            self.assertFalse(proposal_root.exists() and any(proposal_root.iterdir()))

    def test_apply_lock_migration_rejects_registry_symlink_before_run_effects(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            registry = root / "_registry" / "placement-map.yml"
            outside_registry = Path(outside) / "placement-map.yml"
            outside_registry.write_bytes(registry.read_bytes())
            registry.unlink()
            registry.symlink_to(outside_registry)

            code, stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("registry", stderr)
            self.assertFalse(Path(proposal["paths"]["active_marker"]).exists())
            self.assertFalse(Path(proposal["paths"]["placement_lock"]).exists())
            self.assertFalse(Path(proposal["paths"]["incomplete_run"]).exists())

    def test_preview_lock_migration_rejects_symlinked_pending_directory(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            pending = root / "_registry" / "pending"
            pending.rmdir()
            pending.symlink_to(Path(outside), target_is_directory=True)

            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("manifest directory", stderr)

    def test_preview_lock_migration_rejects_symlinked_decision_manifest_entry(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            outside_entry = Path(outside) / "decision.yml"
            outside_entry.write_text("status: forged\n", encoding="utf-8")
            entry = root / "_registry" / "decisions" / "decision.yml"
            entry.symlink_to(outside_entry)

            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("manifest entry", stderr)

    def test_preview_lock_migration_blocks_dangling_placement_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            placement_lock = root / "_registry" / "placement-map.lock"
            placement_lock.symlink_to(root / "_registry" / "missing-placement-lock")

            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("placement lock to be absent", stderr)
            proposal_root = root / "_registry" / "lock-migrations" / "proposals"
            self.assertEqual(list(proposal_root.glob("*/proposal.json")), [])

    def test_apply_lock_migration_rejects_invalid_id_before_file_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                "../../../../outside",
                "--proposal-sha256",
                "a" * 64,
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "error: invalid lock migration id\n")

    def test_apply_lock_migration_rejects_symlinked_proposal_before_effects(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal_path = Path(preview["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            displaced = outside_root / "proposal.json"
            proposal_path.rename(displaced)
            proposal_path.symlink_to(displaced)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("proposal is unreadable", stderr)
            self.assertFalse(os.path.lexists(proposal["paths"]["active_marker"]))
            self.assertFalse(os.path.lexists(proposal["paths"]["incomplete_run"]))

    def test_preview_lock_migration_blocks_unregistered_installed_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp)
            self.run_cli("bootstrap", "--root", str(root))
            old_writer = install_root / "mnemosyne-old.py"
            old_writer.write_text("#!/usr/bin/env python3\n# pre-M0 writer\n", encoding="utf-8")
            manifest = self.write_entrypoint_manifest(
                root,
                discovery_roots=[Path(mnemosyne.__file__).resolve().parent, install_root],
            )

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_item = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(proposal_item["path"]).read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertEqual(
                proposal["blockers"],
                [
                    {
                        "kind": "UNREGISTERED_ENTRYPOINT",
                        "path": str(old_writer.resolve()),
                    }
                ],
            )

    def test_preview_lock_migration_accepts_registered_mnemosyne_control_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            canonical = self.canonical_entrypoint_path()
            launcher = canonical.parent / "mnemosyne-control"
            manifest_path = self.write_entrypoint_manifest(root)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_path = Path(json.loads(stdout)["registry_updates"][0]["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertTrue(proposal["approval_ready"])
            self.assertEqual(proposal["blockers"], [])
            self.assertEqual(
                proposal["entrypoint_evidence"]["launchers"][0]["path"], str(launcher)
            )

    def test_preview_lock_migration_blocks_source_launcher_with_generic_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            manifest_path = self.write_entrypoint_manifest(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["launchers"][0]["kind"] = "direct-exec-v1"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_path = Path(json.loads(stdout)["registry_updates"][0]["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertIn(
                {
                    "kind": "LAUNCHER_DELEGATE_MISMATCH",
                    "path": str(self.canonical_entrypoint_path().parent / "mnemosyne-control"),
                },
                proposal["blockers"],
            )

    def test_preview_lock_migration_accepts_registered_mnemosyne_control_launcher_alias(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            canonical = self.canonical_entrypoint_path()
            launcher = canonical.parent / "mnemosyne-control"
            launcher_alias = install_root / "mnemosyne-control"
            launcher_alias.symlink_to(launcher)
            manifest_path = self.write_entrypoint_manifest(
                root,
                discovery_roots=[canonical.parent, install_root],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schema_version"] = 3
            manifest["launcher_aliases"] = [
                {
                    "path": str(launcher_alias),
                    "must_resolve_to": str(launcher),
                }
            ]
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_path = Path(json.loads(stdout)["registry_updates"][0]["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertTrue(proposal["approval_ready"])
            self.assertEqual(proposal["blockers"], [])
            self.assertEqual(
                proposal["entrypoint_evidence"]["launcher_aliases"][0]["path"],
                str(launcher_alias),
            )

    def test_preview_lock_migration_blocks_launcher_alias_with_wrong_target(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            canonical = self.canonical_entrypoint_path()
            launcher = canonical.parent / "mnemosyne-control"
            foreign_target = install_root / "foreign-control"
            foreign_target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            foreign_target.chmod(0o700)
            launcher_alias = install_root / "mnemosyne-control"
            launcher_alias.symlink_to(foreign_target)
            manifest_path = self.write_entrypoint_manifest(
                root,
                discovery_roots=[canonical.parent, install_root],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["launcher_aliases"] = [
                {
                    "path": str(launcher_alias),
                    "must_resolve_to": str(launcher),
                }
            ]
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_path = Path(json.loads(stdout)["registry_updates"][0]["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertIn(
                {"kind": "LAUNCHER_ALIAS_NOT_CANONICAL", "path": str(launcher_alias)},
                proposal["blockers"],
            )

    def test_preview_lock_migration_blocks_differently_named_legacy_writer(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            legacy_writer = install_root / "legacy-curator"
            legacy_writer.write_text(
                "#!/bin/sh\n# Mnemosyne legacy placement-map.yml propose-place writer\n",
                encoding="utf-8",
            )
            legacy_writer.chmod(0o700)
            unrelated = install_root / "ordinary-tool"
            unrelated.write_text("#!/bin/sh\necho unrelated\n", encoding="utf-8")
            unrelated.chmod(0o700)
            manifest = self.write_entrypoint_manifest(
                root,
                discovery_roots=[Path(mnemosyne.__file__).resolve().parent, install_root],
            )

            code, stdout, stderr = self.run_cli_exact(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--entrypoint-manifest", str(manifest),
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_item = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(proposal_item["path"]).read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertEqual(
                proposal["blockers"],
                [{"kind": "UNREGISTERED_ENTRYPOINT", "path": str(legacy_writer)}],
            )

    def test_preview_lock_migration_blocks_differently_named_legacy_writer_symlink(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            tempfile.TemporaryDirectory() as install_tmp,
            tempfile.TemporaryDirectory() as outside_tmp,
        ):
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            outside_root = Path(outside_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            historic_writer = outside_root / "historic-writer"
            historic_writer.write_text(
                "#!/bin/sh\n# Mnemosyne legacy placement-map.yml propose-place writer\n",
                encoding="utf-8",
            )
            historic_writer.chmod(0o700)
            legacy_alias = install_root / "legacy-curator"
            legacy_alias.symlink_to(historic_writer)
            manifest = self.write_entrypoint_manifest(
                root,
                discovery_roots=[Path(mnemosyne.__file__).resolve().parent, install_root],
            )

            code, stdout, stderr = self.run_cli_exact(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--entrypoint-manifest", str(manifest),
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_item = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(proposal_item["path"]).read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertEqual(
                proposal["blockers"],
                [{"kind": "UNREGISTERED_ENTRYPOINT", "path": str(legacy_alias)}],
            )

    def test_preview_lock_migration_cannot_omit_authoritative_install_root(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            old_writer = install_root / "mnemosyne-old.py"
            old_writer.write_text("#!/usr/bin/env python3\n# pre-M0\n", encoding="utf-8")
            manifest_path = self.write_entrypoint_manifest(root)
            canonical_root = Path(mnemosyne.__file__).resolve().parent

            self.authoritative_entrypoint_roots = [canonical_root, install_root]
            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_item = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(proposal_item["path"]).read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertIn(
                {"kind": "INSTALL_SURFACE_NOT_COVERED", "path": str(install_root)},
                proposal["blockers"],
            )
            self.assertIn(
                {"kind": "UNREGISTERED_ENTRYPOINT", "path": str(old_writer)},
                proposal["blockers"],
            )

    def test_preview_lock_migration_blocks_launcher_with_unbound_delegate(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            launcher = install_root / "mnemosyne"
            launcher.write_text("#!/bin/sh\nexec /old/mnemosyne.py \"$@\"\n", encoding="utf-8")
            launcher.chmod(0o755)
            manifest_path = self.write_entrypoint_manifest(
                root,
                discovery_roots=[Path(mnemosyne.__file__).resolve().parent, install_root],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["launchers"] = [
                {
                    "kind": "direct-exec-v1",
                    "path": str(launcher),
                    "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
                    "delegates_to": "/old/mnemosyne.py",
                }
            ]
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_item = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(proposal_item["path"]).read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertIn(
                {"kind": "LAUNCHER_DELEGATE_MISMATCH", "path": str(launcher)},
                proposal["blockers"],
            )

    def test_preview_lock_migration_blocks_launcher_that_lies_about_canonical_delegate(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            launcher = install_root / "mnemosyne"
            launcher.write_text("#!/bin/sh\nexec /old/mnemosyne.py \"$@\"\n", encoding="utf-8")
            launcher.chmod(0o755)
            manifest_path = self.write_entrypoint_manifest(
                root,
                discovery_roots=[Path(mnemosyne.__file__).resolve().parent, install_root],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["launchers"] = [
                {
                    "kind": "direct-exec-v1",
                    "path": str(launcher),
                    "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
                    "delegates_to": str(Path(mnemosyne.__file__).resolve()),
                }
            ]
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_item = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(proposal_item["path"]).read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertIn(
                {"kind": "LAUNCHER_DELEGATE_MISMATCH", "path": str(launcher)},
                proposal["blockers"],
            )

    def test_preview_lock_migration_rejects_world_writable_launcher(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            canonical = Path(mnemosyne.__file__).resolve()
            launcher = install_root / "mnemosyne"
            launcher.write_text(f'#!/bin/sh\nexec {canonical} "$@"\n', encoding="utf-8")
            launcher.chmod(0o666)
            manifest_path = self.write_entrypoint_manifest(
                root,
                discovery_roots=[canonical.parent, install_root],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["launchers"] = [
                {
                    "kind": "direct-exec-v1",
                    "path": str(launcher),
                    "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
                    "delegates_to": str(canonical),
                }
            ]
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--entrypoint-manifest", str(manifest_path),
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("launcher identity is unsafe", stderr)

    def test_preview_lock_migration_accepts_bound_symlink_writer_alias(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            canonical = Path(mnemosyne.__file__).resolve()
            alias = install_root / "mnemosyne"
            alias.symlink_to(canonical)
            manifest_path = self.write_entrypoint_manifest(
                root,
                discovery_roots=[canonical.parent, install_root],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["writer_aliases"] = [
                {"path": str(alias), "must_resolve_to": str(canonical)}
            ]
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--entrypoint-manifest", str(manifest_path),
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_path = Path(json.loads(stdout)["registry_updates"][0]["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertTrue(proposal["approval_ready"])
            alias_evidence = proposal["entrypoint_evidence"]["writer_aliases"][0]
            self.assertEqual(alias_evidence["lexical_kind"], "symlink")
            self.assertEqual(alias_evidence["link_target"], str(canonical))

    def test_resume_completed_migration_rejects_launcher_drift(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as install_tmp:
            root = Path(tmp)
            install_root = Path(install_tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            canonical = Path(mnemosyne.__file__).resolve()
            launcher = install_root / "mnemosyne"
            launcher.write_text(f'#!/bin/sh\nexec {canonical} "$@"\n', encoding="utf-8")
            launcher.chmod(0o755)
            manifest_path = self.write_entrypoint_manifest(
                root,
                discovery_roots=[canonical.parent, install_root],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["launchers"].append(
                {
                    "kind": "direct-exec-v1",
                    "path": str(launcher),
                    "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
                    "delegates_to": str(canonical),
                }
            )
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)
            code, stdout, stderr = self.run_cli_exact(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--entrypoint-manifest", str(manifest_path),
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli_exact(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            launcher.write_text("#!/bin/sh\nexec /old/mnemosyne.py \"$@\"\n", encoding="utf-8")
            launcher.chmod(0o755)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("launcher hash mismatch", stderr)

    def test_apply_lock_migration_rejects_entrypoint_manifest_drift_before_active_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            manifest_path = self.write_entrypoint_manifest(root)
            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["declared_by"] = "changed-installer"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: installed entrypoint manifest changed after lock migration preview\n",
            )
            self.assertFalse((root / "_registry" / "lock-migrations" / "active").exists())
            self.assertFalse((root / "_registry" / "placement-map.lock").exists())

    def test_apply_lock_migration_rejects_runtime_module_drift_before_active_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            runtime_paths = self.use_copied_runtime_modules(root)
            manifest_path = self.write_entrypoint_manifest(root)
            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            runtime_paths[-1].write_bytes(runtime_paths[-1].read_bytes() + b"# drift\n")
            runtime_paths[-1].chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("runtime module hash mismatch", stderr)
            self.assertFalse((root / "_registry" / "lock-migrations" / "active").exists())
            self.assertFalse((root / "_registry" / "placement-map.lock").exists())

    def test_apply_lock_migration_accepts_same_bytes_runtime_module_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            runtime_paths = self.use_copied_runtime_modules(root)
            manifest_path = self.write_entrypoint_manifest(root)
            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            runtime_bytes = runtime_paths[-1].read_bytes()
            original_inode = runtime_paths[-1].stat().st_ino
            replacement = runtime_paths[-1].with_name(runtime_paths[-1].name + ".replacement")
            replacement.write_bytes(runtime_bytes)
            replacement.chmod(0o600)
            os.replace(replacement, runtime_paths[-1])
            self.assertNotEqual(runtime_paths[-1].stat().st_ino, original_inode)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["mode"], "apply-lock-migration")
            self.assertFalse((root / "_registry" / "lock-migrations" / "active").exists())
            self.assertTrue((root / "_registry" / "placement-map.lock").is_file())
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())

    def test_apply_lock_migration_rechecks_runtime_modules_after_cleanup_seam(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            runtime_paths = self.use_copied_runtime_modules(root)
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def drift_after_cleanup(name: str, _root: Path, _migration_id: str) -> None:
                if name == "stale-leases-quarantined":
                    runtime_paths[-1].write_bytes(runtime_paths[-1].read_bytes() + b"# drift\n")
                    runtime_paths[-1].chmod(0o600)

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", drift_after_cleanup):
                code, stdout, stderr = self.run_cli(
                    "curation",
                    "apply-lock-migration",
                    "--proposal-id",
                    proposal["migration_id"],
                    "--proposal-sha256",
                    preview["sha256"],
                    "--approved-by",
                    "tester",
                    "--maintenance-window-confirmed",
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("runtime module hash mismatch", stderr)
            self.assertTrue(Path(proposal["paths"]["active_marker"]).is_file())
            self.assertFalse(Path(proposal["paths"]["placement_lock"]).exists())
            self.assertFalse(Path(proposal["paths"]["completed_marker"]).exists())

    def test_apply_lock_migration_rechecks_runtime_modules_before_completion_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            runtime_paths = self.use_copied_runtime_modules(root)
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def drift_after_result(name: str, _root: Path, _migration_id: str) -> None:
                if name == "completed-result-published":
                    runtime_paths[-1].write_bytes(runtime_paths[-1].read_bytes() + b"# drift\n")
                    runtime_paths[-1].chmod(0o600)

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", drift_after_result):
                code, stdout, stderr = self.run_cli(
                    "curation",
                    "apply-lock-migration",
                    "--proposal-id",
                    proposal["migration_id"],
                    "--proposal-sha256",
                    preview["sha256"],
                    "--approved-by",
                    "tester",
                    "--maintenance-window-confirmed",
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("runtime module hash mismatch", stderr)
            self.assertTrue(Path(proposal["paths"]["active_marker"]).is_file())
            self.assertTrue(Path(proposal["paths"]["placement_lock"]).is_file())
            self.assertTrue(Path(proposal["paths"]["completed_result"]).is_file())
            self.assertFalse(Path(proposal["paths"]["completed_marker"]).exists())

    def test_lock_migration_survives_same_bytes_runtime_reinstall_after_lock_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            runtime_paths = self.use_copied_runtime_modules(root)
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            replaced = False

            def reinstall_same_bytes(name: str, _root: Path, _migration_id: str) -> None:
                nonlocal replaced
                if name != "placement-lock-published" or replaced:
                    return
                replaced = True
                payload = runtime_paths[-1].read_bytes()
                original_inode = runtime_paths[-1].stat().st_ino
                replacement = runtime_paths[-1].with_name(runtime_paths[-1].name + ".replacement")
                replacement.write_bytes(payload)
                replacement.chmod(0o600)
                os.replace(replacement, runtime_paths[-1])
                self.assertNotEqual(runtime_paths[-1].stat().st_ino, original_inode)

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", reinstall_same_bytes):
                code, stdout, stderr = self.run_cli(
                    "curation",
                    "apply-lock-migration",
                    "--proposal-id",
                    proposal["migration_id"],
                    "--proposal-sha256",
                    preview["sha256"],
                    "--approved-by",
                    "tester",
                    "--maintenance-window-confirmed",
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertTrue(replaced)
            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["mode"], "apply-lock-migration")
            self.assertFalse(Path(proposal["paths"]["active_marker"]).exists())
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())

    def test_completed_lock_migration_accepts_compatible_runtime_closure_expansion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            runtime_paths = self.use_copied_runtime_modules(root)
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)

            added_module = root / "installed-runtime" / "99-curation-foundation.py"
            added_module.write_text("CURATION_FOUNDATION_VERSION = 1\n", encoding="utf-8")
            added_module.chmod(0o600)
            self.authoritative_runtime_modules = [*runtime_paths, added_module.resolve()]
            refreshed_manifest = self.write_entrypoint_manifest(root)
            self.assertNotEqual(
                hashlib.sha256(refreshed_manifest.read_bytes()).hexdigest(),
                proposal["entrypoint_manifest"]["sha256"],
            )

            source = root / "inbox" / "after-compatible-upgrade.md"
            source.write_text("compatible upgrade\n", encoding="utf-8")
            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertTrue(stdout.startswith("created proposal "))

            incompatible_source = root / "inbox" / "after-incompatible-protocol.md"
            incompatible_source.write_text("must be blocked\n", encoding="utf-8")
            with mock.patch.object(
                mnemosyne,
                "PLACEMENT_LOCK_PROTOCOL_VERSION",
                "placement-lock-v2",
            ):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(incompatible_source),
                    "--target",
                    str(root / "docs" / incompatible_source.name),
                    "--root",
                    str(root),
                )
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("placement lock payload binding is invalid", stderr)

    def test_preview_lock_migration_never_creates_proposal_through_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            manifest_path = self.write_entrypoint_manifest(root)
            proposals = root / "_registry" / "lock-migrations" / "proposals"
            proposals.symlink_to(outside_root, target_is_directory=True)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--entrypoint-manifest",
                str(manifest_path),
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("verified proposal parent", stderr)
            self.assertEqual(list(outside_root.iterdir()), [])

    def test_preview_lock_migration_derives_entrypoint_from_verified_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            manifest_path = self.write_entrypoint_manifest(root)
            entrypoint = Path(mnemosyne.__file__).resolve()
            original_read_bytes = Path.read_bytes

            def forge_redundant_entrypoint_read(path: Path) -> bytes:
                if path.resolve() == entrypoint:
                    return b"unverified redundant read\n"
                return original_read_bytes(path)

            with mock.patch.object(Path, "read_bytes", forge_redundant_entrypoint_read):
                code, stdout, stderr = self.run_cli_exact(
                    "curation",
                    "preview-lock-migration",
                    "--requested-by",
                    "tester",
                    "--entrypoint-manifest",
                    str(manifest_path),
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertEqual(code, 0, stderr)
            proposal_path = Path(json.loads(stdout)["registry_updates"][0]["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            canonical = proposal["entrypoint_evidence"]["canonical_writer"]
            self.assertEqual(
                proposal["entrypoint"],
                {
                    "path": canonical["path"],
                    "compatibility_version": mnemosyne.MNEMOSYNE_COMPATIBILITY_VERSION,
                    "sha256": canonical["sha256"],
                },
            )

            forged = dict(proposal)
            forged["entrypoint"] = {**proposal["entrypoint"], "sha256": "0" * 64}
            with self.assertRaisesRegex(
                mnemosyne.MnemosyneError,
                "proposal entrypoint binding is invalid",
            ):
                mnemosyne.verify_proposal_entrypoint_evidence(forged)

    def test_preview_lock_migration_seals_proposal_without_data_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            corpus_file = root / "inbox" / "untouched.md"
            corpus_file.write_text("untouched\n", encoding="utf-8")
            registry = root / "_registry" / "placement-map.yml"
            registry_before = registry.read_bytes()
            pending_before = sorted(path.read_bytes() for path in (root / "_registry" / "pending").glob("*.yml"))
            decisions_before = sorted(
                path.read_bytes() for path in (root / "_registry" / "decisions").glob("*.yml")
            )

            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            report = json.loads(stdout)
            self.assertEqual(
                set(report),
                {
                    "mode",
                    "registry_updates",
                    "content_placement_writes",
                    "memory_updates",
                    "not_modified",
                    "needs_review",
                },
            )
            self.assertEqual(report["mode"], "preview-lock-migration")
            self.assertEqual(report["content_placement_writes"], [])
            self.assertEqual(report["memory_updates"], [])
            self.assertEqual(len(report["registry_updates"]), 1)
            proposal_path = Path(report["registry_updates"][0]["path"])
            self.assertTrue(proposal_path.is_file())
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertEqual(proposal["schema_version"], 1)
            self.assertEqual(proposal["kind"], "LOCK_MIGRATION")
            self.assertEqual(proposal["requested_by"], "tester")
            self.assertTrue(proposal["approval_ready"])
            self.assertEqual(proposal["entrypoint_evidence"]["schema_version"], 3)
            self.assertEqual(
                [item["path"] for item in proposal["entrypoint_evidence"]["runtime_modules"]],
                [str(path) for path in mnemosyne.authoritative_runtime_module_paths()],
            )
            self.assertEqual(proposal["registry_sha256"], hashlib.sha256(registry_before).hexdigest())
            self.assertEqual(proposal["leases"], [])
            self.assertEqual(proposal["cleanup_effects"], [])
            self.assertEqual(registry.read_bytes(), registry_before)
            self.assertEqual(
                sorted(path.read_bytes() for path in (root / "_registry" / "pending").glob("*.yml")),
                pending_before,
            )
            self.assertEqual(
                sorted(path.read_bytes() for path in (root / "_registry" / "decisions").glob("*.yml")),
                decisions_before,
            )
            self.assertEqual(corpus_file.read_text(encoding="utf-8"), "untouched\n")
            self.assertFalse((root / "_registry" / "placement-map.lock").exists())
            self.assertFalse((root / "_registry" / "curation" / "ledger.sqlite3").exists())

    def test_preview_lock_migration_blocks_live_lease_and_only_proposes_stale_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            registry = root / "_registry" / "placement-map.yml"
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            lease_dir.mkdir(parents=True, exist_ok=True)
            common = {
                "schema_version": 1,
                "pid": os.getpid(),
                "command": "approve",
                "registry_sha256": hashlib.sha256(registry.read_bytes()).hexdigest(),
            }
            live_path = lease_dir / "live"
            live_path.write_text(
                json.dumps(
                    {
                        **common,
                        "process_start_identity": mnemosyne.process_start_identity(os.getpid()),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            live_path.chmod(0o600)
            stale_path = lease_dir / "stale"
            stale_path.write_text(
                json.dumps({**common, "process_start_identity": "reused-pid-start"}) + "\n",
                encoding="utf-8",
            )
            stale_path.chmod(0o600)
            stale_before = stale_path.read_bytes()

            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            report = json.loads(stdout)
            proposal_path = Path(report["registry_updates"][0]["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            by_path = {entry["path"]: entry for entry in proposal["leases"]}
            self.assertEqual(by_path[str(live_path.resolve())]["status"], "alive")
            self.assertEqual(by_path[str(stale_path.resolve())]["status"], "dead")
            self.assertEqual(by_path[str(stale_path.resolve())]["reason"], "pid-reused")
            self.assertEqual(len(proposal["blockers"]), 1)
            self.assertEqual(proposal["blockers"][0]["path"], str(live_path.resolve()))
            self.assertEqual(len(proposal["cleanup_effects"]), 1)
            cleanup = proposal["cleanup_effects"][0]
            self.assertEqual(cleanup["source"], str(stale_path.resolve()))
            self.assertEqual(cleanup["source_sha256"], hashlib.sha256(stale_before).hexdigest())
            self.assertTrue(cleanup["target"].endswith("/stale"))
            self.assertEqual(stale_path.read_bytes(), stale_before)
            self.assertTrue(live_path.is_file())

    def test_preview_lock_migration_blocks_multilink_stale_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            registry = root / "_registry" / "placement-map.yml"
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            lease_dir.mkdir(parents=True, exist_ok=True)
            stale = lease_dir / "stale"
            stale.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "pid": os.getpid(),
                        "process_start_identity": "reused-pid-start",
                        "command": "approve",
                        "registry_sha256": hashlib.sha256(registry.read_bytes()).hexdigest(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            stale.chmod(0o600)
            os.link(stale, lease_dir / "stale-alias")

            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 0, stderr)
            proposal_path = Path(json.loads(stdout)["registry_updates"][0]["path"])
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertFalse(proposal["approval_ready"])
            self.assertEqual(proposal["cleanup_effects"], [])
            self.assertTrue(
                all(lease["reason"] == "unsafe-link-count" for lease in proposal["leases"])
            )

    def test_apply_lock_migration_never_creates_run_through_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            runs = root / "_registry" / "lock-migrations" / "runs"
            runs.symlink_to(outside_root, target_is_directory=True)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("verified run parent", stderr)
            self.assertEqual(list(outside_root.iterdir()), [])

    def test_apply_lock_migration_publishes_verified_completion_without_data_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            corpus_file = root / "inbox" / "still-here.md"
            corpus_file.write_text("still here\n", encoding="utf-8")
            registry = root / "_registry" / "placement-map.yml"
            registry_before = registry.read_bytes()
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview_report = json.loads(stdout)
            preview_item = preview_report["registry_updates"][0]
            proposal = json.loads(Path(preview_item["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]

            code, stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview_item["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            report = json.loads(stdout)
            self.assertEqual(report["mode"], "apply-lock-migration")
            self.assertEqual(report["content_placement_writes"], [])
            self.assertEqual(report["memory_updates"], [])
            lock_path = root / "_registry" / "placement-map.lock"
            self.assertTrue(lock_path.is_file())
            lock_stat = lock_path.stat()
            self.assertEqual(stat.S_IMODE(lock_stat.st_mode), 0o600)
            self.assertEqual(lock_stat.st_uid, os.getuid())
            self.assertEqual(lock_stat.st_nlink, 1)
            lock_payload = json.loads(lock_path.read_text(encoding="utf-8"))
            self.assertEqual(lock_payload["migration_id"], migration_id)
            self.assertEqual(lock_payload["proposal_sha256"], preview_item["sha256"])
            final_run = Path(proposal["paths"]["final_run"])
            incomplete_run = Path(proposal["paths"]["incomplete_run"])
            completed_result = Path(proposal["paths"]["completed_result"])
            completed_marker = Path(proposal["paths"]["completed_marker"])
            self.assertTrue((final_run / "plan.json").is_file())
            self.assertTrue((final_run / "result.json").is_file())
            self.assertFalse(incomplete_run.exists())
            self.assertTrue(completed_result.is_file())
            self.assertTrue(completed_marker.is_file())
            self.assertFalse((root / "_registry" / "lock-migrations" / "active").exists())
            result = json.loads(completed_result.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "COMPLETE")
            self.assertEqual(result["migration_id"], migration_id)
            self.assertEqual(result["proposal_sha256"], preview_item["sha256"])
            self.assertEqual(result["registry_sha256"], hashlib.sha256(registry_before).hexdigest())
            self.assertEqual(result["entrypoint"], proposal["entrypoint"])
            self.assertEqual(result["entrypoint_manifest"], proposal["entrypoint_manifest"])
            self.assertEqual(
                result["entrypoint_evidence_sha256"],
                proposal["entrypoint_evidence_sha256"],
            )
            self.assertEqual(
                lock_payload["entrypoint_manifest_sha256"],
                proposal["entrypoint_manifest"]["sha256"],
            )
            self.assertEqual(
                lock_payload["entrypoint_evidence_sha256"],
                proposal["entrypoint_evidence_sha256"],
            )
            self.assertEqual(registry.read_bytes(), registry_before)
            self.assertEqual(corpus_file.read_text(encoding="utf-8"), "still here\n")
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])
            self.assertEqual(list((root / "_registry" / "decisions").glob("*.yml")), [])

    def test_apply_lock_migration_never_replaces_racing_final_run_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            final_run = Path(proposal["paths"]["final_run"])
            competitor_inodes = []

            def publish_competitor(_source: Path, target: Path) -> None:
                target.mkdir()
                competitor_inodes.append(target.stat().st_ino)

            with mock.patch.object(
                mnemosyne,
                "lock_migration_before_final_run_publish",
                publish_competitor,
            ):
                code, stdout, stderr = self.run_cli_exact(
                    "curation",
                    "apply-lock-migration",
                    "--proposal-id",
                    proposal["migration_id"],
                    "--proposal-sha256",
                    preview["sha256"],
                    "--approved-by",
                    "tester",
                    "--maintenance-window-confirmed",
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                f"error: refusing to overwrite lock migration run: {final_run}\n",
            )
            self.assertEqual(len(competitor_inodes), 1)
            self.assertTrue(final_run.is_dir())
            self.assertEqual(final_run.stat().st_ino, competitor_inodes[0])

    def test_resume_lock_migration_recovers_plan_published_before_active_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def crash_after_plan(name: str, _root: Path, _migration_id: str) -> None:
                if name == "plan-published":
                    raise RuntimeError("simulated crash after plan")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_plan):
                with self.assertRaisesRegex(RuntimeError, "simulated crash after plan"):
                    self.run_cli_exact(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        proposal["migration_id"],
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            incomplete_run = Path(proposal["paths"]["incomplete_run"])
            self.assertTrue((incomplete_run / "plan.json").is_file())
            self.assertFalse((root / "_registry" / "lock-migrations" / "active").exists())

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["mode"], "resume-lock-migration")
            self.assertTrue(Path(proposal["paths"]["completed_result"]).is_file())
            self.assertFalse(incomplete_run.exists())

    def test_resume_lock_migration_rejects_symlinked_incomplete_run_before_active(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def crash_after_plan(name: str, _root: Path, _migration_id: str) -> None:
                if name == "plan-published":
                    raise RuntimeError("simulated crash after plan")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_plan):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation", "apply-lock-migration",
                        "--proposal-id", proposal["migration_id"],
                        "--proposal-sha256", preview["sha256"],
                        "--approved-by", "tester", "--maintenance-window-confirmed",
                        "--root", str(root), "--json",
                    )
            incomplete_run = Path(proposal["paths"]["incomplete_run"])
            displaced = outside_root / "incomplete-run"
            incomplete_run.rename(displaced)
            incomplete_run.symlink_to(displaced, target_is_directory=True)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("run directory is not verified", stderr)
            self.assertFalse(os.path.lexists(proposal["paths"]["active_marker"]))
            self.assertFalse(os.path.lexists(proposal["paths"]["placement_lock"]))

    def test_apply_lock_migration_stops_when_manual_recovery_blocker_appears_after_active_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def publish_blocker_after_active(
                name: str,
                checkpoint_root: Path,
                _migration_id: str,
            ) -> None:
                if name == "active-marker-published":
                    self.publish_manual_recovery_blocker(checkpoint_root)

            with mock.patch.object(
                mnemosyne,
                "lock_migration_checkpoint",
                publish_blocker_after_active,
            ):
                code, stdout, stderr = self.run_cli_exact(
                    "curation",
                    "apply-lock-migration",
                    "--proposal-id",
                    proposal["migration_id"],
                    "--proposal-sha256",
                    preview["sha256"],
                    "--approved-by",
                    "tester",
                    "--maintenance-window-confirmed",
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("unresolved manual recovery blocker", stderr)
            self.assertTrue(Path(proposal["paths"]["active_marker"]).is_file())
            self.assertFalse(Path(proposal["paths"]["placement_lock"]).exists())
            self.assertFalse(Path(proposal["paths"]["completed_marker"]).exists())

    def test_resume_lock_migration_after_active_marker_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            registry_before = (root / "_registry" / "placement-map.yml").read_bytes()
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]

            def crash_after_marker(name: str, _root: Path, _migration_id: str) -> None:
                if name == "active-marker-published":
                    raise RuntimeError("simulated crash after active marker")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_marker):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        migration_id,
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            active_marker = root / "_registry" / "lock-migrations" / "active"
            self.assertTrue(active_marker.is_file())
            self.assertTrue((Path(proposal["paths"]["incomplete_run"]) / "plan.json").is_file())
            self.assertFalse((root / "_registry" / "placement-map.lock").exists())

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["mode"], "resume-lock-migration")
            self.assertFalse(active_marker.exists())
            self.assertTrue((root / "_registry" / "placement-map.lock").is_file())
            self.assertTrue(Path(proposal["paths"]["completed_result"]).is_file())
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())
            self.assertEqual((root / "_registry" / "placement-map.yml").read_bytes(), registry_before)

    def test_resume_active_lock_migration_rejects_runtime_module_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            runtime_paths = self.use_copied_runtime_modules(root)
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def crash_after_marker(name: str, _root: Path, _migration_id: str) -> None:
                if name == "active-marker-published":
                    raise RuntimeError("simulated crash after active marker")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_marker):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        proposal["migration_id"],
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )
            runtime_paths[-1].write_bytes(runtime_paths[-1].read_bytes() + b"# drift\n")
            runtime_paths[-1].chmod(0o600)

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("runtime module hash mismatch", stderr)
            self.assertTrue(Path(proposal["paths"]["active_marker"]).is_file())
            self.assertFalse(Path(proposal["paths"]["placement_lock"]).exists())

    def test_resume_lock_migration_after_placement_lock_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]

            def crash_after_lock(name: str, _root: Path, _migration_id: str) -> None:
                if name == "placement-lock-published":
                    raise RuntimeError("simulated crash after placement lock")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_lock):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        migration_id,
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            lock_path = root / "_registry" / "placement-map.lock"
            lock_before = lock_path.read_bytes()
            self.assertTrue((root / "_registry" / "lock-migrations" / "active").is_file())
            self.assertFalse((Path(proposal["paths"]["incomplete_run"]) / "result.json").exists())

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["mode"], "resume-lock-migration")
            self.assertEqual(lock_path.read_bytes(), lock_before)
            self.assertTrue(Path(proposal["paths"]["completed_result"]).is_file())
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())

    def test_resume_lock_migration_after_partial_placement_lock_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            original_publish = mnemosyne.publish_placement_lock_no_replace
            real_write = os.write
            injected = False

            def crash_placement_publish(publish_root: Path, value: dict) -> str:
                nonlocal injected
                if injected:
                    return original_publish(publish_root, value)
                injected = True
                write_calls = 0

                def partial_then_crash(fd: int, data: bytes) -> int:
                    nonlocal write_calls
                    write_calls += 1
                    if write_calls == 1:
                        return real_write(fd, data[: max(1, len(data) // 2)])
                    raise OSError("injected placement write crash")

                with mock.patch.object(mnemosyne.os, "write", partial_then_crash):
                    return original_publish(publish_root, value)

            with mock.patch.object(
                mnemosyne,
                "publish_placement_lock_no_replace",
                crash_placement_publish,
            ):
                code, stdout, stderr = self.run_cli(
                    "curation", "apply-lock-migration",
                    "--proposal-id", proposal["migration_id"],
                    "--proposal-sha256", preview["sha256"],
                    "--approved-by", "tester", "--maintenance-window-confirmed",
                    "--root", str(root), "--json",
                )

            lock_path = Path(proposal["paths"]["placement_lock"])
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertFalse(os.path.lexists(lock_path))
            self.assertEqual(
                len(list(lock_path.parent.glob(f".{lock_path.name}.incomplete-*"))),
                1,
            )

            code, stdout, stderr = self.run_cli(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["mode"], "resume-lock-migration")
            self.assertTrue(lock_path.is_file())
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())

    def test_resume_lock_migration_after_partial_plan_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            original_publish = mnemosyne.publish_json_no_replace
            real_write = os.write
            injected = False

            def crash_plan_publish(path: Path, value: dict, *, mode: int = 0o600) -> str:
                nonlocal injected
                if path.name != "plan.json" or injected:
                    return original_publish(path, value, mode=mode)
                injected = True
                write_calls = 0

                def partial_then_crash(fd: int, data: bytes) -> int:
                    nonlocal write_calls
                    write_calls += 1
                    if write_calls == 1:
                        return real_write(fd, data[: max(1, len(data) // 2)])
                    raise OSError("injected plan write crash")

                with mock.patch.object(mnemosyne.os, "write", partial_then_crash):
                    return original_publish(path, value, mode=mode)

            with mock.patch.object(mnemosyne, "publish_json_no_replace", crash_plan_publish):
                code, stdout, stderr = self.run_cli(
                    "curation", "apply-lock-migration",
                    "--proposal-id", proposal["migration_id"],
                    "--proposal-sha256", preview["sha256"],
                    "--approved-by", "tester", "--maintenance-window-confirmed",
                    "--root", str(root), "--json",
                )

            incomplete_run = Path(proposal["paths"]["incomplete_run"])
            plan_path = incomplete_run / "plan.json"
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertFalse(os.path.lexists(plan_path))
            self.assertEqual(
                len(list(incomplete_run.glob(f".{plan_path.name}.incomplete-*"))),
                1,
            )
            self.assertFalse(os.path.lexists(proposal["paths"]["active_marker"]))

            code, stdout, stderr = self.run_cli(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["mode"], "resume-lock-migration")
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())

    def test_resume_lock_migration_reuses_existing_result_after_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]

            def crash_after_result(name: str, _root: Path, _migration_id: str) -> None:
                if name == "result-published":
                    raise RuntimeError("simulated crash after result")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_result):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        migration_id,
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            incomplete_result = Path(proposal["paths"]["incomplete_run"]) / "result.json"
            result_before = incomplete_result.read_bytes()

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            final_result = Path(proposal["paths"]["final_run"]) / "result.json"
            self.assertEqual(final_result.read_bytes(), result_before)
            self.assertEqual(Path(proposal["paths"]["completed_result"]).read_bytes(), result_before)
            self.assertEqual(json.loads(stdout)["mode"], "resume-lock-migration")

    def test_resume_lock_migration_rejects_symlinked_incomplete_result(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def crash_after_result(name: str, _root: Path, _migration_id: str) -> None:
                if name == "result-published":
                    raise RuntimeError("simulated crash after result")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_result):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation", "apply-lock-migration",
                        "--proposal-id", proposal["migration_id"],
                        "--proposal-sha256", preview["sha256"],
                        "--approved-by", "tester", "--maintenance-window-confirmed",
                        "--root", str(root), "--json",
                    )
            incomplete_result = Path(proposal["paths"]["incomplete_run"]) / "result.json"
            displaced = outside_root / "result.json"
            incomplete_result.rename(displaced)
            incomplete_result.symlink_to(displaced)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("existing lock migration result", stderr)
            self.assertTrue(Path(proposal["paths"]["active_marker"]).is_file())
            self.assertFalse(os.path.lexists(proposal["paths"]["completed_result"]))

    def test_resume_lock_migration_after_final_run_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]

            def crash_after_final_run(name: str, _root: Path, _migration_id: str) -> None:
                if name == "final-run-published":
                    raise RuntimeError("simulated crash after final run")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_final_run):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        migration_id,
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            final_run = Path(proposal["paths"]["final_run"])
            result_before = (final_run / "result.json").read_bytes()
            self.assertFalse(Path(proposal["paths"]["incomplete_run"]).exists())
            self.assertFalse(Path(proposal["paths"]["completed_result"]).exists())

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual((final_run / "result.json").read_bytes(), result_before)
            self.assertEqual(Path(proposal["paths"]["completed_result"]).read_bytes(), result_before)
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())

    def test_resume_lock_migration_rejects_symlinked_completed_result(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def crash_after_final_run(name: str, _root: Path, _migration_id: str) -> None:
                if name == "final-run-published":
                    raise RuntimeError("simulated crash after final run")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_final_run):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation", "apply-lock-migration",
                        "--proposal-id", proposal["migration_id"],
                        "--proposal-sha256", preview["sha256"],
                        "--approved-by", "tester", "--maintenance-window-confirmed",
                        "--root", str(root), "--json",
                    )
            completed_result = Path(proposal["paths"]["completed_result"])
            completed_result.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            displaced = outside_root / "result.json"
            displaced.write_bytes(
                (Path(proposal["paths"]["final_run"]) / "result.json").read_bytes()
            )
            displaced.chmod(0o600)
            completed_result.symlink_to(displaced)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("completed result", stderr)
            self.assertTrue(Path(proposal["paths"]["active_marker"]).is_file())
            self.assertFalse(os.path.lexists(proposal["paths"]["completed_marker"]))

    def test_resume_lock_migration_after_completed_result_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]

            def crash_after_completed_result(name: str, _root: Path, _migration_id: str) -> None:
                if name == "completed-result-published":
                    raise RuntimeError("simulated crash after completed result")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_completed_result):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        migration_id,
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            completed_result = Path(proposal["paths"]["completed_result"])
            completed_marker = Path(proposal["paths"]["completed_marker"])
            result_before = completed_result.read_bytes()
            self.assertFalse(completed_marker.exists())
            self.assertTrue((root / "_registry" / "lock-migrations" / "active").is_file())

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(completed_result.read_bytes(), result_before)
            self.assertTrue(completed_marker.is_file())
            self.assertFalse((root / "_registry" / "lock-migrations" / "active").exists())

    def test_lock_migration_never_publishes_completed_marker_through_replaced_parent(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            active_marker = Path(proposal["paths"]["active_marker"])
            completed_marker = Path(proposal["paths"]["completed_marker"])

            def replace_completed_parent(_active: Path, completed: Path) -> None:
                original_parent = completed.parent.with_name(completed.parent.name + "-original")
                completed.parent.rename(original_parent)
                completed.parent.symlink_to(outside_root, target_is_directory=True)

            with mock.patch.object(
                mnemosyne,
                "lock_migration_before_completed_marker_publish",
                replace_completed_parent,
            ):
                code, stdout, stderr = self.run_cli_exact(
                    "curation",
                    "apply-lock-migration",
                    "--proposal-id",
                    proposal["migration_id"],
                    "--proposal-sha256",
                    preview["sha256"],
                    "--approved-by",
                    "tester",
                    "--maintenance-window-confirmed",
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("verified completed marker parent", stderr)
            self.assertTrue(active_marker.is_file())
            self.assertEqual(list(outside_root.iterdir()), [])

    def test_lock_migration_keeps_active_if_completed_parent_changes_after_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            active_marker = Path(proposal["paths"]["active_marker"])
            completed_marker = Path(proposal["paths"]["completed_marker"])
            displaced_parent = completed_marker.parent.with_name(
                completed_marker.parent.name + "-displaced"
            )

            def replace_after_link(name: str, _root: Path, _migration_id: str) -> None:
                if name == "completed-marker-linked":
                    completed_marker.parent.rename(displaced_parent)
                    completed_marker.parent.mkdir(mode=0o700)

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", replace_after_link):
                code, stdout, stderr = self.run_cli_exact(
                    "curation",
                    "apply-lock-migration",
                    "--proposal-id",
                    proposal["migration_id"],
                    "--proposal-sha256",
                    preview["sha256"],
                    "--approved-by",
                    "tester",
                    "--maintenance-window-confirmed",
                    "--root",
                    str(root),
                    "--json",
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("completed lock migration marker", stderr)
            self.assertTrue(active_marker.is_file())
            self.assertFalse(completed_marker.exists())
            self.assertTrue((displaced_parent / completed_marker.name).is_file())

    def test_apply_lock_migration_blocks_dangling_active_before_run_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            active_marker = Path(proposal["paths"]["active_marker"])
            active_marker.symlink_to(active_marker.parent / "missing-active-target")

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("another lock migration is active", stderr)
            self.assertFalse(os.path.lexists(proposal["paths"]["incomplete_run"]))
            self.assertFalse(os.path.lexists(proposal["paths"]["final_run"]))

    def test_resume_lock_migration_rejects_symlinked_active_before_effects(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def crash_after_active_marker(name: str, _root: Path, _migration_id: str) -> None:
                if name == "active-marker-published":
                    raise RuntimeError("simulated crash after active marker")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_active_marker):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        proposal["migration_id"],
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            active_marker = Path(proposal["paths"]["active_marker"])
            original_active = outside_root / "active.json"
            active_marker.rename(original_active)
            active_marker.symlink_to(original_active)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("active marker is not a regular file", stderr)
            self.assertFalse(os.path.lexists(proposal["paths"]["placement_lock"]))
            self.assertFalse(os.path.lexists(proposal["paths"]["completed_result"]))
            self.assertFalse(os.path.lexists(proposal["paths"]["completed_marker"]))
            self.assertTrue(Path(proposal["paths"]["incomplete_run"]).is_dir())
            self.assertFalse(os.path.lexists(proposal["paths"]["final_run"]))

    def test_resume_completed_migration_rejects_dangling_active_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            active_marker = Path(proposal["paths"]["active_marker"])
            active_marker.symlink_to(active_marker.parent / "missing-active-target")

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("active marker is not a regular file", stderr)
            self.assertTrue(active_marker.is_symlink())

    def test_resume_completed_migration_rejects_symlinked_final_run(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            final_run = Path(proposal["paths"]["final_run"])
            displaced = outside_root / "final-run"
            final_run.rename(displaced)
            final_run.symlink_to(displaced, target_is_directory=True)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("completed lock migration evidence", stderr)
            self.assertTrue(final_run.is_symlink())

    def test_resume_lock_migration_finishes_linked_marker_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]

            def crash_after_marker_link(name: str, _root: Path, _migration_id: str) -> None:
                if name == "completed-marker-linked":
                    raise RuntimeError("simulated crash after marker link")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_marker_link):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        migration_id,
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            active_marker = root / "_registry" / "lock-migrations" / "active"
            completed_marker = Path(proposal["paths"]["completed_marker"])
            self.assertTrue(active_marker.is_file())
            self.assertTrue(completed_marker.is_file())
            self.assertEqual(active_marker.stat().st_ino, completed_marker.stat().st_ino)
            self.assertEqual(completed_marker.stat().st_nlink, 2)

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertFalse(active_marker.exists())
            self.assertTrue(completed_marker.is_file())
            self.assertEqual(completed_marker.stat().st_nlink, 1)

    def test_resume_completed_lock_migration_is_read_only_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            before = {
                str(path.relative_to(root)): (path.stat().st_mode, path.read_bytes())
                for path in root.rglob("*")
                if path.is_file()
            }

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            after = {
                str(path.relative_to(root)): (path.stat().st_mode, path.read_bytes())
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(code, 0, stderr)
            report = json.loads(stdout)
            self.assertEqual(report["mode"], "resume-lock-migration")
            self.assertEqual(report["registry_updates"], [])
            self.assertEqual(before, after)

    def test_resume_completed_lock_migration_rejects_runtime_module_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            runtime_paths = self.use_copied_runtime_modules(root)
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            completed_result = Path(proposal["paths"]["completed_result"])
            completed_before = completed_result.read_bytes()
            runtime_paths[-1].write_bytes(runtime_paths[-1].read_bytes() + b"# drift\n")
            runtime_paths[-1].chmod(0o600)

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("runtime module hash mismatch", stderr)
            self.assertEqual(completed_result.read_bytes(), completed_before)
            self.assertTrue(Path(proposal["paths"]["completed_marker"]).is_file())

    def test_resume_completed_migration_rejects_forged_result_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            final_result = Path(proposal["paths"]["final_run"]) / "result.json"
            completed_result = Path(proposal["paths"]["completed_result"])
            forged = json.loads(final_result.read_text(encoding="utf-8"))
            forged["approved_by"] = "forged-actor"
            forged["completed_at"] = "2099-01-01T00:00:00Z"
            forged["unexpected"] = "field"
            forged_bytes = (
                json.dumps(forged, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            final_result.write_bytes(forged_bytes)
            completed_result.write_bytes(forged_bytes)
            final_result.chmod(0o600)
            completed_result.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("result binding mismatch", stderr)

    def test_resume_completed_migration_rejects_rebound_registry_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            registry = root / "_registry" / "placement-map.yml"
            registry.write_text(registry.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")
            rebound_hash = hashlib.sha256(registry.read_bytes()).hexdigest()
            final_result = Path(proposal["paths"]["final_run"]) / "result.json"
            completed_result = Path(proposal["paths"]["completed_result"])
            rebound = json.loads(final_result.read_text(encoding="utf-8"))
            rebound["registry_sha256"] = rebound_hash
            rebound_bytes = (
                json.dumps(rebound, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            final_result.write_bytes(rebound_bytes)
            completed_result.write_bytes(rebound_bytes)
            final_result.chmod(0o600)
            completed_result.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("result binding mismatch", stderr)

    def test_resume_lock_migration_rejects_forged_active_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def crash_after_active(name: str, _root: Path, _migration_id: str) -> None:
                if name == "active-marker-published":
                    raise RuntimeError("stop after active")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_active):
                with self.assertRaisesRegex(RuntimeError, "stop after active"):
                    self.run_cli(
                        "curation", "apply-lock-migration",
                        "--proposal-id", proposal["migration_id"],
                        "--proposal-sha256", preview["sha256"],
                        "--approved-by", "tester", "--maintenance-window-confirmed",
                        "--root", str(root), "--json",
                    )
            active = Path(proposal["paths"]["active_marker"])
            forged = json.loads(active.read_text(encoding="utf-8"))
            forged["started_at"] = "2099-01-01T00:00:00Z"
            active.write_bytes(mnemosyne.canonical_json_bytes(forged))
            active.chmod(0o600)

            code, stdout, stderr = self.run_cli(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("active lock migration marker does not match stored plan", stderr)
            self.assertFalse(Path(proposal["paths"]["completed_marker"]).exists())

    def test_resume_lock_migration_rejects_forged_plan_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))

            def crash_after_plan(name: str, _root: Path, _migration_id: str) -> None:
                if name == "plan-published":
                    raise RuntimeError("stop after plan")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_plan):
                with self.assertRaisesRegex(RuntimeError, "stop after plan"):
                    self.run_cli(
                        "curation", "apply-lock-migration",
                        "--proposal-id", proposal["migration_id"],
                        "--proposal-sha256", preview["sha256"],
                        "--approved-by", "tester", "--maintenance-window-confirmed",
                        "--root", str(root), "--json",
                    )
            plan_path = Path(proposal["paths"]["incomplete_run"]) / "plan.json"
            forged = json.loads(plan_path.read_text(encoding="utf-8"))
            forged["approved_by"] = "forged-actor"
            forged["unexpected"] = "field"
            plan_path.write_bytes(mnemosyne.canonical_json_bytes(forged))
            plan_path.chmod(0o600)

            code, stdout, stderr = self.run_cli(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("stored lock migration plan does not match proposal", stderr)
            self.assertFalse(Path(proposal["paths"]["active_marker"]).exists())

    def test_resume_completed_migration_rejects_forged_lock_payload_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            lock_path = Path(proposal["paths"]["placement_lock"])
            forged_lock = json.loads(lock_path.read_text(encoding="utf-8"))
            forged_lock["schema_version"] = 999
            forged_lock["unexpected"] = "field"
            forged_lock_bytes = mnemosyne.canonical_json_bytes(forged_lock)
            lock_path.write_bytes(forged_lock_bytes)
            lock_path.chmod(0o600)
            forged_hash = hashlib.sha256(forged_lock_bytes).hexdigest()
            final_result = Path(proposal["paths"]["final_run"]) / "result.json"
            completed_result = Path(proposal["paths"]["completed_result"])
            rebound = json.loads(final_result.read_text(encoding="utf-8"))
            rebound["placement_lock"]["sha256"] = forged_hash
            rebound_bytes = mnemosyne.canonical_json_bytes(rebound)
            final_result.write_bytes(rebound_bytes)
            completed_result.write_bytes(rebound_bytes)
            final_result.chmod(0o600)
            completed_result.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("placement lock binding mismatch", stderr)

    def test_resume_completed_migration_rejects_duplicate_quarantine_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            registry = root / "_registry" / "placement-map.yml"
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            lease_dir.mkdir(parents=True, exist_ok=True)
            for name in ["stale-a", "stale-b"]:
                lease = lease_dir / name
                lease.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "pid": os.getpid(),
                            "process_start_identity": f"reused-{name}",
                            "command": "approve",
                            "registry_sha256": hashlib.sha256(registry.read_bytes()).hexdigest(),
                        },
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                lease.chmod(0o600)
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            self.assertEqual(len(proposal["cleanup_effects"]), 2)
            code, _stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            final_result = Path(proposal["paths"]["final_run"]) / "result.json"
            completed_result = Path(proposal["paths"]["completed_result"])
            forged = json.loads(final_result.read_text(encoding="utf-8"))
            forged["quarantined_leases"] = [
                forged["quarantined_leases"][0],
                forged["quarantined_leases"][0],
            ]
            forged_bytes = mnemosyne.canonical_json_bytes(forged)
            final_result.write_bytes(forged_bytes)
            completed_result.write_bytes(forged_bytes)
            final_result.chmod(0o600)
            completed_result.chmod(0o600)

            code, stdout, stderr = self.run_cli_exact(
                "curation", "resume-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--resumed-by", "tester", "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("quarantine binding mismatch", stderr)

    def test_apply_lock_migration_never_quarantines_through_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            registry = root / "_registry" / "placement-map.yml"
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            lease_dir.mkdir(parents=True, exist_ok=True)
            stale = lease_dir / "stale"
            stale.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "pid": os.getpid(),
                        "process_start_identity": "reused-pid-start",
                        "command": "approve",
                        "registry_sha256": hashlib.sha256(registry.read_bytes()).hexdigest(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            stale.chmod(0o600)
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            quarantine = Path(proposal["cleanup_effects"][0]["target"])
            quarantine.parent.parent.mkdir(parents=True, exist_ok=True)
            quarantine.parent.symlink_to(outside_root, target_is_directory=True)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("verified quarantine parent", stderr)
            self.assertTrue(stale.is_file())
            self.assertEqual(list(outside_root.iterdir()), [])

    def test_apply_lock_migration_fails_if_quarantine_disappears_after_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            registry = root / "_registry" / "placement-map.yml"
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            lease_dir.mkdir(parents=True, exist_ok=True)
            stale = lease_dir / "stale"
            stale.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "pid": os.getpid(),
                        "process_start_identity": "reused-pid-start",
                        "command": "approve",
                        "registry_sha256": hashlib.sha256(registry.read_bytes()).hexdigest(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            stale.chmod(0o600)
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            quarantine = Path(proposal["cleanup_effects"][0]["target"])

            def remove_after_cleanup(name: str, _root: Path, _migration_id: str) -> None:
                if name == "stale-leases-quarantined":
                    quarantine.unlink()

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", remove_after_cleanup):
                code, stdout, stderr = self.run_cli_exact(
                    "curation", "apply-lock-migration",
                    "--proposal-id", proposal["migration_id"],
                    "--proposal-sha256", preview["sha256"],
                    "--approved-by", "tester", "--maintenance-window-confirmed",
                    "--root", str(root), "--json",
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("quarantined lease identity changed", stderr)
            self.assertTrue(Path(proposal["paths"]["active_marker"]).is_file())
            self.assertFalse(os.path.lexists(proposal["paths"]["placement_lock"]))
            self.assertFalse(os.path.lexists(proposal["paths"]["completed_marker"]))

    def test_resume_lock_migration_after_stale_lease_quarantine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            registry = root / "_registry" / "placement-map.yml"
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            lease_dir.mkdir(parents=True, exist_ok=True)
            stale = lease_dir / "stale"
            stale.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "pid": os.getpid(),
                        "process_start_identity": "reused-pid-start",
                        "command": "approve",
                        "registry_sha256": hashlib.sha256(registry.read_bytes()).hexdigest(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            stale.chmod(0o600)
            stale_before = stale.read_bytes()
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            migration_id = proposal["migration_id"]
            quarantine = Path(proposal["cleanup_effects"][0]["target"])

            def crash_after_quarantine(name: str, _root: Path, _migration_id: str) -> None:
                if name == "stale-leases-quarantined":
                    raise RuntimeError("simulated crash after stale quarantine")

            with mock.patch.object(mnemosyne, "lock_migration_checkpoint", crash_after_quarantine):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.run_cli(
                        "curation",
                        "apply-lock-migration",
                        "--proposal-id",
                        migration_id,
                        "--proposal-sha256",
                        preview["sha256"],
                        "--approved-by",
                        "tester",
                        "--maintenance-window-confirmed",
                        "--root",
                        str(root),
                        "--json",
                    )

            self.assertFalse(stale.exists())
            self.assertEqual(quarantine.read_bytes(), stale_before)

            code, stdout, stderr = self.run_cli(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                migration_id,
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(quarantine.read_bytes(), stale_before)
            self.assertFalse(stale.exists())
            result = json.loads(Path(proposal["paths"]["completed_result"]).read_text(encoding="utf-8"))
            self.assertEqual(result["quarantined_leases"][0]["target"], str(quarantine))

    def test_resume_completed_migration_rejects_recreated_quarantine_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            registry = root / "_registry" / "placement-map.yml"
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            lease_dir.mkdir(parents=True, exist_ok=True)
            stale = lease_dir / "stale"
            stale.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "pid": os.getpid(),
                        "process_start_identity": "reused-pid-start",
                        "command": "approve",
                        "registry_sha256": hashlib.sha256(registry.read_bytes()).hexdigest(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            stale.chmod(0o600)
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            quarantine = Path(proposal["cleanup_effects"][0]["target"])
            original_bytes = quarantine.read_bytes()
            original_inode = quarantine.stat().st_ino
            quarantine.unlink()
            quarantine.write_bytes(original_bytes)
            quarantine.chmod(0o600)
            self.assertNotEqual(quarantine.stat().st_ino, original_inode)

            code, stdout, stderr = self.run_cli_exact(
                "curation",
                "resume-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--resumed-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("quarantined lease identity changed", stderr)

    def test_legacy_writer_uses_verified_shared_lock_after_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            source = root / "inbox" / "post-migration.md"
            target = root / "docs" / source.name
            source.write_text("shared lock\n", encoding="utf-8")
            observed: list[Path] = []

            def inspect_shared_lock(_root: Path, lock_path: Path, lock_fd: int) -> None:
                self.assertEqual(lock_path, root.resolve() / "_registry" / "placement-map.lock")
                self.assertEqual(os.fstat(lock_fd).st_ino, lock_path.stat().st_ino)
                observed.append(lock_path)

            with mock.patch.object(
                mnemosyne,
                "legacy_writer_after_shared_lock_acquire",
                inspect_shared_lock,
                create=True,
            ):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(target),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(len(observed), 1)
            self.assertTrue(stdout.startswith("created proposal "))
            lease_dir = root / "_registry" / "lock-migrations" / "legacy-leases"
            self.assertFalse(lease_dir.exists() and any(lease_dir.iterdir()))

    def test_shared_lock_checkpoint_rejects_late_manual_recovery_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            source = root / "inbox" / "late-shared-blocker.md"
            source.write_text("must remain pending\n", encoding="utf-8")

            def publish_blocker_after_shared_lock(
                checkpoint_root: Path,
                _lock_path: Path,
                _lock_fd: int,
            ) -> None:
                self.publish_manual_recovery_blocker(checkpoint_root)

            with mock.patch.object(
                mnemosyne,
                "legacy_writer_after_shared_lock_acquire",
                publish_blocker_after_shared_lock,
            ):
                code, stdout, stderr = self.run_cli(
                    "propose-place",
                    str(source),
                    "--target",
                    str(root / "docs" / source.name),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("unresolved manual recovery blocker", stderr)
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_legacy_writer_rejects_same_bytes_placement_lock_aba_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            source = root / "inbox" / "aba.md"
            source.write_text("must not publish\n", encoding="utf-8")
            target = root / "docs" / source.name
            held_fds: list[int] = []

            def replace_lock(_root: Path, lock_path: Path, _lock_fd: int) -> None:
                displaced = lock_path.with_name("placement-map.lock.displaced")
                lock_path.rename(displaced)
                lock_path.write_bytes(displaced.read_bytes())
                lock_path.chmod(0o600)
                replacement_fd = os.open(lock_path, os.O_RDWR)
                mnemosyne.fcntl.flock(
                    replacement_fd,
                    mnemosyne.fcntl.LOCK_EX | mnemosyne.fcntl.LOCK_NB,
                )
                held_fds.append(replacement_fd)

            try:
                with mock.patch.object(
                    mnemosyne,
                    "legacy_writer_after_shared_lock_acquire",
                    replace_lock,
                ):
                    code, stdout, stderr = self.run_cli(
                        "propose-place", str(source), "--target", str(target),
                        "--root", str(root),
                    )
            finally:
                for held_fd in held_fds:
                    os.close(held_fd)

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("placement lock identity changed", stderr)
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_apply_lock_migration_rechecks_ledger_absence_after_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            ledger = root / "_registry" / "curation" / "ledger.sqlite3"
            ledger.parent.mkdir(parents=True, exist_ok=True)
            ledger.write_bytes(b"later M1 state")

            code, stdout, stderr = self.run_cli(
                "curation", "apply-lock-migration",
                "--proposal-id", proposal["migration_id"],
                "--proposal-sha256", preview["sha256"],
                "--approved-by", "tester", "--maintenance-window-confirmed",
                "--root", str(root), "--json",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("ledger to be absent", stderr)
            self.assertFalse(Path(proposal["paths"]["active_marker"]).exists())
            self.assertFalse(Path(proposal["paths"]["placement_lock"]).exists())
            self.assertFalse(Path(proposal["paths"]["incomplete_run"]).exists())
            self.assertFalse(Path(proposal["paths"]["final_run"]).exists())
            self.assertFalse(Path(proposal["paths"]["completed_marker"]).exists())

    def test_apply_lock_migration_rechecks_ledger_after_completion_seam(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation", "preview-lock-migration", "--requested-by", "tester",
                "--root", str(root), "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            ledger = root / "_registry" / "curation" / "ledger.sqlite3"

            def create_late_ledger(_active: Path, _completed: Path) -> None:
                ledger.parent.mkdir(parents=True, exist_ok=True)
                ledger.write_bytes(b"late M1 state")

            with mock.patch.object(
                mnemosyne,
                "lock_migration_before_completed_marker_publish",
                create_late_ledger,
            ):
                code, stdout, stderr = self.run_cli(
                    "curation", "apply-lock-migration",
                    "--proposal-id", proposal["migration_id"],
                    "--proposal-sha256", preview["sha256"],
                    "--approved-by", "tester", "--maintenance-window-confirmed",
                    "--root", str(root), "--json",
                )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("ledger to be absent", stderr)
            self.assertTrue(Path(proposal["paths"]["active_marker"]).is_file())
            self.assertFalse(Path(proposal["paths"]["completed_marker"]).exists())

    def test_legacy_writer_still_uses_shared_lock_after_curation_policy_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)

            registry = root / "_registry" / "placement-map.yml"
            registry.write_text(
                registry.read_text(encoding="utf-8")
                + "\ncuration:\n"
                + "  movement_writer: legacy\n"
                + "  structural_apply: disabled\n"
                + "  writer_epoch: legacy-v1\n",
                encoding="utf-8",
            )
            source = root / "inbox" / "after-policy-bootstrap.md"
            source.write_text("shared lock remains authoritative\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertTrue(stdout.startswith("created proposal "))

    def test_legacy_writer_never_falls_back_when_completed_placement_lock_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            (root / "_registry" / "placement-map.lock").unlink()
            source = root / "inbox" / "missing-lock.md"
            source.write_text("must remain\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: completed lock migration requires placement lock; lockless fallback is forbidden\n",
            )
            self.assertTrue(source.is_file())
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_legacy_writer_never_falls_back_through_symlinked_completed_root(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_root = Path(outside).resolve()
            self.run_cli("bootstrap", "--root", str(root))
            code, stdout, stderr = self.run_cli(
                "curation",
                "preview-lock-migration",
                "--requested-by",
                "tester",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            preview = json.loads(stdout)["registry_updates"][0]
            proposal = json.loads(Path(preview["path"]).read_text(encoding="utf-8"))
            code, _stdout, stderr = self.run_cli(
                "curation",
                "apply-lock-migration",
                "--proposal-id",
                proposal["migration_id"],
                "--proposal-sha256",
                preview["sha256"],
                "--approved-by",
                "tester",
                "--maintenance-window-confirmed",
                "--root",
                str(root),
                "--json",
            )
            self.assertEqual(code, 0, stderr)
            (root / "_registry" / "placement-map.lock").unlink()
            completed_root = root / "_registry" / "lock-migrations" / "completed"
            completed_root.rename(root / "_registry" / "lock-migrations" / "completed-hidden")
            completed_root.symlink_to(outside_root, target_is_directory=True)
            source = root / "inbox" / "hidden-completion.md"
            source.write_text("must remain\n", encoding="utf-8")

            code, stdout, stderr = self.run_cli_exact(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / source.name),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(
                stderr,
                "error: completed lock migration requires placement lock; lockless fallback is forbidden\n",
            )
            self.assertEqual(list((root / "_registry" / "pending").glob("*.yml")), [])

    def test_audit_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            (root / "loose.txt").write_text("orphan\n", encoding="utf-8")
            before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))

            code, stdout, stderr = self.run_cli("audit", "--root", str(root), "--max-depth", "2")

            after = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
            self.assertEqual(code, 0, stderr)
            self.assertIn("writes: none", stdout)
            self.assertEqual(before, after)

    def test_never_touch_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "graphify-out" / "graph.json"
            source.parent.mkdir()
            source.write_text("{}", encoding="utf-8")

            code, _, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "docs" / "graph.json"),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("never-touch", stderr)

    def test_directory_proposal_rejects_symlink_descendant(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "artifacts" / "okf-candidate" / "example"
            source.mkdir(parents=True)
            document = source / "index.md"
            document.write_text("# Example\n", encoding="utf-8")
            (source / "linked.md").symlink_to(document)

            code, _, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(root / "artifacts" / "okf" / "example"),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("symlink descendant", stderr)

    def test_proposal_rejects_top_level_source_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            real_source = root / "artifacts" / "real"
            real_source.mkdir(parents=True)
            (real_source / "index.md").write_text("# Real\n", encoding="utf-8")
            alias = root / "inbox" / "alias"
            alias.symlink_to(real_source, target_is_directory=True)

            code, _, stderr = self.run_cli(
                "propose-place",
                str(alias),
                "--target",
                str(root / "artifacts" / "moved"),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("symlink component", stderr)
            self.assertTrue(real_source.exists())

    def test_proposal_rejects_external_alias_to_raw_root(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as aliases:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "note.md"
            source.write_text("note\n", encoding="utf-8")
            root_alias = Path(aliases) / "raw-alias"
            root_alias.symlink_to(root, target_is_directory=True)

            code, _, stderr = self.run_cli(
                "propose-place",
                str(root_alias / "inbox" / "note.md"),
                "--target",
                str(root / "docs" / "note.md"),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("symlink component", stderr)
            self.assertTrue(source.exists())

    def test_approval_rejects_target_parent_replaced_by_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "note.md"
            source.write_text("note\n", encoding="utf-8")
            target = root / "docs" / "note.md"

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]

            redirect = root / "artifacts" / "redirect"
            redirect.mkdir(parents=True)
            (root / "docs").symlink_to(redirect, target_is_directory=True)

            code, _, stderr = self.run_cli("approve", proposal_id, "--root", str(root))

            self.assertEqual(code, 2)
            self.assertIn("symlink component", stderr)
            self.assertTrue(source.exists())
            self.assertFalse((redirect / "note.md").exists())

    def test_approval_rejects_target_parent_symlink_to_raw_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "inbox" / "note.md"
            source.write_text("note\n", encoding="utf-8")
            target = root / "docs" / "note.md"

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]
            (root / "docs").symlink_to(root, target_is_directory=True)

            code, _, stderr = self.run_cli("approve", proposal_id, "--root", str(root))

            self.assertEqual(code, 2)
            self.assertIn("symlink component", stderr)
            self.assertTrue(source.exists())
            self.assertFalse((root / "note.md").exists())

    def test_approve_moves_safe_directory_and_records_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            source = root / "artifacts" / "okf-candidate" / "example"
            source.mkdir(parents=True)
            (source / "index.md").write_text("# Example\n", encoding="utf-8")
            target = root / "artifacts" / "okf" / "example"

            code, stdout, stderr = self.run_cli(
                "propose-place",
                str(source),
                "--target",
                str(target),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            proposal_id = stdout.strip().splitlines()[-1].split()[-1]

            code, _, stderr = self.run_cli(
                "approve",
                proposal_id,
                "--actor",
                "tester",
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertFalse(source.exists())
            self.assertEqual((target / "index.md").read_text(encoding="utf-8"), "# Example\n")
            self.assertEqual(len(list((root / "_registry" / "decisions").glob("*.yml"))), 1)

    def test_memory_sync_snapshot_replaces_prior_current_state_detail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = self.write_memory_workspace(root)
            first, _ = mnemosyne.build_updated_snapshot(
                snapshot.read_text(encoding="utf-8"),
                "2026-07-09T00:00:00Z",
                ["memory-sync: first"],
                "example-service",
                "First sync",
                "First summary.",
                [{"title": "Current fact", "items": ["Old fact"]}],
            )
            second, _ = mnemosyne.build_updated_snapshot(
                first,
                "2026-07-10T00:00:00Z",
                ["memory-sync: second"],
                "example-service",
                "Second sync",
                "Second summary.",
                [{"title": "Current fact", "items": ["New fact"]}],
            )

            self.assertIn("New fact", second)
            self.assertNotIn("Old fact", second)
            self.assertEqual(second.count("  current_state:"), 1)

    def test_memory_sync_plan_seals_effects_without_writing_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_text(encoding="utf-8")
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "workspace-sync-plan.json"

            code, stdout, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "PR 123 merged",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertIn("mode: memory-sync plan", stdout)
            self.assertIn("plan_sha256:", stdout)
            self.assertTrue(plan_path.is_file())
            self.assertEqual(stat.S_IMODE(plan_path.stat().st_mode), 0o600)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["schema"], "mnemosyne-workspace-sync-plan-v2")
            self.assertEqual(plan["workstream_status"], "new")
            self.assertEqual(plan["workspace"], "example-service")
            snapshot_effect = next(
                effect for effect in plan["effects"] if effect["path"].endswith("/snapshot.md")
            )
            self.assertIn("- id: example-service", snapshot_effect["final_text"])
            self.assertIn("status: active", snapshot_effect["final_text"])
            self.assertIn("Sanitized outcome summary.", snapshot_effect["final_text"])
            self.assertIn("현재 저장소와 CI에서 확인된 사실", snapshot_effect["final_text"])
            self.assertEqual(snapshot.read_text(encoding="utf-8"), before)
            self.assertFalse((root / "memory" / "example-service" / "history").exists())

    def test_memory_sync_requires_structured_approval_review_before_sealing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_text(encoding="utf-8")
            plan_path = root / "workspace-sync-plan.json"

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "PR 123 merged",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("requires --approval-review", stderr)
            self.assertFalse(plan_path.exists())
            self.assertEqual(snapshot.read_text(encoding="utf-8"), before)

    def test_memory_sync_rejects_plan_that_exceeds_apply_size_bound_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_text(encoding="utf-8")
            review_path = self.write_memory_sync_approval_review(root)
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review["current_state_groups"] = [
                {
                    "title": "Large bounded review",
                    "items": [("safe detail. " * 240_000).strip()],
                }
            ]
            review_path.write_text(
                json.dumps(review, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            review_path.chmod(0o600)
            plan_path = root / "workspace-sync-plan.json"

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Bounded approval review",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("workspace sync Plan is too large", stderr)
            self.assertFalse(plan_path.exists())
            self.assertEqual(snapshot.read_text(encoding="utf-8"), before)
            self.assertFalse((root / "memory" / "example-service" / "history").exists())

    def test_memory_sync_rejects_plan_that_exceeds_operation_request_transport_bound_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_text(encoding="utf-8")
            review_path = self.write_memory_sync_approval_review(root)
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review["current_state_groups"] = [
                {
                    "title": "Transport-bounded review",
                    "items": [("safe detail. " * 90_000).strip()],
                }
            ]
            review_path.write_text(
                json.dumps(review, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            review_path.chmod(0o600)
            self.assertLess(review_path.stat().st_size, 8 * 1024 * 1024)
            plan_path = root / "workspace-sync-plan.json"

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Transport-bounded approval review",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("operation request transport limit", stderr)
            self.assertFalse(plan_path.exists())
            self.assertEqual(snapshot.read_text(encoding="utf-8"), before)
            self.assertFalse((root / "memory" / "example-service" / "history").exists())

    def test_memory_sync_rejects_plan_output_inside_raw_memory_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_text(encoding="utf-8")
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "memory" / "example-service" / "pending-plan.json"

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Plan destination boundary",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("plan output must be outside raw memory", stderr)
            self.assertFalse(plan_path.exists())
            self.assertEqual(snapshot.read_text(encoding="utf-8"), before)

    def test_memory_sync_rejects_plan_output_parent_swapped_into_raw_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "raw"
            root.mkdir()
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_text(encoding="utf-8")
            review_path = self.write_memory_sync_approval_review(root)
            plan_parent = root.parent / "safe-plans"
            plan_parent.mkdir()
            plan_path = plan_parent / "pending-plan.json"
            raw_memory_parent = root / "memory" / "example-service"
            original_write = mnemosyne.write_owner_only_plan

            def swap_parent_then_write(path, plan_bytes, **kwargs):
                plan_parent.rename(root.parent / "safe-plans-original")
                os.symlink(raw_memory_parent, plan_parent)
                return original_write(path, plan_bytes, **kwargs)

            with mock.patch.object(
                mnemosyne,
                "write_owner_only_plan",
                side_effect=swap_parent_then_write,
            ):
                code, _, stderr = self.run_cli(
                    "memory-sync",
                    "--workspace",
                    "example-service",
                    "--title",
                    "Plan parent boundary",
                    "--summary",
                    "Sanitized outcome summary.",
                    "--ref",
                    "public-pr: example-service#123",
                    "--approval-review",
                    str(review_path),
                    "--plan-out",
                    str(plan_path),
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertIn("plan output parent changed", stderr)
            self.assertFalse((raw_memory_parent / plan_path.name).exists())
            self.assertEqual(snapshot.read_text(encoding="utf-8"), before)

    def test_memory_sync_renders_sealed_adaptive_approval_card(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_text(encoding="utf-8")
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "workspace-sync-plan.json"

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "PR 123 merged",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["schema"], "mnemosyne-workspace-sync-plan-v2")
            self.assertEqual(
                plan["approval_review"]["schema"],
                "mnemosyne-workspace-sync-approval-review-v1",
            )

            code, card, stderr = self.run_cli(
                "memory-sync",
                "--render-approval-card",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertTrue(card.startswith("# 승인 요청 — example-service\n\n## 한눈에 보기\n"))
            self.assertIn("> - **저장할 요약:** Sanitized outcome summary.", card)
            self.assertLess(card.index("## 한눈에 보기"), card.index("## 최신 상태에 반영할 내용"))
            self.assertLess(card.index("## 최신 상태에 반영할 내용"), card.index("## 기록으로 남길 내용"))
            self.assertLess(card.index("## 기록으로 남길 내용"), card.index("## 이번 기록에 포함하지 않는 내용"))
            self.assertIn("### 현재 저장소와 CI에서 확인된 사실", card)
            self.assertIn("### 사용자가 정한 운영 방향", card)
            self.assertIn("### 아직 실제 실행으로 확인하지 않은 것", card)
            self.assertIn("### 기존 기록에서 이어 가거나 바로잡는 내용", card)
            self.assertIn("`public-pr: example-service#123` — 현재 구현과 CI를 대조한 자료", card)
            self.assertNotIn(str(plan_path), card)
            self.assertNotIn("plan_sha256:", card)
            self.assertEqual(card.rstrip().splitlines()[-1], "이 내용 그대로 적용할까요?")
            self.assertEqual(snapshot.read_text(encoding="utf-8"), before)
            self.assertFalse((root / "memory" / "example-service" / "history").exists())

    def test_memory_sync_card_exposes_effect_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            self.write_memory_workspace(root)
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "workspace-sync-plan.json"

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Timestamp-bound review",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))

            code, card, stderr = self.run_cli(
                "memory-sync",
                "--render-approval-card",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertIn(f"> - **기록 시각:** {plan['created_at']}", card)

    def test_memory_sync_rejects_symlinked_approved_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_text(encoding="utf-8")
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "workspace-sync-plan.json"
            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Symlinked plan boundary",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            linked_plan = root / "linked-plan.json"
            linked_plan.symlink_to(plan_path.name)

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--render-approval-card",
                str(linked_plan),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("cannot open approved plan", stderr)
            self.assertEqual(snapshot.read_text(encoding="utf-8"), before)

    def test_memory_sync_apply_plan_creates_history_receipt_and_updates_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "workspace-sync-plan.json"

            code, plan_stdout, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "PR 123 merged",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--workstream",
                "example-service",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            plan_sha256 = next(
                line.split(":", 1)[1].strip()
                for line in plan_stdout.splitlines()
                if line.startswith("plan_sha256:")
            )

            code, stdout, stderr = self.run_cli(
                "memory-sync",
                "--apply-plan",
                str(plan_path),
                "--expected-plan-sha256",
                plan_sha256,
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertIn("outcome: completed", stdout)
            self.assertIn("claim_mode: HISTORICAL", stdout)
            self.assertIn("history:", stdout)
            self.assertIn("receipt:", stdout)
            history_files = list((root / "memory" / "example-service" / "history").glob("*.md"))
            self.assertEqual(len(history_files), 1)
            history = history_files[0].read_text(encoding="utf-8")
            self.assertIn("workspace: example-service", history)
            self.assertIn("workstream: example-service", history)
            self.assertIn("Sanitized outcome summary.", history)
            self.assertIn("## 최신 상태에 반영한 내용", history)
            self.assertIn("### 기존 기록에서 이어 가거나 바로잡는 내용", history)

            updated = snapshot.read_text(encoding="utf-8")
            self.assertIn("- existing-ref: keep-me", updated)
            self.assertIn("- memory-sync: pr-123-merged", updated)
            self.assertIn("- public-pr: example-service#123", updated)
            self.assertNotIn("updated_at: 2026-01-01T00:00:00Z", updated)
            self.assertIn("- id: example-service", updated)
            self.assertIn("status: active", updated)
            self.assertIn("Sanitized outcome summary.", updated)
            self.assertIn("current_state:", updated)
            self.assertIn("아직 실제 실행으로 확인하지 않은 것", updated)
            receipt_files = list((root / "memory" / "_receipts" / "workspace-sync").glob("*.json"))
            self.assertEqual(len(receipt_files), 1)

    def test_memory_sync_apply_plan_rejects_effect_not_derived_from_sealed_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_bytes()
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "workspace-sync-plan.json"
            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Captured outcome",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            history_effect = next(
                effect
                for effect in plan["effects"]
                if "/history/" in effect["path"]
            )
            hidden_effect = "Hidden effect not shown in the approval card."
            history_effect["final_text"] += f"\n{hidden_effect}\n"
            history_effect["final_sha256"] = mnemosyne.sha256_bytes(
                history_effect["final_text"].encode("utf-8")
            )
            plan_bytes = mnemosyne.canonical_json_bytes(plan) + b"\n"
            plan_path.write_bytes(plan_bytes)
            expected_plan_sha256 = mnemosyne.sha256_bytes(plan_bytes)

            code, card, stderr = self.run_cli(
                "memory-sync",
                "--render-approval-card",
                str(plan_path),
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertNotIn(hidden_effect, card)

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--apply-plan",
                str(plan_path),
                "--expected-plan-sha256",
                expected_plan_sha256,
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("PLAN_MISMATCH", stderr)
            self.assertEqual(snapshot.read_bytes(), before)
            self.assertFalse((root / "memory" / "example-service" / "history").exists())
            self.assertFalse((root / "memory" / "_receipts").exists())

    def test_memory_sync_apply_plan_rejects_changed_snapshot_without_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "workspace-sync-plan.json"
            code, stdout, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Captured outcome",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            plan_sha256 = next(
                line.split(":", 1)[1].strip()
                for line in stdout.splitlines()
                if line.startswith("plan_sha256:")
            )
            changed = snapshot.read_text(encoding="utf-8") + "Concurrent update.\n"
            snapshot.write_text(changed, encoding="utf-8")

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--apply-plan",
                str(plan_path),
                "--expected-plan-sha256",
                plan_sha256,
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("BASE_CHANGED", stderr)
            self.assertEqual(snapshot.read_text(encoding="utf-8"), changed)
            self.assertFalse((root / "memory" / "example-service" / "history").exists())
            self.assertFalse((root / "memory" / "_receipts").exists())

    def test_memory_sync_apply_plan_rolls_back_partial_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            snapshot = self.write_memory_workspace(root)
            before = snapshot.read_bytes()
            review_path = self.write_memory_sync_approval_review(root)
            plan_path = root / "workspace-sync-plan.json"
            code, stdout, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Captured outcome",
                "--summary",
                "Sanitized outcome summary.",
                "--ref",
                "public-pr: example-service#123",
                "--approval-review",
                str(review_path),
                "--plan-out",
                str(plan_path),
                "--root",
                str(root),
            )
            self.assertEqual(code, 0, stderr)
            plan_sha256 = next(
                line.split(":", 1)[1].strip()
                for line in stdout.splitlines()
                if line.startswith("plan_sha256:")
            )
            original_replace = mnemosyne.os.replace
            calls = 0

            def fail_third_rename(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("injected workspace sync failure")
                return original_replace(*args, **kwargs)

            with mock.patch.object(mnemosyne.os, "replace", side_effect=fail_third_rename):
                code, _, stderr = self.run_cli(
                    "memory-sync",
                    "--apply-plan",
                    str(plan_path),
                    "--expected-plan-sha256",
                    plan_sha256,
                    "--root",
                    str(root),
                )

            self.assertEqual(code, 2)
            self.assertIn("APPLY_FAILED", stderr)
            self.assertEqual(snapshot.read_bytes(), before)
            self.assertFalse((root / "memory" / "example-service" / "history").exists())
            self.assertFalse((root / "memory" / "_receipts").exists())

    def test_memory_sync_unknown_workspace_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            (root / "memory").mkdir(exist_ok=True)
            (root / "memory" / "workspaces.yml").write_text("schema_version: 1\nworkspaces:\n", encoding="utf-8")

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "missing",
                "--title",
                "Event",
                "--summary",
                "Summary",
                "--ref",
                "public-pr: repo#1",
                "--plan-out",
                str(root / "unknown-workspace-plan.json"),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("unknown workspace", stderr)

    def test_memory_sync_rejects_unsafe_content_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            self.write_memory_workspace(root)

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "example-service",
                "--title",
                "Unsafe",
                "--summary",
                "Bearer abcdefghijklmnopqrstuvwxyz",
                "--ref",
                "public-pr: repo#1",
                "--plan-out",
                str(root / "unsafe-plan.json"),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("unsafe content", stderr)
            self.assertFalse((root / "memory" / "example-service" / "history").exists())

    def test_memory_sync_rejects_workspace_slug_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            (root / "memory").mkdir(exist_ok=True)
            (root / "memory" / "workspaces.yml").write_text("schema_version: 1\nworkspaces:\n", encoding="utf-8")

            code, _, stderr = self.run_cli(
                "memory-sync",
                "--workspace",
                "../worktrees",
                "--title",
                "Event",
                "--summary",
                "Summary",
                "--ref",
                "public-pr: repo#1",
                "--allow-unknown",
                "--plan-out",
                str(root / "traversal-plan.json"),
                "--root",
                str(root),
            )

            self.assertEqual(code, 2)
            self.assertIn("invalid workspace slug", stderr)

    def test_context_unknown_workspace_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            (root / "memory").mkdir(exist_ok=True)
            (root / "memory" / "workspaces.yml").write_text("schema_version: 1\nworkspaces:\n", encoding="utf-8")

            code, _, stderr = self.run_cli("context", "--workspace", "missing", "--root", str(root))

            self.assertEqual(code, 2)
            self.assertIn("unknown workspace", stderr)

    def test_context_returns_snapshot_and_history_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            self.write_memory_workspace(root)
            self.write_history(
                root,
                "example-service",
                "20260709T010000Z-alpha.md",
                "Alpha Event",
                "Alpha sanitized history body.",
            )

            code, stdout, stderr = self.run_cli(
                "context",
                "--workspace",
                "example-service",
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertIn("mode: context", stdout)
            self.assertIn("## Snapshot", stdout)
            self.assertIn("Existing body stays.", stdout)
            self.assertIn("## Recent history", stdout)
            self.assertIn("Alpha Event", stdout)
            self.assertIn("writes: none", stdout)

    def test_context_history_limit_max_chars_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            self.write_memory_workspace(root)
            self.write_history(root, "example-service", "20260709T010000Z-one.md", "One", "first body " * 50)
            self.write_history(root, "example-service", "20260709T020000Z-two.md", "Two", "second body " * 50)
            before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))

            code, stdout, stderr = self.run_cli(
                "context",
                "--workspace",
                "example-service",
                "--history",
                "1",
                "--max-chars",
                "900",
                "--root",
                str(root),
            )

            after = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
            self.assertEqual(code, 0, stderr)
            self.assertLessEqual(len(stdout), 900)
            self.assertIn("Recent history (1)", stdout)
            self.assertEqual(before, after)

    def test_context_question_prefers_matching_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            self.write_memory_workspace(root)
            self.write_history(root, "example-service", "20260709T010000Z-alpha.md", "Alpha", "alpha unrelated body")
            self.write_history(
                root,
                "example-service",
                "20260709T020000Z-quarantine.md",
                "Quarantine Fix",
                "quarantine retry ledger body",
            )

            code, stdout, stderr = self.run_cli(
                "context",
                "--workspace",
                "example-service",
                "--question",
                "quarantine retry",
                "--history",
                "1",
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            self.assertIn("Quarantine Fix", stdout)
            self.assertNotIn("alpha unrelated body", stdout)

    def test_context_json_contains_stable_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            self.write_memory_workspace(root)
            self.write_history(root, "example-service", "20260709T010000Z-alpha.md", "Alpha", "Alpha body")

            code, stdout, stderr = self.run_cli(
                "context",
                "--workspace",
                "example-service",
                "--json",
                "--root",
                str(root),
            )

            self.assertEqual(code, 0, stderr)
            package = __import__("json").loads(stdout)
            self.assertEqual(package["mode"], "context")
            self.assertEqual(package["workspace"], "example-service")
            self.assertIn("snapshot_excerpt", package)
            self.assertEqual(package["history"][0]["title"], "Alpha")
            self.assertIsNone(package["graphify"])

    def test_context_with_graphify_soft_fails_when_graph_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.run_cli("bootstrap", "--root", str(root))
            self.write_memory_workspace(root)
            before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))

            code, stdout, stderr = self.run_cli(
                "context",
                "--workspace",
                "example-service",
                "--with-graphify",
                "--root",
                str(root),
            )

            after = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
            self.assertEqual(code, 0, stderr)
            self.assertIn("graphify not available", stdout)
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
