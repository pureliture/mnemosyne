import ast
import inspect
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR.parent / "tests"))

import mnemosyne  # noqa: E402
import mnemosyne_core  # noqa: E402
from mnemosyne_core import ledger_runtime  # noqa: E402
from mnemosyne_core import m4_workflow  # noqa: E402
from mnemosyne_core import m3_schema_migration  # noqa: E402
from mnemosyne_core import authority_runtime  # noqa: E402
from mnemosyne_core import curation_audit  # noqa: E402
from mnemosyne_core import inspect_audit_operation  # noqa: E402
from mnemosyne_core import operation_contract  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402
from mnemosyne_core.operation_control import composition, execution  # noqa: E402
from test_mnemosyne_ledger_runtime import BASE_REGISTRY, LedgerRuntimeFixture  # noqa: E402


class D1bOperationControlBoundaryTest(unittest.TestCase):
    def _capabilities_request(self):
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.capabilities",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.NONE,
            root="/private/tmp/mnemosyne-d1b-operation-control",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.NONE,
            payload={},
            bounds={"max_items": 50},
        )

    def _audit_request(self, root: Path):
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.audit",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            payload={"offset": 0},
            bounds={"max_items": 64},
        )

    def test_root_exposes_only_the_single_operation_control_executor(self):
        self.assertEqual(mnemosyne_core.__all__, ["execute_request_bytes"])
        self.assertIs(
            mnemosyne_core.execute_request_bytes,
            execution.execute_request_bytes,
        )
        for module_name in (
            "mnemosyne_core.operation_control.composition",
            "mnemosyne_core.operation_control.execution",
        ):
            with self.subTest(module_name=module_name):
                self.assertIn(module_name, mnemosyne._BOOTSTRAP_CORE_MODULES)
                self.assertIs(
                    sys.modules[module_name],
                    mnemosyne._BOOTSTRAP_CORE_MODULES[module_name],
                )

    def test_normal_import_cannot_bypass_verified_bootstrap(self):
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(SCRIPT_DIR)

        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import mnemosyne_core; mnemosyne_core.execute_request_bytes",
            ],
            cwd=str(SCRIPT_DIR),
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(probe.returncode, 0)
        self.assertIn("_verified_source_manifest", probe.stderr)

    def test_composition_has_one_complete_static_row_per_existing_capability(self):
        catalog = composition.DEFAULT_OPERATION_CATALOG
        source_hashes = mnemosyne._BOOTSTRAP_CORE_SOURCE_HASHES
        source_manifest = mnemosyne._mnemosyne_core._verified_source_manifest

        self.assertEqual(len(catalog.specs), 55)
        self.assertEqual(
            {spec.operation_kind for spec in catalog.specs},
            {
                "control.bootstrap",
                "control.lock_migration",
                "control.schema_migration",
                "control.writer_cutover",
                "curation.activation",
                "curation.plan_apply",
                "graphify.query",
                "graphify.update",
                "inspect.audit",
                "inspect.capabilities",
                "inspect.history",
                "inspect.pending",
                "inspect.recovery",
                "inspect.scope",
                "inspect.status",
                "inventory.run",
                "librarian.decision",
                "librarian.placement",
                "librarian.proposal",
                "memory.workspace_sync",
                "movement.placement",
                "movement.recovery",
                "movement.reversal",
                "navigation.baseline_drift",
                "navigation.build",
                "navigation.projects_baseline",
                "navigation.sync",
                "navigation.update",
                "okf.bundle",
                "okf.validation",
                "pilot.expansion",
                "pilot.gate",
                "pilot.poststate",
                "pilot.prework",
                "pilot.prework_validation",
                "pilot.rebase",
                "pilot.retry",
                "policy.bootstrap",
                "policy.change",
                "policy.drift",
                "policy.reconcile",
                "review.batch",
                "review.batch_event",
                "review.batch_split",
                "review.decision",
                "review.deferral",
                "review.deferral_evidence",
                "review.draft",
                "review.legacy_import",
                "review.run",
                "review.submission",
                "review.unit_explosion",
                "review.validation",
                "scope.expansion",
                "workstream.lifecycle_override",
            },
        )
        available = {
            spec.operation_kind
            for spec in catalog.specs
            if spec.availability is composition.OperationAvailability.AVAILABLE
        }
        self.assertEqual(
            available,
            {
                "curation.activation",
                "curation.plan_apply",
                "inspect.audit",
                "inspect.capabilities",
                "inspect.history",
                "inspect.pending",
                "inspect.scope",
                "librarian.decision",
                "librarian.placement",
                "librarian.proposal",
                "memory.workspace_sync",
            },
        )
        for spec in catalog.specs:
            with self.subTest(operation_kind=spec.operation_kind):
                self.assertEqual(
                    spec.source_module,
                    "mnemosyne_core.operation_control.composition",
                )
                self.assertEqual(spec.source_symbol, "_ROW_SPECS")
                self.assertEqual(
                    spec.source_path,
                    "operation_control/composition.py",
                )
                self.assertEqual(
                    spec.source_sha256,
                    source_hashes[spec.source_module],
                )
                def callable_metadata(value):
                    if value is None:
                        return None
                    return {
                        "module": value.__module__,
                        "path": source_manifest[value.__module__]["relative_path"],
                        "sha256": source_hashes[value.__module__],
                        "symbol": value.__name__,
                    }

                expected_handler = callable_metadata(spec.handler)
                expected_identity = {
                    "actions": [
                        action.value
                        for action in spec.admission_contract.allowed_actions
                    ],
                    "authority_mode": spec.admission_contract.authority_mode.value,
                    "availability": spec.availability.value,
                    "availability_reason": spec.availability_reason,
                    "approval_required": spec.admission_contract.approval_required,
                    "approval_requirement": (
                        spec.admission_contract.approval_requirement.canonical_value
                        if spec.admission_contract.approval_requirement is not None
                        else None
                    ),
                    "bounds_schema": list(spec.admission_contract.bounds_schema),
                    "claim_modes": [
                        claim_mode.value
                        for claim_mode in spec.admission_contract.allowed_claim_modes
                    ],
                    "handler": expected_handler,
                    "operation_kind": spec.operation_kind,
                    "read_profile": spec.admission_contract.read_profile.value,
                    "prerequisite_artifacts": [
                        requirement.canonical_value
                        for requirement in spec.admission_contract.prerequisite_artifacts
                    ],
                    "request_validator": callable_metadata(spec.request_validator),
                    "result_validator": callable_metadata(spec.result_validator),
                    "row_source": {
                        "module": spec.source_module,
                        "path": spec.source_path,
                        "sha256": spec.source_sha256,
                        "symbol": spec.source_symbol,
                    },
                    "schema_version": 1,
                    "scope_schema": list(spec.admission_contract.scope_schema),
                    "spec_identity": spec.spec_identity,
                    "write_profile": spec.admission_contract.write_profile.value,
                }
                self.assertEqual(
                    spec.spec_sha256,
                    sha256_bytes(canonical_json_bytes(expected_identity)),
                )
                if spec.operation_kind in available:
                    self.assertTrue(callable(spec.handler))
                    self.assertTrue(callable(spec.request_validator))
                    self.assertTrue(callable(spec.result_validator))
                    self.assertEqual(
                        spec.handler_sha256,
                        source_hashes[spec.handler_module],
                    )
                else:
                    self.assertIsNone(spec.handler)
                    self.assertIsNone(spec.request_validator)
                    self.assertIsNone(spec.result_validator)

        audit = catalog.require_spec("inspect.audit")
        self.assertEqual(
            audit.admission_contract.read_profile,
            operation_contract.ReadProfile.CURATION_AUDIT,
        )
        self.assertEqual(
            audit.handler_module,
            "mnemosyne_core.inspect_audit_operation",
        )
        self.assertEqual(audit.handler_symbol, "audit_handler")
        self.assertEqual(
            catalog.require_spec("inspect.capabilities").admission_contract.read_profile,
            operation_contract.ReadProfile.STANDARD,
        )
        activation = catalog.require_spec("curation.activation")
        self.assertIs(
            activation.availability,
            composition.OperationAvailability.AVAILABLE,
        )
        self.assertIsNone(activation.availability_reason)
        self.assertEqual(
            activation.admission_contract.allowed_actions,
            (operation_contract.LifecycleAction.APPLY,),
        )
        self.assertEqual(
            activation.admission_contract.allowed_claim_modes,
            (operation_contract.ClaimMode.CURRENT,),
        )
        self.assertEqual(
            activation.admission_contract.authority_mode,
            operation_contract.AuthorityMode.WRITE,
        )
        self.assertEqual(activation.admission_contract.scope_schema, ("activation_id",))
        self.assertEqual(activation.admission_contract.bounds_schema, ())
        self.assertEqual(
            activation.admission_contract.write_profile.value,
            "CURATION_ACTIVATION",
        )
        self.assertEqual(activation.handler_symbol, "activation_handler")
        self.assertEqual(
            activation.request_validator.__name__,
            "validate_activation_request",
        )
        self.assertEqual(
            activation.result_validator.__name__,
            "validate_activation_result",
        )

    def test_stateless_capabilities_request_uses_the_production_executor(self):
        request = self._capabilities_request()

        raw_result = mnemosyne_core.execute_request_bytes(request.canonical_bytes)
        result = json.loads(raw_result.decode("utf-8"))

        self.assertEqual(result["outcome_kind"], "completed")
        self.assertEqual(result["request_sha256"], request.sha256)
        self.assertEqual(
            result["result"]["summary"],
            {"available": 11, "blocked": 21, "deferred": 23, "total": 55},
        )
        self.assertEqual(result["result"]["returned"], 50)
        self.assertTrue(result["result"]["truncated"])
        self.assertEqual(
            [entry["operation_kind"] for entry in result["result"]["capabilities"]],
            sorted(entry["operation_kind"] for entry in result["result"]["capabilities"]),
        )

    def test_public_executor_rejects_oversized_bytes_before_decode(self):
        raw = b"x" * (1024 * 1024 + 1)

        with mock.patch.object(
            execution,
            "decode_operation_request",
            side_effect=AssertionError("oversized bytes reached the decoder"),
        ):
            result = json.loads(
                mnemosyne_core.execute_request_bytes(raw).decode("utf-8")
            )

        self.assertEqual(result["outcome_kind"], "blocked")
        self.assertEqual(result["reason_code"], "INVALID_REQUEST")
        self.assertEqual(result["next_safe_action"], "correct-request")

    def test_public_audit_unactivated_root_is_nonactivating(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            registry = root / "_registry"
            registry.mkdir(mode=0o755)
            registry_path = registry / "placement-map.yml"
            registry_path.write_bytes(
                BASE_REGISTRY.replace(b"{root}", str(root).encode("utf-8"))
            )
            registry_path.chmod(0o644)
            before = tuple(root.rglob("*"))
            request = self._audit_request(root)

            with mock.patch.object(
                ledger_runtime,
                "open_reader_session",
                side_effect=AssertionError("unactivated audit must not open a reader"),
            ):
                raw_result = mnemosyne_core.execute_request_bytes(
                    request.canonical_bytes
                )
            after = tuple(root.rglob("*"))
            curation_exists = (root / "_registry" / "curation").exists()

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "completed")
        self.assertEqual(result["request_sha256"], request.sha256)
        self.assertEqual(result["result"]["view"], "audit")
        self.assertEqual(result["result"]["schema_version"], 2)
        self.assertEqual(result["result"]["activation_state"], "NOT_ACTIVATED")
        self.assertTrue(result["result"]["activation_eligible"])
        self.assertTrue(result["result"]["read_only"])
        self.assertEqual(result["result"]["returned"], 0)
        self.assertFalse(result["result"]["truncated"])
        self.assertEqual(after, before)
        self.assertFalse(curation_exists)

    def test_public_audit_active_profile_uses_immutable_readers_only(self):
        policy = SimpleNamespace(
            raw_hash="a" * 64,
            full_hash="b" * 64,
            writer_control_hash="c" * 64,
            foundation_hash="d" * 64,
            generation=1,
            source_kind="INITIAL",
            source_run_id="audit-profile-test",
            guard_epoch=0,
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            control_root = root / "_registry" / "curation"
            control_root.mkdir(parents=True, mode=0o700)
            registry_path = root / "_registry" / "placement-map.yml"
            registry_path.write_bytes(
                BASE_REGISTRY.replace(b"{root}", str(root).encode("utf-8"))
            )
            registry_path.chmod(0o644)
            reader = mock.MagicMock()
            reader.current_policy.return_value = policy
            connection = sqlite3.connect(":memory:")
            connection.row_factory = sqlite3.Row
            reader.connection = connection
            reader.compiled_policy = SimpleNamespace(
                foundation=SimpleNamespace(state_root=str(control_root)),
                workstreams=(),
            )
            reader_session = mock.MagicMock()
            reader_session.__enter__.return_value = reader
            reader_session.__exit__.return_value = False
            request = self._audit_request(root)
            self.assertFalse(hasattr(m4_workflow, "curation_audit"))

            try:
                with mock.patch.object(
                    ledger_runtime,
                    "open_reader_session",
                    return_value=reader_session,
                ) as open_reader:
                    raw_result = mnemosyne_core.execute_request_bytes(
                        request.canonical_bytes
                    )
            finally:
                connection.close()

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "completed")
        self.assertEqual(result["result"]["schema_version"], 2)
        self.assertEqual(
            result["result"]["activation_state"],
            "RECOVERY_REQUIRED",
        )
        self.assertFalse(result["result"]["activation_eligible"])
        self.assertEqual(
            result["result"]["reason_code"],
            "PRESEAL_ORPHAN",
        )
        self.assertIsNone(result["result"]["initial_policy"])
        self.assertNotIn("activation_markers", result["result"])
        self.assertEqual(
            open_reader.call_args_list,
            [
                mock.call(root, immutable=True),
                mock.call(root, immutable=True),
            ],
        )

    def test_public_audit_policy_blocked_preserves_audit_diagnostic(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            (root / "_registry" / "curation").mkdir(parents=True, mode=0o700)
            registry_path = root / "_registry" / "placement-map.yml"
            registry_path.write_bytes(
                BASE_REGISTRY.replace(b"{root}", str(root).encode("utf-8"))
            )
            registry_path.chmod(0o644)
            request = self._audit_request(root)
            failure = ledger_runtime.PolicyAdmissionError("policy is unavailable")

            with mock.patch.object(
                ledger_runtime,
                "open_reader_session",
                side_effect=failure,
            ):
                raw_result = mnemosyne_core.execute_request_bytes(
                    request.canonical_bytes
                )

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "completed")
        self.assertEqual(result["result"]["schema_version"], 2)
        self.assertEqual(
            result["result"]["activation_state"],
            "RECOVERY_REQUIRED",
        )
        self.assertFalse(result["result"]["activation_eligible"])
        self.assertEqual(
            result["result"]["reason_code"],
            "PRESEAL_ORPHAN",
        )
        self.assertNotIn("activation_markers", result["result"])

    def test_public_audit_unavailable_preserves_audit_diagnostic(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            (root / "_registry" / "curation").mkdir(parents=True, mode=0o700)
            registry_path = root / "_registry" / "placement-map.yml"
            registry_path.write_bytes(
                BASE_REGISTRY.replace(b"{root}", str(root).encode("utf-8"))
            )
            registry_path.chmod(0o644)
            request = self._audit_request(root)
            failure = ledger_runtime.LedgerRuntimeError("reader is unavailable")

            with mock.patch.object(
                ledger_runtime,
                "open_reader_session",
                side_effect=failure,
            ):
                raw_result = mnemosyne_core.execute_request_bytes(
                    request.canonical_bytes
                )

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "completed")
        self.assertEqual(result["result"]["schema_version"], 2)
        self.assertEqual(
            result["result"]["activation_state"],
            "RECOVERY_REQUIRED",
        )
        self.assertFalse(result["result"]["activation_eligible"])
        self.assertEqual(
            result["result"]["reason_code"],
            "PRESEAL_ORPHAN",
        )
        self.assertNotIn("activation_markers", result["result"])

    def test_policy_blocked_audit_fences_when_availability_recovers_on_open(self):
        policy = SimpleNamespace(
            raw_hash="a" * 64,
            full_hash="b" * 64,
            writer_control_hash="c" * 64,
            foundation_hash="d" * 64,
            generation=1,
            source_kind="INITIAL",
            source_run_id="audit-recovery-fence-test",
            guard_epoch=0,
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            (root / "_registry" / "curation").mkdir(parents=True, mode=0o700)
            request = self._audit_request(root)
            reader = mock.MagicMock()
            reader.current_policy.return_value = policy
            reader_session = mock.MagicMock()
            reader_session.__enter__.return_value = reader
            reader_session.__exit__.return_value = False

            with mock.patch.object(
                ledger_runtime,
                "open_reader_session",
                side_effect=[
                    ledger_runtime.PolicyAdmissionError("policy blocked"),
                    reader_session,
                ],
            ):
                raw_result = mnemosyne_core.execute_request_bytes(
                    request.canonical_bytes
                )

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "blocked")
        self.assertEqual(result["reason_code"], "ADMISSION_DENIED")

    def test_invalid_audit_page_is_rejected_before_root_admission(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.audit",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root="/private/tmp/mnemosyne-d1b-no-root-access",
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            payload={"offset": -1},
            bounds={"max_items": 64},
        )

        with mock.patch.object(
            authority_runtime,
            "admit",
            side_effect=AssertionError("invalid audit page reached authority admission"),
        ):
            raw_result = mnemosyne_core.execute_request_bytes(request.canonical_bytes)

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "blocked")
        self.assertEqual(result["reason_code"], "INVALID_REQUEST")

    def test_activation_fence_preserves_typed_public_reason(self):
        request = self._audit_request(
            Path("/private/tmp/mnemosyne-a3-typed-activation-fence")
        )
        fence = authority_runtime.ActivationOperationFence(
            "same activation request is required",
            reason_code="REQUEST_MISMATCH",
            next_safe_action="review-original-request",
        )

        with mock.patch.object(authority_runtime, "admit", side_effect=fence):
            raw_result = mnemosyne_core.execute_request_bytes(
                request.canonical_bytes
            )

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "blocked")
        self.assertEqual(result["reason_code"], "REQUEST_MISMATCH")
        self.assertEqual(
            result["next_safe_action"],
            "review-original-request",
        )

    def test_audit_v2_projection_keeps_full_report_findings_and_totals(self):
        report = curation_audit.report_from_findings(
            [
                {
                    "blocking": True,
                    "category": "integrity",
                    "code": "curation-state-not-activated",
                },
                {
                    "blocking": True,
                    "category": "orphan",
                    "code": "second-finding",
                },
                {
                    "blocking": False,
                    "category": "integrity",
                    "code": "third-finding",
                },
            ]
        )

        evidence = SimpleNamespace(
            public_fields=lambda: {
                "exact_root": "/private/tmp/mnemosyne-audit-v2",
                "activation_state": "BLOCKED",
                "activation_eligible": False,
                "reason_code": "FOUNDATION_READBACK_FAILED",
                "next_safe_action": "Review the activation foundation manually.",
                "allowed_namespace": "_registry/curation",
                "corpus_effect": "none",
                "root_identity_sha256": "e" * 64,
                "initial_policy": None,
            }
        )
        result = inspect_audit_operation.project_activation_audit_report(
            report,
            evidence,
            offset=1,
            maximum=1,
        )

        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["activation_state"], "BLOCKED")
        self.assertNotIn("activation_markers", result)
        self.assertEqual(result["blocking_total"], 2)
        self.assertEqual(result["findings"], [report["findings"][1]])
        self.assertEqual(
            result["blockers"],
            ["audit-findings-truncated", "second-finding"],
        )
        self.assertEqual(result["next_offset"], 2)
        self.assertTrue(result["truncated"])

    def test_audit_handler_module_has_no_legacy_or_raw_capability_imports(self):
        source = inspect.getsource(inspect_audit_operation)
        imports = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imports.update(alias.name.rsplit(".", 1)[-1] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module.rsplit(".", 1)[-1])

        self.assertTrue(
            imports.isdisjoint(
                {
                    "curation_harness",
                    "curation_registry",
                    "ledger_runtime",
                    "m4_workflow",
                    "pathlib",
                    "sqlite3",
                }
            )
        )

    def test_unactivated_audit_fences_control_root_created_after_admission(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            request = self._audit_request(root)
            original_admit = authority_runtime.admit

            def admit_then_change_control(*args, **kwargs):
                admitted = original_admit(*args, **kwargs)
                (root / "_registry" / "curation").mkdir(parents=True, mode=0o700)
                return admitted

            with mock.patch.object(
                authority_runtime,
                "admit",
                side_effect=admit_then_change_control,
            ):
                raw_result = mnemosyne_core.execute_request_bytes(
                    request.canonical_bytes
                )

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "blocked")
        self.assertEqual(result["reason_code"], "ADMISSION_DENIED")
        self.assertNotIn("result", result)

    def test_active_audit_fences_policy_changed_after_query(self):
        initial = SimpleNamespace(
            raw_hash="a" * 64,
            full_hash="b" * 64,
            writer_control_hash="c" * 64,
            foundation_hash="d" * 64,
            generation=1,
            source_kind="INITIAL",
            source_run_id="audit-drift-test",
            guard_epoch=0,
        )
        changed = SimpleNamespace(
            raw_hash="a" * 64,
            full_hash="e" * 64,
            writer_control_hash="c" * 64,
            foundation_hash="d" * 64,
            generation=2,
            source_kind="INITIAL",
            source_run_id="audit-drift-test",
            guard_epoch=0,
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            control_root = root / "_registry" / "curation"
            control_root.mkdir(parents=True, mode=0o700)
            connection = sqlite3.connect(":memory:")
            connection.row_factory = sqlite3.Row
            reader = mock.MagicMock()
            reader.connection = connection
            reader.current_policy.side_effect = [initial, initial, initial, changed]
            reader.compiled_policy = SimpleNamespace(
                foundation=SimpleNamespace(state_root=str(control_root)),
                workstreams=(),
            )
            reader_session = mock.MagicMock()
            reader_session.__enter__.return_value = reader
            reader_session.__exit__.return_value = False
            request = self._audit_request(root)

            try:
                with mock.patch.object(
                    ledger_runtime,
                    "open_reader_session",
                    return_value=reader_session,
                ):
                    raw_result = mnemosyne_core.execute_request_bytes(
                        request.canonical_bytes
                    )
            finally:
                connection.close()

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "blocked")
        self.assertEqual(result["reason_code"], "ADMISSION_DENIED")
        self.assertNotIn("result", result)

    def test_audit_result_validator_rejects_forged_activation_state(self):
        report = curation_audit.not_activated_report()
        evidence = SimpleNamespace(
            public_fields=lambda: {
                "exact_root": "/private/tmp/mnemosyne-audit-v2",
                "activation_state": "NOT_ACTIVATED",
                "activation_eligible": True,
                "reason_code": "FRESH_CURATION_STATE",
                "next_safe_action": "Review one activation draft; no document will move.",
                "allowed_namespace": "_registry/curation",
                "corpus_effect": "none",
                "root_identity_sha256": "e" * 64,
                "initial_policy": {
                    "mode": "safe-librarian-initial-curation-v1",
                    "registry_input_sha256": "1" * 64,
                    "overlay_sha256": "2" * 64,
                    "effective_policy_source_sha256": "3" * 64,
                    "full_hash": "4" * 64,
                    "writer_control_hash": "5" * 64,
                    "foundation_hash": "6" * 64,
                },
            }
        )
        result = inspect_audit_operation.project_activation_audit_report(
            report,
            evidence,
            offset=0,
            maximum=64,
        )
        result["activation_state"] = "ACTIVE"
        outcome = operation_contract.OperationOutcome.completed(
            "a" * 64,
            result=result,
        )

        with self.assertRaisesRegex(ValueError, "activation audit result"):
            inspect_audit_operation.validate_audit_result(outcome)


class D1bPublicActiveAuditRuntimeTest(LedgerRuntimeFixture):
    def setUp(self):
        super().setUp()
        self.migrate_to_v2()
        plan = m3_schema_migration.preview_m3_migration(
            self.root,
            plan_id="m3mig-plan-d1b-public-audit",
            requested_by="d1b-public-audit-test",
        )
        approval = m3_schema_migration.approve_m3_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approved_by="d1b-public-audit-approver",
        )
        m3_schema_migration.apply_m3_migration(
            self.root,
            plan_id=plan["plan_id"],
            expected_plan_sha256=plan["plan_sha256"],
            requested_by=plan["requested_by"],
            approval_id=approval["approval_id"],
            approval_sha256=approval["approval_sha256"],
            executed_by="d1b-public-audit-executor",
        )

    def _tree_snapshot(self):
        entries = []
        for path in self.root.rglob("*"):
            info = path.lstat()
            file_type = stat.S_IFMT(info.st_mode)
            if stat.S_ISREG(info.st_mode):
                content_identity = sha256_bytes(path.read_bytes())
            elif stat.S_ISLNK(info.st_mode):
                content_identity = os.readlink(path)
            else:
                content_identity = None
            entries.append(
                (
                    str(path.relative_to(self.root)),
                    file_type,
                    stat.S_IMODE(info.st_mode),
                    info.st_uid,
                    info.st_nlink,
                    content_identity,
                )
            )
        return tuple(sorted(entries))

    def test_public_executor_preserves_active_audit_and_tree(self):
        request = operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="inspect.audit",
            action=operation_contract.LifecycleAction.INSPECT,
            claim_mode=operation_contract.ClaimMode.HISTORICAL,
            root=str(self.root),
            actor="operator",
            requested_authority=operation_contract.AuthorityMode.READ,
            payload={"offset": 0},
            bounds={"max_items": 64},
        )
        before = self._tree_snapshot()

        raw_result = mnemosyne_core.execute_request_bytes(request.canonical_bytes)

        result = json.loads(raw_result.decode("utf-8"))
        self.assertEqual(result["outcome_kind"], "completed")
        self.assertEqual(result["request_sha256"], request.sha256)
        self.assertEqual(result["result"]["schema_version"], 2)
        self.assertEqual(result["result"]["activation_state"], "BLOCKED")
        self.assertFalse(result["result"]["activation_eligible"])
        self.assertEqual(
            result["result"]["reason_code"],
            "LEGACY_AUTHORITY_PRESENT",
        )
        self.assertFalse(result["result"]["integrity_ok"])
        self.assertIsNone(result["result"]["initial_policy"])
        self.assertNotIn("activation_markers", result["result"])
        self.assertEqual(result["result"]["view"], "audit")
        self.assertEqual(self._tree_snapshot(), before)


if __name__ == "__main__":
    unittest.main()
