"""TDD coverage for Context-bound Plan activation."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import (  # noqa: E402
    canonical_curation,
    canonical_curation_review,
    context_assembly,
    operation_contract,
    workstream_curation,
)
from mnemosyne_core.authority_runtime import canonical_curation as runtime  # noqa: E402
from mnemosyne_core.cli.request_builder import (  # noqa: E402
    build_context_activation_request,
)
from mnemosyne_core.operation_contract.codec import encode_operation_request  # noqa: E402
from mnemosyne_core.operation_control import execution  # noqa: E402
from test_mnemosyne_context_bound_curation_plan import (  # noqa: E402
    _complete_context,
    _plan,
)
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


_HASH = "a" * 64


def _context_plan() -> canonical_curation.ContextBoundCurationPlan:
    return canonical_curation.compile_curation_plan(
        _plan(),
        context_assembly=_complete_context(),
    )


def _context_plan_with_effect_count(
    effect_count: int,
) -> canonical_curation.ContextBoundCurationPlan:
    base_complete = _complete_context()
    base_assembly = base_complete.assembly
    base_source = base_assembly.sources[0]
    base_plan = _plan()
    base_observation = base_plan.source_observations[0]
    base_effect = base_plan.effects[0]
    sources = []
    observations = []
    effects = []
    for index in range(effect_count):
        suffix = f"{index:03d}"
        observation_id = f"obs-current-local-{suffix}"
        source_path = f"projects/alpha/note-{suffix}.md"
        output_path = f"projects/alpha/work-results/note-{suffix}.md"
        inode = 100 + index
        modified_time_ns = 1000 + index
        sources.append(
            replace(
                base_source,
                source_id=observation_id,
                relative_path=source_path,
                observation_id=observation_id,
                identity=(11, inode, 1000, 0o600, 1, 7, modified_time_ns),
            )
        )
        observations.append(
            replace(
                base_observation,
                observation_id=observation_id,
                relative_path=source_path,
                inode=inode,
                modified_time_ns=modified_time_ns,
            )
        )
        effects.append(
            replace(
                base_effect,
                effect_id=f"effect-current-local-{suffix}",
                input_observation_id=observation_id,
                source_path=source_path,
                output_path=output_path,
            )
        )
    assembly = replace(
        base_assembly,
        sources=tuple(sources),
        coverage=replace(
            base_assembly.coverage,
            local_inspected=effect_count,
            source_group_counts=(("OTHER_NESTED", effect_count),),
        ),
    )
    complete = assembly.require_complete(
        expected_workstream=assembly.workstream,
        expected_policy_sha256=assembly.policy_sha256,
        expected_root_identity=assembly.root_identity,
        expected_project_identity=assembly.project_identity,
        expected_assembly_sha256=assembly.sha256,
        expected_coverage_sha256=assembly.coverage_sha256,
    )
    return canonical_curation.compile_curation_plan(
        replace(
            base_plan,
            source_observations=tuple(observations),
            effects=tuple(effects),
            coverage=(
                ("bounds", {"max_depth": 4, "max_items": effect_count}),
                ("inspected_files", effect_count),
            ),
        ),
        context_assembly=complete,
    )


def _request(
    plan: canonical_curation.ContextBoundCurationPlan,
    *,
    root: str,
) -> operation_contract.OperationRequest:
    return operation_contract.OperationRequest(
        schema_version=1,
        operation_kind="curation.plan_apply",
        action=operation_contract.LifecycleAction.APPLY,
        claim_mode=operation_contract.ClaimMode.CURRENT,
        root=root,
        actor="context-fence-test",
        requested_authority=operation_contract.AuthorityMode.WRITE,
        payload={
            "decision": {
                "action": "APPROVE_ALL",
                "approved_plan_sha256": plan.sha256,
                "displayed_plan_sha256": plan.sha256,
                "reason": None,
                "review_package_hashes": {
                    "html_sha256": _HASH,
                    "markdown_sha256": _HASH,
                    "meta_sha256": _HASH,
                    "semantic_sha256": _HASH,
                },
                "selected_effect_ids": [effect.effect_id for effect in plan.effects],
                "source_observation_sha256": plan.plan.source_observation_sha256,
            },
            "plan": plan.canonical_value,
            "review_package_directory": "/private/tmp/context-bound-review",
        },
        bounds={"max_effects": 16, "max_total_bytes": 1024 * 1024},
        scope={
            "plan_sha256": plan.sha256,
            "workstream_id": plan.primary_workstream_id,
        },
    )


def _request_payload_copy(request: operation_contract.OperationRequest) -> dict[str, object]:
    return json.loads(request.canonical_bytes)["payload"]


class ContextBoundCurationApplyFenceTest(unittest.TestCase):
    def test_context_request_builder_has_no_fixed_effect_count_ceiling(self):
        plan = _context_plan_with_effect_count(4)

        request = build_context_activation_request(
            root="/private/tmp/context-count-unbounded",
            actor="context-count-test",
            plan=plan,
            review_package_directory="/private/tmp/context-count-review",
            review_package_hashes={
                "html_sha256": _HASH,
                "markdown_sha256": _HASH,
                "meta_sha256": _HASH,
                "semantic_sha256": _HASH,
            },
            decision="APPROVE_ALL",
        )

        self.assertEqual(request.bounds["max_effects"], 4)

    def test_context_operation_control_has_no_fixed_effect_count_ceiling(self):
        plan = _context_plan_with_effect_count(65)
        request = build_context_activation_request(
            root="/private/tmp/context-count-unbounded",
            actor="context-count-test",
            plan=plan,
            review_package_directory="/private/tmp/context-count-review",
            review_package_hashes={
                "html_sha256": _HASH,
                "markdown_sha256": _HASH,
                "meta_sha256": _HASH,
                "semantic_sha256": _HASH,
            },
            decision="APPROVE_ALL",
        )

        runtime.validate_plan_apply_request(request)
        decoded, *_rest = runtime.decode_context_admitted_input(
            {
                "action": request.action,
                "approval_artifact": None,
                "bounds": dict(request.bounds),
                "operation_kind": request.operation_kind,
                "payload": dict(request.payload),
                "prerequisite_artifacts": [],
                "scope": dict(request.scope),
            }
        )

        self.assertEqual(len(decoded.effects), 65)

    def test_curation_result_validation_has_no_fixed_effect_count_ceiling(self):
        effects = [
            {
                "content_sha256": "b" * 64,
                "effect_id": f"effect-current-local-{index:03d}",
                "output_path": f"projects/alpha/work-results/note-{index:03d}.md",
                "source_path": f"projects/alpha/note-{index:03d}.md",
            }
            for index in range(65)
        ]
        outcome = operation_contract.OperationOutcome.completed(
            "a" * 64,
            result={
                "decision_sha256": "c" * 64,
                "effect_count": 65,
                "effects": effects,
                "equality": {
                    "content_hashes_match": True,
                    "effect_membership_complete": True,
                    "staging_empty": True,
                },
                "plan_sha256": "d" * 64,
                "reason_code": None,
                "request_sha256": "a" * 64,
                "schema": "mnemosyne-canonical-curation-result-v1",
                "status": "FINALIZED",
                "workstream_id": "alpha",
            },
        )

        runtime.validate_plan_apply_result(outcome)

    def test_recovery_intent_has_no_fixed_effect_count_ceiling(self):
        plan = _context_plan_with_effect_count(65)
        intent = runtime._intent_value(
            plan,
            request_sha256="a" * 64,
            decision_sha256="c" * 64,
        )

        membership = runtime._validate_intent_membership(intent, plan.sha256)

        self.assertEqual(len(membership), 65)

    def test_exact_decoder_reconstructs_complete_context_bound_plan(self):
        plan = _context_plan()

        decoded = runtime.decode_context_bound_plan(plan.canonical_value)

        self.assertEqual(decoded.canonical_value, plan.canonical_value)
        self.assertEqual(decoded.sha256, plan.sha256)

    def test_context_admitted_decoder_rejects_finding_bearing_plan(self):
        plan = canonical_curation.compile_curation_plan(
            replace(
                _plan(),
                findings=(
                    canonical_curation.CurationFinding(
                        finding_id="finding-000000000000000000000001",
                        finding_kind="ROLE_AMBIGUOUS",
                        relative_path="projects/alpha/notes.md",
                        evidence=("explicit role conflict",),
                    ),
                ),
            ),
            context_assembly=_complete_context(),
        )
        request = _request(plan, root="/private/tmp/context-finding-decoder")
        admitted_input = {
            "action": request.action,
            "approval_artifact": None,
            "bounds": {"max_effects": 1, "max_total_bytes": 1024 * 1024},
            "operation_kind": request.operation_kind,
            "payload": request.payload,
            "prerequisite_artifacts": [],
            "scope": request.scope,
        }

        with self.assertRaisesRegex(
            ValueError,
            "Context-bound Curation admitted input scope or bounds mismatch",
        ):
            runtime.decode_context_admitted_input(admitted_input)

    def test_decoder_rejects_noncanonical_nested_coverage_and_binding_mismatch(self):
        plan = _context_plan()
        nested_coverage = dict(plan.canonical_value)
        nested_coverage["coverage"] = dict(nested_coverage["coverage"])
        nested_coverage["coverage"]["bounds"]["max_depth"] = 4.5
        wrong_binding = dict(plan.canonical_value)
        wrong_binding["context_binding"] = dict(wrong_binding["context_binding"])
        wrong_binding["context_binding"]["coverage_sha256"] = "b" * 64

        for malformed in (nested_coverage, wrong_binding):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    runtime.decode_context_bound_plan(malformed)

    def test_malformed_context_bound_schema_is_invalid_request(self):
        plan = _context_plan()
        malformed = dict(plan.canonical_value)
        malformed["context_binding"] = dict(malformed["context_binding"])
        malformed["context_binding"]["outcome"] = "PARTIAL"
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            request = _request(plan, root=temporary)
            payload = _request_payload_copy(request)
            payload["plan"] = malformed
            malformed_request = operation_contract.OperationRequest(
                schema_version=request.schema_version,
                operation_kind=request.operation_kind,
                action=request.action,
                claim_mode=request.claim_mode,
                root=request.root,
                actor=request.actor,
                requested_authority=request.requested_authority,
                payload=payload,
                bounds=dict(request.bounds),
                scope=dict(request.scope),
            )

            outcome = json.loads(
                execution.execute_request_bytes(encode_operation_request(malformed_request))
            )

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")

    def test_dispatcher_preserves_legacy_v1_and_transform_v2_routes(self):
        legacy_request = _request(_context_plan(), root="/private/tmp/context-route")
        legacy_payload = _request_payload_copy(legacy_request)
        legacy_plan = _plan()
        legacy_payload["plan"] = legacy_plan.canonical_value
        legacy_request = operation_contract.OperationRequest(
            schema_version=legacy_request.schema_version,
            operation_kind=legacy_request.operation_kind,
            action=legacy_request.action,
            claim_mode=legacy_request.claim_mode,
            root=legacy_request.root,
            actor=legacy_request.actor,
            requested_authority=legacy_request.requested_authority,
            payload=legacy_payload,
            bounds=dict(legacy_request.bounds),
            scope={
                "plan_sha256": legacy_plan.sha256,
                "workstream_id": legacy_plan.primary_workstream_id,
            },
        )
        transform_payload = dict(legacy_payload)
        transform_payload["plan"] = {"schema": "mnemosyne-canonical-curation-plan-v2"}
        transform_request = operation_contract.OperationRequest(
            schema_version=legacy_request.schema_version,
            operation_kind=legacy_request.operation_kind,
            action=legacy_request.action,
            claim_mode=legacy_request.claim_mode,
            root=legacy_request.root,
            actor=legacy_request.actor,
            requested_authority=legacy_request.requested_authority,
            payload=transform_payload,
            bounds=dict(legacy_request.bounds),
            scope=dict(legacy_request.scope),
        )

        with mock.patch.object(runtime, "_validated_request") as legacy_validate:
            runtime.validate_plan_apply_request(legacy_request)
        legacy_validate.assert_called_once_with(legacy_request)

        with mock.patch(
            "mnemosyne_core.authority_runtime.canonical_curation_m3.validate_plan_apply_request"
        ) as transform_validate:
            runtime.validate_plan_apply_request(transform_request)
        transform_validate.assert_called_once_with(transform_request)


class ContextBoundCurationApplyPublicTest(LedgerRuntimeFixture):
    """Prove one sealed Context Plan uses the existing public move boundary."""

    def setUp(self) -> None:
        with mock.patch.object(tempfile, "tempdir", "/private/tmp"):
            super().setUp()
        self.migrate_to_v2()
        self.project = self.root / "example-service"
        self.target_directory = self.project / "decisions"
        self.target_directory.mkdir(parents=True, mode=0o700)
        self.source = self.project / "loose-decision.md"
        self.target = self.target_directory / "loose-decision.md"
        self.source_bytes = b"# Decision\n\nMove this exact document.\n"
        self.source.write_bytes(self.source_bytes)
        self.source.chmod(0o600)
        self.review_temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.review_temporary.cleanup)
        self.review_directory = Path(self.review_temporary.name).resolve() / "review"
        self.review_directory.mkdir(mode=0o700)

    def _add_two_more_effect_sources(
        self,
    ) -> tuple[tuple[Path, Path, bytes], ...]:
        status_directory = self.project / "status"
        references_directory = self.project / "references"
        status_directory.mkdir(mode=0o700)
        references_directory.mkdir(mode=0o700)
        rows = (
            (
                self.project / "current-status.md",
                status_directory / "current-status.md",
                b"# Current Status\n\nReady for review.\n",
            ),
            (
                self.project / "reference-evidence.md",
                references_directory / "reference-evidence.md",
                b"# Reference Evidence\n\nBounded source.\n",
            ),
        )
        for source, _target, raw in rows:
            source.write_bytes(raw)
            source.chmod(0o600)
        return rows

    def _sealed_plan(self, *, expected_effects: int = 1) -> tuple[
        canonical_curation.ContextBoundCurationPlan,
        dict[str, str],
        object,
    ]:
        inspection = workstream_curation.inspect_workstream(
            root=self.root,
            workstream_ref="example-service",
            review_package_directory=self.review_directory,
            max_items=16,
            max_depth=4,
            max_hint_bytes=4096,
            actor="context-activation-test",
        )
        self.assertEqual(inspection["outcome_kind"], "completed")
        hashes, plan_value, assembly = (
            canonical_curation_review.validate_context_bound_review_directory(
                self.review_directory,
                expected_plan_sha256=inspection["result"]["plan"]["sha256"],
            )
        )
        plan = runtime.decode_context_bound_plan(plan_value)
        self.assertEqual(len(plan.effects), expected_effects)
        effect_paths = {
            (effect.source_path, effect.output_path) for effect in plan.effects
        }
        if expected_effects:
            self.assertIn(
                (
                    "example-service/loose-decision.md",
                    "example-service/decisions/loose-decision.md",
                ),
                effect_paths,
            )
        return (
            plan,
            {
                "html_sha256": hashes.html_sha256,
                "markdown_sha256": hashes.markdown_sha256,
                "meta_sha256": hashes.meta_sha256,
                "semantic_sha256": hashes.semantic_sha256,
            },
            assembly,
        )

    def _request(
        self,
        plan: canonical_curation.ContextBoundCurationPlan,
        review_hashes: dict[str, str],
        *,
        review_directory: Path | None = None,
    ) -> operation_contract.OperationRequest:
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="curation.plan_apply",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="context-activation-test",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={
                "decision": {
                    "action": "APPROVE_ALL",
                    "approved_plan_sha256": plan.sha256,
                    "displayed_plan_sha256": plan.sha256,
                    "reason": None,
                    "review_package_hashes": review_hashes,
                    "selected_effect_ids": [
                        effect.effect_id for effect in plan.effects
                    ],
                    "source_observation_sha256": plan.source_observation_sha256,
                },
                "plan": plan.canonical_value,
                "review_package_directory": str(
                    self.review_directory
                    if review_directory is None
                    else review_directory
                ),
            },
            bounds={"max_effects": len(plan.effects), "max_total_bytes": 1024 * 1024},
            scope={
                "plan_sha256": plan.sha256,
                "workstream_id": "example-service",
            },
        )

    def test_more_than_sixty_four_effects_apply_in_one_transaction(self) -> None:
        source_bytes = {self.source: self.source_bytes}
        for index in range(65):
            source = self.project / f"implementation-notes-{index:03d}.md"
            raw = f"# Implementation Notes {index:03d}\n\nExact source.\n".encode(
                "utf-8"
            )
            source.write_bytes(raw)
            source.chmod(0o600)
            source_bytes[source] = raw
        work_directory = self.project / "work"
        work_directory.mkdir(mode=0o700)

        inspection = workstream_curation.inspect_workstream(
            root=self.root,
            workstream_ref="example-service",
            review_package_directory=self.review_directory,
            max_items=128,
            max_depth=4,
            max_hint_bytes=4096,
            actor="context-count-runtime-test",
        )
        self.assertEqual(inspection["outcome_kind"], "completed")
        hashes, plan_value, _assembly = (
            canonical_curation_review.validate_context_bound_review_directory(
                self.review_directory,
                expected_plan_sha256=inspection["result"]["plan"]["sha256"],
            )
        )
        plan = runtime.decode_context_bound_plan(plan_value)
        request = build_context_activation_request(
            root=str(self.root),
            actor="context-count-runtime-test",
            plan=plan,
            review_package_directory=str(self.review_directory),
            review_package_hashes={
                "html_sha256": hashes.html_sha256,
                "markdown_sha256": hashes.markdown_sha256,
                "meta_sha256": hashes.meta_sha256,
                "semantic_sha256": hashes.semantic_sha256,
            },
            decision="APPROVE_ALL",
        )

        outcome = json.loads(
            execution.execute_request_bytes(encode_operation_request(request))
        )

        self.assertEqual(len(plan.effects), 66)
        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertEqual(outcome["result"]["status"], "FINALIZED")
        self.assertEqual(outcome["result"]["effect_count"], 66)
        for source, raw in source_bytes.items():
            target = self.target if source == self.source else work_directory / source.name
            self.assertFalse(source.exists())
            self.assertEqual(target.read_bytes(), raw)
            self.assertEqual(
                hashlib.sha256(target.read_bytes()).hexdigest(),
                hashlib.sha256(raw).hexdigest(),
            )

    def test_public_exact_context_plan_moves_one_file(self) -> None:
        plan, review_hashes, _assembly = self._sealed_plan()
        request = self._request(plan, review_hashes)

        outcome = json.loads(
            execution.execute_request_bytes(encode_operation_request(request))
        )

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertEqual(outcome["result"]["status"], "FINALIZED")
        self.assertEqual(outcome["result"]["plan_sha256"], plan.sha256)
        self.assertFalse(self.source.exists())
        self.assertEqual(self.target.read_bytes(), self.source_bytes)

    def test_approve_all_with_finding_is_blocked_without_mutation(self) -> None:
        plan, _review_hashes, assembly = self._sealed_plan()
        complete = assembly.require_complete(
            expected_workstream=assembly.workstream,
            expected_policy_sha256=assembly.policy_sha256,
            expected_root_identity=assembly.root_identity,
            expected_project_identity=assembly.project_identity,
            expected_assembly_sha256=assembly.sha256,
            expected_coverage_sha256=assembly.coverage_sha256,
        )
        blocked_inner_plan = replace(
            plan.plan,
            findings=(
                canonical_curation.CurationFinding(
                    finding_id="finding-000000000000000000000001",
                    finding_kind="ROLE_AMBIGUOUS",
                    relative_path="example-service/loose-decision.md",
                    evidence=("explicit role conflict",),
                ),
            ),
        )
        blocked_plan = canonical_curation.compile_curation_plan(
            blocked_inner_plan,
            context_assembly=complete,
        )
        blocked_review_directory = (
            Path(self.review_temporary.name).resolve() / "blocked-review"
        )
        blocked_review_directory.mkdir(mode=0o700)
        payload = canonical_curation_review.compile_context_bound_review(
            blocked_plan,
            context_assembly=complete,
            rendered_at="2026-07-20T00:00:00Z",
            renderer_id="context-finding-apply-fence-test",
        )
        hashes = canonical_curation_review.write_context_bound_review_package(
            blocked_review_directory,
            payload,
        )
        review_hashes = {
            "html_sha256": hashes.html_sha256,
            "markdown_sha256": hashes.markdown_sha256,
            "meta_sha256": hashes.meta_sha256,
            "semantic_sha256": hashes.semantic_sha256,
        }

        outcome = json.loads(
            execution.execute_request_bytes(
                encode_operation_request(
                    self._request(
                        blocked_plan,
                        review_hashes,
                        review_directory=blocked_review_directory,
                    )
                )
            )
        )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assertFalse(self.target.exists())

    def test_public_exact_context_plan_moves_three_files_as_one_transaction(self) -> None:
        extra_rows = self._add_two_more_effect_sources()
        plan, review_hashes, _assembly = self._sealed_plan(expected_effects=3)

        outcome = json.loads(
            execution.execute_request_bytes(
                encode_operation_request(self._request(plan, review_hashes))
            )
        )

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertEqual(outcome["result"]["status"], "FINALIZED")
        self.assertEqual(outcome["result"]["plan_sha256"], plan.sha256)
        for source in (self.source, *(row[0] for row in extra_rows)):
            self.assertFalse(source.exists())
        self.assertEqual(self.target.read_bytes(), self.source_bytes)
        for _source, target, raw in extra_rows:
            self.assertEqual(target.read_bytes(), raw)

    def test_resealed_context_subset_applies_as_approve_all(self) -> None:
        extra_rows = self._add_two_more_effect_sources()
        full_plan, _full_hashes, assembly = self._sealed_plan(expected_effects=3)
        self.assertIsInstance(assembly, context_assembly.ContextAssembly)
        complete = assembly.require_complete(
            expected_workstream=assembly.workstream,
            expected_policy_sha256=assembly.policy_sha256,
            expected_root_identity=assembly.root_identity,
            expected_project_identity=assembly.project_identity,
            expected_assembly_sha256=assembly.sha256,
            expected_coverage_sha256=assembly.coverage_sha256,
        )
        selected_effect = next(
            effect
            for effect in full_plan.effects
            if effect.source_path == "example-service/loose-decision.md"
        )
        subset = full_plan.subset(
            (selected_effect.effect_id,),
            context_assembly=complete,
        )
        subset_directory = Path(self.review_temporary.name).resolve() / "subset-review"
        subset_directory.mkdir(mode=0o700)
        payload = canonical_curation_review.compile_context_bound_review(
            subset,
            context_assembly=complete,
            rendered_at="2026-07-20T00:00:00Z",
            renderer_id="context-subset-test",
        )
        hashes = canonical_curation_review.write_context_bound_review_package(
            subset_directory,
            payload,
        )
        review_hashes = {
            "html_sha256": hashes.html_sha256,
            "markdown_sha256": hashes.markdown_sha256,
            "meta_sha256": hashes.meta_sha256,
            "semantic_sha256": hashes.semantic_sha256,
        }

        outcome = json.loads(
            execution.execute_request_bytes(
                encode_operation_request(
                    self._request(
                        subset,
                        review_hashes,
                        review_directory=subset_directory,
                    )
                )
            )
        )

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertEqual(outcome["result"]["plan_sha256"], subset.sha256)
        self.assertFalse(self.source.exists())
        self.assertEqual(self.target.read_bytes(), self.source_bytes)
        for source, target, raw in extra_rows:
            self.assertEqual(source.read_bytes(), raw)
            self.assertFalse(target.exists())

    def test_new_current_local_source_after_review_is_stale_without_mutation(self) -> None:
        plan, review_hashes, _assembly = self._sealed_plan()
        unexpected = self.project / "new-work-result.md"
        unexpected_bytes = b"# New Work Result\n\nNot present during approval.\n"
        unexpected.write_bytes(unexpected_bytes)
        unexpected.chmod(0o600)

        outcome = json.loads(
            execution.execute_request_bytes(
                encode_operation_request(self._request(plan, review_hashes))
            )
        )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assertFalse(self.target.exists())
        self.assertEqual(unexpected.read_bytes(), unexpected_bytes)

    def test_direct_approve_selected_is_invalid_without_mutation(self) -> None:
        plan, review_hashes, _assembly = self._sealed_plan()
        request = self._request(plan, review_hashes)
        payload = _request_payload_copy(request)
        payload["decision"]["action"] = "APPROVE_SELECTED"
        invalid_request = operation_contract.OperationRequest(
            schema_version=request.schema_version,
            operation_kind=request.operation_kind,
            action=request.action,
            claim_mode=request.claim_mode,
            root=request.root,
            actor=request.actor,
            requested_authority=request.requested_authority,
            payload=payload,
            bounds=dict(request.bounds),
            scope=dict(request.scope),
        )

        outcome = json.loads(
            execution.execute_request_bytes(
                encode_operation_request(invalid_request)
            )
        )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assertFalse(self.target.exists())

    def test_four_effect_context_plan_applies_as_one_transaction(self) -> None:
        extra_rows = list(self._add_two_more_effect_sources())
        work_directory = self.project / "work"
        work_directory.mkdir(mode=0o700)
        work_source = self.project / "implementation-notes.md"
        work_target = work_directory / work_source.name
        work_bytes = b"# Implementation Notes\n\nFourth effect.\n"
        work_source.write_bytes(work_bytes)
        work_source.chmod(0o600)
        extra_rows.append((work_source, work_target, work_bytes))
        plan, review_hashes, _assembly = self._sealed_plan(expected_effects=4)

        outcome = json.loads(
            execution.execute_request_bytes(
                encode_operation_request(self._request(plan, review_hashes))
            )
        )

        self.assertEqual(outcome["outcome_kind"], "completed", outcome)
        self.assertEqual(outcome["result"]["status"], "FINALIZED")
        self.assertEqual(outcome["result"]["effect_count"], 4)
        self.assertFalse(self.source.exists())
        self.assertEqual(self.target.read_bytes(), self.source_bytes)
        for source, target, raw in extra_rows:
            self.assertFalse(source.exists())
            self.assertEqual(target.read_bytes(), raw)

    def test_zero_effect_context_plan_is_invalid_without_control_write(self) -> None:
        self.source.unlink()
        plan, review_hashes, _assembly = self._sealed_plan(expected_effects=0)

        outcome = json.loads(
            execution.execute_request_bytes(
                encode_operation_request(self._request(plan, review_hashes))
            )
        )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
        transaction = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "transactions"
            / ("p-" + plan.sha256)
        )
        self.assertFalse(transaction.exists())

    def test_foreign_v3_review_hash_is_stale_without_mutation(self) -> None:
        plan, review_hashes, _assembly = self._sealed_plan()
        request = self._request(plan, review_hashes)
        payload = _request_payload_copy(request)
        payload["decision"]["review_package_hashes"]["semantic_sha256"] = "f" * 64
        stale_request = operation_contract.OperationRequest(
            schema_version=request.schema_version,
            operation_kind=request.operation_kind,
            action=request.action,
            claim_mode=request.claim_mode,
            root=request.root,
            actor=request.actor,
            requested_authority=request.requested_authority,
            payload=payload,
            bounds=dict(request.bounds),
            scope=dict(request.scope),
        )

        outcome = json.loads(
            execution.execute_request_bytes(encode_operation_request(stale_request))
        )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assertFalse(self.target.exists())

    def test_fault_after_first_publish_rolls_back_all_three_effects(self) -> None:
        extra_rows = self._add_two_more_effect_sources()
        plan, review_hashes, _assembly = self._sealed_plan(expected_effects=3)
        first_effect_id = plan.effects[0].effect_id

        def interrupt(point: str) -> None:
            if point == "after-publish:" + first_effect_id:
                raise RuntimeError("simulated transaction fault")

        with mock.patch.object(runtime, "_run_checkpoint", side_effect=interrupt):
            outcome = json.loads(
                execution.execute_request_bytes(
                    encode_operation_request(self._request(plan, review_hashes))
                )
            )

        self.assertEqual(outcome["outcome_kind"], "blocked", outcome)
        self.assertEqual(outcome["reason_code"], "ROLLED_BACK")
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assertFalse(self.target.exists())
        for source, target, raw in extra_rows:
            self.assertEqual(source.read_bytes(), raw)
            self.assertFalse(target.exists())
        transaction = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "transactions"
            / ("p-" + plan.sha256)
        )
        result = json.loads((transaction / "result.json").read_bytes())
        self.assertEqual(result["status"], "ROLLED_BACK")
        self.assertEqual(result["plan_sha256"], plan.sha256)
        self.assertNotEqual(plan.sha256, plan.plan.sha256)

    def test_retry_after_publish_uses_immutable_outer_context_intent(self) -> None:
        plan, review_hashes, _assembly = self._sealed_plan()
        request = self._request(plan, review_hashes)

        class SimulatedCrash(BaseException):
            pass

        def crash(point: str) -> None:
            if point == "after-publish:" + plan.effects[0].effect_id:
                raise SimulatedCrash("simulated process loss")

        with mock.patch.object(runtime, "_run_checkpoint", side_effect=crash):
            with self.assertRaises(SimulatedCrash):
                execution.execute_request_bytes(encode_operation_request(request))

        with mock.patch.object(
            workstream_curation,
            "_capture_context_curation",
            side_effect=AssertionError("recovery must not reinterpret current Context"),
        ):
            recovered = json.loads(
                execution.execute_request_bytes(encode_operation_request(request))
            )

        self.assertEqual(recovered["outcome_kind"], "completed", recovered)
        self.assertEqual(recovered["result"]["status"], "FINALIZED")
        self.assertEqual(recovered["result"]["plan_sha256"], plan.sha256)
        self.assertFalse(self.source.exists())
        self.assertEqual(self.target.read_bytes(), self.source_bytes)
        outer_transaction = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "transactions"
            / ("p-" + plan.sha256)
        )
        inner_transaction = outer_transaction.parent / ("p-" + plan.plan.sha256)
        self.assertTrue((outer_transaction / "intent.json").is_file())
        self.assertTrue((outer_transaction / "result.json").is_file())
        self.assertFalse(inner_transaction.exists())

    def test_retry_after_stage_rolls_back_without_context_recapture(self) -> None:
        plan, review_hashes, _assembly = self._sealed_plan()
        request = self._request(plan, review_hashes)

        class SimulatedCrash(BaseException):
            pass

        def crash(point: str) -> None:
            if point == "after-stage:" + plan.effects[0].effect_id:
                raise SimulatedCrash("simulated process loss")

        with mock.patch.object(runtime, "_run_checkpoint", side_effect=crash):
            with self.assertRaises(SimulatedCrash):
                execution.execute_request_bytes(encode_operation_request(request))

        with mock.patch.object(
            workstream_curation,
            "_capture_context_curation",
            side_effect=AssertionError("recovery must not reinterpret current Context"),
        ):
            recovered = json.loads(
                execution.execute_request_bytes(encode_operation_request(request))
            )

        self.assertEqual(recovered["outcome_kind"], "blocked", recovered)
        self.assertEqual(recovered["reason_code"], "ROLLED_BACK")
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assertFalse(self.target.exists())
        transaction = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "transactions"
            / ("p-" + plan.sha256)
        )
        result = json.loads((transaction / "result.json").read_bytes())
        self.assertEqual(result["status"], "ROLLED_BACK")
        self.assertEqual(result["plan_sha256"], plan.sha256)


if __name__ == "__main__":
    unittest.main()
