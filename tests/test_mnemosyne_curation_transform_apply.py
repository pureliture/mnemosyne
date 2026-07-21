import hashlib
import json
import os
import stat
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
import mnemosyne_core  # noqa: E402
from mnemosyne_core import (  # noqa: E402
    canonical_curation,
    canonical_curation_m3,
    canonical_curation_m3_review,
    operation_contract,
)
from mnemosyne_core.authority_runtime import (  # noqa: E402
    canonical_curation as stage_a_transaction,
    canonical_curation_m3 as curation_transaction,
    librarian_snapshot,
)
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402
from mnemosyne_core.operation_contract.codec import (  # noqa: E402
    decode_operation_request,
    encode_operation_request,
)
from mnemosyne_core.workstream_curation import _read_compiled_policy  # noqa: E402
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _filesystem_identity(path: Path) -> tuple[int, int, int, int]:
    info = path.stat()
    return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid


class CurationTransformApplyPublicTest(LedgerRuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.review_temporary_directory = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.review_temporary_directory.cleanup)
        self.review_root = Path(self.review_temporary_directory.name).resolve()
        self.migrate_to_v2()
        self.project = self.root / "example-service"
        self.project.mkdir(parents=True, mode=0o700)
        self.readme = self.project / "README.md"
        self.readme.write_bytes(b"# Example Project\n\nProject overview.\n")
        self.sources = (
            self.project / "notes-a.md",
            self.project / "notes-b.md",
        )
        self.source_bytes = (
            b"# A\n\nAlpha decision.\n",
            b"# B\n\nBeta result.\n",
        )
        for source, raw in zip(self.sources, self.source_bytes):
            source.write_bytes(raw)
            source.chmod(0o600)
        self.target = self.project / "combined.md"
        self.output_bytes = (
            b"# Combined\n\n## Alpha\n\nAlpha decision.\n\n"
            b"## Beta\n\nBeta result.\n"
        )

    def _plan(self) -> canonical_curation_m3.TransformationPlan:
        compiled_policy, _registry_sha256 = _read_compiled_policy(self.root)
        observations = []
        for index, source in enumerate(self.sources, 1):
            relative_path = source.relative_to(self.root).as_posix()
            snapshot = librarian_snapshot.observe_regular_file(
                self.root,
                compiled_policy,
                relative_path,
                max_total_bytes=1024 * 1024,
            )
            observations.append(
                canonical_curation.SourceObservation(
                    observation_id=f"obs-{index:024d}",
                    relative_path=relative_path,
                    owner_kind="workstream",
                    owner_id="example-service",
                    lifecycle="active",
                    document_role="work_results",
                    classification="EXACT",
                    classification_evidence=("temporary-root fixture",),
                    content_summary=f"fixture source {index}",
                    device=snapshot["device"],
                    inode=snapshot["inode"],
                    owner=snapshot["owner"],
                    mode=snapshot["mode"],
                    link_count=snapshot["link_count"],
                    size=snapshot["size"],
                    modified_time_ns=snapshot["modified_time_ns"],
                    content_sha256=snapshot["content_sha256"],
                    snapshot_sha256=snapshot["snapshot_sha256"],
                )
            )
        output = canonical_curation_m3.CompleteOutput(
            output_id="output-000000000000000000000001",
            output_path=self.target.relative_to(self.root).as_posix(),
            content=self.output_bytes.decode(),
            content_sha256=_sha256(self.output_bytes),
            document_role="work_results",
        )
        mappings = tuple(
            canonical_curation_m3.SourceOutputMapping(
                mapping_id=f"mapping-{index:024d}",
                source_observation_id=observation.observation_id,
                source_sections=("A" if index == 1 else "B",),
                output_id=output.output_id,
                output_sections=("Alpha" if index == 1 else "Beta",),
                disposition="RETAINED",
            )
            for index, observation in enumerate(observations, 1)
        )
        effect = canonical_curation_m3.TransformationEffect(
            effect_id="effect-000000000000000000000001",
            action="merge",
            input_observation_ids=tuple(
                observation.observation_id for observation in observations
            ),
            outputs=(output,),
            source_output_mappings=mappings,
            disappearing_content=(),
            risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
        )
        spine = tuple(
            canonical_curation.SpineEntry(
                role=role,
                current_path=(
                    self.readme.relative_to(self.root).as_posix()
                    if role == "overview"
                    else None
                ),
                current_heading=("Example Project" if role == "overview" else None),
                proposed_path=(
                    self.readme.relative_to(self.root).as_posix()
                    if role == "overview"
                    else self.target.relative_to(self.root).as_posix()
                    if role == "work_results"
                    else None
                ),
                proposed_heading=("Example Project" if role == "overview" else None),
                status=(
                    "PRESENT"
                    if role == "overview"
                    else "PROPOSED"
                    if role == "work_results"
                    else "MISSING"
                ),
            )
            for role in canonical_curation.COMMON_SPINE_ROLES
        )
        return canonical_curation_m3.TransformationPlan(
            primary_workstream_id="example-service",
            captured_lifecycle="active",
            project_home=self.project.relative_to(self.root).as_posix(),
            project_identity=_filesystem_identity(self.project),
            root_identity=_filesystem_identity(self.root),
            policy_sha256=compiled_policy.full_hash,
            source_observations=tuple(observations),
            effects=(effect,),
            spine=spine,
            findings=(),
            unchanged_paths=(self.readme.relative_to(self.root).as_posix(),),
            out_of_scope_paths=(),
            final_paths=(
                self.readme.relative_to(self.root).as_posix(),
                self.target.relative_to(self.root).as_posix(),
            ),
            coverage=(("truncated", False),),
        )

    def _request(self, plan: canonical_curation_m3.TransformationPlan) -> operation_contract.OperationRequest:
        hashes, review_directory = self._sealed_review(plan)
        decision = canonical_curation_m3.compile_decision(
            plan,
            action="APPROVE_ALL",
            review_package_hashes=hashes,
            irreversible_acknowledgement=canonical_curation_m3.IRREVERSIBLE_CONSEQUENCE_KO,
        )
        return self._request_for_decision(plan, decision, review_directory)

    def _sealed_review(
        self,
        displayed_plan: canonical_curation_m3.TransformationPlan,
    ) -> tuple[dict[str, str], Path]:
        review_directory = self.review_root / ("p-" + displayed_plan.sha256)
        review_directory.mkdir(mode=0o700)
        payload = canonical_curation_m3_review.compile_review(
            displayed_plan,
            rendered_at="2026-07-19T12:00:00Z",
            renderer_id="m3-runtime-test",
        )
        hashes = canonical_curation_m3_review.write_review_package(
            review_directory,
            payload,
        )
        return (
            {
                "html_sha256": hashes.html_sha256,
                "markdown_sha256": hashes.markdown_sha256,
                "meta_sha256": hashes.meta_sha256,
                "semantic_sha256": hashes.semantic_sha256,
            },
            review_directory,
        )

    def _request_for_decision(
        self,
        plan: canonical_curation_m3.TransformationPlan,
        decision: canonical_curation_m3.TransformationDecision,
        review_directory: Path,
    ) -> operation_contract.OperationRequest:
        return operation_contract.OperationRequest(
            schema_version=1,
            operation_kind="curation.plan_apply",
            action=operation_contract.LifecycleAction.APPLY,
            claim_mode=operation_contract.ClaimMode.CURRENT,
            root=str(self.root),
            actor="test-operator",
            requested_authority=operation_contract.AuthorityMode.WRITE,
            payload={
                "decision": decision.canonical_value,
                "plan": plan.canonical_value,
                "review_package_directory": str(review_directory),
            },
            bounds={
                "max_effects": 16,
                "max_total_bytes": 8 * 1024 * 1024,
            },
            scope={
                "plan_sha256": plan.sha256,
                "workstream_id": plan.primary_workstream_id,
            },
        )

    def _two_effect_plan(
        self,
    ) -> tuple[canonical_curation_m3.TransformationPlan, tuple[Path, Path], tuple[bytes, bytes]]:
        base = self._plan()
        target_paths = (
            self.project / "canonical-a.md",
            self.project / "canonical-b.md",
        )
        output_bytes = (
            b"# Canonical A\n\nAlpha decision.\n",
            b"# Canonical B\n\nBeta result.\n",
        )
        effects = []
        for index, (observation, target, raw) in enumerate(
            zip(base.source_observations, target_paths, output_bytes),
            1,
        ):
            output = canonical_curation_m3.CompleteOutput(
                output_id=f"output-{index + 10:024d}",
                output_path=target.relative_to(self.root).as_posix(),
                content=raw.decode(),
                content_sha256=_sha256(raw),
                document_role="work_results",
            )
            effects.append(
                canonical_curation_m3.TransformationEffect(
                    effect_id=f"effect-{index + 10:024d}",
                    action="rewrite",
                    input_observation_ids=(observation.observation_id,),
                    outputs=(output,),
                    source_output_mappings=(
                        canonical_curation_m3.SourceOutputMapping(
                            mapping_id=f"mapping-{index + 10:024d}",
                            source_observation_id=observation.observation_id,
                            source_sections=("document",),
                            output_id=output.output_id,
                            output_sections=("document",),
                            disposition="REORGANIZED",
                        ),
                    ),
                    disappearing_content=(),
                    risk_codes=("IRREVERSIBLE_TRANSFORMATION",),
                )
            )
        plan = replace(
            base,
            effects=tuple(effects),
            final_paths=(
                self.readme.relative_to(self.root).as_posix(),
                target_paths[0].relative_to(self.root).as_posix(),
                target_paths[1].relative_to(self.root).as_posix(),
            ),
        )
        return plan, target_paths, output_bytes

    def _effect_fingerprint(self) -> tuple[tuple[object, ...], ...]:
        rows = []
        for path in (*self.sources, self.target, self.readme):
            relative_path = path.relative_to(self.root).as_posix()
            if not path.exists():
                rows.append((relative_path, None))
                continue
            info = path.stat()
            rows.append(
                (
                    relative_path,
                    info.st_dev,
                    info.st_ino,
                    stat.S_IMODE(info.st_mode),
                    info.st_uid,
                    info.st_nlink,
                    info.st_size,
                    info.st_mtime_ns,
                    _sha256(path.read_bytes()),
                )
            )
        return tuple(rows)

    @staticmethod
    def _execute(request: operation_contract.OperationRequest) -> dict[str, object]:
        return json.loads(
            mnemosyne_core.execute_request_bytes(encode_operation_request(request))
        )

    def test_public_transform_apply_commits_one_canonical_output_and_removes_originals(
        self,
    ) -> None:
        plan = self._plan()

        outcome = self._execute(self._request(plan))

        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertEqual(outcome["result"]["schema"], "mnemosyne-canonical-curation-result-v2")
        self.assertEqual(outcome["result"]["status"], "FINALIZED")
        self.assertEqual(outcome["result"]["cutoff_state"], "CLEANUP_VERIFIED")
        self.assertEqual(self.target.read_bytes(), self.output_bytes)
        self.assertTrue(all(not source.exists() for source in self.sources))
        self.assertTrue(self.readme.exists())
        stage = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v2"
            / "staging"
            / ("p-" + plan.sha256)
        )
        self.assertFalse(stage.exists())
        control_bytes = b"\n".join(
            path.read_bytes()
            for path in (self.root / "_registry" / "curation" / "canonical-curation-v2").rglob("*")
            if path.is_file()
        )
        for original in self.source_bytes:
            self.assertNotIn(original, control_bytes)

    def test_public_selected_transform_applies_only_exact_subset(self) -> None:
        displayed, targets, output_bytes = self._two_effect_plan()
        hashes, review_directory = self._sealed_review(displayed)
        decision = canonical_curation_m3.compile_decision(
            displayed,
            action="APPROVE_SELECTED",
            review_package_hashes=hashes,
            selected_effect_ids=("effect-000000000000000000000011",),
            irreversible_acknowledgement=canonical_curation_m3.IRREVERSIBLE_CONSEQUENCE_KO,
        )
        subset = decision.approved_plan

        outcome = self._execute(
            self._request_for_decision(subset, decision, review_directory)
        )

        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertFalse(self.sources[0].exists())
        self.assertEqual(targets[0].read_bytes(), output_bytes[0])
        self.assertEqual(self.sources[1].read_bytes(), self.source_bytes[1])
        self.assertFalse(targets[1].exists())

    def test_fault_before_cutoff_restores_exact_pre_apply_state(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        before = self._effect_fingerprint()

        def fail(point: str) -> None:
            if point == "after-published-verified":
                raise RuntimeError("simulated pre-cutoff crash")

        with mock.patch.object(curation_transaction, "_run_checkpoint", side_effect=fail):
            outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "ROLLED_BACK")
        self.assertEqual(self._effect_fingerprint(), before)
        self.assertFalse(self.target.exists())
        stage = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v2"
            / "staging"
            / ("p-" + plan.sha256)
        )
        self.assertFalse(stage.exists())

    def test_every_pre_cutoff_phase_failure_rolls_back_exactly(self) -> None:
        points = (
            "after-prepared",
            "before-stage:obs-000000000000000000000001",
            "after-stage:obs-000000000000000000000001",
            "before-stage:obs-000000000000000000000002",
            "after-stage:obs-000000000000000000000002",
            "before-output-stage:output-000000000000000000000001",
            "after-output-stage:output-000000000000000000000001",
            "before-output-publish:output-000000000000000000000001",
            "after-output-publish:output-000000000000000000000001",
        )
        for point in points:
            with self.subTest(point=point):
                case = CurationTransformApplyPublicTest(
                    "test_public_transform_apply_commits_one_canonical_output_and_removes_originals"
                )
                case.setUp()
                try:
                    plan = case._plan()
                    request = case._request(plan)
                    before = case._effect_fingerprint()

                    def fail(observed: str) -> None:
                        if observed == point:
                            raise RuntimeError("simulated pre-cutoff crash")

                    with mock.patch.object(
                        curation_transaction,
                        "_run_checkpoint",
                        side_effect=fail,
                    ):
                        outcome = case._execute(request)

                    self.assertEqual(outcome["outcome_kind"], "blocked")
                    self.assertEqual(outcome["reason_code"], "ROLLED_BACK")
                    self.assertEqual(case._effect_fingerprint(), before)
                finally:
                    case.doCleanups()

    def test_missing_acknowledgement_is_rejected_before_any_corpus_or_control_write(
        self,
    ) -> None:
        plan = self._plan()
        request = self._request(plan)
        before = self._effect_fingerprint()
        forged_value = json.loads(request.canonical_bytes)
        forged_value["payload"]["decision"]["irreversible_acknowledgement"] = None
        forged = decode_operation_request(canonical_json_bytes(forged_value))

        outcome = self._execute(forged)

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
        self.assertEqual(self._effect_fingerprint(), before)
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "canonical-curation-v2"
            ).exists()
        )

    def test_forged_incomplete_output_is_rejected_before_mutation(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        before = self._effect_fingerprint()
        forged_value = json.loads(request.canonical_bytes)
        forged_value["payload"]["plan"]["effects"][0]["outputs"][0]["content"] = "# Forged\n"
        forged = decode_operation_request(canonical_json_bytes(forged_value))

        outcome = self._execute(forged)

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
        self.assertEqual(self._effect_fingerprint(), before)
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "canonical-curation-v2"
            ).exists()
        )

    def test_fault_after_cutoff_blocks_then_same_exact_request_finishes_cleanup(
        self,
    ) -> None:
        plan = self._plan()
        request = self._request(plan)
        first_observation_id = plan.source_observations[0].observation_id

        def fail(point: str) -> None:
            if point == "after-cleanup:" + first_observation_id:
                raise RuntimeError("simulated post-cutoff crash")

        with mock.patch.object(curation_transaction, "_run_checkpoint", side_effect=fail):
            interrupted = self._execute(request)

        self.assertEqual(interrupted["outcome_kind"], "blocked_recovery")
        self.assertEqual(interrupted["recovery_owner"], "canonical-curation-v2")
        self.assertEqual(interrupted["continuation_identity"], plan.sha256)
        self.assertEqual(
            curation_transaction.workstream_mutation_status(
                self.root,
                plan.primary_workstream_id,
            ),
            "RECOVERY_REQUIRED",
        )
        self.assertEqual(
            stage_a_transaction.workstream_mutation_status(
                self.root,
                plan.primary_workstream_id,
            ),
            "RECOVERY_REQUIRED",
        )
        different_value = json.loads(request.canonical_bytes)
        different_value["actor"] = "different-operator"
        different_request = decode_operation_request(canonical_json_bytes(different_value))
        conflict = self._execute(different_request)
        self.assertEqual(conflict["outcome_kind"], "blocked")
        self.assertEqual(conflict["reason_code"], "PLAN_CONFLICT")

        recovered = self._execute(request)

        self.assertEqual(recovered["outcome_kind"], "completed")
        self.assertEqual(recovered["result"]["status"], "FINALIZED")
        self.assertEqual(self.target.read_bytes(), self.output_bytes)
        self.assertTrue(all(not source.exists() for source in self.sources))
        self.assertIsNone(
            curation_transaction.workstream_mutation_status(
                self.root,
                plan.primary_workstream_id,
            )
        )

    def test_each_post_cutoff_interruption_resumes_only_exact_cleanup(self) -> None:
        points = (
            "after-cutoff-committed",
            "after-cleanup:obs-000000000000000000000002",
            "after-cleanup-verified",
        )
        for point in points:
            with self.subTest(point=point):
                case = CurationTransformApplyPublicTest(
                    "test_public_transform_apply_commits_one_canonical_output_and_removes_originals"
                )
                case.setUp()
                try:
                    plan = case._plan()
                    request = case._request(plan)

                    def fail(observed: str) -> None:
                        if observed == point:
                            raise RuntimeError("simulated post-cutoff crash")

                    with mock.patch.object(
                        curation_transaction,
                        "_run_checkpoint",
                        side_effect=fail,
                    ):
                        interrupted = case._execute(request)

                    self.assertEqual(interrupted["outcome_kind"], "blocked_recovery")
                    self.assertEqual(interrupted["continuation_identity"], plan.sha256)
                    recovered = case._execute(request)
                    self.assertEqual(recovered["outcome_kind"], "completed")
                    self.assertEqual(case.target.read_bytes(), case.output_bytes)
                    self.assertTrue(all(not source.exists() for source in case.sources))
                finally:
                    case.doCleanups()

    def test_terminal_replay_rejects_even_empty_recreated_staging_directory(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        completed = self._execute(request)
        self.assertEqual(completed["outcome_kind"], "completed")
        stage = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v2"
            / "staging"
            / ("p-" + plan.sha256)
        )
        stage.mkdir(mode=0o700)

        replay = self._execute(request)

        self.assertEqual(replay["outcome_kind"], "blocked_recovery")
        self.assertEqual(
            stage_a_transaction.workstream_mutation_status(
                self.root,
                plan.primary_workstream_id,
            ),
            "RECOVERY_REQUIRED",
        )

    def test_tampered_cutoff_marker_never_authorizes_cleanup(self) -> None:
        plan = self._plan()
        request = self._request(plan)

        def fail(point: str) -> None:
            if point == "after-cutoff-committed":
                raise RuntimeError("simulated post-cutoff crash")

        with mock.patch.object(curation_transaction, "_run_checkpoint", side_effect=fail):
            interrupted = self._execute(request)
        self.assertEqual(interrupted["outcome_kind"], "blocked_recovery")
        transaction = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v2"
            / "transactions"
            / ("p-" + plan.sha256)
        )
        marker = json.loads((transaction / "committed-cleanup.json").read_bytes())
        marker["phase"] = "PUBLISHED_VERIFIED"
        (transaction / "committed-cleanup.json").write_bytes(canonical_json_bytes(marker))

        retry = self._execute(request)

        self.assertEqual(retry["outcome_kind"], "blocked_recovery")
        source_stage = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v2"
            / "staging"
            / ("p-" + plan.sha256)
            / "sources"
        )
        self.assertTrue(any(source_stage.iterdir()))


if __name__ == "__main__":
    unittest.main()
