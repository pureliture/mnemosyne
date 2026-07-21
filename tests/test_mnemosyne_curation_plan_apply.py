import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import threading
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
    canonical_curation_review,
    operation_contract,
    workstream_curation,
)
from mnemosyne_core.authority_runtime import (  # noqa: E402
    canonical_curation as curation_transaction,
    librarian_snapshot,
)
from mnemosyne_core.operation_contract.codec import encode_operation_request  # noqa: E402
from mnemosyne_core.operation_control import execution  # noqa: E402
from mnemosyne_core.workstream_curation import _read_compiled_policy  # noqa: E402
from test_mnemosyne_ledger_runtime import LedgerRuntimeFixture  # noqa: E402


def _filesystem_identity(path: Path) -> tuple[int, int, int, int]:
    info = path.stat()
    return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid


class CurationPlanApplyPublicTest(LedgerRuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.review_temporary_directory = tempfile.TemporaryDirectory(
            dir="/private/tmp"
        )
        self.addCleanup(self.review_temporary_directory.cleanup)
        self.review_root = Path(self.review_temporary_directory.name).resolve()
        self.migrate_to_v2()
        self.project = self.root / "example-service"
        (self.project / "decisions").mkdir(parents=True, mode=0o700)
        (self.project / "references").mkdir(mode=0o700)
        (self.project / "README.md").write_text(
            "# Security Scanner\n\nProject overview.\n",
            encoding="utf-8",
        )
        self.inbox = self.root / "inbox"
        self.inbox.mkdir(mode=0o700)
        self.sources = (
            self.project / "loose-decision.md",
            self.inbox / "example-service-reference.md",
        )
        self.targets = (
            self.project / "decisions" / "loose-decision.md",
            self.project / "references" / "example-service-reference.md",
        )
        self.source_bytes = (
            b"# Decision\n\nKeep one canonical document.\n",
            b"# Reference\n\nEvidence for example-service.\n",
        )
        for source, raw in zip(self.sources, self.source_bytes):
            source.write_bytes(raw)
            source.chmod(0o600)

    def _plan(self) -> canonical_curation.CurationPlan:
        compiled_policy, _registry_sha256 = _read_compiled_policy(self.root)
        observations = []
        effects = []
        roles = ("decisions", "references")
        for index, (source, target, role) in enumerate(
            zip(self.sources, self.targets, roles),
            1,
        ):
            relative_source = source.relative_to(self.root).as_posix()
            snapshot = librarian_snapshot.observe_regular_file(
                self.root,
                compiled_policy,
                relative_source,
                max_total_bytes=1024 * 1024,
            )
            observation = canonical_curation.SourceObservation(
                observation_id=f"obs-{index:024d}",
                relative_path=relative_source,
                owner_kind="workstream" if index == 1 else "unassigned",
                owner_id="example-service" if index == 1 else "unassigned",
                lifecycle="active" if index == 1 else "unassigned",
                document_role=role,
                classification="EXACT",
                classification_evidence=("independent-test-evidence",),
                content_summary=f"Source {index}",
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
            effects.append(
                canonical_curation.PlanEffect(
                    effect_id=f"effect-{index:024d}",
                    action="move",
                    input_observation_id=observation.observation_id,
                    source_path=relative_source,
                    output_path=target.relative_to(self.root).as_posix(),
                    expected_output_sha256=observation.content_sha256,
                    risk_codes=("PATH_ONLY_CHANGE",),
                )
            )
            observations.append(observation)
        proposed = {effect.output_path: effect for effect in effects}
        spine = tuple(
            canonical_curation.SpineEntry(
                role=role,
                current_path=(
                    "example-service/README.md" if role == "overview" else None
                ),
                current_heading=("Security Scanner" if role == "overview" else None),
                proposed_path=(
                    "example-service/README.md"
                    if role == "overview"
                    else next(
                        (
                            path
                            for path, effect in proposed.items()
                            if observations[effects.index(effect)].document_role == role
                        ),
                        None,
                    )
                ),
                proposed_heading=(
                    "Security Scanner" if role == "overview" else None
                ),
                status=(
                    "PRESENT"
                    if role == "overview"
                    else "PROPOSED"
                    if role in roles
                    else "MISSING"
                ),
            )
            for role in canonical_curation.COMMON_SPINE_ROLES
        )
        return canonical_curation.CurationPlan(
            primary_workstream_id="example-service",
            captured_lifecycle="active",
            project_home="example-service",
            project_identity=_filesystem_identity(self.project),
            root_identity=_filesystem_identity(self.root),
            policy_sha256=compiled_policy.full_hash,
            source_observations=tuple(observations),
            effects=tuple(effects),
            spine=spine,
            findings=(),
            unchanged_paths=("example-service/README.md",),
            out_of_scope_paths=(),
            coverage=(("truncated", False),),
        )

    def _sealed_review(
        self,
        displayed_plan: canonical_curation.CurationPlan,
    ) -> tuple[dict[str, str], Path]:
        directory = self.review_root / ("p-" + displayed_plan.sha256)
        directory.mkdir(mode=0o700, exist_ok=True)
        payload = canonical_curation_review.compile_review(
            displayed_plan,
            rendered_at="2026-07-19T12:00:00Z",
            renderer_id="m2-independent-test",
        )
        hashes = canonical_curation_review.write_review_package(
            directory,
            payload,
        )
        return (
            {
                "html_sha256": hashes.html_sha256,
                "markdown_sha256": hashes.markdown_sha256,
                "meta_sha256": hashes.meta_sha256,
                "semantic_sha256": hashes.semantic_sha256,
            },
            directory,
        )

    def _request(
        self,
        plan: canonical_curation.CurationPlan,
    ) -> operation_contract.OperationRequest:
        review_hashes, review_directory = self._sealed_review(plan)
        decision = canonical_curation.compile_decision(
            plan,
            action="APPROVE_ALL",
            review_package_hashes=review_hashes,
        )
        return self._request_for_decision(plan, decision, review_directory)

    def _request_for_decision(
        self,
        plan: canonical_curation.CurationPlan,
        decision: canonical_curation.CurationDecision,
        review_package_directory: Path,
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
                "review_package_directory": str(review_package_directory),
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

    @staticmethod
    def _execute(request: operation_contract.OperationRequest) -> dict[str, object]:
        return json.loads(
            mnemosyne_core.execute_request_bytes(
                encode_operation_request(request)
            )
        )

    def _effect_fingerprint(self) -> tuple[tuple[object, ...], ...]:
        paths = (*self.sources, *self.targets)
        rows = []
        for path in paths:
            if not path.exists():
                rows.append((path.relative_to(self.root).as_posix(), None))
                continue
            info = path.stat()
            rows.append(
                (
                    path.relative_to(self.root).as_posix(),
                    info.st_dev,
                    info.st_ino,
                    stat.S_IMODE(info.st_mode),
                    info.st_uid,
                    info.st_nlink,
                    info.st_size,
                    info.st_mtime_ns,
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
        return tuple(rows)

    def test_public_exact_plan_moves_all_effects_and_leaves_no_content_backup(
        self,
    ) -> None:
        plan = self._plan()
        request = self._request(plan)

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertEqual(outcome["result"]["status"], "FINALIZED")
        self.assertEqual(outcome["result"]["plan_sha256"], plan.sha256)
        observations = {
            observation.relative_path: observation
            for observation in plan.source_observations
        }
        for source in self.sources:
            self.assertFalse(source.exists())
        for source, target, expected in zip(
            self.sources,
            self.targets,
            self.source_bytes,
        ):
            self.assertEqual(target.read_bytes(), expected)
            info = target.stat()
            observation = observations[source.relative_to(self.root).as_posix()]
            self.assertEqual(info.st_ino, observation.inode)
            self.assertEqual(stat.S_IMODE(info.st_mode), observation.mode)
        receipt = json.dumps(outcome["result"], sort_keys=True).encode("utf-8")
        for raw in self.source_bytes:
            self.assertNotIn(raw, receipt)
        transaction = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "transactions"
            / ("p-" + plan.sha256)
        )
        self.assertEqual(
            sorted(path.name for path in transaction.iterdir()),
            ["intent.json", "result.json"],
        )
        for record in transaction.iterdir():
            for raw in self.source_bytes:
                self.assertNotIn(raw, record.read_bytes())
        staging = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "staging"
            / ("p-" + plan.sha256)
        )
        self.assertFalse(staging.exists())

    def test_curation_dispatch_cli_executes_one_owner_only_request_file(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            request_file = Path(temporary) / "plan-apply.json"
            request_file.write_bytes(encode_operation_request(request))
            request_file.chmod(0o600)
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = mnemosyne.main(
                    [
                        "curation",
                        "dispatch",
                        "--request-file",
                        str(request_file),
                    ]
                )

        outcome = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertEqual(outcome["result"]["status"], "FINALIZED")

    def test_same_finalized_plan_is_idempotent_without_rewriting_targets(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        first = self._execute(request)
        identities = tuple(
            (target.stat().st_dev, target.stat().st_ino, target.stat().st_mtime_ns)
            for target in self.targets
        )

        second = self._execute(request)

        self.assertEqual(first, second)
        self.assertEqual(
            tuple(
                (target.stat().st_dev, target.stat().st_ino, target.stat().st_mtime_ns)
                for target in self.targets
            ),
            identities,
        )

    def test_finalized_plan_rejects_a_different_request_identity(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        completed = self._execute(request)
        transaction = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "transactions"
            / ("p-" + plan.sha256)
        )
        records_before = {
            path.name: path.read_bytes() for path in transaction.iterdir()
        }

        request_value = json.loads(request.canonical_bytes)
        replay = self._execute(
            operation_contract.OperationRequest(
                schema_version=request.schema_version,
                operation_kind=request.operation_kind,
                action=request.action,
                claim_mode=request.claim_mode,
                root=request.root,
                actor="different-operator",
                requested_authority=request.requested_authority,
                payload=request_value["payload"],
                bounds=request_value["bounds"],
                scope=request_value["scope"],
            )
        )

        self.assertEqual(completed["outcome_kind"], "completed")
        self.assertEqual(replay["outcome_kind"], "blocked")
        self.assertEqual(replay["reason_code"], "PLAN_CONFLICT")
        self.assertEqual(
            {path.name: path.read_bytes() for path in transaction.iterdir()},
            records_before,
        )

    def test_changed_sealed_review_package_is_stale_before_transaction(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        review_directory = Path(request.payload["review_package_directory"])
        (review_directory / "review.html").write_bytes(
            (review_directory / "review.html").read_bytes() + b"tampered"
        )
        before = self._effect_fingerprint()

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(self._effect_fingerprint(), before)
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "canonical-curation-v1"
                / "transactions"
                / ("p-" + plan.sha256)
            ).exists()
        )

    def test_review_package_with_an_extra_entry_is_stale_before_transaction(
        self,
    ) -> None:
        plan = self._plan()
        request = self._request(plan)
        review_directory = Path(request.payload["review_package_directory"])
        extra = review_directory / "unbound-note.txt"
        extra.write_text("not part of the sealed package\n", encoding="utf-8")
        extra.chmod(0o600)
        before = self._effect_fingerprint()

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(self._effect_fingerprint(), before)
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "canonical-curation-v1"
                / "transactions"
                / ("p-" + plan.sha256)
            ).exists()
        )

    def test_selected_approval_applies_only_the_new_subset_plan(self) -> None:
        displayed = self._plan()
        review_hashes, review_directory = self._sealed_review(displayed)
        decision = canonical_curation.compile_decision(
            displayed,
            action="APPROVE_SELECTED",
            selected_effect_ids=(displayed.effects[0].effect_id,),
            review_package_hashes=review_hashes,
        )
        selected = decision.approved_plan
        self.assertIsNotNone(selected)

        outcome = self._execute(
            self._request_for_decision(selected, decision, review_directory)
        )

        self.assertEqual(outcome["outcome_kind"], "completed")
        self.assertFalse(self.sources[0].exists())
        self.assertEqual(self.targets[0].read_bytes(), self.source_bytes[0])
        self.assertEqual(self.sources[1].read_bytes(), self.source_bytes[1])
        self.assertFalse(self.targets[1].exists())

    def test_selected_approval_rejects_a_plan_not_derived_from_the_displayed_plan(
        self,
    ) -> None:
        displayed = self._plan()
        review_hashes, review_directory = self._sealed_review(displayed)
        selected_ids = (displayed.effects[0].effect_id,)
        expected_subset = displayed.subset(selected_ids)
        rogue_effect = replace(
            expected_subset.effects[0],
            output_path="example-service/references/not-reviewed.md",
        )
        rogue_plan = replace(expected_subset, effects=(rogue_effect,))
        decision = canonical_curation.CurationDecision(
            action="APPROVE_SELECTED",
            displayed_plan_sha256=displayed.sha256,
            approved_plan=rogue_plan,
            selected_effect_ids=selected_ids,
            review_package_hashes=tuple(sorted(review_hashes.items())),
            reason=None,
        )
        before = self._effect_fingerprint()

        outcome = self._execute(
            self._request_for_decision(
                rogue_plan,
                decision,
                review_directory,
            )
        )

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(self._effect_fingerprint(), before)
        self.assertFalse(
            self.project.joinpath("references", "not-reviewed.md").exists()
        )

    def test_reject_and_defer_cannot_enter_the_apply_session(self) -> None:
        plan = self._plan()
        hashes, review_directory = self._sealed_review(plan)
        for action in ("REJECT", "DEFER"):
            with self.subTest(action=action):
                decision = canonical_curation.compile_decision(
                    plan,
                    action=action,
                    review_package_hashes=hashes,
                    reason="Do not write the corpus.",
                )
                request = self._request_for_decision(
                    plan,
                    decision,
                    review_directory,
                )
                before = self._effect_fingerprint()

                with mock.patch.object(
                    execution.authority_runtime,
                    "admit",
                    side_effect=AssertionError("non-approval reached admission"),
                ):
                    outcome = self._execute(request)

                self.assertEqual(outcome["outcome_kind"], "blocked")
                self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")
                self.assertEqual(self._effect_fingerprint(), before)

    def test_fault_at_each_pre_cutoff_phase_restores_exact_effect_state(self) -> None:
        fault_points = (
            "after-prepared",
            "after-stage:effect-000000000000000000000001",
            "after-stage:effect-000000000000000000000002",
            "after-publish:effect-000000000000000000000001",
            "after-publish:effect-000000000000000000000002",
            "after-published-verified",
        )

        for point in fault_points:
            with self.subTest(point=point):
                case = type(self)(methodName="runTest")
                case.setUp()
                try:
                    plan = case._plan()
                    request = case._request(plan)
                    before = case._effect_fingerprint()

                    def interrupt(observed: str) -> None:
                        if observed == point:
                            raise RuntimeError("simulated pre-cutoff fault")

                    with mock.patch.object(
                        curation_transaction,
                        "_run_checkpoint",
                        side_effect=interrupt,
                    ):
                        outcome = case._execute(request)

                    self.assertEqual(outcome["outcome_kind"], "blocked")
                    self.assertEqual(outcome["reason_code"], "ROLLED_BACK")
                    self.assertEqual(case._effect_fingerprint(), before)
                    staging = (
                        case.root
                        / "_registry"
                        / "curation"
                        / "canonical-curation-v1"
                        / "staging"
                        / ("p-" + plan.sha256)
                    )
                    self.assertFalse(staging.exists())
                finally:
                    case.doCleanups()

    def test_source_policy_and_target_drift_fail_closed_before_effects(self) -> None:
        cases = ("source", "policy", "target")
        for drift in cases:
            with self.subTest(drift=drift):
                case = type(self)(methodName="runTest")
                case.setUp()
                try:
                    plan = case._plan()
                    if drift == "source":
                        case.sources[0].write_bytes(
                            b"# Decision\n\nThis source changed after review.\n"
                        )
                        expected_reason = "STALE"
                    elif drift == "policy":
                        plan = replace(plan, policy_sha256="e" * 64)
                        expected_reason = "STALE"
                    else:
                        case.targets[0].write_bytes(b"existing target")
                        case.targets[0].chmod(0o600)
                        expected_reason = "TARGET_CONFLICT"
                    before = case._effect_fingerprint()

                    outcome = case._execute(case._request(plan))

                    self.assertEqual(outcome["outcome_kind"], "blocked")
                    self.assertEqual(outcome["reason_code"], expected_reason)
                    self.assertEqual(case._effect_fingerprint(), before)
                finally:
                    case.doCleanups()

    def test_lifecycle_policy_race_after_staging_rolls_back_before_stale(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        before = self._effect_fingerprint()

        def pause_workstream(point: str) -> None:
            if point != "after-stage:effect-000000000000000000000001":
                return
            raw = self.registry_path.read_bytes()
            self.registry_path.write_bytes(
                raw.replace(b"lifecycle: active", b"lifecycle: paused", 1)
            )
            self.registry_path.chmod(0o600)

        with mock.patch.object(
            curation_transaction,
            "_run_checkpoint",
            side_effect=pause_workstream,
        ):
            outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "STALE")
        self.assertEqual(self._effect_fingerprint(), before)

    def test_target_parent_swap_after_staging_rolls_back_without_publishing(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        before = self._effect_fingerprint()
        decisions = self.project / "decisions"
        displaced = self.project / "decisions-displaced"

        def swap_target_parent(point: str) -> None:
            if point != "after-stage:effect-000000000000000000000002":
                return
            decisions.rename(displaced)
            decisions.mkdir(mode=0o700)

        with mock.patch.object(
            curation_transaction,
            "_run_checkpoint",
            side_effect=swap_target_parent,
        ):
            outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "TARGET_CONFLICT")
        self.assertEqual(self._effect_fingerprint(), before)
        self.assertEqual(list(displaced.iterdir()), [])

    def test_unprovable_rollback_returns_recovery_required_and_root_stop(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        first_stage = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "staging"
            / ("p-" + plan.sha256)
            / "effect-000000000000000000000001.stage"
        )

        def make_membership_ambiguous(point: str) -> None:
            if point != "after-stage:effect-000000000000000000000001":
                return
            self.targets[0].write_bytes(first_stage.read_bytes())
            self.targets[0].chmod(0o600)
            raise RuntimeError("simulated ambiguous rollback state")

        with mock.patch.object(
            curation_transaction,
            "_run_checkpoint",
            side_effect=make_membership_ambiguous,
        ):
            outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked_recovery")
        self.assertEqual(outcome["reason_code"], "CURATION_PLAN_RECOVERY_REQUIRED")
        self.assertEqual(
            curation_transaction.workstream_mutation_status(
                self.root,
                "example-service",
            ),
            "RECOVERY_REQUIRED",
        )
        root_stops = (
            self.root
            / "_registry"
            / "curation"
            / "authority-runtime"
            / "snapshot-v1"
            / "root-stops"
        )
        self.assertTrue(any(root_stops.iterdir()))

    def test_orphan_staging_fences_readers_and_plan_admission(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        orphan = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "staging"
            / ("p-" + plan.sha256)
        )
        orphan.mkdir(parents=True, mode=0o700)

        self.assertEqual(
            curation_transaction.workstream_mutation_status(
                self.root,
                "example-service",
            ),
            "RECOVERY_REQUIRED",
        )

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked_recovery")
        self.assertEqual(
            outcome["reason_code"],
            "CURATION_PLAN_RECOVERY_REQUIRED",
        )
        self.assertFalse(
            (
                self.root
                / "_registry"
                / "curation"
                / "canonical-curation-v1"
                / "transactions"
                / ("p-" + plan.sha256)
            ).exists()
        )
        for source, expected in zip(self.sources, self.source_bytes):
            self.assertEqual(source.read_bytes(), expected)
        for target in self.targets:
            self.assertFalse(target.exists())

    def test_incomplete_plan_rejects_a_different_plan_before_mutation(self) -> None:
        class SimulatedCrash(BaseException):
            pass

        plan = self._plan()
        request = self._request(plan)

        def crash_after_intent(point: str) -> None:
            if point == "after-prepared":
                raise SimulatedCrash("simulated process loss")

        with mock.patch.object(
            curation_transaction,
            "_run_checkpoint",
            side_effect=crash_after_intent,
        ):
            with self.assertRaises(SimulatedCrash):
                self._execute(request)

        different = replace(
            plan,
            coverage=(("revision", 2), ("truncated", False)),
        )
        before = self._effect_fingerprint()
        outcome = self._execute(self._request(different))

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "PLAN_CONFLICT")
        self.assertEqual(self._effect_fingerprint(), before)

    def test_same_exact_request_recovers_crash_by_rollback_or_finalize(self) -> None:
        cases = (
            (
                "after-stage:effect-000000000000000000000001",
                "blocked",
                "ROLLED_BACK",
            ),
            (
                "after-publish:effect-000000000000000000000002",
                "completed",
                "FINALIZED",
            ),
        )

        for point, outcome_kind, status in cases:
            with self.subTest(point=point):
                case = type(self)(methodName="runTest")
                case.setUp()
                try:
                    class SimulatedCrash(BaseException):
                        pass

                    plan = case._plan()
                    request = case._request(plan)

                    def crash(observed: str) -> None:
                        if observed == point:
                            raise SimulatedCrash("simulated process loss")

                    with mock.patch.object(
                        curation_transaction,
                        "_run_checkpoint",
                        side_effect=crash,
                    ):
                        with self.assertRaises(SimulatedCrash):
                            case._execute(request)

                    recovered = case._execute(request)

                    self.assertEqual(recovered["outcome_kind"], outcome_kind)
                    if outcome_kind == "completed":
                        self.assertEqual(recovered["result"]["status"], status)
                        for source in case.sources:
                            self.assertFalse(source.exists())
                        for target, expected in zip(case.targets, case.source_bytes):
                            self.assertEqual(target.read_bytes(), expected)
                    else:
                        self.assertEqual(recovered["reason_code"], status)
                        for source, expected in zip(case.sources, case.source_bytes):
                            self.assertEqual(source.read_bytes(), expected)
                        for target in case.targets:
                            self.assertFalse(target.exists())
                finally:
                    case.doCleanups()

    def test_competing_same_plan_writer_cannot_enter_the_transaction(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        paused = threading.Event()
        release = threading.Event()
        second_done = threading.Event()
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def checkpoint(point: str) -> None:
            if point == "after-prepared" and not paused.is_set():
                paused.set()
                if not release.wait(5):
                    raise RuntimeError("test release timed out")

        def execute(*, second: bool) -> None:
            try:
                results.append(self._execute(request))
            except BaseException as exc:
                errors.append(exc)
            finally:
                if second:
                    second_done.set()

        with mock.patch.object(
            curation_transaction,
            "_run_checkpoint",
            side_effect=checkpoint,
        ):
            first = threading.Thread(target=execute, kwargs={"second": False})
            first.start()
            self.assertTrue(paused.wait(5))
            second = threading.Thread(target=execute, kwargs={"second": True})
            second.start()
            rejected_while_first_was_paused = second_done.wait(1)
            release.set()
            first.join(10)
            second.join(10)

        self.assertTrue(rejected_while_first_was_paused)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(
            sorted(result["outcome_kind"] for result in results),
            ["blocked", "completed"],
        )
        blocked = next(result for result in results if result["outcome_kind"] == "blocked")
        self.assertEqual(blocked["reason_code"], "WRITER_BUSY")
        for target, expected in zip(self.targets, self.source_bytes):
            self.assertEqual(target.read_bytes(), expected)

    def test_malformed_plan_or_decision_is_rejected_before_admission(self) -> None:
        plan = self._plan()
        request = self._request(plan)
        payload = json.loads(request.canonical_bytes)["payload"]
        payload["plan"]["relation_projection"] = {"unsupported": True}
        malformed = operation_contract.OperationRequest(
            schema_version=1,
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

        with mock.patch.object(
            execution.authority_runtime,
            "admit",
            side_effect=AssertionError("invalid Plan reached admission"),
        ):
            outcome = self._execute(malformed)

        self.assertEqual(outcome["outcome_kind"], "blocked")
        self.assertEqual(outcome["reason_code"], "INVALID_REQUEST")

    def test_unfinished_transaction_fences_new_current_inspection(self) -> None:
        class SimulatedCrash(BaseException):
            pass

        plan = self._plan()
        request = self._request(plan)

        def crash_after_intent(point: str) -> None:
            if point == "after-prepared":
                raise SimulatedCrash("simulated process loss")

        with mock.patch.object(
            curation_transaction,
            "_run_checkpoint",
            side_effect=crash_after_intent,
        ):
            with self.assertRaises(SimulatedCrash):
                self._execute(request)

        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            package = Path(temporary) / "review"
            package.mkdir(mode=0o700)
            with self.assertRaises(
                workstream_curation.WorkstreamCurationError
            ) as raised:
                workstream_curation.inspect_workstream(
                    root=self.root,
                    workstream_ref="example-service",
                    review_package_directory=package,
                    max_items=32,
                    max_depth=4,
                    max_hint_bytes=8192,
                    actor="test-operator",
                )

        self.assertEqual(raised.exception.reason_code, "MUTATION_IN_PROGRESS")

    def test_changed_expected_stage_file_requires_recovery(self) -> None:
        class SimulatedCrash(BaseException):
            pass

        plan = self._plan()
        request = self._request(plan)

        def crash_after_first_stage(point: str) -> None:
            if point == "after-stage:effect-000000000000000000000001":
                raise SimulatedCrash("simulated process loss")

        with mock.patch.object(
            curation_transaction,
            "_run_checkpoint",
            side_effect=crash_after_first_stage,
        ):
            with self.assertRaises(SimulatedCrash):
                self._execute(request)

        stage_file = (
            self.root
            / "_registry"
            / "curation"
            / "canonical-curation-v1"
            / "staging"
            / ("p-" + plan.sha256)
            / "effect-000000000000000000000001.stage"
        )
        stage_file.write_bytes(b"changed after the crash\n")
        stage_file.chmod(0o600)

        self.assertEqual(
            curation_transaction.workstream_mutation_status(
                self.root,
                "example-service",
            ),
            "RECOVERY_REQUIRED",
        )

        outcome = self._execute(request)

        self.assertEqual(outcome["outcome_kind"], "blocked_recovery")
        self.assertEqual(
            outcome["reason_code"],
            "CURATION_PLAN_RECOVERY_REQUIRED",
        )


if __name__ == "__main__":
    unittest.main()
