import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import curation_scheduler, projection_refresh  # noqa: E402
from mnemosyne_core.workstream_curation import WorkstreamCurationError  # noqa: E402


SOURCE_A = "a" * 64
SOURCE_B = "b" * 64
PLAN_SHA = "c" * 64
PACKAGE_HASHES = {
    "html_sha256": "d" * 64,
    "markdown_sha256": "e" * 64,
    "meta_sha256": "f" * 64,
    "semantic_sha256": "0" * 64,
}
EXPECTED_PROJECTION = (
    "_registry/curation/projections/v1/workstreams/alpha/inventory.json"
)


def _projection_request(
    root: Path,
    *,
    source_sha256: str = SOURCE_A,
    output: bytes = b'{"files":1}\n',
    kind: str = "inventory",
) -> projection_refresh.ProjectionRefreshRequest:
    return projection_refresh.ProjectionRefreshRequest(
        root=root,
        workstream_id="alpha",
        projection_kind=kind,
        source_observation_sha256=source_sha256,
        output=output,
        media_type="application/json",
        actor="m4-test",
    )


def _scheduled_request(root: Path) -> curation_scheduler.ScheduledInspectionRequest:
    return curation_scheduler.ScheduledInspectionRequest(
        root=root,
        workstream_ref="alpha",
        review_package_directory=root.parent / "review-package",
        max_items=32,
        max_depth=4,
        max_hint_bytes=4096,
        actor="m4-test",
    )


def _inspection(
    *,
    effects: list[dict[str, object]],
    findings: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "outcome_kind": "completed",
        "result": {
            "plan": {
                "effects": effects,
                "findings": findings or [],
                "sha256": PLAN_SHA,
                "source_observation_sha256": SOURCE_A,
            },
            "review_package": {
                "directory": "/private/tmp/review-package",
                **PACKAGE_HASHES,
            },
            "workstream": {
                "id": "alpha",
                "lifecycle": "active",
                "project_home": "projects/alpha",
            },
        },
    }


def _move_effect() -> dict[str, object]:
    return {
        "action": "move",
        "id": "effect-000000000000000000000001",
        "source": "inbox/example-project.md",
        "source_sha256": "1" * 64,
        "target": "projects/alpha/references/example-project.md",
        "output_sha256": "1" * 64,
    }


class ProjectionRefreshMvpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "raw"
        self.root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_allowlisted_projection_is_source_bound_atomic_and_idempotent(self) -> None:
        first = projection_refresh.refresh_projection(
            _projection_request(self.root),
            refreshed_at="2026-07-19T15:00:00Z",
        )
        target = self.root / EXPECTED_PROJECTION
        first_bytes = target.read_bytes()
        envelope = json.loads(first_bytes)

        self.assertEqual(first.status, "CURRENT")
        self.assertTrue(first.changed)
        self.assertEqual(first.relative_path, EXPECTED_PROJECTION)
        self.assertEqual(envelope["schema"], "mnemosyne.curation-projection.v1")
        self.assertEqual(envelope["projection_kind"], "inventory")
        self.assertEqual(envelope["workstream_id"], "alpha")
        self.assertEqual(envelope["source_observation_sha256"], SOURCE_A)
        self.assertIsNone(envelope["previous_source_observation_sha256"])
        self.assertEqual(envelope["output"]["text"], '{"files":1}\n')
        self.assertEqual(
            envelope["output"]["content_sha256"],
            hashlib.sha256(b'{"files":1}\n').hexdigest(),
        )
        self.assertEqual(envelope["receipt"]["status"], "CURRENT")
        self.assertEqual(stat_mode(target), 0o600)

        repeated = projection_refresh.refresh_projection(
            _projection_request(self.root),
            refreshed_at="2026-07-19T15:05:00Z",
        )
        self.assertEqual(repeated.status, "CURRENT")
        self.assertFalse(repeated.changed)
        self.assertEqual(target.read_bytes(), first_bytes)

        updated = projection_refresh.refresh_projection(
            _projection_request(
                self.root,
                source_sha256=SOURCE_B,
                output=b'{"files":2}\n',
            ),
            refreshed_at="2026-07-19T15:10:00Z",
        )
        updated_envelope = json.loads(target.read_bytes())
        self.assertTrue(updated.changed)
        self.assertEqual(updated_envelope["source_observation_sha256"], SOURCE_B)
        self.assertEqual(
            updated_envelope["previous_source_observation_sha256"],
            SOURCE_A,
        )

    def test_failed_refresh_preserves_previous_and_protected_kind_is_impossible(self) -> None:
        projection_refresh.refresh_projection(
            _projection_request(self.root),
            refreshed_at="2026-07-19T15:00:00Z",
        )
        target = self.root / EXPECTED_PROJECTION
        previous = target.read_bytes()

        def stop(checkpoint: str) -> None:
            if checkpoint == "before_atomic_replace":
                raise RuntimeError("injected failure")

        with self.assertRaises(projection_refresh.ProjectionRefreshError):
            projection_refresh.refresh_projection(
                _projection_request(
                    self.root,
                    source_sha256=SOURCE_B,
                    output=b'{"files":2}\n',
                ),
                refreshed_at="2026-07-19T15:10:00Z",
                checkpoint=stop,
            )
        self.assertEqual(target.read_bytes(), previous)
        self.assertEqual(
            [path.name for path in target.parent.iterdir() if path.name.startswith(".tmp-")],
            [],
        )

        before = tuple(sorted(path.relative_to(self.root) for path in self.root.rglob("*")))
        with self.assertRaises(ValueError):
            _projection_request(self.root, kind="memory")
        after = tuple(sorted(path.relative_to(self.root) for path in self.root.rglob("*")))
        self.assertEqual(after, before)


class ScheduledInspectionMvpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "raw"
        self.root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_common_contract_is_quiet_or_review_ready(self) -> None:
        quiet = curation_scheduler.run_scheduled_inspection(
            _scheduled_request(self.root),
            inspector=lambda **_kwargs: _inspection(effects=[]),
        )
        self.assertEqual(quiet.status, "QUIET")
        self.assertIsNone(quiet.question)
        self.assertEqual(quiet.plan_sha256, PLAN_SHA)

        review = curation_scheduler.run_scheduled_inspection(
            _scheduled_request(self.root),
            inspector=lambda **_kwargs: _inspection(effects=[_move_effect()]),
        )
        self.assertEqual(review.status, "REVIEW_READY")
        self.assertEqual(review.plan_sha256, PLAN_SHA)
        self.assertEqual(review.source_observation_sha256, SOURCE_A)
        self.assertEqual(dict(review.review_package_hashes), PACKAGE_HASHES)
        self.assertEqual(review.idempotency_key, f"mnemosyne-review:{PLAN_SHA}")
        self.assertIn("inbox/example-project.md", review.brief)
        self.assertIn("projects/alpha/references/example-project.md", review.brief)
        self.assertIsNotNone(review.question)

    def test_blocked_inspection_is_actionable_without_guessing_approval(self) -> None:
        def blocked(**_kwargs: object) -> dict[str, object]:
            raise WorkstreamCurationError(
                "Workstream has an unfinished transaction",
                reason_code="MUTATION_IN_PROGRESS",
            )

        result = curation_scheduler.run_scheduled_inspection(
            _scheduled_request(self.root),
            inspector=blocked,
        )

        self.assertEqual(result.status, "REVIEW_READY")
        self.assertEqual(result.action_kind, "INSPECTION_BLOCKED")
        self.assertIsNone(result.plan_sha256)
        self.assertIn("MUTATION_IN_PROGRESS", result.brief)
        self.assertNotIn("승인", result.question or "")

    def test_finding_without_effect_is_not_misreported_as_quiet(self) -> None:
        finding = {
            "evidence": ["OWNER_AMBIGUOUS"],
            "id": "finding-000000000000000000000001",
            "kind": "EXTERNAL_OWNER_REVIEW",
            "path": "inbox/shared-example-project.md",
            "status": "BLOCKED_UNTIL_REINFORCEMENT",
        }
        result = curation_scheduler.run_scheduled_inspection(
            _scheduled_request(self.root),
            inspector=lambda **_kwargs: _inspection(effects=[], findings=[finding]),
        )

        self.assertEqual(result.status, "REVIEW_READY")
        self.assertEqual(result.action_kind, "FINDING_REVIEW")
        self.assertIn("inbox/shared-example-project.md", result.brief)
        self.assertNotIn("승인", result.question or "")

    def test_codex_and_hermes_use_one_stable_idempotency_key(self) -> None:
        result = curation_scheduler.run_scheduled_inspection(
            _scheduled_request(self.root),
            inspector=lambda **_kwargs: _inspection(effects=[_move_effect()]),
        )
        sessions: dict[str, str] = {}

        def create_or_get(key: str, payload: dict[str, object]) -> dict[str, object]:
            created = key not in sessions
            session_id = sessions.setdefault(key, "session-1")
            return {
                "continuable": True,
                "created": created,
                "session_id": session_id,
                "question": payload["question"],
            }

        codex = curation_scheduler.deliver_to_codex(
            result,
            create_or_get_session=create_or_get,
        )
        hermes = curation_scheduler.deliver_to_hermes(
            result,
            create_or_get_session=create_or_get,
        )

        self.assertEqual(codex.status, "REVIEW_READY")
        self.assertEqual(hermes.status, "REVIEW_READY")
        self.assertEqual(codex.idempotency_key, hermes.idempotency_key)
        self.assertEqual(codex.session_id, hermes.session_id)
        self.assertTrue(codex.created)
        self.assertFalse(hermes.created)
        self.assertEqual(len(sessions), 1)

        pending = curation_scheduler.deliver_to_codex(
            result,
            create_or_get_session=None,
        )
        self.assertEqual(pending.status, "PENDING_DELIVERY")
        self.assertEqual(pending.idempotency_key, result.idempotency_key)
        self.assertIsNone(pending.session_id)


def stat_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
