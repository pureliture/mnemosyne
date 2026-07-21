from __future__ import annotations

import datetime
import json
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from mnemosyne_core import (  # noqa: E402
    canonical_json,
    control,
    deferral_service,
    deferral_store,
    ledger_schema,
    m3_schema,
)


HASH_A = "a" * 64
HASH_B = "b" * 64
ITEM_ID = "11111111-1111-4111-8111-111111111111"


def create_v3_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in control.CONTROL_SCHEMA_STATEMENTS:
            connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_INDEX_STATEMENTS:
            connection.execute(statement)
        for statement in control.CONTROL_SCHEMA_TRIGGER_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations VALUES (?, ?, ?)",
            (control.CONTROL_SCHEMA_VERSION, control.CONTROL_SCHEMA_SHA256, "bootstrap-v1"),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        connection.close()
        raise
    ledger_schema.ensure_v2_schema(
        connection,
        migration_id="document-curation-m2-v2",
    )
    m3_schema.ensure_v3_schema(connection)
    return connection


def seed_current_deferral(
    connection: sqlite3.Connection,
    *,
    trigger_kind: str = "EVIDENCE",
    version: int = 1,
) -> None:
    empty = canonical_json.canonical_json_bytes({})
    required = canonical_json.canonical_json_bytes(["new evidence"])
    connection.execute(
        "INSERT INTO inventory_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "run-1",
            HASH_A,
            "inventory/run-1",
            HASH_B,
            HASH_A,
            1,
            HASH_B,
            HASH_A,
            HASH_B,
            "INITIAL",
            "policy-run-1",
            0,
            None,
            "OPENED",
        ),
    )
    connection.execute(
        "INSERT INTO campaigns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "campaign-1",
            "run-1",
            HASH_A,
            "READY",
            "snapshot-1",
            HASH_B,
            1,
            None,
            "owner",
            empty,
            "campaigns/campaign-1/campaign.json",
            "c" * 64,
        ),
    )
    connection.execute(
        "INSERT INTO items VALUES (?, ?, ?)",
        (ITEM_ID, "run-1", "REVIEW_READY"),
    )
    connection.execute(
        "INSERT INTO decision_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "decision-1",
            "campaign-1",
            None,
            ITEM_ID,
            "snapshot-1",
            HASH_B,
            1,
            1,
            "owner",
            "DEFER",
            None,
            None,
            empty,
            canonical_json.sha256_bytes(empty),
            "2026-07-15T00:00:00Z",
        ),
    )
    revisit_date = "2026-07-15" if trigger_kind == "DATE" else None
    timezone = "Asia/Seoul" if trigger_kind == "DATE" else None
    workstream_id = "example-paused-service" if trigger_kind == "WORKSTREAM_RESUME" else None
    lifecycle = "paused" if trigger_kind == "WORKSTREAM_RESUME" else None
    policy_hash = HASH_A if trigger_kind == "WORKSTREAM_RESUME" else None
    connection.execute(
        "INSERT INTO deferrals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "deferral-1",
            ITEM_ID,
            "decision-1",
            version,
            "wait for exact trigger",
            required,
            canonical_json.sha256_bytes(required),
            trigger_kind,
            revisit_date,
            timezone,
            workstream_id,
            lifecycle,
            policy_hash,
            "owner",
            "CURRENT",
        ),
    )
    connection.execute(
        "INSERT INTO item_curation_projection VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ITEM_ID,
            "DEFERRED",
            "decision-1",
            "deferral-1",
            "run-1",
            "FRESH",
            "decision-1",
            None,
            1,
            0,
            0,
            0,
            0,
            0,
        ),
    )


def eligible_request() -> deferral_service.EvidenceAttachmentInput:
    return deferral_service.EvidenceAttachmentInput(
        event_id="evidence-1",
        deferral_id="deferral-1",
        deferral_version=1,
        actor="reviewer",
        scope_class="eligible",
        allowed_metadata=(("kind", "report"), ("size", 19)),
        source_ref="incoming/report.md",
        content_sha256=HASH_B,
    )


class DeferralEvidenceStoreTests(unittest.TestCase):
    def test_attach_persists_safe_prepared_evidence_then_owner_only_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            control_root = Path(temporary).resolve() / "curation"
            control_root.mkdir(mode=0o700)
            connection = create_v3_connection()
            seed_current_deferral(connection)
            stages = []

            result = deferral_store.attach_deferral_evidence(
                control_root,
                connection,
                eligible_request(),
                checkpoint=stages.append,
            )

            self.assertEqual(
                stages,
                ["prepared", "artifact-published", "published"],
            )
            self.assertEqual(result.state, "PUBLISHED")
            row = connection.execute(
                "SELECT evidence_event_id, deferral_id, deferral_version, actor, "
                "source_reference, supplied_content_sha256, opaque_source_id, "
                "actor_attestation, idempotency_key, payload_json, payload_sha256, "
                "final_path, final_sha256, state "
                "FROM deferral_evidence_events"
            ).fetchone()
            self.assertEqual(row[0:6], ("evidence-1", "deferral-1", 1, "reviewer", "incoming/report.md", HASH_B))
            self.assertEqual(row[6:8], (None, None))
            self.assertEqual(row[8], result.idempotency_key)
            self.assertEqual(row[9], result.payload_bytes)
            self.assertEqual(row[10], canonical_json.sha256_bytes(result.payload_bytes))
            self.assertEqual(
                row[11],
                "campaigns/campaign-1/deferral-evidence/evidence-1/evidence.json",
            )
            self.assertEqual(row[12], canonical_json.sha256_bytes(result.payload_bytes))
            self.assertEqual(row[13], "PUBLISHED")
            artifact = control_root / row[11]
            self.assertEqual(artifact.read_bytes(), result.payload_bytes)
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(artifact.parent.stat().st_mode), 0o700)
            self.assertEqual(
                canonical_json.canonical_json_bytes(
                    json.loads(result.payload_bytes.decode("utf-8"))
                ),
                result.payload_bytes,
            )
            connection.close()

    def test_resume_uses_only_the_canonical_bytes_stored_at_prepare(self):
        class SimulatedCrash(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            control_root = Path(temporary).resolve() / "curation"
            control_root.mkdir(mode=0o700)
            connection = create_v3_connection()
            seed_current_deferral(connection)

            def crash_after_prepare(stage):
                if stage == "prepared":
                    raise SimulatedCrash("after prepare")

            with self.assertRaisesRegex(SimulatedCrash, "after prepare"):
                deferral_store.attach_deferral_evidence(
                    control_root,
                    connection,
                    eligible_request(),
                    checkpoint=crash_after_prepare,
                )
            stored = connection.execute(
                "SELECT payload_json, final_path, state FROM deferral_evidence_events"
            ).fetchone()
            self.assertEqual(stored[2], "PREPARED")
            self.assertFalse((control_root / stored[1]).exists())

            stages = []
            result = deferral_store.resume_deferral_evidence(
                control_root,
                connection,
                "evidence-1",
                checkpoint=stages.append,
            )

            self.assertTrue(result.resumed)
            self.assertEqual(result.payload_bytes, stored[0])
            self.assertEqual(stages, ["artifact-published", "published"])
            self.assertEqual((control_root / stored[1]).read_bytes(), stored[0])
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM deferral_evidence_events"
                ).fetchone(),
                ("PUBLISHED",),
            )
            connection.close()

    def test_resume_after_artifact_publish_crash_reads_back_without_replacing(self):
        class SimulatedCrash(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            control_root = Path(temporary).resolve() / "curation"
            control_root.mkdir(mode=0o700)
            connection = create_v3_connection()
            seed_current_deferral(connection)

            def crash_after_artifact(stage):
                if stage == "artifact-published":
                    raise SimulatedCrash("after artifact")

            with self.assertRaisesRegex(SimulatedCrash, "after artifact"):
                deferral_store.attach_deferral_evidence(
                    control_root,
                    connection,
                    eligible_request(),
                    checkpoint=crash_after_artifact,
                )
            stored = connection.execute(
                "SELECT payload_json, final_path, state FROM deferral_evidence_events"
            ).fetchone()
            artifact = control_root / stored[1]
            before = (artifact.stat().st_ino, artifact.stat().st_mtime_ns, artifact.read_bytes())
            self.assertEqual(stored[2], "PREPARED")

            result = deferral_store.resume_deferral_evidence(
                control_root,
                connection,
                "evidence-1",
            )

            self.assertEqual(
                (artifact.stat().st_ino, artifact.stat().st_mtime_ns, artifact.read_bytes()),
                before,
            )
            self.assertEqual(result.state, "PUBLISHED")
            self.assertTrue(result.resumed)
            connection.close()

    def test_stale_version_after_prepare_blocks_the_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            control_root = Path(temporary).resolve() / "curation"
            control_root.mkdir(mode=0o700)
            connection = create_v3_connection()
            seed_current_deferral(connection)

            def make_stale(stage):
                if stage == "prepared":
                    connection.execute(
                        "UPDATE deferrals SET version = 2 WHERE deferral_id = 'deferral-1'"
                    )

            with self.assertRaisesRegex(deferral_store.DeferralStoreError, "stale"):
                deferral_store.attach_deferral_evidence(
                    control_root,
                    connection,
                    eligible_request(),
                    checkpoint=make_stale,
                )

            row = connection.execute(
                "SELECT final_path, state FROM deferral_evidence_events"
            ).fetchone()
            self.assertEqual(row[1], "BLOCKED")
            self.assertTrue((control_root / row[0]).is_file())
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM deferral_trigger_events"
                ).fetchone(),
                (0,),
            )
            connection.close()

    def test_existing_mismatched_artifact_is_never_overwritten_and_blocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            control_root = Path(temporary).resolve() / "curation"
            control_root.mkdir(mode=0o700)
            connection = create_v3_connection()
            seed_current_deferral(connection)
            tampered = b'{"tampered":true}\n'

            def inject_tampered_artifact(stage):
                if stage != "prepared":
                    return
                relative = connection.execute(
                    "SELECT final_path FROM deferral_evidence_events"
                ).fetchone()[0]
                artifact = control_root / relative
                artifact.parent.mkdir(parents=True, mode=0o700)
                artifact.write_bytes(tampered)
                artifact.chmod(0o600)

            with self.assertRaisesRegex(
                deferral_store.DeferralStoreError,
                "readback mismatch",
            ):
                deferral_store.attach_deferral_evidence(
                    control_root,
                    connection,
                    eligible_request(),
                    checkpoint=inject_tampered_artifact,
                )

            row = connection.execute(
                "SELECT final_path, state FROM deferral_evidence_events"
            ).fetchone()
            self.assertEqual(row[1], "BLOCKED")
            self.assertEqual((control_root / row[0]).read_bytes(), tampered)
            connection.close()

    def test_duplicate_semantic_evidence_returns_the_first_stored_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            control_root = Path(temporary).resolve() / "curation"
            control_root.mkdir(mode=0o700)
            connection = create_v3_connection()
            seed_current_deferral(connection)
            first = deferral_store.attach_deferral_evidence(
                control_root,
                connection,
                eligible_request(),
            )
            duplicate = eligible_request()
            duplicate = deferral_service.EvidenceAttachmentInput(
                event_id="evidence-duplicate",
                deferral_id=duplicate.deferral_id,
                deferral_version=duplicate.deferral_version,
                actor=duplicate.actor,
                scope_class=duplicate.scope_class,
                allowed_metadata=duplicate.allowed_metadata,
                source_ref=duplicate.source_ref,
                content_sha256=duplicate.content_sha256,
            )

            stored = deferral_store.attach_deferral_evidence(
                control_root,
                connection,
                duplicate,
            )

            self.assertEqual(stored.event_id, first.event_id)
            self.assertEqual(stored.final_path, first.final_path)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM deferral_evidence_events"
                ).fetchone(),
                (1,),
            )
            self.assertFalse(
                (
                    control_root
                    / "campaigns/campaign-1/deferral-evidence/evidence-duplicate"
                ).exists()
            )
            connection.close()


class DeferralTriggerStoreTests(unittest.TestCase):
    def test_published_evidence_is_consumed_once_with_atomic_review_ready_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            control_root = Path(temporary).resolve() / "curation"
            control_root.mkdir(mode=0o700)
            connection = create_v3_connection()
            seed_current_deferral(connection)
            publication = deferral_store.attach_deferral_evidence(
                control_root,
                connection,
                eligible_request(),
            )
            clock = datetime.datetime(
                2026, 7, 15, 1, 2, 3, tzinfo=datetime.timezone.utc
            )

            first = deferral_store.evaluate_deferral(
                control_root,
                connection,
                deferral_id="deferral-1",
                expected_version=1,
                actor="reviewer",
                now=clock,
                evidence_event_id="evidence-1",
            )

            pure_record = deferral_service.DeferralRecord(
                deferral_id="deferral-1",
                item_id=ITEM_ID,
                version=1,
                state="waiting",
                trigger_kind="evidence",
            )
            pure_evidence = deferral_service.PublishedEvidence(
                event_id="evidence-1",
                event_sha256=publication.final_sha256,
                deferral_id="deferral-1",
                deferral_version=1,
                state="PUBLISHED",
            )
            evaluator = deferral_service.DeferralTriggerEvaluator()
            pure_preview = evaluator.preview(
                pure_record,
                now=clock,
                published_evidence=pure_evidence,
            )
            pure_intent = evaluator.evaluate(
                pure_record,
                pure_preview,
                actor="reviewer",
            )
            self.assertEqual(
                first.payload_bytes,
                canonical_json.canonical_json_bytes(pure_intent.event),
            )
            self.assertFalse(first.repeated)
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM deferrals WHERE deferral_id = 'deferral-1'"
                ).fetchone(),
                ("TRIGGERED",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT primary_state, current_deferral_id, source_event_id, "
                    "projection_generation FROM item_curation_projection"
                ).fetchone(),
                ("REVIEW_READY", None, first.trigger_event_id, 2),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM deferral_evidence_events"
                ).fetchone(),
                ("CONSUMED",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT source_evidence_event_id, payload_json "
                    "FROM deferral_trigger_events"
                ).fetchone(),
                ("evidence-1", first.payload_bytes),
            )

            repeated = deferral_store.evaluate_deferral(
                control_root,
                connection,
                deferral_id="deferral-1",
                expected_version=1,
                actor="reviewer",
                now=clock + datetime.timedelta(days=1),
                evidence_event_id="evidence-1",
            )

            self.assertTrue(repeated.repeated)
            self.assertEqual(repeated.trigger_event_id, first.trigger_event_id)
            self.assertEqual(repeated.projection_generation, 2)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM deferral_trigger_events"
                ).fetchone(),
                (1,),
            )
            for table in (
                "policy_bootstrap_approvals",
                "policy_change_approvals",
                "document_relation_events",
                "batch_events",
            ):
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM " + table).fetchone(),
                    (0,),
                )
            self.assertEqual(
                [path.relative_to(control_root).as_posix() for path in control_root.rglob("*") if path.is_file()],
                ["campaigns/campaign-1/deferral-evidence/evidence-1/evidence.json"],
            )
            connection.close()

    def test_date_workstream_and_manual_triggers_persist_only_pure_evaluator_intent(self):
        cases = (
            (
                "DATE",
                {},
                deferral_service.DeferralRecord(
                    deferral_id="deferral-1",
                    item_id=ITEM_ID,
                    version=1,
                    state="waiting",
                    trigger_kind="date",
                    review_date="2026-07-15",
                    timezone="Asia/Seoul",
                ),
                None,
            ),
            (
                "WORKSTREAM_RESUME",
                {
                    "current_workstream_lifecycle": "active",
                    "current_policy_hash": HASH_B,
                },
                deferral_service.DeferralRecord(
                    deferral_id="deferral-1",
                    item_id=ITEM_ID,
                    version=1,
                    state="waiting",
                    trigger_kind="workstream-resume",
                    workstream_id="example-paused-service",
                    captured_lifecycle="paused",
                    captured_policy_hash=HASH_A,
                ),
                HASH_B,
            ),
            (
                "MANUAL_REOPEN",
                {"manual_reason": "new authority evidence is available"},
                deferral_service.DeferralRecord(
                    deferral_id="deferral-1",
                    item_id=ITEM_ID,
                    version=1,
                    state="waiting",
                    trigger_kind="manual-reopen",
                ),
                None,
            ),
        )
        clock = datetime.datetime(
            2026, 7, 15, 0, 0, tzinfo=datetime.timezone.utc
        )
        for trigger_kind, arguments, pure_record, expected_policy_hash in cases:
            with self.subTest(trigger_kind=trigger_kind), tempfile.TemporaryDirectory() as temporary:
                control_root = Path(temporary).resolve() / "curation"
                control_root.mkdir(mode=0o700)
                connection = create_v3_connection()
                seed_current_deferral(connection, trigger_kind=trigger_kind)

                result = deferral_store.evaluate_deferral(
                    control_root,
                    connection,
                    deferral_id="deferral-1",
                    expected_version=1,
                    actor="reviewer",
                    now=clock,
                    **arguments,
                )

                evaluator = deferral_service.DeferralTriggerEvaluator()
                manual = None
                if trigger_kind == "MANUAL_REOPEN":
                    manual = deferral_service.ManualReopenEvidence(
                        deferral_id="deferral-1",
                        deferral_version=1,
                        actor="reviewer",
                        reason=arguments["manual_reason"],
                    )
                pure_preview = evaluator.preview(
                    pure_record,
                    now=clock,
                    current_workstream_lifecycle=arguments.get(
                        "current_workstream_lifecycle"
                    ),
                    current_policy_hash=arguments.get("current_policy_hash"),
                    manual_reopen=manual,
                )
                pure_intent = evaluator.evaluate(
                    pure_record,
                    pure_preview,
                    actor="reviewer",
                )
                self.assertEqual(
                    result.payload_bytes,
                    canonical_json.canonical_json_bytes(pure_intent.event),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT source_evidence_event_id, policy_sha256, payload_json "
                        "FROM deferral_trigger_events"
                    ).fetchone(),
                    (None, expected_policy_hash, result.payload_bytes),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT state FROM deferrals"
                    ).fetchone(),
                    ("TRIGGERED",),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT primary_state FROM item_curation_projection"
                    ).fetchone(),
                    ("REVIEW_READY",),
                )
                self.assertEqual(list(control_root.rglob("*")), [])
                connection.close()

    def test_stale_or_tampered_published_evidence_blocks_without_trigger_effects(self):
        for failure in ("stale", "tampered"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                control_root = Path(temporary).resolve() / "curation"
                control_root.mkdir(mode=0o700)
                connection = create_v3_connection()
                seed_current_deferral(connection)
                publication = deferral_store.attach_deferral_evidence(
                    control_root,
                    connection,
                    eligible_request(),
                )
                if failure == "stale":
                    connection.execute(
                        "UPDATE deferrals SET version = 2 WHERE deferral_id = 'deferral-1'"
                    )
                else:
                    publication.final_path.write_bytes(b'{"tampered":true}\n')
                    publication.final_path.chmod(0o600)

                with self.assertRaises(deferral_store.DeferralStoreError):
                    deferral_store.evaluate_deferral(
                        control_root,
                        connection,
                        deferral_id="deferral-1",
                        expected_version=1,
                        actor="reviewer",
                        now=datetime.datetime.now(datetime.timezone.utc),
                        evidence_event_id="evidence-1",
                    )

                self.assertEqual(
                    connection.execute(
                        "SELECT state FROM deferral_evidence_events"
                    ).fetchone(),
                    ("BLOCKED",),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM deferral_trigger_events"
                    ).fetchone(),
                    (0,),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT primary_state, projection_generation "
                        "FROM item_curation_projection"
                    ).fetchone(),
                    ("DEFERRED", 1),
                )
                connection.close()


if __name__ == "__main__":
    unittest.main()
