from __future__ import annotations

import hashlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from mnemosyne_core import control, ledger_schema, legacy_import, m3_schema  # noqa: E402


CURRENT_DECISION_KEYS = (
    "id",
    "proposal_id",
    "decision",
    "decided_at",
    "actor",
    "source",
    "target",
    "category",
    "reason",
    "proposal_created_at",
)


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


def decision_bytes(
    root: Path,
    *,
    decision_id: str,
    proposal_id: str,
    decision: str,
    source_name: str | None = None,
    target_name: str | None = None,
) -> bytes:
    values = {
        "id": decision_id,
        "proposal_id": proposal_id,
        "decision": decision,
        "decided_at": "2026-07-14T07:14:29Z",
        "actor": "operator",
        "source": str(root / "inbox" / (source_name or (proposal_id + ".md"))),
        "target": str(root / "docs" / (target_name or (proposal_id + ".md"))),
        "category": "manual",
        "reason": "legacy placement decision",
        "proposal_created_at": "2026-07-14T07:13:00Z",
    }
    return (
        "\n".join('%s: "%s"' % (key, values[key]) for key in CURRENT_DECISION_KEYS)
        + "\n"
    ).encode("utf-8")


class LegacyHistoryPreviewTests(unittest.TestCase):
    def test_preview_is_sorted_write_free_and_ignores_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)

            second = decision_bytes(
                root,
                decision_id="rejected-20260714T071430Z-bbbbbbbb",
                proposal_id="place-b",
                decision="rejected",
            )
            first = decision_bytes(
                root,
                decision_id="approved-20260714T071429Z-aaaaaaaa",
                proposal_id="place-a",
                decision="approved",
            )
            (decisions / "z.yml").write_bytes(second)
            (decisions / "a.yml").write_bytes(first)
            (pending / "place-unimported.yml").write_text(
                'id: "place-unimported"\nstatus: "pending"\n',
                encoding="utf-8",
            )
            before = {
                path: path.read_bytes()
                for path in sorted((root / "_registry").rglob("*.yml"))
            }

            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-001",
                requested_by="tester",
            )

            self.assertEqual(
                [row["legacy_path"] for row in preview["entries"]],
                ["decisions/a.yml", "decisions/z.yml"],
            )
            self.assertEqual(
                [row["content_sha256"] for row in preview["entries"]],
                [hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest()],
            )
            self.assertEqual(
                [row["parse_result"]["status"] for row in preview["entries"]],
                ["PARSED", "PARSED"],
            )
            self.assertEqual(preview["pending_count"], 1)
            self.assertEqual(
                [row["idempotency_key"] for row in preview["entries"]],
                [
                    ["decisions/a.yml", hashlib.sha256(first).hexdigest()],
                    ["decisions/z.yml", hashlib.sha256(second).hexdigest()],
                ],
            )
            self.assertEqual(
                before,
                {path: path.read_bytes() for path in before},
            )
            self.assertFalse((root / "_registry" / "curation").exists())

    def test_import_blocks_while_pending_proposals_exist(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            (decisions / "approved.yml").write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                )
            )
            (pending / "place-unimported.yml").write_text(
                'id: "place-unimported"\nstatus: "pending"\n',
                encoding="utf-8",
            )
            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-blocked-001",
                requested_by="requester",
            )
            connection = create_v3_connection()
            try:
                with self.assertRaisesRegex(
                    legacy_import.LegacyImportError,
                    "pending proposals",
                ):
                    legacy_import.import_legacy_history(
                        root,
                        connection,
                        preview=preview,
                        expected_preview_sha256=preview["preview_sha256"],
                        import_run_id="legacy-import-blocked-001",
                        actor="importer",
                    )
            finally:
                connection.close()

    def test_preview_reports_strict_parse_failures_and_path_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            (decisions / "a.yml").write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                    source_name="shared.md",
                )
            )
            (decisions / "b.yml").write_bytes(
                decision_bytes(
                    root,
                    decision_id="rejected-20260714T071430Z-bbbbbbbb",
                    proposal_id="place-b",
                    decision="rejected",
                    source_name="shared.md",
                )
            )
            malformed = decision_bytes(
                root,
                decision_id="approved-20260714T071431Z-cccccccc",
                proposal_id="place-c",
                decision="approved",
            ).replace(b'actor: "operator"\n', b'actor: "operator"\nactor: "other"\n')
            (decisions / "c.yml").write_bytes(malformed)

            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-002",
                requested_by="tester",
            )

            self.assertEqual(
                [row["parse_result"]["status"] for row in preview["entries"]],
                ["PARSED", "PARSED", "UNPARSED"],
            )
            self.assertEqual(
                preview["collisions"],
                [
                    {
                        "kinds": ["same-source"],
                        "left": "decisions/a.yml",
                        "right": "decisions/b.yml",
                    }
                ],
            )


class LegacyHistoryImportTests(unittest.TestCase):
    def test_import_rejects_schema_drift_before_prepare_or_result_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            (decisions / "approved.yml").write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                )
            )
            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-schema-001",
                requested_by="requester",
            )
            connection = create_v3_connection()
            connection.execute("DROP TRIGGER legacy_imports_no_update")
            try:
                with self.assertRaisesRegex(
                    legacy_import.LegacyImportError,
                    "schema",
                ):
                    legacy_import.import_legacy_history(
                        root,
                        connection,
                        preview=preview,
                        expected_preview_sha256=preview["preview_sha256"],
                        import_run_id="legacy-import-schema-001",
                        actor="importer",
                    )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM legacy_import_runs").fetchone(),
                    (0,),
                )
                self.assertFalse((root / "_registry" / "curation").exists())
            finally:
                connection.close()

    def test_import_commits_exact_rows_head_and_owner_only_result_idempotently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            source = decisions / "approved.yml"
            source.write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                )
            )
            before = source.read_bytes()
            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-import-001",
                requested_by="requester",
            )
            connection = create_v3_connection()
            try:
                first = legacy_import.import_legacy_history(
                    root,
                    connection,
                    preview=preview,
                    expected_preview_sha256=preview["preview_sha256"],
                    import_run_id="legacy-import-001",
                    actor="importer",
                )
                second = legacy_import.import_legacy_history(
                    root,
                    connection,
                    preview=preview,
                    expected_preview_sha256=preview["preview_sha256"],
                    import_run_id="legacy-import-001",
                    actor="importer",
                )

                self.assertEqual(first, second)
                self.assertEqual(first["state"], "COMPLETE")
                self.assertEqual(source.read_bytes(), before)
                self.assertEqual(
                    connection.execute(
                        "SELECT generation, manifest_sha256, import_run_id "
                        "FROM legacy_import_head WHERE id = 1"
                    ).fetchone(),
                    (1, preview["manifest_sha256"], "legacy-import-001"),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT normalized_source_path, content_sha256, parse_status "
                        "FROM legacy_imports"
                    ).fetchall(),
                    [
                        (
                            "decisions/approved.yml",
                            hashlib.sha256(before).hexdigest(),
                            "PARSED",
                        )
                    ],
                )
                result = Path(first["result_path"])
                self.assertEqual(result.read_bytes(), legacy_import.result_bytes(first))
                self.assertEqual(result.stat().st_mode & 0o777, 0o600)
                self.assertEqual(result.parent.stat().st_mode & 0o777, 0o700)
            finally:
                connection.close()

    def test_resume_uses_only_stored_prepared_bytes_after_prepare_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            source = decisions / "approved.yml"
            source.write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                )
            )
            before = source.read_bytes()
            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-resume-001",
                requested_by="requester",
            )
            connection = create_v3_connection()

            def crash_after_prepare(phase: str) -> None:
                if phase == "prepared":
                    raise RuntimeError("simulated crash")

            try:
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    legacy_import.import_legacy_history(
                        root,
                        connection,
                        preview=preview,
                        expected_preview_sha256=preview["preview_sha256"],
                        import_run_id="legacy-import-resume-001",
                        actor="importer",
                        checkpoint=crash_after_prepare,
                    )
                row = connection.execute(
                    "SELECT state, result_path FROM legacy_import_runs "
                    "WHERE import_run_id = 'legacy-import-resume-001'"
                ).fetchone()
                self.assertEqual(row[0], "PREPARED")
                self.assertFalse(Path(row[1]).exists())

                completed = legacy_import.resume_legacy_history_import(
                    root,
                    connection,
                    import_run_id="legacy-import-resume-001",
                    resumed_by="resumer",
                )

                self.assertEqual(completed["state"], "COMPLETE")
                self.assertEqual(
                    connection.execute(
                        "SELECT state FROM legacy_import_runs "
                        "WHERE import_run_id = 'legacy-import-resume-001'"
                    ).fetchone(),
                    ("COMPLETE",),
                )
                self.assertEqual(source.read_bytes(), before)
            finally:
                connection.close()

    def test_resume_blocks_prepared_run_when_legacy_source_drifted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            source = decisions / "approved.yml"
            source.write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                )
            )
            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-drift-001",
                requested_by="requester",
            )
            connection = create_v3_connection()

            def crash_after_prepare(phase: str) -> None:
                if phase == "prepared":
                    raise RuntimeError("simulated crash")

            try:
                with self.assertRaises(RuntimeError):
                    legacy_import.import_legacy_history(
                        root,
                        connection,
                        preview=preview,
                        expected_preview_sha256=preview["preview_sha256"],
                        import_run_id="legacy-import-drift-001",
                        actor="importer",
                        checkpoint=crash_after_prepare,
                    )
                source.write_bytes(source.read_bytes().replace(b"operator", b"attacker"))

                with self.assertRaisesRegex(
                    legacy_import.LegacyImportError,
                    "changed",
                ):
                    legacy_import.resume_legacy_history_import(
                        root,
                        connection,
                        import_run_id="legacy-import-drift-001",
                        resumed_by="resumer",
                    )

                self.assertEqual(
                    connection.execute(
                        "SELECT state FROM legacy_import_runs "
                        "WHERE import_run_id = 'legacy-import-drift-001'"
                    ).fetchone(),
                    ("BLOCKED",),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM legacy_import_head").fetchone(),
                    (0,),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM legacy_imports").fetchone(),
                    (0,),
                )
            finally:
                connection.close()

    def test_resume_accepts_only_exact_no_replace_result_after_publish_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            (decisions / "approved.yml").write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                )
            )
            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-published-001",
                requested_by="requester",
            )
            connection = create_v3_connection()

            def crash_after_publish(phase: str) -> None:
                if phase == "result-published":
                    raise RuntimeError("simulated crash")

            try:
                with self.assertRaises(RuntimeError):
                    legacy_import.import_legacy_history(
                        root,
                        connection,
                        preview=preview,
                        expected_preview_sha256=preview["preview_sha256"],
                        import_run_id="legacy-import-published-001",
                        actor="importer",
                        checkpoint=crash_after_publish,
                    )
                row = connection.execute(
                    "SELECT state, result_path, result_sha256 FROM legacy_import_runs "
                    "WHERE import_run_id = 'legacy-import-published-001'"
                ).fetchone()
                self.assertEqual(row[0], "PREPARED")
                self.assertEqual(hashlib.sha256(Path(row[1]).read_bytes()).hexdigest(), row[2])

                completed = legacy_import.resume_legacy_history_import(
                    root,
                    connection,
                    import_run_id="legacy-import-published-001",
                    resumed_by="resumer",
                )

                self.assertEqual(completed["state"], "COMPLETE")
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM legacy_imports").fetchone(),
                    (1,),
                )
            finally:
                connection.close()

    def test_resume_blocks_instead_of_overwriting_a_tampered_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            (decisions / "approved.yml").write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                )
            )
            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-tamper-001",
                requested_by="requester",
            )
            connection = create_v3_connection()

            def crash_after_publish(phase: str) -> None:
                if phase == "result-published":
                    raise RuntimeError("simulated crash")

            try:
                with self.assertRaises(RuntimeError):
                    legacy_import.import_legacy_history(
                        root,
                        connection,
                        preview=preview,
                        expected_preview_sha256=preview["preview_sha256"],
                        import_run_id="legacy-import-tamper-001",
                        actor="importer",
                        checkpoint=crash_after_publish,
                    )
                result_path = Path(
                    connection.execute(
                        "SELECT result_path FROM legacy_import_runs "
                        "WHERE import_run_id = 'legacy-import-tamper-001'"
                    ).fetchone()[0]
                )
                result_path.write_bytes(b"{}\n")

                with self.assertRaisesRegex(
                    legacy_import.LegacyImportError,
                    "readback",
                ):
                    legacy_import.resume_legacy_history_import(
                        root,
                        connection,
                        import_run_id="legacy-import-tamper-001",
                        resumed_by="resumer",
                    )

                self.assertEqual(result_path.read_bytes(), b"{}\n")
                self.assertEqual(
                    connection.execute(
                        "SELECT state FROM legacy_import_runs "
                        "WHERE import_run_id = 'legacy-import-tamper-001'"
                    ).fetchone(),
                    ("BLOCKED",),
                )
            finally:
                connection.close()


class LegacyCurationSourceGuardTests(unittest.TestCase):
    def test_preview_and_import_block_matching_open_curation_batch_path(self):
        def digest(number: int) -> str:
            return "%064x" % number

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inbox = root / "inbox"
            decisions = root / "_registry" / "decisions"
            pending = root / "_registry" / "pending"
            inbox.mkdir(mode=0o700)
            decisions.mkdir(parents=True, mode=0o700)
            pending.mkdir(mode=0o700)
            (inbox / "batch-item.md").write_text("body\n", encoding="utf-8")
            (decisions / "approved.yml").write_bytes(
                decision_bytes(
                    root,
                    decision_id="approved-20260714T071429Z-aaaaaaaa",
                    proposal_id="place-a",
                    decision="approved",
                    source_name="batch-item.md",
                )
            )
            preview = legacy_import.preview_legacy_history_import(
                root,
                preview_id="legacy-preview-curation-source-001",
                requested_by="requester",
            )
            self.assertEqual(len(preview["curation_source_blockers"]), 0)

            connection = create_v3_connection()
            try:
                connection.execute(
                    "INSERT INTO inventory_runs ("
                    "run_id, run_sha256, package_path, manifest_sha256, policy_raw_hash, "
                    "policy_generation, policy_full_hash, policy_writer_control_hash, "
                    "policy_foundation_hash, policy_source_kind, policy_source_run_id, "
                    "policy_guard_epoch, parent_run_id, state"
                    ") VALUES ('run-root', ?, 'runs/root', ?, ?, 1, ?, ?, ?, 'INITIAL', "
                    "'policy-run', 0, NULL, 'OPENED')",
                    tuple(digest(value) for value in range(1, 7)),
                )
                connection.execute(
                    "INSERT INTO campaigns ("
                    "campaign_id, root_run_id, root_run_sha256, status, "
                    "current_snapshot_id, current_snapshot_sha256, review_revision, "
                    "active_integration_id, opened_by, payload_json, campaign_path, "
                    "campaign_sha256"
                    ") VALUES ('campaign-1', 'run-root', ?, 'READY', 'campaign-snapshot', ?, "
                    "1, NULL, 'operator', ?, 'campaigns/campaign-1/campaign.json', ?)",
                    (digest(1), digest(7), b"{}\n", digest(8)),
                )
                connection.execute(
                    "INSERT INTO items VALUES ('00000001-0000-4000-8000-000000000001', "
                    "'run-root', 'REVIEW_READY')"
                )
                connection.execute(
                    "INSERT INTO review_batches VALUES ("
                    "'batch-1', 'campaign-1', ?, 'OPEN', 'snapshot-1', ?, 1, 0)",
                    (digest(9), digest(10)),
                )
                connection.execute(
                    "INSERT INTO batch_memberships VALUES ("
                    "'membership-1', 'batch-1', 'unit-1', "
                    "'00000001-0000-4000-8000-000000000001', "
                    "'inbox/batch-item.md', 'OPEN')"
                )
                blockers = legacy_import.curation_source_blockers(
                    root,
                    preview["entries"],
                    connection=connection,
                )
                self.assertEqual(len(blockers), 1)
                self.assertEqual(blockers[0]["kind"], "open-curation-batch-path")

                with self.assertRaisesRegex(
                    legacy_import.LegacyImportError,
                    "curation source conflicts",
                ):
                    legacy_import.import_legacy_history(
                        root,
                        connection,
                        preview=preview,
                        expected_preview_sha256=preview["preview_sha256"],
                        import_run_id="legacy-import-curation-source-001",
                        actor="importer",
                    )
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
