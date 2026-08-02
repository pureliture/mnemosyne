import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path

from mnemosyne_core import raw_memory_query


def _fingerprint(root: Path):
    return {
        path.relative_to(root).as_posix(): (
            stat.S_IMODE(path.stat().st_mode),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _owner_only(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    return directory


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def _history(
    *,
    created_at: str | None,
    body: str,
    source_refs: tuple[str, ...] = ("source: fixture",),
    summary: str | None = None,
    workstream: str | None = None,
) -> str:
    lines = ["---", "schema_version: 1", "event_type: snapshot-update"]
    if created_at is not None:
        lines.append(f"created_at: {created_at}")
    if summary is not None:
        lines.append(f"summary: {summary}")
    if workstream is not None:
        lines.append(f"workstream: {workstream}")
    lines.append("source_refs:")
    lines.extend(f"- {source}" for source in source_refs)
    return "\n".join((*lines, "---", "", body, ""))


class RawMemoryQueryTest(unittest.TestCase):
    def make_raw(self, temporary: Path, workspaces: dict[str, str]) -> Path:
        raw = _owner_only(temporary / "raw")
        memory = _owner_only(raw / "memory")
        registry = ["workspaces:"]
        for name, root in workspaces.items():
            registry.extend((f"  {name}:", f"    root: {root}"))
        _write(memory / "workspaces.yml", "\n".join((*registry, "")))
        for name in workspaces:
            workspace = _owner_only(memory / name)
            _owner_only(workspace / "history")
        return raw

    def test_collect_inclusive_range_expands_bullets_dedupes_only_identical_and_never_mutates(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            raw = self.make_raw(temporary, {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            _write(
                history / "20260801-items.md",
                _history(
                    created_at="2026-08-01T09:00:00Z",
                    body=(
                        "# Sync\n\n## 최신 상태에 반영한 내용\n\n"
                        "- 첫 작업\n- 둘째 작업\n- 첫 작업\n\n"
                        "## 이번 기록에 포함하지 않은 내용\n\n- 제외 작업\n"
                    ),
                    source_refs=("jira: ABC-1", "session: alpha"),
                    workstream="billing",
                ),
            )
            _write(
                history / "20260802-summary.md",
                _history(
                    created_at="2026-08-02T09:00:00Z",
                    body="# Legacy\n\n본문이 비어 있습니다.\n",
                    summary="레거시 요약 작업",
                ),
            )
            _write(
                history / "20260731-outside.md",
                _history(
                    created_at="2026-07-31T23:59:59Z", body="- 범위 밖"
                ),
            )
            before = _fingerprint(raw)

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-08-01", end_date="2026-08-02"
            )

            self.assertEqual(result.status, "found")
            self.assertEqual([item.item for item in result.items], ["첫 작업", "둘째 작업", "레거시 요약 작업"])
            self.assertEqual(result.items[0].source_refs, ("jira: ABC-1", "session: alpha"))
            self.assertEqual(result.items[0].history_path, "memory/alpha/history/20260801-items.md")
            self.assertEqual(result.items[0].workstream, "billing")
            self.assertEqual(before, _fingerprint(raw))

    def test_collect_reports_malformed_history_without_failing_other_records(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            raw = self.make_raw(Path(temporary_directory), {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            _write(
                history / "good.md",
                _history(
                    created_at="2026-08-02T00:00:00Z",
                    body="## 기록으로 남긴 내용\n\n- 정상\n",
                ),
            )
            _write(history / "bad.md", "not frontmatter\n")

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-08-02", end_date="2026-08-02"
            )

            self.assertEqual([item.item for item in result.items], ["정상"])
            self.assertTrue(any(issue.path.endswith("bad.md") for issue in result.issues))

    def test_collect_prioritizes_in_range_filename_records_before_history_cap(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            raw = self.make_raw(Path(temporary_directory), {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            for index in range(512):
                _write(
                    history / f"20200101T000000Z-old-{index:03d}.md",
                    _history(created_at="2020-01-01T00:00:00Z", body="범위 밖"),
                )
            _write(
                history / "20260802T000000Z-target.md",
                _history(
                    created_at="2026-08-02T00:00:00Z",
                    body="## 기록으로 남긴 내용\n\n- 범위 안 작업\n",
                ),
            )

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-08-02", end_date="2026-08-02"
            )

            self.assertEqual(result.status, "found")
            self.assertEqual([item.item for item in result.items], ["범위 안 작업"])
            self.assertTrue(
                any(
                    issue.kind == "truncated"
                    and issue.path == "memory/alpha/history"
                    for issue in result.issues
                )
            )

    def test_collect_does_not_report_not_found_when_history_cap_leaves_undated_records_unread(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            raw = self.make_raw(Path(temporary_directory), {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            for index in range(512):
                _write(
                    history / f"old-{index:03d}.md",
                    _history(created_at="2020-01-01T00:00:00Z", body="범위 밖"),
                )
            _write(
                history / "target.md",
                _history(
                    created_at="2026-08-02T00:00:00Z",
                    body="## 기록으로 남긴 내용\n\n- 읽지 못한 범위 안 작업\n",
                ),
            )

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-08-02", end_date="2026-08-02"
            )

            self.assertEqual(result.status, "unavailable")
            self.assertFalse(result.items)
            self.assertTrue(
                any(
                    issue.kind == "truncated"
                    and "matching records may be unread" in issue.detail
                    for issue in result.issues
                )
            )

    def test_lookup_uses_normalized_exact_root_and_ranks_history_by_question_and_task_context(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            project = temporary / "project"
            project.mkdir()
            raw = self.make_raw(temporary, {"alpha": str(project / ".." / "project")})
            workspace = raw / "memory" / "alpha"
            _write(
                workspace / "snapshot.md",
                "---\nupdated_at: 2026-08-02T09:00:00Z\n---\n# Snapshot\n\n현재 맥락\n",
            )
            history = workspace / "history"
            _write(
                history / "generic.md",
                _history(created_at="2026-08-01T00:00:00Z", body="- 일반 작업"),
            )
            _write(
                history / "target.md",
                _history(created_at="2026-08-02T00:00:00Z", body="- 결제 API 계약 변경"),
            )
            before = _fingerprint(raw)

            result = raw_memory_query.lookup_project_context(
                raw,
                project_root=project,
                question="결제 API는 어떻게 바뀌었나?",
                task_context="API 계약 확인",
            )

            self.assertEqual(result.status, "found")
            self.assertEqual(result.workspace, "alpha")
            self.assertEqual(result.snapshot_path, "memory/alpha/snapshot.md")
            self.assertIn("현재 맥락", result.snapshot_excerpt or "")
            self.assertEqual(result.history[0].history_path, "memory/alpha/history/target.md")
            self.assertGreater(result.history[0].relevance, result.history[1].relevance)
            self.assertEqual(before, _fingerprint(raw))

    def test_lookup_prefers_newest_when_relevance_ties_and_keeps_excerpts_within_bound(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            project = temporary / "project"
            project.mkdir()
            raw = self.make_raw(temporary, {"alpha": str(project)})
            workspace = raw / "memory" / "alpha"
            _write(workspace / "snapshot.md", "---\nupdated_at: 2026-08-02T09:00:00Z\n---\n" + "가" * 40)
            history = workspace / "history"
            _write(history / "old.md", _history(created_at="2026-08-01T00:00:00Z", body="동일"))
            _write(history / "new.md", _history(created_at="2026-08-02T00:00:00Z", body="동일"))

            result = raw_memory_query.lookup_project_context(
                raw,
                project_root=project,
                snapshot_char_limit=10,
                history_excerpt_char_limit=5,
            )

            self.assertEqual(result.history[0].history_path, "memory/alpha/history/new.md")
            self.assertLessEqual(len(result.snapshot_excerpt or ""), 10)
            self.assertLessEqual(len(result.history[0].excerpt), 5)

    def test_lookup_history_cap_keeps_newest_records_available_for_relevance_ranking(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            project = temporary / "project"
            project.mkdir()
            raw = self.make_raw(temporary, {"alpha": str(project)})
            history = raw / "memory" / "alpha" / "history"
            for index in range(512):
                _write(
                    history / f"20260801T000000Z-old-{index:03d}.md",
                    _history(created_at="2026-08-01T00:00:00Z", body="일반 기록"),
                )
            _write(
                history / "20260802T000000Z-target.md",
                _history(created_at="2026-08-02T00:00:00Z", body="특정 최신 맥락"),
            )

            result = raw_memory_query.lookup_project_context(
                raw, project_root=project, question="특정 최신 맥락", history_limit=1
            )

            self.assertEqual(result.status, "found")
            self.assertEqual(
                result.history[0].history_path,
                "memory/alpha/history/20260802T000000Z-target.md",
            )
            self.assertTrue(any(issue.kind == "truncated" for issue in result.issues))

    def test_collect_reads_legacy_source_workstream_timestamp_and_filename_forms(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            raw = self.make_raw(Path(temporary_directory), {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            _write(
                history / "2026-06-25T05-29-30Z-legacy.md",
                "\n".join(
                    (
                        "- Workspace: alpha",
                        "- Workstream: legacy-stream",
                        "- Updated at: 2026-06-25T05-29:30Z",
                        "- Source refs: branch: release",
                        "",
                        "## Summary",
                        "",
                        "레거시 요약 작업",
                        "",
                    )
                ),
            )
            _write(
                history / "20260625T083000Z-workstream-id.md",
                "---\nworkstream_id: id-stream\nrecorded_at: 2026-06-25T08:30:00Z\nsource_refs:\n  branch: main\n---\n\n## Summary\n\n아이디 작업\n",
            )
            _write(
                history / "20260625T093000+0900-workstream-map.md",
                "---\nworkstream:\n  id: mapped-stream\n  status: active\nevent_time: 2026-06-25T09:30:00+09:00\nsource_refs:\n  - type: branch\n    ref: feature/query\n---\n\n## Summary\n\n매핑 작업\n",
            )
            _write(
                history / "20260625T103000Z-filename-only.md",
                "## Summary\n\n파일명 시각 작업\n",
            )

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-06-25", end_date="2026-06-25"
            )

            self.assertEqual(result.status, "found")
            self.assertEqual(
                [item.item for item in result.items],
                ["레거시 요약 작업", "아이디 작업", "매핑 작업", "파일명 시각 작업"],
            )
            self.assertEqual(
                [item.workstream for item in result.items],
                ["legacy-stream", "id-stream", "mapped-stream", "alpha"],
            )
            self.assertEqual(result.items[0].recorded_at, "2026-06-25T05:29:30Z")
            self.assertEqual(result.items[0].source_refs, ("branch: release",))
            self.assertEqual(result.items[1].source_refs, ("branch: main",))
            self.assertEqual(result.items[2].source_refs, ("branch: feature/query",))
            self.assertEqual(result.items[3].recorded_at, "2026-06-25T10:30:00Z")
            self.assertFalse(result.issues)

    def test_collect_skips_out_of_range_malformed_legacy_files_before_parsing(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            raw = self.make_raw(Path(temporary_directory), {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            _write(history / "20260720T000000Z-broken.md", "\xff")
            _write(
                history / "20260721T000000Z-good.md",
                "## Summary\n\n범위 안 작업\n",
            )

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-07-21", end_date="2026-07-21"
            )

            self.assertEqual([item.item for item in result.items], ["범위 안 작업"])
            self.assertFalse(result.issues)

    def test_collect_uses_created_at_instead_of_filename_date(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            raw = self.make_raw(Path(temporary_directory), {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            _write(
                history / "20260720T235959Z-recorded-next-day.md",
                _history(
                    created_at="2026-07-21T00:00:01Z",
                    body="## Summary\n\n기록 시각 기준 작업",
                ),
            )

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-07-21", end_date="2026-07-21"
            )

            self.assertEqual([item.item for item in result.items], ["기록 시각 기준 작업"])

    def test_collect_rejects_invalid_full_recorded_timestamp(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            raw = self.make_raw(Path(temporary_directory), {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            _write(
                history / "20260802T000000Z-invalid-time.md",
                _history(
                    created_at="2026-08-02-not-a-time",
                    body="## Summary\n\n잘못된 시각 작업",
                ),
            )

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-08-02", end_date="2026-08-02"
            )

            self.assertEqual(result.status, "not_found")
            self.assertFalse(result.items)
            self.assertTrue(
                any(issue.detail == "recorded timestamp is invalid" for issue in result.issues)
            )

    def test_query_caps_malformed_issues_deterministically(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            raw = self.make_raw(Path(temporary_directory), {"alpha": "/projects/alpha"})
            history = raw / "memory" / "alpha" / "history"
            for index in range(40):
                path = history / f"broken-{index:02d}.md"
                path.write_bytes(b"\xff")
                path.chmod(0o600)

            result = raw_memory_query.collect_sync_history(
                raw, start_date="2026-07-21", end_date="2026-07-21"
            )

            self.assertEqual(len(result.issues), 33)
            self.assertEqual(result.issues[-1].kind, "truncated")
            self.assertEqual(result.issues[-1].detail, "additional issues omitted")

    def test_lookup_reads_snapshot_above_old_bound_but_below_two_mebibytes(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            project = temporary / "project"
            project.mkdir()
            raw = self.make_raw(temporary, {"alpha": str(project)})
            _write(
                raw / "memory" / "alpha" / "snapshot.md",
                "---\nupdated_at: 2026-08-02T09:00:00Z\n---\n" + "가" * (130 * 1024),
            )

            result = raw_memory_query.lookup_project_context(
                raw, project_root=project, snapshot_char_limit=100
            )

            self.assertEqual(raw_memory_query._MAX_SNAPSHOT_BYTES, 2 * 1024 * 1024)
            self.assertEqual(result.status, "found")
            self.assertLessEqual(len(result.snapshot_excerpt or ""), 100)

    def test_lookup_returns_not_found_ambiguous_and_unavailable_outcomes(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            project = temporary / "project"
            project.mkdir()
            raw = self.make_raw(temporary, {"alpha": str(project)})

            no_match = raw_memory_query.lookup_project_context(
                raw, project_root=temporary / "other"
            )
            self.assertEqual(no_match.status, "not_found")

            registry = raw / "memory" / "workspaces.yml"
            _write(
                registry,
                "workspaces:\n  alpha:\n    root: %s\n  beta:\n    root: %s\n"
                % (project, project),
            )
            _owner_only(raw / "memory" / "beta")
            _owner_only(raw / "memory" / "beta" / "history")
            ambiguous = raw_memory_query.lookup_project_context(raw, project_root=project)
            self.assertEqual(ambiguous.status, "ambiguous")
            self.assertEqual(ambiguous.candidates, ("alpha", "beta"))

            unavailable = raw_memory_query.lookup_project_context(
                temporary / "missing-raw", project_root=project
            )
            self.assertEqual(unavailable.status, "unavailable")

    def test_lookup_accepts_actual_registry_metadata_and_fails_closed_without_root(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            project = temporary / "project"
            project.mkdir()
            raw = self.make_raw(temporary, {"alpha": str(project)})
            _write(
                raw / "memory" / "alpha" / "snapshot.md",
                "---\nupdated_at: 2026-08-02T09:00:00Z\n---\n# Alpha\n",
            )
            _write(
                raw / "memory" / "workspaces.yml",
                "\n".join(
                    (
                        "# Human-maintained workspace registry",
                        "workspaces:",
                        "  alpha:",
                        f"    root: {project}",
                        "    confirmed_at: 2026-06-23T00:00:00Z",
                        "    comment: confirmed project root",
                        "    confirmation:",
                        "      status: confirmed",
                        "      source: manual review",
                        "",
                    )
                ),
            )

            found = raw_memory_query.lookup_project_context(raw, project_root=project)
            self.assertEqual(found.status, "found")
            self.assertEqual(found.workspace, "alpha")

            _write(raw / "memory" / "workspaces.yml", "workspaces:\n  alpha:\n    confirmed_at: 2026-06-23T00:00:00Z\n")
            malformed = raw_memory_query.lookup_project_context(raw, project_root=project)
            self.assertEqual(malformed.status, "unavailable")
            self.assertTrue(any(issue.kind == "malformed" for issue in malformed.issues))

            _write(
                raw / "memory" / "workspaces.yml",
                f"workspaces:\n  ../escape:\n    root: {project}\n",
            )
            unsafe_slug = raw_memory_query.lookup_project_context(raw, project_root=project)
            self.assertEqual(unsafe_slug.status, "unavailable")
            self.assertTrue(
                any("invalid workspace" in issue.detail for issue in unsafe_slug.issues)
            )

    def test_lookup_treats_invalid_registry_root_as_unavailable_but_rejects_invalid_caller_root(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            project = temporary / "project"
            project.mkdir()
            raw = self.make_raw(temporary, {"alpha": str(project)})
            registry = raw / "memory" / "workspaces.yml"
            _write(registry, "workspaces:\n  alpha:\n    root: invalid\x00root\n")

            malformed = raw_memory_query.lookup_project_context(raw, project_root=project)

            self.assertEqual(malformed.status, "unavailable")
            self.assertTrue(
                any(
                    issue.kind == "malformed" and issue.path == "memory/workspaces.yml"
                    for issue in malformed.issues
                )
            )

            _write(registry, f"workspaces:\n  alpha:\n    root: {project}\n")
            with self.assertRaisesRegex(raw_memory_query.RawMemoryQueryError, "project root is invalid"):
                raw_memory_query.lookup_project_context(raw, project_root="invalid\x00root")
            with self.assertRaisesRegex(raw_memory_query.RawMemoryQueryError, "project root is invalid"):
                raw_memory_query.lookup_project_context(
                    temporary / "missing-raw", project_root="invalid\x00root"
                )

    def test_lookup_is_unavailable_when_neither_snapshot_nor_history_can_be_read(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary_directory:
            temporary = Path(temporary_directory)
            project = temporary / "project"
            project.mkdir()
            raw = self.make_raw(temporary, {"alpha": str(project)})
            empty = raw_memory_query.lookup_project_context(raw, project_root=project)
            self.assertEqual(empty.status, "unavailable")

            history = raw / "memory" / "alpha" / "history"
            history.rmdir()
            _write(history, "not a directory")

            result = raw_memory_query.lookup_project_context(raw, project_root=project)

            self.assertEqual(result.status, "unavailable")
            self.assertTrue(any(issue.kind == "unavailable" for issue in result.issues))


if __name__ == "__main__":
    unittest.main()
