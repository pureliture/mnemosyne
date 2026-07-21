import importlib.util
import hashlib
import json
import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest import mock

from mnemosyne_core import canonical_curation, context_assembly, policy


def _empty_complete_assembly():
    return context_assembly.ContextAssembly(
        workstream=context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=(),
            memory_workspace=None,
        ),
        root_identity=(1, 2, 448, 501),
        project_identity=(1, 3, 448, 501),
        policy_sha256="a" * 64,
        outcome="COMPLETE",
        bounds=context_assembly.ContextAssemblyBounds(),
        sources=(),
        claims=(),
        gaps=(),
        coverage=context_assembly.ContextCoverage(
            local_inspected=0,
            local_excluded=0,
            local_unreadable=0,
            local_truncated=0,
            source_group_counts=(),
            memory_status="NOT_CONFIGURED",
            memory_history_inspected=0,
            memory_history_included=0,
            memory_history_excluded=0,
            memory_history_malformed=0,
            memory_history_truncated=0,
            external_verified=0,
            external_unverified=0,
            excluded_paths=(),
            gap_paths=(),
            redaction_counts=(),
        ),
    )


def _require_complete(assembly, **overrides):
    expected = {
        "expected_workstream": assembly.workstream,
        "expected_policy_sha256": assembly.policy_sha256,
        "expected_root_identity": assembly.root_identity,
        "expected_project_identity": assembly.project_identity,
        "expected_assembly_sha256": assembly.sha256,
        "expected_coverage_sha256": assembly.coverage_sha256,
    }
    expected.update(overrides)
    return assembly.require_complete(**expected)


def _source_observation(root, source_path):
    raw = source_path.read_bytes()
    info = source_path.stat()
    relative_path = source_path.relative_to(root).as_posix()
    return canonical_curation.SourceObservation(
        observation_id="obs-" + hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:24],
        relative_path=relative_path,
        owner_kind="workstream",
        owner_id="alpha",
        lifecycle="active",
        document_role="work_results",
        classification="EXACT",
        classification_evidence=("independent-test-observation",),
        content_summary="Release decision",
        device=info.st_dev,
        inode=info.st_ino,
        owner=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
        link_count=info.st_nlink,
        size=info.st_size,
        modified_time_ns=info.st_mtime_ns,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        snapshot_sha256="c" * 64,
    )


def _directory_identity(path):
    info = path.stat()
    return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid


def _regular_file_hashes(root):
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


class ContextAssemblyPublicSeamTest(unittest.TestCase):
    def test_context_assembly_module_is_importable(self):
        self.assertIsNotNone(
            importlib.util.find_spec("mnemosyne_core.context_assembly")
        )

    def test_outcome_priority_is_unsafe_then_stale_then_gap_then_complete(self):
        decide = getattr(context_assembly, "decide_outcome", None)
        self.assertTrue(callable(decide))
        self.assertEqual(
            decide(unsafe_reason_codes=("ROOT_UNSAFE",), stale_reason_codes=("DRIFT",), gaps=("MISSING",)),
            "BLOCKED_UNSAFE",
        )
        self.assertEqual(
            decide(unsafe_reason_codes=(), stale_reason_codes=("DRIFT",), gaps=("MISSING",)),
            "STALE",
        )
        self.assertEqual(
            decide(unsafe_reason_codes=(), stale_reason_codes=(), gaps=("MISSING",)),
            "INCOMPLETE",
        )
        self.assertEqual(
            decide(unsafe_reason_codes=(), stale_reason_codes=(), gaps=()),
            "COMPLETE",
        )


class ContextAssemblyLocalReaderTest(unittest.TestCase):
    def test_current_local_reader_uses_exact_utf8_safe_75_25_excerpt(self):
        raw_text = "# T\n가나다라마바사\nmiddle-middle-middle\nTAIL\n"
        expected_excerpt = "# T\n가\n[... CONTENT OMITTED ...]\nAIL\n"
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            source_path = root / "projects" / "alpha" / "unicode.md"
            source_path.parent.mkdir(parents=True, mode=0o700)
            source_path.write_text(raw_text, encoding="utf-8")
            source_path.chmod(0o600)

            source = context_assembly.read_current_local_source(
                root,
                _source_observation(root, source_path),
                group="OTHER_NESTED",
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    local_excerpt_bytes=40,
                ),
            )

        projection = source.content_projection
        self.assertEqual(projection.excerpt, expected_excerpt)
        self.assertLessEqual(len(projection.excerpt.encode("utf-8")), 40)
        self.assertTrue(projection.excerpt_truncated)

    def test_current_local_reader_lexically_redacts_all_v1_local_patterns(self):
        token_fixtures = (
            "sk-" + "abcdefgh",
            "ghp_" + "abcdefgh",
            "github_pat_" + "abcdefgh",
            "xoxa-" + "abcdefgh",
            "xoxb-" + "abcdefgh",
            "xoxp-" + "abcdefgh",
            "xoxr-" + "abcdefgh",
            "xoxs-" + "abcdefgh",
            "AKIA" + "ABCDEFGHIJKLMNOP",
            "AIza" + "ABCDEFGHIJKLMNOPQRST",
        )
        raw = (
            "# https://example.test/title\n"
            "## Reach alice@example.test\n"
            'TOKEN: "plain-secret"\n'
            "password = unquoted-secret\n"
            "user_id: person-1\n"
            'ACCOUNT_ID = "acct-2"\n'
            "customer_id: customer-3\n"
            "employee_id = employee-4\n"
            "api_key: primary-api-key\n"
            "  implicit-continuation-secret\n"
            "after-implicit-continuation\n"
            "credential: |\n"
            "  first-continuation-secret\n"
            "  second-continuation-secret\n"
            "after-block\n"
            "secret: >\n"
            "  folded-secret\n"
            "outside\n"
            'token: "unterminated\n'
            "Authorization: Bearer header-secret\n"
            "Proxy-Authorization: proxy-secret\n"
            "bare Bearer body-secret\n"
            "[issue](https://jira.example.test/browse/PROJ-1)\n"
            "<https://confluence.example.test/display/space/page>\n"
            "https://foundry.example.test/data/dataset\n"
            "https://ordinary.example.test/path?query=1\n"
            "https://localhost:8443/admin\n"
            "tokens "
            + " ".join(token_fixtures)
            + "\n"
            + "A" * 80
            + "\n"
        )
        expected_excerpt = (
            "# [EXTERNAL:url:d8e1ef0ccf6ec5e91fd4ab7b6c6742b3dff797a6eb5d42e98ce429f3ce4bdba1]\n"
            "## Reach [REDACTED_EMAIL]\n"
            "TOKEN: [REDACTED_SECRET]\n"
            "password = [REDACTED_SECRET]\n"
            "user_id: [REDACTED_PERSONAL_ID]\n"
            "ACCOUNT_ID = [REDACTED_PERSONAL_ID]\n"
            "customer_id: [REDACTED_PERSONAL_ID]\n"
            "employee_id = [REDACTED_PERSONAL_ID]\n"
            "api_key: [REDACTED_SECRET]\n"
            "  [REDACTED_SECRET]\n"
            "after-implicit-continuation\n"
            "credential: [REDACTED_SECRET]\n"
            "  [REDACTED_SECRET]\n"
            "  [REDACTED_SECRET]\n"
            "after-block\n"
            "secret: [REDACTED_SECRET]\n"
            "  [REDACTED_SECRET]\n"
            "outside\n"
            "[REDACTED_AMBIGUOUS]\n"
            "Authorization: [REDACTED_SECRET]\n"
            "Proxy-Authorization: [REDACTED_SECRET]\n"
            "bare Bearer [REDACTED_SECRET]\n"
            "[issue]([EXTERNAL:jira:a995100118c5068d98ef4aaa6303242b03b435762506a80e633ba3d61b0e3813])\n"
            "<[EXTERNAL:confluence:450097ba00b57a84672007d903db9f954457028b07a8d48d2bb2c109e49d59a7]>\n"
            "[EXTERNAL:foundry:c68600b3b30309b45d069c0cf451796a86449ffe001d5f5da57e7bb032dcfbc4]\n"
            "[EXTERNAL:url:139b526228f149d520e140f57912698835a08e85c5cd4c84a750aca09b11c76a]\n"
            "[EXTERNAL:unknown:574a024299e1307685d9b44418395685a3bd3182cffbba1a0a8de4ca665f914a]\n"
            "tokens [REDACTED_SECRET] [REDACTED_SECRET] [REDACTED_SECRET] "
            "[REDACTED_SECRET] [REDACTED_SECRET] [REDACTED_SECRET] "
            "[REDACTED_SECRET] [REDACTED_SECRET] [REDACTED_SECRET] "
            "[REDACTED_SECRET]\n"
            "[REDACTED_SECRET]\n"
        )
        raw_sensitive_spans = (
            "alice@example.test",
            "plain-secret",
            "unquoted-secret",
            "person-1",
            "acct-2",
            "customer-3",
            "employee-4",
            "primary-api-key",
            "implicit-continuation-secret",
            "first-continuation-secret",
            "folded-secret",
            "unterminated",
            "header-secret",
            "proxy-secret",
            "body-secret",
            "https://jira.example.test/browse/PROJ-1",
            *token_fixtures,
            "A" * 80,
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            source_path = root / "projects" / "alpha" / "redaction.md"
            source_path.parent.mkdir(parents=True, mode=0o700)
            source_path.write_text(raw, encoding="utf-8")
            source_path.chmod(0o600)
            source = context_assembly.read_current_local_source(
                root,
                _source_observation(root, source_path),
                group="OTHER_NESTED",
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        projection = source.content_projection
        self.assertIsNotNone(projection)
        self.assertEqual(projection.excerpt, expected_excerpt)
        self.assertEqual(
            projection.redaction_counts,
            (
                ("ambiguous", 1),
                ("email", 1),
                ("external", 6),
                ("personal_id", 4),
                ("secret", 19),
            ),
        )
        self.assertEqual(
            projection.title,
            "[EXTERNAL:url:d8e1ef0ccf6ec5e91fd4ab7b6c6742b3dff797a6eb5d42e98ce429f3ce4bdba1]",
        )
        self.assertEqual(projection.headings, ("Reach [REDACTED_EMAIL]",))
        for raw_sensitive_span in raw_sensitive_spans:
            with self.subTest(raw_sensitive_span=raw_sensitive_span):
                self.assertNotIn(raw_sensitive_span, projection.excerpt)
                self.assertNotIn(raw_sensitive_span, projection.title)
                self.assertNotIn(raw_sensitive_span, projection.headings)

    def test_current_local_reader_redacts_complete_and_unterminated_pem_blocks(self):
        private_key_begin = "-----BEGIN " + "PRIVATE KEY-----"
        private_key_end = "-----END " + "PRIVATE KEY-----"
        rsa_private_key_begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
        raw = (
            "# PEM fixture\n"
            + private_key_begin
            + "\n"
            + "complete-private-key-material\n"
            + private_key_end
            + "\n"
            + "Visible line\n"
            + rsa_private_key_begin
            + "\n"
            + "unterminated-private-key-material\n"
        )
        expected_excerpt = (
            "# PEM fixture\n"
            "[REDACTED_SECRET]\n"
            "Visible line\n"
            "[REDACTED_SECRET]\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            source_path = root / "projects" / "alpha" / "pem.md"
            source_path.parent.mkdir(parents=True, mode=0o700)
            source_path.write_text(raw, encoding="utf-8")
            source_path.chmod(0o600)
            source = context_assembly.read_current_local_source(
                root,
                _source_observation(root, source_path),
                group="OTHER_NESTED",
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        projection = source.content_projection
        self.assertIsNotNone(projection)
        self.assertEqual(projection.excerpt, expected_excerpt)
        self.assertEqual(projection.redaction_counts, (("secret", 2),))
        self.assertNotIn("complete-private-key-material", projection.excerpt)
        self.assertNotIn("unterminated-private-key-material", projection.excerpt)

    def test_current_local_reader_binds_actual_bytes_and_redacts_before_projection(self):
        raw = (
            b"# Release decision\n"
            b"## Scope\n"
            b'token: "do-not-persist"\n'
            b"Contact: alice@example.test\n"
            b"Current local evidence.\n"
        )
        expected_excerpt = (
            "# Release decision\n"
            "## Scope\n"
            "token: [REDACTED_SECRET]\n"
            "Contact: [REDACTED_EMAIL]\n"
            "Current local evidence.\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            source_path = root / "projects" / "alpha" / "notes.md"
            source_path.parent.mkdir(parents=True, mode=0o700)
            source_path.write_bytes(raw)
            source_path.chmod(0o600)
            info = source_path.stat()
            observation = _source_observation(root, source_path)

            source = context_assembly.read_current_local_source(
                root,
                observation,
                group="OTHER_NESTED",
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        projection = source.content_projection
        self.assertIsNotNone(projection)
        self.assertEqual(source.source_id, observation.observation_id)
        self.assertEqual(source.identity, (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
        ))
        self.assertEqual(projection.title, "Release decision")
        self.assertEqual(projection.headings, ("Scope",))
        self.assertEqual(projection.excerpt, expected_excerpt)
        self.assertFalse(projection.headings_truncated)
        self.assertFalse(projection.excerpt_truncated)
        self.assertEqual(
            projection.redaction_counts,
            (("email", 1), ("secret", 1)),
        )
        self.assertEqual(projection.full_content_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(projection.full_content_byte_count, len(raw))
        self.assertNotIn("do-not-persist", projection.excerpt)
        self.assertNotIn("alice@example.test", projection.excerpt)

    def test_current_local_reader_fails_closed_on_changed_unsafe_or_unreadable_source(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)

            changed = project / "changed.md"
            changed.write_bytes(b"# Before\n")
            changed.chmod(0o600)
            changed_observation = _source_observation(root, changed)
            changed.write_bytes(b"# After!\n")

            oversized = project / "oversized.md"
            oversized.write_bytes(b"# Too large\n")
            oversized.chmod(0o600)
            oversized_observation = _source_observation(root, oversized)

            invalid_utf8 = project / "invalid.md"
            invalid_utf8.write_bytes(b"# Invalid\n\xff\n")
            invalid_utf8.chmod(0o600)
            invalid_observation = _source_observation(root, invalid_utf8)

            target = project / "target.md"
            target.write_bytes(b"# Target\n")
            target.chmod(0o600)
            symlink = project / "link.md"
            symlink.symlink_to(target.name)
            symlink_observation = replace(
                _source_observation(root, target),
                relative_path=symlink.relative_to(root).as_posix(),
            )

            cases = (
                (changed_observation, context_assembly.ContextAssemblyBounds()),
                (
                    oversized_observation,
                    context_assembly.ContextAssemblyBounds(local_source_bytes=4),
                ),
                (invalid_observation, context_assembly.ContextAssemblyBounds()),
                (symlink_observation, context_assembly.ContextAssemblyBounds()),
            )
            for observation, bounds in cases:
                with self.subTest(path=observation.relative_path):
                    with self.assertRaises(context_assembly.ContextAssemblyError):
                        context_assembly.read_current_local_source(
                            root,
                            observation,
                            group="OTHER_NESTED",
                            bounds=bounds,
                        )


class ContextAssemblyMemoryReaderTest(unittest.TestCase):
    def test_memory_reader_ignores_slash_prose_and_anchors_project_relative_hint(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
            b"  Thick/Thin and review/merge are prose, not files.\n"
            b"  path: meetings/july.md\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)

            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        local_paths = {
            hint.relative_path for hint in capture.hints if hint.kind == "LOCAL_PATH"
        }
        self.assertEqual(local_paths, {"projects/alpha/meetings/july.md"})

    def test_memory_reader_accepts_raw_memory_sync_unquoted_rfc3339_timestamps(self):
        snapshot_raw = (
            b"---\n"
            b"schema_version: 1\n"
            b"workspace:\n  slug: raw\n  root: /private/tmp/raw\n"
            b"updated_at: 2026-07-14T04:17:20Z\n"
            b"source_refs:\n  - bounded_summary\n"
            b"---\n"
            b"## Workstreams\n- id: alpha\n  path: projects/alpha/README.md\n"
        )
        history_raw = (
            b"---\n"
            b"schema_version: 1\n"
            b"workspace:\n  slug: raw\n  root: /private/tmp/raw\n"
            b"created_at: 2026-07-14T05:17:20Z\n"
            b"workstream: alpha\n"
            b"source_refs:\n  - bounded_summary\n"
            b"---\n"
            b"path: projects/alpha/notes/current.md\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            entry = history / "2026-07-14T05-17-20Z-alpha.md"
            entry.write_bytes(history_raw)
            entry.chmod(0o600)

            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertIsNotNone(capture.snapshot)
        self.assertEqual(capture.snapshot.recorded_at, "2026-07-14T04:17:20Z")
        self.assertEqual(len(capture.history), 1)
        self.assertEqual(capture.history[0].recorded_at, "2026-07-14T05:17:20Z")
        self.assertEqual(capture.counts.history_malformed, 0)
        self.assertEqual(capture.gaps, ())

    def test_memory_reader_routes_exact_legacy_events_by_membership(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-14T04:17:20Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        legacy_event_raw = (
            b"---\n"
            b"schema_version: 1\n"
            b"workspace:\n  slug: raw\n  root: /private/tmp/raw\n"
            b"event_time: 2026-06-28T08:27:46Z\n"
            b"workstream:\n"
            b"  id: example-service/ubuntu-access-route\n"
            b"  status: active\n"
            b"source_refs:\n  - sanitized_summary\n"
            b"---\n"
            b"# Unrelated legacy event\n"
        )
        matching_event_raw = legacy_event_raw.replace(
            b"example-service/ubuntu-access-route",
            b"alpha",
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            entry = history / "legacy-event.md"
            entry.write_bytes(legacy_event_raw)
            entry.chmod(0o600)
            matching_entry = history / "matching-legacy-event.md"
            matching_entry.write_bytes(matching_event_raw)
            matching_entry.chmod(0o600)

            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(len(capture.history), 1)
        self.assertEqual(capture.history[0].recorded_at, "2026-06-28T08:27:46Z")
        self.assertEqual(capture.counts.history_excluded, 1)
        self.assertEqual(capture.counts.history_malformed, 0)
        self.assertEqual(capture.gaps, ())

    def test_memory_reader_rejects_non_exact_legacy_event_membership(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-14T04:17:20Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        variants = {
            "missing schema": (
                b"event_time: 2026-06-28T08:27:46Z\n"
                b"workstream:\n  id: alpha\n  status: active\n"
            ),
            "wrong schema": (
                b"schema_version: 2\n"
                b"event_time: 2026-06-28T08:27:46Z\n"
                b"workstream:\n  id: alpha\n  status: active\n"
            ),
            "extra membership key": (
                b"schema_version: 1\n"
                b"event_time: 2026-06-28T08:27:46Z\n"
                b"workstream:\n  id: alpha\n  status: active\n  alias: beta\n"
            ),
            "invalid status": (
                b"schema_version: 1\n"
                b"event_time: 2026-06-28T08:27:46Z\n"
                b"workstream:\n  id: alpha\n  status: archived\n"
            ),
            "mixed created at": (
                b"schema_version: 1\n"
                b"event_time: 2026-06-28T08:27:46Z\n"
                b"created_at: 2026-06-28T08:27:46Z\n"
                b"workstream:\n  id: alpha\n  status: active\n"
            ),
            "invalid calendar time": (
                b"schema_version: 1\n"
                b"event_time: 2026-99-99T99:99:99Z\n"
                b"workstream:\n  id: alpha\n  status: active\n"
            ),
            "invalid utc offset": (
                b"schema_version: 1\n"
                b"event_time: 2026-06-28T08:27:46+99:99\n"
                b"workstream:\n  id: alpha\n  status: active\n"
            ),
        }
        for label, membership in variants.items():
            with self.subTest(label=label):
                legacy_event_raw = b"---\n" + membership + b"---\nlegacy\n"
                with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
                    root = Path(temporary).resolve()
                    history = root / "memory" / "raw" / "history"
                    history.mkdir(parents=True, mode=0o700)
                    snapshot = history.parent / "snapshot.md"
                    snapshot.write_bytes(snapshot_raw)
                    snapshot.chmod(0o600)
                    entry = history / "legacy-event.md"
                    entry.write_bytes(legacy_event_raw)
                    entry.chmod(0o600)

                    capture = context_assembly.read_memory_context(
                        root,
                        context_assembly.ContextWorkstream(
                            id="alpha",
                            lifecycle="active",
                            project_home="projects/alpha",
                            aliases=(),
                            memory_workspace="raw",
                        ),
                        bounds=context_assembly.ContextAssemblyBounds(),
                    )

                self.assertEqual(capture.history, ())
                self.assertEqual(capture.counts.history_excluded, 0)
                self.assertEqual(capture.counts.history_malformed, 1)
                self.assertEqual(len(capture.gaps), 1)
                self.assertEqual(
                    capture.gaps[0].reason_code,
                    "HISTORY_MEMBER_MALFORMED",
                )

    def test_memory_reader_normalizes_in_root_absolute_and_lexical_path_hints(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_text(
                "---\n"
                'updated_at: "2026-07-19T10:00:00Z"\n'
                "---\n"
                "## Workstreams\n"
                "- id: alpha\n"
                "  source: %s/projects/alpha/absolute.md\n"
                "  [Meeting](%s/projects/alpha/meetings/july.md)\n"
                "  Research token projects/alpha/docs/research/foundry.md\n"
                "  source: /private/outside/secret.md\n"
                % (root.as_posix(), root.as_posix()),
                encoding="utf-8",
            )
            snapshot.chmod(0o600)

            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(
            tuple(
                sorted(
                    hint.relative_path
                    for hint in capture.hints
                    if hint.kind == "LOCAL_PATH"
                )
            ),
            (
                "projects/alpha/absolute.md",
                "projects/alpha/docs/research/foundry.md",
                "projects/alpha/meetings/july.md",
            ),
        )
        encoded = json.dumps(capture.canonical_value, sort_keys=True).encode("utf-8")
        self.assertNotIn(root.as_posix().encode("utf-8"), encoded)
        self.assertNotIn(b"/private/outside/secret.md", encoded)

    def test_memory_reader_extracts_privacy_safe_hints_from_matching_history_body(self):
        external_target = "https://foundry.example.test/dataset/private-id"
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        history_raw = (
            b"---\nworkstream: alpha\n"
            b'created_at: "2026-07-19T11:00:00Z"\n---\n'
            b"path: projects/alpha/history-note.md\n"
            + ("ref: %s\n" % external_target).encode("utf-8")
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            entry = history / "history.data"
            entry.write_bytes(history_raw)
            entry.chmod(0o600)
            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(
            {hint.kind for hint in capture.hints},
            {"LOCAL_PATH", "EXTERNAL_REFERENCE"},
        )
        self.assertEqual(
            {source_id for hint in capture.hints for source_id in hint.historical_source_ids},
            {capture.history[0].source_id},
        )
        encoded = json.dumps(capture.canonical_value, sort_keys=True).encode("utf-8")
        self.assertNotIn(external_target.encode("utf-8"), encoded)
        self.assertNotIn(b"private-id", encoded)

    def test_memory_reader_rejects_contradictory_history_membership_fields(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        history_raw = (
            b"---\n"
            b"workstream_id: alpha\n"
            b"workstream: beta\n"
            b'created_at: "2026-07-19T11:00:00Z"\n'
            b"---\nbody\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            entry = history / "contradictory.data"
            entry.write_bytes(history_raw)
            entry.chmod(0o600)

            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(capture.history, ())
        self.assertEqual(capture.counts.history_malformed, 1)
        self.assertIn(
            "HISTORY_MEMBER_MALFORMED",
            {gap.reason_code for gap in capture.gaps},
        )

    def test_memory_reader_rejects_noncanonical_history_timestamp(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        history_raw = (
            b"---\n"
            b"workstream: alpha\n"
            b"created_at: 2026-02-30T11:00:00Z\n"
            b"---\nbody\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            entry = history / "invalid-timestamp.data"
            entry.write_bytes(history_raw)
            entry.chmod(0o600)

            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(capture.history, ())
        self.assertEqual(capture.counts.history_malformed, 1)
        self.assertIn(
            "HISTORY_MEMBER_MALFORMED",
            {gap.reason_code for gap in capture.gaps},
        )

    def test_memory_reader_rejects_noncanonical_snapshot_timestamp(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-99-99T99:99:99Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertIsNone(capture.snapshot)
        self.assertIn(
            "SNAPSHOT_UPDATED_AT_INVALID",
            {gap.reason_code for gap in capture.gaps},
        )

    def test_memory_reader_rejects_snapshot_changed_during_capture(self):
        first_snapshot = (
            '---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            "## Workstreams\n- id: alpha\n"
        )
        changed_snapshot = first_snapshot.replace("10:00:00Z", "10:01:00Z")
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_text(first_snapshot, encoding="utf-8")
            snapshot.chmod(0o600)
            original_parser = context_assembly._parse_memory_frontmatter
            parse_count = 0

            def parse_then_mutate(*args, **kwargs):
                nonlocal parse_count
                parsed = original_parser(*args, **kwargs)
                parse_count += 1
                if parse_count == 1:
                    snapshot.write_text(changed_snapshot, encoding="utf-8")
                return parsed

            with mock.patch.object(
                context_assembly,
                "_parse_memory_frontmatter",
                side_effect=parse_then_mutate,
            ):
                with self.assertRaises(context_assembly.ContextAssemblyError) as raised:
                    context_assembly.read_memory_context(
                        root,
                        context_assembly.ContextWorkstream(
                            id="alpha",
                            lifecycle="active",
                            project_home="projects/alpha",
                            aliases=(),
                            memory_workspace="raw",
                        ),
                        bounds=context_assembly.ContextAssemblyBounds(),
                    )

        self.assertEqual(raised.exception.reason_code, "CONTEXT_STALE")

    def test_memory_reader_rejects_history_source_changed_during_capture(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        first_history = (
            '---\nworkstream: alpha\ncreated_at: "2026-07-19T11:00:00Z"\n'
            "---\noriginal\n"
        )
        changed_history = first_history.replace("original", "changed!")
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            history_entry = history / "matching.data"
            history_entry.write_text(first_history, encoding="utf-8")
            history_entry.chmod(0o600)
            original_parser = context_assembly._parse_memory_frontmatter
            parse_count = 0

            def parse_then_mutate(*args, **kwargs):
                nonlocal parse_count
                parsed = original_parser(*args, **kwargs)
                parse_count += 1
                if parse_count == 2:
                    history_entry.write_text(changed_history, encoding="utf-8")
                return parsed

            with mock.patch.object(
                context_assembly,
                "_parse_memory_frontmatter",
                side_effect=parse_then_mutate,
            ):
                with self.assertRaises(context_assembly.ContextAssemblyError) as raised:
                    context_assembly.read_memory_context(
                        root,
                        context_assembly.ContextWorkstream(
                            id="alpha",
                            lifecycle="active",
                            project_home="projects/alpha",
                            aliases=(),
                            memory_workspace="raw",
                        ),
                        bounds=context_assembly.ContextAssemblyBounds(),
                    )

        self.assertEqual(raised.exception.reason_code, "CONTEXT_STALE")

    def test_memory_reader_detects_history_membership_drift_during_capture(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            with mock.patch.object(
                context_assembly.os,
                "listdir",
                side_effect=[[], ["late-entry.md"]],
            ):
                with self.assertRaises(
                    context_assembly.ContextAssemblyError
                ) as raised:
                    context_assembly.read_memory_context(
                        root,
                        context_assembly.ContextWorkstream(
                            id="alpha",
                            lifecycle="active",
                            project_home="projects/alpha",
                            aliases=(),
                            memory_workspace="raw",
                        ),
                        bounds=context_assembly.ContextAssemblyBounds(),
                    )

        self.assertEqual(raised.exception.reason_code, "CONTEXT_STALE")

    def test_memory_reader_bounds_total_history_bytes_and_hint_tokens(self):
        workstream = context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=(),
            memory_workspace="raw",
        )
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
            b"  path: projects/alpha/one.md\n"
            b"  source: projects/alpha/two.md\n"
        )
        history_raw = (
            b"---\nworkstream: alpha\n"
            b'created_at: "2026-07-19T11:00:00Z"\n---\nbody\n'
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            for name in ("01-alpha.bin", "02-alpha.bin"):
                entry = history / name
                entry.write_bytes(history_raw)
                entry.chmod(0o600)
            capture = context_assembly.read_memory_context(
                root,
                workstream,
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    history_total_bytes=len(history_raw) + 1,
                    hint_token_count=1,
                ),
            )

        self.assertEqual(len(capture.hints), 1)
        self.assertEqual(capture.counts.hint_tokens_extracted, 1)
        self.assertEqual(len(capture.history), 1)
        self.assertEqual(capture.counts.history_inspected, 2)
        self.assertEqual(capture.counts.history_truncated, 1)
        self.assertEqual(
            {gap.reason_code for gap in capture.gaps},
            {"HISTORY_TOTAL_LIMIT", "MEMORY_HINT_TOKEN_LIMIT"},
        )

    def test_memory_reader_counts_repeated_hint_tokens_before_deduplication(self):
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
            b"  path: projects/alpha/repeated.md\n"
            b"  path: projects/alpha/repeated.md\n"
            b"  path: projects/alpha/repeated.md\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)

            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    hint_token_count=2,
                ),
            )

        self.assertEqual(len(capture.hints), 1)
        self.assertEqual(capture.counts.snapshot_hint_count, 1)
        self.assertEqual(capture.counts.hint_tokens_extracted, 2)
        self.assertIn(
            "MEMORY_HINT_TOKEN_LIMIT",
            {gap.reason_code for gap in capture.gaps},
        )

    def test_memory_reader_unsafe_type_link_and_mode_matrix_has_no_semantic_capture(self):
        workstream = context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=(),
            memory_workspace="raw",
        )
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        for unsafe_case in (
            "snapshot_symlink",
            "history_symlink",
            "member_symlink",
            "member_directory",
            "member_hardlink",
            "member_group_writable",
        ):
            with self.subTest(unsafe_case=unsafe_case):
                with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
                    root = Path(temporary).resolve()
                    workspace = root / "memory" / "raw"
                    history = workspace / "history"
                    history.mkdir(parents=True, mode=0o700)
                    snapshot = workspace / "snapshot.md"
                    snapshot.write_bytes(snapshot_raw)
                    snapshot.chmod(0o600)
                    if unsafe_case == "snapshot_symlink":
                        snapshot.unlink()
                        target = workspace / "target.md"
                        target.write_bytes(snapshot_raw)
                        target.chmod(0o600)
                        snapshot.symlink_to(target.name)
                    elif unsafe_case == "history_symlink":
                        history.rmdir()
                        target = workspace / "other-history"
                        target.mkdir(mode=0o700)
                        history.symlink_to(target.name)
                    elif unsafe_case == "member_directory":
                        (history / "nested").mkdir(mode=0o700)
                    else:
                        member = history / "member.data"
                        member.write_bytes(b"---\nworkstream: beta\ncreated_at: now\n---\n")
                        member.chmod(0o600)
                        if unsafe_case == "member_symlink":
                            link = history / "link.data"
                            link.symlink_to(member.name)
                        elif unsafe_case == "member_hardlink":
                            os.link(member, history / "hardlink.data")
                        elif unsafe_case == "member_group_writable":
                            member.chmod(0o620)

                    with self.assertRaises(
                        context_assembly.ContextAssemblyError
                    ) as raised:
                        context_assembly.read_memory_context(
                            root,
                            workstream,
                            bounds=context_assembly.ContextAssemblyBounds(),
                        )

                self.assertEqual(raised.exception.reason_code, "CONTEXT_BLOCKED_UNSAFE")

    def test_memory_reader_records_bounds_as_incomplete_without_guessing_hidden_evidence(self):
        workstream = context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=(),
            memory_workspace="raw",
        )
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        history_raw = (
            b"---\nworkstream: alpha\n"
            b'created_at: "2026-07-19T11:00:00Z"\n---\nbody\n'
        )

        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            capture = context_assembly.read_memory_context(
                root,
                workstream,
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    snapshot_bytes=8,
                ),
            )

        self.assertIsNone(capture.snapshot)
        self.assertIn("SNAPSHOT_BYTE_LIMIT", {gap.reason_code for gap in capture.gaps})

        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            for name in ("01-alpha.bin", "02-alpha.bin"):
                entry = history / name
                entry.write_bytes(history_raw)
                entry.chmod(0o600)
            capture = context_assembly.read_memory_context(
                root,
                workstream,
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    history_entry_count=1,
                ),
            )

        self.assertEqual(capture.counts.history_inspected, 1)
        self.assertEqual(capture.counts.history_included, 1)
        self.assertEqual(capture.counts.history_truncated, 1)
        self.assertIn("HISTORY_ENTRY_LIMIT", {gap.reason_code for gap in capture.gaps})

        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            entry = history / "oversized.bin"
            entry.write_bytes(history_raw)
            entry.chmod(0o600)
            capture = context_assembly.read_memory_context(
                root,
                workstream,
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    history_file_bytes=8,
                ),
            )

        self.assertEqual(capture.history, ())
        self.assertEqual(capture.counts.history_inspected, 1)
        self.assertEqual(capture.counts.history_truncated, 1)
        self.assertIn("HISTORY_FILE_LIMIT", {gap.reason_code for gap in capture.gaps})

    def test_memory_reader_hashes_external_hints_and_never_persists_raw_targets(self):
        external_target = "https://jira.example.test/browse/SECRET-123"
        history_target = "https://foundry.example.test/datasets/HIDDEN-456"
        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n"
            b"- id: alpha\n"
            b"  path: projects/alpha/notes.md\n"
            + ("  ref: %s\n" % external_target).encode("utf-8")
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            history_entry = history / "matching.data"
            history_entry.write_text(
                "---\n"
                "workstream: alpha\n"
                'created_at: "2026-07-19T11:00:00Z"\n'
                "---\n"
                "ref: %s\n" % history_target,
                encoding="utf-8",
            )
            history_entry.chmod(0o600)
            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(
            tuple(hint.kind for hint in capture.hints),
            ("EXTERNAL_REFERENCE", "EXTERNAL_REFERENCE", "LOCAL_PATH"),
        )
        external_hint = next(
            hint
            for hint in capture.hints
            if hint.reference_sha256
            == hashlib.sha256(external_target.encode("utf-8")).hexdigest()
        )
        self.assertEqual(external_hint.reference_family, "jira")
        self.assertEqual(
            external_hint.reference_sha256,
            hashlib.sha256(external_target.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(capture.counts.snapshot_hint_count, 2)
        self.assertEqual(capture.counts.hint_tokens_extracted, 3)
        encoded = json.dumps(capture.canonical_value, sort_keys=True).encode("utf-8")
        self.assertNotIn(external_target.encode("utf-8"), encoded)
        self.assertNotIn(b"SECRET-123", encoded)
        self.assertNotIn(history_target.encode("utf-8"), encoded)
        self.assertNotIn(b"HIDDEN-456", encoded)

    def test_memory_reader_distinguishes_unconfigured_and_safe_missing_routes(self):
        bounds = context_assembly.ContextAssemblyBounds()
        local_only = context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=(),
            memory_workspace=None,
        )
        configured = replace(local_only, memory_workspace="raw")
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            unconfigured = context_assembly.read_memory_context(
                root,
                local_only,
                bounds=bounds,
            )
            missing_workspace = context_assembly.read_memory_context(
                root,
                configured,
                bounds=bounds,
            )

        self.assertEqual(unconfigured.status, "NOT_CONFIGURED")
        self.assertIsNone(unconfigured.workspace_identity)
        self.assertEqual(unconfigured.gaps, ())
        self.assertEqual(missing_workspace.status, "CONFIGURED")
        self.assertIsNone(missing_workspace.snapshot)
        self.assertEqual(missing_workspace.history, ())
        self.assertEqual(
            {gap.reason_code for gap in missing_workspace.gaps},
            {"SNAPSHOT_MISSING", "HISTORY_DIRECTORY_MISSING"},
        )

        snapshot_raw = (
            b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            b"## Workstreams\n- id: alpha\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            workspace = root / "memory" / "raw"
            workspace.mkdir(parents=True, mode=0o700)
            snapshot = workspace / "snapshot.md"
            snapshot.write_bytes(snapshot_raw)
            snapshot.chmod(0o600)
            missing_history = context_assembly.read_memory_context(
                root,
                configured,
                bounds=bounds,
            )

        self.assertIsNotNone(missing_history.snapshot)
        self.assertEqual(
            tuple(gap.reason_code for gap in missing_history.gaps),
            ("HISTORY_DIRECTORY_MISSING",),
        )

        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            missing_snapshot = context_assembly.read_memory_context(
                root,
                configured,
                bounds=bounds,
            )

        self.assertIsNone(missing_snapshot.snapshot)
        self.assertEqual(missing_snapshot.history, ())
        self.assertEqual(
            tuple(gap.reason_code for gap in missing_snapshot.gaps),
            ("SNAPSHOT_MISSING",),
        )

    def test_memory_reader_keeps_safe_partial_history_when_snapshot_or_member_is_malformed(self):
        snapshot_cases = (
            (
                b"- id: beta\n  path: projects/beta/notes.md\n",
                "SNAPSHOT_WORKSTREAM_UNMATCHED",
            ),
            (
                b"- id: alpha\n- id: alpha\n",
                "SNAPSHOT_WORKSTREAM_AMBIGUOUS",
            ),
        )
        for snapshot_blocks, snapshot_reason in snapshot_cases:
            with self.subTest(snapshot_reason=snapshot_reason):
                with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
                    root = Path(temporary).resolve()
                    history = root / "memory" / "raw" / "history"
                    history.mkdir(parents=True, mode=0o700)
                    snapshot = history.parent / "snapshot.md"
                    snapshot.write_bytes(
                        b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
                        b"## Workstreams\n"
                        + snapshot_blocks
                    )
                    snapshot.chmod(0o600)
                    matching = history / "matching.bin"
                    matching.write_bytes(
                        b"---\nworkstream: alpha\n"
                        b'created_at: "2026-07-19T11:00:00Z"\n---\nbody\n'
                    )
                    matching.chmod(0o600)
                    malformed = history / "malformed.data"
                    malformed.write_bytes(b"not-frontmatter\n")
                    malformed.chmod(0o600)

                    capture = context_assembly.read_memory_context(
                        root,
                        context_assembly.ContextWorkstream(
                            id="alpha",
                            lifecycle="active",
                            project_home="projects/alpha",
                            aliases=(),
                            memory_workspace="raw",
                        ),
                        bounds=context_assembly.ContextAssemblyBounds(),
                    )

                self.assertIsNone(capture.snapshot)
                self.assertEqual(len(capture.history), 1)
                self.assertEqual(capture.counts.history_inspected, 2)
                self.assertEqual(capture.counts.history_included, 1)
                self.assertEqual(capture.counts.history_malformed, 1)
                self.assertEqual(
                    {gap.reason_code for gap in capture.gaps},
                    {snapshot_reason, "HISTORY_MEMBER_MALFORMED"},
                )

    def test_memory_reader_selects_exact_snapshot_and_suffix_independent_history(self):
        snapshot_raw = (
            b"---\n"
            b'updated_at: "2026-07-19T10:00:00Z"\n'
            b"---\n"
            b"## Workstreams\n"
            b"- id: alpha\n"
            b"  path: projects/alpha/notes.md\n"
            b"- id: beta\n"
            b"  path: projects/beta/notes.md\n"
        )
        matching_history = (
            b"---\n"
            b"workstream_id: alpha\n"
            b'created_at: "2026-07-19T11:00:00Z"\n'
            b"---\n"
            b"historical only\n"
        )
        excluded_history = (
            b"---\n"
            b"workstream: beta\n"
            b'created_at: "2026-07-19T12:00:00Z"\n'
            b"---\n"
            b"excluded body\n"
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            workspace = root / "memory" / "raw"
            history = workspace / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot_path = workspace / "snapshot.md"
            snapshot_path.write_bytes(snapshot_raw)
            snapshot_path.chmod(0o600)
            matching_path = history / "01-alpha.bin"
            matching_path.write_bytes(matching_history)
            matching_path.chmod(0o600)
            excluded_path = history / "02-beta.md"
            excluded_path.write_bytes(excluded_history)
            excluded_path.chmod(0o600)

            capture = context_assembly.read_memory_context(
                root,
                context_assembly.ContextWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=("alpha-project",),
                    memory_workspace="raw",
                ),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(capture.status, "CONFIGURED")
        self.assertEqual(capture.snapshot.group, "MEMORY_SNAPSHOT")
        self.assertEqual(capture.snapshot.mode, "HISTORICAL_HINT")
        self.assertEqual(capture.snapshot.relative_path, "memory/raw/snapshot.md")
        self.assertEqual(capture.snapshot.recorded_at, "2026-07-19T10:00:00Z")
        self.assertIsNone(capture.snapshot.content_projection)
        self.assertEqual(len(capture.history), 1)
        self.assertEqual(capture.history[0].group, "MEMORY_HISTORY")
        self.assertEqual(
            capture.history[0].relative_path,
            "memory/raw/history/01-alpha.bin",
        )
        self.assertEqual(capture.history[0].recorded_at, "2026-07-19T11:00:00Z")
        self.assertEqual(len(capture.hints), 1)
        self.assertEqual(capture.hints[0].kind, "LOCAL_PATH")
        self.assertEqual(capture.hints[0].relative_path, "projects/alpha/notes.md")
        self.assertEqual(capture.gaps, ())
        self.assertEqual(capture.counts.history_inspected, 2)
        self.assertEqual(capture.counts.history_included, 1)
        self.assertEqual(capture.counts.history_excluded, 1)
        self.assertEqual(capture.counts.history_malformed, 0)
        self.assertEqual(capture.counts.history_truncated, 0)
        canonical_bytes = json.dumps(
            capture.canonical_value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertNotIn(b"historical only", canonical_bytes)
        self.assertNotIn(b"excluded body", canonical_bytes)


class ContextAssemblyBuilderTest(unittest.TestCase):
    def test_builder_returns_incomplete_gap_for_invalid_utf8_local_source(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            source_path = project / "invalid.md"
            source_path.write_bytes(b"# Invalid\n\xff\n")
            source_path.chmod(0o600)

            assembly = context_assembly.build_context_assembly(
                root=root,
                compiled_workstream=policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace=None,
                ),
                policy_sha256="a" * 64,
                root_identity=_directory_identity(root),
                project_identity=_directory_identity(project),
                local_observations=(
                    context_assembly.ContextLocalObservation(
                        observation=_source_observation(root, source_path),
                        group="PROJECT_ROOT",
                    ),
                ),
                local_gaps=(),
                excluded_paths=(),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(assembly.outcome, "INCOMPLETE")
        self.assertEqual(
            sum(source.mode == "CURRENT_LOCAL" for source in assembly.sources),
            0,
        )
        self.assertIn(
            "LOCAL_SOURCE_INVALID_UTF8",
            {gap.reason_code for gap in assembly.gaps},
        )
        self.assertEqual(assembly.coverage.local_unreadable, 1)

    def test_builder_rechecks_memory_capture_after_local_assembly(self):
        first_snapshot = (
            '---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
            "## Workstreams\n- id: alpha\n"
        )
        changed_snapshot = first_snapshot.replace("10:00:00Z", "10:01:00Z")
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_text(first_snapshot, encoding="utf-8")
            snapshot.chmod(0o600)
            original_reader = context_assembly.read_memory_context
            read_count = 0

            def read_then_mutate(*args, **kwargs):
                nonlocal read_count
                capture = original_reader(*args, **kwargs)
                read_count += 1
                if read_count == 1:
                    snapshot.write_text(changed_snapshot, encoding="utf-8")
                return capture

            with mock.patch.object(
                context_assembly,
                "read_memory_context",
                side_effect=read_then_mutate,
            ):
                with self.assertRaises(context_assembly.ContextAssemblyError) as raised:
                    context_assembly.build_context_assembly(
                        root=root,
                        compiled_workstream=policy.CompiledWorkstream(
                            id="alpha",
                            lifecycle="active",
                            project_home="projects/alpha",
                            aliases=(),
                            memory_workspace="raw",
                        ),
                        policy_sha256="a" * 64,
                        root_identity=_directory_identity(root),
                        project_identity=_directory_identity(project),
                        local_observations=(),
                        local_gaps=(),
                        excluded_paths=(),
                        bounds=context_assembly.ContextAssemblyBounds(),
                    )

        self.assertEqual(raised.exception.reason_code, "CONTEXT_STALE")

    def test_builder_rechecks_local_source_after_context_capture(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            source_path = project / "notes.md"
            source_path.write_text("# Alpha\noriginal\n", encoding="utf-8")
            source_path.chmod(0o600)
            observation = _source_observation(root, source_path)
            original_reader = context_assembly.read_current_local_source
            read_count = 0

            def read_then_mutate(*args, **kwargs):
                nonlocal read_count
                source = original_reader(*args, **kwargs)
                read_count += 1
                if read_count == 1:
                    source_path.write_text("# Alpha\nchanged!\n", encoding="utf-8")
                return source

            with mock.patch.object(
                context_assembly,
                "read_current_local_source",
                side_effect=read_then_mutate,
            ):
                with self.assertRaises(context_assembly.ContextAssemblyError) as raised:
                    context_assembly.build_context_assembly(
                        root=root,
                        compiled_workstream=policy.CompiledWorkstream(
                            id="alpha",
                            lifecycle="active",
                            project_home="projects/alpha",
                            aliases=(),
                            memory_workspace=None,
                        ),
                        policy_sha256="a" * 64,
                        root_identity=_directory_identity(root),
                        project_identity=_directory_identity(project),
                        local_observations=(
                            context_assembly.ContextLocalObservation(
                                observation=observation,
                                group="PROJECT_ROOT",
                            ),
                        ),
                        local_gaps=(),
                        excluded_paths=(),
                        bounds=context_assembly.ContextAssemblyBounds(),
                    )

        self.assertEqual(raised.exception.reason_code, "CONTEXT_STALE")

    def test_builder_caps_aggregate_projection_without_lowering_complete_local_evidence(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            paths = (project / "one.md", project / "two.md")
            for index, path in enumerate(paths, 1):
                path.write_text(
                    "# Title %s\n## First\n## Second\n%s\n"
                    % (index, "body " * 30),
                    encoding="utf-8",
                )
                path.chmod(0o600)
            bounds = replace(
                context_assembly.ContextAssemblyBounds(),
                local_excerpt_bytes=96,
                local_excerpt_total_bytes=120,
                local_heading_count=8,
                local_heading_total_count=2,
                local_projection_total_bytes=180,
            )
            assembly = context_assembly.build_context_assembly(
                root=root,
                compiled_workstream=policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace=None,
                ),
                policy_sha256="a" * 64,
                root_identity=_directory_identity(root),
                project_identity=_directory_identity(project),
                local_observations=tuple(
                    context_assembly.ContextLocalObservation(
                        observation=_source_observation(root, path),
                        group="PROJECT_ROOT",
                    )
                    for path in paths
                ),
                local_gaps=(),
                excluded_paths=(),
                bounds=bounds,
            )

        projections = tuple(
            source.content_projection
            for source in assembly.sources
            if source.mode == "CURRENT_LOCAL"
        )
        self.assertEqual(assembly.outcome, "COMPLETE")
        self.assertLessEqual(
            sum(len(projection.excerpt.encode("utf-8")) for projection in projections),
            bounds.local_excerpt_total_bytes,
        )
        self.assertLessEqual(
            sum(len(projection.headings) for projection in projections),
            bounds.local_heading_total_count,
        )
        self.assertLessEqual(
            sum(
                len(projection.title.encode("utf-8"))
                + sum(len(heading.encode("utf-8")) for heading in projection.headings)
                + len(projection.excerpt.encode("utf-8"))
                for projection in projections
            ),
            bounds.local_projection_total_bytes,
        )
        self.assertTrue(any(projection.excerpt_truncated for projection in projections))
        self.assertTrue(any(projection.headings_truncated for projection in projections))

    def test_builder_enforces_aggregate_local_byte_and_reference_bounds(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            paths = (project / "one.md", project / "two.md")
            for index, path in enumerate(paths, 1):
                path.write_text("# %s\nlocal body\n" % index, encoding="utf-8")
                path.chmod(0o600)
            assembly = context_assembly.build_context_assembly(
                root=root,
                compiled_workstream=policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace=None,
                ),
                policy_sha256="a" * 64,
                root_identity=_directory_identity(root),
                project_identity=_directory_identity(project),
                local_observations=tuple(
                    context_assembly.ContextLocalObservation(
                        observation=_source_observation(root, path),
                        group="PROJECT_ROOT",
                    )
                    for path in reversed(paths)
                ),
                local_gaps=(),
                excluded_paths=(),
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    local_total_bytes=paths[0].stat().st_size,
                ),
            )

        self.assertEqual(assembly.outcome, "INCOMPLETE")
        self.assertEqual(
            sum(source.mode == "CURRENT_LOCAL" for source in assembly.sources),
            1,
        )
        self.assertIn("LOCAL_TOTAL_LIMIT", {gap.reason_code for gap in assembly.gaps})
        self.assertEqual(assembly.coverage.local_truncated, 1)

        targets = (
            "https://jira.example.test/browse/A-1",
            "https://confluence.example.test/wiki/B-2",
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            paths = (project / "one.md", project / "two.md")
            for path, target in zip(paths, targets):
                path.write_text("# Link\n%s\n" % target, encoding="utf-8")
                path.chmod(0o600)
            assembly = context_assembly.build_context_assembly(
                root=root,
                compiled_workstream=policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace=None,
                ),
                policy_sha256="a" * 64,
                root_identity=_directory_identity(root),
                project_identity=_directory_identity(project),
                local_observations=tuple(
                    context_assembly.ContextLocalObservation(
                        observation=_source_observation(root, path),
                        group="PROJECT_ROOT",
                    )
                    for path in paths
                ),
                local_gaps=(),
                excluded_paths=(),
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    local_reference_total=1,
                ),
            )

        self.assertEqual(assembly.outcome, "INCOMPLETE")
        self.assertEqual(
            sum(source.mode == "UNVERIFIED_EXTERNAL" for source in assembly.sources),
            1,
        )
        self.assertIn(
            "LOCAL_REFERENCE_TOTAL_LIMIT",
            {gap.reason_code for gap in assembly.gaps},
        )
        self.assertEqual(assembly.coverage.local_truncated, 1)

    def test_builder_keeps_full_read_local_external_reference_when_excerpt_omits_it(self):
        external_target = "https://confluence.example.test/wiki/private-page"
        raw = (
            "# Local links\n"
            + "A" * 120
            + "\n"
            + external_target
            + "\n"
            + "B" * 120
            + "\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            source_path = project / "links.md"
            source_path.write_bytes(raw)
            source_path.chmod(0o600)
            assembly = context_assembly.build_context_assembly(
                root=root,
                compiled_workstream=policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace=None,
                ),
                policy_sha256="a" * 64,
                root_identity=_directory_identity(root),
                project_identity=_directory_identity(project),
                local_observations=(
                    context_assembly.ContextLocalObservation(
                        observation=_source_observation(root, source_path),
                        group="PROJECT_ROOT",
                    ),
                ),
                local_gaps=(),
                excluded_paths=(),
                bounds=replace(
                    context_assembly.ContextAssemblyBounds(),
                    local_excerpt_bytes=64,
                ),
            )

        external_id = (
            "external:confluence:"
            + hashlib.sha256(external_target.encode("utf-8")).hexdigest()
        )
        local_source = next(
            source for source in assembly.sources if source.mode == "CURRENT_LOCAL"
        )
        self.assertEqual(local_source.reference_source_ids, (external_id,))
        self.assertIn(external_id, {source.source_id for source in assembly.sources})
        self.assertIn(
            "UNVERIFIED_EXTERNAL",
            {claim.mode for claim in assembly.claims},
        )
        self.assertNotIn(external_target.encode("utf-8"), assembly.canonical_bytes)

    def test_builder_keeps_unresolved_local_hint_historical_and_incomplete(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(
                b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
                b"## Workstreams\n- id: alpha\n"
                b"  path: projects/alpha/missing.md\n"
            )
            snapshot.chmod(0o600)
            assembly = context_assembly.build_context_assembly(
                root=root,
                compiled_workstream=policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                policy_sha256="a" * 64,
                root_identity=_directory_identity(root),
                project_identity=_directory_identity(project),
                local_observations=(),
                local_gaps=(),
                excluded_paths=(),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(assembly.outcome, "INCOMPLETE")
        self.assertIn("LOCAL_HINT_UNRESOLVED", {gap.reason_code for gap in assembly.gaps})
        self.assertEqual(
            {claim.mode for claim in assembly.claims},
            {"HISTORICAL_HINT", "MISSING"},
        )
        missing_claim = next(
            claim for claim in assembly.claims if claim.mode == "MISSING"
        )
        self.assertTrue(missing_claim.supporting_source_ids)
        with self.assertRaises(context_assembly.ContextAssemblyError):
            _require_complete(assembly)

    def test_builder_keeps_policy_excluded_hint_historical_without_missing_gap(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(
                b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
                b"## Workstreams\n- id: alpha\n"
                b"  path: projects/alpha/generated.storage.xml\n"
            )
            snapshot.chmod(0o600)
            assembly = context_assembly.build_context_assembly(
                root=root,
                compiled_workstream=policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=(),
                    memory_workspace="raw",
                ),
                policy_sha256="a" * 64,
                root_identity=_directory_identity(root),
                project_identity=_directory_identity(project),
                local_observations=(),
                local_gaps=(),
                excluded_paths=("projects/alpha/generated.storage.xml",),
                bounds=context_assembly.ContextAssemblyBounds(),
            )

        self.assertEqual(assembly.outcome, "COMPLETE")
        self.assertNotIn(
            "LOCAL_HINT_UNRESOLVED",
            {gap.reason_code for gap in assembly.gaps},
        )
        self.assertEqual({claim.mode for claim in assembly.claims}, {"HISTORICAL_HINT"})

    def test_builder_combines_current_local_historical_and_unverified_evidence_read_only(self):
        external_target = "https://jira.example.test/browse/ALPHA-1"
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary).resolve()
            project = root / "projects" / "alpha"
            project.mkdir(parents=True, mode=0o700)
            local_path = project / "meetings" / "july.md"
            local_path.parent.mkdir(mode=0o700)
            local_path.write_bytes(
                b"# July decision\n## Launch\nCurrent local evidence.\n"
            )
            local_path.chmod(0o600)
            observation = _source_observation(root, local_path)

            history = root / "memory" / "raw" / "history"
            history.mkdir(parents=True, mode=0o700)
            snapshot = history.parent / "snapshot.md"
            snapshot.write_bytes(
                b'---\nupdated_at: "2026-07-19T10:00:00Z"\n---\n'
                b"## Workstreams\n- id: alpha\n"
                b"  path: projects/alpha/meetings/july.md\n"
                + ("  ref: %s\n" % external_target).encode("utf-8")
            )
            snapshot.chmod(0o600)
            history_entry = history / "alpha.data"
            history_entry.write_bytes(
                b"---\nworkstream: alpha\n"
                b'created_at: "2026-07-19T11:00:00Z"\n---\n'
                b"historical context only\n"
            )
            history_entry.chmod(0o600)
            before = _regular_file_hashes(root)

            assembly = context_assembly.build_context_assembly(
                root=root,
                compiled_workstream=policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home="projects/alpha",
                    aliases=("alpha-project",),
                    memory_workspace="raw",
                ),
                policy_sha256="a" * 64,
                root_identity=_directory_identity(root),
                project_identity=_directory_identity(project),
                local_observations=(
                    context_assembly.ContextLocalObservation(
                        observation=observation,
                        group="MEETING",
                    ),
                ),
                local_gaps=(),
                excluded_paths=(),
                bounds=context_assembly.ContextAssemblyBounds(),
            )
            after = _regular_file_hashes(root)

        self.assertEqual(before, after)
        self.assertEqual(assembly.outcome, "COMPLETE")
        self.assertEqual(
            {source.group for source in assembly.sources},
            {"MEETING", "MEMORY_SNAPSHOT", "MEMORY_HISTORY", "EXTERNAL_REFERENCE"},
        )
        self.assertEqual(
            {claim.mode for claim in assembly.claims},
            {"CURRENT_LOCAL", "HISTORICAL_HINT", "UNVERIFIED_EXTERNAL"},
        )
        current_claim = next(
            claim for claim in assembly.claims if claim.mode == "CURRENT_LOCAL"
        )
        self.assertTrue(current_claim.historical_source_ids)
        self.assertEqual(assembly.coverage.memory_history_inspected, 1)
        self.assertEqual(assembly.coverage.memory_history_included, 1)
        self.assertEqual(assembly.coverage.memory_snapshot_hint_count, 2)
        self.assertEqual(assembly.coverage.external_unverified, 1)
        self.assertGreater(assembly.coverage.memory_snapshot_bytes_read, 0)
        self.assertGreater(assembly.coverage.memory_history_bytes_read, 0)
        complete = _require_complete(assembly)
        self.assertEqual(complete.assembly_sha256, assembly.sha256)
        self.assertNotIn(external_target.encode("utf-8"), assembly.canonical_bytes)


class ContextAssemblyDomainTest(unittest.TestCase):
    def test_complete_capability_requires_exact_authority_and_hash_binding(self):
        assembly = _empty_complete_assembly()

        with self.assertRaises(TypeError):
            assembly.require_complete()
        complete = _require_complete(assembly)
        self.assertEqual(complete.assembly_sha256, assembly.sha256)
        self.assertEqual(complete.coverage_sha256, assembly.coverage_sha256)

        mismatches = (
            {"expected_workstream": replace(assembly.workstream, id="beta")},
            {"expected_policy_sha256": "b" * 64},
            {"expected_root_identity": (9, 2, 448, 501)},
            {"expected_project_identity": (9, 3, 448, 501)},
            {"expected_assembly_sha256": "b" * 64},
            {"expected_coverage_sha256": "b" * 64},
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    _require_complete(assembly, **mismatch)

    def test_complete_assembly_rejects_blocker_and_wrong_authority_claims(self):
        source = context_assembly.ContextSource(
            source_id="external:jira:" + "e" * 64,
            group="EXTERNAL_REFERENCE",
            mode="UNVERIFIED_EXTERNAL",
            reference_family="jira",
            reference_sha256="e" * 64,
        )
        coverage = replace(
            _empty_complete_assembly().coverage,
            source_group_counts=(("EXTERNAL_REFERENCE", 1),),
            external_unverified=1,
        )
        valid_claim = context_assembly.ContextClaim(
            claim_id="claim-external",
            mode="UNVERIFIED_EXTERNAL",
            subject="external-reference-present",
            supporting_source_ids=(source.source_id,),
        )
        assembly = replace(
            _empty_complete_assembly(),
            sources=(source,),
            claims=(valid_claim,),
            coverage=coverage,
        )
        self.assertEqual(assembly.outcome, "COMPLETE")

        for invalid_mode in (
            "CURRENT_LOCAL",
            "HISTORICAL_HINT",
            "MISSING",
            "CONFLICT",
        ):
            with self.subTest(mode=invalid_mode):
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    replace(
                        assembly,
                        claims=(replace(valid_claim, mode=invalid_mode),),
                    )

    def test_external_reference_family_is_a_closed_non_sensitive_vocabulary(self):
        source = context_assembly.ContextSource(
            source_id="external:jira:" + "e" * 64,
            group="EXTERNAL_REFERENCE",
            mode="UNVERIFIED_EXTERNAL",
            reference_family="jira",
            reference_sha256="e" * 64,
        )

        self.assertEqual(source.reference_family, "jira")
        for unsafe_family in (
            "JIRA",
            "https://jira.example.test/browse/SECRET-123",
            "customer-123",
            "projects/example-project/private-reference",
        ):
            with self.subTest(reference_family=unsafe_family):
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    replace(source, reference_family=unsafe_family)

        for unsafe_source_id in (
            "https://jira.example.test/browse/SECRET-123",
            "person@example.test",
            "customer-123",
            "external:jira:" + "f" * 64,
            "external:url:" + "e" * 64,
        ):
            with self.subTest(source_id=unsafe_source_id):
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    replace(source, source_id=unsafe_source_id)

    def test_assembly_rejects_coverage_that_contradicts_sources_or_gaps(self):
        missing_gap = context_assembly.ContextGap(
            gap_id="gap-missing",
            kind="MISSING",
            group="OTHER_NESTED",
            reason_code="SOURCE_MISSING",
            relative_path="projects/alpha/missing.md",
        )
        with self.assertRaises(context_assembly.ContextAssemblyError):
            replace(
                _empty_complete_assembly(),
                outcome="INCOMPLETE",
                gaps=(missing_gap,),
            )

        external_source = context_assembly.ContextSource(
            source_id="external:jira:" + "e" * 64,
            group="EXTERNAL_REFERENCE",
            mode="UNVERIFIED_EXTERNAL",
            reference_family="jira",
            reference_sha256="e" * 64,
        )
        correct_coverage = replace(
            _empty_complete_assembly().coverage,
            source_group_counts=(("EXTERNAL_REFERENCE", 1),),
            external_unverified=1,
        )
        assembly = replace(
            _empty_complete_assembly(),
            sources=(external_source,),
            coverage=correct_coverage,
        )
        self.assertEqual(assembly.coverage.external_unverified, 1)

        for inconsistent_coverage in (
            replace(correct_coverage, source_group_counts=()),
            replace(correct_coverage, external_unverified=0),
            replace(correct_coverage, external_verified=1),
            replace(correct_coverage, memory_history_included=1),
            replace(correct_coverage, memory_status="CONFIGURED"),
        ):
            with self.subTest(coverage=inconsistent_coverage):
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    replace(assembly, coverage=inconsistent_coverage)

    def test_complete_capability_and_volatile_envelopes_enforce_outcome_boundary(self):
        envelope_type = getattr(context_assembly, "ContextAssemblyEnvelope", None)
        complete_type = getattr(context_assembly, "CompleteContextAssembly", None)
        resolution_fence = getattr(
            context_assembly, "blocked_workstream_resolution", None
        )
        self.assertTrue(callable(envelope_type))
        self.assertTrue(callable(complete_type))
        self.assertTrue(callable(resolution_fence))

        assembly = _empty_complete_assembly()
        complete = _require_complete(assembly)
        self.assertIsInstance(complete, complete_type)
        self.assertEqual(complete.assembly_sha256, assembly.sha256)
        self.assertEqual(complete.coverage_sha256, assembly.coverage_sha256)

        first = envelope_type(
            request_id="request-one",
            observed_at="2026-07-19T20:00:00+09:00",
            outcome="COMPLETE",
            assembly_id=assembly.sha256,
            diagnostic_reason_codes=(),
        )
        second = replace(
            first,
            request_id="request-two",
            observed_at="2026-07-19T20:01:00+09:00",
        )
        self.assertNotEqual(first.public_value, second.public_value)
        self.assertNotIn(b"request-one", assembly.canonical_bytes)
        self.assertNotIn(b"2026-07-19T20:00:00+09:00", assembly.canonical_bytes)

        blocked = resolution_fence(
            reason_code="WORKSTREAM_AMBIGUOUS",
            request_id="request-three",
            observed_at="2026-07-19T20:02:00+09:00",
            candidate_count=2,
        )
        self.assertEqual(blocked.outcome, "BLOCKED_UNSAFE")
        self.assertIsNone(blocked.assembly_id)
        self.assertEqual(blocked.candidate_count, 2)
        with self.assertRaises(context_assembly.ContextAssemblyError):
            envelope_type(
                request_id="request-four",
                observed_at="2026-07-19T20:03:00+09:00",
                outcome="STALE",
                assembly_id=assembly.sha256,
                diagnostic_reason_codes=("POLICY_CHANGED",),
            )

    def test_incomplete_assembly_has_literal_coverage_digest_and_no_complete_capability(self):
        coverage = context_assembly.ContextCoverage(
            local_inspected=0,
            local_excluded=0,
            local_unreadable=0,
            local_truncated=0,
            source_group_counts=(),
            memory_status="CONFIGURED",
            memory_history_inspected=0,
            memory_history_included=0,
            memory_history_excluded=0,
            memory_history_malformed=0,
            memory_history_truncated=0,
            external_verified=0,
            external_unverified=0,
            excluded_paths=(),
            gap_paths=("memory/raw/history",),
            redaction_counts=(),
        )
        incomplete = context_assembly.ContextAssembly(
            workstream=context_assembly.ContextWorkstream(
                id="alpha",
                lifecycle="active",
                project_home="projects/alpha",
                aliases=(),
                memory_workspace="raw",
            ),
            root_identity=(1, 2, 448, 501),
            project_identity=(1, 3, 448, 501),
            policy_sha256="a" * 64,
            outcome="INCOMPLETE",
            bounds=context_assembly.ContextAssemblyBounds(
                snapshot_bytes=10,
                memory_frontmatter_bytes=11,
                history_entry_count=12,
                history_file_bytes=13,
                history_total_bytes=14,
                hint_token_count=15,
                local_source_bytes=16,
                local_total_bytes=17,
                local_excerpt_bytes=18,
                local_excerpt_total_bytes=19,
                local_heading_count=20,
                local_heading_total_count=21,
                local_reference_per_source=22,
                local_reference_total=23,
                local_projection_total_bytes=24,
            ),
            sources=(),
            claims=(),
            gaps=(
                context_assembly.ContextGap(
                    gap_id="gap-history",
                    kind="MISSING",
                    group="MEMORY_HISTORY",
                    reason_code="HISTORY_DIRECTORY_MISSING",
                    relative_path="memory/raw/history",
                ),
            ),
            coverage=coverage,
        )
        coverage_literal = {
            "excluded_paths": [],
            "external_unverified": 0,
            "external_verified": 0,
            "gap_paths": ["memory/raw/history"],
            "local_excluded": 0,
            "local_inspected": 0,
            "local_truncated": 0,
            "local_unreadable": 0,
            "memory_history_excluded": 0,
            "memory_history_included": 0,
            "memory_history_inspected": 0,
            "memory_history_malformed": 0,
            "memory_history_truncated": 0,
            "memory_history_bytes_read": 0,
            "memory_freshness_sha256": "58062a597ceb174686ba86c4dfcd78031572b3c5e1bd8bba42b3795abc9cfdfd",
            "memory_hint_tokens_extracted": 0,
            "memory_snapshot_bytes_read": 0,
            "memory_snapshot_hint_count": 0,
            "memory_status": "CONFIGURED",
            "redaction_counts": {},
            "source_group_counts": {},
        }
        coverage_bytes = (
            json.dumps(coverage_literal, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        expected_literal = {
            "bounds": {
                "hint_token_count": 15,
                "history_entry_count": 12,
                "history_file_bytes": 13,
                "history_total_bytes": 14,
                "local_excerpt_bytes": 18,
                "local_excerpt_total_bytes": 19,
                "local_heading_count": 20,
                "local_heading_total_count": 21,
                "local_projection_total_bytes": 24,
                "local_reference_per_source": 22,
                "local_reference_total": 23,
                "local_source_bytes": 16,
                "local_total_bytes": 17,
                "memory_frontmatter_bytes": 11,
                "snapshot_bytes": 10,
            },
            "claims": [],
            "coverage": coverage_literal,
            "coverage_sha256": hashlib.sha256(coverage_bytes).hexdigest(),
            "gaps": [
                {
                    "gap_id": "gap-history",
                    "group": "MEMORY_HISTORY",
                    "kind": "MISSING",
                    "reason_code": "HISTORY_DIRECTORY_MISSING",
                    "relative_path": "memory/raw/history",
                }
            ],
            "outcome": "INCOMPLETE",
            "policy_sha256": "a" * 64,
            "project_identity": [1, 3, 448, 501],
            "root_identity": [1, 2, 448, 501],
            "schema": "mnemosyne-workstream-context-assembly-v1",
            "sources": [],
            "spec_sha256": "6f4407aadab564962bf796856994fa226dd38912b8abd6d9f1231406e54d06a9",
            "workstream": {
                "aliases": [],
                "id": "alpha",
                "lifecycle": "active",
                "memory_workspace": "raw",
                "project_home": "projects/alpha",
            },
        }
        expected_bytes = (
            json.dumps(
                expected_literal,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

        self.assertEqual(incomplete.canonical_bytes, expected_bytes)
        self.assertEqual(incomplete.sha256, hashlib.sha256(expected_bytes).hexdigest())
        with self.assertRaisesRegex(
            context_assembly.ContextAssemblyError, "capability is unavailable"
        ):
            _require_complete(incomplete)

    def test_content_identity_and_claim_mode_are_hash_bound_and_values_are_frozen(self):
        projection = context_assembly.ContextContentProjection(
            title="Current",
            headings=("Current",),
            headings_truncated=False,
            excerpt="distinctive nested content",
            excerpt_truncated=False,
            redaction_counts=(),
            full_content_sha256="b" * 64,
            full_content_byte_count=26,
        )
        source = context_assembly.ContextSource(
            source_id="source-current",
            group="OTHER_NESTED",
            mode="CURRENT_LOCAL",
            relative_path="projects/alpha/nested/current.md",
            observation_id="observation-current",
            identity=(1, 4, 501, 384, 1, 26, 100),
            content_sha256="b" * 64,
            snapshot_sha256="c" * 64,
            content_projection=projection,
        )
        claim = context_assembly.ContextClaim(
            claim_id="claim-current",
            mode="CURRENT_LOCAL",
            subject="nested-content-present",
            supporting_source_ids=("source-current",),
        )
        coverage = replace(
            _empty_complete_assembly().coverage,
            local_inspected=1,
            source_group_counts=(("OTHER_NESTED", 1),),
        )
        assembly = replace(
            _empty_complete_assembly(),
            sources=(source,),
            claims=(claim,),
            coverage=coverage,
        )
        changed_projection = replace(
            projection,
            full_content_sha256="d" * 64,
        )
        changed_source = replace(
            source,
            content_sha256="d" * 64,
            content_projection=changed_projection,
        )
        changed_content = replace(assembly, sources=(changed_source,))
        claim_gap = context_assembly.ContextGap(
            gap_id="gap-claim",
            kind="MISSING",
            group="OTHER_NESTED",
            reason_code="CLAIM_UNRESOLVED",
            relative_path="projects/alpha/nested/current.md",
        )
        missing_mode = replace(
            assembly,
            outcome="INCOMPLETE",
            claims=(replace(claim, mode="MISSING"),),
            gaps=(claim_gap,),
            coverage=replace(
                coverage,
                gap_paths=("projects/alpha/nested/current.md",),
            ),
        )
        conflict_mode = replace(
            missing_mode,
            claims=(replace(claim, mode="CONFLICT"),),
        )

        self.assertNotEqual(assembly.sha256, changed_content.sha256)
        self.assertNotEqual(missing_mode.sha256, conflict_mode.sha256)
        with self.assertRaises(context_assembly.ContextAssemblyError):
            replace(claim, mode="CURRENT_EXTERNAL")
        with self.assertRaises(FrozenInstanceError):
            assembly.outcome = "INCOMPLETE"

    def test_complete_assembly_has_order_independent_literal_canonical_identity(self):
        required_types = (
            "ContextAssemblyBounds",
            "ContextWorkstream",
            "ContextContentProjection",
            "ContextSource",
            "ContextClaim",
            "ContextCoverage",
            "ContextAssembly",
        )
        for name in required_types:
            self.assertTrue(callable(getattr(context_assembly, name, None)), name)

        bounds = context_assembly.ContextAssemblyBounds(
            snapshot_bytes=100,
            memory_frontmatter_bytes=20,
            history_entry_count=3,
            history_file_bytes=40,
            history_total_bytes=80,
            hint_token_count=5,
            local_source_bytes=200,
            local_total_bytes=400,
            local_excerpt_bytes=30,
            local_excerpt_total_bytes=60,
            local_heading_count=4,
            local_heading_total_count=8,
            local_reference_per_source=2,
            local_reference_total=6,
            local_projection_total_bytes=120,
        )
        projection = context_assembly.ContextContentProjection(
            title="July decision",
            headings=("Decision",),
            headings_truncated=False,
            excerpt="Use verified local data.",
            excerpt_truncated=False,
            redaction_counts=(("email", 0), ("secret", 0)),
            full_content_sha256="1" * 64,
            full_content_byte_count=24,
        )
        local_source = context_assembly.ContextSource(
            source_id="source-local",
            group="MEETING",
            mode="CURRENT_LOCAL",
            relative_path="projects/example-project/meetings/july.md",
            observation_id="observation-local",
            identity=(1, 2, 501, 384, 1, 24, 99),
            content_sha256="1" * 64,
            snapshot_sha256="2" * 64,
            content_projection=projection,
        )
        memory_source = context_assembly.ContextSource(
            source_id="source-memory",
            group="MEMORY_SNAPSHOT",
            mode="HISTORICAL_HINT",
            relative_path="memory/raw/snapshot.md",
            identity=(1, 3, 501, 384, 1, 18, 88),
            content_sha256="3" * 64,
            evidence_sha256="4" * 64,
            recorded_at="2026-07-18T12:00:00+09:00",
        )
        coverage = context_assembly.ContextCoverage(
            local_inspected=1,
            local_excluded=0,
            local_unreadable=0,
            local_truncated=0,
            source_group_counts=(("MEMORY_SNAPSHOT", 1), ("MEETING", 1)),
            memory_status="CONFIGURED",
            memory_history_inspected=0,
            memory_history_included=0,
            memory_history_excluded=0,
            memory_history_malformed=0,
            memory_history_truncated=0,
            external_verified=0,
            external_unverified=0,
            excluded_paths=(),
            gap_paths=(),
            redaction_counts=(("email", 0), ("secret", 0)),
        )
        assembly = context_assembly.ContextAssembly(
            workstream=context_assembly.ContextWorkstream(
                id="example-project-workstream",
                lifecycle="active",
                project_home="projects/example-project",
                aliases=("example-project",),
                memory_workspace="raw",
            ),
            root_identity=(1, 10, 448, 501),
            project_identity=(1, 11, 448, 501),
            policy_sha256="5" * 64,
            outcome="COMPLETE",
            bounds=bounds,
            sources=(memory_source, local_source),
            claims=(
                context_assembly.ContextClaim(
                    claim_id="claim-local",
                    mode="CURRENT_LOCAL",
                    subject="july-decision-present",
                    supporting_source_ids=("source-local",),
                    historical_source_ids=("source-memory",),
                ),
            ),
            gaps=(),
            coverage=coverage,
        )

        coverage_literal = {
            "excluded_paths": [],
            "external_unverified": 0,
            "external_verified": 0,
            "gap_paths": [],
            "local_excluded": 0,
            "local_inspected": 1,
            "local_truncated": 0,
            "local_unreadable": 0,
            "memory_history_excluded": 0,
            "memory_history_included": 0,
            "memory_history_inspected": 0,
            "memory_history_malformed": 0,
            "memory_history_truncated": 0,
            "memory_history_bytes_read": 0,
            "memory_freshness_sha256": "58062a597ceb174686ba86c4dfcd78031572b3c5e1bd8bba42b3795abc9cfdfd",
            "memory_hint_tokens_extracted": 0,
            "memory_snapshot_bytes_read": 0,
            "memory_snapshot_hint_count": 0,
            "memory_status": "CONFIGURED",
            "redaction_counts": {"email": 0, "secret": 0},
            "source_group_counts": {"MEETING": 1, "MEMORY_SNAPSHOT": 1},
        }
        coverage_bytes = (
            json.dumps(
                coverage_literal,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        expected_literal = {
            "bounds": {
                "hint_token_count": 5,
                "history_entry_count": 3,
                "history_file_bytes": 40,
                "history_total_bytes": 80,
                "local_excerpt_bytes": 30,
                "local_excerpt_total_bytes": 60,
                "local_heading_count": 4,
                "local_heading_total_count": 8,
                "local_projection_total_bytes": 120,
                "local_reference_per_source": 2,
                "local_reference_total": 6,
                "local_source_bytes": 200,
                "local_total_bytes": 400,
                "memory_frontmatter_bytes": 20,
                "snapshot_bytes": 100,
            },
            "claims": [
                {
                    "claim_id": "claim-local",
                    "historical_source_ids": ["source-memory"],
                    "mode": "CURRENT_LOCAL",
                    "subject": "july-decision-present",
                    "supporting_source_ids": ["source-local"],
                }
            ],
            "coverage": coverage_literal,
            "coverage_sha256": hashlib.sha256(coverage_bytes).hexdigest(),
            "gaps": [],
            "outcome": "COMPLETE",
            "policy_sha256": "5" * 64,
            "project_identity": [1, 11, 448, 501],
            "root_identity": [1, 10, 448, 501],
            "schema": "mnemosyne-workstream-context-assembly-v1",
            "sources": [
                {
                    "content_projection": {
                        "encoding": "utf-8",
                        "excerpt": "Use verified local data.",
                        "excerpt_truncated": False,
                        "full_content_byte_count": 24,
                        "full_content_sha256": "1" * 64,
                        "headings": ["Decision"],
                        "headings_truncated": False,
                        "redaction_counts": {"email": 0, "secret": 0},
                        "title": "July decision",
                    },
                    "content_sha256": "1" * 64,
                    "group": "MEETING",
                    "identity": [1, 2, 501, 384, 1, 24, 99],
                    "mode": "CURRENT_LOCAL",
                    "observation_id": "observation-local",
                    "relative_path": "projects/example-project/meetings/july.md",
                    "snapshot_sha256": "2" * 64,
                    "source_id": "source-local",
                },
                {
                    "content_sha256": "3" * 64,
                    "evidence_sha256": "4" * 64,
                    "group": "MEMORY_SNAPSHOT",
                    "identity": [1, 3, 501, 384, 1, 18, 88],
                    "mode": "HISTORICAL_HINT",
                    "recorded_at": "2026-07-18T12:00:00+09:00",
                    "relative_path": "memory/raw/snapshot.md",
                    "source_id": "source-memory",
                },
            ],
            "spec_sha256": "6f4407aadab564962bf796856994fa226dd38912b8abd6d9f1231406e54d06a9",
            "workstream": {
                "aliases": ["example-project"],
                "id": "example-project-workstream",
                "lifecycle": "active",
                "memory_workspace": "raw",
                "project_home": "projects/example-project",
            },
        }
        expected_bytes = (
            json.dumps(
                expected_literal,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

        self.assertEqual(assembly.canonical_bytes, expected_bytes)
        self.assertEqual(assembly.sha256, hashlib.sha256(expected_bytes).hexdigest())
        self.assertEqual(
            replace(assembly, sources=tuple(reversed(assembly.sources))).canonical_bytes,
            expected_bytes,
        )


if __name__ == "__main__":
    unittest.main()
