import errno
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import inventory  # noqa: E402


def _frozen_decision(lifecycle: str = "completed") -> inventory.ScopeDecision:
    return inventory.ScopeDecision(
        rule_id="paused-completed",
        scope_class="coverage-only",
        traversal="directory-count-only",
        lifecycle=lifecycle,
        content_inspection="none",
    )


def _bounds(*, max_items: int = 64, max_depth: int = 8) -> inventory.TraversalBounds:
    return inventory.TraversalBounds(
        max_entries=max_items,
        max_direct_entries=max_items,
        max_depth=max_depth,
        max_file_bytes=0,
        max_content_bytes=0,
    )


def _directory_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _close_if_open(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


class FrozenCountInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "project"
        self.root.mkdir(mode=0o700)

    def _open_root(self) -> int:
        descriptor = os.open(self.root, _directory_flags())
        self.addCleanup(_close_if_open, descriptor)
        return descriptor

    def test_exact_root_count_only_is_filename_free_and_never_opens_files(
        self,
    ) -> None:
        alpha = self.root / "alpha"
        zeta = self.root / "zeta"
        alpha.mkdir(mode=0o700)
        zeta.mkdir(mode=0o700)
        root_file = self.root / "private-root-name.md"
        nested_file = alpha / "private-nested-name.json"
        root_file.write_text("root secret", encoding="utf-8")
        nested_file.write_text("nested secret", encoding="utf-8")
        (self.root / "unsafe-link.txt").symlink_to(root_file)
        os.mkfifo(self.root / "unsafe-pipe", mode=0o600)
        caller_descriptor = self._open_root()
        caller_identity = os.fstat(caller_descriptor)
        real_open = os.open
        forbidden_names = {
            os.fsencode(root_file.name),
            os.fsencode(nested_file.name),
        }

        def reject_content_open(path, flags, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                raw_name = os.path.basename(os.fsencode(path))
                if raw_name in forbidden_names:
                    raise AssertionError("count-only scan opened project content")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(inventory.os, "open", side_effect=reject_content_open):
            first = inventory.scan_directory_count_only(
                "frozen-count-001",
                caller_descriptor,
                _frozen_decision(),
                _bounds(),
            )

        reopened_descriptor = self._open_root()
        second = inventory.scan_directory_count_only(
            "frozen-count-001",
            reopened_descriptor,
            _frozen_decision(),
            _bounds(),
        )

        self.assertEqual(
            (os.fstat(caller_descriptor).st_dev, os.fstat(caller_descriptor).st_ino),
            (caller_identity.st_dev, caller_identity.st_ino),
        )
        self.assertEqual(first.observations_jsonl(), second.observations_jsonl())
        self.assertEqual(first.coverage_json(), second.coverage_json())
        self.assertEqual(
            [row.display_path for row in first.observations],
            [".", "alpha", "zeta"],
        )
        self.assertTrue(
            all(row.physical_kind == "directory" for row in first.observations)
        )
        self.assertTrue(
            all(row.traversal == "directory-count-only" for row in first.observations)
        )
        self.assertTrue(
            all(not row.content_inspected for row in first.observations)
        )
        self.assertTrue(
            all(row.reference_projection is None for row in first.observations)
        )
        self.assertTrue(
            all(row.classification_projection is None for row in first.observations)
        )
        self.assertTrue(
            all(row.fingerprint_value is None for row in first.observations)
        )
        self.assertNotIn(b'"physical_kind":"file"', first.observations_jsonl())
        self.assertNotIn(b'"kind":"file"', first.observations_jsonl())
        self.assertNotIn(b'"kind":"sha256"', first.observations_jsonl())
        for forbidden in (
            b"private-root-name.md",
            b"private-nested-name.json",
            b"unsafe-link.txt",
            b"unsafe-pipe",
            b"root secret",
            b"nested secret",
        ):
            self.assertNotIn(forbidden, first.observations_jsonl())

        by_path = {row.display_path: row for row in first.observations}
        self.assertEqual(by_path["."].direct_file_count, 1)
        self.assertEqual(by_path["."].direct_other_count, 2)
        self.assertEqual(by_path["alpha"].direct_file_count, 1)
        self.assertEqual(first.coverage["files"]["denominator"], 2)
        self.assertEqual(first.coverage["other_items"]["aggregated"], 2)
        self.assertEqual(first.coverage["content_bytes_attempted"], 0)

    def test_unreadable_and_unsafe_entries_are_aggregated_without_name_rows(
        self,
    ) -> None:
        blocked = self.root / "blocked-directory"
        blocked.mkdir(mode=0o700)
        (blocked / "hidden.md").write_text("hidden", encoding="utf-8")
        regular = self.root / "ordinary.txt"
        regular.write_text("ordinary", encoding="utf-8")
        (self.root / "unsafe-link").symlink_to(regular)
        descriptor = self._open_root()
        real_open = os.open

        def deny_blocked_directory(path, flags, *args, **kwargs):
            if (
                isinstance(path, (str, bytes, os.PathLike))
                and os.path.basename(os.fsencode(path)) == b"blocked-directory"
            ):
                raise PermissionError(errno.EACCES, "denied")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(
            inventory.os,
            "open",
            side_effect=deny_blocked_directory,
        ):
            result = inventory.scan_directory_count_only(
                "frozen-count-unreadable",
                descriptor,
                _frozen_decision("paused"),
                _bounds(),
            )

        by_path = {row.display_path: row for row in result.observations}
        self.assertEqual(set(by_path), {".", "blocked-directory"})
        self.assertEqual(by_path["."].direct_file_count, 1)
        self.assertEqual(by_path["."].direct_other_count, 1)
        self.assertEqual(
            by_path["blocked-directory"].errors,
            ("directory-open-failed",),
        )
        self.assertEqual(
            result.coverage["partial_reasons"]["error:directory-open-failed"],
            1,
        )
        self.assertNotIn(b"ordinary.txt", result.observations_jsonl())
        self.assertNotIn(b"unsafe-link", result.observations_jsonl())
        self.assertNotIn(b"hidden.md", result.observations_jsonl())

    def test_item_and_depth_bounds_are_hard_and_report_truncation(self) -> None:
        deepest = self.root / "a" / "b" / "c"
        deepest.mkdir(parents=True, mode=0o700)
        (deepest / "hidden.md").write_text("hidden", encoding="utf-8")
        (self.root / "d").mkdir(mode=0o700)

        item_limited = inventory.scan_directory_count_only(
            "frozen-count-items",
            self._open_root(),
            _frozen_decision(),
            _bounds(max_items=2, max_depth=8),
        )
        depth_limited = inventory.scan_directory_count_only(
            "frozen-count-depth",
            self._open_root(),
            _frozen_decision(),
            _bounds(max_items=16, max_depth=1),
        )

        self.assertLessEqual(len(item_limited.observations), 2)
        self.assertEqual(
            [row.display_path for row in item_limited.observations],
            [".", "a"],
        )
        self.assertEqual(item_limited.coverage["state"], "explained-partial")
        self.assertGreater(item_limited.coverage["descendant_unknown"], 0)
        self.assertTrue(
            all(
                row.display_path == "." or row.display_path.count("/") < 1
                for row in depth_limited.observations
            )
        )
        self.assertEqual(depth_limited.coverage["state"], "explained-partial")
        self.assertGreater(depth_limited.coverage["descendant_unknown"], 0)

    def test_existing_inventory_engine_scan_remains_content_aware(self) -> None:
        note = self.root / "note.md"
        note.write_text("# Existing scan\n", encoding="utf-8")
        observed = []
        active = inventory.ScopeDecision(
            rule_id="active-workstream-content",
            scope_class="eligible",
            traversal="full",
            lifecycle="active",
            content_inspection="bounded-text",
        )
        engine = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(default=active),
            inventory.TraversalBounds(
                max_entries=16,
                max_direct_entries=16,
                max_depth=4,
                max_file_bytes=1024,
                max_content_bytes=4096,
            ),
            observation_hook=observed.append,
        )

        result = engine.scan("existing-scan-regression")

        by_path = {row.display_path: row for row in result.observations}
        self.assertTrue(by_path["note.md"].content_inspected)
        self.assertEqual(by_path["note.md"].fingerprint_kind, "sha256")
        self.assertEqual(tuple(observed), result.observations)


if __name__ == "__main__":
    unittest.main()
