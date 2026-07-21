import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core.authority_runtime import auxiliary_index  # noqa: E402


class AuxiliaryIndexTest(unittest.TestCase):
    WORKSTREAM_ID = "example-completed-workstream"

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.root.chmod(0o700)
        self.project_home = self.root / "projects" / self.WORKSTREAM_ID
        self.project_home.mkdir(parents=True, mode=0o700)
        self.snapshot = (
            self.root
            / "_index"
            / "memory"
            / self.WORKSTREAM_ID
            / "snapshot.md"
        )
        self.snapshot.parent.mkdir(parents=True, mode=0o700)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)

    def tearDown(self) -> None:
        os.close(self.root_fd)
        self._temporary.cleanup()

    def _document(
        self,
        *,
        workstream_id: str | None = None,
        project_home: Path | None = None,
        updated_at: str | None = "2026-07-18T09:30:00+09:00",
        extra_frontmatter: bytes = b"",
        body: bytes = b"# body must remain unread\nStatus: active\n",
    ) -> bytes:
        identifier = workstream_id or self.WORKSTREAM_ID
        project = project_home or self.project_home
        frontmatter = (
            b"---\n"
            b"schema_version: 1\n"
            b"workspace:\n"
            + ('  slug: "%s"\n' % identifier).encode("utf-8")
            + ('  root: "%s"\n' % project).encode("utf-8")
        )
        if updated_at is not None:
            frontmatter += ('updated_at: "%s"\n' % updated_at).encode("utf-8")
        return frontmatter + extra_frontmatter + b"---\n" + body

    def _write(self, payload: bytes, *, mode: int = 0o644) -> None:
        self.snapshot.write_bytes(payload)
        self.snapshot.chmod(mode)

    def _token(self) -> object:
        return auxiliary_index.derive_snapshot_token(self.WORKSTREAM_ID)

    def _inspect(self) -> object:
        with auxiliary_index.open_snapshot_capability(
            self.root_fd,
            self._token(),
        ) as capability:
            return auxiliary_index.inspect_snapshot(
                capability,
                expected_workstream_id=self.WORKSTREAM_ID,
                expected_project_home=self.project_home,
                raw_root=self.root,
            )

    def _single_finding(self, payload: bytes) -> object:
        self._write(payload)
        inspection = self._inspect()
        self.assertEqual(len(inspection.findings), 1)
        finding = inspection.findings[0]
        self.assertTrue(finding.requires_manual_review)
        self.assertIsInstance(finding.source_id, str)
        self.assertTrue(finding.source_id)
        return finding

    def test_safe_one_segment_token_rejects_unsafe_values_before_any_open(self) -> None:
        unsafe_values = (
            "",
            ".",
            "..",
            "invest/agent",
            "invest\\agent",
            "invest\x00agent",
            "invest\nagent",
            "invest%2fagent",
            "invest%2Fagent",
            "invest%5cagent",
            "invest%5Cagent",
        )

        for value in unsafe_values:
            with self.subTest(value=repr(value)):
                with mock.patch.object(auxiliary_index.os, "open") as opened:
                    with self.assertRaises(auxiliary_index.AuxiliaryIndexError) as error:
                        auxiliary_index.derive_snapshot_token(value)
                self.assertEqual(error.exception.reason_code, "AUXILIARY_UNSAFE")
                self.assertFalse(error.exception.blocks_authority)
                opened.assert_not_called()

        with mock.patch.object(auxiliary_index.os, "open") as opened:
            with self.assertRaises(auxiliary_index.AuxiliaryIndexError) as error:
                with auxiliary_index.open_snapshot_capability(
                    self.root_fd,
                    self.WORKSTREAM_ID,
                ):
                    self.fail("a raw string must never become a path capability")
        self.assertEqual(error.exception.reason_code, "AUXILIARY_UNSAFE")
        opened.assert_not_called()

    def test_exact_capability_closes_its_fd_and_stops_at_first_delimiter(self) -> None:
        body = (
            b"Status: active\n"
            b"---\n"
            b"schema_version: [invalid]\n"
            b"workspace:\n"
            b"  slug: attacker\n"
            b"---\n"
        )
        payload = self._document(body=body)
        self._write(payload)
        consumed = payload.index(b"---\n", len(b"---\n")) + len(b"---\n")

        with auxiliary_index.open_snapshot_capability(
            self.root_fd,
            self._token(),
        ) as capability:
            self.assertIs(
                type(capability),
                auxiliary_index.AuxiliarySnapshotCapability,
            )
            capability_fd = capability.file_descriptor
            opened = os.fstat(capability_fd)
            self.assertTrue(stat.S_ISREG(opened.st_mode))
            self.assertEqual(capability.identity.device, opened.st_dev)
            self.assertEqual(capability.identity.inode, opened.st_ino)
            self.assertEqual(capability.identity.mode, stat.S_IMODE(opened.st_mode))
            self.assertEqual(capability.identity.uid, os.getuid())
            self.assertEqual(capability.identity.link_count, 1)
            inspection = auxiliary_index.inspect_snapshot(
                capability,
                expected_workstream_id=self.WORKSTREAM_ID,
                expected_project_home=self.project_home,
                raw_root=self.root,
            )
            offset = os.lseek(capability_fd, 0, os.SEEK_CUR)
            os.fstat(self.root_fd)

        self.assertIs(type(inspection), auxiliary_index.AuxiliaryInspection)
        self.assertEqual(inspection.findings, ())
        self.assertEqual(inspection.metadata_bytes_used, consumed)
        self.assertFalse(inspection.truncated)
        self.assertEqual(offset, consumed)
        os.fstat(self.root_fd)
        with self.assertRaises(OSError):
            os.fstat(capability_fd)
        with self.assertRaises(TypeError):
            auxiliary_index.inspect_snapshot(
                object(),
                expected_workstream_id=self.WORKSTREAM_ID,
                expected_project_home=self.project_home,
                raw_root=self.root,
            )

    def test_missing_symlinked_or_unsafe_identity_is_typed_and_non_blocking(self) -> None:
        with self.assertRaises(auxiliary_index.AuxiliaryIndexError) as missing:
            with auxiliary_index.open_snapshot_capability(
                self.root_fd,
                self._token(),
            ):
                self.fail("a missing snapshot cannot yield a capability")
        self.assertEqual(missing.exception.reason_code, "AUXILIARY_MISSING")
        self.assertFalse(missing.exception.blocks_authority)

        real_snapshot = self.snapshot.with_name("real-snapshot.md")
        real_snapshot.write_bytes(self._document())
        real_snapshot.chmod(0o644)
        self.snapshot.symlink_to(real_snapshot)
        with self.assertRaises(auxiliary_index.AuxiliaryIndexError) as symlink:
            with auxiliary_index.open_snapshot_capability(
                self.root_fd,
                self._token(),
            ):
                self.fail("a symlink cannot yield a capability")
        self.assertEqual(symlink.exception.reason_code, "AUXILIARY_UNSAFE")
        self.assertFalse(symlink.exception.blocks_authority)
        self.snapshot.unlink()

        unsafe_cases = ("hard-link", "group-writable", "wrong-owner")
        for case in unsafe_cases:
            with self.subTest(case=case):
                self._write(self._document())
                patcher = mock.patch.object(auxiliary_index.os, "getuid")
                uid_patch = None
                if case == "hard-link":
                    os.link(self.snapshot, self.snapshot.with_name("snapshot-copy.md"))
                elif case == "group-writable":
                    self.snapshot.chmod(0o664)
                else:
                    current_uid = os.getuid()
                    uid_patch = patcher.start()
                    uid_patch.return_value = current_uid + 1
                try:
                    with self.assertRaises(auxiliary_index.AuxiliaryIndexError) as error:
                        with auxiliary_index.open_snapshot_capability(
                            self.root_fd,
                            self._token(),
                        ):
                            self.fail("unsafe identity cannot yield a capability")
                    self.assertEqual(error.exception.reason_code, "AUXILIARY_UNSAFE")
                    self.assertFalse(error.exception.blocks_authority)
                finally:
                    if uid_patch is not None:
                        patcher.stop()
                    extra_link = self.snapshot.with_name("snapshot-copy.md")
                    if extra_link.exists():
                        extra_link.unlink()
        os.fstat(self.root_fd)

    def test_strict_yaml_duplicate_is_ambiguous_and_other_bad_shapes_malformed(
        self,
    ) -> None:
        duplicate = self._single_finding(
            self._document(extra_frontmatter=b"schema_version: 2\n")
        )
        self.assertEqual(duplicate.reason_code, "AUXILIARY_AMBIGUOUS")

        malformed_fragments = (
            b"alias: *shared\n",
            b"merge:\n  <<: *shared\n",
            b"multiline: |\n  forbidden\n",
            b"unknown_top_level: value\n",
        )
        for fragment in malformed_fragments:
            with self.subTest(fragment=fragment):
                finding = self._single_finding(
                    self._document(extra_frontmatter=fragment)
                )
                self.assertEqual(finding.reason_code, "AUXILIARY_MALFORMED")
                self.assertIsNone(finding.observed_value)

        wrong_scalar = self._single_finding(
            self._document().replace(b"schema_version: 1", b'schema_version: "1"')
        )
        self.assertEqual(wrong_scalar.reason_code, "AUXILIARY_MALFORMED")
        self.assertIsNone(wrong_scalar.observed_value)

    def test_overlong_line_stops_at_the_exact_8192_byte_limit(self) -> None:
        payload = b"---\nvalue: \"" + (b"x" * 9000) + b"\"\n---\nbody\n"
        self._write(payload)

        with auxiliary_index.open_snapshot_capability(
            self.root_fd,
            self._token(),
        ) as capability:
            inspection = auxiliary_index.inspect_snapshot(
                capability,
                expected_workstream_id=self.WORKSTREAM_ID,
                expected_project_home=self.project_home,
                raw_root=self.root,
            )
            offset = os.lseek(capability.file_descriptor, 0, os.SEEK_CUR)

        self.assertEqual(auxiliary_index.MAX_FRONTMATTER_BYTES, 8192)
        self.assertEqual(inspection.metadata_bytes_used, 8192)
        self.assertTrue(inspection.truncated)
        self.assertEqual(offset, 8192)
        self.assertEqual(
            tuple(item.reason_code for item in inspection.findings),
            ("AUXILIARY_LIMIT_EXCEEDED",),
        )
        self.assertTrue(inspection.findings[0].requires_manual_review)

    def test_mismatch_and_freshness_findings_are_bounded_and_non_authoritative(
        self,
    ) -> None:
        id_finding = self._single_finding(
            self._document(workstream_id="other-workstream")
        )
        self.assertEqual(id_finding.reason_code, "AUXILIARY_ID_MISMATCH")
        self.assertEqual(id_finding.field, "workspace.slug")
        self.assertEqual(id_finding.authority_value, self.WORKSTREAM_ID)
        self.assertEqual(id_finding.observed_value, "other-workstream")

        other_project = self.root / "projects" / "other-project"
        root_finding = self._single_finding(
            self._document(project_home=other_project)
        )
        self.assertEqual(root_finding.reason_code, "AUXILIARY_ROOT_MISMATCH")
        self.assertEqual(root_finding.field, "workspace.root")
        self.assertEqual(
            root_finding.authority_value,
            "projects/example-completed-workstream",
        )
        self.assertEqual(root_finding.observed_value, "projects/other-project")

        outside = Path("/outside/raw/private-project")
        outside_finding = self._single_finding(
            self._document(project_home=outside)
        )
        self.assertEqual(outside_finding.reason_code, "AUXILIARY_ROOT_MISMATCH")
        self.assertIsNone(outside_finding.observed_value)
        self.assertNotIn(str(outside), repr(outside_finding))

        for timestamp in (None, "not-a-timestamp"):
            with self.subTest(timestamp=timestamp):
                finding = self._single_finding(
                    self._document(updated_at=timestamp)
                )
                self.assertEqual(
                    finding.reason_code,
                    "AUXILIARY_FRESHNESS_MISSING",
                )
                self.assertEqual(finding.field, "updated_at")


if __name__ == "__main__":
    unittest.main()
