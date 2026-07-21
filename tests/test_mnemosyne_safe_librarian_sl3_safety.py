import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import safety  # noqa: E402
from mnemosyne_core.authority_runtime import librarian, librarian_snapshot  # noqa: E402


class PlacementSafetyError(Exception):
    pass


class SafeLibrarianSl3RenameSafetyTest(unittest.TestCase):
    def test_existing_target_parent_mode_never_creates_a_missing_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source_parent = root / "source"
            source_parent.mkdir(mode=0o700)
            source = source_parent / "note.md"
            source_bytes = b"must remain at source\n"
            source.write_bytes(source_bytes)
            source.chmod(0o600)
            target = root / "missing" / "nested" / "note.md"

            with self.assertRaisesRegex(
                PlacementSafetyError,
                "cannot open verified target parent",
            ):
                safety.rename_path_no_replace(
                    source,
                    target,
                    collision_error="target already exists",
                    require_directory=False,
                    create_target_parent=False,
                    error_type=PlacementSafetyError,
                )

            self.assertEqual(source.read_bytes(), source_bytes)
            self.assertFalse(target.parent.exists())

    def test_default_mode_preserves_target_parent_creation_for_existing_callers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source_parent = root / "source"
            source_parent.mkdir(mode=0o700)
            source = source_parent / "note.md"
            source_bytes = b"legacy-compatible move\n"
            source.write_bytes(source_bytes)
            source.chmod(0o600)
            target = root / "created" / "nested" / "note.md"

            safety.rename_path_no_replace(
                source,
                target,
                collision_error="target already exists",
                require_directory=False,
                error_type=PlacementSafetyError,
            )

            self.assertFalse(source.exists())
            self.assertEqual(target.read_bytes(), source_bytes)


class SafeLibrarianSl3PlacementObservationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        self.inbox = self.root / "inbox"
        self.inbox.mkdir(mode=0o700)
        self.workstream = self.root / "example-service"
        self.target_parent = self.workstream / "docs"
        self.target_parent.mkdir(parents=True, mode=0o700)
        self.policy = SimpleNamespace(
            never_touch=(),
            archive_roots=(),
            workstreams=(
                SimpleNamespace(
                    id="example-service",
                    lifecycle="active",
                    project_home=str(self.workstream),
                ),
            ),
            categories=(),
        )
        self.scope = {
            "proposal_id": "p-60000000000000000000000000000001",
            "source_relative_path": "inbox/note.md",
            "target_relative_path": "example-service/docs/note.md",
        }
        self.bounds = {
            "max_entries": 16,
            "max_depth": 4,
            "max_total_bytes": 4096,
        }
        self.payload = {
            "destination_kind": "workstream",
            "destination_id": "example-service",
            "reason": "The exact note belongs to the active Workstream.",
        }

    def test_category_owner_precedes_nested_active_workstream(self) -> None:
        project = self.root / "projects" / "example-service"
        paused_project = self.root / "projects" / "paused-scanner"
        target_parent = project / "docs"
        target_parent.mkdir(parents=True, mode=0o700)
        paused_project.mkdir(mode=0o700)
        source = self.inbox / "category-note.md"
        source.write_bytes(b"# Category-owned note\n")
        source.chmod(0o600)
        policy = SimpleNamespace(
            never_touch=(),
            archive_roots=(),
            workstreams=(
                SimpleNamespace(
                    id="example-service",
                    lifecycle="active",
                    project_home=str(project),
                ),
                SimpleNamespace(
                    id="paused-scanner",
                    lifecycle="paused",
                    project_home=str(paused_project),
                ),
            ),
            categories=(
                SimpleNamespace(
                    id="projects",
                    target=str(self.root / "projects"),
                ),
            ),
        )
        scope = {
            "proposal_id": "p-60000000000000000000000000000003",
            "source_relative_path": "inbox/category-note.md",
            "target_relative_path": "projects/example-service/docs/category-note.md",
        }
        with self.assertRaises(librarian_snapshot.LibrarianSnapshotError) as raised:
            librarian_snapshot.observe_proposal(
                self.root,
                policy,
                scope,
                self.bounds,
                {
                    "destination_kind": "workstream",
                    "destination_id": "example-service",
                    "reason": "The target is nested under this active Workstream.",
                },
            )
        self.assertEqual(raised.exception.reason_code, "DESTINATION_INVALID")

        try:
            observed = librarian_snapshot.observe_proposal(
                self.root,
                policy,
                scope,
                self.bounds,
                {
                    "destination_kind": "manual_category",
                    "destination_id": "projects",
                    "reason": "The category owns targets beneath the projects root.",
                },
            )
        except librarian_snapshot.LibrarianSnapshotError as exc:
            self.fail(
                "manual_category/projects must own the overlapping target, got "
                + exc.reason_code
            )

        self.assertEqual(
            observed["target_absent"]["relative_path"],
            "projects/example-service/docs/category-note.md",
        )

    def test_category_target_inside_inactive_sibling_remains_blocked(self) -> None:
        active_project = self.root / "projects" / "example-service"
        paused_project = self.root / "projects" / "paused-scanner"
        active_project.mkdir(parents=True, mode=0o700)
        target_parent = paused_project / "docs"
        target_parent.mkdir(parents=True, mode=0o700)
        source = self.inbox / "paused-note.md"
        source.write_bytes(b"# Paused note\n")
        source.chmod(0o600)
        policy = SimpleNamespace(
            never_touch=(),
            archive_roots=(),
            workstreams=(
                SimpleNamespace(
                    id="example-service",
                    lifecycle="active",
                    project_home=str(active_project),
                ),
                SimpleNamespace(
                    id="paused-scanner",
                    lifecycle="paused",
                    project_home=str(paused_project),
                ),
            ),
            categories=(
                SimpleNamespace(
                    id="projects",
                    target=str(self.root / "projects"),
                ),
            ),
        )

        with self.assertRaises(librarian_snapshot.LibrarianSnapshotError) as raised:
            librarian_snapshot.observe_proposal(
                self.root,
                policy,
                {
                    "proposal_id": "p-60000000000000000000000000000004",
                    "source_relative_path": "inbox/paused-note.md",
                    "target_relative_path": "projects/paused-scanner/docs/paused-note.md",
                },
                self.bounds,
                {
                    "destination_kind": "manual_category",
                    "destination_id": "projects",
                    "reason": "This target is inside the paused sibling.",
                },
            )

        self.assertEqual(raised.exception.reason_code, "WORKSTREAM_INACTIVE")

    def test_directory_source_containing_inactive_workstream_is_blocked(self) -> None:
        source = self.inbox / "bundle"
        paused_project = source / "paused-scanner"
        paused_project.mkdir(parents=True, mode=0o700)
        (paused_project / "note.md").write_bytes(b"# Frozen subtree\n")
        active_project = self.root / "projects" / "example-service"
        active_project.mkdir(parents=True, mode=0o700)
        target_parent = self.root / "projects" / "drop"
        target_parent.mkdir(mode=0o700)
        policy = SimpleNamespace(
            never_touch=(),
            archive_roots=(),
            workstreams=(
                SimpleNamespace(
                    id="example-service",
                    lifecycle="active",
                    project_home=str(active_project),
                ),
                SimpleNamespace(
                    id="paused-scanner",
                    lifecycle="paused",
                    project_home=str(paused_project),
                ),
            ),
            categories=(
                SimpleNamespace(
                    id="projects",
                    target=str(self.root / "projects"),
                ),
            ),
        )

        with self.assertRaises(librarian_snapshot.LibrarianSnapshotError) as raised:
            librarian_snapshot.observe_proposal(
                self.root,
                policy,
                {
                    "proposal_id": "p-60000000000000000000000000000005",
                    "source_relative_path": "inbox/bundle",
                    "target_relative_path": "projects/drop/bundle",
                },
                self.bounds,
                {
                    "destination_kind": "manual_category",
                    "destination_id": "projects",
                    "reason": "The bundle otherwise belongs to the projects category.",
                },
            )

        self.assertEqual(raised.exception.reason_code, "WORKSTREAM_INACTIVE")

    def test_scope_inspection_reports_category_owner_before_nested_workstream(
        self,
    ) -> None:
        project = self.root / "projects" / "example-service"
        scope_directory = project / "docs"
        scope_directory.mkdir(parents=True, mode=0o700)
        (scope_directory / "category-note.md").write_bytes(
            b"# Category-owned note\n"
        )
        policy = SimpleNamespace(
            never_touch=(),
            archive_roots=(),
            workstreams=(
                SimpleNamespace(
                    id="example-service",
                    lifecycle="active",
                    project_home=str(project),
                ),
            ),
            categories=(
                SimpleNamespace(
                    id="projects",
                    target=str(self.root / "projects"),
                ),
            ),
        )

        result = librarian.inspect_scope(
            root=self.root,
            compiled_policy=policy,
            relative_path="projects/example-service/docs",
            max_items=8,
            max_depth=2,
            max_hint_bytes=1024,
        )

        item = next(
            row
            for row in result["organized"]
            if row["relative_path"]
            == "projects/example-service/docs/category-note.md"
        )
        self.assertEqual(
            {
                "destination_kind": item["destination_kind"],
                "destination_id": item["destination_id"],
            },
            {
                "destination_kind": "manual_category",
                "destination_id": "projects",
            },
        )

    def test_pre_move_verification_matches_the_exact_proposal_observation(self) -> None:
        source = self.inbox / "note.md"
        source_bytes = b"# Exact note\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.target_parent / "note.md"
        expected = librarian_snapshot.observe_proposal(
            self.root,
            self.policy,
            self.scope,
            self.bounds,
            self.payload,
        )

        observed = librarian_snapshot.verify_placement_pre_move(
            root=self.root,
            compiled_policy=self.policy,
            scope=self.scope,
            bounds=self.bounds,
            payload=self.payload,
            expected_observation=expected,
        )

        self.assertEqual(observed, expected)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse(target.exists())

    def test_post_move_verification_proves_source_absence_and_exact_target_file(self) -> None:
        source = self.inbox / "note.md"
        source_bytes = b"# Exact note\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.target_parent / "note.md"
        expected = librarian_snapshot.observe_proposal(
            self.root,
            self.policy,
            self.scope,
            self.bounds,
            self.payload,
        )
        safety.rename_path_no_replace(
            source,
            target,
            collision_error="target already exists",
            require_directory=False,
            expected_source_identity=safety.source_identity(source.stat()),
            create_target_parent=False,
            error_type=PlacementSafetyError,
        )

        observed = librarian_snapshot.verify_placement_post_move(
            root=self.root,
            compiled_policy=self.policy,
            scope=self.scope,
            bounds=self.bounds,
            payload=self.payload,
            expected_observation=expected,
        )

        self.assertEqual(
            observed["source_absent"],
            {
                "observed_absent": True,
                "relative_path": "inbox/note.md",
                "parent": expected["source_snapshot"]["parent"],
            },
        )
        target_snapshot = observed["target_snapshot"]
        self.assertEqual(target_snapshot["kind"], "regular_file")
        self.assertEqual(
            target_snapshot["relative_path"],
            "example-service/docs/note.md",
        )
        self.assertEqual(
            target_snapshot["content_sha256"],
            hashlib.sha256(source_bytes).hexdigest(),
        )
        self.assertEqual(
            (target_snapshot["device"], target_snapshot["inode"]),
            (
                expected["source_snapshot"]["device"],
                expected["source_snapshot"]["inode"],
            ),
        )
        self.assertNotIn("content", target_snapshot)
        self.assertNotIn("body", target_snapshot)
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), source_bytes)

    def test_pre_move_verification_rejects_changed_source_evidence(self) -> None:
        source = self.inbox / "note.md"
        source.write_bytes(b"original\n")
        source.chmod(0o600)
        expected = librarian_snapshot.observe_proposal(
            self.root,
            self.policy,
            self.scope,
            self.bounds,
            self.payload,
        )
        source.write_bytes(b"changed\n")
        source.chmod(0o600)

        with self.assertRaises(librarian_snapshot.LibrarianSnapshotError) as raised:
            librarian_snapshot.verify_placement_pre_move(
                root=self.root,
                compiled_policy=self.policy,
                scope=self.scope,
                bounds=self.bounds,
                payload=self.payload,
                expected_observation=expected,
            )

        self.assertEqual(raised.exception.reason_code, "SOURCE_CHANGED")
        self.assertEqual(raised.exception.next_safe_action, "create-proposal")
        self.assertEqual(source.read_bytes(), b"changed\n")
        self.assertFalse((self.target_parent / "note.md").exists())

    def test_pre_move_verification_rejects_replaced_target_parent(self) -> None:
        source = self.inbox / "note.md"
        source_bytes = b"parent-bound\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        expected = librarian_snapshot.observe_proposal(
            self.root,
            self.policy,
            self.scope,
            self.bounds,
            self.payload,
        )
        displaced = self.workstream / "docs-original"
        self.target_parent.rename(displaced)
        self.target_parent.mkdir(mode=0o700)

        with self.assertRaises(librarian_snapshot.LibrarianSnapshotError) as raised:
            librarian_snapshot.verify_placement_pre_move(
                root=self.root,
                compiled_policy=self.policy,
                scope=self.scope,
                bounds=self.bounds,
                payload=self.payload,
                expected_observation=expected,
            )

        self.assertEqual(raised.exception.reason_code, "SOURCE_CHANGED")
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertFalse((self.target_parent / "note.md").exists())
        self.assertFalse((displaced / "note.md").exists())

    def test_post_move_verification_rejects_changed_target_as_recovery_required(self) -> None:
        source = self.inbox / "note.md"
        source.write_bytes(b"approved\n")
        source.chmod(0o600)
        target = self.target_parent / "note.md"
        expected = librarian_snapshot.observe_proposal(
            self.root,
            self.policy,
            self.scope,
            self.bounds,
            self.payload,
        )
        safety.rename_path_no_replace(
            source,
            target,
            collision_error="target already exists",
            require_directory=False,
            expected_source_identity=safety.source_identity(source.stat()),
            create_target_parent=False,
            error_type=PlacementSafetyError,
        )
        target.write_bytes(b"changed after move\n")
        target.chmod(0o600)

        with self.assertRaises(librarian_snapshot.LibrarianSnapshotError) as raised:
            librarian_snapshot.verify_placement_post_move(
                root=self.root,
                compiled_policy=self.policy,
                scope=self.scope,
                bounds=self.bounds,
                payload=self.payload,
                expected_observation=expected,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "PLACEMENT_RECOVERY_REQUIRED",
        )
        self.assertEqual(raised.exception.next_safe_action, "inspect-recovery")
        self.assertFalse(source.exists())
        self.assertEqual(target.read_bytes(), b"changed after move\n")

    def test_post_move_verification_rejects_a_source_that_still_exists(self) -> None:
        source = self.inbox / "note.md"
        source_bytes = b"must move, not copy\n"
        source.write_bytes(source_bytes)
        source.chmod(0o600)
        target = self.target_parent / "note.md"
        expected = librarian_snapshot.observe_proposal(
            self.root,
            self.policy,
            self.scope,
            self.bounds,
            self.payload,
        )
        target.write_bytes(source_bytes)
        target.chmod(0o600)

        with self.assertRaises(librarian_snapshot.LibrarianSnapshotError) as raised:
            librarian_snapshot.verify_placement_post_move(
                root=self.root,
                compiled_policy=self.policy,
                scope=self.scope,
                bounds=self.bounds,
                payload=self.payload,
                expected_observation=expected,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "PLACEMENT_RECOVERY_REQUIRED",
        )
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual(target.read_bytes(), source_bytes)

    def test_post_move_verification_proves_exact_directory_manifest(self) -> None:
        source = self.inbox / "bundle"
        nested = source / "nested"
        nested.mkdir(parents=True, mode=0o700)
        first = source / "a.md"
        second = nested / "b.md"
        first_bytes = b"A\n"
        second_bytes = b"B\n"
        first.write_bytes(first_bytes)
        second.write_bytes(second_bytes)
        first.chmod(0o600)
        second.chmod(0o600)
        target = self.target_parent / "bundle"
        scope = dict(self.scope)
        scope.update(
            {
                "proposal_id": "p-60000000000000000000000000000002",
                "source_relative_path": "inbox/bundle",
                "target_relative_path": "example-service/docs/bundle",
            }
        )
        expected = librarian_snapshot.observe_proposal(
            self.root,
            self.policy,
            scope,
            self.bounds,
            self.payload,
        )
        safety.rename_path_no_replace(
            source,
            target,
            collision_error="target already exists",
            require_directory=True,
            expected_source_identity=safety.source_identity(source.stat()),
            create_target_parent=False,
            error_type=PlacementSafetyError,
        )

        observed = librarian_snapshot.verify_placement_post_move(
            root=self.root,
            compiled_policy=self.policy,
            scope=scope,
            bounds=self.bounds,
            payload=self.payload,
            expected_observation=expected,
        )

        target_snapshot = observed["target_snapshot"]
        self.assertEqual(target_snapshot["kind"], "directory")
        self.assertEqual(target_snapshot["entry_count"], 3)
        self.assertEqual(target_snapshot["file_count"], 2)
        self.assertEqual(target_snapshot["total_bytes"], 4)
        self.assertEqual(
            target_snapshot["manifest_sha256"],
            expected["source_snapshot"]["manifest_sha256"],
        )
        self.assertNotIn("manifest", target_snapshot)
        self.assertFalse(source.exists())
        self.assertEqual((target / "a.md").read_bytes(), first_bytes)
        self.assertEqual((target / "nested" / "b.md").read_bytes(), second_bytes)


if __name__ == "__main__":
    unittest.main()
