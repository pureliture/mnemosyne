import json
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import inventory  # noqa: E402


def active_scope():
    return inventory.ScopeDecision(
        rule_id="active-workstream-content",
        scope_class="eligible",
        traversal="full",
        lifecycle="active",
        content_inspection="bounded-text",
    )


def metadata_scope(rule_id="fallback-unassigned", scope_class="unassigned-intake"):
    return inventory.ScopeDecision(
        rule_id=rule_id,
        scope_class=scope_class,
        traversal="metadata-only",
        lifecycle="unassigned",
        content_inspection="none",
    )


def request(run_id="run-001"):
    return inventory.InventoryRunRequest.create(
        run_id=run_id,
        policy_authority={
            "generation": 1,
            "source_kind": "INITIAL",
            "full_hash": "a" * 64,
            "guard_epoch": 0,
        },
        scope={"kind": "root", "root_identity": "temp-root"},
        bounds={"max_entries": 100, "max_file_bytes": 4096},
        expected_artifacts=("coverage.json", "observations.jsonl"),
    )


ROOT_CURSOR = inventory.canonical_raw_path(())


def chunk_payload(before=ROOT_CURSOR, after=None, items=None, source_identities=None):
    if after is None:
        after = inventory.canonical_raw_path((b"next",))
    return {
        "cursor_before": before,
        "cursor_after": after,
        "items": [] if items is None else items,
        "source_identities": [] if source_identities is None else source_identities,
    }


def checkpoint_payload(next_cursor=None, observations=1, content_bytes=0):
    if next_cursor is None:
        next_cursor = inventory.canonical_raw_path((b"next",))
    return {
        "next_cursor": next_cursor,
        "counters": {
            "observations": observations,
            "content_bytes": content_bytes,
        },
    }


class ScopeInputTest(unittest.TestCase):
    def test_scope_input_cannot_turn_restrictive_rules_into_content_authority(self):
        forbidden_cases = (
            ("paused-completed", "coverage-only", "paused"),
            ("paused-completed", "coverage-only", "completed"),
            ("private-reviewable", "private-reviewable", "active"),
            ("opaque-evidence", "opaque", "active"),
            ("protected", "protected", "active"),
            ("control", "control", "active"),
        )
        for rule_id, scope_class, lifecycle in forbidden_cases:
            with self.subTest(rule_id=rule_id, lifecycle=lifecycle):
                with self.assertRaises(inventory.ScopeInputError):
                    inventory.ScopeDecision(
                        rule_id=rule_id,
                        scope_class=scope_class,
                        traversal="full",
                        lifecycle=lifecycle,
                        content_inspection="bounded-text",
                    )

    def test_scope_map_is_prefix_deterministic_and_immutable(self):
        scope_map = inventory.ScopeMap.create(
            default=metadata_scope(),
            bindings=(((b"projects", b"active"), active_scope()),),
        )
        self.assertEqual(
            scope_map.decision_for((b"projects", b"active", b"README.md")),
            active_scope(),
        )
        with self.assertRaises(AttributeError):
            scope_map.bindings = ()

    def test_unassigned_parent_allows_active_child_but_hard_parent_does_not(self):
        active_path = (b"projects", b"active", b"README.md")
        routed = inventory.ScopeMap.create(
            default=metadata_scope(),
            bindings=(
                ((b"projects",), metadata_scope()),
                ((b"projects", b"active"), active_scope()),
            ),
        )
        self.assertEqual(routed.decision_for(active_path), active_scope())

        paused = inventory.ScopeDecision(
            rule_id="paused-completed",
            scope_class="coverage-only",
            traversal="directory-count-only",
            lifecycle="paused",
            content_inspection="none",
        )
        restricted = inventory.ScopeMap.create(
            default=metadata_scope(),
            bindings=(
                ((b"projects",), paused),
                ((b"projects", b"active"), active_scope()),
            ),
        )
        self.assertEqual(restricted.decision_for(active_path), paused)

    def test_scope_decision_is_a_canonical_positive_allowlist_not_free_form(self):
        invalid = (
            dict(
                rule_id="typo-active",
                scope_class="eligible",
                traversal="metadata-only",
                lifecycle="active",
                content_inspection="none",
            ),
            dict(
                rule_id="active-workstream-content",
                scope_class="eligible",
                traversal="metadata-only",
                lifecycle="active",
                content_inspection="none",
            ),
            dict(
                rule_id="fallback-unassigned",
                scope_class="new-unknown-class",
                traversal="metadata-only",
                lifecycle="unassigned",
                content_inspection="none",
            ),
            dict(
                rule_id="opaque-evidence",
                scope_class="eligible",
                traversal="full",
                lifecycle="active",
                content_inspection="bounded-text",
            ),
            dict(
                rule_id="paused-completed",
                scope_class="eligible",
                traversal="full",
                lifecycle="active",
                content_inspection="bounded-text",
            ),
            dict(
                rule_id="active-workstream-content",
                scope_class="eligible",
                traversal="full",
                lifecycle="unknown",
                content_inspection="bounded-text",
            ),
        )
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(inventory.ScopeInputError):
                    inventory.ScopeDecision(**values)

    def test_physical_restrictions_precede_permissive_routes_case_insensitively(self):
        active = active_scope()
        scope_map = inventory.ScopeMap.create(
            default=metadata_scope(),
            bindings=(
                ((b"MeMoRy",), active),
                ((b"MeMoRy", b"nested", b"active"), active),
                ((b"MiRrOrS",), active),
                ((b"PrIvAtE",), active),
                ((b"_InDeX", b"MeMoRy"), active),
                ((b"sensitive-cleanup-audit",), active),
            ),
        )
        cases = {
            (b"MeMoRy", b"notes.md"): ("memory", "metadata-only"),
            (b"MeMoRy", b"nested", b"active", b"notes.md"): (
                "memory",
                "metadata-only",
            ),
            (b"MeMoRy", b"WoRkSpAcEs.YmL"): ("control", "not-entered"),
            (b"MiRrOrS", b"repo.md"): ("mirror", "metadata-only"),
            (b"PrIvAtE", b"note.md"): ("private-reviewable", "metadata-only"),
            (b"_InDeX", b"MeMoRy", b"old.md"): (
                "coverage-only",
                "directory-count-only",
            ),
            (b"sensitive-cleanup-audit", b"evidence.md"): (
                "opaque-private-evidence",
                "metadata-only",
            ),
            (b"projects", b".GiT", b"config"): ("never-touch", "not-entered"),
            (b"_ReGiStRy", b"placement-map.yml"): ("control", "not-entered"),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                decision = scope_map.decision_for(path)
                self.assertEqual((decision.scope_class, decision.traversal), expected)

    def test_bounds_json_and_reserved_names_fail_closed_on_edge_values(self):
        for field in (
            "max_entries",
            "max_direct_entries",
            "max_depth",
            "max_file_bytes",
            "max_content_bytes",
        ):
            values = {field: True}
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    inventory.TraversalBounds(**values)
        with self.assertRaises(ValueError):
            inventory.TextPolicy(max_json_bytes=True)
        with self.assertRaises(ValueError):
            inventory.InventoryRunRequest.create(
                run_id="bool-request-bound",
                policy_authority={},
                scope={},
                bounds={"max_entries": True},
                expected_artifacts=("coverage.json",),
            )
        with self.assertRaises(ValueError):
            inventory._canonical_json_bytes({"not_finite": float("nan")})
        with self.assertRaises(ValueError):
            request("FaIlEd")
        with self.assertRaises(ValueError):
            inventory.InventoryRunRequest.create(
                run_id="reserved-artifact-case",
                policy_authority={},
                scope={},
                bounds={},
                expected_artifacts=("RUN.JSON",),
            )

    def test_public_constructors_cannot_bypass_factory_invariants(self):
        with self.assertRaises(inventory.ScopeInputError):
            inventory.ScopeMap(
                default=metadata_scope(),
                bindings=[],
                never_touch=(),
            )
        with self.assertRaises(inventory.ScopeInputError):
            inventory.ScopeMap(
                default=metadata_scope(),
                bindings=(((b"active",), active_scope()),),
                never_touch=(),
            )
        with self.assertRaises(ValueError):
            inventory.InventoryRunRequest(
                run_id="forged-request",
                canonical_bytes=b"{}\n",
                sha256="0" * 64,
                expected_artifacts=(),
            )
        with self.assertRaises(ValueError):
            inventory.InventoryRunRequest.create(
                run_id="non-mapping-request",
                policy_authority=[],
                scope={},
                bounds={"max_entries": 1},
                expected_artifacts=("coverage.json",),
            )

    def test_expected_artifact_names_cannot_collide_after_casefold(self):
        with self.assertRaises(ValueError):
            inventory.InventoryRunRequest.create(
                run_id="artifact-casefold-collision",
                policy_authority={},
                scope={},
                bounds={"max_entries": 1},
                expected_artifacts=("Coverage.json", "coverage.json"),
            )


class InventoryTraversalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temp.name) / "raw-root"
        self.root.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def test_raw_filename_encoding_is_reversible_and_json_safe(self):
        components = (b"ordinary", b"bad-\xff-name")
        encoded = inventory.canonical_raw_path(components)
        self.assertEqual(inventory.decode_canonical_raw_path(encoded), components)
        self.assertEqual(encoded, inventory.canonical_raw_path(components))
        json.dumps({"path": encoded}).encode("utf-8")
        self.assertEqual(
            inventory.display_raw_path(("a\u202eb".encode("utf-8"),)),
            "a\\u202eb",
        )

    def test_componentwise_root_open_rejects_an_intermediate_symlink(self):
        real_parent = Path(self.temp.name) / "real-parent"
        real_root = real_parent / "raw"
        real_root.mkdir(parents=True)
        linked_parent = Path(self.temp.name) / "linked-parent"
        os.symlink(real_parent, linked_parent)
        with self.assertRaises(inventory.InventorySafetyError):
            inventory.InventoryEngine(
                linked_parent / "raw",
                inventory.ScopeMap.create(default=metadata_scope()),
                inventory.TraversalBounds(),
            ).scan("scan-symlink-root")

    def test_scan_never_enters_self_output_never_touch_symlink_or_special(self):
        active = self.root / "projects" / "active"
        active.mkdir(parents=True)
        (active / "README.md").write_text("safe text", encoding="utf-8")

        self_output = self.root / "_registry" / "curation-runs" / "old-run"
        self_output.mkdir(parents=True)
        (self_output / "must-not-see.md").write_text("secret", encoding="utf-8")

        graph = self.root / "graphify-out"
        graph.mkdir()
        (graph / "must-not-see.md").write_text("secret", encoding="utf-8")
        nested_git = active / "nested" / ".git"
        nested_git.mkdir(parents=True)
        (nested_git / "must-not-see.md").write_text("secret", encoding="utf-8")
        nested_agents = active / "nested" / ".agents"
        nested_agents.mkdir()
        (nested_agents / "must-not-see.md").write_text("secret", encoding="utf-8")

        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside secret", encoding="utf-8")
        os.symlink(outside, active / "outside-link")
        os.mkfifo(active / "pipe")

        scope_map = inventory.ScopeMap.create(
            default=metadata_scope(),
            bindings=(((b"projects", b"active"), active_scope()),),
        )
        result = inventory.InventoryEngine(
            self.root,
            scope_map,
            inventory.TraversalBounds(
                max_entries=100,
                max_depth=16,
                max_file_bytes=1024,
                max_content_bytes=4096,
            ),
        ).scan("scan-001")

        by_display = {row.display_path: row for row in result.observations}
        self.assertTrue(by_display["projects/active/README.md"].content_inspected)
        self.assertEqual(by_display["projects/active/outside-link"].kind, "symlink")
        self.assertEqual(by_display["projects/active/pipe"].kind, "special")
        self.assertEqual(by_display["graphify-out"].traversal, "not-entered")
        self.assertEqual(by_display["graphify-out"].excluded_reason, "never-touch")
        self.assertEqual(
            by_display["_registry"].excluded_reason,
            "control",
        )
        self.assertEqual(by_display["projects/active/nested/.git"].excluded_reason, "never-touch")
        self.assertEqual(by_display["projects/active/nested/.agents"].excluded_reason, "never-touch")
        self.assertNotIn("graphify-out/must-not-see.md", by_display)
        self.assertNotIn("_registry/curation-runs", by_display)
        self.assertNotIn("_registry/curation-runs/old-run", by_display)
        self.assertNotIn("projects/active/nested/.git/must-not-see.md", by_display)
        self.assertNotIn("projects/active/nested/.agents/must-not-see.md", by_display)
        self.assertNotIn("outside secret", repr(result.observations))

        self.assertNotEqual(
            result.coverage["folders"]["denominator"],
            result.coverage["files"]["denominator"],
        )
        self.assertEqual(result.coverage["state"], "explained-partial")
        self.assertEqual(result.coverage["partial_reasons"]["never-touch"], 3)
        self.assertEqual(result.coverage["partial_reasons"]["control"], 1)
        self.assertFalse(result.coverage["prework_eligible"])
        self.assertIn("eligible", result.coverage["by_scope"])

    def test_content_read_stays_on_open_traversal_parent_during_lexical_swap(self):
        active = self.root / "active"
        active.mkdir()
        original = b"original bytes"
        alternate = b"alternate bytes"
        (active / "README.md").write_bytes(original)
        swapped = {"done": False}

        def checkpoint(event, _path):
            if event != "content-before-open" or swapped["done"]:
                return
            swapped["done"] = True
            active.rename(self.root / "active-original")
            active.mkdir()
            (active / "README.md").write_bytes(alternate)

        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(
                default=metadata_scope(),
                bindings=(((b"active",), active_scope()),),
            ),
            inventory.TraversalBounds(),
            fault_checkpoint=checkpoint,
        ).scan("scan-parent-swap")
        row = next(item for item in result.observations if item.display_path == "active/README.md")
        self.assertTrue(row.content_inspected)
        self.assertEqual(row.fingerprint_value, hashlib.sha256(original).hexdigest())
        self.assertNotEqual(row.fingerprint_value, hashlib.sha256(alternate).hexdigest())
        self.assertIn("directory-race", result.observations[0].errors)

    def test_bounded_text_seals_only_safe_internal_reference_projection_v2(self):
        active = self.root / "projects" / "alpha" / "docs"
        active.mkdir(parents=True)
        source = active / "README.md"
        source.write_text(
            "# Alpha guide\nsecret prose [guide](../shared/guide.md#install) "
            "[external](https://example.com/private?q=1)",
            encoding="utf-8",
        )
        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(
                default=metadata_scope(),
                bindings=(((b"projects", b"alpha"), active_scope()),),
            ),
            inventory.TraversalBounds(),
        ).scan("scan-reference-projection")

        row = next(
            item for item in result.observations if item.display_path.endswith("README.md")
        )
        serialized = row.to_dict()
        self.assertEqual(serialized["schema_version"], 2)
        self.assertEqual(
            serialized["classification_projection"]["title"],
            "Alpha guide",
        )
        self.assertEqual(
            serialized["reference_projection"]["references"],
            [
                {
                    "kind": "markdown-inline",
                    "target": inventory.canonical_raw_path(
                        (b"projects", b"alpha", b"shared", b"guide.md")
                    ),
                }
            ],
        )
        projection_payload = {
            "parser_types": serialized["reference_projection"]["parser_types"],
            "projection_version": "internal-reference-v2",
            "references": serialized["reference_projection"]["references"],
            "source_path": row.path,
        }
        self.assertEqual(
            serialized["reference_projection"]["projection_sha256"],
            hashlib.sha256(
                inventory._canonical_json_bytes(projection_payload)
            ).hexdigest(),
        )
        sealed = result.observations_jsonl()
        self.assertNotIn(b"secret prose", sealed)
        self.assertNotIn(b"example.com", sealed)

    def test_reference_projection_declares_full_parser_coverage_and_safe_literals(self):
        projection = inventory._reference_projection(
            (b"projects", b"alpha", b"notes.md"),
            (
                "See ../shared/guide.md and `_registry/workstreams.yml`; "
                "also [index](index.md)."
            ),
        )

        self.assertEqual(
            projection.parser_types,
            (
                "generated-navigation-source",
                "html-attribute",
                "markdown-autolink",
                "markdown-inline",
                "markdown-reference",
                "registry-path",
                "safe-path-literal",
            ),
        )
        self.assertEqual(
            {(row.kind, row.target) for row in projection.references},
            {
                (
                    "markdown-inline",
                    inventory.canonical_raw_path(
                        (b"projects", b"alpha", b"index.md")
                    ),
                ),
                (
                    "safe-path-literal",
                    inventory.canonical_raw_path(
                        (b"projects", b"shared", b"guide.md")
                    ),
                ),
                (
                    "registry-path",
                    inventory.canonical_raw_path(
                        (b"_registry", b"workstreams.yml")
                    ),
                ),
            },
        )

    def test_classification_projection_keeps_only_bounded_safe_structure(self):
        projection = inventory._classification_projection(
            "---\n"
            "workstream: alpha\n"
            "authority: requirements\n"
            "title: Alpha release notes\n"
            "---\n"
            "# Alpha release notes\n"
            "## Current architecture\n"
            "LEAK_SENTINEL_RAW_BODY must not be persisted.\n"
        )

        self.assertEqual(projection.title, "Alpha release notes")
        self.assertEqual(projection.headings, ("Current architecture",))
        self.assertEqual(
            projection.frontmatter,
            (("authority", "requirements"), ("workstream", "alpha")),
        )
        self.assertIn("alpha", projection.tokens)
        self.assertIn("architecture", projection.tokens)
        self.assertNotIn(
            "LEAK_SENTINEL_RAW_BODY",
            json.dumps(projection.to_dict(), sort_keys=True),
        )

    def test_reference_projection_covers_bounded_supported_reference_kinds(self):
        active = self.root / "projects" / "alpha" / "docs"
        active.mkdir(parents=True)
        (active / "README.md").write_text(
            "[guide][guide-id]\n"
            "[guide-id]: ../shared/reference.md\n"
            "<../shared/autolink.md>\n"
            '<img src="../assets/diagram.png">\n',
            encoding="utf-8",
        )
        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(
                default=metadata_scope(),
                bindings=(((b"projects", b"alpha"), active_scope()),),
            ),
            inventory.TraversalBounds(),
        ).scan("scan-reference-kinds")

        row = next(
            item for item in result.observations if item.display_path.endswith("README.md")
        )
        self.assertEqual(
            [item["kind"] for item in row.to_dict()["reference_projection"]["references"]],
            ["autolink", "html-attribute", "markdown-reference"],
        )

    def test_reference_projection_resolves_relative_target_under_non_utf8_parent(self):
        projection = inventory._reference_projection(
            (b"projects", b"\xffalpha", b"docs", b"README.md"),
            "[guide](../guide.md)",
        )

        self.assertEqual(
            projection.references,
            (
                inventory.InternalReference(
                    "markdown-inline",
                    inventory.canonical_raw_path(
                        (b"projects", b"\xffalpha", b"guide.md")
                    ),
                ),
            ),
        )

    def test_observation_v2_rejects_tampered_or_restricted_projection_evidence(self):
        projection = inventory._reference_projection(
            (b"private", b"note.md"),
            "[safe](other.md)",
        )
        with self.assertRaisesRegex(ValueError, "hash"):
            inventory.ReferenceProjection(
                source_path=projection.source_path,
                projection_version=projection.projection_version,
                projection_sha256="0" * 64,
                references=projection.references,
                parser_types=projection.parser_types,
            )
        identity = inventory.FileIdentity(
            device=1,
            inode=1,
            mode=stat.S_IFREG | 0o600,
            size=10,
            mtime_ns=1,
        )
        with self.assertRaises(ValueError):
            inventory.Observation(
                run_id="restricted-v2",
                path=projection.source_path,
                display_path="private/note.md",
                kind="file",
                physical_kind="file",
                scope_class="private-reviewable",
                scope_rule_id="private-reviewable",
                traversal="metadata-only",
                content_inspected=False,
                excluded_reason=None,
                identity=identity,
                fingerprint_kind="metadata",
                fingerprint_value=None,
                content_policy_outcome="metadata-only",
                reference_projection=projection,
            )

        classification_projection = inventory._classification_projection(
            "# Restricted title\n"
        )
        with self.assertRaises(ValueError):
            inventory.Observation(
                run_id="restricted-v2",
                path=projection.source_path,
                display_path="private/note.md",
                kind="file",
                physical_kind="file",
                scope_class="private-reviewable",
                scope_rule_id="private-reviewable",
                traversal="metadata-only",
                content_inspected=False,
                excluded_reason=None,
                identity=identity,
                fingerprint_kind="metadata",
                fingerprint_value=None,
                content_policy_outcome="metadata-only",
                classification_projection=classification_projection,
            )
        with self.assertRaisesRegex(ValueError, "restricted"):
            inventory.Observation(
                run_id="restricted-fingerprint-v2",
                path=projection.source_path,
                display_path="private/note.md",
                kind="file",
                physical_kind="file",
                scope_class="private-reviewable",
                scope_rule_id="private-reviewable",
                traversal="metadata-only",
                content_inspected=False,
                excluded_reason=None,
                identity=identity,
                fingerprint_kind="metadata",
                fingerprint_value="a" * 64,
                content_policy_outcome="metadata-only",
            )

    def test_directory_snapshot_ignores_atime_only_entry_changes(self):
        target = self.root / "atime-only.md"
        target.write_bytes(b"stable")
        changed = {"value": False}

        def checkpoint(event, path):
            if event != "directory-listed" or path != "raw-b64-v1:" or changed["value"]:
                return
            changed["value"] = True
            before = target.stat()
            os.utime(
                target,
                ns=(before.st_atime_ns + 1_000_000_000, before.st_mtime_ns),
                follow_symlinks=False,
            )

        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(default=metadata_scope()),
            inventory.TraversalBounds(),
            fault_checkpoint=checkpoint,
        ).scan("scan-atime-only")

        self.assertTrue(changed["value"])
        self.assertNotIn("directory-race", result.observations[0].errors)

    def test_direct_and_global_listing_bounds_stop_observation_growth(self):
        crowded = self.root / "crowded"
        crowded.mkdir()
        for index in range(20):
            (crowded / ("%02d.md" % index)).write_text("x", encoding="utf-8")
        scope = inventory.ScopeMap.create(default=metadata_scope())

        direct = inventory.InventoryEngine(
            self.root,
            scope,
            inventory.TraversalBounds(max_entries=100, max_direct_entries=3),
        ).scan("scan-direct-bound")
        crowded_row = next(row for row in direct.observations if row.display_path == "crowded")
        self.assertEqual(crowded_row.descendant_unknown, 17)
        self.assertIn("max-direct-entries", crowded_row.errors)
        self.assertEqual(direct.coverage["descendant_unknown"], 17)

        global_bound = inventory.InventoryEngine(
            self.root,
            scope,
            inventory.TraversalBounds(max_entries=3, max_direct_entries=20),
        ).scan("scan-global-bound")
        self.assertLessEqual(len(global_bound.observations), 3)
        self.assertGreater(global_bound.coverage["descendant_unknown"], 0)
        self.assertEqual(global_bound.coverage["state"], "explained-partial")

    def test_coverage_has_disjoint_detailed_outcomes_and_scope_partitions(self):
        (self.root / "folder").mkdir()
        (self.root / "folder" / "one.md").write_text("one", encoding="utf-8")
        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(default=metadata_scope()),
            inventory.TraversalBounds(),
        ).scan("scan-coverage-contract")
        coverage = result.coverage
        folder_outcomes = coverage["folders"]["outcomes"]
        file_outcomes = coverage["files"]["outcomes"]
        self.assertEqual(sum(folder_outcomes.values()), coverage["folders"]["denominator"])
        self.assertEqual(sum(file_outcomes.values()), coverage["files"]["denominator"])
        self.assertEqual(coverage["by_scope"]["unassigned-intake"]["folders"], 2)
        self.assertEqual(coverage["by_scope"]["unassigned-intake"]["files"], 1)
        self.assertFalse(coverage["prework_eligible"])

    def test_invalid_raw_filename_is_observed_without_loss_or_absolute_path(self):
        root_bytes = os.fsencode(self.root)
        raw_name = b"report-\xff.md"
        fd = os.open(root_bytes, os.O_RDONLY | os.O_DIRECTORY)
        try:
            try:
                file_fd = os.open(
                    raw_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=fd,
                )
            except OSError as exc:
                self.skipTest("filesystem rejects non-UTF-8 filenames: %s" % exc)
            os.write(file_fd, b"metadata only")
            os.close(file_fd)
        finally:
            os.close(fd)

        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(default=metadata_scope()),
            inventory.TraversalBounds(),
        ).scan("scan-raw-name")
        row = next(item for item in result.observations if item.physical_kind == "file")
        self.assertEqual(inventory.decode_canonical_raw_path(row.path), (raw_name,))
        self.assertNotIn(str(self.root), row.path)
        self.assertFalse(row.content_inspected)

    def test_paused_and_default_private_stay_metadata_only(self):
        (self.root / "paused").mkdir()
        (self.root / "paused" / "note.md").write_text("paused body", encoding="utf-8")
        (self.root / "private").mkdir()
        (self.root / "private" / "note.md").write_text("private body", encoding="utf-8")
        paused = inventory.ScopeDecision(
            rule_id="paused-completed",
            scope_class="coverage-only",
            traversal="directory-count-only",
            lifecycle="paused",
            content_inspection="none",
        )
        private = inventory.ScopeDecision(
            rule_id="private-reviewable",
            scope_class="private-reviewable",
            traversal="metadata-only",
            lifecycle="active",
            content_inspection="none",
        )
        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(
                default=metadata_scope(),
                bindings=(((b"paused",), paused), ((b"private",), private)),
            ),
            inventory.TraversalBounds(),
        ).scan("scan-restrictive")
        files = [row for row in result.observations if row.physical_kind == "file"]
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].display_path, "private/note.md")
        self.assertTrue(all(not row.content_inspected for row in files))
        self.assertEqual(result.coverage["files"]["denominator"], 2)
        self.assertEqual(result.coverage["files"]["outcomes"]["metadata_only"], 2)
        self.assertNotIn("paused body", repr(result.observations))
        self.assertNotIn("private body", repr(result.observations))
        self.assertTrue(all(row.reference_projection is None for row in files))
        sealed = result.observations_jsonl()
        self.assertNotIn(b"private body", sealed)
        self.assertNotIn(b"reference_projection\":{", sealed)

    def test_bounded_reader_rejects_oversize_nul_invalid_utf8_and_postread_race(self):
        active = self.root / "active"
        active.mkdir()
        (active / "large.md").write_bytes(b"x" * 33)
        (active / "nul.md").write_bytes(b"a\x00b")
        (active / "invalid.md").write_bytes(b"\xff")
        race_path = active / "race.md"
        race_path.write_bytes(b"before")

        def checkpoint(event, canonical_path):
            if event == "content-read" and canonical_path.endswith("/cmFjZS5tZA"):
                race_path.write_bytes(b"changed-and-longer")

        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(
                default=metadata_scope(),
                bindings=(((b"active",), active_scope()),),
            ),
            inventory.TraversalBounds(
                max_entries=100,
                max_depth=16,
                max_file_bytes=32,
                max_content_bytes=1024,
            ),
            fault_checkpoint=checkpoint,
        ).scan("scan-reader")
        by_display = {row.display_path: row for row in result.observations}
        self.assertIn("content-too-large", by_display["active/large.md"].errors)
        self.assertIn("content-has-nul", by_display["active/nul.md"].errors)
        self.assertIn("content-invalid-utf8", by_display["active/invalid.md"].errors)
        self.assertIn("content-race", by_display["active/race.md"].errors)
        self.assertTrue(
            all(not row.content_inspected for row in by_display.values() if row.physical_kind == "file")
        )

    def test_failed_content_reads_still_consume_the_global_run_byte_budget(self):
        active = self.root / "active"
        active.mkdir()
        (active / "a-invalid.md").write_bytes(b"\xff")
        (active / "b-nul.md").write_bytes(b"x\x00")
        (active / "c-safe.md").write_bytes(b"safe")
        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(
                default=metadata_scope(),
                bindings=(((b"active",), active_scope()),),
            ),
            inventory.TraversalBounds(
                max_entries=100,
                max_file_bytes=32,
                max_content_bytes=1,
            ),
        ).scan("scan-failed-byte-budget")
        by_display = {row.display_path: row for row in result.observations}
        self.assertIn("content-invalid-utf8", by_display["active/a-invalid.md"].errors)
        self.assertIn("content-run-byte-bound", by_display["active/b-nul.md"].errors)
        self.assertIn("content-run-byte-bound", by_display["active/c-safe.md"].errors)
        self.assertEqual(result.coverage["content_bytes_attempted"], 1)

    def test_nul_and_postread_race_bytes_also_consume_the_run_budget(self):
        cases = ("nul", "race")
        for case in cases:
            with self.subTest(case=case):
                case_root = Path(self.temp.name) / ("raw-%s" % case)
                active = case_root / "active"
                active.mkdir(parents=True, mode=0o700)
                bad_path = active / "a-bad.md"
                original = b"abc"
                bad_path.write_bytes(b"a\x00b" if case == "nul" else original)
                (active / "b-safe.md").write_bytes(b"ok")

                def checkpoint(event, canonical_path):
                    if (
                        case == "race"
                        and event == "content-read"
                        and canonical_path.endswith("/YS1iYWQubWQ")
                    ):
                        bad_path.write_bytes(b"changed")

                result = inventory.InventoryEngine(
                    case_root,
                    inventory.ScopeMap.create(
                        default=metadata_scope(),
                        bindings=(((b"active",), active_scope()),),
                    ),
                    inventory.TraversalBounds(
                        max_entries=100,
                        max_file_bytes=32,
                        max_content_bytes=3,
                    ),
                    fault_checkpoint=checkpoint,
                ).scan("scan-budget-%s" % case)
                by_display = {row.display_path: row for row in result.observations}
                expected_error = "content-has-nul" if case == "nul" else "content-race"
                self.assertIn(expected_error, by_display["active/a-bad.md"].errors)
                self.assertIn(
                    "content-run-byte-bound",
                    by_display["active/b-safe.md"].errors,
                )
                self.assertEqual(result.coverage["content_bytes_attempted"], 3)

    def test_symlink_readlink_is_bounded_dirfd_relative_and_has_exact_statuses(self):
        links = self.root / "links"
        links.mkdir()
        names = (
            "safe",
            "absolute",
            "out",
            "secret",
            "invalid",
            "oversize",
            "unavailable",
        )
        for name in names:
            os.symlink("placeholder", links / name)
        calls = []
        values = {
            b"safe": (b"folder/item.md", False),
            b"absolute": (b"/etc/passwd", False),
            b"out": (b"../../../outside", False),
            b"secret": (b"credentials/api-token.txt", False),
            b"invalid": (b"bad-\xff", False),
            b"oversize": (None, True),
        }

        def readlink_spy(parent_fd, raw_name, maximum_bytes):
            calls.append((parent_fd, raw_name, maximum_bytes))
            if raw_name == b"unavailable":
                raise OSError("unavailable")
            return values[raw_name]

        with mock.patch.object(inventory, "_bounded_readlinkat", side_effect=readlink_spy):
            result = inventory.InventoryEngine(
                self.root,
                inventory.ScopeMap.create(default=metadata_scope()),
                inventory.TraversalBounds(),
            ).scan("scan-links")
        by_display = {row.display_path: row for row in result.observations}
        expected = {
            "links/safe": "safe-relative",
            "links/absolute": "absolute",
            "links/out": "out-of-root",
            "links/secret": "secret-like",
            "links/invalid": "invalid",
            "links/oversize": "oversize",
            "links/unavailable": "unavailable",
        }
        self.assertEqual(
            {path: by_display[path].link_text_status for path in expected},
            expected,
        )
        self.assertEqual(by_display["links/safe"].safe_link_text, "folder/item.md")
        for path, status in expected.items():
            if status != "safe-relative":
                self.assertIsNone(by_display[path].safe_link_text)
        self.assertEqual({name for _, name, _ in calls}, {name.encode() for name in names})
        self.assertTrue(all(isinstance(parent_fd, int) for parent_fd, _, _ in calls))
        self.assertTrue(all(limit > 0 for _, _, limit in calls))

    def test_inventory_result_coverage_is_deeply_immutable_and_canonicalized(self):
        (self.root / "one.md").write_text("one", encoding="utf-8")
        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(default=metadata_scope()),
            inventory.TraversalBounds(),
        ).scan("scan-deep-immutable")
        before = result.coverage_json()
        with self.assertRaises(TypeError):
            result.coverage["state"] = "tampered"
        with self.assertRaises(TypeError):
            result.coverage["folders"]["outcomes"]["error"] = 999
        self.assertEqual(result.coverage_json(), before)
        self.assertEqual(before, inventory._canonical_json_bytes(json.loads(before)))

    def test_directory_count_only_is_the_canonical_paused_completed_traversal(self):
        paused = inventory.ScopeDecision(
            rule_id="paused-completed",
            scope_class="coverage-only",
            traversal="directory-count-only",
            lifecycle="paused",
            content_inspection="none",
        )
        (self.root / "paused" / "nested").mkdir(parents=True)
        (self.root / "paused" / "nested" / "note.md").write_text(
            "must stay unread", encoding="utf-8"
        )
        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(
                default=metadata_scope(),
                bindings=(((b"paused",), paused),),
            ),
            inventory.TraversalBounds(),
        ).scan("scan-directory-count")
        rows = [row for row in result.observations if row.display_path.startswith("paused")]
        self.assertTrue(rows)
        self.assertTrue(all(row.traversal == "directory-count-only" for row in rows))
        self.assertTrue(all(not row.content_inspected for row in rows))
        self.assertEqual(
            {row.display_path for row in rows},
            {"paused", "paused/nested"},
        )
        nested = next(row for row in rows if row.display_path == "paused/nested")
        self.assertEqual(nested.direct_file_count, 1)
        self.assertEqual(result.coverage["files"]["denominator"], 1)
        self.assertEqual(
            result.coverage["files"]["outcomes"]["metadata_only"],
            1,
        )
        self.assertNotIn("paused/nested/note.md", result.observations_jsonl().decode())

    def test_content_policy_rejection_is_not_a_structural_inventory_error(self):
        active = self.root / "active-policy"
        active.mkdir()
        (active / "document.pdf").write_bytes(b"not opened")
        result = inventory.InventoryEngine(
            self.root,
            inventory.ScopeMap.create(
                default=metadata_scope(),
                bindings=(((b"active-policy",), active_scope()),),
            ),
            inventory.TraversalBounds(),
        ).scan("scan-content-policy-outcome")
        row = next(
            item
            for item in result.observations
            if item.display_path == "active-policy/document.pdf"
        )
        self.assertEqual(row.content_policy_outcome, "rejected-type")
        self.assertIn("content-type-not-allowed", row.errors)
        self.assertEqual(
            result.coverage["content_policy_outcomes"]["rejected-type"],
            1,
        )
        self.assertNotIn(
            "error:content-type-not-allowed",
            result.coverage["partial_reasons"],
        )

    def test_scan_rechecks_the_raw_root_lexical_identity_before_return(self):
        (self.root / "one.md").write_text("one", encoding="utf-8")
        swapped = {"done": False}

        def checkpoint(event, _path):
            if event != "scan-before-root-identity-recheck" or swapped["done"]:
                return
            swapped["done"] = True
            self.root.rename(Path(self.temp.name) / "parked-root")
            self.root.mkdir(mode=0o700)

        with self.assertRaises(inventory.InventorySafetyError):
            inventory.InventoryEngine(
                self.root,
                inventory.ScopeMap.create(default=metadata_scope()),
                inventory.TraversalBounds(),
                fault_checkpoint=checkpoint,
            ).scan("scan-root-swap")


class InventoryRunStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.raw_root = Path(self.temp.name) / "raw"
        self.raw_root.mkdir(mode=0o700)
        self.corpus = self.raw_root / "document.md"
        self.corpus.write_bytes(b"unchanged corpus")
        self.runs = self.raw_root / "_registry" / "curation-runs"
        self.runs.mkdir(parents=True, mode=0o700)
        os.chmod(self.runs, 0o700)
        self.store = inventory.InventoryRunStore(self.runs)

    def tearDown(self):
        self.temp.cleanup()

    def artifacts(self):
        return {
            "coverage.json": b'{"state":"complete"}\n',
            "observations.jsonl": b'{"path":"raw-b64-v1:"}\n',
        }

    def source_record(self, relative=(b"document.md",)):
        path = self.raw_root.joinpath(*(os.fsdecode(part) for part in relative))
        value = os.stat(path, follow_symlinks=False)
        return {
            "path": inventory.canonical_raw_path(relative),
            "identity": inventory.FileIdentity.from_stat(value).to_dict(),
        }

    def write_terminal_provenance(self, session, source_records=None):
        session.write_chunk(
            0,
            {
                "cursor_before": ROOT_CURSOR,
                "cursor_after": None,
                "source_identities": (
                    [self.source_record()]
                    if source_records is None
                    else source_records
                ),
                "items": [],
            },
        )
        session.write_checkpoint(
            0,
            {
                "next_cursor": None,
                "counters": {"observations": 1, "content_bytes": 0},
            },
        )

    def test_publish_is_sealed_no_replace_and_foundation_only(self):
        run_request = request()
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            terminal = session.publish(self.artifacts())
            self.assertEqual(terminal.state, "complete")

        final = self.runs / "run-001"
        run_json = json.loads((final / "run.json").read_text())
        self.assertEqual(run_json["package_version"], "inventory-foundation-v1")
        self.assertFalse(run_json["openable"])
        self.assertFalse(run_json["approval_ready"])
        self.assertEqual(self.corpus.read_bytes(), b"unchanged corpus")
        self.assertFalse((self.raw_root / "_registry" / "curation" / "ledger.sqlite3").exists())

        manifest_lines = (final / "manifest.jsonl").read_text().splitlines()
        manifest_paths = {json.loads(line)["path"] for line in manifest_lines}
        self.assertIn("run.lock", manifest_paths)
        self.assertIn("request.json", manifest_paths)
        self.assertIn("chunks/00000000.json", manifest_paths)
        self.assertIn("checkpoints/00000000.json", manifest_paths)
        self.assertNotIn("manifest.jsonl", manifest_paths)

        existing = self.store.resume(run_request)
        self.assertIsInstance(existing, inventory.InventoryTerminal)
        self.assertEqual(existing.package_sha256, terminal.package_sha256)
        opened = self.store.open_terminal("run-001")
        self.assertEqual(opened, terminal)
        with self.assertRaises(inventory.RunCollisionError):
            self.store.start(run_request)

    def test_open_terminal_reconstructs_exact_sealed_request_and_rejects_tamper(self):
        run_request = request("open-terminal-001")
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            terminal = session.publish(self.artifacts())

        self.assertEqual(self.store.open_terminal(run_request.run_id), terminal)
        package = self.store.read_complete_package(run_request.run_id)
        self.assertEqual(package.terminal, terminal)
        self.assertEqual(package.request.canonical_bytes, run_request.canonical_bytes)
        self.assertEqual(dict(package.artifacts), self.artifacts())
        request_path = self.runs / run_request.run_id / "request.json"
        request_path.write_bytes(request_path.read_bytes() + b" ")
        with self.assertRaises(inventory.RunIntegrityError):
            self.store.open_terminal(run_request.run_id)

    def test_open_terminal_rejects_unknown_or_failed_run_for_campaign_use(self):
        with self.assertRaises(inventory.RunStateError):
            self.store.open_terminal("missing-run")

        run_request = request("failed-terminal-001")
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            session.fail("synthetic-failure", {"error_type": "Synthetic"})
        with self.assertRaisesRegex(inventory.RunStateError, "not complete"):
            self.store.open_terminal(run_request.run_id)

    def test_resume_requires_exact_request_and_run_lock_is_lifetime_exclusive(self):
        run_request = request("resume-001")
        session = self.store.start(run_request)
        try:
            self.write_terminal_provenance(session)
            with self.assertRaises(inventory.RunBusyError):
                self.store.resume(run_request)
        finally:
            session.close()

        wrong = inventory.InventoryRunRequest.create(
            run_id="resume-001",
            policy_authority={"generation": 2, "full_hash": "b" * 64},
            scope={"kind": "root"},
            bounds={"max_entries": 99},
            expected_artifacts=("coverage.json", "observations.jsonl"),
        )
        with self.assertRaises(inventory.RunRequestMismatchError):
            self.store.resume(wrong)

        resumed = self.store.resume(run_request)
        self.assertIsInstance(resumed, inventory.InventoryRunSession)
        with resumed:
            terminal = resumed.publish(self.artifacts())
        self.assertEqual(terminal.state, "complete")

    def test_fail_is_mutually_exclusive_and_terminal_retry_is_readback_only(self):
        run_request = request("failed-001")
        with self.store.start(run_request) as session:
            terminal = session.fail(
                "source-race",
                {"canonical_path": inventory.canonical_raw_path((b"document.md",))},
            )
            self.assertEqual(terminal.state, "failed")
            with self.assertRaises(inventory.RunStateError):
                session.publish(self.artifacts())

        self.assertTrue((self.runs / "failed" / "failed-001" / "failure.json").is_file())
        self.assertFalse((self.runs / "failed-001").exists())
        existing = self.store.resume(run_request)
        self.assertEqual(existing.state, "failed")
        self.assertFalse(existing.approval_ready)
        self.assertFalse(existing.openable)

    def test_final_collision_is_not_replaced(self):
        run_request = request("collision-001")
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            collision = self.runs / "collision-001"
            collision.mkdir(mode=0o700)
            marker = collision / "owner.txt"
            marker.write_text("competitor", encoding="utf-8")
            with self.assertRaises(inventory.RunCollisionError):
                session.publish(self.artifacts())
            self.assertEqual(marker.read_text(encoding="utf-8"), "competitor")
            self.assertTrue((self.runs / ".incomplete-collision-001").is_dir())

    def test_terminal_manifest_tamper_is_detected_on_readback(self):
        run_request = request("tamper-001")
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            session.publish(self.artifacts())
        (self.runs / "tamper-001" / "coverage.json").write_bytes(b"tampered\n")
        with self.assertRaises(inventory.RunIntegrityError):
            self.store.resume(run_request)

    def test_staging_lexical_replacement_is_never_moved_to_final(self):
        run_request = request("source-swap-001")
        swapped = {"done": False}

        def checkpoint(event, _details):
            if event != "terminal-before-rename" or swapped["done"]:
                return
            swapped["done"] = True
            staging = self.runs / ".incomplete-source-swap-001"
            staging.rename(self.runs / "parked-original")
            staging.mkdir(mode=0o700)
            (staging / "competitor.txt").write_text("competitor", encoding="utf-8")

        store = inventory.InventoryRunStore(self.runs, fault_checkpoint=checkpoint)
        with store.start(run_request) as session:
            self.write_terminal_provenance(session)
            with self.assertRaises(inventory.RunIntegrityError):
                session.publish(self.artifacts())
        self.assertFalse((self.runs / "source-swap-001").exists())
        self.assertEqual(
            (self.runs / ".incomplete-source-swap-001" / "competitor.txt").read_text(),
            "competitor",
        )
        self.assertTrue((self.runs / "parked-original" / "request.json").is_file())

    def test_postrename_target_replacement_surfaces_manual_recovery(self):
        run_request = request("postrename-swap-001")
        changed = {"done": False}

        def checkpoint(event, details):
            if (
                event != "terminal-rename-directory-check"
                or details["sequence"] != 3
                or changed["done"]
            ):
                return
            changed["done"] = True
            final = self.runs / "postrename-swap-001"
            final.rename(self.runs / "displaced-original")
            final.mkdir(mode=0o700)
            (final / "competitor.txt").write_text("competitor", encoding="utf-8")

        store = inventory.InventoryRunStore(self.runs, fault_checkpoint=checkpoint)
        with store.start(run_request) as session:
            self.write_terminal_provenance(session)
            with self.assertRaises(inventory.ManualRecoveryRequired):
                session.publish(self.artifacts())
        self.assertEqual(
            (self.runs / "postrename-swap-001" / "competitor.txt").read_text(),
            "competitor",
        )
        self.assertTrue((self.runs / "displaced-original" / "manifest.jsonl").is_file())

    def test_terminal_readback_rechecks_final_lexical_identity(self):
        run_request = request("readback-swap-001")
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            session.publish(self.artifacts())
        swapped = {"done": False}

        def checkpoint(event, _details):
            if event != "terminal-readback-before-lexical-recheck" or swapped["done"]:
                return
            swapped["done"] = True
            final = self.runs / "readback-swap-001"
            final.rename(self.runs / "readback-original")
            final.mkdir(mode=0o700)
            (final / "competitor.txt").write_text("competitor", encoding="utf-8")

        store = inventory.InventoryRunStore(self.runs, fault_checkpoint=checkpoint)
        with self.assertRaises(inventory.RunIntegrityError):
            store.resume(run_request)
        self.assertEqual(
            (self.runs / "readback-swap-001" / "competitor.txt").read_text(),
            "competitor",
        )

    def test_terminal_readback_rejects_same_bytes_aba_before_open(self):
        run_request = request("readback-aba-001")
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            session.publish(self.artifacts())
        swapped = {"done": False}

        def checkpoint(event, _details):
            if event != "terminal-discovered-before-open" or swapped["done"]:
                return
            swapped["done"] = True
            final = self.runs / "readback-aba-001"
            parked = self.runs / "readback-aba-original"
            final.rename(parked)
            shutil.copytree(parked, final, copy_function=shutil.copy2)

        store = inventory.InventoryRunStore(self.runs, fault_checkpoint=checkpoint)
        with self.assertRaisesRegex(inventory.RunIntegrityError, "before open"):
            store.resume(run_request)
        self.assertEqual(
            (self.runs / "readback-aba-001" / "request.json").read_bytes(),
            (self.runs / "readback-aba-original" / "request.json").read_bytes(),
        )

    def test_run_and_manifest_require_exact_canonical_bytes(self):
        run_request = request("canonical-001")
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            session.publish(self.artifacts())
        final = self.runs / "canonical-001"
        run_path = final / "run.json"
        run_payload = json.loads(run_path.read_text())
        run_payload["unexpected"] = "field"
        run_path.write_text(
            json.dumps(run_payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path = final / "manifest.jsonl"
        rows = [json.loads(line) for line in manifest_path.read_text().splitlines()]
        for row in rows:
            if row["path"] == "run.json":
                row["sha256"] = hashlib.sha256(run_path.read_bytes()).hexdigest()
        manifest_path.write_text(
            "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
            encoding="utf-8",
        )
        with self.assertRaises(inventory.RunIntegrityError):
            self.store.resume(run_request)

        # A fresh package with reordered manifest rows is non-canonical too.
        second = request("manifest-order-001")
        with self.store.start(second) as session:
            self.write_terminal_provenance(session)
            session.publish(self.artifacts())
        second_manifest = self.runs / "manifest-order-001" / "manifest.jsonl"
        lines = second_manifest.read_bytes().splitlines(keepends=True)
        second_manifest.write_bytes(b"".join(reversed(lines)))
        with self.assertRaises(inventory.RunIntegrityError):
            self.store.resume(second)

    def test_crash_seams_resume_before_and_after_terminal_rename(self):
        before_request = request("crash-before-rename")
        before_once = {"raised": False}

        def before_checkpoint(event, _details):
            if event == "terminal-before-rename" and not before_once["raised"]:
                before_once["raised"] = True
                raise RuntimeError("injected crash before rename")

        before_store = inventory.InventoryRunStore(
            self.runs, fault_checkpoint=before_checkpoint
        )
        with before_store.start(before_request) as session:
            self.write_terminal_provenance(session)
            with self.assertRaisesRegex(RuntimeError, "before rename"):
                session.publish(self.artifacts())
        resumed_before = before_store.resume(before_request)
        self.assertIsInstance(resumed_before, inventory.InventoryRunSession)
        with resumed_before:
            completed_before = resumed_before.publish(self.artifacts())
        self.assertEqual(completed_before.state, "complete")

        after_request = request("crash-after-rename")
        after_once = {"raised": False}

        def after_checkpoint(event, _details):
            if (
                event == "terminal-readback-before-lexical-recheck"
                and not after_once["raised"]
            ):
                after_once["raised"] = True
                raise RuntimeError("injected crash after rename")

        after_store = inventory.InventoryRunStore(
            self.runs, fault_checkpoint=after_checkpoint
        )
        with after_store.start(after_request) as session:
            self.write_terminal_provenance(session)
            with self.assertRaisesRegex(RuntimeError, "after rename"):
                session.publish(self.artifacts())
        completed_after = after_store.resume(after_request)
        self.assertIsInstance(completed_after, inventory.InventoryTerminal)
        self.assertEqual(completed_after.state, "complete")

    def test_resumability_files_are_canonical_contiguous_and_hash_chained(self):
        run_request = request("chain-001")
        first_cursor = inventory.canonical_raw_path((b"document.md",))
        with self.store.start(run_request) as session:
            session.write_chunk(
                0,
                chunk_payload(
                    before=ROOT_CURSOR,
                    after=first_cursor,
                    items=[{"path": first_cursor}],
                    source_identities=[
                        self.source_record(()),
                        self.source_record(),
                    ],
                ),
            )
            session.write_checkpoint(
                0,
                checkpoint_payload(
                    next_cursor=first_cursor,
                    observations=1,
                    content_bytes=0,
                ),
            )
            session.write_chunk(
                1,
                {
                    "cursor_before": first_cursor,
                    "cursor_after": None,
                    "items": [],
                    "source_identities": [],
                },
            )
            session.write_checkpoint(
                1,
                {
                    "next_cursor": None,
                    "counters": {"observations": 2, "content_bytes": 0},
                },
            )
            session.publish(self.artifacts())

        final = self.runs / "chain-001"
        chunk_zero_raw = (final / "chunks" / "00000000.json").read_bytes()
        chunk_one_raw = (final / "chunks" / "00000001.json").read_bytes()
        checkpoint_zero_raw = (final / "checkpoints" / "00000000.json").read_bytes()
        checkpoint_one_raw = (final / "checkpoints" / "00000001.json").read_bytes()
        chunk_zero = json.loads(chunk_zero_raw)
        chunk_one = json.loads(chunk_one_raw)
        checkpoint_zero = json.loads(checkpoint_zero_raw)
        checkpoint_one = json.loads(checkpoint_one_raw)
        self.assertEqual(chunk_zero_raw, inventory._canonical_json_bytes(chunk_zero))
        self.assertEqual(checkpoint_one_raw, inventory._canonical_json_bytes(checkpoint_one))
        self.assertIsNone(chunk_zero["previous_chunk_sha256"])
        self.assertEqual(
            chunk_one["previous_chunk_sha256"], hashlib.sha256(chunk_zero_raw).hexdigest()
        )
        self.assertIsNone(checkpoint_zero["previous_checkpoint_sha256"])
        self.assertEqual(
            checkpoint_one["previous_checkpoint_sha256"],
            hashlib.sha256(checkpoint_zero_raw).hexdigest(),
        )
        self.assertEqual(
            checkpoint_one["chunk_sha256"], hashlib.sha256(chunk_one_raw).hexdigest()
        )
        self.assertIsNone(checkpoint_one["next_cursor"])
        self.assertRegex(checkpoint_one["completed_prefix_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(checkpoint_one["source_identity_prefix_sha256"], r"^[0-9a-f]{64}$")

    def test_resumability_writer_rejects_gap_cursor_and_counter_regression(self):
        run_request = request("chain-input-guards")
        first_cursor = inventory.canonical_raw_path((b"a",))
        second_cursor = inventory.canonical_raw_path((b"b",))
        with self.store.start(run_request) as session:
            with self.assertRaises(inventory.RunStateError):
                session.write_chunk(1, chunk_payload(after=first_cursor))
            session.write_chunk(0, chunk_payload(after=first_cursor))
            with self.assertRaises(inventory.RunStateError):
                session.write_checkpoint(
                    0,
                    checkpoint_payload(next_cursor=second_cursor),
                )
            session.write_checkpoint(
                0,
                checkpoint_payload(
                    next_cursor=first_cursor,
                    observations=2,
                    content_bytes=1,
                ),
            )
            session.write_chunk(
                1,
                {
                    "cursor_before": first_cursor,
                    "cursor_after": None,
                    "items": [],
                    "source_identities": [],
                },
            )
            with self.assertRaises(inventory.RunStateError):
                session.write_checkpoint(
                    1,
                    checkpoint_payload(
                        next_cursor=None,
                        observations=1,
                        content_bytes=0,
                    ),
                )
            session.write_checkpoint(
                1,
                {
                    "next_cursor": None,
                    "counters": {"observations": 3, "content_bytes": 1},
                },
            )
            terminal = session.publish(self.artifacts())
        self.assertEqual(terminal.state, "complete")

    def test_uncheckpointed_corrupt_gap_and_bad_hash_resume_close_failed(self):
        scenarios = (
            "uncheckpointed",
            "gap",
            "noncanonical",
            "bad-hash",
            "bad-source-hash",
            "bad-cursor",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                run_id = "provenance-%s" % scenario
                run_request = request(run_id)
                session = self.store.start(run_request)
                session.write_chunk(0, chunk_payload())
                if scenario in (
                    "noncanonical",
                    "bad-hash",
                    "bad-source-hash",
                    "bad-cursor",
                ):
                    session.write_checkpoint(0, checkpoint_payload())
                session.close()
                staging = self.runs / (".incomplete-%s" % run_id)
                if scenario == "gap":
                    (staging / "chunks" / "00000000.json").rename(
                        staging / "chunks" / "00000001.json"
                    )
                elif scenario == "noncanonical":
                    path = staging / "checkpoints" / "00000000.json"
                    path.write_bytes(path.read_bytes() + b" ")
                elif scenario == "bad-hash":
                    path = staging / "checkpoints" / "00000000.json"
                    payload = json.loads(path.read_text())
                    payload["chunk_sha256"] = "0" * 64
                    path.write_bytes(inventory._canonical_json_bytes(payload))
                elif scenario == "bad-source-hash":
                    path = staging / "chunks" / "00000000.json"
                    payload = json.loads(path.read_text())
                    payload["source_identities_sha256"] = "0" * 64
                    path.write_bytes(inventory._canonical_json_bytes(payload))
                elif scenario == "bad-cursor":
                    path = staging / "checkpoints" / "00000000.json"
                    payload = json.loads(path.read_text())
                    payload["next_cursor"] = inventory.canonical_raw_path((b"else",))
                    path.write_bytes(inventory._canonical_json_bytes(payload))

                terminal = self.store.resume(run_request)
                self.assertIsInstance(terminal, inventory.InventoryTerminal)
                self.assertEqual(terminal.state, "failed")
                failed = self.runs / "failed" / run_id
                failure = json.loads((failed / "failure.json").read_text())
                self.assertEqual(failure["reason"], "resume-provenance-invalid")
                self.assertFalse(staging.exists())
                self.assertTrue((failed / "manifest.jsonl").is_file())

    def test_start_crash_seams_exactly_resume_without_ambiguous_staging(self):
        seams = (
            ("start-after-staging-mkdir", None),
            ("start-after-run-lock", None),
            ("start-after-request", None),
            ("start-after-child-directory", "chunks"),
            ("start-after-child-directory", "checkpoints"),
        )
        for index, (event_name, child_name) in enumerate(seams):
            with self.subTest(event=event_name, child=child_name):
                run_id = "start-crash-%02d" % index
                run_request = request(run_id)
                raised = {"done": False}

                def checkpoint(event, details):
                    if raised["done"] or event != event_name:
                        return
                    if child_name is not None and details.get("directory") != child_name:
                        return
                    raised["done"] = True
                    raise RuntimeError("injected start crash")

                store = inventory.InventoryRunStore(
                    self.runs,
                    fault_checkpoint=checkpoint,
                )
                with self.assertRaisesRegex(RuntimeError, "start crash"):
                    store.start(run_request)
                resumed = store.resume(run_request)
                self.assertIsInstance(resumed, inventory.InventoryRunSession)
                with resumed:
                    self.write_terminal_provenance(resumed)
                    terminal = resumed.publish(self.artifacts())
                self.assertEqual(terminal.state, "complete")
                self.assertFalse((self.runs / (".incomplete-%s" % run_id)).exists())

    def test_complete_publish_requires_nonempty_terminal_checkpoint_and_root_counter(self):
        empty_request = request("complete-empty-provenance")
        with self.store.start(empty_request) as session:
            with self.assertRaises(inventory.RunStateError):
                session.publish(self.artifacts())

        cursor_request = request("complete-nonterminal-cursor")
        with self.store.start(cursor_request) as session:
            session.write_chunk(0, chunk_payload())
            session.write_checkpoint(0, checkpoint_payload())
            with self.assertRaises(inventory.RunStateError):
                session.publish(self.artifacts())

        zero_request = request("complete-zero-root-counter")
        with self.store.start(zero_request) as session:
            session.write_chunk(
                0,
                {
                    "cursor_before": ROOT_CURSOR,
                    "cursor_after": None,
                    "source_identities": [self.source_record()],
                    "items": [],
                },
            )
            session.write_checkpoint(
                0,
                {
                    "next_cursor": None,
                    "counters": {"observations": 0, "content_bytes": 0},
                },
            )
            with self.assertRaises(inventory.RunStateError):
                session.publish(self.artifacts())

    def test_source_identity_order_is_global_and_bound_to_chunk_cursor(self):
        run_request = request("source-order-bound")
        first_cursor = inventory.canonical_raw_path((b"z",))
        regressive = inventory.canonical_raw_path((b"a",))
        identity = self.source_record()["identity"]
        with self.store.start(run_request) as session:
            session.write_chunk(
                0,
                {
                    "cursor_before": ROOT_CURSOR,
                    "cursor_after": first_cursor,
                    "source_identities": [
                        {"path": first_cursor, "identity": identity}
                    ],
                },
            )
            session.write_checkpoint(
                0,
                {
                    "next_cursor": first_cursor,
                    "counters": {"observations": 1, "content_bytes": 0},
                },
            )
            with self.assertRaises(inventory.RunProvenanceError):
                session.write_chunk(
                    1,
                    {
                        "cursor_before": first_cursor,
                        "cursor_after": None,
                        "source_identities": [
                            {"path": regressive, "identity": identity}
                        ],
                    },
                )

    def test_live_source_identity_is_revalidated_on_publish_and_resume(self):
        publish_request = request("source-drift-publish")
        with self.store.start(publish_request) as session:
            self.write_terminal_provenance(session)
            self.corpus.write_bytes(b"changed before publish")
            terminal = session.publish(self.artifacts())
        self.assertEqual(terminal.state, "failed")
        self.corpus.write_bytes(b"unchanged corpus")

        resume_request = request("source-drift-resume")
        session = self.store.start(resume_request)
        self.write_terminal_provenance(session)
        session.close()
        self.corpus.write_bytes(b"changed before resume")
        resumed = self.store.resume(resume_request)
        self.assertIsInstance(resumed, inventory.InventoryTerminal)
        self.assertEqual(resumed.state, "failed")

    def test_source_revalidation_ignores_atime_only_changes(self):
        run_request = request("source-atime-only")
        with self.store.start(run_request) as session:
            self.write_terminal_provenance(session)
            before = os.stat(self.corpus, follow_symlinks=False)
            os.utime(
                self.corpus,
                ns=(before.st_atime_ns + 1000000000, before.st_mtime_ns),
                follow_symlinks=False,
            )
            terminal = session.publish(self.artifacts())
        self.assertEqual(terminal.state, "complete")

    def test_request_mismatch_unexpected_entry_and_bad_child_seal_failed(self):
        cases = ("request", "unexpected", "bad-child")
        for case in cases:
            with self.subTest(case=case):
                run_id = "stage-corruption-%s" % case
                run_request = request(run_id)
                session = self.store.start(run_request)
                session.close()
                staging = self.runs / (".incomplete-%s" % run_id)
                if case == "request":
                    (staging / "request.json").write_bytes(b"partial")
                elif case == "unexpected":
                    (staging / "surprise.txt").write_text("unexpected", encoding="utf-8")
                else:
                    (staging / "chunks").rmdir()
                    (staging / "chunks").write_text("not a directory", encoding="utf-8")
                terminal = self.store.resume(run_request)
                self.assertIsInstance(terminal, inventory.InventoryTerminal)
                self.assertEqual(terminal.state, "failed")
                self.assertFalse(staging.exists())
                self.assertTrue((self.runs / "failed" / run_id / "failure.json").is_file())

    def test_request_create_write_and_prefsync_crashes_resume_exactly(self):
        seams = (
            "request-after-create",
            "request-after-partial-write",
            "request-before-fsync",
        )
        for index, seam in enumerate(seams):
            with self.subTest(seam=seam):
                run_id = "request-crash-%02d" % index
                run_request = request(run_id)
                raised = {"done": False}

                def checkpoint(event, details):
                    if raised["done"] or event != seam:
                        return
                    raised["done"] = True
                    raise RuntimeError("request crash")

                store = inventory.InventoryRunStore(
                    self.runs,
                    fault_checkpoint=checkpoint,
                )
                with self.assertRaisesRegex(RuntimeError, "request crash"):
                    store.start(run_request)
                resumed = store.resume(run_request)
                self.assertIsInstance(resumed, inventory.InventoryRunSession)
                with resumed:
                    self.write_terminal_provenance(resumed)
                    terminal = resumed.publish(self.artifacts())
                self.assertEqual(terminal.state, "complete")

    def test_publish_result_reuses_exact_provenance_and_artifacts_after_resume(self):
        run_id = "publish-result-resume"
        run_request = request(run_id)
        result = inventory.InventoryEngine(
            self.raw_root,
            inventory.ScopeMap.create(default=metadata_scope()),
            inventory.TraversalBounds(),
        ).scan(run_id)
        raised = {"done": False}

        def checkpoint(event, _details):
            if event == "terminal-before-rename" and not raised["done"]:
                raised["done"] = True
                raise RuntimeError("publish result crash")

        store = inventory.InventoryRunStore(
            self.runs,
            fault_checkpoint=checkpoint,
        )
        with store.start(run_request) as session:
            with self.assertRaisesRegex(RuntimeError, "publish result crash"):
                session.publish_result(result)

        staging = self.runs / (".incomplete-%s" % run_id)
        relative_paths = (
            "chunks/00000000.json",
            "checkpoints/00000000.json",
            "coverage.json",
            "observations.jsonl",
        )
        before = {
            name: (
                (staging / name).read_bytes(),
                os.stat(staging / name, follow_symlinks=False).st_ino,
                os.stat(staging / name, follow_symlinks=False).st_mtime_ns,
            )
            for name in relative_paths
        }

        resumed = store.resume(run_request)
        self.assertIsInstance(resumed, inventory.InventoryRunSession)
        with resumed:
            terminal = resumed.publish_result(result)
        self.assertEqual(terminal.state, "complete")

        final = self.runs / run_id
        after = {
            name: (
                (final / name).read_bytes(),
                os.stat(final / name, follow_symlinks=False).st_ino,
                os.stat(final / name, follow_symlinks=False).st_mtime_ns,
            )
            for name in relative_paths
        }
        self.assertEqual(after, before)
        readback = store.resume(run_request)
        self.assertIsInstance(readback, inventory.InventoryTerminal)
        self.assertEqual(readback.package_sha256, terminal.package_sha256)

    def test_publish_result_source_set_excludes_aggregates_but_tracks_policy_files(self):
        paused_dir = self.raw_root / "paused"
        paused_dir.mkdir()
        aggregated_file = paused_dir / "hidden.md"
        aggregated_file.write_text("hidden version one", encoding="utf-8")
        active_dir = self.raw_root / "active"
        active_dir.mkdir()
        rejected_file = active_dir / "archive.bin"
        rejected_file.write_bytes(b"opaque payload")
        paused = inventory.ScopeDecision(
            rule_id="paused-completed",
            scope_class="coverage-only",
            traversal="directory-count-only",
            lifecycle="paused",
            content_inspection="none",
        )
        scope_map = inventory.ScopeMap.create(
            default=metadata_scope(),
            bindings=(
                ((b"active",), active_scope()),
                ((b"paused",), paused),
            ),
        )

        first_run_id = "publish-result-aggregate"
        first_result = inventory.InventoryEngine(
            self.raw_root,
            scope_map,
            inventory.TraversalBounds(),
        ).scan(first_run_id)
        display_paths = {row.display_path for row in first_result.observations}
        self.assertNotIn("paused/hidden.md", display_paths)
        rejected = next(
            row
            for row in first_result.observations
            if row.display_path == "active/archive.bin"
        )
        self.assertEqual(rejected.content_policy_outcome, "rejected-type")
        self.assertEqual(first_result.coverage["files"]["outcomes"]["error"], 0)
        self.assertEqual(
            first_result.coverage["content_policy_outcomes"]["rejected-type"],
            1,
        )
        self.assertNotIn(
            "error:content-type-not-allowed",
            first_result.coverage["partial_reasons"],
        )

        aggregated_file.write_text("hidden version two", encoding="utf-8")
        first_request = request(first_run_id)
        with self.store.start(first_request) as session:
            terminal = session.publish_result(first_result)
        self.assertEqual(terminal.state, "complete")
        chunk = json.loads(
            (self.runs / first_run_id / "chunks" / "00000000.json").read_text()
        )
        source_paths = {row["path"] for row in chunk["source_identities"]}
        self.assertNotIn(
            inventory.canonical_raw_path((b"paused", b"hidden.md")),
            source_paths,
        )
        self.assertIn(
            inventory.canonical_raw_path((b"active", b"archive.bin")),
            source_paths,
        )

        second_run_id = "publish-result-policy-drift"
        second_result = inventory.InventoryEngine(
            self.raw_root,
            scope_map,
            inventory.TraversalBounds(),
        ).scan(second_run_id)
        rejected_file.write_bytes(b"changed opaque payload")
        second_request = request(second_run_id)
        with self.store.start(second_request) as session:
            failed = session.publish_result(second_result)
        self.assertEqual(failed.state, "failed")

    def test_provenance_schema_and_sequence_require_exact_integers(self):
        run_request = request("exact-integer-provenance")
        session = self.store.start(run_request)
        session.write_chunk(
            0,
            {
                "cursor_before": ROOT_CURSOR,
                "cursor_after": None,
                "source_identities": [self.source_record()],
            },
        )
        chunk_path = (
            self.runs
            / ".incomplete-exact-integer-provenance"
            / "chunks"
            / "00000000.json"
        )
        payload = json.loads(chunk_path.read_text())
        payload["schema_version"] = 1.0
        payload["sequence"] = 0.0
        chunk_path.write_bytes(inventory._canonical_json_bytes(payload))
        with self.assertRaises(inventory.RunProvenanceError):
            session.write_checkpoint(
                0,
                {
                    "next_cursor": None,
                    "counters": {"observations": 1, "content_bytes": 0},
                },
            )
        session.close()


if __name__ == "__main__":
    unittest.main()
