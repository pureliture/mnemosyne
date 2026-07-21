import json
import stat
import sys
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import admission, inventory, policy, run_review  # noqa: E402
from mnemosyne_core.canonical_json import sha256_bytes  # noqa: E402


def approved_policy():
    return admission.ApprovedPolicyRef(
        raw_hash="1" * 64,
        full_hash="2" * 64,
        writer_control_hash="3" * 64,
        foundation_hash="4" * 64,
        generation=1,
        source_kind="INITIAL",
        source_run_id="policy-run-1",
        guard_epoch=0,
    )


def compiled_policy(raw_root="/private/tmp/raw"):
    return policy.CompiledPolicy(
        raw_hash="1" * 64,
        full_json=b"{}\n",
        full_hash="2" * 64,
        writer_control=policy.CompiledWriterControl(
            movement_writer="legacy",
            structural_apply="disabled",
            writer_epoch="legacy-v1",
        ),
        writer_json=b"{}\n",
        writer_hash="3" * 64,
        foundation=policy.CompiledFoundation(
            profile_version=1,
            state_root=raw_root + "/_registry/curation",
            runs_root=raw_root + "/_registry/curation-runs",
        ),
        foundation_json=b"{}\n",
        foundation_hash="4" * 64,
        workstreams=(
            policy.CompiledWorkstream(
                id="alpha",
                lifecycle="active",
                project_home=raw_root + "/projects/alpha",
                aliases=("alpha",),
            ),
        ),
        archive_roots=(),
        scope_rules=(
            policy.CompiledScopeRule(
                id="active-workstream-content",
                path_selectors=("workstream-project-home",),
                workstream_lifecycle=("active",),
                sensitivity="standard",
                access_domain="local",
                traversal="recursive-no-follow",
                inventory="content-aware",
                content_inspection="allowed",
                write="approved-only",
                catch_all=False,
            ),
            policy.CompiledScopeRule(
                id="private-reviewable",
                path_selectors=("private-reviewable",),
                workstream_lifecycle=("any",),
                sensitivity="private",
                access_domain="local-restricted",
                traversal="metadata-no-follow",
                inventory="metadata-only",
                content_inspection="scoped-approved",
                write="forbidden",
                catch_all=False,
            ),
        ),
        registry_anchors=policy.CompiledRegistryAnchors(
            registry_root=raw_root + "/_registry",
            inbox=raw_root + "/inbox",
            memory_workspaces=raw_root + "/memory/workspaces.yml",
        ),
        never_touch=(),
        categories=(
            policy.CompiledCategory(
                id="docs",
                target=raw_root + "/docs",
                patterns=("*.md",),
            ),
        ),
    )


def package(rows, *, max_entries=100):
    policy_ref = approved_policy()
    request = inventory.InventoryRunRequest.create(
        run_id="inventory-root-1",
        policy_authority={
            "raw_hash": policy_ref.raw_hash,
            "full_hash": policy_ref.full_hash,
            "writer_control_hash": policy_ref.writer_control_hash,
            "foundation_hash": policy_ref.foundation_hash,
            "generation": policy_ref.generation,
            "source_kind": policy_ref.source_kind,
            "source_run_id": policy_ref.source_run_id,
            "guard_epoch": policy_ref.guard_epoch,
        },
        scope={"raw_root": "/private/tmp/raw", "scope_hash": "5" * 64},
        bounds={"max_entries": max_entries},
        expected_artifacts=("coverage.json", "observations.jsonl"),
    )
    coverage = inventory._build_coverage(rows)
    result = inventory.InventoryResult("inventory-root-1", tuple(rows), coverage)
    return inventory.InventoryPackageReadback(
        inventory.InventoryTerminal(
            run_id="inventory-root-1",
            state="complete",
            path="/private/tmp/raw/_registry/curation-runs/inventory-root-1",
            package_sha256="6" * 64,
        ),
        request,
        (
            ("coverage.json", result.coverage_json()),
            ("observations.jsonl", result.observations_jsonl()),
        ),
    )


def observation(path, display, *, scope_class="eligible", rule="active-workstream-content", inspected=True):
    return inventory.Observation(
        run_id="inventory-root-1",
        path=path,
        display_path=display,
        kind="file",
        physical_kind="file",
        scope_class=scope_class,
        scope_rule_id=rule,
        traversal="entered",
        content_inspected=inspected,
        excluded_reason=None,
        identity=inventory.FileIdentity(
            device=1,
            inode=10,
            mode=stat.S_IFREG | 0o600,
            size=12,
            mtime_ns=100,
        ),
        fingerprint_kind="sha256" if inspected else "metadata",
        fingerprint_value="7" * 64 if inspected else None,
        content_policy_outcome="inspected" if inspected else "metadata-only",
        schema_version=1,
    )


def projected_observation(path, display, *, text="", fingerprint="7" * 64):
    return inventory.Observation(
        run_id="inventory-root-1",
        path=path,
        display_path=display,
        kind="file",
        physical_kind="file",
        scope_class="eligible",
        scope_rule_id="active-workstream-content",
        traversal="entered",
        content_inspected=True,
        excluded_reason=None,
        identity=inventory.FileIdentity(
            device=1,
            inode=10,
            mode=stat.S_IFREG | 0o600,
            size=12,
            mtime_ns=100,
        ),
        fingerprint_kind="sha256",
        fingerprint_value=fingerprint,
        content_policy_outcome="inspected",
        reference_projection=inventory._reference_projection(
            inventory.decode_canonical_raw_path(path),
            text,
        ),
        classification_projection=inventory._classification_projection(text),
    )


def root_observation():
    return inventory.Observation(
        run_id="inventory-root-1",
        path=inventory.canonical_raw_path(()),
        display_path=".",
        kind="directory",
        physical_kind="directory",
        scope_class="eligible",
        scope_rule_id="active-workstream-content",
        traversal="entered",
        content_inspected=False,
        excluded_reason=None,
        identity=inventory.FileIdentity(
            device=1,
            inode=1,
            mode=stat.S_IFDIR | 0o700,
            size=0,
            mtime_ns=100,
        ),
        fingerprint_kind="metadata",
        fingerprint_value=None,
    )


def partial_directory_observation(path, display):
    return inventory.Observation(
        run_id="inventory-root-1",
        path=path,
        display_path=display,
        kind="directory",
        physical_kind="directory",
        scope_class="eligible",
        scope_rule_id="active-workstream-content",
        traversal="full",
        content_inspected=False,
        excluded_reason=None,
        identity=inventory.FileIdentity(
            device=1,
            inode=2,
            mode=stat.S_IFDIR | 0o700,
            size=0,
            mtime_ns=100,
        ),
        fingerprint_kind="metadata",
        fingerprint_value=None,
        descendant_unknown=7,
    )


def restricted_directory_observation(path, display, *, scope_class):
    return inventory.Observation(
        run_id="inventory-root-1",
        path=path,
        display_path=display,
        kind="directory",
        physical_kind="directory",
        scope_class=scope_class,
        scope_rule_id=scope_class,
        traversal="not-entered",
        content_inspected=False,
        excluded_reason=scope_class,
        identity=inventory.FileIdentity(
            device=1,
            inode=3,
            mode=stat.S_IFDIR | 0o700,
            size=0,
            mtime_ns=100,
        ),
        fingerprint_kind="metadata",
        fingerprint_value=None,
        descendant_unknown=1,
    )


def safe_relative_symlink_observation(path, display, *, target="a.md"):
    return inventory.Observation(
        run_id="inventory-root-1",
        path=path,
        display_path=display,
        kind="symlink",
        physical_kind="symlink",
        scope_class="eligible",
        scope_rule_id="active-workstream-content",
        traversal="not-entered",
        content_inspected=False,
        excluded_reason="symlink",
        identity=inventory.FileIdentity(
            device=1,
            inode=4,
            mode=stat.S_IFLNK | 0o777,
            size=len(target),
            mtime_ns=100,
        ),
        fingerprint_kind="metadata",
        fingerprint_value=None,
        link_text_status="safe-relative",
        safe_link_text=target,
    )


class RootReviewAssemblerTest(unittest.TestCase):
    def _single_v2_snapshot(self):
        path = inventory.canonical_raw_path((b"projects", b"alpha", b"a.md"))
        return run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        path,
                        "projects/alpha/a.md",
                        text="[self](a.md)",
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-context-validation",
            snapshot_id="snapshot-context-validation",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                path: "11111111-1111-4111-8111-111111111111"
            },
        )

    def test_partial_root_coverage_is_bound_and_reference_incomplete(self):
        root_path = inventory.canonical_raw_path((b"projects", b"alpha"))
        file_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"docs", b"a.md")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    partial_directory_observation(
                        root_path,
                        "projects/alpha",
                    ),
                    projected_observation(
                        file_path,
                        "projects/alpha/docs/a.md",
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-1",
            snapshot_id="snapshot-1",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                file_path: "11111111-1111-4111-8111-111111111111"
            },
        )

        unit = prepared.batch_units[0]
        self.assertFalse(unit.reference_complete)
        self.assertIn("reference-incomplete", unit.warning_codes)
        payload = json.loads(prepared.snapshot_payload_json)
        self.assertEqual(
            payload["analysis_contexts"][0]["coverage_issues"],
            [
                {
                    "kind": "error",
                    "path": root_path,
                    "reason": "descendant-unknown",
                }
            ],
        )

    def test_uninspected_policy_relevant_document_outside_workstream_root_closes_frontier(self):
        active_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"spec.md")
        )
        fallback_path = inventory.canonical_raw_path((b"docs", b"index.md"))
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        active_path,
                        "projects/alpha/spec.md",
                    ),
                    observation(
                        fallback_path,
                        "docs/index.md",
                        rule="fallback-unassigned",
                        inspected=False,
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-global-frontier",
            snapshot_id="snapshot-global-frontier",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                active_path: "11111111-1111-4111-8111-111111111111",
                fallback_path: "22222222-2222-4222-8222-222222222222",
            },
        )

        payload = json.loads(prepared.snapshot_payload_json)
        context = payload["analysis_contexts"][0]
        self.assertFalse(context["frontier_complete"])
        self.assertIn(
            fallback_path,
            {document["path"] for document in context["documents"]},
        )
        references_by_path = {
            item["reference"]["candidate_path"]: item["reference"]
            for unit in payload["units"]
            for item in unit["analysis_provenance"]["items"]
        }
        self.assertFalse(references_by_path[active_path]["complete"])
        self.assertIn(
            {
                "kind": "exclusion",
                "path": fallback_path,
                "reason": "content-uninspected",
            },
            context["coverage_issues"],
        )

    def test_control_and_never_touch_files_inside_workstream_root_are_unopened_exclusions(self):
        active_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"spec.md")
        )
        control_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b".control.md")
        )
        never_touch_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"sealed.key")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        active_path,
                        "projects/alpha/spec.md",
                    ),
                    observation(
                        control_path,
                        "projects/alpha/.control.md",
                        scope_class="control",
                        rule="control",
                        inspected=False,
                    ),
                    observation(
                        never_touch_path,
                        "projects/alpha/sealed.key",
                        scope_class="never-touch",
                        rule="never-touch",
                        inspected=False,
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-workstream-control-frontier",
            snapshot_id="snapshot-workstream-control-frontier",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                active_path: "11111111-1111-4111-8111-111111111111",
                control_path: "22222222-2222-4222-8222-222222222222",
                never_touch_path: "33333333-3333-4333-8333-333333333333",
            },
        )

        payload = json.loads(prepared.snapshot_payload_json)
        context = payload["analysis_contexts"][0]
        document_by_path = {
            document["path"]: document for document in context["documents"]
        }

        for path, scope_class in (
            (control_path, "control"),
            (never_touch_path, "never-touch"),
        ):
            with self.subTest(scope_class=scope_class):
                restricted_document = document_by_path[path]
                self.assertEqual(
                    restricted_document["exclusion_reason"],
                    "restricted-scope",
                )
                self.assertIsNone(restricted_document["error"])
                self.assertFalse(restricted_document["inspected"])
                self.assertIsNone(restricted_document["projection"])
                self.assertEqual(
                    restricted_document["scope_class"],
                    scope_class,
                )
                self.assertRegex(
                    restricted_document["fingerprint"],
                    r"^[0-9a-f]{64}$",
                )
        self.assertFalse(context["frontier_complete"])
        reference_by_path = {
            item["reference"]["candidate_path"]: item["reference"]
            for unit in payload["units"]
            for item in unit["analysis_provenance"]["items"]
        }
        self.assertFalse(reference_by_path[active_path]["complete"])

    def test_restricted_file_inside_selected_external_root_closes_frontier(self):
        active_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"spec.md")
        )
        fallback_path = inventory.canonical_raw_path((b"docs", b"index.md"))
        control_path = inventory.canonical_raw_path(
            (b"docs", b".control.md")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        active_path,
                        "projects/alpha/spec.md",
                    ),
                    observation(
                        fallback_path,
                        "docs/index.md",
                        rule="fallback-unassigned",
                    ),
                    observation(
                        control_path,
                        "docs/.control.md",
                        scope_class="control",
                        rule="control",
                        inspected=False,
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-external-control-frontier",
            snapshot_id="snapshot-external-control-frontier",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                active_path: "11111111-1111-4111-8111-111111111111",
                fallback_path: "22222222-2222-4222-8222-222222222222",
                control_path: "33333333-3333-4333-8333-333333333333",
            },
        )

        payload = json.loads(prepared.snapshot_payload_json)
        context = payload["analysis_contexts"][0]
        document_by_path = {
            document["path"]: document for document in context["documents"]
        }
        restricted = document_by_path[control_path]
        self.assertEqual(restricted["exclusion_reason"], "restricted-scope")
        self.assertFalse(restricted["inspected"])
        self.assertIsNone(restricted["projection"])
        self.assertFalse(context["frontier_complete"])

        reference_by_path = {
            item["reference"]["candidate_path"]: item["reference"]
            for unit in payload["units"]
            for item in unit["analysis_provenance"]["items"]
        }
        self.assertFalse(reference_by_path[active_path]["complete"])
        self.assertFalse(reference_by_path[fallback_path]["complete"])

    def test_safe_relative_symlink_inside_workstream_closes_frontier_unopened(self):
        active_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"a.md")
        )
        link_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"a-link")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        active_path,
                        "projects/alpha/a.md",
                    ),
                    safe_relative_symlink_observation(
                        link_path,
                        "projects/alpha/a-link",
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-safe-symlink-frontier",
            snapshot_id="snapshot-safe-symlink-frontier",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                active_path: "11111111-1111-4111-8111-111111111111",
            },
        )

        payload = json.loads(prepared.snapshot_payload_json)
        context = payload["analysis_contexts"][0]
        self.assertEqual(
            context["coverage_issues"],
            [
                {
                    "kind": "exclusion",
                    "path": link_path,
                    "reason": "symlink",
                }
            ],
        )
        self.assertFalse(context["frontier_complete"])
        self.assertNotIn(
            link_path,
            {document["path"] for document in context["documents"]},
        )
        self.assertTrue(
            all(
                link_path not in (edge["source_path"], edge["target_path"])
                for edge in context["edges"]
            )
        )
        reference_by_path = {
            item["reference"]["candidate_path"]: item["reference"]
            for unit in payload["units"]
            for item in unit["analysis_provenance"]["items"]
        }
        self.assertFalse(reference_by_path[active_path]["complete"])

    def test_restricted_directory_gap_inside_workstream_root_closes_frontier(self):
        active_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"spec.md")
        )
        restricted_root = inventory.canonical_raw_path(
            (b"projects", b"alpha", b".control")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        active_path,
                        "projects/alpha/spec.md",
                    ),
                    restricted_directory_observation(
                        restricted_root,
                        "projects/alpha/.control",
                        scope_class="control",
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-workstream-control-gap",
            snapshot_id="snapshot-workstream-control-gap",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                active_path: "11111111-1111-4111-8111-111111111111",
            },
        )

        context = json.loads(prepared.snapshot_payload_json)[
            "analysis_contexts"
        ][0]

        self.assertFalse(context["frontier_complete"])
        self.assertEqual(
            context["coverage_issues"],
            [
                {
                    "kind": "error",
                    "path": restricted_root,
                    "reason": "descendant-unknown",
                },
                {
                    "kind": "exclusion",
                    "path": restricted_root,
                    "reason": "control",
                },
                {
                    "kind": "exclusion",
                    "path": restricted_root,
                    "reason": "traversal-not-entered",
                },
            ],
        )

    def test_root_projects_navigation_is_singleton_without_control_tree_expansion(self):
        active_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"spec.md")
        )
        navigation_path = inventory.canonical_raw_path((b"_projects.md",))
        registry_control_path = inventory.canonical_raw_path(
            (b"_registry", b"secret.md")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        active_path,
                        "projects/alpha/spec.md",
                    ),
                    observation(
                        navigation_path,
                        "_projects.md",
                        scope_class="control",
                        rule="control",
                        inspected=False,
                    ),
                    observation(
                        registry_control_path,
                        "_registry/secret.md",
                        scope_class="control",
                        rule="control",
                        inspected=False,
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-navigation-singleton",
            snapshot_id="snapshot-navigation-singleton",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                active_path: "11111111-1111-4111-8111-111111111111",
                navigation_path: "22222222-2222-4222-8222-222222222222",
                registry_control_path: "33333333-3333-4333-8333-333333333333",
            },
        )

        context = json.loads(prepared.snapshot_payload_json)[
            "analysis_contexts"
        ][0]
        document_paths = {
            document["path"] for document in context["documents"]
        }

        self.assertIn(navigation_path, document_paths)
        self.assertNotIn(registry_control_path, document_paths)
        self.assertIn(navigation_path, context["scanned_roots"])
        self.assertNotIn(
            inventory.canonical_raw_path((b"_registry",)),
            context["scanned_roots"],
        )
        self.assertNotIn(inventory.canonical_raw_path(()), context["scanned_roots"])
        self.assertEqual(
            context["navigation_sources"],
            [
                {
                    "path": navigation_path,
                    "sha256": next(
                        document["fingerprint"]
                        for document in context["documents"]
                        if document["path"] == navigation_path
                    ),
                }
            ],
        )
        self.assertFalse(context["frontier_complete"])

    def test_root_snapshot_v2_rejects_tampered_workstream_projection(self):
        prepared = self._single_v2_snapshot()

        for field, replacement in (
            ("review_items", 0),
            ("blocked", 0),
            ("errors", 1),
            ("lifecycle", "paused"),
        ):
            with self.subTest(field=field):
                payload = json.loads(prepared.snapshot_payload_json)
                alpha = next(
                    row
                    for row in payload["review_context"]["workstreams"]
                    if row["workstream_id"] == "alpha"
                )
                alpha[field] = replacement

                with self.assertRaisesRegex(
                    run_review.RunReviewError,
                    "workstream|context",
                ):
                    run_review.review_document_from_campaign_snapshot(
                        inventory._canonical_json_bytes(payload)
                    )

    def test_private_sealed_row_rejects_disguised_fingerprint_value(self):
        private_path = inventory.canonical_raw_path((b"private", b"note.md"))
        value = observation(
            private_path,
            "private/note.md",
            scope_class="private-reviewable",
            rule="private-reviewable",
            inspected=False,
        ).to_dict()
        value["fingerprint"]["value"] = "a" * 64

        with self.assertRaisesRegex(run_review.RunReviewError, "content evidence"):
            run_review._parse_observation_line(
                inventory._canonical_json_bytes(value),
                "inventory-root-1",
            )

    def test_v2_projected_siblings_reach_folder_with_bound_analysis_provenance(self):
        first_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"docs", b"a.md")
        )
        second_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"docs", b"b.md")
        )
        source = package(
            (
                projected_observation(
                    first_path,
                    "projects/alpha/docs/a.md",
                    text="",
                ),
                projected_observation(
                    second_path,
                    "projects/alpha/docs/b.md",
                    text="",
                ),
            )
        )
        prepared = run_review.prepare_root_review(
            source,
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-1",
            snapshot_id="snapshot-1",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                first_path: "11111111-1111-4111-8111-111111111111",
                second_path: "22222222-2222-4222-8222-222222222222",
            },
        )

        self.assertEqual(
            prepared.snapshot_sha256,
            "add65cdcc0678820d1f57fd2612d6fa44e0bd1948a1157bae87b045c5b72cbf7",
        )
        self.assertEqual(len(prepared.batch_units), 1)
        unit = prepared.batch_units[0]
        self.assertEqual(unit.unit_kind, "folder")
        self.assertTrue(unit.reference_complete)
        self.assertFalse(unit.target_proven)
        self.assertIsNone(unit.target_path)
        provenance = json.loads(unit.analysis_provenance_json)
        self.assertEqual(len(provenance["items"]), 2)
        self.assertTrue(
            all(item["reference"]["complete"] for item in provenance["items"])
        )
        self.assertTrue(
            all(item["target"]["status"] == "blocked" for item in provenance["items"])
        )
        self.assertTrue(
            all(
                item["target"]["uncertainty"] == "classification-not-confirmed"
                for item in provenance["items"]
            )
        )
        self.assertTrue(
            all(item["risk"]["band"] == "blocked" for item in provenance["items"])
        )
        self.assertEqual(len(prepared.import_plan.placement_target_candidates), 2)
        evidence = b"\n".join(
            row.evidence_json
            for row in prepared.import_plan.classification_candidates
        )
        self.assertIn(b'"provider":"exact-duplicate"', evidence)

    def test_v2_safe_classification_projection_reaches_production_classifier(self):
        path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"release-notes.md")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        path,
                        "projects/alpha/release-notes.md",
                        text="# Alpha release notes\n",
                        fingerprint="8" * 64,
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-safe-classification",
            snapshot_id="snapshot-safe-classification",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                path: "11111111-1111-4111-8111-111111111111"
            },
        )

        evidence = b"\n".join(
            candidate.evidence_json
            for candidate in prepared.import_plan.classification_candidates
        )
        self.assertIn(b'"provider":"safe-content-token"', evidence)

    def test_root_snapshot_v2_shares_one_reference_context_across_items(self):
        alpha_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"a.md")
        )
        beta_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"b.md")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        alpha_path,
                        "projects/alpha/a.md",
                        text="[beta](b.md)",
                        fingerprint="8" * 64,
                    ),
                    projected_observation(
                        beta_path,
                        "projects/alpha/b.md",
                        text="[alpha](a.md)",
                        fingerprint="9" * 64,
                    ),
                )
            ),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-shared-context",
            snapshot_id="snapshot-shared-context",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                alpha_path: "11111111-1111-4111-8111-111111111111",
                beta_path: "22222222-2222-4222-8222-222222222222",
            },
        )

        payload = json.loads(prepared.snapshot_payload_json)
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(len(payload["analysis_contexts"]), 1)
        context = payload["analysis_contexts"][0]
        self.assertEqual(len(context["documents"]), 2)
        references_by_item = [
            item["reference"]
            for unit in payload["units"]
            for item in unit["analysis_provenance"]["items"]
        ]
        self.assertEqual(
            {row["context_id"] for row in references_by_item},
            {context["context_id"]},
        )
        self.assertEqual(
            {row["context_sha256"] for row in references_by_item},
            {context["context_sha256"]},
        )
        self.assertTrue(
            all("input_manifest" not in row for row in references_by_item)
        )

    def test_root_snapshot_reference_context_scales_linearly_under_runtime_bounds(self):
        def prepare_count(count):
            rows = []
            item_ids = {}
            for index in range(count):
                path = inventory.canonical_raw_path(
                    (
                        b"projects",
                        b"alpha",
                        ("doc-%04d.md" % index).encode("ascii"),
                    )
                )
                rows.append(
                    projected_observation(
                        path,
                        "projects/alpha/doc-%04d.md" % index,
                        text="",
                        fingerprint="%064x" % (index + 1),
                    )
                )
                item_ids[path] = str(uuid.UUID(int=index + 1, version=4))
            return run_review.prepare_root_review(
                package(tuple(rows), max_entries=count),
                compiled_policy(),
                approved_policy(),
                campaign_id="campaign-scale-%d" % count,
                snapshot_id="snapshot-scale-%d" % count,
                rendered_at="2026-07-15T03:00:00Z",
                item_ids_by_path=item_ids,
            )

        with mock.patch.object(
            inventory,
            "_reference_projection",
            wraps=inventory._reference_projection,
        ) as parser:
            forty = prepare_count(40)
        self.assertEqual(parser.call_count, 40)
        eighty = prepare_count(80)
        self.assertLess(
            len(eighty.snapshot_payload_json),
            len(forty.snapshot_payload_json) * 2.5,
        )
        for count in (830, 1266):
            prepared = prepare_count(count)
            self.assertLess(len(prepared.snapshot_payload_json), 64 * 1024 * 1024)
            self.assertEqual(
                len(json.loads(prepared.snapshot_payload_json)["analysis_contexts"]),
                1,
            )

    def test_root_snapshot_v2_rejects_missing_tampered_or_wrong_reference_context(self):
        prepared = self._single_v2_snapshot()

        missing = json.loads(prepared.snapshot_payload_json)
        del missing["analysis_contexts"]
        with self.assertRaises(run_review.RunReviewError):
            run_review.review_document_from_campaign_snapshot(
                inventory._canonical_json_bytes(missing)
            )

        tampered = json.loads(prepared.snapshot_payload_json)
        tampered["analysis_contexts"][0]["documents"].append(
            {
                "content_sha256": "a" * 64,
                "document_type": "markdown",
                "path": inventory.canonical_raw_path(
                    (b"projects", b"alpha", b"injected.md")
                ),
                "projection_sha256": "b" * 64,
                "projection_version": "internal-reference-v2",
            }
        )
        with self.assertRaisesRegex(
            run_review.RunReviewError,
            "hash mismatch|document fields",
        ):
            run_review.review_document_from_campaign_snapshot(
                inventory._canonical_json_bytes(tampered)
            )

        wrong = json.loads(prepared.snapshot_payload_json)
        wrong["units"][0]["analysis_provenance"]["items"][0]["reference"][
            "context_id"
        ] = "reference-context-" + "f" * 24
        with self.assertRaisesRegex(run_review.RunReviewError, "binding"):
            run_review.review_document_from_campaign_snapshot(
                inventory._canonical_json_bytes(wrong)
            )

    def test_root_snapshot_v2_requires_exact_provenance_membership(self):
        prepared = self._single_v2_snapshot()

        missing = json.loads(prepared.snapshot_payload_json)
        missing["units"][0]["analysis_provenance"]["items"] = []
        with self.assertRaisesRegex(run_review.RunReviewError, "membership|references"):
            run_review.review_document_from_campaign_snapshot(
                inventory._canonical_json_bytes(missing)
            )

        extra = json.loads(prepared.snapshot_payload_json)
        extra_item = json.loads(
            inventory._canonical_json_bytes(
                extra["units"][0]["analysis_provenance"]["items"][0]
            )
        )
        extra_item["item_id"] = "22222222-2222-4222-8222-222222222222"
        extra["units"][0]["analysis_provenance"]["items"].append(extra_item)
        with self.assertRaisesRegex(run_review.RunReviewError, "membership|references"):
            run_review.review_document_from_campaign_snapshot(
                inventory._canonical_json_bytes(extra)
            )

        duplicate = json.loads(prepared.snapshot_payload_json)
        duplicate["units"][0]["analysis_provenance"]["items"].append(
            duplicate["units"][0]["analysis_provenance"]["items"][0]
        )
        with self.assertRaisesRegex(run_review.RunReviewError, "membership|references"):
            run_review.review_document_from_campaign_snapshot(
                inventory._canonical_json_bytes(duplicate)
            )

    def test_root_snapshot_v2_rejects_member_path_binding_mismatch(self):
        prepared = self._single_v2_snapshot()
        payload = json.loads(prepared.snapshot_payload_json)
        payload["units"][0]["member_paths"][0] = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"other.md")
        )

        with self.assertRaisesRegex(run_review.RunReviewError, "binding|candidate"):
            run_review.review_document_from_campaign_snapshot(
                inventory._canonical_json_bytes(payload)
            )

    def test_root_snapshot_v2_rejects_rehashed_unknown_nested_context_field(self):
        prepared = self._single_v2_snapshot()
        payload = json.loads(prepared.snapshot_payload_json)
        context = payload["analysis_contexts"][0]
        context["documents"][0]["raw_body"] = "LEAK_SENTINEL"
        content = {
            key: value
            for key, value in context.items()
            if key
            not in {
                "content_sha256",
                "context_id",
                "context_sha256",
                "schema_version",
            }
        }
        context["content_sha256"] = sha256_bytes(
            inventory._canonical_json_bytes(content)
        )
        context["context_id"] = "reference-context-%s" % context[
            "content_sha256"
        ][:24]
        context.pop("context_sha256")
        context["context_sha256"] = sha256_bytes(
            inventory._canonical_json_bytes(context)
        )
        manifest_sha256 = sha256_bytes(
            inventory._canonical_json_bytes(context)
        )
        for unit in payload["units"]:
            for item in unit["analysis_provenance"]["items"]:
                reference = item["reference"]
                reference["context_id"] = context["context_id"]
                reference["context_sha256"] = context["context_sha256"]
                reference["input_manifest_sha256"] = manifest_sha256

        with self.assertRaisesRegex(run_review.RunReviewError, "context|document"):
            run_review.review_document_from_campaign_snapshot(
                inventory._canonical_json_bytes(payload)
            )

    def test_root_snapshot_v1_remains_read_only_compatible(self):
        prepared = self._single_v2_snapshot()
        legacy = json.loads(prepared.snapshot_payload_json)
        legacy["schema_version"] = 1
        del legacy["analysis_contexts"]

        restored = run_review.review_document_from_campaign_snapshot(
            inventory._canonical_json_bytes(legacy)
        )

        self.assertEqual(restored.items, prepared.review_document.items)

    def test_root_snapshot_finds_cross_workstream_inbound_reference(self):
        current_policy = compiled_policy()
        beta = policy.CompiledWorkstream(
            id="beta",
            lifecycle="active",
            project_home="/private/tmp/raw/projects/beta",
            aliases=("beta",),
        )
        current_policy = replace(
            current_policy,
            workstreams=current_policy.workstreams + (beta,),
        )
        alpha_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"spec.md")
        )
        beta_path = inventory.canonical_raw_path(
            (b"projects", b"beta", b"index.md")
        )
        prepared = run_review.prepare_root_review(
            package(
                (
                    projected_observation(
                        alpha_path,
                        "projects/alpha/spec.md",
                        text="",
                        fingerprint="8" * 64,
                    ),
                    projected_observation(
                        beta_path,
                        "projects/beta/index.md",
                        text="[alpha](../alpha/spec.md)",
                        fingerprint="9" * 64,
                    ),
                )
            ),
            current_policy,
            approved_policy(),
            campaign_id="campaign-cross-root",
            snapshot_id="snapshot-cross-root",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                alpha_path: "11111111-1111-4111-8111-111111111111",
                beta_path: "22222222-2222-4222-8222-222222222222",
            },
        )

        payload = json.loads(prepared.snapshot_payload_json)
        references_by_path = {
            item["reference"]["candidate_path"]: item["reference"]
            for unit in payload["units"]
            for item in unit["analysis_provenance"]["items"]
        }
        self.assertTrue(references_by_path[alpha_path]["complete"])
        self.assertEqual(
            references_by_path[alpha_path]["matches"],
            [
                {
                    "direction": "inbound",
                    "reference_kind": "markdown-inline",
                    "source_path": beta_path,
                    "target_path": alpha_path,
                }
            ],
        )

    def test_v1_inspected_observation_remains_file_only_and_reference_incomplete(self):
        path = inventory.canonical_raw_path((b"projects", b"alpha", b"legacy.md"))
        prepared = run_review.prepare_root_review(
            package((observation(path, "projects/alpha/legacy.md"),)),
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-1",
            snapshot_id="snapshot-1",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                path: "11111111-1111-4111-8111-111111111111"
            },
        )

        self.assertEqual(len(prepared.batch_units), 1)
        self.assertEqual(prepared.batch_units[0].unit_kind, "file")
        self.assertFalse(prepared.batch_units[0].reference_complete)
        payload = json.loads(prepared.snapshot_payload_json)
        self.assertEqual(
            payload["analysis_contexts"][0]["coverage_issues"][0]["reason"],
            "projection-unavailable-v1",
        )

    def test_root_directory_observation_is_coverage_not_an_item_identity(self):
        path = inventory.canonical_raw_path((b"projects", b"alpha", b"a.md"))
        source = package(
            (
                root_observation(),
                observation(path, "projects/alpha/a.md"),
            )
        )

        self.assertEqual(run_review.root_review_item_paths(source), (path,))
        prepared = run_review.prepare_root_review(
            source,
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-1",
            snapshot_id="snapshot-1",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path={
                path: "11111111-1111-4111-8111-111111111111"
            },
        )
        self.assertEqual(len(prepared.import_plan.items), 1)
        self.assertEqual(len(prepared.import_plan.observations), 2)

    def test_sealed_metadata_builds_tentative_import_units_and_run_overview(self):
        active_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"spec.md")
        )
        private_path = inventory.canonical_raw_path((b"private", b"note.md"))
        source = package(
            (
                observation(active_path, "projects/alpha/spec.md"),
                observation(
                    private_path,
                    "private/note.md",
                    scope_class="private-reviewable",
                    rule="private-reviewable",
                    inspected=False,
                ),
            )
        )
        ids = {
            active_path: "11111111-1111-4111-8111-111111111111",
            private_path: "22222222-2222-4222-8222-222222222222",
        }

        self.assertEqual(
            run_review.root_review_item_paths(source),
            tuple(sorted(ids)),
        )

        prepared = run_review.prepare_root_review(
            source,
            compiled_policy(),
            approved_policy(),
            campaign_id="campaign-1",
            snapshot_id="snapshot-1",
            rendered_at="2026-07-15T03:00:00Z",
            item_ids_by_path=ids,
        )

        self.assertEqual(
            {row.item_id for row in prepared.import_plan.items}, set(ids.values())
        )
        self.assertEqual(len(prepared.import_plan.observations), 2)
        self.assertEqual(len(prepared.import_plan.links), 2)
        self.assertEqual(
            {row.axis for row in prepared.import_plan.classification_candidates},
            {"workstream", "role", "authority", "lifecycle"},
        )
        self.assertEqual(len(prepared.batch_units), 2)
        active = next(unit for unit in prepared.batch_units if unit.path == active_path)
        private = next(unit for unit in prepared.batch_units if unit.path == private_path)
        self.assertEqual(active.primary_workstream, "alpha")
        self.assertEqual(active.document_role, "docs")
        self.assertEqual(private.primary_workstream, "unassigned")
        self.assertEqual(private.risk_band, "blocked")
        self.assertFalse(active.reference_complete)
        self.assertIn("reference-incomplete", active.warning_codes)
        self.assertIn("private-metadata-only", private.warning_codes)
        self.assertIn("reference-incomplete", private.warning_codes)
        self.assertNotIn(b"private body", prepared.snapshot_payload_json)
        self.assertEqual(
            prepared.snapshot_sha256,
            "979e32080dc7b0b66492351901c5ff630398195965fe820d1ff269905700c43a",
        )
        payload = json.loads(prepared.snapshot_payload_json)
        self.assertFalse(payload["structural_approval_ready"])
        self.assertEqual(payload["units"], [unit.to_dict() for unit in prepared.batch_units])
        for serialized_unit in payload["units"]:
            self.assertIn("analysis_provenance", serialized_unit)
            self.assertIn("target_proven", serialized_unit)
            for item_provenance in serialized_unit["analysis_provenance"]["items"]:
                self.assertIn("reference", item_provenance)
                self.assertIn("risk", item_provenance)
                self.assertIn("target", item_provenance)
        self.assertEqual(prepared.review_document.source_kind, "campaign-snapshot")
        self.assertEqual(
            prepared.review_document.source_snapshot_sha256,
            prepared.snapshot_sha256,
        )
        self.assertEqual(
            run_review.review_document_from_campaign_snapshot(
                prepared.snapshot_payload_json
            ),
            prepared.review_document,
        )
        self.assertEqual(
            tuple(row.unit_id for row in prepared.review_document.items),
            tuple(sorted(unit.unit_id for unit in prepared.batch_units)),
        )

    def test_item_ids_are_explicit_uuid4_and_never_derived_from_path_or_hash(self):
        path = inventory.canonical_raw_path((b"projects", b"alpha", b"a.md"))
        source = package((observation(path, "projects/alpha/a.md"),))

        with self.assertRaisesRegex(run_review.RunReviewError, "item id mapping"):
            run_review.prepare_root_review(
                source,
                compiled_policy(),
                approved_policy(),
                campaign_id="campaign-1",
                snapshot_id="snapshot-1",
                rendered_at="2026-07-15T03:00:00Z",
                item_ids_by_path={},
            )
        with self.assertRaisesRegex(run_review.RunReviewError, "UUID4"):
            run_review.prepare_root_review(
                source,
                compiled_policy(),
                approved_policy(),
                campaign_id="campaign-1",
                snapshot_id="snapshot-1",
                rendered_at="2026-07-15T03:00:00Z",
                item_ids_by_path={path: "item-from-path-hash"},
            )

    def test_package_policy_and_canonical_artifacts_are_reverified(self):
        path = inventory.canonical_raw_path((b"projects", b"alpha", b"a.md"))
        source = package((observation(path, "projects/alpha/a.md"),))
        tampered = inventory.InventoryPackageReadback(
            source.terminal,
            source.request,
            (
                source.artifacts[0],
                ("observations.jsonl", source.artifacts[1][1] + b"{}"),
            ),
        )

        with self.assertRaisesRegex(run_review.RunReviewError, "canonical"):
            run_review.prepare_root_review(
                tampered,
                compiled_policy(),
                approved_policy(),
                campaign_id="campaign-1",
                snapshot_id="snapshot-1",
                rendered_at="2026-07-15T03:00:00Z",
                item_ids_by_path={
                    path: "11111111-1111-4111-8111-111111111111"
                },
            )

        stale = approved_policy()
        object.__setattr__(stale, "generation", 2)
        with self.assertRaisesRegex(run_review.RunReviewError, "policy"):
            run_review.prepare_root_review(
                source,
                compiled_policy(),
                stale,
                campaign_id="campaign-1",
                snapshot_id="snapshot-1",
                rendered_at="2026-07-15T03:00:00Z",
                item_ids_by_path={
                    path: "11111111-1111-4111-8111-111111111111"
                },
            )


if __name__ == "__main__":
    unittest.main()
