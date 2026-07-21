import ast
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import references, review_compiler, review_context  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes, sha256_bytes  # noqa: E402


def context():
    return review_context.ReviewContext(
        rendered_at="2026-07-15T04:00:00Z",
        policy_binding="generation=1;source=INITIAL/policy-1;guard=0",
        coverage=review_compiler.CoverageSummary(
            folders_total=2,
            folders_traversed=2,
            folders_excluded=0,
            folders_error=0,
            files_total=2,
            files_inspected=0,
            files_metadata_only=2,
            files_excluded=0,
            files_error=0,
        ),
        workstreams=(
            review_compiler.WorkstreamSummary(
                workstream_id="alpha",
                lifecycle="active",
                review_items=2,
                blocked=0,
                errors=0,
            ),
        ),
        warning_codes=("m2-no-structural-authority",),
    )


def unit(unit_id, item_id, path):
    return {
        "access_domain": "local",
        "analysis_provenance": {
            "items": [
                {
                    "item_id": item_id,
                    "reference": {
                        "complete": True,
                        "input_manifest_sha256": "c" * 64,
                    },
                    "risk": {"band": "medium", "input_sha256": "d" * 64},
                    "target": {"input_sha256": "e" * 64, "status": "blocked"},
                }
            ],
            "schema_version": 1,
        },
        "authority": "reference",
        "canonical_conflict": False,
        "canonical_path": path,
        "context_freshness": "fresh",
        "display_path": path,
        "document_lifecycle": "current",
        "document_role": "docs",
        "effect_count": 0,
        "effect_codes": ["plan-unavailable-m2"],
        "evidence_providers": ["registry-route"],
        "file_count": 1,
        "lifecycle_class": "active",
        "member_item_ids": [item_id],
        "member_paths": [path],
        "override_class": "none",
        "primary_workstream": "alpha",
        "recommended_action": "keep",
        "reference_complete": True,
        "relation_conflict": False,
        "related_workstreams": [],
        "risk_band": "medium",
        "scope_rule_id": "active-workstream-content",
        "scope_class": "eligible",
        "sensitivity": "standard",
        "shared": False,
        "target_path": None,
        "target_proven": False,
        "total_bytes": 10,
        "unit_id": unit_id,
        "unit_kind": "file",
        "underlying_file_count": 1,
        "warning_codes": ["m2-no-structural-authority"],
    }


def analysis_context(context_name="alpha", edges=()):
    document_paths = tuple(
        sorted(
            {
                "projects/%s/a.md" % context_name,
                "projects/%s/b.md" % context_name,
            }
            | {
                path
                for source, target, _kind in edges
                for path in (source, target)
            }
        )
    )
    content = {
        "analyzer_version": "reference-m2-v2",
        "coverage_issues": [],
        "documents": [
            {
                "document_type": "markdown",
                "error": None,
                "exclusion_reason": None,
                "fingerprint": sha256_bytes(path.encode("utf-8")),
                "inspected": True,
                "path": path,
                "projection": None,
                "scope_class": "eligible",
            }
            for path in document_paths
        ],
        "edges": [
            {
                "reference_kind": kind,
                "source_path": source,
                "target_path": target,
            }
            for source, target, kind in edges
        ],
        "frontier_complete": True,
        "navigation_sources": [],
        "parser_types": [
            "generated-navigation-source",
            "html-attribute",
            "markdown-autolink",
            "markdown-inline",
            "markdown-reference",
            "registry-path",
            "safe-path-literal",
        ],
        "registry_source": {
            "kind": "compiled-registry",
            "sha256": sha256_bytes(context_name.encode("utf-8")),
            "source_id": "placement-registry",
        },
        "scanned_roots": ["projects/%s" % context_name],
    }
    content_sha256 = sha256_bytes(canonical_json_bytes(content))
    value = dict(content)
    value.update(
        {
            "content_sha256": content_sha256,
            "context_id": "reference-context-%s" % content_sha256[:24],
            "schema_version": 1,
        }
    )
    value["context_sha256"] = sha256_bytes(canonical_json_bytes(value))
    return value


def reseal_context(value):
    resealed = json.loads(canonical_json_bytes(value))
    content = {
        key: item
        for key, item in resealed.items()
        if key
        not in {
            "content_sha256",
            "context_id",
            "context_sha256",
            "schema_version",
        }
    }
    content_sha256 = sha256_bytes(canonical_json_bytes(content))
    resealed["content_sha256"] = content_sha256
    resealed["context_id"] = "reference-context-%s" % content_sha256[:24]
    resealed.pop("context_sha256", None)
    resealed["context_sha256"] = sha256_bytes(canonical_json_bytes(resealed))
    return resealed


def bind_unit_to_context(value, context_value):
    bound = json.loads(canonical_json_bytes(value))
    paths = dict(zip(bound["member_item_ids"], bound["member_paths"]))
    for item in bound["analysis_provenance"]["items"]:
        candidate_path = paths[item["item_id"]]
        matches = []
        for edge in context_value["edges"]:
            direction = None
            if edge["source_path"] == candidate_path:
                direction = "outbound"
            elif edge["target_path"] == candidate_path:
                direction = "inbound"
            if direction is not None:
                matches.append(
                    {
                        "direction": direction,
                        "reference_kind": edge["reference_kind"],
                        "source_path": edge["source_path"],
                        "target_path": edge["target_path"],
                    }
                )
        matches.sort(
            key=lambda row: (
                0 if row["direction"] == "outbound" else 1,
                row["source_path"],
                row["target_path"],
                row["reference_kind"],
            )
        )
        item["reference"] = {
            "candidate_path": candidate_path,
            "complete": context_value["frontier_complete"]
            and any(
                candidate_path == root
                or candidate_path.startswith(root + "/")
                for root in context_value["scanned_roots"]
            ),
            "context_id": context_value["context_id"],
            "context_sha256": context_value["context_sha256"],
            "input_manifest_sha256": sha256_bytes(
                canonical_json_bytes(context_value)
            ),
            "matches": matches,
            "schema_version": 2,
        }
    return bound


class ReviewContextTest(unittest.TestCase):
    def test_current_m2_review_modules_and_tests_remain_python39_compatible(self):
        roots = (
            SCRIPT_DIR / "mnemosyne_core" / "review_context.py",
            SCRIPT_DIR / "mnemosyne_core" / "batch_service.py",
            SCRIPT_DIR / "mnemosyne_core" / "explode_service.py",
            SCRIPT_DIR / "mnemosyne_core" / "m2_workflow.py",
            Path(__file__),
            Path(__file__).with_name("test_mnemosyne_batch_service.py"),
            Path(__file__).with_name("test_mnemosyne_explode_service.py"),
            Path(__file__).with_name("test_mnemosyne_m2_workflow.py"),
        )

        for path in roots:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(
                    source,
                    filename=str(path),
                    feature_version=(3, 9),
                )
                incompatible_zip_calls = [
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "zip"
                    and any(
                        keyword.arg == "strict" for keyword in node.keywords
                    )
                ]
                self.assertEqual(incompatible_zip_calls, [])

    def test_reference_fixture_runs_with_python39_zip_call_contract(self):
        builtin_zip = zip

        def python39_zip(*values):
            return builtin_zip(*values)

        with mock.patch("builtins.zip", python39_zip):
            bound = bind_unit_to_context(
                unit(
                    "unit-a",
                    "00000000-0000-4000-8000-00000000000a",
                    "projects/alpha/a.md",
                ),
                analysis_context(),
            )

        self.assertEqual(
            bound["analysis_provenance"]["items"][0]["reference"][
                "candidate_path"
            ],
            "projects/alpha/a.md",
        )

    def test_analysis_context_bundle_roundtrips_exact_canonical_bytes(self):
        value = analysis_context()
        raw = canonical_json_bytes([value])

        bundle = review_context.AnalysisContextBundle.from_canonical_bytes(raw)

        self.assertEqual(bundle.canonical_bytes, raw)
        self.assertEqual(bundle.to_json_value(), [value])

    def test_analysis_context_bundle_parses_each_context_once_for_repeated_validation(self):
        context_value = analysis_context(
            edges=(
                (
                    "projects/alpha/a.md",
                    "projects/alpha/b.md",
                    "markdown-inline",
                ),
            )
        )
        value = bind_unit_to_context(
            unit(
                "unit-a",
                "00000000-0000-4000-8000-00000000000a",
                "projects/alpha/a.md",
            ),
            context_value,
        )

        with mock.patch.object(
            references,
            "reference_context_from_dict",
            wraps=references.reference_context_from_dict,
        ) as parser:
            bundle = review_context.AnalysisContextBundle.from_canonical_bytes(
                canonical_json_bytes([context_value])
            )
            bundle.require_exact_unit_bindings((value,))
            bundle.require_exact_unit_bindings((value,))
            bundle.to_json_value()

        self.assertEqual(parser.call_count, 1)

    def test_analysis_context_bundle_rejects_tampered_item_candidate_path(self):
        context_value = analysis_context(
            edges=(
                (
                    "projects/alpha/a.md",
                    "projects/alpha/b.md",
                    "markdown-inline",
                ),
            )
        )
        value = bind_unit_to_context(
            unit(
                "unit-a",
                "00000000-0000-4000-8000-00000000000a",
                "projects/alpha/a.md",
            ),
            context_value,
        )
        value["analysis_provenance"]["items"][0]["reference"][
            "candidate_path"
        ] = "projects/alpha/b.md"
        bundle = review_context.AnalysisContextBundle.from_canonical_bytes(
            canonical_json_bytes([context_value])
        )

        with self.assertRaisesRegex(
            review_context.ReviewContextError,
            "candidate path",
        ):
            bundle.require_exact_unit_bindings((value,))

    def test_analysis_context_bundle_requires_exact_item_membership(self):
        context_value = analysis_context()
        value = bind_unit_to_context(
            unit(
                "unit-a",
                "00000000-0000-4000-8000-00000000000a",
                "projects/alpha/a.md",
            ),
            context_value,
        )
        bundle = review_context.AnalysisContextBundle.from_canonical_bytes(
            canonical_json_bytes([context_value])
        )

        for label, mutate in (
            (
                "missing",
                lambda candidate: candidate["analysis_provenance"].update(
                    {"items": []}
                ),
            ),
            (
                "extra",
                lambda candidate: candidate["analysis_provenance"]["items"].append(
                    {
                        **candidate["analysis_provenance"]["items"][0],
                        "item_id": "00000000-0000-4000-8000-00000000000b",
                    }
                ),
            ),
            (
                "duplicate",
                lambda candidate: candidate["analysis_provenance"]["items"].append(
                    candidate["analysis_provenance"]["items"][0]
                ),
            ),
        ):
            with self.subTest(label=label):
                candidate = json.loads(canonical_json_bytes(value))
                mutate(candidate)
                with self.assertRaisesRegex(
                    review_context.ReviewContextError,
                    "references|membership",
                ):
                    bundle.require_exact_unit_bindings((candidate,))

    def test_analysis_context_bundle_rejects_member_path_mismatch(self):
        context_value = analysis_context()
        value = bind_unit_to_context(
            unit(
                "unit-a",
                "00000000-0000-4000-8000-00000000000a",
                "projects/alpha/a.md",
            ),
            context_value,
        )
        value["member_paths"][0] = "projects/alpha/other.md"
        bundle = review_context.AnalysisContextBundle.from_canonical_bytes(
            canonical_json_bytes([context_value])
        )

        with self.assertRaisesRegex(
            review_context.ReviewContextError,
            "candidate path",
        ):
            bundle.require_exact_unit_bindings((value,))

    def test_analysis_context_bundle_rejects_rehashed_duplicate_scanned_roots(self):
        value = analysis_context()
        value["scanned_roots"].append(value["scanned_roots"][0])
        value = reseal_context(value)

        with self.assertRaisesRegex(
            review_context.ReviewContextError,
            "scanned roots",
        ):
            review_context.AnalysisContextBundle.from_canonical_bytes(
                canonical_json_bytes([value])
            )

    def test_analysis_context_bundle_selects_exact_referenced_subset(self):
        alpha = analysis_context("alpha")
        beta = analysis_context("beta")
        alpha_unit = bind_unit_to_context(
            unit(
                "unit-a",
                "00000000-0000-4000-8000-00000000000a",
                "projects/alpha/a.md",
            ),
            alpha,
        )
        beta_unit = bind_unit_to_context(
            unit(
                "unit-b",
                "00000000-0000-4000-8000-00000000000b",
                "projects/beta/b.md",
            ),
            beta,
        )
        contexts = sorted((alpha, beta), key=lambda row: row["context_id"])
        bundle = review_context.AnalysisContextBundle.from_canonical_bytes(
            canonical_json_bytes(contexts)
        )
        bundle.require_exact_unit_bindings((alpha_unit, beta_unit))

        with self.assertRaisesRegex(
            review_context.ReviewContextError,
            "unrelated",
        ):
            bundle.require_exact_unit_bindings((alpha_unit,))

        original_matches_for = references.ReferenceContext.matches_for
        with mock.patch.object(
            references.ReferenceContext,
            "matches_for",
            autospec=True,
            side_effect=lambda context_value, candidate_path: original_matches_for(
                context_value, candidate_path
            ),
        ) as matches_for:
            selected = bundle.select_for_units((alpha_unit,))

        self.assertEqual(matches_for.call_count, 1)
        self.assertEqual(selected.to_json_value(), [alpha])

    def test_analysis_context_bundle_rejects_duplicate_context_ids(self):
        value = analysis_context()

        with self.assertRaisesRegex(
            review_context.ReviewContextError,
            "duplicated",
        ):
            review_context.AnalysisContextBundle.from_canonical_bytes(
                canonical_json_bytes([value, value])
            )

    def test_validated_unit_payload_uses_shared_review_row_mapping(self):
        value = unit(
            "unit-a",
            "00000000-0000-4000-8000-00000000000a",
            "projects/alpha/a.md",
        )

        self.assertEqual(set(value), review_context.REVIEW_UNIT_PAYLOAD_FIELDS)
        row = review_context.review_row_from_validated_unit_payload(value)

        self.assertEqual(
            row,
            review_compiler.ReviewRow(
                unit_id="unit-a",
                unit_kind="file",
                canonical_path="projects/alpha/a.md",
                display_path="projects/alpha/a.md",
                underlying_file_count=1,
                primary_workstream="alpha",
                related_workstreams=(),
                shared=False,
                document_role="docs",
                authority="reference",
                document_lifecycle="current",
                scope_class="eligible",
                sensitivity="standard",
                access_domain="local",
                recommended_action="keep",
                target_path=None,
                risk_band="medium",
                context_freshness="fresh",
                evidence_providers=("registry-route",),
                warning_codes=("m2-no-structural-authority",),
                effect_codes=("plan-unavailable-m2",),
            ),
        )

    def test_workstream_summaries_allow_zero_unit_root_projection(self):
        result = review_context.workstream_summaries_for_unit_payloads(
            (),
            context(),
        )

        self.assertEqual(
            result,
            (
                review_compiler.WorkstreamSummary(
                    workstream_id="alpha",
                    lifecycle="active",
                    review_items=0,
                    blocked=0,
                    errors=0,
                ),
            ),
        )

    def test_context_roundtrip_and_batch_document_reconstruction(self):
        review_context_value = context()
        encoded_context = review_context_value.canonical_bytes()
        analysis_context_value = analysis_context(
            edges=(
                (
                    "projects/alpha/a.md",
                    "projects/alpha/b.md",
                    "markdown-inline",
                ),
            )
        )
        self.assertEqual(
            review_context.ReviewContext.from_canonical_bytes(encoded_context),
            review_context_value,
        )
        payload = canonical_json_bytes(
            {
                "analysis_contexts": [analysis_context_value],
                "actor": "reviewer",
                "approval_ready": False,
                "batch_id": "batch-1",
                "batch_version": 1,
                "bounds": {
                    "bytes": 20,
                    "effects": 1,
                    "files": 5,
                    "items": 4,
                },
                "campaign_id": "campaign-1",
                "campaign_review_revision": 1,
                "campaign_snapshot_sha256": "a" * 64,
                "parent_snapshot_id": None,
                "parent_snapshot_sha256": None,
                "request_hash": "b" * 64,
                "review_context": json.loads(encoded_context),
                "schema_version": 2,
                "snapshot_id": "snapshot-1",
                "structural_approval_ready": False,
                "structural_blocker": "effect-preview-not-available-m2",
                "units": [
                    bind_unit_to_context(
                        unit(
                            "unit-a",
                            "00000000-0000-4000-8000-00000000000a",
                            "projects/alpha/a.md",
                        ),
                        analysis_context_value,
                    ),
                    bind_unit_to_context(
                        unit(
                            "unit-b",
                            "00000000-0000-4000-8000-00000000000b",
                            "projects/alpha/b.md",
                        ),
                        analysis_context_value,
                    ),
                ],
            }
        )

        document = review_context.batch_review_document_from_snapshot(payload)

        self.assertEqual(document.review_kind, "batch-preview")
        self.assertEqual(document.source_snapshot_sha256, sha256_bytes(payload))
        self.assertEqual(document.bounds.review_items, 2)
        self.assertEqual(document.bounds.underlying_files, 2)
        self.assertEqual(tuple(row.unit_id for row in document.items), ("unit-a", "unit-b"))

    def test_batch_document_rejects_context_or_membership_tamper(self):
        value = context()
        encoded = value.canonical_bytes()
        decoded = json.loads(encoded)
        decoded["warning_codes"].append("forged-warning")
        with self.assertRaises(review_context.ReviewContextError):
            review_context.ReviewContext.from_canonical_bytes(
                canonical_json_bytes(decoded)
            )

    def test_batch_snapshot_parser_keeps_nonempty_unit_invariant(self):
        analysis_context_value = analysis_context()
        payload = {
            "analysis_contexts": [analysis_context_value],
            "actor": "reviewer",
            "approval_ready": False,
            "batch_id": "batch-1",
            "batch_version": 1,
            "bounds": {"bytes": 1, "effects": 1, "files": 1, "items": 1},
            "campaign_id": "campaign-1",
            "campaign_review_revision": 1,
            "campaign_snapshot_sha256": "a" * 64,
            "parent_snapshot_id": None,
            "parent_snapshot_sha256": None,
            "request_hash": "b" * 64,
            "review_context": context().to_dict(),
            "schema_version": 2,
            "snapshot_id": "snapshot-1",
            "structural_approval_ready": False,
            "structural_blocker": "effect-preview-not-available-m2",
            "units": [],
        }

        with self.assertRaisesRegex(
            review_context.ReviewContextError,
            "contract",
        ):
            review_context.parse_batch_review_snapshot(
                canonical_json_bytes(payload),
                lineage_policy=review_context.GENESIS_BATCH_LINEAGE,
            )


if __name__ == "__main__":
    unittest.main()
