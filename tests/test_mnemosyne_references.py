import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import inventory, references  # noqa: E402


class ReferenceAnalyzerTest(unittest.TestCase):
    @staticmethod
    def _reseal_context(value):
        value = json.loads(references.canonical_json_bytes(value))
        content_payload = {
            key: item
            for key, item in value.items()
            if key
            not in {
                "content_sha256",
                "context_id",
                "context_sha256",
                "schema_version",
            }
        }
        value["content_sha256"] = references.sha256_bytes(
            references.canonical_json_bytes(content_payload)
        )
        value["context_id"] = "reference-context-%s" % value[
            "content_sha256"
        ][:24]
        context_payload = {
            key: item for key, item in value.items() if key != "context_sha256"
        }
        value["context_sha256"] = references.sha256_bytes(
            references.canonical_json_bytes(context_payload)
        )
        return value

    @staticmethod
    def _reference_rich_context(size, topology, *, counter=None):
        paths = tuple("docs/node-%04d.md" % index for index in range(size))
        documents = []
        for index, path in enumerate(paths):
            if topology == "chain" and index + 1 < size:
                text = "[next](node-%04d.md)" % (index + 1)
            elif topology == "star" and index:
                text = "[root](node-0000.md)"
            else:
                text = "# Node"
            documents.append(
                references.ReferenceDocument(
                    path=path,
                    document_type="markdown",
                    fingerprint=("%064x" % (index + 1))[-64:],
                    scope_class="eligible",
                    text=text,
                    inspected=True,
                )
            )
        context = references.ReferenceAnalyzer("refs-linear-v1").build_context(
            documents=tuple(documents),
            scanned_roots=("docs",),
            registry_source_sha256="f" * 64,
            traversal_counter=counter,
        )
        return context, paths

    def test_runtime_index_visits_each_edge_once_and_queries_only_matches(self):
        for topology in ("chain", "star"):
            for size in (40, 80, 160, 320):
                with self.subTest(topology=topology, size=size):
                    build_counter = references.ReferenceTraversalCounter()
                    context, paths = self._reference_rich_context(
                        size,
                        topology,
                        counter=build_counter,
                    )
                    self.assertEqual(build_counter.document_visits, size)
                    self.assertEqual(
                        build_counter.source_reference_visits,
                        size - 1,
                    )
                    self.assertEqual(build_counter.serialized_edge_visits, 0)
                    self.assertEqual(build_counter.indexed_edge_visits, size - 1)
                    query_counter = references.ReferenceTraversalCounter()
                    returned = sum(
                        len(
                            context.matches_for(
                                path,
                                traversal_counter=query_counter,
                            )
                        )
                        for path in paths
                    )
                    self.assertEqual(returned, 2 * (size - 1))
                    self.assertEqual(
                        query_counter.returned_match_visits,
                        2 * (size - 1),
                    )
                    self.assertEqual(query_counter.indexed_edge_visits, 0)

    def test_reference_rich_availability_sizes_have_linear_edge_visits(self):
        for size in (830, 1266):
            with self.subTest(size=size):
                build_counter = references.ReferenceTraversalCounter()
                context, paths = self._reference_rich_context(
                    size,
                    "chain",
                    counter=build_counter,
                )
                query_counter = references.ReferenceTraversalCounter()
                for path in paths:
                    context.matches_for(
                        path,
                        traversal_counter=query_counter,
                    )
                self.assertEqual(build_counter.document_visits, size)
                self.assertEqual(
                    build_counter.source_reference_visits,
                    size - 1,
                )
                self.assertEqual(build_counter.serialized_edge_visits, 0)
                self.assertEqual(build_counter.indexed_edge_visits, size - 1)
                self.assertEqual(
                    query_counter.returned_match_visits,
                    2 * (size - 1),
                )
                self.assertEqual(query_counter.indexed_edge_visits, 0)

    def test_strict_parser_reuses_canonical_hash_and_adjacency_index(self):
        context, paths = self._reference_rich_context(40, "chain")

        parse_counter = references.ReferenceTraversalCounter()
        parsed = references.reference_context_from_dict(
            context.to_dict(),
            traversal_counter=parse_counter,
        )
        counter = references.ReferenceTraversalCounter()

        self.assertEqual(parsed.to_dict(), context.to_dict())
        self.assertEqual(parsed.canonical_bytes, context.canonical_bytes)
        self.assertEqual(parsed.canonical_sha256, context.canonical_sha256)
        self.assertEqual(parse_counter.document_visits, 40)
        self.assertEqual(parse_counter.source_reference_visits, 0)
        self.assertEqual(parse_counter.serialized_edge_visits, 39)
        self.assertEqual(parse_counter.indexed_edge_visits, 39)
        expected_matches = context.matches_for(paths[20])
        with mock.patch.object(
            references,
            "canonical_json_bytes",
            side_effect=AssertionError("candidate lookup recomputed context JSON"),
        ):
            self.assertEqual(
                parsed.matches_for(paths[20], traversal_counter=counter),
                expected_matches,
            )
            self.assertEqual(parsed.canonical_sha256, context.canonical_sha256)
        self.assertEqual(counter.returned_match_visits, 2)
        self.assertEqual(counter.indexed_edge_visits, 0)

    def test_context_nested_payload_is_immutable_and_to_dict_is_detached(self):
        projection = inventory._reference_projection(
            (b"projects", b"alpha", b"index.md"),
            "[spec](spec.md)",
        )
        context = references.ReferenceAnalyzer("refs-immutable-v1").build_context(
            documents=(
                references.ReferenceDocument(
                    path=projection.source_path,
                    document_type="markdown",
                    fingerprint="a" * 64,
                    scope_class="eligible",
                    text=None,
                    inspected=True,
                    projection=projection,
                ),
            ),
            scanned_roots=(projection.source_path,),
            registry_source_sha256="b" * 64,
        )
        parsed = references.reference_context_from_dict(context.to_dict())
        baseline = parsed.to_dict()

        detached = parsed.to_dict()
        detached["documents"][0]["projection"]["references"][0][
            "target"
        ] = "projects/forged.md"

        self.assertEqual(parsed.to_dict(), baseline)
        self.assertEqual(parsed.canonical_bytes, context.canonical_bytes)
        with self.assertRaises(TypeError):
            parsed.documents[0]["projection"]["references"][0][
                "target"
            ] = "projects/forged.md"

    def test_strict_parser_rejects_unknown_nested_keys_even_when_resealed(self):
        first = inventory._reference_projection(
            (b"projects", b"alpha", b"_projects.md"),
            "[spec](spec.md)",
        )
        documents = (
            references.ReferenceDocument(
                path=first.source_path,
                document_type="generated-navigation",
                fingerprint="a" * 64,
                scope_class="eligible",
                text=None,
                inspected=True,
                projection=first,
            ),
            references.ReferenceDocument(
                path="projects/alpha/private.md",
                document_type="markdown",
                fingerprint="b" * 64,
                scope_class="protected",
                text=None,
                inspected=False,
                exclusion_reason="protected-scope",
            ),
        )
        original = references.ReferenceAnalyzer("refs-strict-v1").build_context(
            documents=documents,
            scanned_roots=("projects/alpha",),
            registry_source_sha256="c" * 64,
        ).to_dict()
        projected_index = next(
            index
            for index, row in enumerate(original["documents"])
            if row["projection"] is not None
        )
        mutations = {
            "context": lambda value: value.__setitem__("raw_body", "LEAK"),
            "registry": lambda value: value["registry_source"].__setitem__(
                "raw_body", "LEAK"
            ),
            "navigation": lambda value: value["navigation_sources"][0].__setitem__(
                "raw_body", "LEAK"
            ),
            "document": lambda value: value["documents"][0].__setitem__(
                "raw_body", "LEAK"
            ),
            "projection": lambda value: value["documents"][projected_index][
                "projection"
            ].__setitem__("raw_body", "LEAK"),
            "reference": lambda value: value["documents"][projected_index][
                "projection"
            ]["references"][0].__setitem__("raw_body", "LEAK"),
            "coverage": lambda value: value["coverage_issues"][0].__setitem__(
                "raw_body", "LEAK"
            ),
            "edge": lambda value: value["edges"][0].__setitem__(
                "raw_body", "LEAK"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                value = json.loads(references.canonical_json_bytes(original))
                mutate(value)
                value = self._reseal_context(value)
                with self.assertRaises(references.ReferenceAnalysisError):
                    references.reference_context_from_dict(value)

    def test_strict_parser_rejects_reordered_duplicates_and_forged_projection(self):
        projections = (
            inventory._reference_projection(
                (b"projects", b"alpha", b"a.md"),
                "[b](b.md)",
            ),
            inventory._reference_projection(
                (b"projects", b"alpha", b"b.md"),
                "# B",
            ),
        )
        original = references.ReferenceAnalyzer("refs-strict-v1").build_context(
            documents=tuple(
                references.ReferenceDocument(
                    path=projection.source_path,
                    document_type="markdown",
                    fingerprint=("a" if index == 0 else "b") * 64,
                    scope_class="eligible",
                    text=None,
                    inspected=True,
                    projection=projection,
                )
                for index, projection in enumerate(projections)
            ),
            scanned_roots=("projects/alpha",),
            registry_source_sha256="c" * 64,
        ).to_dict()

        invalid_values = []
        reordered_documents = json.loads(references.canonical_json_bytes(original))
        reordered_documents["documents"].reverse()
        invalid_values.append(reordered_documents)
        duplicate_edge = json.loads(references.canonical_json_bytes(original))
        duplicate_edge["edges"].append(dict(duplicate_edge["edges"][0]))
        invalid_values.append(duplicate_edge)
        forged_projection = json.loads(references.canonical_json_bytes(original))
        projection = forged_projection["documents"][0]["projection"]
        projection["references"][0]["target"] = "projects/alpha/other.md"
        projection_payload = {
            "parser_types": projection["parser_types"],
            "projection_version": projection["projection_version"],
            "references": projection["references"],
            "source_path": forged_projection["documents"][0]["path"],
        }
        projection["projection_sha256"] = references.sha256_bytes(
            references.canonical_json_bytes(projection_payload)
        )
        invalid_values.append(forged_projection)
        wrong_boolean = json.loads(references.canonical_json_bytes(original))
        wrong_boolean["frontier_complete"] = 1
        invalid_values.append(wrong_boolean)

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(references.ReferenceAnalysisError):
                    references.reference_context_from_dict(
                        self._reseal_context(value)
                    )

    def test_legacy_projection_parser_coverage_keeps_context_incomplete(self):
        source_path = inventory.canonical_raw_path(
            (b"projects", b"alpha", b"legacy.md")
        )
        payload = {
            "projection_version": "internal-reference-v1",
            "references": [],
            "source_path": source_path,
        }
        projection = inventory.ReferenceProjection(
            source_path=source_path,
            projection_version="internal-reference-v1",
            projection_sha256=hashlib.sha256(
                inventory._canonical_json_bytes(payload)
            ).hexdigest(),
            references=(),
            parser_types=inventory._LEGACY_REFERENCE_PARSER_TYPES,
        )
        document = references.ReferenceDocument(
            path=source_path,
            document_type="markdown",
            fingerprint="a" * 64,
            scope_class="eligible",
            text=None,
            inspected=True,
            projection=projection,
        )

        context = references.ReferenceAnalyzer("refs-legacy-v1").build_context(
            documents=(document,),
            scanned_roots=(
                inventory.canonical_raw_path((b"projects", b"alpha")),
            ),
            registry_source_sha256="b" * 64,
        )

        self.assertFalse(context.frontier_complete)
        self.assertEqual(
            tuple(
                (issue.kind, issue.path, issue.reason)
                for issue in context.coverage_issues
            ),
            (("exclusion", source_path, "parser-coverage-incomplete"),),
        )

    def test_shared_context_finds_cross_root_inbound_reference_once(self):
        alpha = inventory._reference_projection(
            (b"projects", b"alpha", b"spec.md"),
            "Alpha specification",
        )
        beta = inventory._reference_projection(
            (b"projects", b"beta", b"index.md"),
            "See [alpha](../alpha/spec.md).",
        )
        documents = tuple(
            references.ReferenceDocument(
                path=projection.source_path,
                document_type="markdown",
                fingerprint=("a" if index == 0 else "b") * 64,
                scope_class="eligible",
                text=None,
                inspected=True,
                projection=projection,
            )
            for index, projection in enumerate((alpha, beta))
        )
        analyzer = references.ReferenceAnalyzer("refs-context-v2")

        context = analyzer.build_context(
            documents=documents,
            scanned_roots=(
                inventory.canonical_raw_path((b"projects", b"alpha")),
                inventory.canonical_raw_path((b"projects", b"beta")),
            ),
            registry_source_sha256="c" * 64,
        )
        envelope = analyzer.analyze_context(
            context=context,
            candidate_path=alpha.source_path,
        )
        second_envelope = analyzer.analyze_context(
            context=context,
            candidate_path=beta.source_path,
        )

        self.assertTrue(envelope.complete)
        self.assertEqual(envelope.context_id, context.context_id)
        self.assertEqual(envelope.context_sha256, context.context_sha256)
        self.assertIs(envelope.input_manifest, context.canonical_bytes)
        self.assertIs(second_envelope.input_manifest, context.canonical_bytes)
        self.assertEqual(
            [
                (match.direction, match.source_path, match.target_path)
                for match in envelope.matches
            ],
            [("inbound", beta.source_path, alpha.source_path)],
        )
        payload = context.to_dict()
        self.assertEqual(payload["content_sha256"], context.content_sha256)
        self.assertEqual(payload["context_sha256"], context.context_sha256)
        self.assertEqual(len(payload["documents"]), 2)
        self.assertEqual(len(payload["edges"]), 1)
        self.assertEqual(
            payload["registry_source"],
            {
                "kind": "compiled-registry",
                "sha256": "c" * 64,
                "source_id": "placement-registry",
            },
        )

    def test_sealed_safe_projection_drives_analysis_without_raw_body(self):
        source_projection = inventory._reference_projection(
            (b"projects", b"alpha", b"spec.md"),
            "secret prose [roadmap](roadmap.md)",
        )
        inbound_projection = inventory._reference_projection(
            (b"projects", b"alpha", b"index.md"),
            "private words [spec](spec.md)",
        )
        documents = tuple(
            references.ReferenceDocument(
                path=projection.source_path,
                document_type="markdown",
                fingerprint=("a" if index == 0 else "b") * 64,
                scope_class="eligible",
                text=None,
                inspected=True,
                projection=projection,
            )
            for index, projection in enumerate(
                (source_projection, inbound_projection)
            )
        )

        result = references.ReferenceAnalyzer("refs-projection-v1").analyze(
            candidate_path=source_projection.source_path,
            documents=documents,
            scanned_roots=(
                inventory.canonical_raw_path((b"projects", b"alpha")),
            ),
            registry_source_sha256="c" * 64,
        )

        self.assertTrue(result.complete)
        self.assertEqual(
            {(row.direction, row.reference_kind) for row in result.matches},
            {("outbound", "markdown-inline"), ("inbound", "markdown-inline")},
        )
        self.assertNotIn(b"secret prose", result.input_manifest)
        self.assertNotIn(b"private words", result.input_manifest)
        self.assertIn(source_projection.projection_sha256.encode(), result.input_manifest)

    def test_markdown_inbound_and_outbound_references_have_canonical_manifest(self):
        documents = (
            references.ReferenceDocument(
                path="docs/spec.md",
                document_type="markdown",
                fingerprint="a" * 64,
                scope_class="active-workstream-content",
                text="See [roadmap](../projects/alpha/roadmap.md).",
                inspected=True,
            ),
            references.ReferenceDocument(
                path="projects/alpha/index.md",
                document_type="markdown",
                fingerprint="b" * 64,
                scope_class="active-workstream-content",
                text="Read [the spec](../../docs/spec.md).",
                inspected=True,
            ),
        )
        analyzer = references.ReferenceAnalyzer("refs-v1")

        first = analyzer.analyze(
            candidate_path="docs/spec.md",
            documents=documents,
            scanned_roots=("docs", "projects/alpha"),
            registry_source_sha256="c" * 64,
        )
        second = analyzer.analyze(
            candidate_path="docs/spec.md",
            documents=tuple(reversed(documents)),
            scanned_roots=("projects/alpha", "docs"),
            registry_source_sha256="c" * 64,
        )

        self.assertTrue(first.complete)
        self.assertEqual(
            [(match.direction, match.source_path, match.target_path) for match in first.matches],
            [
                ("outbound", "docs/spec.md", "projects/alpha/roadmap.md"),
                ("inbound", "projects/alpha/index.md", "docs/spec.md"),
            ],
        )
        self.assertEqual(first.input_manifest_sha256, second.input_manifest_sha256)
        self.assertEqual(first, second)

    def test_opaque_protected_or_error_exclusion_makes_envelope_incomplete(self):
        documents = (
            references.ReferenceDocument(
                path="docs/spec.md",
                document_type="markdown",
                fingerprint="a" * 64,
                scope_class="active-workstream-content",
                text="No links.",
                inspected=True,
            ),
            references.ReferenceDocument(
                path="private/evidence.md",
                document_type="markdown",
                fingerprint="b" * 64,
                scope_class="opaque-private-evidence",
                text=None,
                inspected=False,
                exclusion_reason="opaque-scope",
            ),
            references.ReferenceDocument(
                path="protected/index.md",
                document_type="markdown",
                fingerprint="c" * 64,
                scope_class="protected",
                text=None,
                inspected=False,
                error="permission-denied",
            ),
        )

        result = references.ReferenceAnalyzer("refs-v1").analyze(
            candidate_path="docs/spec.md",
            documents=documents,
            scanned_roots=("docs", "private", "protected"),
            registry_source_sha256="d" * 64,
        )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.exclusions,
            (("private/evidence.md", "opaque-scope"),),
        )
        self.assertEqual(
            result.errors,
            (("protected/index.md", "permission-denied"),),
        )
        self.assertNotIn(b"No links.", result.input_manifest)

    def test_markdown_reference_definition_is_inbound_reference_evidence(self):
        documents = (
            references.ReferenceDocument(
                path="projects/alpha/readme.md",
                document_type="markdown",
                fingerprint="a" * 64,
                scope_class="active-workstream-content",
                text="See [the spec][spec].\n\n[spec]: spec.md\n",
                inspected=True,
            ),
            references.ReferenceDocument(
                path="projects/alpha/spec.md",
                document_type="markdown",
                fingerprint="b" * 64,
                scope_class="active-workstream-content",
                text="# Spec\n",
                inspected=True,
            ),
        )

        envelope = references.ReferenceAnalyzer("refs-v1").analyze(
            candidate_path="projects/alpha/spec.md",
            documents=documents,
            scanned_roots=("projects",),
            registry_source_sha256="c" * 64,
        )

        self.assertEqual(
            tuple((row.direction, row.reference_kind) for row in envelope.matches),
            (("inbound", "markdown-reference"),),
        )

    def test_empty_or_noncovering_scan_roots_can_never_be_complete(self):
        document = references.ReferenceDocument(
            path="projects/alpha/spec.md",
            document_type="markdown",
            fingerprint="a" * 64,
            scope_class="active-workstream-content",
            text="# Spec\n",
            inspected=True,
        )
        analyzer = references.ReferenceAnalyzer("refs-v1")

        empty = analyzer.analyze(
            candidate_path=document.path,
            documents=(document,),
            scanned_roots=(),
            registry_source_sha256="b" * 64,
        )
        noncovering = analyzer.analyze(
            candidate_path=document.path,
            documents=(document,),
            scanned_roots=("other",),
            registry_source_sha256="b" * 64,
        )

        self.assertFalse(empty.complete)
        self.assertFalse(noncovering.complete)

    def test_candidate_absent_from_manifest_is_incomplete_even_under_scanned_root(self):
        document = references.ReferenceDocument(
            path="projects/alpha/spec.md",
            document_type="markdown",
            fingerprint="a" * 64,
            scope_class="active-workstream-content",
            text="# Spec\n",
            inspected=True,
        )
        analyzer = references.ReferenceAnalyzer("refs-manifest-v1")
        context = analyzer.build_context(
            documents=(document,),
            scanned_roots=("projects/alpha",),
            registry_source_sha256="b" * 64,
        )

        generated = analyzer.analyze_context(
            context=context,
            candidate_path="projects/alpha/missing.md",
        )
        parsed = references.reference_context_from_dict(context.to_dict())
        restored = analyzer.analyze_context(
            context=parsed,
            candidate_path="projects/alpha/missing.md",
        )

        self.assertTrue(context.frontier_complete)
        self.assertFalse(generated.complete)
        self.assertFalse(restored.complete)

    def test_uninspected_document_requires_visible_exclusion_or_error(self):
        with self.assertRaisesRegex(
            references.ReferenceAnalysisError,
            "exclusion reason or error",
        ):
            references.ReferenceDocument(
                path="protected/item.md",
                document_type="markdown",
                fingerprint="a" * 64,
                scope_class="protected",
                text=None,
                inspected=False,
            )


if __name__ == "__main__":
    unittest.main()
