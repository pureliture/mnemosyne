import json
import re
import sys
import unittest
from dataclasses import replace
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import review_compiler  # noqa: E402


def batch_document(display_path="projects/alpha/spec.md"):
    return review_compiler.ReviewDocument(
        review_kind="batch-preview",
        source_kind="batch-snapshot",
        source_id="snapshot-001",
        source_snapshot_sha256="a" * 64,
        rendered_at="2026-07-15T00:00:00Z",
        campaign_id="campaign-001",
        batch_id="batch-001",
        snapshot_id="snapshot-001",
        snapshot_version=1,
        policy_binding="generation=1;source=INITIAL/polrun-001;guard=0",
        coverage=review_compiler.CoverageSummary(
            folders_total=1,
            folders_traversed=1,
            folders_excluded=0,
            folders_error=0,
            files_total=2,
            files_inspected=2,
            files_metadata_only=0,
            files_excluded=0,
            files_error=0,
        ),
        bounds=review_compiler.ReviewBounds(
            review_items=1,
            underlying_files=2,
            total_bytes=30,
            leaf_folders=1,
            effect_count=0,
        ),
        workstreams=(
            review_compiler.WorkstreamSummary(
                workstream_id="alpha",
                lifecycle="active",
                review_items=1,
                blocked=0,
                errors=0,
            ),
        ),
        items=(
            review_compiler.ReviewRow(
                unit_id="unit-alpha",
                unit_kind="folder",
                canonical_path="projects/alpha",
                display_path=display_path,
                underlying_file_count=2,
                primary_workstream="alpha",
                related_workstreams=(),
                shared=False,
                document_role="docs",
                authority="reference",
                document_lifecycle="current",
                scope_class="active-workstream-content",
                sensitivity="public",
                access_domain="default",
                recommended_action="move",
                target_path="docs/spec.md",
                risk_band="low",
                context_freshness="fresh",
                evidence_providers=("path-pattern", "registry-route"),
                warning_codes=(),
                effect_codes=("plan-unavailable-m2",),
            ),
        ),
        warning_codes=("m2-no-structural-authority",),
    )


def run_document():
    return replace(
        batch_document(),
        review_kind="run-overview",
        source_kind="inventory-run",
        source_id="run-001",
        campaign_id=None,
        batch_id=None,
        snapshot_id=None,
        snapshot_version=None,
        bounds=None,
    )


def canonical_json_bytes(value):
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def with_rebound_html_hash(artifacts, html):
    meta = json.loads(artifacts.meta_json)
    meta["html_sha256"] = review_compiler.sha256_bytes(html)
    return replace(artifacts, html=html, meta_json=canonical_json_bytes(meta))


class ReviewCompilerTest(unittest.TestCase):
    def test_html_is_derived_from_exact_markdown_bytes_and_meta_binds_hashes(self):
        compiler = review_compiler.ReviewCompiler("renderer-v1")

        artifacts = compiler.compile(batch_document())
        meta = json.loads(artifacts.meta_json)

        self.assertTrue(
            artifacts.markdown.startswith(
                "# Mnemosyne 문서 정리 검토".encode("utf-8")
            )
        )
        self.assertIn(
            meta["markdown_sha256"].encode("ascii"),
            artifacts.html,
        )
        self.assertEqual(meta["source_snapshot_sha256"], "a" * 64)
        self.assertEqual(meta["renderer_id"], "renderer-v1")
        self.assertEqual(meta["rendered_at"], "2026-07-15T00:00:00Z")
        self.assertEqual(meta["html_sha256"], review_compiler.sha256_bytes(artifacts.html))
        self.assertTrue(review_compiler.validate_review_artifacts(artifacts))
        self.assertEqual(
            review_compiler.semantic_json_from_markdown(artifacts.markdown),
            artifacts.semantic_json,
        )

    def test_validator_rejects_html_item_row_removal_even_if_html_hash_is_rebound(self):
        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            batch_document()
        )
        tampered_html = re.sub(
            rb'<tr data-item-id=.*?</tr>\n',
            b"",
            artifacts.html,
            count=1,
            flags=re.DOTALL,
        )
        meta = json.loads(artifacts.meta_json)
        meta["html_sha256"] = review_compiler.sha256_bytes(tampered_html)
        tampered = review_compiler.ReviewArtifacts(
            markdown=artifacts.markdown,
            html=tampered_html,
            meta_json=(
                json.dumps(meta, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8"),
            semantic_json=artifacts.semantic_json,
        )

        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "semantic coverage differs",
        ):
            review_compiler.validate_review_artifacts(tampered)

    def test_validator_rejects_markdown_action_tamper_even_if_outer_hashes_are_rebound(self):
        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            batch_document()
        )
        tampered_markdown = artifacts.markdown.replace(
            b"| move | docs/spec.md |",
            b"| archive | docs/spec.md |",
            1,
        )
        self.assertNotEqual(tampered_markdown, artifacts.markdown)
        old_markdown_hash = review_compiler.sha256_bytes(artifacts.markdown)
        new_markdown_hash = review_compiler.sha256_bytes(tampered_markdown)
        tampered_html = artifacts.html.replace(
            old_markdown_hash.encode("ascii"),
            new_markdown_hash.encode("ascii"),
            1,
        )
        meta = json.loads(artifacts.meta_json)
        meta["markdown_sha256"] = new_markdown_hash
        meta["html_sha256"] = review_compiler.sha256_bytes(tampered_html)
        tampered = replace(
            artifacts,
            markdown=tampered_markdown,
            html=tampered_html,
            meta_json=canonical_json_bytes(meta),
        )

        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "semantic manifest mismatch",
        ):
            review_compiler.validate_review_artifacts(tampered)

    def test_validator_rejects_hidden_item_row_even_if_html_hash_is_rebound(self):
        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            batch_document()
        )
        injected_row = (
            b'<tr style="display:none" data-item-id="unit-forged" '
            b'data-action="move" data-effect="none" data-warning="none">'
            b'<th scope="row">unit-forged</th></tr>\n'
        )
        tampered_html = artifacts.html.replace(
            b"</tbody></table>",
            injected_row + b"</tbody></table>",
            1,
        )
        tampered = with_rebound_html_hash(artifacts, tampered_html)

        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "hidden review content",
        ):
            review_compiler.validate_review_artifacts(tampered)

    def test_validator_rejects_forged_approval_notice_with_all_hashes_rebound(self):
        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            batch_document()
        )
        forged_markdown_notice = (
            "> [notice:approval-granted] 구조 변경이 승인되었습니다.\n"
        ).encode("utf-8")
        notice_anchor = (
            "> [notice:non-authoritative] 이 문서는 검토용입니다. "
            "파일 이동·보관 승인이나 machine state SoT가 아닙니다.\n"
        ).encode("utf-8")
        tampered_markdown = artifacts.markdown.replace(
            notice_anchor,
            notice_anchor + forged_markdown_notice,
            1,
        )
        self.assertNotEqual(tampered_markdown, artifacts.markdown)
        old_markdown_hash = review_compiler.sha256_bytes(artifacts.markdown)
        new_markdown_hash = review_compiler.sha256_bytes(tampered_markdown)
        forged_html_notice = (
            '<aside class="notice" data-notice="approval-granted">'
            "구조 변경이 승인되었습니다.</aside>\n"
        ).encode("utf-8")
        tampered_html = artifacts.html.replace(
            old_markdown_hash.encode("ascii"),
            new_markdown_hash.encode("ascii"),
            1,
        ).replace(
            b'</aside>\n<h2 id="identity"',
            b"</aside>\n" + forged_html_notice + b'<h2 id="identity"',
            1,
        )
        semantic = json.loads(artifacts.semantic_json)
        semantic["notices"].append("approval-granted")
        semantic_json = canonical_json_bytes(semantic)
        meta = json.loads(artifacts.meta_json)
        meta["markdown_sha256"] = new_markdown_hash
        meta["html_sha256"] = review_compiler.sha256_bytes(tampered_html)
        meta["semantic_sha256"] = review_compiler.sha256_bytes(semantic_json)
        tampered = review_compiler.ReviewArtifacts(
            markdown=tampered_markdown,
            html=tampered_html,
            meta_json=canonical_json_bytes(meta),
            semantic_json=semantic_json,
        )

        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "approval notice|notice contract|unsupported notice",
        ):
            review_compiler.validate_review_artifacts(tampered)

    def test_validator_rejects_golden_notice_copy_tamper_with_hashes_rebound(self):
        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            batch_document()
        )
        original_copy = (
            "이 문서는 검토용입니다. 파일 이동·보관 승인이나 "
            "machine state SoT가 아닙니다."
        )
        forged_copy = "구조 변경이 승인되었으며 즉시 실행할 수 있습니다."
        tampered_markdown = artifacts.markdown.replace(
            original_copy.encode("utf-8"),
            forged_copy.encode("utf-8"),
            1,
        )
        old_markdown_hash = review_compiler.sha256_bytes(artifacts.markdown)
        new_markdown_hash = review_compiler.sha256_bytes(tampered_markdown)
        tampered_html = artifacts.html.replace(
            old_markdown_hash.encode("ascii"),
            new_markdown_hash.encode("ascii"),
            1,
        ).replace(
            original_copy.encode("utf-8"),
            forged_copy.encode("utf-8"),
            1,
        )
        meta = json.loads(artifacts.meta_json)
        meta["markdown_sha256"] = new_markdown_hash
        meta["html_sha256"] = review_compiler.sha256_bytes(tampered_html)
        tampered = replace(
            artifacts,
            markdown=tampered_markdown,
            html=tampered_html,
            meta_json=canonical_json_bytes(meta),
        )

        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "approval notice|notice copy|golden copy",
        ):
            review_compiler.validate_review_artifacts(tampered)

    def test_adversarial_display_path_cannot_inject_heading_row_script_or_bidi(self):
        dangerous = "notes/x.md\n## forged | `tick` <script>alert(1)</script>\u202E"

        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            batch_document(display_path=dangerous)
        )

        self.assertNotIn(b"<script>", artifacts.markdown)
        self.assertNotIn(b"<script>", artifacts.html)
        self.assertNotIn("\u202E".encode("utf-8"), artifacts.markdown)
        self.assertIn(b"\\u000A", artifacts.markdown)
        self.assertIn(b"\\u007C", artifacts.markdown)
        self.assertIn(b"\\u003Cscript\\u003E", artifacts.markdown)
        semantic = json.loads(artifacts.semantic_json)
        self.assertEqual(
            [heading["id"] for heading in semantic["headings"]],
            ["review", "identity", "coverage", "workstreams", "bounds", "items", "warnings", "next-step"],
        )
        self.assertEqual(len(semantic["items"]), 1)
        self.assertTrue(review_compiler.validate_review_artifacts(artifacts))

    def test_private_or_opaque_row_cannot_be_movement_ready_or_use_content_evidence(self):
        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "private or opaque row cannot be movement-ready",
        ):
            review_compiler.ReviewRow(
                unit_id="unit-private",
                unit_kind="file",
                canonical_path="private/spec.md",
                display_path="private/spec.md",
                underlying_file_count=1,
                primary_workstream="alpha",
                related_workstreams=(),
                shared=False,
                document_role="private-evidence",
                authority="unknown",
                document_lifecycle="unknown",
                scope_class="private-reviewable",
                sensitivity="private",
                access_domain="owner",
                recommended_action="move",
                target_path="projects/alpha/spec.md",
                risk_band="blocked",
                context_freshness="unknown",
                evidence_providers=("safe-content-token",),
                warning_codes=("private-metadata-only",),
                effect_codes=("plan-unavailable-m2",),
            )

    def test_private_review_row_shows_fixed_metadata_only_notice(self):
        base = batch_document()
        private_row = replace(
            base.items[0],
            unit_kind="file",
            canonical_path="private/spec.md",
            display_path="private/spec.md",
            underlying_file_count=1,
            document_role="private-evidence",
            authority="unknown",
            document_lifecycle="unknown",
            scope_class="private-reviewable",
            sensitivity="private",
            access_domain="owner",
            recommended_action="defer",
            target_path=None,
            risk_band="blocked",
            context_freshness="unknown",
            evidence_providers=("registry-route",),
            warning_codes=("private-metadata-only",),
        )

        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            replace(
                base,
                items=(private_row,),
                bounds=replace(base.bounds, underlying_files=1),
                warning_codes=("m2-no-structural-authority", "private-metadata-only"),
            )
        )

        self.assertIn(b"private-reviewable", artifacts.markdown)
        self.assertIn(
            "콘텐츠 미노출 — private-reviewable 정책".encode("utf-8"),
            artifacts.markdown,
        )
        self.assertTrue(review_compiler.validate_review_artifacts(artifacts))

    def test_opaque_review_row_shows_fixed_unopened_notice_without_content_evidence(self):
        base = batch_document()
        opaque_row = replace(
            base.items[0],
            unit_kind="file",
            canonical_path="evidence/internal-secret-sentinel.bin",
            display_path="evidence/sealed.bin",
            underlying_file_count=1,
            document_role="audit-evidence",
            authority="unknown",
            document_lifecycle="frozen",
            scope_class="opaque-private-evidence",
            sensitivity="restricted",
            access_domain="evidence",
            recommended_action="defer",
            target_path=None,
            risk_band="blocked",
            context_freshness="unknown",
            evidence_providers=("registry-route",),
            warning_codes=("opaque-content-unopened",),
        )

        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            replace(
                base,
                items=(opaque_row,),
                bounds=replace(base.bounds, underlying_files=1),
                warning_codes=("m2-no-structural-authority", "opaque-content-unopened"),
            )
        )
        persisted = b"\n".join(
            (
                artifacts.markdown,
                artifacts.html,
                artifacts.meta_json,
                artifacts.semantic_json,
            )
        )

        self.assertIn(b"opaque-private-evidence", artifacts.markdown)
        self.assertIn(
            "내용을 열지 않음 — opaque evidence 범위".encode("utf-8"),
            artifacts.markdown,
        )
        self.assertNotIn(b"internal-secret-sentinel", persisted)
        self.assertNotIn(b"safe-content-token", persisted)
        self.assertNotIn(b"ephemeral-private-projection", persisted)
        self.assertTrue(review_compiler.validate_review_artifacts(artifacts))

    def test_private_and_opaque_rows_require_their_fixed_noncontent_warning(self):
        base = batch_document().items[0]
        cases = (
            (
                "private-reviewable",
                "private",
                "owner",
                "private-metadata-only",
            ),
            (
                "opaque-private-evidence",
                "restricted",
                "evidence",
                "opaque-content-unopened",
            ),
        )
        for scope_class, sensitivity, access_domain, warning_code in cases:
            with self.subTest(scope_class=scope_class):
                with self.assertRaisesRegex(
                    review_compiler.ReviewCompileError,
                    warning_code,
                ):
                    replace(
                        base,
                        unit_kind="file",
                        canonical_path="bounded/item.bin",
                        display_path="bounded/item.bin",
                        underlying_file_count=1,
                        document_role="evidence",
                        authority="unknown",
                        document_lifecycle="unknown",
                        scope_class=scope_class,
                        sensitivity=sensitivity,
                        access_domain=access_domain,
                        recommended_action="defer",
                        target_path=None,
                        risk_band="blocked",
                        context_freshness="unknown",
                        evidence_providers=("registry-route",),
                        warning_codes=(),
                    )

    def test_run_overview_omits_batch_identity_and_bounds_but_preserves_coverage(self):
        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            run_document()
        )
        semantic = json.loads(artifacts.semantic_json)

        self.assertEqual(semantic["identity"]["Review kind"], "run-overview")
        self.assertEqual(semantic["identity"]["Source kind"], "inventory-run")
        self.assertEqual(semantic["identity"]["Source ID"], "run-001")
        self.assertNotIn("Campaign ID", semantic["identity"])
        self.assertNotIn("Batch ID", semantic["identity"])
        self.assertNotIn("Snapshot ID", semantic["identity"])
        self.assertNotIn("Snapshot version", semantic["identity"])
        self.assertNotIn(b"## Bounded scope {#bounds}", artifacts.markdown)
        self.assertIn(b"## Coverage {#coverage}", artifacts.markdown)
        self.assertTrue(review_compiler.validate_review_artifacts(artifacts))

    def test_review_kind_rejects_the_wrong_source_kind(self):
        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "batch preview source",
        ):
            replace(batch_document(), source_kind="inventory-run")
        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "run overview source",
        ):
            replace(run_document(), source_kind="batch-snapshot")

    def test_batch_bounds_must_match_exact_review_membership(self):
        document = batch_document()
        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "review item bound",
        ):
            replace(
                document,
                bounds=replace(document.bounds, review_items=2),
            )
        with self.assertRaisesRegex(
            review_compiler.ReviewCompileError,
            "underlying file bound",
        ):
            replace(
                document,
                bounds=replace(document.bounds, underlying_files=3),
            )

    def test_compilation_is_byte_deterministic_and_matches_golden_hashes(self):
        compiler = review_compiler.ReviewCompiler("renderer-v1")

        first = compiler.compile(run_document())
        second = compiler.compile(run_document())

        self.assertEqual(first, second)
        self.assertEqual(
            {
                "markdown": review_compiler.sha256_bytes(first.markdown),
                "html": review_compiler.sha256_bytes(first.html),
                "meta": review_compiler.sha256_bytes(first.meta_json),
                "semantic": review_compiler.sha256_bytes(first.semantic_json),
            },
            {
                "markdown": "5dfbc869c8f5c72e363c9e1320dddb489cc5f2774b17bd2441d67197e4e0019f",
                "html": "f2abd8fe75f4a36e68015bdb5c605b16856842a57834a40a929e6deb03407edb",
                "meta": "d25f33c2ef56a19ed4106bf8063df0b5d55e3ab04cea0cfaae21f0c233e113f7",
                "semantic": "b499e02c63f306ba8a3306a36169280c791dc3ed9614bee25dfd8e6757ce9671",
            },
        )

    def test_validator_rejects_removal_of_static_accessibility_contract(self):
        artifacts = review_compiler.ReviewCompiler("renderer-v1").compile(
            batch_document()
        )
        mutations = (
            ("filter-label", b'<label for="review-filter">\xed\x95\xad\xeb\xaa\xa9 \xed\x95\x84\xed\x84\xb0</label>\n', b""),
            ("filter-description", b' aria-describedby="filter-help"', b""),
            ("table-caption", b"<caption>\xea\xb2\x80\xed\x86\xa0\xeb\xb3\xb8 \xec\x8b\x9d\xeb\xb3\x84</caption>", b""),
            ("column-scope", b'<th scope="col">', b"<th>"),
        )
        for label, old, new in mutations:
            with self.subTest(contract=label):
                tampered_html = artifacts.html.replace(old, new, 1)
                self.assertNotEqual(tampered_html, artifacts.html)
                tampered = with_rebound_html_hash(artifacts, tampered_html)
                with self.assertRaisesRegex(
                    review_compiler.ReviewCompileError,
                    "accessibility contract",
                ):
                    review_compiler.validate_review_artifacts(tampered)


if __name__ == "__main__":
    unittest.main()
