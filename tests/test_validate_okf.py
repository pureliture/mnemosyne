import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "validate_okf.py"


class ValidateOkfCliTest(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            check=False,
            capture_output=True,
            text=True,
        )

    def write_minimal_bundle(self, root: Path) -> Path:
        bundle = root / "artifacts" / "okf" / "example"
        bundle.mkdir(parents=True)
        (bundle / "index.md").write_text(
            '---\nokf_version: "0.1"\n---\n\n# Example\n\n* [Workstream](workstream.md)\n',
            encoding="utf-8",
        )
        (bundle / "workstream.md").write_text(
            "---\ntype: Workstream\n---\n\n# Example Workstream\n",
            encoding="utf-8",
        )
        return bundle

    def test_valid_minimal_bundle_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("mode: okf-validate", result.stdout)
            self.assertIn("errors: 0", result.stdout)

    def test_bundle_id_loads_path_and_allowlist_from_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            source_root = root / "projects" / "example"
            source_root.mkdir(parents=True)
            (source_root / "source.md").write_text("# Source\n", encoding="utf-8")
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Source](../../../projects/example/source.md)\n",
                encoding="utf-8",
            )
            registry = root / "_registry" / "placement-map.yml"
            registry.parent.mkdir(parents=True)
            registry.write_text(
                "\n".join(
                    [
                        "schema_version: 1",
                        "knowledge_formats:",
                        "  okf:",
                        '    spec_version: "0.1"',
                        "    adoption_status: adopted",
                        "    profile_version: 1",
                        "    authority: derived",
                        "    enforcement: registry-driven-validator",
                        f"    output_root: {root / 'artifacts' / 'okf'}",
                        f"    validator: {SCRIPT}",
                        "    bundles:",
                        "      - id: example",
                        f"        path: {bundle}",
                        "        allow_source_roots:",
                        f"          - {source_root}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle-id", "example")

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_registry_bundle_must_be_within_output_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            outside_bundle = root / "projects" / "example"
            outside_bundle.parent.mkdir(parents=True)
            bundle.rename(outside_bundle)
            registry = root / "_registry" / "placement-map.yml"
            registry.parent.mkdir(parents=True)
            registry.write_text(
                "\n".join(
                    [
                        "schema_version: 1",
                        "knowledge_formats:",
                        "  okf:",
                        '    spec_version: "0.1"',
                        "    adoption_status: adopted",
                        "    profile_version: 1",
                        "    authority: derived",
                        "    enforcement: registry-driven-validator",
                        f"    output_root: {root / 'artifacts' / 'okf'}",
                        f"    validator: {SCRIPT}",
                        "    bundles:",
                        "      - id: example",
                        f"        path: {outside_bundle}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle-id", "example")

            self.assertEqual(result.returncode, 2)
            self.assertIn("registry-bundle-outside-output-root", result.stderr)

    def test_registry_authority_enforcement_and_validator_are_enforced(self):
        cases = {
            "authority": ("authoritative", "registry-okf-profile-not-adopted"),
            "enforcement": ("manual", "registry-okf-profile-not-adopted"),
            "validator": ("/tmp/not-the-okf-validator.py", "registry-validator-mismatch"),
        }
        for field, (invalid_value, expected_rule) in cases.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = self.write_minimal_bundle(root)
                values = {
                    "authority": "derived",
                    "enforcement": "registry-driven-validator",
                    "validator": str(SCRIPT),
                }
                values[field] = invalid_value
                registry = root / "_registry" / "placement-map.yml"
                registry.parent.mkdir(parents=True)
                registry.write_text(
                    "\n".join(
                        [
                            "schema_version: 1",
                            "knowledge_formats:",
                            "  okf:",
                            '    spec_version: "0.1"',
                            "    adoption_status: adopted",
                            "    profile_version: 1",
                            f"    authority: {values['authority']}",
                            f"    enforcement: {values['enforcement']}",
                            f"    output_root: {root / 'artifacts' / 'okf'}",
                            f"    validator: {values['validator']}",
                            "    bundles:",
                            "      - id: example",
                            f"        path: {bundle}",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )

                result = self.run_cli("--root", str(root), "--bundle-id", "example")

                self.assertEqual(result.returncode, 2)
                self.assertIn(expected_rule, result.stderr)

    def test_broken_local_link_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n# Example\n\n[Missing](missing.md)\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("link-target-missing", result.stdout)

    def test_leading_slash_link_is_bundle_root_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "index.md").write_text(
                '---\nokf_version: "0.1"\n---\n\n# Example\n\n[Workstream](/workstream.md)\n',
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_symlink_anywhere_in_bundle_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "linked.md").symlink_to(bundle / "workstream.md")

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("symlink-forbidden", result.stdout)

    def test_symlink_target_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            outside = root / "outside-invalid.md"
            outside.write_bytes(b"\xff\xfe")
            (bundle / "linked.md").symlink_to(outside)

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("symlink-forbidden", result.stdout)
            self.assertNotIn("markdown-not-utf8", result.stdout)

    def test_bundle_path_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            alias = root / "artifacts" / "okf" / "alias"
            alias.symlink_to(bundle, target_is_directory=True)

            result = self.run_cli("--root", str(root), "--bundle", str(alias))

            self.assertEqual(result.returncode, 2)
            self.assertIn("bundle-symlink-forbidden", result.stderr)

    def test_bundle_under_forbidden_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            private_bundle = root / "private" / "example"
            private_bundle.parent.mkdir(parents=True)
            bundle.rename(private_bundle)

            result = self.run_cli("--root", str(root), "--bundle", str(private_bundle))

            self.assertEqual(result.returncode, 2)
            self.assertIn("bundle-forbidden", result.stderr)

    def test_outside_bundle_link_requires_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            source = root / "projects" / "example" / "source.md"
            source.parent.mkdir(parents=True)
            source.write_text("# Source\n", encoding="utf-8")
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Source](../../../projects/example/source.md)\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("source-root-not-allowed", result.stdout)

    def test_allow_source_root_permits_existing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            source = root / "projects" / "example" / "source.md"
            source.parent.mkdir(parents=True)
            source.write_text("# Source\n", encoding="utf-8")
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Source](../../../projects/example/source.md)\n",
                encoding="utf-8",
            )

            result = self.run_cli(
                "--root",
                str(root),
                "--bundle",
                str(bundle),
                "--allow-source-root",
                "projects/example",
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_forbidden_source_root_cannot_be_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            source = root / "private" / "source.md"
            source.parent.mkdir(parents=True)
            source.write_text("# Private Source\n", encoding="utf-8")
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Source](../../../private/source.md)\n",
                encoding="utf-8",
            )

            result = self.run_cli(
                "--root",
                str(root),
                "--bundle",
                str(bundle),
                "--allow-source-root",
                "private",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("forbidden-source-root", result.stderr)

    def test_raw_root_allowlist_cannot_bypass_forbidden_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            source = root / "private" / "source.md"
            source.parent.mkdir(parents=True)
            source.write_text("# Private Source\n", encoding="utf-8")
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Source](../../../private/source.md)\n",
                encoding="utf-8",
            )

            result = self.run_cli(
                "--root",
                str(root),
                "--bundle",
                str(bundle),
                "--allow-source-root",
                ".",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("forbidden-source-root", result.stderr)

    def test_lifecycle_source_frontmatter_is_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            private_source = root / "private" / "lifecycle.md"
            private_source.parent.mkdir(parents=True)
            private_source.write_text("# Private Lifecycle\n", encoding="utf-8")
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\nlifecycle_source: ../../../private/lifecycle.md\n---\n\n# Example\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("source-forbidden", result.stdout)

    def test_external_url_requires_https_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Public](https://example.com/source)\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("external-url-not-allowed", result.stdout)

    def test_reference_autolink_and_html_links_require_allowlist(self):
        cases = {
            "reference": "[Public][src]\n\n[src]: https://example.com/private\n",
            "autolink": "<https://example.com/private>\n",
            "html-anchor": '<a href="https://example.com/private">Public</a>\n',
            "html-image": '<img src="https://example.com/private" alt="Public">\n',
        }
        for name, body in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = self.write_minimal_bundle(root)
                (bundle / "workstream.md").write_text(
                    f"---\ntype: Workstream\n---\n\n{body}",
                    encoding="utf-8",
                )

                result = self.run_cli("--root", str(root), "--bundle", str(bundle))

                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn("external-url-not-allowed", result.stdout)

    def test_nested_escaped_entity_and_generic_html_links_require_allowlist(self):
        cases = {
            "nested-label": "[foo [bar]](https://example.com/private)\n",
            "escaped-label": r"[foo \] bar](https://example.com/private)" + "\n",
            "escaped-reference-label": (
                r"[Public][foo \] bar]" + "\n\n"
                r"[foo \] bar]: https://example.com/private" + "\n"
            ),
            "entity-scheme": "[Public](https&colon;//example.com/private)\n",
            "iframe": '<iframe src="https://example.com/private"></iframe>\n',
        }
        for name, body in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = self.write_minimal_bundle(root)
                (bundle / "workstream.md").write_text(
                    f"---\ntype: Workstream\n---\n\n{body}",
                    encoding="utf-8",
                )

                result = self.run_cli("--root", str(root), "--bundle", str(bundle))

                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn("external-url-not-allowed", result.stdout)

    def test_multiline_markdown_destinations_require_allowlist(self):
        cases = {
            "inline": "[Public](\nhttps://example.com/private)\n",
            "reference": (
                "[Public][src]\n\n"
                "[src]:\n"
                "https://example.com/private\n"
            ),
        }
        for name, body in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = self.write_minimal_bundle(root)
                (bundle / "workstream.md").write_text(
                    f"---\ntype: Workstream\n---\n\n{body}",
                    encoding="utf-8",
                )

                result = self.run_cli("--root", str(root), "--bundle", str(bundle))

                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn("external-url-not-allowed", result.stdout)

    def test_container_and_multiline_reference_definitions_require_allowlist(self):
        cases = {
            "blockquote": "> [foo]: https://example.com/private\n",
            "blockquote-continuation": "> [foo]:\n> https://example.com/private\n",
            "list": "- [foo]: https://example.com/private\n",
            "multiline-label": "[foo\nbar]: https://example.com/private\n",
        }
        for name, body in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = self.write_minimal_bundle(root)
                (bundle / "workstream.md").write_text(
                    f"---\ntype: Workstream\n---\n\n{body}",
                    encoding="utf-8",
                )

                result = self.run_cli("--root", str(root), "--bundle", str(bundle))

                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn("external-url-not-allowed", result.stdout)

    def test_html_request_url_attributes_require_allowlist(self):
        cases = {
            "srcset": '<img srcset="https://example.com/one 1x, https://example.com/two 2x">\n',
            "action": '<form action="https://example.com/private"></form>\n',
            "poster": '<video poster="https://example.com/private"></video>\n',
        }
        for name, body in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = self.write_minimal_bundle(root)
                (bundle / "workstream.md").write_text(
                    f"---\ntype: Workstream\n---\n\n{body}",
                    encoding="utf-8",
                )

                result = self.run_cli("--root", str(root), "--bundle", str(bundle))

                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn("external-url-not-allowed", result.stdout)

    def test_allowed_https_prefix_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Public](https://example.com/source)\n",
                encoding="utf-8",
            )

            result = self.run_cli(
                "--root",
                str(root),
                "--bundle",
                str(bundle),
                "--allow-url-prefix",
                "https://example.com/",
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_extended_link_forms_honor_https_allowlist(self):
        cases = {
            "nested-label": "[foo [bar]](https://example.com/private)\n",
            "entity-scheme": "[Public](https&colon;//example.com/private)\n",
            "iframe": '<iframe src="https://example.com/private"></iframe>\n',
            "multiline-inline": "[Public](\nhttps://example.com/private)\n",
            "multiline-reference": "[Public][src]\n\n[src]:\nhttps://example.com/private\n",
            "blockquote-reference": "> [src]: https://example.com/private\n",
            "blockquote-reference-continuation": "> [src]:\n> https://example.com/private\n",
            "multiline-reference-label": "[foo\nbar]: https://example.com/private\n",
            "srcset": '<img srcset="https://example.com/one 1x, https://example.com/two 2x">\n',
            "form-action": '<form action="https://example.com/private"></form>\n',
        }
        for name, body in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = self.write_minimal_bundle(root)
                (bundle / "workstream.md").write_text(
                    f"---\ntype: Workstream\n---\n\n{body}",
                    encoding="utf-8",
                )

                result = self.run_cli(
                    "--root",
                    str(root),
                    "--bundle",
                    str(bundle),
                    "--allow-url-prefix",
                    "https://example.com/",
                )

                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_empty_url_prefix_is_rejected_as_configuration_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Public](https://example.com/source)\n",
                encoding="utf-8",
            )

            result = self.run_cli(
                "--root",
                str(root),
                "--bundle",
                str(bundle),
                "--allow-url-prefix",
                "",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid-url-prefix", result.stderr)

    def test_external_url_dot_segments_cannot_escape_allowed_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\n---\n\n[Bad](https://example.com/allowed/../../private)\n",
                encoding="utf-8",
            )

            result = self.run_cli(
                "--root",
                str(root),
                "--bundle",
                str(bundle),
                "--allow-url-prefix",
                "https://example.com/allowed/",
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("external-url-traversal", result.stdout)

    def test_double_encoded_traversal_is_rejected_without_echoing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            malicious = "%252e%252e/%252e%252e/%252e%252e/private/secret.md"
            (bundle / "workstream.md").write_text(
                f"---\ntype: Workstream\n---\n\n[Bad]({malicious})\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle), "--json")

            self.assertEqual(result.returncode, 1)
            self.assertIn("link-traversal", result.stdout)
            self.assertNotIn(malicious, result.stdout + result.stderr)

    def test_duplicate_frontmatter_key_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "workstream.md").write_text(
                "---\ntype: Workstream\ntype: Boundary\n---\n\n# Duplicate\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("frontmatter-duplicate-key", result.stdout)

    def test_type_must_be_non_empty_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "workstream.md").write_text(
                "---\ntype: false\n---\n\n# Invalid Type\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("type-invalid", result.stdout)

    def test_type_inline_list_is_not_a_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "workstream.md").write_text(
                "---\ntype: [Workstream]\n---\n\n# Invalid Type\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("type-invalid", result.stdout)

    def test_root_version_must_be_quoted_zero_point_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "index.md").write_text(
                "---\nokf_version: 0.1\n---\n\n# Example\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("root-version-invalid", result.stdout)

    def test_root_version_quote_check_is_limited_to_frontmatter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "index.md").write_text(
                '---\nokf_version: 0.1\n---\n\n# Example\n\nokf_version: "0.1"\n',
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("root-version-invalid", result.stdout)

    def test_log_date_headings_must_be_iso_and_newest_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "log.md").write_text(
                "# Update Log\n\n## 2026-01-01\n* Older\n\n## 2026-02-01\n* Newer\n",
                encoding="utf-8",
            )

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("log-dates-not-newest-first", result.stdout)

    def test_nested_index_rejects_even_empty_frontmatter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            nested = bundle / "concepts"
            nested.mkdir()
            (nested / "index.md").write_text("---\n---\n\n# Concepts\n", encoding="utf-8")

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("reserved-frontmatter-present", result.stdout)

    def test_non_markdown_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            (bundle / "payload.json").write_text("{}\n", encoding="utf-8")

            result = self.run_cli("--root", str(root), "--bundle", str(bundle))

            self.assertEqual(result.returncode, 1)
            self.assertIn("unexpected-file", result.stdout)

    def test_unreadable_directory_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self.write_minimal_bundle(root)
            blocked = bundle / "blocked"
            blocked.mkdir()
            (blocked / "hidden.md").write_text(
                "---\ntype: Hidden\n---\n\n# Hidden\n",
                encoding="utf-8",
            )
            blocked.chmod(0)
            try:
                result = self.run_cli("--root", str(root), "--bundle", str(bundle))
            finally:
                blocked.chmod(0o700)

            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            self.assertIn("directory-scan-failed", result.stdout)

    def test_missing_bundle_error_does_not_echo_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "artifacts" / "okf" / "sensitive-name"

            result = self.run_cli("--root", str(root), "--bundle", str(missing))

            self.assertEqual(result.returncode, 2)
            self.assertIn("path-not-found", result.stderr)
            self.assertNotIn(str(missing), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
