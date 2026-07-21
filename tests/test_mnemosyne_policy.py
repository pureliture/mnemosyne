import hashlib
import sys
import unittest
from collections import OrderedDict
from dataclasses import FrozenInstanceError
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import policy  # noqa: E402


ROOT = "/private/tmp/mnemosyne-policy-root"


def registry_without_curation() -> bytes:
    return (
        "# existing registry bytes are immutable during preview\n"
        "schema_version: 1\n"
        f"root: {ROOT}\n"
        f"registry_root: {ROOT}/_registry\n"
        f"inbox: {ROOT}/inbox\n"
        "decision_policy: propose-approve-apply\n"
        "graphify_update: explicit-request-only\n"
        f"memory_workspaces: {ROOT}/memory/workspaces.yml\n"
        "placement_model: category-first\n"
        "spec_source: https://example.test/okf/SPEC.md#profile\n"
        "workstreams:\n"
        "  - id: alpha\n"
        "    lifecycle: active\n"
        f"    project_home: {ROOT}/projects/alpha\n"
        "    aliases:\n"
        "      - alpha/mobile\n"
        "    memory_workspace: alpha\n"
        "    lifecycle_source: user-confirmed\n"
        "    lifecycle_confirmed_at: \"2026-07-14\"\n"
        "  - id: beta\n"
        "    lifecycle: paused\n"
        f"    project_home: {ROOT}/projects/beta\n"
        "    aliases: []\n"
        "    memory_workspace: null\n"
        "    lifecycle_source: user-confirmed\n"
        "    lifecycle_confirmed_at: \"2026-07-14\"\n"
        "knowledge_formats:\n"
        "  okf:\n"
        "    spec_version: \"0.1\"\n"
        "    adoption_status: adopted\n"
        f"    output_root: {ROOT}/artifacts/okf\n"
        "    bundles:\n"
        "      - id: alpha\n"
        f"        path: {ROOT}/artifacts/okf/alpha\n"
        "        allow_url_prefixes:\n"
        "          - https://example.test/source/alpha/\n"
        "never_touch:\n"
        "  - worktrees/\n"
        "  - graphify-out/\n"
        "categories:\n"
        "  - id: projects\n"
        f"    target: {ROOT}/projects\n"
        "    description: Project-specific source references.\n"
        "    patterns:\n"
        "      - projects/**\n"
        "      - \"*project*\"\n"
        "  - id: docs\n"
        f"    target: {ROOT}/docs\n"
        "    description: General human-readable notes.\n"
        "    patterns:\n"
        "      - docs/**\n"
        "      - \"*.md\"\n"
    ).encode("utf-8")


def compiled_registry() -> bytes:
    return policy.build_additive_curation_postimage(
        registry_without_curation(), ROOT
    )


class StrictYamlSubsetTest(unittest.TestCase):
    def test_parses_ordered_maps_lists_comments_urls_and_exact_scalar_types(self):
        parsed = policy.parse_strict_yaml(
            b"""
# comment
name: 'a ''quoted'' value' # trailing comment
description: operator's plain note # apostrophe is not a quote delimiter here
url: https://example.test/a:b?x=1&y=2#fragment
enabled: true
disabled: false
count: -12
empty: null
items: []
nested:
  - id: first
    label: "escaped\\nlabel"
  - plain
"""
        )

        self.assertIsInstance(parsed, OrderedDict)
        self.assertEqual(
            list(parsed),
            [
                "name",
                "description",
                "url",
                "enabled",
                "disabled",
                "count",
                "empty",
                "items",
                "nested",
            ],
        )
        self.assertEqual(parsed["name"], "a 'quoted' value")
        self.assertEqual(parsed["description"], "operator's plain note")
        self.assertEqual(
            parsed["url"], "https://example.test/a:b?x=1&y=2#fragment"
        )
        self.assertIs(parsed["enabled"], True)
        self.assertIs(parsed["disabled"], False)
        self.assertEqual(parsed["count"], -12)
        self.assertIsNone(parsed["empty"])
        self.assertEqual(parsed["items"], [])
        self.assertEqual(parsed["nested"][0]["label"], "escaped\nlabel")

    def test_rejects_duplicate_keys_tabs_bad_indentation_and_yaml_extensions(self):
        cases = {
            "duplicate key": b"a: 1\na: 2\n",
            "tab": b"a:\n\t- value\n",
            "odd indentation": b"a:\n   - value\n",
            "indent jump": b"a:\n    value: bad\n",
            "anchor": b"a: &shared value\n",
            "alias": b"a: *shared\n",
            "tag": b"a: !secret value\n",
            "merge": b"a:\n  <<: *shared\n",
            "literal multiline": b"a: |\n  value\n",
            "folded multiline": b"a: >\n  value\n",
            "flow map": b"a: {}\n",
            "flow list": b"a: [one, two]\n",
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(policy.StrictYAMLError):
                    policy.parse_strict_yaml(source)

    def test_rejects_ambiguous_unquoted_typed_scalars(self):
        values = (
            "yes",
            "NO",
            "on",
            "~",
            "Null",
            "01",
            "+1",
            "1.0",
            "1e3",
            "0x10",
            ".inf",
            "2026-07-14",
            "12:30:00",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    policy.StrictYAMLError, "ambiguous typed scalar"
                ):
                    policy.parse_strict_yaml(f"value: {value}\n".encode())

    def test_quoted_ambiguous_values_are_strings(self):
        parsed = policy.parse_strict_yaml(
            b'date: "2026-07-14"\nflag: "yes"\nversion: "0.1"\n'
        )
        self.assertEqual(parsed["date"], "2026-07-14")
        self.assertEqual(parsed["flag"], "yes")
        self.assertEqual(parsed["version"], "0.1")


class PolicyCompilerTest(unittest.TestCase):
    def test_initial_postimage_is_additive_and_compiles_canonical_projections(self):
        before = registry_without_curation()
        postimage = policy.build_additive_curation_postimage(before, ROOT)

        self.assertEqual(postimage[: len(before)], before)
        compiled = policy.compile_policy(postimage, ROOT)
        self.assertEqual(compiled.raw_hash, hashlib.sha256(postimage).hexdigest())
        self.assertEqual(compiled.foundation.profile_version, 1)
        self.assertEqual(
            compiled.foundation.state_root, f"{ROOT}/_registry/curation"
        )
        self.assertEqual(
            compiled.foundation.runs_root, f"{ROOT}/_registry/curation-runs"
        )
        self.assertEqual(
            compiled.writer_control,
            policy.CompiledWriterControl(
                movement_writer="legacy",
                structural_apply="disabled",
                writer_epoch="legacy-v1",
            ),
        )
        self.assertEqual(
            compiled.workstreams,
            (
                policy.CompiledWorkstream(
                    id="alpha",
                    lifecycle="active",
                    project_home=f"{ROOT}/projects/alpha",
                    aliases=("alpha/mobile",),
                    memory_workspace="alpha",
                ),
                policy.CompiledWorkstream(
                    id="beta",
                    lifecycle="paused",
                    project_home=f"{ROOT}/projects/beta",
                    aliases=(),
                    memory_workspace=None,
                ),
            ),
        )
        self.assertEqual(compiled.workstreams[0].memory_workspace, "alpha")
        self.assertIsNone(compiled.workstreams[1].memory_workspace)
        self.assertEqual(compiled.archive_roots, ())
        self.assertEqual(
            compiled.registry_anchors,
            policy.CompiledRegistryAnchors(
                registry_root=f"{ROOT}/_registry",
                inbox=f"{ROOT}/inbox",
                memory_workspaces=f"{ROOT}/memory/workspaces.yml",
            ),
        )
        self.assertEqual(
            compiled.never_touch,
            (
                policy.CompiledPathPrefix(("worktrees",)),
                policy.CompiledPathPrefix(("graphify-out",)),
            ),
        )
        self.assertEqual(
            compiled.categories,
            (
                policy.CompiledCategory(
                    id="projects",
                    target=f"{ROOT}/projects",
                    patterns=("projects/**", "*project*"),
                ),
                policy.CompiledCategory(
                    id="docs",
                    target=f"{ROOT}/docs",
                    patterns=("docs/**", "*.md"),
                ),
            ),
        )
        self.assertIn(b'"knowledge_formats"', compiled.full_json)
        self.assertIn(b'"categories"', compiled.full_json)
        self.assertIn(b'"memory_workspace":null', compiled.full_json)
        self.assertEqual(
            [rule.id for rule in compiled.scope_rules],
            [
                "active-workstream-content",
                "paused-completed",
                "opaque-evidence",
                "private-reviewable",
                "fallback-unassigned",
            ],
        )
        self.assertTrue(compiled.scope_rules[-1].catch_all)
        for payload, digest in (
            (compiled.full_json, compiled.full_hash),
            (compiled.writer_json, compiled.writer_hash),
            (compiled.foundation_json, compiled.foundation_hash),
        ):
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)

    def test_compiled_authority_projections_are_deeply_immutable(self):
        compiled = policy.compile_policy(compiled_registry(), ROOT)
        original_hashes = (
            compiled.full_hash,
            compiled.writer_hash,
            compiled.foundation_hash,
        )

        with self.assertRaises(FrozenInstanceError):
            compiled.writer_control.movement_writer = "curation"
        with self.assertRaises(FrozenInstanceError):
            compiled.foundation.state_root = f"{ROOT}/other"
        with self.assertRaises(FrozenInstanceError):
            compiled.workstreams[0].project_home = f"{ROOT}/other"
        with self.assertRaises(FrozenInstanceError):
            compiled.scope_rules[0].write = "forbidden"
        with self.assertRaises(FrozenInstanceError):
            compiled.categories[0].target = f"{ROOT}/other"
        with self.assertRaises((AttributeError, TypeError)):
            compiled.workstreams[0].aliases[0] = "changed"
        with self.assertRaises((AttributeError, TypeError)):
            compiled.never_touch[0].components[0] = "changed"
        self.assertFalse(hasattr(compiled, "registry"))
        self.assertEqual(
            (
                compiled.full_hash,
                compiled.writer_hash,
                compiled.foundation_hash,
            ),
            original_hashes,
        )

    def test_rejects_unsafe_physical_scope_anchors(self):
        base = compiled_registry()
        cases = {
            "outside category target": base.replace(
                f"target: {ROOT}/docs".encode(),
                b"target: /private/tmp/outside-docs",
            ),
            "absolute never-touch": base.replace(
                b"  - worktrees/\n",
                b"  - /worktrees/\n",
            ),
            "parent never-touch": base.replace(
                b"  - worktrees/\n",
                b"  - ../worktrees/\n",
            ),
            "duplicate never-touch": base.replace(
                b"  - graphify-out/\n",
                b"  - worktrees/\n",
            ),
            "noncanonical double-slash category": base.replace(
                f"target: {ROOT}/docs".encode(),
                f"target: //private/tmp/{Path(ROOT).name}/docs".encode(),
            ),
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(policy.PolicyError):
                    policy.compile_policy(source, ROOT)

    def test_additive_postimage_preserves_source_without_final_newline(self):
        before = registry_without_curation().rstrip(b"\n")
        postimage = policy.build_additive_curation_postimage(before, ROOT)
        self.assertEqual(postimage[: len(before)], before)
        self.assertEqual(postimage[len(before) : len(before) + 11], b"\ncuration:\n")
        policy.compile_policy(postimage, ROOT)

    def test_comments_change_raw_hash_but_not_normalized_policy_hashes(self):
        source = compiled_registry()
        with_comment = b"# a different transport comment\n" + source

        first = policy.compile_policy(source, ROOT)
        second = policy.compile_policy(with_comment, ROOT)
        self.assertNotEqual(first.raw_hash, second.raw_hash)
        self.assertEqual(first.full_hash, second.full_hash)
        self.assertEqual(first.writer_hash, second.writer_hash)
        self.assertEqual(first.foundation_hash, second.foundation_hash)

    def test_postimage_refuses_an_existing_curation_section(self):
        source = compiled_registry()
        with self.assertRaisesRegex(policy.PolicyError, "already has curation"):
            policy.build_additive_curation_postimage(source, ROOT)

    def test_duplicate_workstream_id_is_rejected(self):
        source = compiled_registry().replace(
            b"  - id: beta\n", b"  - id: alpha\n", 1
        )
        with self.assertRaisesRegex(policy.PolicyError, "duplicate Workstream id"):
            policy.compile_policy(source, ROOT)

    def test_alias_and_overlapping_project_routes_are_rejected(self):
        alias_collision = compiled_registry().replace(
            b"    aliases: []\n", b"    aliases:\n      - alpha/mobile\n", 1
        )
        with self.assertRaisesRegex(policy.PolicyError, "ambiguous Workstream alias"):
            policy.compile_policy(alias_collision, ROOT)

        nested_route = compiled_registry().replace(
            f"{ROOT}/projects/beta".encode(),
            f"{ROOT}/projects/alpha/nested".encode(),
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "ambiguous Workstream project routes"):
            policy.compile_policy(nested_route, ROOT)

    def test_prefix_overlapping_cross_workstream_route_tokens_are_rejected(self):
        source = compiled_registry().replace(
            b"    aliases: []\n",
            b"    aliases:\n      - alpha/mobile/v2\n",
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "ambiguous Workstream alias"):
            policy.compile_policy(source, ROOT)

    def test_workstream_project_home_must_stay_inside_raw_root(self):
        source = compiled_registry().replace(
            f"{ROOT}/projects/beta".encode(),
            b"/private/tmp/outside-mnemosyne-policy-root/beta",
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "inside raw root"):
            policy.compile_policy(source, ROOT)

    def test_memory_workspace_requires_exact_optional_canonical_token(self):
        base = compiled_registry()
        cases = {
            "uppercase": b"Alpha",
            "slash": b"alpha/mobile",
            "empty": b'""',
            "too long": ("a" * 65).encode("ascii"),
            "boolean": b"true",
            "list": b"[]",
        }
        for label, value in cases.items():
            with self.subTest(label=label):
                source = base.replace(
                    b"    memory_workspace: alpha\n",
                    b"    memory_workspace: " + value + b"\n",
                    1,
                )
                with self.assertRaisesRegex(policy.PolicyError, "memory_workspace"):
                    policy.compile_policy(source, ROOT)

    def test_workstream_ids_and_routes_reject_noncanonical_or_control_values(self):
        base = compiled_registry()
        unsafe_ids = (".", "..", "/leading", "trailing/", "a/../b", "bad\x01id")
        for value in unsafe_ids:
            with self.subTest(kind="id", value=repr(value)):
                source = base.replace(b"  - id: alpha\n", f"  - id: {value}\n".encode(), 1)
                with self.assertRaisesRegex(policy.PolicyError, "route token"):
                    policy.compile_policy(source, ROOT)

        unsafe_alias = base.replace(
            b"      - alpha/mobile\n", b"      - alpha/../mobile\n", 1
        )
        with self.assertRaisesRegex(policy.PolicyError, "route token"):
            policy.compile_policy(unsafe_alias, ROOT)

        unsafe_project_home = base.replace(
            f"{ROOT}/projects/beta".encode(),
            f"{ROOT}/projects/\x01beta".encode(),
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "control character"):
            policy.compile_policy(unsafe_project_home, ROOT)

        noncanonical_project_home = base.replace(
            f"{ROOT}/projects/beta".encode(),
            f"{ROOT}/projects/../escape".encode(),
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "canonical absolute path"):
            policy.compile_policy(noncanonical_project_home, ROOT)

    def test_scope_rules_reject_unknown_ids_and_unknown_mapping_keys(self):
        source = compiled_registry()
        unknown_key = source.replace(
            b"    - id: active-workstream-content\n",
            b"    - id: active-workstream-content\n      surprise: ignored-before\n",
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "unknown fields"):
            policy.compile_policy(unknown_key, ROOT)

        unknown_rule = source.replace(
            b"    - id: fallback-unassigned\n",
            (
                b"    - id: custom-without-compiler-semantics\n"
                b"      path_selectors:\n"
                b"        - custom\n"
                b"      workstream_lifecycle:\n"
                b"        - any\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local\n"
                b"      traversal: metadata-no-follow\n"
                b"      inventory: metadata-only\n"
                b"      content_inspection: forbidden\n"
                b"      write: forbidden\n"
                b"    - id: fallback-unassigned\n"
            ),
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "unsupported scope rule id"):
            policy.compile_policy(unknown_rule, ROOT)

    def test_profile_v1_curation_and_archive_entries_use_exact_allowlists(self):
        source = compiled_registry()
        unknown_curation = source.replace(
            b"curation:\n",
            b"curation:\n  experimental_switch: disabled\n",
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "curation has unknown fields"):
            policy.compile_policy(unknown_curation, ROOT)

        valid_archive = source.replace(
            b"  archive_roots: []\n",
            (
                b"  archive_roots:\n"
                b"    - workstream_id: alpha\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local\n"
                + f"      root: {ROOT}/archive/alpha\n".encode()
            ),
            1,
        )
        compiled = policy.compile_policy(valid_archive, ROOT)
        self.assertEqual(
            compiled.archive_roots,
            (
                policy.CompiledArchiveRoot(
                    workstream_id="alpha",
                    sensitivity="standard",
                    access_domain="local",
                    root=f"{ROOT}/archive/alpha",
                ),
            ),
        )

        noncanonical_workstream_reference = valid_archive.replace(
            b"    - workstream_id: alpha\n",
            b"    - workstream_id: ALPHA\n",
            1,
        )
        with self.assertRaisesRegex(
            policy.PolicyError, "exact canonical Workstream id"
        ):
            policy.compile_policy(noncanonical_workstream_reference, ROOT)

        unknown_archive_key = valid_archive.replace(
            b"    - workstream_id: alpha\n      sensitivity: standard\n",
            (
                b"    - workstream_id: alpha\n"
                b"      sensitivity: standard\n"
                b"      retention: forever\n"
            ),
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "archive_roots.*unknown fields"):
            policy.compile_policy(unknown_archive_key, ROOT)

        unknown_sensitivity = valid_archive.replace(
            b"    - workstream_id: alpha\n      sensitivity: standard\n",
            b"    - workstream_id: alpha\n      sensitivity: public\n",
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "approved sensitivity"):
            policy.compile_policy(unknown_sensitivity, ROOT)

        noncanonical_domain_pair = valid_archive.replace(
            (
                b"    - workstream_id: alpha\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local\n"
            ),
            (
                b"    - workstream_id: alpha\n"
                b"      sensitivity: standard\n"
                b"      access_domain: local-restricted\n"
            ),
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "approved sensitivity/access"):
            policy.compile_policy(noncanonical_domain_pair, ROOT)

    def test_missing_or_nonfinal_fallback_and_writer_pair_mismatch_are_rejected(self):
        source = compiled_registry()
        missing_text = source.decode("utf-8")
        missing_start = missing_text.index("    - id: fallback-unassigned\n")
        missing_end = missing_text.index("  archive_roots: []\n", missing_start)
        missing_fallback = (
            missing_text[:missing_start] + missing_text[missing_end:]
        ).encode("utf-8")
        with self.assertRaisesRegex(policy.PolicyError, "required scope rule"):
            policy.compile_policy(missing_fallback, ROOT)

        text = source.decode("utf-8")
        private_start = text.index("    - id: private-reviewable\n")
        fallback_start = text.index("    - id: fallback-unassigned\n")
        rules_end = text.index("  archive_roots: []\n", fallback_start)
        nonfinal_fallback = (
            text[:private_start]
            + text[fallback_start:rules_end]
            + text[private_start:fallback_start]
            + text[rules_end:]
        ).encode("utf-8")
        with self.assertRaises(policy.PolicyError):
            policy.compile_policy(nonfinal_fallback, ROOT)

        invalid_writer = source.replace(
            b"  movement_writer: legacy\n", b"  movement_writer: curation\n", 1
        )
        with self.assertRaisesRegex(policy.PolicyError, "writer-control combination"):
            policy.compile_policy(invalid_writer, ROOT)

    def test_foundation_paths_must_be_canonical_for_the_supplied_raw_root(self):
        source = compiled_registry().replace(
            f"{ROOT}/_registry/curation-runs".encode(),
            f"{ROOT}/other-runs".encode(),
            1,
        )
        with self.assertRaisesRegex(policy.PolicyError, "canonical curation foundation"):
            policy.compile_policy(source, ROOT)


if __name__ == "__main__":
    unittest.main()
