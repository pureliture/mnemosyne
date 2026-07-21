import copy
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import context_assembly


def _coverage(*, memory_status, sources=(), gaps=()):
    group_counts = {}
    for source in sources:
        group_counts[source.group] = group_counts.get(source.group, 0) + 1
    return context_assembly.ContextCoverage(
        local_inspected=1 if any(source.mode == "CURRENT_LOCAL" for source in sources) else 0,
        local_excluded=0,
        local_unreadable=0,
        local_truncated=0,
        source_group_counts=tuple(sorted(group_counts.items())),
        memory_status=memory_status,
        memory_history_inspected=0,
        memory_history_included=sum(source.group == "MEMORY_HISTORY" for source in sources),
        memory_history_excluded=0,
        memory_history_malformed=0,
        memory_history_truncated=0,
        external_verified=0,
        external_unverified=sum(source.mode == "UNVERIFIED_EXTERNAL" for source in sources),
        excluded_paths=(),
        gap_paths=tuple(sorted(gap.relative_path for gap in gaps if gap.relative_path)),
        redaction_counts=(("secret", 1),) if sources else (),
    )


def _complete_assembly():
    external = context_assembly.ContextSource(
        source_id="external:jira:" + "e" * 64,
        group="EXTERNAL_REFERENCE",
        mode="UNVERIFIED_EXTERNAL",
        reference_family="jira",
        reference_sha256="e" * 64,
    )
    projection = context_assembly.ContextContentProjection(
        title="Decision",
        headings=("Evidence",),
        headings_truncated=False,
        excerpt="Safe excerpt",
        excerpt_truncated=False,
        redaction_counts=(("secret", 1),),
        full_content_sha256="a" * 64,
        full_content_byte_count=12,
    )
    local = context_assembly.ContextSource(
        source_id="observation-1",
        group="PROJECT_ROOT",
        mode="CURRENT_LOCAL",
        relative_path="projects/alpha/decision.md",
        observation_id="observation-1",
        identity=(1, 2, 501, 448, 1, 12, 3),
        content_sha256="a" * 64,
        snapshot_sha256="b" * 64,
        content_projection=projection,
        reference_source_ids=(external.source_id,),
    )
    sources = (local, external)
    return context_assembly.ContextAssembly(
        workstream=context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=("a",),
            memory_workspace=None,
        ),
        root_identity=(1, 2, 448, 501),
        project_identity=(1, 3, 448, 501),
        policy_sha256="c" * 64,
        outcome="COMPLETE",
        bounds=context_assembly.ContextAssemblyBounds(snapshot_bytes=7),
        sources=sources,
        claims=(
            context_assembly.ContextClaim(
                claim_id="claim-local",
                mode="CURRENT_LOCAL",
                subject="current decision",
                supporting_source_ids=(local.source_id,),
            ),
            context_assembly.ContextClaim(
                claim_id="claim-external",
                mode="UNVERIFIED_EXTERNAL",
                subject="reference exists",
                supporting_source_ids=(external.source_id,),
            ),
        ),
        gaps=(),
        coverage=_coverage(memory_status="NOT_CONFIGURED", sources=sources),
    )


def _incomplete_assembly():
    gap = context_assembly.ContextGap(
        gap_id="gap-history",
        kind="MISSING",
        group="MEMORY_HISTORY",
        reason_code="HISTORY_DIRECTORY_MISSING",
        relative_path="memory/alpha/history",
    )
    return context_assembly.ContextAssembly(
        workstream=context_assembly.ContextWorkstream(
            id="alpha",
            lifecycle="active",
            project_home="projects/alpha",
            aliases=(),
            memory_workspace="alpha",
        ),
        root_identity=(1, 2, 448, 501),
        project_identity=(1, 3, 448, 501),
        policy_sha256="c" * 64,
        outcome="INCOMPLETE",
        bounds=context_assembly.ContextAssemblyBounds(),
        sources=(),
        claims=(),
        gaps=(gap,),
        coverage=_coverage(memory_status="CONFIGURED", gaps=(gap,)),
    )


class ContextAssemblyDecoderTest(unittest.TestCase):
    def test_complete_and_incomplete_canonical_values_round_trip_exactly(self):
        decoder = getattr(context_assembly, "decode_context_assembly", None)
        self.assertTrue(callable(decoder))

        for assembly in (_complete_assembly(), _incomplete_assembly()):
            with self.subTest(outcome=assembly.outcome):
                decoded = decoder(copy.deepcopy(assembly.canonical_value))
                self.assertIsInstance(decoded, context_assembly.ContextAssembly)
                self.assertEqual(decoded.canonical_value, assembly.canonical_value)
                self.assertEqual(decoded.sha256, assembly.sha256)

    def test_rejects_unknown_missing_and_noncanonical_collection_shapes(self):
        decoder = getattr(context_assembly, "decode_context_assembly", None)
        value = _complete_assembly().canonical_value
        cases = {
            "unknown-root-field": lambda v: v.update({"surprise": "no"}),
            "missing-root-field": lambda v: v.pop("coverage_sha256"),
            "tuple-instead-of-list": lambda v: v.__setitem__("sources", tuple(v["sources"])),
            "bool-as-int": lambda v: v["bounds"].__setitem__("snapshot_bytes", True),
            "unknown-nested-field": lambda v: v["coverage"].update({"surprise": 1}),
        }
        for name, tamper in cases.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(value)
                tamper(candidate)
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    decoder(candidate)

    def test_rejects_nested_tampering_and_nonsemantic_envelopes(self):
        decoder = getattr(context_assembly, "decode_context_assembly", None)
        value = _complete_assembly().canonical_value
        cases = {
            "wrong-schema": lambda v: v.__setitem__("schema", "blocked-envelope-v1"),
            "wrong-spec": lambda v: v.__setitem__("spec_sha256", "f" * 64),
            "coverage-hash": lambda v: v.__setitem__("coverage_sha256", "f" * 64),
            "workstream-alias": lambda v: v["workstream"].__setitem__("aliases", ["a", "a"]),
            "projection-hash": lambda v: v["sources"][1]["content_projection"].__setitem__("full_content_sha256", "f" * 64),
            "claim-source": lambda v: v["claims"][0].__setitem__("supporting_source_ids", ["missing"]),
            "source-reference": lambda v: v["sources"][1].__setitem__("reference_source_ids", []),
            "coverage-source-count": lambda v: v["coverage"].__setitem__("source_group_counts", {"PROJECT_ROOT": 9}),
        }
        for name, tamper in cases.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(value)
                tamper(candidate)
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    decoder(candidate)

        incomplete = _incomplete_assembly().canonical_value
        for name, tamper in {
            "gap-field-set": lambda v: v["gaps"][0].update({"surprise": "no"}),
            "gap-coverage-binding": lambda v: v["coverage"].__setitem__("gap_paths", []),
        }.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(incomplete)
                tamper(candidate)
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    decoder(candidate)

        for envelope in (
            {"outcome": "BLOCKED_UNSAFE", "assembly_id": None},
            {"outcome": "STALE", "assembly_id": "a" * 64},
        ):
            with self.subTest(envelope=envelope["outcome"]):
                with self.assertRaises(context_assembly.ContextAssemblyError):
                    decoder(envelope)
