import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from mnemosyne_core import review_units  # noqa: E402


def item(item_id, path, **changes):
    values = {
        "item_id": item_id,
        "path": path,
        "size": 10,
        "scope_class": "active-workstream-content",
        "scope_rule_id": "active-workstream-content",
        "primary_workstream": "alpha",
        "related_workstreams": (),
        "shared": False,
        "document_role": "docs",
        "authority": "reference",
        "document_lifecycle": "current",
        "sensitivity": "public",
        "access_domain": "default",
        "recommended_action": "move",
        "risk_band": "low",
        "freeze_state": "active",
        "reference_complete": True,
        "negative_flags": (),
    }
    values.update(changes)
    return review_units.ReviewItem(**values)


class ReviewUnitBuilderTest(unittest.TestCase):
    def test_homogeneous_descendants_collapse_to_one_folder_unit(self):
        items = (
            item("item-a", "projects/alpha/a.md"),
            item("item-b", "projects/alpha/b.md", size=20),
        )

        result = review_units.ReviewUnitBuilder("units-v1").build(items)

        self.assertEqual(len(result.units), 1)
        unit = result.units[0]
        self.assertEqual(unit.kind, "folder")
        self.assertEqual(unit.path, "projects/alpha")
        self.assertEqual(unit.member_item_ids, ("item-a", "item-b"))
        self.assertEqual(unit.underlying_file_count, 2)
        self.assertEqual(unit.total_bytes, 30)
        self.assertEqual(unit.explode_reasons, ())
        self.assertEqual(len(unit.descendant_manifest_sha256), 64)

    def test_mixed_risk_forces_file_units_without_duplicate_membership(self):
        items = (
            item("item-a", "projects/alpha/a.md", risk_band="low"),
            item("item-b", "projects/alpha/b.md", risk_band="high"),
        )

        result = review_units.ReviewUnitBuilder("units-v1").build(items)

        self.assertEqual([unit.kind for unit in result.units], ["file", "file"])
        self.assertEqual(
            [member for unit in result.units for member in unit.member_item_ids],
            ["item-a", "item-b"],
        )
        self.assertFalse(
            any(unit.kind == "folder" for unit in result.units)
        )

    def test_parallel_snapshot_and_pure_explode_api_are_not_exposed(self):
        self.assertFalse(hasattr(review_units, "ReviewUnitSnapshot"))
        self.assertFalse(hasattr(review_units, "explode_review_unit"))
        self.assertNotIn("ReviewUnitSnapshot", review_units.__all__)
        self.assertNotIn("explode_review_unit", review_units.__all__)

    def test_grouping_property_each_homogeneity_axis_or_negative_flag_forces_explode(self):
        axis_changes = (
            {"scope_class": "fallback-unassigned"},
            {"scope_rule_id": "fallback-unassigned"},
            {"primary_workstream": "beta"},
            {"related_workstreams": ("beta",)},
            {"shared": True},
            {"document_role": "requirements"},
            {"authority": "evidence"},
            {"document_lifecycle": "draft"},
            {"sensitivity": "private"},
            {"access_domain": "owner"},
            {"recommended_action": "defer"},
            {"risk_band": "medium"},
            {"freeze_state": "frozen"},
            {"reference_complete": False},
        )
        negative_flags = (
            "competing-workstream",
            "unresolved-ambiguity",
            "protected",
            "opaque",
            "unreadable",
            "inventory-error",
            "mount-boundary",
            "symlink-boundary",
            "lifecycle-override-required",
            "link-impact",
            "path-dependent-output",
            "user-item-marker",
        )

        for changes in axis_changes:
            with self.subTest(changes=changes):
                result = review_units.ReviewUnitBuilder("units-v1").build(
                    (
                        item("item-a", "projects/alpha/a.md"),
                        item("item-b", "projects/alpha/b.md", **changes),
                    )
                )
                self.assertEqual([unit.kind for unit in result.units], ["file", "file"])
        for flag in negative_flags:
            with self.subTest(flag=flag):
                result = review_units.ReviewUnitBuilder("units-v1").build(
                    (
                        item("item-a", "projects/alpha/a.md"),
                        item(
                            "item-b",
                            "projects/alpha/b.md",
                            negative_flags=(flag,),
                        ),
                    )
                )
                memberships = [
                    member for unit in result.units for member in unit.member_item_ids
                ]
                self.assertEqual(sorted(memberships), ["item-a", "item-b"])
                self.assertEqual(len(memberships), len(set(memberships)))
                self.assertFalse(any(unit.kind == "folder" for unit in result.units))


if __name__ == "__main__":
    unittest.main()
