"""D5-internal read-model coverage retained across the D1b public cutover.

The public audit/capabilities adapters now belong to the Operation Control and
CLI suites.  This module deliberately exercises only the still-unbound,
read-only status/history/pending projections that D5 will migrate.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402,F401
from mnemosyne_core import curation_inspect, curation_inspect_query  # noqa: E402
from mnemosyne_core.operation_control import composition  # noqa: E402
from mnemosyne_core.operation_control.catalog import OperationAvailability  # noqa: E402


def tree_fingerprint(root):
    entries = []
    for path in (root, *sorted(root.rglob("*"))):
        relative = "." if path == root else path.relative_to(root).as_posix()
        status = os.lstat(path)
        digest = None
        target = None
        if path.is_file() and not path.is_symlink():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.is_symlink():
            target = os.readlink(path)
        entries.append(
            (
                relative,
                status.st_dev,
                status.st_ino,
                status.st_mode,
                status.st_uid,
                status.st_gid,
                status.st_nlink,
                status.st_size,
                status.st_mtime_ns,
                status.st_ctime_ns,
                digest,
                target,
            )
        )
    return tuple(entries)


class CurationInspectInternalReadModelTest(unittest.TestCase):
    def test_four_gated_views_have_real_missing_root_read_models_without_binding(self):
        requests = (
            (
                "inspect.status",
                {
                    "as_of": "2026-07-15T00:00:00Z",
                    "reference": {"kind": "workstream", "id": "example-service"},
                },
            ),
            (
                "inspect.history",
                {"reference": {"kind": "item", "id": "item-1"}},
            ),
            (
                "inspect.pending",
                {
                    "as_of": "2026-07-15T00:00:00Z",
                    "reference": None,
                    "state": "all",
                },
            ),
        )
        readers = {
            "inspect.status": lambda root, payload: curation_inspect.read_status(
                root,
                reference=payload["reference"],
                as_of=payload["as_of"],
                max_items=16,
            ),
            "inspect.history": lambda root, payload: curation_inspect.read_history(
                root,
                reference=payload["reference"],
                max_items=16,
            ),
            "inspect.pending": lambda root, payload: curation_inspect.read_pending(
                root,
                reference=payload["reference"],
                state=payload["state"],
                as_of=payload["as_of"],
                max_items=16,
            ),
        }
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "raw"
            root.mkdir(mode=0o700)
            before = tree_fingerprint(root)
            for kind, payload in requests:
                with self.subTest(operation_kind=kind):
                    result = readers[kind](root, payload)
                    self.assertTrue(result["read_only"])
                    self.assertEqual(
                        result["activation_state"],
                        "NOT_ACTIVATED",
                    )
                    self.assertEqual(
                        result["view"],
                        kind.removeprefix("inspect."),
                    )
                    spec = composition.DEFAULT_OPERATION_CATALOG.require_spec(kind)
                    expected_availability = (
                        OperationAvailability.AVAILABLE
                        if kind in {"inspect.history", "inspect.pending"}
                        else OperationAvailability.BLOCKED
                    )
                    self.assertIs(spec.availability, expected_availability)
                    if expected_availability is OperationAvailability.AVAILABLE:
                        self.assertTrue(callable(spec.handler))
                    else:
                        self.assertIsNone(spec.handler)
            self.assertEqual(tree_fingerprint(root), before)
            self.assertFalse((root / "_registry").exists())
            recovery = curation_inspect_query.not_activated_recovery_projection()
            self.assertEqual(recovery["view"], "recovery")
            self.assertEqual(recovery["activation_state"], "NOT_ACTIVATED")
            self.assertEqual(recovery["coverage"], "CONTROL_ROOT_ABSENT")
            self.assertEqual(recovery["entries"], [])
            recovery_spec = composition.DEFAULT_OPERATION_CATALOG.require_spec(
                "inspect.recovery"
            )
            self.assertIsNone(recovery_spec.handler)
            self.assertIs(
                recovery_spec.availability,
                OperationAvailability.DEFERRED,
            )

    def test_gated_progress_readers_use_immutable_session_and_revalidate_policy(self):
        policy = SimpleNamespace(
            full_hash="a" * 64,
            generation=7,
            guard_epoch=3,
        )
        reader = SimpleNamespace(
            approved_policy_ref=policy,
            compiled_policy=SimpleNamespace(
                workstreams=(
                    SimpleNamespace(id="example-service", lifecycle="active"),
                )
            ),
            connection=object(),
            current_policy=mock.Mock(return_value=policy),
        )
        session = mock.MagicMock()
        session.__enter__.return_value = reader
        observed_times = []

        class FakeQuery:
            def __init__(self, _connection, *, now, workstream_lifecycle, current_policy_hash):
                observed_times.append(now().strftime("%Y-%m-%dT%H:%M:%SZ"))
                self.lifecycle = workstream_lifecycle
                self.policy_hash = current_policy_hash

            def workstream_home(self, workstream_id, *, max_items):
                self.lifecycle(workstream_id)
                self.policy_hash()
                return {
                    "kind": "WorkstreamHome",
                    "returned": 0,
                    "truncated": False,
                }

            def history(self, _item_id, *, max_items):
                return {"entries": [], "returned": 0, "truncated": False}

            def list_deferred(self, *, state, workstream_id, max_items):
                if workstream_id is not None:
                    self.lifecycle(workstream_id)
                return {"items": [], "returned": 0, "truncated": False}

        root = Path("/private/tmp/mnemosyne-internal-inspect-active")
        with (
            mock.patch.object(curation_inspect, "_control_root_present", return_value=True),
            mock.patch.object(
                curation_inspect.ledger_runtime,
                "open_reader_session",
                return_value=session,
            ) as opened,
            mock.patch.object(
                curation_inspect.progress_query,
                "ProgressQuery",
                FakeQuery,
            ),
        ):
            status = curation_inspect.read_status(
                root,
                reference={"kind": "workstream", "id": "example-service"},
                as_of="2026-07-15T00:00:00Z",
                max_items=16,
            )
            history = curation_inspect.read_history(
                root,
                reference={"kind": "item", "id": "item-1"},
                max_items=16,
            )
            pending = curation_inspect.read_pending(
                root,
                reference={"kind": "workstream", "id": "example-service"},
                state="due",
                as_of="2026-07-16T00:00:00Z",
                max_items=16,
            )

        self.assertEqual(
            opened.call_args_list,
            [mock.call(root, immutable=True)] * 3,
        )
        self.assertEqual(reader.current_policy.call_count, 3)
        self.assertEqual(
            observed_times,
            [
                "2026-07-15T00:00:00Z",
                "1970-01-01T00:00:00Z",
                "2026-07-16T00:00:00Z",
            ],
        )
        for projection in (status, history, pending):
            self.assertEqual(projection["activation_state"], "ACTIVATED")
            self.assertEqual(projection["policy"]["generation"], 7)
            with self.assertRaises(TypeError):
                projection["activation_state"] = "changed"

    def test_invalid_gated_filters_fail_before_control_or_reader_access(self):
        root = Path("/private/tmp/mnemosyne-invalid-inspect")
        invalid_calls = (
            lambda: curation_inspect.read_status(
                root,
                reference={"kind": "unknown", "id": "id-1"},
                as_of="2026-07-15T00:00:00Z",
                max_items=16,
            ),
            lambda: curation_inspect.read_pending(
                root,
                reference=None,
                state="all",
                as_of="2026-07-15 00:00:00",
                max_items=16,
            ),
            lambda: curation_inspect.read_history(
                root,
                reference={"kind": "item", "id": "item-1"},
                max_items=257,
            ),
        )
        with (
            mock.patch.object(curation_inspect, "_control_root_present") as present,
            mock.patch.object(
                curation_inspect.ledger_runtime,
                "open_reader_session",
            ) as opened,
        ):
            for call in invalid_calls:
                with self.subTest(call=call):
                    with self.assertRaises(curation_inspect.InspectReadError):
                        call()
        present.assert_not_called()
        opened.assert_not_called()

    def test_internal_progress_projections_reject_aggregate_oversize_results(self):
        policy = SimpleNamespace(
            full_hash="a" * 64,
            generation=7,
            guard_epoch=3,
        )
        reader = SimpleNamespace(
            approved_policy_ref=policy,
            compiled_policy=SimpleNamespace(
                workstreams=(
                    SimpleNamespace(id="example-service", lifecycle="active"),
                )
            ),
            connection=object(),
            current_policy=mock.Mock(return_value=policy),
        )
        session = mock.MagicMock()
        session.__enter__.return_value = reader
        huge = "x" * (64 * 1024)

        class HugeQuery:
            def __init__(self, *_args, **_kwargs):
                pass

            def workstream_home(self, _workstream_id, *, max_items):
                return {
                    "items": [huge] * max_items,
                    "returned": max_items,
                    "truncated": False,
                }

            def history(self, _item_id, *, max_items):
                return {
                    "entries": [huge] * max_items,
                    "returned": max_items,
                    "truncated": False,
                }

            def list_deferred(self, *, state, workstream_id, max_items):
                return {
                    "items": [huge] * max_items,
                    "returned": max_items,
                    "truncated": False,
                }

        root = Path("/private/tmp/mnemosyne-oversize-inspect")
        calls = (
            lambda: curation_inspect.read_status(
                root,
                reference={"kind": "workstream", "id": "example-service"},
                as_of="2026-07-15T00:00:00Z",
                max_items=256,
            ),
            lambda: curation_inspect.read_history(
                root,
                reference={"kind": "item", "id": "item-1"},
                max_items=256,
            ),
            lambda: curation_inspect.read_pending(
                root,
                reference=None,
                state="all",
                as_of="2026-07-15T00:00:00Z",
                max_items=256,
            ),
        )
        with (
            mock.patch.object(curation_inspect, "_control_root_present", return_value=True),
            mock.patch.object(
                curation_inspect.ledger_runtime,
                "open_reader_session",
                return_value=session,
            ),
            mock.patch.object(
                curation_inspect.progress_query,
                "ProgressQuery",
                HugeQuery,
            ),
        ):
            for call in calls:
                with self.subTest(call=call):
                    with self.assertRaises(curation_inspect.InspectReadError):
                        call()


if __name__ == "__main__":
    unittest.main()
