import hashlib
import json
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import mnemosyne  # noqa: E402
from mnemosyne_core import curation_contract  # noqa: E402
from mnemosyne_core.canonical_json import canonical_json_bytes  # noqa: E402


class CurationContractLoaderTest(unittest.TestCase):
    def test_contract_module_is_in_the_verified_source_closure(self):
        closure = {
            module_name: relative_path
            for module_name, relative_path, _is_package in mnemosyne.RUNTIME_MODULE_CLOSURE
        }

        self.assertEqual(
            closure.get("mnemosyne_core.curation_contract"),
            "curation_contract.py",
        )
        self.assertTrue((SCRIPT_DIR / "mnemosyne_core" / "curation_contract.py").is_file())


class HarnessRequestContractTest(unittest.TestCase):
    def request_payload(self):
        return {
            "schema_version": 1,
            "operation_kind": "control.lock_migration",
            "action": "PLAN",
            "root": "/private/tmp/raw",
            "actor": "operator",
            "authority": {"expected_generation": 7},
            "payload": {"requested_scope": ["projects/example-service"]},
            "limits": {"max_items": 25},
        }

    def test_logically_equal_json_has_one_canonical_request_identity(self):
        payload = self.request_payload()
        canonical = curation_contract.parse_request_bytes(canonical_json_bytes(payload))
        reordered = dict(reversed(tuple(payload.items())))
        presentation_bytes = json.dumps(
            reordered,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")

        presented = curation_contract.parse_request_bytes(presentation_bytes)

        self.assertEqual(canonical, presented)
        self.assertEqual(canonical.schema_version, 1)
        self.assertEqual(canonical.operation_kind, "control.lock_migration")
        self.assertIs(canonical.action, curation_contract.LifecycleAction.PLAN)
        self.assertEqual(canonical.root, "/private/tmp/raw")
        self.assertEqual(canonical.actor, "operator")
        self.assertEqual(canonical.canonical_bytes, canonical_json_bytes(payload))
        self.assertEqual(
            canonical.sha256,
            hashlib.sha256(canonical.canonical_bytes).hexdigest(),
        )

    def test_request_is_deeply_immutable_and_exports_only_a_detached_copy(self):
        request = curation_contract.parse_request_bytes(
            canonical_json_bytes(self.request_payload())
        )
        before_bytes = request.canonical_bytes
        before_hash = request.sha256

        with self.assertRaises(TypeError):
            request.authority["expected_generation"] = 8
        with self.assertRaises(TypeError):
            request.payload["requested_scope"].append("projects/example-project")
        with self.assertRaises(TypeError):
            request.limits.update({"max_items": 100})
        with self.assertRaises(TypeError):
            dict.__setitem__(request.authority, "expected_generation", 8)
        with self.assertRaises(TypeError):
            list.append(request.payload["requested_scope"], "projects/example-project")

        detached = curation_contract.request_payload(request)
        detached["authority"]["expected_generation"] = 9
        detached["payload"]["requested_scope"].append("projects/example-project")

        self.assertEqual(request.canonical_bytes, before_bytes)
        self.assertEqual(request.sha256, before_hash)

    def test_direct_constructor_copies_mutable_json_container_subclasses(self):
        class MutableDict(dict):
            pass

        class MutableList(list):
            pass

        payload = MutableDict({"values": MutableList(["original"])})
        request = curation_contract.HarnessRequest(
            schema_version=1,
            operation_kind="test.echo",
            action=curation_contract.LifecycleAction.PLAN,
            root="/private/tmp/raw",
            actor="operator",
            authority={},
            payload=payload,
            limits={},
        )
        before = request.canonical_bytes

        payload["values"].append("outside-mutation")
        with self.assertRaises(TypeError):
            request.payload["values"].append("inside-mutation")

        self.assertEqual(request.payload, {"values": ["original"]})
        self.assertEqual(request.canonical_bytes, before)

    def test_malformed_or_ambiguous_request_bytes_fail_closed(self):
        valid = self.request_payload()
        invalid_values = []

        extra = dict(valid, adapter="skill")
        invalid_values.append(canonical_json_bytes(extra))
        missing = dict(valid)
        missing.pop("actor")
        invalid_values.append(canonical_json_bytes(missing))
        for field, value in (
            ("schema_version", True),
            ("schema_version", 2),
            ("operation_kind", "lock-migration"),
            ("action", "EXECUTE"),
            ("root", "private/tmp/raw"),
            ("root", "/private/tmp/../tmp/raw"),
            ("root", "/private//tmp/raw"),
            ("actor", " operator"),
            ("actor", "operator\nadmin"),
            ("authority", []),
            ("payload", []),
            ("limits", []),
        ):
            candidate = dict(valid)
            candidate[field] = value
            invalid_values.append(canonical_json_bytes(candidate))
        float_payload = self.request_payload()
        float_payload["payload"] = {"ratio": 0.5}
        invalid_values.append(canonical_json_bytes(float_payload))
        bool_limit = self.request_payload()
        bool_limit["limits"] = {"max_items": True}
        invalid_values.append(canonical_json_bytes(bool_limit))
        nested = self.request_payload()
        nested_value = "leaf"
        for _ in range(curation_contract.MAX_JSON_DEPTH + 1):
            nested_value = [nested_value]
        nested["payload"] = {"value": nested_value}
        invalid_values.append(canonical_json_bytes(nested))

        duplicate = canonical_json_bytes(valid).decode("utf-8").replace(
            '"actor":"operator",',
            '"actor":"operator","actor":"forged",',
            1,
        ).encode("utf-8")
        invalid_values.extend(
            (
                duplicate,
                b'{"schema_version":1,"operation_kind":NaN}',
                b"\xff",
                b"",
                b" " * (curation_contract.MAX_REQUEST_BYTES + 1),
            )
        )

        for raw in invalid_values:
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(curation_contract.CurationContractError) as raised:
                    curation_contract.parse_request_bytes(raw)
                self.assertEqual(raised.exception.code, "INVALID_REQUEST")

        with self.assertRaises(curation_contract.CurationContractError) as raised:
            curation_contract.parse_request_bytes(bytearray(canonical_json_bytes(valid)))
        self.assertEqual(raised.exception.code, "INVALID_REQUEST")

        with self.assertRaises(curation_contract.CurationContractError) as raised:
            curation_contract.HarnessRequest(
                schema_version=1,
                operation_kind="test.echo",
                action=curation_contract.LifecycleAction.PLAN,
                root="/private/tmp/raw",
                actor="operator",
                authority={},
                payload={"\ud800": "invalid-utf8-scalar"},
                limits={},
            )
        self.assertEqual(raised.exception.code, "INVALID_REQUEST")


class HarnessResultContractTest(unittest.TestCase):
    def test_result_is_strictly_shaped_canonical_and_deeply_immutable(self):
        result = curation_contract.HarnessResult(
            schema_version=1,
            operation_kind="control.lock_migration",
            action=curation_contract.LifecycleAction.PLAN,
            request_sha256="a" * 64,
            outcome=curation_contract.HarnessOutcome.COMPLETE,
            read_only=False,
            artifacts=[{"artifact_id": "proposal-1", "sha256": "b" * 64}],
            effects=[{"kind": "sealed-proposal", "path": "proposals/proposal-1.json"}],
            not_modified=["corpus", "placement-map"],
            blockers=[],
            next_actions=[{"action": "APPROVE", "requires": ["proposal_id", "sha256"]}],
            payload={"proposal_id": "proposal-1"},
        )
        before = result.canonical_bytes

        with self.assertRaises(TypeError):
            result.artifacts[0]["artifact_id"] = "forged"
        with self.assertRaises(TypeError):
            result.effects.append({"kind": "write"})
        with self.assertRaises(TypeError):
            result.next_actions[0]["requires"].append("actor")
        with self.assertRaises(TypeError):
            list.append(result.effects, {"kind": "base-class-write"})
        with self.assertRaises(TypeError):
            dict.__setitem__(result.payload, "proposal_id", "base-class-forged")

        detached = curation_contract.result_payload(result)
        detached["payload"]["proposal_id"] = "forged"

        self.assertEqual(result.canonical_bytes, before)
        self.assertEqual(
            json.loads(before.decode("utf-8")),
            {
                "schema_version": 1,
                "operation_kind": "control.lock_migration",
                "action": "PLAN",
                "request_sha256": "a" * 64,
                "outcome": "COMPLETE",
                "read_only": False,
                "artifacts": [{"artifact_id": "proposal-1", "sha256": "b" * 64}],
                "effects": [
                    {
                        "kind": "sealed-proposal",
                        "path": "proposals/proposal-1.json",
                    }
                ],
                "not_modified": ["corpus", "placement-map"],
                "blockers": [],
                "next_actions": [
                    {
                        "action": "APPROVE",
                        "requires": ["proposal_id", "sha256"],
                    }
                ],
                "payload": {"proposal_id": "proposal-1"},
            },
        )

    def test_result_rejects_aggregate_canonical_output_over_global_bound(self):
        item = "x" * (curation_contract.MAX_TEXT_BYTES // 2)
        item_count = curation_contract.MAX_RESULT_BYTES // len(item) + 2
        self.assertLessEqual(item_count, curation_contract.MAX_CONTAINER_ITEMS)

        with self.assertRaises(curation_contract.CurationContractError) as raised:
            curation_contract.HarnessResult(
                schema_version=1,
                operation_kind="test.echo",
                action=curation_contract.LifecycleAction.PLAN,
                request_sha256="a" * 64,
                outcome=curation_contract.HarnessOutcome.COMPLETE,
                read_only=False,
                artifacts=[item] * item_count,
                effects=[],
                not_modified=[],
                blockers=[],
                next_actions=[],
                payload={},
            )

        self.assertEqual(raised.exception.code, "HANDLER_RESULT_INVALID")


class CapabilityDescriptorContractTest(unittest.TestCase):
    def test_descriptor_is_machine_readable_and_contains_no_dispatch_callable(self):
        descriptor = curation_contract.CapabilityDescriptor(
            schema_version=1,
            operation_kind="control.lock_migration",
            actions=(
                curation_contract.ActionContract(
                    action=curation_contract.LifecycleAction.PLAN,
                    read_only=False,
                    approval_required=False,
                    authority_fields=(),
                    payload_fields=("entrypoint_manifest",),
                ),
                curation_contract.ActionContract(
                    action=curation_contract.LifecycleAction.APPLY,
                    read_only=False,
                    approval_required=True,
                    authority_fields=("proposal_id", "proposal_sha256"),
                    payload_fields=(),
                ),
                curation_contract.ActionContract(
                    action=curation_contract.LifecycleAction.RESUME,
                    read_only=False,
                    approval_required=False,
                    authority_fields=("proposal_id",),
                    payload_fields=(),
                ),
            ),
            availability=curation_contract.CapabilityAvailability.BLOCKED,
            hard_limits={"max_request_bytes": 65536},
            activation_required=True,
            prerequisite="handler-migration-pending",
        )

        with self.assertRaises(TypeError):
            descriptor.hard_limits["max_request_bytes"] = 131072
        with self.assertRaises(TypeError):
            dict.__setitem__(
                descriptor.hard_limits,
                "max_request_bytes",
                131072,
            )

        payload = curation_contract.capability_descriptor_payload(descriptor)
        self.assertEqual(payload["operation_kind"], "control.lock_migration")
        self.assertEqual(payload["availability"], "BLOCKED")
        self.assertEqual(
            [entry["action"] for entry in payload["actions"]],
            ["PLAN", "APPLY", "RESUME"],
        )
        self.assertEqual(
            frozenset(payload),
            frozenset(
                (
                    "schema_version",
                    "operation_kind",
                    "actions",
                    "availability",
                    "hard_limits",
                    "activation_required",
                    "prerequisite",
                )
            ),
        )
        self.assertNotIn("handler", payload)
        self.assertNotIn("module", payload)
        self.assertNotIn("import_path", payload)
        self.assertEqual(
            payload["actions"][1]["authority_fields"],
            ["proposal_id", "proposal_sha256"],
        )
        self.assertEqual(
            payload["actions"][0]["payload_fields"],
            ["entrypoint_manifest"],
        )


if __name__ == "__main__":
    unittest.main()
