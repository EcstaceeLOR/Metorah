"""Unit tests for deterministic lifecycle policy and idempotency fingerprinting."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.orchestrator.service import (  # noqa: E402
    Actor,
    DurableOrchestrator,
    OrchestrationError,
    TRANSITIONS,
    canonical_request_hash,
)


class OrchestratorPolicyTests(unittest.TestCase):
    def test_canonical_hash_is_order_independent_for_json_objects(self):
        self.assertEqual(
            canonical_request_hash({"target": "prepared", "version": 1}),
            canonical_request_hash({"version": 1, "target": "prepared"}),
        )

    def test_canonical_hash_changes_with_semantic_payload(self):
        self.assertNotEqual(
            canonical_request_hash({"target": "prepared", "version": 1}),
            canonical_request_hash({"target": "frozen", "version": 1}),
        )

    def test_non_json_nan_is_rejected(self):
        with self.assertRaises(ValueError):
            canonical_request_hash({"amount": float("nan")})

    def test_transition_rules_require_roles_and_verified_gates(self):
        roles, gates = TRANSITIONS[("draft", "prepared")]
        self.assertIn("operator", roles)
        self.assertEqual(gates, frozenset({"source_eligible", "mapping_window_closed"}))

    def test_illegal_shortcut_is_not_in_transition_table(self):
        self.assertNotIn(("draft", "activated"), TRANSITIONS)
        self.assertNotIn(("completed", "draft"), TRANSITIONS)
        self.assertNotIn(("cancelled", "prepared"), TRANSITIONS)

    def test_role_policy_separates_reviewer_from_activator(self):
        approve_roles, _ = TRANSITIONS[("review", "approved")]
        activate_roles, _ = TRANSITIONS[("ready", "activated")]
        self.assertIn("security_reviewer", approve_roles)
        self.assertNotIn("security_reviewer", activate_roles)
        self.assertIn("governance", activate_roles)

    def test_actor_validation_fails_closed(self):
        with self.assertRaises(OrchestrationError) as missing:
            DurableOrchestrator._validate_actor(None)
        self.assertEqual(missing.exception.code, "unauthorized")
        with self.assertRaises(OrchestrationError) as bad_type:
            DurableOrchestrator._validate_actor(Actor("tenant-a", "worker", ("admin",), "untrusted"))
        self.assertEqual(bad_type.exception.code, "unauthorized")


if __name__ == "__main__":
    unittest.main()
