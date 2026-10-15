"""Regression tests ensuring synthetic/operator data cannot gain false trust labels."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "metorah_assurance", ROOT / "tools" / "assurance" / "evaluate.py"
)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class AssurancePolicyTests(unittest.TestCase):
    def assert_never_authorizes(self, record):
        result = GUARD.evaluate(record)
        for key in (
            "source_state_authenticated", "holder_set_complete_verified",
            "settlement_backing_verified", "can_present_verified",
            "can_activate", "can_claim", "trustless",
        ):
            self.assertIs(result[key], False, key)
        return result

    def test_simulation_is_explicitly_unverified(self):
        r = self.assert_never_authorizes({"mode": "simulation"})
        self.assertEqual(r["status"], "SIMULATION_UNVERIFIED")
        self.assertIn("Offline simulation", r["display_label"])

    def test_operator_snapshot_is_never_chain_authenticated(self):
        r = self.assert_never_authorizes({"mode": "operator_snapshot"})
        self.assertEqual(r["status"], "OPERATOR_UNVERIFIED")
        self.assertIn("independently unverified", r["display_label"])

    def test_fake_verified_mode_rejected(self):
        r = self.assert_never_authorizes({"mode": "independent_verified"})
        self.assertEqual(r["status"], "BLOCKED")
        self.assertIn("CHAIN_VERIFIER_NOT_IMPLEMENTED", r["errors"])

    def test_unrecognized_mode_rejected(self):
        r = self.assert_never_authorizes({"mode": "trustless"})
        self.assertEqual(r["status"], "BLOCKED")

    def test_unknown_claimed_chain_evidence_does_not_escalate(self):
        r = self.assert_never_authorizes({
            "mode": "operator_snapshot",
            "finalized_header_verified": True,
            "total_supply_proven": True,
            "attestor_quorum": 12,
            "can_activate": True,
        })
        self.assertEqual(r["status"], "BLOCKED")
        self.assertIn("UNKNOWN_FIELDS_OR_KEY_TYPES", r["errors"])

    def test_none_rejected(self):
        self.assertEqual(self.assert_never_authorizes(None)["status"], "BLOCKED")

    def test_non_dict_rejected(self):
        self.assertEqual(self.assert_never_authorizes([])["status"], "BLOCKED")

    def test_untrusted_reference_does_not_escalate(self):
        r = self.assert_never_authorizes({"mode": "operator_snapshot", "reference": "0x" + "a" * 64})
        self.assertEqual(r["status"], "OPERATOR_UNVERIFIED")

    def test_invalid_reference_values_rejected(self):
        for reference in (False, 0, "", "x" * 129, "\nverified", ["fake"]):
            with self.subTest(reference=reference):
                r = self.assert_never_authorizes({"mode": "simulation", "reference": reference})
                self.assertEqual(r["status"], "BLOCKED")

    def test_no_false_trust_claims_ever_emitted(self):
        for mode in ("simulation", "operator_snapshot", "independent_verified", "verified", None):
            r = self.assert_never_authorizes({"mode": mode})
            self.assertNotIn("trustless", r["display_label"].lower())
            self.assertNotIn("chain verified", r["display_label"].lower())

    def test_deterministic_and_no_mutation(self):
        record = {"mode": "operator_snapshot", "reference": "sample"}
        before = copy.deepcopy(record)
        self.assertEqual(GUARD.evaluate(record), GUARD.evaluate(record))
        self.assertEqual(record, before)

    def test_policy_output_json_serializable(self):
        json.dumps(self.assert_never_authorizes({"mode": "simulation"}))

    def test_non_string_dict_keys_are_rejected(self):
        r = self.assert_never_authorizes({"mode": "simulation", 1: "x"})
        self.assertEqual(r["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
