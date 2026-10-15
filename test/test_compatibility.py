"""Behavioral tests: policy must fail closed for unsupported capabilities."""
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("metorah_compatibility", ROOT / "tools" / "compatibility" / "check.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
FIXTURE = json.loads((ROOT / "tools" / "compatibility" / "example-candidate.json").read_text())


class CompatibilityTests(unittest.TestCase):
    def base(self):
        return json.loads(json.dumps(FIXTURE))

    def test_candidate_is_not_authorized_to_freeze_or_activate(self):
        result = CHECK.evaluate(self.base())
        self.assertEqual(result["status"], "CANDIDATE_REQUIRES_INDEPENDENT_VERIFICATION")
        self.assertTrue(result["candidate_for_design_review"])
        self.assertFalse(result["can_freeze"])
        self.assertFalse(result["can_activate"])
        self.assertFalse(result["source_state_authenticated"])

    def test_absent_descriptor_rejected(self):
        self.assertEqual(CHECK.evaluate(None)["status"], "BLOCKED")

    def test_nft_rejected(self):
        m = self.base(); m["asset_kind"] = "nft_721"
        self.assertIn("UNSUPPORTED_ASSET_KIND", CHECK.evaluate(m)["reasons"])

    def test_unenumerable_mapping_rejected(self):
        m = self.base(); m["enumerates_complete_holder_set"] = False
        self.assertIn("REQUIREMENT_NOT_DECLARED:enumerates_complete_holder_set", CHECK.evaluate(m)["reasons"])

    def test_unknown_extra_state_rejected(self):
        m = self.base(); m["features"].append("roles")
        self.assertIn("UNSUPPORTED_STATE_FEATURES:roles", CHECK.evaluate(m)["reasons"])

    def test_ambiguous_features_rejected(self):
        m = self.base(); m["features"].append("fungible_balances")
        self.assertIn("DUPLICATE_FEATURES", CHECK.evaluate(m)["reasons"])

    def test_missing_wallet_binding_rejected(self):
        m = self.base(); m["features"].remove("destination_bindings")
        self.assertIn("MISSING_REQUIRED_FEATURES:destination_bindings", CHECK.evaluate(m)["reasons"])

    def test_unknown_metadata_field_rejected(self):
        m = self.base(); m["can_mint_at_destination"] = True
        self.assertIn("UNKNOWN_FIELDS:can_mint_at_destination", CHECK.evaluate(m)["reasons"])

    def test_wrong_execution_environment_rejected(self):
        m = self.base(); m["source_vm"] = "evm"
        self.assertIn("UNSUPPORTED_SOURCE_VM", CHECK.evaluate(m)["reasons"])

    def test_malformed_genesis_rejected(self):
        m = self.base(); m["source_genesis_hash"] = "not-a-real-genesis"
        self.assertIn("MISSING_OR_INVALID_SOURCE_GENESIS", CHECK.evaluate(m)["reasons"])

    def test_missing_finality_or_proof_rejected(self):
        m = self.base(); del m["pins_state_to_finalized_block"]
        m["exposes_verifiable_storage_evidence"] = "true"
        x = CHECK.evaluate(m)
        self.assertFalse(x["candidate_for_design_review"])
        self.assertFalse(x["can_activate"])
        self.assertIn("REQUIREMENT_NOT_DECLARED:pins_state_to_finalized_block", x["reasons"])
        self.assertIn("REQUIREMENT_NOT_DECLARED:exposes_verifiable_storage_evidence", x["reasons"])

    def test_repeated_assessment_is_deterministic(self):
        m = self.base(); m["features"] = ["arbitrary_storage", "vesting"]
        self.assertEqual(CHECK.evaluate(m), CHECK.evaluate(m))


if __name__ == "__main__":
    unittest.main()
