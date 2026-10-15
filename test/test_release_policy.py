"""Prevent false readiness claims from metadata controlled by operators."""
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("metorah_release", ROOT / "tools/release/check.py")
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
SHA = "a" * 40


class ReleasePolicyTests(unittest.TestCase):
    def guarded(self, record):
        result = RELEASE.evaluate(record)
        self.assertFalse(result["can_run_live_pilot"])
        self.assertFalse(result["can_process_customer_assets"])
        self.assertFalse(result["can_deploy_to_chain"])
        self.assertFalse(result["chain_evidence_authenticated"])
        self.assertFalse(result["external_audit_completed"])
        return result

    def test_only_research_with_sha_allowed(self):
        x = self.guarded({"phase": "research", "commit_sha": SHA})
        self.assertEqual(x["status"], "RESEARCH_ONLY")
        self.assertTrue(x["can_publish_research"])

    def test_missing_commit_blocks_even_research(self):
        x = self.guarded({"phase": "research"})
        self.assertEqual(x["status"], "BLOCKED")
        self.assertIn("MISSING_OR_INVALID_SOURCE_COMMIT", x["errors"])

    def test_invalid_commit_blocks(self):
        for sha in (0, None, "", "0x" + SHA, "a" * 39, "z" * 40):
            with self.subTest(sha=sha):
                self.assertEqual(self.guarded({"phase": "research", "commit_sha": sha})["status"], "BLOCKED")

    def test_testnet_cannot_authorize_itself(self):
        x = self.guarded({"phase": "testnet_pilot", "commit_sha": SHA})
        self.assertIn("LIVE_SECURITY_GATES_UNIMPLEMENTED", x["errors"])

    def test_design_partner_blocked(self):
        self.assertEqual(self.guarded({"phase": "design_partner_beta", "commit_sha": SHA})["status"], "BLOCKED")

    def test_production_blocked(self):
        self.assertEqual(self.guarded({"phase": "production", "commit_sha": SHA})["status"], "BLOCKED")

    def test_fake_reviews_and_chain_receipts_cannot_escalate(self):
        x = self.guarded({
            "phase": "production", "commit_sha": SHA, "chain_verified": True,
            "audit_passed": True, "tx_hash": "0x" + "c" * 64, "approval": "yes",
        })
        self.assertEqual(x["status"], "BLOCKED")
        self.assertIn("UNKNOWN_FIELDS_OR_KEY_TYPES", x["errors"])

    def test_bad_type_rejected(self):
        for bad in (None, [], "yes", True):
            self.assertEqual(self.guarded(bad)["status"], "BLOCKED")

    def test_unknown_phase_rejected(self):
        x = self.guarded({"phase": "mainnet", "commit_sha": SHA})
        self.assertIn("UNSUPPORTED_RELEASE_PHASE", x["errors"])

    def test_cannot_inject_trust_fields_even_on_research(self):
        x = self.guarded({"phase": "research", "commit_sha": SHA, "can_deploy_to_chain": True})
        self.assertEqual(x["status"], "BLOCKED")

    def test_summary_is_descriptive_only(self):
        x = self.guarded({"phase": "research", "commit_sha": SHA, "summary": "DEPLOYED"})
        self.assertEqual(x["status"], "RESEARCH_ONLY")
        self.assertFalse(x["can_deploy_to_chain"])

    def test_oversized_summary_rejected(self):
        self.assertEqual(self.guarded({"phase": "research", "commit_sha": SHA, "summary": "x" * 513})["status"], "BLOCKED")

    def test_output_deterministic_and_serializable(self):
        item = {"phase": "research", "commit_sha": SHA}
        self.assertEqual(self.guarded(item), self.guarded(item))
        json.dumps(RELEASE.evaluate(item))

    def test_nonstring_keys_rejected(self):
        self.assertEqual(self.guarded({"phase": "research", "commit_sha": SHA, 3: "x"})["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
