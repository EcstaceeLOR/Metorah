"""Offline challenge policy adversarial regression tests."""
import importlib.util
from pathlib import Path
import sys
import unittest

FILE = Path(__file__).resolve().parents[1] / "tools/disputes/policy.py"
SPEC = importlib.util.spec_from_file_location("metorah_dispute_policy", FILE)
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)
H = "a" * 64
J = "b" * 64

def review():
    return policy.Review.open("migration-1", H, 100, 200, "operator", {"alice", "bob"}, {"guardian"})

class DisputePolicyTests(unittest.TestCase):
    def reject(self, fn, reason):
        with self.assertRaisesRegex(policy.Rejected, reason):
            fn()

    def test_approval_requires_all_reviewers_and_expired_challenge_window(self):
        x = review()
        self.assertFalse(x.decision(300)["review_policy_pass"])
        x.approve("alice", 150)
        self.assertFalse(x.decision(300)["review_policy_pass"])
        x.approve("bob", 151)
        self.assertFalse(x.decision(200)["review_policy_pass"])
        self.assertTrue(x.decision(201)["review_policy_pass"])
        self.assertFalse(x.decision(201)["can_activate"])
        self.assertFalse(x.decision(201)["can_claim"])
        self.assertFalse(x.decision(201)["source_chain_authenticated"])
        self.assertTrue(x.verify_history())

    def test_challenge_blocks_and_resets_existing_approvals(self):
        x = review(); x.approve("alice", 120)
        x.challenge("c1", "OMITTED_HOLDER", "holder", J, 130)
        self.assertFalse(x.approvals)
        self.reject(lambda: x.approve("bob", 140), "UNRESOLVED_OBJECTION")
        self.reject(lambda: x.resolve("c1", "holder", "REJECTED", H, 150), "REVIEWER_REQUIRED")
        x.resolve("c1", "alice", "REJECTED", H, 151)
        x.approve("alice", 152); x.approve("bob", 153)
        self.assertTrue(x.decision(201)["review_policy_pass"])

    def test_upheld_challenge_invalidates(self):
        x = review(); x.challenge("c1", "SOURCE_FORK", "holder", J, 140)
        x.resolve("c1", "bob", "UPHELD", H, 150)
        self.assertFalse(x.decision(300)["review_policy_pass"])
        self.reject(lambda: x.approve("alice", 160), "REVIEW_NOT_ACTIVE")
        y = x.replace("operator", J, 170, 270)
        self.assertEqual(x.state, "REPLACED")
        self.assertEqual(y.revision, 1)
        self.assertTrue(y.verify_history())
        self.assertFalse(y.decision(250)["review_policy_pass"])

    def test_guardian_hold_and_cancel(self):
        x = review(); x.approve("alice", 120); x.approve("bob", 121)
        x.set_hold("guardian", True, 130)
        self.assertIn("GUARDIAN_HOLD", x.decision(250)["reasons"])
        self.assertFalse(x.approvals)
        self.reject(lambda: x.set_hold("operator", False, 140), "GUARDIAN_REQUIRED")
        x.set_hold("guardian", False, 141)
        x.approve("alice", 142); x.approve("bob", 143)
        self.assertTrue(x.decision(250)["review_policy_pass"])
        x.cancel("guardian", 251)
        self.assertFalse(x.decision(300)["review_policy_pass"])

    def test_input_validation_and_separation_of_duties(self):
        self.reject(lambda: policy.Review.open("m1", H, 100, 100, "op", {"a", "b"}, {"g"}), "BAD_REVIEW_WINDOW")
        self.reject(lambda: policy.Review.open("m1", H, 100, 200, "op", {"op", "b"}, {"g"}), "CONFLICT_OF_INTEREST")
        self.reject(lambda: policy.Review.open("m1", H, 100, 200, "op", {"g", "b"}, {"g"}), "REVIEWER_GUARDIAN_CONFLICT")
        self.reject(lambda: policy.Review.open("m1", "wrong", 100, 200, "op", {"a", "b"}, {"g"}), "INVALID_HASH")

    def test_window_duplicate_replay_and_stale_time(self):
        x = review()
        self.reject(lambda: x.challenge("c1", "OTHER", "holder", J, 201), "CHALLENGE_WINDOW_CLOSED")
        x.challenge("c1", "OTHER", "holder", J, 150)
        self.reject(lambda: x.challenge("c1", "OTHER", "holder", J, 151), "DUPLICATE_CHALLENGE")
        self.reject(lambda: x.resolve("c1", "alice", "REJECTED", H, 149), "NONMONOTONIC_TIMESTAMP")
        self.reject(lambda: x.resolve("c1", "alice", "ACCEPT", H, 151), "BAD_DECISION")

    def test_event_hash_chain_detects_mutation(self):
        x = review(); x.challenge("c1", "OTHER", "holder", J, 150)
        self.assertTrue(x.verify_history())
        x.events[1]["details"]["kind"] = "WRONG_ROOT"
        self.assertFalse(x.verify_history())

    def test_reviewers_cannot_adjudicate_their_own_challenges(self):
        x = review(); x.challenge("c1", "OTHER", "alice", J, 140)
        self.reject(lambda: x.resolve("c1", "alice", "REJECTED", H, 150), "SELF_ADJUDICATION_FORBIDDEN")

    def test_replacement_requires_new_manifest_and_proposer(self):
        x = review()
        self.reject(lambda: x.replace("operator", H, 130, 250), "SAME_MANIFEST_FORBIDDEN")
        self.reject(lambda: x.replace("guardian", J, 130, 250), "PROPOSER_REQUIRED")
        x.replace("operator", J, 131, 250)
        self.reject(lambda: x.replace("operator", "c" * 64, 132, 250), "REPLACEMENT_FORBIDDEN")

if __name__ == "__main__":
    unittest.main()
