"""Offline migration reference model tests. Gate flags are test fixtures only."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("metorah_lifecycle", ROOT / "tools/lifecycle/model.py")
import sys
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


def fixture(funded=100):
    return MODEL.Migration((MODEL.Entitlement(0, "0xAlice", 40), MODEL.Entitlement(1, "0xBob", 60)), 100, funded)


def move(m, target, actor, gates, n):
    return m.transition(target, actor, frozenset(gates), str(n))


def until_review(m):
    move(m, "PREPARED", "operator", {"source_eligible", "mapping_window_closed"}, 1)
    move(m, "FROZEN", "source_governance", {"freeze_finalized", "source_retired"}, 2)
    move(m, "VERIFIED", "verifier", {"header_verified", "trie_verified", "holders_complete", "bindings_verified"}, 3)
    move(m, "REVIEW", "security_reviewer", {"manifest_domain_bound"}, 4)


def activate(m):
    until_review(m)
    move(m, "ACTIVATED", "governance", {"review_complete", "backing_verified", "disputes_cleared", "source_retired"}, 5)


class LifecycleTests(unittest.TestCase):
    def test_full_happy_path_and_conservation(self):
        m = fixture(); activate(m)
        m.claim(0, "0xAlice", 40, "a")
        m.claim(1, "0xBob", 60, "b")
        self.assertEqual((m.claimed_total, m.outstanding_total), (100, 0))
        move(m, "COMPLETED", "governance", {"claim_window_ended", "liabilities_reconciled"}, 6)
        self.assertEqual(m.state, "COMPLETED")
        m.assert_invariants()

    def test_wrong_source_sum_rejected(self):
        with self.assertRaisesRegex(MODEL.LifecycleError, "SOURCE_ALLOCATION_MISMATCH"):
            MODEL.Migration((MODEL.Entitlement(0, "A", 5),), 6, 6)

    def test_duplicate_holder_index_rejected(self):
        with self.assertRaisesRegex(MODEL.LifecycleError, "DUPLICATE_INDEX"):
            MODEL.Migration((MODEL.Entitlement(1, "A", 5), MODEL.Entitlement(1, "B", 5)), 10, 10)

    def test_no_claim_before_activation(self):
        m = fixture()
        with self.assertRaisesRegex(MODEL.LifecycleError, "CLAIM_NOT_ACTIVE"):
            m.claim(0, "0xAlice", 40, "x")

    def test_skip_freeze_not_allowed(self):
        m = fixture()
        with self.assertRaisesRegex(MODEL.LifecycleError, "FORBIDDEN_TRANSITION"):
            move(m, "ACTIVATED", "governance", set(), 1)

    def test_only_approved_role_fixture(self):
        m = fixture()
        with self.assertRaisesRegex(MODEL.LifecycleError, "UNAUTHORIZED_ROLE_FIXTURE"):
            move(m, "PREPARED", "attacker", {"source_eligible", "mapping_window_closed"}, 1)

    def test_missing_freeze_evidence_blocks(self):
        m = fixture(); move(m, "PREPARED", "operator", {"source_eligible", "mapping_window_closed"}, 1)
        with self.assertRaisesRegex(MODEL.LifecycleError, "MISSING_EVIDENCE_FIXTURE"):
            move(m, "FROZEN", "source_governance", {"freeze_finalized"}, 2)

    def test_missing_trie_or_holder_proof_blocks(self):
        m = fixture(); move(m, "PREPARED", "operator", {"source_eligible", "mapping_window_closed"}, 1)
        move(m, "FROZEN", "source_governance", {"freeze_finalized", "source_retired"}, 2)
        with self.assertRaisesRegex(MODEL.LifecycleError, "MISSING_EVIDENCE_FIXTURE"):
            move(m, "VERIFIED", "verifier", {"header_verified", "holders_complete"}, 3)

    def test_underfunded_activation_fails_even_if_flag_present(self):
        m = fixture(funded=99); until_review(m)
        with self.assertRaisesRegex(MODEL.LifecycleError, "BACKING_SHORTFALL"):
            move(m, "ACTIVATED", "governance", {"review_complete", "backing_verified", "disputes_cleared", "source_retired"}, 5)

    def test_attacker_cannot_change_beneficiary_or_amount(self):
        m = fixture(); activate(m)
        for index, who, amount in ((0, "0xMallory", 40), (0, "0xAlice", 41), (2, "0xUnknown", 1)):
            with self.subTest(index=index, who=who, amount=amount):
                with self.assertRaisesRegex(MODEL.LifecycleError, "INVALID_ENTITLEMENT_PROOF_FIXTURE"):
                    m.claim(index, who, amount, f"wrong-{index}-{who}-{amount}")

    def test_duplicate_claim_rejected(self):
        m = fixture(); activate(m)
        m.claim(0, "0xAlice", 40, "claim-A")
        with self.assertRaisesRegex(MODEL.LifecycleError, "ALREADY_CLAIMED"):
            m.claim(0, "0xAlice", 40, "claim-B")
        m.assert_invariants()

    def test_same_request_replay_is_idempotent(self):
        m = fixture(); activate(m)
        a = m.claim(0, "0xAlice", 40, "claim-A")
        self.assertEqual(a, m.claim(0, "0xAlice", 40, "claim-A"))
        self.assertEqual(m.claimed_total, 40)
        self.assertEqual(sum(e.action == "claim" for e in m.events), 1)

    def test_changed_request_payload_rejected(self):
        m = fixture(); activate(m)
        m.claim(0, "0xAlice", 40, "claim-A")
        with self.assertRaisesRegex(MODEL.LifecycleError, "IDEMPOTENCY_KEY_REUSE"):
            m.claim(1, "0xBob", 60, "claim-A")

    def test_dispute_terminates_old_review_and_requires_reverification(self):
        m = fixture(); until_review(m)
        move(m, "DISPUTED", "guardian", {"challenge_recorded"}, 6)
        with self.assertRaisesRegex(MODEL.LifecycleError, "FORBIDDEN_TRANSITION"):
            move(m, "ACTIVATED", "governance", {"review_complete"}, 7)
        move(m, "FROZEN", "verifier", {"dispute_resolved", "freeze_finalized", "source_retired"}, 8)
        self.assertEqual(m.state, "FROZEN")

    def test_pause_resumes_only_after_incident_and_funding_review(self):
        m = fixture(); activate(m)
        move(m, "PAUSED", "guardian", set(), 6)
        with self.assertRaisesRegex(MODEL.LifecycleError, "CLAIM_NOT_ACTIVE"):
            m.claim(0, "0xAlice", 40, "fail")
        with self.assertRaisesRegex(MODEL.LifecycleError, "MISSING_EVIDENCE_FIXTURE"):
            move(m, "ACTIVATED", "guardian", {"incident_resolved"}, 7)
        move(m, "ACTIVATED", "guardian", {"incident_resolved", "backing_verified"}, 8)
        m.claim(0, "0xAlice", 40, "good")
        move(m, "PAUSED", "guardian", set(), 9)
        with self.assertRaisesRegex(MODEL.LifecycleError, "INVALID_RESUME_STATE"):
            move(m, "ACTIVATED", "guardian", {"incident_resolved", "backing_verified"}, 10)
        move(m, "CLAIMING", "guardian", {"incident_resolved", "backing_verified"}, 11)
        m.assert_invariants()

    def test_cancelled_is_terminal(self):
        m = fixture()
        move(m, "CANCELLED", "governance", {"no_settlement"}, 1)
        with self.assertRaisesRegex(MODEL.LifecycleError, "FORBIDDEN_TRANSITION"):
            move(m, "PREPARED", "operator", {"source_eligible", "mapping_window_closed"}, 2)

    def test_cannot_complete_before_claim(self):
        m = fixture(); activate(m)
        with self.assertRaisesRegex(MODEL.LifecycleError, "FORBIDDEN_TRANSITION"):
            move(m, "COMPLETED", "governance", {"claim_window_ended", "liabilities_reconciled"}, 6)

    def test_outstanding_liability_after_partial_claim(self):
        m = fixture(); activate(m); m.claim(0, "0xAlice", 40, "partial")
        self.assertEqual(m.outstanding_total, 60)
        m.assert_invariants()

    def test_transition_event_is_idempotent(self):
        m = fixture()
        flags = {"source_eligible", "mapping_window_closed"}
        e = move(m, "PREPARED", "operator", flags, 1)
        self.assertEqual(e, move(m, "PREPARED", "operator", flags, 1))
        self.assertEqual(len(m.events), 1)


if __name__ == "__main__":
    unittest.main()
