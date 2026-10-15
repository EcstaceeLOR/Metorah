"""Offline tests for migration-scoped beneficiary and registration-history checks."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("metorah_binding_inspect", ROOT / "tools" / "bindings" / "inspect.py")
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)
from test_enumeration import SCAN, MockLedger, BLOCK, acct

SOURCE_CONTRACT = acct(9000)
CHAIN_ID = 31337
DESTINATION = "0x" + "9" * 40
MIGRATION = "0x" + "b" * 64


def h160(n: int) -> str:
    return f"0x{n:040x}"


class RegistrationReader:
    def __init__(self, balances=(40, 0, 60)):
        self.source = MockLedger(list(balances))
        self.header = SCAN.scan(self.source, pinned_block_hash=BLOCK)
        self.domain = (CHAIN_ID, DESTINATION, MIGRATION)
        self.domain_calls = 0
        self.domain_last_override = None
        self.reads = []
        self.bindings = {}
        self.histories = {}
        for e in self.header["positive_holders"]:
            owner = e["source_account"]
            ben = h160(100 + e["source_index"])
            self.bindings[owner] = {"beneficiary": ben, "nonce": 1}
            self.histories[owner] = [self.event(owner, 1, "0x" + "0" * 40, ben)]

    def event(self, owner, nonce, old, new):
        return {
            "source_owner": owner,
            "source_contract": SOURCE_CONTRACT,
            "destination_chain_id": CHAIN_ID,
            "destination_contract": DESTINATION,
            "migration_id": MIGRATION,
            "previous_beneficiary": old,
            "beneficiary": new,
            "nonce": nonce,
        }

    def pinned(self, block):
        assert block == BLOCK
        self.reads.append(block)

    def destination_domain(self, at_block):
        self.pinned(at_block)
        self.domain_calls += 1
        if self.domain_calls > 1 and self.domain_last_override is not None:
            return self.domain_last_override
        return self.domain

    def binding_at(self, index, at_block):
        self.pinned(at_block)
        owner, units = self.source.entries[index]
        return (owner, units, copy.deepcopy(self.bindings.get(owner)))

    def binding_of(self, owner, at_block):
        self.pinned(at_block)
        return copy.deepcopy(self.bindings.get(owner))

    def registration_events(self, owner, at_block):
        self.pinned(at_block)
        return copy.deepcopy(self.histories.get(owner, []))


class BindingsAuditTests(unittest.TestCase):
    def check_failure(self, reader, code, **kwargs):
        with self.assertRaises(AUDIT.BindingAuditError) as err:
            AUDIT.inspect(
                reader, inventory=reader.header, pinned_block_hash=BLOCK,
                source_contract=SOURCE_CONTRACT, **kwargs
            )
        self.assertEqual(err.exception.code, code)

    def success(self, reader):
        out = AUDIT.inspect(
            reader, inventory=reader.header, pinned_block_hash=BLOCK,
            source_contract=SOURCE_CONTRACT,
        )
        self.assertEqual(out["status"], "BINDINGS_RECONCILED_UNAUTHENTICATED")
        self.assertFalse(out["can_activate"])
        self.assertFalse(out["can_claim"])
        self.assertFalse(out["binding_events_chain_authenticated"])
        self.assertFalse(out["source_chain_authenticated"])
        self.assertTrue(all(block == BLOCK for block in reader.reads))
        return out

    def test_produces_positive_eligible_holder_candidate_records(self):
        r = RegistrationReader()
        out = self.success(r)
        self.assertEqual([x["source_index"] for x in out["positive_holders"]], [0, 2])
        self.assertEqual(out["total_supply_units"], "100")
        self.assertEqual(out["positive_holders"][0]["beneficiary"], h160(100))
        self.assertEqual(out["positive_holders"][1]["registration_nonce"], 1)

    def test_source_wallet_can_change_its_target_before_freeze_in_model(self):
        r = RegistrationReader()
        owner = acct(1)
        initial = r.bindings[owner]["beneficiary"]
        updated = h160(500)
        r.histories[owner].append(r.event(owner, 2, initial, updated))
        r.bindings[owner] = {"beneficiary": updated, "nonce": 2}
        out = self.success(r)
        self.assertEqual(out["positive_holders"][0]["registration_nonce"], 2)
        self.assertEqual(out["positive_holders"][0]["beneficiary"], updated)

    def test_empty_snapshot_has_no_binding_records(self):
        r = RegistrationReader([])
        self.assertEqual(self.success(r)["positive_holders"], [])

    def test_missing_mapping_fails(self):
        r = RegistrationReader()
        r.bindings.pop(acct(1))
        self.check_failure(r, "MISSING_OR_INVALID_BINDING")

    def test_missing_registration_history_fails(self):
        r = RegistrationReader()
        r.histories[acct(1)] = []
        self.check_failure(r, "INCOMPLETE_BINDING_HISTORY")

    def test_event_owner_swap_fails(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["source_owner"] = acct(2)
        self.check_failure(r, "EVENT_SOURCE_MISMATCH")

    def test_event_source_contract_swap_fails(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["source_contract"] = acct(3)
        self.check_failure(r, "EVENT_SOURCE_MISMATCH")

    def test_cross_migration_event_replay_fails(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["migration_id"] = acct(303)
        self.check_failure(r, "EVENT_DESTINATION_DOMAIN_MISMATCH")

    def test_cross_destination_chain_replay_fails(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["destination_chain_id"] = 1
        self.check_failure(r, "EVENT_DESTINATION_DOMAIN_MISMATCH")

    def test_cross_destination_contract_replay_fails(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["destination_contract"] = h160(31)
        self.check_failure(r, "EVENT_DESTINATION_DOMAIN_MISMATCH")

    def test_bool_chain_id_event_is_not_treated_as_integer_one(self):
        r = RegistrationReader()
        r.domain = (1, DESTINATION, MIGRATION)
        r.histories[acct(1)][0]["destination_chain_id"] = True
        r.histories[acct(3)][0]["destination_chain_id"] = 1
        self.check_failure(r, "EVENT_DESTINATION_DOMAIN_MISMATCH")

    def test_nonce_gaps_fail(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["nonce"] = 2
        self.check_failure(r, "NONCONTIGUOUS_BINDING_NONCE")

    def test_updated_history_missing_first_event_fails(self):
        r = RegistrationReader()
        r.bindings[acct(1)]["nonce"] = 2
        self.check_failure(r, "INCOMPLETE_BINDING_HISTORY")

    def test_wrong_previous_beneficiary_breaks_history(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["previous_beneficiary"] = h160(9)
        self.check_failure(r, "BINDING_HISTORY_BROKEN")

    def test_final_event_recipient_mismatch_fails(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["beneficiary"] = h160(8)
        self.check_failure(r, "FINAL_BENEFICIARY_MISMATCH")

    def test_changed_target_in_direct_storage_fails(self):
        r = RegistrationReader()
        original = r.binding_of
        def wrong(owner, block):
            value = original(owner, block)
            if owner == acct(1):
                value["beneficiary"] = h160(999)
            return value
        r.binding_of = wrong
        self.check_failure(r, "DIRECT_BINDING_DISAGREEMENT")

    def test_wrong_units_in_binding_at_fails(self):
        r = RegistrationReader()
        original = r.binding_at
        r.binding_at = lambda i, b: (lambda row: (row[0], row[1] + 1, row[2]))(original(i, b))
        self.check_failure(r, "BINDING_ROW_DISAGREEMENT")

    def test_invalid_zero_evm_address_fails(self):
        r = RegistrationReader()
        r.bindings[acct(1)]["beneficiary"] = "0x" + "0" * 40
        self.check_failure(r, "INVALID_BENEFICIARY")

    def test_wrong_source_account_index_fails(self):
        r = RegistrationReader()
        original = r.binding_at
        r.binding_at = lambda i, b: (acct(876), original(i, b)[1], original(i, b)[2])
        self.check_failure(r, "BINDING_ROW_DISAGREEMENT")

    def test_source_chain_authentication_claim_not_accepted(self):
        r = RegistrationReader()
        r.header["source_chain_authenticated"] = True
        self.check_failure(r, "UNEXPECTED_AUTHENTICATION_CLAIM")

    def test_block_mismatch_fails(self):
        r = RegistrationReader()
        r.header["pinned_block_hash"] = acct(500)
        self.check_failure(r, "PINNED_BLOCK_MISMATCH")

    def test_invalid_chain_id_and_domain_fails(self):
        r = RegistrationReader()
        r.domain = (0, DESTINATION, MIGRATION)
        self.check_failure(r, "INVALID_CHAIN_ID")

    def test_domain_changed_during_scan_fails(self):
        r = RegistrationReader()
        r.domain_last_override = (CHAIN_ID + 1, DESTINATION, MIGRATION)
        self.check_failure(r, "DESTINATION_DOMAIN_CHANGED")

    def test_reader_failure_fails_closed(self):
        r = RegistrationReader()
        def failure(*args):
            raise OSError("RPC down")
        r.binding_of = failure
        self.check_failure(r, "BINDING_READER_FAILED")

    def test_malformed_registration_event_fails(self):
        r = RegistrationReader()
        r.histories[acct(1)][0]["arbitrary_operator_signature"] = True
        self.check_failure(r, "INVALID_BINDING_EVENT")

    def test_bad_account_nonce_types_fails(self):
        r = RegistrationReader()
        r.bindings[acct(1)]["nonce"] = True
        self.check_failure(r, "INVALID_BINDING_NONCE")

    def test_deterministic_diagnostic_not_merkle_proof(self):
        a = self.success(RegistrationReader())
        b = self.success(RegistrationReader())
        self.assertEqual(a, b)
        self.assertEqual(len(a["diagnostic_sha256_not_merkle"]), 64)
        self.assertNotIn("merkle_root", a)
        json.dumps(a)

    def test_noncanonical_uint_amount_fails(self):
        r = RegistrationReader()
        r.header["positive_holders"][0]["units"] = "040"
        self.check_failure(r, "INVALID_ENTITLEMENT_UNITS")

    def test_wrong_report_total_fails(self):
        r = RegistrationReader()
        r.header["total_supply_units"] = "101"
        self.check_failure(r, "TOTAL_ALLOCATION_MISMATCH")


if __name__ == "__main__":
    unittest.main()
