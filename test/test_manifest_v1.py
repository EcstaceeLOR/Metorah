"""Cross-language V1 vectors and adversarial canonical-manifest tests.

The values below are SYNTHETIC. Passing these tests proves encoding only, not
the actual Portaldot chain or asset settlement.
"""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

BASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("metorah_canonical_manifest", BASE / "tools/manifest/canonical.py")
V1 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = V1
SPEC.loader.exec_module(V1)

HEADER = {
    "source_genesis": "0x" + "11" * 32,
    "finalized_block_hash": "0x" + "22" * 32,
    "finalized_block_number": "12345",
    "finalized_state_root": "0x" + "33" * 32,
    "source_contract": "0x" + "44" * 32,
    "source_code_hash": "0x" + "55" * 32,
    "migration_id": "0x" + "66" * 32,
    "asset_id": "0x" + "77" * 32,
    "destination_chain_id": "31337",
    "destination_contract": "0x" + "88" * 20,
    "entitlement_kind": 1,
    "decimals": 12,
    "historical_holder_count": 4,
    "active_holder_count": 3,
    "total_units": "90",
}
ENTRIES = [
    {"leaf_index": 0, "historical_index": 0,
     "source_account": "0x" + "aa" * 32, "beneficiary": "0x" + "11" * 20,
     "units": "10", "binding_nonce": "1"},
    {"leaf_index": 1, "historical_index": 2,
     "source_account": "0x" + "bb" * 32, "beneficiary": "0x" + "22" * 20,
     "units": "30", "binding_nonce": "2"},
    {"leaf_index": 2, "historical_index": 3,
     "source_account": "0x" + "cc" * 32, "beneficiary": "0x" + "33" * 20,
     "units": "50", "binding_nonce": "1"},
]
EXPECTED = {
    "header": "d8a338af8ac7ac775f65646714d3de231b3d679b1ba130bd83ad511fe3f400ba",
    "leaves": [
        "31fd1d1354ec4a31635782b658d76a7a24d9c568686a7063c110049b14da876f",
        "d6bafe136167850d2d43217a5e0fb0ff1a4ed6329a943aab062719c3296b746e",
        "3b2567bf18b77629a18970da6f354db9816d2497804bcd21c56669e34fab1b1f",
    ],
    "node01": "f6112ada26f352d1f304c5f44e1ba41f835e45d3e1d3f4413e879a5b5056e22f",
    "node22": "b50840082b5c970ae048310d964aa71e0802b1e4e5fc11439964ac9a3280f80d",
    "root": "d1b8fe5f690cd868bd784a22e50c71c55593ff78f91dde76ffec919efe39a060",
    "manifest": "e8de0555b6a4dacbaeb2bee30fad6652341a00d4f83b932c02a07240390e217f",
}


class CanonicalTests(unittest.TestCase):
    def good(self):
        return V1.build(copy.deepcopy(HEADER), copy.deepcopy(ENTRIES))

    def fails(self, header=None, entries=None, code=None):
        with self.assertRaises(V1.ManifestError) as err:
            V1.build(HEADER if header is None else header,
                     ENTRIES if entries is None else entries)
        if code:
            self.assertEqual(err.exception.code, code)

    def test_cross_language_vectors_exact(self):
        report = self.good()
        self.assertEqual(report["header_hash"], "0x" + EXPECTED["header"])
        self.assertEqual(report["merkle_root"], "0x" + EXPECTED["root"])
        self.assertEqual(report["manifest_digest"], "0x" + EXPECTED["manifest"])
        hashed = [V1.leaf_hash(bytes.fromhex(EXPECTED["header"]), e, HEADER).hex() for e in ENTRIES]
        self.assertEqual(hashed, EXPECTED["leaves"])
        self.assertEqual(V1.node_hash(bytes.fromhex(hashed[0]), bytes.fromhex(hashed[1])).hex(), EXPECTED["node01"])
        self.assertEqual(V1.node_hash(bytes.fromhex(hashed[2]), bytes.fromhex(hashed[2])).hex(), EXPECTED["node22"])
        self.assertEqual(len(V1._canonical_header(HEADER)), 286)
        self.assertEqual(len(V1._canonical_leaf(ENTRIES[0], active_count=3, historical_count=4)), 84)

    def test_round_trip_all_positional_proofs(self):
        report = self.good()
        for i, entry in enumerate(ENTRIES):
            self.assertTrue(V1.verify_proof(HEADER, entry, V1.proof_for(report, i), report["merkle_root"]))
            self.assertEqual(len(V1.proof_for(report, i)), 2)

    def test_odd_leaf_duplicates_itself(self):
        r = self.good()
        proof = V1.proof_for(r, 2)
        self.assertEqual(proof[0], "0x" + EXPECTED["leaves"][2])
        self.assertEqual(proof[1], "0x" + EXPECTED["node01"])
        proof[0] = "0x" + EXPECTED["leaves"][1]
        self.assertFalse(V1.verify_proof(HEADER, ENTRIES[2], proof, r["merkle_root"]))

    def test_extra_missing_or_illtyped_proof_fails(self):
        r = self.good()
        proof = V1.proof_for(r, 0)
        for candidate in ([], proof + [proof[0]], [123, *proof[1:]], ["0xf", proof[1]]):
            with self.subTest(candidate=candidate):
                self.assertFalse(V1.verify_proof(HEADER, ENTRIES[0], candidate, r["merkle_root"]))

    def test_untrusted_success_never_authorizes_claims(self):
        r = self.good()
        self.assertTrue(V1.verify_manifest(r))
        self.assertEqual(r["assurance"], "E1_ENCODING_ONLY")
        self.assertFalse(r["source_chain_authenticated"])
        self.assertFalse(r["can_activate"])
        self.assertFalse(r["can_claim"])
        r["can_claim"] = True
        self.assertFalse(V1.verify_manifest(r))

    def test_source_genesis_replay_changes_root(self):
        h = copy.deepcopy(HEADER);h["source_genesis"] = "0x" + "ff" * 32
        self.assertNotEqual(V1.build(h, ENTRIES)["merkle_root"], self.good()["merkle_root"])

    def test_finalized_block_replay_changes_root(self):
        for key, val in [("finalized_block_hash", "0x" + "ff"*32),
                         ("finalized_state_root", "0x" + "ef"*32),
                         ("finalized_block_number", "12346")]:
            h = copy.deepcopy(HEADER);h[key] = val
            self.assertNotEqual(V1.build(h, ENTRIES)["merkle_root"], self.good()["merkle_root"])

    def test_source_contract_and_code_replay_changes_root(self):
        for key in ("source_contract", "source_code_hash", "asset_id", "migration_id"):
            h=copy.deepcopy(HEADER);h[key] = "0x" + "ef"*32
            self.assertNotEqual(V1.build(h, ENTRIES)["merkle_root"], self.good()["merkle_root"])

    def test_destination_domain_replay_changes_root(self):
        for key, val in (("destination_chain_id", "1"), ("destination_contract", "0x" + "ef"*20)):
            h=copy.deepcopy(HEADER);h[key] = val
            self.assertNotEqual(V1.build(h, ENTRIES)["merkle_root"], self.good()["merkle_root"])

    def test_user_or_recipient_or_registration_replay_changes_leaf(self):
        r = self.good()
        for key, val in (("source_account", "0x"+"99"*32),
                         ("beneficiary", "0x"+"99"*20),
                         ("binding_nonce", "3"),
                         ("units", "9")):
            e=copy.deepcopy(ENTRIES[0]);e[key] = val
            self.assertFalse(V1.verify_proof(HEADER, e, V1.proof_for(r, 0), r["merkle_root"]))

    def test_cannot_swap_holder_order(self):
        v=copy.deepcopy(ENTRIES);v[0],v[1] = v[1],v[0]
        self.fails(entries=v,code="NONCANONICAL_LEAF_INDEX")

    def test_skipped_or_reused_leaf_indices_rejected(self):
        v=copy.deepcopy(ENTRIES);v[1]["leaf_index"] = 0
        self.fails(entries=v,code="NONCANONICAL_LEAF_INDEX")

    def test_historical_index_must_increase(self):
        v=copy.deepcopy(ENTRIES);v[1]["historical_index"] = 0
        self.fails(entries=v,code="NONCANONICAL_HOLDER_ORDER")

    def test_duplicate_owner_different_index_rejected(self):
        v=copy.deepcopy(ENTRIES);v[1]["source_account"] = v[0]["source_account"]
        self.fails(entries=v,code="DUPLICATE_SOURCE_ACCOUNT")

    def test_zero_beneficiary_rejected(self):
        v=copy.deepcopy(ENTRIES);v[0]["beneficiary"] = "0x"+"00"*20
        self.fails(entries=v,code="ZERO_BENEFICIARY")

    def test_zero_units_rejected(self):
        v=copy.deepcopy(ENTRIES);v[0]["units"] = "0"
        self.fails(entries=v,code="INVALID_UNITS")

    def test_zero_registration_nonce_rejected(self):
        v=copy.deepcopy(ENTRIES);v[0]["binding_nonce"] = "0"
        self.fails(entries=v,code="INVALID_BINDING_NONCE")

    def test_decimal_amount_strings_are_lossless(self):
        for val in ("01", "1.0", 1, "+1", "-1", " 1", "1e0", "0x1"):
            v=copy.deepcopy(ENTRIES);v[0]["units"] = val
            with self.subTest(value=val):
                self.fails(entries=v,code="INVALID_UNITS")

    def test_uint128_aggregate_overflow(self):
        h=copy.deepcopy(HEADER);h["total_units"] = str(V1.MAX_U128)
        v=copy.deepcopy(ENTRIES)
        v[0]["units"] = str(V1.MAX_U128)
        v[1]["units"] = "1"
        self.fails(header=h,entries=v,code="AGGREGATE_OVERFLOW")

    def test_mismatched_source_total_rejected(self):
        h=copy.deepcopy(HEADER);h["total_units"] = "91"
        self.fails(header=h,code="TOTAL_SUPPLY_MISMATCH")

    def test_missing_positive_holder_rejected(self):
        self.fails(entries=ENTRIES[:2],code="LEAF_COUNT_MISMATCH")

    def test_more_positive_than_historical_rejected(self):
        h=copy.deepcopy(HEADER);h["historical_holder_count"]=2
        self.fails(header=h,code="INVALID_HOLDER_COUNTS")

    def test_zero_or_invalid_chain_domains_rejected(self):
        for key,val,err in [
            ("source_genesis","0x"+"00"*32,"ZERO_SOURCE_GENESIS"),
            ("destination_chain_id","0","INVALID_DESTINATION_CHAIN_ID"),
            ("destination_contract","0x"+"00"*20,"ZERO_DESTINATION_CONTRACT"),
            ("migration_id","0x"+"00"*32,"ZERO_MIGRATION_ID"),
        ]:
            h=copy.deepcopy(HEADER);h[key]=val
            with self.subTest(key=key):
                self.fails(header=h,code=err)

    def test_reject_leading_zero_chain_id(self):
        h=copy.deepcopy(HEADER);h["destination_chain_id"]="031337"
        self.fails(header=h,code="INVALID_DESTINATION_CHAIN_ID")

    def test_case_sensitive_canonical_hex(self):
        h=copy.deepcopy(HEADER);h["source_contract"]="0x"+"AA"*32
        self.fails(header=h,code="INVALID_SOURCE_CONTRACT")

    def test_unsupported_entitlement_kind(self):
        h=copy.deepcopy(HEADER);h["entitlement_kind"]=2
        self.fails(header=h,code="UNSUPPORTED_ENTITLEMENT_KIND")

    def test_decimals_zero_valid_and_above_18_rejected(self):
        h=copy.deepcopy(HEADER);h["decimals"]=0
        self.assertTrue(V1.verify_manifest(V1.build(h,ENTRIES)))
        h["decimals"]=19
        self.fails(header=h,code="INVALID_DECIMALS")

    def test_unknown_header_or_entry_fields_rejected(self):
        h=copy.deepcopy(HEADER);h["operator_says_verified"]=True
        self.fails(header=h,code="INVALID_HEADER_SCHEMA")
        v=copy.deepcopy(ENTRIES);v[0]["claimed"]=True
        self.fails(entries=v,code="INVALID_LEAF_SCHEMA")

    def test_proof_does_not_rely_on_sorted_siblings(self):
        r=self.good();p=V1.proof_for(r,1)
        self.assertTrue(V1.verify_proof(HEADER,ENTRIES[1],p,r["merkle_root"]))
        p.reverse()
        self.assertFalse(V1.verify_proof(HEADER,ENTRIES[1],p,r["merkle_root"]))

    def test_one_leaf_root_equals_leaf(self):
        h=copy.deepcopy(HEADER);h["active_holder_count"]=1;h["total_units"]="10"
        e=[copy.deepcopy(ENTRIES[0])]
        r=V1.build(h,e)
        self.assertEqual(r["merkle_root"],"0x"+V1.leaf_hash(V1.header_hash(h),e[0],h).hex())
        self.assertEqual(V1.proof_for(r,0),[])
        self.assertTrue(V1.verify_proof(h,e[0],[],r["merkle_root"]))

    def test_boolean_integer_coercion_is_blocked(self):
        h=copy.deepcopy(HEADER);h["entitlement_kind"]=True
        self.fails(header=h,code="UNSUPPORTED_ENTITLEMENT_KIND")

    def test_manifest_digest_tampering_detected(self):
        r=self.good();r["manifest_digest"]="0x"+"ff"*32
        self.assertFalse(V1.verify_manifest(r))


if __name__ == "__main__":
    unittest.main()
