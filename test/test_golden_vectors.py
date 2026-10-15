"""Immutable source-free, no-private-key four-language golden fixture validations."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/manifest"))
import canonical as V1
import generate_golden as GENERATOR

FIXTURE = json.loads((ROOT / "fixtures/manifest-v1/golden.json").read_text())


class GoldenVectorTests(unittest.TestCase):
    def test_tracked_fixture_bytes_are_identical_to_regenerated_artifact(self):
        self.assertEqual(
            (ROOT / "fixtures/manifest-v1/golden.json").read_text(),
            GENERATOR.render(),
        )

    def test_expected_sizes_and_synthetic_assurance_guard(self):
        self.assertEqual([x["holders"] for x in FIXTURE["cases"]], [1, 2, 3, 257])
        for k in ("source_chain_authenticated", "can_activate", "can_claim"):
            self.assertIs(FIXTURE[k], False)
        self.assertEqual(FIXTURE["assurance"], "E1_ENCODING_ONLY")

    def test_header_root_manifest_and_every_sample_proof(self):
        for item in FIXTURE["cases"]:
            generated = GENERATOR.fixture_case(item["holders"])
            self.assertEqual(item, generated)
            n = item["holders"]
            self.assertEqual(item["historical_holder_count"], n + (n - 1) // 8 + 1)
            self.assertEqual(len(item["samples"]), 1 if n == 1 else 2)
            self.assertEqual(len(item["header_hash"]), 66)
            self.assertEqual(len(item["merkle_root"]), 66)

    def test_zero_or_forged_last_sibling_does_not_pass(self):
        for n in (3, 257):
            f = GENERATOR.fixture_case(n)
            header, entries = self._inputs(n)
            sample = f["samples"][-1]
            forged = list(sample["proof"])
            self.assertEqual(forged[0], sample["leaf_hash"])
            forged[0] = f["header_hash"]
            self.assertFalse(V1.verify_proof(header, entries[-1], forged, f["merkle_root"]))

    def test_beneficiary_redirection_or_migration_replay_breaks_golden(self):
        h, entries = self._inputs(3)
        root = GENERATOR.fixture_case(3)["merkle_root"]
        proof = GENERATOR.fixture_case(3)["samples"][0]["proof"]
        changed = copy.deepcopy(entries[0])
        changed["beneficiary"] = "0x" + "aa" * 20
        self.assertFalse(V1.verify_proof(h, changed, proof, root))
        changed_h = dict(h, destination_chain_id="1")
        self.assertFalse(V1.verify_proof(changed_h, entries[0], proof, root))
        changed_h = dict(h, migration_id="0x" + "aa"*32)
        self.assertFalse(V1.verify_proof(changed_h, entries[0], proof, root))

    def test_misordered_or_duplicate_histories_fail_closed(self):
        h, entries = self._inputs(3)
        with self.assertRaises(V1.ManifestError):
            V1.build(h, [entries[1], entries[0], entries[2]])
        dup = copy.deepcopy(entries)
        dup[1]["source_account"] = dup[0]["source_account"]
        with self.assertRaises(V1.ManifestError):
            V1.build(h, dup)

    def test_largest_case_has_nine_level_positional_path(self):
        f = GENERATOR.fixture_case(257)
        self.assertEqual(len(f["samples"][-1]["proof"]), 9)
        self.assertEqual(f["samples"][-1]["proof"][0], f["samples"][-1]["leaf_hash"])
        self.assertEqual(f["total_units"], "6022795")

    @staticmethod
    def _inputs(n):
        fixture = GENERATOR.fixture_case(n)
        # Generate fresh independent source data exactly per the public formula.
        h = {
            "source_genesis": "0x"+"11"*32, "finalized_block_hash": "0x"+"22"*32,
            "finalized_block_number": "12345", "finalized_state_root": "0x"+"33"*32,
            "source_contract": "0x"+"44"*32, "source_code_hash": "0x"+"55"*32,
            "migration_id": "0x"+"66"*32, "asset_id": "0x"+"77"*32,
            "destination_chain_id": "31337", "destination_contract": "0x"+"88"*20,
            "entitlement_kind": 1, "decimals": 12,
            "historical_holder_count": fixture["historical_holder_count"],
            "active_holder_count": n, "total_units": fixture["total_units"],
        }
        entries = [
            {
                "leaf_index": i, "historical_index": i+i//8,
                "source_account": f"0x{i+1:064x}", "beneficiary": f"0x{i+1001:040x}",
                "units": str((i+1)*(i+11)), "binding_nonce": str(1+i%3),
            } for i in range(n)
        ]
        return h, entries


if __name__ == "__main__":
    unittest.main()
