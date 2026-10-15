"""Adversarial read-only freeze evidence tests.

The reader deliberately pretends to be a chain RPC. A passing test never
authenticates Portaldot, consensus, a block hash or a source storage proof.
"""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("metorah_freeze_observe", ROOT / "tools/freeze/observe.py")
OBS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OBS
SPEC.loader.exec_module(OBS)


def h256(n: int) -> str:
    return f"0x{n:064x}"


GENESIS = h256(1)
CONTRACT = h256(2)
CODE = h256(3)
TX = h256(4)
BLOCK = h256(5)
FINAL = h256(6)
ROOT = h256(7)
PARENT = h256(8)
OWNER = h256(9)
ASSET = h256(10)
MIGRATION = h256(11)
DESTINATION = "0x" + "a" * 40
NUMBER = 77


class FakeChain:
    def __init__(self):
        self.calls: list[tuple] = []
        self.genesis = GENESIS
        self.finalized = FINAL
        self.headers = {
            BLOCK: {"number": NUMBER, "state_root": ROOT, "parent_hash": PARENT},
            FINAL: {"number": NUMBER + 3, "state_root": h256(15), "parent_hash": h256(16)},
        }
        self.canonical_block = BLOCK
        self.second_canonical_block = None
        self.block_hash_calls = 0
        self.code_hash = CODE
        self.owner = OWNER
        self.snap = {
            "frozen": True,
            "asset_id": ASSET,
            "decimals": 12,
            "max_supply": 1_000,
            "total_supply": 100,
            "holder_count": 3,
            "active_holder_count": 2,
        }
        self.second_snapshot = None
        self.snapshot_calls = 0
        self.marker = (NUMBER, 100, 3, 2, 0)
        self.domain = (31337, DESTINATION, MIGRATION)
        self.unbound = 0
        self.freeze_event = {
            "type": "SourceFrozen",
            "by": OWNER,
            "source_contract": CONTRACT,
            "source_block": NUMBER,
            "asset_id": ASSET,
            "migration_id": MIGRATION,
            "destination_chain_id": 31337,
            "destination_contract": DESTINATION,
            "total_supply": 100,
            "holder_count": 3,
            "active_holder_count": 2,
            "unbound_active_holders": 0,
        }
        self.receipt = {
            "tx_hash": TX,
            "block_hash": BLOCK,
            "extrinsic_index": 2,
            "dispatch_success": True,
            "source_contract": CONTRACT,
            "signer": OWNER,
            "events": [self.freeze_event],
        }

    def _copy(self, name, out, *extra):
        self.calls.append((name, *extra))
        return copy.deepcopy(out)

    def chain_genesis_hash(self):
        return self._copy("chain_genesis_hash", self.genesis)

    def finalized_head_hash(self):
        return self._copy("finalized_head_hash", self.finalized)

    def block_hash_at(self, number):
        assert number == NUMBER
        self.block_hash_calls += 1
        return self._copy(
            "block_hash_at",
            self.second_canonical_block if self.block_hash_calls > 1 and self.second_canonical_block is not None else self.canonical_block,
            number,
        )

    def header_at(self, block):
        return self._copy("header_at", self.headers.get(block), block)

    def freeze_receipt(self, tx):
        assert tx == TX
        return self._copy("freeze_receipt", self.receipt, tx)

    def contract_code_hash(self, account, block):
        assert (account, block) == (CONTRACT, BLOCK)
        return self._copy("contract_code_hash", self.code_hash, account, block)

    def contract_owner(self, account, block):
        assert (account, block) == (CONTRACT, BLOCK)
        return self._copy("contract_owner", self.owner, account, block)

    def freeze_marker(self, account, block):
        assert (account, block) == (CONTRACT, BLOCK)
        return self._copy("freeze_marker", self.marker, account, block)

    def registry_snapshot(self, account, block):
        assert (account, block) == (CONTRACT, BLOCK)
        self.snapshot_calls += 1
        result = self.second_snapshot if self.snapshot_calls > 1 and self.second_snapshot is not None else self.snap
        return self._copy("registry_snapshot", result, account, block)

    def destination_domain(self, account, block):
        assert (account, block) == (CONTRACT, BLOCK)
        return self._copy("destination_domain", self.domain, account, block)

    def unbound_active_holders(self, account, block):
        assert (account, block) == (CONTRACT, BLOCK)
        return self._copy("unbound_active_holders", self.unbound, account, block)


class FreezeObservationTests(unittest.TestCase):
    def observe(self, reader, **override):
        options = dict(
            expected_genesis=GENESIS,
            expected_source_contract=CONTRACT,
            expected_source_code_hash=CODE,
            freeze_tx_hash=TX,
            freeze_block_hash=BLOCK,
        )
        options.update(override)
        return OBS.observe(reader, **options)

    def fails(self, reader, code, **kwargs):
        with self.assertRaises(OBS.FreezeEvidenceError) as err:
            self.observe(reader, **kwargs)
        self.assertEqual(err.exception.code, code)

    def test_consistent_frozen_cutoff_is_still_unverified(self):
        r = self.observe(FakeChain())
        self.assertEqual(r["status"], "FREEZE_OBSERVED_UNAUTHENTICATED")
        self.assertFalse(r["genesis_authenticated"])
        self.assertFalse(r["finality_cryptographically_verified"])
        self.assertFalse(r["finalized_ancestry_verified"])
        self.assertFalse(r["storage_trie_membership_verified"])
        self.assertFalse(r["source_contract_code_authenticated"])
        self.assertFalse(r["signed_extrinsic_authenticated"])
        self.assertFalse(r["freeze_is_irreversible_on_chain"])
        self.assertFalse(r["can_activate"])
        self.assertFalse(r["can_claim"])
        self.assertEqual(r["observed"]["snapshot"]["total_supply"], 100)

    def test_repeatable_diagnostic_not_cryptographic_proof(self):
        a = self.observe(FakeChain())
        b = self.observe(FakeChain())
        self.assertEqual(a, b)
        self.assertEqual(len(a["diagnostic_sha256_not_proof"]), 64)
        self.assertNotIn("merkle_root", a)

    def test_caller_pinned_wrong_genesis_blocks(self):
        self.fails(FakeChain(), "GENESIS_MISMATCH", expected_genesis=h256(120))

    def test_wrong_source_contract_receipt_blocks(self):
        f = FakeChain()
        f.receipt["source_contract"] = h256(99)
        self.fails(f, "WRONG_SOURCE_CONTRACT")

    def test_wrong_event_contract_blocks(self):
        f = FakeChain()
        f.freeze_event["source_contract"] = h256(99)
        self.fails(f, "WRONG_EVENT_CONTRACT")

    def test_wrong_receipt_block_blocks(self):
        f = FakeChain()
        f.receipt["block_hash"] = h256(99)
        self.fails(f, "FREEZE_BLOCK_MISMATCH")

    def test_wrong_receipt_transaction_blocks(self):
        f = FakeChain()
        f.receipt["tx_hash"] = h256(99)
        self.fails(f, "FREEZE_TRANSACTION_MISMATCH")

    def test_failed_freeze_dispatch_blocks(self):
        f = FakeChain()
        f.receipt["dispatch_success"] = False
        self.fails(f, "FREEZE_EXTRINSIC_FAILED")

    def test_truthy_string_not_success(self):
        f = FakeChain()
        f.receipt["dispatch_success"] = "true"
        self.fails(f, "FREEZE_EXTRINSIC_FAILED")

    def test_missing_event_blocks(self):
        f = FakeChain()
        f.receipt["events"] = []
        self.fails(f, "MISSING_OR_DUPLICATE_FREEZE_EVENT")

    def test_duplicate_event_blocks(self):
        f = FakeChain()
        f.receipt["events"].append(copy.deepcopy(f.freeze_event))
        self.fails(f, "MISSING_OR_DUPLICATE_FREEZE_EVENT")

    def test_wrong_event_type_blocks(self):
        f = FakeChain()
        f.freeze_event["type"] = "Transferred"
        self.fails(f, "WRONG_EVENT_TYPE")

    def test_wrong_signer_blocks(self):
        f = FakeChain()
        f.receipt["signer"] = h256(91)
        self.fails(f, "UNAUTHORIZED_FREEZE_SIGNER")

    def test_wrong_event_actor_blocks(self):
        f = FakeChain()
        f.freeze_event["by"] = h256(91)
        self.fails(f, "EVENT_SIGNER_MISMATCH")

    def test_nonfinal_cutoff_blocks(self):
        f = FakeChain()
        f.headers[FINAL]["number"] = NUMBER - 1
        self.fails(f, "FREEZE_BLOCK_NOT_FINALIZED")

    def test_orphaned_or_reorged_block_blocks(self):
        f = FakeChain()
        f.canonical_block = h256(91)
        self.fails(f, "ORPHANED_OR_REORGED_FREEZE_BLOCK")

    def test_reorg_observed_midscan_blocks(self):
        f = FakeChain()
        f.second_canonical_block = h256(91)
        self.fails(f, "REORG_DURING_EVIDENCE_SCAN")

    def test_cutoff_event_number_mismatch(self):
        f = FakeChain()
        f.freeze_event["source_block"] = NUMBER + 1
        self.fails(f, "CUTOFF_BLOCK_MISMATCH")

    def test_wrong_source_code_hash(self):
        f = FakeChain()
        f.code_hash = h256(91)
        self.fails(f, "SOURCE_CODE_HASH_MISMATCH")

    def test_missing_freeze_marker(self):
        f = FakeChain()
        f.marker = None
        self.fails(f, "MISSING_FREEZE_MARKER")

    def test_wrong_freeze_marker_block(self):
        f = FakeChain()
        f.marker = (NUMBER - 1, 100, 3, 2, 0)
        self.fails(f, "FREEZE_MARKER_MISMATCH")

    def test_wrong_marker_supply(self):
        f = FakeChain()
        f.marker = (NUMBER, 99, 3, 2, 0)
        self.fails(f, "FREEZE_MARKER_MISMATCH")

    def test_postfreeze_unbound_holder_blocks(self):
        f = FakeChain()
        f.unbound = 1
        self.fails(f, "UNBOUND_FUNDED_HOLDERS")

    def test_unbound_event_count_mismatch(self):
        f = FakeChain()
        f.freeze_event["unbound_active_holders"] = 1
        self.fails(f, "FREEZE_EVENT_STATE_MISMATCH")

    def test_unfrozen_snapshot_blocks(self):
        f = FakeChain()
        f.snap["frozen"] = False
        self.fails(f, "SOURCE_NOT_FROZEN")

    def test_supply_event_mismatch_blocks(self):
        f = FakeChain()
        f.freeze_event["total_supply"] = 101
        self.fails(f, "FREEZE_EVENT_STATE_MISMATCH")

    def test_holder_count_mismatch_blocks(self):
        f = FakeChain()
        f.freeze_event["holder_count"] = 9
        self.fails(f, "FREEZE_EVENT_STATE_MISMATCH")

    def test_wrong_migration_domain_blocks(self):
        f = FakeChain()
        f.freeze_event["migration_id"] = h256(99)
        self.fails(f, "FREEZE_EVENT_STATE_MISMATCH")

    def test_wrong_evm_contract_blocks(self):
        f = FakeChain()
        f.freeze_event["destination_contract"] = "0x" + "f" * 40
        self.fails(f, "FREEZE_EVENT_STATE_MISMATCH")

    def test_wrong_destination_chain_id_blocks(self):
        f = FakeChain()
        f.freeze_event["destination_chain_id"] = 1
        self.fails(f, "FREEZE_EVENT_STATE_MISMATCH")

    def test_bool_destination_chain_id_is_not_integer(self):
        f = FakeChain()
        f.freeze_event["destination_chain_id"] = True
        self.fails(f, "INVALID_EVENT_CHAIN_ID")

    def test_snapshot_mutation_during_scan_blocks(self):
        f = FakeChain()
        f.second_snapshot = dict(f.snap, total_supply=99)
        self.fails(f, "CHANGED_FROZEN_SNAPSHOT")

    def test_rpc_exception_cannot_pass(self):
        f = FakeChain()
        def broken(_):
            raise ConnectionError("node offline")
        f.header_at = broken
        self.fails(f, "SOURCE_RPC_UNAVAILABLE")

    def test_noncanonical_extra_receipt_metadata_blocks(self):
        f = FakeChain()
        f.receipt["verified"] = True
        self.fails(f, "INVALID_RECEIPT")

    def test_invented_certification_cannot_upgrade_status(self):
        f = FakeChain()
        f.genesis = GENESIS
        f.receipt["dispatch_success"] = True
        result = self.observe(f)
        self.assertFalse(result["can_activate"])
        self.assertFalse(result["finality_cryptographically_verified"])
        self.assertFalse(result["freeze_is_irreversible_on_chain"])

    def test_all_storage_reads_share_exact_cutoff_block(self):
        f = FakeChain()
        self.observe(f)
        for name, *args in f.calls:
            if name in (
                "contract_code_hash", "contract_owner", "freeze_marker",
                "registry_snapshot", "destination_domain", "unbound_active_holders",
            ):
                self.assertEqual(args[-1], BLOCK)


if __name__ == "__main__":
    unittest.main()
