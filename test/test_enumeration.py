"""Adversarial tests of the independent, unauthenticated enumeration auditor.

Fixtures emulate pinned read-only ink! views, not a trusted Portaldot node.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "metorah_enumeration", ROOT / "tools" / "enumeration" / "scan.py"
)
SCAN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SCAN
SPEC.loader.exec_module(SCAN)

BLOCK = "0x" + "a" * 64


def acct(number: int) -> str:
    return f"0x{number:064x}"


class MockLedger:
    """Untrusted reader, with explicit injectable inconsistencies."""

    def __init__(self, balances: list[int]):
        self.entries = [(acct(i + 1), balance) for i, balance in enumerate(balances)]
        self.balance_map = dict(self.entries)
        self.index_map = {owner: i for i, (owner, _) in enumerate(self.entries)}
        self.header_calls = 0
        self.calls = []
        self.header_override = {}
        self.second_header_override = {}
        self.page_transform = None
        self.at_override = {}
        self.index_override = {}
        self.balance_override = {}

    def pin(self, block):
        self.calls.append(block)
        if block != BLOCK:
            raise RuntimeError("non-pinned read")

    def registry_snapshot(self, at_block):
        self.pin(at_block)
        self.header_calls += 1
        result = {
            "frozen": True,
            "asset_id": acct(7_000),
            "decimals": 12,
            "max_supply": SCAN.UINT128_MAX,
            "total_supply": sum(b for _, b in self.entries),
            "holder_count": len(self.entries),
            "active_holder_count": sum(b > 0 for _, b in self.entries),
        }
        result.update(self.header_override)
        if self.header_calls >= 2:
            result.update(self.second_header_override)
        return result

    def holder_page_indexed(self, start, limit, at_block):
        self.pin(at_block)
        page = [(index, *self.entries[index]) for index in
                range(start, min(start + limit, len(self.entries)))]
        if self.page_transform:
            return self.page_transform(start, limit, page)
        return page

    def holder_at(self, index, at_block):
        self.pin(at_block)
        if index in self.at_override:
            return self.at_override[index]
        return self.entries[index] if 0 <= index < len(self.entries) else None

    def index_of(self, account, at_block):
        self.pin(at_block)
        return self.index_override.get(account, self.index_map.get(account))

    def balance_of(self, account, at_block):
        self.pin(at_block)
        return self.balance_override.get(account, self.balance_map.get(account, 0))


class EnumerationTests(unittest.TestCase):
    def assert_fails(self, reader, error_code, **kwargs):
        with self.assertRaises(SCAN.ScanError) as err:
            SCAN.scan(reader, pinned_block_hash=BLOCK, **kwargs)
        self.assertEqual(err.exception.code, error_code)

    def assert_not_authenticated(self, result):
        self.assertEqual(result["status"], "RECONCILED_UNAUTHENTICATED")
        self.assertFalse(result["source_chain_authenticated"])
        self.assertFalse(result["holder_set_cryptographically_complete"])
        self.assertFalse(result["freeze_finality_verified"])
        self.assertFalse(result["destination_bindings_verified"])
        self.assertFalse(result["can_activate"])
        self.assertFalse(result["can_claim"])

    def test_empty_source_is_reconciled_not_authenticated(self):
        m = MockLedger([])
        r = SCAN.scan(m, pinned_block_hash=BLOCK)
        self.assert_not_authenticated(r)
        self.assertEqual(r["total_supply_units"], "0")
        self.assertEqual(r["historical_holder_count"], 0)
        self.assertEqual(r["positive_holders"], [])

    def test_historical_tombstones_preserved_but_not_allocated(self):
        m = MockLedger([60, 0, 40, 0])
        r = SCAN.scan(m, pinned_block_hash=BLOCK, page_size=2)
        self.assertEqual([h["source_index"] for h in r["positive_holders"]], [0, 2])
        self.assertEqual(r["zero_balance_tombstones"], 2)
        self.assertEqual(r["active_holder_count"], 2)
        self.assertEqual(r["total_supply_units"], "100")
        self.assert_not_authenticated(r)
        self.assertTrue(all(c == BLOCK for c in m.calls))

    def test_large_population_with_nonmultiple_page_size(self):
        n = 4_097
        balances = [0 if i % 17 == 0 else (i % 113) + 1 for i in range(n)]
        m = MockLedger(balances)
        r = SCAN.scan(m, pinned_block_hash=BLOCK, page_size=64, max_holders=5_000)
        self.assertEqual(r["historical_holder_count"], n)
        self.assertEqual(len(r["positive_holders"]), sum(b > 0 for b in balances))
        self.assertEqual(int(r["total_supply_units"]), sum(balances))
        self.assertEqual(r["positive_holders"][-1]["source_index"], n - 1)
        self.assert_not_authenticated(r)

    def test_one_entry_pages_reconcile(self):
        m = MockLedger([2, 3, 0, 5])
        self.assertEqual(SCAN.scan(m, pinned_block_hash=BLOCK, page_size=1)["total_supply_units"], "10")

    def test_unfrozen_ledger_denied(self):
        m = MockLedger([10])
        m.header_override["frozen"] = False
        self.assert_fails(m, "SOURCE_NOT_FROZEN")

    def test_missing_index_page_denied(self):
        m = MockLedger([10, 20, 30])
        m.page_transform = lambda s, n, page: page[:-1]
        self.assert_fails(m, "INCOMPLETE_REGISTRY_PAGE")

    def test_wrong_index_page_denied(self):
        m = MockLedger([10, 20])
        m.page_transform = lambda s, n, p: [(99, *p[0][1:])] + p[1:]
        self.assert_fails(m, "NONCONTIGUOUS_REGISTRY_INDEX")

    def test_duplicate_account_page_denied(self):
        m = MockLedger([10, 20])
        m.page_transform = lambda s, n, p: [p[0], (1, p[0][1], 20)]
        self.assert_fails(m, "DUPLICATE_HOLDER")

    def test_missing_holder_at_denied(self):
        m = MockLedger([10, 20])
        m.at_override[0] = None
        self.assert_fails(m, "MISSING_HOLDER_AT")

    def test_contradictory_holder_at_denied(self):
        m = MockLedger([10, 20])
        m.at_override[0] = (acct(1), 11)
        self.assert_fails(m, "HOLDER_AT_DISAGREEMENT")

    def test_wrong_index_of_denied(self):
        m = MockLedger([10, 20])
        m.index_override[acct(2)] = 0
        self.assert_fails(m, "REVERSE_INDEX_DISAGREEMENT")

    def test_wrong_balance_of_denied(self):
        m = MockLedger([10, 20])
        m.balance_override[acct(1)] = 11
        self.assert_fails(m, "BALANCE_OF_DISAGREEMENT")

    def test_wrong_total_supply_denied(self):
        m = MockLedger([10, 20])
        m.header_override["total_supply"] = 31
        self.assert_fails(m, "TOTAL_SUPPLY_MISMATCH")

    def test_wrong_active_count_denied(self):
        m = MockLedger([0, 20])
        m.header_override["active_holder_count"] = 2
        self.assert_fails(m, "ACTIVE_HOLDER_COUNT_MISMATCH")

    def test_negative_and_boolean_amounts_denied(self):
        for bad in [-1, True, "12"]:
            m = MockLedger([10, 20])
            m.page_transform = lambda s, n, p: [(0, acct(1), bad), p[1]]
            with self.subTest(bad=bad):
                self.assert_fails(m, "INVALID_HOLDER_AMOUNT")

    def test_u128_aggregate_overflow_denied(self):
        m = MockLedger([SCAN.UINT128_MAX, 1])
        m.header_override["total_supply"] = SCAN.UINT128_MAX
        self.assert_fails(m, "AGGREGATE_OVERFLOW")

    def test_malformed_account_denied(self):
        m = MockLedger([1])
        m.page_transform = lambda s, n, p: [(0, "alice", 1)]
        self.assert_fails(m, "INVALID_SOURCE_ACCOUNT")

    def test_zero_source_account_denied(self):
        m = MockLedger([1])
        m.page_transform = lambda s, n, p: [(0, "0x" + "0" * 64, 1)]
        self.assert_fails(m, "ZERO_SOURCE_ACCOUNT")

    def test_mutation_between_header_checks_denied(self):
        m = MockLedger([10, 20])
        m.second_header_override["total_supply"] = 29
        self.assert_fails(m, "SNAPSHOT_CHANGED_DURING_SCAN")

    def test_population_cap_denied_before_enumeration(self):
        m = MockLedger([1] * 101)
        self.assert_fails(m, "HOLDER_POPULATION_OVER_LIMIT", max_holders=100)
        self.assertEqual(m.calls, [BLOCK])

    def test_bad_page_sizes_denied(self):
        for size in (0, 65, True, -1, 3.5):
            with self.subTest(size=size):
                self.assert_fails(MockLedger([1]), "INVALID_PAGE_SIZE", page_size=size)

    def test_bad_block_reference_denied_before_any_read(self):
        m = MockLedger([1])
        with self.assertRaisesRegex(SCAN.ScanError, "INVALID_BLOCK_REFERENCE"):
            SCAN.scan(m, pinned_block_hash="fake")
        self.assertEqual(m.calls, [])

    def test_missing_or_wrong_header_fields_denied(self):
        m = MockLedger([1])
        m.header_override["verified_chain"] = True
        self.assert_fails(m, "INVALID_REGISTRY_HEADER")

    def test_missing_supplied_frozen_flag_denied(self):
        m = MockLedger([1])
        m.header_override["frozen"] = 1
        self.assert_fails(m, "SOURCE_NOT_FROZEN")

    def test_boolean_holder_count_denied(self):
        m = MockLedger([1])
        m.header_override["holder_count"] = True
        self.assert_fails(m, "INVALID_HOLDER_COUNT")

    def test_malformed_page_record_denied(self):
        m = MockLedger([1])
        m.page_transform = lambda s, n, p: [(0, acct(1))]
        self.assert_fails(m, "MALFORMED_REGISTRY_RECORD")

    def test_reader_failure_is_never_reported_as_valid(self):
        m = MockLedger([1])
        def failure(s, n, p):
            raise RuntimeError("RPC unavailable")
        m.page_transform = failure
        self.assert_fails(m, "SOURCE_READ_FAILED")

    def test_deterministic_diagnostic_hash_not_protocol_merkle(self):
        a = SCAN.scan(MockLedger([1, 0, 2]), pinned_block_hash=BLOCK)
        b = SCAN.scan(MockLedger([1, 0, 2]), pinned_block_hash=BLOCK)
        self.assertEqual(a, b)
        self.assertEqual(len(a["diagnostic_sha256_not_merkle"]), 64)
        self.assertNotIn("merkle_root", a)
        json.dumps(a)
        self.assert_not_authenticated(a)

    def test_consistent_dishonest_source_cannot_be_called_verified(self):
        # A dishonest source can omit a third holder while consistently
        # fabricating all indexed pages, counters and balances. No ordinary
        # getter cross-check alone establishes chain-authenticated completeness.
        dishonest = MockLedger([10, 20])
        result = SCAN.scan(dishonest, pinned_block_hash=BLOCK)
        self.assertEqual(result["total_supply_units"], "30")
        self.assert_not_authenticated(result)


if __name__ == "__main__":
    unittest.main()
