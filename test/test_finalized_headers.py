"""Adversarial finalized-header RPC fixtures. Synthetic headers are NOT proofs."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.finality import substrate as F


def h(n: int) -> str:
    return f"0x{n:064x}"


GENESIS = h(100)
CHECKPOINT = h(104)
FINALIZED = h(106)


class FakeRpc:
    def __init__(self):
        self.calls: list[tuple[str, list]] = []
        self.by_height = {n: h(100+n) for n in range(7)}
        self.headers = {
            h(100+n): {
                "number": hex(n),
                "parentHash": h(100+n-1) if n else h(0),
                "stateRoot": h(200+n),
                "extrinsicsRoot": h(300+n),
                "digest": {"logs": ["0x"]},
            }
            for n in range(7)
        }
        self.finalized = FINALIZED
        self.runtime = {
            "specName": "synthetic-substrate",
            "implName": "synthetic-node",
            "specVersion": 25,
            "implVersion": 1,
            "transactionVersion": 3,
        }
        self.genesis_flip_after_first = False
        self.finalized_flip_after_first = False
        self.changed_checkpoint_on_second = False
        self.canonical_reorg_after_first = False
        self.genesis_calls = 0
        self.finality_calls = 0
        self.checkpoint_calls = 0
        self.checkpoint_height_calls = 0
        self.raise_method = None
        self.storage = {"0x01": "0x1234", "0x02": None}

    def call(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if self.raise_method == method:
            raise ConnectionError("synthetic unavailable")
        if method == "chain_getBlockHash":
            n = params[0]
            if n == 0:
                self.genesis_calls += 1
                if self.genesis_flip_after_first and self.genesis_calls >= 2:
                    return h(999)
            if n == 4:
                self.checkpoint_height_calls += 1
                if self.canonical_reorg_after_first and self.checkpoint_height_calls >= 2:
                    return h(999)
            return self.by_height.get(n)
        if method == "chain_getFinalizedHead":
            self.finality_calls += 1
            if self.finalized_flip_after_first and self.finality_calls >= 2:
                return h(105)
            return self.finalized
        if method == "chain_getHeader":
            block = params[0]
            if block == CHECKPOINT:
                self.checkpoint_calls += 1
                if self.changed_checkpoint_on_second and self.checkpoint_calls >= 2:
                    out = copy.deepcopy(self.headers[block])
                    out["stateRoot"] = h(999)
                    return out
            return copy.deepcopy(self.headers.get(block))
        if method == "state_getRuntimeVersion":
            assert len(params) == 1 and params[0] in self.headers, params
            return copy.deepcopy(self.runtime)
        if method == "state_getStorage":
            self.assert_pinned(params[1:])
            return self.storage.get(params[0])
        raise AssertionError("RPC should not call " + method)

    @staticmethod
    def assert_pinned(params):
        assert params == [CHECKPOINT], params


class FinalityObservationTests(unittest.TestCase):
    def collect(self, rpc=None, **kwargs):
        params = dict(expected_genesis_hash=GENESIS, pinned_block_hash=CHECKPOINT, max_finalized_lag=16)
        params.update(kwargs)
        return F.observe(rpc or FakeRpc(), **params)

    def failed(self, rpc, code, **kwargs):
        with self.assertRaises(F.FinalityObservationError) as error:
            self.collect(rpc, **kwargs)
        self.assertEqual(error.exception.code, code)

    def test_observation_never_authenticates_finality_or_storage(self):
        r = FakeRpc()
        report = self.collect(r)
        self.assertEqual(report["status"], F.REPORT_STATUS)
        self.assertEqual(report["observed"]["snapshot_block_hash"], CHECKPOINT)
        self.assertEqual(report["observed"]["snapshot_state_root"], h(204))
        self.assertEqual(report["observed"]["reported_finalized_number"], 6)
        self.assertEqual(report["observed"]["ancestry_links_examined"], 2)
        for k in ("genesis_authenticated", "header_hash_recomputed",
                  "consensus_finality_cryptographically_verified",
                  "finalized_ancestry_cryptographically_verified",
                  "storage_trie_membership_verified", "can_claim", "can_activate"):
            self.assertIs(report[k], False)
        self.assertTrue(report["finalized_ancestry_observed"])
        self.assertEqual(len(report["diagnostic_sha256_not_proof"]), 64)
        self.assertEqual(report, self.collect(FakeRpc()))

    def test_wrong_genesis_rejected(self):
        self.failed(FakeRpc(), "WRONG_GENESIS", expected_genesis_hash=h(999))

    def test_wrong_expected_checkpoint_not_accepted_as_canonical(self):
        self.failed(FakeRpc(), "MISSING_HEADER", pinned_block_hash=h(999))

    def test_unfinalized_future_checkpoint_rejected(self):
        r = FakeRpc()
        r.headers[h(107)] = {
            "number": "0x7", "parentHash": FINALIZED,
            "stateRoot": h(207), "extrinsicsRoot": h(307), "digest": {"logs": []},
        }
        self.failed(r, "UNFINALIZED_CHECKPOINT", pinned_block_hash=h(107))

    def test_stale_checkpoint_rejected_by_configured_height_lag(self):
        self.failed(FakeRpc(), "STALE_CHECKPOINT", max_finalized_lag=1)

    def test_staleness_is_height_based_and_configured_policy_is_bounded(self):
        self.failed(FakeRpc(), "INVALID_FINALITY_LAG_POLICY", max_finalized_lag=99999)
        self.failed(FakeRpc(), "INVALID_FINALITY_LAG_POLICY", max_finalized_lag=True)

    def test_wrong_finalized_head_height_hash_rejected(self):
        r = FakeRpc()
        r.by_height[6] = h(500)
        self.failed(r, "INCONSISTENT_FINALIZED_HEAD")

    def test_noncanonical_fork_at_intermediate_header_rejected(self):
        r = FakeRpc()
        r.by_height[5] = h(999)
        self.failed(r, "ORPHANED_OR_FORKED_CHECKPOINT")

    def test_checkpoint_reorg_at_initial_observation_rejected(self):
        r = FakeRpc()
        r.by_height[4] = h(999)
        self.failed(r, "ORPHANED_OR_FORKED_CHECKPOINT")

    def test_snapshot_reorg_mid_scan_rejected(self):
        r = FakeRpc()
        r.canonical_reorg_after_first = True
        self.failed(r, "CHECKPOINT_REORG_DURING_SCAN")

    def test_changed_reported_finality_during_observation_rejected(self):
        r = FakeRpc()
        r.finalized_flip_after_first = True
        self.failed(r, "FINALIZED_HEAD_CHANGED_DURING_SCAN")

    def test_changed_genesis_during_scan_rejected(self):
        r = FakeRpc()
        r.genesis_flip_after_first = True
        self.failed(r, "GENESIS_CHANGED_DURING_SCAN")

    def test_changed_snapshot_state_root_rejected(self):
        r = FakeRpc()
        r.changed_checkpoint_on_second = True
        self.failed(r, "CONFLICTING_CHECKPOINT_HEADER")

    def test_parent_gap_breaks_observed_finalized_ancestry(self):
        r = FakeRpc()
        r.headers[h(105)]["number"] = "0x3"
        self.failed(r, "BROKEN_ANCESTRY_HEIGHT")

    def test_unknown_parent_fails(self):
        r = FakeRpc()
        r.headers[FINALIZED]["parentHash"] = h(999)
        self.failed(r, "MISSING_HEADER")

    def test_invalid_header_state_root_fails(self):
        r = FakeRpc()
        r.headers[CHECKPOINT]["stateRoot"] = "0x01"
        self.failed(r, "INVALID_STATE_ROOT")

    def test_invalid_header_extra_digest_fails(self):
        r = FakeRpc()
        r.headers[CHECKPOINT]["digest"] = {"logs": ["not scale"]}
        self.failed(r, "INVALID_HEADER_DIGEST")

    def test_noncanonical_height_fails(self):
        r = FakeRpc()
        r.headers[CHECKPOINT]["number"] = "0x04"
        self.failed(r, "INVALID_HEADER_NUMBER")

    def test_malformed_runtime_spec_version_fails(self):
        r = FakeRpc()
        r.runtime["specVersion"] = True
        self.failed(r, "INVALID_RUNTIME_VERSION")

    def test_missing_runtime_version_fails(self):
        r = FakeRpc()
        r.runtime = None
        self.failed(r, "MISSING_RUNTIME_VERSION")

    def test_rpc_errors_fail_closed(self):
        r = FakeRpc()
        r.raise_method = "chain_getHeader"
        self.failed(r, "RPC_READ_FAILED")

    def test_all_read_calls_are_strictly_read_only(self):
        r = FakeRpc()
        self.collect(r)
        self.assertTrue(all(method in F.READ_ONLY_METHODS for method, _ in r.calls))
        self.assertFalse(any("submit" in method.lower() for method, _ in r.calls))
        self.assertIn(("state_getRuntimeVersion", [CHECKPOINT]), r.calls)

    def test_pin_storage_to_same_checkpoint(self):
        r = FakeRpc()
        obs = self.collect(r)
        pinned = F.PinnedStateReader(r, obs)
        self.assertEqual(pinned.storage("0x01"), "0x1234")
        self.assertIsNone(pinned.storage("0x02"))
        self.assertEqual(pinned.keys_read, ["0x01", "0x02"])
        self.assertEqual(pinned.block_hash, CHECKPOINT)
        self.assertEqual(pinned.state_root, h(204))
        calls = [params for method, params in r.calls if method == "state_getStorage"]
        self.assertEqual(calls, [["0x01", CHECKPOINT], ["0x02", CHECKPOINT]])

    def test_storage_requires_byte_key(self):
        pinned = F.PinnedStateReader(FakeRpc(), self.collect())
        for key in ("0x", "0x1", "not-key", "0X01"):
            with self.subTest(key=key), self.assertRaises(F.FinalityObservationError):
                pinned.storage(key)

    def test_malformed_storage_value_fails(self):
        r = FakeRpc()
        pinned = F.PinnedStateReader(r, self.collect(r))
        r.storage["0x01"] = "0xhello"
        with self.assertRaises(F.FinalityObservationError) as error:
            pinned.storage("0x01")
        self.assertEqual(error.exception.code, "INVALID_STORAGE_VALUE")

    def test_pinned_reader_must_reject_fake_activation_report(self):
        obs = self.collect()
        obs["can_activate"] = True
        with self.assertRaises(F.FinalityObservationError) as error:
            F.PinnedStateReader(FakeRpc(), obs)
        self.assertEqual(error.exception.code, "UNEXPECTED_PROOF_CLAIM")

    def test_user_cannot_pass_unauthorized_rpc_method(self):
        r = FakeRpc()
        with self.assertRaises(F.FinalityObservationError) as error:
            F._read(r, "author_submitExtrinsic", ["0x1234"])
        self.assertEqual(error.exception.code, "UNAUTHORIZED_RPC_METHOD")
        self.assertEqual(r.calls, [])

    def test_checkpoint_equal_to_reported_finalized_head(self):
        r = FakeRpc()
        obs = self.collect(r, pinned_block_hash=FINALIZED, max_finalized_lag=0)
        self.assertEqual(obs["observed"]["lag_in_blocks"], 0)

    def test_contradictory_parent_not_finalized_ancestor(self):
        r = FakeRpc()
        fork = h(500)
        r.headers[fork] = {
            "number": "0x4", "parentHash": h(103),
            "stateRoot": h(501), "extrinsicsRoot": h(502), "digest": {"logs": []},
        }
        r.headers[h(105)]["parentHash"] = fork
        r.by_height[4] = fork
        self.failed(r, "NOT_FINALIZED_ANCESTOR")

    def test_canonical_hashes_during_traversal_are_bounded(self):
        r = FakeRpc()
        self.collect(r)
        self.assertEqual(len([m for m, _ in r.calls if m == "chain_getHeader"]), 5)
        # Initial genesis, finalized height, three walked heights,
        # repeated genesis and final checkpoint consistency read.
        self.assertEqual(len([m for m, _ in r.calls if m == "chain_getBlockHash"]), 7)


if __name__ == "__main__":
    unittest.main()
