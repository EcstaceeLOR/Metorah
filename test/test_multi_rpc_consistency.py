"""Deterministic multi-RPC split-brain / outage / corruption / resume chaos tests.

All blockchain responses are SYNTHETIC and UNAUTHENTICATED; no network, funds
or user keys. A matching RPC quorum is not a cryptographic finality proof.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.finality.quorum import (
    MultiRPC, Provider, QuorumError, ResumableAcquisition, STATUS,
)


def h(n: int) -> str:
    return f"0x{n:064x}"


GENESIS = h(100)
CHECKPOINT = h(104)


class Replica:
    def __init__(self):
        self.by_height = {n: h(100+n) for n in range(7)}
        self.headers = {
            h(100+n): {
                "number": hex(n),
                "parentHash": h(100+n-1) if n else h(0),
                "stateRoot": h(200+n),
                "extrinsicsRoot": h(300+n),
                "digest": {"logs": ["0x"]},
            } for n in range(7)
        }
        self.finalized = h(106)
        self.runtime = {
            "specName": "synthetic-source", "implName": "synthetic-node",
            "specVersion": 25, "implVersion": 1, "transactionVersion": 3,
        }
        self.metadata = "0x" + "ab" * 256
        self.values = {"0x01": "0x1234", "0x02": None, "0x03": "0x5678", "0x04": "0xabcd"}
        self.calls = []
        self.unavailable_methods = set()
        self.fail_storage_keys = set()
        self.root_changes_after_storage = False
        self.canonical_fork_after_storage = False
        self.finality_flips_during_scan = False
        self.finality_calls = 0
        self.storage_calls = 0

    def call(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if method in self.unavailable_methods:
            raise ConnectionError("synthetic RPC timeout")
        if method == "chain_getBlockHash":
            return self.by_height.get(params[0])
        if method == "chain_getFinalizedHead":
            self.finality_calls += 1
            if self.finality_flips_during_scan and self.finality_calls >= 2:
                return h(105)
            return self.finalized
        if method == "chain_getHeader":
            return copy.deepcopy(self.headers.get(params[0]))
        if method == "state_getRuntimeVersion":
            assert params == [CHECKPOINT]
            return copy.deepcopy(self.runtime)
        if method == "state_getMetadata":
            assert params == [CHECKPOINT]
            return self.metadata
        if method == "state_getStorage":
            assert params[1] == CHECKPOINT
            if params[0] in self.fail_storage_keys:
                raise ConnectionError("synthetic storage endpoint failed")
            self.storage_calls += 1
            v = self.values.get(params[0])
            if self.root_changes_after_storage:
                self.headers[CHECKPOINT]["stateRoot"] = h(999)
            if self.canonical_fork_after_storage:
                self.by_height[4] = h(999)
            return v
        raise AssertionError("unexpected RPC method")


def sources():
    rs = [Replica(), Replica(), Replica()]
    providers = [
        Provider("rpc-" + str(i), "operator-" + str(i), r)
        for i, r in enumerate(rs, start=1)
    ]
    return rs, providers


def session(rs=None, providers=None, **kwargs):
    if providers is None:
        rs, providers = sources()
    return MultiRPC(
        providers, expected_genesis_hash=GENESIS,
        pinned_block_hash=CHECKPOINT, **kwargs,
    )


class MultiRPCChaosTests(unittest.TestCase):
    def setUp(self):
        self.rs, self.providers = sources()

    def make(self, **kwargs):
        return session(providers=self.providers, **kwargs)

    def fails(self, code, task):
        with self.assertRaises(QuorumError) as raised:
            task()
        self.assertEqual(raised.exception.code, code)

    def test_quorum_reports_same_pinned_checkpoint_metadata_and_checksum(self):
        q = self.make()
        healthy, failures = q.observe_quorum()
        self.assertEqual(sorted(healthy), ["rpc-1", "rpc-2", "rpc-3"])
        self.assertEqual(failures, [])
        self.assertEqual(q.source_metadata["snapshot_block_hash"], CHECKPOINT)
        self.assertEqual(q.source_metadata["snapshot_state_root"], h(204))
        self.assertEqual(q.source_metadata["runtime_metadata_size"], 256)
        self.assertEqual(len(q.source_metadata["runtime_metadata_sha256"]), 64)
        self.assertEqual(q.metadata_checksum, self.make().metadata_checksum)
        for node in self.rs:
            self.assertIn(("state_getMetadata", [CHECKPOINT]), node.calls)

    def test_single_timeout_is_ignored_only_with_two_independent_agreeing_peers(self):
        self.rs[2].unavailable_methods.add("chain_getHeader")
        q = self.make()
        rows = q.read_batch(["0x01", "0x02"])
        self.assertEqual(rows["agreeing_providers"], ["rpc-1", "rpc-2"])
        self.assertIn("rpc-3", rows["unavailable_providers"])
        self.assertEqual(rows["records"], [
            {"key": "0x01", "value": "0x1234"}, {"key": "0x02", "value": None},
        ])

    def test_single_storage_timeout_discards_that_peers_entire_batch(self):
        self.rs[2].fail_storage_keys.add("0x02")
        result = self.make().read_batch(["0x01", "0x02"])
        self.assertEqual(result["agreeing_providers"], ["rpc-1", "rpc-2"])

    def test_two_unavailable_nodes_cannot_vote_as_single_remaining_node(self):
        self.rs[1].unavailable_methods.add("chain_getHeader")
        self.rs[2].unavailable_methods.add("chain_getHeader")
        self.fails("INSUFFICIENT_INDEPENDENT_RPC_QUORUM",
                   lambda: self.make().observe_quorum())

    def test_semantic_wrong_genesis_is_fatal_even_if_two_peers_match(self):
        self.rs[2].by_height[0] = h(999)
        self.fails("RPC_SEMANTIC_FAILURE_WRONG_GENESIS",
                   lambda: self.make().observe_quorum())

    def test_malicious_root_fails_even_with_two_good_nodes(self):
        self.rs[2].headers[CHECKPOINT]["stateRoot"] = h(999)
        self.fails("RPC_CHECKPOINT_SPLIT_BRAIN",
                   lambda: self.make().observe_quorum())

    def test_malicious_metadata_bytes_fail_without_fallback_to_majority(self):
        self.rs[2].metadata = "0x" + "bc" * 256
        self.fails("RPC_CHECKPOINT_SPLIT_BRAIN",
                   lambda: self.make().observe_quorum())

    def test_malicious_runtime_spec_version_fails(self):
        self.rs[1].runtime["specVersion"] += 1
        self.fails("RPC_CHECKPOINT_SPLIT_BRAIN",
                   lambda: self.make().observe_quorum())

    def test_malformed_runtime_metadata_fails(self):
        self.rs[2].metadata = "0xabc"
        self.fails("INVALID_RUNTIME_METADATA_BYTES",
                   lambda: self.make().observe_quorum())

    def test_symmetric_finalized_height_with_different_hash_is_split_brain(self):
        other = h(999)
        self.rs[2].headers[other] = copy.deepcopy(self.rs[2].headers[h(106)])
        self.rs[2].by_height[6] = other
        self.rs[2].finalized = other
        self.fails("SPLIT_BRAIN_FINALIZED_HEAD",
                   lambda: self.make().observe_quorum())

    def test_legitimately_one_block_lagged_peer_can_still_verify_pinned_ancestor(self):
        self.rs[2].finalized = h(105)
        q = self.make(max_head_delta=1)
        healthy, _ = q.observe_quorum()
        self.assertEqual(len(healthy), 3)

    def test_lagged_peer_blocks_when_policy_requires_identical_height(self):
        self.rs[2].finalized = h(105)
        self.fails("STALLED_OR_STALE_FINALIZED_HEAD",
                   lambda: self.make(max_head_delta=0).observe_quorum())

    def test_wrong_orphaned_checkpoint_fails_even_when_other_peers_agree(self):
        self.rs[2].by_height[4] = h(999)
        self.fails("RPC_SEMANTIC_FAILURE_ORPHANED_OR_FORKED_CHECKPOINT",
                   lambda: self.make().observe_quorum())

    def test_finalized_head_change_within_single_rpc_observation_fails(self):
        self.rs[2].finality_flips_during_scan = True
        self.fails("RPC_SEMANTIC_FAILURE_FINALIZED_HEAD_CHANGED_DURING_SCAN",
                   lambda: self.make().observe_quorum())

    def test_malicious_storage_value_is_not_overridden_by_majority(self):
        self.rs[2].values["0x02"] = "0xff"
        self.fails("RPC_STORAGE_VALUE_SPLIT_BRAIN",
                   lambda: self.make().read_batch(["0x01", "0x02"]))

    def test_absence_is_distinct_from_empty_present_bytes(self):
        self.rs[2].values["0x02"] = "0x"
        self.fails("RPC_STORAGE_VALUE_SPLIT_BRAIN",
                   lambda: self.make().read_batch(["0x02"]))

    def test_mid_batch_root_change_rejected_and_not_persisted(self):
        self.rs[2].root_changes_after_storage = True
        self.fails("RPC_CHECKPOINT_SPLIT_BRAIN",
                   lambda: self.make().read_batch(["0x01"]))

    def test_mid_batch_canonical_height_reorg_rejected(self):
        self.rs[2].canonical_fork_after_storage = True
        self.fails("RPC_SEMANTIC_FAILURE_ORPHANED_OR_FORKED_CHECKPOINT",
                   lambda: self.make().read_batch(["0x01"]))

    def test_noncanonical_hex_key_rejected(self):
        self.fails("INVALID_CANONICAL_STORAGE_KEY",
                   lambda: self.make().read_batch(["0X01"]))
        self.fails("INVALID_CANONICAL_STORAGE_KEY",
                   lambda: self.make().read_batch(["0x0aB1"]))
        self.fails("INVALID_CANONICAL_STORAGE_KEY",
                   lambda: self.make().read_batch(["0x1"]))

    def test_duplicate_or_wrong_order_keys_rejected(self):
        self.fails("INVALID_BATCH_STORAGE_KEYS",
                   lambda: self.make().read_batch(["0x02", "0x01"]))
        self.fails("INVALID_BATCH_STORAGE_KEYS",
                   lambda: self.make().read_batch(["0x01", "0x01"]))

    def test_malformed_storage_value_is_fatal(self):
        self.rs[2].values["0x01"] = "untrusted"
        self.fails("RPC_STORAGE_FAILURE_INVALID_STORAGE_VALUE",
                   lambda: self.make().read_batch(["0x01"]))

    def test_oversize_storage_value_rejected(self):
        self.rs[2].values["0x01"] = "0x" + "12" * (1_048_576 + 1)
        self.fails("INVALID_STORAGE_VALUE",
                   lambda: self.make().read_batch(["0x01"]))

    def test_mutating_finalized_head_between_batches_is_regression(self):
        q = self.make()
        q.read_batch(["0x01"])
        self.rs[2].finalized = h(105)
        self.fails("FINALIZED_HEAD_REGRESSION",
                   lambda: q.read_batch(["0x02"]))

    def test_duplicate_declared_operator_identity_rejected(self):
        providers = self.providers.copy()
        providers[2] = Provider("rpc-3", "operator-1", self.rs[2])
        self.fails("INVALID_OR_DUPLICATE_PROVIDER_IDENTITY",
                   lambda: session(providers=providers))

    def test_not_enough_configured_operators_rejected(self):
        self.fails("INVALID_PROVIDER_COUNT",
                   lambda: session(providers=self.providers[:2]))

    def test_unreasonable_quorum_or_lag_policy_rejected(self):
        self.fails("INVALID_QUORUM_POLICY",
                   lambda: self.make(min_quorum=1))
        self.fails("INVALID_FINALITY_LAG_POLICY",
                   lambda: self.make(max_finalized_lag=9999))
        self.fails("INVALID_FINALIZED_HEAD_DELTA",
                   lambda: self.make(max_head_delta=-1))

    def test_no_consensus_proof_can_be_asserted_by_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = ResumableAcquisition(
                self.make(), ["0x01", "0x02"], Path(tmp) / "journal.json",
            ).run()
        self.assertEqual(report["status"], STATUS)
        for k in ("genesis_authenticated", "finality_cryptographically_verified",
                  "trie_membership_verified", "operator_independence_verified",
                  "can_activate", "can_claim"):
            self.assertIs(report[k], False)

    def test_complete_acquisition_retries_from_exact_same_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            q = self.make()
            expected = ResumableAcquisition(q, ["0x01", "0x02", "0x03"], path,
                                           batch_size=2).run()
            self.assertEqual(expected["completed_batches"], 2)
            fresh = sources()[1]
            replay = ResumableAcquisition(session(providers=fresh),
                                          ["0x01", "0x02", "0x03"], path,
                                          batch_size=2).run()
            self.assertEqual(expected, replay)

    def test_lost_quorum_mid_acquisition_keeps_only_completed_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = Path(tmp) / "journal.json"
            for peer in self.rs[1:]:
                peer.fail_storage_keys.add("0x03")
            acq = ResumableAcquisition(self.make(), ["0x01", "0x02", "0x03"],
                                       journal, batch_size=2)
            self.fails("INSUFFICIENT_STABLE_RPC_VOTES", acq.run)
            parsed = json.loads(journal.read_text())
            self.assertEqual(parsed["status"], "CHECKPOINT_ACQUISITION_PARTIAL_UNAUTHENTICATED")
            self.assertEqual(len(parsed["batches"]), 1)
            for peer in self.rs[1:]:
                peer.fail_storage_keys.clear()
            finished = ResumableAcquisition(self.make(), ["0x01", "0x02", "0x03"],
                                             journal, batch_size=2).run()
            self.assertEqual(finished["queried_storage_keys"], 3)
            self.assertEqual(finished["completed_batches"], 2)

    def test_resume_with_different_state_root_rejected_before_reading_saved_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            ResumableAcquisition(self.make(), ["0x01"], path).run()
            new_rs, new_sources = sources()
            for peer in new_rs:
                peer.headers[CHECKPOINT]["stateRoot"] = h(230)
            self.fails("JOURNAL_SESSION_OR_DIGEST_MISMATCH",
                       lambda: ResumableAcquisition(session(providers=new_sources),
                                                    ["0x01"], path).run())

    def test_resume_with_different_key_set_or_batch_size_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            ResumableAcquisition(self.make(), ["0x01", "0x02"], path, batch_size=1).run()
            self.fails("JOURNAL_SESSION_OR_DIGEST_MISMATCH",
                       lambda: ResumableAcquisition(self.make(),
                           ["0x01", "0x03"], path, batch_size=1).run())
            self.fails("JOURNAL_SESSION_OR_DIGEST_MISMATCH",
                       lambda: ResumableAcquisition(self.make(),
                           ["0x01", "0x02"], path, batch_size=2).run())

    def test_corrupt_journal_bytes_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            ResumableAcquisition(self.make(), ["0x01"], path).run()
            bad = json.loads(path.read_text())
            bad["batches"][0]["records"][0]["value"] = "0xdead"
            path.write_text(json.dumps(bad))
            self.fails("JOURNAL_SESSION_OR_DIGEST_MISMATCH",
                       lambda: ResumableAcquisition(self.make(), ["0x01"], path).run())

    def test_sophisticated_resigned_diagnostic_journal_still_rechecked_against_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            acq = ResumableAcquisition(self.make(), ["0x01"], path)
            acq.run()
            forged = json.loads(path.read_text())
            forged["batches"][0]["records"][0]["value"] = "0xdead"
            path.write_text(json.dumps(acq._seal(forged)))
            self.fails("RESUME_PREVIOUS_STORAGE_MISMATCH",
                       lambda: ResumableAcquisition(self.make(), ["0x01"], path).run())

    def test_cannot_relabel_one_corporate_operator_as_two_independent_voters(self):
        providers = [
            Provider("node-a", "corp-a", Replica()),
            Provider("node-b", "corp-a", Replica()),
            Provider("node-c", "corp-c", Replica()),
        ]
        self.fails("INVALID_OR_DUPLICATE_PROVIDER_IDENTITY",
                   lambda: session(providers=providers))

    def test_resume_does_not_allow_unverified_claim_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            acq = ResumableAcquisition(self.make(), ["0x01"], path)
            acq.run()
            bad = json.loads(path.read_text())
            bad["can_claim"] = True
            path.write_text(json.dumps(acq._seal(bad)))
            self.fails("JOURNAL_SESSION_OR_DIGEST_MISMATCH",
                       lambda: ResumableAcquisition(self.make(), ["0x01"], path).run())

    def test_existing_unrelated_journal_is_not_clobbered(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            path.write_text('{"different_app": true}')
            self.fails("JOURNAL_SESSION_OR_DIGEST_MISMATCH",
                       lambda: ResumableAcquisition(self.make(), ["0x01"], path).run())
            self.assertEqual(path.read_text(), '{"different_app": true}')


if __name__ == "__main__":
    unittest.main()
