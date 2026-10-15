"""Source storage proof acquisition unit tests: NO genuine node, NO chain finality."""
from __future__ import annotations

import unittest

from tools.finality import substrate as F
from tools.trie_verifier.collector import collect

BLOCK = "0x" + "04" * 32
ROOT = "0x" + "07" * 32


class FakeProofRPC:
    def __init__(self):
        self.at = BLOCK
        self.proof = ["0x010203", "0x040506"]
        self.values = {"0x01": "0xa1b2", "0x02": None}
        self.calls = []
        self.fail = None

    def call(self, method, params):
        self.calls.append((method, params))
        if self.fail == method:
            raise ConnectionError("unavailable")
        if method == "state_getReadProof":
            return {"at": self.at, "proof": list(self.proof)}
        if method == "state_getStorage":
            return self.values.get(params[0])
        raise AssertionError("unexpected method " + method)


def observation():
    return {
        "status": F.REPORT_STATUS,
        "can_activate": False,
        "can_claim": False,
        "observed": {
            "snapshot_block_hash": BLOCK,
            "snapshot_state_root": ROOT,
        },
    }


class TrieCollectorTests(unittest.TestCase):
    def grab(self, rpc=None, *, keys=None, version=1, obs=None):
        r = rpc or FakeProofRPC()
        return collect(r, obs if obs is not None else observation(),
                       ["0x01", "0x02"] if keys is None else keys,
                       state_version=version)

    def denies(self, r, expected, **opts):
        with self.assertRaises(F.FinalityObservationError) as exc:
            self.grab(r, **opts)
        self.assertEqual(str(exc.exception), expected)

    def test_bundle_is_only_an_unverified_input_for_rust_verifier(self):
        r = FakeProofRPC()
        v = self.grab(r)
        self.assertEqual(v, {
            "schema_version": "metorah-substrate-storage-proof-v1",
            "block_hash": BLOCK, "state_root": ROOT,
            "state_version": 1,
            "nodes": ["0x010203", "0x040506"],
            "items": [{"key": "0x01", "value": "0xa1b2"}, {"key": "0x02", "value": None}],
        })
        self.assertNotIn("can_activate", v)
        self.assertNotIn("can_claim", v)
        self.assertNotIn("source_authenticated", v)

    def test_every_storage_read_is_bound_to_exact_same_hash(self):
        r = FakeProofRPC()
        self.grab(r)
        self.assertEqual(r.calls, [
            ("state_getReadProof", [["0x01", "0x02"], BLOCK]),
            ("state_getStorage", ["0x01", BLOCK]),
            ("state_getStorage", ["0x02", BLOCK]),
        ])

    def test_observation_cannot_authorize_activations(self):
        o = observation()
        o["can_claim"] = True
        self.denies(FakeProofRPC(), "UNEXPECTED_PROOF_CLAIM", obs=o)

    def test_proof_response_cannot_be_at_different_block(self):
        r = FakeProofRPC()
        r.at = "0x" + "ff" * 32
        self.denies(r, "PROOF_NOT_AT_PINNED_BLOCK")

    def test_duplicate_proof_nodes_denied(self):
        r = FakeProofRPC()
        r.proof.append(r.proof[0])
        self.denies(r, "DUPLICATE_TRIE_PROOF_NODE")

    def test_empty_proof_nodes_denied(self):
        r = FakeProofRPC()
        r.proof = []
        self.denies(r, "INVALID_TRIE_PROOF_NODE_COUNT")

    def test_broken_node_data_denied(self):
        r = FakeProofRPC()
        r.proof = ["0xabc"]
        self.denies(r, "INVALID_TRIE_PROOF_NODE")

    def test_empty_storage_key_denied(self):
        self.denies(FakeProofRPC(), "EMPTY_STORAGE_KEY", keys=["0x"])

    def test_duplicate_storage_key_denied(self):
        self.denies(FakeProofRPC(), "DUPLICATED_OR_UNSORTED_STORAGE_KEYS",
                    keys=["0x01", "0x01"])

    def test_reordered_storage_key_denied(self):
        self.denies(FakeProofRPC(), "DUPLICATED_OR_UNSORTED_STORAGE_KEYS",
                    keys=["0x02", "0x01"])

    def test_version_bool_rejected(self):
        self.denies(FakeProofRPC(), "UNSUPPORTED_TRIE_STATE_VERSION", version=True)

    def test_unknown_trie_state_version_rejected(self):
        self.denies(FakeProofRPC(), "UNSUPPORTED_TRIE_STATE_VERSION", version=2)

    def test_unbounded_proof_node_list_denied(self):
        r = FakeProofRPC()
        r.proof = ["0x010203"] * 513
        self.denies(r, "INVALID_TRIE_PROOF_NODE_COUNT")

    def test_oversized_storage_proof_denied(self):
        r = FakeProofRPC()
        r.proof = ["0x" + "ab" * (1024 * 1024 + 1)]
        self.denies(r, "TRIE_PROOF_TOO_LARGE")

    def test_untrusted_transport_error_denied(self):
        r = FakeProofRPC()
        r.fail = "state_getReadProof"
        self.denies(r, "RPC_READ_FAILED")

    def test_untrusted_malformed_value_denied(self):
        r = FakeProofRPC()
        r.values["0x01"] = "not-hex"
        self.denies(r, "INVALID_STORAGE_VALUE")

    def test_missing_or_extra_response_fields_denied(self):
        class Malformed(FakeProofRPC):
            def call(self, method, params):
                if method == "state_getReadProof":
                    return {"at": BLOCK, "proof": ["0x01"], "verified": True}
                return super().call(method, params)
        self.denies(Malformed(), "INVALID_READ_PROOF_RESPONSE")


if __name__ == "__main__":
    unittest.main()
