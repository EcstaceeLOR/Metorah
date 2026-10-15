import unittest

from tools.orchestrator.snapshot_worker import (
    HolderRecord,
    RegistryCommitment,
    SnapshotError,
    VerifiedCheckpoint,
    VerifiedHolder,
    _validate_checkpoint,
    _validate_commitment,
    canonical_inventory_digest,
    partition_ranges,
)


def checkpoint():
    return VerifiedCheckpoint(
        source_chain_id="00000000-0000-4000-8000-000000000003",
        block_number=12345,
        block_hash=b"b" * 32,
        state_root=b"s" * 32,
        genesis_hash=b"g" * 32,
        trie_state_version=1,
        finality_evidence_digest=b"f" * 32,
    )


class SnapshotWorkerTests(unittest.TestCase):
    def test_partition_ranges_cover_every_index_exactly_once(self):
        ranges = partition_ranges(257, 64)
        self.assertEqual(len(ranges), 5)
        self.assertEqual(ranges[0], (0, 0, 64))
        self.assertEqual(ranges[-1], (4, 256, 257))
        flattened = [index for _, start, end in ranges for index in range(start, end)]
        self.assertEqual(flattened, list(range(257)))

    def test_partition_ranges_reject_zero_or_unbounded_inputs(self):
        for count, size in [(0, 64), (1_000_001, 64), (10, 0), (10, 257), (True, 10)]:
            with self.subTest(count=count, size=size):
                with self.assertRaises(SnapshotError):
                    partition_ranges(count, size)

    def test_checkpoint_requires_hashes_and_supported_trie_version(self):
        _validate_checkpoint(checkpoint())
        with self.assertRaisesRegex(SnapshotError, "INVALID_BLOCK_HASH"):
            _validate_checkpoint(VerifiedCheckpoint(
                source_chain_id="chain", block_number=1, block_hash=b"short", state_root=b"s"*32,
                genesis_hash=b"g"*32, trie_state_version=1, finality_evidence_digest=b"f"*32
            ))
        with self.assertRaisesRegex(SnapshotError, "UNSUPPORTED_TRIE_STATE_VERSION"):
            _validate_checkpoint(VerifiedCheckpoint(
                source_chain_id="chain", block_number=1, block_hash=b"b"*32, state_root=b"s"*32,
                genesis_hash=b"g"*32, trie_state_version=2, finality_evidence_digest=b"f"*32
            ))

    def test_registry_commitment_requires_a_bounded_complete_holder_count(self):
        _validate_commitment(RegistryCommitment(3, 100, b"h"*32, "trie-verifier/1"))
        with self.assertRaisesRegex(SnapshotError, "HOLDER_COUNT_OUT_OF_RANGE"):
            _validate_commitment(RegistryCommitment(0, 0, b"h"*32, "trie-verifier/1"))
        with self.assertRaisesRegex(SnapshotError, "INVALID_EXPECTED_TOTAL_SUPPLY"):
            _validate_commitment(RegistryCommitment(3, -1, b"h"*32, "trie-verifier/1"))

    def test_inventory_digest_is_deterministic_and_commits_to_proofs(self):
        first = VerifiedHolder(0, b"a"*32, b"\x01", 5, b"p"*32)
        second = VerifiedHolder(1, b"b"*32, b"\x02", 7, b"q"*32)
        self.assertEqual(canonical_inventory_digest([first, second]), canonical_inventory_digest([second, first]))
        changed = VerifiedHolder(1, b"b"*32, b"\x02", 7, b"r"*32)
        self.assertNotEqual(canonical_inventory_digest([first, second]), canonical_inventory_digest([first, changed]))

    def test_inventory_digest_separates_amounts_and_account_identity(self):
        base = VerifiedHolder(0, b"a"*32, b"\x01", 5, b"p"*32)
        amount_changed = VerifiedHolder(0, b"a"*32, b"\x01", 6, b"p"*32)
        account_changed = VerifiedHolder(0, b"z"*32, b"\x01", 5, b"p"*32)
        self.assertNotEqual(canonical_inventory_digest([base]), canonical_inventory_digest([amount_changed]))
        self.assertNotEqual(canonical_inventory_digest([base]), canonical_inventory_digest([account_changed]))


if __name__ == "__main__":
    unittest.main()
