"""Build a strict, hash-pinned Substrate read-proof bundle for offline Rust verification.

Do NOT call this result a verified proof. A hostile JSON-RPC may forge both
values and nodes; only the separate sp-trie verifier checks membership against
the supplied root, and finality of that root is still unverified.
"""
from __future__ import annotations

import re
from typing import Any

from tools.finality.substrate import (
    FinalityObservationError, PinnedStateReader, _read, _hash
)

HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
MAX_KEYS = 256
MAX_NODES = 512
MAX_PROOF_BYTES = 1024 * 1024


def _bytes(value: Any, label: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        raise FinalityObservationError("INVALID_" + label)
    if nonempty and value == "0x":
        raise FinalityObservationError("EMPTY_" + label)
    return value.lower()


def collect(
    reader,
    observation: dict,
    storage_keys: list[str],
    *,
    state_version: int,
) -> dict:
    """Ask one pinned checkpoint for exact keys, values and raw trie nodes.

    State version MUST be externally confirmed from real chain metadata; it
    is never inferred from a block number or other unauthenticated label.
    """
    if type(state_version) is not int or state_version not in (0, 1):
        raise FinalityObservationError("UNSUPPORTED_TRIE_STATE_VERSION")
    if not isinstance(storage_keys, list) or not 1 <= len(storage_keys) <= MAX_KEYS:
        raise FinalityObservationError("INVALID_STORAGE_KEY_COUNT")
    keys = [_bytes(k, "STORAGE_KEY", nonempty=True) for k in storage_keys]
    if keys != sorted(set(keys)):
        raise FinalityObservationError("DUPLICATED_OR_UNSORTED_STORAGE_KEYS")
    pinned = PinnedStateReader(reader, observation)
    result = _read(reader, "state_getReadProof", [keys, pinned.block_hash])
    if not isinstance(result, dict) or set(result) != {"at", "proof"}:
        raise FinalityObservationError("INVALID_READ_PROOF_RESPONSE")
    if _hash(result["at"], "INVALID_PROOF_BLOCK") != pinned.block_hash:
        raise FinalityObservationError("PROOF_NOT_AT_PINNED_BLOCK")
    proof = result["proof"]
    if not isinstance(proof, list) or not 1 <= len(proof) <= MAX_NODES:
        raise FinalityObservationError("INVALID_TRIE_PROOF_NODE_COUNT")
    nodes = [_bytes(node, "TRIE_PROOF_NODE", nonempty=True) for node in proof]
    if len(set(nodes)) != len(nodes):
        raise FinalityObservationError("DUPLICATE_TRIE_PROOF_NODE")
    if sum(len(n) // 2 - 1 for n in nodes) > MAX_PROOF_BYTES:
        raise FinalityObservationError("TRIE_PROOF_TOO_LARGE")
    # Read values at the EXACT same checkpoint. A malicious RPC can claim
    # arbitrary values; the offline verifier rejects ones unsupported by trie.
    entries = [{"key": k, "value": pinned.storage(k)} for k in keys]
    return {
        "schema_version": "metorah-substrate-storage-proof-v1",
        "block_hash": pinned.block_hash,
        "state_root": pinned.state_root,
        "state_version": state_version,
        "nodes": nodes,
        "items": entries,
    }
