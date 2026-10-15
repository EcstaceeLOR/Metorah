"""Metorah finalized Substrate header *observation* and hash-pinned storage reader.

SECURITY: self-consistent JSON-RPC is NOT GRANDPA/BEEFY finality, trust-anchor
verification, independent SCALE header hashing, or authenticated trie storage.
This module never upgrades to E3, activates migration, or authorizes claims.
Only caller-configured genesis and historical checkpoint are considered.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Protocol

HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
HEX_BYTES = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
HEX_UINT = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")
MAX_U64 = 2**64 - 1
MAX_ANCESTRY = 4096
REPORT_STATUS = "FINALIZED_HEADER_OBSERVED_UNAUTHENTICATED"
READ_ONLY_METHODS = frozenset({
    "chain_getBlockHash",
    "chain_getFinalizedHead",
    "chain_getHeader",
    "state_getRuntimeVersion",
    "state_getMetadata",
    "state_getStorage",
})


class FinalityObservationError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class JsonRpcReader(Protocol):
    def call(self, method: str, params: list[Any]) -> Any: ...


def _read(reader: JsonRpcReader, method: str, params: list[Any]) -> Any:
    if method not in READ_ONLY_METHODS:
        raise FinalityObservationError("UNAUTHORIZED_RPC_METHOD")
    try:
        return reader.call(method, params)
    except FinalityObservationError:
        raise
    except Exception as exc:
        raise FinalityObservationError("RPC_READ_FAILED") from exc


def _hash(value: Any, code: str, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise FinalityObservationError(code)
    out = value.lower()
    if not allow_zero and int(out[2:], 16) == 0:
        raise FinalityObservationError(code)
    return out


def _height(value: Any) -> int:
    if not isinstance(value, str) or HEX_UINT.fullmatch(value) is None:
        raise FinalityObservationError("INVALID_HEADER_NUMBER")
    num = int(value, 16)
    if num > MAX_U64:
        raise FinalityObservationError("INVALID_HEADER_NUMBER")
    return num


def _header(value: Any, *, block_hash: str) -> dict[str, Any]:
    # Standard Substrate header fields. Extra runtime-specific metadata is
    # allowed but must never replace validated core fields.
    if not isinstance(value, dict):
        raise FinalityObservationError("MISSING_HEADER")
    required = {"number", "parentHash", "stateRoot", "extrinsicsRoot", "digest"}
    if not required.issubset(value):
        raise FinalityObservationError("INCOMPLETE_HEADER")
    digest = value["digest"]
    if not isinstance(digest, dict) or not isinstance(digest.get("logs"), list):
        raise FinalityObservationError("INVALID_HEADER_DIGEST")
    for log in digest["logs"]:
        if not isinstance(log, str) or HEX_BYTES.fullmatch(log) is None:
            raise FinalityObservationError("INVALID_HEADER_DIGEST")
    number = _height(value["number"])
    parent = _hash(value["parentHash"], "INVALID_PARENT_HASH", allow_zero=number == 0)
    if number > 0 and int(parent[2:], 16) == 0:
        raise FinalityObservationError("INVALID_PARENT_HASH")
    return {
        "hash": block_hash,
        "number": number,
        "parent_hash": parent,
        "state_root": _hash(value["stateRoot"], "INVALID_STATE_ROOT"),
        "extrinsics_root": _hash(value["extrinsicsRoot"], "INVALID_EXTRINSICS_ROOT", allow_zero=True),
        "digest_logs": [v.lower() for v in digest["logs"]],
    }


def _runtime(value: Any) -> dict[str, int | str]:
    if not isinstance(value, dict):
        raise FinalityObservationError("MISSING_RUNTIME_VERSION")
    for key in ("specName", "implName"):
        if not isinstance(value.get(key), str) or not value[key].strip() or len(value[key]) > 128:
            raise FinalityObservationError("INVALID_RUNTIME_IDENTITY")
    versions = {}
    for key in ("specVersion", "implVersion", "transactionVersion"):
        val = value.get(key)
        if type(val) is not int or not 0 <= val <= (2**32 - 1):
            raise FinalityObservationError("INVALID_RUNTIME_VERSION")
        versions[key] = val
    return {"spec_name": value["specName"], "impl_name": value["implName"], **versions}


def _report(facts: dict[str, Any]) -> dict[str, Any]:
    digest = sha256(
        b"METORAH_FINALITY_OBSERVATION_V1\n"
        + json.dumps(facts, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "metorah-finality-observation-v1",
        "status": REPORT_STATUS,
        "observed": facts,
        "diagnostic_sha256_not_proof": digest,
        "genesis_authenticated": False,
        "header_hash_recomputed": False,
        "consensus_finality_cryptographically_verified": False,
        "finalized_ancestry_observed": True,
        "finalized_ancestry_cryptographically_verified": False,
        "storage_trie_membership_verified": False,
        "can_activate": False,
        "can_claim": False,
        "warning": (
            "RPC may forge genesis, headers, reported finalized head, runtime and "
            "storage. Parent links and canonical height hashes are only RPC "
            "observations. Independent trusted genesis, SCALE header hashing, "
            "GRANDPA/BEEFY proofs and trie verification remain required."
        ),
    }


def observe(
    reader: JsonRpcReader,
    *,
    expected_genesis_hash: str,
    pinned_block_hash: str,
    max_finalized_lag: int = 256,
) -> dict[str, Any]:
    """Observe candidate pinned source checkpoint under reported finalization.

    Walk every parent hash from reported finalized head to the nominated block;
    cross-check canonical height mapping at each step and repeat finality/head
    and checkpoint reads to catch a reorg or inconsistent read session.

    No timestamp-based freshness claim is possible from a bare Substrate header.
    max_finalized_lag is a *height difference* guard, not a seconds guard.
    """
    genesis = _hash(expected_genesis_hash, "INVALID_EXPECTED_GENESIS")
    checkpoint = _hash(pinned_block_hash, "INVALID_PINNED_BLOCK")
    if type(max_finalized_lag) is not int or not 0 <= max_finalized_lag <= MAX_ANCESTRY:
        raise FinalityObservationError("INVALID_FINALITY_LAG_POLICY")
    reported_genesis = _hash(
        _read(reader, "chain_getBlockHash", [0]), "INVALID_REPORTED_GENESIS"
    )
    if genesis != reported_genesis:
        raise FinalityObservationError("WRONG_GENESIS")
    finalized = _hash(
        _read(reader, "chain_getFinalizedHead", []), "INVALID_FINALIZED_HEAD"
    )
    head = _header(
        _read(reader, "chain_getHeader", [finalized]), block_hash=finalized
    )
    checkpoint_header = _header(
        _read(reader, "chain_getHeader", [checkpoint]), block_hash=checkpoint
    )
    if head["number"] < checkpoint_header["number"]:
        raise FinalityObservationError("UNFINALIZED_CHECKPOINT")
    gap = head["number"] - checkpoint_header["number"]
    if gap > max_finalized_lag:
        raise FinalityObservationError("STALE_CHECKPOINT")
    if _hash(_read(reader, "chain_getBlockHash", [head["number"]]), "INVALID_HEIGHT_HASH") != finalized:
        raise FinalityObservationError("INCONSISTENT_FINALIZED_HEAD")
    seen = set()
    cursor_hash = finalized
    cursor = head
    for step in range(gap + 1):
        if cursor_hash in seen:
            raise FinalityObservationError("ANCESTRY_CYCLE")
        seen.add(cursor_hash)
        if cursor["number"] != head["number"] - step:
            raise FinalityObservationError("BROKEN_ANCESTRY_HEIGHT")
        at_height = _hash(
            _read(reader, "chain_getBlockHash", [cursor["number"]]),
            "INVALID_CANONICAL_HEIGHT_HASH",
        )
        if at_height != cursor_hash:
            raise FinalityObservationError("ORPHANED_OR_FORKED_CHECKPOINT")
        if step == gap:
            if cursor_hash != checkpoint:
                raise FinalityObservationError("NOT_FINALIZED_ANCESTOR")
            if cursor != checkpoint_header:
                raise FinalityObservationError("CONFLICTING_CHECKPOINT_HEADER")
            break
        next_hash = cursor["parent_hash"]
        cursor = _header(_read(reader, "chain_getHeader", [next_hash]), block_hash=next_hash)
        cursor_hash = next_hash

    runtime = _runtime(_read(reader, "state_getRuntimeVersion", [checkpoint]))
    if _hash(_read(reader, "chain_getBlockHash", [0]), "INVALID_REPORTED_GENESIS") != genesis:
        raise FinalityObservationError("GENESIS_CHANGED_DURING_SCAN")
    if _hash(_read(reader, "chain_getFinalizedHead", []), "INVALID_FINALIZED_HEAD") != finalized:
        # A legitimate advancing head also triggers fail-closed recheck. This
        # is conservative and avoids ambiguous cross-head observations.
        raise FinalityObservationError("FINALIZED_HEAD_CHANGED_DURING_SCAN")
    if _header(_read(reader, "chain_getHeader", [checkpoint]), block_hash=checkpoint) != checkpoint_header:
        raise FinalityObservationError("CHECKPOINT_HEADER_CHANGED")
    if _hash(_read(reader, "chain_getBlockHash", [checkpoint_header["number"]]), "INVALID_HEIGHT_HASH") != checkpoint:
        raise FinalityObservationError("CHECKPOINT_REORG_DURING_SCAN")

    facts = {
        "reported_genesis_hash": genesis,
        "snapshot_block_hash": checkpoint,
        "snapshot_block_number": checkpoint_header["number"],
        "snapshot_state_root": checkpoint_header["state_root"],
        "snapshot_extrinsics_root": checkpoint_header["extrinsics_root"],
        "reported_finalized_hash": finalized,
        "reported_finalized_number": head["number"],
        "finalized_head_state_root": head["state_root"],
        "ancestry_links_examined": gap,
        "lag_in_blocks": gap,
        "runtime_at_snapshot": runtime,
    }
    return _report(facts)


class PinnedStateReader:
    """Ensure every storage RPC is bound to the same *observed* checkpoint.

    The returned bytes/None remain UNAUTHENTICATED. This is a convenience
    guard for indexing pipelines, not a storage-trie verifier.
    """

    def __init__(self, reader: JsonRpcReader, observation: dict[str, Any]):
        if not isinstance(observation, dict) or observation.get("status") != REPORT_STATUS:
            raise FinalityObservationError("INVALID_PINNED_OBSERVATION")
        if observation.get("can_activate") is not False or observation.get("can_claim") is not False:
            raise FinalityObservationError("UNEXPECTED_PROOF_CLAIM")
        try:
            facts = observation["observed"]
            if not isinstance(facts, dict):
                raise ValueError()
            block = _hash(facts["snapshot_block_hash"], "INVALID_PINNED_BLOCK")
            root = _hash(facts["snapshot_state_root"], "INVALID_STATE_ROOT")
        except (KeyError, TypeError, ValueError) as exc:
            raise FinalityObservationError("INVALID_PINNED_OBSERVATION") from exc
        self._reader = reader
        self.block_hash = block
        self.state_root = root
        self.keys_read: list[str] = []

    def storage(self, key: str) -> str | None:
        if not isinstance(key, str) or HEX_BYTES.fullmatch(key) is None or key == "0x":
            raise FinalityObservationError("INVALID_STORAGE_KEY")
        value = _read(self._reader, "state_getStorage", [key.lower(), self.block_hash])
        if value is not None and (not isinstance(value, str) or HEX_BYTES.fullmatch(value) is None):
            raise FinalityObservationError("INVALID_STORAGE_VALUE")
        self.keys_read.append(key.lower())
        return value.lower() if isinstance(value, str) else None
