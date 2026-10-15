"""Read-only, fail-closed *observation* of Metorah WASM source freeze.

This is NOT finality verification, runtime signature verification, a Substrate
header hash verifier, a storage-trie verifier, or sufficient activation evidence.
The reader and supplied expected IDs may be wholly adversarial. There is no
trusted chain adapter in this release; all outputs forbid activation.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Protocol

H256 = re.compile(r"^0x[0-9a-fA-F]{64}$")
H160 = re.compile(r"^0x[0-9a-fA-F]{40}$")
UINT32 = 2**32 - 1
UINT64 = 2**64 - 1
UINT128 = 2**128 - 1
HEADER_KEYS = frozenset({"number", "state_root", "parent_hash"})
SNAPSHOT_KEYS = frozenset({
    "frozen", "asset_id", "decimals", "max_supply", "total_supply",
    "holder_count", "active_holder_count",
})
RECEIPT_KEYS = frozenset({
    "tx_hash", "block_hash", "extrinsic_index", "dispatch_success",
    "source_contract", "signer", "events",
})
EVENT_KEYS = frozenset({
    "type", "by", "source_contract", "source_block", "asset_id",
    "migration_id", "destination_chain_id", "destination_contract",
    "total_supply", "holder_count", "active_holder_count",
    "unbound_active_holders",
})


class FreezeEvidenceError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ReadOnlyFreezeReader(Protocol):
    """Each method is a *reported* RPC observation, NOT a trusted assertion."""

    def chain_genesis_hash(self) -> str: ...
    def finalized_head_hash(self) -> str: ...
    def block_hash_at(self, number: int) -> str: ...
    def header_at(self, block_hash: str) -> dict[str, Any]: ...
    def freeze_receipt(self, tx_hash: str) -> dict[str, Any]: ...
    def contract_code_hash(self, account: str, block_hash: str) -> str: ...
    def contract_owner(self, account: str, block_hash: str) -> str: ...
    def freeze_marker(self, account: str, block_hash: str) -> tuple: ...
    def registry_snapshot(self, account: str, block_hash: str) -> dict: ...
    def destination_domain(self, account: str, block_hash: str) -> tuple: ...
    def unbound_active_holders(self, account: str, block_hash: str) -> int: ...


def _hex(value: Any, pattern: re.Pattern, code: str, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise FreezeEvidenceError(code)
    v = value.lower()
    if not allow_zero and int(v, 16) == 0:
        raise FreezeEvidenceError(code)
    return v


def _uint(value: Any, code: str, maximum: int, zero: bool = True) -> int:
    if type(value) is not int or not (0 if zero else 1) <= value <= maximum:
        raise FreezeEvidenceError(code)
    return value


def _read(fn, *args):
    try:
        return fn(*args)
    except FreezeEvidenceError:
        raise
    except Exception as exc:
        raise FreezeEvidenceError("SOURCE_RPC_UNAVAILABLE") from exc


def _header(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != HEADER_KEYS:
        raise FreezeEvidenceError("INVALID_BLOCK_HEADER")
    return {
        "number": _uint(value["number"], "INVALID_HEADER_NUMBER", UINT32),
        "state_root": _hex(value["state_root"], H256, "INVALID_STATE_ROOT"),
        "parent_hash": _hex(value["parent_hash"], H256, "INVALID_PARENT_HASH", allow_zero=True),
    }


def _snapshot(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != SNAPSHOT_KEYS:
        raise FreezeEvidenceError("INVALID_REGISTRY_SNAPSHOT")
    if value["frozen"] is not True:
        raise FreezeEvidenceError("SOURCE_NOT_FROZEN")
    max_supply = _uint(value["max_supply"], "INVALID_MAX_SUPPLY", UINT128, zero=False)
    total = _uint(value["total_supply"], "INVALID_TOTAL_SUPPLY", UINT128)
    if total > max_supply:
        raise FreezeEvidenceError("TOTAL_SUPPLY_EXCEEDS_MAX")
    count = _uint(value["holder_count"], "INVALID_HOLDER_COUNT", UINT32)
    active = _uint(value["active_holder_count"], "INVALID_ACTIVE_COUNT", UINT32)
    if active > count or (count == 0 and total > 0):
        raise FreezeEvidenceError("IMPOSSIBLE_REGISTRY_COUNTS")
    return {
        "frozen": True,
        "asset_id": _hex(value["asset_id"], H256, "INVALID_ASSET_ID"),
        "decimals": _uint(value["decimals"], "INVALID_DECIMALS", 18),
        "max_supply": max_supply,
        "total_supply": total,
        "holder_count": count,
        "active_holder_count": active,
    }


def observe(
    reader: ReadOnlyFreezeReader,
    *,
    expected_genesis: str,
    expected_source_contract: str,
    expected_source_code_hash: str,
    freeze_tx_hash: str,
    freeze_block_hash: str,
) -> dict:
    """Require consistent *reported* finality, receipt, event and frozen state.

    This does not verify finalized ancestry, signatures, state trie membership,
    block header hashes or chain identity. Always fail closed for activation.
    """
    genesis = _hex(expected_genesis, H256, "INVALID_EXPECTED_GENESIS")
    source = _hex(expected_source_contract, H256, "INVALID_SOURCE_CONTRACT")
    code_hash = _hex(expected_source_code_hash, H256, "INVALID_EXPECTED_CODE_HASH")
    tx = _hex(freeze_tx_hash, H256, "INVALID_FREEZE_TRANSACTION")
    block = _hex(freeze_block_hash, H256, "INVALID_FREEZE_BLOCK")
    observed_genesis = _hex(_read(reader.chain_genesis_hash), H256, "INVALID_OBSERVED_GENESIS")
    if genesis != observed_genesis:
        raise FreezeEvidenceError("GENESIS_MISMATCH")

    receipt = _read(reader.freeze_receipt, tx)
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS:
        raise FreezeEvidenceError("INVALID_RECEIPT")
    if _hex(receipt["tx_hash"], H256, "INVALID_RECEIPT_TX") != tx:
        raise FreezeEvidenceError("FREEZE_TRANSACTION_MISMATCH")
    if _hex(receipt["block_hash"], H256, "INVALID_RECEIPT_BLOCK") != block:
        raise FreezeEvidenceError("FREEZE_BLOCK_MISMATCH")
    if receipt["dispatch_success"] is not True:
        raise FreezeEvidenceError("FREEZE_EXTRINSIC_FAILED")
    extrinsic = _uint(receipt["extrinsic_index"], "INVALID_EXTRINSIC_INDEX", UINT32)
    if _hex(receipt["source_contract"], H256, "INVALID_RECEIPT_CONTRACT") != source:
        raise FreezeEvidenceError("WRONG_SOURCE_CONTRACT")

    signer = _hex(receipt["signer"], H256, "INVALID_SIGNER")
    if _hex(_read(reader.contract_owner, source, block), H256, "INVALID_OWNER") != signer:
        raise FreezeEvidenceError("UNAUTHORIZED_FREEZE_SIGNER")
    events = receipt["events"]
    if not isinstance(events, list) or len(events) != 1:
        raise FreezeEvidenceError("MISSING_OR_DUPLICATE_FREEZE_EVENT")
    event = events[0]
    if not isinstance(event, dict) or set(event) != EVENT_KEYS:
        raise FreezeEvidenceError("INVALID_FREEZE_EVENT")
    if event["type"] != "SourceFrozen":
        raise FreezeEvidenceError("WRONG_EVENT_TYPE")
    if _hex(event["by"], H256, "INVALID_FREEZE_ACTOR") != signer:
        raise FreezeEvidenceError("EVENT_SIGNER_MISMATCH")
    if _hex(event["source_contract"], H256, "INVALID_EVENT_CONTRACT") != source:
        raise FreezeEvidenceError("WRONG_EVENT_CONTRACT")

    freeze_header = _header(_read(reader.header_at, block))
    height = freeze_header["number"]
    if _uint(event["source_block"], "INVALID_EVENT_BLOCK", UINT32) != height:
        raise FreezeEvidenceError("CUTOFF_BLOCK_MISMATCH")
    if _hex(_read(reader.block_hash_at, height), H256, "INVALID_CANONICAL_BLOCK") != block:
        raise FreezeEvidenceError("ORPHANED_OR_REORGED_FREEZE_BLOCK")
    finalized_hash = _hex(_read(reader.finalized_head_hash), H256, "INVALID_FINALIZED_HEAD")
    final_header = _header(_read(reader.header_at, finalized_hash))
    if final_header["number"] < height:
        raise FreezeEvidenceError("FREEZE_BLOCK_NOT_FINALIZED")
    # Comparing height and one RPC's canonical hash is NOT a proof of ancestor
    # relation to the finalized head, or a cryptographic finality proof.
    if finalized_hash == block and final_header != freeze_header:
        raise FreezeEvidenceError("CONFLICTING_FINALIZED_HEADER")

    observed_code = _hex(
        _read(reader.contract_code_hash, source, block), H256, "INVALID_OBSERVED_CODE_HASH"
    )
    if observed_code != code_hash:
        raise FreezeEvidenceError("SOURCE_CODE_HASH_MISMATCH")
    snap = _snapshot(_read(reader.registry_snapshot, source, block))
    marker = _read(reader.freeze_marker, source, block)
    if not isinstance(marker, (tuple, list)) or len(marker) != 5:
        raise FreezeEvidenceError("MISSING_FREEZE_MARKER")
    marker = (
        _uint(marker[0], "INVALID_MARKER_BLOCK", UINT32),
        _uint(marker[1], "INVALID_MARKER_SUPPLY", UINT128),
        _uint(marker[2], "INVALID_MARKER_HOLDER_COUNT", UINT32),
        _uint(marker[3], "INVALID_MARKER_ACTIVE_COUNT", UINT32),
        _uint(marker[4], "INVALID_MARKER_UNBOUND_COUNT", UINT32),
    )
    if marker != (height, snap["total_supply"], snap["holder_count"], snap["active_holder_count"], 0):
        raise FreezeEvidenceError("FREEZE_MARKER_MISMATCH")
    if _uint(_read(reader.unbound_active_holders, source, block), "INVALID_UNBOUND_COUNT", UINT32) != 0:
        raise FreezeEvidenceError("UNBOUND_FUNDED_HOLDERS")

    domain = _read(reader.destination_domain, source, block)
    if not isinstance(domain, (tuple, list)) or len(domain) != 3:
        raise FreezeEvidenceError("INVALID_DESTINATION_DOMAIN")
    chain_id = _uint(domain[0], "INVALID_DESTINATION_CHAIN_ID", UINT64, zero=False)
    dest_contract = _hex(domain[1], H160, "INVALID_DESTINATION_CONTRACT")
    migration = _hex(domain[2], H256, "INVALID_MIGRATION_ID")

    comparisons = {
        "asset_id": (snap["asset_id"], _hex(event["asset_id"], H256, "INVALID_EVENT_ASSET")),
        "migration_id": (migration, _hex(event["migration_id"], H256, "INVALID_EVENT_MIGRATION")),
        "destination_contract": (dest_contract, _hex(event["destination_contract"], H160, "INVALID_EVENT_DESTINATION")),
        "total_supply": (snap["total_supply"], _uint(event["total_supply"], "INVALID_EVENT_SUPPLY", UINT128)),
        "holder_count": (snap["holder_count"], _uint(event["holder_count"], "INVALID_EVENT_HOLDER_COUNT", UINT32)),
        "active_holder_count": (snap["active_holder_count"], _uint(event["active_holder_count"], "INVALID_EVENT_ACTIVE_COUNT", UINT32)),
        "unbound_active_holders": (0, _uint(event["unbound_active_holders"], "INVALID_EVENT_UNBOUND_COUNT", UINT32)),
        "destination_chain_id": (chain_id, _uint(event["destination_chain_id"], "INVALID_EVENT_CHAIN_ID", UINT64, zero=False)),
    }
    for expected, reported in comparisons.values():
        if expected != reported:
            raise FreezeEvidenceError("FREEZE_EVENT_STATE_MISMATCH")

    # Re-check canonical block, finalized height and source state at same
    # pinned hash. A dishonest provider can still forge all results.
    if _hex(_read(reader.block_hash_at, height), H256, "INVALID_CANONICAL_BLOCK") != block:
        raise FreezeEvidenceError("REORG_DURING_EVIDENCE_SCAN")
    if _header(_read(reader.header_at, block)) != freeze_header:
        raise FreezeEvidenceError("CONFLICTING_FREEZE_HEADER")
    if _snapshot(_read(reader.registry_snapshot, source, block)) != snap:
        raise FreezeEvidenceError("CHANGED_FROZEN_SNAPSHOT")
    final_again = _header(_read(reader.header_at, _hex(_read(reader.finalized_head_hash), H256, "INVALID_FINALIZED_HEAD")))
    if final_again["number"] < height:
        raise FreezeEvidenceError("FINALIZED_HEAD_REGRESSION")

    payload = {
        "genesis": genesis, "source": source, "code": observed_code, "tx": tx,
        "block": block, "state_root": freeze_header["state_root"],
        "height": height, "finalized_observation_height": final_header["number"],
        "owner": signer, "extrinsic_index": extrinsic,
        "snapshot": snap,
        "destination": {
            "chain_id": chain_id, "contract": dest_contract, "migration_id": migration,
        },
    }
    fingerprint = hashlib.sha256(
        b"METORAH_FREEZE_OBSERVATION_V1\n"
        + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "metorah-freeze-observation-v1",
        "status": "FREEZE_OBSERVED_UNAUTHENTICATED",
        "observed": payload,
        "diagnostic_sha256_not_proof": fingerprint,
        "genesis_authenticated": False,
        "finality_cryptographically_verified": False,
        "finalized_ancestry_verified": False,
        "storage_trie_membership_verified": False,
        "source_contract_code_authenticated": False,
        "signed_extrinsic_authenticated": False,
        "freeze_is_irreversible_on_chain": False,
        "can_activate": False,
        "can_claim": False,
        "warning": "All reads came from an untrusted observer; no official trust anchor, finalized ancestry, consensus signatures, header hash recomputation, storage proof, or runtime upgrade guarantee was verified.",
    }
