"""Metorah feasibility POC (SIMULATED LEDGERS; NOT Portaldot/EVM deployment).

This module proves limited application-level invariants under a trusted,
fully enumerable source ledger. It does NOT verify Substrate trie proofs,
finality, source contract correctness, or perform any on-chain transactions.
"""
from __future__ import annotations

from dataclasses import dataclass
from copy import deepcopy
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_UINT128 = 2**128 - 1
DOMAIN_LEAF = b"statelift/poc-v1/leaf\x00"
DOMAIN_NODE = b"statelift/poc-v1/node\x00"
DOMAIN_EMPTY = b"statelift/poc-v1/empty\x00"
DOMAIN_STATE = b"statelift/poc-v1/simulated-source-state\x00"
DOMAIN_MIGRATION = b"statelift/poc-v1/migration-id\x00"
DOMAIN_BIND = b"statelift/poc-v1/account-binding\x00"


class MigrationError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _valid_pubkey(s: str) -> None:
    try:
        raw = bytes.fromhex(s)
        if len(raw) != 32:
            raise ValueError("length")
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise MigrationError("invalid 32-byte Ed25519 public key") from exc


def _valid_units(v: int) -> None:
    if type(v) is not int or v <= 0 or v > MAX_UINT128:
        raise MigrationError("amount must be positive uint128")


@dataclass(frozen=True)
class FrozenState:
    # "block" and hash below are explicitly SIMULATED, never chain-authenticated.
    source_genesis: str
    source_contract: str
    simulated_block_number: int
    simulated_state_hash: str
    balances: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.balances.values())


class SourceLedger:
    """Models a *cooperative, freezeable* contract; NOT a chain implementation."""

    def __init__(self, source_genesis: str, source_contract: str, balances: dict[str, int]):
        if not source_genesis or not source_contract or not balances:
            raise MigrationError("source identity and accounts required")
        for key, val in balances.items():
            _valid_pubkey(key)
            _valid_units(val)
        if sum(balances.values()) > MAX_UINT128:
            raise MigrationError("total exceeds uint128")
        self.genesis = source_genesis
        self.contract = source_contract
        self.balances = dict(balances)
        self.frozen = False
        self.height = 40  # illustrative, not a genuine finalized block

    def transfer(self, source: str, destination: str, units: int) -> None:
        if self.frozen:
            raise MigrationError("source frozen: transfers disabled")
        _valid_units(units)
        if source not in self.balances or destination not in self.balances:
            raise MigrationError("unknown account")
        if self.balances[source] < units:
            raise MigrationError("insufficient balance")
        self.balances[source] -= units
        self.balances[destination] += units
        # A production implementation must define how zero-amount records are treated.
        self.height += 1

    def freeze(self) -> FrozenState:
        if self.frozen:
            raise MigrationError("source already frozen")
        self.frozen = True
        self.height += 1
        payload = {"source_genesis": self.genesis, "source_contract": self.contract,
                   "simulated_block_number": self.height,
                   "balances": self.balances}
        return FrozenState(self.genesis, self.contract, self.height,
                           sha256_hex(DOMAIN_STATE + canonical(payload)), deepcopy(self.balances))


def leaf_hash(entry: dict[str, Any]) -> bytes:
    return hashlib.sha256(DOMAIN_LEAF + canonical(entry)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(DOMAIN_NODE + left + right).digest()


def root_for(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return sha256_hex(DOMAIN_EMPTY)
    layer = [leaf_hash(x) for x in entries]
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0].hex()


def proof_for(entries: list[dict[str, Any]], index: int) -> list[dict[str, str]]:
    if not 0 <= index < len(entries):
        raise MigrationError("invalid leaf index")
    layer = [leaf_hash(x) for x in entries]
    idx = index
    path = []
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        sibling = idx ^ 1
        path.append({"side": "left" if sibling < idx else "right", "hash": layer[sibling].hex()})
        layer = [node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        idx //= 2
    return path


def verify_proof(entry: dict[str, Any], proof: list[dict[str, str]], expected_root: str) -> bool:
    try:
        result = leaf_hash(entry)
        if len(proof) > 64:
            return False
        for p in proof:
            sibling = bytes.fromhex(p["hash"])
            if len(sibling) != 32:
                return False
            if p["side"] == "left":
                result = node_hash(sibling, result)
            elif p["side"] == "right":
                result = node_hash(result, sibling)
            else:
                return False
        return result.hex() == expected_root
    except (ValueError, TypeError, KeyError):
        return False


def migration_id_for(metadata: dict[str, Any]) -> str:
    return sha256_hex(DOMAIN_MIGRATION + canonical(metadata))


def make_manifest(frozen: FrozenState, target_genesis: str, target_contract: str) -> dict[str, Any]:
    if not target_genesis or not target_contract:
        raise MigrationError("destination identity required")
    if frozen.source_genesis == target_genesis and frozen.source_contract == target_contract:
        raise MigrationError("same source and destination not allowed")
    meta = {
        "protocol": "statelift-poc-v1",
        "source_genesis": frozen.source_genesis,
        "source_contract": frozen.source_contract,
        "simulated_block_number": frozen.simulated_block_number,
        "simulated_state_hash": frozen.simulated_state_hash,
        "target_genesis": target_genesis,
        "target_contract": target_contract,
    }
    mid = migration_id_for(meta)
    entries = [{"migration_id": mid, "source_pubkey": pub, "units": units}
               for pub, units in sorted(frozen.balances.items()) if units > 0]
    return {"metadata": meta, "migration_id": mid, "entries": entries,
            "root": root_for(entries), "total": sum(e["units"] for e in entries)}


@dataclass(frozen=True)
class VerifiedSnapshot:
    """A trusted local validation result. NOT a proof that a chain state root is valid."""
    migration_id: str
    root: str
    total: int
    target_genesis: str
    target_contract: str


def verify_snapshot(source: SourceLedger, frozen: FrozenState,
                    manifest: dict[str, Any]) -> VerifiedSnapshot:
    """Independent read of entire source ledger is the trust assumption."""
    if not source.frozen:
        raise MigrationError("source is not frozen")
    if source.balances != frozen.balances:
        raise MigrationError("source state changed since freeze")
    if source.genesis != frozen.source_genesis or source.contract != frozen.source_contract:
        raise MigrationError("source identity mismatch")
    if source.height != frozen.simulated_block_number:
        raise MigrationError("source block changed since freeze")
    payload = {"source_genesis": source.genesis, "source_contract": source.contract,
               "simulated_block_number": source.height, "balances": source.balances}
    if frozen.simulated_state_hash != sha256_hex(DOMAIN_STATE + canonical(payload)):
        raise MigrationError("simulation source-state hash mismatch")
    meta = manifest["metadata"]
    if meta["source_genesis"] != source.genesis or meta["source_contract"] != source.contract:
        raise MigrationError("manifest source identity mismatch")
    if meta["simulated_block_number"] != frozen.simulated_block_number or meta["simulated_state_hash"] != frozen.simulated_state_hash:
        raise MigrationError("manifest source-state mismatch")
    if not meta["target_genesis"] or not meta["target_contract"]:
        raise MigrationError("invalid destination identity")
    mid = migration_id_for(meta)
    if mid != manifest["migration_id"]:
        raise MigrationError("migration id mismatch")
    entries = manifest["entries"]
    expected_nonzero = {pub: units for pub, units in source.balances.items() if units > 0}
    if len(entries) != len(expected_nonzero) or len(entries) == 0:
        raise MigrationError("snapshot omits positive entitlements or contains extras")
    seen = set()
    for entry in entries:
        pub = entry["source_pubkey"]
        _valid_pubkey(pub)
        _valid_units(entry["units"])
        if pub in seen:
            raise MigrationError("duplicate account in manifest")
        seen.add(pub)
        if entry["migration_id"] != mid or source.balances.get(pub) != entry["units"]:
            raise MigrationError("snapshot entitlement differs from trusted source")
    if sum(e["units"] for e in entries) != sum(source.balances.values()):
        raise MigrationError("snapshot total differs from source total")
    if manifest["total"] != sum(source.balances.values()):
        raise MigrationError("manifest total differs from source")
    if manifest["root"] != root_for(entries):
        raise MigrationError("snapshot merkle root mismatch")
    if entries != sorted(entries, key=lambda v: v["source_pubkey"]):
        raise MigrationError("noncanonical snapshot order")
    return VerifiedSnapshot(mid, manifest["root"], manifest["total"],
                            meta["target_genesis"], meta["target_contract"])


def binding_payload(migration_id: str, root: str, source_pubkey: str,
                    target_pubkey: str, units: int) -> bytes:
    return DOMAIN_BIND + canonical({"migration_id": migration_id,
                                   "merkle_root": root, "source_pubkey": source_pubkey,
                                   "target_pubkey": target_pubkey, "units": units})


class TargetLedger:
    """Simulates a destination claim contract, with atomic state transitions."""

    def __init__(self, verified: VerifiedSnapshot, target_genesis: str, target_contract: str):
        if verified.target_genesis != target_genesis or verified.target_contract != target_contract:
            raise MigrationError("verified snapshot is for a different destination")
        self.verified = verified
        self.claimed_source = set()
        self.balances: dict[str, int] = {}
        self.claimed_total = 0
        self.claim_events: list[dict[str, Any]] = []

    def claim(self, entry: dict[str, Any], proof: list[dict[str, str]],
              target_pubkey: str, source_signature_hex: str) -> None:
        _valid_pubkey(target_pubkey)
        source_pubkey = entry.get("source_pubkey")
        _valid_pubkey(source_pubkey)
        units = entry.get("units")
        _valid_units(units)
        if entry.get("migration_id") != self.verified.migration_id:
            raise MigrationError("migration domain mismatch")
        if source_pubkey in self.claimed_source:
            raise MigrationError("already claimed")
        if not verify_proof(entry, proof, self.verified.root):
            raise MigrationError("invalid Merkle entitlement proof")
        message = binding_payload(self.verified.migration_id, self.verified.root,
                                  source_pubkey, target_pubkey, units)
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(source_pubkey)).verify(
                bytes.fromhex(source_signature_hex), message)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise MigrationError("invalid source-account authorization") from exc
        if self.claimed_total + units > self.verified.total:
            raise MigrationError("migration exceeds verified supply")
        # Only mutate after every validation, equivalent to an atomic transaction.
        self.claimed_source.add(source_pubkey)
        self.balances[target_pubkey] = self.balances.get(target_pubkey, 0) + units
        self.claimed_total += units
        self.claim_events.append({"source": source_pubkey, "destination": target_pubkey,
                                  "units": units, "migration_id": self.verified.migration_id})

    @property
    def unclaimed_total(self) -> int:
        return self.verified.total - self.claimed_total
