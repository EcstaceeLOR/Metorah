"""Metorah canonical manifest V1 — deterministic offline encoding, NOT source proof.

These hashes authenticate only the supplied bytes. This module neither
authenticates a finalized source block nor authorizes destination claims.

Binary integers: unsigned *big-endian* fixed widths. SHA-256 over tagged
byte strings. Leaves are POSITIONAL (left/right), never sorted by hash.
Odd layers duplicate their last hash. Empty manifests are prohibited.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

SCHEMA = "metorah-canonical-v1"
HEADER_TAG = b"METORAH_HEADER_V1\x00"
LEAF_TAG = b"METORAH_LEAF_V1\x00"
NODE_TAG = b"METORAH_NODE_V1\x00"
MANIFEST_TAG = b"METORAH_MANIFEST_V1\x00"
MAX_U128 = (1 << 128) - 1
MAX_U64 = (1 << 64) - 1
MAX_U32 = (1 << 32) - 1
H32 = re.compile(r"0x[0-9a-f]{64}\Z")
H20 = re.compile(r"0x[0-9a-f]{40}\Z")
DEC = re.compile(r"(0|[1-9][0-9]*)\Z")
HEADER_KEYS = frozenset({
    "source_genesis", "finalized_block_hash", "finalized_block_number",
    "finalized_state_root", "source_contract", "source_code_hash",
    "migration_id", "asset_id", "destination_chain_id",
    "destination_contract", "entitlement_kind", "decimals",
    "historical_holder_count", "active_holder_count", "total_units",
})
LEAF_KEYS = frozenset({
    "leaf_index", "historical_index", "source_account",
    "beneficiary", "units", "binding_nonce",
})
OUTPUT_KEYS = frozenset({
    "schema_version", "header", "entries", "header_hash",
    "merkle_root", "manifest_digest", "assurance",
    "source_chain_authenticated", "can_activate", "can_claim",
})


class ManifestError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _fixed_hex(value: Any, size: int, name: str, *, allow_zero: bool = False) -> bytes:
    if not isinstance(value, str) or not (H32 if size == 32 else H20).fullmatch(value):
        raise ManifestError(f"INVALID_{name.upper()}")
    raw = bytes.fromhex(value[2:])
    if not allow_zero and not any(raw):
        raise ManifestError(f"ZERO_{name.upper()}")
    return raw


def _uint(value: Any, width: int, name: str, *, serialized: bool = False, permit_zero: bool = False) -> bytes:
    if serialized:
        if not isinstance(value, str) or DEC.fullmatch(value) is None:
            raise ManifestError(f"INVALID_{name.upper()}")
        number = int(value)
    else:
        if type(value) is not int:
            raise ManifestError(f"INVALID_{name.upper()}")
        number = value
    if not (0 if permit_zero else 1) <= number < (1 << (8 * width)):
        raise ManifestError(f"INVALID_{name.upper()}")
    return number.to_bytes(width, "big")


def _canonical_header(header: Any) -> bytes:
    if not isinstance(header, dict) or set(header) != HEADER_KEYS:
        raise ManifestError("INVALID_HEADER_SCHEMA")
    kind = header["entitlement_kind"]
    if type(kind) is not int or kind != 1:
        raise ManifestError("UNSUPPORTED_ENTITLEMENT_KIND")
    decimals = header["decimals"]
    if type(decimals) is not int or not 0 <= decimals <= 18:
        raise ManifestError("INVALID_DECIMALS")
    historical = header["historical_holder_count"]
    active = header["active_holder_count"]
    if type(historical) is not int or type(active) is not int or not 0 < active <= historical <= MAX_U32:
        raise ManifestError("INVALID_HOLDER_COUNTS")
    if not isinstance(header["total_units"], str) or DEC.fullmatch(header["total_units"]) is None:
        raise ManifestError("INVALID_TOTAL_UNITS")
    if not 0 < int(header["total_units"]) <= MAX_U128:
        raise ManifestError("INVALID_TOTAL_UNITS")
    return b"".join((
        _fixed_hex(header["source_genesis"], 32, "source_genesis"),
        _fixed_hex(header["finalized_block_hash"], 32, "finalized_block_hash"),
        _uint(header["finalized_block_number"], 8, "finalized_block_number", serialized=True),
        _fixed_hex(header["finalized_state_root"], 32, "finalized_state_root"),
        _fixed_hex(header["source_contract"], 32, "source_contract"),
        _fixed_hex(header["source_code_hash"], 32, "source_code_hash"),
        _fixed_hex(header["migration_id"], 32, "migration_id"),
        _fixed_hex(header["asset_id"], 32, "asset_id"),
        _uint(header["destination_chain_id"], 8, "destination_chain_id", serialized=True),
        _fixed_hex(header["destination_contract"], 20, "destination_contract"),
        _uint(kind, 1, "entitlement_kind"),
        _uint(decimals, 1, "decimals", permit_zero=True),
        _uint(historical, 4, "historical_holder_count"),
        _uint(active, 4, "active_holder_count"),
        _uint(header["total_units"], 16, "total_units", serialized=True),
    ))


def _canonical_leaf(entry: Any, *, active_count: int, historical_count: int) -> bytes:
    if not isinstance(entry, dict) or set(entry) != LEAF_KEYS:
        raise ManifestError("INVALID_LEAF_SCHEMA")
    index = entry["leaf_index"]
    historical = entry["historical_index"]
    if type(index) is not int or not 0 <= index < active_count:
        raise ManifestError("INVALID_LEAF_INDEX")
    if type(historical) is not int or not 0 <= historical < historical_count:
        raise ManifestError("INVALID_HISTORICAL_INDEX")
    return b"".join((
        _uint(index, 4, "leaf_index", permit_zero=True),
        _uint(historical, 4, "historical_index", permit_zero=True),
        _fixed_hex(entry["source_account"], 32, "source_account"),
        _fixed_hex(entry["beneficiary"], 20, "beneficiary"),
        _uint(entry["units"], 16, "units", serialized=True),
        _uint(entry["binding_nonce"], 8, "binding_nonce", serialized=True),
    ))


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def header_hash(header: dict[str, Any]) -> bytes:
    return sha(HEADER_TAG + _canonical_header(header))


def leaf_hash(header_digest: bytes, entry: dict[str, Any], header: dict[str, Any]) -> bytes:
    if not isinstance(header_digest, bytes) or len(header_digest) != 32:
        raise ManifestError("INVALID_HEADER_DIGEST")
    body = _canonical_leaf(entry, active_count=header["active_holder_count"],
                           historical_count=header["historical_holder_count"])
    return sha(LEAF_TAG + header_digest + body)


def node_hash(left: bytes, right: bytes) -> bytes:
    if not isinstance(left, bytes) or not isinstance(right, bytes) or len(left) != 32 or len(right) != 32:
        raise ManifestError("INVALID_NODE_INPUT")
    return sha(NODE_TAG + left + right)


def _layers(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        raise ManifestError("EMPTY_MANIFEST")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append([
            node_hash(current[i], current[i + 1] if i + 1 < len(current) else current[i])
            for i in range(0, len(current), 2)
        ])
    return levels


def _parts(header: dict[str, Any], entries: list[dict[str, Any]]):
    encoded = _canonical_header(header)
    if not isinstance(entries, list) or len(entries) != header["active_holder_count"]:
        raise ManifestError("LEAF_COUNT_MISMATCH")
    digest = sha(HEADER_TAG + encoded)
    leaves = []
    seen = set()
    previous_historical = -1
    total = 0
    for expected, entry in enumerate(entries):
        encoded_entry = _canonical_leaf(
            entry, active_count=header["active_holder_count"],
            historical_count=header["historical_holder_count"],
        )
        if entry["leaf_index"] != expected:
            raise ManifestError("NONCANONICAL_LEAF_INDEX")
        if entry["historical_index"] <= previous_historical:
            raise ManifestError("NONCANONICAL_HOLDER_ORDER")
        previous_historical = entry["historical_index"]
        source = entry["source_account"]
        if source in seen:
            raise ManifestError("DUPLICATE_SOURCE_ACCOUNT")
        seen.add(source)
        total += int(entry["units"])
        if total > MAX_U128:
            raise ManifestError("AGGREGATE_OVERFLOW")
        leaves.append(sha(LEAF_TAG + digest + encoded_entry))
    if total != int(header["total_units"]):
        raise ManifestError("TOTAL_SUPPLY_MISMATCH")
    levels = _layers(leaves)
    return digest, levels


def build(header: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    digest, layers = _parts(header, entries)
    root = layers[-1][0]
    manifest_hash = sha(MANIFEST_TAG + digest + root)
    return {
        "schema_version": SCHEMA,
        "header": header,
        "entries": entries,
        "header_hash": "0x" + digest.hex(),
        "merkle_root": "0x" + root.hex(),
        "manifest_digest": "0x" + manifest_hash.hex(),
        "assurance": "E1_ENCODING_ONLY",
        "source_chain_authenticated": False,
        "can_activate": False,
        "can_claim": False,
    }


def verify_manifest(manifest: Any) -> bool:
    try:
        if not isinstance(manifest, dict) or set(manifest) != OUTPUT_KEYS:
            return False
        if (manifest["schema_version"] != SCHEMA or
                manifest["assurance"] != "E1_ENCODING_ONLY" or
                manifest["source_chain_authenticated"] is not False or
                manifest["can_activate"] is not False or manifest["can_claim"] is not False):
            return False
        recreated = build(manifest["header"], manifest["entries"])
        return recreated == manifest
    except (ManifestError, TypeError, KeyError, ValueError):
        return False


def proof_for(manifest: dict[str, Any], leaf_index: int) -> list[str]:
    if not verify_manifest(manifest):
        raise ManifestError("INVALID_MANIFEST")
    if type(leaf_index) is not int or not 0 <= leaf_index < len(manifest["entries"]):
        raise ManifestError("INVALID_PROOF_INDEX")
    _, levels = _parts(manifest["header"], manifest["entries"])
    path = []
    index = leaf_index
    for layer in levels[:-1]:
        sibling = index ^ 1
        if sibling >= len(layer):
            sibling = index  # exact duplicated-last rule
        path.append("0x" + layer[sibling].hex())
        index //= 2
    return path


def verify_proof(
    header: dict[str, Any],
    entry: dict[str, Any],
    siblings: list[str],
    root: str,
) -> bool:
    try:
        head = header_hash(header)
        leaf = leaf_hash(head, entry, header)
        active = header["active_holder_count"]
        index = entry["leaf_index"]
        if type(index) is not int or not 0 <= index < active:
            return False
        if not isinstance(siblings, list):
            return False
        expected = 0
        n = active
        while n > 1:
            n = (n + 1) // 2
            expected += 1
        if len(siblings) != expected:
            return False
        current = leaf
        count = active
        for sibling in siblings:
            sib = _fixed_hex(sibling, 32, "proof_sibling", allow_zero=True)
            if (index ^ 1) >= count and sib != current:
                return False
            current = node_hash(sib, current) if index & 1 else node_hash(current, sib)
            index //= 2
            count = (count + 1) // 2
        return current == _fixed_hex(root, 32, "root", allow_zero=True)
    except (ManifestError, KeyError, TypeError, ValueError):
        return False
