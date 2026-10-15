"""Strict, offline source-inventory reconciliation for the Metorah ink! ledger.

Reader methods MUST be bound to the SAME block hash; a future network adapter
must obtain and verify finalized headers and storage proofs (#27–#29).
This module does NOT establish holder-set authenticity from an untrusted RPC.
It is an *independent computational auditor*, not a blockchain verifier.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Protocol

UINT128_MAX = 2**128 - 1
UINT32_MAX = 2**32 - 1
ACCOUNT = re.compile(r"^0x[0-9a-fA-F]{64}$")
BLOCK_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
EXPECTED_HEADER_FIELDS = frozenset({
    "frozen", "asset_id", "decimals", "max_supply",
    "total_supply", "holder_count", "active_holder_count",
})
MAX_PAGE_SIZE = 64
DEFAULT_MAX_HOLDERS = 100_000


class ScanError(ValueError):
    """Fail-closed inventory error with a stable machine-readable code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class PinnedLedgerReader(Protocol):
    """Untrusted source viewer interface; every read must use the same block."""

    def registry_snapshot(self, at_block: str) -> dict[str, Any]: ...
    def holder_page_indexed(self, start: int, limit: int, at_block: str) -> list: ...
    def holder_at(self, index: int, at_block: str) -> tuple | None: ...
    def index_of(self, account: str, at_block: str) -> int | None: ...
    def balance_of(self, account: str, at_block: str) -> int: ...


def _uint(value: Any, *, field: str, maximum: int = UINT128_MAX) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ScanError(f"INVALID_{field.upper()}")
    return value


def _account(value: Any) -> str:
    if not isinstance(value, str) or not ACCOUNT.fullmatch(value):
        raise ScanError("INVALID_SOURCE_ACCOUNT")
    canonical = value.lower()
    if canonical == "0x" + "0" * 64:
        raise ScanError("ZERO_SOURCE_ACCOUNT")
    return canonical


def _header(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != EXPECTED_HEADER_FIELDS:
        raise ScanError("INVALID_REGISTRY_HEADER")
    if raw["frozen"] is not True:
        raise ScanError("SOURCE_NOT_FROZEN")
    asset = raw["asset_id"]
    if not isinstance(asset, str) or not ACCOUNT.fullmatch(asset) or int(asset, 16) == 0:
        raise ScanError("INVALID_ASSET_ID")
    decimals = _uint(raw["decimals"], field="decimals", maximum=18)
    cap = _uint(raw["max_supply"], field="max_supply")
    if cap == 0:
        raise ScanError("INVALID_SUPPLY_CAP")
    total = _uint(raw["total_supply"], field="total_supply")
    if total > cap:
        raise ScanError("SUPPLY_EXCEEDS_CAP")
    holders = _uint(raw["holder_count"], field="holder_count", maximum=UINT32_MAX)
    active = _uint(raw["active_holder_count"], field="active_holder_count", maximum=UINT32_MAX)
    if active > holders:
        raise ScanError("ACTIVE_EXCEEDS_HISTORICAL_COUNT")
    if holders == 0 and total != 0:
        raise ScanError("NONEMPTY_SUPPLY_WITH_NO_HOLDERS")
    return {
        "frozen": True,
        "asset_id": asset.lower(),
        "decimals": decimals,
        "max_supply": cap,
        "total_supply": total,
        "holder_count": holders,
        "active_holder_count": active,
    }


def _read(func, *args):
    try:
        return func(*args)
    except ScanError:
        raise
    except Exception as exc:
        raise ScanError("SOURCE_READ_FAILED") from exc


def _pair(value: Any, code: str) -> tuple[str, int]:
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ScanError(code)
    account = _account(value[0])
    amount = _uint(value[1], field="holder_amount")
    return (account, amount)


def scan(
    reader: PinnedLedgerReader,
    *,
    pinned_block_hash: str,
    page_size: int = MAX_PAGE_SIZE,
    max_holders: int = DEFAULT_MAX_HOLDERS,
) -> dict[str, Any]:
    """Enumerate each *reported* registry index, cross-check, and reconcile.

    Even when this succeeds, a compromised node can lie consistently about
    header, registry and balances. Never use it to activate a migration.
    """
    if not isinstance(pinned_block_hash, str) or not BLOCK_HASH.fullmatch(pinned_block_hash):
        raise ScanError("INVALID_BLOCK_REFERENCE")
    pinned = pinned_block_hash.lower()
    if type(page_size) is not int or not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ScanError("INVALID_PAGE_SIZE")
    if type(max_holders) is not int or not 0 < max_holders <= UINT32_MAX:
        raise ScanError("INVALID_SCAN_LIMIT")

    meta = _header(_read(reader.registry_snapshot, pinned))
    n = meta["holder_count"]
    if n > max_holders:
        raise ScanError("HOLDER_POPULATION_OVER_LIMIT")

    seen: set[str] = set()
    amount_total = 0
    active = 0
    positive: list[dict[str, Any]] = []

    for start in range(0, n, page_size):
        count = min(page_size, n - start)
        page = _read(reader.holder_page_indexed, start, count, pinned)
        if not isinstance(page, (list, tuple)) or len(page) != count:
            raise ScanError("INCOMPLETE_REGISTRY_PAGE")
        for offset, raw in enumerate(page):
            expected_index = start + offset
            if not isinstance(raw, (list, tuple)) or len(raw) != 3:
                raise ScanError("MALFORMED_REGISTRY_RECORD")
            index, owner_raw, units_raw = raw
            if type(index) is not int or index != expected_index:
                raise ScanError("NONCONTIGUOUS_REGISTRY_INDEX")
            owner = _account(owner_raw)
            units = _uint(units_raw, field="holder_amount")
            if owner in seen:
                raise ScanError("DUPLICATE_HOLDER")
            seen.add(owner)

            direct = _read(reader.holder_at, expected_index, pinned)
            if direct is None:
                raise ScanError("MISSING_HOLDER_AT")
            if _pair(direct, "MALFORMED_HOLDER_AT") != (owner, units):
                raise ScanError("HOLDER_AT_DISAGREEMENT")
            owner_index = _read(reader.index_of, owner, pinned)
            if type(owner_index) is not int or owner_index != expected_index:
                raise ScanError("REVERSE_INDEX_DISAGREEMENT")
            direct_balance = _read(reader.balance_of, owner, pinned)
            if type(direct_balance) is not int or direct_balance != units:
                raise ScanError("BALANCE_OF_DISAGREEMENT")

            if amount_total > UINT128_MAX - units:
                raise ScanError("AGGREGATE_OVERFLOW")
            amount_total += units
            if units > 0:
                active += 1
                positive.append({
                    "source_index": index,
                    "source_account": owner,
                    "units": str(units),
                })

    if len(seen) != n:
        raise ScanError("HISTORICAL_REGISTRY_COUNT_MISMATCH")
    if amount_total != meta["total_supply"]:
        raise ScanError("TOTAL_SUPPLY_MISMATCH")
    if active != meta["active_holder_count"]:
        raise ScanError("ACTIVE_HOLDER_COUNT_MISMATCH")

    after = _header(_read(reader.registry_snapshot, pinned))
    if after != meta:
        raise ScanError("SNAPSHOT_CHANGED_DURING_SCAN")

    # Diagnostic only, NOT the cross-VM Merkle commitment or storage proof.
    digest_payload = {
        "asset_id": meta["asset_id"],
        "block_hash": pinned,
        "decimals": meta["decimals"],
        "historical_holder_count": n,
        "supply": str(meta["total_supply"]),
        "entries": positive,
    }
    diagnostic = hashlib.sha256(
        b"METORAH_DIAGNOSTIC_INVENTORY_V1\n"
        + json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "schema_version": "metorah-enumeration-v1",
        "status": "RECONCILED_UNAUTHENTICATED",
        "evidence_grade": "E1_COMPUTATIONAL_ONLY",
        "pinned_block_hash": pinned,
        "asset_id": meta["asset_id"],
        "decimals": meta["decimals"],
        "historical_holder_count": n,
        "active_holder_count": active,
        "zero_balance_tombstones": n - active,
        "total_supply_units": str(amount_total),
        "positive_holders": positive,
        "diagnostic_sha256_not_merkle": diagnostic,
        "source_chain_authenticated": False,
        "holder_set_cryptographically_complete": False,
        "freeze_finality_verified": False,
        "destination_bindings_verified": False,
        "can_activate": False,
        "can_claim": False,
        "warning": (
            "Inventory reconciles only against reader-reported source fields at "
            "the requested block. The reader, block identity, complete state "
            "and storage proofs are NOT independently authenticated."
        ),
    }
