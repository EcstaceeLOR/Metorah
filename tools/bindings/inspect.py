"""Candidate beneficiary snapshot audit for frozen ink! source ledgers.

Checks expected domain, per-holder final mapping and a sequential registration
event history. All inputs still come from an UNTRUSTED reader. This is not
signature validation, finalized storage proof verification or claim authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Protocol

H160 = re.compile(r"^0x[0-9a-fA-F]{40}$")
H256 = re.compile(r"^0x[0-9a-fA-F]{64}$")
MAX_NONCE = (1 << 64) - 1


class BindingAuditError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class BindingReader(Protocol):
    def destination_domain(self, at_block: str) -> tuple: ...
    def binding_at(self, index: int, at_block: str) -> tuple | None: ...
    def binding_of(self, source: str, at_block: str) -> dict | None: ...
    def registration_events(self, source: str, at_block: str) -> list[dict]: ...


def _hex(value: Any, pattern: re.Pattern, code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise BindingAuditError(code)
    val = value.lower()
    if int(val, 16) == 0:
        raise BindingAuditError(code)
    return val


def _u64(value: Any, code: str, *, permit_zero: bool = False) -> int:
    if type(value) is not int or value > MAX_NONCE or value < (0 if permit_zero else 1):
        raise BindingAuditError(code)
    return value


def _read(fn, *args):
    try:
        return fn(*args)
    except BindingAuditError:
        raise
    except Exception as e:
        raise BindingAuditError("BINDING_READER_FAILED") from e


def _domain(raw: Any) -> dict:
    if not isinstance(raw, (tuple, list)) or len(raw) != 3:
        raise BindingAuditError("INVALID_DESTINATION_DOMAIN")
    return {
        "chain_id": _u64(raw[0], "INVALID_CHAIN_ID"),
        "destination_contract": _hex(raw[1], H160, "INVALID_DESTINATION_CONTRACT"),
        "migration_id": _hex(raw[2], H256, "INVALID_MIGRATION_ID"),
    }


def _binding(raw: Any) -> tuple[str, int]:
    if not isinstance(raw, dict) or set(raw) != {"beneficiary", "nonce"}:
        raise BindingAuditError("MISSING_OR_INVALID_BINDING")
    return (
        _hex(raw["beneficiary"], H160, "INVALID_BENEFICIARY"),
        _u64(raw["nonce"], "INVALID_BINDING_NONCE"),
    )


def inspect(
    reader: BindingReader,
    *,
    inventory: dict[str, Any],
    pinned_block_hash: str,
    source_contract: str,
) -> dict[str, Any]:
    """Reconcile source getter state and *untrusted* event history only."""
    if not isinstance(inventory, dict) or inventory.get("status") != "RECONCILED_UNAUTHENTICATED":
        raise BindingAuditError("UNSUPPORTED_INVENTORY")
    block = _hex(pinned_block_hash, H256, "INVALID_BLOCK_HASH")
    source = _hex(source_contract, H256, "INVALID_SOURCE_CONTRACT")
    if inventory.get("pinned_block_hash") != block:
        raise BindingAuditError("PINNED_BLOCK_MISMATCH")
    if inventory.get("source_chain_authenticated") is not False:
        raise BindingAuditError("UNEXPECTED_AUTHENTICATION_CLAIM")
    candidates = inventory.get("positive_holders")
    if not isinstance(candidates, list):
        raise BindingAuditError("MALFORMED_INVENTORY")
    if type(inventory.get("active_holder_count")) is not int or len(candidates) != inventory["active_holder_count"]:
        raise BindingAuditError("HOLDER_COUNT_MISMATCH")
    domain = _domain(_read(reader.destination_domain, block))
    output: list[dict[str, Any]] = []
    seen_indices: set[int] = set()
    seen_accounts: set[str] = set()
    seen_total = 0

    for item in candidates:
        if not isinstance(item, dict) or set(item) != {"source_index", "source_account", "units"}:
            raise BindingAuditError("MALFORMED_INVENTORY_ENTRY")
        index = item["source_index"]
        if type(index) is not int or index < 0 or index in seen_indices:
            raise BindingAuditError("DUPLICATE_OR_INVALID_INDEX")
        seen_indices.add(index)
        acct = _hex(item["source_account"], H256, "INVALID_SOURCE_OWNER")
        if acct in seen_accounts:
            raise BindingAuditError("DUPLICATE_SOURCE_OWNER")
        seen_accounts.add(acct)
        try:
            units = int(item["units"])
        except (ValueError, TypeError):
            raise BindingAuditError("INVALID_ENTITLEMENT_UNITS") from None
        if not isinstance(item["units"], str) or str(units) != item["units"] or units <= 0 or units > (1 << 128) - 1:
            raise BindingAuditError("INVALID_ENTITLEMENT_UNITS")

        row = _read(reader.binding_at, index, block)
        if not isinstance(row, (tuple, list)) or len(row) != 3:
            raise BindingAuditError("MISSING_BINDING_AT")
        row_account, row_units, row_binding = row
        if _hex(row_account, H256, "INVALID_ROW_ACCOUNT") != acct or type(row_units) is not int or row_units != units:
            raise BindingAuditError("BINDING_ROW_DISAGREEMENT")
        beneficiary, nonce = _binding(row_binding)
        direct = _binding(_read(reader.binding_of, acct, block))
        if direct != (beneficiary, nonce):
            raise BindingAuditError("DIRECT_BINDING_DISAGREEMENT")

        history = _read(reader.registration_events, acct, block)
        if not isinstance(history, list) or len(history) != nonce or nonce > 100_000:
            raise BindingAuditError("INCOMPLETE_BINDING_HISTORY")
        prior = "0x" + "0" * 40
        for expected, event in enumerate(history, start=1):
            keys = {
                "source_owner", "source_contract", "destination_chain_id",
                "destination_contract", "migration_id",
                "previous_beneficiary", "beneficiary", "nonce",
            }
            if not isinstance(event, dict) or set(event) != keys:
                raise BindingAuditError("INVALID_BINDING_EVENT")
            if _hex(event["source_owner"], H256, "INVALID_EVENT_OWNER") != acct or _hex(event["source_contract"], H256, "INVALID_EVENT_CONTRACT") != source:
                raise BindingAuditError("EVENT_SOURCE_MISMATCH")
            if (
                event["destination_chain_id"] != domain["chain_id"]
                or _hex(event["destination_contract"], H160, "INVALID_EVENT_DESTINATION") != domain["destination_contract"]
                or _hex(event["migration_id"], H256, "INVALID_EVENT_MIGRATION") != domain["migration_id"]
            ):
                raise BindingAuditError("EVENT_DESTINATION_DOMAIN_MISMATCH")
            if type(event["nonce"]) is not int or event["nonce"] != expected:
                raise BindingAuditError("NONCONTIGUOUS_BINDING_NONCE")
            event_prior = event["previous_beneficiary"]
            if not isinstance(event_prior, str) or not H160.fullmatch(event_prior) or event_prior.lower() != prior:
                raise BindingAuditError("BINDING_HISTORY_BROKEN")
            prior = _hex(event["beneficiary"], H160, "INVALID_EVENT_BENEFICIARY")
        if prior != beneficiary:
            raise BindingAuditError("FINAL_BENEFICIARY_MISMATCH")
        seen_total += units
        output.append({
            "source_index": index,
            "source_account": acct,
            "units": str(units),
            "beneficiary": beneficiary,
            "registration_nonce": nonce,
        })

    if str(seen_total) != inventory.get("total_supply_units"):
        raise BindingAuditError("TOTAL_ALLOCATION_MISMATCH")
    if _domain(_read(reader.destination_domain, block)) != domain:
        raise BindingAuditError("DESTINATION_DOMAIN_CHANGED")

    payload = {"source_contract": source, "block": block, "domain": domain, "entries": output}
    fingerprint = hashlib.sha256(
        b"METORAH_BINDING_DIAGNOSTIC_V1\n"
        + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "metorah-binding-candidate-v1",
        "status": "BINDINGS_RECONCILED_UNAUTHENTICATED",
        "source_contract": source,
        "pinned_block_hash": block,
        "destination_domain": domain,
        "positive_holders": output,
        "total_supply_units": str(seen_total),
        "diagnostic_sha256_not_merkle": fingerprint,
        "source_chain_authenticated": False,
        "binding_events_chain_authenticated": False,
        "freeze_finality_verified": False,
        "can_activate": False,
        "can_claim": False,
        "warning": (
            "Reader responses and event histories are not independently "
            "authenticated. Real signatures, finalized source proofs and "
            "complete event inclusion remain future chain-integration work."
        ),
    }
