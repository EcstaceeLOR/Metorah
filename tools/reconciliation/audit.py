"""Independent OFFLINE event-replay/registry/manifest reconciliation for #29.

Every input is untrusted until separately authenticated by real Portaldot V3
consensus finality, contract-state storage and complete event/registry proofs.
This module cannot authenticate history, finality, signatures or release assets.
It detects omissions only relative to a COMPLETE independently checked source
registry and event stream; a malicious operator can otherwise fake both.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from tools.manifest import canonical as manifest_v1

UINT128 = (1 << 128) - 1
UINT64 = (1 << 64) - 1
UINT32 = (1 << 32) - 1
MAX_HOLDERS = 100_000
MAX_EVENTS = 300_000
ZERO_H160 = "0x" + "00" * 20
SNAPSHOT_KEYS = frozenset({
    "schema_version", "header", "owner", "max_supply", "frozen",
    "freeze_block_number", "unbound_active_holders", "slots", "events",
})
SLOT_KEYS = frozenset({"index", "source_account", "units", "beneficiary", "binding_nonce"})
EVENT_KEYS = {
    "Issued": frozenset({"event_index", "kind", "to", "amount"}),
    "Transferred": frozenset({"event_index", "kind", "from", "to", "amount"}),
    "Burned": frozenset({"event_index", "kind", "from", "amount"}),
    "BeneficiaryRegistered": frozenset({
        "event_index", "kind", "source_owner", "source_contract",
        "destination_chain_id", "destination_contract", "migration_id",
        "previous_beneficiary", "beneficiary", "nonce",
    }),
    "SourceFrozen": frozenset({
        "event_index", "kind", "by", "source_contract", "source_block",
        "asset_id", "migration_id", "destination_chain_id",
        "destination_contract", "total_supply", "holder_count",
        "active_holder_count", "unbound_active_holders",
    }),
}


class ReconciliationError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _keys(value: Any, expected: frozenset[str], code: str) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise ReconciliationError(code)
    return value


def _u(value: Any, name: str, limit: int, *, permit_zero: bool = False) -> int:
    if (not isinstance(value, str)
            or manifest_v1.DEC.fullmatch(value) is None
            or len(value) > len(str(limit))):
        # Bound parsed digits BEFORE int() to prevent untrusted 10k-digit
        # decimal values from triggering Python's integer-string conversion
        # exception or excessive CPU/memory use.
        raise ReconciliationError("INVALID_" + name.upper())
    n = int(value)
    if n > limit or n < (0 if permit_zero else 1):
        raise ReconciliationError("INVALID_" + name.upper())
    return n


def _count(value: Any, name: str, limit: int, *, permit_zero: bool = True) -> int:
    if type(value) is not int or not (0 if permit_zero else 1) <= value <= limit:
        raise ReconciliationError("INVALID_" + name.upper())
    return value


def _hex(value: Any, kind: str, *, allow_zero: bool = False) -> str:
    pat = manifest_v1.H32 if kind == "account" else manifest_v1.H20
    if type(value) is not str or pat.fullmatch(value) is None:
        raise ReconciliationError("INVALID_" + kind.upper())
    if not allow_zero and int(value[2:], 16) == 0:
        raise ReconciliationError("ZERO_" + kind.upper())
    return value


def _amount(value: Any) -> int:
    return _u(value, "amount", UINT128)


def _get_balance(balances: dict[str, int], account: str) -> int:
    return balances.get(account, 0)


def audit(snapshot: dict[str, Any], operator_manifest: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct all accounts and live balances via the complete supplied events.

    MUST receive an independently collected storage snapshot and event stream,
    both authenticated separately before anyone treats balances as real.
    """
    s = _keys(snapshot, SNAPSHOT_KEYS, "INVALID_SNAPSHOT_SCHEMA")
    if s["schema_version"] != "metorah-source-replay-v1":
        raise ReconciliationError("UNSUPPORTED_SNAPSHOT_SCHEMA")
    h = s["header"]
    try:
        manifest_v1._canonical_header(h)
    except (manifest_v1.ManifestError, TypeError, KeyError, ValueError) as e:
        raise ReconciliationError("INVALID_CANONICAL_HEADER") from e
    owner = _hex(s["owner"], "account")
    if s["frozen"] is not True:
        raise ReconciliationError("SOURCE_NOT_FROZEN")
    cutoff = _u(s["freeze_block_number"], "freeze_block_number", UINT64)
    if cutoff != _u(h["finalized_block_number"], "header_block_number", UINT64):
        raise ReconciliationError("FREEZE_CUTOFF_MISMATCH")
    cap = _u(s["max_supply"], "max_supply", UINT128)
    total = _u(h["total_units"], "total_units", UINT128)
    if total > cap:
        raise ReconciliationError("SUPPLY_CAP_EXCEEDED")
    n = _count(h["historical_holder_count"], "holder_count", MAX_HOLDERS, permit_zero=False)
    active_expected = _count(h["active_holder_count"], "active_holder_count", n, permit_zero=False)
    if _count(s["unbound_active_holders"], "unbound_active_holders", n) != 0:
        raise ReconciliationError("UNBOUND_FUNDED_HOLDERS")
    slots = s["slots"]
    events = s["events"]
    if type(slots) is not list or len(slots) != n:
        raise ReconciliationError("INCOMPLETE_HISTORICAL_REGISTRY")
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise ReconciliationError("INVALID_EVENT_COVERAGE")

    balances: dict[str, int] = {}
    holder_order: list[str] = []
    bindings: dict[str, tuple[str, int]] = {}
    issued = 0
    burned = 0
    current_supply = 0
    freeze_seen = False
    binding_events = 0

    def register(account: str) -> None:
        if account not in balances:
            if len(holder_order) >= MAX_HOLDERS:
                raise ReconciliationError("HOLDER_REGISTRY_OVERFLOW")
            balances[account] = 0
            holder_order.append(account)

    def domain_matches(event: dict) -> None:
        if (
            event["source_contract"] != h["source_contract"]
            or _u(event["destination_chain_id"], "event_chain_id", UINT64)
                != _u(h["destination_chain_id"], "destination_chain_id", UINT64)
            or event["destination_contract"] != h["destination_contract"]
            or event["migration_id"] != h["migration_id"]
        ):
            raise ReconciliationError("EVENT_DOMAIN_MISMATCH")

    for index, event in enumerate(events):
        if type(event) is not dict:
            raise ReconciliationError("INVALID_EVENT_SCHEMA")
        kind = event.get("kind")
        fields = EVENT_KEYS.get(kind) if type(kind) is str else None
        if fields is None or set(event) != fields:
            raise ReconciliationError("INVALID_EVENT_SCHEMA")
        if _count(event["event_index"], "event_index", MAX_EVENTS - 1) != index:
            raise ReconciliationError("EVENT_SEQUENCE_GAP")
        if freeze_seen:
            raise ReconciliationError("EVENT_AFTER_FREEZE")
        if kind == "Issued":
            to = _hex(event["to"], "account")
            qty = _amount(event["amount"])
            if current_supply > cap - qty:
                raise ReconciliationError("ISSUANCE_EXCEEDS_CAP")
            register(to)
            if balances[to] > UINT128 - qty:
                raise ReconciliationError("BALANCE_OVERFLOW")
            balances[to] += qty
            current_supply += qty
            issued += qty
        elif kind == "Transferred":
            src = _hex(event["from"], "account")
            dst = _hex(event["to"], "account")
            qty = _amount(event["amount"])
            if src == dst:
                raise ReconciliationError("SELF_TRANSFER")
            if _get_balance(balances, src) < qty:
                raise ReconciliationError("INSUFFICIENT_TRANSFER_BALANCE")
            if _get_balance(balances, dst) > UINT128 - qty:
                raise ReconciliationError("BALANCE_OVERFLOW")
            register(dst)
            balances[src] -= qty
            balances[dst] += qty
        elif kind == "Burned":
            src = _hex(event["from"], "account")
            qty = _amount(event["amount"])
            if _get_balance(balances, src) < qty or current_supply < qty:
                raise ReconciliationError("INSUFFICIENT_BURN_BALANCE")
            balances[src] -= qty
            current_supply -= qty
            burned += qty
        elif kind == "BeneficiaryRegistered":
            who = _hex(event["source_owner"], "account")
            domain_matches(event)
            if _get_balance(balances, who) == 0:
                raise ReconciliationError("BINDING_WITHOUT_ACTIVE_ENTITLEMENT")
            beneficiary = _hex(event["beneficiary"], "beneficiary")
            prev = event["previous_beneficiary"]
            if type(prev) is not str or manifest_v1.H20.fullmatch(prev) is None:
                raise ReconciliationError("INVALID_PREVIOUS_BENEFICIARY")
            old, nonce = bindings.get(who, (ZERO_H160, 0))
            if prev != old or _u(event["nonce"], "binding_nonce", UINT64) != nonce + 1:
                raise ReconciliationError("INVALID_BINDING_HISTORY")
            bindings[who] = (beneficiary, nonce + 1)
            binding_events += 1
        else:  # SourceFrozen must be unique, terminal and complete
            if index != len(events) - 1:
                raise ReconciliationError("FREEZE_NOT_LAST_EVENT")
            _hex(event["by"], "account")
            if event["by"] != owner:
                raise ReconciliationError("UNAUTHORIZED_FREEZE_ACTOR")
            domain_matches(event)
            if event["asset_id"] != h["asset_id"]:
                raise ReconciliationError("FREEZE_ASSET_MISMATCH")
            if _u(event["source_block"], "event_freeze_block", UINT64) != cutoff:
                raise ReconciliationError("FREEZE_CUTOFF_MISMATCH")
            if _u(event["total_supply"], "event_total_supply", UINT128) != current_supply:
                raise ReconciliationError("FREEZE_SUPPLY_MISMATCH")
            if _count(event["holder_count"], "event_holder_count", MAX_HOLDERS) != len(holder_order):
                raise ReconciliationError("FREEZE_HOLDER_COUNT_MISMATCH")
            active = sum(units > 0 for units in balances.values())
            if _count(event["active_holder_count"], "event_active_count", MAX_HOLDERS) != active:
                raise ReconciliationError("FREEZE_ACTIVE_COUNT_MISMATCH")
            unbound = sum(units > 0 and who not in bindings for who, units in balances.items())
            if _count(event["unbound_active_holders"], "event_unbound_count", MAX_HOLDERS) != unbound:
                raise ReconciliationError("FREEZE_UNBOUND_COUNT_MISMATCH")
            if unbound:
                raise ReconciliationError("UNBOUND_FUNDED_HOLDERS")
            freeze_seen = True

    if not freeze_seen:
        raise ReconciliationError("MISSING_FREEZE_EVENT")
    if issued - burned != current_supply or current_supply != total:
        raise ReconciliationError("EVENT_SUPPLY_RECONCILIATION_FAILED")
    if len(holder_order) != n:
        raise ReconciliationError("HISTORICAL_REGISTRY_COUNT_MISMATCH")
    active = sum(units > 0 for units in balances.values())
    if active != active_expected:
        raise ReconciliationError("ACTIVE_HOLDER_COUNT_MISMATCH")

    # All historical slots, including zero-balance tombstones, must exist.
    # The order is the order first registered by issuance/inbound transfer,
    # not a sorted account list. This catches missing funded owners even when
    # an operator generates a perfectly consistent Merkle tree for a subset.
    manifest_entries = []
    for index, raw in enumerate(slots):
        row = _keys(raw, SLOT_KEYS, "INVALID_SLOT_SCHEMA")
        if _count(row["index"], "slot_index", MAX_HOLDERS - 1) != index:
            raise ReconciliationError("MISSING_OR_REORDERED_SLOT")
        who = _hex(row["source_account"], "account")
        if who != holder_order[index]:
            raise ReconciliationError("REGISTRY_EVENT_ORDER_MISMATCH")
        units = _u(row["units"], "slot_units", UINT128, permit_zero=True)
        if units != balances[who]:
            raise ReconciliationError("REGISTRY_BALANCE_DISAGREEMENT")
        binding = bindings.get(who)
        if binding is None:
            if row["beneficiary"] is not None or row["binding_nonce"] != "0":
                raise ReconciliationError("UNEXPECTED_SLOT_BINDING")
        else:
            if row["beneficiary"] != binding[0] or row["binding_nonce"] != str(binding[1]):
                raise ReconciliationError("REGISTRY_BINDING_DISAGREEMENT")
        if units > 0:
            if binding is None:
                raise ReconciliationError("UNBOUND_FUNDED_HOLDERS")
            manifest_entries.append({
                "leaf_index": len(manifest_entries),
                "historical_index": index,
                "source_account": who,
                "beneficiary": binding[0],
                "units": str(units),
                "binding_nonce": str(binding[1]),
            })
    if len(manifest_entries) != active_expected:
        raise ReconciliationError("INCOMPLETE_POSITIVE_ENTITLEMENTS")
    if sum(int(row["units"]) for row in manifest_entries) != current_supply:
        raise ReconciliationError("ENTITLEMENTS_NOT_CONSERVED")
    try:
        expected_manifest = manifest_v1.build(h, manifest_entries)
    except (manifest_v1.ManifestError, TypeError, KeyError, ValueError) as exc:
        raise ReconciliationError("INVALID_RECONSTRUCTED_MANIFEST") from exc
    # A proposed manifest MUST equal the independent calculation. Valid Merkle
    # proofs for only selected users cannot evade this complete-set comparison.
    if not manifest_v1.verify_manifest(operator_manifest):
        raise ReconciliationError("INVALID_OPERATOR_MANIFEST")
    if operator_manifest != expected_manifest:
        raise ReconciliationError("OPERATOR_MANIFEST_DISAGREEMENT")

    diagnostic = hashlib.sha256(
        b"METORAH_REPLAY_DIAGNOSTIC_V1\x00"
        + json.dumps({
            "manifest_digest": expected_manifest["manifest_digest"],
            "event_count": len(events),
            "historical_holder_count": n,
            "active_holder_count": active,
            "issued": str(issued), "burned": str(burned),
        }, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "metorah-entitlement-reconciliation-v1",
        "status": "COMPLETE_RELATIVE_TO_SUPPLIED_DATA_UNAUTHENTICATED",
        "manifest_digest": expected_manifest["manifest_digest"],
        "merkle_root": expected_manifest["merkle_root"],
        "event_count": len(events),
        "binding_event_count": binding_events,
        "historical_holder_count": n,
        "active_holder_count": active,
        "zero_balance_tombstones": n - active,
        "issued_units": str(issued),
        "burned_units": str(burned),
        "total_supply_units": str(current_supply),
        "diagnostic_sha256_not_proof": diagnostic,
        "independent_source_finality_verified": False,
        "registry_storage_proofs_verified": False,
        "complete_event_history_cryptographically_verified": False,
        "beneficiary_signatures_verified": False,
        "can_activate": False,
        "can_claim": False,
        "warning": (
            "Completeness holds only relative to supplied frozen registry and "
            "supplied events. Source chain, storage proofs, complete event "
            "history and user signatures have NOT been independently authenticated."
        ),
    }
