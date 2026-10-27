"""Finality-gated destination-chain broadcaster and reorg-aware event projection.

JSON-RPC provider is injected; no transaction is signed without an external signer.
All persisted projections are derived from canonical block hashes, never HTTP success.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


class DestinationError(RuntimeError):
    pass


class FinalityPending(DestinationError):
    pass


def hex_int(value: str | int) -> int:
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)
    raise DestinationError("invalid_rpc_quantity")


def normalize_hash(value: str) -> str:
    if not isinstance(value, str) or len(value) != 66 or not value.startswith("0x"):
        raise DestinationError("invalid_hash")
    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        raise DestinationError("invalid_hash") from exc
    return value.lower()


def normalize_address(value: str) -> str:
    if not isinstance(value, str) or len(value) != 42 or not value.startswith("0x"):
        raise DestinationError("invalid_address")
    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        raise DestinationError("invalid_address") from exc
    return value.lower()


@dataclass(frozen=True)
class DestinationConfig:
    chain_id: int
    ledger_address: str
    settlement_address: str
    confirmations: int = 12
    max_batch: int = 500

    def __post_init__(self) -> None:
        if self.chain_id <= 0 or self.confirmations < 1 or not 1 <= self.max_batch <= 2000:
            raise DestinationError("invalid_destination_config")
        normalize_address(self.ledger_address)
        normalize_address(self.settlement_address)


class Broadcaster:
    """Simulate, sign externally, and broadcast; submission is NEVER settlement."""

    def __init__(self, rpc: Any, config: DestinationConfig, signer: Callable[[dict], str]):
        self.rpc, self.config, self.signer = rpc, config, signer

    def broadcast(self, transaction: dict) -> dict:
        if hex_int(self.rpc.call("eth_chainId", [])) != self.config.chain_id:
            raise DestinationError("chain_id_mismatch")
        to = normalize_address(transaction.get("to"))
        if to not in (normalize_address(self.config.ledger_address), normalize_address(self.config.settlement_address)):
            raise DestinationError("unauthorized_destination")
        if not transaction.get("from") or not transaction.get("data"):
            raise DestinationError("missing_transaction_fields")
        if hex_int(transaction.get("value", "0x0")) != 0:
            raise DestinationError("native_value_forbidden")
        try:
            self.rpc.call("eth_call", [transaction, "pending"])
            estimated = hex_int(self.rpc.call("eth_estimateGas", [transaction]))
            if estimated <= 0:
                raise DestinationError("invalid_gas_estimate")
            signed = self.signer({**transaction, "gas": hex(estimated)})
            if not isinstance(signed, str) or not signed.startswith("0x"):
                raise DestinationError("invalid_signed_transaction")
            tx_hash = normalize_hash(self.rpc.call("eth_sendRawTransaction", [signed]))
        except DestinationError:
            raise
        except Exception as exc:
            raise DestinationError("broadcast_failed") from exc
        return {"tx_hash": tx_hash, "state": "submitted", "settled": False}

    def confirmed_receipt(self, tx_hash: str) -> dict:
        tx_hash = normalize_hash(tx_hash)
        if hex_int(self.rpc.call("eth_chainId", [])) != self.config.chain_id:
            raise DestinationError("chain_id_mismatch")
        receipt = self.rpc.call("eth_getTransactionReceipt", [tx_hash])
        if receipt is None:
            raise FinalityPending("transaction_not_mined")
        if hex_int(receipt["status"]) != 1:
            raise DestinationError("transaction_reverted")
        block_number = hex_int(receipt["blockNumber"])
        head = hex_int(self.rpc.call("eth_blockNumber", []))
        if head < block_number + self.config.confirmations:
            raise FinalityPending("confirmation_depth_not_met")
        block = self.rpc.call("eth_getBlockByNumber", [hex(block_number), False])
        if block is None or normalize_hash(block["hash"]) != normalize_hash(receipt["blockHash"]):
            raise FinalityPending("receipt_block_reorganized")
        return receipt


@dataclass(frozen=True)
class IndexedEvent:
    chain_id: int
    block_number: int
    block_hash: str
    tx_hash: str
    log_index: int
    contract: str
    topic0: str
    topics: tuple[str, ...]
    data: str


@dataclass
class DestinationProjection:
    """Rebuildable, canonical-only view. No immutable evidence is edited."""

    blocks: dict[int, str] = field(default_factory=dict)
    events: dict[tuple[str, int], IndexedEvent] = field(default_factory=dict)
    cursor: int = -1

    def replace_from(self, from_block: int, new_blocks: list[tuple[int, str]],
                     new_events: list[IndexedEvent]) -> None:
        for number in list(self.blocks):
            if number >= from_block:
                del self.blocks[number]
        for key, event in list(self.events.items()):
            if event.block_number >= from_block:
                del self.events[key]
        for number, block_hash in new_blocks:
            self.blocks[number] = normalize_hash(block_hash)
        for event in new_events:
            if self.blocks.get(event.block_number) != event.block_hash:
                raise DestinationError("noncanonical_event")
            key = (event.tx_hash, event.log_index)
            if key in self.events:
                raise DestinationError("duplicate_log")
            self.events[key] = event
        self.cursor = max(self.blocks, default=-1)

    def events_by_topic(self, topic: str) -> list[IndexedEvent]:
        return sorted((e for e in self.events.values() if e.topic0 == topic),
                      key=lambda e: (e.block_number, e.log_index))

    def reconcile_claims(self, claim_topic: str, expected_claims: dict[str, int],
                         decode_claim: Callable[[IndexedEvent], tuple[str, int]]) -> dict:
        """Compare claims with canonical settlement events; never infer success from tx submission."""
        actual: dict[str, int] = {}
        for event in self.events_by_topic(claim_topic):
            claim_id, amount = decode_claim(event)
            if amount <= 0 or claim_id in actual:
                raise DestinationError("invalid_or_duplicate_claim_event")
            actual[claim_id] = amount
        mismatches = {
            key: {"expected": amount, "on_chain": actual.get(key, 0)}
            for key, amount in expected_claims.items() if actual.get(key) != amount
        }
        unexpected = {key: amount for key, amount in actual.items() if key not in expected_claims}
        return {
            "reconciled": not mismatches and not unexpected,
            "expected_total": sum(expected_claims.values()),
            "on_chain_total": sum(actual.values()),
            "mismatches": mismatches,
            "unexpected": unexpected,
            "confirmed_claims": actual,
            "cursor": self.cursor,
        }


class DestinationIndexer:
    def __init__(self, rpc: Any, config: DestinationConfig, projection: DestinationProjection, store: Any = None):
        self.rpc, self.config, self.projection, self.store = rpc, config, projection, store

    def scan(self, from_block: int = 0) -> dict:
        if hex_int(self.rpc.call("eth_chainId", [])) != self.config.chain_id:
            raise DestinationError("chain_id_mismatch")
        head = hex_int(self.rpc.call("eth_blockNumber", []))
        safe_head = head - self.config.confirmations
        if safe_head < from_block:
            return {"cursor": self.projection.cursor, "indexed": 0, "pending": True}
        # Verify all existing canonical hashes, including the cursor's ancestry.
        divergence = None
        for number in sorted(self.projection.blocks):
            if number > safe_head:
                divergence = number
                break
            block = self.rpc.call("eth_getBlockByNumber", [hex(number), False])
            if block is None or normalize_hash(block["hash"]) != self.projection.blocks[number]:
                divergence = number
                break
        start = min(divergence, self.projection.cursor + 1) if divergence is not None else self.projection.cursor + 1
        start = max(from_block, start)
        if start > safe_head:
            return {"cursor": self.projection.cursor, "indexed": 0, "pending": False}
        stop = min(safe_head, start + self.config.max_batch - 1)
        blocks: list[tuple[int, str]] = []
        for number in range(start, stop + 1):
            block = self.rpc.call("eth_getBlockByNumber", [hex(number), False])
            if block is None:
                raise FinalityPending("canonical_block_missing")
            block_hash = normalize_hash(block["hash"])
            if number > 0 and number - 1 in dict(blocks):
                if normalize_hash(block["parentHash"]) != blocks[-1][1]:
                    raise FinalityPending("block_parent_mismatch")
            elif number > 0 and number - 1 in self.projection.blocks and start != divergence:
                if normalize_hash(block["parentHash"]) != self.projection.blocks[number - 1]:
                    raise FinalityPending("block_parent_mismatch")
            blocks.append((number, block_hash))
        addresses = [normalize_address(self.config.ledger_address), normalize_address(self.config.settlement_address)]
        logs = self.rpc.call("eth_getLogs", [{"fromBlock": hex(start), "toBlock": hex(stop), "address": addresses}])
        block_map = dict(blocks)
        events: list[IndexedEvent] = []
        for log in logs:
            number = hex_int(log["blockNumber"])
            block_hash = normalize_hash(log["blockHash"])
            if log.get("removed") or block_map.get(number) != block_hash:
                raise FinalityPending("reorg_during_scan")
            contract = normalize_address(log["address"])
            if contract not in addresses:
                raise DestinationError("unexpected_log_address")
            topics = tuple(normalize_hash(t) for t in log["topics"])
            if not topics:
                raise DestinationError("missing_event_signature")
            events.append(IndexedEvent(
                self.config.chain_id, number, block_hash, normalize_hash(log["transactionHash"]),
                hex_int(log["logIndex"]), contract, topics[0], topics, log["data"]
            ))
        # Recheck the batch tip before committing a canonical projection.
        tip = self.rpc.call("eth_getBlockByNumber", [hex(stop), False])
        if tip is None or normalize_hash(tip["hash"]) != blocks[-1][1]:
            raise FinalityPending("reorg_during_scan")
        if self.store is not None:
            self.projection = self.store.replace_from(start, blocks, events)
        else:
            self.projection.replace_from(start, blocks, events)
        return {"cursor": self.projection.cursor, "indexed": len(events), "pending": stop < safe_head}
