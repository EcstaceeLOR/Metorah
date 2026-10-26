import unittest
from tools.destination.indexer import (
    Broadcaster, DestinationConfig, DestinationError, DestinationIndexer,
    DestinationProjection, FinalityPending, IndexedEvent,
)

def h(number):
    return "0x" + f"{number:064x}"

LEDGER = "0x" + "11" * 20
ESCROW = "0x" + "22" * 20
TOPIC = h(10)

class FakeRPC:
    def __init__(self):
        self.head = 16
        self.blocks = {
            n: {"hash": h(n + 100), "parentHash": h(n + 99)}
            for n in range(17)
        }
        self.logs = []
        self.receipt = None
        self.simulation_error = False

    def call(self, method, params):
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            return self.blocks.get(int(params[0], 16))
        if method == "eth_getLogs":
            a, b = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
            return [x for x in self.logs if a <= int(x["blockNumber"], 16) <= b]
        if method == "eth_getTransactionReceipt":
            return self.receipt
        if method == "eth_call":
            if self.simulation_error:
                raise RuntimeError("revert")
            return "0x"
        if method == "eth_estimateGas":
            return "0x10000"
        if method == "eth_sendRawTransaction":
            return h(50)
        raise AssertionError(method)


class DestinationTests(unittest.TestCase):
    def setUp(self):
        self.rpc = FakeRPC()
        self.config = DestinationConfig(1, LEDGER, ESCROW, confirmations=3, max_batch=5)
        self.projection = DestinationProjection()

    def test_broadcast_does_not_mark_claim_settled(self):
        broadcaster = Broadcaster(self.rpc, self.config, lambda tx: "0xabcdef")
        result = broadcaster.broadcast({"from": LEDGER, "to": LEDGER, "data": "0x1234", "value": "0x0"})
        self.assertEqual(result["state"], "submitted")
        self.assertFalse(result["settled"])
        self.assertEqual(result["tx_hash"], h(50))

    def test_simulation_revert_prevents_broadcast(self):
        self.rpc.simulation_error = True
        broadcaster = Broadcaster(self.rpc, self.config, lambda tx: self.fail("should not sign"))
        with self.assertRaisesRegex(DestinationError, "broadcast_failed"):
            broadcaster.broadcast({"from": LEDGER, "to": LEDGER, "data": "0x1234"})

    def test_destination_allowlist_and_chain_id(self):
        broadcaster = Broadcaster(self.rpc, self.config, lambda tx: "0xabcd")
        with self.assertRaisesRegex(DestinationError, "unauthorized_destination"):
            broadcaster.broadcast({"from": LEDGER, "to": "0x" + "33"*20, "data": "0x1234"})
        self.rpc.call = lambda method, params: "0x2" if method == "eth_chainId" else "0x0"
        with self.assertRaisesRegex(DestinationError, "chain_id_mismatch"):
            broadcaster.broadcast({"from": LEDGER, "to": LEDGER, "data": "0x1234"})

    def test_receipt_requires_success_and_confirmations_and_canonical_block(self):
        broadcaster = Broadcaster(self.rpc, self.config, lambda tx: "0x1234")
        with self.assertRaises(FinalityPending):
            broadcaster.confirmed_receipt(h(50))
        self.rpc.receipt = {"status": "0x1", "blockNumber": "0xf", "blockHash": h(115)}
        with self.assertRaisesRegex(FinalityPending, "confirmation_depth"):
            broadcaster.confirmed_receipt(h(50))
        self.rpc.head = 19
        with self.assertRaisesRegex(FinalityPending, "receipt_block_reorganized"):
            self.rpc.receipt["blockHash"] = h(1)
            broadcaster.confirmed_receipt(h(50))
        self.rpc.receipt["blockHash"] = h(115)
        self.assertEqual(broadcaster.confirmed_receipt(h(50)), self.rpc.receipt)
        self.rpc.receipt["status"] = "0x0"
        with self.assertRaisesRegex(DestinationError, "transaction_reverted"):
            broadcaster.confirmed_receipt(h(50))

    def test_indexer_waits_for_confirmation_depth_and_paginates(self):
        indexer = DestinationIndexer(self.rpc, self.config, self.projection)
        self.assertEqual(indexer.scan()["cursor"], 4)
        self.assertEqual(indexer.scan()["cursor"], 9)
        self.assertEqual(indexer.scan()["cursor"], 13)
        self.assertEqual(indexer.scan()["cursor"], 13)

    def test_canonical_event_and_reorg_replay_correct_derived_state(self):
        self.rpc.logs = [{
            "blockNumber": "0x2", "blockHash": h(102), "transactionHash": h(60),
            "logIndex": "0x0", "address": LEDGER, "topics": [TOPIC], "data": "0x",
        }]
        indexer = DestinationIndexer(self.rpc, self.config, self.projection)
        indexer.scan()
        self.assertEqual(len(self.projection.events_by_topic(TOPIC)), 1)
        original = self.projection.reconcile_claims(TOPIC, {"claim-1": 100}, lambda e: ("claim-1", 100))
        self.assertTrue(original["reconciled"])
        self.rpc.blocks[2] = {"hash": h(999), "parentHash": h(101)}
        self.rpc.blocks[3] = {"hash": h(1000), "parentHash": h(999)}
        self.rpc.blocks[4] = {"hash": h(1001), "parentHash": h(1000)}
        self.rpc.logs = []
        indexer.scan()
        self.assertEqual(self.projection.events_by_topic(TOPIC), [])
        corrected = self.projection.reconcile_claims(TOPIC, {"claim-1": 100}, lambda e: ("claim-1", 100))
        self.assertFalse(corrected["reconciled"])
        self.assertEqual(corrected["on_chain_total"], 0)

    def test_reorg_during_scan_does_not_mutate_projection(self):
        self.rpc.logs = [{
            "blockNumber": "0x2", "blockHash": h(900), "transactionHash": h(60),
            "logIndex": "0x0", "address": LEDGER, "topics": [TOPIC], "data": "0x",
        }]
        with self.assertRaisesRegex(FinalityPending, "reorg_during_scan"):
            DestinationIndexer(self.rpc, self.config, self.projection).scan()
        self.assertEqual(self.projection.cursor, -1)

    def test_reconciliation_rejects_duplicate_settlement_events(self):
        e = IndexedEvent(1, 2, h(102), h(60), 0, LEDGER, TOPIC, (TOPIC,), "0x")
        self.projection.replace_from(2, [(2, h(102))], [e])
        self.assertFalse(self.projection.reconcile_claims(TOPIC, {"claim": 5}, lambda e: ("claim", 6))["reconciled"])
        e2 = IndexedEvent(1, 2, h(102), h(61), 1, LEDGER, TOPIC, (TOPIC,), "0x")
        self.projection.replace_from(2, [(2, h(102))], [e, e2])
        with self.assertRaisesRegex(DestinationError, "invalid_or_duplicate_claim_event"):
            self.projection.reconcile_claims(TOPIC, {"claim": 5}, lambda e: ("claim", 5))

if __name__ == "__main__":
    unittest.main()
