"""Local mocked RPC tests. No external node or live Portaldot capability claimed."""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("metorah_portaldot_probe", ROOT / "local_model/portaldot_probe.py")
PROBE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROBE
SPEC.loader.exec_module(PROBE)

GENESIS = "0x" + "1" * 64
OTHER = "0x" + "2" * 64
FINAL = "0x" + "a" * 64
FAKE = {
    "system_chain": "Example not Portaldot V3",
    "system_name": "fake",
    "system_version": "0.0.1",
    "chain_getBlockHash": GENESIS,
    "chain_getFinalizedHead": FINAL,
    "chain_getHeader": {"number": "0x10", "stateRoot": "0x" + "b" * 64},
    "state_getRuntimeVersion": {"specName": "fake", "specVersion": 1},
    "rpc_methods": {"methods": ["contracts_call", "eth_chainId", "eth_getBlockByNumber"]},
    "eth_chainId": "0xa",
    "state_getMetadata": "0x1234",
}


class FakeSocket:
    def __init__(self, values=None, bad_id=False):
        self.values = dict(FAKE if values is None else values)
        self.bad_id = bad_id
        self.methods = []
        self.last = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def send(self, msg):
        self.last = json.loads(msg)
        self.methods.append(self.last["method"])

    async def recv(self):
        msg = {"jsonrpc": "2.0", "id": 999 if self.bad_id else self.last["id"],
               "result": self.values.get(self.last["method"])}
        return json.dumps(msg)


class ProbeTests(unittest.TestCase):
    def run_probe(self, fake=None, **kwargs):
        sock = fake or FakeSocket()
        result = asyncio.run(PROBE.collect(
            "ws://127.0.0.1:9944", connector=lambda *args, **kw: sock, **kwargs
        ))
        self.assertFalse(result["source_chain_authenticated"])
        self.assertFalse(result["portaldot_v3_qualified"])
        self.assertFalse(result["wasm_pallet_contracts_verified"])
        self.assertFalse(result["evm_deployment_verified"])
        self.assertFalse(result["may_deploy_or_claim"])
        return result, sock

    def test_observed_but_not_qualified(self):
        report, _ = self.run_probe()
        self.assertEqual(report["status"], "OBSERVED_UNPINNED")

    def test_user_supplied_genesis_is_not_official_qualification(self):
        report, _ = self.run_probe(expected_genesis=GENESIS)
        self.assertEqual(report["status"], "OBSERVED_MATCHES_CALLER_GENESIS_NOT_V3_VERIFIED")

    def test_wrong_genesis_is_blocked(self):
        report, _ = self.run_probe(expected_genesis=OTHER)
        self.assertEqual(report["status"], "BLOCKED_GENESIS_MISMATCH")

    def test_invalid_expected_genesis_rejected(self):
        report, _ = self.run_probe(expected_genesis="not-a-hash")
        self.assertEqual(report["status"], "BLOCKED_INVALID_EXPECTED_GENESIS")

    def test_no_signing_or_broadcast_rpc_methods(self):
        _, sock = self.run_probe()
        self.assertNotIn("author_submitExtrinsic", sock.methods)
        self.assertNotIn("eth_sendRawTransaction", sock.methods)
        self.assertNotIn("eth_sendTransaction", sock.methods)
        self.assertIn("chain_getBlockHash", sock.methods)

    def test_rpc_method_list_does_not_prove_pallet_is_deployable(self):
        report, _ = self.run_probe()
        self.assertEqual(report["observed"]["rpc_contract_method_names"], ["contracts_call"])
        self.assertFalse(report["wasm_pallet_contracts_verified"])

    def test_metadata_content_not_dumped(self):
        report, _ = self.run_probe()
        self.assertEqual(report["observed"]["metadata_bytes"], 2)
        self.assertNotIn("state_getMetadata", report["observed"])

    def test_missing_runtime_is_incomplete(self):
        vals = dict(FAKE); vals["state_getRuntimeVersion"] = None
        report, _ = self.run_probe(fake=FakeSocket(vals))
        self.assertEqual(report["status"], "INCOMPLETE_RPC_EVIDENCE")

    def test_rpc_id_mismatch_is_rejected(self):
        report, _ = self.run_probe(fake=FakeSocket(bad_id=True))
        self.assertEqual(report["status"], "INCOMPLETE_RPC_EVIDENCE")
        self.assertIn("chain_getBlockHash", report["rpc_errors"])

    def test_disallow_plaintext_remote_rpc(self):
        self.assertFalse(PROBE.endpoint_is_allowed("ws://untrusted.example:9944"))
        self.assertTrue(PROBE.endpoint_is_allowed("wss://example.com"))
        self.assertTrue(PROBE.endpoint_is_allowed("ws://localhost:9944"))

    def test_embedded_credentials_and_query_rejected(self):
        self.assertFalse(PROBE.endpoint_is_allowed("wss://alice:password@example.com"))
        self.assertFalse(PROBE.endpoint_is_allowed("wss://example.com/ws?secret=abc"))
        self.assertFalse(PROBE.endpoint_is_allowed("ftp://example.com"))

    def test_reject_timeout_without_network(self):
        r, _ = self.run_probe(timeout=-1)
        self.assertEqual(r["status"], "BLOCKED_INVALID_TIMEOUT")

    def test_bad_url_fails_closed(self):
        r = asyncio.run(PROBE.collect("ws://evil.example"))
        self.assertEqual(r["status"], "BLOCKED_INVALID_ENDPOINT")


if __name__ == "__main__":
    unittest.main()
