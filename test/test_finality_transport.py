"""Transport and CLI safety without a single live RPC/network request."""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.finality.http_rpc import HttpJsonRpc, NoRedirects
from tools.finality.substrate import FinalityObservationError
from tools.finality.acquire import main


class Response:
    status = 200
    def __init__(self, data: bytes):
        self.data = data
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def read(self, n):
        return self.data[:n]


class Opener:
    def __init__(self, data):
        self.data = data
        self.requests = []
    def open(self, req, timeout=None):
        self.requests.append((req, timeout))
        return Response(self.data)


class TransportTests(unittest.TestCase):
    def test_refuse_insecure_remote_http_and_auth_in_url(self):
        for url in (
            "http://remote.example/rpc", "http://10.1.1.1", "ftp://127.0.0.1",
            "https://user:secret@example.org", "https://example.org?token=abc",
            "https://example.org#frag", "https://example.org/path",
        ):
            with self.subTest(url=url), self.assertRaises(FinalityObservationError):
                HttpJsonRpc(url)

    def test_reject_wrong_rpc_ids_and_duplicate_json_fields(self):
        rpc = HttpJsonRpc("http://127.0.0.1:9933")
        for payload, code in (
            (b'{"jsonrpc":"2.0","id":4,"result":"0x"}', "MISMATCHED_RPC_ENVELOPE"),
            (b'{"jsonrpc":"2.0","id":1,"result":"0x","result":"0x"}', "DUPLICATE_JSON_FIELD"),
            (b'{"jsonrpc":"2.0","id":1,"result":null,"error":null}', "MISMATCHED_RPC_ENVELOPE"),
        ):
            rpc._seq = 0
            rpc._opener = Opener(payload)
            with self.subTest(payload=payload), self.assertRaises(FinalityObservationError) as exc:
                rpc.call("chain_getFinalizedHead", [])
            self.assertEqual(exc.exception.code, code)

    def test_read_only_rpc_body_is_explicit_and_bounded(self):
        rpc = HttpJsonRpc("http://localhost:9933", timeout=2)
        op = Opener(b'{"jsonrpc":"2.0","id":1,"result":"0x1234"}')
        rpc._opener = op
        self.assertEqual(rpc.call("chain_getHeader", ["0x01"]), "0x1234")
        request, timeout = op.requests[0]
        self.assertEqual(timeout, 2)
        self.assertEqual(request.get_method(), "POST")
        body = json.loads(request.data)
        self.assertEqual(body["method"], "chain_getHeader")
        self.assertEqual(body["params"], ["0x01"])
        self.assertNotIn("author_submitExtrinsic", request.data.decode())

    def test_unapproved_rpc_method_is_rejected_without_network(self):
        rpc = HttpJsonRpc("https://example.org")
        with self.assertRaises(FinalityObservationError) as exc:
            rpc.call("author_submitExtrinsic", ["0x00"])
        self.assertEqual(exc.exception.code, "UNAUTHORIZED_RPC_METHOD")

    def test_empty_or_broken_response_not_trusted(self):
        rpc = HttpJsonRpc("http://localhost")
        rpc._opener = Opener(b'{"broken":')
        with self.assertRaises(FinalityObservationError) as exc:
            rpc.call("chain_getFinalizedHead", [])
        self.assertEqual(exc.exception.code, "INVALID_RPC_JSON")

    def test_rpc_error_envelope_fails_closed(self):
        rpc = HttpJsonRpc("http://localhost")
        rpc._opener = Opener(b'{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"unavailable"}}')
        with self.assertRaises(FinalityObservationError) as exc:
            rpc.call("chain_getFinalizedHead", [])
        self.assertEqual(exc.exception.code, "RPC_ERROR_RESPONSE")

    def test_report_cannot_be_created_without_explicit_network_optin(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "never-created.json"
            code = main([
                "--rpc-url", "https://example.org",
                "--expected-genesis", "0x" + "11"*32,
                "--checkpoint", "0x" + "22"*32,
                "--output", str(path),
            ])
            self.assertEqual(code, 2)
            self.assertFalse(path.exists())

    def test_external_redirects_rejected(self):
        redirects = NoRedirects()
        with self.assertRaises(FinalityObservationError):
            redirects.redirect_request(None, None, 302, "new endpoint", {}, "https://elsewhere.org")


if __name__ == "__main__":
    unittest.main()
