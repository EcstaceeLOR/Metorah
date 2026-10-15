"""Explicit opt-in, READ-ONLY Substrate JSON-RPC HTTP transport.

Does not decide whether an endpoint belongs to Portaldot V3. Rejects redirects,
authenticators, unbounded responses, malformed/duplicate JSON keys, RPC errors
and all methods other than a minimal vetted read-only allowlist.
"""
from __future__ import annotations

import json
import ssl
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request
from urllib.error import HTTPError, URLError
from typing import Any

from .substrate import READ_ONLY_METHODS, FinalityObservationError

MAX_RESPONSE_BYTES = 1024 * 1024


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FinalityObservationError("RPC_REDIRECT_FORBIDDEN")


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise FinalityObservationError("DUPLICATE_JSON_FIELD")
        out[key] = value
    return out


class HttpJsonRpc:
    def __init__(self, url: str, *, timeout: float = 10.0):
        if not isinstance(url, str):
            raise FinalityObservationError("INVALID_RPC_URL")
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
        except ValueError as exc:
            raise FinalityObservationError("INVALID_RPC_URL") from exc
        if (
            parsed.scheme not in {"https", "http"}
            or not hostname or parsed.username is not None
            or parsed.password is not None
            or parsed.query or parsed.fragment
            or (parsed.path not in {"", "/"})
        ):
            raise FinalityObservationError("INVALID_RPC_URL")
        if parsed.scheme == "http" and hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise FinalityObservationError("INSECURE_REMOTE_RPC")
        if type(timeout) not in (int, float) or not 1 <= timeout <= 30:
            raise FinalityObservationError("INVALID_RPC_TIMEOUT")
        self.url = url
        self.timeout = timeout
        self._seq = 0
        self._opener = build_opener(NoRedirects())
        self._context = ssl.create_default_context()  # HTTPS verification by stdlib

    def call(self, method: str, params: list[Any]) -> Any:
        if method not in READ_ONLY_METHODS or type(params) is not list:
            raise FinalityObservationError("UNAUTHORIZED_RPC_METHOD")
        self._seq += 1
        req = Request(
            self.url,
            data=json.dumps(
                {"jsonrpc": "2.0", "id": self._seq, "method": method, "params": params},
                separators=(",", ":"),
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as response:
                if response.status != 200:
                    raise FinalityObservationError("RPC_HTTP_FAILURE")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except FinalityObservationError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise FinalityObservationError("RPC_UNAVAILABLE") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise FinalityObservationError("RPC_RESPONSE_TOO_LARGE")
        try:
            envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
        except FinalityObservationError:
            raise
        except (UnicodeError, ValueError) as exc:
            raise FinalityObservationError("INVALID_RPC_JSON") from exc
        if (
            not isinstance(envelope, dict)
            or envelope.get("jsonrpc") != "2.0"
            or type(envelope.get("id")) is not int
            or envelope["id"] != self._seq
            or set(envelope) - {"jsonrpc", "id", "result", "error"}
            or ("result" in envelope) == ("error" in envelope)
        ):
            raise FinalityObservationError("MISMATCHED_RPC_ENVELOPE")
        if "error" in envelope:
            raise FinalityObservationError("RPC_ERROR_RESPONSE")
        return envelope["result"]
