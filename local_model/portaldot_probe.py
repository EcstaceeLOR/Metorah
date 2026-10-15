"""Read-only Portaldot RPC observer. NOT a blockchain authenticity verifier.

Never sends transactions, calls wallets, signs data or executes node binaries.
Even matching a user-provided genesis ID does not qualify an endpoint as V3.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from websockets.asyncio.client import connect

H256_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
READS = (
    ("system_chain", []),
    ("system_name", []),
    ("system_version", []),
    ("chain_getBlockHash", [0]),
    ("chain_getFinalizedHead", []),
    ("state_getRuntimeVersion", []),
    ("rpc_methods", []),
    ("eth_chainId", []),
    ("state_getMetadata", []),
)


def endpoint_is_allowed(url: str) -> bool:
    try:
        u = urlsplit(url)
        if u.username or u.password or u.query or u.fragment:
            return False
        if u.scheme == "wss" and u.hostname:
            return True
        return u.scheme == "ws" and u.hostname in {"localhost", "127.0.0.1", "::1"}
    except (TypeError, ValueError):
        return False


def display_endpoint(url: str) -> str:
    try:
        u = urlsplit(url)
        return f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "") + (u.path or "")
    except (TypeError, ValueError):
        return "<invalid endpoint>"


async def collect(
    url: str,
    *,
    timeout: float = 4.0,
    expected_genesis: str | None = None,
    connector=connect,
) -> dict:
    result = {
        "tool": "metorah-portaldot-readonly-probe-v2",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "rpc_endpoint": display_endpoint(url),
        "read_only": True,
        "rpc_reachable": False,
        "observed": {},
        "rpc_errors": {},
        "status": "UNAVAILABLE",
        "source_chain_authenticated": False,
        "portaldot_v3_qualified": False,
        "wasm_pallet_contracts_verified": False,
        "evm_deployment_verified": False,
        "finality_cryptographically_verified": False,
        "may_deploy_or_claim": False,
        "warning": "RPC observation is not organizer-approved network identity, finality proof, WASM support, EVM deployment or asset safety.",
    }
    if not endpoint_is_allowed(url):
        result["status"] = "BLOCKED_INVALID_ENDPOINT"
        return result
    if type(timeout) not in (int, float) or not 0 < timeout <= 30:
        result["status"] = "BLOCKED_INVALID_TIMEOUT"
        return result
    if expected_genesis is not None and (
        not isinstance(expected_genesis, str) or not H256_RE.fullmatch(expected_genesis)
    ):
        result["status"] = "BLOCKED_INVALID_EXPECTED_GENESIS"
        return result

    ident = 0
    async def call(sock, method: str, params: list):
        nonlocal ident
        ident += 1
        await sock.send(json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": ident}))
        try:
            msg = json.loads(await asyncio.wait_for(sock.recv(), timeout))
            if not isinstance(msg, dict) or msg.get("id") != ident or msg.get("jsonrpc") != "2.0":
                raise ValueError("RPC_ID_OR_PROTOCOL_MISMATCH")
            if "error" in msg:
                result["rpc_errors"][method] = "RPC_METHOD_ERROR"
                return None
            return msg.get("result")
        except (asyncio.TimeoutError, ValueError, TypeError, json.JSONDecodeError):
            result["rpc_errors"][method] = "INVALID_OR_TIMEOUT_RESPONSE"
            return None

    try:
        async with asyncio.timeout(timeout * 15):
            async with connector(url, open_timeout=timeout, close_timeout=timeout, max_size=16 * 1024 * 1024) as sock:
                result["rpc_reachable"] = True
                for method, params in READS:
                    val = await call(sock, method, params)
                    if method == "state_getMetadata":
                        if isinstance(val, str) and val.startswith("0x"):
                            try:
                                data = bytes.fromhex(val[2:])
                                result["observed"]["metadata_sha256"] = hashlib.sha256(data).hexdigest()
                                result["observed"]["metadata_bytes"] = len(data)
                            except ValueError:
                                result["rpc_errors"][method] = "INVALID_METADATA_HEX"
                        continue
                    if method == "rpc_methods":
                        supported = val.get("methods") if isinstance(val, dict) else None
                        if isinstance(supported, list):
                            result["observed"]["rpc_contract_method_names"] = [
                                x for x in supported if isinstance(x, str) and x.startswith("contracts_")
                            ]
                            result["observed"]["rpc_evm_method_names"] = [
                                x for x in supported if isinstance(x, str) and x.startswith("eth_")
                            ]
                        continue
                    result["observed"][method] = val
                finalized = result["observed"].get("chain_getFinalizedHead")
                if isinstance(finalized, str) and H256_RE.fullmatch(finalized):
                    result["observed"]["chain_getHeader"] = await call(sock, "chain_getHeader", [finalized])
    except (Exception, asyncio.TimeoutError) as exc:
        result["rpc_errors"]["connection"] = type(exc).__name__
        if not result["rpc_reachable"]:
            return result

    genesis = result["observed"].get("chain_getBlockHash")
    finalized = result["observed"].get("chain_getFinalizedHead")
    runtime = result["observed"].get("state_getRuntimeVersion")
    if not (
        isinstance(genesis, str) and H256_RE.fullmatch(genesis)
        and isinstance(finalized, str) and H256_RE.fullmatch(finalized)
        and isinstance(runtime, dict)
    ):
        result["status"] = "INCOMPLETE_RPC_EVIDENCE"
    elif expected_genesis is None:
        result["status"] = "OBSERVED_UNPINNED"
    elif genesis.lower() != expected_genesis.lower():
        result["status"] = "BLOCKED_GENESIS_MISMATCH"
    else:
        result["status"] = "OBSERVED_MATCHES_CALLER_GENESIS_NOT_V3_VERIFIED"
    # No mode returns authenticated/qualified. Any matching genesis is self-supplied.
    return result


async def main(url: str, timeout: float, out: Path, expected_genesis: str | None = None) -> dict:
    report = await collect(url, timeout=timeout, expected_genesis=expected_genesis)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("RPC observation:", report["status"])
    print("No contract deployment or trusted finality verification was performed.")
    print("Report:", out)
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Read-only RPC inspection; no transactions or V3 qualification")
    p.add_argument("--url", default="ws://127.0.0.1:9944")
    p.add_argument("--timeout", type=float, default=4.0)
    p.add_argument("--expected-genesis", default=None, help="Trusted 0x-prefixed 32-byte genesis hash, obtained independently")
    p.add_argument("--output", type=Path, default=Path(__file__).parent / "artifacts" / "portaldot-probe.json")
    a = p.parse_args()
    outcome = asyncio.run(main(a.url, a.timeout, a.output, expected_genesis=a.expected_genesis))
    raise SystemExit(0 if outcome["status"].startswith("OBSERVED_") else 2)
