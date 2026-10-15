#!/usr/bin/env python3
"""Opt-in network acquisition of UNAUDITED Substrate finalized header observations.

Never calls a network unless user explicitly passes --enable-network and a
caller-provided endpoint, expected genesis and exact hash. Never sends tokens,
signs transactions, certifies finalized headers or authenticates source storage.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.finality.http_rpc import HttpJsonRpc
from tools.finality.substrate import FinalityObservationError, observe


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Acquire UNAUTHENTICATED finalized-header observations")
    parser.add_argument("--enable-network", action="store_true", help="explicitly allow read-only RPC requests")
    parser.add_argument("--rpc-url", required=True, help="operator-specified HTTPS RPC or loopback HTTP")
    parser.add_argument("--expected-genesis", required=True, help="independently verified expected genesis hash")
    parser.add_argument("--checkpoint", required=True, help="exact source block hash, not a height or 'latest'")
    parser.add_argument("--max-finalized-lag", type=int, default=256)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if not args.enable_network:
        print("FAIL CLOSED: opt-in --enable-network is required. No RPC contacted.", file=sys.stderr)
        return 2
    if args.output.is_dir():
        print("Output must be a JSON file, not a directory.", file=sys.stderr)
        return 2
    try:
        reader = HttpJsonRpc(args.rpc_url)
        report = observe(
            reader,
            expected_genesis_hash=args.expected_genesis,
            pinned_block_hash=args.checkpoint,
            max_finalized_lag=args.max_finalized_lag,
        )
    except FinalityObservationError as error:
        print(f"Checkpoint rejected: {error.code}. No report written.", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Checkpoint observation recorded (UNAUTHENTICATED, cannot activate).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
