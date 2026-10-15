#!/usr/bin/env python3
"""Opt-in, read-only collection of UNVERIFIED Substrate trie proof nodes.

Output is input to an independently executed, offline Rust sp-trie verifier.
Even verified trie membership cannot authorize a migration without trusted
consensus-finalized header, runtime metadata, exhaustive holder enumeration.
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
from tools.trie_verifier.collector import collect


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Acquire UNAUTHENTICATED pinned trie proof")
    parser.add_argument("--enable-network", action="store_true",
                        help="explicit opt-in; read-only authenticated TLS requests")
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--expected-genesis", required=True)
    parser.add_argument("--checkpoint", required=True,
                        help="exact pinned finalized-block hash from independent configuration")
    parser.add_argument("--state-version", type=int, required=True,
                        help="0 or 1 from externally verified runtime metadata")
    parser.add_argument("--storage-keys", nargs="+", required=True,
                        help="hex keys from authenticated storage metadata, sorted ascending")
    parser.add_argument("--max-finalized-lag", type=int, default=256)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if not args.enable_network:
        print("FAIL CLOSED: --enable-network required. No RPC was contacted.", file=sys.stderr)
        return 2
    try:
        reader = HttpJsonRpc(args.rpc_url)
        reported = observe(reader,
                           expected_genesis_hash=args.expected_genesis,
                           pinned_block_hash=args.checkpoint,
                           max_finalized_lag=args.max_finalized_lag)
        bundle = collect(reader, reported, args.storage_keys,
                         state_version=args.state_version)
    except FinalityObservationError as error:
        print(f"Read-proof collection failed: {error.code}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print("RAW UNAUTHENTICATED read-proof saved. Must verify with independent sp-trie and trusted root.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
