#!/usr/bin/env python3
"""Explicit opt-in: acquire hash-pinned raw storage only with cross-RPC quorum.

No network without --enable-network. Never cryptographically authenticates
consensus finality or upgrades acquired bytes to proof/claim authority.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.finality.http_rpc import HttpJsonRpc
from tools.finality.quorum import (
    MultiRPC, Provider, QuorumError, ResumableAcquisition,
)
from tools.finality.substrate import FinalityObservationError

MAX_CONFIG_BYTES = 256 * 1024


def _no_duplicate_keys(pairs):
    doc = {}
    for k, v in pairs:
        if k in doc:
            raise QuorumError("DUPLICATE_CONFIGURATION_KEY")
        doc[k] = v
    return doc


def _load(path: Path):
    if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
        raise QuorumError("INVALID_CONFIGURATION_FILE")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, ValueError) as exc:
        raise QuorumError("INVALID_CONFIGURATION_JSON") from exc


def _providers(doc):
    if type(doc) is not dict or set(doc) != {"operators"} or type(doc["operators"]) is not list:
        raise QuorumError("INVALID_PROVIDER_CONFIGURATION")
    result = []
    for item in doc["operators"]:
        if type(item) is not dict or set(item) != {"provider_id", "operator_id", "url"}:
            raise QuorumError("INVALID_PROVIDER_CONFIGURATION")
        result.append(Provider(
            provider_id=item["provider_id"],
            operator_id=item["operator_id"],
            reader=HttpJsonRpc(item["url"]),
        ))
    return result


def _write_new(path: Path, data: dict) -> None:
    """Write as atomic new-only file; existing reports cannot be overwritten."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=".metorah-report-", suffix=".tmp", delete=False,
        ) as fh:
            temporary = Path(fh.name)
            json.dump(data, fh, sort_keys=True, indent=2, allow_nan=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.link(temporary, path)
    except FileExistsError as exc:
        raise QuorumError("REPORT_ALREADY_EXISTS") from exc
    except OSError as exc:
        raise QuorumError("REPORT_WRITE_FAILED") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only multi-RPC UNAUTHENTICATED storage acquisition")
    parser.add_argument("--enable-network", action="store_true", help="mandatory explicit opt-in to RPC requests")
    parser.add_argument("--providers", type=Path, required=True, help="JSON operators and HTTPS endpoints")
    parser.add_argument("--storage-keys", type=Path, required=True, help="JSON array, ascending hex storage keys")
    parser.add_argument("--expected-genesis", required=True, help="independently configured genesis hash")
    parser.add_argument("--checkpoint", required=True, help="exact source block hash, not a height")
    parser.add_argument("--journal", type=Path, required=True, help="resumable checkpoint-bound journal")
    parser.add_argument("--output", type=Path, required=True, help="new-only read-only diagnostic JSON")
    parser.add_argument("--min-quorum", type=int, default=2)
    parser.add_argument("--max-head-delta", type=int, default=2)
    parser.add_argument("--max-finalized-lag", type=int, default=256)
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args(argv)

    if not args.enable_network:
        print("FAIL CLOSED: --enable-network not supplied, zero RPC requests made.", file=sys.stderr)
        return 2
    try:
        inputs = {args.providers.resolve(), args.storage_keys.resolve(), args.journal.resolve()}
        if args.output.resolve() in inputs or args.journal.resolve() in {
            args.providers.resolve(), args.storage_keys.resolve(),
        }:
            raise QuorumError("INPUT_OUTPUT_PATH_COLLISION")
        if args.output.exists() or args.output.is_symlink():
            raise QuorumError("REPORT_ALREADY_EXISTS")
        providers = _providers(_load(args.providers))
        keys = _load(args.storage_keys)
        quorum = MultiRPC(
            providers, expected_genesis_hash=args.expected_genesis,
            pinned_block_hash=args.checkpoint, min_quorum=args.min_quorum,
            max_head_delta=args.max_head_delta, max_finalized_lag=args.max_finalized_lag,
        )
        report = ResumableAcquisition(quorum, keys, args.journal, batch_size=args.batch_size).run()
        _write_new(args.output, report)
    except (QuorumError, FinalityObservationError, OSError) as e:
        name = getattr(e, "code", "LOCAL_IO_FAILURE")
        print(f"FAIL CLOSED: {name}. No authorized migration produced.", file=sys.stderr)
        return 2
    print("MULTI_RPC_STORAGE_CONSISTENT_UNAUTHENTICATED; can_activate=false; can_claim=false",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
