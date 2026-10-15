#!/usr/bin/env python3
"""Regenerate *synthetic* four-language golden vectors for Metorah V1.

Only the normative canonical encoder is used. This is an offline compatibility
fixture, NEVER finalized chain evidence. --check compares tracked bytes exactly.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import canonical as v1

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "fixtures/manifest-v1/golden.json"
SIZES = (1, 2, 3, 257)


def fixture_case(n: int) -> dict:
    header = {
        "source_genesis": "0x" + "11" * 32,
        "finalized_block_hash": "0x" + "22" * 32,
        "finalized_block_number": "12345",
        "finalized_state_root": "0x" + "33" * 32,
        "source_contract": "0x" + "44" * 32,
        "source_code_hash": "0x" + "55" * 32,
        "migration_id": "0x" + "66" * 32,
        "asset_id": "0x" + "77" * 32,
        "destination_chain_id": "31337",
        "destination_contract": "0x" + "88" * 20,
        "entitlement_kind": 1,
        "decimals": 12,
        "historical_holder_count": n + (n - 1) // 8 + 1,
        "active_holder_count": n,
        "total_units": str(sum((i + 1) * (i + 11) for i in range(n))),
    }
    entries = [
        {
            "leaf_index": i,
            "historical_index": i + i // 8,
            "source_account": f"0x{i + 1:064x}",
            "beneficiary": f"0x{i + 1001:040x}",
            "units": str((i + 1) * (i + 11)),
            "binding_nonce": str(1 + i % 3),
        }
        for i in range(n)
    ]
    manifest = v1.build(header, entries)
    hd = v1.header_hash(header)
    samples = [
        {
            "index": i,
            "leaf_hash": "0x" + v1.leaf_hash(hd, entries[i], header).hex(),
            "proof": v1.proof_for(manifest, i),
        }
        for i in sorted({0, n - 1})
    ]
    for s in samples:
        if not v1.verify_proof(header, entries[s["index"]], s["proof"], manifest["merkle_root"]):
            raise RuntimeError("Internal canonical proof failure")
    return {
        "holders": n,
        "historical_holder_count": header["historical_holder_count"],
        "total_units": header["total_units"],
        "header_hash": manifest["header_hash"],
        "merkle_root": manifest["merkle_root"],
        "manifest_digest": manifest["manifest_digest"],
        "samples": samples,
    }


def render() -> str:
    body = {
        "schema_version": "metorah-golden-v1",
        "assurance": "E1_ENCODING_ONLY",
        "source_chain_authenticated": False,
        "can_activate": False,
        "can_claim": False,
        "cases": [fixture_case(n) for n in SIZES],
    }
    return json.dumps(body, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail unless checked-in bytes match")
    args = parser.parse_args()
    text = render()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != text:
            print("Golden vectors changed; run python tools/manifest/generate_golden.py and review.", file=sys.stderr)
            return 2
        print(f"Golden fixture matches normative Python encoder: {len(SIZES)} cases")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
