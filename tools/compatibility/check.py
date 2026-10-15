"""Strict *declarative* compatibility screen for Metorah's first migration class.

This module makes NO chain RPC calls, storage proof checks, or assertion that a
source is actually frozen/enumerable. Passing produces CANDIDATE status only.
A separate independently authenticated runtime verifier must be a hard gate
before migration freeze, root commitment, activation or settlement.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

POLICY_VERSION = "metorah-capability-policy-v1"
REQUIRED_FEATURES = frozenset({"fungible_balances", "destination_bindings"})
REQUIRED_FLAGS = (
    "supports_irreversible_freeze",
    "enumerates_complete_holder_set",
    "exposes_per_holder_balances",
    "exposes_verifiable_total_supply",
    "source_authorizes_beneficiary_bindings",
    "pins_state_to_finalized_block",
    "exposes_verifiable_storage_evidence",
)
ALLOWED_FIELDS = frozenset({
    "asset_kind", "source_vm", "destination_vm", "source_genesis_hash",
    "features", *REQUIRED_FLAGS,
})
GENESIS_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


def evaluate(metadata: Any) -> dict[str, Any]:
    """Screen untrusted declarative metadata; never confer deployment approval.

    All errors are returned as stable string codes in deterministic order.
    Unknown capabilities are blocked rather than interpreted optimistically.
    """
    errors: list[str] = []
    if not isinstance(metadata, dict):
        metadata = {}
        errors.append("INVALID_DESCRIPTOR")

    unexpected = sorted(set(metadata).difference(ALLOWED_FIELDS))
    if unexpected:
        errors.append("UNKNOWN_FIELDS:" + ",".join(unexpected))
    if metadata.get("asset_kind") != "fungible_entitlement":
        errors.append("UNSUPPORTED_ASSET_KIND")
    if metadata.get("source_vm") != "wasm":
        errors.append("UNSUPPORTED_SOURCE_VM")
    if metadata.get("destination_vm") != "evm":
        errors.append("UNSUPPORTED_DESTINATION_VM")
    genesis = metadata.get("source_genesis_hash")
    if not isinstance(genesis, str) or not GENESIS_RE.fullmatch(genesis):
        errors.append("MISSING_OR_INVALID_SOURCE_GENESIS")

    features = metadata.get("features")
    if not isinstance(features, list) or any(not isinstance(x, str) for x in features):
        errors.append("INVALID_FEATURE_LIST")
    else:
        declared = set(features)
        if len(declared) != len(features):
            errors.append("DUPLICATE_FEATURES")
        missing = sorted(REQUIRED_FEATURES.difference(declared))
        if missing:
            errors.append("MISSING_REQUIRED_FEATURES:" + ",".join(missing))
        unsupported = sorted(declared.difference(REQUIRED_FEATURES))
        if unsupported:
            errors.append("UNSUPPORTED_STATE_FEATURES:" + ",".join(unsupported))

    for name in REQUIRED_FLAGS:
        if metadata.get(name) is not True:
            errors.append("REQUIREMENT_NOT_DECLARED:" + name)

    candidate = len(errors) == 0
    return {
        "policy_version": POLICY_VERSION,
        "status": "CANDIDATE_REQUIRES_INDEPENDENT_VERIFICATION" if candidate else "BLOCKED",
        "candidate_for_design_review": candidate,
        "can_freeze": False,
        "can_activate": False,
        "source_state_authenticated": False,
        "reasons": errors,
        "required_next_gate": (
            "Verify chain identity, finalized storage proof, complete holder enumeration, "
            "authorized beneficiary bindings and settlement backing independently."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Screen a draft Metorah source descriptor (NOT chain verification)")
    parser.add_argument("descriptor", type=Path, help="Path to a JSON descriptor")
    args = parser.parse_args(argv)
    try:
        record = json.loads(args.descriptor.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reasons": ["UNREADABLE_DESCRIPTOR"]}), file=sys.stdout)
        print(f"metadata reading failed: {type(exc).__name__}", file=sys.stderr)
        return 2
    result = evaluate(record)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["candidate_for_design_review"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
