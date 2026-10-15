"""Metorah v1 assurance *presentation* policy — NOT a chain verifier.

Fail closed for unverifiable data. This tool never sets an authorization flag.
Any future independent-chain mode requires an authenticated verifier and a
separate reviewed policy revision; user-supplied JSON cannot enable it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

VERSION = "metorah-assurance-v1"
MODES = frozenset({"simulation", "operator_snapshot", "independent_verified"})
FIELDS = frozenset({"mode", "reference"})
LABELS = {
    "simulation": "Offline simulation — not chain authenticated",
    "operator_snapshot": "Operator-provided snapshot — independently unverified",
}


def evaluate(record: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(record, dict):
        record = {}
        errors.append("INVALID_RECORD")
    extras = sorted(k for k in record if k not in FIELDS) if all(isinstance(k, str) for k in record) else []
    if len(extras) or any(not isinstance(k, str) for k in record):
        errors.append("UNKNOWN_FIELDS_OR_KEY_TYPES")
    mode = record.get("mode")
    if not isinstance(mode, str) or mode not in MODES:
        errors.append("UNSUPPORTED_MODE")
    reference = record.get("reference")
    if reference is not None and (
        not isinstance(reference, str) or not (0 < len(reference) <= 128)
        or any(ord(ch) < 32 or ord(ch) > 126 for ch in reference)
    ):
        errors.append("INVALID_REFERENCE")
    if mode == "independent_verified":
        errors.append("CHAIN_VERIFIER_NOT_IMPLEMENTED")
    blocked = bool(errors)
    status = (
        "BLOCKED" if blocked else
        "SIMULATION_UNVERIFIED" if mode == "simulation" else
        "OPERATOR_UNVERIFIED"
    )
    return {
        "policy_version": VERSION,
        "status": status,
        "display_label": (
            "Not verified — assessment blocked" if blocked else LABELS[mode]
        ),
        "source_state_authenticated": False,
        "holder_set_complete_verified": False,
        "settlement_backing_verified": False,
        "can_present_verified": False,
        "can_activate": False,
        "can_claim": False,
        "trustless": False,
        "errors": errors,
        "explanation": (
            "This is a presentation guard only; no chain identity, finality, "
            "storage proof, complete holder inventory, binding or settlement "
            "has been independently verified."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate trust labels. Not a cryptographic proof verifier."
    )
    parser.add_argument("record", type=Path)
    args = parser.parse_args(argv)
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        print(json.dumps(evaluate(None), indent=2))
        return 2
    result = evaluate(record)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 2 if result["status"] == "BLOCKED" else 0


if __name__ == "__main__":
    sys.exit(main())
