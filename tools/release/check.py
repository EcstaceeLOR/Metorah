"""Fail-closed Metorah release *label* guard, NOT a chain-evidence verifier.

Only research documents and offline test claims are currently expressible.
No JSON supplied by operators can authorize deploying or handling assets.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

VERSION = "metorah-release-policy-v1"
PHASES = frozenset({"research", "testnet_pilot", "design_partner_beta", "production"})
FIELDS = frozenset({"phase", "commit_sha", "summary"})
SHA_RE = re.compile(r"^[a-fA-F0-9]{40}$")


def evaluate(record: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(record, dict):
        record = {}
        errors.append("INVALID_RECORD")
    if any(not isinstance(key, str) for key in record) or set(record).difference(FIELDS):
        errors.append("UNKNOWN_FIELDS_OR_KEY_TYPES")
    phase = record.get("phase")
    if not isinstance(phase, str) or phase not in PHASES:
        errors.append("UNSUPPORTED_RELEASE_PHASE")
    sha = record.get("commit_sha")
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        errors.append("MISSING_OR_INVALID_SOURCE_COMMIT")
    summary = record.get("summary")
    if summary is not None and (not isinstance(summary, str) or len(summary) > 512):
        errors.append("INVALID_SUMMARY")
    if phase != "research" and phase in PHASES:
        errors.append("LIVE_SECURITY_GATES_UNIMPLEMENTED")
    research = phase == "research" and not errors
    return {
        "policy_version": VERSION,
        "status": "RESEARCH_ONLY" if research else "BLOCKED",
        "label": "Research artifact — no chain deployment or asset authorization" if research else "Not cleared for release",
        "can_publish_research": research,
        "can_run_live_pilot": False,
        "can_process_customer_assets": False,
        "can_deploy_to_chain": False,
        "chain_evidence_authenticated": False,
        "external_audit_completed": False,
        "errors": errors,
        "note": "This script does not authenticate commit existence, proofs, contracts, approvals or audit signatures.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check release label (not network or asset safety)")
    parser.add_argument("record", type=Path)
    args = parser.parse_args(argv)
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        print(json.dumps(evaluate(None), indent=2))
        return 2
    result = evaluate(record)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["status"] == "RESEARCH_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
