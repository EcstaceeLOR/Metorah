#!/usr/bin/env python3
"""Reproduce an OFFLINE, unauthenticated source-inventory/event replay audit.

Usage:
    python tools/reconciliation/check.py --snapshot frozen.json --manifest candidate.json --output report.json

A successful exit means internal consistency of supplied data only. It is NOT
proof of actual chain state, signature authentication or migration solvency.
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
from tools.reconciliation.audit import ReconciliationError, audit

MAX_INPUT_BYTES = 12 * 1024 * 1024


def _reject_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ReconciliationError("DUPLICATE_JSON_FIELD")
        out[key] = value
    return out


def _load(path: Path) -> dict:
    try:
        if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
            raise ReconciliationError("MISSING_OR_OVERSIZE_INPUT")
        data = path.read_bytes()
        if len(data) > MAX_INPUT_BYTES:
            raise ReconciliationError("OVERSIZE_INPUT")
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             ReconciliationError("NONFINITE_JSON_NUMBER")))
        if type(doc) is not dict:
            raise ReconciliationError("INVALID_JSON_OBJECT")
        return doc
    except ReconciliationError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReconciliationError("INVALID_OR_UNREADABLE_INPUT") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed offline holder-event and manifest audit")
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.resolve() in {args.snapshot.resolve(), args.manifest.resolve()}:
            raise ReconciliationError("OUTPUT_MUST_NOT_OVERWRITE_INPUT")
        if args.output.exists():
            raise ReconciliationError("OUTPUT_ALREADY_EXISTS")
        snapshot, manifest = _load(args.snapshot), _load(args.manifest)
        report = audit(snapshot, manifest)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically only after all checks pass. Failure must not leave
        # a partial report that could be mistakenly consumed by another tool.
        target = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=args.output.parent,
                prefix=".metorah-audit-", suffix=".tmp", delete=False,
            ) as handle:
                target = Path(handle.name)
                json.dump(report, handle, sort_keys=True, indent=2)
                handle.write("\n")
            os.replace(target, args.output)
        finally:
            if target is not None:
                target.unlink(missing_ok=True)
    except (ReconciliationError, OSError) as error:
        code = error.code if isinstance(error, ReconciliationError) else "AUDIT_REPORT_WRITE_FAILED"
        print(f"OFFLINE_AUDIT_FAILED: {code}", file=sys.stderr)
        return 2
    print("COMPLETE_RELATIVE_TO_SUPPLIED_DATA_UNAUTHENTICATED — NEVER activation evidence",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
