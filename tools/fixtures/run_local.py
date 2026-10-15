#!/usr/bin/env python3
"""Run a *real local ink! test harness*, never fabricate Portaldot RPC evidence.

Exits nonzero on a failed Rust test, missing lockfile or unavailable compiler.
Reports observed command exit codes and stdout/stderr SHA256, no mock chain IDs.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "contracts/wasm/source-ledger/Cargo.toml"
LOCKFILE = ROOT / "contracts/wasm/source-ledger/Cargo.lock"
SOURCE = ROOT / "contracts/wasm/source-ledger/lib.rs"
COMMANDS = (
    ("ink_fixture_tests", ["cargo", "test", "--locked", "--manifest-path", str(MANIFEST), "fixture_", "--", "--nocapture"]),
    ("ink_compile_check", ["cargo", "check", "--locked", "--manifest-path", str(MANIFEST)]),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_step(name: str, args: list[str], *, timeout: int = 900) -> dict:
    try:
        completed = subprocess.run(
            args, cwd=ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
        )
        code = completed.returncode
        out = completed.stdout
        err = completed.stderr
        error = None
    except (OSError, subprocess.TimeoutExpired) as exc:
        code = 2
        out = ""
        err = ""
        error = type(exc).__name__
    return {
        "step": name,
        "argv": [a.replace(str(ROOT), "<repo>") for a in args],
        "exit_code": code,
        "executed": error is None,
        "execution_error": error,
        "stdout_sha256": hashlib.sha256(out.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(err.encode()).hexdigest(),
        # Bounded diagnostics; a report is not a canonical test output archive.
        "stdout_tail": out[-4000:],
        "stderr_tail": err[-4000:],
    }


def build_report(steps: list[dict], *, present: bool, source_digest: str | None, lock_digest: str | None) -> dict:
    accepted = bool(present and len(steps) == len(COMMANDS) and
                    all(s.get("exit_code") == 0 and s.get("executed") is True for s in steps))
    return {
        "schema_version": "metorah-source-offline-fixture-v1",
        "status": "OFFLINE_FIXTURE_PASSED" if accepted else "OFFLINE_FIXTURE_FAILED",
        "assurance": "OFFLINE_RUST_INK_TEST_ONLY",
        "source_sha256": source_digest,
        "cargo_lock_sha256": lock_digest,
        "steps": steps,
        "portaldot_network_verified": False,
        "actual_source_contract_deployed": False,
        "actual_signed_chain_transactions": False,
        "real_tx_or_block_hashes_collected": False,
        "finality_or_storage_proofs_verified": False,
        "can_activate": False,
        "can_claim": False,
        "note": (
            "Only local ink! test environment and build checks ran. No RPC was "
            "contacted. No on-chain deployment, explorer receipts, signed "
            "transaction or finalized source storage proof is claimed."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run deterministic offline source fixtures only")
    p.add_argument("--output", type=Path, default=ROOT / "local_model/artifacts/source-fixture-local.json")
    p.add_argument("--timeout", type=int, default=900)
    args = p.parse_args(argv)
    if not 10 <= args.timeout <= 3600:
        p.error("--timeout must be between 10 and 3600 seconds")
    present = SOURCE.is_file() and MANIFEST.is_file() and LOCKFILE.is_file()
    results: list[dict] = []
    if present:
        for label, command in COMMANDS:
            step = run_step(label, command, timeout=args.timeout)
            results.append(step)
            print(label, "passed" if step["exit_code"] == 0 else "failed", file=sys.stderr)
            if step["exit_code"] != 0:
                break
    report = build_report(
        results,
        present=present,
        source_digest=sha256_file(SOURCE) if SOURCE.is_file() else None,
        lock_digest=sha256_file(LOCKFILE) if LOCKFILE.is_file() else None,
    )
    # The timestamp is informative, never treated as cryptographic evidence.
    report["recorded_at_utc"] = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Fixture:", report["status"], "Report:", args.output, file=sys.stderr)
    return 0 if report["status"] == "OFFLINE_FIXTURE_PASSED" else 2


if __name__ == "__main__":
    sys.exit(main())
