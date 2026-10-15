#!/usr/bin/env python3
"""Offline Ed25519 report signing, independent reproduction and history review.

A valid operator-signed E1 report is NOT trusted source finality or permission
to mint, transfer, claim, or activate any real customer assets.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.attestations.report import (
    ReportError, MAX_REPORT, _load_json, _hex32, build_payload,
    fresh_nonce, read_evidence, sign_payload, verify_signed,
)
from tools.attestations.history import append_history, check_history_file


def _new_report(path: Path, data: dict) -> None:
    if path.is_symlink():
        raise ReportError("REPORT_PATH_IS_SYMLINK")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ReportError("REPORT_ALREADY_EXISTS") from exc
    except OSError as exc:
        raise ReportError("REPORT_CREATE_FAILED") from exc
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True).encode("utf-8") + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
    except (OSError, ValueError) as exc:
        path.unlink(missing_ok=True)
        raise ReportError("REPORT_WRITE_FAILED") from exc


def _key(path: Path) -> Ed25519PrivateKey:
    # Raw, exactly 32-byte Ed25519 seed. This never leaves local process.
    if not path.is_file() or path.is_symlink() or path.stat().st_size != 32:
        raise ReportError("INVALID_PRIVATE_KEY_FILE")
    if os.name == "posix" and (stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ReportError("INSECURE_PRIVATE_KEY_PERMISSIONS")
    try:
        return Ed25519PrivateKey.from_private_bytes(path.read_bytes())
    except ValueError as exc:
        raise ReportError("INVALID_PRIVATE_KEY") from exc


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Sign/reproduce OFFLINE, unauthenticated migration evidence")
    subs = p.add_subparsers(dest="action", required=True)
    signer = subs.add_parser("sign", help="generate an E1-only signed report")
    signer.add_argument("--evidence-dir", type=Path, required=True)
    signer.add_argument("--signing-key-file", type=Path, required=True,
                        help="raw 32-byte Ed25519 secret file with 0600 permissions")
    signer.add_argument("--tool-revision", required=True, help="exact 40-char Git SHA")
    signer.add_argument("--tool-version", default="metorah-report-v1")
    signer.add_argument("--tool-build-sha256", required=True,
                        help="independently measured verifier executable/build SHA-256")
    signer.add_argument("--report", type=Path, required=True, help="must not exist")
    signer.add_argument("--history", type=Path, help="append signed receipt to tamper-evident history")

    verifier = subs.add_parser("verify", help="recalculate E1 verdict and validate trusted signature")
    verifier.add_argument("--evidence-dir", type=Path, required=True)
    verifier.add_argument("--report", type=Path, required=True)
    verifier.add_argument("--trusted-public-key", required=True, help="externally pinned signer key hex")
    verifier.add_argument("--expected-tool-build-sha256", required=True,
                          help="externally pinned verifier executable/build SHA-256")
    verifier.add_argument("--history", type=Path, help="optionally append independently verified report")

    h = subs.add_parser("history-check", help="audit local signatures, order and externally anchored head")
    h.add_argument("--history", type=Path, required=True)
    h.add_argument("--trusted-public-key", required=True)
    h.add_argument("--expected-head", help="last entry SHA-256 witnessed outside this local file")

    opts = p.parse_args(argv)
    try:
        if opts.action == "sign":
            if opts.report.resolve() in {opts.signing_key_file.resolve(), opts.evidence_dir.resolve()}:
                raise ReportError("INPUT_OUTPUT_COLLISION")
            artifacts = read_evidence(opts.evidence_dir)
            from cryptography.hazmat.primitives import serialization
            key = _key(opts.signing_key_file)
            payload = build_payload(
                artifacts, tool_build_sha256=opts.tool_build_sha256,
                tool_revision=opts.tool_revision, tool_version=opts.tool_version,
                issued_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                run_nonce=fresh_nonce(),
            )
            report = sign_payload(payload, key)
            public_key = report["signer_public_key"]
            # Recompute and verify signature BEFORE emitting bytes.
            verify_signed(report, artifacts, trusted_public_key=public_key,
                          expected_tool_build_sha256=opts.tool_build_sha256)
            _new_report(opts.report, report)
            if opts.history:
                head = append_history(opts.history, report, artifacts,
                    trusted_public_key=public_key,
                    expected_tool_build_sha256=opts.tool_build_sha256)
            else:
                head = None
            print(json.dumps({
                "report_digest": report["report_digest"],
                "signer_public_key": public_key,
                "verification_result": payload["verification_result"],
                "verification_scope": payload["verification_scope"],
                "history_head": None if head is None else head["head_digest"],
                "source_chain_authenticated": False,
                "can_activate": False, "can_claim": False,
            }, sort_keys=True))
            return 0

        if opts.action == "verify":
            if opts.report.is_symlink() or not opts.report.is_file() or opts.report.stat().st_size > MAX_REPORT:
                raise ReportError("INVALID_REPORT_FILE")
            report = _load_json(opts.report.read_bytes())
            artifacts = read_evidence(opts.evidence_dir)
            result = verify_signed(
                report, artifacts, trusted_public_key=opts.trusted_public_key,
                expected_tool_build_sha256=opts.expected_tool_build_sha256,
            )
            if opts.history:
                history = append_history(opts.history, report, artifacts,
                    trusted_public_key=opts.trusted_public_key,
                    expected_tool_build_sha256=opts.expected_tool_build_sha256)
                result["history_head"] = history["head_digest"]
            print(json.dumps(result, sort_keys=True))
            return 0 if result["verification_result"] == "E1_CHECKS_PASS" else 1

        result = check_history_file(
            opts.history, trusted_public_key=opts.trusted_public_key,
            expected_head=opts.expected_head,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ReportError, OSError) as exc:
        print(f"VERIFICATION_FAIL_CLOSED: {getattr(exc, 'code', 'LOCAL_IO_FAILURE')}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
