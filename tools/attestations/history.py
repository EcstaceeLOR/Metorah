"""Locally append-only, tamper-evident history of E1 operator attestations.

A SHA-256 chain detects middle deletion, reordering, and edits but CANNOT
prevent a malicious operator from truncating a suffix unless an external party
publishes/retains the last head digest. NOT a consensus transparency log.
"""
from __future__ import annotations

import fcntl
from hashlib import sha256
import os
from pathlib import Path
import tempfile
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tools.attestations.report import (
    ReportError, canonical_bytes, _load_json, _hex32,
    SIGNED_DOMAIN, verify_signed,
)

SCHEMA = "metorah-attestation-history-v1"
CHAIN_DOMAIN = b"METORAH_ATTESTATION_HISTORY_ENTRY_V1\x00"
GENESIS = "0x" + "00" * 32
MAX_HISTORY = 12 * 1024 * 1024
MAX_ENTRIES = 10_000


def _hash_entry(entry: dict) -> str:
    content = {key: value for key, value in entry.items() if key != "entry_hash"}
    return "0x" + sha256(CHAIN_DOMAIN + canonical_bytes(content)).hexdigest()


def _history_data(path: Path) -> dict:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ReportError("INVALID_HISTORY_PATH")
    if not path.exists():
        return {"schema_version": SCHEMA, "entries": []}
    if path.stat().st_size > MAX_HISTORY:
        raise ReportError("HISTORY_FILE_TOO_LARGE")
    result = _load_json(path.read_bytes())
    if type(result) is not dict or set(result) != {"schema_version", "entries"}:
        raise ReportError("INVALID_HISTORY_SCHEMA")
    if result["schema_version"] != SCHEMA or type(result["entries"]) is not list:
        raise ReportError("INVALID_HISTORY_SCHEMA")
    if len(result["entries"]) > MAX_ENTRIES:
        raise ReportError("HISTORY_TOO_MANY_ENTRIES")
    return result


def verify_history(
    entries: Any, *, trusted_public_key: str,
    expected_head: str | None = None,
) -> dict:
    pubkey = _hex32(trusted_public_key, "TRUSTED_PUBLIC_KEY")
    if type(entries) is not list or len(entries) > MAX_ENTRIES:
        raise ReportError("INVALID_HISTORY_ENTRIES")
    last = GENESIS
    nonces: set[tuple[str, str]] = set()
    reports: set[str] = set()
    for i, item in enumerate(entries):
        if (type(item) is not dict or set(item) != {
            "sequence", "previous_entry_hash", "report_digest", "signer_public_key",
            "signature_ed25519", "run_nonce", "migration_id", "entry_hash",
        } or type(item["sequence"]) is not int or item["sequence"] != i):
            raise ReportError("BROKEN_HISTORY_SEQUENCE")
        if item["previous_entry_hash"] != last:
            raise ReportError("BROKEN_HISTORY_PREVIOUS_HASH")
        for name in ("report_digest", "signer_public_key", "run_nonce", "migration_id", "entry_hash"):
            _hex32(item[name], "HISTORY_" + name.upper())
        if item["signer_public_key"] != pubkey:
            raise ReportError("HISTORY_UNTRUSTED_SIGNER")
        if (type(item["signature_ed25519"]) is not str
                or len(item["signature_ed25519"]) != 130
                or not all(c in "0123456789abcdef" for c in item["signature_ed25519"][2:])
                or not item["signature_ed25519"].startswith("0x")):
            raise ReportError("INVALID_HISTORY_SIGNATURE")
        if item["entry_hash"] != _hash_entry(item):
            raise ReportError("HISTORY_ENTRY_HASH_MISMATCH")
        marker = (item["migration_id"], item["run_nonce"])
        if marker in nonces or item["report_digest"] in reports:
            raise ReportError("REPLAYED_SIGNED_REPORT")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey[2:])).verify(
                bytes.fromhex(item["signature_ed25519"][2:]),
                SIGNED_DOMAIN + bytes.fromhex(item["report_digest"][2:]),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ReportError("INVALID_HISTORY_ATTESTATION_SIGNATURE") from exc
        nonces.add(marker)
        reports.add(item["report_digest"])
        last = item["entry_hash"]
    if expected_head is not None and _hex32(expected_head, "EXTERNAL_HEAD") != last:
        raise ReportError("EXTERNALLY_ANCHORED_HISTORY_HEAD_MISMATCH")
    return {
        "schema_version": "metorah-attestation-history-check-v1",
        "entries_checked": len(entries),
        "head_digest": last,
        "signatures_verified": len(entries),
        "head_anchored_externally": expected_head is not None,
        "finality_authenticated": False,
        "can_activate": False,
        "can_claim": False,
    }


def _atomic_write(path: Path, value: dict) -> None:
    content = canonical_bytes(value) + b"\n"
    if len(content) > MAX_HISTORY:
        raise ReportError("HISTORY_TOO_LARGE_TO_WRITE")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=".metorah-attestations-",
            suffix=".tmp", delete=False,
        ) as stream:
            temp = Path(stream.name)
            os.chmod(temp, 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink():
            raise ReportError("INVALID_HISTORY_PATH")
        os.replace(temp, path)
        # fsync the directory after replacing, for durable rename on POSIX.
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ReportError("HISTORY_WRITE_FAILED") from exc
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def append_history(
    path: Path, report: dict, evidence: dict[str, bytes], *,
    trusted_public_key: str, expected_tool_build_sha256: str,
) -> dict:
    """Append an independently verified report with exclusive POSIX lock.

    This requires an out-of-band expected signer key. A self-declared key in
    the receipt is not enough. Never generates a new report during append.
    """
    checked = verify_signed(
        report, evidence, trusted_public_key=trusted_public_key,
        expected_tool_build_sha256=expected_tool_build_sha256,
    )
    if not isinstance(path, Path) or path.is_symlink():
        raise ReportError("INVALID_HISTORY_PATH")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    if lock.is_symlink():
        raise ReportError("INVALID_HISTORY_LOCK")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(lock, flags, 0o600)
    except OSError as exc:
        raise ReportError("HISTORY_LOCK_FAILED") from exc
    try:
        with os.fdopen(fd, "a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            prior = _history_data(path)
            state = verify_history(prior["entries"], trusted_public_key=trusted_public_key)
            if len(prior["entries"]) == MAX_ENTRIES:
                raise ReportError("HISTORY_TOO_MANY_ENTRIES")
            payload = report["payload"]
            entry = {
                "sequence": len(prior["entries"]),
                "previous_entry_hash": state["head_digest"],
                "report_digest": checked["report_digest"],
                "signer_public_key": report["signer_public_key"],
                "signature_ed25519": report["signature_ed25519"],
                "run_nonce": payload["run_nonce"],
                "migration_id": payload["migration_id"],
            }
            entry["entry_hash"] = _hash_entry(entry)
            updated = prior["entries"] + [entry]
            summary = verify_history(updated, trusted_public_key=trusted_public_key)
            _atomic_write(path, {"schema_version": SCHEMA, "entries": updated})
            return summary
    finally:
        # file descriptor context releases the exclusive lock automatically
        pass


def check_history_file(path: Path, *, trusted_public_key: str,
                       expected_head: str | None = None) -> dict:
    if not path.exists():
        raise ReportError("MISSING_HISTORY_FILE")
    return verify_history(_history_data(path)["entries"],
                          trusted_public_key=trusted_public_key,
                          expected_head=expected_head)
