"""Offline public transparency index. Integrity != authenticity or availability."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SCHEMA = "metorah-public-evidence-index-v1"
PUBLIC_KINDS = frozenset({"signed_report_redacted", "public_verifier_build", "public_challenge_status", "public_methodology"})
HASH = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}\Z")
MAX_ARTIFACT = 32 * 1024 * 1024
MAX_ITEMS = 512

class InvalidEvidence(ValueError):
    pass

def require(condition, code):
    if not condition:
        raise InvalidEvidence(code)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")

def digest(data):
    return hashlib.sha256(data).hexdigest()

def _identifier(value):
    require(isinstance(value, str) and ID.fullmatch(value) is not None, "INVALID_IDENTIFIER")
    return value

def _hash(value):
    require(isinstance(value, str) and HASH.fullmatch(value) is not None, "INVALID_SHA256")
    return value

def _read_public(root: Path, sha: str):
    _hash(sha)
    path = root / "objects" / sha
    require(not path.is_symlink() and path.is_file(), "OBJECT_MISSING_OR_LINKED")
    require(path.stat().st_size <= MAX_ARTIFACT, "OBJECT_TOO_LARGE")
    data = path.read_bytes()
    require(digest(data) == sha, "OBJECT_DIGEST_MISMATCH")
    return data

def publish(root, migration_id, entries, *, consent_record=None):
    """Write public index with content-addressed public artifacts only.

    Caller must supply already reviewed/redacted public bytes. This function
    rejects known sensitive field names recursively but cannot classify all PII.
    Explicit out-of-band consent and legal review remain required.
    """
    root = Path(root)
    _identifier(migration_id)
    require(isinstance(entries, list) and 1 <= len(entries) <= MAX_ITEMS, "INVALID_ENTRIES")
    require(isinstance(consent_record, dict) and consent_record.get("approved") is True
            and isinstance(consent_record.get("reviewer"), str)
            and ID.fullmatch(consent_record["reviewer"]) is not None,
            "PUBLICATION_APPROVAL_REQUIRED")
    seen = set()
    records = []
    blobs = []
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"name", "kind", "content"}, "BAD_ENTRY_SCHEMA")
        name = _identifier(entry["name"])
        require(name not in seen, "DUPLICATE_ENTRY")
        seen.add(name)
        kind = entry["kind"]
        require(isinstance(kind, str) and kind in PUBLIC_KINDS, "NONPUBLIC_ARTIFACT_KIND")
        data = entry["content"]
        require(isinstance(data, bytes) and 0 < len(data) <= MAX_ARTIFACT, "INVALID_PUBLIC_BYTES")
        require(b"PRIVATE KEY" not in data.upper() and b"BEGIN OPENSSH" not in data.upper()
                and b"BEGIN RSA PRIVATE" not in data.upper(), "OBVIOUS_SECRET_IN_PUBLIC_BYTES")
        if kind in {"signed_report_redacted", "public_challenge_status"}:
            try:
                document = json.loads(data, object_pairs_hook=_no_duplicate_keys)
            except InvalidEvidence:
                raise
            except (ValueError, UnicodeDecodeError) as exc:
                raise InvalidEvidence("INVALID_PUBLIC_JSON") from exc
            _scan_public_json(document)
        sha = digest(data)
        records.append({"name": name, "kind": kind, "sha256": sha, "bytes": len(data)})
        blobs.append((sha, data))
    records.sort(key=lambda r: r["name"])
    index = {"schema": SCHEMA, "migration_id": migration_id, "assurance": "E1_CONTENT_INTEGRITY_ONLY",
             "source_chain_authenticated": False, "can_activate": False, "can_claim": False,
             "objects": records}
    encoded = canonical(index)
    index_hash = digest(encoded)
    objects = root / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    require(not objects.is_symlink(), "UNSAFE_OBJECT_DIR")
    for sha, data in blobs:
        path = objects / sha
        if path.exists() or path.is_symlink():
            require(_read_public(root, sha) == data, "OBJECT_COLLISION")
        else:
            with path.open("xb") as f:
                f.write(data)
    path = root / ("index-" + index_hash + ".json")
    if path.exists() or path.is_symlink():
        require(not path.is_symlink() and path.read_bytes() == encoded, "INDEX_COLLISION")
    else:
        with path.open("xb") as f:
            f.write(encoded)
    return {"index_sha256": index_hash, "index_path": str(path), "objects": len(records),
            "can_activate": False, "can_claim": False}

BLOCKED_KEYS = frozenset({
    "email", "phone", "phone_number", "ip_address", "private_key", "seed_phrase", "mnemonic",
    "secret", "password", "access_token", "wallet_address", "source_wallet",
    "destination_wallet", "beneficiary", "beneficiary_address", "holder_address",
    "source_address", "destination_address", "allocations", "holders", "balances",
    "source_to_destination", "identity", "legal_name", "full_name",
})

def _no_duplicate_keys(pairs):
    obj = {}
    for key, val in pairs:
        if key in obj:
            raise InvalidEvidence("DUPLICATE_JSON_KEY")
        obj[key] = val
    return obj

def _scan_public_json(value, depth=0):
    require(depth <= 24, "JSON_TOO_DEEP")
    if isinstance(value, dict):
        for key, val in value.items():
            require(isinstance(key, str) and key.lower() not in BLOCKED_KEYS, "SENSITIVE_FIELD")
            _scan_public_json(val, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _scan_public_json(item, depth + 1)

def verify(root, index_sha256):
    """Verify exact, locally retrieved bytes against an externally pinned index hash."""
    root = Path(root)
    _hash(index_sha256)
    path = root / ("index-" + index_sha256 + ".json")
    require(not path.is_symlink() and path.is_file(), "INDEX_MISSING_OR_LINKED")
    encoded = path.read_bytes()
    require(len(encoded) <= 1024 * 1024 and digest(encoded) == index_sha256, "INDEX_TAMPERED")
    try:
        index = json.loads(encoded, object_pairs_hook=_no_duplicate_keys)
    except InvalidEvidence:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidEvidence("INVALID_INDEX_JSON") from exc
    require(canonical(index) == encoded, "NONCANONICAL_INDEX")
    require(isinstance(index, dict) and set(index) == {"schema", "migration_id", "assurance",
             "source_chain_authenticated", "can_activate", "can_claim", "objects"}, "INDEX_SCHEMA")
    require(index["schema"] == SCHEMA and index["assurance"] == "E1_CONTENT_INTEGRITY_ONLY",
            "INDEX_ASSURANCE_MISMATCH")
    require(index["source_chain_authenticated"] is False and index["can_activate"] is False
            and index["can_claim"] is False, "UNSAFE_ASSURANCE_CLAIM")
    _identifier(index["migration_id"])
    records = index["objects"]
    require(isinstance(records, list) and 1 <= len(records) <= MAX_ITEMS, "INVALID_ENTRIES")
    seen = set()
    for record in records:
        require(isinstance(record, dict) and set(record) == {"name", "kind", "sha256", "bytes"}, "OBJECT_SCHEMA")
        name = _identifier(record["name"])
        require(name not in seen, "DUPLICATE_ENTRY")
        seen.add(name)
        require(record["kind"] in PUBLIC_KINDS, "NONPUBLIC_ARTIFACT_KIND")
        require(type(record["bytes"]) is int and 0 < record["bytes"] <= MAX_ARTIFACT, "INVALID_OBJECT_LENGTH")
        data = _read_public(root, record["sha256"])
        require(len(data) == record["bytes"], "OBJECT_LENGTH_MISMATCH")
        require(b"PRIVATE KEY" not in data.upper() and b"BEGIN OPENSSH" not in data.upper()
                and b"BEGIN RSA PRIVATE" not in data.upper(), "OBVIOUS_SECRET_IN_PUBLIC_BYTES")
        if record["kind"] in {"signed_report_redacted", "public_challenge_status"}:
            try:
                doc = json.loads(data, object_pairs_hook=_no_duplicate_keys)
            except InvalidEvidence:
                raise
            except (ValueError, UnicodeDecodeError) as exc:
                raise InvalidEvidence("INVALID_PUBLIC_JSON") from exc
            _scan_public_json(doc)
    require([r["name"] for r in records] == sorted(seen), "NONCANONICAL_OBJECT_ORDER")
    return {"status": "PUBLIC_BYTES_INTEGRITY_VERIFIED", "index_sha256": index_sha256,
            "objects_verified": len(records), "source_chain_authenticated": False,
            "can_activate": False, "can_claim": False}
