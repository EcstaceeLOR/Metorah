"""Canonical, independently reproducible, Ed25519-signed E1 evidence reports.

A valid signature authenticates a DECLARED operator's bytes only. Neither the
operator key nor its data is proof of Portaldot genesis, consensus finality,
storage membership, holder completeness or funded destination settlement.
E1_CHECKS_PASS NEVER means a migration can activate or be claimed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import re
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from tools.manifest import canonical as manifest_v1

SCHEMA = "metorah-verification-report-v1"
PAYLOAD_SCHEMA = "metorah-verification-payload-v1"
SCOPE = "E1_OFFLINE_EVIDENCE_CONSISTENCY_ONLY"
SIGNED_DOMAIN = b"METORAH_ED25519_VERIFICATION_REPORT_V1\x00"
REPORT_DOMAIN = b"METORAH_VERIFICATION_REPORT_HASH_V1\x00"
H32 = re.compile(r"0x[0-9a-f]{64}\Z")
H20 = re.compile(r"0x[0-9a-f]{40}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\Z")
ISO_UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")
NAMES = ("manifest.json", "header-observation.json", "trie-proof-bundle.json", "holder-reconciliation.json")
MAX_ARTIFACT = 8 * 1024 * 1024
MAX_REPORT = 64 * 1024

class ReportError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ReportError("NONCANONICAL_JSON_INPUT") from exc


def _hex32(value: Any, name: str) -> str:
    if type(value) is not str or H32.fullmatch(value) is None:
        raise ReportError("INVALID_" + name)
    return value


def _load_json(raw: bytes) -> Any:
    def object_pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ReportError("DUPLICATE_JSON_KEY")
            out[key] = value
        return out
    def bad_constant(_):
        raise ReportError("NONFINITE_JSON")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                          parse_constant=bad_constant)
    except ReportError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReportError("INVALID_EVIDENCE_JSON") from exc


def read_evidence(folder: Path) -> dict[str, bytes]:
    if not isinstance(folder, Path) or not folder.is_dir() or folder.is_symlink():
        raise ReportError("INVALID_EVIDENCE_DIRECTORY")
    out = {}
    for name in NAMES:
        path = folder / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARTIFACT:
            raise ReportError("MISSING_OR_OVERSIZE_" + name.replace(".", "_").upper())
        data = path.read_bytes()
        if len(data) > MAX_ARTIFACT:
            raise ReportError("EVIDENCE_OVERSIZE")
        out[name] = data
    return out


def commitments(artifacts: dict[str, bytes]) -> dict[str, dict[str, Any]]:
    if type(artifacts) is not dict or set(artifacts) != set(NAMES):
        raise ReportError("INCOMPLETE_EVIDENCE_PACKAGE")
    result = {}
    for name in NAMES:
        raw = artifacts[name]
        if type(raw) is not bytes or len(raw) > MAX_ARTIFACT:
            raise ReportError("INVALID_ARTIFACT_BYTES")
        result[name] = {"sha256": "0x" + sha256(raw).hexdigest(), "size": len(raw)}
    return result


def _manifest_header(artifacts: dict[str, bytes]) -> dict:
    doc = _load_json(artifacts["manifest.json"])
    if type(doc) is not dict or type(doc.get("header")) is not dict:
        raise ReportError("INVALID_REPORT_MANIFEST_HEADER")
    try:
        manifest_v1._canonical_header(doc["header"])
    except (manifest_v1.ManifestError, ValueError, KeyError, TypeError) as exc:
        raise ReportError("INVALID_REPORT_MANIFEST_HEADER") from exc
    return doc["header"]


def evaluate(artifacts: dict[str, bytes]) -> tuple[str, list[str]]:
    """Deterministic PASS/FAIL over supplied offline material, not on-chain proof.

    Results here must be recomputed by verifier, NOT supplied by signer.
    Only E1 manifest, cross-artifact identity, and self-reported denial of
    chain authentication are checked; trie/signatures/finality are NOT proved.
    """
    commitments(artifacts)
    header = _manifest_header(artifacts)
    findings = []
    doc = _load_json(artifacts["manifest.json"])
    if not manifest_v1.verify_manifest(doc):
        findings.append("CANONICAL_MANIFEST_INVALID")
    for name in NAMES[1:]:
        try:
            item = _load_json(artifacts[name])
        except ReportError:
            findings.append("INVALID_JSON_" + name.replace("-", "_").replace(".", "_").upper())
            continue
        if type(item) is not dict:
            findings.append("INVALID_SCHEMA_" + name.replace("-", "_").replace(".", "_").upper())
            continue
        # An operator-signed record is not allowed to self-assert release
        # permissions or cryptographic finality that this CLI cannot inspect.
        for flag in (
            "can_activate", "can_claim", "source_chain_authenticated",
            "consensus_finality_cryptographically_verified",
            "root_authenticated_by_finality", "finality_cryptographically_verified",
            "registry_storage_proofs_verified", "complete_event_history_cryptographically_verified",
        ):
            if item.get(flag) is True:
                findings.append("UNSUPPORTED_CHAIN_ASSURANCE_ASSERTION_" + name.replace("-", "_").replace(".", "_").upper())
                break
        if name == "header-observation.json":
            facts = item.get("observed")
            if (item.get("status") != "FINALIZED_HEADER_OBSERVED_UNAUTHENTICATED"
                    or type(facts) is not dict or item.get("can_claim") is not False
                    or item.get("can_activate") is not False
                    or item.get("consensus_finality_cryptographically_verified") is not False):
                findings.append("INVALID_HEADER_OBSERVATION_STATUS")
            elif (facts.get("reported_genesis_hash") != header["source_genesis"]
                    or facts.get("snapshot_block_hash") != header["finalized_block_hash"]
                    or facts.get("snapshot_state_root") != header["finalized_state_root"]
                    or type(facts.get("snapshot_block_number")) is not int
                    or str(facts["snapshot_block_number"]) != header["finalized_block_number"]):
                findings.append("HEADER_OBSERVATION_SOURCE_MISMATCH")
        elif name == "trie-proof-bundle.json":
            if item.get("schema_version") != "metorah-substrate-storage-proof-v1":
                findings.append("INVALID_TRIE_PROOF_BUNDLE_SCHEMA")
            if (item.get("block_hash") != header["finalized_block_hash"]
                    or item.get("state_root") != header["finalized_state_root"]):
                findings.append("TRIE_PROOF_BUNDLE_SOURCE_MISMATCH")
            if (type(item.get("nodes")) is not list or not item["nodes"]
                    or type(item.get("items")) is not list or not item["items"]):
                findings.append("TRIE_PROOF_BUNDLE_EMPTY")
        else:
            if (item.get("schema_version") != "metorah-entitlement-reconciliation-v1"
                    or item.get("status") != "COMPLETE_RELATIVE_TO_SUPPLIED_DATA_UNAUTHENTICATED"
                    or item.get("can_activate") is not False
                    or item.get("can_claim") is not False
                    or item.get("registry_storage_proofs_verified") is not False):
                findings.append("INVALID_RECONCILIATION_STATUS")
            if (item.get("manifest_digest") != doc.get("manifest_digest")
                    or item.get("merkle_root") != doc.get("merkle_root")
                    or item.get("historical_holder_count") != header["historical_holder_count"]
                    or item.get("active_holder_count") != header["active_holder_count"]
                    or item.get("total_supply_units") != header["total_units"]):
                findings.append("RECONCILIATION_ALLOCATION_MISMATCH")
    findings.sort()
    return ("E1_CHECKS_FAIL" if findings else "E1_CHECKS_PASS"), findings


def _issued_at(value: str) -> str:
    if type(value) is not str or ISO_UTC.fullmatch(value) is None:
        raise ReportError("INVALID_UTC_ISSUANCE_TIME")
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReportError("INVALID_UTC_ISSUANCE_TIME") from exc
    if dt.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ReportError("INVALID_UTC_ISSUANCE_TIME")
    return value


def build_payload(
    artifacts: dict[str, bytes], *, tool_build_sha256: str,
    tool_revision: str, tool_version: str, issued_at: str, run_nonce: str,
) -> dict[str, Any]:
    header = _manifest_header(artifacts)
    result, findings = evaluate(artifacts)
    if type(tool_revision) is not str or REVISION.fullmatch(tool_revision) is None:
        raise ReportError("INVALID_TOOL_REVISION")
    if type(tool_version) is not str or VERSION.fullmatch(tool_version) is None:
        raise ReportError("INVALID_TOOL_VERSION")
    return {
        "schema_version": PAYLOAD_SCHEMA,
        "verification_scope": SCOPE,
        "verification_result": result,
        "findings": findings,
        "issued_at_utc": _issued_at(issued_at),
        "run_nonce": _hex32(run_nonce, "RUN_NONCE"),
        "migration_id": header["migration_id"],
        "source_genesis": header["source_genesis"],
        "source_contract": header["source_contract"],
        "source_code_hash": header["source_code_hash"],
        "source_block_hash": header["finalized_block_hash"],
        "source_block_number": header["finalized_block_number"],
        "source_state_root": header["finalized_state_root"],
        "destination_chain_id": header["destination_chain_id"],
        "destination_contract": header["destination_contract"],
        "manifest_digest": _load_json(artifacts["manifest.json"]).get("manifest_digest"),
        "merkle_root": _load_json(artifacts["manifest.json"]).get("merkle_root"),
        "tool_revision": tool_revision,
        "tool_version": tool_version,
        "tool_build_sha256": _hex32(tool_build_sha256, "TOOL_BUILD_HASH"),
        "artifact_commitments": commitments(artifacts),
        "source_chain_authenticated": False,
        "consensus_finality_verified": False,
        "storage_trie_verified": False,
        "signer_scope": "OPERATOR_ATTESTATION_ONLY_NOT_FINALITY_PROOF",
        "can_activate": False,
        "can_claim": False,
    }


def payload_hash(payload: dict) -> str:
    return "0x" + sha256(REPORT_DOMAIN + canonical_bytes(payload)).hexdigest()


def sign_payload(payload: dict, private_key: Ed25519PrivateKey) -> dict:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ReportError("INVALID_SIGNER_KEY")
    digest = payload_hash(payload)
    pubkey = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(SIGNED_DOMAIN + bytes.fromhex(digest[2:]))
    return {
        "schema_version": SCHEMA,
        "payload": payload,
        "report_digest": digest,
        "signer_public_key": "0x" + pubkey.hex(),
        "signature_ed25519": "0x" + signature.hex(),
    }


def verify_signed(
    report: Any, artifacts: dict[str, bytes], *,
    trusted_public_key: str,
    expected_tool_build_sha256: str,
) -> dict:
    if (type(report) is not dict
            or set(report) != {
                "schema_version", "payload", "report_digest", "signer_public_key", "signature_ed25519"
            } or report["schema_version"] != SCHEMA):
        raise ReportError("INVALID_SIGNED_REPORT_SCHEMA")
    provided = _hex32(trusted_public_key, "TRUSTED_SIGNER")
    if report["signer_public_key"] != provided:
        raise ReportError("UNTRUSTED_SIGNER_KEY")
    payload = report["payload"]
    if type(payload) is not dict or payload.get("schema_version") != PAYLOAD_SCHEMA:
        raise ReportError("INVALID_SIGNED_PAYLOAD")
    if payload.get("verification_scope") != SCOPE:
        raise ReportError("FORBIDDEN_ASSURANCE_SCOPE")
    if (payload.get("can_activate") is not False
            or payload.get("can_claim") is not False
            or payload.get("source_chain_authenticated") is not False
            or payload.get("consensus_finality_verified") is not False
            or payload.get("storage_trie_verified") is not False
            or payload.get("signer_scope") != "OPERATOR_ATTESTATION_ONLY_NOT_FINALITY_PROOF"):
        raise ReportError("FORBIDDEN_AUTHENTICATION_CLAIM")
    expected_build = _hex32(expected_tool_build_sha256, "EXPECTED_VERIFIER_BUILD")
    if payload.get("tool_build_sha256") != expected_build:
        raise ReportError("VERIFIER_BUILD_MISMATCH")
    nonce = _hex32(payload.get("run_nonce"), "RUN_NONCE")
    if int(nonce[2:], 16) == 0:
        raise ReportError("ZERO_RUN_NONCE")
    _issued_at(payload.get("issued_at_utc"))
    _hex32(report.get("report_digest"), "REPORT_DIGEST")
    signature = report.get("signature_ed25519")
    if type(signature) is not str or re.fullmatch(r"0x[0-9a-f]{128}", signature) is None:
        raise ReportError("INVALID_ED25519_SIGNATURE_ENCODING")
    if report["report_digest"] != payload_hash(payload):
        raise ReportError("REPORT_DIGEST_MISMATCH")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(provided[2:])).verify(
            bytes.fromhex(signature[2:]),
            SIGNED_DOMAIN + bytes.fromhex(report["report_digest"][2:]),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ReportError("ED25519_SIGNATURE_INVALID") from exc
    actual = commitments(artifacts)
    if actual != payload.get("artifact_commitments"):
        raise ReportError("EVIDENCE_BYTE_COMMITMENT_MISMATCH")
    # Even after validating the signature, independently recompute every
    # report outcome and immutable domain referent from the published files.
    recreated = build_payload(
        artifacts,
        tool_build_sha256=expected_build,
        tool_revision=payload.get("tool_revision"),
        tool_version=payload.get("tool_version"),
        issued_at=payload.get("issued_at_utc"),
        run_nonce=nonce,
    )
    if payload != recreated:
        raise ReportError("INDEPENDENT_REPRODUCTION_MISMATCH")
    return {
        "report_digest": report["report_digest"],
        "verification_result": payload["verification_result"],
        "findings": payload["findings"],
        "verification_scope": SCOPE,
        "signature_valid_for_trusted_public_key": True,
        "source_chain_authenticated": False,
        "can_activate": False,
        "can_claim": False,
    }


def fresh_nonce() -> str:
    return "0x" + secrets.token_bytes(32).hex()
