"""Adversarial E1 report signature/reproduction/history tests; synthetic only."""
from __future__ import annotations

import copy
from datetime import datetime
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.manifest import canonical as m
from tools.attestations.report import (
    ReportError, build_payload, commitments, evaluate, payload_hash,
    read_evidence, sign_payload, verify_signed, _load_json, _hex32,
)
from tools.attestations.history import (
    append_history, check_history_file, verify_history, _hash_entry,
)
from tools.attestations import cli as CLI

BUILD = "0x" + "91" * 32
BAD_BUILD = "0x" + "92" * 32
REVISION = "a" * 40
TIME = "2026-10-15T18:00:00Z"
NONCE = "0x" + "b3" * 32


def h32(n):
    return "0x" + f"{n:02x}" * 32


def h20(n):
    return "0x" + f"{n:02x}" * 20


def evidence():
    header = {
        "source_genesis": h32(1), "finalized_block_hash": h32(2),
        "finalized_block_number": "12345", "finalized_state_root": h32(3),
        "source_contract": h32(4), "source_code_hash": h32(5),
        "migration_id": h32(6), "asset_id": h32(7),
        "destination_chain_id": "31337", "destination_contract": h20(8),
        "entitlement_kind": 1, "decimals": 12, "historical_holder_count": 3,
        "active_holder_count": 2, "total_units": "90",
    }
    entries = [
        {"leaf_index": 0, "historical_index": 0, "source_account": h32(10),
         "beneficiary": h20(11), "units": "40", "binding_nonce": "1"},
        {"leaf_index": 1, "historical_index": 2, "source_account": h32(12),
         "beneficiary": h20(13), "units": "50", "binding_nonce": "2"},
    ]
    manifest = m.build(header, entries)
    obs = {
        "schema_version": "metorah-finality-observation-v1",
        "status": "FINALIZED_HEADER_OBSERVED_UNAUTHENTICATED",
        "observed": {
            "reported_genesis_hash": header["source_genesis"],
            "snapshot_block_hash": header["finalized_block_hash"],
            "snapshot_block_number": 12345,
            "snapshot_state_root": header["finalized_state_root"],
        },
        "consensus_finality_cryptographically_verified": False,
        "can_activate": False, "can_claim": False,
    }
    proof = {
        "schema_version": "metorah-substrate-storage-proof-v1",
        "block_hash": header["finalized_block_hash"],
        "state_root": header["finalized_state_root"],
        "state_version": 1, "nodes": ["0x010203"], "items": [
            {"key": "0x01", "value": "0xdead"},
        ],
    }
    reconcile = {
        "schema_version": "metorah-entitlement-reconciliation-v1",
        "status": "COMPLETE_RELATIVE_TO_SUPPLIED_DATA_UNAUTHENTICATED",
        "manifest_digest": manifest["manifest_digest"],
        "merkle_root": manifest["merkle_root"],
        "historical_holder_count": 3, "active_holder_count": 2,
        "total_supply_units": "90",
        "registry_storage_proofs_verified": False,
        "can_activate": False, "can_claim": False,
    }
    return {
        "manifest.json": json.dumps(manifest, sort_keys=True).encode(),
        "header-observation.json": json.dumps(obs, sort_keys=True).encode(),
        "trie-proof-bundle.json": json.dumps(proof, sort_keys=True).encode(),
        "holder-reconciliation.json": json.dumps(reconcile, sort_keys=True).encode(),
    }


def update_json(artifacts, filename, callback):
    out = artifacts.copy()
    item = json.loads(out[filename])
    callback(item)
    out[filename] = json.dumps(item, sort_keys=True).encode()
    return out


def build(artifacts, nonce=NONCE, build_sha=BUILD):
    return build_payload(artifacts, tool_build_sha256=build_sha,
                         tool_revision=REVISION, tool_version="test-build-v1",
                         issued_at=TIME, run_nonce=nonce)


def public(key):
    return "0x" + key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ).hex()


class SignedVerificationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pub = public(self.key)
        self.files = evidence()
        self.report = sign_payload(build(self.files), self.key)

    def checked(self, report=None, artifacts=None, *, key=None, buildsha=BUILD):
        return verify_signed(
            self.report if report is None else report,
            self.files if artifacts is None else artifacts,
            trusted_public_key=self.pub if key is None else key,
            expected_tool_build_sha256=buildsha,
        )

    def rejected(self, code, callback):
        with self.assertRaises(ReportError) as err:
            callback()
        self.assertEqual(err.exception.code, code)

    def test_evidence_pass_is_explicitly_only_E1_consistency(self):
        self.assertEqual(evaluate(self.files), ("E1_CHECKS_PASS", []))
        res = self.checked()
        self.assertEqual(res["verification_result"], "E1_CHECKS_PASS")
        self.assertTrue(res["signature_valid_for_trusted_public_key"])
        self.assertFalse(res["source_chain_authenticated"])
        self.assertFalse(res["can_activate"])
        self.assertFalse(res["can_claim"])

    def test_report_exactly_binds_migration_source_destination_manifest_and_build(self):
        p = self.report["payload"]
        manifest = json.loads(self.files["manifest.json"])
        header = manifest["header"]
        for a,b in (("migration_id","migration_id"), ("source_genesis","source_genesis"),
                    ("source_contract","source_contract"), ("source_block_hash","finalized_block_hash"),
                    ("source_state_root","finalized_state_root"),
                    ("destination_chain_id","destination_chain_id"),
                    ("destination_contract","destination_contract")):
            self.assertEqual(p[a], header[b])
        self.assertEqual(p["manifest_digest"], manifest["manifest_digest"])
        self.assertEqual(p["merkle_root"], manifest["merkle_root"])
        self.assertEqual(p["tool_build_sha256"], BUILD)
        self.assertEqual(p["tool_revision"], REVISION)
        self.assertEqual(set(p["artifact_commitments"]), set(self.files))

    def test_commitments_are_exact_bytes_not_fuzzy_json_objects(self):
        modified = self.files.copy()
        modified["manifest.json"] += b" "
        self.rejected("EVIDENCE_BYTE_COMMITMENT_MISMATCH",
                      lambda: self.checked(artifacts=modified))

    def test_signature_tampering_cannot_reproduce(self):
        x = copy.deepcopy(self.report)
        x["signature_ed25519"] = "0x" + "00" * 64
        self.rejected("ED25519_SIGNATURE_INVALID", lambda: self.checked(report=x))

    def test_fake_pass_result_fails_without_valid_signature(self):
        x = copy.deepcopy(self.report)
        x["payload"]["verification_result"] = "E3_FINALITY_PASS"
        self.rejected("REPORT_DIGEST_MISMATCH", lambda: self.checked(report=x))

    def test_signed_e3_assurance_scope_is_forbidden_even_with_valid_key(self):
        p = copy.deepcopy(self.report["payload"])
        p["verification_scope"] = "E3_AUTHENTICATED_SOURCE"
        self.rejected("FORBIDDEN_ASSURANCE_SCOPE",
                      lambda: self.checked(report=sign_payload(p, self.key)))

    def test_signed_assertion_that_claims_can_activate_always_rejected(self):
        p = copy.deepcopy(self.report["payload"])
        p["can_activate"] = True
        self.rejected("FORBIDDEN_AUTHENTICATION_CLAIM",
                      lambda: self.checked(report=sign_payload(p, self.key)))

    def test_self_declared_signer_not_trusted(self):
        other = public(Ed25519PrivateKey.generate())
        self.rejected("UNTRUSTED_SIGNER_KEY",
                      lambda: self.checked(key=other))

    def test_valid_signature_from_wrong_key_not_equivalent_to_trusted_key(self):
        forged = sign_payload(build(self.files), Ed25519PrivateKey.generate())
        self.rejected("UNTRUSTED_SIGNER_KEY",
                      lambda: self.checked(report=forged))

    def test_wrong_verifier_build_hash_rejected(self):
        self.rejected("VERIFIER_BUILD_MISMATCH", lambda: self.checked(buildsha=BAD_BUILD))

    def test_change_source_state_root_after_signing_fails(self):
        other = update_json(self.files, "header-observation.json",
                            lambda x: x["observed"].update({"snapshot_state_root": h32(90)}))
        self.rejected("EVIDENCE_BYTE_COMMITMENT_MISMATCH",
                      lambda: self.checked(artifacts=other))

    def test_seller_can_sign_E1_fail_but_independent_verifier_reproduces_fail(self):
        bad = update_json(self.files, "holder-reconciliation.json",
                          lambda x: x.update({"active_holder_count": 1}))
        res, reasons = evaluate(bad)
        self.assertEqual(res, "E1_CHECKS_FAIL")
        self.assertIn("RECONCILIATION_ALLOCATION_MISMATCH", reasons)
        signed = sign_payload(build(bad), self.key)
        actual = self.checked(report=signed, artifacts=bad)
        self.assertEqual(actual["verification_result"], "E1_CHECKS_FAIL")
        self.assertFalse(actual["can_activate"])

    def test_source_genesis_in_observation_mismatch_reproduces_fail(self):
        bad = update_json(self.files, "header-observation.json",
                          lambda x: x["observed"].update({"reported_genesis_hash": h32(111)}))
        self.assertIn("HEADER_OBSERVATION_SOURCE_MISMATCH", evaluate(bad)[1])

    def test_metadata_proof_bundle_wrong_root_reproduces_fail(self):
        bad = update_json(self.files, "trie-proof-bundle.json",
                          lambda x: x.update({"state_root": h32(244)}))
        self.assertIn("TRIE_PROOF_BUNDLE_SOURCE_MISMATCH", evaluate(bad)[1])

    def test_trie_bundle_node_presence_is_not_claimed_as_trie_proof_validation(self):
        self.assertEqual(evaluate(self.files)[0], "E1_CHECKS_PASS")
        self.assertFalse(self.checked()["source_chain_authenticated"])

    def test_unsigned_artifact_cannot_claim_crypto_finality(self):
        bad = update_json(self.files, "header-observation.json",
                          lambda x: x.update({"consensus_finality_cryptographically_verified": True}))
        self.assertEqual(evaluate(bad)[0], "E1_CHECKS_FAIL")
        self.assertTrue(any(s.startswith("UNSUPPORTED_CHAIN_ASSURANCE_ASSERTION") for s in evaluate(bad)[1]))

    def test_duplicate_keys_in_material_are_invalid(self):
        changed = self.files.copy()
        changed["trie-proof-bundle.json"] = b'{"state_root":"0x01","state_root":"0x02"}'
        self.assertEqual(evaluate(changed)[0], "E1_CHECKS_FAIL")
        self.assertIn("INVALID_JSON_TRIE_PROOF_BUNDLE_JSON", evaluate(changed)[1])

    def test_manifest_leaves_omitted_can_never_be_signed_as_E1_pass(self):
        bad = update_json(self.files, "manifest.json",
                          lambda x: x.update({"merkle_root": h32(233)}))
        self.assertEqual(evaluate(bad)[0], "E1_CHECKS_FAIL")
        self.assertIn("CANONICAL_MANIFEST_INVALID", evaluate(bad)[1])

    def test_wrong_run_nonce_encoding_rejected(self):
        self.rejected("INVALID_RUN_NONCE",
                      lambda: build_payload(self.files, tool_build_sha256=BUILD,
                          tool_revision=REVISION, tool_version="v1", issued_at=TIME,
                          run_nonce="0xa"))

    def test_non_utc_issuance_time_rejected(self):
        self.rejected("INVALID_UTC_ISSUANCE_TIME",
                      lambda: build_payload(self.files, tool_build_sha256=BUILD,
                          tool_revision=REVISION, tool_version="v1",
                          issued_at="2026-10-15T18:00:00+01:00", run_nonce=NONCE))

    def test_empty_evidence_is_not_partial_success(self):
        self.rejected("INCOMPLETE_EVIDENCE_PACKAGE",
                      lambda: evaluate({"manifest.json": self.files["manifest.json"]}))

    def test_independent_reproduction_catches_validly_resigned_altered_domain(self):
        p = copy.deepcopy(self.report["payload"])
        p["destination_chain_id"] = "42"
        signed = sign_payload(p, self.key)
        self.rejected("INDEPENDENT_REPRODUCTION_MISMATCH",
                      lambda: self.checked(report=signed))

    def test_private_payload_nonce_zero_rejected_even_when_signed(self):
        p = build(self.files, nonce="0x" + "00" * 32)
        signed = sign_payload(p, self.key)
        self.rejected("ZERO_RUN_NONCE",
                      lambda: self.checked(report=signed))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "reports.json"
        self.key = Ed25519PrivateKey.generate()
        self.pub = public(self.key)
        self.files = evidence()

    def report(self, nonce=NONCE):
        return sign_payload(build(self.files, nonce=nonce), self.key)

    def append(self, item):
        return append_history(self.path, item, self.files,
                              trusted_public_key=self.pub,
                              expected_tool_build_sha256=BUILD)

    def fails(self, code, function):
        with self.assertRaises(ReportError) as exc:
            function()
        self.assertEqual(exc.exception.code, code)

    def test_append_checks_signature_and_exposes_publishable_head(self):
        first = self.append(self.report())
        self.assertEqual(first["entries_checked"], 1)
        self.assertEqual(first["signatures_verified"], 1)
        self.assertFalse(first["can_claim"])
        second = self.append(self.report(nonce="0x" + "e4" * 32))
        self.assertEqual(second["entries_checked"], 2)
        self.assertNotEqual(first["head_digest"], second["head_digest"])
        proof = check_history_file(self.path, trusted_public_key=self.pub,
                                   expected_head=second["head_digest"])
        self.assertEqual(proof["entries_checked"], 2)
        self.assertTrue(proof["head_anchored_externally"])

    def test_replayed_same_signed_receipt_never_appended(self):
        one = self.report()
        self.append(one)
        self.fails("REPLAYED_SIGNED_REPORT", lambda: self.append(one))
        self.assertEqual(check_history_file(self.path, trusted_public_key=self.pub)["entries_checked"], 1)

    def test_reused_nonce_for_same_migration_rejected_even_with_different_issuance_time(self):
        self.append(self.report())
        updated = build_payload(self.files, tool_build_sha256=BUILD,
                                tool_revision=REVISION, tool_version="test-build-v1",
                                issued_at="2026-10-15T18:00:01Z", run_nonce=NONCE)
        another = sign_payload(updated, self.key)
        self.fails("REPLAYED_SIGNED_REPORT", lambda: self.append(another))

    def test_changed_evidence_does_not_enter_history(self):
        changed = update_json(self.files, "trie-proof-bundle.json",
                              lambda x: x.update({"block_hash": h32(111)}))
        one = self.report()
        self.fails("EVIDENCE_BYTE_COMMITMENT_MISMATCH",
                   lambda: append_history(self.path, one, changed,
                        trusted_public_key=self.pub, expected_tool_build_sha256=BUILD))
        self.assertFalse(self.path.exists())

    def test_middle_mutation_detected(self):
        self.append(self.report())
        self.append(self.report(nonce="0x" + "02" * 32))
        doc = json.loads(self.path.read_text())
        doc["entries"][0]["migration_id"] = h32(10)
        self.path.write_text(json.dumps(doc))
        self.fails("HISTORY_ENTRY_HASH_MISMATCH",
                   lambda: check_history_file(self.path, trusted_public_key=self.pub))

    def test_reordered_entries_fail(self):
        self.append(self.report())
        self.append(self.report(nonce="0x" + "02" * 32))
        doc = json.loads(self.path.read_text())
        doc["entries"][0], doc["entries"][1] = doc["entries"][1], doc["entries"][0]
        self.path.write_text(json.dumps(doc))
        self.fails("BROKEN_HISTORY_SEQUENCE",
                   lambda: check_history_file(self.path, trusted_public_key=self.pub))

    def test_truncated_suffix_needs_an_externally_witnessed_head_to_detect(self):
        self.append(self.report())
        full = self.append(self.report(nonce="0x" + "02" * 32))
        doc = json.loads(self.path.read_text())
        doc["entries"].pop()
        self.path.write_text(json.dumps(doc))
        # Local hash chains cannot detect removal of an entire valid suffix.
        self.assertEqual(check_history_file(self.path, trusted_public_key=self.pub)["entries_checked"], 1)
        self.fails("EXTERNALLY_ANCHORED_HISTORY_HEAD_MISMATCH",
                   lambda: check_history_file(self.path, trusted_public_key=self.pub,
                                              expected_head=full["head_digest"]))

    def test_deleting_middle_entry_detected(self):
        self.append(self.report())
        self.append(self.report(nonce="0x" + "02" * 32))
        self.append(self.report(nonce="0x" + "03" * 32))
        doc = json.loads(self.path.read_text())
        doc["entries"].pop(1)
        self.path.write_text(json.dumps(doc))
        self.fails("BROKEN_HISTORY_SEQUENCE",
                   lambda: check_history_file(self.path, trusted_public_key=self.pub))

    def test_modified_history_signature_with_rehashed_entry_still_fails(self):
        self.append(self.report())
        doc = json.loads(self.path.read_text())
        doc["entries"][0]["signature_ed25519"] = "0x" + "00" * 64
        doc["entries"][0]["entry_hash"] = _hash_entry(doc["entries"][0])
        self.path.write_text(json.dumps(doc))
        self.fails("INVALID_HISTORY_ATTESTATION_SIGNATURE",
                   lambda: check_history_file(self.path, trusted_public_key=self.pub))

    def test_history_cannot_be_revalidated_with_wrong_key(self):
        self.append(self.report())
        key = public(Ed25519PrivateKey.generate())
        self.fails("HISTORY_UNTRUSTED_SIGNER",
                   lambda: check_history_file(self.path, trusted_public_key=key))

    def test_existing_nonschema_file_not_overwritten(self):
        self.path.write_text('{"other":"content"}')
        self.fails("INVALID_HISTORY_SCHEMA",
                   lambda: self.append(self.report()))
        self.assertEqual(self.path.read_text(), '{"other":"content"}')

    def test_duplicate_json_fields_in_history_fail(self):
        self.path.write_text('{"entries":[],"entries":[],"schema_version":"metorah-attestation-history-v1"}')
        self.fails("DUPLICATE_JSON_KEY",
                   lambda: self.append(self.report()))


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        for name, data in evidence().items():
            (self.folder / name).write_bytes(data)
        key = Ed25519PrivateKey.generate()
        self.pub = public(key)
        self.secret = self.folder / "private.bin"
        self.secret.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        os.chmod(self.secret, 0o600)
        self.report = self.folder / "signed.json"

    def args(self):
        return ["sign", "--evidence-dir", str(self.folder),
                "--signing-key-file", str(self.secret),
                "--tool-revision", REVISION, "--tool-build-sha256", BUILD,
                "--report", str(self.report)]

    def test_sign_and_verify_independently_without_private_key(self):
        self.assertEqual(CLI.main(self.args()), 0)
        self.assertTrue(self.report.exists())
        self.assertEqual(CLI.main([
            "verify", "--evidence-dir", str(self.folder),
            "--report", str(self.report),
            "--trusted-public-key", self.pub,
            "--expected-tool-build-sha256", BUILD,
        ]), 0)

    def test_wrong_public_key_cannot_verify(self):
        self.assertEqual(CLI.main(self.args()), 0)
        self.assertEqual(CLI.main([
            "verify", "--evidence-dir", str(self.folder),
            "--report", str(self.report),
            "--trusted-public-key", public(Ed25519PrivateKey.generate()),
            "--expected-tool-build-sha256", BUILD,
        ]), 2)

    def test_insecure_key_file_permissions_rejected_without_report(self):
        os.chmod(self.secret, 0o644)
        self.assertEqual(CLI.main(self.args()), 2)
        self.assertFalse(self.report.exists())

    def test_never_overwrite_previous_signed_report(self):
        self.assertEqual(CLI.main(self.args()), 0)
        original = self.report.read_bytes()
        self.assertEqual(CLI.main(self.args()), 2)
        self.assertEqual(self.report.read_bytes(), original)

    def test_cli_signed_fail_result_independently_reproduced(self):
        p = self.folder / "holder-reconciliation.json"
        data = json.loads(p.read_text())
        data["total_supply_units"] = "91"
        p.write_text(json.dumps(data))
        self.assertEqual(CLI.main(self.args()), 0)
        self.assertEqual(CLI.main([
            "verify", "--evidence-dir", str(self.folder),
            "--report", str(self.report),
            "--trusted-public-key", self.pub,
            "--expected-tool-build-sha256", BUILD,
        ]), 1)

    def test_history_cli_anchor_rejects_wrong_head(self):
        history = self.folder / "history.json"
        self.assertEqual(CLI.main(self.args() + ["--history", str(history)]), 0)
        self.assertEqual(CLI.main([
            "history-check", "--history", str(history),
            "--trusted-public-key", self.pub,
            "--expected-head", h32(200),
        ]), 2)

    def test_report_paths_and_private_key_collisions_are_rejected(self):
        args = self.args()
        args[args.index("--report") + 1] = str(self.secret)
        self.assertEqual(CLI.main(args), 2)
        self.assertEqual(self.secret.stat().st_size, 32)

    def test_symlink_evidence_rejected(self):
        original = self.folder / "trie-proof-bundle.json"
        alt = self.folder / "outside.json"
        alt.write_bytes(original.read_bytes())
        original.unlink()
        try:
            original.symlink_to(alt)
        except OSError:
            self.skipTest("This Windows runner cannot create symlinks")
        self.assertEqual(CLI.main(self.args()), 2)
        self.assertFalse(self.report.exists())


if __name__ == "__main__":
    unittest.main()
