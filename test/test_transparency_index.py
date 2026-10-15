"""Adversarial public evidence index tests; no network or customer data."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("transparency_index", Path(__file__).resolve().parents[1] / "tools/transparency/index.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
PUBLIC = b'{"status":"REVIEW","can_activate":false}'
APPROVAL = {"approved": True, "reviewer": "privacy-reviewer"}

class TransparencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.entry = [{"name": "status", "kind": "public_challenge_status", "content": PUBLIC}]

    def publish(self, entries=None, approval=APPROVAL):
        return module.publish(self.root, "migration-1", self.entry if entries is None else entries, consent_record=approval)

    def reject(self, method, code):
        with self.assertRaisesRegex(module.InvalidEvidence, code):
            method()

    def test_reproduce_public_index(self):
        receipt = self.publish()
        result = module.verify(self.root, receipt["index_sha256"])
        self.assertEqual(result["objects_verified"], 1)
        self.assertFalse(result["can_activate"])
        self.assertFalse(result["source_chain_authenticated"])

    def test_deterministic_and_same_content_dedup(self):
        first = self.publish()
        second = self.publish()
        self.assertEqual(first["index_sha256"], second["index_sha256"])

    def test_reject_without_external_privacy_review(self):
        self.reject(lambda: self.publish(approval=None), "PUBLICATION_APPROVAL_REQUIRED")
        self.reject(lambda: self.publish(approval={"approved": 1, "reviewer": "r"}), "PUBLICATION_APPROVAL_REQUIRED")

    def test_reject_sensitive_wallet_mapping(self):
        for key in ("wallet_address", "source_wallet", "destination_address", "email", "allocations", "balances", "private_key"):
            with self.subTest(key=key):
                e = [{"name": "status", "kind": "public_challenge_status", "content": json.dumps({key: "sensitive"}).encode()}]
                self.reject(lambda: self.publish(entries=e), "SENSITIVE_FIELD")

    def test_reject_sensitive_nested_fields(self):
        e = [{"name": "status", "kind": "public_challenge_status", "content": b'{"safe":[{"source_wallet":"abc"}]}'}]
        self.reject(lambda: self.publish(entries=e), "SENSITIVE_FIELD")

    def test_reject_raw_private_evidence_kind(self):
        e = [{"name": "raw", "kind": "raw_holder_registry", "content": b'private'}]
        self.reject(lambda: self.publish(entries=e), "NONPUBLIC_ARTIFACT_KIND")

    def test_reject_duplicate_artifacts(self):
        self.reject(lambda: self.publish(entries=self.entry * 2), "DUPLICATE_ENTRY")

    def test_reject_bad_identifiers_and_bytes(self):
        self.reject(lambda: module.publish(self.root, "../evil", self.entry, consent_record=APPROVAL), "INVALID_IDENTIFIER")
        self.reject(lambda: self.publish(entries=[{"name": "../escape", "kind": "public_methodology", "content": b"doc"}]), "INVALID_IDENTIFIER")
        self.reject(lambda: self.publish(entries=[{"name": "x", "kind": "public_methodology", "content": ""}]), "INVALID_PUBLIC_BYTES")

    def test_reject_obvious_secret(self):
        self.reject(lambda: self.publish(entries=[{"name": "x", "kind": "public_methodology", "content": b"BEGIN OPENSSH PRIVATE KEY"}]), "OBVIOUS_SECRET_IN_PUBLIC_BYTES")

    def test_object_tamper(self):
        r = self.publish()
        sha = module.digest(PUBLIC)
        (self.root / "objects" / sha).write_bytes(b'{"status":"FAKE"}')
        self.reject(lambda: module.verify(self.root, r["index_sha256"]), "OBJECT_DIGEST_MISMATCH")

    def test_index_tamper(self):
        r = self.publish()
        Path(r["index_path"]).write_bytes(b'{}')
        self.reject(lambda: module.verify(self.root, r["index_sha256"]), "INDEX_TAMPERED")

    def test_missing_artifact(self):
        r = self.publish()
        (self.root / "objects" / module.digest(PUBLIC)).unlink()
        self.reject(lambda: module.verify(self.root, r["index_sha256"]), "OBJECT_MISSING_OR_LINKED")

    def test_bad_pin(self):
        r = self.publish()
        self.reject(lambda: module.verify(self.root, "0" * 64), "INDEX_MISSING_OR_LINKED")

    def test_symlink_object_rejected(self):
        r = self.publish()
        path = self.root / "objects" / module.digest(PUBLIC)
        path.unlink()
        try:
            path.symlink_to(Path(r["index_path"]))
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable")
        self.reject(lambda: module.verify(self.root, r["index_sha256"]), "OBJECT_MISSING_OR_LINKED")

    def test_reject_duplicate_json_keys(self):
        e = [{"name": "status", "kind": "public_challenge_status", "content": b'{"status":1,"status":2}'}]
        self.reject(lambda: self.publish(entries=e), "DUPLICATE_JSON_KEY")

    def test_reject_unsafe_index_claim_even_with_rehashed_pin(self):
        r = self.publish()
        path = Path(r["index_path"])
        data = json.loads(path.read_text())
        data["can_activate"] = True
        forged = module.canonical(data)
        fake_pin = module.digest(forged)
        (self.root / ("index-" + fake_pin + ".json")).write_bytes(forged)
        self.reject(lambda: module.verify(self.root, fake_pin), "UNSAFE_ASSURANCE_CLAIM")

if __name__ == "__main__":
    unittest.main()
