import io
import unittest

from tools.artifacts.store import (
    ArtifactActor,
    ArtifactDownload,
    ArtifactError,
    S3CompatibleBackend,
    ArtifactStore,
    can_download,
    validate_upload,
    verify_artifact_content,
)
from hashlib import sha256
from tools.api.artifact_handlers import download_artifact_response, upload_artifact_response


class FakeS3:
    def __init__(self, versioning=True):
        self.objects = {}
        self.versioning = versioning
        self.last_put = None

    def put_object(self, **kwargs):
        self.last_put = kwargs
        key = kwargs["Key"]
        if key in self.objects:
            raise RuntimeError("precondition failed")
        version = "v1" if self.versioning else None
        self.objects[key] = {
            "Body": kwargs["Body"],
            "Metadata": kwargs["Metadata"],
            "ContentType": kwargs["ContentType"],
            "ContentLength": len(kwargs["Body"]),
            "VersionId": version,
        }
        return {"VersionId": version}

    def head_object(self, **kwargs):
        return {key: value for key, value in self.objects[kwargs["Key"]].items() if key != "Body"}

    def get_object(self, **kwargs):
        item = self.objects[kwargs["Key"]]
        if kwargs.get("VersionId") != item["VersionId"]:
            raise RuntimeError("wrong version")
        return {
            "Body": io.BytesIO(item["Body"]),
            "Metadata": item["Metadata"],
            "ContentLength": item["ContentLength"],
            "VersionId": item["VersionId"],
        }

    def delete_object(self, **kwargs):
        item = self.objects.get(kwargs["Key"])
        if item and item["VersionId"] == kwargs["VersionId"]:
            del self.objects[kwargs["Key"]]


class ArtifactStorageTests(unittest.TestCase):
    def setUp(self):
        self.operator = ArtifactActor("tenant-a", "operator-1", ("operator",))
        self.privacy = ArtifactActor("tenant-a", "privacy-1", ("privacy_officer",))
        self.content = b'{"proof":"sample"}'

    def test_account_mappings_are_forced_into_private_classification(self):
        validate_upload(self.privacy, "account_mapping", "private_mapping", self.content, "application/json", 1)
        with self.assertRaisesRegex(ArtifactError, "privacy_classification_required"):
            validate_upload(self.privacy, "account_mapping", "public_evidence", self.content, "application/json", 1)
        with self.assertRaisesRegex(ArtifactError, "invalid_private_artifact_kind"):
            validate_upload(self.privacy, "signed_report", "private_mapping", self.content, "application/json", 1)

    def test_least_privilege_upload_roles_are_enforced(self):
        validate_upload(self.operator, "proof_bundle", "public_evidence", self.content, "application/octet-stream", 1)
        with self.assertRaisesRegex(ArtifactError, "forbidden"):
            validate_upload(self.operator, "account_mapping", "private_mapping", self.content, "application/json", 1)
        with self.assertRaisesRegex(ArtifactError, "forbidden"):
            validate_upload(self.operator, "signed_report", "confidential", self.content, "application/pdf", 1)

    def test_unsafe_media_type_and_empty_content_are_rejected(self):
        with self.assertRaisesRegex(ArtifactError, "unsupported_media_type"):
            validate_upload(self.operator, "proof_bundle", "public_evidence", self.content, "text/html", 1)
        with self.assertRaisesRegex(ArtifactError, "empty_artifact"):
            validate_upload(self.operator, "proof_bundle", "public_evidence", b"", "application/octet-stream", 1)

    def test_download_acl_separates_public_confidential_and_private_mapping(self):
        viewer = ArtifactActor("tenant-a", "viewer-1", ("viewer",))
        reviewer = ArtifactActor("tenant-a", "reviewer-1", ("reviewer",))
        privacy = ArtifactActor("tenant-a", "privacy-1", ("privacy_officer",))
        self.assertTrue(can_download(viewer, "public_evidence"))
        self.assertFalse(can_download(viewer, "confidential"))
        self.assertFalse(can_download(reviewer, "private_mapping"))
        self.assertTrue(can_download(privacy, "private_mapping"))
        self.assertFalse(can_download(ArtifactActor("tenant-b", "viewer-2", ("viewer",)), "unknown"))

    def test_storage_key_is_tenant_scoped_and_content_addressed(self):
        digest = sha256(self.content).hexdigest()
        key_a = ArtifactStore._key("tenant-a", "private-mapping", digest)
        key_b = ArtifactStore._key("tenant-b", "private-mapping", digest)
        self.assertIn("/sha256/" + digest[:2] + "/" + digest, key_a)
        self.assertNotEqual(key_a, key_b)
        self.assertIn("tenant-a/private-mapping", key_a)

    def test_s3_backend_uses_conditional_private_versioned_write(self):
        client = FakeS3()
        backend = S3CompatibleBackend(client, "private-evidence-bucket", "kms-key-1")
        digest = sha256(self.content).hexdigest()
        version = backend.put_if_absent("tenant/key", self.content, "application/json", digest, "public_evidence")
        self.assertEqual(version, "v1")
        self.assertEqual(client.last_put["IfNoneMatch"], "*")
        self.assertEqual(client.last_put["ServerSideEncryption"], "aws:kms")
        self.assertNotIn("ACL", client.last_put)

    def test_existing_content_addressed_object_is_idempotent_only_when_hash_matches(self):
        client = FakeS3()
        backend = S3CompatibleBackend(client, "private-evidence-bucket")
        digest = sha256(self.content).hexdigest()
        backend.put_if_absent("tenant/key", self.content, "application/json", digest, "public_evidence")
        self.assertEqual(
            backend.put_if_absent("tenant/key", self.content, "application/json", digest, "public_evidence"),
            "v1",
        )
        with self.assertRaisesRegex(ArtifactError, "immutable_object_conflict"):
            backend.put_if_absent("tenant/key", b"changed", "application/json", sha256(b"changed").hexdigest(), "public_evidence")

    def test_unversioned_bucket_is_rejected(self):
        backend = S3CompatibleBackend(FakeS3(versioning=False), "private-evidence-bucket")
        with self.assertRaisesRegex(ArtifactError, "object_versioning_required"):
            backend.put_if_absent("tenant/key", self.content, "application/json", sha256(self.content).hexdigest(), "public_evidence")

    def test_read_integrity_checks_hash_size_and_metadata(self):
        digest = sha256(self.content).hexdigest()
        metadata = {"sha256": digest, "content_length": len(self.content)}
        verify_artifact_content(self.content, digest, len(self.content), metadata)
        with self.assertRaisesRegex(ArtifactError, "artifact_integrity_failure"):
            verify_artifact_content(self.content, digest, len(self.content), metadata, expected_version="v1")
        with self.assertRaisesRegex(ArtifactError, "artifact_integrity_failure"):
            verify_artifact_content(self.content + b"x", digest, len(self.content), metadata)
        with self.assertRaisesRegex(ArtifactError, "artifact_integrity_failure"):
            verify_artifact_content(self.content, digest, len(self.content), {"sha256": "0" * 64})

    def test_download_handler_returns_verified_attachment_without_storage_key(self):
        content = b"evidence bytes"
        digest = sha256(content).hexdigest()
        class FakeStore:
            def download(self, **kwargs):
                return ArtifactDownload(
                    content=content, content_sha256=digest, content_type="application/pdf",
                    content_size=len(content), classification="public_evidence",
                    artifact_kind="signed_report", revision=2, integrity_verified=True,
                )
        response = download_artifact_response(
            FakeStore(), self.operator, "migration-1", digest, "signed_report", "request-1"
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, content)
        self.assertEqual(response.headers["X-Content-SHA256"], digest)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Content-Disposition"], f'attachment; filename="evidence-{digest}.bin"')
        self.assertNotIn("storage_key", response.headers)

    def test_handler_errors_do_not_expose_backend_details(self):
        class FailingStore:
            def download(self, **kwargs):
                raise ArtifactError(502, "artifact_integrity_failure", "bucket private-internal-name failed")
        response = download_artifact_response(
            FailingStore(), self.operator, "migration-1", "a"*64, "proof_bundle", "request-2"
        )
        self.assertEqual(response.status, 502)
        self.assertIn(b"Stored artifact failed integrity verification", response.body)
        self.assertNotIn(b"private-internal-name", response.body)
        self.assertEqual(response.headers["X-Request-Id"], "request-2")

    def test_upload_handler_returns_only_public_artifact_metadata(self):
        class FakeStore:
            def put(self, **kwargs):
                return {
                    "artifact_id": "artifact-1", "content_sha256": "a"*64,
                    "content_size": len(kwargs["content"]), "classification": kwargs["classification"],
                    "artifact_kind": kwargs["artifact_kind"], "revision": kwargs["revision"],
                }
        response = upload_artifact_response(
            FakeStore(), self.operator, "migration-1", "proof_bundle", "public_evidence",
            b"proof", "application/octet-stream", 1, "request-3"
        )
        self.assertEqual(response.status, 201)
        self.assertIn(b'"content_sha256"', response.body)
        self.assertNotIn(b"storage_key", response.body)
        self.assertEqual(response.headers["X-Request-Id"], "request-3")

    def test_s3_backend_reads_and_deletes_exact_object_version(self):
        client = FakeS3()
        backend = S3CompatibleBackend(client, "private-evidence-bucket")
        digest = sha256(self.content).hexdigest()
        version = backend.put_if_absent("tenant/key", self.content, "application/json", digest, "public_evidence")
        content, metadata = backend.get("tenant/key", version)
        verify_artifact_content(content, digest, len(self.content), metadata, expected_version=version)
        backend.delete("tenant/key", version)
        self.assertNotIn("tenant/key", client.objects)


if __name__ == "__main__":
    unittest.main()
