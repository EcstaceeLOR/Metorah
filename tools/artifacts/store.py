"""Tenant-scoped content-addressed evidence storage with verified reads.

The S3-compatible backend requires a private, versioned bucket and conditional writes.
The caller must provide an authenticated actor; this module does not verify JWTs.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Callable
import re


class ArtifactError(RuntimeError):
    def __init__(self, status: int, code: str, message: str | None = None):
        super().__init__(message or code)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class ArtifactActor:
    tenant_id: str
    subject: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class ArtifactDownload:
    content: bytes
    content_sha256: str
    content_type: str
    content_size: int
    classification: str
    artifact_kind: str
    revision: int
    object_version: str
    integrity_verified: bool


ALLOWED_MEDIA_TYPES = {
    "application/json", "application/cbor", "application/pdf",
    "application/octet-stream", "application/zip", "text/plain", "text/csv",
}
CLASSIFICATIONS = {"public_evidence", "confidential", "private_mapping"}
ARTIFACT_KINDS = {"manifest", "proof_bundle", "signed_report", "account_mapping", "verification_trace"}
UPLOAD_ROLES = {
    "manifest": {"owner", "admin", "operator"},
    "proof_bundle": {"owner", "admin", "operator", "verifier"},
    "signed_report": {"owner", "admin", "reviewer", "security_reviewer"},
    "account_mapping": {"owner", "admin", "privacy_officer"},
    "verification_trace": {"owner", "admin", "operator", "verifier"},
}
DOWNLOAD_ROLES = {
    "public_evidence": {"owner", "admin", "operator", "reviewer", "viewer", "verifier", "security_reviewer"},
    "confidential": {"owner", "admin", "security_reviewer"},
    "private_mapping": {"owner", "admin", "privacy_officer"},
}
SUBJECT_RE = re.compile(r"^[^\x00\r\n]{1,256}$")


def validate_upload(actor: ArtifactActor, artifact_kind: str, classification: str, content: bytes, media_type: str, revision: int) -> None:
    if not isinstance(actor, ArtifactActor) or not actor.tenant_id or not actor.subject or not actor.roles:
        raise ArtifactError(401, "unauthorized", "Authenticated tenant-scoped actor is required.")
    if not SUBJECT_RE.fullmatch(actor.subject):
        raise ArtifactError(401, "unauthorized", "Actor subject is invalid.")
    if artifact_kind not in ARTIFACT_KINDS or classification not in CLASSIFICATIONS:
        raise ArtifactError(400, "invalid_artifact_metadata", "Artifact kind or classification is unsupported.")
    if not isinstance(content, bytes) or not content:
        raise ArtifactError(400, "empty_artifact", "Artifact content must be non-empty bytes.")
    if media_type not in ALLOWED_MEDIA_TYPES:
        raise ArtifactError(415, "unsupported_media_type", "Media type is not allowed.")
    if type(revision) is not int or revision < 1:
        raise ArtifactError(400, "invalid_revision", "Revision must be a positive integer.")
    if artifact_kind == "account_mapping" and classification != "private_mapping":
        raise ArtifactError(400, "privacy_classification_required", "Account mapping artifacts must be private_mapping.")
    if classification == "private_mapping" and artifact_kind != "account_mapping":
        raise ArtifactError(400, "invalid_private_artifact_kind", "private_mapping is reserved for account mappings.")
    if not UPLOAD_ROLES[artifact_kind].intersection(actor.roles):
        raise ArtifactError(403, "forbidden", "Actor role cannot upload this artifact kind.")


def verify_artifact_content(content: bytes, content_sha256: str, expected_size: int, metadata: dict, expected_version: str | None = None) -> None:
    """Reject any read whose bytes, size, or immutable object metadata do not match."""
    if not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
        raise ArtifactError(502, "artifact_integrity_failure")
    if (
        not isinstance(content, bytes)
        or len(content) != expected_size
        or sha256(content).hexdigest() != content_sha256
        or metadata.get("sha256") != content_sha256
        or int(metadata.get("content_length", len(content))) != expected_size
        or (expected_version is not None and metadata.get("version_id") != expected_version)
    ):
        raise ArtifactError(502, "artifact_integrity_failure")


class S3CompatibleBackend:
    """Minimal boto3-compatible backend; injected client keeps the core dependency-free."""

    def __init__(self, client: Any, bucket: str, kms_key_id: str | None = None):
        if not bucket:
            raise ValueError("bucket is required")
        self._client = client
        self._bucket = bucket
        self._kms_key_id = kms_key_id

    def put_if_absent(self, key: str, content: bytes, media_type: str, digest_hex: str, classification: str) -> str:
        args = {
            "Bucket": self._bucket, "Key": key, "Body": content, "ContentType": media_type,
            "Metadata": {"sha256": digest_hex, "classification": classification},
            "IfNoneMatch": "*",
            "ServerSideEncryption": "aws:kms" if self._kms_key_id else "AES256",
        }
        if self._kms_key_id:
            args["SSEKMSKeyId"] = self._kms_key_id
        try:
            response = self._client.put_object(**args)
            version_id = response.get("VersionId")
            if not version_id or version_id == "null":
                raise ArtifactError(503, "object_versioning_required", "Bucket versioning must be enabled.")
            return str(version_id)
        except ArtifactError:
            raise
        except Exception as exc:
            # A conditional-write conflict is idempotent only if the existing object matches exactly.
            try:
                head = self._client.head_object(Bucket=self._bucket, Key=key)
            except Exception:
                raise ArtifactError(503, "object_storage_write_failed") from exc
            metadata = head.get("Metadata", {})
            version_id = head.get("VersionId")
            if (
                metadata.get("sha256") == digest_hex
                and metadata.get("classification") == classification
                and int(head.get("ContentLength", -1)) == len(content)
                and head.get("ContentType") == media_type
                and version_id and version_id != "null"
            ):
                return str(version_id)
            raise ArtifactError(409, "immutable_object_conflict", "Existing content-addressed object failed metadata verification.") from exc

    def get(self, key: str, version_id: str) -> tuple[bytes, dict]:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key, VersionId=version_id)
            body = response["Body"].read()
            metadata = dict(response.get("Metadata", {}))
            metadata["content_length"] = int(response.get("ContentLength", len(body)))
            metadata["version_id"] = response.get("VersionId")
            return body, metadata
        except Exception as exc:
            raise ArtifactError(502, "object_storage_read_failed") from exc

    def delete(self, key: str, version_id: str) -> None:
        try:
            self._client.delete_object(Bucket=self._bucket, Key=key, VersionId=version_id)
        except Exception as exc:
            raise ArtifactError(503, "object_storage_delete_failed") from exc


class ArtifactStore:
    def __init__(self, connection_factory: Callable[[], Any], backend: Any):
        self._connect = connection_factory
        self._backend = backend

    def _open(self):
        connection = self._connect()
        return connection, connection.cursor()

    @staticmethod
    def _close(connection: Any, cursor: Any, error: BaseException | None = None) -> None:
        try:
            if error is None:
                connection.commit()
            else:
                connection.rollback()
        finally:
            try:
                cursor.close()
            finally:
                connection.close()

    @staticmethod
    def _key(tenant_id: str, prefix: str, digest_hex: str) -> str:
        return f"tenants/{tenant_id}/{prefix}/sha256/{digest_hex[:2]}/{digest_hex}"

    @staticmethod
    def _access_event(cursor: Any, tenant_id: str, migration_id: str | None, object_id: str | None,
                      subject: str, action: str, outcome: str, request_id: str | None, details: dict) -> None:
        import json
        cursor.execute(
            "INSERT INTO artifact_access_events (tenant_id, migration_id, artifact_object_id, actor_subject, "
            "action, outcome, request_id, details) VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
            (tenant_id, migration_id, object_id, subject, action, outcome, request_id,
             json.dumps(details, sort_keys=True, separators=(",", ":"))),
        )

    def put(
        self,
        actor: ArtifactActor,
        migration_id: str,
        artifact_kind: str,
        classification: str,
        content: bytes,
        media_type: str,
        revision: int,
        request_id: str | None = None,
    ) -> dict:
        validate_upload(actor, artifact_kind, classification, content, media_type, revision)
        digest = sha256(content).digest()
        digest_hex = digest.hex()
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT retention_days, max_size_bytes, storage_prefix, policy_version "
                "FROM artifact_retention_policies WHERE classification=%s",
                (classification,),
            )
            policy = cursor.fetchone()
            if policy is None:
                raise ArtifactError(500, "retention_policy_missing")
            retention_days, max_size, prefix, policy_version = int(policy[0]), int(policy[1]), str(policy[2]), str(policy[3])
            if len(content) > max_size:
                raise ArtifactError(413, "artifact_too_large")
            cursor.execute("SELECT 1 FROM migrations WHERE id=%s AND tenant_id=%s", (migration_id, actor.tenant_id))
            if cursor.fetchone() is None:
                raise ArtifactError(404, "migration_not_found")
            self._close(connection, cursor)
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

        storage_key = self._key(actor.tenant_id, prefix, digest_hex)
        object_version = self._backend.put_if_absent(storage_key, content, media_type, digest_hex, classification)
        retention_until = datetime.now(timezone.utc) + timedelta(days=retention_days)
        connection, cursor = self._open()
        try:
            cursor.execute(
                "INSERT INTO artifact_objects (tenant_id, content_sha256, content_size, media_type, classification, "
                "storage_key, object_version, retention_until, retention_policy_version, created_by) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (tenant_id, content_sha256, classification) DO NOTHING "
                "RETURNING id, content_size, media_type, storage_key, object_version, retention_until, retention_policy_version",
                (actor.tenant_id, digest, len(content), media_type, classification, storage_key,
                 object_version, retention_until, policy_version, actor.subject),
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute(
                    "SELECT id, content_size, media_type, storage_key, object_version, retention_until, retention_policy_version "
                    "FROM artifact_objects WHERE tenant_id=%s AND content_sha256=%s AND classification=%s FOR UPDATE",
                    (actor.tenant_id, digest, classification),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ArtifactError(409, "artifact_registration_race")
                if int(row[1]) != len(content) or row[2] != media_type or row[3] != storage_key or row[4] != object_version:
                    raise ArtifactError(409, "artifact_metadata_conflict")
            object_id = str(row[0])
            cursor.execute(
                "INSERT INTO migration_artifacts (tenant_id, migration_id, artifact_object_id, artifact_kind, revision, uploaded_by) "
                "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (migration_id, tenant_id, artifact_kind, revision) DO NOTHING "
                "RETURNING id, artifact_object_id",
                (actor.tenant_id, migration_id, object_id, artifact_kind, revision, actor.subject),
            )
            link = cursor.fetchone()
            if link is None:
                cursor.execute(
                    "SELECT id, artifact_object_id FROM migration_artifacts "
                    "WHERE migration_id=%s AND tenant_id=%s AND artifact_kind=%s AND revision=%s FOR UPDATE",
                    (migration_id, actor.tenant_id, artifact_kind, revision),
                )
                link = cursor.fetchone()
                if link is None or str(link[1]) != object_id:
                    raise ArtifactError(409, "artifact_revision_conflict")
            self._access_event(
                cursor, actor.tenant_id, migration_id, object_id, actor.subject, "uploaded", "success", request_id,
                {"kind": artifact_kind, "classification": classification, "size": len(content), "sha256": digest_hex},
            )
            result = {
                "artifact_id": str(link[0]), "object_id": object_id, "migration_id": migration_id,
                "content_sha256": digest_hex, "content_size": len(content), "media_type": media_type,
                "classification": classification, "artifact_kind": artifact_kind, "revision": revision,
                "retention_until": row[5].isoformat(), "object_version": str(row[4]),
            }
            self._close(connection, cursor)
            connection = None
            return result
        except BaseException as exc:
            if connection is not None:
                self._close(connection, cursor, exc)
            raise

    def download(
        self,
        actor: ArtifactActor,
        migration_id: str,
        content_sha256: str,
        artifact_kind: str | None = None,
        request_id: str | None = None,
    ) -> ArtifactDownload:
        if not isinstance(actor, ArtifactActor) or not actor.tenant_id or not actor.subject or not actor.roles:
            raise ArtifactError(401, "unauthorized")
        if not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
            raise ArtifactError(400, "invalid_content_hash")
        connection, cursor = self._open()
        try:
            query = (
                "SELECT ao.id, ao.content_sha256, ao.content_size, ao.media_type, ao.classification, "
                "ao.storage_key, ao.object_version, ao.retention_until, ma.artifact_kind, ma.revision, "
                "al.status, al.legal_hold "
                "FROM migration_artifacts ma JOIN artifact_objects ao ON ao.id=ma.artifact_object_id AND ao.tenant_id=ma.tenant_id "
                "JOIN artifact_lifecycle al ON al.artifact_object_id=ao.id AND al.tenant_id=ao.tenant_id "
                "WHERE ma.tenant_id=%s AND ma.migration_id=%s AND ao.content_sha256=%s"
            )
            params: list[Any] = [actor.tenant_id, migration_id, bytes.fromhex(content_sha256)]
            if artifact_kind is not None:
                query += " AND ma.artifact_kind=%s"
                params.append(artifact_kind)
            query += " ORDER BY ma.revision DESC LIMIT 1"
            cursor.execute(query, tuple(params))
            row = cursor.fetchone()
            if row is None:
                raise ArtifactError(404, "artifact_not_found")
            object_id, digest, size, media_type, classification, key, version, retention_until, kind, revision, status, legal_hold = row
            if classification not in DOWNLOAD_ROLES or not DOWNLOAD_ROLES[classification].intersection(actor.roles):
                self._access_event(cursor, actor.tenant_id, migration_id, str(object_id), actor.subject,
                                   "denied", "denied", request_id, {"code": "forbidden"})
                self._close(connection, cursor)
                connection = None
                raise ArtifactError(403, "forbidden")
            if status != "available" or (retention_until <= datetime.now(timezone.utc) and not legal_hold):
                self._access_event(cursor, actor.tenant_id, migration_id, str(object_id), actor.subject,
                                   "denied", "denied", request_id, {"code": "artifact_expired"})
                self._close(connection, cursor)
                connection = None
                raise ArtifactError(410, "artifact_expired")
            self._close(connection, cursor)
            connection = None
        except BaseException as exc:
            if connection is not None:
                self._close(connection, cursor, exc)
            raise

        try:
            content, metadata = self._backend.get(str(key), str(version))
            try:
                verify_artifact_content(content, content_sha256, int(size), metadata, str(version))
                if sha256(content).digest() != bytes(digest):
                    raise ArtifactError(502, "artifact_integrity_failure")
            except ArtifactError:
                self._access_event_for_download(actor, migration_id, str(object_id), request_id,
                                                "integrity_failed", "failed", {"code": "content_hash_mismatch"})
                raise
        except ArtifactError:
            raise
        except Exception as exc:
            self._access_event_for_download(actor, migration_id, str(object_id), request_id,
                                            "integrity_failed", "failed", {"code": "object_storage_read_failed"})
            raise ArtifactError(502, "artifact_integrity_failure") from exc

        self._access_event_for_download(actor, migration_id, str(object_id), request_id,
                                        "downloaded", "success", {"sha256": content_sha256, "size": len(content)})
        return ArtifactDownload(
            content=content, content_sha256=content_sha256, content_type=str(media_type),
            content_size=len(content), classification=str(classification), artifact_kind=str(kind),
            revision=int(revision), object_version=str(version), integrity_verified=True,
        )

    def _access_event_for_download(self, actor: ArtifactActor, migration_id: str, object_id: str,
                                   request_id: str | None, action: str, outcome: str, details: dict) -> None:
        connection, cursor = self._open()
        try:
            self._access_event(cursor, actor.tenant_id, migration_id, object_id, actor.subject,
                               action, outcome, request_id, details)
            self._close(connection, cursor)
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def set_legal_hold(self, actor: ArtifactActor, content_sha256: str, classification: str,
                       enabled: bool, reason_code: str, request_id: str | None = None) -> None:
        if not isinstance(actor, ArtifactActor) or not {"owner", "admin", "privacy_officer"}.intersection(actor.roles):
            raise ArtifactError(403, "forbidden")
        if not re.fullmatch(r"[0-9a-f]{64}", content_sha256) or classification not in CLASSIFICATIONS:
            raise ArtifactError(400, "invalid_artifact_reference")
        if type(enabled) is not bool or not isinstance(reason_code, str) or not reason_code.strip():
            raise ArtifactError(400, "invalid_retention_action")
        action = "legal_hold_added" if enabled else "legal_hold_released"
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT ao.id, al.status, al.legal_hold FROM artifact_objects ao "
                "JOIN artifact_lifecycle al ON al.artifact_object_id=ao.id AND al.tenant_id=ao.tenant_id "
                "WHERE ao.tenant_id=%s AND ao.content_sha256=%s AND ao.classification=%s FOR UPDATE OF al",
                (actor.tenant_id, bytes.fromhex(content_sha256), classification),
            )
            row = cursor.fetchone()
            if row is None:
                raise ArtifactError(404, "artifact_not_found")
            object_id, status, current_hold = str(row[0]), str(row[1]), bool(row[2])
            if status != "available":
                raise ArtifactError(410, "artifact_not_available_for_hold")
            if current_hold == enabled:
                self._close(connection, cursor)
                return
            cursor.execute(
                "INSERT INTO artifact_retention_events (artifact_object_id, tenant_id, action, actor_subject, reason_code) "
                "VALUES (%s,%s,%s,%s,%s)",
                (object_id, actor.tenant_id, action, actor.subject, reason_code),
            )
            cursor.execute(
                "UPDATE artifact_lifecycle SET legal_hold=%s, updated_by=%s WHERE artifact_object_id=%s",
                (enabled, actor.subject, object_id),
            )
            self._access_event(cursor, actor.tenant_id, None, object_id, actor.subject, action, "success",
                               request_id, {"reason_code": reason_code})
            self._close(connection, cursor)
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def expire_due(self, limit: int = 100, worker_subject: str = "artifact-retention-worker") -> dict:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ArtifactError(400, "invalid_batch_size")
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT ao.id, ao.tenant_id, ao.storage_key, ao.object_version, ao.content_sha256, ao.classification, "
                "l.status FROM artifact_objects ao JOIN artifact_lifecycle l ON l.artifact_object_id=ao.id AND l.tenant_id=ao.tenant_id "
                "WHERE ao.retention_until <= now() AND l.legal_hold=false AND l.status IN ('available','expired') "
                "ORDER BY ao.retention_until, ao.id LIMIT %s FOR UPDATE OF l SKIP LOCKED",
                (limit,),
            )
            rows = cursor.fetchall()
            for row in rows:
                object_id, tenant_id, key, version, digest, classification, status = row
                if status == "available":
                    cursor.execute(
                        "INSERT INTO artifact_retention_events (artifact_object_id, tenant_id, action, actor_subject, reason_code) "
                        "VALUES (%s,%s,'expired',%s,'retention_period_elapsed')",
                        (object_id, tenant_id, worker_subject),
                    )
                    cursor.execute(
                        "UPDATE artifact_lifecycle SET status='expired', updated_by=%s WHERE artifact_object_id=%s",
                        (worker_subject, object_id),
                    )
                    self._access_event(cursor, str(tenant_id), None, str(object_id), worker_subject,
                                       "expired", "success", None, {"classification": classification})
            self._close(connection, cursor)
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

        deleted = 0
        failed = 0
        for row in rows:
            object_id, tenant_id, key, version, digest, classification, status = row
            try:
                self._backend.delete(str(key), str(version))
                connection, cursor = self._open()
                try:
                    cursor.execute(
                        "SELECT status, legal_hold FROM artifact_lifecycle WHERE artifact_object_id=%s AND tenant_id=%s FOR UPDATE",
                        (object_id, tenant_id),
                    )
                    current = cursor.fetchone()
                    if current is None or current[0] == "deleted" or current[1]:
                        self._close(connection, cursor)
                        connection = None
                        continue
                    cursor.execute(
                        "INSERT INTO artifact_retention_events (artifact_object_id, tenant_id, action, actor_subject, reason_code) "
                        "VALUES (%s,%s,'deleted',%s,'retention_object_deleted')",
                        (object_id, tenant_id, worker_subject),
                    )
                    cursor.execute(
                        "UPDATE artifact_lifecycle SET status='deleted', deleted_at=now(), updated_by=%s "
                        "WHERE artifact_object_id=%s AND tenant_id=%s",
                        (worker_subject, object_id, tenant_id),
                    )
                    self._access_event(cursor, str(tenant_id), None, str(object_id), worker_subject,
                                       "deleted", "success", None, {"classification": classification})
                    self._close(connection, cursor)
                    connection = None
                    deleted += 1
                except BaseException as exc:
                    if connection is not None:
                        self._close(connection, cursor, exc)
                    raise
            except Exception:
                failed += 1
        return {"examined": len(rows), "deleted": deleted, "failed": failed}
