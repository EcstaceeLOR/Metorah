"""Framework-neutral HTTP response adapters for the artifact API contract.

A web framework can pass its already-authenticated tenant actor into these handlers.
JWT verification, request-size limits, multipart parsing, rate limits, and CSRF controls
remain responsibilities of the hosting HTTP layer.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from uuid import UUID, uuid4
from typing import Any

from tools.artifacts.store import ArtifactActor, ArtifactError, ArtifactStore


@dataclass(frozen=True)
class ArtifactHTTPResponse:
    status: int
    headers: dict[str, str]
    body: bytes


SAFE_MESSAGES = {
    "unauthorized": "Authentication is required.",
    "forbidden": "The actor cannot access this artifact.",
    "migration_not_found": "Migration not found.",
    "artifact_not_found": "Artifact not found.",
    "artifact_expired": "Artifact is no longer available.",
    "artifact_integrity_failure": "Stored artifact failed integrity verification.",
    "artifact_too_large": "Artifact exceeds the allowed size.",
    "unsupported_media_type": "Artifact media type is not supported.",
    "privacy_classification_required": "Account mappings require private classification.",
    "artifact_revision_conflict": "Artifact revision already refers to different content.",
    "immutable_object_conflict": "Stored content-addressed object conflicts with the requested bytes.",
}


def _request_id(value: str | None) -> str:
    if isinstance(value, str):
        try:
            return str(UUID(value))
        except ValueError:
            pass
    return str(uuid4())


def _error_response(error: ArtifactError, request_id: str) -> ArtifactHTTPResponse:
    body = {
        "error": {
            "code": error.code,
            "message": SAFE_MESSAGES.get(error.code, "Artifact request could not be completed."),
            "request_id": request_id,
            "retryable": error.status >= 500,
        }
    }
    return ArtifactHTTPResponse(
        status=error.status,
        headers={"Content-Type": "application/json", "Cache-Control": "no-store", "X-Request-Id": request_id},
        body=json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )


def upload_artifact_response(
    store: ArtifactStore,
    actor: ArtifactActor,
    migration_id: str,
    artifact_kind: str,
    classification: str,
    content: bytes,
    media_type: str,
    revision: int,
    request_id: str | None = None,
) -> ArtifactHTTPResponse:
    request_id = _request_id(request_id)
    try:
        result = store.put(
            actor=actor, migration_id=migration_id, artifact_kind=artifact_kind,
            classification=classification, content=content, media_type=media_type,
            revision=revision, request_id=request_id,
        )
        return ArtifactHTTPResponse(
            status=201,
            headers={"Content-Type": "application/json", "Cache-Control": "no-store", "X-Request-Id": request_id},
            body=json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
    except ArtifactError as error:
        return _error_response(error, request_id)


def download_artifact_response(
    store: ArtifactStore,
    actor: ArtifactActor,
    migration_id: str,
    content_sha256: str,
    artifact_kind: str,
    request_id: str | None = None,
) -> ArtifactHTTPResponse:
    request_id = _request_id(request_id)
    try:
        artifact = store.download(
            actor=actor, migration_id=migration_id, content_sha256=content_sha256,
            artifact_kind=artifact_kind, request_id=request_id,
        )
        # Never use a client-supplied filename or render evidence inline.
        return ArtifactHTTPResponse(
            status=200,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(artifact.content_size),
                "Content-Disposition": f'attachment; filename="evidence-{artifact.content_sha256}.bin"',
                "Cache-Control": "no-store",
                "X-Request-Id": request_id,
                "X-Content-SHA256": artifact.content_sha256,
                "X-Artifact-Classification": artifact.classification,
                "X-Artifact-Kind": artifact.artifact_kind,
                "X-Artifact-Revision": str(artifact.revision),
                "X-Artifact-Media-Type": artifact.content_type,
            },
            body=artifact.content,
        )
    except ArtifactError as error:
        return _error_response(error, request_id)
