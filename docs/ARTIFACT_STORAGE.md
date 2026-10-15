# Evidence artifact storage and privacy controls

## Storage contract

`tools/artifacts/store.py` provides a content-addressed artifact store and a boto3-compatible S3 backend. The service computes SHA-256 itself; callers cannot choose a digest or object key. Keys are tenant- and classification-scoped:

```text
tenants/<tenant-id>/<classification>/sha256/<digest-prefix>/<sha256>
```

Writes use `IfNoneMatch: *` and require a non-null S3 object version ID. The backend never sets a public ACL. Configure a private bucket with versioning enabled, server-side encryption (SSE-S3 or SSE-KMS), TLS-only access, public access blocks, bucket policy denying overwrite/delete to normal application roles, and narrowly scoped retention-worker delete permission. Where available, use Object Lock or equivalent immutable retention controls. S3-compatible providers must support conditional writes and versioned reads/deletes.

On read, the store fetches the recorded object version and independently checks the bytes' SHA-256, byte count, and stored hash metadata before returning any content. A mismatch produces `artifact_integrity_failure` and an append-only audit event. The returned `content_sha256` is suitable for independent verification, e.g. `sha256sum downloaded-file`.

## Authorization and classification

- `public_evidence`: manifests, proof bundles, signed reports and verification traces visible to tenant viewers, operators, reviewers, and administrators.
- `confidential`: limited to owners, administrators and security reviewers.
- `private_mapping`: reserved exclusively for account-mapping artifacts; upload/download is limited to owners, administrators and privacy officers.

Tenant and migration scope is checked before an artifact can be downloaded. Artifact metadata, migration links, access events, and retention events are append-only. Access logs record digest, size, classification, action, outcome, and request ID; they must not contain raw account mappings, proof payloads, secrets, or signed URLs.

## Retention

The schema seeds versioned policy values:

| Classification | Maximum size | Retention |
|---|---:|---:|
| public_evidence | 50 MiB | 3,650 days |
| confidential | 50 MiB | 365 days |
| private_mapping | 10 MiB | 30 days |

Retention is fixed on object creation and enforced by a database trigger. A mapping cannot be stored under a less restrictive classification. Legal holds require a matching append-only retention event; held objects cannot expire or be deleted. The `expire_due` worker first makes due objects inaccessible, then deletes the exact stored object version and records the result. Failed deletions remain expired/inaccessible and can be retried. Configure bucket lifecycle rules as a backstop, not as a replacement for the database retention worker.

If object upload succeeds but the database transaction fails, an unindexed object may remain. Production operations should run an orphan-object reconciliation process and rely on classification-specific lifecycle policies to bound orphan retention. Do not list objects or expose object keys to tenant clients.

## Validation and limits

The PostgreSQL integration test applies all schema migrations and exercises content-addressed key validation, tenant scoping, account-mapping classification, append-only metadata/audit rows, legal-hold events, retention rejection, and rollback. Python unit tests cover upload role policy, private-mapping rules, conditional writes, versioning requirements, exact-version reads/deletes, and hash/size verification.

The repository includes the storage adapter and policy primitives, not a connected production bucket or HTTP deployment. The deployment must inject a configured S3-compatible client, configure bucket security/versioning/lifecycle, wire authenticated API handlers, and verify operational backup/restore and object-access monitoring before handling real customer data.
