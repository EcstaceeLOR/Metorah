# PostgreSQL persistence schema

The PostgreSQL schema is applied in order by `db/migrations/0001_initial.sql` through `0004_artifact_storage.sql`; each migration has a matching destructive rollback. The integration script applies all four against a clean, disposable database, rolls all four back, and reapplies them. Do not run the rollback against production without a separately approved backup/restore plan.

## Data model

- **Tenancy and access**: `tenants`, `users`, `tenant_memberships`. Membership roles are constrained, and tenant/user deletion is restricted rather than cascading away operational history.
- **Networks and assets**: `chains`, `source_assets`. A source asset is tied to one chain and unique by chain plus asset identity.
- **Migration lifecycle**: `migrations`, `migration_state_events`. Migration status is constrained; states that require a source freeze also require a block number and 32-byte block hash. A status transition requires transaction-local `metorah.actor_type`, `metorah.actor_id`, and `metorah.reason_code` settings; a trigger writes the transition event in the same transaction, and the event is append-only.
- **Manifests and verification**: `manifest_versions`, `verified_evidence`, `proof_verifications`. Digests and hashes have explicit 32-byte checks; manifest versions, evidence, and verification results are append-only records.
- **Durable work**: `jobs`, `job_attempts`, `idempotency_records`, `job_attempt_events`, `outbox_events`, and `outbox_delivery`. Worker leases and delivery leases are recoverable; immutable event payloads are separated from mutable delivery state; idempotency records bind the request hash to the initiating subject.
- **Snapshot completeness**: `snapshot_runs`, `snapshot_partitions`, `snapshot_holders`, `snapshot_reconciliations`, and `snapshot_failures`. Pinned finalized-header fields are immutable, holder indices/accounts are unique, and lifecycle review/activation is blocked until a verified reconciliation matches the source-freeze block.
- **Evidence artifacts**: `artifact_objects`, `migration_artifacts`, `artifact_lifecycle`, `artifact_access_events`, `artifact_retention_events`, and `artifact_retention_policies`. Objects are content-addressed and immutable, links are tenant-scoped, private account mappings have stricter classification/retention, and legal holds require audited events.
- **Approvals**: `approvals` stores public approval signatures and signer identities, not private signing keys or wallet secrets. A signer can provide only one decision for a given migration, approval kind, subject digest, and identity.
- **Claims and receipts**: `claims`, `claim_receipts`. Claim index and source-account digest are unique within a migration; a claim has at most one canonical receipt, unique by destination chain, transaction, and log index.
- **Audit history**: `audit_events` records tenant-scoped actors, entity references, correlation IDs, payloads, and optional previous-event hashes. UPDATE, DELETE, and TRUNCATE are rejected by database triggers. The schema does not claim cryptographic hash-chain validation until the application computes and verifies each event hash.

## Integrity and operations

Foreign keys use `ON DELETE RESTRICT` for records that participate in verification, approvals, claims, or audit history. Lifecycle, job, and claim state fields use explicit allowlists. Partial indexes support queued-job polling and expired lease inspection; other indexes support migration, evidence, claims, and audit timelines.

Run the disposable-database integration check:

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/metorah_test \
  bash tools/db/test_migrations.sh
```

The script applies all four migrations, inserts relational smoke fixtures, verifies attributed lifecycle transitions, outbox writes, snapshot completeness gates, artifact classification/retention controls, and append-only/uniqueness failures, rolls back to an empty schema, reapplies, and reruns the fixtures. GitHub Actions provisions PostgreSQL 16 for this job.

## Security boundaries

This is the initial schema, not a complete production database service. Application authorization and row-level tenant isolation must be enforced in the API/database role policy; database credentials must be least-privilege; connection secrets belong in a secret manager. Do not store wallet signing secrets, seed phrases, or private keys. Evidence rows are immutable; corrections must be new rows with provenance, not UPDATEs. Production adoption still requires reviewed backup/restore, migration locking, access policy, and audit-hash computation.
