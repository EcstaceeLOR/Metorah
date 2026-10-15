# PostgreSQL persistence schema

The initial relational schema is in `db/migrations/0001_initial.sql`; the matching destructive rollback is `db/migrations/0001_rollback.sql`. The migration is intended to run against a clean, disposable database for this first version. Do not run the rollback against production without a separately approved backup/restore plan.

## Data model

- **Tenancy and access**: `tenants`, `users`, `tenant_memberships`. Membership roles are constrained, and tenant/user deletion is restricted rather than cascading away operational history.
- **Networks and assets**: `chains`, `source_assets`. A source asset is tied to one chain and unique by chain plus asset identity.
- **Migration lifecycle**: `migrations`, `migration_state_events`. Migration status is constrained; states that require a source freeze also require a block number and 32-byte block hash. A status transition requires transaction-local `metorah.actor_type`, `metorah.actor_id`, and `metorah.reason_code` settings; a trigger writes the transition event in the same transaction, and the event is append-only.
- **Manifests and verification**: `manifest_versions`, `verified_evidence`, `proof_verifications`. Digests and hashes have explicit 32-byte checks; manifest versions, evidence, and verification results are append-only records.
- **Durable work**: `jobs`, `job_attempts`. Migration-scoped idempotency keys and per-job attempt numbers are unique; attempts are append-only.
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

The script applies the schema, inserts a relational smoke fixture, verifies an attributed lifecycle transition is recorded atomically, proves append-only/uniqueness/attribution failures are rejected, rolls back to an empty schema, reapplies, and reruns the fixture. GitHub Actions provisions PostgreSQL 16 for this job.

## Security boundaries

This is the initial schema, not a complete production database service. Application authorization and row-level tenant isolation must be enforced in the API/database role policy; database credentials must be least-privilege; connection secrets belong in a secret manager. Do not store wallet signing secrets, seed phrases, or private keys. Evidence rows are immutable; corrections must be new rows with provenance, not UPDATEs. Production adoption still requires reviewed backup/restore, migration locking, access policy, and audit-hash computation.
