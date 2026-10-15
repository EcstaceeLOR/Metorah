# Durable migration orchestrator

## Persistence and transactions

The PostgreSQL-backed implementation lives in `tools/orchestrator/service.py`; schema changes are in `db/migrations/0002_durable_orchestrator.sql` with rollback in `0002_rollback.sql`. The service accepts a DB-API connection factory (for example, a configured psycopg connection pool) and keeps each operation in one transaction.

- Migration status changes lock the tenant-scoped migration row, require the expected version, enforce role/gate policy in the service, update status/version atomically, and rely on database triggers to enforce legal state edges and require transaction-local actor/reason context.
- The status trigger inserts the lifecycle event and outbox event/delivery row in the same transaction as the state change. A failed transaction therefore cannot leave a status change without its durable event.
- Idempotency records are unique by tenant, operation, and key; they store a canonical SHA-256 request hash and committed response. Exact retries return the saved response; payload reuse conflicts; another subject cannot replay the stored response.
- Job enqueueing is durable and tenant-scoped. Jobs begin in `queued`; the database rejects direct creation in terminal/running states and rejects illegal state transitions.
- Workers claim ready/expired jobs using `FOR UPDATE SKIP LOCKED`, a worker ID, attempt counter, and expiring lease. Heartbeats extend only a live lease owned by that worker. Completion is accepted only from the current lease owner.
- Failed attempts use bounded exponential retry. A worker that disappears leaves an expiring lease; the next worker records the expired attempt before taking a new one. Job attempt events are append-only.
- Outbox workers lease delivery rows independently of immutable event payloads. Published events are marked once; failures return to a delayed retry state; the same event ID/key is retained for consumer idempotency.

## Lifecycle controls

The service transition table separates operator, verifier, reviewer, governance, guardian, and service responsibilities and requires gate names supplied by trusted internal evidence/review services. These gate values are not accepted from client JSON and are not themselves cryptographic proofs. The database independently rejects invalid state edges, requires actor identity/reason settings for state changes, and records transitions atomically.

New migrations must begin in `draft` at version 1. Cancelled and completed states are terminal. A paused migration resumes to `activated` only when no settled claim exists, or to `claiming` when prior settled claims exist. A migration with a settled claim cannot be cancelled.

## Integration and limits

Run the PostgreSQL integration script against an empty disposable database:

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/metorah_test \
  bash tools/db/test_migrations.sh
```

It applies both migrations, exercises state-transition auditing, outbox insertion, job-state transitions, idempotency uniqueness, append-only enforcement, rollback to an empty schema, and reapplication. Unit tests cover canonical idempotency hashes and transition/role policy.

This is a durable orchestration core, not a fully deployed HTTP service. Production must supply a real JWT verifier, least-privilege DB credentials, verified evidence adapters, a worker supervisor, monitored lease expiry, outbox consumer deduplication, operational dashboards, backup/restore, and external security review. Do not treat fixture gate names as chain evidence or return success to a client before the transaction commits.
