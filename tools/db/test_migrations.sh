#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?Set DATABASE_URL to an empty disposable PostgreSQL database}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PSQL=(psql "$DATABASE_URL" -v ON_ERROR_STOP=1)

apply_and_smoke() {
  "${PSQL[@]}" -f "$ROOT/db/migrations/0001_initial.sql"
  "${PSQL[@]}" -f "$ROOT/db/migrations/0002_durable_orchestrator.sql"
  "${PSQL[@]}" -f "$ROOT/db/migrations/0003_resumable_snapshots.sql"
  "${PSQL[@]}" -f "$ROOT/db/tests/0001_smoke.sql"
}

expect_failure() {
  local description="$1"
  shift
  if "$@"; then
    echo "ERROR: expected failure did not occur: $description" >&2
    exit 1
  fi
  echo "Expected constraint/immutability rejection: $description"
}

apply_and_smoke

expect_failure "audit event UPDATE is forbidden" \
  "${PSQL[@]}" -c "UPDATE audit_events SET payload = '{}'::jsonb WHERE id = 1"
expect_failure "audit event DELETE is forbidden" \
  "${PSQL[@]}" -c "DELETE FROM audit_events WHERE id = 1"
expect_failure "audit event TRUNCATE is forbidden" \
  "${PSQL[@]}" -c "TRUNCATE audit_events"
expect_failure "verified evidence UPDATE is forbidden" \
  "${PSQL[@]}" -c "UPDATE verified_evidence SET outcome = 'rejected' WHERE id = '00000000-0000-4000-8000-000000000008'"
expect_failure "migration status change requires actor/reason context" \
  "${PSQL[@]}" -c "UPDATE migrations SET status = 'frozen' WHERE id = '00000000-0000-4000-8000-000000000006'"
expect_failure "invalid lifecycle edge is rejected by database trigger" \
  "${PSQL[@]}" -c "UPDATE migrations SET status = 'activated' WHERE id = '00000000-0000-4000-8000-000000000006'"
expect_failure "outbox event UPDATE is forbidden" \
  "${PSQL[@]}" -c "UPDATE outbox_events SET payload = '{}'::jsonb WHERE event_key LIKE 'migration:%'"
expect_failure "pinned snapshot checkpoint is immutable" \
  "${PSQL[@]}" -c "UPDATE snapshot_runs SET pinned_block_hash = decode(repeat('13', 32), 'hex') WHERE id = '00000000-0000-4000-8000-000000000012'"
expect_failure "completed snapshot partition cannot be reopened" \
  "${PSQL[@]}" -c "UPDATE snapshot_partitions SET status = 'queued' WHERE run_id = '00000000-0000-4000-8000-000000000011' AND partition_index = 0"
expect_failure "reconciliation record is required before snapshot completion" \
  "${PSQL[@]}" -c "UPDATE snapshot_runs SET status = 'reconciled', processed_holder_count = 1, recombined_digest = decode(repeat('88', 32), 'hex') WHERE id = '00000000-0000-4000-8000-000000000012'"
expect_failure "idempotency key uniqueness is enforced" \
  "${PSQL[@]}" -c "INSERT INTO idempotency_records (tenant_id, operation, actor_subject, idempotency_key, request_hash) VALUES ('00000000-0000-4000-8000-000000000001', 'migration.transition', 'user-operator', 'transition-v1-key', decode(repeat('cc', 32), 'hex'))"
expect_failure "tenant slug uniqueness" \
  "${PSQL[@]}" -c "INSERT INTO tenants (slug, display_name) VALUES ('acme-team', 'Duplicate')"
expect_failure "cross-tenant foreign key is enforced" \
  "${PSQL[@]}" -c "INSERT INTO tenant_memberships (tenant_id, user_id, role) VALUES ('ffffffff-ffff-4fff-8fff-ffffffffffff', '00000000-0000-4000-8000-000000000002', 'viewer')"

"${PSQL[@]}" -f "$ROOT/db/migrations/0003_rollback.sql"
"${PSQL[@]}" -f "$ROOT/db/migrations/0002_rollback.sql"
"${PSQL[@]}" -f "$ROOT/db/migrations/0001_rollback.sql"
if [[ "$("${PSQL[@]}" -Atqc "SELECT to_regclass('public.tenants') IS NULL")" != "t" ]]; then
  echo "ERROR: rollback left schema tables behind" >&2
  exit 1
fi
echo "Rollback from clean schema: PASS"

# Reapply after rollback to prove the migration is repeatable from a clean database.
apply_and_smoke
echo "PostgreSQL migration + integrity + append-only + rollback + reapply: PASS"
