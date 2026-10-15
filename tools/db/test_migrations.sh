#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?Set DATABASE_URL to an empty disposable PostgreSQL database}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PSQL=(psql "$DATABASE_URL" -v ON_ERROR_STOP=1)

apply_and_smoke() {
  "${PSQL[@]}" -f "$ROOT/db/migrations/0001_initial.sql"
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
expect_failure "verified evidence UPDATE is forbidden" \
  "${PSQL[@]}" -c "UPDATE verified_evidence SET outcome = 'rejected' WHERE id = '00000000-0000-4000-8000-000000000008'"
expect_failure "tenant slug uniqueness" \
  "${PSQL[@]}" -c "INSERT INTO tenants (slug, display_name) VALUES ('acme-team', 'Duplicate')"
expect_failure "cross-tenant foreign key is enforced" \
  "${PSQL[@]}" -c "INSERT INTO tenant_memberships (tenant_id, user_id, role) VALUES ('ffffffff-ffff-4fff-8fff-ffffffffffff', '00000000-0000-4000-8000-000000000002', 'viewer')"

"${PSQL[@]}" -f "$ROOT/db/migrations/0001_rollback.sql"
if [[ "$("${PSQL[@]}" -Atqc "SELECT to_regclass('public.tenants') IS NULL")" != "t" ]]; then
  echo "ERROR: rollback left schema tables behind" >&2
  exit 1
fi
echo "Rollback from clean schema: PASS"

# Reapply after rollback to prove the migration is repeatable from a clean database.
apply_and_smoke
echo "PostgreSQL migration + integrity + append-only + rollback + reapply: PASS"
