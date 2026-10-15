BEGIN;

DROP TRIGGER IF EXISTS migrations_snapshot_gate ON migrations;
DROP TRIGGER IF EXISTS snapshot_runs_guard ON snapshot_runs;
DROP TRIGGER IF EXISTS snapshot_partitions_guard ON snapshot_partitions;
DROP TRIGGER IF EXISTS snapshot_holders_append_only ON snapshot_holders;
DROP TRIGGER IF EXISTS snapshot_holders_no_truncate ON snapshot_holders;
DROP TRIGGER IF EXISTS snapshot_failures_append_only ON snapshot_failures;
DROP TRIGGER IF EXISTS snapshot_failures_no_truncate ON snapshot_failures;
DROP TRIGGER IF EXISTS snapshot_reconciliations_append_only ON snapshot_reconciliations;
DROP TRIGGER IF EXISTS snapshot_reconciliations_no_truncate ON snapshot_reconciliations;

DROP FUNCTION IF EXISTS guard_migration_snapshot_gate();
DROP FUNCTION IF EXISTS guard_snapshot_partition_update();
DROP FUNCTION IF EXISTS guard_snapshot_run_update();

DROP TABLE IF EXISTS snapshot_reconciliations;
DROP TABLE IF EXISTS snapshot_failures;
DROP TABLE IF EXISTS snapshot_holders;
DROP TABLE IF EXISTS snapshot_partitions;
DROP TABLE IF EXISTS snapshot_runs;

ALTER TABLE migrations DROP CONSTRAINT IF EXISTS migrations_id_tenant_source_chain_unique;

COMMIT;
