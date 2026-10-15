BEGIN;

DROP TRIGGER IF EXISTS jobs_outbox_insert ON jobs;
DROP TRIGGER IF EXISTS jobs_outbox_state ON jobs;
DROP TRIGGER IF EXISTS jobs_state_guard ON jobs;
DROP TRIGGER IF EXISTS migrations_status_audit ON migrations;
DROP TRIGGER IF EXISTS migrations_initial_state_guard ON migrations;
DROP TRIGGER IF EXISTS outbox_events_append_only ON outbox_events;
DROP TRIGGER IF EXISTS outbox_events_no_truncate ON outbox_events;
DROP TRIGGER IF EXISTS job_attempt_events_append_only ON job_attempt_events;
DROP TRIGGER IF EXISTS job_attempt_events_no_truncate ON job_attempt_events;

DROP FUNCTION IF EXISTS record_job_outbox_event();
DROP FUNCTION IF EXISTS guard_job_state_transition();
DROP FUNCTION IF EXISTS guard_migration_initial_state();
DROP FUNCTION IF EXISTS record_migration_status_transition();

DROP TABLE IF EXISTS job_attempt_events;
DROP TABLE IF EXISTS outbox_delivery;
DROP TABLE IF EXISTS outbox_events;
DROP TABLE IF EXISTS idempotency_records;

ALTER TABLE jobs
    DROP COLUMN IF EXISTS completed_at,
    DROP COLUMN IF EXISTS last_heartbeat_at,
    DROP COLUMN IF EXISTS last_started_at,
    DROP COLUMN IF EXISTS worker_id,
    DROP COLUMN IF EXISTS max_attempts,
    DROP COLUMN IF EXISTS payload;

DO $$
DECLARE constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'migrations'::regclass AND contype = 'c'
          AND (pg_get_constraintdef(oid) ILIKE '%status%' OR conname = 'migrations_freeze_checkpoint_check')
    LOOP
        EXECUTE format('ALTER TABLE migrations DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END;
$$;

ALTER TABLE migrations ADD CONSTRAINT migrations_status_check CHECK (status IN (
    'draft', 'enumerating', 'frozen', 'verifying', 'review', 'approved',
    'funding', 'ready', 'activated', 'paused', 'cancelled', 'completed', 'incident'
));
ALTER TABLE migrations ADD CONSTRAINT migrations_freeze_checkpoint_check CHECK (
    status NOT IN ('frozen', 'verifying', 'review', 'approved', 'funding', 'ready', 'activated', 'paused', 'completed')
    OR (source_freeze_block_number IS NOT NULL AND source_freeze_block_hash IS NOT NULL)
);

CREATE FUNCTION record_migration_status_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    actor_type_value text;
    actor_id_value text;
    reason_value text;
    correlation_value text;
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        actor_type_value := current_setting('metorah.actor_type', true);
        actor_id_value := current_setting('metorah.actor_id', true);
        reason_value := current_setting('metorah.reason_code', true);
        correlation_value := current_setting('metorah.correlation_id', true);
        IF actor_type_value IS NULL OR actor_type_value NOT IN ('user', 'service', 'governance', 'chain')
            OR actor_id_value IS NULL OR length(trim(actor_id_value)) = 0
            OR reason_value IS NULL OR length(trim(reason_value)) = 0 THEN
            RAISE EXCEPTION 'migration status changes require transaction-local actor and reason context'
                USING ERRCODE = '42501';
        END IF;
        INSERT INTO migration_state_events (
            migration_id, from_state, to_state, actor_type, actor_id, reason_code,
            correlation_id, details
        ) VALUES (
            NEW.id, OLD.status, NEW.status, actor_type_value, actor_id_value, reason_value,
            NULLIF(correlation_value, '')::uuid,
            jsonb_build_object('migration_version', NEW.version)
        );
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER migrations_status_audit BEFORE UPDATE OF status ON migrations
FOR EACH ROW EXECUTE FUNCTION record_migration_status_transition();

COMMIT;
