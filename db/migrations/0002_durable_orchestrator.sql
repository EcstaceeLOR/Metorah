BEGIN;

DO $$
DECLARE constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'migrations'::regclass AND contype = 'c'
          AND pg_get_constraintdef(oid) ILIKE '%status%'
    LOOP
        EXECUTE format('ALTER TABLE migrations DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END;
$$;

ALTER TABLE migrations ADD CONSTRAINT migrations_status_allowed_check CHECK (status IN (
    'draft', 'prepared', 'enumerating', 'frozen', 'verifying', 'review', 'approved',
    'funding', 'ready', 'activated', 'claiming', 'paused', 'disputed',
    'cancelled', 'completed', 'incident'
));
ALTER TABLE migrations ADD CONSTRAINT migrations_freeze_checkpoint_check CHECK (
    status NOT IN ('frozen', 'verifying', 'review', 'approved', 'funding', 'ready', 'activated', 'claiming', 'paused', 'completed')
    OR (source_freeze_block_number IS NOT NULL AND source_freeze_block_hash IS NOT NULL)
);

ALTER TABLE jobs
    ADD COLUMN payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100),
    ADD COLUMN worker_id text,
    ADD COLUMN last_started_at timestamptz,
    ADD COLUMN last_heartbeat_at timestamptz,
    ADD COLUMN completed_at timestamptz;

CREATE TABLE idempotency_records (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (length(trim(operation)) > 0),
    idempotency_key text NOT NULL CHECK (length(trim(idempotency_key)) >= 8),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_status integer,
    response_body jsonb,
    resource_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    UNIQUE (tenant_id, operation, idempotency_key),
    CHECK ((response_status IS NULL) = (response_body IS NULL))
);
CREATE INDEX idempotency_expiry_idx ON idempotency_records (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE outbox_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    migration_id uuid NOT NULL REFERENCES migrations(id) ON DELETE RESTRICT,
    event_key text NOT NULL UNIQUE,
    event_type text NOT NULL,
    aggregate_version integer NOT NULL CHECK (aggregate_version > 0),
    payload jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE outbox_delivery (
    event_id uuid PRIMARY KEY REFERENCES outbox_events(id) ON DELETE RESTRICT,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'leased', 'published', 'failed')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    worker_id text,
    lease_until timestamptz,
    published_at timestamptz,
    last_error text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((state <> 'published') OR published_at IS NOT NULL)
);
CREATE INDEX outbox_delivery_ready_idx ON outbox_delivery (available_at, event_id) WHERE state IN ('pending', 'failed');
CREATE INDEX outbox_delivery_lease_idx ON outbox_delivery (lease_until) WHERE state = 'leased';

CREATE TABLE job_attempt_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    event_type text NOT NULL CHECK (event_type IN ('started', 'heartbeat', 'lease_expired', 'succeeded', 'failed', 'retry_scheduled', 'cancelled')),
    worker_id text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX job_attempt_events_timeline_idx ON job_attempt_events (job_id, attempt_number, occurred_at, id);

CREATE OR REPLACE FUNCTION record_migration_status_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    actor_type_value text;
    actor_id_value text;
    reason_value text;
    correlation_value text;
    allowed boolean := false;
    tenant_value uuid;
    event_id_value uuid;
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        allowed :=
            (OLD.status = 'draft' AND NEW.status IN ('prepared', 'enumerating', 'cancelled', 'incident')) OR
            (OLD.status = 'prepared' AND NEW.status IN ('frozen', 'disputed', 'cancelled', 'incident')) OR
            (OLD.status = 'enumerating' AND NEW.status IN ('frozen', 'disputed', 'cancelled', 'incident')) OR
            (OLD.status = 'frozen' AND NEW.status IN ('verifying', 'disputed', 'cancelled', 'incident')) OR
            (OLD.status = 'verifying' AND NEW.status IN ('review', 'frozen', 'disputed', 'incident')) OR
            (OLD.status = 'review' AND NEW.status IN ('approved', 'frozen', 'disputed', 'cancelled', 'incident')) OR
            (OLD.status = 'approved' AND NEW.status IN ('funding', 'ready', 'paused', 'cancelled', 'incident')) OR
            (OLD.status = 'funding' AND NEW.status IN ('ready', 'paused', 'incident')) OR
            (OLD.status = 'ready' AND NEW.status IN ('activated', 'paused', 'incident')) OR
            (OLD.status = 'activated' AND NEW.status IN ('claiming', 'paused', 'incident')) OR
            (OLD.status = 'claiming' AND NEW.status IN ('paused', 'completed', 'incident')) OR
            (OLD.status = 'paused' AND NEW.status IN ('activated', 'claiming', 'incident')) OR
            (OLD.status = 'disputed' AND NEW.status IN ('frozen', 'cancelled', 'incident')) OR
            (OLD.status = 'incident' AND NEW.status IN ('paused', 'verifying', 'frozen'));
        IF NOT allowed THEN
            RAISE EXCEPTION 'forbidden migration lifecycle transition: % -> %', OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'paused' AND NEW.status = 'activated'
            AND EXISTS (SELECT 1 FROM claims WHERE migration_id = NEW.id AND state = 'settled') THEN
            RAISE EXCEPTION 'paused migration with prior claims must resume in claiming state'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.status = 'paused' AND NEW.status = 'claiming'
            AND NOT EXISTS (SELECT 1 FROM claims WHERE migration_id = NEW.id AND state = 'settled') THEN
            RAISE EXCEPTION 'paused migration without prior claims must resume in activated state'
                USING ERRCODE = '23514';
        END IF;

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

        SELECT tenant_id INTO tenant_value FROM migrations WHERE id = NEW.id;
        event_id_value := gen_random_uuid();
        INSERT INTO outbox_events (
            id, tenant_id, migration_id, event_key, event_type, aggregate_version, payload
        ) VALUES (
            event_id_value, tenant_value, NEW.id,
            'migration:' || NEW.id::text || ':version:' || NEW.version::text,
            'migration.status_changed', NEW.version,
            jsonb_build_object(
                'migration_id', NEW.id, 'from_state', OLD.status, 'to_state', NEW.status,
                'version', NEW.version, 'actor_type', actor_type_value, 'actor_id', actor_id_value,
                'reason_code', reason_value, 'correlation_id', NULLIF(correlation_value, '')
            )
        );
        INSERT INTO outbox_delivery (event_id) VALUES (event_id_value);
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_job_state_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE allowed boolean := false;
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        allowed :=
            (OLD.state = 'queued' AND NEW.state IN ('running', 'cancelled')) OR
            (OLD.state = 'retry_wait' AND NEW.state IN ('running', 'cancelled', 'failed')) OR
            (OLD.state = 'running' AND NEW.state IN ('succeeded', 'failed', 'retry_wait', 'cancelled'));
        IF NOT allowed THEN
            RAISE EXCEPTION 'forbidden job transition: % -> %', OLD.state, NEW.state
                USING ERRCODE = '23514';
        END IF;
        IF NEW.state IN ('succeeded', 'failed', 'cancelled') THEN NEW.completed_at := now(); END IF;
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER jobs_state_guard BEFORE UPDATE OF state ON jobs
FOR EACH ROW EXECUTE FUNCTION guard_job_state_transition();

CREATE FUNCTION record_job_outbox_event() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    tenant_value uuid;
    event_id_value uuid;
    previous_state text;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.state IS NOT DISTINCT FROM OLD.state THEN RETURN NEW; END IF;
    SELECT tenant_id INTO tenant_value FROM migrations WHERE id = NEW.migration_id;
    event_id_value := gen_random_uuid();
    previous_state := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.state END;
    INSERT INTO outbox_events (
        id, tenant_id, migration_id, event_key, event_type, aggregate_version, payload
    ) VALUES (
        event_id_value, tenant_value, NEW.migration_id,
        'job:' || NEW.id::text || ':attempt:' || NEW.attempt_count::text || ':state:' || NEW.state,
        'job.state_changed', GREATEST(NEW.attempt_count, 1),
        jsonb_build_object('job_id', NEW.id, 'migration_id', NEW.migration_id,
            'from_state', previous_state, 'to_state', NEW.state, 'attempt_count', NEW.attempt_count)
    ) ON CONFLICT (event_key) DO NOTHING;
    INSERT INTO outbox_delivery (event_id)
        SELECT event_id_value WHERE EXISTS (SELECT 1 FROM outbox_events WHERE id = event_id_value)
    ON CONFLICT (event_id) DO NOTHING;
    RETURN NEW;
END;
$$;
CREATE TRIGGER jobs_outbox_insert AFTER INSERT ON jobs
FOR EACH ROW EXECUTE FUNCTION record_job_outbox_event();
CREATE TRIGGER jobs_outbox_state AFTER UPDATE OF state ON jobs
FOR EACH ROW EXECUTE FUNCTION record_job_outbox_event();

CREATE OR REPLACE FUNCTION reject_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only; % is forbidden', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER outbox_events_append_only BEFORE UPDATE OR DELETE ON outbox_events
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
CREATE TRIGGER outbox_events_no_truncate BEFORE TRUNCATE ON outbox_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_mutation();
CREATE TRIGGER job_attempt_events_append_only BEFORE UPDATE OR DELETE ON job_attempt_events
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
CREATE TRIGGER job_attempt_events_no_truncate BEFORE TRUNCATE ON job_attempt_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_mutation();

COMMIT;
