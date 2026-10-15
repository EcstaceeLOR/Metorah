BEGIN;

ALTER TABLE migrations
    ADD CONSTRAINT migrations_id_tenant_source_chain_unique UNIQUE (id, tenant_id, source_chain_id);

CREATE TABLE snapshot_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    migration_id uuid NOT NULL,
    source_chain_id uuid NOT NULL REFERENCES chains(id) ON DELETE RESTRICT,
    pinned_block_number numeric(78,0) NOT NULL CHECK (pinned_block_number >= 0),
    pinned_block_hash bytea NOT NULL CHECK (octet_length(pinned_block_hash) = 32),
    state_root bytea NOT NULL CHECK (octet_length(state_root) = 32),
    genesis_hash bytea NOT NULL CHECK (octet_length(genesis_hash) = 32),
    trie_state_version smallint NOT NULL CHECK (trie_state_version IN (0, 1)),
    finality_evidence_digest bytea NOT NULL CHECK (octet_length(finality_evidence_digest) = 32),
    registry_header_digest bytea NOT NULL CHECK (octet_length(registry_header_digest) = 32),
    expected_holder_count integer NOT NULL CHECK (expected_holder_count BETWEEN 1 AND 1000000),
    expected_total_supply numeric(78,0) NOT NULL CHECK (expected_total_supply >= 0),
    status text NOT NULL DEFAULT 'created' CHECK (status IN ('created','scanning','reconciling','reconciled','failed','cancelled')),
    processed_holder_count integer NOT NULL DEFAULT 0 CHECK (processed_holder_count >= 0),
    observed_total_supply numeric(78,0) NOT NULL DEFAULT 0 CHECK (observed_total_supply >= 0),
    recombined_digest bytea CHECK (recombined_digest IS NULL OR octet_length(recombined_digest) = 32),
    failure_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (migration_id, source_chain_id, pinned_block_hash),
    UNIQUE (id, migration_id),
    FOREIGN KEY (migration_id, tenant_id, source_chain_id)
        REFERENCES migrations(id, tenant_id, source_chain_id) ON DELETE RESTRICT,
    CHECK (processed_holder_count <= expected_holder_count),
    CHECK ((status <> 'reconciled') OR (processed_holder_count = expected_holder_count AND recombined_digest IS NOT NULL)),
    CHECK ((status <> 'failed') OR failure_code IS NOT NULL)
);

CREATE TABLE snapshot_partitions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id uuid NOT NULL REFERENCES snapshot_runs(id) ON DELETE RESTRICT,
    partition_index integer NOT NULL CHECK (partition_index >= 0),
    start_index integer NOT NULL CHECK (start_index >= 0),
    end_index integer NOT NULL CHECK (end_index > start_index),
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','leased','completed','permanent_failed')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100),
    available_at timestamptz NOT NULL DEFAULT now(),
    worker_id text,
    lease_until timestamptz,
    processed_count integer NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
    amount_sum numeric(78,0) NOT NULL DEFAULT 0 CHECK (amount_sum >= 0),
    partial_digest bytea CHECK (partial_digest IS NULL OR octet_length(partial_digest) = 32),
    proof_bundle_digest bytea CHECK (proof_bundle_digest IS NULL OR octet_length(proof_bundle_digest) = 32),
    completed_at timestamptz,
    last_error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, partition_index),
    UNIQUE (run_id, start_index, end_index),
    CHECK ((status <> 'completed') OR (
        processed_count = end_index - start_index AND partial_digest IS NOT NULL
        AND proof_bundle_digest IS NOT NULL AND completed_at IS NOT NULL
    ))
);
CREATE INDEX snapshot_partition_ready_idx ON snapshot_partitions (available_at, run_id, partition_index)
    WHERE status = 'queued';
CREATE INDEX snapshot_partition_lease_idx ON snapshot_partitions (lease_until, run_id)
    WHERE status = 'leased';

CREATE TABLE snapshot_holders (
    run_id uuid NOT NULL REFERENCES snapshot_runs(id) ON DELETE RESTRICT,
    source_index integer NOT NULL CHECK (source_index >= 0),
    source_account_id bytea NOT NULL CHECK (octet_length(source_account_id) BETWEEN 1 AND 64),
    source_account_digest bytea NOT NULL CHECK (octet_length(source_account_digest) = 32),
    storage_key bytea NOT NULL CHECK (octet_length(storage_key) BETWEEN 1 AND 512),
    amount numeric(78,0) NOT NULL CHECK (amount >= 0),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    partition_index integer NOT NULL CHECK (partition_index >= 0),
    verified_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, source_index),
    UNIQUE (run_id, source_account_digest),
    FOREIGN KEY (run_id, partition_index) REFERENCES snapshot_partitions(run_id, partition_index) ON DELETE RESTRICT
);

CREATE TABLE snapshot_failures (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES snapshot_runs(id) ON DELETE RESTRICT,
    partition_index integer,
    worker_id text,
    failure_code text NOT NULL,
    retryable boolean NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE snapshot_reconciliations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id uuid NOT NULL UNIQUE REFERENCES snapshot_runs(id) ON DELETE RESTRICT,
    outcome text NOT NULL CHECK (outcome IN ('verified','failed')),
    pinned_block_hash bytea NOT NULL CHECK (octet_length(pinned_block_hash) = 32),
    expected_holder_count integer NOT NULL CHECK (expected_holder_count >= 1),
    actual_holder_count integer NOT NULL CHECK (actual_holder_count >= 0),
    expected_total_supply numeric(78,0) NOT NULL CHECK (expected_total_supply >= 0),
    actual_total_supply numeric(78,0) NOT NULL CHECK (actual_total_supply >= 0),
    recombined_digest bytea NOT NULL CHECK (octet_length(recombined_digest) = 32),
    verifier_version text NOT NULL,
    mismatch_codes text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION guard_snapshot_run_update() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE allowed boolean := false;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.migration_id IS DISTINCT FROM OLD.migration_id
        OR NEW.source_chain_id IS DISTINCT FROM OLD.source_chain_id
        OR NEW.pinned_block_number IS DISTINCT FROM OLD.pinned_block_number
        OR NEW.pinned_block_hash IS DISTINCT FROM OLD.pinned_block_hash
        OR NEW.state_root IS DISTINCT FROM OLD.state_root
        OR NEW.genesis_hash IS DISTINCT FROM OLD.genesis_hash
        OR NEW.trie_state_version IS DISTINCT FROM OLD.trie_state_version
        OR NEW.finality_evidence_digest IS DISTINCT FROM OLD.finality_evidence_digest
        OR NEW.registry_header_digest IS DISTINCT FROM OLD.registry_header_digest
        OR NEW.expected_holder_count IS DISTINCT FROM OLD.expected_holder_count
        OR NEW.expected_total_supply IS DISTINCT FROM OLD.expected_total_supply THEN
        RAISE EXCEPTION 'snapshot checkpoint and commitment are immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        allowed :=
            (OLD.status = 'created' AND NEW.status IN ('scanning','failed','cancelled')) OR
            (OLD.status = 'scanning' AND NEW.status IN ('reconciling','failed','cancelled')) OR
            (OLD.status = 'reconciling' AND NEW.status IN ('reconciled','failed'));
        IF NOT allowed THEN
            RAISE EXCEPTION 'forbidden snapshot run transition: % -> %', OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
        IF NEW.status = 'reconciled' AND NOT EXISTS (
            SELECT 1 FROM snapshot_reconciliations r
            WHERE r.run_id = OLD.id AND r.outcome = 'verified'
              AND r.pinned_block_hash = OLD.pinned_block_hash
              AND r.actual_holder_count = OLD.expected_holder_count
              AND r.actual_total_supply = OLD.expected_total_supply
              AND r.recombined_digest = NEW.recombined_digest
        ) THEN
            RAISE EXCEPTION 'verified reconciliation record required before snapshot can complete'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.status = 'failed' AND NEW.failure_code IS NULL THEN
            RAISE EXCEPTION 'failed snapshot requires failure_code'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
CREATE TRIGGER snapshot_runs_guard BEFORE UPDATE ON snapshot_runs
FOR EACH ROW EXECUTE FUNCTION guard_snapshot_run_update();

CREATE FUNCTION guard_snapshot_partition_update() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE allowed boolean := false;
BEGIN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.partition_index IS DISTINCT FROM OLD.partition_index
        OR NEW.start_index IS DISTINCT FROM OLD.start_index
        OR NEW.end_index IS DISTINCT FROM OLD.end_index
        OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts THEN
        RAISE EXCEPTION 'snapshot partition identity and range are immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'completed' OR OLD.status = 'permanent_failed' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'terminal snapshot partition cannot be modified'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        allowed :=
            (OLD.status = 'queued' AND NEW.status IN ('leased','permanent_failed')) OR
            (OLD.status = 'leased' AND NEW.status IN ('leased','queued','completed','permanent_failed'));
        IF NEW.status IS DISTINCT FROM OLD.status AND NOT allowed THEN
            RAISE EXCEPTION 'forbidden snapshot partition transition: % -> %', OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
CREATE TRIGGER snapshot_partitions_guard BEFORE UPDATE ON snapshot_partitions
FOR EACH ROW EXECUTE FUNCTION guard_snapshot_partition_update();

CREATE FUNCTION guard_migration_snapshot_gate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IN ('review','approved','funding','ready','activated','claiming','completed')
       AND NEW.status IS DISTINCT FROM OLD.status
       AND NOT EXISTS (
           SELECT 1 FROM snapshot_runs s
           WHERE s.migration_id = NEW.id
             AND s.source_chain_id = NEW.source_chain_id
             AND s.pinned_block_hash = NEW.source_freeze_block_hash
             AND s.status = 'reconciled'
       ) THEN
        RAISE EXCEPTION 'verified complete snapshot at the frozen source block is required'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER migrations_snapshot_gate BEFORE UPDATE OF status ON migrations
FOR EACH ROW EXECUTE FUNCTION guard_migration_snapshot_gate();

CREATE OR REPLACE FUNCTION reject_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only; % is forbidden', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$;
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['snapshot_holders','snapshot_failures','snapshot_reconciliations'] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation()',
            table_name || '_append_only', table_name
        );
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_mutation()',
            table_name || '_no_truncate', table_name
        );
    END LOOP;
END;
$$;

CREATE INDEX snapshot_runs_migration_status_idx ON snapshot_runs (migration_id, status, created_at DESC);
CREATE INDEX snapshot_failures_run_time_idx ON snapshot_failures (run_id, occurred_at, id);

COMMIT;
