BEGIN;

CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    display_name text NOT NULL CHECK (length(trim(display_name)) > 0),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE CHECK (email = lower(trim(email))),
    display_name text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_memberships (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'reviewer', 'viewer')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE chains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace text NOT NULL CHECK (namespace IN ('eip155', 'polkadot', 'kusama', 'custom')),
    chain_reference text NOT NULL CHECK (length(trim(chain_reference)) > 0),
    display_name text NOT NULL,
    finality_policy jsonb NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (namespace, chain_reference)
);

CREATE TABLE source_assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id uuid NOT NULL REFERENCES chains(id) ON DELETE RESTRICT,
    asset_namespace text NOT NULL,
    asset_reference text NOT NULL,
    standard text NOT NULL CHECK (standard IN ('native', 'erc20', 'erc721', 'erc1155', 'substrate_asset', 'vesting', 'other')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (chain_id, asset_namespace, asset_reference),
    UNIQUE (id, chain_id)
);

CREATE TABLE migrations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    migration_key text NOT NULL CHECK (length(trim(migration_key)) > 0),
    source_chain_id uuid NOT NULL REFERENCES chains(id) ON DELETE RESTRICT,
    destination_chain_id uuid NOT NULL REFERENCES chains(id) ON DELETE RESTRICT,
    source_asset_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'draft' CHECK (status IN (
        'draft', 'enumerating', 'frozen', 'verifying', 'review', 'approved',
        'funding', 'ready', 'activated', 'paused', 'cancelled', 'completed', 'incident'
    )),
    source_freeze_block_number numeric(78,0),
    source_freeze_block_hash bytea CHECK (source_freeze_block_hash IS NULL OR octet_length(source_freeze_block_hash) = 32),
    authorized_allocation numeric(78,0) NOT NULL CHECK (authorized_allocation > 0),
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, migration_key),
    UNIQUE (id, tenant_id),
    FOREIGN KEY (source_asset_id, source_chain_id) REFERENCES source_assets(id, chain_id) ON DELETE RESTRICT,
    CHECK (source_chain_id <> destination_chain_id),
    CHECK (status NOT IN ('frozen', 'verifying', 'review', 'approved', 'funding', 'ready', 'activated', 'paused', 'completed')
        OR (source_freeze_block_number IS NOT NULL AND source_freeze_block_hash IS NOT NULL))
);

CREATE TABLE manifest_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id uuid NOT NULL REFERENCES migrations(id) ON DELETE RESTRICT,
    version integer NOT NULL CHECK (version > 0),
    format_version text NOT NULL CHECK (length(trim(format_version)) > 0),
    manifest_hash bytea NOT NULL CHECK (octet_length(manifest_hash) = 32),
    leaf_count numeric(78,0) NOT NULL CHECK (leaf_count > 0),
    total_allocation numeric(78,0) NOT NULL CHECK (total_allocation > 0),
    content_uri text,
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (migration_id, version),
    UNIQUE (migration_id, manifest_hash),
    UNIQUE (id, migration_id)
);

CREATE TABLE verified_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id uuid NOT NULL REFERENCES migrations(id) ON DELETE RESTRICT,
    manifest_version_id uuid,
    evidence_kind text NOT NULL CHECK (evidence_kind IN ('freeze', 'enumeration', 'finality', 'storage_proof', 'binding', 'funding', 'settlement', 'incident')),
    source_chain_id uuid REFERENCES chains(id) ON DELETE RESTRICT,
    source_block_number numeric(78,0),
    source_block_hash bytea CHECK (source_block_hash IS NULL OR octet_length(source_block_hash) = 32),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    verifier_version text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('verified', 'rejected', 'inconclusive')),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    verified_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (manifest_version_id, migration_id) REFERENCES manifest_versions(id, migration_id) ON DELETE RESTRICT,
    UNIQUE (migration_id, evidence_kind, evidence_digest)
);

CREATE TABLE proof_verifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id uuid NOT NULL REFERENCES migrations(id) ON DELETE RESTRICT,
    manifest_version_id uuid NOT NULL,
    proof_kind text NOT NULL CHECK (length(trim(proof_kind)) > 0),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    outcome text NOT NULL CHECK (outcome IN ('verified', 'rejected', 'inconclusive')),
    verifier_version text NOT NULL,
    report jsonb NOT NULL DEFAULT '{}'::jsonb,
    checked_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (manifest_version_id, migration_id) REFERENCES manifest_versions(id, migration_id) ON DELETE RESTRICT,
    UNIQUE (migration_id, proof_kind, proof_digest)
);

CREATE TABLE jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id uuid NOT NULL REFERENCES migrations(id) ON DELETE RESTRICT,
    job_kind text NOT NULL CHECK (length(trim(job_kind)) > 0),
    idempotency_key text NOT NULL CHECK (length(trim(idempotency_key)) > 0),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'retry_wait')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_until timestamptz,
    last_error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (migration_id, idempotency_key)
);

CREATE TABLE job_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    outcome text NOT NULL CHECK (outcome IN ('running', 'succeeded', 'failed', 'cancelled')),
    error_code text,
    diagnostic jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (job_id, attempt_number),
    CHECK (finished_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE approvals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id uuid NOT NULL REFERENCES migrations(id) ON DELETE RESTRICT,
    manifest_version_id uuid,
    approval_kind text NOT NULL CHECK (approval_kind IN ('source_freeze', 'manifest', 'activation', 'recovery', 'resume', 'release')),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    signer_identity text NOT NULL CHECK (length(trim(signer_identity)) > 0),
    signature bytea NOT NULL CHECK (octet_length(signature) > 0),
    decision text NOT NULL CHECK (decision IN ('approve', 'reject', 'revoke')),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (manifest_version_id, migration_id) REFERENCES manifest_versions(id, migration_id) ON DELETE RESTRICT,
    UNIQUE (migration_id, approval_kind, subject_digest, signer_identity)
);

CREATE TABLE claims (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id uuid NOT NULL REFERENCES migrations(id) ON DELETE RESTRICT,
    claim_index numeric(78,0) NOT NULL CHECK (claim_index >= 0),
    source_account_digest bytea NOT NULL CHECK (octet_length(source_account_digest) = 32),
    beneficiary_chain_id uuid NOT NULL REFERENCES chains(id) ON DELETE RESTRICT,
    beneficiary_address text NOT NULL CHECK (length(trim(beneficiary_address)) > 0),
    amount numeric(78,0) NOT NULL CHECK (amount > 0),
    state text NOT NULL DEFAULT 'eligible' CHECK (state IN ('eligible', 'submitted', 'settled', 'failed', 'disputed')),
    destination_tx_hash bytea CHECK (destination_tx_hash IS NULL OR octet_length(destination_tx_hash) = 32),
    destination_block_number numeric(78,0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    settled_at timestamptz,
    UNIQUE (migration_id, claim_index),
    UNIQUE (migration_id, source_account_digest),
    CHECK ((state <> 'settled') OR (destination_tx_hash IS NOT NULL AND settled_at IS NOT NULL))
);

CREATE TABLE claim_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id uuid NOT NULL UNIQUE REFERENCES claims(id) ON DELETE RESTRICT,
    receipt_chain_id uuid NOT NULL REFERENCES chains(id) ON DELETE RESTRICT,
    transaction_hash bytea NOT NULL CHECK (octet_length(transaction_hash) = 32),
    block_number numeric(78,0) NOT NULL CHECK (block_number >= 0),
    block_hash bytea NOT NULL CHECK (octet_length(block_hash) = 32),
    log_index integer NOT NULL CHECK (log_index >= 0),
    receipt_digest bytea NOT NULL CHECK (octet_length(receipt_digest) = 32),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (receipt_chain_id, transaction_hash, log_index)
);

CREATE TABLE migration_state_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    migration_id uuid NOT NULL REFERENCES migrations(id) ON DELETE RESTRICT,
    from_state text,
    to_state text NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'service', 'governance', 'chain')),
    actor_id text,
    reason_code text NOT NULL,
    correlation_id uuid,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    details jsonb NOT NULL DEFAULT '{}'::jsonb
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

CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    actor_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'service', 'governance', 'chain', 'system')),
    event_type text NOT NULL CHECK (length(trim(event_type)) > 0),
    entity_type text NOT NULL CHECK (length(trim(entity_type)) > 0),
    entity_id uuid,
    correlation_id uuid,
    previous_event_hash bytea CHECK (previous_event_hash IS NULL OR octet_length(previous_event_hash) = 32),
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, event_hash)
);

CREATE TRIGGER migrations_status_audit
BEFORE UPDATE OF status ON migrations
FOR EACH ROW EXECUTE FUNCTION record_migration_status_transition();

CREATE INDEX migrations_tenant_status_idx ON migrations (tenant_id, status, updated_at DESC);
CREATE INDEX evidence_migration_kind_idx ON verified_evidence (migration_id, evidence_kind, verified_at DESC);
CREATE INDEX proofs_migration_outcome_idx ON proof_verifications (migration_id, outcome, checked_at DESC);
CREATE INDEX jobs_ready_idx ON jobs (state, available_at) WHERE state IN ('queued', 'retry_wait');
CREATE INDEX jobs_lease_idx ON jobs (lease_until) WHERE state = 'running';
CREATE INDEX claims_migration_state_idx ON claims (migration_id, state);
CREATE INDEX audit_tenant_time_idx ON audit_events (tenant_id, occurred_at DESC, id DESC);
CREATE INDEX migration_events_timeline_idx ON migration_state_events (migration_id, occurred_at, id);

CREATE FUNCTION reject_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only; % is forbidden', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$;

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'manifest_versions', 'verified_evidence', 'proof_verifications',
        'job_attempts', 'approvals', 'claim_receipts',
        'migration_state_events', 'audit_events'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation()',
            table_name || '_append_only', table_name
        );
    END LOOP;
END;
$$;

COMMIT;
