BEGIN;

CREATE TABLE artifact_retention_policies (
    classification text PRIMARY KEY CHECK (classification IN ('public_evidence','confidential','private_mapping')),
    retention_days integer NOT NULL CHECK (retention_days BETWEEN 1 AND 36500),
    max_size_bytes bigint NOT NULL CHECK (max_size_bytes BETWEEN 1 AND 104857600),
    storage_prefix text NOT NULL UNIQUE,
    policy_version text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO artifact_retention_policies (classification, retention_days, max_size_bytes, storage_prefix, policy_version) VALUES
    ('public_evidence', 3650, 52428800, 'public-evidence', 'retention-v1'),
    ('confidential', 365, 52428800, 'confidential', 'retention-v1'),
    ('private_mapping', 30, 10485760, 'private-mapping', 'privacy-retention-v1');

CREATE TABLE artifact_objects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    content_size bigint NOT NULL CHECK (content_size BETWEEN 1 AND 104857600),
    media_type text NOT NULL CHECK (media_type IN (
        'application/json','application/cbor','application/pdf','application/octet-stream',
        'application/zip','text/plain','text/csv'
    )),
    classification text NOT NULL REFERENCES artifact_retention_policies(classification) ON DELETE RESTRICT,
    storage_key text NOT NULL UNIQUE CHECK (storage_key NOT LIKE '/%' AND position('..' in storage_key) = 0 AND position(chr(92) in storage_key) = 0),
    object_version text NOT NULL CHECK (length(trim(object_version)) > 0),
    retention_until timestamptz NOT NULL,
    retention_policy_version text NOT NULL,
    created_by text NOT NULL CHECK (length(trim(created_by)) > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, content_sha256, classification),
    UNIQUE (id, tenant_id)
);

CREATE TABLE migration_artifacts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    migration_id uuid NOT NULL,
    artifact_object_id uuid NOT NULL,
    artifact_kind text NOT NULL CHECK (artifact_kind IN ('manifest','proof_bundle','signed_report','account_mapping','verification_trace')),
    revision integer NOT NULL CHECK (revision > 0),
    uploaded_by text NOT NULL CHECK (length(trim(uploaded_by)) > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (migration_id, tenant_id, artifact_kind, revision),
    FOREIGN KEY (migration_id, tenant_id) REFERENCES migrations(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (artifact_object_id, tenant_id) REFERENCES artifact_objects(id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX migration_artifacts_digest_idx ON migration_artifacts (tenant_id, artifact_object_id);

CREATE TABLE artifact_lifecycle (
    artifact_object_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'available' CHECK (status IN ('available','expired','deleted')),
    legal_hold boolean NOT NULL DEFAULT false,
    deleted_at timestamptz,
    updated_by text NOT NULL DEFAULT 'artifact-store',
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (artifact_object_id, tenant_id) REFERENCES artifact_objects(id, tenant_id) ON DELETE RESTRICT,
    CHECK ((status <> 'deleted') OR deleted_at IS NOT NULL)
);

CREATE TABLE artifact_access_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    migration_id uuid,
    artifact_object_id uuid,
    actor_subject text NOT NULL CHECK (length(trim(actor_subject)) > 0),
    action text NOT NULL CHECK (action IN ('uploaded','downloaded','denied','integrity_failed','expired','deleted','legal_hold_added','legal_hold_released')),
    outcome text NOT NULL CHECK (outcome IN ('success','denied','not_found','failed')),
    request_id text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (migration_id, tenant_id) REFERENCES migrations(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (artifact_object_id, tenant_id) REFERENCES artifact_objects(id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX artifact_access_timeline_idx ON artifact_access_events (tenant_id, occurred_at, id);
CREATE INDEX artifact_access_object_idx ON artifact_access_events (artifact_object_id, occurred_at, id) WHERE artifact_object_id IS NOT NULL;

CREATE TABLE artifact_retention_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_object_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('legal_hold_added','legal_hold_released','expired','deleted')),
    actor_subject text NOT NULL CHECK (length(trim(actor_subject)) > 0),
    reason_code text NOT NULL CHECK (length(trim(reason_code)) > 0),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (artifact_object_id, tenant_id) REFERENCES artifact_objects(id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX artifact_retention_timeline_idx ON artifact_retention_events (artifact_object_id, occurred_at, id);

CREATE FUNCTION guard_artifact_object_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE policy artifact_retention_policies%ROWTYPE;
BEGIN
    SELECT * INTO policy FROM artifact_retention_policies WHERE classification=NEW.classification;
    IF NOT FOUND THEN RAISE EXCEPTION 'artifact retention policy is missing' USING ERRCODE = '23514'; END IF;
    IF NEW.content_size > policy.max_size_bytes THEN
        RAISE EXCEPTION 'artifact exceeds classification size limit' USING ERRCODE = '23514';
    END IF;
    IF NEW.retention_until <= NEW.created_at OR
       NEW.retention_until > NEW.created_at + make_interval(days => policy.retention_days) THEN
        RAISE EXCEPTION 'artifact retention exceeds classification policy' USING ERRCODE = '23514';
    END IF;
    IF NEW.storage_key <> (
        'tenants/' || NEW.tenant_id::text || '/' || policy.storage_prefix || '/sha256/' ||
        substr(encode(NEW.content_sha256, 'hex'), 1, 2) || '/' || encode(NEW.content_sha256, 'hex')
    ) THEN
        RAISE EXCEPTION 'artifact key must exactly match tenant, classification and content digest'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER artifact_objects_insert_guard BEFORE INSERT ON artifact_objects
FOR EACH ROW EXECUTE FUNCTION guard_artifact_object_insert();

CREATE FUNCTION guard_migration_artifact_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE object_classification text;
BEGIN
    SELECT classification INTO object_classification
    FROM artifact_objects WHERE id=NEW.artifact_object_id AND tenant_id=NEW.tenant_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'artifact object must exist in the same tenant' USING ERRCODE = '23503';
    END IF;
    IF (NEW.artifact_kind = 'account_mapping' AND object_classification <> 'private_mapping')
       OR (object_classification = 'private_mapping' AND NEW.artifact_kind <> 'account_mapping') THEN
        RAISE EXCEPTION 'account mapping artifacts must use the private_mapping classification'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER migration_artifacts_classification_guard BEFORE INSERT ON migration_artifacts
FOR EACH ROW EXECUTE FUNCTION guard_migration_artifact_insert();

CREATE FUNCTION initialize_artifact_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO artifact_lifecycle (artifact_object_id, tenant_id, status, legal_hold, updated_by)
    VALUES (NEW.id, NEW.tenant_id, 'available', false, NEW.created_by);
    RETURN NEW;
END;
$$;
CREATE TRIGGER artifact_objects_lifecycle_init AFTER INSERT ON artifact_objects
FOR EACH ROW EXECUTE FUNCTION initialize_artifact_lifecycle();

CREATE FUNCTION guard_artifact_lifecycle_update() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE required_action text;
BEGIN
    IF OLD.status = 'deleted' THEN
        RAISE EXCEPTION 'deleted artifact lifecycle is terminal' USING ERRCODE = '23514';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NOT ((OLD.status='available' AND NEW.status IN ('expired','deleted')) OR
                (OLD.status='expired' AND NEW.status='deleted')) THEN
            RAISE EXCEPTION 'forbidden artifact lifecycle transition: % -> %', OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
        IF NEW.status IN ('expired','deleted') AND (OLD.legal_hold OR NEW.legal_hold) THEN
            RAISE EXCEPTION 'artifact under legal hold cannot expire or be deleted' USING ERRCODE = '23514';
        END IF;
        IF NEW.status IN ('expired','deleted') AND (SELECT retention_until FROM artifact_objects WHERE id=OLD.artifact_object_id) > now() THEN
            RAISE EXCEPTION 'artifact retention period has not elapsed' USING ERRCODE = '23514';
        END IF;
        IF NEW.legal_hold IS DISTINCT FROM OLD.legal_hold AND NEW.status <> 'available' THEN
            RAISE EXCEPTION 'legal hold can only change while an artifact is available' USING ERRCODE = '23514';
        END IF;
        IF NEW.status='deleted' THEN NEW.deleted_at := COALESCE(NEW.deleted_at, now()); END IF;
        required_action := CASE NEW.status WHEN 'expired' THEN 'expired' WHEN 'deleted' THEN 'deleted' ELSE NULL END;
        IF required_action IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM artifact_retention_events e
            WHERE e.artifact_object_id=OLD.artifact_object_id AND e.action=required_action
              AND e.actor_subject=NEW.updated_by
        ) THEN
            RAISE EXCEPTION 'retention event required for lifecycle transition' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.legal_hold IS DISTINCT FROM OLD.legal_hold THEN
        required_action := CASE WHEN NEW.legal_hold THEN 'legal_hold_added' ELSE 'legal_hold_released' END;
        IF NOT EXISTS (
            SELECT 1 FROM artifact_retention_events e
            WHERE e.artifact_object_id=OLD.artifact_object_id AND e.action=required_action
              AND e.actor_subject=NEW.updated_by
        ) THEN
            RAISE EXCEPTION 'retention event required for legal-hold change' USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
CREATE TRIGGER artifact_lifecycle_update_guard BEFORE UPDATE ON artifact_lifecycle
FOR EACH ROW EXECUTE FUNCTION guard_artifact_lifecycle_update();

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
    FOREACH table_name IN ARRAY ARRAY['artifact_objects','migration_artifacts','artifact_access_events','artifact_retention_events'] LOOP
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

COMMIT;
