BEGIN;

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS migration_state_events;
DROP TABLE IF EXISTS claim_receipts;
DROP TABLE IF EXISTS claims;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS job_attempts;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS proof_verifications;
DROP TABLE IF EXISTS verified_evidence;
DROP TABLE IF EXISTS manifest_versions;
DROP TABLE IF EXISTS migrations;
DROP TABLE IF EXISTS source_assets;
DROP TABLE IF EXISTS chains;
DROP TABLE IF EXISTS tenant_memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
DROP FUNCTION IF EXISTS reject_append_only_mutation();

COMMIT;
