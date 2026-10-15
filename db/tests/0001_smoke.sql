\set ON_ERROR_STOP on
INSERT INTO tenants (id, slug, display_name)
VALUES ('00000000-0000-4000-8000-000000000001', 'acme-team', 'Acme Team');
INSERT INTO users (id, email, display_name)
VALUES ('00000000-0000-4000-8000-000000000002', 'operator@example.test', 'Operator');
INSERT INTO tenant_memberships (tenant_id, user_id, role)
VALUES ('00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', 'owner');
INSERT INTO chains (id, namespace, chain_reference, display_name, finality_policy, enabled)
VALUES
 ('00000000-0000-4000-8000-000000000003', 'eip155', '11155111', 'Sepolia', '{"confirmations": 12}'::jsonb, true),
 ('00000000-0000-4000-8000-000000000004', 'polkadot', 'test-parachain', 'Test Parachain', '{"finality": "grandpa"}'::jsonb, true);
INSERT INTO source_assets (id, chain_id, asset_namespace, asset_reference, standard)
VALUES ('00000000-0000-4000-8000-000000000005', '00000000-0000-4000-8000-000000000003', 'erc20', '0x0000000000000000000000000000000000000001', 'erc20');
INSERT INTO migrations (
 id, tenant_id, migration_key, source_chain_id, destination_chain_id, source_asset_id,
 status, source_freeze_block_number, source_freeze_block_hash, authorized_allocation, created_by
) VALUES (
 '00000000-0000-4000-8000-000000000006',
 '00000000-0000-4000-8000-000000000001', 'migration-test-1',
 '00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000004',
 '00000000-0000-4000-8000-000000000005', 'frozen', 12345,
 decode(repeat('11', 32), 'hex'), 1000, '00000000-0000-4000-8000-000000000002'
);
INSERT INTO manifest_versions (
 id, migration_id, version, format_version, manifest_hash, leaf_count, total_allocation, created_by
) VALUES (
 '00000000-0000-4000-8000-000000000007',
 '00000000-0000-4000-8000-000000000006', 1, 'v1',
 decode(repeat('22', 32), 'hex'), 1, 1000, '00000000-0000-4000-8000-000000000002'
);
INSERT INTO verified_evidence (
 id, migration_id, manifest_version_id, evidence_kind, source_chain_id, source_block_number,
 source_block_hash, evidence_digest, verifier_version, outcome
) VALUES (
 '00000000-0000-4000-8000-000000000008',
 '00000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000007',
 'freeze', '00000000-0000-4000-8000-000000000003', 12345,
 decode(repeat('11', 32), 'hex'), decode(repeat('33', 32), 'hex'), 'test-verifier/1', 'verified'
);
INSERT INTO proof_verifications (
 migration_id, manifest_version_id, proof_kind, proof_digest, outcome, verifier_version
) VALUES (
 '00000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000007',
 'merkle', decode(repeat('44', 32), 'hex'), 'verified', 'test-verifier/1'
);
INSERT INTO jobs (id, migration_id, job_kind, idempotency_key, state)
VALUES ('00000000-0000-4000-8000-000000000009', '00000000-0000-4000-8000-000000000006', 'verify', 'verify-v1', 'succeeded');
INSERT INTO job_attempts (job_id, attempt_number, started_at, finished_at, outcome)
VALUES ('00000000-0000-4000-8000-000000000009', 1, now() - interval '1 minute', now(), 'succeeded');
INSERT INTO approvals (
 migration_id, manifest_version_id, approval_kind, subject_digest, signer_identity, signature, decision
) VALUES (
 '00000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000007',
 'manifest', decode(repeat('55', 32), 'hex'), 'attester:1', decode('aabbcc', 'hex'), 'approve'
);
INSERT INTO claims (
 id, migration_id, claim_index, source_account_digest, beneficiary_chain_id,
 beneficiary_address, amount, state, destination_tx_hash, destination_block_number, settled_at
) VALUES (
 '00000000-0000-4000-8000-000000000010',
 '00000000-0000-4000-8000-000000000006', 0, decode(repeat('66', 32), 'hex'),
 '00000000-0000-4000-8000-000000000004', '5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8j2VY6F5p5M5Z', 1000,
 'settled', decode(repeat('77', 32), 'hex'), 54321, now()
);
INSERT INTO claim_receipts (
 claim_id, receipt_chain_id, transaction_hash, block_number, block_hash, log_index, receipt_digest
) VALUES (
 '00000000-0000-4000-8000-000000000010', '00000000-0000-4000-8000-000000000004',
 decode(repeat('77', 32), 'hex'), 54321, decode(repeat('88', 32), 'hex'), 0,
 decode(repeat('99', 32), 'hex')
);
INSERT INTO migration_state_events (migration_id, from_state, to_state, actor_type, actor_id, reason_code)
VALUES ('00000000-0000-4000-8000-000000000006', 'draft', 'frozen', 'user', 'operator@example.test', 'source-freeze-confirmed');

BEGIN;
SELECT set_config('metorah.actor_type', 'user', true);
SELECT set_config('metorah.actor_id', 'operator@example.test', true);
SELECT set_config('metorah.reason_code', 'verification-started', true);
UPDATE migrations SET status = 'verifying', version = version + 1
WHERE id = '00000000-0000-4000-8000-000000000006';
COMMIT;

INSERT INTO audit_events (
 tenant_id, actor_user_id, actor_type, event_type, entity_type, entity_id, event_hash, payload
) VALUES (
 '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002',
 'user', 'migration.frozen', 'migration', '00000000-0000-4000-8000-000000000006',
 decode(repeat('aa', 32), 'hex'), '{"migration_key":"migration-test-1"}'::jsonb
);

DO $$
BEGIN
    IF (SELECT count(*) FROM migrations WHERE status = 'verifying' AND version = 2) <> 1 THEN RAISE EXCEPTION 'migration status transition missing'; END IF;
    IF (SELECT count(*) FROM verified_evidence) <> 1 THEN RAISE EXCEPTION 'verified evidence row missing'; END IF;
    IF (SELECT count(*) FROM claims WHERE state = 'settled') <> 1 THEN RAISE EXCEPTION 'settled claim missing'; END IF;
    IF (SELECT count(*) FROM audit_events) <> 1 THEN RAISE EXCEPTION 'audit row missing'; END IF;
    IF (SELECT count(*) FROM migration_state_events WHERE migration_id = '00000000-0000-4000-8000-000000000006') <> 2 THEN RAISE EXCEPTION 'status transition was not recorded atomically'; END IF;
END;
$$;
