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
 '00000000-0000-4000-8000-000000000005', 'draft', NULL,
 NULL, 1000, '00000000-0000-4000-8000-000000000002'
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
INSERT INTO jobs (id, migration_id, job_kind, idempotency_key, state, payload)
VALUES ('00000000-0000-4000-8000-000000000009', '00000000-0000-4000-8000-000000000006', 'verify', 'verify-v1', 'queued', '{"manifest_version":1}'::jsonb);
UPDATE jobs SET state='running', attempt_count=1, worker_id='test-worker',
    last_started_at=now(), last_heartbeat_at=now(), lease_until=now() + interval '1 minute'
WHERE id='00000000-0000-4000-8000-000000000009';
INSERT INTO job_attempt_events (job_id, attempt_number, event_type, worker_id)
VALUES ('00000000-0000-4000-8000-000000000009', 1, 'started', 'test-worker');
UPDATE jobs SET state='succeeded', worker_id=NULL, lease_until=NULL
WHERE id='00000000-0000-4000-8000-000000000009';
INSERT INTO job_attempts (job_id, attempt_number, started_at, finished_at, outcome)
VALUES ('00000000-0000-4000-8000-000000000009', 1, now() - interval '1 minute', now(), 'succeeded');
INSERT INTO job_attempt_events (job_id, attempt_number, event_type, worker_id)
VALUES ('00000000-0000-4000-8000-000000000009', 1, 'succeeded', 'test-worker');

INSERT INTO idempotency_records (
 tenant_id, operation, actor_subject, idempotency_key, request_hash, response_status, response_body, resource_id
) VALUES (
 '00000000-0000-4000-8000-000000000001', 'migration.transition', 'user-operator', 'transition-v1-key',
 decode(repeat('bb', 32), 'hex'), 200, '{"status":"verifying","version":2}'::jsonb,
 '00000000-0000-4000-8000-000000000006'
);
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
BEGIN;
SELECT set_config('metorah.actor_type', 'user', true);
SELECT set_config('metorah.actor_id', 'operator@example.test', true);
SELECT set_config('metorah.reason_code', 'source-eligible', true);
UPDATE migrations SET status = 'enumerating', version = version + 1
WHERE id = '00000000-0000-4000-8000-000000000006';
SELECT set_config('metorah.reason_code', 'source-freeze-confirmed', true);
UPDATE migrations SET status = 'frozen', version = version + 1,
    source_freeze_block_number = 12345, source_freeze_block_hash = decode(repeat('11', 32), 'hex')
WHERE id = '00000000-0000-4000-8000-000000000006';
SELECT set_config('metorah.reason_code', 'verification-started', true);
UPDATE migrations SET status = 'verifying', version = version + 1
WHERE id = '00000000-0000-4000-8000-000000000006';
COMMIT;

DO $
BEGIN
    BEGIN
        UPDATE migrations SET status = 'review', version = version + 1
        WHERE id = '00000000-0000-4000-8000-000000000006';
        RAISE EXCEPTION 'expected snapshot gate to reject review';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END;
$;

INSERT INTO audit_events (
 tenant_id, actor_user_id, actor_type, event_type, entity_type, entity_id, event_hash, payload
) VALUES (
 '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002',
 'user', 'migration.frozen', 'migration', '00000000-0000-4000-8000-000000000006',
 decode(repeat('aa', 32), 'hex'), '{"migration_key":"migration-test-1"}'::jsonb
);

INSERT INTO snapshot_runs (
 id, tenant_id, migration_id, source_chain_id, pinned_block_number, pinned_block_hash, state_root,
 genesis_hash, trie_state_version, finality_evidence_digest, registry_header_digest,
 expected_holder_count, expected_total_supply
) VALUES (
 '00000000-0000-4000-8000-000000000011',
 '00000000-0000-4000-8000-000000000001',
 '00000000-0000-4000-8000-000000000006',
 '00000000-0000-4000-8000-000000000003',
 12345, decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'),
 decode(repeat('33', 32), 'hex'), 1, decode(repeat('44', 32), 'hex'),
 decode(repeat('55', 32), 'hex'), 1, 1000
);
INSERT INTO snapshot_partitions (run_id, partition_index, start_index, end_index)
VALUES ('00000000-0000-4000-8000-000000000011', 0, 0, 1);
UPDATE snapshot_runs SET status='scanning' WHERE id='00000000-0000-4000-8000-000000000011';
INSERT INTO snapshot_holders (
 run_id, source_index, source_account_id, source_account_digest, storage_key, amount, proof_digest, partition_index
) VALUES (
 '00000000-0000-4000-8000-000000000011', 0, decode(repeat('ab', 32), 'hex'),
 decode(repeat('bc', 32), 'hex'), decode('01', 'hex'), 1000, decode(repeat('cd', 32), 'hex'), 0
);
UPDATE snapshot_partitions SET status='leased', attempt_count=1, worker_id='snapshot-worker',
 lease_until=now()+interval '1 minute' WHERE run_id='00000000-0000-4000-8000-000000000011' AND partition_index=0;
UPDATE snapshot_partitions SET status='completed', worker_id=NULL, lease_until=NULL, processed_count=1,
 amount_sum=1000, partial_digest=decode(repeat('de', 32), 'hex'),
 proof_bundle_digest=decode(repeat('ef', 32), 'hex'), completed_at=now()
WHERE run_id='00000000-0000-4000-8000-000000000011' AND partition_index=0;
UPDATE snapshot_runs SET processed_holder_count=1, observed_total_supply=1000
WHERE id='00000000-0000-4000-8000-000000000011';
UPDATE snapshot_runs SET status='reconciling' WHERE id='00000000-0000-4000-8000-000000000011';
INSERT INTO snapshot_reconciliations (
 run_id, outcome, pinned_block_hash, expected_holder_count, actual_holder_count,
 expected_total_supply, actual_total_supply, recombined_digest, verifier_version
) VALUES (
 '00000000-0000-4000-8000-000000000011', 'verified', decode(repeat('11', 32), 'hex'), 1, 1,
 1000, 1000, decode(repeat('88', 32), 'hex'), 'test-snapshot-verifier/1'
);
UPDATE snapshot_runs SET status='reconciled', recombined_digest=decode(repeat('88', 32), 'hex')
WHERE id='00000000-0000-4000-8000-000000000011';

INSERT INTO snapshot_runs (
 id, tenant_id, migration_id, source_chain_id, pinned_block_number, pinned_block_hash, state_root,
 genesis_hash, trie_state_version, finality_evidence_digest, registry_header_digest,
 expected_holder_count, expected_total_supply
) VALUES (
 '00000000-0000-4000-8000-000000000012',
 '00000000-0000-4000-8000-000000000001',
 '00000000-0000-4000-8000-000000000006',
 '00000000-0000-4000-8000-000000000003',
 12345, decode(repeat('12', 32), 'hex'), decode(repeat('22', 32), 'hex'),
 decode(repeat('33', 32), 'hex'), 1, decode(repeat('44', 32), 'hex'),
 decode(repeat('55', 32), 'hex'), 1, 1000
);
UPDATE snapshot_runs SET status='scanning' WHERE id='00000000-0000-4000-8000-000000000012';
UPDATE snapshot_runs SET status='reconciling' WHERE id='00000000-0000-4000-8000-000000000012';

BEGIN;
SELECT set_config('metorah.actor_type', 'user', true);
SELECT set_config('metorah.actor_id', 'operator@example.test', true);
SELECT set_config('metorah.reason_code', 'snapshot-reconciled', true);
UPDATE migrations SET status = 'review', version = version + 1
WHERE id = '00000000-0000-4000-8000-000000000006';
COMMIT;

DO $
BEGIN
    IF (SELECT count(*) FROM migrations WHERE status = 'review' AND version = 5) <> 1 THEN RAISE EXCEPTION 'migration status transition missing'; END IF;
    IF (SELECT count(*) FROM verified_evidence) <> 1 THEN RAISE EXCEPTION 'verified evidence row missing'; END IF;
    IF (SELECT count(*) FROM claims WHERE state = 'settled') <> 1 THEN RAISE EXCEPTION 'settled claim missing'; END IF;
    IF (SELECT count(*) FROM audit_events) <> 1 THEN RAISE EXCEPTION 'audit row missing'; END IF;
    IF (SELECT count(*) FROM migration_state_events WHERE migration_id = '00000000-0000-4000-8000-000000000006') <> 4 THEN RAISE EXCEPTION 'status transition was not recorded atomically'; END IF;
    IF (SELECT count(*) FROM outbox_events) <> 7 THEN RAISE EXCEPTION 'transactional outbox events missing'; END IF;
    IF (SELECT count(*) FROM outbox_delivery) <> 7 THEN RAISE EXCEPTION 'outbox delivery rows missing'; END IF;
    IF (SELECT count(*) FROM job_attempt_events WHERE job_id = '00000000-0000-4000-8000-000000000009') <> 2 THEN RAISE EXCEPTION 'job attempt timeline missing'; END IF;
    IF (SELECT count(*) FROM idempotency_records WHERE operation = 'migration.transition') <> 1 THEN RAISE EXCEPTION 'idempotency record missing'; END IF;
    IF (SELECT count(*) FROM snapshot_runs WHERE status = 'reconciled' AND pinned_block_hash = decode(repeat('11', 32), 'hex')) <> 1 THEN RAISE EXCEPTION 'pinned snapshot did not reconcile'; END IF;
    IF (SELECT count(*) FROM snapshot_holders WHERE run_id = '00000000-0000-4000-8000-000000000011') <> 1 THEN RAISE EXCEPTION 'snapshot holder not persisted'; END IF;
END;
$$;
