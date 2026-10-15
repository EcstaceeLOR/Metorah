# Resumable source snapshot workers

## Trust boundaries

The worker is in `tools/orchestrator/snapshot_worker.py`; schema is `db/migrations/0003_resumable_snapshots.sql`. A run is pinned to one source chain ID, finalized block number/hash, state root, genesis hash, trie state version, finality-evidence digest, and verified registry-header commitment. The worker refuses to start unless trusted finality and registry-header verifier callbacks accept the exact checkpoint and commitment. An ordinary RPC response, a client-supplied boolean, or a header hash without authenticated finality evidence is not sufficient.

The callbacks are injected dependencies: the worker does not implement a live Substrate finality verifier or RPC transport itself. The deployment must connect the established finality/header and trie/storage-proof verifiers and must not expose these callbacks as client-controlled inputs.

## Durable partition processing

- Each run records the expected holder count and total supply from a verified registry-header commitment.
- Source indices are split into deterministic half-open ranges. The database stores the immutable range and pins every partition to the run.
- Workers claim partitions using row locks with `SKIP LOCKED`, bounded attempts, and expiring worker leases. Expired leases can be reclaimed; exhausted partitions fail the run instead of remaining stuck.
- A partition is committed only after every record has a valid storage proof against the run's pinned state root and the verifier's decoded account, storage key, index, and amount match the scanned record.
- Source indices must be contiguous and accounts are unique per run. Holder records, failures, and reconciliation evidence are append-only. A proof mismatch, duplicate account/index, or invalid persisted record fails the run closed.
- Exact repeated completion of an already-completed partition returns the stored result without inserting holders again. Transient verifier outages can release the lease into bounded exponential retry; cryptographic mismatches are permanent failures.
- The last partition triggers reconciliation of all index ranges, holder count, total supply, and a deterministic domain-separated inventory digest. The run cannot become `reconciled` without a matching verified reconciliation record.
- Migration lifecycle transitions into review/approval/funding/ready/activation/claiming/completed are blocked unless a reconciled run is pinned to the exact source-freeze block hash.

## Restart behavior

Use `resume_run(tenant_id, run_id)` to recover the persisted checkpoint. It takes no replacement block number/hash; workers obtain their checkpoint from the run row. Database triggers reject changes to checkpoint/commitment fields and prevent reopening terminal runs or completed partitions.

## Validation and limits

The PostgreSQL integration script applies all migrations, exercises the status gate before and after reconciliation, checks pinned checkpoint and terminal partition immutability, and tests the failure path for a missing reconciliation record. Python tests cover checkpoint shape, bounded deterministic partition ranges, and inventory digest determinism.

This implements the durable orchestration boundary and reconciliation logic. It does not assert that a production finality adapter, RPC endpoint, or deployment has been connected or independently audited.
