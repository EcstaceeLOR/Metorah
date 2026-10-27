# Destination broadcaster and canonical event indexer

Issue #48 introduces `tools/destination/indexer.py` and `tools/destination/persistence.py`.

## Security model

- The broadcaster requires an explicitly configured chain ID, ledger/escrow destination allowlist, zero native value, successful `eth_call` simulation, and successful gas estimation before an externally supplied signer can sign. It returns **submitted**, never **settled**.
- A successful receipt requires `status == 1`, the configured confirmation depth, and the canonical block hash. HTTP acceptance is not a claim settlement.
- The indexer indexes only blocks deeper than the confirmation threshold. It checks canonical block hashes, validates event addresses and log hashes, and rescans after reorgs. The index is a **derived projection**, not the immutable source evidence.
- The SQLite store commits block cursor and event projection in a single transaction. It is a single-worker adapter; distributed deployments require a coordinated transactional store and exclusive lease.
- Reconciliation compares canonical settlement-event projections to expected claims; it must not be used to authorize transfers or treat unverified events as final.

## Required production integration

Inject a trusted authenticated JSON-RPC transport and a separately managed signer. Restrict the event decoder to verified ABI signatures for the deployed ledger, settlement and factory contracts. Register the deployment chain ID and contract addresses from independently verified deployment evidence. Configure finality depth according to the actual chain. Wire the resulting projection to the claim database with a transactional reconciliation worker; do not mark a claim settled solely on broadcast or receipt without validating its settlement log and account binding. Provide chain transaction hashes as evidence only after they have actually been observed. Neither live deployments nor real transactions are asserted by the included tests.

## Tests

Run `python -m unittest discover -s test -p test_destination_indexer.py -v`. Tests cover chain allowlisting, simulation failures, confirmation gating, canonical reorg replay, persisted cursor recovery, and reconciliation mismatches.
