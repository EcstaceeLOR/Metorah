# Metorah threat model

The maintained, issue-linked threat model and evidence-claim policy is
**[SECURITY_TRUST_MODEL.md](SECURITY_TRUST_MODEL.md)** (issue #14).

This repository currently has only an offline Python simulation and a draft
Solidity accounting ledger. It does **not** prove real Portaldot chain finality,
source holder-set completeness, irrevocable source retirement, owner-approved
destination bindings, or backed destination settlement.

Neither an administrator-selected Merkle root nor an operator's approval is
proof that a migration is authentic. The new assurance presentation policy
(`tools/assurance/evaluate.py`) fails closed and does not perform cryptographic
verification or grant on-chain activation rights.

See #18, #20–#29, #36–#39, #73–#74 for dependent implementations and audits.
