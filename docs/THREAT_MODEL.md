# Metorah outstanding security gates

- An administrator-supplied Merkle root is **not an authenticated source snapshot**. The final product needs chain-verifiable source proof or an openly governed trusted-root model.
- Source state completeness may be unknowable for non-enumerable mappings. The first version supports only explicitly enumerable, compatible contracts.
- Source must be irreversibly frozen/retired or locked for the full migration to prevent double use.
- Old AccountId32 ownership must be bound to the EVM beneficiary by verifiable, wallet-appropriate signatures, not by guessing address equivalence.
- Reorganizations and finality must be handled by explicit block hashes and storage roots; RPC response ≠ proof of finality.
- Users need a remediation flow for wrong destination mappings, unclaimed entitlements and unsupported state.
- Target claim ledger here records credits only. Real token issuance or redemption is not supplied.
- Root uniqueness doesn't imply supply completeness; independent audit of holder set and total allocation remains essential.
