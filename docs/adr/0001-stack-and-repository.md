# ADR-0001 — Metorah monorepo and provisional technology stack

Date: 2026-10-15 · Status: **Accepted for foundation**, conditional for chain-specific compatibility (#18).

## Context

Metorah is a long-lived cross-VM protocol product. The earlier baseline shipped an offline Python model and a Foundry Solidity draft. A single repo must eventually hold verifiable source WASM, EVM destination, canonical proof codec, backend, SDK, and web product while preventing unreviewed ABI/domain drift.

## Decision

- **Monorepo:** pnpm workspaces (not Turborepo by default). Keep build commands package-local; avoid nested Vercel `apps/web/apps/web` output-path errors. The root is not a deployable web app.
- **Apps (when implementation issues begin):** `apps/web` for Next.js + TypeScript frontend, `apps/api` for TypeScript/Fastify backend, `apps/worker` for durable verification/indexer jobs. No pretend pages or API endpoints are added by this ADR.
- **Shared modules:** `packages/protocol-core` for shared *noncryptographic* vocabulary today; future `packages/proof-format`, `packages/sdk`, and wallet adapters only after #25 defines canonical encoding.
- **Smart contracts:** Solidity 0.8.24 via Foundry for destination (already verified in CI); Rust/ink! for source **only when** Portaldot V3's actual WASM runtime and compiler compatibility are established (#18–#20). `rust-toolchain.toml` pins a provisional Rust 1.90.0 development baseline and does **not** certify chain deployment.
- **Infrastructure target:** PostgreSQL for durable migration state/audit, Redis-backed or equivalent durable queued workers, content-addressed object evidence storage; authentication with wallet challenge and organization roles. This is the design decision, not deployed infrastructure.
- **Local feasibility:** Python 3.13.7 test-only tooling. Pin legacy model transitive dependencies in `local_model/requirements.lock`. The historical `requirements.txt` remains range-based for explanatory compatibility; CI uses the lock.
- **JS version management:** Node 24.13.0 LTS, pnpm 10.19.0 with a committed zero-dependency lockfile and explicit workspace packages. The shared module uses Node's built-in test runner, so no external JS dependency is introduced prematurely.
- **Foundry:** retain Solidity version 0.8.24; pin Foundry installer input to released `v1.3.6` rather than mutable `stable`. Actual CLI fingerprint is recorded by CI; runtime compatibility remains separately verified.
- **CI:** independent Solidity, Python and JS jobs; a Rust toolchain smoke check, not a fabricated WASM source-contract test. New packages require new executable checks before merging.

## Constraints and security policy

`main` is protected *procedurally*: one issue branch, one PR, checks pass, merge and close issue. Enforce actual GitHub branch rules when repository settings/permissions allow. Pin action commit SHAs and update automation in supply-chain hardening issue #76. All chain IDs, ABI hashes, RPCs and deployment addresses must be from verified environments and configured explicitly. No credentials or locally generated private keys in source control. No placeholder `verified` backend and no default mainnet funds.

This ADR is not a protocol-version lock. Changing hash/domain encodings requires explicit versioning, test vectors and a separate reviewed ADR (#25–#26).

## Alternatives and tradeoffs

A single Next.js server for API and dashboard reduces initial files but ties workers and chain scanning to short-lived web requests, so rejected. Separate repositories would allow independently changing proof encodings without CI visibility, so rejected for initial product. A Turborepo can be added if justified by build metrics, but is not required for correctness.

## Revisit

After Portaldot runtime qualification (#18), proof spec (#25), database schema (#43), production deployment (#78), and dependency scanning (#76). Version changes must preserve published manifests and wallet-signature domains.
