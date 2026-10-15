# WASM and Foundry toolchain qualification (issue #19)

**Status: toolchain build verification in progress; Portaldot V3 runtime support unverified.**

Metorah currently develops two independent contract toolchains:
- **Destination EVM:** Solidity `0.8.24`, Foundry `v1.3.6` (`foundry.toml`); GitHub Actions must compile and run its existing Foundry suite on each PR.
- **Source WASM development baseline only:** Rust `1.90.0` with `rust-src` and `wasm32-unknown-unknown`, ink! `5.1.1`, cargo-contract `5.0.3`. These are **candidates**, not an officially approved Portaldot V3 combination. The 2026 ink! docs warn active maintenance stopped in January 2026; assess long-term viability and alternative WASM runtime when #18 completes.

## What the fixture proves — and does not prove

`contracts/wasm/toolchain-smoke/` is a real ink! contract with a constructor, messages and three off-chain `#[ink::test]` unit tests. Its internal `freeze` flag tests compiler/ABI/test-harness basics. It **does not** migrate users' balances, enumerate holders, produce source proofs, authenticate beneficiaries, make source immutability guarantees, or contain production claim logic.

Successful `cargo contract build --release` establishes **ink! compatibility with that Rust/cargo-contract build toolchain**, not bytecode acceptance on Portaldot. The contract must not be deployed with funds. The real source contract is issue #20, and deployment runtime qualification remains #18.

## Reproduce clean-room

Install only vetted Rust and Foundry binaries. Do not run unknown Portaldot node archives or submit transactions with an experimental toolchain.

```sh
rustup toolchain install 1.90.0 --profile minimal --component rust-src --component rustfmt --component clippy --target wasm32-unknown-unknown
rustup run 1.90.0 rustc --version
cargo install cargo-contract --version 5.0.3 --locked
cargo contract --version

# Use the exact checked-in Cargo.lock, once generated and code-reviewed.
cargo test --manifest-path contracts/wasm/toolchain-smoke/Cargo.toml --locked
cargo contract build --release --manifest-path contracts/wasm/toolchain-smoke/Cargo.toml
# Inspect target/ink/metorah_toolchain_smoke.contract and its code/metadata hash.

forge --version
forge build
forge test -vvv
```

`cargo contract build` typically packages `.wasm`, contract ABI metadata and `.contract`; validate the output exists before reporting build success. Hash every artifact as part of CI and retain logs with the source commit.

## Remaining blocking work

1. #18: obtain organizer-authenticated V3 network genesis, RPC endpoints, actual contracts pallet versus pallet-revive support and EVM chain ID. Merely recognizing `contracts_call` or `eth_chainId` from an RPC method list is not enough.
2. Verify the actual required WASM contract generation, runtime configuration, and API compatibility against official source metadata or a vetted node. Re-pin ink!/cargo-contract/Rust if incompatible.
3. Do not merge an allegedly "qualified" environment PR if its contract build job is red. Expose compiler mismatch with failing CI logs and keep the issue open until acceptance gates pass.
4. #20: implement the real source ledger including complete holder inventory, auth and irreversible freeze, then run genuine chain-specific deployment tests.
