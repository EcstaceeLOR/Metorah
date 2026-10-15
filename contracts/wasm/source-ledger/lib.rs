#![cfg_attr(not(feature = "std"), no_std, no_main)]
//! Metorah source-side fungible ledger — development implementation for #20.
//!
//! WARNING: NOT deployed, NOT Portaldot V3-qualified, NOT externally audited.
//! A local ink! unit test is not a finality/storage proof or complete migration.
//! User beneficiary registration, canonical proofs and chain finality are separate issues.

#[ink::contract]
mod metorah_source_ledger {
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;

    const PAGE_LIMIT: u32 = 64;

    /// Only prevalidated transitions are allowed to mutate persistent state.
    #[derive(Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub enum LedgerError {
        Unauthorized,
        AlreadyFrozen,
        Frozen,
        InvalidAmount,
        InvalidRecipient,
        SelfTransfer,
        InsufficientBalance,
        SupplyCapExceeded,
        ArithmeticOverflow,
        HolderRegistryFull,
        InvalidBeneficiary,
        NoActiveEntitlement,
        InvalidBindingNonce,
        BindingNonceExhausted,
        UnboundActiveHolders,
    }

    pub type Result<T> = core::result::Result<T, LedgerError>;

    /// Authorized by the source AccountId that dispatched the ink! message.
    /// The target chain, target contract and migration ID are immutable
    /// deployment-wide domain fields, not arbitrarily caller-selected values.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
    pub struct BindingRecord {
        pub beneficiary: [u8; 20],
        pub nonce: u64,
    }

    /// The complete historical set of funded holders can be read by dense index.
    /// A zero balance does not remove a holder, preventing holes or index reuse.
    #[ink(storage)]
    pub struct MetorahSourceLedger {
        owner: AccountId,
        frozen: bool,
        freeze_block: Option<BlockNumber>,
        asset_id: [u8; 32],
        decimals: u8,
        max_supply: Balance,
        total_supply: Balance,
        balances: Mapping<AccountId, Balance>,
        holders: Mapping<u32, AccountId>,
        slots_plus_one: Mapping<AccountId, u32>,
        holder_count: u32,
        active_holder_count: u32,
        unbound_active_holders: u32,
        destination_chain_id: u64,
        destination_contract: [u8; 20],
        migration_id: [u8; 32],
        bindings: Mapping<AccountId, BindingRecord>,
    }

    #[ink(event)]
    pub struct Issued {
        #[ink(topic)]
        to: AccountId,
        amount: Balance,
    }

    #[ink(event)]
    pub struct Transferred {
        #[ink(topic)]
        from: AccountId,
        #[ink(topic)]
        to: AccountId,
        amount: Balance,
    }

    #[ink(event)]
    pub struct Burned {
        #[ink(topic)]
        from: AccountId,
        amount: Balance,
    }

    #[ink(event)]
    pub struct SourceFrozen {
        #[ink(topic)]
        by: AccountId,
        #[ink(topic)]
        source_contract: AccountId,
        source_block: BlockNumber,
        asset_id: [u8; 32],
        migration_id: [u8; 32],
        destination_chain_id: u64,
        destination_contract: [u8; 20],
        total_supply: Balance,
        holder_count: u32,
        active_holder_count: u32,
        unbound_active_holders: u32,
    }

    #[ink(event)]
    pub struct BeneficiaryRegistered {
        #[ink(topic)]
        source_owner: AccountId,
        source_contract: AccountId,
        destination_chain_id: u64,
        destination_contract: [u8; 20],
        migration_id: [u8; 32],
        previous_beneficiary: [u8; 20],
        beneficiary: [u8; 20],
        nonce: u64,
    }

    impl MetorahSourceLedger {
        /// No pre-funded or hidden allocations are created by deployment.
        /// The asset ID is application-defined, NOT a chain-authenticated claim.
        #[ink(constructor)]
        pub fn new(
            asset_id: [u8; 32],
            decimals: u8,
            max_supply: Balance,
            destination_chain_id: u64,
            destination_contract: [u8; 20],
            migration_id: [u8; 32],
        ) -> Self {
            assert!(asset_id != [0u8; 32], "asset ID cannot be all zero");
            assert!(decimals <= 18, "unsupported decimal precision");
            assert!(max_supply > 0, "supply cap must be positive");
            assert!(destination_chain_id != 0, "destination chain ID cannot be zero");
            assert!(destination_contract != [0u8; 20], "destination contract cannot be zero");
            assert!(migration_id != [0u8; 32], "migration ID cannot be zero");
            Self {
                owner: Self::env().caller(),
                frozen: false,
                freeze_block: None,
                asset_id,
                decimals,
                max_supply,
                total_supply: 0,
                balances: Mapping::default(),
                holders: Mapping::default(),
                slots_plus_one: Mapping::default(),
                holder_count: 0,
                active_holder_count: 0,
                unbound_active_holders: 0,
                destination_chain_id,
                destination_contract,
                migration_id,
                bindings: Mapping::default(),
            }
        }

        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }

        #[ink(message)]
        pub fn asset_id(&self) -> [u8; 32] {
            self.asset_id
        }

        #[ink(message)]
        pub fn decimals(&self) -> u8 {
            self.decimals
        }

        #[ink(message)]
        pub fn max_supply(&self) -> Balance {
            self.max_supply
        }

        #[ink(message)]
        pub fn total_supply(&self) -> Balance {
            self.total_supply
        }

        #[ink(message)]
        pub fn is_frozen(&self) -> bool {
            self.frozen
        }

        /// Source-RUNTIME-observed block, immutable after successful freeze.
        /// This is not a finalized block attestation or storage proof.
        #[ink(message)]
        pub fn freeze_marker(&self) -> Option<(BlockNumber, Balance, u32, u32, u32)> {
            self.freeze_block.map(|block| (
                block,
                self.total_supply,
                self.holder_count,
                self.active_holder_count,
                self.unbound_active_holders,
            ))
        }

        #[ink(message)]
        pub fn holder_count(&self) -> u32 {
            self.holder_count
        }

        #[ink(message)]
        pub fn active_holder_count(&self) -> u32 {
            self.active_holder_count
        }

        /// Number of funded holders that have not registered a destination.
        /// A freeze with outstanding unbound rights is rejected atomically.
        #[ink(message)]
        pub fn unbound_active_holders(&self) -> u32 {
            self.unbound_active_holders
        }

        /// Immutable migration-specific replay domain. This does not assert
        /// whether the current WASM runtime is a trusted chain.
        #[ink(message)]
        pub fn destination_domain(&self) -> (u64, [u8; 20], [u8; 32]) {
            (self.destination_chain_id, self.destination_contract, self.migration_id)
        }

        #[ink(message)]
        pub fn binding_of(&self, source_owner: AccountId) -> Option<BindingRecord> {
            self.bindings.get(source_owner)
        }

        /// Bind a beneficiary to the *transaction caller*, NEVER to a
        /// caller-supplied source-account argument or administrator override.
        /// Normal Substrate signed extrinsic authentication of env().caller()
        /// must be verified through the actual source chain (#18, #23).
        /// expected_nonce enforces strict increasing 1..u64::MAX versions.
        #[ink(message)]
        pub fn register_beneficiary(&mut self, beneficiary: [u8; 20], expected_nonce: u64) -> Result<u64> {
            self.ensure_open()?;
            if beneficiary == [0u8; 20] {
                return Err(LedgerError::InvalidBeneficiary);
            }
            let source_owner = self.env().caller();
            Self::ensure_account(&source_owner)?;
            if self.balance_of_ref(&source_owner) == 0 {
                return Err(LedgerError::NoActiveEntitlement);
            }
            let old = self.bindings.get(&source_owner);
            let prior = old.as_ref().map(|b: &BindingRecord| b.nonce).unwrap_or(0);
            let next = prior.checked_add(1).ok_or(LedgerError::BindingNonceExhausted)?;
            if expected_nonce != next {
                return Err(LedgerError::InvalidBindingNonce);
            }
            let unbound_next = if old.is_none() {
                self.unbound_active_holders.checked_sub(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?
            } else {
                self.unbound_active_holders
            };
            let previous_beneficiary = old.map(|b: BindingRecord| b.beneficiary).unwrap_or([0u8; 20]);
            let next_binding = BindingRecord { beneficiary, nonce: next };
            self.bindings.insert(&source_owner, &next_binding);
            self.unbound_active_holders = unbound_next;
            self.env().emit_event(BeneficiaryRegistered {
                source_owner,
                source_contract: self.env().account_id(),
                destination_chain_id: self.destination_chain_id,
                destination_contract: self.destination_contract,
                migration_id: self.migration_id,
                previous_beneficiary,
                beneficiary,
                nonce: next,
            });
            Ok(next)
        }

        #[ink(message)]
        pub fn binding_at(&self, index: u32) -> Option<(AccountId, Balance, Option<BindingRecord>)> {
            if index >= self.holder_count {
                return None;
            }
            self.holders.get(index).map(|owner: AccountId| {
                let balance = self.balance_of_ref(&owner);
                let binding = self.bindings.get(&owner);
                (owner, balance, binding)
            })
        }

        #[ink(message)]
        pub fn balance_of(&self, account: AccountId) -> Balance {
            self.balance_of_ref(&account)
        }

        /// Stable index, even if an account later has zero balance.
        #[ink(message)]
        pub fn index_of(&self, account: AccountId) -> Option<u32> {
            self.slots_plus_one.get(account).map(|slot| slot - 1)
        }

        #[ink(message)]
        pub fn holder_at(&self, index: u32) -> Option<(AccountId, Balance)> {
            if index >= self.holder_count {
                return None;
            }
            self.holders.get(index).map(|account| {
                let amount = self.balance_of_ref(&account);
                (account, amount)
            })
        }

        /// Read-only, bounded pagination. Does not prove the RPC response
        /// is authentic; a finalized storage proof is required separately.
        #[ink(message)]
        pub fn holder_page(&self, start: u32, limit: u32) -> Vec<(AccountId, Balance)> {
            let end = core::cmp::min(
                self.holder_count,
                start.saturating_add(core::cmp::min(limit, PAGE_LIMIT)),
            );
            let mut output = Vec::new();
            for index in start..end {
                if let Some(account) = self.holders.get(index) {
                    output.push((account, self.balance_of_ref(&account)));
                }
            }
            output
        }

        /// Atomically read a snapshot *summary* at one source runtime state.
        /// The caller must pin reads to a finalized block and authenticate
        /// storage proofs independently (#27–#29); RPC views are not proofs.
        #[ink(message)]
        pub fn registry_snapshot(&self) -> (bool, [u8; 32], u8, Balance, Balance, u32, u32) {
            (
                self.frozen,
                self.asset_id,
                self.decimals,
                self.max_supply,
                self.total_supply,
                self.holder_count,
                self.active_holder_count,
            )
        }

        /// Explicit index on each row makes skipped registry slots detectable.
        /// Includes zero-balance tombstones; does not filter unclaimed holders.
        #[ink(message)]
        pub fn holder_page_indexed(&self, start: u32, limit: u32) -> Vec<(u32, AccountId, Balance)> {
            let end = core::cmp::min(
                self.holder_count,
                start.saturating_add(core::cmp::min(limit, PAGE_LIMIT)),
            );
            let mut page = Vec::new();
            for index in start..end {
                if let Some(account) = self.holders.get(index) {
                    page.push((index, account, self.balance_of_ref(&account)));
                }
            }
            page
        }

        fn balance_of_ref(&self, account: &AccountId) -> Balance {
            self.balances.get(account).unwrap_or(0)
        }

        fn ensure_open(&self) -> Result<()> {
            if self.frozen {
                Err(LedgerError::Frozen)
            } else {
                Ok(())
            }
        }

        fn ensure_admin(&self) -> Result<()> {
            if self.env().caller() != self.owner {
                Err(LedgerError::Unauthorized)
            } else {
                Ok(())
            }
        }

        fn ensure_account(account: &AccountId) -> Result<()> {
            if *account == AccountId::from([0u8; 32]) {
                Err(LedgerError::InvalidRecipient)
            } else {
                Ok(())
            }
        }

        /// All callers preflight this BEFORE any persistent state mutation.
        fn ensure_holder_capacity(&self, account: &AccountId) -> Result<()> {
            if self.slots_plus_one.get(account).is_none() && self.holder_count == u32::MAX {
                return Err(LedgerError::HolderRegistryFull);
            }
            Ok(())
        }

        /// No fallible operation is allowed after this method begins.
        /// A historical holder is registered only once, on the first deposit.
        fn register_holder(&mut self, account: &AccountId) {
            if self.slots_plus_one.get(account).is_none() {
                let slot = self.holder_count + 1; // prechecked against u32::MAX
                self.holders.insert(self.holder_count, account);
                self.slots_plus_one.insert(account, &slot);
                self.holder_count = slot;
            }
        }

        /// Only the issuance authority may create units; never above cap.
        /// Error paths are preflighted before any storage write.
        #[ink(message)]
        pub fn mint(&mut self, to: AccountId, amount: Balance) -> Result<()> {
            self.ensure_open()?;
            self.ensure_admin()?;
            Self::ensure_account(&to)?;
            if amount == 0 {
                return Err(LedgerError::InvalidAmount);
            }
            let current = self.balance_of_ref(&to);
            let next_balance = current.checked_add(amount)
                .ok_or(LedgerError::ArithmeticOverflow)?;
            let next_supply = self.total_supply.checked_add(amount)
                .ok_or(LedgerError::ArithmeticOverflow)?;
            if next_supply > self.max_supply {
                return Err(LedgerError::SupplyCapExceeded);
            }
            self.ensure_holder_capacity(&to)?;
            let next_active = if current == 0 {
                self.active_holder_count.checked_add(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?
            } else {
                self.active_holder_count
            };
            let next_unbound = if current == 0 && self.bindings.get(&to).is_none() {
                self.unbound_active_holders.checked_add(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?
            } else {
                self.unbound_active_holders
            };
            self.register_holder(&to);
            self.balances.insert(&to, &next_balance);
            self.unbound_active_holders = next_unbound;
            self.active_holder_count = next_active;
            self.total_supply = next_supply;
            self.env().emit_event(Issued { to, amount });
            Ok(())
        }

        /// Holder-authorized transfer; admin has NO allowance to move
        /// another person's balance.
        #[ink(message)]
        pub fn transfer(&mut self, to: AccountId, amount: Balance) -> Result<()> {
            self.ensure_open()?;
            Self::ensure_account(&to)?;
            let from = self.env().caller();
            if from == to {
                return Err(LedgerError::SelfTransfer);
            }
            if amount == 0 {
                return Err(LedgerError::InvalidAmount);
            }
            let from_balance = self.balance_of_ref(&from);
            if from_balance < amount {
                return Err(LedgerError::InsufficientBalance);
            }
            let to_balance = self.balance_of_ref(&to);
            let next_to = to_balance.checked_add(amount)
                .ok_or(LedgerError::ArithmeticOverflow)?;
            let next_from = from_balance - amount;
            self.ensure_holder_capacity(&to)?;
            let after_outflow = if next_from == 0 {
                self.active_holder_count.checked_sub(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?
            } else {
                self.active_holder_count
            };
            let next_active = if to_balance == 0 {
                after_outflow.checked_add(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?
            } else {
                after_outflow
            };
            let mut next_unbound = self.unbound_active_holders;
            if next_from == 0 && self.bindings.get(&from).is_none() {
                next_unbound = next_unbound.checked_sub(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?;
            }
            if to_balance == 0 && self.bindings.get(&to).is_none() {
                next_unbound = next_unbound.checked_add(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?;
            }
            self.register_holder(&to);
            self.balances.insert(&from, &next_from);
            self.balances.insert(&to, &next_to);
            self.unbound_active_holders = next_unbound;
            self.active_holder_count = next_active;
            self.env().emit_event(Transferred { from, to, amount });
            Ok(())
        }

        /// Only the account owner can destroy their own units.
        #[ink(message)]
        pub fn burn(&mut self, amount: Balance) -> Result<()> {
            self.ensure_open()?;
            if amount == 0 {
                return Err(LedgerError::InvalidAmount);
            }
            let from = self.env().caller();
            let current = self.balance_of_ref(&from);
            if current < amount {
                return Err(LedgerError::InsufficientBalance);
            }
            let next_balance = current - amount;
            let next_supply = self.total_supply.checked_sub(amount)
                .ok_or(LedgerError::ArithmeticOverflow)?;
            let next_active = if next_balance == 0 {
                self.active_holder_count.checked_sub(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?
            } else {
                self.active_holder_count
            };
            let next_unbound = if next_balance == 0 && self.bindings.get(&from).is_none() {
                self.unbound_active_holders.checked_sub(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?
            } else {
                self.unbound_active_holders
            };
            self.balances.insert(&from, &next_balance);
            self.total_supply = next_supply;
            self.unbound_active_holders = next_unbound;
            self.active_holder_count = next_active;
            self.env().emit_event(Burned { from, amount });
            Ok(())
        }

        /// Irreversible in this contract; no unlock or state-changing
        /// owner-renewal method exists. Chain-level runtime upgrades still
        /// require independent authorization and review.
        #[ink(message)]
        pub fn freeze(&mut self) -> Result<()> {
            self.ensure_admin()?;
            if self.frozen {
                return Err(LedgerError::AlreadyFrozen);
            }
            // Never strand funded users behind an immutable cutover.
            // Destination activation ALSO requires finalized on-chain proof
            // of every binding, outside this contract.
            if self.unbound_active_holders != 0 {
                return Err(LedgerError::UnboundActiveHolders);
            }
            let observed_block = self.env().block_number();
            self.frozen = true;
            self.freeze_block = Some(observed_block);
            self.env().emit_event(SourceFrozen {
                by: self.env().caller(),
                source_contract: self.env().account_id(),
                source_block: observed_block,
                asset_id: self.asset_id,
                migration_id: self.migration_id,
                destination_chain_id: self.destination_chain_id,
                destination_contract: self.destination_contract,
                total_supply: self.total_supply,
                holder_count: self.holder_count,
                active_holder_count: self.active_holder_count,
                unbound_active_holders: self.unbound_active_holders,
            });
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink::env::test;

        fn accounts() -> test::DefaultAccounts<ink::env::DefaultEnvironment> {
            test::default_accounts::<ink::env::DefaultEnvironment>()
        }
        fn caller(who: AccountId) {
            test::set_caller::<ink::env::DefaultEnvironment>(who);
        }
        fn ledger() -> MetorahSourceLedger {
            MetorahSourceLedger::new([7; 32], 12, 1_000, 31_337, [9; 20], [11; 32])
        }
        fn seeded() -> MetorahSourceLedger {
            let a = accounts();
            caller(a.alice);
            let mut l = ledger();
            assert_eq!(l.mint(a.alice, 60), Ok(()));
            assert_eq!(l.mint(a.bob, 40), Ok(()));
            assert_eq!(l.register_beneficiary([1; 20], 1), Ok(1));
            caller(a.bob);
            assert_eq!(l.register_beneficiary([2; 20], 1), Ok(1));
            caller(a.alice);
            l
        }
        #[ink::test]
        fn fresh_deployment_no_hidden_supply() {
            let a = accounts();
            let l = ledger();
            assert_eq!(l.owner(), a.alice);
            assert_eq!(l.total_supply(), 0);
            assert_eq!(l.holder_count(), 0);
            assert_eq!(l.active_holder_count(), 0);
            assert_eq!(l.asset_id(), [7; 32]);
            assert_eq!(l.decimals(), 12);
            assert!(!l.is_frozen());
        }
        #[ink::test]
        #[should_panic(expected = "asset ID cannot be all zero")]
        fn invalid_asset_id_rejected() {
            MetorahSourceLedger::new([0; 32], 12, 100, 31_337, [9; 20], [11; 32]);
        }
        #[ink::test]
        #[should_panic(expected = "unsupported decimal precision")]
        fn excessive_decimals_rejected() {
            MetorahSourceLedger::new([1; 32], 19, 100, 31_337, [9; 20], [11; 32]);
        }
        #[ink::test]
        #[should_panic(expected = "supply cap must be positive")]
        fn invalid_cap_rejected() {
            MetorahSourceLedger::new([1; 32], 12, 0, 31_337, [9; 20], [11; 32]);
        }
        #[ink::test]
        fn unauthorized_mint_fails_without_mutation() {
            let a = accounts();
            let mut l = ledger();
            caller(a.bob);
            assert_eq!(l.mint(a.bob, 10), Err(LedgerError::Unauthorized));
            assert_eq!(l.total_supply(), 0);
            assert_eq!(l.holder_count(), 0);
        }
        #[ink::test]
        fn mint_registers_unique_holders_and_supply() {
            let a = accounts();
            let mut l = ledger();
            assert_eq!(l.mint(a.bob, 10), Ok(()));
            assert_eq!(l.mint(a.bob, 15), Ok(()));
            assert_eq!(l.total_supply(), 25);
            assert_eq!(l.holder_count(), 1);
            assert_eq!(l.active_holder_count(), 1);
            assert_eq!(l.index_of(a.bob), Some(0));
            assert_eq!(l.holder_at(0), Some((a.bob, 25)));
        }
        #[ink::test]
        fn cap_violation_is_atomic() {
            let a = accounts();
            let mut l = ledger();
            assert_eq!(l.mint(a.alice, 950), Ok(()));
            assert_eq!(l.mint(a.bob, 51), Err(LedgerError::SupplyCapExceeded));
            assert_eq!(l.balance_of(a.bob), 0);
            assert_eq!(l.holder_count(), 1);
            assert_eq!(l.total_supply(), 950);
        }
        #[ink::test]
        fn overflow_never_partially_mutates() {
            let a = accounts();
            let mut l = MetorahSourceLedger::new([1; 32], 18, u128::MAX, 31_337, [9; 20], [11; 32]);
            assert_eq!(l.mint(a.alice, u128::MAX), Ok(()));
            assert_eq!(l.mint(a.bob, 1), Err(LedgerError::ArithmeticOverflow));
            assert_eq!(l.total_supply(), u128::MAX);
            assert_eq!(l.holder_count(), 1);
        }
        #[ink::test]
        fn zero_mint_and_zero_address_disallowed() {
            let a = accounts();
            let mut l = ledger();
            assert_eq!(l.mint(a.bob, 0), Err(LedgerError::InvalidAmount));
            assert_eq!(l.mint(AccountId::from([0;32]), 5), Err(LedgerError::InvalidRecipient));
            assert_eq!(l.holder_count(), 0);
        }
        #[ink::test]
        fn transfer_preserves_total_and_registers_recipient() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.alice, 100).unwrap();
            assert_eq!(l.transfer(a.bob, 35), Ok(()));
            assert_eq!(l.balance_of(a.alice), 65);
            assert_eq!(l.balance_of(a.bob), 35);
            assert_eq!(l.total_supply(), 100);
            assert_eq!(l.holder_count(), 2);
            assert_eq!(l.active_holder_count(), 2);
        }
        #[ink::test]
        fn transfer_full_amount_updates_active_count() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.alice, 100).unwrap();
            l.transfer(a.bob, 100).unwrap();
            assert_eq!(l.active_holder_count(), 1);
            assert_eq!(l.holder_count(), 2);
            assert_eq!(l.holder_at(0), Some((a.alice, 0)));
            assert_eq!(l.holder_at(1), Some((a.bob, 100)));
        }
        #[ink::test]
        fn transferring_back_does_not_reuse_holder_index() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            l.transfer(a.alice, 40).unwrap();
            caller(a.alice);
            l.transfer(a.bob, 20).unwrap();
            assert_eq!(l.holder_count(), 2);
            assert_eq!(l.active_holder_count(), 2);
            assert_eq!(l.index_of(a.bob), Some(1));
            assert_eq!(l.total_supply(), 100);
        }
        #[ink::test]
        fn insufficient_or_self_transfer_cannot_change_balance() {
            let a = accounts();
            let mut l = seeded();
            assert_eq!(l.transfer(a.bob, 61), Err(LedgerError::InsufficientBalance));
            assert_eq!(l.transfer(a.alice, 1), Err(LedgerError::SelfTransfer));
            assert_eq!(l.transfer(a.bob, 0), Err(LedgerError::InvalidAmount));
            assert_eq!(l.balance_of(a.alice), 60);
            assert_eq!(l.total_supply(), 100);
        }
        #[ink::test]
        fn admin_cannot_transfer_from_other_holder() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            assert_eq!(l.transfer(a.charlie, 41), Err(LedgerError::InsufficientBalance));
            assert_eq!(l.balance_of(a.alice), 60);
            assert_eq!(l.balance_of(a.bob), 40);
        }
        #[ink::test]
        fn burn_only_own_balance_and_supply_decrease() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            assert_eq!(l.burn(12), Ok(()));
            assert_eq!(l.balance_of(a.bob), 28);
            assert_eq!(l.total_supply(), 88);
            assert_eq!(l.burn(29), Err(LedgerError::InsufficientBalance));
            assert_eq!(l.total_supply(), 88);
        }
        #[ink::test]
        fn burn_to_zero_then_mint_keeps_historical_slot() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            l.burn(40).unwrap();
            assert_eq!(l.holder_count(), 2);
            assert_eq!(l.active_holder_count(), 1);
            caller(a.alice);
            l.mint(a.bob, 7).unwrap();
            assert_eq!(l.holder_count(), 2);
            assert_eq!(l.active_holder_count(), 2);
            assert_eq!(l.index_of(a.bob), Some(1));
        }
        #[ink::test]
        fn no_burn_of_zero() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            assert_eq!(l.burn(0), Err(LedgerError::InvalidAmount));
        }
        #[ink::test]
        fn unauthorized_freeze_denied() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            assert_eq!(l.freeze(), Err(LedgerError::Unauthorized));
            assert!(!l.is_frozen());
        }
        #[ink::test]
        fn freeze_once_blocks_every_mutation() {
            let a = accounts();
            let mut l = seeded();
            let total = l.total_supply();
            let hist = l.holder_count();
            let active = l.active_holder_count();
            assert_eq!(l.freeze(), Ok(()));
            assert_eq!(l.freeze(), Err(LedgerError::AlreadyFrozen));
            assert_eq!(l.mint(a.charlie, 1), Err(LedgerError::Frozen));
            assert_eq!(l.transfer(a.charlie, 1), Err(LedgerError::Frozen));
            assert_eq!(l.burn(1), Err(LedgerError::Frozen));
            caller(a.bob);
            assert_eq!(l.transfer(a.charlie, 1), Err(LedgerError::Frozen));
            assert_eq!(l.burn(1), Err(LedgerError::Frozen));
            assert_eq!(l.total_supply(), total);
            assert_eq!(l.holder_count(), hist);
            assert_eq!(l.active_holder_count(), active);
            assert_eq!(l.holder_at(1), Some((a.bob, 40)));
        }
        #[ink::test]
        fn bounded_page_yields_each_holder_in_index_order() {
            let a = accounts();
            let l = seeded();
            assert_eq!(l.holder_page(0, 64), vec![(a.alice, 60), (a.bob, 40)]);
            assert_eq!(l.holder_page(1, u32::MAX), vec![(a.bob, 40)]);
            assert!(l.holder_page(2, 64).is_empty());
            assert!(l.holder_page(0, 0).is_empty());
            assert!(l.holder_page(u32::MAX, u32::MAX).is_empty());
        }
        #[ink::test]
        fn supply_matches_independent_holder_scan() {
            let a = accounts();
            let mut l = seeded();
            l.transfer(a.charlie, 13).unwrap();
            caller(a.bob);
            l.burn(3).unwrap();
            let mut sum = 0u128;
            let mut positive = 0u32;
            for idx in 0..l.holder_count() {
                let (_, amount) = l.holder_at(idx).unwrap();
                sum += amount;
                if amount > 0 { positive += 1; }
            }
            assert_eq!(sum, l.total_supply());
            assert_eq!(positive, l.active_holder_count());
            assert_eq!(l.holder_count(), 3);
        }
        #[ink::test]
        fn snapshot_summary_tracks_exact_counts_and_supply() {
            let a = accounts();
            let mut l = seeded();
            assert_eq!(l.registry_snapshot(), (false, [7; 32], 12, 1_000, 100, 2, 2));
            caller(a.bob);
            l.burn(40).unwrap();
            assert_eq!(l.registry_snapshot(), (false, [7; 32], 12, 1_000, 60, 2, 1));
            caller(a.alice);
            l.freeze().unwrap();
            assert_eq!(l.registry_snapshot(), (true, [7; 32], 12, 1_000, 60, 2, 1));
        }

        #[ink::test]
        fn indexed_pages_preserve_tombstones_and_exact_positions() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            l.burn(40).unwrap();
            assert_eq!(l.holder_page_indexed(0, 64), vec![
                (0, a.alice, 60),
                (1, a.bob, 0),
            ]);
            assert_eq!(l.holder_page_indexed(1, 1), vec![(1, a.bob, 0)]);
            assert!(l.holder_page_indexed(2, 64).is_empty());
            assert!(l.holder_page_indexed(0, 0).is_empty());
            caller(a.alice);
            l.mint(a.bob, 5).unwrap();
            assert_eq!(l.holder_page_indexed(1, 1), vec![(1, a.bob, 5)]);
            assert_eq!(l.holder_count(), 2);
            assert_eq!(l.active_holder_count(), 2);
        }

        #[ink::test]
        fn indexed_pages_are_bounded_and_contiguous() {
            let a = accounts();
            let mut l = seeded();
            // Three existing accounts; a re-used account cannot add an index.
            l.mint(a.charlie, 1).unwrap();
            assert_eq!(l.holder_page_indexed(0, u32::MAX), vec![
                (0, a.alice, 60),
                (1, a.bob, 40),
                (2, a.charlie, 1),
            ]);
            assert_eq!(l.holder_page_indexed(1, 2), vec![
                (1, a.bob, 40),
                (2, a.charlie, 1),
            ]);
            assert!(l.holder_page_indexed(u32::MAX, u32::MAX).is_empty());
        }

        #[ink::test]
        fn one_hundred_thirty_holders_cross_page_boundaries_without_gaps() {
            let a = accounts();
            caller(a.alice);
            let mut l = ledger();
            for n in 1u8..=130u8 {
                let address = AccountId::from([n; 32]);
                assert_eq!(l.mint(address, 1), Ok(()));
                caller(address);
                assert_eq!(l.register_beneficiary([n; 20], 1), Ok(1));
                caller(a.alice);
            }
            assert_eq!(l.holder_count(), 130);
            assert_eq!(l.active_holder_count(), 130);
            assert_eq!(l.total_supply(), 130);
            assert_eq!(l.holder_page_indexed(0, 64).len(), 64);
            assert_eq!(l.holder_page_indexed(64, 64).len(), 64);
            assert_eq!(l.holder_page_indexed(128, 64).len(), 2);
            let mut total = 0u128;
            let mut seen = ink::prelude::collections::BTreeSet::new();
            for index in 0..l.holder_count() {
                let (account, units) = l.holder_at(index).expect("dense slot expected");
                assert!(seen.insert(account));
                assert_eq!(l.index_of(account), Some(index));
                total += units;
            }
            assert_eq!(seen.len(), 130);
            assert_eq!(total, l.total_supply());
            caller(AccountId::from([64u8; 32]));
            assert_eq!(l.burn(1), Ok(()));
            assert_eq!(l.holder_at(63), Some((AccountId::from([64u8; 32]), 0)));
            assert_eq!(l.holder_count(), 130);
            assert_eq!(l.active_holder_count(), 129);
            caller(a.alice);
            assert_eq!(l.freeze(), Ok(()));
            assert_eq!(l.registry_snapshot(), (true, [7; 32], 12, 1_000, 129, 130, 129));
        }

        #[ink::test]
        fn immutable_destination_domain_is_explicit_and_exact() {
            let l = ledger();
            assert_eq!(l.destination_domain(), (31_337, [9; 20], [11; 32]));
            assert_eq!(l.unbound_active_holders(), 0);
            assert_eq!(l.binding_of(accounts().alice), None);
        }

        #[ink::test]
        #[should_panic(expected = "destination chain ID cannot be zero")]
        fn reject_zero_destination_chain_id() {
            MetorahSourceLedger::new([7; 32], 12, 1_000, 0, [9; 20], [11; 32]);
        }

        #[ink::test]
        #[should_panic(expected = "destination contract cannot be zero")]
        fn reject_zero_destination_contract() {
            MetorahSourceLedger::new([7; 32], 12, 1_000, 31_337, [0; 20], [11; 32]);
        }

        #[ink::test]
        #[should_panic(expected = "migration ID cannot be zero")]
        fn reject_zero_migration_id() {
            MetorahSourceLedger::new([7; 32], 12, 1_000, 31_337, [9; 20], [0; 32]);
        }

        #[ink::test]
        fn source_holder_registration_binds_exact_source_account() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.bob, 25).unwrap();
            assert_eq!(l.unbound_active_holders(), 1);
            caller(a.bob);
            assert_eq!(l.register_beneficiary([7; 20], 1), Ok(1));
            assert_eq!(l.binding_of(a.bob), Some(BindingRecord { beneficiary: [7; 20], nonce: 1 }));
            assert_eq!(l.binding_at(0), Some((a.bob, 25, Some(BindingRecord { beneficiary: [7; 20], nonce: 1 }))));
            assert_eq!(l.unbound_active_holders(), 0);
            assert_eq!(l.destination_domain(), (31_337, [9; 20], [11; 32]));
            caller(a.alice);
            assert_eq!(l.binding_of(a.alice), None);
        }

        #[ink::test]
        fn unregistered_or_zero_balance_account_cannot_write_a_mapping() {
            let a = accounts();
            let mut l = ledger();
            caller(a.bob);
            assert_eq!(l.register_beneficiary([7; 20], 1), Err(LedgerError::NoActiveEntitlement));
            caller(a.alice);
            l.mint(a.bob, 10).unwrap();
            caller(a.bob);
            l.burn(10).unwrap();
            assert_eq!(l.register_beneficiary([7; 20], 1), Err(LedgerError::NoActiveEntitlement));
            assert_eq!(l.binding_of(a.bob), None);
        }

        #[ink::test]
        fn admin_cannot_register_for_another_holder_without_their_source_caller() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.bob, 10).unwrap();
            // There is deliberately no source-owner parameter on the method.
            // The administrator can only register for their own funded balance.
            assert_eq!(l.register_beneficiary([9; 20], 1), Err(LedgerError::NoActiveEntitlement));
            assert_eq!(l.binding_of(a.bob), None);
            caller(a.bob);
            assert_eq!(l.register_beneficiary([2; 20], 1), Ok(1));
            caller(a.alice);
            assert_eq!(l.binding_of(a.bob).unwrap().beneficiary, [2; 20]);
        }

        #[ink::test]
        fn monotonic_nonces_reject_replayed_or_skipped_updates() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.bob, 10).unwrap();
            caller(a.bob);
            assert_eq!(l.register_beneficiary([2; 20], 2), Err(LedgerError::InvalidBindingNonce));
            assert_eq!(l.register_beneficiary([2; 20], 0), Err(LedgerError::InvalidBindingNonce));
            assert_eq!(l.binding_of(a.bob), None);
            assert_eq!(l.register_beneficiary([2; 20], 1), Ok(1));
            let registered = l.binding_of(a.bob);
            assert_eq!(l.register_beneficiary([3; 20], 1), Err(LedgerError::InvalidBindingNonce));
            assert_eq!(l.register_beneficiary([3; 20], 3), Err(LedgerError::InvalidBindingNonce));
            assert_eq!(l.binding_of(a.bob), registered);
            assert_eq!(l.register_beneficiary([3; 20], 2), Ok(2));
            assert_eq!(l.binding_of(a.bob), Some(BindingRecord { beneficiary: [3; 20], nonce: 2 }));
            assert_eq!(l.register_beneficiary([4; 20], 2), Err(LedgerError::InvalidBindingNonce));
        }

        #[ink::test]
        fn no_registration_after_final_freeze_even_with_correct_nonce() {
            let a = accounts();
            let mut l = seeded();
            assert_eq!(l.unbound_active_holders(), 0);
            l.freeze().unwrap();
            caller(a.bob);
            assert_eq!(l.register_beneficiary([5; 20], 2), Err(LedgerError::Frozen));
            assert_eq!(l.binding_of(a.bob), Some(BindingRecord { beneficiary: [2; 20], nonce: 1 }));
            assert_eq!(l.unbound_active_holders(), 0);
        }

        #[ink::test]
        fn freeze_refuses_to_strand_unregistered_positive_holders() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.bob, 10).unwrap();
            assert_eq!(l.freeze(), Err(LedgerError::UnboundActiveHolders));
            assert!(!l.is_frozen());
            assert_eq!(l.total_supply(), 10);
            assert_eq!(l.unbound_active_holders(), 1);
            caller(a.bob);
            l.register_beneficiary([2; 20], 1).unwrap();
            caller(a.alice);
            assert_eq!(l.freeze(), Ok(()));
            assert!(l.is_frozen());
        }

        #[ink::test]
        fn zero_address_beneficiary_rejected_before_state_change() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            let previous = l.binding_of(a.bob);
            let events = test::recorded_events().count();
            assert_eq!(l.register_beneficiary([0; 20], 2), Err(LedgerError::InvalidBeneficiary));
            assert_eq!(l.binding_of(a.bob), previous);
            assert_eq!(test::recorded_events().count(), events);
        }

        #[ink::test]
        fn legitimate_holder_changes_beneficiary_pre_freeze_with_audit_event() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            let n = test::recorded_events().count();
            assert_eq!(l.register_beneficiary([7; 20], 2), Ok(2));
            assert_eq!(test::recorded_events().count(), n + 1);
            assert_eq!(l.binding_at(1), Some((a.bob, 40, Some(BindingRecord { beneficiary: [7; 20], nonce: 2 }))));
            assert_eq!(l.unbound_active_holders(), 0);
            caller(a.alice);
            l.freeze().unwrap();
            caller(a.bob);
            assert_eq!(l.register_beneficiary([8; 20], 3), Err(LedgerError::Frozen));
            assert_eq!(l.binding_of(a.bob).unwrap().nonce, 2);
        }

        #[ink::test]
        fn recipient_without_mapping_increases_unbound_count_on_transfer() {
            let a = accounts();
            let mut l = seeded();
            assert_eq!(l.unbound_active_holders(), 0);
            l.transfer(a.charlie, 10).unwrap();
            assert_eq!(l.unbound_active_holders(), 1);
            assert_eq!(l.active_holder_count(), 3);
            assert_eq!(l.freeze(), Err(LedgerError::UnboundActiveHolders));
            caller(a.charlie);
            assert_eq!(l.register_beneficiary([3; 20], 1), Ok(1));
            caller(a.alice);
            assert_eq!(l.freeze(), Ok(()));
        }

        #[ink::test]
        fn unbound_sender_drains_to_bound_recipient_without_stranding() {
            let a = accounts();
            let mut l = seeded();
            l.mint(a.charlie, 20).unwrap();
            assert_eq!(l.unbound_active_holders(), 1);
            caller(a.charlie);
            l.transfer(a.bob, 20).unwrap();
            assert_eq!(l.unbound_active_holders(), 0);
            assert_eq!(l.balance_of(a.charlie), 0);
            assert_eq!(l.active_holder_count(), 2);
            caller(a.alice);
            assert_eq!(l.freeze(), Ok(()));
        }

        #[ink::test]
        fn unbound_sender_to_unbound_recipient_keeps_one_unbound() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.bob, 20).unwrap();
            assert_eq!(l.unbound_active_holders(), 1);
            caller(a.bob);
            l.transfer(a.charlie, 20).unwrap();
            assert_eq!(l.unbound_active_holders(), 1);
            assert_eq!(l.active_holder_count(), 1);
            assert_eq!(l.freeze(), Err(LedgerError::Unauthorized));
            caller(a.alice);
            assert_eq!(l.freeze(), Err(LedgerError::UnboundActiveHolders));
        }

        #[ink::test]
        fn unbound_burn_to_zero_eliminates_unbound_liability() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.bob, 20).unwrap();
            assert_eq!(l.unbound_active_holders(), 1);
            caller(a.bob);
            l.burn(20).unwrap();
            assert_eq!(l.unbound_active_holders(), 0);
            assert_eq!(l.active_holder_count(), 0);
            caller(a.alice);
            assert_eq!(l.freeze(), Ok(()));
        }

        #[ink::test]
        fn registered_zero_balance_tombstone_keeps_binding_for_future_receipts() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            l.burn(40).unwrap();
            assert_eq!(l.active_holder_count(), 1);
            assert_eq!(l.binding_at(1).unwrap().2.unwrap().beneficiary, [2; 20]);
            caller(a.alice);
            l.mint(a.bob, 15).unwrap();
            assert_eq!(l.unbound_active_holders(), 0);
            assert_eq!(l.binding_at(1), Some((a.bob, 15, Some(BindingRecord { beneficiary: [2; 20], nonce: 1 }))));
            assert_eq!(l.freeze(), Ok(()));
        }

        #[ink::test]
        fn nonce_overflow_rejected_without_losing_old_mapping() {
            let a = accounts();
            let mut l = seeded();
            let original = BindingRecord { beneficiary: [2; 20], nonce: u64::MAX };
            l.bindings.insert(&a.bob, &original);
            caller(a.bob);
            assert_eq!(l.register_beneficiary([3; 20], 0), Err(LedgerError::BindingNonceExhausted));
            assert_eq!(l.binding_of(a.bob), Some(original));
            assert_eq!(l.unbound_active_holders(), 0);
        }

        #[ink::test]
        fn historical_account_without_binding_is_visible_and_nonclaimable() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.bob, 5).unwrap();
            caller(a.bob);
            l.burn(5).unwrap();
            assert_eq!(l.binding_at(0), Some((a.bob, 0, None)));
            assert_eq!(l.unbound_active_holders(), 0);
            caller(a.alice);
            assert_eq!(l.freeze(), Ok(()));
        }

        #[ink::test]
        fn constructor_rejects_cross_migration_domain_substitution() {
            // ink! off-chain Mapping storage is shared within one mocked
            // execution environment; it does NOT model two deployed
            // contracts' isolated chain storage. Test only the per-instance
            // immutable domain here. Actual replay/storage isolation across
            // deployments must be validated on a real chain (#18, #23).
            let first = ledger();
            let first_domain = first.destination_domain();
            let second = MetorahSourceLedger::new(
                [7; 32], 12, 1_000, 31_338, [8; 20], [12; 32]
            );
            assert_eq!(first.destination_domain(), first_domain);
            assert_eq!(first_domain, (31_337, [9; 20], [11; 32]));
            assert_eq!(second.destination_domain(), (31_338, [8; 20], [12; 32]));
            assert_ne!(first_domain, second.destination_domain());
        }

        #[ink::test]
        fn malicious_attempt_to_update_another_holders_binding_only_changes_caller() {
            let a = accounts();
            let mut l = seeded();
            caller(a.charlie);
            assert_eq!(l.register_beneficiary([8; 20], 1), Err(LedgerError::NoActiveEntitlement));
            assert_eq!(l.binding_of(a.bob).unwrap().beneficiary, [2; 20]);
            caller(a.alice);
            // Even the issuer can only modify its own beneficiary.
            l.register_beneficiary([8; 20], 2).unwrap();
            assert_eq!(l.binding_of(a.alice).unwrap().beneficiary, [8; 20]);
            assert_eq!(l.binding_of(a.bob).unwrap().beneficiary, [2; 20]);
        }

        #[ink::test]
        fn freeze_marker_is_absent_before_cutover_and_unchanged_after() {
            let a = accounts();
            let mut l = seeded();
            assert_eq!(l.freeze_marker(), None);
            test::advance_block::<ink::env::DefaultEnvironment>();
            let freeze_height = l.env().block_number();
            let prior_events = test::recorded_events().count();
            assert_eq!(l.freeze(), Ok(()));
            assert_eq!(test::recorded_events().count(), prior_events + 1);
            assert_eq!(l.freeze_marker(), Some((freeze_height, 100, 2, 2, 0)));
            test::advance_block::<ink::env::DefaultEnvironment>();
            assert_eq!(l.freeze(), Err(LedgerError::AlreadyFrozen));
            assert_eq!(l.freeze_marker(), Some((freeze_height, 100, 2, 2, 0)));
            caller(a.alice);
            assert_eq!(l.mint(a.charlie, 1), Err(LedgerError::Frozen));
        }

        #[ink::test]
        fn rejected_early_cutover_leaves_no_marker_or_event() {
            let a = accounts();
            let mut l = ledger();
            l.mint(a.bob, 10).unwrap();
            let original_events = test::recorded_events().count();
            assert_eq!(l.freeze(), Err(LedgerError::UnboundActiveHolders));
            assert!(!l.is_frozen());
            assert_eq!(l.freeze_marker(), None);
            assert_eq!(test::recorded_events().count(), original_events);
            caller(a.bob);
            assert_eq!(l.register_beneficiary([8; 20], 1), Ok(1));
            caller(a.alice);
            assert_eq!(l.freeze(), Ok(()));
            assert!(l.freeze_marker().is_some());
        }

        #[ink::test]
        fn every_write_path_is_disabled_after_freeze_even_as_issuer_or_holder() {
            let a = accounts();
            let mut l = seeded();
            assert_eq!(l.freeze(), Ok(()));
            let marker = l.freeze_marker();
            let events = test::recorded_events().count();
            assert_eq!(l.mint(a.charlie, 3), Err(LedgerError::Frozen));
            assert_eq!(l.transfer(a.charlie, 1), Err(LedgerError::Frozen));
            assert_eq!(l.burn(1), Err(LedgerError::Frozen));
            assert_eq!(l.register_beneficiary([4; 20], 2), Err(LedgerError::Frozen));
            caller(a.bob);
            assert_eq!(l.transfer(a.alice, 1), Err(LedgerError::Frozen));
            assert_eq!(l.burn(1), Err(LedgerError::Frozen));
            assert_eq!(l.register_beneficiary([5; 20], 2), Err(LedgerError::Frozen));
            assert_eq!(l.freeze(), Err(LedgerError::Unauthorized));
            assert_eq!(test::recorded_events().count(), events);
            assert_eq!(l.total_supply(), 100);
            assert_eq!(l.active_holder_count(), 2);
            assert_eq!(l.holder_count(), 2);
            assert_eq!(l.unbound_active_holders(), 0);
            assert_eq!(l.freeze_marker(), marker);
            assert_eq!(l.binding_of(a.bob).unwrap().beneficiary, [2; 20]);
        }

        #[ink::test]
        fn freeze_marker_keeps_cutoff_after_zero_balance_tombstone() {
            let a = accounts();
            let mut l = seeded();
            caller(a.bob);
            l.burn(40).unwrap();
            caller(a.alice);
            assert_eq!(l.freeze(), Ok(()));
            let marker = l.freeze_marker().unwrap();
            assert_eq!(marker.1, 60);
            assert_eq!(marker.2, 2);
            assert_eq!(marker.3, 1);
            assert_eq!(marker.4, 0);
            assert_eq!(l.holder_at(1), Some((a.bob, 0)));
        }

        #[ink::test]
        fn errors_do_not_emit_events() {
            let a = accounts();
            let mut l = ledger();
            let before = test::recorded_events().count();
            assert_eq!(l.mint(a.bob, 0), Err(LedgerError::InvalidAmount));
            assert_eq!(test::recorded_events().count(), before);
        }
    }
}
