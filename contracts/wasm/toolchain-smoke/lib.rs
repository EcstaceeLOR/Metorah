#![cfg_attr(not(feature = "std"), no_std, no_main)]
//! Toolchain-validation fixture only. NOT a migratable ledger or a deployed
//! Portaldot source contract. The real source implementation belongs to #20.

#[ink::contract]
mod toolchain_smoke {
    #[ink(storage)]
    pub struct ToolchainSmoke {
        frozen: bool,
        owner: AccountId,
    }

    impl ToolchainSmoke {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                frozen: false,
                owner: Self::env().caller(),
            }
        }

        #[ink(message)]
        pub fn freeze(&mut self) -> bool {
            if self.frozen || self.env().caller() != self.owner {
                return false;
            }
            self.frozen = true;
            true
        }

        #[ink(message)]
        pub fn is_frozen(&self) -> bool {
            self.frozen
        }

        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn constructor_starts_unfrozen() {
            let fixture = ToolchainSmoke::new();
            assert!(!fixture.is_frozen());
        }

        #[ink::test]
        fn owner_can_freeze_once_only() {
            let mut fixture = ToolchainSmoke::new();
            assert!(fixture.freeze());
            assert!(fixture.is_frozen());
            assert!(!fixture.freeze());
        }

        #[ink::test]
        fn another_account_cannot_freeze() {
            let accounts = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
            let mut fixture = ToolchainSmoke::new();
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.bob);
            assert!(!fixture.freeze());
            assert!(!fixture.is_frozen());
            assert_ne!(fixture.owner(), accounts.bob);
        }
    }
}
