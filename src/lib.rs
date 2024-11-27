use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::json_types::{U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    near,
    assert_one_yocto, env, ext_contract, near_bindgen, AccountId, BorshStorageKey, CryptoHash, Gas,
    NearToken, PanicOnDefault, Promise,
};
use std::collections::HashMap;

use crate::external::*;
use crate::internal::*;
use crate::sale::*;

mod external;
mod internal;
mod nft_callbacks;
mod sale;
mod sale_views;

const GAS_FOR_NFT_TRANSFER: Gas = Gas::from_tgas(15);
const ZERO_NEAR: NearToken = NearToken::from_yoctonear(0);
const ONE_YOCTONEAR: NearToken = NearToken::from_yoctonear(1);
static DELIMETER: &str = ".";
#[derive(Debug, Clone, Eq, PartialEq)]
#[near(serializers = [json, borsh])]
pub struct SaleCondition {
    pub token: String,
    pub amount: U128,
}
pub type TokenId = String;
pub type FungibleTokenId = AccountId;
pub type ContractAndTokenId = String;

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Payout {
    pub payout: HashMap<AccountId, NearToken>,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Contract {
    pub owner_id: AccountId,
    pub sales: UnorderedMap<ContractAndTokenId, Sale>,
    pub by_owner_id: LookupMap<AccountId, UnorderedSet<ContractAndTokenId>>,
    pub by_nft_contract_id: LookupMap<AccountId, UnorderedSet<TokenId>>,
    pub storage_deposits: LookupMap<AccountId, NearToken>,
}

#[derive(BorshStorageKey, BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    Sales,
    ByOwnerId,
    ByOwnerIdInner { account_id_hash: CryptoHash },
    ByNFTContractId,
    ByNFTContractIdInner { account_id_hash: CryptoHash },
    ByNFTTokenType,
    ByNFTTokenTypeInner { token_type_hash: CryptoHash },
    FTTokenIds,
    StorageDeposits,
}

#[near_bindgen]
impl Contract {
    #[init(ignore_state)]
    pub fn new(owner_id: AccountId) -> Self {
        let this = Self {
            owner_id,
            sales: UnorderedMap::new(b"1"), // StorageKey::Sales
            by_owner_id: LookupMap::new(b"2"), // StorageKey::ByOwnerId
            by_nft_contract_id: LookupMap::new(b"3"), // StorageKey::ByNFTContractId
            storage_deposits: LookupMap::new(b"4"), // StorageKey::StorageDeposits
        };

        this
    }

    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) {
        let storage_account_id = account_id
            .map(|a| a.into())
            .unwrap_or_else(env::predecessor_account_id);
        let deposit = env::attached_deposit();

        assert!(
            deposit.ge(&storage_per_sale()),
            "Requires minimum deposit of {}",
            storage_per_sale()
        );

        let mut balance: NearToken = self
            .storage_deposits
            .get(&storage_account_id)
            .unwrap_or(ZERO_NEAR);

        balance = balance.saturating_add(deposit);
        self.storage_deposits.insert(&storage_account_id, &balance);
    }

    #[payable]
    pub fn storage_withdraw(&mut self) {
        assert_one_yocto();

        let owner_id = env::predecessor_account_id();
        let mut amount = self.storage_deposits.remove(&owner_id).unwrap_or(ZERO_NEAR);
        let sales = self.by_owner_id.get(&owner_id);
        let len = sales.map(|s| s.len()).unwrap_or_default();
        let diff = storage_per_sale().saturating_mul(u128::from(len));

        amount = amount.saturating_sub(diff);

        if amount.gt(&ZERO_NEAR) {
            Promise::new(owner_id.clone()).transfer(amount);
        }

        if diff.gt(&ZERO_NEAR) {
            self.storage_deposits.insert(&owner_id, &diff);
        }
    }

    pub fn storage_minimum_balance(&self) -> NearToken {
        storage_per_sale()
    }

    pub fn storage_balance_of(&self, account_id: AccountId) -> NearToken {
        self.storage_deposits.get(&account_id).unwrap_or(ZERO_NEAR)
    }
}

#[cfg(test)]
mod tests;
