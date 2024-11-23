use crate::*;
use near_sdk::{log, promise_result_as_success, NearSchema, PromiseError};
use near_sdk::serde_json::json;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, NearSchema)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Sale {
    pub owner_id: AccountId,
    pub approval_id: u64,
    pub nft_contract_id: String,
    pub token_id: String,
    pub sale_conditions: SaleCondition,
}

#[derive(Serialize, Deserialize, NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct JsonToken {
    pub owner_id: AccountId,
}

#[near_bindgen]
impl Contract {
    #[payable]
    pub fn list_nft_for_sale(
      &mut self,
      nft_contract_id: AccountId,
      token_id: TokenId,
      approval_id: u64,
      sale_conditions: SaleCondition,
    ) {
        let owner_id = env::predecessor_account_id();

        let storage_amount = self.storage_minimum_balance();
        let owner_paid_storage = self.storage_deposits.get(&owner_id).unwrap_or(ZERO_NEAR);
        let signer_storage_required = storage_amount.saturating_mul((self.get_supply_by_owner_id(owner_id.clone()).0 + 1).into());
        
        assert!(
            owner_paid_storage.ge(&signer_storage_required),
            "Insufficient storage paid: {}, for {} sales at {} rate of per sale",
            owner_paid_storage, signer_storage_required.saturating_div(storage_per_sale().as_yoctonear()), storage_per_sale()
        );

        let nft_token_promise = Promise::new(nft_contract_id.clone()).function_call(
          "nft_token".to_owned(),
          json!({ "token_id": token_id }).to_string().into_bytes(),
          ZERO_NEAR,
          Gas::from_gas(10u64.pow(13))
        );
        let nft_is_approved_promise = Promise::new(nft_contract_id.clone()).function_call(
          "nft_is_approved".to_owned(),
          json!({ "token_id": token_id, "approved_account_id": env::current_account_id(), "approval_id": approval_id }).to_string().into_bytes(),
          ZERO_NEAR,
          Gas::from_gas(10u64.pow(13))
        );
        nft_token_promise
          .and(nft_is_approved_promise)
          .then(Self::ext(env::current_account_id()).process_listing(owner_id.clone(), nft_contract_id, token_id, approval_id, sale_conditions));
    }

    #[payable]
    pub fn remove_sale(&mut self, nft_contract_id: AccountId, token_id: String) {
        assert_one_yocto();
        let sale = self.internal_remove_sale(nft_contract_id.into(), token_id);
        let owner_id = env::predecessor_account_id();
        assert_eq!(owner_id, sale.owner_id, "Must be sale owner");
    }

    #[payable]
    pub fn offer(&mut self, nft_contract_id: AccountId, token_id: String, offer_price: SaleCondition) {
        let deposit = env::attached_deposit();
        assert!(!deposit.is_zero(), "Attached deposit must be greater than 0");

        let contract_id: AccountId = nft_contract_id.into();
        let contract_and_token_id = format!("{}{}{}", contract_id, DELIMETER, token_id);        
        let sale = self.sales.get(&contract_and_token_id).expect("No sale");
        let buyer_id = env::predecessor_account_id();
        
        assert_ne!(sale.owner_id, buyer_id, "Cannot bid on your own sale.");

        let price = sale.sale_conditions;

        assert!(
            offer_price.amount.ge(&price.amount),
            "Offer amount {} is less than the listed price {}",
            offer_price.amount.0,
            price.amount.0
        );
        assert_eq!(
            offer_price.token,
            price.token,
            "Incorrect token offered. Expected {}, got {}",
            price.token,
            offer_price.token
        );

        self.process_purchase(
            contract_id,
            token_id,
            deposit,
            buyer_id,
        );
    }

    #[private]
    pub fn process_purchase(
        &mut self,
        nft_contract_id: AccountId,
        token_id: String,
        price: NearToken,
        buyer_id: AccountId,
    ) -> Promise {
        let sale = self.internal_remove_sale(nft_contract_id.clone(), token_id.clone());

        ext_contract::ext(nft_contract_id)
            .with_attached_deposit(ONE_YOCTONEAR)
            .with_static_gas(GAS_FOR_NFT_TRANSFER)
            .nft_transfer(
                buyer_id.clone(),
                token_id,
                Some(sale.approval_id),
                Some("payout from market".to_string()),
            )
        .then(
            Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_RESOLVE_PURCHASE)
            .resolve_purchase(
                buyer_id,
                price,
            )
        )
    }

    #[private]
    pub fn resolve_purchase(
        &mut self,
        buyer_id: AccountId,
        price: NearToken,
    ) -> NearToken {
        let payout_option = promise_result_as_success().and_then(|value| {
            near_sdk::serde_json::from_slice::<Payout>(&value)
                .ok()
                .and_then(|payout_object| {
                    if payout_object.payout.len() > 10 || payout_object.payout.is_empty() {
                        env::log_str("Cannot have more than 10 royalties");
                        None
                    } else {
                        let mut remainder = price;
                        for &value in payout_object.payout.values() {
                            remainder = remainder.checked_sub(value)?;
                        }
                        if remainder.eq(&ZERO_NEAR) || remainder.eq(&NearToken::from_yoctonear(1)) {
                            Some(payout_object.payout)
                        } else {
                            None
                        }
                    }
                })
        });

        let payout = if let Some(payout_option) = payout_option {
            payout_option
        } else {
            Promise::new(buyer_id).transfer(price);
            return price;
        };

        for (receiver_id, amount) in payout {
            Promise::new(receiver_id).transfer(amount);
        }

        price
    }

    #[private]
    pub fn process_listing(
        &mut self,
        owner_id: AccountId,
        nft_contract_id: AccountId,
        token_id: TokenId,
        approval_id: u64,
        sale_conditions: SaleCondition,
        #[callback_result] nft_token_result: Result<JsonToken, PromiseError>,
        #[callback_result] nft_is_approved_result: Result<bool, PromiseError>,
    ) {
        if let Ok(result) = nft_token_result {
            assert_eq!(
                result.owner_id,
                owner_id,
                "Signer is not NFT owner",
            )
        } else {
            log!("nft_is_approved call failed");
        }
        if let Ok(result) = nft_is_approved_result {
            assert_eq!(
                result,
                true,
                "Marketplace contract is not approved",
            )
        } else {
            log!("nft_is_approved call failed");
        } 
    
        let contract_and_token_id = format!("{}{}{}", nft_contract_id, DELIMETER, token_id);
        
        self.sales.insert(
            &contract_and_token_id,
            &Sale {
                owner_id: owner_id.clone(),
                approval_id,
                nft_contract_id: nft_contract_id.to_string(),
                token_id: token_id.clone(),
                sale_conditions,
          },
        );

        let mut by_owner_id = self.by_owner_id.get(&owner_id).unwrap_or_else(|| {
            UnorderedSet::new(
                StorageKey::ByOwnerIdInner {
                    account_id_hash: hash_account_id(&owner_id),
                }
            )
        });
        
        by_owner_id.insert(&contract_and_token_id);
        self.by_owner_id.insert(&owner_id, &by_owner_id);

        let mut by_nft_contract_id = self
            .by_nft_contract_id
            .get(&nft_contract_id)
            .unwrap_or_else(|| {
                UnorderedSet::new(
                    StorageKey::ByNFTContractIdInner {
                        account_id_hash: hash_account_id(&nft_contract_id),
                    }
                )
            });
        
        by_nft_contract_id.insert(&token_id);
        self.by_nft_contract_id
            .insert(&nft_contract_id, &by_nft_contract_id);
    }
}


#[ext_contract(ext_self)]
trait ExtSelf {
    fn resolve_purchase(
        &mut self,
        buyer_id: AccountId,
        price: NearToken,
    ) -> Promise;
}