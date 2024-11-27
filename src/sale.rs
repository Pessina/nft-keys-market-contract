use crate::*;
use near_sdk::NearSchema;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, NearSchema)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Sale {
    pub owner_id: AccountId,
    pub approval_id: u64,
    pub nft_contract_id: String,
    pub token_id: String,
    pub path: String, // Derivation path for the key holding the funds
    pub token: String, // Token that the key holds the funds
    pub sale_conditions: SaleCondition,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, NearSchema)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Offer {
    pub token_id: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct JsonToken {
    pub owner_id: AccountId,
}

#[near_bindgen]
impl Contract {
    #[payable]
    pub fn remove_sale(&mut self, nft_contract_id: AccountId, token_id: String) {
        assert_one_yocto();
        let sale = self.internal_remove_sale(nft_contract_id.into(), token_id);
        let owner_id = env::predecessor_account_id();
        assert_eq!(owner_id, sale.owner_id, "Must be sale owner");
    }

    #[private]
    pub fn process_purchase(
        &mut self,
        nft_contract_id: AccountId,
        buyer_id: AccountId,
        buyer_token_id: String,
        approval_id: u64,
        seller_id: AccountId,
        seller_token_id: String,
    ) -> Promise {
        let sale = self.internal_remove_sale(nft_contract_id.clone(), seller_token_id.clone());

        ext_contract::ext(nft_contract_id.clone())
            .with_attached_deposit(ONE_YOCTONEAR)
            .with_static_gas(GAS_FOR_NFT_TRANSFER)
            .nft_transfer(
                buyer_id,
                seller_token_id,
                Some(sale.approval_id),
                Some("payout from market".to_string()),
        )
        .then(
            ext_contract::ext(nft_contract_id)
            .with_attached_deposit(ONE_YOCTONEAR)
            .with_static_gas(GAS_FOR_NFT_TRANSFER)
            .nft_transfer(
                seller_id,
                buyer_token_id,
                Some(approval_id),
                Some("payout from market".to_string()),
            )
        )
    }  
}