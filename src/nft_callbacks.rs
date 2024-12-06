use krnl_auth::KrnlPayload;
use near_sdk::{log, require};

use crate::*;

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SaleArgs {
    pub path: String,
    pub token: String,
    pub sale_conditions: SaleCondition,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct OfferArgs {
    pub token_id: String,
    pub krnl_payload: KrnlPayload,
    pub debug_disable_check: bool,
}

trait NonFungibleTokenApprovalsReceiver {
    fn nft_on_approve(
        &mut self,
        token_id: TokenId,
        owner_id: AccountId,
        approval_id: u64,
        msg: String,
    );
}

#[near_bindgen]
impl NonFungibleTokenApprovalsReceiver for Contract {
    fn nft_on_approve(
        &mut self,
        token_id: TokenId,
        owner_id: AccountId,
        approval_id: u64,
        msg: String,
    ) {
        let nft_contract_id = env::predecessor_account_id();
        let signer_id = env::signer_account_id();

        // Try to parse as SaleArgs first
        log!("Attempting to parse message as SaleArgs: {}", msg);
        if let Ok(SaleArgs { token, path, sale_conditions }) = near_sdk::serde_json::from_str(&msg) {
            log!("Successfully parsed SaleArgs. Token: {}, Path: {}", token, path);
            
            let storage_amount = self.storage_minimum_balance();
            let owner_paid_storage = self.storage_deposits.get(&signer_id).unwrap_or(NearToken::from_yoctonear(0));
            let storage_required = (self.get_supply_by_owner_id(nft_contract_id.clone()).0 + 1) as u128 * storage_amount.as_yoctonear();
            
            log!("Storage check - Paid: {}, Required: {}", owner_paid_storage, storage_required);

            assert!(
                owner_paid_storage >= NearToken::from_yoctonear(storage_required),
                "Insufficient storage paid: {}, for {} sales at {} per sale",
                owner_paid_storage, 
                storage_required / storage_amount.as_yoctonear(), 
                storage_amount
            );

            let contract_and_token_id = format!("{}{}{}", nft_contract_id, DELIMETER, token_id);
            log!("Creating sale with contract_and_token_id: {}", contract_and_token_id);
            
            self.sales.insert(
                &contract_and_token_id,
                &Sale {
                    owner_id: owner_id.clone(),
                    approval_id,
                    nft_contract_id: nft_contract_id.to_string(),
                    token_id: token_id.clone(),
                    path,
                    token,
                    sale_conditions,
               },
            );
            log!("Sale object created and inserted");

            let mut by_owner_id = self.by_owner_id.get(&owner_id).unwrap_or_else(|| {
                log!("Creating new UnorderedSet for owner_id: {}", owner_id);
                UnorderedSet::new(
                    StorageKey::ByOwnerIdInner {
                        account_id_hash: hash_account_id(&owner_id),
                    },
                )
            });
            
            by_owner_id.insert(&contract_and_token_id);
            self.by_owner_id.insert(&owner_id, &by_owner_id);
            log!("Updated by_owner_id index");

            let mut by_nft_contract_id = self
                .by_nft_contract_id
                .get(&nft_contract_id)
                .unwrap_or_else(|| {
                    log!("Creating new UnorderedSet for nft_contract_id: {}", nft_contract_id);
                    UnorderedSet::new(
                        StorageKey::ByNFTContractIdInner {
                            account_id_hash: hash_account_id(&nft_contract_id),
                        },
                    )
                });
            
            by_nft_contract_id.insert(&token_id);
            self.by_nft_contract_id
                .insert(&nft_contract_id, &by_nft_contract_id);
            log!("Updated by_nft_contract_id index");

        } else if let Ok(OfferArgs { token_id: purchase_token_id, krnl_payload, debug_disable_check}) = near_sdk::serde_json::from_str(&msg) {
            log!("Processing offer with purchase_token_id: {}", purchase_token_id);

            let contract_and_token_id = format!("{}{}{}", nft_contract_id, DELIMETER, purchase_token_id);
            log!("Looking up sale for contract_and_token_id: {}", contract_and_token_id);
            
            let sale = self.sales.get(&contract_and_token_id).expect("No sale");
            log!("Found sale owned by: {}", sale.owner_id);
            
            assert_ne!(sale.owner_id, signer_id, "Cannot bid on your own sale.");
            log!("Validated signer is not sale owner");

            if !debug_disable_check {
                require!(self.is_krnl_authorized(krnl_payload.clone()), "Kernel authorization failed");

                let wallet = self.decode_kernel_responses(krnl_payload.auth.kernel_responses);
                let offer_address = self.get_address(format!("{},", token_id), sale.sale_conditions.token, env::predecessor_account_id().to_string());

                log!("Wallet address: {}", wallet.address);
                log!("Offer address: {}", offer_address);

                require!(offer_address == wallet.address, "Offer address does not match");
                require!(U128::from(wallet.balance.parse::<u128>().unwrap()) >= sale.sale_conditions.amount, "Offer token does not hold the necessary amount");

                // Check if the key being offered was never used to sign any transaction
                // Check bugs on approvals
            }

            log!("Processing purchase with nft_contract_id: {}, signer_id: {}, token_id: {}, owner_id: {}, sale_token_id: {}", 
                nft_contract_id, signer_id, token_id, sale.owner_id, sale.token_id);

            self.process_purchase(
                nft_contract_id,
                signer_id,
                token_id,
                approval_id,
                sale.owner_id,
                sale.token_id,
            );
        } else {
            log!("Invalid args - must be SaleArgs or OfferArgs");
        }
    }
}