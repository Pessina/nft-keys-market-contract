use crate::*;

pub(crate) fn hash_account_id(account_id: &AccountId) -> CryptoHash {
    let mut hash = CryptoHash::default();
    hash.copy_from_slice(&env::sha256(account_id.as_bytes()));
    hash
}

pub(crate) fn storage_per_sale() -> NearToken {
  env::storage_byte_cost().saturating_mul(1000)
}

impl Contract {
    pub(crate) fn internal_remove_sale(
        &mut self,
        nft_contract_id: AccountId,
        token_id: TokenId,
    ) -> Sale {
        let contract_and_token_id = format!("{}{}{}", &nft_contract_id, DELIMETER, token_id);
        let sale = self.sales.remove(&contract_and_token_id).expect("No sale");
        let mut by_owner_id = self.by_owner_id.get(&sale.owner_id).expect("No sale by_owner_id");
        
        by_owner_id.remove(&contract_and_token_id);
        
        if by_owner_id.is_empty() {
            self.by_owner_id.remove(&sale.owner_id);
        } else {
            self.by_owner_id.insert(&sale.owner_id, &by_owner_id);
        }

        let mut by_nft_contract_id = self
            .by_nft_contract_id
            .get(&nft_contract_id)
            .expect("No sale by nft_contract_id");
        
        by_nft_contract_id.remove(&token_id);
        
        if by_nft_contract_id.is_empty() {
            self.by_nft_contract_id.remove(&nft_contract_id);
        } else {
            self.by_nft_contract_id
                .insert(&nft_contract_id, &by_nft_contract_id);
        }

        sale
    }
}
