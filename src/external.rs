use crate::*;

//initiate a cross contract call to the nft contract
#[ext_contract(ext_contract)]
trait ExtContract {
    //This will transfer the token to the buyer and return a payout object used for the market to distribute funds to the appropriate accounts
    fn nft_transfer(
        &mut self,
        receiver_id: AccountId,
        token_id: TokenId,
        approval_id: Option<u32>,
        memo: Option<String>,
    );
    fn nft_token(&self, token_id: TokenId);
    fn nft_is_approved(
        &self,
        token_id: TokenId,
        approved_account_id: AccountId,
        approval_id: u32,
    );
}